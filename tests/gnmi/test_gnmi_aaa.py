"""gNMI audit, authentication, and authorization tests."""

import logging
import time

import grpc
import pytest
from pygnmi.client import gNMIException
from pygnmi.spec.v080 import gnmi_pb2

from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    _restart_gnoi_server,
    gnmi_tls,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.gnmi_connection import gnmi_connection
from tests.common.helpers.gnmi_audit import (
    RPC_COMPLETION_PREFIX,
    get_audit_log_offset,
    parse_audit_records,
    wait_for_audit_record,
    wait_for_audit_records,
)
from tests.common.helpers.sonic_db import (
    CONFIG_DB,
    redis_del,
    redis_hdel,
    redis_hget,
    redis_hset,
    redis_keys,
)
from tests.common.helpers.syslog_helpers import (
    capture_remote_syslog,
    is_mgmt_vrf_enabled,
    read_syslog_payloads,
)
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.pygnmi_client import GetDataType, PygnmiClientError

pytestmark = [
    pytest.mark.topology("any"),
]
logger = logging.getLogger(__name__)
allure.logger = logger
CLIENT_PRINCIPAL = "test.client.gnmi.sonic"
GENERIC_NOACCESS_ROLE = "gnmi_noaccess"
GENERIC_READONLY_ROLE = "gnmi_readonly"
GENERIC_READWRITE_ROLE = "gnmi_readwrite"
CONFIG_DB_NOACCESS_ROLE = "gnmi_config_db_noaccess"
CONFIG_DB_READONLY_ROLE = "gnmi_config_db_readonly"
CONFIG_DB_READWRITE_ROLE = "gnmi_config_db_readwrite"
NO_ACCESS_ERROR = r"does not have access.*role {}\b"
UNMAPPED_CN_ERROR = "Unauthenticated|unauthenticated|Invalid cert cname|" "not a trusted|common name mapping"
GET_METHOD = "/gnmi.gNMI/Get"
SET_METHOD = "/gnmi.gNMI/Set"
RATE_LIMIT_BURST = 60
RATE_LIMIT_REFILL_SECONDS = 60
CONFIG_DB_GET_PATH = "sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost"
CONFIG_DB_SET_PATH = "{}/cloudtype".format(CONFIG_DB_GET_PATH)
AUDIT_GET_PATH = "/CONFIG_DB/localhost/DEVICE_METADATA/localhost"
AUDIT_SET_PATH = "{}/cloudtype".format(AUDIT_GET_PATH)


def _set_configdb(env):
    request = gnmi_pb2.SetRequest(
        prefix=gnmi_pb2.Path(origin="sonic-db"),
        update=[gnmi_pb2.Update(
            path=gnmi_pb2.Path(elem=[gnmi_pb2.PathElem(name=name) for name in (
                "CONFIG_DB", "localhost", "DEVICE_METADATA", "localhost", "cloudtype",
            )]),
            val=gnmi_pb2.TypedValue(json_ietf_val=b'"Public"'),
        )],
    )
    with gnmi_connection(env) as (_, client):
        client.Set(request, timeout=30)


def _get_configdb(env):
    request = gnmi_pb2.GetRequest(
        prefix=gnmi_pb2.Path(origin="sonic-db"),
        path=[gnmi_pb2.Path(elem=[gnmi_pb2.PathElem(name=name) for name in (
            "CONFIG_DB", "localhost", "DEVICE_METADATA", "localhost",
        )])],
        type=gnmi_pb2.GetRequest.ALL,
        encoding=gnmi_pb2.JSON_IETF,
    )
    with gnmi_connection(env) as (_, client):
        client.Get(request, timeout=30)


def _get_countersdb(env):
    request = gnmi_pb2.GetRequest(
        prefix=gnmi_pb2.Path(target="COUNTERS_DB"),
        path=[gnmi_pb2.Path(elem=[gnmi_pb2.PathElem(name="COUNTERS_PORT_NAME_MAP")])],
        type=gnmi_pb2.GetRequest.ALL,
        encoding=gnmi_pb2.JSON_IETF,
    )
    with gnmi_connection(env) as (_, client):
        client.Get(request, timeout=30)


def _get_capabilities(env):
    result = env.pygnmi_client.capabilities()
    models = result.get("supported_models", [])
    encodings = result.get("supported_encodings", [])
    pytest_assert(
        any(model.get("name") == "sonic-db" for model in models),
        "sonic-db not found in gNMI capabilities: {}".format(models),
    )
    pytest_assert(
        "json_ietf" in encodings,
        "json_ietf not found in gNMI capabilities: {}".format(encodings),
    )


def _set_client_cert_role(duthost, role):
    role_key = "GNMI_CLIENT_CERT|{}".format(CLIENT_PRINCIPAL)
    if role is None:
        result = redis_del(duthost, CONFIG_DB, role_key)[0]
        pytest_assert(
            result["rc"] == 0 and result["stdout"].strip() == "1",
            "Failed to remove client certificate mapping: {}".format(result),
        )
        return

    result = redis_hset(duthost, CONFIG_DB, role_key, **{"role@": role})
    pytest_assert(
        result["rc"] == 0,
        "Failed to set role {!r}: {}".format(role, result),
    )
    pytest_assert(
        redis_hget(duthost, CONFIG_DB, role_key, "role@") == role,
        "Client certificate role was not set to {!r}".format(role),
    )


AUDIT_ACTIVITIES = [
    pytest.param(_get_countersdb, GET_METHOD, id="get"),
    pytest.param(_set_configdb, SET_METHOD, id="set"),
]


@pytest.mark.parametrize("operation,method", AUDIT_ACTIVITIES)
def test_gnmi_audit_log(gnmi_tls, operation, method):  # noqa: F811
    duthost = gnmi_tls.duthost
    offset = get_audit_log_offset(duthost)

    operation(gnmi_tls)
    wait_for_audit_record(duthost, offset, method, CLIENT_PRINCIPAL)


def test_gnmi_audit_rate_limit(gnmi_tls):  # noqa: F811
    """Verify Get outcome buckets are limited and Set remains unlimited."""
    duthost = gnmi_tls.duthost
    offset = get_audit_log_offset(duthost)

    burst_started = time.monotonic()
    with gnmi_tls.pygnmi_client._build_client() as client:
        for _ in range(RATE_LIMIT_BURST + 1):
            client.get(
                path=[CONFIG_DB_GET_PATH],
                encoding="json_ietf",
            )

        get_burst_seconds = time.monotonic() - burst_started
        pytest_assert(
            get_burst_seconds < RATE_LIMIT_REFILL_SECONDS,
            "Get burst took {:.1f}s; requests crossed the 60s refill " "boundary".format(get_burst_seconds),
        )

        with pytest.raises(gNMIException, match="unsupported request type"):
            client.get(
                path=[CONFIG_DB_GET_PATH],
                datatype=str(GetDataType.STATE),
                encoding="json_ietf",
            )

    get_records = wait_for_audit_records(
        duthost,
        offset,
        GET_METHOD,
        CLIENT_PRINCIPAL,
        expected_count=RATE_LIMIT_BURST,
        code="OK",
        path=AUDIT_GET_PATH,
    )
    pytest_assert(
        all(record["suppressed"] == 0 for record in get_records),
        "In-limit Get records unexpectedly reported suppression",
    )

    unimplemented_records = wait_for_audit_records(
        duthost,
        offset,
        GET_METHOD,
        CLIENT_PRINCIPAL,
        expected_count=1,
        code="Unimplemented",
        path=AUDIT_GET_PATH,
    )
    pytest_assert(
        unimplemented_records[0]["suppressed"] == 0,
        "Get/Unimplemented did not use an independent outcome bucket",
    )

    _set_client_cert_role(duthost, CONFIG_DB_READONLY_ROLE)
    with gnmi_tls.pygnmi_client._build_client() as client:
        for _ in range(RATE_LIMIT_BURST + 1):
            with pytest.raises(gNMIException, match=CONFIG_DB_READONLY_ROLE):
                client.set(
                    update=[(CONFIG_DB_SET_PATH, '"Public"')],
                    encoding="json_ietf",
                )

    set_records = wait_for_audit_records(
        duthost,
        offset,
        SET_METHOD,
        CLIENT_PRINCIPAL,
        expected_count=RATE_LIMIT_BURST + 1,
        code="Unknown",
        path=AUDIT_SET_PATH,
    )
    pytest_assert(
        all(record["suppressed"] == 0 for record in set_records),
        "Set records were unexpectedly rate-limited",
    )

    refill_wait = max(
        0,
        RATE_LIMIT_REFILL_SECONDS + 1 - (time.monotonic() - burst_started),
    )
    time.sleep(refill_wait)
    gnmi_tls.pygnmi_client.get(CONFIG_DB_GET_PATH)

    get_records = wait_for_audit_records(
        duthost,
        offset,
        GET_METHOD,
        CLIENT_PRINCIPAL,
        expected_count=RATE_LIMIT_BURST + 1,
        code="OK",
        path=AUDIT_GET_PATH,
    )
    pytest_assert(
        get_records[-1]["suppressed"] == 1,
        "First refilled Get record did not report one suppressed request: {}".format(get_records[-1]),
    )


@pytest.mark.parametrize("operation,method", AUDIT_ACTIVITIES)
def test_gnmi_audit_log_remote_forwarding(gnmi_tls, ptfhost, operation, method):  # noqa: F811
    duthost = gnmi_tls.duthost
    syslog_vrf = "mgmt" if is_mgmt_vrf_enabled(duthost) else None

    with capture_remote_syslog(duthost, ptfhost.mgmt_ip, vrf=syslog_vrf) as (capture_result, capture_file):
        offset = get_audit_log_offset(duthost)
        with allure.step("Generate a {} audit record".format(method)):
            operation(gnmi_tls)

        with allure.step("Verify the remotely forwarded audit record"):
            local_records = wait_for_audit_record(duthost, offset, method, CLIENT_PRINCIPAL)
            forwarded_payloads = read_syslog_payloads(duthost, capture_result, capture_file)
            pytest_assert(
                any(RPC_COMPLETION_PREFIX in payload for payload in forwarded_payloads),
                "No RPC_COMPLETION marker found in forwarded UDP packets",
            )
            streamed_records = [
                record
                for payload in forwarded_payloads
                for record in parse_audit_records(payload, method, CLIENT_PRINCIPAL)
            ]
            pytest_assert(
                streamed_records == local_records,
                "Streamed audit records differ from local gNMI records: "
                "local={}, streamed={}".format(
                    local_records,
                    streamed_records,
                ),
            )


def test_gnmi_default_cert_auth(gnmi_tls):  # noqa: F811
    """Default certificate authentication rejects an unmapped CN at Capabilities."""
    duthost = gnmi_tls.duthost
    delete_result = redis_hdel(duthost, CONFIG_DB, "GNMI|gnmi", "user_auth")
    pytest_assert(
        delete_result["rc"] == 0 and delete_result["stdout"].strip() == "1",
        "Failed to delete GNMI|gnmi.user_auth: {}".format(delete_result),
    )
    pytest_assert(
        not redis_hget(duthost, CONFIG_DB, "GNMI|gnmi", "user_auth"),
        "GNMI|gnmi.user_auth is still configured after HDEL",
    )
    _restart_gnoi_server(duthost)

    redis_del(
        duthost,
        CONFIG_DB,
        *redis_keys(duthost, CONFIG_DB, "GNMI_CLIENT_CERT|*"),
    )
    with pytest.raises(
        PygnmiClientError,
        match=UNMAPPED_CN_ERROR,
    ):
        _get_capabilities(gnmi_tls)


CAPABILITIES_ROLE_CASES = [
    pytest.param(
        GENERIC_NOACCESS_ROLE,
        _get_capabilities,
        NO_ACCESS_ERROR.format(GENERIC_NOACCESS_ROLE),
        id="generic-noaccess-capabilities",
    ),
    pytest.param(
        GENERIC_READONLY_ROLE,
        _get_capabilities,
        None,
        id="generic-readonly-capabilities",
    ),
    pytest.param(
        GENERIC_READWRITE_ROLE,
        _get_capabilities,
        None,
        id="generic-readwrite-capabilities",
    ),
    pytest.param(
        "",
        _get_capabilities,
        None,
        id="empty-role-capabilities",
    ),
]

CONFIG_DB_ROLE_CASES = [
    pytest.param(
        CONFIG_DB_NOACCESS_ROLE,
        _get_configdb,
        NO_ACCESS_ERROR.format(CONFIG_DB_NOACCESS_ROLE),
        id="configdb-noaccess-get",
    ),
    pytest.param(
        CONFIG_DB_NOACCESS_ROLE,
        _set_configdb,
        NO_ACCESS_ERROR.format(CONFIG_DB_NOACCESS_ROLE),
        id="configdb-noaccess-set",
    ),
    pytest.param(
        CONFIG_DB_READONLY_ROLE,
        _get_configdb,
        None,
        id="configdb-readonly-get",
    ),
    pytest.param(
        CONFIG_DB_READONLY_ROLE,
        _set_configdb,
        NO_ACCESS_ERROR.format(CONFIG_DB_READONLY_ROLE),
        id="configdb-readonly-set",
    ),
    pytest.param(
        CONFIG_DB_READWRITE_ROLE,
        _get_configdb,
        None,
        id="configdb-readwrite-get",
    ),
    pytest.param(
        CONFIG_DB_READWRITE_ROLE,
        _set_configdb,
        None,
        id="configdb-readwrite-set",
    ),
    pytest.param(
        CONFIG_DB_NOACCESS_ROLE + "," + CONFIG_DB_READWRITE_ROLE,
        _set_configdb,
        NO_ACCESS_ERROR.format(CONFIG_DB_NOACCESS_ROLE),
        id="configdb-noaccess-readwrite-set",
    ),
    pytest.param(
        CONFIG_DB_READWRITE_ROLE + "," + CONFIG_DB_NOACCESS_ROLE,
        _set_configdb,
        NO_ACCESS_ERROR.format(CONFIG_DB_NOACCESS_ROLE),
        id="configdb-readwrite-noaccess-set",
    ),
    pytest.param(
        GENERIC_READWRITE_ROLE,
        _set_configdb,
        r"does not have write access, target gnmi_config_db\b",
        id="configdb-generic-readwrite-set-denied",
    ),
    pytest.param(
        "",
        _set_configdb,
        r"does not have write access, target gnmi_config_db\b",
        id="configdb-empty-role-set-denied",
    ),
]

UNMAPPED_CN_ROLE_CASES = [
    pytest.param(
        None,
        _get_capabilities,
        UNMAPPED_CN_ERROR,
        id="unmapped-capabilities",
    ),
]


@pytest.mark.parametrize(
    "role,operation,error_pattern",
    CAPABILITIES_ROLE_CASES + CONFIG_DB_ROLE_CASES + UNMAPPED_CN_ROLE_CASES,
)
def test_cn_role_access(gnmi_tls, role, operation, error_pattern):  # noqa: F811
    """Verify generic and target-specific role authorization."""
    duthost = gnmi_tls.duthost
    if operation is _set_configdb:
        redis_hset(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", cloudtype="Private")
        pytest_assert(
            redis_hget(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", "cloudtype") == "Private",
            "Failed to seed the Set authorization sentinel",
        )
    if role == "":
        original_role = redis_hget(duthost, CONFIG_DB, "GNMI_CLIENT_CERT|" + CLIENT_PRINCIPAL, "role@")
        pytest_assert(original_role, "Empty-role test requires a valid fixture role to restore")
    try:
        _set_client_cert_role(duthost, role)
        if error_pattern:
            error_type = PygnmiClientError if operation is _get_capabilities else grpc.RpcError
            with pytest.raises(error_type, match=error_pattern):
                operation(gnmi_tls)
        else:
            operation(gnmi_tls)
        if operation is _set_configdb:
            expected = "Private" if error_pattern else "Public"
            pytest_assert(
                redis_hget(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", "cloudtype") == expected,
                "CONFIG_DB state does not match the Set authorization outcome",
            )
    finally:
        if role == "":
            # GCU cannot parse an empty role list during checkpoint rollback.
            # Remove this intentionally invalid test state before gnmi_tls restores CONFIG_DB.
            _set_client_cert_role(duthost, original_role)
