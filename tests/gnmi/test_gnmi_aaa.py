"""gNMI audit, authentication, and authorization tests."""

import base64
import hashlib
import json
import logging
import re
import time
import uuid

import pytest
from pygnmi.client import gNMIException

from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    _restart_gnoi_server,
    gnmi_tls,
)
from tests.common.helpers.assertions import pytest_assert
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
    redis_hgetall,
    redis_hset,
    redis_keys,
)
from tests.common.helpers.syslog_helpers import (
    capture_remote_syslog,
    is_mgmt_vrf_enabled,
    read_syslog_payloads,
)
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.ptf_grpc import PtfGrpcError
from tests.common.pygnmi_client import GetDataType, PygnmiClientError
from tests.common.utilities import wait_until


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
NO_ACCESS_ERROR = "does not have access|gnmi.*noaccess"
UNMAPPED_CN_ERROR = (
    "Unauthenticated|unauthenticated|Invalid cert cname|"
    "not a trusted|common name mapping"
)
GET_METHOD = "/gnmi.gNMI/Get"
SET_METHOD = "/gnmi.gNMI/Set"
RATE_LIMIT_BURST = 60
RATE_LIMIT_REFILL_SECONDS = 60
CONFIG_DB_GET_PATH = (
    "sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost"
)
CONFIG_DB_SET_PATH = "{}/cloudtype".format(CONFIG_DB_GET_PATH)
AUDIT_GET_PATH = "/CONFIG_DB/localhost/DEVICE_METADATA/localhost"
AUDIT_SET_PATH = "{}/cloudtype".format(AUDIT_GET_PATH)
BYPASS_HEADER = {"x-sonic-ss-bypass-validation": "true"}
BYPASS_SKUS = ("Cisco-8101", "Cisco-8102", "Cisco-8223")
FILE_CONTENT = b"sonic-mgmt write authorization sentinel\n"


def _set_configdb(client):
    client.set(
        update=[(
            "sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost/cloudtype",
            '"Public"',
        )],
    )


def _get_configdb(client):
    client.get(
        "sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost"
    )


def _get_countersdb(client):
    client.get(
        "COUNTERS_PORT_NAME_MAP",
        target="COUNTERS_DB",
    )


def _get_capabilities(client):
    result = client.capabilities()
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

    operation(gnmi_tls.pygnmi_client)
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
            "Get burst took {:.1f}s; requests crossed the 60s refill "
            "boundary".format(get_burst_seconds),
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
            with pytest.raises(
                gNMIException, match=CONFIG_DB_READONLY_ROLE
            ):
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
        "First refilled Get record did not report one suppressed request: {}"
        .format(get_records[-1]),
    )


@pytest.mark.parametrize("operation,method", AUDIT_ACTIVITIES)
def test_gnmi_audit_log_remote_forwarding(
    gnmi_tls, ptfhost, operation, method  # noqa: F811
):
    duthost = gnmi_tls.duthost
    syslog_vrf = "mgmt" if is_mgmt_vrf_enabled(duthost) else None

    with capture_remote_syslog(
        duthost, ptfhost.mgmt_ip, vrf=syslog_vrf
    ) as (capture_result, capture_file):
        offset = get_audit_log_offset(duthost)
        with allure.step("Generate a {} audit record".format(method)):
            operation(gnmi_tls.pygnmi_client)

        with allure.step("Verify the remotely forwarded audit record"):
            local_records = wait_for_audit_record(
                duthost, offset, method, CLIENT_PRINCIPAL
            )
            forwarded_payloads = read_syslog_payloads(
                duthost, capture_result, capture_file
            )
            pytest_assert(
                any(RPC_COMPLETION_PREFIX in payload
                    for payload in forwarded_payloads),
                "No RPC_COMPLETION marker found in forwarded UDP packets",
            )
            streamed_records = [
                record
                for payload in forwarded_payloads
                for record in parse_audit_records(
                    payload, method, CLIENT_PRINCIPAL
                )
            ]
            pytest_assert(
                streamed_records == local_records,
                "Streamed audit records differ from local gNMI records: "
                "local={}, streamed={}".format(
                    local_records,
                    streamed_records,
                ),
            )


@pytest.mark.parametrize("operation,method", AUDIT_ACTIVITIES)
def test_gnmi_default_cert_auth(gnmi_tls, operation, method):  # noqa: F811
    duthost = gnmi_tls.duthost
    delete_result = redis_hdel(
        duthost, CONFIG_DB, "GNMI|gnmi", "user_auth"
    )
    pytest_assert(
        delete_result["rc"] == 0
        and delete_result["stdout"].strip() == "1",
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
        match="Unauthenticated|unauthenticated|common name mapping",
    ):
        operation(gnmi_tls.pygnmi_client)


CAPABILITIES_ROLE_CASES = [
    pytest.param(
        GENERIC_NOACCESS_ROLE,
        _get_capabilities,
        NO_ACCESS_ERROR,
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
        NO_ACCESS_ERROR,
        id="configdb-noaccess-get",
    ),
    pytest.param(
        CONFIG_DB_NOACCESS_ROLE,
        _set_configdb,
        NO_ACCESS_ERROR,
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
        CONFIG_DB_READONLY_ROLE,
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
]

UNMAPPED_CN_ROLE_CASES = [
    pytest.param(
        None,
        _get_configdb,
        UNMAPPED_CN_ERROR,
        id="unmapped-get",
    ),
    pytest.param(
        None,
        _set_configdb,
        UNMAPPED_CN_ERROR,
        id="unmapped-set",
    ),
]


@pytest.mark.parametrize(
    "role,operation,error_pattern",
    CAPABILITIES_ROLE_CASES + CONFIG_DB_ROLE_CASES + UNMAPPED_CN_ROLE_CASES,
)
def test_cn_role_access(
    gnmi_tls, role, operation, error_pattern  # noqa: F811
):
    """Verify generic and target-specific role authorization."""
    duthost = gnmi_tls.duthost
    role_key = "GNMI_CLIENT_CERT|{}".format(CLIENT_PRINCIPAL)
    original_role = redis_hget(duthost, CONFIG_DB, role_key, "role@")
    pytest_assert(original_role, "Client certificate role is not configured")
    try:
        _set_client_cert_role(duthost, role)
        if error_pattern:
            with pytest.raises(PygnmiClientError, match=error_pattern):
                operation(gnmi_tls.pygnmi_client)
        else:
            operation(gnmi_tls.pygnmi_client)
    finally:
        _set_client_cert_role(duthost, original_role)


@pytest.fixture
def authorization_env(gnmi_tls):  # noqa: F811
    """Bound RPC deadlines and restore the certificate mapping after each case."""
    duthost = gnmi_tls.duthost
    role_key = "GNMI_CLIENT_CERT|{}".format(CLIENT_PRINCIPAL)
    original = redis_hgetall(duthost, CONFIG_DB, role_key)
    pytest_assert(original, "TLS fixture did not install a certificate mapping")
    gnmi_tls.grpc.configure_max_time(30)
    try:
        yield gnmi_tls
    finally:
        for result in redis_del(duthost, CONFIG_DB, role_key):
            pytest_assert(result["rc"] == 0, "Failed to remove test certificate role")
        result = redis_hset(duthost, CONFIG_DB, role_key, **original)
        pytest_assert(result["rc"] == 0, "Failed to restore certificate mapping")
        pytest_assert(redis_hgetall(duthost, CONFIG_DB, role_key) == original,
                      "Certificate mapping was not restored")


def _assert_denied(call, role):
    """Transport, request-validation and backend errors are not authz evidence."""
    with pytest.raises(PtfGrpcError) as caught:
        call()
    message = str(caught.value)
    if role is None:
        pytest_assert(re.search(r"Code:\s*Unauthenticated\b", message), message)
    else:
        # checkRoleAccess currently returns a plain Go error (gRPC Unknown).
        pytest_assert(re.search(r"Code:\s*(Unknown|PermissionDenied)\b", message), message)
        pytest_assert("does not have access" in message and role in message, message)


# Denied RPCs and the deliberately invalid writer probes log server errors.
@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize("identity", ["readonly", "unmapped", "readwrite"])
@pytest.mark.parametrize("rpc", ["TransferToRemote", "Put", "Remove", "Start", "Install"])
def test_gnoi_write_authorization(authorization_env, identity, rpc):
    """Regress sonic-gnmi PR 790: all five RPCs must reject non-writers.

    File.Put/Remove exercise temporary files. TransferToRemote and OS.Install
    use invalid requests to check authorization before request validation.
    FactoryReset uses the host service's unsupported zero-fill request; its
    writer control must return the explicit reset error, not perform a reset.
    """
    env = authorization_env
    duthost = env.duthost
    role = None if identity == "unmapped" else "gnoi_{}".format(identity)
    directory = duthost.tempfile(state="directory", path="/tmp", prefix="gnoi_authz_")["path"]
    path = directory + "/sentinel"
    try:
        duthost.copy(content=FILE_CONTENT.decode(), dest=path)
        before = duthost.stat(path=path, get_checksum=True)["stat"]
        _set_client_cert_role(duthost, role)

        def invoke():
            if rpc == "Put":
                return env.grpc.call_client_streaming("gnoi.file.File", rpc, [
                    {"open": {"remoteFile": path, "permissions": 420}},
                    {"contents": base64.b64encode(b"authorized replacement\n").decode()},
                    {"hash": {
                        "method": "MD5",
                        "hash": base64.b64encode(hashlib.md5(b"authorized replacement\n").digest()).decode(),
                    }},
                ])
            if rpc == "Install":
                # No TransferRequest: authenticated handler returns before any
                # backend call, image creation or installation is possible.
                return env.grpc.call_bidirectional_streaming("gnoi.os.OS", rpc, [{}])
            if rpc == "Start":
                return env.grpc.call_unary("gnoi.factory_reset.FactoryReset", rpc,
                                           {"factoryOs": True, "zeroFill": True})
            if rpc == "TransferToRemote":
                # Missing remote_download: no network transfer can occur even
                # on a vulnerable image that accepts the reader identity.
                return env.grpc.call_unary("gnoi.file.File", rpc, {"localPath": path})
            return env.grpc.call_unary("gnoi.file.File", rpc, {"remoteFile": path})

        if identity != "readwrite":
            _assert_denied(invoke, role)
        elif rpc in ("TransferToRemote", "Install"):
            detail = "remote_download cannot be nil" if rpc == "TransferToRemote" else "Expected TransferRequest"
            with pytest.raises(PtfGrpcError) as caught:
                invoke()
            message = str(caught.value)
            pytest_assert(re.search(r"Code:\s*InvalidArgument\b", message) and detail in message, message)
        elif rpc == "Start":
            response = invoke()
            detail = response.get("resetError", {}).get("detail", "")
            pytest_assert("zero_fill operation is currently unsupported" in detail, response)
        else:
            invoke()

        after = duthost.stat(path=path, get_checksum=True)["stat"]
        if identity == "readwrite" and rpc == "Remove":
            pytest_assert(not after["exists"], "Authorized Remove did not remove the sentinel")
        elif identity == "readwrite" and rpc == "Put":
            content = duthost.slurp(src=path)["content"]
            pytest_assert(base64.b64decode(content) == b"authorized replacement\n", "Put content mismatch")
        else:
            pytest_assert(after["exists"] and after["checksum"] == before["checksum"],
                          "RPC modified the sentinel unexpectedly")
        pytest_assert(not duthost.stat(path=path + ".tmp")["stat"]["exists"], "Put left a temporary file")
    finally:
        duthost.file(path=directory, state="absent")


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize("identity", ["readonly", "unmapped", "readwrite"])
@pytest.mark.parametrize("wire_form", ["prefix-target", "database-in-path"])
@pytest.mark.parametrize("operation", ["update", "replace", "delete"])
def test_native_set_bypass_authorization(authorization_env, identity, wire_form, operation):
    """Regress sonic-gnmi PR 791: bypass metadata must not grant write access.

    Requires a bypass-enabled SKU and checks the fast-path log in addition to
    CONFIG_DB state, so ordinary native Set success cannot mask a bypass skip.
    """
    env = authorization_env
    duthost = env.duthost
    hwsku = redis_hget(duthost, CONFIG_DB, "DEVICE_METADATA|localhost", "hwsku")
    if not hwsku.startswith(BYPASS_SKUS):
        pytest.skip("Native Set bypass requires Cisco-8101/8102/8223; DUT SKU is {}".format(hwsku))

    # PrefixListMgr ignores keys without a '|' separated prefix. This isolated
    # name exercises an allowed table without creating an FRR prefix-list or
    # changing a live route. The log assertion below proves bypass selection.
    name = "gnmi_authz_" + uuid.uuid4().hex[:12]
    key = "PREFIX_LIST|" + name
    original = {"action": "permit"}
    updated = {"action": "deny"}
    pytest_assert(not redis_hgetall(duthost, CONFIG_DB, key), "Test key already exists")
    prefix = {"origin": "sonic-db"}
    elements = ["PREFIX_LIST", name]
    if wire_form == "prefix-target":
        prefix["target"] = "CONFIG_DB"
    else:
        elements = ["CONFIG_DB", "localhost"] + elements
    path = {"elem": [{"name": element} for element in elements]}
    request = {"prefix": prefix}
    if operation == "delete":
        request[operation] = [path]
    else:
        value = json.dumps(updated).encode()
        request[operation] = [{"path": path, "val": {"jsonIetfVal": base64.b64encode(value).decode()}}]

    role = None if identity == "unmapped" else "gnmi_config_db_{}".format(identity)
    try:
        result = redis_hset(duthost, CONFIG_DB, key, **original)
        pytest_assert(result["rc"] == 0 and redis_hgetall(duthost, CONFIG_DB, key) == original,
                      "Failed to seed CONFIG_DB sentinel")
        # Prove this exact request reaches the bypass before testing a denied
        # identity, even when pytest selects only a single negative case.
        _set_client_cert_role(duthost, CONFIG_DB_READWRITE_ROLE)
        offset = get_audit_log_offset(duthost)

        def invoke():
            return env.grpc.call_unary("gnmi.gNMI", "Set", request, metadata=BYPASS_HEADER)

        response = invoke()
        pytest_assert(response.get("response"), "Set returned no operation results")
        expected = {} if operation == "delete" else updated
        pytest_assert(redis_hgetall(duthost, CONFIG_DB, key) == expected, "Authorized Set state mismatch")

        def bypass_logged():
            log = duthost.shell("sudo tail -c +{} /var/log/gnmi.log".format(offset + 1))["stdout"]
            return "Bypass fast path: direct ConfigDB operations" in log

        pytest_assert(wait_until(10, 1, 0, bypass_logged), "Set succeeded without exercising the bypass path")
        if identity != "readwrite":
            result = redis_hset(duthost, CONFIG_DB, key, **original)
            pytest_assert(result["rc"] == 0 and redis_hgetall(duthost, CONFIG_DB, key) == original,
                          "Failed to restore sentinel before denial check")
            _set_client_cert_role(duthost, role)
            _assert_denied(invoke, role)
            pytest_assert(redis_hgetall(duthost, CONFIG_DB, key) == original,
                          "Denied bypass Set changed CONFIG_DB")
    finally:
        result = redis_del(duthost, CONFIG_DB, key)[0]
        pytest_assert(result["rc"] == 0, "Failed to remove CONFIG_DB sentinel")
        pytest_assert(not redis_hgetall(duthost, CONFIG_DB, key), "CONFIG_DB sentinel still exists")
