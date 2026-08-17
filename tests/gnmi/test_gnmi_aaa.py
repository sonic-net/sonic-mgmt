"""gNMI audit, authentication, and authorization tests."""

import logging
import os
import shlex
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
    read_forwarded_payloads,
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
    add_syslog_server,
    del_syslog_server,
    is_mgmt_vrf_enabled,
)
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
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

ROLE_ACCESS_CASES = [
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


@pytest.fixture
def remote_syslog_capture(gnmi_tls, ptfhost):  # noqa: F811
    duthost = gnmi_tls.duthost
    ptf_ip = ptfhost.mgmt_ip
    syslog_vrf = "mgmt" if is_mgmt_vrf_enabled(duthost) else None
    capture_file = "/tmp/gnmi-audit-{}.pcap".format(uuid.uuid4().hex)
    capture_pool = None
    capture_result = None
    syslog_server_added = False

    try:
        logger.info("Adding temporary remote syslog server %s", ptf_ip)
        add_result = add_syslog_server(duthost, ptf_ip, vrf=syslog_vrf)
        pytest_assert(
            add_result["rc"] == 0,
            "Failed to add temporary syslog server",
        )
        syslog_server_added = True

        remote_action = 'Target="{}" Port="514"'.format(ptf_ip)

        def remote_action_configured():
            command = "grep -F {} /etc/rsyslog.conf".format(
                shlex.quote(remote_action)
            )
            if syslog_vrf:
                command += " | grep -Fq {}".format(
                    shlex.quote('Device="{}"'.format(syslog_vrf))
                )
            else:
                command += " >/dev/null"
            return duthost.shell(
                command, module_ignore_errors=True
            )["rc"] == 0

        logger.info("Waiting for remote syslog configuration")
        pytest_assert(
            wait_until(30, 1, 0, remote_action_configured),
            "Host rsyslog did not configure UDP/514 forwarding",
        )

        logger.info("Starting remote syslog packet capture")
        capture_command = (
            "sudo timeout 30 tcpdump -i any -y LINUX_SLL -nn "
            "-s0 -U -w {} "
            "'udp and dst host {} and dst port 514'"
        ).format(shlex.quote(capture_file), ptf_ip)
        capture_pool, capture_result = duthost.shell(
            capture_command,
            module_async=True,
            module_ignore_errors=True,
        )

        def capture_started():
            command = "sudo test $(stat -c %s {}) -ge 24".format(
                shlex.quote(capture_file)
            )
            return duthost.shell(
                command, module_ignore_errors=True
            )["rc"] == 0

        logger.info("Waiting for remote syslog packet capture")
        pytest_assert(
            wait_until(10, 1, 0, capture_started),
            "UDP/514 packet capture did not start",
        )

        yield capture_result, capture_file
    finally:
        if capture_pool is not None:
            if capture_result.ready():
                capture_pool.close()
            else:
                capture_pool.terminate()
            capture_pool.join()
        duthost.shell(
            "sudo rm -f {}".format(shlex.quote(capture_file)),
            module_ignore_errors=True,
        )
        if os.path.exists(capture_file):
            os.remove(capture_file)
        if syslog_server_added:
            del_syslog_server(duthost, ptf_ip, module_ignore_errors=True)


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
    gnmi_tls, remote_syslog_capture, operation, method  # noqa: F811
):
    duthost = gnmi_tls.duthost
    capture_result, capture_file = remote_syslog_capture
    offset = get_audit_log_offset(duthost)

    with allure.step("Generate a {} audit record".format(method)):
        operation(gnmi_tls.pygnmi_client)

    with allure.step("Verify the remotely forwarded audit record"):
        local_records = wait_for_audit_record(
            duthost, offset, method, CLIENT_PRINCIPAL
        )
        forwarded_payloads = read_forwarded_payloads(
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


@pytest.mark.parametrize("role,operation,error_pattern", ROLE_ACCESS_CASES)
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
