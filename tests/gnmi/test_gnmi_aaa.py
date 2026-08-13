"""gNMI audit, authentication, and authorization tests."""

import logging
import os
import shlex
import uuid

import pytest

from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    _restart_gnoi_server,
    gnmi_tls,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.gnmi_audit import (
    RPC_COMPLETION_PREFIX,
    parse_audit_records,
    read_forwarded_payloads,
    wait_for_audit_record,
)
from tests.common.helpers.sonic_db import (
    CONFIG_DB,
    redis_del,
    redis_hdel,
    redis_hset,
    redis_keys,
)
from tests.common.helpers.syslog_helpers import (
    add_syslog_server,
    del_syslog_server,
)
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.pygnmi_client import PygnmiClientError
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("any"),
]
logger = logging.getLogger(__name__)
allure.logger = logger
CLIENT_PRINCIPAL = "test.client.gnmi.sonic"
READWRITE_CLIENT_PRINCIPAL = "test.client.readwrite.gnmi.sonic"
READONLY_ROLE = "gnmi_config_db_readonly"
READWRITE_ROLE = "gnmi_config_db_readwrite"


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


AUDIT_ACTIVITIES = [
    pytest.param(_get_countersdb, "/gnmi.gNMI/Get", id="get"),
    pytest.param(_set_configdb, "/gnmi.gNMI/Set", id="set"),
]


@pytest.fixture
def remote_syslog_capture(gnmi_tls, ptfhost):  # noqa: F811
    duthost = gnmi_tls.duthost
    ptf_ip = ptfhost.mgmt_ip
    capture_file = "/tmp/gnmi-audit-{}.pcap".format(uuid.uuid4().hex)
    capture_pool = None
    capture_result = None
    syslog_server_added = False

    try:
        logger.info("Adding temporary remote syslog server %s", ptf_ip)
        add_result = add_syslog_server(duthost, ptf_ip)
        pytest_assert(
            add_result["rc"] == 0,
            "Failed to add temporary syslog server",
        )
        syslog_server_added = True

        remote_action = 'Target="{}" Port="514"'.format(ptf_ip)

        def remote_action_configured():
            command = "grep -Fq {} /etc/rsyslog.conf".format(
                shlex.quote(remote_action)
            )
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
    offset = int(
        duthost.shell(
            "sudo stat -c %s /var/log/gnmi.log"
        )["stdout"].strip()
    )

    operation(gnmi_tls.pygnmi_client)
    wait_for_audit_record(duthost, offset, method, CLIENT_PRINCIPAL)


@pytest.mark.parametrize("operation,method", AUDIT_ACTIVITIES)
def test_gnmi_audit_log_remote_forwarding(
    gnmi_tls, remote_syslog_capture, operation, method  # noqa: F811
):
    duthost = gnmi_tls.duthost
    capture_result, capture_file = remote_syslog_capture
    offset = int(
        duthost.shell(
            "sudo stat -c %s /var/log/gnmi.log"
        )["stdout"].strip()
    )

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
    redis_hdel(duthost, CONFIG_DB, "GNMI|gnmi", "user_auth")
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


@pytest.mark.parametrize(
    "cn_roles,error_pattern",
    [
        pytest.param(
            {
                CLIENT_PRINCIPAL: READONLY_ROLE,
                READWRITE_CLIENT_PRINCIPAL: READWRITE_ROLE,
            },
            READONLY_ROLE,
            id="readonly",
        ),
        pytest.param(
            {READWRITE_CLIENT_PRINCIPAL: READWRITE_ROLE},
            "Unauthenticated|Invalid cert cname|not a trusted",
            id="unmapped",
        ),
    ],
)
def test_cn_insufficient_access(gnmi_tls, cn_roles, error_pattern):  # noqa: F811
    duthost = gnmi_tls.duthost
    redis_del(
        duthost,
        CONFIG_DB,
        *redis_keys(duthost, CONFIG_DB, "GNMI_CLIENT_CERT|*"),
    )
    for cname, role in cn_roles.items():
        redis_hset(
            duthost,
            CONFIG_DB,
            "GNMI_CLIENT_CERT|{}".format(cname),
            **{"role@": role}
        )

    with pytest.raises(
        PygnmiClientError,
        match=error_pattern,
    ):
        _set_configdb(gnmi_tls.pygnmi_client)


@pytest.mark.parametrize(
    "role,operation",
    [
        pytest.param(READONLY_ROLE, _get_configdb, id="readonly-get"),
        pytest.param(READWRITE_ROLE, _get_configdb, id="readwrite-get"),
        pytest.param(READWRITE_ROLE, _set_configdb, id="readwrite-set"),
    ],
)
def test_cn_allowed_access(gnmi_tls, role, operation):  # noqa: F811
    """Verify a mapped CN can perform the requested CONFIG_DB operation."""
    duthost = gnmi_tls.duthost
    redis_hset(
        duthost,
        CONFIG_DB,
        "GNMI_CLIENT_CERT|{}".format(CLIENT_PRINCIPAL),
        **{"role@": role}
    )

    operation(gnmi_tls.pygnmi_client)
