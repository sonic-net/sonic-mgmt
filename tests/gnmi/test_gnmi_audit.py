"""gNMI audit tests."""

import json
import logging
import os
import shlex
import uuid
from contextlib import contextmanager

import pytest
from scapy.all import Raw, UDP, rdpcap

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.gu_utils import (
    create_checkpoint,
    delete_checkpoint,
    rollback,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.pygnmi_client import PygnmiClientError
from tests.common.utilities import wait_until
from tests.syslog.syslog_utils import add_syslog_server


pytestmark = [
    pytest.mark.topology("any"),
]
logger = logging.getLogger(__name__)
allure.logger = logger
RPC_COMPLETION_PREFIX = "RPC_COMPLETION "
CLIENT_PRINCIPAL = "test.client.gnmi.sonic"
INVALID_CN_CHECKPOINT = "invalid_cn_test"
REMOTE_SYSLOG_CHECKPOINT = "gnmi_audit_remote_syslog"


@contextmanager
def _config_db_checkpoint(duthost, checkpoint_name):
    create_checkpoint(duthost, checkpoint_name)
    try:
        yield
    finally:
        rollback_result = rollback(duthost, checkpoint_name)
        pytest_assert(
            rollback_result["rc"] == 0
            and "Config rolled back successfully"
            in rollback_result["stdout"],
            "Failed to restore CONFIG_DB checkpoint {}".format(
                checkpoint_name
            ),
        )
        delete_checkpoint(duthost, checkpoint_name)


def _clear_client_cn_mappings(duthost):
    result = duthost.shell(
        "sonic-db-cli CONFIG_DB keys 'GNMI_CLIENT_CERT|*'"
    )
    for key in result["stdout_lines"]:
        duthost.shell(
            "sonic-db-cli CONFIG_DB del {}".format(shlex.quote(key))
        )

    remaining = duthost.shell(
        "sonic-db-cli CONFIG_DB keys 'GNMI_CLIENT_CERT|*'"
    )["stdout_lines"]
    pytest_assert(
        not remaining,
        "Failed to clear GNMI client CN mappings: {}".format(remaining),
    )


def _get_completions(log_text):
    records = []
    decoder = json.JSONDecoder()
    for line in log_text.splitlines():
        _, separator, payload = line.partition(RPC_COMPLETION_PREFIX)
        if not separator:
            continue
        try:
            record, _ = decoder.raw_decode(payload)
        except json.JSONDecodeError:
            continue
        if (record.get("method") == "/gnmi.gNMI/Get"
                and record.get("path") == ["/COUNTERS_PORT_NAME_MAP"]
                and record.get("principal") == CLIENT_PRINCIPAL):
            records.append(record)
    return records


@pytest.fixture
def gnmi_tls_with_cn_enforcement(
    request,
    duthosts,
    rand_one_dut_hostname,
):
    duthost = duthosts[rand_one_dut_hostname]
    process = duthost.shell(
        "docker exec gnmi ps -eo args | grep '[t]elemetry'",
        module_ignore_errors=True,
    )
    original_cn_enforcement = (
        "--config_table_name GNMI_CLIENT_CERT" in process["stdout"]
    )
    if not original_cn_enforcement:
        pytest.xfail(
            "Original gNMI service does not enforce GNMI_CLIENT_CERT"
        )

    return request.getfixturevalue("gnmi_tls")


@pytest.fixture
def remote_syslog_capture(gnmi_tls, ptfhost):  # noqa: F811
    duthost = gnmi_tls.duthost
    ptf_ip = ptfhost.mgmt_ip
    capture_file = "/tmp/gnmi-audit-{}.pcap".format(uuid.uuid4().hex)
    capture_pool = None

    try:
        with _config_db_checkpoint(
            duthost,
            REMOTE_SYSLOG_CHECKPOINT,
        ):
            with allure.step("Add remote syslog configuration"):
                add_result = add_syslog_server(duthost, ptf_ip)
                pytest_assert(
                    add_result["rc"] == 0,
                    "Failed to add temporary syslog server",
                )

            remote_action = 'Target="{}" Port="514"'.format(ptf_ip)

            def remote_action_configured():
                command = "grep -Fq {} /etc/rsyslog.conf".format(
                    shlex.quote(remote_action)
                )
                return duthost.shell(
                    command, module_ignore_errors=True
                )["rc"] == 0

            with allure.step("Verify remote syslog configuration"):
                pytest_assert(
                    wait_until(30, 1, 0, remote_action_configured),
                    "Host rsyslog did not configure UDP/514 forwarding",
                )

            with allure.step("Start remote syslog packet capture"):
                capture_command = (
                    "sudo timeout 10 tcpdump -i any -y LINUX_SLL -nn "
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

            with allure.step("Verify remote syslog packet capture is ready"):
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


def test_gnmi_get_audit_log(gnmi_tls):  # noqa: F811
    duthost = gnmi_tls.duthost
    offset = int(
        duthost.shell(
            "sudo stat -c %s /var/log/gnmi.log"
        )["stdout"].strip()
    )

    gnmi_tls.pygnmi_client.get(
        "COUNTERS_PORT_NAME_MAP",
        target="COUNTERS_DB",
    )

    def audit_record_written():
        new_log = duthost.shell(
            "sudo tail -c +{} /var/log/gnmi.log".format(offset + 1),
            module_ignore_errors=True,
        )["stdout"]
        return bool(_get_completions(new_log))

    pytest_assert(
        wait_until(30, 1, 0, audit_record_written),
        "No new Get completion record in /var/log/gnmi.log",
    )
    new_log = duthost.shell(
        "sudo tail -c +{} /var/log/gnmi.log".format(offset + 1)
    )["stdout"]
    pytest_assert(
        len(_get_completions(new_log)) == 1,
        "Expected exactly one new Get completion record",
    )


def test_gnmi_invalid_cn_name(gnmi_tls_with_cn_enforcement):
    tls_fixture = gnmi_tls_with_cn_enforcement
    duthost = tls_fixture.duthost
    with _config_db_checkpoint(duthost, INVALID_CN_CHECKPOINT):
        _clear_client_cn_mappings(duthost)
        with pytest.raises(
            PygnmiClientError,
            match="Unauthenticated|unauthenticated|common name mapping",
        ):
            tls_fixture.pygnmi_client.get(
                "COUNTERS_PORT_NAME_MAP",
                target="COUNTERS_DB",
            )


def test_gnmi_get_audit_log_remote_forwarding(
    gnmi_tls, remote_syslog_capture  # noqa: F811
):
    duthost = gnmi_tls.duthost
    capture_result, capture_file = remote_syslog_capture

    with allure.step("Generate a gNMI audit record"):
        gnmi_tls.pygnmi_client.get(
            "COUNTERS_PORT_NAME_MAP",
            target="COUNTERS_DB",
        )

    with allure.step("Verify the remotely forwarded audit record"):
        pytest_assert(
            wait_until(15, 1, 0, capture_result.ready),
            "UDP/514 packet capture did not finish",
        )
        capture_status = capture_result.get()
        pcap_status = duthost.shell(
            "sudo test -s {}".format(shlex.quote(capture_file)),
            module_ignore_errors=True,
        )
        pytest_assert(
            pcap_status["rc"] == 0,
            "UDP/514 capture file is empty or missing: {}".format(
                capture_status
            ),
        )
        duthost.fetch(src=capture_file, dest="/tmp/", flat=True)
        packets = rdpcap(capture_file)
        matching_records = []
        for packet in packets:
            if UDP not in packet or Raw not in packet:
                continue
            payload = bytes(packet[Raw].load).decode(
                "utf-8", errors="replace"
            )
            matching_records.extend(_get_completions(payload))
        pytest_assert(
            len(matching_records) == 1,
            "Expected one forwarded UDP/514 Get audit record",
        )
