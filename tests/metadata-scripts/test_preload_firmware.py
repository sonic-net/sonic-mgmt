"""Focused preload_firmware tests that do not install images or reboot."""

import hashlib
import json
import logging
import shlex
import uuid

import pytest
from upgrade_strategies import run_preload_firmware_script
from utilities import stage_metadata_scripts
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.disable_memory_utilization,
    pytest.mark.skip_check_dut_health
]
logger = logging.getLogger(__name__)


@pytest.fixture
def preload_ehf_payload_server(localhost, ptfhost, request):
    """Serve an EHF test payload from the PTF management interface."""
    if not request.config.getoption('metadata_process'):
        pytest.skip("This test requires --metadata_process")
    if request.config.getoption('upgrade_strategy') != 'script':
        pytest.skip("This test validates the script-based preload strategy")

    server_token = str(uuid.uuid4())
    server_root = "/tmp/preload-firmware-ehf-{}".format(server_token)
    payload_name = "preload-firmware-ehf-payload"
    payload_path = "{}/{}".format(server_root, payload_name)
    server_log = "{}.log".format(server_root)
    payload_content = "SONiC preload_firmware EHF checksum failure payload\n"
    server_pid = ""

    port_result = ptfhost.shell(
        "python3 -c \"import socket; s=socket.socket(); s.bind(('', 0)); "
        "print(s.getsockname()[1]); s.close()\""
    )
    server_port = int(port_result["stdout"].strip())

    try:
        ptfhost.file(path=server_root, state="directory")
        ptfhost.copy(content=payload_content, dest=payload_path)
        payload_md5 = hashlib.md5(
            payload_content.encode("utf-8")
        ).hexdigest()
        http_server_command = (
            "cd {root} && exec python3 -m http.server {port} --bind 0.0.0.0"
        ).format(
            root=shlex.quote(server_root),
            port=server_port
        )
        server_result = ptfhost.shell(
            "nohup sh -c {command} > {log} 2>&1 & echo $!".format(
                command=shlex.quote(http_server_command),
                log=shlex.quote(server_log)
            )
        )
        server_pid = server_result["stdout"].strip().splitlines()[-1]
        pytest_assert(
            server_pid.isdigit(),
            "Failed to start EHF payload server: {}".format(server_result)
        )
        localhost.wait_for(
            host=ptfhost.mgmt_ip,
            port=server_port,
            state="started",
            timeout=30
        )

        yield {
            "filename": payload_name,
            "md5": payload_md5,
            "url": "http://{}:{}/{}".format(
                ptfhost.mgmt_ip,
                server_port,
                payload_name
            )
        }
    finally:
        if server_pid.isdigit():
            ptfhost.shell(
                "kill {}".format(server_pid),
                module_ignore_errors=True
            )
        ptfhost.file(path=server_root, state="absent")
        ptfhost.file(path=server_log, state="absent")


def test_preload_firmware_ehf_checksum_failure(
        localhost, duthosts, rand_one_dut_hostname,
        preload_ehf_payload_server):
    """Test checksum failure leaves a non-retriable EHF report."""
    duthost = duthosts[rand_one_dut_hostname]
    event_guid = str(uuid.uuid4())
    payload_name = preload_ehf_payload_server["filename"]
    payload_url = preload_ehf_payload_server["url"]
    payload_path = "/tmp/{}".format(payload_name)
    report_path = (
        "/host/sonic-upgrade-reports/preload_firmware.{}.json".format(
            event_guid
        )
    )
    incorrect_md5 = "0" * 32
    cleanup_command = "sudo rm -f {payload} {report} {report_tmp}".format(
        payload=shlex.quote(payload_path),
        report=shlex.quote(report_path),
        report_tmp=shlex.quote(report_path + ".tmp")
    )

    try:
        duthost.shell(cleanup_command, module_ignore_errors=True)
        stage_metadata_scripts(duthost, localhost)
        result = run_preload_firmware_script(
            duthost,
            payload_url,
            payload_name,
            incorrect_md5,
            event_guid=event_guid,
            module_ignore_errors=True
        )
        pytest_assert(
            result["rc"] == 3,
            (
                "Expected preload_firmware checksum failure rc=3, got "
                "rc={}: stdout={!r}, stderr={!r}"
            ).format(
                result["rc"],
                result.get("stdout", ""),
                result.get("stderr", "")
            )
        )

        payload_stat = duthost.stat(path=payload_path)["stat"]
        pytest_assert(payload_stat["exists"] and payload_stat["size"] > 0,
                      "preload_firmware did not download the EHF test payload")
        downloaded_md5_result = duthost.command(
            "md5sum {}".format(shlex.quote(payload_path))
        )
        downloaded_md5 = downloaded_md5_result["stdout"].split()[0]
        pytest_assert(
            downloaded_md5 == preload_ehf_payload_server["md5"],
            "Downloaded EHF test payload does not match the PTF source"
        )

        report_result = duthost.command(
            "sudo cat {}".format(shlex.quote(report_path))
        )
        report = json.loads(report_result["stdout"])
        summary = report.get("sonic_upgrade_summary", {})
        actions = report.get("sonic_upgrade_actions", {})
        logger.info("Validated preload_firmware EHF report: %s",
                    json.dumps(report, sort_keys=True))

        pytest_assert(
            summary.get("script_name") == "preload_firmware",
            "EHF report has the wrong script_name: {}".format(summary)
        )
        pytest_assert(
            summary.get("guid") == event_guid,
            "EHF report GUID does not match: {}".format(summary)
        )
        pytest_assert(
            summary.get("fault_code") == "3",
            "EHF report has the wrong fault_code: {}".format(summary)
        )
        pytest_assert(
            actions.get("retriable") is False,
            "EHF checksum failure must be non-retriable: {}".format(actions)
        )
    finally:
        duthost.shell(cleanup_command, module_ignore_errors=True)
