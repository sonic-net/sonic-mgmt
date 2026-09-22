import time

import pytest

from tests.common.helpers.dut_utils import get_group_program_info
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.utilities import kill_process_by_pid, wait_until


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("mx"),
]

DHCP_SERVER_CONTAINER = "dhcp_server"
DHCP_SERVER_PROCESS_GROUP = "dhcp-server-ipv4"
PROCESS_ALERT_WAIT_SECONDS = 70


def _get_dhcp_server_processes(duthost):
    return get_group_program_info(
        duthost,
        DHCP_SERVER_CONTAINER,
        DHCP_SERVER_PROCESS_GROUP,
    )


def _dhcp_server_processes_running(duthost, expected_processes):
    process_info = _get_dhcp_server_processes(duthost)
    return all(
        process_info.get(process_name, [None])[0] == "RUNNING"
        for process_name in expected_processes
    )


def _caclmgrd_is_running(duthost):
    result = duthost.shell(
        "systemctl is-active caclmgrd",
        module_ignore_errors=True,
    )
    return result.get("stdout", "").strip() == "active"


def _start_dhcp_server_processes(duthost, process_names):
    for process_name in process_names:
        duthost.shell(
            "docker exec {} supervisorctl start {}:{}".format(
                DHCP_SERVER_CONTAINER,
                DHCP_SERVER_PROCESS_GROUP,
                process_name,
            ),
            module_ignore_errors=True,
        )

    pytest_assert(
        wait_until(
            120,
            5,
            0,
            _dhcp_server_processes_running,
            duthost,
            process_names,
        ),
        "dhcp_server critical processes did not recover",
    )


def _verify_dhcp_server_process_alerts(duthost, phase):
    process_info = _get_dhcp_server_processes(duthost)
    pytest_assert(
        process_info,
        "No processes found in dhcp_server Supervisor group '{}'".format(
            DHCP_SERVER_PROCESS_GROUP
        ),
    )
    process_names = sorted(process_info)
    pytest_assert(
        _dhcp_server_processes_running(duthost, process_names),
        "Not all dhcp_server critical processes are running before {}".format(phase),
    )

    loganalyzer = LogAnalyzer(
        ansible_host=duthost,
        marker_prefix="dhcp_server_process_alerts_{}".format(phase),
    )
    loganalyzer.expect_regex = [
        r".*Process '{}' is not running in namespace 'host'.*".format(
            process_name
        )
        for process_name in process_names
    ]
    marker = loganalyzer.init()

    try:
        for process_name in process_names:
            status, pid = process_info[process_name]
            pytest_assert(
                status == "RUNNING",
                "dhcp_server process '{}' is in state '{}'".format(
                    process_name, status
                ),
            )
            kill_process_by_pid(
                duthost,
                DHCP_SERVER_CONTAINER,
                "{}:{}".format(DHCP_SERVER_PROCESS_GROUP, process_name),
                pid,
            )

        time.sleep(PROCESS_ALERT_WAIT_SECONDS)
        loganalyzer.analyze(marker)
    finally:
        _start_dhcp_server_processes(duthost, process_names)


def test_dhcp_server_process_alerts_after_cacl_rebuild(duthost):
    feature_status, succeeded = duthost.get_feature_status()
    pytest_assert(succeeded, "Failed to read FEATURE status")
    if feature_status.get(DHCP_SERVER_CONTAINER) != "enabled":
        pytest.skip("dhcp_server feature is not enabled on this DUT")

    _verify_dhcp_server_process_alerts(duthost, "before_rebuild")

    duthost.command("sudo systemctl restart caclmgrd")
    pytest_assert(
        wait_until(60, 5, 0, _caclmgrd_is_running, duthost),
        "caclmgrd did not recover after restart",
    )

    _verify_dhcp_server_process_alerts(duthost, "after_rebuild")
