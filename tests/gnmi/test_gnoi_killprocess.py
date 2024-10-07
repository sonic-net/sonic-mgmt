import pytest
from .helper import gnoi_request
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_container_running


# This test ensures functionality of KillProcess API to kill and restart a process when a valid process name is passed
# When an invalid process name is passed, this test ensures that the expected error is returned
@pytest.mark.parametrize("process,is_valid, expected_msg", [
    ("gnmi", False, "Dbus does not support gnmi service management"),
    ("nonexistent", False, "Dbus does not support nonexistent service management"),
    ("", False, "Dbus stop_service called with no service specified"),
    ("snmp", True, ""),
    ("dhcp_relay", True, ""),
    ("radv", True, ""),
    ("restapi", True, ""),
    ("lldp", True, ""),
    ("sshd", True, ""),
    ("swss", True, ""),
    ("pmon", True, ""),
    ("rsyslog", True, ""),
    ("telemetry", True, "")
])
def test_gnoi_killprocess_then_restart(duthosts, rand_one_dut_hostname, localhost, process, is_valid, expected_msg):
    duthost = duthosts[rand_one_dut_hostname]

    if process and process != "nonexistent":
        pytest_assert(duthost.is_host_service_running(process),
                      "{} should be running before KillProcess test attempts to kill this process".format(process))

    request_kill_json_data = '{{"name": "{}", "signal": 1}}'.format(process)
    ret, msg = gnoi_request(duthost, localhost, "KillProcess", request_kill_json_data)
    if is_valid:
        pytest_assert(ret == 0, "KillProcess API unexpectedly reported failure")
        pytest_assert(not is_container_running(duthost, process),
                      "{} found running after KillProcess reported success".format(process))

        request_restart_json_data = '{{"name": "{}", "restart": true, "signal": 1}}'.format(process)
        ret, msg = gnoi_request(duthost, localhost, "KillProcess", request_restart_json_data)
        pytest_assert(ret == 0,
                      "KillProcess API unexpectedly reported failure when attempting to restart {}".format(process))
        pytest_assert(duthost.is_host_service_running(process),
                      "{} not running after KillProcess reported successful restart".format(process))
    else:
        pytest_assert(ret != 0, "KillProcess API unexpectedly succeeded with invalid request parameters")
        pytest_assert(expected_msg in msg, "Unexpected error message in response to invalid gNOI request")

    pytest_assert(duthost.critical_services_fully_started, "System unhealthy after gNOI API request")


# This test performs additional verification of the restart request under KillProcess API
# This test focuses on edge conditions of restart value in the request, so we only test against one service: snmp
@pytest.mark.parametrize("request_restart_value, is_valid", [
    ("invalid", False),
    ("", False)
])
def test_gnoi_killprocess_restart(duthosts, rand_one_dut_hostname, localhost, request_restart_value, is_valid):
    duthost = duthosts[rand_one_dut_hostname]
    request_json_data = f'{{"name": "snmp", "restart": {request_restart_value}, "signal": 1}}'
    ret, msg = gnoi_request(duthost, localhost, "KillProcess", request_json_data)
    if is_valid:
        pytest_assert(ret == 0, "KillProcess API unexpectedly reported failure")
        pytest_assert(is_container_running(duthost, "snmp"),
                      "snmp not running after KillProcess API reported successful restart")
    else:
        pytest_assert(ret != 0, "KillProcess API unexpectedly succeeded with invalid request parameters")
        pytest_assert("panic" in msg, "Unexpected error message in response to invalid gNOI request")
    pytest_assert(duthost.critical_services_fully_started, "System unhealthy after gNOI API request")


def test_invalid_signal(duthosts, rand_one_dut_hostname, localhost):
    duthost = duthosts[rand_one_dut_hostname]
    request_json_data = '{"name": "snmp", "restart": true, "signal": 2}'
    ret, msg = gnoi_request(duthost, localhost, "KillProcess", request_json_data)

    pytest_assert(ret != 0, "KillProcess API unexpectedly succeeded with invalid request parameters")
    pytest_assert("KillProcess only supports SIGNAL_TERM (option 1)" in msg,
                  "Unexpected error message in response to invalid gNOI request")
    pytest_assert(duthost.critical_services_fully_started, "System unhealthy after gNOI API request")
