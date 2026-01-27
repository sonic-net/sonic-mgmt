import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_container_running
from tests.common.platform.processes_utils import wait_critical_processes


# Import fixtures to ensure pytest discovers them
from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    setup_gnoi_tls_server, ptf_gnoi, ptf_grpc
)


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.usefixtures("setup_gnoi_tls_server")
]


def _kill_process(ptf_gnoi, name: str, restart: bool = False, signal: int = 1):
    """
    Invoke gNOI System.KillProcess via the underlying grpc client.
    Returns (ret, msg) to mirror the old gnoi_request helper behavior:
      ret == 0 => success, non-zero => failure
      msg      => stringified service message / error
    """
    request = {"name": name, "restart": restart, "signal": signal}
    try:
        # Use the low-level PtfGrpc client to call the gNOI RPC directly.
        resp = ptf_gnoi.grpc_client.call_unary("gnoi.system.System", "KillProcess", request)
        # Best-effort stringify for diagnostics
        return 0, (str(resp) if resp is not None else "")
    except Exception as e:
        # Normalize exception to (non-zero, message) like previous helper
        return 1, str(e)


# This test ensures functionality of KillProcess API to kill and restart a process when a valid process name is passed.
# When an invalid process name is passed, this test ensures that the expected error is returned.
@pytest.mark.parametrize("process,is_valid,expected_msg", [
    ("gnmi", False, "Dbus does not support gnmi service management"),
    ("nonexistent", False, "Dbus does not support nonexistent service management"),
    ("", False, "Dbus stop_service called with no service specified"),
    ("snmp", True, ""),
    ("dhcp_relay", True, ""),   # service names align with host services
    ("radv", True, ""),
    ("restapi", True, ""),
    ("lldp", True, ""),
    ("sshd", True, ""),
    ("swss", True, ""),
    ("pmon", True, ""),
    ("rsyslog", True, ""),
    ("telemetry", True, ""),
])
def test_gnoi_killprocess_then_restart(
    duthosts, rand_one_dut_hostname, ptf_gnoi, process, is_valid, expected_msg
):
    duthost = duthosts[rand_one_dut_hostname]

    if process and not duthost.is_host_service_running(process):
        pytest.skip(f"{process} is not running")

    # Kill attempt
    ret, msg = _kill_process(ptf_gnoi, name=process, restart=False, signal=1)

    if is_valid:
        pytest_assert(ret == 0, "KillProcess API unexpectedly reported failure")
        pytest_assert(
            not is_container_running(duthost, process),
            f"{process} found running after KillProcess reported success"
        )

        # Restart attempt
        ret, msg = _kill_process(ptf_gnoi, name=process, restart=True, signal=1)
        pytest_assert(
            ret == 0,
            f"KillProcess API unexpectedly reported failure when attempting to restart {process}"
        )
        pytest_assert(
            duthost.is_host_service_running(process),
            f"{process} not running after KillProcess reported successful restart"
        )
    else:
        pytest_assert(ret != 0, "KillProcess API unexpectedly succeeded with invalid request parameters")
        pytest_assert(
            expected_msg in msg,
            "Unexpected error message in response to invalid gNOI request"
        )

    # Post-conditions: DUT should return to healthy state
    wait_critical_processes(duthost)
    pytest_assert(duthost.critical_services_fully_started, "System unhealthy after gNOI API request")


# This test performs additional verification of the restart request under KillProcess API.
# It focuses on edge conditions of the restart value, so we only test against one service: snmp.
@pytest.mark.parametrize("request_restart_value,is_valid", [
    ("invalid", False),
    ("", False),
])
def test_gnoi_killprocess_restart(
    duthosts, rand_one_dut_hostname, ptf_gnoi, request_restart_value, is_valid
):
    duthost = duthosts[rand_one_dut_hostname]

    # Translate string inputs to Python types expected by client
    # invalid -> not a boolean; "" -> empty string, both should fail
    restart_arg = request_restart_value
    if request_restart_value == "":
        restart_arg = ""  # explicit empty string

    ret, msg = _kill_process(ptf_gnoi, name="snmp", restart=restart_arg, signal=1)

    if is_valid:
        pytest_assert(ret == 0, "KillProcess API unexpectedly reported failure")
        pytest_assert(
            is_container_running(duthost, "snmp"),
            "snmp not running after KillProcess API reported successful restart"
        )
    else:
        pytest_assert(ret != 0, "KillProcess API unexpectedly succeeded with invalid request parameters")
        pytest_assert(
            "panic" in msg,
            "Unexpected error message in response to invalid gNOI request"
        )

    wait_critical_processes(duthost)
    pytest_assert(duthost.critical_services_fully_started, "System unhealthy after gNOI API request")


def test_invalid_signal(duthosts, rand_one_dut_hostname, ptf_gnoi):
    duthost = duthosts[rand_one_dut_hostname]

    ret, msg = _kill_process(ptf_gnoi, name="snmp", restart=True, signal=2)
    pytest_assert(ret != 0, "KillProcess API unexpectedly succeeded with invalid request parameters")
    pytest_assert(
        "KillProcess only supports SIGNAL_TERM (option 1)" in msg,
        "Unexpected error message in response to invalid gNOI request"
    )

    wait_critical_processes(duthost)
    pytest_assert(duthost.critical_services_fully_started, "System unhealthy after gNOI API request")
