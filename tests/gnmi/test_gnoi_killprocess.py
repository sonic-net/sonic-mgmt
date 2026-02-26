import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_container_running
from tests.common.ptf_gnoi import SIGNAL_TERM, SIGNAL_KILL, SIGNAL_HUP, SIGNAL_ABRT
from tests.common.platform.processes_utils import wait_critical_processes

pytest_plugins = ["tests.common.fixtures.grpc_fixtures"]  # noqa: F401


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.usefixtures("setup_gnoi_tls_server"),
]


@pytest.mark.parametrize(
    "process,is_valid,expected_msg",
    [
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
        ("telemetry", True, ""),
    ],
)
def test_gnoi_killprocess_then_restart(
    duthosts,
    rand_one_dut_hostname,
    ptf_gnoi,
    process,
    is_valid,
    expected_msg,
):
    """
    Test gNOI KillProcess on various services.

    Verify that valid services can be stopped and restarted,
    and that invalid service names are rejected appropriately.
    """
    duthost = duthosts[rand_one_dut_hostname]

    if is_valid and process and not duthost.is_host_service_running(process):
        pytest.skip(f"{process} is not running")

    if is_valid:
        ptf_gnoi.kill_process(name=process, restart=False, signal=SIGNAL_TERM)
        pytest_assert(
            not is_container_running(duthost, process),
            f"{process} found running after KillProcess reported success",
        )

        ptf_gnoi.kill_process(name=process, restart=True, signal=SIGNAL_TERM)
        pytest_assert(
            duthost.is_host_service_running(process),
            f"{process} not running after KillProcess reported successful restart",
        )
    else:
        with pytest.raises(Exception, match=expected_msg):
            ptf_gnoi.kill_process(name=process, restart=False, signal=SIGNAL_TERM)

    wait_critical_processes(duthost)
    pytest_assert(
        duthost.critical_services_fully_started,
        "System unhealthy after gNOI API request",
    )


@pytest.mark.parametrize(
    "restart_value,should_be_running_after",
    [
        (True, True),
        (False, False),
    ],
)
def test_gnoi_killprocess_restart(
    duthosts,
    rand_one_dut_hostname,
    ptf_gnoi,
    restart_value,
    should_be_running_after,
):
    """
    Verify the restart parameter behavior in KillProcess API.

    Tests that restart=True brings the service back up, and restart=False
    leaves it down.
    """
    duthost = duthosts[rand_one_dut_hostname]
    process = "snmp"

    if not duthost.is_host_service_running(process):
        pytest.skip(f"{process} is not running")

    ptf_gnoi.kill_process(name=process, restart=restart_value, signal=SIGNAL_TERM)

    # Check if service state matches expectations based on restart parameter
    is_running = is_container_running(duthost, process)
    pytest_assert(
        is_running == should_be_running_after,
        f"After KillProcess with restart={restart_value}: "
        f"expected running={should_be_running_after}, got running={is_running}",
    )

    # If service was stopped, restart it for cleanup
    if not should_be_running_after:
        ptf_gnoi.kill_process(name=process, restart=True, signal=SIGNAL_TERM)

    wait_critical_processes(duthost)
    pytest_assert(
        duthost.critical_services_fully_started,
        "System unhealthy after gNOI API request",
    )


@pytest.mark.parametrize(
    "signal",
    [
        SIGNAL_TERM,
        SIGNAL_KILL,
        SIGNAL_HUP,
        SIGNAL_ABRT,
    ],
)
def test_gnoi_killprocess_signal_types(
    duthosts,
    rand_one_dut_hostname,
    ptf_gnoi,
    signal,
):
    """
    Test all 4 signal types defined in gNOI specification.

    Per gNOI system.proto:
    - SIGNAL_TERM (1): Terminate the process gracefully
    - SIGNAL_KILL (2): Terminate the process immediately
    - SIGNAL_HUP (3): Reload the process configuration
    - SIGNAL_ABRT (4): Terminate immediately and dump core file

    Note: Current SONiC implementation may only support SIGNAL_TERM.
          This test documents the expected behavior for full gNOI compliance.
    """
    duthost = duthosts[rand_one_dut_hostname]
    process = "snmp"

    if not duthost.is_host_service_running(process):
        pytest.skip(f"{process} is not running")

    # For SIGNAL_HUP, restart parameter is ignored per spec
    restart = False if signal == SIGNAL_HUP else True

    if signal == SIGNAL_TERM:
        # SIGNAL_TERM is supported - should succeed
        ptf_gnoi.kill_process(name=process, restart=restart, signal=signal)

        if restart:
            # With restart=True, service should be running
            pytest_assert(
                duthost.is_host_service_running(process),
                f"{process} not running after {signal} with restart=True",
            )
    else:
        # Other signals are not yet supported - should fail
        with pytest.raises(Exception, match="only supports SIGNAL_TERM"):
            ptf_gnoi.kill_process(name=process, restart=restart, signal=signal)

    # Ensure service is running for next test
    if not duthost.is_host_service_running(process):
        ptf_gnoi.kill_process(name=process, restart=True, signal=SIGNAL_TERM)

    wait_critical_processes(duthost)
    pytest_assert(
        duthost.critical_services_fully_started,
        "System unhealthy after gNOI API request",
    )


def test_invalid_signal(duthosts, rand_one_dut_hostname, ptf_gnoi):
    """
    Verify that invalid signal values are rejected.

    Tests SIGNAL_UNSPECIFIED (0) which is explicitly marked as invalid
    in the gNOI specification.
    """
    duthost = duthosts[rand_one_dut_hostname]

    with pytest.raises(Exception):
        ptf_gnoi.kill_process(name="snmp", restart=True, signal="SIGNAL_UNSPECIFIED")

    wait_critical_processes(duthost)
    pytest_assert(
        duthost.critical_services_fully_started,
        "System unhealthy after gNOI API request",
    )
