import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_container_running
from tests.common.ptf_gnoi import SIGNAL_TERM
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


@pytest.mark.parametrize("restart", [True, False])
def test_gnoi_killprocess_restart(
    duthosts,
    rand_one_dut_hostname,
    ptf_gnoi,
    restart,
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

    ptf_gnoi.kill_process(name=process, restart=restart, signal=SIGNAL_TERM)

    # Check if service state matches expectations based on restart parameter
    is_running = is_container_running(duthost, process)
    pytest_assert(
        is_running == restart,  # Simplified: restart directly implies expected state
        f"After KillProcess with restart={restart}: "
        f"expected running={restart}, got running={is_running}",
    )

    # If service was stopped, restart it for cleanup
    if not restart:
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
