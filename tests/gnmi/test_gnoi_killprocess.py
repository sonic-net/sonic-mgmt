import logging
import time

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

    # Kill the process without restart
    logger.info("gNOI KillProcess request: name=%r restart=False signal=%r", process, SIGNAL_TERM)
    try:
        resp = ptf_gnoi.kill_process(name=process, restart=False, signal=SIGNAL_TERM)
        logger.info("gNOI KillProcess response: %s", resp)
        ret = 0
        msg = str(resp) if resp is not None else ""
    except Exception as exc:
        logger.error("gNOI KillProcess error: %s", exc)
        ret = 1
        msg = str(exc)

    if is_valid:
        pytest_assert(
            ret == 0,
            f"KillProcess API unexpectedly reported failure: {msg}",
        )
        pytest_assert(
            not is_container_running(duthost, process),
            f"{process} found running after KillProcess reported success",
        )

        # Restart the process
        logger.info("gNOI KillProcess request: name=%r restart=True signal=%r", process, SIGNAL_TERM)
        try:
            resp = ptf_gnoi.kill_process(name=process, restart=True, signal=SIGNAL_TERM)
            logger.info("gNOI KillProcess response: %s", resp)
            ret = 0
            msg = str(resp) if resp is not None else ""
        except Exception as exc:
            logger.error("gNOI KillProcess error: %s", exc)
            ret = 1
            msg = str(exc)

        pytest_assert(
            ret == 0,
            (
                "KillProcess API unexpectedly reported failure when "
                f"attempting to restart {process}: {msg}"
            ),
        )
        pytest_assert(
            duthost.is_host_service_running(process),
            f"{process} not running after KillProcess reported successful restart",
        )
    else:
        pytest_assert(
            ret != 0,
            "KillProcess API unexpectedly succeeded with invalid request parameters",
        )
        pytest_assert(expected_msg in msg, f"Unexpected error message: {msg}")

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

    logger.info(
        "gNOI KillProcess request: name=%r restart=%r signal=%r",
        process,
        restart_value,
        SIGNAL_TERM,
    )
    try:
        resp = ptf_gnoi.kill_process(name=process, restart=restart_value, signal=SIGNAL_TERM)
        logger.info("gNOI KillProcess response: %s", resp)
        ret = 0
        msg = str(resp) if resp is not None else ""
    except Exception as exc:
        logger.error("gNOI KillProcess error: %s", exc)
        ret = 1
        msg = str(exc)

    pytest_assert(
        ret == 0,
        f"KillProcess API unexpectedly reported failure: {msg}",
    )

    # Check if service state matches expectations based on restart parameter
    is_running = is_container_running(duthost, process)
    pytest_assert(
        is_running == should_be_running_after,
        f"After KillProcess with restart={restart_value}: "
        f"expected running={should_be_running_after}, got running={is_running}",
    )

    # If service was stopped, restart it for cleanup
    if not should_be_running_after:
        logger.info("Restarting %s for cleanup", process)
        try:
            resp = ptf_gnoi.kill_process(name=process, restart=True, signal=SIGNAL_TERM)
            logger.info("gNOI KillProcess response: %s", resp)
            ret = 0
            msg = str(resp) if resp is not None else ""
        except Exception as exc:
            logger.error("gNOI KillProcess error: %s", exc)
            ret = 1
            msg = str(exc)

        pytest_assert(
            ret == 0,
            f"Failed to restart {process} for cleanup: {msg}",
        )

    wait_critical_processes(duthost)
    pytest_assert(
        duthost.critical_services_fully_started,
        "System unhealthy after gNOI API request",
    )


@pytest.mark.parametrize(
    "signal,expected_behavior",
    [
        (SIGNAL_TERM, "graceful_termination"),
        (SIGNAL_KILL, "immediate_termination"),
        (SIGNAL_HUP, "reload_configuration"),
        (SIGNAL_ABRT, "terminate_with_coredump"),
    ],
)
def test_gnoi_killprocess_signal_types(
    duthosts,
    rand_one_dut_hostname,
    ptf_gnoi,
    signal,
    expected_behavior,
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

    logger.info("gNOI KillProcess request: name=%r restart=%r signal=%r", process, restart, signal)
    try:
        resp = ptf_gnoi.kill_process(name=process, restart=restart, signal=signal)
        logger.info("gNOI KillProcess response: %s", resp)
        ret = 0
        msg = str(resp) if resp is not None else ""
    except Exception as exc:
        logger.error("gNOI KillProcess error: %s", exc)
        ret = 1
        msg = str(exc)

    # If signal is not implemented, it should return an error
    if ret != 0:
        logger.warning(
            f"Signal {signal} not supported. Error: {msg}. "
            "This is expected if full gNOI signal support is not yet implemented."
        )
        # Verify error message indicates unsupported signal
        pytest_assert(
            "only supports SIGNAL_TERM" in msg or "not supported" in msg.lower(),
            f"Unexpected error for unsupported signal {signal}: {msg}",
        )
    else:
        # Signal succeeded - verify service state
        logger.info(f"Signal {signal} succeeded with behavior: {expected_behavior}")

        if signal == SIGNAL_HUP:
            # HUP should reload config, service stays running
            pytest_assert(
                duthost.is_host_service_running(process),
                f"{process} not running after SIGNAL_HUP",
            )
        elif restart:
            # With restart=True, service should be running
            pytest_assert(
                duthost.is_host_service_running(process),
                f"{process} not running after {signal} with restart=True",
            )

    # Ensure service is running for next test
    if not duthost.is_host_service_running(process):
        logger.info("Restarting %s for cleanup", process)
        try:
            resp = ptf_gnoi.kill_process(name=process, restart=True, signal=SIGNAL_TERM)
            logger.info("gNOI KillProcess response: %s", resp)
            ret = 0
            msg = str(resp) if resp is not None else ""
        except Exception as exc:
            logger.error("gNOI KillProcess error: %s", exc)
            ret = 1
            msg = str(exc)

        pytest_assert(ret == 0, f"Failed to restart {process} for cleanup: {msg}")

    wait_critical_processes(duthost)
    pytest_assert(
        duthost.critical_services_fully_started,
        "System unhealthy after gNOI API request",
    )

    # Allow time for gNOI server to fully stabilize between signal tests
    time.sleep(3)


def test_invalid_signal(duthosts, rand_one_dut_hostname, ptf_gnoi):
    """
    Verify that invalid signal values are rejected.

    Tests SIGNAL_UNSPECIFIED (0) which is explicitly marked as invalid
    in the gNOI specification.
    """
    duthost = duthosts[rand_one_dut_hostname]

    logger.info("gNOI KillProcess request: name='snmp' restart=True signal='SIGNAL_UNSPECIFIED'")
    try:
        resp = ptf_gnoi.kill_process(name="snmp", restart=True, signal="SIGNAL_UNSPECIFIED")
        logger.info("gNOI KillProcess response: %s", resp)
        ret = 0
        msg = str(resp) if resp is not None else ""
    except Exception as exc:
        logger.error("gNOI KillProcess error: %s", exc)
        ret = 1
        msg = str(exc)

    pytest_assert(
        ret != 0,
        f"KillProcess API unexpectedly succeeded with SIGNAL_UNSPECIFIED: {msg}",
    )

    wait_critical_processes(duthost)
    pytest_assert(
        duthost.critical_services_fully_started,
        "System unhealthy after gNOI API request",
    )
