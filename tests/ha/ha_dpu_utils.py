import logging
from tests.common.utilities import wait_until

# Mirror the timeouts used by the smartswitch reload test
# (tests/smartswitch/common/device_utils_dpu.py: DPU_MAX_ONLINE_TIMEOUT / DPU_TIME_INT).
CHECK_DPU_STATE_TIMEOUT = 360
CHECK_DPU_STATE_TIME_INT = 30
DPU_STARTUP_ATTEMPTS = 2

logger = logging.getLogger(__name__)



def dpu_power_on_for_index(duthost, dpu_index):    # noqa F811
    """
    Executes power on for a specific DPU
    """
    for attempt in range(1, DPU_STARTUP_ATTEMPTS + 1):
        startup_accepted = wait_until(
            CHECK_DPU_STATE_TIMEOUT, CHECK_DPU_STATE_TIME_INT, 0,
            _startup_dpu_when_transition_settled, duthost, dpu_index
        )
        if not startup_accepted:
            return False

        if wait_until(CHECK_DPU_STATE_TIMEOUT, CHECK_DPU_STATE_TIME_INT, 0,
                      check_dpu_up_state, duthost, dpu_index):
            return True

        logger.warning(
            "DPU%d did not become Online/up after startup attempt %d on %s",
            dpu_index, attempt, duthost.hostname
        )

    return False


def _startup_dpu_when_transition_settled(duthost, dpu_index):
    """Request startup after any prior chassis state transition has settled."""
    if check_dpu_up_state(duthost, dpu_index):
        return True

    result = duthost.shell(
        f"sudo config chassis module startup DPU{dpu_index}",
        module_ignore_errors=True
    )
    output = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
    if "state transition is already in progress" in output.lower():
        logger.info(
            "DPU%d startup is blocked by a state transition on %s",
            dpu_index, duthost.hostname
        )
        return False
    if result.get("rc", 1) != 0:
        logger.error(
            "Failed to request startup for DPU%d on %s: %s",
            dpu_index, duthost.hostname, output.strip()
        )
        return False
    return True


def dpu_power_off_for_index(duthost, dpu_index):    # noqa F811
    """
    Executes power off a specific DPU
    """
    try:
        duthost.shell(f"sudo config chassis module shutdown DPU{dpu_index}")
    except Exception as e:
        logger.error(f"Error powering off dpu{dpu_index}: {e}")
        return False

    status = wait_until(CHECK_DPU_STATE_TIMEOUT, CHECK_DPU_STATE_TIME_INT, 0,
                        check_dpu_down_state, duthost, dpu_index)
    return status


def check_dpu_up_state(duthost, dpu_index):
    """
    Checks if DPU is up.

    A DPU is UP when chassis status reports Online/up.
    Args:
        duthost : Host handle
        dpu_index: Index of the DPU
    Returns:
        Returns True or False based on DPU state up or not
    """
    return check_dpu_module_status(duthost, "on", f"DPU{dpu_index}")


def check_dpu_down_state(duthost, dpu_index):
    """
    Checks if DPU is down.

    Mirrors check_dpu_module_status(..., "off", ...) from the smartswitch reload
    test (tests/smartswitch/common/device_utils_dpu.py): a DPU is DOWN when it is
    "offline" in "show chassis module status".
    Args:
        duthost : Host handle
        dpu_index: Index of the DPU
    Returns:
        Returns True or False if DPU is down or not
    """
    return check_dpu_module_status(duthost, "off", f"DPU{dpu_index}")


def check_dpu_module_status(duthost, power_status, dpu_name):
    """
    Check status of a given DPU module against the expected on/off state.

    Reference: tests/smartswitch/common/device_utils_dpu.py::check_dpu_module_status
    which is what test_reload_dpu.py polls via wait_until to confirm a DPU has
    powered on/off.
    Args:
        duthost : Host handle
        power_status: expected status, "on" or "off"
        dpu_name: name of the DPU module (e.g. "DPU0")
    Returns:
        Returns True or False based on status of the given DPU module
    """
    entries = duthost.show_and_parse("show chassis module status")
    entry = next(
        (item for item in entries if item.get("name") == dpu_name),
        None
    )
    if entry is None:
        logger.warning("'%s' is missing from chassis module status on %s",
                       dpu_name, duthost.hostname)
        return False

    oper_status = entry.get("oper-status", "").lower()
    admin_status = entry.get("admin-status", "").lower()
    logger.info("'%s' is oper=%s admin=%s on %s",
                dpu_name, oper_status, admin_status, duthost.hostname)
    if power_status == "off":
        return oper_status == "offline"
    return oper_status == "online" and admin_status == "up"
