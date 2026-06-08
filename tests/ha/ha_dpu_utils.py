import logging
from tests.common.utilities import wait_until

# Mirror the timeouts used by the smartswitch reload test
# (tests/smartswitch/common/device_utils_dpu.py: DPU_MAX_ONLINE_TIMEOUT / DPU_TIME_INT).
CHECK_DPU_STATE_TIMEOUT = 360
CHECK_DPU_STATE_TIME_INT = 30

logger = logging.getLogger(__name__)



def dpu_power_on_for_index(duthost, dpu_index):    # noqa F811
    """
    Executes power on for a specific DPU
    """
    try:
        duthost.shell(f"sudo config chassis module startup DPU{dpu_index}")
    except Exception as e:
        logger.error(f"Error powering on dpu{dpu_index}: {e}")
        return False

    status = wait_until(CHECK_DPU_STATE_TIMEOUT, CHECK_DPU_STATE_TIME_INT, 0,
                        check_dpu_up_state, duthost, dpu_index)
    return status


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

    Mirrors check_dpu_module_status(..., "on", ...) from the smartswitch reload
    test (tests/smartswitch/common/device_utils_dpu.py): a DPU is UP when it is
    not "offline" in "show chassis module status".
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
    output_dpu_status = duthost.shell(
        'show chassis module status | grep %s' % (dpu_name), module_ignore_errors=True)
    stdout = output_dpu_status.get("stdout", "")

    if "offline" in stdout.lower():
        logger.info(f"'{dpu_name}' is offline on {duthost.hostname}")
        return power_status == "off"
    else:
        logger.info(f"'{dpu_name}' is online on {duthost.hostname}")
        return power_status == "on"
