import logging
from tests.common.utilities import wait_until

CHECK_DPU_STATE_TIMEOUT = 180
CHECK_DPU_STATE_TIME_INT = 60

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


def check_dpu_up_state(duthost,  dpu_index):
    """
    Args:
        duthost : Host handle
        dpu_index: Index of the DPU
    Returns:
        Returns True or False based on DPU state up or not
    """
    dpu_name = f"DPU{dpu_index}"
    output_dpu_health_status = duthost.show_and_parse(f"show system-health dpu {dpu_name}")
    if len(output_dpu_health_status) == 0:
        logger.warning(f"empty return for show dpu on {duthost.hostname}")
        return False
    for status in output_dpu_health_status:
        if status['name'] == dpu_name:
            if status['state-detail'] == "dpu_midplane_link_state":
                if 'up' not in status['state-value'].lower():
                    return False
            if status['state-detail'] == "dpu_control_plane_state":
                if 'up' not in status['state-value'].lower():
                    return False
            if status['state-detail'] == "dpu_data_plane_state":
                if 'up' not in status['state-value'].lower():
                    return False
            return True
    return False


def check_dpu_down_state(duthost, dpu_index):
    """
    Checks if DPU is down
    Args:
        duthost : Host handle
        dpu_index: Index of the DPU
    Returns:
        Returns True or False if DPU is down or not
    """
    dpu_name = f"DPU{dpu_index}"
    output_dpu_health_status = duthost.show_and_parse(f"show system-health dpu {dpu_name}")
    if len(output_dpu_health_status) == 0:
        logger.warning(f"empty return for show dpu on {duthost.hostname}")
        return False

    for status in output_dpu_health_status:
        if status['name'] == dpu_name:
            if status['state-detail'] == "dpu_midplane_link_state":
                if 'up' in status['state-value'].lower():
                    return False
            if status['state-detail'] == "dpu_control_plane_state":
                if 'up' in status['state-value'].lower():
                    return False
            if status['state-detail'] == "dpu_data_plane_state":
                if 'up' in status['state-value'].lower():
                    return False
            return True
    return False
