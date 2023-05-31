from tests.common.broadcom_data import is_broadcom_device
from tests.common.helpers.assertions import pytest_require
from tests.common.cisco_data import is_cisco_device


def skip_warm_reboot(duthost, reboot_type):
    """
    Skip warm/fast reboot tests for TD2 asics and Cisco devices

    Args:
        duthost (pytest fixture): device under test
        reboot_type (string): type of reboot (can be warm, cold, fast)

    Returns:
        None
    """
    SKIP_LIST = ["td2"]
    asic_type = duthost.get_asic_name()
    reboot_case_supported = True
    if (reboot_type == "warm" or reboot_type == "fast") and is_cisco_device(duthost):
        reboot_case_supported = False
    elif is_broadcom_device(duthost) and asic_type in SKIP_LIST and "warm" in reboot_type:
        reboot_case_supported = False
    pytest_require(reboot_case_supported, "Reboot type {} is not supported on {} switches".
                   format(reboot_type, duthost.facts['asic_type']))
