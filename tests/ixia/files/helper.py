from tests.common.broadcom_data import is_broadcom_device
from tests.common.helpers.assertions import pytest_require

def skip_warm_reboot_td2(duthost, reboot_type):
    """
    Skip warm reboot tests for TD2 asics

    Args:
        duthost (pytest fixture): device under test
        reboot_type (string): type of reboot (can be warm, cold, fast)

    Returns:
        None
    """
    asic_type = duthost.get_asic_name()
    pytest_require(not (is_broadcom_device(duthost) and "td2" in asic_type and "warm" in reboot_type), "Warm reboot is not supported on Td2")
