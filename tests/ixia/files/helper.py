from tests.common.broadcom_data import is_broadcom_device
from tests.common.nexthop_data import NexthopPlatform
from tests.common.helpers.assertions import pytest_require


def skip_warm_reboot(duthost, reboot_type):
    """
    Skip warm reboot tests for TD2 asics

    Args:
        duthost (pytest fixture): device under test
        reboot_type (string): type of reboot (can be warm, cold, fast)

    Returns:
        None
    """
    SKIP_LIST = ["td2"]
    asic_type = duthost.get_asic_name()
    skip_reboot = (is_broadcom_device(duthost) and asic_type in SKIP_LIST and "warm" in reboot_type) or \
                  (reboot_type in ("warm", "fast") and
                   not NexthopPlatform(duthost).supports("{}_reboot".format(reboot_type)))
    pytest_require(not skip_reboot,
                   "{} reboot is not supported on {}".format(reboot_type, asic_type))
