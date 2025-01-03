import logging
import pytest

from tests.common.helpers.platform_api import module
from tests.smartswitch.common.reboot import perform_and_check_reboot, REBOOT_TYPE_COLD

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('smartswitch')
]


class TestRebootSmartSwitch(object):
    """
    Test class to test the reboot functionality of the SmartSwitch.
    """

    def test_reboot_dpus(self, duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn, num_dpu_modules):
        """
        Test to reboot all DPUs in the DUT.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        if not duthost.is_smartswitch():
            pytest.skip("Skipping the test as the DUT is not a SmartSwitch")

        for index in range(num_dpu_modules):
            dpu_name = module.get_name(platform_api_conn, index)
            perform_and_check_reboot(duthost, platform_api_conn, REBOOT_TYPE_COLD, index, dpu_name)
