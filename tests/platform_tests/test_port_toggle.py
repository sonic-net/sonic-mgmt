"""
Tests the port toggle in SONiC.
"""

import pytest

from tests.common import port_toggle


pytestmark = [
    pytest.mark.topology("any")
]


class TestPortToggle(object):
    """
    TestPortToggle class for testing port toggle
    """

    def test_port_toggle(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, bring_up_dut_interfaces, tbinfo):
        """
        Validates that port toggle works as expected

        Test steps:
            1.) Flap all interfaces on DUT one by one.
            2.) Verify interfaces are up correctly.

        Pass Criteria: All interfaces are up correctly.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        port_toggle(duthost, tbinfo)
