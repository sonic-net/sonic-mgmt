"""
Tests the link flap in SONiC.
"""

import pytest
import random

from tests.common.plugins.test_completeness import CompletenessLevel
from tests.platform_tests.link_flap.link_flap_utils import build_test_candidates, toggle_one_link

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.supported_completeness_level(CompletenessLevel.debug, CompletenessLevel.basic)
]


class TestLinkFlap(object):
    """
    TestLinkFlap class for link flap
    """
    def __init__(self, request):
        """
        Initialization of parameters for test

        Args:
            request: pytest request object
        """
        self.completeness_level = CompletenessLevel.get_normalized_level(request)

    def run_link_flap_test(self, dut, fanouthosts):
        """
        Test runner of link flap test.

        Args:
            dut: DUT host object
            fanouthosts: List of fanout switch instances.
        """
        candidates = build_test_candidates(dut, fanouthosts, self.completeness_level)

        if not candidates:
            pytest.skip("Didn't find any port that is admin up and present in the connection graph")

        for dut_port, fanout, fanout_port in candidates:
            toggle_one_link(dut, dut_port, fanout, fanout_port)


@pytest.mark.platform('physical')
def test_link_flap(request, duthost, fanouthosts, bring_up_fanout_interfaces):
    """
    Validates that link flap works as expected
    """
    tlf = TestLinkFlap(request)

    dutname, portname = decode_dut_port_name(all_ports)
    for dut in duthosts:
        if dutname == 'unknown' or dutname == dut.hostname:
            tlf.run_link_flap_test(dut, fanouthosts, portname)
