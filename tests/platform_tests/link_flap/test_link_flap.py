"""
Tests the link flap in SONiC.
"""
import logging

import pytest
import random

from tests.common.plugins.test_completeness import CompletenessLevel
from tests.platform_tests.link_flap.link_flap_utils import build_test_candidates, toggle_one_link
from tests.common.helpers.dut_ports import decode_dut_port_name

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.supported_completeness_level(CompletenessLevel.debug, CompletenessLevel.basic)
]

LOOP_TIMES_LEVEL_MAP = {
    'debug': 1,
    'basic': 10,
    'confident': 50,
    'thorough': 100,
    'diagnose': 200
}

class TestLinkFlap(object):
    """
    TestLinkFlap class for link flap
    """
    def run_link_flap_test(self, normalized_level, dut, fanouthosts, port):
        """
        Test runner of link flap test.

        Args:
            dut: DUT host object
            fanouthosts: List of fanout switch instances.
        """
        completeness_level = normalized_level
        candidates = build_test_candidates(dut, fanouthosts, port, completeness_level)
        if candidates:
            for dut_port, fanout, fanout_port in candidates:
                toggle_one_link(dut, dut_port, fanout, fanout_port)


@pytest.mark.platform('physical')
def test_link_flap(duthosts, generate_port_lists, fanouthosts, get_function_conpleteness_level):
    """
    Validates that link flap works as expected
    """
    tlf = TestLinkFlap()

    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = "basic"

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    port_lists = generate_port_lists

    while loop_times > 0:
        loop_times -= 1

        for port in port_lists:
            dutname, portname = decode_dut_port_name(port)

            for dut in duthosts:
                if dutname == 'unknown' or dutname == dut.hostname:
                    tlf.run_link_flap_test(normalized_level, dut, fanouthosts, portname)
