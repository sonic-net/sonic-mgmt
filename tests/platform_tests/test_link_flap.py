import logging

import pytest
import random

from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.utilities import wait_until
from tests.common.plugins.test_completeness import CompletenessLevel
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.dut_ports import decode_dut_port_name

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.supported_completeness_level(CompletenessLevel.debug, CompletenessLevel.basic)
]

class TestLinkFlap:
    def __init__(self, request):
        self.completeness_level = CompletenessLevel.get_normalized_level(request)
        
    def __get_dut_if_status(self, dut, ifname=None):
        if not ifname:
            status = dut.show_interface(command='status')['ansible_facts']['int_status']
        else:
            status = dut.show_interface(command='status', interfaces=[ifname])['ansible_facts']['int_status']

        return status


    def __check_if_status(self, dut, dut_port, exp_state, verbose=False):
        status = self.__get_dut_if_status(dut, dut_port)[dut_port]
        if verbose:
            logger.debug("Interface status : {}".format(status))
        return status['oper_state'] == exp_state


    def __toggle_one_link(self, dut, dut_port, fanout, fanout_port):
        logger.info("Testing link flap on {}".format(dut_port))

        assert self.__check_if_status(dut, dut_port, 'up', verbose=True), "Fail: dut port {}: link operational down".format(dut_port)

        logger.info("Shutting down fanout switch {} port {} connecting to {}".format(fanout.hostname, fanout_port, dut_port))
        self.ports_shutdown_by_test.add((fanout, fanout_port))
        fanout.shutdown(fanout_port)
        wait_until(30, 1, self.__check_if_status, dut, dut_port, 'down')
        assert self.__check_if_status(dut, dut_port, 'down', verbose=True), "dut port {} didn't go down as expected".format(dut_port)

        logger.info("Bring up fanout switch {} port {} connecting to {}".format(fanout.hostname, fanout_port, dut_port))
        fanout.no_shutdown(fanout_port)
        wait_until(30, 1, self.__check_if_status, dut, dut_port, 'up')
        assert self.__check_if_status(dut, dut_port, 'up', verbose=True), "dut port {} didn't go down as expected".format(dut_port)
        self.ports_shutdown_by_test.discard((fanout, fanout_port))


    def __build_candidate_list(self, candidates, fanout, fanout_port, dut_port, status):
        if not fanout or not fanout_port:
            logger.info("Skipping port {} that is not found in connection graph".format(dut_port))
        elif status[dut_port]['admin_state'] == 'down':
            logger.info("Skipping port {} that is admin down".format(dut_port))
        else:
            candidates.append((dut_port, fanout, fanout_port))


    def __build_test_candidates(self, dut, fanouthosts, port):
        candidates = []
        if port != 'unknown':
            status = self.__get_dut_if_status(dut, port)
            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, port)
            self.__build_candidate_list(candidates, fanout, fanout_port, port, status)
        else:
            # Build the full list
            logger.warning("Failed to get ports enumerated as parameter. Fall back to test all ports")
            status = self.__get_dut_if_status(dut)

            for dut_port in status.keys():
                fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, dut_port)
                self.__build_candidate_list(candidates, fanout, fanout_port, dut_port, status)

            if self.completeness_level == 'debug':
                candidates = random.sample(candidates, 1)

        return candidates


    def run_link_flap_test(self, dut, fanouthosts, port):
        self.ports_shutdown_by_test = set()

        candidates = self.__build_test_candidates(dut, fanouthosts, port)
        pytest_require(candidates, "Didn't find any port that is admin up and present in the connection graph")

        try:
            for dut_port, fanout, fanout_port in candidates:
                self.__toggle_one_link(dut, dut_port, fanout, fanout_port)
        finally:
            logger.info("Restoring fanout switch ports that were shut down by test")
            for fanout, fanout_port in self.ports_shutdown_by_test:
                logger.debug("Restoring fanout switch {} port {} shut down by test".format(fanout.hostname, fanout_port))
                fanout.no_shutdown(fanout_port)

@pytest.mark.platform('physical')
def test_link_flap(request, duthosts, all_ports, fanouthosts):
    tlf = TestLinkFlap(request)

    dutname, portname = decode_dut_port_name(all_ports)
    for dut in duthosts:
        if dutname == 'unknown' or dutname == dut.hostname:
            tlf.run_link_flap_test(dut, fanouthosts, portname)
