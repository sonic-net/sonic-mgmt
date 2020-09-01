import logging

import pytest

from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.utilities import wait_until
from tests.common.plugins.test_completeness import CompletenessLevel

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
            logging.debug("Interface status : {}".format(status))
        return status['oper_state'] == exp_state


    def __toggle_one_link(self, dut, dut_port, fanout, fanout_port):
        logging.info("Testing link flap on {}".format(dut_port))

        assert self.__check_if_status(dut, dut_port, 'up', verbose=True), "Fail: dut port {}: link operational down".format(dut_port)

        logging.info("Shutting down fanout switch {} port {} connecting to {}".format(fanout.hostname, fanout_port, dut_port))
        self.ports_shutdown_by_test.add((fanout, fanout_port))
        fanout.shutdown(fanout_port)
        wait_until(30, 1, self.__check_if_status, dut, dut_port, 'down')
        assert self.__check_if_status(dut, dut_port, 'down', verbose=True), "dut port {} didn't go down as expected".format(dut_port)

        logging.info("Bring up fanout switch {} port {} connecting to {}".format(fanout.hostname, fanout_port, dut_port))
        fanout.no_shutdown(fanout_port)
        wait_until(30, 1, self.__check_if_status, dut, dut_port, 'up')
        assert self.__check_if_status(dut, dut_port, 'up', verbose=True), "dut port {} didn't go down as expected".format(dut_port)
        self.ports_shutdown_by_test.discard((fanout, fanout_port))


    def __build_test_candidates(self, dut, fanouthosts):
        status = self.__get_dut_if_status(dut)
        candidates = []

        for dut_port in status.keys():
            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, dut_port)

            if not fanout or not fanout_port:
                logging.info("Skipping port {} that is not found in connection graph".format(dut_port))
            elif status[dut_port]['admin_state'] == 'down':
                logging.info("Skipping port {} that is admin down".format(dut_port))
            else:
                candidates.append((dut_port, fanout, fanout_port))
                if self.completeness_level == 'debug':
                    # Run the test for one port only - to just test if the test works fine
                    return candidates

        return candidates


    def run_link_flap_test(self, dut, fanouthosts):
        self.ports_shutdown_by_test = set()

        candidates = self.__build_test_candidates(dut, fanouthosts)
        if not candidates:
            pytest.skip("Didn't find any port that is admin up and present in the connection graph")

        try:
            for dut_port, fanout, fanout_port in candidates:
                self.__toggle_one_link(dut, dut_port, fanout, fanout_port)
        finally:
            logging.info("Restoring fanout switch ports that were shut down by test")
            for fanout, fanout_port in self.ports_shutdown_by_test:
                logging.debug("Restoring fanout switch {} port {} shut down by test".format(fanout.hostname, fanout_port))
                fanout.no_shutdown(fanout_port)

@pytest.mark.platform('physical')
def test_link_flap(request, duthost, fanouthosts):
    tlf = TestLinkFlap(request)
    tlf.run_link_flap_test(duthost, fanouthosts)
