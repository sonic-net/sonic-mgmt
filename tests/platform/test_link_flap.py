import logging

import pytest

from common.platform.device_utils import fanout_switch_port_lookup
from common.utilities import wait_until

class TestLinkFlap:
    def __init__(self):
        self.ports_shutdown_by_test = set()


    def __get_dut_if_facts(self, dut):
        interface_facts = dut.interface_facts()
        ansible_facts   = interface_facts['ansible_facts']
        if_facts        = ansible_facts['ansible_interface_facts']

        return if_facts


    def __check_if_status(self, dut, dut_port, exp_state):
        ifstate = self.__get_dut_if_facts(dut)[dut_port]
        return ifstate['active'] == exp_state


    def __toggle_one_link(self, dut, dut_port, fanout, fanout_port):
        logging.info("Testing link flap on {}".format(dut_port))

        ifstate = self.__get_dut_if_facts(dut)[dut_port]
        assert ifstate['active'], "dut port {} is down".format(dut_port)

        logging.debug("Shutting down fanout switch {} port {} connecting to {}".format(fanout.hostname, fanout_port, dut_port))
        self.ports_shutdown_by_test.add((fanout, fanout_port))
        fanout.shutdown(fanout_port)
        wait_until(30, 0.2, self.__check_if_status, dut, dut_port, False)
        ifstate = self.__get_dut_if_facts(dut)[dut_port]
        logging.debug("Interface fact  : {}".format(ifstate))
        assert not ifstate['active'], "dut port {} didn't go down as expected".format(dut_port)

        logging.debug("Bring up fanout switch {} port {} connecting to {}".format(fanout.hostname, fanout_port, dut_port))
        fanout.no_shutdown(fanout_port)
        wait_until(30, 0.2, self.__check_if_status, dut, dut_port, True)
        ifstate = self.__get_dut_if_facts(dut)[dut_port]
        logging.debug("Interface fact  : {}".format(ifstate))
        assert ifstate['active'], "dut port {} didn't come up as expected".format(dut_port)
        self.ports_shutdown_by_test.discard((fanout, fanout_port))


    def __build_test_candidates(self, dut, fanouthosts):
        if_facts = self.__get_dut_if_facts(dut)
        candidates = []
        for dut_port in if_facts.keys():
            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, dut_port)

            if not fanout or not fanout_port:
                logging.info("Skipping port {} that is not found in connection graph".format(dut_port))
            else:
                candidates.append((dut_port, fanout, fanout_port))

        return candidates


    def run_link_flap_test(self, dut, fanouthosts):
        candidates = self.__build_test_candidates(dut, fanouthosts)

        try:
            for dut_port, fanout, fanout_port in candidates:
                self.__toggle_one_link(dut, dut_port, fanout, fanout_port)
        finally:
            logging.info("Restoring fanout switch ports that were shut down by test")
            for fanout, fanout_port in self.ports_shutdown_by_test:
                logging.debug("Restoring fanout switch {} port {} shut down by test".format(fanout.hostname, fanout_port))
                fanout.no_shutdown(fanout_port)


@pytest.mark.topology_agnostic
@pytest.mark.platform_physical
def test_link_flap(duthost, fanouthosts):
    tlf = TestLinkFlap()
    tlf.run_link_flap_test(duthost, fanouthosts)
