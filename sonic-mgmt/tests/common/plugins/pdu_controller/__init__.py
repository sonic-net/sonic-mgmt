import logging

import pytest
from pdu_manager import pdu_manager_factory


logger = logging.getLogger(__name__)

def get_pdu_hosts(duthost):
    inv_mgr = duthost.host.options["inventory_manager"]
    pdu_host_list = inv_mgr.get_host(duthost.hostname).get_vars().get("pdu_host")
    pdu_hosts = {}
    if pdu_host_list:
        for ph in pdu_host_list.split(','):
            var_list = inv_mgr.get_host(ph).get_vars()
            pdu_hosts[ph] = var_list
    else:
        logging.debug("No 'pdu_host' is defined in inventory file for '%s'." %
                     duthost.hostname)

    return pdu_hosts


@pytest.fixture(scope="module")
def pdu_controller(duthosts, enum_rand_one_per_hwsku_hostname, conn_graph_facts, pdu):
    """
    @summary: Fixture for controlling power supply to PSUs of DUT
    @param duthost: Fixture duthost defined in sonic-mgmt/tests/conftest.py
    @returns: Returns a pdu controller object implementing the BasePduController interface defined in
              controller_base.py.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    pdu_hosts = get_pdu_hosts(duthost) 
    controller = pdu_manager_factory(duthost.hostname, pdu_hosts, conn_graph_facts, pdu)

    yield controller

    logger.info("pdu_controller fixture teardown, ensure that all PDU outlets are turned on after test")
    if controller:
        controller.turn_on_outlet()
        controller.close()

@pytest.fixture(scope="module")
def get_pdu_controller(conn_graph_facts, pdu):
    controller_map = {}

    def pdu_controller_helper(duthost):
        if duthost.hostname not in controller_map:
            pdu_hosts = get_pdu_hosts(duthost)
            controller = pdu_manager_factory(duthost.hostname, pdu_hosts, conn_graph_facts, pdu)
            controller_map[duthost.hostname] = controller

        return controller_map[duthost.hostname]

    yield pdu_controller_helper

    for controller in controller_map.values():
        controller.turn_on_outlet()
        controller.close()
