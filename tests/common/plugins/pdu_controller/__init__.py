import logging

import pytest
from .pdu_manager import pdu_manager_factory
from tests.common.utilities import get_host_visible_vars, get_sup_node_or_random_node


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


def get_pdu_visible_vars(inventories, pdu_hostnames):
    pdu_hosts_vars = {}
    for pdu_hostname in pdu_hostnames:
        pdu_hosts_vars[pdu_hostname] = get_host_visible_vars(inventories, pdu_hostname)
    return pdu_hosts_vars


@pytest.fixture(scope="module")
def pdu_controller(duthosts, conn_graph_facts):
    """
    @summary: Fixture for controlling power supply to PSUs of DUT
    @param duthost: Fixture duthost defined in sonic-mgmt/tests/conftest.py
    @returns: Returns a pdu controller object implementing the BasePduController interface defined in
              controller_base.py.
    """
    duthost = get_sup_node_or_random_node(duthosts)
    pdu_hosts = get_pdu_hosts(duthost)
    pdu_hostnames = []
    if pdu_hosts:
        pdu_hostnames = pdu_hosts.keys()
    else:
        duthost_pdu_info = conn_graph_facts.get("device_pdu_info", {}).get(duthost.hostname, {})
        pdu_hostnames = [pdu["Hostname"] for pdu in duthost_pdu_info.values()]

    pdu_vars = get_pdu_visible_vars(duthost.host.options["inventory_manager"]._sources, pdu_hostnames)
    controller = pdu_manager_factory(duthost.hostname, pdu_hosts, conn_graph_facts, pdu_vars)

    yield controller

    logger.info("pdu_controller fixture teardown, ensure that all PDU outlets are turned on after test")
    if controller:
        controller.turn_on_outlet()
        controller.close()


@pytest.fixture(scope="module")
def get_pdu_controller(conn_graph_facts):
    controller_map = {}

    def pdu_controller_helper(duthost):
        if duthost.hostname not in controller_map:
            pdu_hosts = get_pdu_hosts(duthost)
            pdu_hostnames = []
            if pdu_hosts:
                pdu_hostnames = pdu_hosts.keys()
            else:

                duthost_pdu_info = conn_graph_facts.get("device_pdu_info", {}).get(duthost.hostname, {})
                pdu_hostnames = [pdu["Hostname"] for pdu in duthost_pdu_info.values()]
            pdu_vars = get_pdu_visible_vars(duthost.host.options["inventory_manager"]._sources, pdu_hostnames)
            controller = pdu_manager_factory(duthost.hostname, pdu_hosts, conn_graph_facts, pdu_vars)
            controller_map[duthost.hostname] = controller

        return controller_map[duthost.hostname]

    yield pdu_controller_helper

    for controller in list(controller_map.values()):
        if controller:
            controller.turn_on_outlet()
            controller.close()
