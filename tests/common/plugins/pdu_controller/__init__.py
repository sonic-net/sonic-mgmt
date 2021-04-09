import logging

import pytest
from pdu_manager import pdu_manager_factory


logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def pdu_controller(duthosts, enum_rand_one_per_hwsku_hostname, conn_graph_facts, pdu):
    """
    @summary: Fixture for controlling power supply to PSUs of DUT
    @param duthost: Fixture duthost defined in sonic-mgmt/tests/conftest.py
    @returns: Returns a pdu controller object implementing the BasePduController interface defined in
              controller_base.py.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    inv_mgr = duthost.host.options["inventory_manager"]
    pdu_host_list = inv_mgr.get_host(duthost.hostname).get_vars().get("pdu_host")
    pdu_hosts = {}
    for ph in pdu_host_list.split(','):
        var_list = inv_mgr.get_host(ph).get_vars()
        pdu_hosts[ph] = var_list

    controller = pdu_manager_factory(duthost.hostname, pdu_hosts, conn_graph_facts, pdu)

    yield controller

    logger.info("pdu_controller fixture teardown, ensure that all PDU outlets are turned on after test")
    if controller:
        controller.turn_on_outlet()
        controller.close()
