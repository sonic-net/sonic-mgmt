import logging

import pytest

from tests.common.fixtures.conn_graph_facts import get_graph_facts
from tests.common.utilities import get_host_visible_vars, get_sup_node_or_random_node
from tests.common.plugins.pdu_controller import get_pdu_visible_vars, resolve_env_variables
from tests.common.plugins.pdu_controller.pdu_manager import pdu_manager_factory
from .controller_base import PowerControllerBase
from .openbmc_controller import OpenBmcRedfishController
from .pdu_adapter import PduWholeDeviceAdapter

logger = logging.getLogger(__name__)


def _get_bmc_ip(bmc_links, hostname):
    """Return BMC IP from graph links, or fail if missing/ambiguous/empty."""
    if len(bmc_links) == 1:
        bmc_link = next(iter(bmc_links.values()))
    else:
        bmc_link = bmc_links.get("BMC")
        if bmc_link is None:
            pytest.fail(f"Ambiguous BMC links for {hostname}: {list(bmc_links.keys())}")

    bmc_ip = bmc_link.get("bmc_ip", "").split("/")[0]
    if not bmc_ip:
        pytest.fail(f"Empty bmc_ip for {hostname}")
    return bmc_ip


def _get_pdu_controller(duthost, conn_graph_facts):
    hostname = duthost.hostname
    device_pdu_links = conn_graph_facts.get("device_pdu_links", {})
    device_pdu_info = conn_graph_facts.get("device_pdu_info", {})

    pdu_links = device_pdu_links.get(hostname, {})
    if not pdu_links:
        return None

    pdu_info = device_pdu_info.get(hostname, {})
    pdu_vars = get_pdu_visible_vars(duthost.host.options["inventory_manager"]._sources, pdu_info.keys())
    pdu_manager = pdu_manager_factory(duthost.hostname, pdu_links, pdu_info, pdu_vars)
    if pdu_manager:
        return PduWholeDeviceAdapter(pdu_manager)
    return None


def _create_power_controller(duthost, conn_graph_facts):
    hostname = duthost.hostname

    pdu_controller = _get_pdu_controller(duthost, conn_graph_facts)
    if pdu_controller:
        return pdu_controller

    device_bmc_link = conn_graph_facts.get("device_bmc_link", {})
    bmc_links = device_bmc_link.get(hostname, {})
    if bmc_links:
        bmc_ip = _get_bmc_ip(bmc_links, hostname)

        inventories = duthost.host.options["inventory_manager"]._sources
        raw_vars = get_host_visible_vars(inventories, hostname)
        dut_vars = resolve_env_variables(raw_vars) if raw_vars else {}
        bmc_user = dut_vars.get("sonic_bmc_root_user")
        bmc_password = dut_vars.get("sonic_bmc_root_password")
        if not bmc_user or not bmc_password:
            pytest.fail(
                f"BMC credentials missing for {hostname}; set sonic_bmc_root_user/"
                f"sonic_bmc_root_password in ansible/group_vars/lab/secrets.yml"
            )
        logger.info("No PDU links for %s, BMC link found (ip=%s), using OpenBMC power control",
                    hostname, bmc_ip)
        return OpenBmcRedfishController(hostname, bmc_ip, bmc_user, bmc_password)

    return None


@pytest.fixture(scope="module")
def power_controller(duthosts, conn_graph_facts):
    """
    @summary: Fixture for whole-device power control of DUT
    @param duthosts: Fixture duthosts defined in sonic-mgmt/tests/conftest.py
    @param conn_graph_facts: Fixture that provides connection graph facts
    @returns: Returns a power controller object implementing the PowerControllerBase
              interface defined in controller_base.py, or None if no backend is configured.
    """
    duthost = get_sup_node_or_random_node(duthosts)
    controller = _create_power_controller(duthost, conn_graph_facts)
    yield controller

    logger.info("power_controller fixture teardown, ensure host power is restored after test")
    if controller:
        controller.power_on()
        controller.close()


@pytest.fixture(scope="module")
def get_power_controller(conn_graph_facts, localhost):
    """
    @summary: Fixture that returns a helper for acquiring per-DUT power controllers
    @param conn_graph_facts: Fixture that provides connection graph facts
    @param localhost: Fixture localhost used to reload graph facts on demand
    @returns: Returns a helper callable that maps a duthost to a PowerControllerBase
              implementation, or None if no backend is configured.
    """
    controller_map = {}

    def power_controller_helper(duthost):
        if duthost.hostname not in controller_map:
            # conn_graph_facts is scoped to the testbed duthosts. When asked for a host
            # that is not part of that set, its PDU/BMC wiring may be absent, so load
            # the graph facts for that host on demand instead of returning None.
            facts = conn_graph_facts
            hostname = duthost.hostname
            has_pdu = hostname in facts.get("device_pdu_links", {})
            has_bmc = hostname in facts.get("device_bmc_link", {})
            if not has_pdu and not has_bmc:
                facts = get_graph_facts(duthost, localhost, [hostname])
            controller_map[hostname] = _create_power_controller(duthost, facts)
        return controller_map[duthost.hostname]

    yield power_controller_helper

    for controller in list(controller_map.values()):
        if controller:
            controller.power_on()
            controller.close()


__all__ = [
    "PowerControllerBase",
    "OpenBmcRedfishController",
    "PduWholeDeviceAdapter",
    "_create_power_controller",
]
