import logging
import os
import re

import pytest
from .pdu_manager import pdu_manager_factory
from tests.common.utilities import get_host_visible_vars, get_sup_node_or_random_node


logger = logging.getLogger(__name__)


def resolve_env_variables(data):
    """
    Resolve environment variable lookups in data.

    This function processes data (dict, string, or other types) and replaces
    any patterns like '{{ lookup('env','VARIABLE_NAME') }}' with the actual
    environment variable values.

    Args:
        data: The data to process (can be dict, string, list, or other types)

    Returns:
        The processed data with environment variables resolved
    """
    if isinstance(data, dict):
        return {key: resolve_env_variables(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [resolve_env_variables(item) for item in data]
    elif isinstance(data, str):
        # Pattern to match {{ lookup('env','VARIABLE_NAME') }}
        pattern = r'\{\{\s*lookup\s*\(\s*[\'"]env[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)\s*\}\}'

        def replace_env_var(match):
            env_var_name = match.group(1)
            env_value = os.getenv(env_var_name)
            if env_value is None:
                logger.warning(f"Environment variable '{env_var_name}' not found, keeping original value")
                return match.group(0)  # Return original if env var not found
            return env_value

        return re.sub(pattern, replace_env_var, data)
    else:
        # For other types (int, bool, etc.), return as-is
        return data


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
        raw_vars = get_host_visible_vars(inventories, pdu_hostname)
        if raw_vars:
            # Resolve environment variables in the PDU variables
            pdu_hosts_vars[pdu_hostname] = resolve_env_variables(raw_vars)
        else:
            pdu_hosts_vars[pdu_hostname] = raw_vars
    return pdu_hosts_vars


def _get_pdu_controller(duthost, conn_graph_facts):
    hostname = duthost.hostname
    # To adapt to the kvm testbed, conn_graph_facts is None for kvm.
    # Unfortunately, for most DUTs
    # we will get None because there is no key pdu_host under most of the hosts in iventory.
    # And although we can get the pdu hosts list of a DUT from inventory
    # we can not get the hwsku and os of pdu host from inventory.
    # So we give the default value `{}` to kvm.
    device_pdu_links = conn_graph_facts.get('device_pdu_links', {})
    device_pdu_info = conn_graph_facts.get('device_pdu_info', {})

    pdu_links = device_pdu_links.get(hostname, {})
    pdu_info = device_pdu_info.get(hostname, {})
    pdu_vars = get_pdu_visible_vars(duthost.host.options["inventory_manager"]._sources, pdu_info.keys())

    return pdu_manager_factory(duthost.hostname, pdu_links, pdu_info, pdu_vars)


@pytest.fixture(scope="module")
def pdu_controller(duthosts, conn_graph_facts):
    """
    @summary: Fixture for controlling power supply to PSUs of DUT
    @param duthost: Fixture duthost defined in sonic-mgmt/tests/conftest.py
    @returns: Returns a pdu controller object implementing the BasePduController interface defined in
              controller_base.py.
    """
    duthost = get_sup_node_or_random_node(duthosts)
    controller = _get_pdu_controller(duthost, conn_graph_facts)

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
            controller = _get_pdu_controller(duthost, conn_graph_facts)
            controller_map[duthost.hostname] = controller

        return controller_map[duthost.hostname]

    yield pdu_controller_helper

    for controller in list(controller_map.values()):
        if controller:
            controller.turn_on_outlet()
            controller.close()
