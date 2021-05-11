import logging
import pytest
import yaml

from os import path
from vnet_utils import combine_dicts, safe_open_template

from vnet_constants import *

logger = logging.getLogger(__name__)

@pytest.fixture(scope="module")
def scaled_vnet_params(request):
    """
    Fixture to get CLI parameters for scaled vnet testing

    Args:
        request: Pytest fixture containing parsed CLI parameters

    Returns:
        A dictionary holding each scaled vnet parameter with the parameter name as the key
            * num_vnet
            * num_routes
            * num_endpoints
    """

    params = {}
    params[NUM_VNET_KEY] = request.config.option.num_vnet
    params[NUM_ROUTES_KEY] = request.config.option.num_routes
    params[NUM_ENDPOINTS_KEY] = request.config.option.num_endpoints
    return params

@pytest.fixture(scope="module")
def vnet_test_params(request):
    """
    Fixture to get CLI parameters for vnet testing

    Args:
        request: Pytest fixture containing parsed CLI parameters

    Returns:
        A dictionary holding each parameter with the parameter name as the key
            * ipv6_vxlan_test - whether to include ipv6 functionality in testing
            * cleanup - whether to remove test data/configs after test is finished
            * apply_new_config - whether to apply new configurations that were pushed to the DUT
    """

    params = {}
    params[IPV6_VXLAN_TEST_KEY] = request.config.option.ipv6_vxlan_test
    params[CLEANUP_KEY] = not request.config.option.skip_cleanup
    params[APPLY_NEW_CONFIG_KEY] = not request.config.option.skip_apply_config
    params[NUM_INTF_PER_VNET_KEY] = request.config.option.num_intf_per_vnet
    params[LOWER_BOUND_UDP_PORT_KEY] = request.config.option.lower_bound_udp_port
    params[UPPER_BOUND_UDP_PORT_KEY] = request.config.option.upper_bound_udp_port
    return params

@pytest.fixture(scope="module")
def minigraph_facts(duthosts, rand_one_dut_hostname, tbinfo):
    """
    Fixture to get minigraph facts

    Args:
        duthost: DUT host object

    Returns:
        Dictionary containing minigraph information
    """
    duthost = duthosts[rand_one_dut_hostname]

    return duthost.get_extended_minigraph_facts(tbinfo)

@pytest.fixture(scope="module")
def vnet_config(minigraph_facts, vnet_test_params, scaled_vnet_params):
    """
    Fixture to generate vnet configuration from templates/vnet_config.j2

    Args:
        minigraph_facts: minigraph information/facts
        vnet_test_params: Dictionary holding vnet test parameters
        scaled_vnet_params: Dictionary holding scaled vnet testing parameters

    Returns:
        A dictionary containing the generated vnet configuration information
    """

    num_rifs = vnet_test_params[NUM_INTF_PER_VNET_KEY] * scaled_vnet_params[NUM_VNET_KEY]

    if num_rifs > 128:
        logger.warning("Total number of configured interfaces will be greater than 128. This is not a supported test scenario")

    combined_args = combine_dicts(minigraph_facts, vnet_test_params, scaled_vnet_params)
    return yaml.safe_load(safe_open_template(path.join(TEMPLATE_DIR, "vnet_config.j2")).render(combined_args))
