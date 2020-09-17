import logging
import pytest
import yaml

from os import path
from vnet_utils import combine_dicts, safe_open_template

from vnet_constants import *

logger = logging.getLogger(__name__)

def pytest_addoption(parser):
    """
    Adds pytest options that are used by VxLAN tests
    """

    parser.addoption(
        "--num_vnet",
        action="store",
        default=8,
        type=int,
        help="number of VNETs for VNET VxLAN test"
    )

    parser.addoption(
        "--num_routes",
        action="store",
        default=16000,
        type=int,
        help="number of routes for VNET VxLAN test"
    )

    parser.addoption(
        "--num_endpoints",
        action="store",
        default=4000,
        type=int,
        help="number of endpoints for VNET VxLAN"
    )

    parser.addoption(
        "--num_intf_per_vnet",
        action="store",
        default=1,
        type=int,
        help="number of VLAN interfaces per VNET"
    )

    parser.addoption(
        "--ipv6_vxlan_test",
        action="store_true",
        help="Use IPV6 for VxLAN test"
    )

    parser.addoption(
        "--skip_cleanup",
        action="store_true",
        help="Do not cleanup after VNET VxLAN test"
    )

    parser.addoption(
        "--skip_apply_config",
        action="store_true",
        help="Apply new configurations on DUT"
    )

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
    return params

@pytest.fixture(scope="module")
def minigraph_facts(duthost):
    """
    Fixture to get minigraph facts

    Args:
        duthost: DUT host object

    Returns:
        Dictionary containing minigraph information
    """

    return duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]

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
