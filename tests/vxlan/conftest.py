
import logging
import yaml

import pytest

from os import path
from tests.vxlan.vnet_utils import combine_dicts, safe_open_template
from tests.vxlan.vnet_constants import *

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    """
    Adds pytest options that are used by VxLAN tests
    """

    vxlan_group = parser.getgroup("VXLAN test suite options")

    vxlan_group.addoption(
        "--vxlan_port",
        action="store",
        default=4789,
        type=int,
        help="The UDP port to use for VxLAN. It must be a viable UDP port - not one of the already used standard protocol ports"
    )

    vxlan_group.addoption(
        "--num_vnet",
        action="store",
        default=8,
        type=int,
        help="number of VNETs for VNET VxLAN test"
    )

    vxlan_group.addoption(
        "--num_routes",
        action="store",
        default=16000,
        type=int,
        help="number of routes for VNET VxLAN test"
    )

    vxlan_group.addoption(
        "--num_endpoints",
        action="store",
        default=4000,
        type=int,
        help="number of endpoints for VNET VxLAN"
    )

    vxlan_group.addoption(
        "--num_intf_per_vnet",
        action="store",
        default=1,
        type=int,
        help="number of VLAN interfaces per VNET"
    )

    vxlan_group.addoption(
        "--ipv6_vxlan_test",
        action="store_true",
        help="Use IPV6 for VxLAN test"
    )

    vxlan_group.addoption(
        "--skip_cleanup",
        action="store_true",
        help="Do not cleanup after VNET VxLAN test"
    )

    vxlan_group.addoption(
        "--skip_apply_config",
        action="store_true",
        help="Apply new configurations on DUT"
    )

    vxlan_group.addoption(
        "--udp_src_port",
        action="store",
        type=int,
        help="Expected base VXLAN UDP src port"
    )

    vxlan_group.addoption(
        "--udp_src_port_mask",
        action="store",
        type=int,
        help="Expected base VXLAN UDP src port mask"
    )

    # ECMP options
    vxlan_group.addoption(
        "--total_number_of_endpoints",
        action="store",
        default=2,
        type=int,
        help="Total number of uniq endpoints that can be used in the DUT"
    )

    vxlan_group.addoption(
        "--ecmp_nhs_per_destination",
        action="store",
        default=1,
        type=int,
        help="ECMP: Number of tunnel endpoints to provide for each tunnel destination"
    )

    vxlan_group.addoption(
        "--debug_enabled",
        action="store_true",
        help="Enable debugging the script. The config file names will *not* be time-stamped, every run of the script will over-write the previously created config files."
    )

    vxlan_group.addoption(
        "--keep_temp_files",
        action="store_true",
        help="This will keep the config files in the DUT and PTF."
    )

    vxlan_group.addoption(
        "--dut_hostid",
        default=1,
        type=int,
        help="This is the host part of the IP addresses for interfaces in the DUT to be used in this script."
    )

    # This will decide the number of destinations.
    vxlan_group.addoption(
        "--total_number_of_nexthops",
        action="store",
        default=2, # Max: 32k, 64K, or 128 K
        type=int,
        help="ECMP: Number of tunnel nexthops to be tested. (number of nhs_per_destination X number_of_destinations)"
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
def vnet_test_params(duthost, request):
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
    params[VXLAN_UDP_SPORT_KEY] = 0
    params[VXLAN_UDP_SPORT_MASK_KEY] = 0

    vxlan_range_enable = duthost.shell('redis-cli -n 4 hget "DEVICE_METADATA|localhost" vxlan_port_range')['stdout'] == "enable"

    if request.config.option.udp_src_port is not None or request.config.option.udp_src_port_mask is not None:
        vxlan_range_enable = True

    if request.config.option.udp_src_port:
        params[VXLAN_UDP_SPORT_KEY] = request.config.option.udp_src_port

    if request.config.option.udp_src_port_mask:
        params[VXLAN_UDP_SPORT_MASK_KEY] = request.config.option.udp_src_port_mask

    params[VXLAN_RANGE_ENABLE_KEY] = vxlan_range_enable
    params[IPV6_VXLAN_TEST_KEY] = request.config.option.ipv6_vxlan_test
    params[CLEANUP_KEY] = not request.config.option.skip_cleanup
    params[APPLY_NEW_CONFIG_KEY] = not request.config.option.skip_apply_config
    params[NUM_INTF_PER_VNET_KEY] = request.config.option.num_intf_per_vnet
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
