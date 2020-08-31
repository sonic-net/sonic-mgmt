import logging
import pytest
import re

from vnet_constants import *
from vnet_utils import cleanup_vnet_routes, cleanup_dut_vnets, cleanup_vxlan_tunnels, \
                       apply_dut_config_files, generate_dut_config_files

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0")
]

TESTING_STATUS = "Testing"
CLEANUP_STATUS = "Cleanup"
SHOW_VNET_ROUTES_CMD = "show vnet routes all"
SHOW_BGP_SUMMARY_CMD = "show ip bgp summary"
SHOW_BGP_ADV_ROUTES_CMD_TEMPLATE = "show ip bgp neighbor {} advertised-routes"


@pytest.fixture(scope="module")
def configure_dut(minigraph_facts, duthost, vnet_config, vnet_test_params):
    """
    Setup/teardown fixture for VNET route leak test

    During the setup portion, generates VNET VxLAN configurations and applies them to the DUT
    During the teardown portion, removes all previously pushed VNET VxLAN information from the DUT

    Args:
        minigraph_facts: Minigraph information
        duthost: DUT host object
        vnet_config: Dictionary containing VNET configuration information
        vnet_test_params: Dictionary containing VNET test parameters
    """

    duthost.shell("sonic-clear fdb all")
    generate_dut_config_files(duthost, minigraph_facts, vnet_test_params, vnet_config)
    apply_dut_config_files(duthost, vnet_test_params)

    # In this case yield is used only to separate this fixture into setup and teardown portions
    yield None

    if vnet_test_params[CLEANUP_KEY]:
        cleanup_vnet_routes(duthost, vnet_test_params)
        cleanup_dut_vnets(duthost, minigraph_facts, vnet_config)
        cleanup_vxlan_tunnels(duthost, vnet_test_params)
    else:
        logger.info("Skipping cleanup")


def test_vnet_route_leak(configure_dut, duthost):
    """
    Test case for VNET route leak check

    Gets a list of all VNET routes programmed to the DUT, and a list of all BGP neighbors
    Verifies that no VNET routes are being advertised to BGP neighbors

    Args:
        configure_dut: Pytest fixture to prepare DUT for testing
        duthost: DUT host object
    """

    vnet_routes = duthost.shell(SHOW_VNET_ROUTES_CMD)["stdout"].split("\n")
    logger.debug("VNET prefixes: {}".format(vnet_routes))

    vnet_prefixes = []

    for line in vnet_routes:
        if any(char.isdigit() for char in line):
            vnet_prefixes.append(line.split()[1])

    bgp_summary = duthost.shell(SHOW_BGP_SUMMARY_CMD)["stdout"].split("\n")
    logger.debug("BGP Summary: {}".format(bgp_summary))

    # Match only IP addresses at the beginning of the line
    # Only IP addresses of neighbors should be matched by this
    ip_addr_regex = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}")

    bgp_neighbors = []

    for line in bgp_summary:
        matched = ip_addr_regex.match(line)

        if matched:
            bgp_neighbors.append(str(matched.group(0)))

    for neighbor in bgp_neighbors:
        adv_routes = duthost.shell(SHOW_BGP_ADV_ROUTES_CMD_TEMPLATE.format(neighbor))["stdout"]

        for prefix in vnet_prefixes:
            assert prefix not in adv_routes
