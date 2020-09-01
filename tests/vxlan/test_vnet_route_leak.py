import logging
import pytest
import re

from tests.common.utilities import wait_until
from vnet_constants import *
from vnet_utils import cleanup_vnet_routes, cleanup_dut_vnets, cleanup_vxlan_tunnels, \
                       apply_dut_config_files, generate_dut_config_files

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0")
]

BGP_WAIT_TIMEOUT = 120

TESTING_STATUS = "Testing"
CLEANUP_STATUS = "Cleanup"

SHOW_VNET_ROUTES_CMD = "show vnet routes all"
SHOW_BGP_SUMMARY_CMD = "show ip bgp summary"
SHOW_BGP_ADV_ROUTES_CMD_TEMPLATE = "show ip bgp neighbor {} advertised-routes"
RESTART_BGP_CMD = "sudo systemctl restart bgp"
CONFIG_SAVE_CMD = "sudo config save -y"
CONFIG_RELOAD_CMD = "sudo config reload -y"


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

        logger.info("Reloading CONFIG_DB from JSON")

        duthost.shell(CONFIG_SAVE_CMD)
        duthost.shell(RESTART_BGP_CMD)
    else:
        logger.info("Skipping cleanup")


def bgp_connected(duthost):
    """
    Checks if BGP connections are up

    BGP connections are "up" once they have received all prefixes (6400) from all neighbors

    Args:
        duthost: DUT host object
    """

    bgp_summary = duthost.shell(SHOW_BGP_SUMMARY_CMD)["stdout"].split("\n")
    logger.debug("BGP Summary: {}".format(bgp_summary))

    # Match entire line containing BGP neighbor information
    bgp_neighbor_regex = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}.*")

    bgp_neighbors = []

    for line in bgp_summary:
        matched = bgp_neighbor_regex.match(line)

        if matched:
            bgp_neighbors.append(str(matched.group(0)))

    if not bgp_neighbors:
        return False

    for neighbor in bgp_neighbors:
        if neighbor.split()[9] != "6400":
            return False

    logger.info("BGP sessions up")

    return True


def no_vnet_route_leak(duthost):
    """
    Gets all VNET routes and checks that they are not advertised to any BGP neighbors

    Args:
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
    bgp_neighbor_addr_regex = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}")

    bgp_neighbors = []

    for line in bgp_summary:
        matched = bgp_neighbor_addr_regex.match(line)

        if matched:
            bgp_neighbors.append(str(matched.group(0)))

    leaked_routes = {}

    for neighbor in bgp_neighbors:
        adv_routes = duthost.shell(SHOW_BGP_ADV_ROUTES_CMD_TEMPLATE.format(neighbor))["stdout"]

        for prefix in vnet_prefixes:
            if prefix in adv_routes:
                if neighbor not in leaked_routes:
                    leaked_routes[neighbor] = []
                leaked_routes[neighbor].append(str(prefix))

    for neighbor, routes in leaked_routes.items():
        logger.error("VNET routes leaked to neighbor {}: {}".format(neighbor, routes))

    return not leaked_routes


def test_vnet_route_leak(configure_dut, duthost):
    """
    Test case for VNET route leak check

    Gets a list of all VNET routes programmed to the DUT, and a list of all BGP neighbors
    Verifies that no VNET routes are being advertised to BGP neighbors

    Args:
        configure_dut: Pytest fixture to prepare DUT for testing
        duthost: DUT host object
    """

    assert no_vnet_route_leak(duthost)

    logger.info("Restarting BGP")
    duthost.shell(RESTART_BGP_CMD)

    if not wait_until(BGP_WAIT_TIMEOUT, 5, bgp_connected, duthost):
        logger.error("BGP sessions not established after {} seconds".format(BGP_WAIT_TIMEOUT))
        assert False

    assert no_vnet_route_leak(duthost)

    logger.info("Saving and reloading CONFIG_DB")
    duthost.shell(CONFIG_SAVE_CMD)
    duthost.shell(CONFIG_RELOAD_CMD)

    if not wait_until(BGP_WAIT_TIMEOUT, 5, bgp_connected, duthost):
        logger.error("BGP sessions not established after {} seconds".format(BGP_WAIT_TIMEOUT))
        assert False

    assert no_vnet_route_leak(duthost)
