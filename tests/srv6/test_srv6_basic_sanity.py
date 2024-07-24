import time
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

from srv6_utils import announce_route
from srv6_utils import find_node_interfaces
from srv6_utils import check_bgp_neighbors
from srv6_utils import check_bgp_neighbors_func

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    pytest.mark.topology("any"),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.skip_check_dut_health
]

test_vm_names = ["PE1", "PE2", "PE3", "P2", "P3", "P4"]

# The number of routes published by each CE
num_ce_routes = 10


#
# Initialize the testbed
#
def setup_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost):
    logger.info("Announce routes from CEs")
    ptfip = ptfhost.mgmt_ip
    nexthop = "10.10.246.254"
    port_num = [5000, 5001, 5002]

    # Publish to PE1
    neighbor = "10.10.246.29"
    # Publish to PE2
    neighbor2 = "10.10.246.30"
    route_prefix_for_pe1_and_pe2 = "192.100.0"
    for x in range(1, num_ce_routes+1):
        route = "{}.{}/32".format(route_prefix_for_pe1_and_pe2, x)
        announce_route(ptfip, neighbor, route, nexthop, port_num[0])
        announce_route(ptfip, neighbor2, route, nexthop, port_num[1])

    # Publish to PE3
    neighbor = "10.10.246.31"
    route_prefix_for_pe3 = "192.200.0"
    for x in range(1, num_ce_routes+1):
        route = "{}.{}/32".format(route_prefix_for_pe3, x)
        announce_route(ptfip, neighbor, route, nexthop, port_num[2])

    # sleep make sure all forwarding structures are settled down.
    sleep_duration_after_annournce = 60
    time.sleep(sleep_duration_after_annournce)
    logger.info(
        "Sleep {} seconds to make sure all forwarding structures are "
        "settled down".format(sleep_duration_after_annournce)
    )


#
# Testbed set up and tear down
#
@pytest.fixture(scope="module", autouse=True)
def srv6_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost):
    setup_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost)


#
# Test case: check number of Ethnernet interfaces
#
def test_interface_on_each_node(duthosts, rand_one_dut_hostname, nbrhosts):
    for vm_name in test_vm_names:
        nbrhost = nbrhosts[vm_name]['host']
        num, hwsku = find_node_interfaces(nbrhost)
        logger.debug("Get {} interfaces on {}, hwsku {}".format(num, vm_name, hwsku))
        if hwsku == "cisco-8101-p4-32x100-vs":
            pytest_assert(num == 32)

    dut = duthosts[rand_one_dut_hostname]
    num, hwsku = find_node_interfaces(dut)
    logger.debug("Get {} interfaces on {}, hwsku {}".format(num, "dut", hwsku))
    if hwsku == "cisco-8101-p4-32x100-vs":
        pytest_assert(num == 32)


#
# Test Case: Check BGP neighbors
#
def test_check_bgp_neighbors(duthosts, rand_one_dut_hostname, nbrhosts):
    logger.info("Check BGP Neighbors")
    # From PE3
    nbrhost = nbrhosts["PE3"]['host']
    pytest_assert(
        wait_until(60, 10, 0, check_bgp_neighbors_func, nbrhost, ['2064:100::1d', '2064:200::1e', 'fc06::2', 'fc08::2']), 
        "wait for PE3 BGP neighbors up"
    )
    check_bgp_neighbors(nbrhost, ['10.10.246.254'], "Vrf1")
    # From PE1
    nbrhost = nbrhosts["PE1"]['host']
    check_bgp_neighbors(nbrhost, ['2064:300::1f', '2064:200::1e', 'fc00::71', 'fc02::2'])
    check_bgp_neighbors(nbrhost, ['10.10.246.254'], "Vrf1")
    # From PE2
    nbrhost = nbrhosts["PE2"]['host']
    check_bgp_neighbors(nbrhost, ['2064:300::1f', '2064:100::1d', 'fc00::75', 'fc03::2'])
    check_bgp_neighbors(nbrhost, ['10.10.246.254'], "Vrf1")
    # From P1
    dut = duthosts[rand_one_dut_hostname]
    check_bgp_neighbors(dut, ['fc00::72', 'fc00::76', 'fc00::7e', 'fc01::85', 'fc00::81'])
    # From P3
    nbrhost = nbrhosts["P3"]['host']
    check_bgp_neighbors(nbrhost, ['fc02::1', 'fc04::1', 'fc00::7d', 'fc03::1', 'fc09::1'])
    # From P2
    nbrhost = nbrhosts["P2"]['host']
    check_bgp_neighbors(nbrhost, ['fc00::82', 'fc09::2', 'fc07::1', 'fc08::1'])
    # From P4
    nbrhost = nbrhosts["P4"]['host']
    check_bgp_neighbors(nbrhost, ['fc01::86', 'fc04::2', 'fc07::2', 'fc06::1'])
