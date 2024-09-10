import logging
import re
import pytest
from tests.common.devices.eos import EosHost
from bgp_helpers import get_routes_not_announced_to_bgpmon, remove_bgp_neighbors, restore_bgp_neighbors
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_ASIC_ID
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
from route_checker import verify_only_loopback_routes_are_announced_to_neighs, parse_routes_on_neighbors, \
    verify_current_routes_announced_to_neighs, check_and_log_routes_diff
from traffic_checker import get_traffic_shift_state, check_tsa_persistence_support, verify_traffic_shift_per_asic
from constants import TS_NORMAL, TS_MAINTENANCE, TS_NO_NEIGHBORS

pytestmark = [
    pytest.mark.topology('t1', 't2')
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def nbrhosts_to_dut(duthosts, enum_rand_one_per_hwsku_frontend_hostname, nbrhosts):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    nbrhosts_to_dut = {}
    for host in list(nbrhosts.keys()):
        if host in mg_facts['minigraph_devices']:
            new_nbrhost = {host: nbrhosts[host]}
            nbrhosts_to_dut.update(new_nbrhost)
    return nbrhosts_to_dut


def verify_all_routes_announce_to_neighs(dut_host, neigh_hosts, routes_dut, ip_ver):
    """
    Verify all routes are announced to neighbors in TSB
    """
    logger.info(
        "Verifying all routes(ipv{}) are announced to bgp neighbors".format(ip_ver))
    routes_on_all_nbrs = parse_routes_on_neighbors(
        dut_host, neigh_hosts, ip_ver)
    # Check routes on all neigh
    for hostname, routes in list(routes_on_all_nbrs.items()):
        logger.info(
            "Verifying all routes(ipv{}) are announced to {}".format(ip_ver, hostname))
        for route, aspaths in list(routes_dut.items()):
            # Filter out routes announced by this neigh
            skip = False
            # We will skip aspath on KVM since KVM does not support aspath
            if isinstance(list(neigh_hosts.items())[0][1]['host'], EosHost):
                for aspath in aspaths:
                    if str(neigh_hosts[hostname]['conf']['bgp']['asn']) in aspath:
                        skip = True
                        break
            if skip:
                continue
            if route not in list(routes.keys()):
                logger.warn("{} not found on {}".format(route, hostname))
                return False
    return True


def test_TSA(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost,
             nbrhosts_to_dut, bgpmon_setup_teardown, traffic_shift_community, tbinfo):
    """
    Test TSA
    Verify all routes are announced to bgp monitor, and only loopback routes are announced to neighs
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    try:
        # Issue TSA on DUT
        duthost.shell("TSA")
        # Verify DUT is in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                      "DUT is not in maintenance state")
        # For T2 - TSA command sets up policies where only loopback address on the iBGP peers on the same linecard
        # are exchanged between the asics. Also, since bgpmon is iBGP as well, routes learnt from other asics on other
        # linecards are also not going to be advertised to bgpmon.
        # So, cannot validate all routes are send to bgpmon on T2.
        if tbinfo['topo']['type'] != 't2':
            pytest_assert(get_routes_not_announced_to_bgpmon(duthost, ptfhost,
                                                             bgpmon_setup_teardown['namespace']) == [],
                          "Not all routes are announced to bgpmon")

        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(duthosts, duthost, nbrhosts_to_dut,
                                                                          traffic_shift_community),
                      "Failed to verify routes on nbr in TSA")
    finally:
        # Recover to Normal state
        duthost.shell("TSB")


def test_TSB(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, nbrhosts, bgpmon_setup_teardown, tbinfo):
    """
    Test TSB.
    Establish BGP session between PTF and DUT, and verify all routes are announced to bgp monitor,
    and all routes are announced to neighbors
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # Ensure that the DUT is not in maintenance already before start of the test
    pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                  "DUT is not in normal state")
    # Get all routes on neighbors before doing TSA
    orig_v4_routes = parse_routes_on_neighbors(duthost, nbrhosts, 4)
    orig_v6_routes = parse_routes_on_neighbors(duthost, nbrhosts, 6)

    # Shift traffic away using TSA
    duthost.shell("TSA")
    pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                  "DUT is not in maintenance state")
    # Issue TSB on DUT to bring traffic back
    duthost.shell("TSB")
    # Verify DUT is in normal state.
    pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                  "DUT is not in normal state")
    if tbinfo['topo']['type'] != 't2':
        pytest_assert(get_routes_not_announced_to_bgpmon(duthost, ptfhost, bgpmon_setup_teardown['namespace']) == [],
                      "Not all routes are announced to bgpmon")

    cur_v4_routes = {}
    cur_v6_routes = {}
    # Verify that all routes advertised to neighbor at the start of the test
    if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                      duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
        if not check_and_log_routes_diff(duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
            pytest.fail("Not all ipv4 routes are announced to neighbors")

    if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                      duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
        if not check_and_log_routes_diff(duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
            pytest.fail("Not all ipv6 routes are announced to neighbors")


def test_TSA_B_C_with_no_neighbors(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                   bgpmon_setup_teardown, nbrhosts, core_dump_and_config_check):
    """
    Test TSA, TSB, TSC with no neighbors on ASIC0 in case of multi-asic and single-asic.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    bgp_neighbors = {}
    duts_data = core_dump_and_config_check
    asic_index = 0 if duthost.is_multi_asic else DEFAULT_ASIC_ID
    # Ensure that the DUT is not in maintenance already before start of the test
    pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                  "DUT is not in normal state")
    try:
        # Get all routes on neighbors before doing TSA
        orig_v4_routes = parse_routes_on_neighbors(duthost, nbrhosts, 4)
        orig_v6_routes = parse_routes_on_neighbors(duthost, nbrhosts, 6)
        # Remove the Neighbors for the particular BGP instance
        bgp_neighbors = remove_bgp_neighbors(duthost, asic_index)

        # Check the traffic state
        output = duthost.shell("TSC")['stdout_lines']

        # Verify DUT is in Normal state, and ASIC0 has no neighbors message.
        pytest_assert(verify_traffic_shift_per_asic(duthost, output, TS_NO_NEIGHBORS, asic_index),
                      "ASIC is not having no neighbors")

    finally:
        # Restore BGP neighbors
        restore_bgp_neighbors(duthost, asic_index, bgp_neighbors)

        # Recover to Normal state
        duthost.shell("TSB")
        wait_critical_processes(duthost)

        # Wait until bgp sessions are established on DUT
        pytest_assert(wait_until(100, 10, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())),
                      "Not all BGP sessions are established on DUT")

        # If expected core dump files exist, add it into duts_data
        if "20191130" in duthost.os_version:
            existing_core_dumps = duthost.shell('ls /var/core/ | grep -v python || true')['stdout'].split()
        else:
            existing_core_dumps = duthost.shell('ls /var/core/')['stdout'].split()
        for core_dump in existing_core_dumps:
            if re.match("dplane_fpm_nl", core_dump):
                duts_data[duthost.hostname]["pre_core_dumps"].append(core_dump)

        # Wait until all routes are announced to neighbors
        cur_v4_routes = {}
        cur_v6_routes = {}
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")


@pytest.mark.disable_loganalyzer
def test_TSA_TSB_with_config_reload(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, nbrhosts,
                                    nbrhosts_to_dut, bgpmon_setup_teardown, traffic_shift_community, tbinfo):
    """
    Test TSA after config save and config reload
    Verify all routes are announced to bgp monitor, and only loopback routes are announced to neighs
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # Ensure that the DUT is not in maintenance already before start of the test
    pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                  "DUT is not in normal state")
    if not check_tsa_persistence_support(duthost):
        pytest.skip("TSA persistence not supported in the image")

    try:
        # Get all routes on neighbors before doing TSA
        orig_v4_routes = parse_routes_on_neighbors(duthost, nbrhosts, 4)
        orig_v6_routes = parse_routes_on_neighbors(duthost, nbrhosts, 6)
        # Issue TSA on DUT
        duthost.shell("TSA")
        duthost.shell('sudo config save -y')
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

        # Verify DUT is in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                      "DUT is not in maintenance state")
        if tbinfo['topo']['type'] != 't2':
            pytest_assert(get_routes_not_announced_to_bgpmon(duthost, ptfhost,
                                                             bgpmon_setup_teardown['namespace']) == [],
                          "Not all routes are announced to bgpmon")

        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(duthosts, duthost, nbrhosts_to_dut,
                                                                          traffic_shift_community),
                      "Failed to verify routes on nbr in TSA")
    finally:
        """
        Test TSB after config save and config reload
        Establish BGP session between PTF and DUT, and verify all routes are announced to bgp monitor,
        and all routes are announced to neighbors
        """
        # Recover to Normal state
        duthost.shell("TSB")
        duthost.shell('sudo config save -y')
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

        # Verify DUT is in normal state.
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                      "DUT is not in normal state")
        # Wait until all routes are announced to neighbors
        cur_v4_routes = {}
        cur_v6_routes = {}
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")


@pytest.mark.disable_loganalyzer
def test_load_minigraph_with_traffic_shift_away(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                                ptfhost, nbrhosts, nbrhosts_to_dut, bgpmon_setup_teardown,
                                                traffic_shift_community, tbinfo):
    """
    Test load_minigraph --traffic-shift-away
    Verify all routes are announced to bgp monitor, and only loopback routes are announced to neighs
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # Ensure that the DUT is not in maintenance already before start of the test
    pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                  "DUT is not in normal state")
    if not check_tsa_persistence_support(duthost):
        pytest.skip("TSA persistence not supported in the image")

    try:
        # Get all routes on neighbors before doing TSA
        orig_v4_routes = parse_routes_on_neighbors(duthost, nbrhosts, 4)
        orig_v6_routes = parse_routes_on_neighbors(duthost, nbrhosts, 6)

        config_reload(duthost, config_source='minigraph', safe_reload=True, check_intf_up_ports=True,
                      traffic_shift_away=True)

        # Verify DUT is in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                      "DUT is not in maintenance state")
        if tbinfo['topo']['type'] != 't2':
            pytest_assert(get_routes_not_announced_to_bgpmon(duthost, ptfhost,
                                                             bgpmon_setup_teardown['namespace']) == [],
                          "Not all routes are announced to bgpmon")

        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(duthosts, duthost, nbrhosts_to_dut,
                                                                          traffic_shift_community),
                      "Failed to verify routes on nbr in TSA")
    finally:
        """
        Recover with TSB and verify route advertisement
        """
        # Recover to Normal state
        duthost.shell("TSB")
        duthost.shell('sudo config save -y')

        # Verify DUT is in normal state.
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                      "DUT is not in normal state")

        # Wait until all routes are announced to neighbors
        cur_v4_routes = {}
        cur_v6_routes = {}
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")
