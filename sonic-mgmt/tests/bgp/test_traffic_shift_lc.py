import logging
import re
import threading

import pytest
from tests.common.devices.eos import EosHost
from tests.bgp.bgp_helpers import remove_bgp_neighbors, restore_bgp_neighbors, initial_tsa_check_before_and_after_test
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_ASIC_ID
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
from tests.bgp.route_checker import assert_only_loopback_routes_announced_to_neighs, parse_routes_on_neighbors, \
    verify_current_routes_announced_to_neighs, check_and_log_routes_diff
from tests.bgp.traffic_checker import get_traffic_shift_state, check_tsa_persistence_support, \
    verify_traffic_shift_per_asic
from tests.bgp.constants import TS_NORMAL, TS_MAINTENANCE, TS_NO_NEIGHBORS
from tests.conftest import get_hosts_per_hwsku

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)

lock = threading.Lock()
_cached_frontend_nodes = None


def get_frontend_nodes_per_hwsku(duthosts, request):
    global _cached_frontend_nodes
    if _cached_frontend_nodes is None:
        _cached_frontend_nodes = [
            duthosts[hostname] for hostname in get_hosts_per_hwsku(
                request,
                [host.hostname for host in duthosts.frontend_nodes],
            )
        ]

    return _cached_frontend_nodes


def nbrhosts_to_dut(duthost, nbrhosts, dut_nbrhosts):
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    all_nbhhosts = {}
    for host in list(nbrhosts.keys()):
        if host in mg_facts['minigraph_devices']:
            new_nbrhost = {host: nbrhosts[host]}
            all_nbhhosts.update(new_nbrhost)

    with lock:
        dut_nbrhosts[duthost] = all_nbhhosts


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
                logger.warning("{} not found on {}".format(route, hostname))
                return False
    return True


def run_traffic_shift_cmd_on_dut(duthost, cmd, should_config_save=False):
    duthost.shell(cmd)
    if should_config_save:
        duthost.shell('sudo config save -y')


def verify_route_on_neighbors(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes):
    for duthost in duthosts:
        cur_v4_routes = {}
        cur_v6_routes = {}
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, dut_nbrhosts[duthost], orig_v4_routes[duthost], cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, dut_nbrhosts[duthost], orig_v4_routes[duthost], cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, dut_nbrhosts[duthost], orig_v6_routes[duthost], cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, dut_nbrhosts[duthost], orig_v6_routes[duthost], cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")


def test_tsa(request, duthosts, nbrhosts, traffic_shift_community, tbinfo):
    """
    Test TSA
    Verify all routes are announced to bgp monitor, and only loopback routes are announced to neighs
    """
    frontend_nodes_per_hwsku = get_frontend_nodes_per_hwsku(duthosts, request)
    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in frontend_nodes_per_hwsku:
            executor.submit(nbrhosts_to_dut, duthost, nbrhosts, dut_nbrhosts)

    # Initially make sure line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)
    try:
        # Issue TSA on DUT
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for duthost in frontend_nodes_per_hwsku:
                executor.submit(run_traffic_shift_cmd_on_dut, duthost, "TSA")

        for duthost in frontend_nodes_per_hwsku:
            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost), "DUT is not in maintenance state")
            assert_only_loopback_routes_announced_to_neighs(
                duthosts,
                duthost,
                dut_nbrhosts[duthost],
                traffic_shift_community,
                "Failed to verify routes on nbr in TSA",
            )
    finally:
        # Recover to Normal state
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for duthost in frontend_nodes_per_hwsku:
                executor.submit(run_traffic_shift_cmd_on_dut, duthost, "TSB")

        # Bring back line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)


def test_tsb(request, duthosts, nbrhosts, tbinfo):
    """
    Test TSB.
    Establish BGP session between PTF and DUT, and verify all routes are announced to bgp monitor,
    and all routes are announced to neighbors
    """
    frontend_nodes_per_hwsku = get_frontend_nodes_per_hwsku(duthosts, request)
    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in frontend_nodes_per_hwsku:
            executor.submit(nbrhosts_to_dut, duthost, nbrhosts, dut_nbrhosts)

    # Initially make sure line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    for duthost in frontend_nodes_per_hwsku:
        # Ensure that the DUT is not in maintenance already before start of the test
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost), "DUT is not in normal state")
        # Get all routes on neighbors before doing TSA
        orig_v4_routes[duthost] = parse_routes_on_neighbors(duthost, dut_nbrhosts[duthost], 4)
        orig_v6_routes[duthost] = parse_routes_on_neighbors(duthost, dut_nbrhosts[duthost], 6)

    # Shift traffic away using TSA
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in frontend_nodes_per_hwsku:
            executor.submit(run_traffic_shift_cmd_on_dut, duthost, "TSA")

    for duthost in frontend_nodes_per_hwsku:
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost), "DUT is not in maintenance state")

    # Issue TSB on DUT to bring traffic back
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in frontend_nodes_per_hwsku:
            executor.submit(run_traffic_shift_cmd_on_dut, duthost, "TSB")

    for duthost in frontend_nodes_per_hwsku:
        # Verify DUT is in normal state.
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost), "DUT is not in normal state")

    verify_route_on_neighbors(frontend_nodes_per_hwsku, dut_nbrhosts, orig_v4_routes, orig_v6_routes)

    # Bring back line cards to the BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)


def test_tsa_b_c_with_no_neighbors(request, duthosts, nbrhosts, core_dump_and_config_check, tbinfo):
    """
    Test TSA, TSB, TSC with no neighbors on ASIC0 in case of multi-asic and single-asic.
    """
    frontend_nodes_per_hwsku = get_frontend_nodes_per_hwsku(duthosts, request)
    duts_data = core_dump_and_config_check
    asic_index = 0 if frontend_nodes_per_hwsku[0].is_multi_asic else DEFAULT_ASIC_ID
    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in frontend_nodes_per_hwsku:
            executor.submit(nbrhosts_to_dut, duthost, nbrhosts, dut_nbrhosts)

    # Initially make sure line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)

    for duthost in frontend_nodes_per_hwsku:
        # Ensure that the DUT is not in maintenance already before start of the test
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost), "DUT is not in normal state")

    bgp_neighbors = {}
    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        for duthost in frontend_nodes_per_hwsku:
            # Get all routes on neighbors before doing TSA
            orig_v4_routes[duthost] = parse_routes_on_neighbors(duthost, dut_nbrhosts[duthost], 4)
            orig_v6_routes[duthost] = parse_routes_on_neighbors(duthost, dut_nbrhosts[duthost], 6)
            # Remove the Neighbors for the particular BGP instance
            bgp_neighbors[duthost] = remove_bgp_neighbors(duthost, asic_index)

            # Check the traffic state
            output = duthost.shell("TSC")['stdout_lines']

            # Verify DUT is in Normal state, and ASIC0 has no neighbors message.
            pytest_assert(verify_traffic_shift_per_asic(duthost, output, TS_NO_NEIGHBORS, asic_index),
                          "ASIC is not having no neighbors")

    finally:

        def restore_bgp_and_wait(dut):
            # Restore BGP neighbors
            restore_bgp_neighbors(dut, asic_index, bgp_neighbors[dut])

            # Recover to Normal state
            dut.shell("TSB")
            wait_critical_processes(dut)

            # Wait until bgp sessions are established on DUT
            pytest_assert(
                wait_until(
                    100, 10, 0,
                    dut.check_bgp_session_state, list(bgp_neighbors[dut].keys()),
                ),
                "Not all BGP sessions are established on DUT"
            )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for duthost in frontend_nodes_per_hwsku:
                executor.submit(restore_bgp_and_wait, duthost)

        for duthost in frontend_nodes_per_hwsku:
            # If expected core dump files exist, add it into duts_data
            if "20191130" in duthost.os_version:
                existing_core_dumps = duthost.shell('ls /var/core/ | grep -v python || true')['stdout'].split()
            else:
                existing_core_dumps = duthost.shell('ls /var/core/')['stdout'].split()
            for core_dump in existing_core_dumps:
                if re.match("dplane_fpm_nl", core_dump):
                    duts_data[duthost.hostname]["pre_core_dumps"].append(core_dump)

        verify_route_on_neighbors(frontend_nodes_per_hwsku, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
        # Bring back line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)


@pytest.mark.disable_loganalyzer
def test_tsa_tsb_with_config_reload(request, duthosts, nbrhosts, traffic_shift_community, tbinfo):
    """
    Test TSA after config save and config reload
    Verify all routes are announced to bgp monitor, and only loopback routes are announced to neighs
    """
    frontend_nodes_per_hwsku = get_frontend_nodes_per_hwsku(duthosts, request)
    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in frontend_nodes_per_hwsku:
            executor.submit(nbrhosts_to_dut, duthost, nbrhosts, dut_nbrhosts)

    # Initially make sure line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)

    for duthost in frontend_nodes_per_hwsku:
        # Ensure that the DUT is not in maintenance already before start of the test
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost), "DUT is not in normal state")
        if not check_tsa_persistence_support(duthost):
            pytest.skip("TSA persistence not supported in the image")

    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        for duthost in frontend_nodes_per_hwsku:
            # Get all routes on neighbors before doing TSA
            orig_v4_routes[duthost] = parse_routes_on_neighbors(duthost, dut_nbrhosts[duthost], 4)
            orig_v6_routes[duthost] = parse_routes_on_neighbors(duthost, dut_nbrhosts[duthost], 6)

        # Issue TSA on DUT
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for duthost in frontend_nodes_per_hwsku:
                executor.submit(run_traffic_shift_cmd_on_dut, duthost, "TSA", should_config_save=True)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for duthost in frontend_nodes_per_hwsku:
                executor.submit(config_reload, duthost, safe_reload=True, check_intf_up_ports=True)

        for duthost in frontend_nodes_per_hwsku:
            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost), "DUT is not in maintenance state")
            assert_only_loopback_routes_announced_to_neighs(
                duthosts,
                duthost,
                dut_nbrhosts[duthost],
                traffic_shift_community,
                "Failed to verify routes on nbr in TSA",
            )
    finally:
        """
        Test TSB after config save and config reload
        Establish BGP session between PTF and DUT, and verify all routes are announced to bgp monitor,
        and all routes are announced to neighbors
        """
        # Recover to Normal state
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for duthost in frontend_nodes_per_hwsku:
                executor.submit(run_traffic_shift_cmd_on_dut, duthost, "TSB", should_config_save=True)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for duthost in frontend_nodes_per_hwsku:
                executor.submit(config_reload, duthost, safe_reload=True, check_intf_up_ports=True)

        # Verify DUT is in normal state.
        for duthost in frontend_nodes_per_hwsku:
            pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost), "DUT is not in normal state")

        verify_route_on_neighbors(frontend_nodes_per_hwsku, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
        # Bring back the supervisor and line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)


@pytest.mark.disable_loganalyzer
def test_load_minigraph_with_traffic_shift_away(request, duthosts, nbrhosts, traffic_shift_community, tbinfo):
    """
    Test load_minigraph --traffic-shift-away
    Verify all routes are announced to bgp monitor, and only loopback routes are announced to neighs
    """
    frontend_nodes_per_hwsku = get_frontend_nodes_per_hwsku(duthosts, request)
    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in frontend_nodes_per_hwsku:
            executor.submit(nbrhosts_to_dut, duthost, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)

    for duthost in frontend_nodes_per_hwsku:
        # Ensure that the DUT is not in maintenance already before start of the test
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost), "DUT is not in normal state")
        if not check_tsa_persistence_support(duthost):
            pytest.skip("TSA persistence not supported in the image")

    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        for duthost in frontend_nodes_per_hwsku:
            # Get all routes on neighbors before doing TSA
            orig_v4_routes[duthost] = parse_routes_on_neighbors(duthost, dut_nbrhosts[duthost], 4)
            orig_v6_routes[duthost] = parse_routes_on_neighbors(duthost, dut_nbrhosts[duthost], 6)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for duthost in frontend_nodes_per_hwsku:
                executor.submit(config_reload, duthost, config_source='minigraph', safe_reload=True,
                                check_intf_up_ports=True, traffic_shift_away=True)

        for duthost in frontend_nodes_per_hwsku:
            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost), "DUT is not in maintenance state")
            assert_only_loopback_routes_announced_to_neighs(
                duthosts,
                duthost,
                dut_nbrhosts[duthost],
                traffic_shift_community,
                "Failed to verify routes on nbr in TSA",
            )
    finally:
        """
        Recover with TSB and verify route advertisement
        """
        # Recover to Normal state
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for duthost in frontend_nodes_per_hwsku:
                executor.submit(run_traffic_shift_cmd_on_dut, duthost, "TSB", should_config_save=True)

        # Verify DUT is in normal state.
        for duthost in frontend_nodes_per_hwsku:
            pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost), "DUT is not in normal state")

        # Wait until all routes are announced to neighbors
        verify_route_on_neighbors(frontend_nodes_per_hwsku, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
        # Bring back the supervisor and line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)
