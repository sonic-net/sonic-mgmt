import logging
import pytest
import random
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_ASIC_ID
from tests.common.utilities import wait_until
from route_checker import verify_only_loopback_routes_are_announced_to_neighs, parse_routes_on_neighbors
from route_checker import verify_current_routes_announced_to_neighs, check_and_log_routes_diff

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)

IDF_ISOLATED_NO_EXPORT = "IDF isolation state: isolated_no_export"
IDF_ISOLATED_WITHDRAW_ALL = "IDF isolation state: isolated_withdraw_all"
IDF_UNISOLATED = "IDF isolation state: unisolated"


def verify_idf_isolation_state_per_asic(host, outputs, match_result, asic_index):
    prefix = "BGP{}: ".format(
        asic_index) if asic_index != DEFAULT_ASIC_ID else ''
    result_str = "{}{}".format(prefix, match_result)
    if result_str in outputs:
        return True
    else:
        return False


def verify_idf_isolation_state(host, outputs, match_result):
    for asic_index in host.get_frontend_asic_ids():
        if not verify_idf_isolation_state_per_asic(host, outputs, match_result, asic_index):
            return "ERROR"

    return match_result


def get_idf_isolation_state(host, cmd="sudo idf_isolation status"):
    outputs = host.shell(cmd)['stdout_lines']
    if verify_idf_isolation_state(host, outputs, IDF_ISOLATED_NO_EXPORT) != "ERROR":
        return IDF_ISOLATED_NO_EXPORT
    if verify_idf_isolation_state(host, outputs, IDF_ISOLATED_WITHDRAW_ALL) != "ERROR":
        return IDF_ISOLATED_WITHDRAW_ALL
    if verify_idf_isolation_state(host, outputs, IDF_UNISOLATED) != "ERROR":
        return IDF_UNISOLATED
    pytest.fail("{} return unexpected state {}".format(cmd, "ERROR"))


# API to check if the image has support for BGP_DEVICE_GLOBAL table in the configDB
def check_idf_isolation_support(duthost):
    # For multi-asic, check DB in one of the namespaces
    asic_index = 0 if duthost.is_multi_asic else DEFAULT_ASIC_ID
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    sonic_db_cmd = "sonic-db-cli {}".format("-n " +
                                            namespace if namespace else "")
    tsa_in_configdb = duthost.shell(
        '{} CONFIG_DB HGET "BGP_DEVICE_GLOBAL|STATE" "idf_isolation_state"'.format(sonic_db_cmd),
        module_ignore_errors=False)['stdout_lines']
    if not tsa_in_configdb:
        return False
    return True


def dut_nbrs(duthost, nbrhosts):
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    nbrs_to_dut = {}
    for host in list(nbrhosts.keys()):
        if host in mg_facts['minigraph_devices']:
            new_nbrhost = {host: nbrhosts[host]}
            nbrs_to_dut.update(new_nbrhost)
    return nbrs_to_dut


# Get one random downlink linecard in a T2 chassis
@pytest.fixture(scope="module")
def rand_one_downlink_duthost(duthosts, tbinfo):
    if tbinfo['topo']['type'] != 't2':
        return []

    dl_duthosts = []
    for dut in duthosts.frontend_nodes:
        minigraph_facts = dut.get_extended_minigraph_facts(tbinfo)
        minigraph_neighbors = minigraph_facts['minigraph_neighbors']
        for key, value in list(minigraph_neighbors.items()):
            if 'T1' in value['name']:
                dl_duthosts.append(dut)
                break
    dut = random.sample(dl_duthosts, 1)
    if dut:
        return dut[0]
    pytest.skip("Skipping test - No downlink linecards found")


def test_idf_isolated_no_export(rand_one_downlink_duthost,
                                nbrhosts, traffic_shift_community):
    """
    Test IDF isolation using no-export community
    Verify all routes to T1 tagged with no-export community
    """
    duthost = rand_one_downlink_duthost
    if not check_idf_isolation_support(duthost):
        pytest.skip("Sequential IDF isolation is not supported in the image")

    pytest_assert(IDF_UNISOLATED == get_idf_isolation_state(duthost),
                  "DUT is not in unisolated state")
    nbrs = dut_nbrs(duthost, nbrhosts)
    orig_v4_routes = parse_routes_on_neighbors(duthost, nbrs, 4)
    orig_v6_routes = parse_routes_on_neighbors(duthost, nbrs, 6)
    up_bgp_neighbors = duthost.get_bgp_neighbors_per_asic("established")
    try:
        # Issue command to isolate with no export community on DUT
        duthost.shell("sudo idf_isolation isolated_no_export")
        # Verify DUT is in isolated-no-export state.
        pytest_assert(IDF_ISOLATED_NO_EXPORT == get_idf_isolation_state(duthost),
                      "DUT is not in isolated_no_export state")
        exp_community = ["no-export", traffic_shift_community]
        cur_v4_routes = {}
        cur_v6_routes = {}
        # verify sessions are established
        pytest_assert(wait_until(300, 10, 0,
                                 duthost.check_bgp_session_state_all_asics, up_bgp_neighbors, "established"),
                                 "All BGP sessions are not up. No point in continuing the test")
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrs, orig_v4_routes, cur_v4_routes, 4, exp_community):
            if not check_and_log_routes_diff(duthost, nbrs, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrs, orig_v6_routes, cur_v6_routes, 6, exp_community):
            if not check_and_log_routes_diff(duthost, nbrs, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")
    finally:
        # Recover to unisolated state
        duthost.shell("sudo idf_isolation unisolated")
        pytest_assert(IDF_UNISOLATED == get_idf_isolation_state(duthost),
                      "DUT is not in unisolated state")
        cur_v4_routes = {}
        cur_v6_routes = {}
        # verify sessions are established
        pytest_assert(wait_until(300, 10, 0,
                                 duthost.check_bgp_session_state_all_asics, up_bgp_neighbors, "established"),
                                 "All BGP sessions are not up. No point in continuing the test")
        # Verify that all routes seen at the start of the test are re-advertised to neighbors
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrs, orig_v4_routes, cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, nbrs, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrs, orig_v6_routes, cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, nbrs, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")


def test_idf_isolated_withdraw_all(duthosts, rand_one_downlink_duthost,
                                   nbrhosts, traffic_shift_community):
    """
    Test IDF isolation using withdraw_all option
    Verify all routes except loopback routes are withdrawn from T1
    """
    duthost = rand_one_downlink_duthost
    if not check_idf_isolation_support(duthost):
        pytest.skip("IDF isolation is not supported in the image")

    pytest_assert(IDF_UNISOLATED == get_idf_isolation_state(duthost),
                  "DUT is not in unisolated state")
    nbrs = dut_nbrs(duthost, nbrhosts)
    orig_v4_routes = parse_routes_on_neighbors(duthost, nbrs, 4)
    orig_v6_routes = parse_routes_on_neighbors(duthost, nbrs, 6)
    up_bgp_neighbors = duthost.get_bgp_neighbors_per_asic("established")
    try:
        # Issue command to isolate by withdrawing all routes
        duthost.shell("sudo idf_isolation isolated_withdraw_all")
        # Verify DUT is in isolated-withdraw-all state.
        pytest_assert(IDF_ISOLATED_WITHDRAW_ALL == get_idf_isolation_state(duthost),
                      "DUT is not in isolated_withdraw_all state")
        # verify sessions are established
        pytest_assert(wait_until(300, 10, 0,
                                 duthost.check_bgp_session_state_all_asics, up_bgp_neighbors, "established"),
                                 "All BGP sessions are not up. No point in continuing the test")
        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(duthosts, duthost, nbrs,
                                                                          traffic_shift_community),
                      "Failed to verify only loopback route in isolated_withdraw_all state")
    finally:
        # Recover to unisolated state
        duthost.shell("sudo idf_isolation unisolated")
        pytest_assert(IDF_UNISOLATED == get_idf_isolation_state(duthost),
                      "DUT is not in unisolated state")
        cur_v4_routes = {}
        cur_v6_routes = {}
        # verify sessions are established
        pytest_assert(wait_until(300, 10, 0,
                                 duthost.check_bgp_session_state_all_asics, up_bgp_neighbors, "established"),
                                 "All BGP sessions are not up. No point in continuing the test")
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrs, orig_v4_routes, cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, nbrs, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrs, orig_v6_routes, cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, nbrs, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")


@pytest.mark.disable_loganalyzer
def test_idf_isolation_no_export_with_config_reload(rand_one_downlink_duthost,
                                                    nbrhosts, traffic_shift_community):
    """
    Test IDF isolation using no-export community after config save and config reload
    Verify all routes to T1 tagged with no-export community
    """
    duthost = rand_one_downlink_duthost
    if not check_idf_isolation_support(duthost):
        pytest.skip("IDF isolation is not supported in the image")

    # Ensure that the DUT is not in maintenance already before start of the test
    pytest_assert(IDF_UNISOLATED == get_idf_isolation_state(duthost),
                  "DUT is not in normal state")
    nbrs = dut_nbrs(duthost, nbrhosts)
    orig_v4_routes = parse_routes_on_neighbors(duthost, nbrs, 4)
    orig_v6_routes = parse_routes_on_neighbors(duthost, nbrs, 6)
    up_bgp_neighbors = duthost.get_bgp_neighbors_per_asic("established")
    try:
        # Issue command to isolate with no export community on DUT
        duthost.shell("sudo idf_isolation isolated_no_export")
        duthost.shell('sudo config save -y')
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

        # Verify DUT is in isolated-no-export state.
        pytest_assert(IDF_ISOLATED_NO_EXPORT == get_idf_isolation_state(duthost),
                      "DUT is not isolated_no_export state")
        exp_community = ["no-export", traffic_shift_community]
        cur_v4_routes = {}
        cur_v6_routes = {}
        # verify sessions are established
        pytest_assert(wait_until(300, 10, 0,
                                 duthost.check_bgp_session_state_all_asics, up_bgp_neighbors, "established"),
                                 "All BGP sessions are not up. No point in continuing the test")
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrs, orig_v4_routes, cur_v4_routes, 4, exp_community):
            if not check_and_log_routes_diff(duthost, nbrs, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrs, orig_v6_routes, cur_v6_routes, 6, exp_community):
            if not check_and_log_routes_diff(duthost, nbrs, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")
    finally:
        """
        Test IDF unisolation after config save and config reload
        Verify all original routes are advertised back to all neighbors
        """
        duthost.shell("sudo idf_isolation unisolated")
        duthost.shell('sudo config save -y')
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

        pytest_assert(IDF_UNISOLATED == get_idf_isolation_state(duthost),
                      "DUT is not isolated_no_export state")
        cur_v4_routes = {}
        cur_v6_routes = {}
        # verify sessions are established
        pytest_assert(wait_until(300, 10, 0,
                                 duthost.check_bgp_session_state_all_asics, up_bgp_neighbors, "established"),
                                 "All BGP sessions are not up. No point in continuing the test")
        # Verify that all routes seen at the start of the test are re-advertised to neighbors
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrs, orig_v4_routes, cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, nbrs, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrs, orig_v6_routes, cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, nbrs, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")


@pytest.mark.disable_loganalyzer
def test_idf_isolation_withdraw_all_with_config_reload(duthosts, rand_one_downlink_duthost, nbrhosts,
                                                       traffic_shift_community):
    """
    Test IDF isolation using withdraw all option after config save and config reload
    Verify all routes except loopback routes are withdrawn from T1
    """
    duthost = rand_one_downlink_duthost
    if not check_idf_isolation_support(duthost):
        pytest.skip("IDF isolation is not supported in the image")

    # Ensure that the DUT is not in maintenance already before start of the test
    pytest_assert(IDF_UNISOLATED == get_idf_isolation_state(duthost),
                  "DUT is not in normal state")
    nbrs = dut_nbrs(duthost, nbrhosts)
    try:
        # Get all routes on neighbors before doing TSA
        orig_v4_routes = parse_routes_on_neighbors(duthost, nbrs, 4)
        orig_v6_routes = parse_routes_on_neighbors(duthost, nbrs, 6)
        up_bgp_neighbors = duthost.get_bgp_neighbors_per_asic("established")

        # Issue command to isolate with no export community on DUT
        duthost.shell("sudo idf_isolation isolated_withdraw_all")
        duthost.shell('sudo config save -y')
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

        # Verify DUT is in isolated-withdraw-all state.
        pytest_assert(IDF_ISOLATED_WITHDRAW_ALL == get_idf_isolation_state(duthost),
                      "DUT is not isolated_no_export state")
        # verify sessions are established
        pytest_assert(wait_until(300, 10, 0,
                                 duthost.check_bgp_session_state_all_asics, up_bgp_neighbors, "established"),
                                 "All BGP sessions are not up. No point in continuing the test")
        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(duthosts, duthost, nbrs,
                                                                          traffic_shift_community),
                      "Failed to verify only loopback route in isolated_withdraw_all state")
    finally:
        """
        Recover to unisolated state
        Verify all original routes are re-advertised to all neighbors
        """
        duthost.shell("sudo idf_isolation unisolated")
        duthost.shell('sudo config save -y')
        pytest_assert(IDF_UNISOLATED == get_idf_isolation_state(duthost),
                      "DUT is not isolated_no_export state")
        # Wait until all routes are announced to neighbors
        cur_v4_routes = {}
        cur_v6_routes = {}
        # verify sessions are established
        pytest_assert(wait_until(300, 10, 0,
                                 duthost.check_bgp_session_state_all_asics, up_bgp_neighbors, "established"),
                                 "All BGP sessions are not up. No point in continuing the test")
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrs, orig_v4_routes, cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs,
                          duthost, nbrs, orig_v6_routes, cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")
