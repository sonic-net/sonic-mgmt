import logging
import re
from tests.common.devices.eos import EosHost
import json

import ipaddr as ipaddress
import pytest

from bgp_helpers import parse_rib, get_routes_not_announced_to_bgpmon, remove_bgp_neighbors, restore_bgp_neighbors
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_ASIC_ID
from tests.common.helpers.parallel import parallel_run
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('t1', 't2')
]

logger = logging.getLogger(__name__)

TS_NORMAL = "System Mode: Normal"
TS_MAINTENANCE = "System Mode: Maintenance"
TS_INCONSISTENT = "System Mode: Not consistent"
TS_NO_NEIGHBORS = "System Mode: No external neighbors"


@pytest.fixture
def traffic_shift_community(duthost):
    community = duthost.shell('sonic-cfggen -y /etc/sonic/constants.yml -v constants.bgp.traffic_shift_community')[
        'stdout']
    return community


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


def verify_traffic_shift_per_asic(host, outputs, match_result, asic_index):
    prefix = "BGP{} : ".format(
        asic_index) if asic_index != DEFAULT_ASIC_ID else ''
    result_str = "{}{}".format(prefix, match_result)
    if result_str in outputs:
        return True
    else:
        return False


def verify_traffic_shift(host, outputs, match_result):
    for asic_index in host.get_frontend_asic_ids():
        if not verify_traffic_shift_per_asic(host, outputs, match_result, asic_index):
            return "ERROR"

    return match_result


def get_traffic_shift_state(host):
    outputs = host.shell('TSC')['stdout_lines']
    if verify_traffic_shift(host, outputs, TS_NORMAL) != "ERROR":
        return TS_NORMAL
    if verify_traffic_shift(host, outputs, TS_MAINTENANCE) != "ERROR":
        return TS_MAINTENANCE
    if verify_traffic_shift(host, outputs, TS_INCONSISTENT) != "ERROR":
        return TS_INCONSISTENT
    pytest.fail("TSC return unexpected state {}".format("ERROR"))


def parse_routes_on_vsonic(dut_host, neigh_hosts, ip_ver):
    mg_facts = dut_host.minigraph_facts(
        host=dut_host.hostname)['ansible_facts']
    asn = mg_facts['minigraph_bgp_asn']
    all_routes = {}

    host_name_map = {}
    for hostname, neigh_host in list(neigh_hosts.items()):
        host_name_map[neigh_host['host'].hostname] = hostname

    def parse_routes_process_vsonic(node=None, results=None):
        hostname = host_name_map[node['host'].hostname]
        host = node['host']
        peer_ips = node['conf']['bgp']['peers'][asn]

        for ip in peer_ips:
            if ipaddress.IPNetwork(ip).version == 4:
                peer_ip_v4 = ip
            else:
                peer_ip_v6 = ip

        if 4 == ip_ver:
            conf_cmd = "sudo vtysh -c 'configure terminal' -c 'router bgp' -c 'address-family ipv4'  -c \
                       'neighbor {} soft-reconfiguration inbound' ".format(peer_ip_v4)
            bgp_nbr_cmd = "sudo vtysh -c 'show ip bgp neighbors {} received-routes json'".format(
                peer_ip_v4)
        else:
            conf_cmd = "sudo vtysh -c 'configure terminal' -c 'router bgp' -c 'address-family ipv6'  -c \
                       'neighbor {} soft-reconfiguration inbound' ".format(peer_ip_v6)
            bgp_nbr_cmd = "sudo vtysh -c 'show bgp ipv6 neighbors {} received-routes json'".format(
                peer_ip_v6)

        host.shell(conf_cmd)
        res = host.shell(bgp_nbr_cmd)
        routes_json = json.loads(res['stdout'])['receivedRoutes']

        routes = {}
        for a_route in routes_json:
            # empty community string
            routes[a_route] = ""
        all_routes[hostname] = routes

    all_routes = parallel_run(parse_routes_process_vsonic, (), {}, list(neigh_hosts.values()),
                              timeout=120, concurrent_tasks=8)
    return all_routes


def parse_routes_on_eos(dut_host, neigh_hosts, ip_ver):
    """
    Parse the output of 'show ip bgp neigh received-routes' on eos, and store in a dict
    """
    mg_facts = dut_host.minigraph_facts(
        host=dut_host.hostname)['ansible_facts']
    asn = mg_facts['minigraph_bgp_asn']
    all_routes = {}
    BGP_ENTRY_HEADING = r"BGP routing table entry for "
    BGP_COMMUNITY_HEADING = r"Community: "

    # {'VM0122': 'ARISTA11T0',...}
    host_name_map = {}
    for hostname, neigh_host in list(neigh_hosts.items()):
        host_name_map[neigh_host['host'].hostname] = hostname

    # Retrieve the routes on all VMs  in parallel by using a thread poll
    def parse_routes_process(node=None, results=None):
        """
        The process to parse routes on a VM.
        :param neigh_host_item: tuple of hostname and host_conf dict
        :return: no return value
        """
        # get hostname('ARISTA11T0') by VM name('VM0122')
        hostname = host_name_map[node['host'].hostname]
        host = node['host']
        peer_ips = node['conf']['bgp']['peers'][asn]
        for ip in peer_ips:
            if ipaddress.IPNetwork(ip).version == 4:
                peer_ip_v4 = ip
            else:
                peer_ip_v6 = ip
        # The json formatter on EOS consumes too much time (over 40 seconds).
        # So we have to parse the raw output instead json.
        if 4 == ip_ver:
            cmd = "show ip bgp neighbors {} received-routes detail | grep -E \"{}|{}\""\
                  .format(peer_ip_v4, BGP_ENTRY_HEADING,  BGP_COMMUNITY_HEADING)
            cmd_backup = ""
        else:
            cmd = "show ipv6 bgp peers {} received-routes detail | grep -E \"{}|{}\""\
                  .format(peer_ip_v6, BGP_ENTRY_HEADING, BGP_COMMUNITY_HEADING)
            # For compatibility on EOS of old version
            cmd_backup = "show ipv6 bgp neighbors {} received-routes detail | grep -E \"{}|{}\""\
                         .format(peer_ip_v6, BGP_ENTRY_HEADING, BGP_COMMUNITY_HEADING)
        res = host.eos_command(commands=[cmd], module_ignore_errors=True)
        if res['failed'] and cmd_backup != "":
            res = host.eos_command(
                commands=[cmd_backup], module_ignore_errors=True)
        pytest_assert(
            not res['failed'], "Failed to retrieve routes from VM {}".format(hostname))
        routes = {}
        entry = None
        for line in res['stdout_lines'][0]:
            addr = re.findall(BGP_ENTRY_HEADING + r"(.+)", line)
            if addr:
                if entry:
                    routes[entry] = ""
                    entry = None
                entry = addr[0]
            community = re.findall(BGP_COMMUNITY_HEADING + r"(.+)", line)
            if community:
                if entry:
                    routes[entry] = community[0]
                    entry = None
                    community = ""
        if entry:
            routes[entry] = community
        results[hostname] = routes
    try:
        all_routes = parallel_run(parse_routes_process, (), {}, list(
            neigh_hosts.values()), timeout=180, concurrent_tasks=8)
    except BaseException as err:
        logger.error(
            'Failed to get routes info from VMs. Got error: {}\n\nTrying one more time.'.format(err))
        all_routes = parallel_run(parse_routes_process, (), {}, list(
            neigh_hosts.values()), timeout=180, concurrent_tasks=8)
    return all_routes


def parse_routes_on_neighbors(dut_host, neigh_hosts, ip_ver):
    if isinstance(list(neigh_hosts.items())[0][1]['host'], EosHost):
        routes_on_all_nbrs = parse_routes_on_eos(dut_host, neigh_hosts, ip_ver)
    else:
        routes_on_all_nbrs = parse_routes_on_vsonic(
            dut_host, neigh_hosts, ip_ver)
    return routes_on_all_nbrs


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


def verify_current_routes_announced_to_neighs(dut_host, neigh_hosts, orig_routes_on_all_nbrs,
                                              cur_routes_on_all_nbrs, ip_ver):
    """
    Verify all the original routes are announced to neighbors after TSB
    """
    logger.info(
        "Verifying all the original routes(ipv{}) are announced to bgp neighbors".format(ip_ver))
    cur_routes_on_all_nbrs.update(
        parse_routes_on_neighbors(dut_host, neigh_hosts, ip_ver))
    # Compare current routes after TSB with original routes advertised to neighbors
    if cur_routes_on_all_nbrs != orig_routes_on_all_nbrs:
        return False
    return True


def check_and_log_routes_diff(duthost, neigh_hosts, orig_routes_on_all_nbrs, cur_routes_on_all_nbrs, ip_ver):
    cur_nbrs = set(cur_routes_on_all_nbrs.keys())
    orig_nbrs = set(orig_routes_on_all_nbrs.keys())
    if cur_nbrs != orig_nbrs:
        logger.warn("Neighbor list mismatch: {}".format(cur_nbrs ^ orig_nbrs))
        return False

    routes_dut = parse_rib(duthost, ip_ver)
    all_diffs_in_host_aspath = True
    for hostname in list(orig_routes_on_all_nbrs.keys()):
        if orig_routes_on_all_nbrs[hostname] != cur_routes_on_all_nbrs[hostname]:
            routes_diff = set(orig_routes_on_all_nbrs[hostname]) ^ set(
                cur_routes_on_all_nbrs[hostname])
            for route in routes_diff:
                if route not in list(routes_dut.keys()):
                    all_diffs_in_host_aspath = False
                    logger.warn(
                        "Missing route on host {}: {}".format(hostname, route))
                    continue
                aspaths = routes_dut[route]
                # Filter out routes announced by this neigh
                skip = False
                if isinstance(list(neigh_hosts.items())[0][1]['host'], EosHost):
                    for aspath in aspaths:
                        if str(neigh_hosts[hostname]['conf']['bgp']['asn']) in aspath:
                            logger.debug(
                                "Skipping route {} on host {}".format(route, hostname))
                            skip = True
                            break
                    if not skip:
                        all_diffs_in_host_aspath = False
                        if route in orig_routes_on_all_nbrs[hostname]:
                            logger.warn(
                                "Missing route on host {}: {}".format(hostname, route))
                        else:
                            logger.warn(
                                "Additional route on host {}: {}".format(hostname, route))

    return all_diffs_in_host_aspath


def verify_loopback_route_with_community(dut_host, neigh_hosts, ip_ver, community):
    logger.info("Verifying only loopback routes are announced to bgp neighbors")
    mg_facts = dut_host.minigraph_facts(
        host=dut_host.hostname)['ansible_facts']
    for i in range(0, 2):
        addr = mg_facts['minigraph_lo_interfaces'][i]['addr']
        if ipaddress.IPNetwork(addr).version == 4:
            lo_addr_v4 = ipaddress.IPNetwork(addr)
        else:
            # The IPv6 Loopback announced to neighbors is /64
            lo_addr_v6 = ipaddress.IPNetwork(addr + "/64")
    if 4 == ip_ver:
        lo_addr = lo_addr_v4
    else:
        lo_addr = lo_addr_v6
    routes_on_all_nbrs = parse_routes_on_neighbors(
        dut_host, neigh_hosts, ip_ver)
    for hostname, routes in list(routes_on_all_nbrs.items()):
        logger.info("Verifying only loopback routes(ipv{}) are announced to {}".format(
            ip_ver, hostname))
        for prefix, received_community in list(routes.items()):
            if ipaddress.IPNetwork(prefix) != lo_addr:
                logger.warn("route for {} is found on {}, which is not in loopback address".format(
                    prefix, hostname))
                return False
            if isinstance(list(neigh_hosts.items())[0][1]['host'], EosHost):
                if received_community != community:
                    logger.warn("community for route {} is unexpected {}".format(
                        prefix, received_community))
                    return False
    return True


def verify_only_loopback_routes_are_announced_to_neighs(dut_host, neigh_hosts, community):
    """
    Verify only loopback routes with certain community are announced to neighs in TSA
    """
    return verify_loopback_route_with_community(dut_host, neigh_hosts, 4, community) and \
        verify_loopback_route_with_community(
            dut_host, neigh_hosts, 6, community)


# API to check if the image has support for BGP_DEVICE_GLOBAL table in the configDB
def check_tsa_persistence_support(duthost):
    # For multi-asic, check DB in one of the namespaces
    asic_index = 0 if duthost.is_multi_asic else DEFAULT_ASIC_ID
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    sonic_db_cmd = "sonic-db-cli {}".format("-n " +
                                            namespace if namespace else "")
    tsa_in_configdb = duthost.shell('{} CONFIG_DB HGET "BGP_DEVICE_GLOBAL|STATE" "tsa_enabled"'.format(sonic_db_cmd),
                                    module_ignore_errors=False)['stdout_lines']
    if not tsa_in_configdb:
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

        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(duthost, nbrhosts_to_dut,
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
                                   bgpmon_setup_teardown, nbrhosts):
    """
    Test TSA, TSB, TSC with no neighbors on ASIC0 in case of multi-asic and single-asic.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    bgp_neighbors = {}
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

        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(duthost, nbrhosts_to_dut,
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

        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(duthost, nbrhosts_to_dut,
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
