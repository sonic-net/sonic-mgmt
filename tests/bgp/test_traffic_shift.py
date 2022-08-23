import pytest
import logging
import ipaddr as ipaddress
from bgp_helpers import parse_rib, get_routes_not_announced_to_bgpmon,remove_bgp_neighbors,restore_bgp_neighbors
from tests.common.helpers.constants import DEFAULT_ASIC_ID
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from multiprocessing.dummy import Pool as ThreadPool
from tests.common import config_reload
import re

from tests.common.platform.processes_utils import wait_critical_processes

pytestmark = [
    pytest.mark.topology('t1','t2')
]

logger = logging.getLogger(__name__)

TS_NORMAL = "System Mode: Normal"
TS_MAINTENANCE = "System Mode: Maintenance"
TS_INCONSISTENT = "System Mode: Not consistent"
TS_NO_NEIGHBORS = "System Mode: No external neighbors"

@pytest.fixture
def traffic_shift_community(duthost):
    community = duthost.shell('sonic-cfggen -y /etc/sonic/constants.yml -v constants.bgp.traffic_shift_community')['stdout']
    return community

def verify_traffic_shift_per_asic(host, outputs, match_result, asic_index):
    prefix = "BGP{} : ".format(asic_index) if asic_index != DEFAULT_ASIC_ID else ''
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
    if verify_traffic_shift(host, outputs, TS_NORMAL) is not "ERROR":
        return TS_NORMAL
    if verify_traffic_shift(host, outputs, TS_MAINTENANCE) is not "ERROR":
        return TS_MAINTENANCE
    if verify_traffic_shift(host, outputs, TS_INCONSISTENT) is not "ERROR":
        return TS_INCONSISTENT
    pytest.fail("TSC return unexpected state {}".format("ERROR"))

def parse_routes_on_eos(dut_host, neigh_hosts, ip_ver):
    """
    Parse the output of 'show ip bgp neigh received-routes' on eos, and store in a dict
    """
    mg_facts = dut_host.minigraph_facts(host=dut_host.hostname)['ansible_facts']
    asn = mg_facts['minigraph_bgp_asn']
    all_routes = {}
    BGP_ENTRY_HEADING = r"BGP routing table entry for "
    BGP_COMMUNITY_HEADING = r"Community: "
    # Retrieve the routes on all VMs  in parallel by using a thread poll
    neigh_host_items = neigh_hosts.items()
    def parse_routes_process(neigh_host_item):
        """
        The process to parse routes on a VM.
        :param neigh_host_item: tuple of hostname and host_conf dict
        :return: no return value
        """
        hostname = neigh_host_item[0]
        host_conf = neigh_host_item[1]
        host = host_conf['host']
        peer_ips = host_conf['conf']['bgp']['peers'][asn]
        for ip in peer_ips:
            if ipaddress.IPNetwork(ip).version == 4:
                peer_ip_v4 = ip
            else:
                peer_ip_v6 = ip
        # The json formatter on EOS consumes too much time (over 40 seconds).
        # So we have to parse the raw output instead json.
        if 4 == ip_ver:
            cmd = "show ip bgp neighbors {} received-routes detail | grep -E \"{}|{}\"".format(peer_ip_v4,
                                                                                               BGP_ENTRY_HEADING,
                                                                                               BGP_COMMUNITY_HEADING)
            cmd_backup = ""
        else:
            cmd = "show ipv6 bgp peers {} received-routes detail | grep -E \"{}|{}\"".format(peer_ip_v6,
                                                                                             BGP_ENTRY_HEADING,
                                                                                             BGP_COMMUNITY_HEADING)
            # For compatibility on EOS of old version
            cmd_backup = "show ipv6 bgp neighbors {} received-routes detail | grep -E \"{}|{}\"".format(peer_ip_v6,
                                                                                                        BGP_ENTRY_HEADING,
                                                                                                        BGP_COMMUNITY_HEADING)
        res = host.eos_command(commands=[cmd], module_ignore_errors=True)
        if res['failed'] and cmd_backup != "":
            res = host.eos_command(commands=[cmd_backup], module_ignore_errors=True)
        pytest_assert(not res['failed'], "Failed to retrieve routes from VM {}".format(hostname))
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
        all_routes[hostname] = routes
    pool = ThreadPool()
    # Run the parse routes process on all VMs in parallel.
    pool.map(parse_routes_process, neigh_host_items)
    pool.close()
    pool.join()
    return all_routes

def verify_all_routes_announce_to_neighs(dut_host, neigh_hosts, routes_dut, ip_ver):
    """
    Verify all routes are announced to neighbors in TSB
    """
    logger.info("Verifying all routes(ipv{}) are announced to bgp neighbors".format(ip_ver))
    routes_on_all_eos = parse_routes_on_eos(dut_host, neigh_hosts, ip_ver)
    # Check routes on all neigh
    for hostname, routes in routes_on_all_eos.iteritems():
        logger.info("Verifying all routes(ipv{}) are announced to {}".format(ip_ver, hostname))
        for route, aspaths in routes_dut.iteritems():
            # Filter out routes announced by this neigh
            skip = False
            for aspath in aspaths:
                if str(neigh_hosts[hostname]['conf']['bgp']['asn']) in aspath:
                    skip = True
                    break
            if skip:
                continue
            if route not in routes.keys():
                logger.warn("{} not found on {}".format(route, hostname))
                return False
    return True

def verify_loopback_route_with_community(dut_host, neigh_hosts, ip_ver, community):
    logger.info("Verifying only loopback routes are announced to bgp neighbors")
    mg_facts = dut_host.minigraph_facts(host=dut_host.hostname)['ansible_facts']
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
    routes_on_all_eos = parse_routes_on_eos(dut_host, neigh_hosts, ip_ver)
    for hostname, routes in routes_on_all_eos.iteritems():
        logger.info("Verifying only loopback routes(ipv{}) are announced to {}".format(ip_ver, hostname))
        for prefix, received_community in routes.iteritems():
            if ipaddress.IPNetwork(prefix) != lo_addr:
                logger.warn("route for {} is found on {}, which is not in loopback address".format(prefix, hostname))
                return False
            if received_community != community:
                logger.warn("community for route {} is unexpected {}".format(prefix, received_community))
                return False
    return True

def verify_only_loopback_routes_are_announced_to_neighs(dut_host, neigh_hosts, community):
    """
    Verify only loopback routes with certain community are announced to neighs in TSA
    """
    return verify_loopback_route_with_community(dut_host, neigh_hosts, 4, community) and \
        verify_loopback_route_with_community(dut_host, neigh_hosts, 6, community)

# API to check if the image has support for BGP_DEVICE_GLOBAL table in the configDB
def check_tsa_persistence_support(duthost):
    # For multi-asic, check DB in one of the namespaces
    asic_index = 0 if duthost.is_multi_asic else DEFAULT_ASIC_ID
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    sonic_db_cmd = "sonic-db-cli {}".format("-n " + namespace if namespace else "")
    tsa_in_configdb = duthost.shell('{} CONFIG_DB HGET "BGP_DEVICE_GLOBAL|STATE" "tsa_enabled"'.format(sonic_db_cmd), module_ignore_errors=False)['stdout_lines']    
    if not tsa_in_configdb:
        return False
    return True

def test_TSA(duthost, ptfhost, nbrhosts, bgpmon_setup_teardown, traffic_shift_community):
    """
    Test TSA
    Verify all routes are announced to bgp monitor, and only loopback routes are announced to neighs
    """
    try:
        # Issue TSA on DUT
        duthost.shell("TSA")
        # Verify DUT is in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                      "DUT is not in maintenance state")
        pytest_assert(get_routes_not_announced_to_bgpmon(duthost, ptfhost)==[],
                      "Not all routes are announced to bgpmon")
        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(duthost, nbrhosts, traffic_shift_community),
                      "Failed to verify routes on eos in TSA")
    finally:
        # Recover to Normal state
        duthost.shell("TSB")

def test_TSB(duthost, ptfhost, nbrhosts, bgpmon_setup_teardown):
    """
    Test TSB.
    Establish BGP session between PTF and DUT, and verify all routes are announced to bgp monitor,
    and all routes are announced to neighbors
    """
    # Issue TSB on DUT
    duthost.shell("TSB")
    # Verify DUT is in normal state.
    pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                  "DUT is not in normal state")
    pytest_assert(get_routes_not_announced_to_bgpmon(duthost, ptfhost)==[],
                  "Not all routes are announced to bgpmon")
    pytest_assert(verify_all_routes_announce_to_neighs(duthost, nbrhosts, parse_rib(duthost, 4), 4),
                  "Not all ipv4 routes are announced to neighbors")
    pytest_assert(verify_all_routes_announce_to_neighs(duthost, nbrhosts, parse_rib(duthost, 6), 6),
                  "Not all ipv6 routes are announced to neighbors")

def test_TSA_B_C_with_no_neighbors(duthost, bgpmon_setup_teardown, nbrhosts, tbinfo):
    """
    Test TSA, TSB, TSC with no neighbors on ASIC0 in case of multi-asic and single-asic.
    """
    bgp_neighbors = {}
    asic_index = 0 if duthost.is_multi_asic else DEFAULT_ASIC_ID


    try:

        routes_4 = parse_rib(duthost, 4)
        routes_6 = parse_rib(duthost, 6)
        # Remove the Neighbors for the particular BGP instance
        bgp_neighbors = remove_bgp_neighbors(duthost, asic_index)

        # Check the traffic state
        output = duthost.shell("TSC")['stdout_lines']

        # Verify DUT is in Normal state, and ASIC0 has no neighbors message.
        pytest_assert(verify_traffic_shift_per_asic(duthost, output, TS_NO_NEIGHBORS, asic_index), "ASIC is not having no neighbors")

    finally:
        # Restore BGP neighbors
        restore_bgp_neighbors(duthost, asic_index, bgp_neighbors)

        # Recover to Normal state
        duthost.shell("TSB")
        wait_critical_processes(duthost)

        # Wait until bgp sessions are established on DUT
        pytest_assert(wait_until(100, 10, 0, duthost.check_bgp_session_state, bgp_neighbors.keys()),
                      "Not all BGP sessions are established on DUT")

        # Wait until all routes are announced to neighbors
        pytest_assert(wait_until(300, 3, 0, verify_all_routes_announce_to_neighs,duthost, nbrhosts, routes_4, 4),
                      "Not all ipv4 routes are announced to neighbors")
        pytest_assert(wait_until(300, 3, 0, verify_all_routes_announce_to_neighs,duthost, nbrhosts, routes_6, 6),
                      "Not all ipv6 routes are announced to neighbors")

def test_TSA_TSB_with_config_reload(duthost, ptfhost, nbrhosts, bgpmon_setup_teardown, traffic_shift_community):
    """
    Test TSA after config save and config reload
    Verify all routes are announced to bgp monitor, and only loopback routes are announced to neighs
    """
    if not check_tsa_persistence_support(duthost):
        pytest.skip("TSA persistence not supported in the image")

    try:
        # Issue TSA on DUT
        duthost.shell("TSA")
        duthost.shell('sudo config save -y')
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

        # Verify DUT is in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                      "DUT is not in maintenance state")
        pytest_assert(get_routes_not_announced_to_bgpmon(duthost, ptfhost)==[],
                      "Not all routes are announced to bgpmon")
        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(duthost, nbrhosts, traffic_shift_community),
                      "Failed to verify routes on eos in TSA")
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
        pytest_assert(verify_all_routes_announce_to_neighs(duthost, nbrhosts, parse_rib(duthost, 4), 4),
                    "Not all ipv4 routes are announced to neighbors")
        pytest_assert(verify_all_routes_announce_to_neighs(duthost, nbrhosts, parse_rib(duthost, 6), 6),
                    "Not all ipv6 routes are announced to neighbors")

def test_load_minigraph_with_traffic_shift_away(duthost, ptfhost, nbrhosts, bgpmon_setup_teardown, traffic_shift_community):
    """
    Test load_minigraph --traffic-shift-away
    Verify all routes are announced to bgp monitor, and only loopback routes are announced to neighs
    """
    if not check_tsa_persistence_support(duthost):
        pytest.skip("TSA persistence not supported in the image")

    try:
        config_reload(duthost, config_source='minigraph', safe_reload=True, check_intf_up_ports=True, traffic_shift_away=True)

        # Verify DUT is in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                      "DUT is not in maintenance state")
        pytest_assert(get_routes_not_announced_to_bgpmon(duthost, ptfhost)==[],
                      "Not all routes are announced to bgpmon")
        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(duthost, nbrhosts, traffic_shift_community),
                      "Failed to verify routes on eos in TSA")
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
        pytest_assert(verify_all_routes_announce_to_neighs(duthost, nbrhosts, parse_rib(duthost, 4), 4),
                  "Not all ipv4 routes are announced to neighbors")
        pytest_assert(verify_all_routes_announce_to_neighs(duthost, nbrhosts, parse_rib(duthost, 6), 6),
                  "Not all ipv6 routes are announced to neighbors")
