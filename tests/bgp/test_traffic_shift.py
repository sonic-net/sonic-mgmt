import pytest
import logging
import json
import time
import ipaddr as ipaddress
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_tcp_connection
from jinja2 import Template
import re

pytestmark = [
    pytest.mark.topology('t1')
]

logger = logging.getLogger(__name__)

TS_NORMAL = "System Mode: Normal"
TS_MAINTENANCE = "System Mode: Maintenance"
TS_INCONSISTENT = "System Mode: Not consistent"

DUMP_FILE = "/tmp/bgp_monitor_dump.log"
CUSTOM_DUMP_SCRIPT = "bgp/bgp_monitor_dump.py"
CUSTOM_DUMP_SCRIPT_DEST = "/usr/share/exabgp/bgp_monitor_dump.py"
BGP_MONITOR_PORT = 7000
BGP_MONITOR_NAME = "bgp_monitor"
BGP_ANNOUNCE_TIME = 30 #should be enough to receive and parse bgp updates

# TODO: remove me
BGPMON_TEMPLATE_FILE = 'bgp/templates/bgp_template.j2'
BGPMON_CONFIG_FILE = '/tmp/bgpmon.json'

@pytest.fixture
def traffic_shift_community(duthost):
    community = duthost.shell('sonic-cfggen -y /etc/sonic/constants.yml -v constants.bgp.traffic_shift_community')['stdout']
    return community

@pytest.fixture
def common_setup_teardown(ptfhost, duthost, localhost):
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    dut_lo_addr = mg_facts['minigraph_lo_interfaces'][0]['addr']
    dut_mgmt_ip = mg_facts['minigraph_mgmt_interface']['addr']
    asn = mg_facts['minigraph_bgp_asn']
    peer_addr = ptfhost.mgmt_ip
    # TODO: Add a common method to load BGPMON config for test_bgpmon and test_traffic_shift
    logger.info("Configuring bgp monitor session on DUT")
    bgpmon_args = {
        'db_table_name': 'BGP_MONITORS',
        'peer_addr': peer_addr,
        'asn': asn,
        'local_addr': dut_lo_addr,
        'peer_name': BGP_MONITOR_NAME
    }
    bgpmon_template = Template(open(BGPMON_TEMPLATE_FILE).read())
    duthost.copy(content=bgpmon_template.render(**bgpmon_args),
                 dest=BGPMON_CONFIG_FILE)

    # Add a static route via mgmt interface on ptf
    ptfhost.shell('ip route add {}/32 via {} dev mgmt'.format(dut_lo_addr, dut_mgmt_ip))
    logger.info("Starting bgp monitor session on PTF")
    ptfhost.file(path=DUMP_FILE, state="absent")
    ptfhost.copy(src=CUSTOM_DUMP_SCRIPT, dest=CUSTOM_DUMP_SCRIPT_DEST)
    ptfhost.exabgp(name=BGP_MONITOR_NAME,
                   state="started",
                   local_ip=peer_addr,
                   router_id=peer_addr,
                   peer_ip=dut_lo_addr,
                   local_asn=asn,
                   peer_asn=asn,
                   port=BGP_MONITOR_PORT,
                   dump_script=CUSTOM_DUMP_SCRIPT_DEST)
    pytest_assert(wait_tcp_connection(localhost, ptfhost.mgmt_ip, BGP_MONITOR_PORT),
                  "Failed to start bgp monitor session on PTF")
    yield
    # Cleanup bgp monitor
    duthost.shell("redis-cli -n 4 -c DEL 'BGP_MONITORS|{}'".format(peer_addr))
    ptfhost.exabgp(name=BGP_MONITOR_NAME, state="absent")
    ptfhost.file(path=CUSTOM_DUMP_SCRIPT_DEST, state="absent")
    ptfhost.file(path=DUMP_FILE, state="absent")
    ptfhost.shell('ip route flush {}/32'.format(dut_lo_addr))

def get_traffic_shift_state(host):
    outputs = host.shell('TSC')['stdout_lines']
    for out in outputs:
        if TS_NORMAL == out.strip():
            return TS_NORMAL
        if TS_MAINTENANCE == out.strip():
            return TS_MAINTENANCE
        if TS_INCONSISTENT == out.strip():
            return TS_INCONSISTENT
    pytest.fail("TSC return unexpected state {}".format(out))

def parse_exabgp_dump(host):
    """
    Parse the dump file of exabgp, and build a set for checking routes
    """
    routes = set()
    output_lines = host.shell("cat {}".format(DUMP_FILE))['stdout_lines']
    for line in output_lines:
        routes.add(line)
    return routes

def parse_rib(host, ip_ver):
    """
    Parse output of 'show bgp ipv4/6' and parse into a dict for checking routes
    """
    routes = {}
    cmd = "vtysh -c \"show bgp ipv%d json\"" % ip_ver
    route_data = json.loads(host.shell(cmd)['stdout'])
    for ip, nexthops in route_data['routes'].iteritems():
        aspath = set()
        for nexthop in nexthops:
            aspath.add(nexthop['aspath'])
        routes[ip] = aspath
    return routes

def verify_all_routes_announce_to_bgpmon(routes_bgpmon, routes_dut):
    logger.info("Verifying all routes are announced to BGPMON")
    for route in routes_dut.keys():
        if route not in routes_bgpmon:
            return False
    return True

def parse_routes_on_eos(dut_host, neigh_hosts, ip_ver):
    """
    Parse the output of 'show ip bgp neigh received-routes' on eos, and store in a dict
    """
    mg_facts = dut_host.minigraph_facts(host=dut_host.hostname)['ansible_facts']
    asn = mg_facts['minigraph_bgp_asn']
    all_routes = {}
    BGP_ENTRY_HEADING = r"BGP routing table entry for "
    BGP_COMMUNITY_HEADING = r"Community: "
    for hostname, host_conf in neigh_hosts.items():
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
            cmd = "show ip bgp neighbors {} received-routes detail | grep -E \"{}|{}\"".format(peer_ip_v4, BGP_ENTRY_HEADING, BGP_COMMUNITY_HEADING)
            cmd_backup = ""
        else:
            cmd = "show ipv6 bgp peers {} received-routes detail | grep -E \"{}|{}\"".format(peer_ip_v6, BGP_ENTRY_HEADING, BGP_COMMUNITY_HEADING)
            # For compatibility on EOS of old version
            cmd_backup = "show ipv6 bgp neighbors {} received-routes detail | grep -E \"{}|{}\"".format(peer_ip_v6, BGP_ENTRY_HEADING, BGP_COMMUNITY_HEADING)
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

def test_TSA(duthost, ptfhost, nbrhosts, common_setup_teardown, traffic_shift_community):
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
        # Start bgpmon on DUT
        logger.info("Starting bgpmon on DUT")
        duthost.command("sonic-cfggen -j {} -w".format(BGPMON_CONFIG_FILE))
        time.sleep(BGP_ANNOUNCE_TIME)
        bgpmon_routes = parse_exabgp_dump(ptfhost)
        rib_v4 = parse_rib(duthost, 4)
        rib_v6 = parse_rib(duthost, 6)
        pytest_assert(verify_all_routes_announce_to_bgpmon(bgpmon_routes, dict(rib_v4.items() + rib_v6.items())),
                      "Not all routes are announced to bgpmon")
        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(duthost, nbrhosts, traffic_shift_community),
                      "Failed to verify routes on eos in TSA")
    finally:
        # Recover to Normal state
        duthost.shell("TSB")

def test_TSB(duthost, ptfhost, nbrhosts, common_setup_teardown):
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
    # Start bgpmon on DUT
    logger.info("Starting bgpmon on DUT")
    duthost.command("sonic-cfggen -j {} -w".format(BGPMON_CONFIG_FILE))
    time.sleep(BGP_ANNOUNCE_TIME)
    bgpmon_routes = parse_exabgp_dump(ptfhost)
    rib_v4 = parse_rib(duthost, 4)
    rib_v6 = parse_rib(duthost, 6)
    pytest_assert(verify_all_routes_announce_to_bgpmon(bgpmon_routes, dict(rib_v4.items() + rib_v6.items())),
                  "Not all routes are announced to bgpmon")
    pytest_assert(verify_all_routes_announce_to_neighs(duthost, nbrhosts, rib_v4, 4),
                  "Not all ipv4 routes are announced to neighbors")
    pytest_assert(verify_all_routes_announce_to_neighs(duthost, nbrhosts, rib_v6, 6),
                  "Not all ipv6 routes are announced to neighbors")
