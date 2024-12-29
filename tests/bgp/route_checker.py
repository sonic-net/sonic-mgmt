import logging
import ipaddr as ipaddress
import re
import json
from tests.bgp.bgp_helpers import parse_rib
from tests.common.devices.eos import EosHost
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.parallel import parallel_run

logger = logging.getLogger(__name__)


def verify_loopback_route_with_community(dut_hosts, duthost, neigh_hosts, ip_ver, community):
    logger.info("Verifying only loopback routes are announced to bgp neighbors")
    device_lo_addr_prefix_set = set()
    device_ipv6_lo_addr_subnet_len_set = set()
    device_traffic_shift_community_set = set()
    device_traffic_shift_community_set.add(community)
    device_ipv6_lo_addr_subnet_len_set.add('64')
    for dut_host in dut_hosts:
        if dut_host.is_supervisor_node():
            continue
        mg_facts = dut_host.minigraph_facts(host=dut_host.hostname)['ansible_facts']
        for i in range(0, 2):
            addr = mg_facts['minigraph_lo_interfaces'][i]['addr']
            if ipaddress.IPNetwork(addr).version == 4:
                if 4 == ip_ver:
                    device_lo_addr_prefix_set.add(addr + "/32")
            else:
                # The IPv6 Loopback announced to neighbors is /64
                if 6 == ip_ver:
                    device_lo_addr_prefix_set.add(ipaddress.IPv6Address(addr).exploded[:20])
    routes_on_all_nbrs = parse_routes_on_neighbors(duthost, neigh_hosts, ip_ver)
    for hostname, routes in list(routes_on_all_nbrs.items()):
        logger.info("Verifying only loopback routes(ipv{}) are announced to {}".format(ip_ver, hostname))
        nbr_prefix_set = set()
        nbr_prefix_community_set = set()
        nbr_prefix_ipv6_subnet_len_set = set()
        for prefix, received_community in list(routes.items()):
            if 4 == ip_ver:
                nbr_prefix_set.add(prefix)
            else:
                nbr_prefix_set.add(ipaddress.IPv6Address(prefix.split('/')[0]).exploded[:20])
                nbr_prefix_ipv6_subnet_len_set.add(prefix.split('/')[1])
            nbr_prefix_community_set.add(received_community)
        if nbr_prefix_set != device_lo_addr_prefix_set:
            logger.warn("missing loopback address or some other routes present on neighbor")
            return False
        if 6 == ip_ver and device_ipv6_lo_addr_subnet_len_set != nbr_prefix_ipv6_subnet_len_set:
            logger.warn("ipv6 subnet is not /64 for loopback")
            return False
        if isinstance(list(neigh_hosts.items())[0][1]['host'], EosHost):
            if nbr_prefix_community_set != device_traffic_shift_community_set:
                logger.warn("traffic shift away community not present on neighbor")
                return False
    return True


def parse_routes_on_eos(dut_host, neigh_hosts, ip_ver, exp_community=[]):
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
    def parse_routes_process(node=None, results=None, my_community=exp_community):
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
                  .format(peer_ip_v4, BGP_ENTRY_HEADING, BGP_COMMUNITY_HEADING)
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
        routes_with_community = {}
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
                    if my_community:
                        for comm in my_community:
                            if comm in community[0]:
                                routes_with_community[entry] = comm
                                break
                    entry = None
                    community = ""
        if entry:
            routes[entry] = ""
            if community:
                routes[entry] = community[0]
                if my_community:
                    for comm in my_community:
                        if comm in community[0]:
                            routes_with_community[entry] = comm
        if my_community:
            results[hostname] = routes_with_community
        else:
            results[hostname] = routes
    try:
        all_routes = parallel_run(parse_routes_process, (), {}, list(
            neigh_hosts.values()), timeout=240, concurrent_tasks=8)
    except BaseException as err:
        logger.error(
            'Failed to get routes info from VMs. Got error: {}\n\nTrying one more time.'.format(err))
        all_routes = parallel_run(parse_routes_process, (), {}, list(
            neigh_hosts.values()), timeout=240, concurrent_tasks=8)
    return all_routes


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
        results[hostname] = routes

    all_routes = parallel_run(parse_routes_process_vsonic, (), {}, list(neigh_hosts.values()),
                              timeout=120, concurrent_tasks=8)
    return all_routes


def verify_only_loopback_routes_are_announced_to_neighs(dut_hosts, duthost, neigh_hosts, community):
    """
    Verify only loopback routes with certain community are announced to neighs in TSA
    """
    return verify_loopback_route_with_community(dut_hosts, duthost, neigh_hosts, 4, community) and \
        verify_loopback_route_with_community(
            dut_hosts, duthost, neigh_hosts, 6, community)


def parse_routes_on_neighbors(dut_host, neigh_hosts, ip_ver, exp_community=[]):
    if isinstance(list(neigh_hosts.items())[0][1]['host'], EosHost):
        routes_on_all_nbrs = parse_routes_on_eos(dut_host, neigh_hosts, ip_ver, exp_community)
    else:
        routes_on_all_nbrs = parse_routes_on_vsonic(
            dut_host, neigh_hosts, ip_ver)
    return routes_on_all_nbrs


def verify_current_routes_announced_to_neighs(dut_host, neigh_hosts, orig_routes_on_all_nbrs,
                                              cur_routes_on_all_nbrs, ip_ver, exp_community=[]):
    """
    Verify all the original routes are announced to neighbors after TSB
    """
    logger.info(
        "Verifying all the original routes(ipv{}) are announced to bgp neighbors".format(ip_ver))
    cur_routes_on_all_nbrs.update(
        parse_routes_on_neighbors(dut_host, neigh_hosts, ip_ver, exp_community))
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
