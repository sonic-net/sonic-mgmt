import logging
import ipaddr as ipaddress
import re
import json
from tests.bgp.bgp_helpers import parse_rib
from tests.common.devices.eos import EosHost
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.parallel import parallel_run
from tests.common.utilities import wait_until

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
            logger.warning("missing loopback address or some other routes present on neighbor")
            return False
        if 6 == ip_ver and device_ipv6_lo_addr_subnet_len_set != nbr_prefix_ipv6_subnet_len_set:
            logger.warning("ipv6 subnet is not /64 for loopback")
            return False
        if isinstance(list(neigh_hosts.items())[0][1]['host'], EosHost):
            if nbr_prefix_community_set != device_traffic_shift_community_set:
                logger.warning("traffic shift away community not present on neighbor")
                return False
    return True


def parse_routes_on_eos(dut_host, neigh_hosts, ip_ver, exp_community=[]):
    """
    Parse the output of 'show ip bgp neigh received-routes' on eos, and store in a dict
    """
    mg_facts = dut_host.minigraph_facts(
        host=dut_host.hostname)['ansible_facts']
    asn = mg_facts['minigraph_bgp_asn']
    confed_asn = dut_host.get_bgp_confed_asn()
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
        multi_vrf_peer = node.get('is_multi_vrf_peer', False)
        if multi_vrf_peer:
            hostname = node['multi_vrf_data']['vrf']
        else:
            # get hostname('ARISTA11T0') by VM name('VM0122')
            hostname = host_name_map[node['host'].hostname]
        host = node['host']
        peer_in_bgp_confed = node['conf']['bgp'].get('peer_in_bgp_confed', False)
        try:
            peer_ips = node['conf']['bgp']['peers'][asn]
        except KeyError as e:
            if peer_in_bgp_confed:
                peer_ips = node['conf']['bgp']['peers'][int(confed_asn)]
            else:
                raise e

        for ip in peer_ips:
            if ipaddress.IPNetwork(ip).version == 4:
                peer_ip_v4 = ip
            else:
                peer_ip_v6 = ip
        # The json formatter on EOS consumes too much time (over 40 seconds).
        # So we have to parse the raw output instead json.
        grepCmd = 'grep -E "{}|{}"'.format(BGP_ENTRY_HEADING, BGP_COMMUNITY_HEADING)
        if 4 == ip_ver:
            cmd = "show ip bgp neighbors {} received-routes detail".format(peer_ip_v4)
            if multi_vrf_peer:
                cmd = "{} vrf {}".format(cmd, hostname)
            cmd = "{} | {}".format(cmd, grepCmd)
            cmd_backup = ""
        else:
            cmd = "show ipv6 bgp peers {} received-routes detail".format(peer_ip_v6)
            if multi_vrf_peer:
                cmd = "{} vrf {}".format(cmd, hostname)
            cmd = "{} | {}".format(cmd, grepCmd)
            # For compatibility on EOS of old version
            cmd_backup = "show ipv6 bgp neighbors {} received-routes detail".format(peer_ip_v6)
            if multi_vrf_peer:
                cmd_backup = "{} vrf {}".format(cmd_backup, hostname)
            cmd_backup = "{} | {}".format(cmd_backup, grepCmd)
        res = host.eos_command(commands=[cmd], module_ignore_errors=True, verbose=False)
        if res['failed'] and cmd_backup != "":
            res = host.eos_command(
                commands=[cmd_backup], module_ignore_errors=True, verbose=False)
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
        res = host.shell(bgp_nbr_cmd, verbose=False)
        routes_json = json.loads(res['stdout'])['receivedRoutes']

        routes = {}
        for a_route in routes_json:
            # empty community string
            routes[a_route] = ""
        results[hostname] = routes

    all_routes = parallel_run(parse_routes_process_vsonic, (), {}, list(neigh_hosts.values()),
                              timeout=120, concurrent_tasks=8)
    return all_routes


def verify_only_loopback_routes_are_announced_to_neighs(dut_hosts, duthost, neigh_hosts, community, is_v6_topo=False):
    """
    Verify only loopback routes with certain community are announced to neighs in TSA
    """
    return (is_v6_topo or verify_loopback_route_with_community(dut_hosts, duthost, neigh_hosts, 4, community)) and \
        verify_loopback_route_with_community(
            dut_hosts, duthost, neigh_hosts, 6, community)


def assert_only_loopback_routes_announced_to_neighs(dut_hosts, duthost, neigh_hosts, community,
                                                    error_msg="", is_v6_topo=False):
    if not error_msg:
        error_msg = "Failed to verify only loopback routes are announced to neighbours"

    pytest_assert(
        wait_until(180, 10, 5, verify_only_loopback_routes_are_announced_to_neighs,
                   dut_hosts, duthost, neigh_hosts, community, is_v6_topo),
        error_msg
    )


def _parse_advertised_routes_plain(output):
    """Parse plain text output of 'show bgp neighbors advertised-routes'.

    Returns a set of advertised prefixes.

    FRR status codes vary (*>, *=, *>i, s>, r>, S, d, h, etc.) and may be
    concatenated with or separated from the prefix.  Instead of matching
    specific status strings, find the "Network" column position from the
    header and extract the prefix at that offset.  Fall back to a regex
    scan if no header is found.
    """
    prefixes = set()
    lines = output.splitlines()

    # Locate the "Network" column position from the header line
    net_col = None
    header_idx = None
    for idx, line in enumerate(lines):
        col = line.find('Network')
        if col >= 0:
            net_col = col
            header_idx = idx
            break

    # IPv4 or IPv6 CIDR pattern
    cidr_re = re.compile(r'([\da-fA-F.:]+/\d+)')

    for line in lines[header_idx + 1 if header_idx is not None else 0:]:
        stripped = line.strip()
        if not stripped or stripped.startswith('Total'):
            continue
        # Try column-based extraction first
        if net_col is not None and len(line) > net_col:
            token = line[net_col:].split()[0] if line[net_col:].split() else ''
            m = cidr_re.match(token)
            if m:
                prefixes.add(m.group(1))
                continue
        # Fallback: find any CIDR prefix on the line
        m = cidr_re.search(stripped)
        if m:
            prefixes.add(m.group(1))
    return prefixes


def get_dut_advertised_routes(duthost, ip_ver, output_format="both"):
    """Get advertised routes from the DUT for each BGP neighbor.

    Args:
        duthost: DUT host object.
        ip_ver: IP version (4 or 6).
        output_format: Controls how advertised routes are parsed.
            "json" - parse only JSON output.
            "plain" - parse only plain text output.
            "both" - parse both and cross-check for consistency (default).

    Returns a dict: {neighbor_ip: set_of_advertised_prefixes}, or
    None if all requested formats fail for any neighbor.
    """
    mg_facts = duthost.minigraph_facts(
        host=duthost.hostname)['ansible_facts']
    advertised = {}
    for bgp_neigh in mg_facts['minigraph_bgp']:
        neigh_addr = bgp_neigh['addr']
        neigh_ver = ipaddress.IPNetwork(neigh_addr).version
        if neigh_ver != ip_ver:
            continue
        if ip_ver == 4:
            cmd_json = ("sudo vtysh -c 'show ip bgp neighbors "
                        "{} advertised-routes json'"
                        .format(neigh_addr))
            cmd_plain = ("sudo vtysh -c 'show ip bgp neighbors "
                         "{} advertised-routes'"
                         .format(neigh_addr))
        else:
            cmd_json = ("sudo vtysh -c 'show bgp ipv6 neighbors "
                        "{} advertised-routes json'"
                        .format(neigh_addr))
            cmd_plain = ("sudo vtysh -c 'show bgp ipv6 neighbors "
                         "{} advertised-routes'"
                         .format(neigh_addr))

        # Collect results from both JSON and plain text formats
        json_prefixes = None
        plain_prefixes = None

        # JSON format
        if output_format in ("json", "both"):
            res = duthost.shell(
                cmd_json, module_ignore_errors=True, verbose=False)
            if res['rc'] == 0:
                try:
                    routes_json = json.loads(res['stdout'])
                    json_prefixes = set(
                        routes_json.get('advertisedRoutes', {}).keys())
                except (ValueError, KeyError) as e:
                    logger.warning(
                        "Failed to parse JSON advertised routes for "
                        "neighbor {}: {}".format(neigh_addr, e))
            else:
                logger.warning(
                    "JSON advertised-routes command failed for "
                    "neighbor {}: {}".format(
                        neigh_addr, res.get('stderr', '')))

        # Plain text format
        if output_format in ("plain", "both"):
            res = duthost.shell(
                cmd_plain, module_ignore_errors=True, verbose=False)
            if res['rc'] == 0:
                plain_prefixes = _parse_advertised_routes_plain(
                    res['stdout'])
            else:
                logger.warning(
                    "Plain text advertised-routes command failed for "
                    "neighbor {}: {}".format(
                        neigh_addr, res.get('stderr', '')))

        # Evaluate results
        if json_prefixes is None and plain_prefixes is None:
            logger.warning(
                "Both JSON and plain text advertised-routes "
                "failed for neighbor {}".format(neigh_addr))
            return None

        if (json_prefixes is not None and plain_prefixes is not None
                and json_prefixes != plain_prefixes):
            logger.warning(
                "JSON and plain text advertised-routes mismatch "
                "for neighbor {}: json_only={}, plain_only={}"
                .format(neigh_addr,
                        json_prefixes - plain_prefixes,
                        plain_prefixes - json_prefixes))

        # Return both formats so callers can inspect each independently
        advertised[neigh_addr] = {
            "json": json_prefixes,
            "plain": plain_prefixes,
        }
    return advertised


def verify_only_loopback_routes_in_dut_advertised_routes(dut_hosts, duthost, ip_ver):
    """
    Verify from the DUT's perspective that only loopback routes are in the advertised-routes
    for each BGP neighbor during TSA.
    """
    logger.info("Verifying only loopback routes(ipv{}) in DUT advertised-routes".format(ip_ver))
    device_lo_addr_prefix_set = set()
    for dut_host in dut_hosts:
        if dut_host.is_supervisor_node():
            continue
        mg_facts = dut_host.minigraph_facts(host=dut_host.hostname)['ansible_facts']
        for lo_intf in mg_facts['minigraph_lo_interfaces']:
            addr = lo_intf['addr']
            if ipaddress.IPNetwork(addr).version == 4:
                if ip_ver == 4:
                    device_lo_addr_prefix_set.add(addr + "/32")
            else:
                if ip_ver == 6:
                    # Compare /64 prefix: exploded IPv6 has 4-char groups separated by colons,
                    # first 20 chars cover the first 4 groups (64 bits), e.g. "fc00:0001:0000:0000"
                    device_lo_addr_prefix_set.add(ipaddress.IPv6Address(addr).exploded[:20])

    advertised = get_dut_advertised_routes(duthost, ip_ver)
    if advertised is None:
        return False

    for peer_addr, route_data in advertised.items():
        logger.info("Checking DUT advertised-routes to neighbor {} (ipv{})".format(peer_addr, ip_ver))

        # Check each available format independently
        for fmt in ("json", "plain"):
            prefixes = route_data.get(fmt)
            if prefixes is None:
                continue
            nbr_prefix_set = set()
            for prefix in prefixes:
                if ip_ver == 4:
                    nbr_prefix_set.add(prefix)
                else:
                    nbr_prefix_set.add(ipaddress.IPv6Address(prefix.split('/')[0]).exploded[:20])
            if nbr_prefix_set != device_lo_addr_prefix_set:
                logger.warning(
                    "DUT advertised-routes ({}) to {} mismatch: expected loopback prefixes {}, got {}".format(
                        fmt, peer_addr, device_lo_addr_prefix_set, nbr_prefix_set))
                return False
    return True


def assert_only_loopback_routes_in_dut_advertised_routes(dut_hosts, duthost, is_v6_topo=False):
    """
    Assert from the DUT's perspective that only loopback routes are advertised to all BGP neighbors.
    """
    def _verify():
        return (is_v6_topo or verify_only_loopback_routes_in_dut_advertised_routes(dut_hosts, duthost, 4)) and \
            verify_only_loopback_routes_in_dut_advertised_routes(dut_hosts, duthost, 6)

    pytest_assert(
        wait_until(180, 10, 5, _verify),
        "DUT advertised-routes contain non-loopback prefixes during TSA"
    )


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
        logger.warning("Neighbor list mismatch: {}".format(cur_nbrs ^ orig_nbrs))
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
                    logger.warning(
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
                            logger.warning(
                                "Missing route on host {}: {}".format(hostname, route))
                        else:
                            logger.warning(
                                "Additional route on host {}: {}".format(hostname, route))

    return all_diffs_in_host_aspath
