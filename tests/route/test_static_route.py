import pytest
import json
import ipaddress
import time
import natsort
import random
import re

from tests.common.fixtures.ptfhost_utils import change_mac_addresses
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.utilities import wait_until
from tests.common import config_reload
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
from pkg_resources import parse_version


pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
]


def skip_201911_and_older(duthost):
    """ Skip the current test if the DUT version is 201911 or older.
    """
    if parse_version(duthost.kernel_version) <= parse_version('4.9.0'):
        pytest.skip("Test not supported for 201911 images or older. Skipping the test")


def is_dualtor(tbinfo):
    """Check if the testbed is dualtor."""
    return "dualtor" in tbinfo["topo"]["name"]


def add_ipaddr(ptfhost, nexthop_addrs, prefix_len, nexthop_devs, ipv6=False):
    for idx in range(len(nexthop_addrs)):
        if ipv6:
            ptfhost.shell("ip -6 addr add {}/{} dev eth{}".format(nexthop_addrs[idx], prefix_len, nexthop_devs[idx]), module_ignore_errors=True)
        else:
            ptfhost.shell("ip addr add {}/{} dev eth{}".format(nexthop_addrs[idx], prefix_len, nexthop_devs[idx]), module_ignore_errors=True)


def del_ipaddr(ptfhost, nexthop_addrs, prefix_len, nexthop_devs, ipv6=False):
    for idx in range(len(nexthop_addrs)):
        if ipv6:
            ptfhost.shell("ip -6 addr del {}/{} dev eth{}".format(nexthop_addrs[idx], prefix_len, nexthop_devs[idx]), module_ignore_errors=True)
        else:
            ptfhost.shell("ip addr del {}/{} dev eth{}".format(nexthop_addrs[idx], prefix_len, nexthop_devs[idx]), module_ignore_errors=True)


def generate_and_verify_traffic(duthost, ptfadapter, tbinfo, ip_dst, expected_ports, ipv6=False):
    if ipv6:
        pkt = testutils.simple_tcpv6_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ipv6_src='2001:db8:85a3::8a2e:370:7334',
            ipv6_dst=ip_dst,
            ipv6_hlim=64,
            tcp_sport=1234,
            tcp_dport=4321)
    else:
        pkt = testutils.simple_tcp_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ip_src='1.1.1.1',
            ip_dst=ip_dst,
            ip_ttl=64,
            tcp_sport=1234,
            tcp_dport=4321)

    exp_pkt = pkt.copy()
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
    if ipv6:
        exp_pkt.set_do_not_care_scapy(packet.IPv6, 'hlim')
        exp_pkt.set_do_not_care_scapy(packet.IPv6, 'chksum')
    else:
        exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')

    ptf_t1_intf = random.choice(get_t1_ptf_ports(duthost, tbinfo))
    ptf_t1_intf_index = int(ptf_t1_intf.strip("eth"))
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_t1_intf_index, pkt)
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=expected_ports)


def check_route_redistribution(duthost, prefix, ipv6, removed=False):
    if ipv6:
        bgp_neighbor_addr_regex = re.compile(r"^([0-9a-fA-F]{1,4}:[0-9a-fA-F:]+)")
        SHOW_BGP_SUMMARY_CMD = "show ipv6 bgp summary"
        SHOW_BGP_ADV_ROUTES_CMD_TEMPLATE = "show ipv6 bgp neighbor {} advertised-routes"
    else:
        bgp_neighbor_addr_regex = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}")
        SHOW_BGP_SUMMARY_CMD = "show ip bgp summary"
        SHOW_BGP_ADV_ROUTES_CMD_TEMPLATE = "show ip bgp neighbor {} advertised-routes"

    bgp_summary = duthost.shell(SHOW_BGP_SUMMARY_CMD)["stdout"].split("\n")

    bgp_neighbors = []

    for line in bgp_summary:
        matched = bgp_neighbor_addr_regex.match(line)
        if matched:
            bgp_neighbors.append(str(matched.group(0)))

    for neighbor in bgp_neighbors:
        adv_routes = duthost.shell(SHOW_BGP_ADV_ROUTES_CMD_TEMPLATE.format(neighbor))["stdout"]
        if removed:
            assert prefix not in adv_routes
        else:
            assert prefix in adv_routes


def run_static_route_test(duthost, ptfadapter, ptfhost, tbinfo, prefix, nexthop_addrs, prefix_len, nexthop_devs, ipv6=False, config_reload_test=False):
    # Add ipaddresses in ptf
    add_ipaddr(ptfhost, nexthop_addrs, prefix_len, nexthop_devs, ipv6=ipv6)

    try:
        # Add static route
        duthost.shell("sonic-db-cli CONFIG_DB hmset 'STATIC_ROUTE|{}' nexthop {}".format(prefix, ",".join(nexthop_addrs)))
        time.sleep(5)

        # Check traffic get forwarded to the nexthop
        ip_dst = str(ipaddress.ip_network(unicode(prefix))[1])
        generate_and_verify_traffic(duthost, ptfadapter, tbinfo, ip_dst, nexthop_devs, ipv6=ipv6)

        # Check the route is advertised to the neighbors
        check_route_redistribution(duthost, prefix, ipv6)

        # Config save and reload if specified
        if config_reload_test:
            duthost.shell('config save -y')
            config_reload(duthost)
            generate_and_verify_traffic(duthost, ptfadapter, tbinfo, ip_dst, nexthop_devs, ipv6=ipv6)
            check_route_redistribution(duthost, prefix, ipv6)

    finally:
        # Remove static route
        duthost.shell("sonic-db-cli CONFIG_DB del 'STATIC_ROUTE|{}'".format(prefix), module_ignore_errors=True)

        # Delete ipaddresses in ptf
        del_ipaddr(ptfhost, nexthop_addrs, prefix_len, nexthop_devs, ipv6=ipv6)

        # Check the advertised route get removed
        time.sleep(5)
        check_route_redistribution(duthost, prefix, ipv6, removed=True)

        # Config save if the saved config_db was updated
        if config_reload_test:
            duthost.shell('config save -y')


def get_nexthops(duthost, tbinfo, ipv6=False, count=1):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vlan_intf = mg_facts['minigraph_vlan_interfaces'][1 if ipv6 else 0]
    prefix_len = vlan_intf['prefixlen']

    if is_dualtor(tbinfo):
        server_ips = mux_cable_server_ip(duthost)
        vlan_intfs = natsort.natsorted(server_ips.keys())
        nexthop_devs = [mg_facts["minigraph_ptf_indices"][_] for _ in vlan_intfs]
        server_ip_key = "server_ipv6" if ipv6 else "server_ipv4"
        nexthop_addrs = [server_ips[_][server_ip_key].split("/")[0] for _ in vlan_intfs]
    else:
        vlan_subnet = ipaddress.ip_network(vlan_intf['subnet'])
        vlan_ports = mg_facts['minigraph_vlans'][mg_facts['minigraph_vlan_interfaces'][1 if ipv6 else 0]['attachto']]['members']
        vlan_ptf_ports = [mg_facts['minigraph_ptf_indices'][port] for port in vlan_ports]
        nexthop_devs = vlan_ptf_ports
        nexthop_addrs = [str(vlan_subnet[i + 2]) for i in range(len(nexthop_devs))]
    count = min(count, len(nexthop_devs))
    indices = random.sample(list(range(len(nexthop_devs))), k=count)
    return prefix_len, [nexthop_addrs[_] for _ in indices], [nexthop_devs[_] for _ in indices]


def test_static_route(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfadapter, ptfhost, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    skip_201911_and_older(duthost)
    prefix_len, nexthop_addrs, nexthop_devs = get_nexthops(duthost, tbinfo)
    run_static_route_test(duthost, ptfadapter, ptfhost, tbinfo, "1.1.1.0/24",
                          nexthop_addrs, prefix_len, nexthop_devs)


def test_static_route_ecmp(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfadapter, ptfhost, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    skip_201911_and_older(duthost)
    prefix_len, nexthop_addrs, nexthop_devs = get_nexthops(duthost, tbinfo, count=3)
    run_static_route_test(duthost, ptfadapter, ptfhost, tbinfo, "2.2.2.0/24",
                          nexthop_addrs, prefix_len, nexthop_devs, config_reload_test=True)


def test_static_route_ipv6(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfadapter, ptfhost, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    skip_201911_and_older(duthost)
    prefix_len, nexthop_addrs, nexthop_devs = get_nexthops(duthost, tbinfo, ipv6=True)
    run_static_route_test(duthost, ptfadapter, ptfhost, tbinfo, "2000:1::/64",
                          nexthop_addrs, prefix_len, nexthop_devs, ipv6=True)


def test_static_route_ecmp_ipv6(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfadapter, ptfhost, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    skip_201911_and_older(duthost)
    prefix_len, nexthop_addrs, nexthop_devs = get_nexthops(duthost, tbinfo, ipv6=True, count=3)
    run_static_route_test(duthost, ptfadapter, ptfhost, tbinfo, "2000:2::/64",
                          nexthop_addrs, prefix_len, nexthop_devs, ipv6=True, config_reload_test=True)
