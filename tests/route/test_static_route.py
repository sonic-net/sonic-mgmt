import pytest
import json
import ipaddress
from tests.common.utilities import wait_until
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
]

ROUTE_TABLE_NAME = 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY'

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

def count_routes(host):
    num = host.shell(
        'sonic-db-cli ASIC_DB eval "return #redis.call(\'keys\', \'{}*\')" 0'.format(ROUTE_TABLE_NAME),
        verbose=True)['stdout']
    return int(num)

def generate_and_verify_traffic(duthost, ptfadapter, ip_dst, expected_ports, ipv6=False):
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

    testutils.send(ptfadapter, 5, pkt)
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=expected_ports)

def run_static_route_test(duthost, ptfadapter, ptfhost, prefix, nexthop_addrs, prefix_len, nexthop_devs, ipv6=False):
    # Add ipaddresses in ptf
    add_ipaddr(ptfhost, nexthop_addrs, prefix_len, nexthop_devs, ipv6=ipv6)

    try:
        # Check the number of routes in ASIC_DB
        start_num_route = count_routes(duthost)

        # Add static route
        duthost.shell("sonic-db-cli CONFIG_DB hmset 'STATIC_ROUTE|{}' nexthop {}".format(prefix, ",".join(nexthop_addrs)))
        # duthost.shell("sudo sonic-cfggen -a '{\"STATIC_ROUTE\":{\"%s\": {\"nexthop\": \"%s\"}}}' --write-to-db" % (prefix, ",".join(nexthop_addrs)))

        # Wait until the route gets applied to ASIC_DB
        def _check_num_routes(expected_num_routes):
            # Check the number of routes in ASIC_DB
            return count_routes(duthost) == expected_num_routes

        if not wait_until(2, 0.5, _check_num_routes, start_num_route + 1):
            pytest.fail('failed to add routes within time limit')

        # Check route entries are correct
        asic_route_keys = duthost.shell('sonic-db-cli ASIC_DB eval "return redis.call(\'keys\', \'{}*\')" 0'\
            .format(ROUTE_TABLE_NAME), verbose=False)['stdout_lines']
        asic_prefixes = []
        for key in asic_route_keys:
            json_obj = key[len(ROUTE_TABLE_NAME) + 1 : ]
            asic_prefixes.append(json.loads(json_obj)['dest'])
        assert prefix in asic_prefixes

        # Check traffic get forwarded to the nexthop
        ip_dst = str(ipaddress.ip_network(unicode(prefix))[1])
        generate_and_verify_traffic(duthost, ptfadapter, ip_dst, nexthop_devs, ipv6=ipv6)

    finally:
        # Remove static route
        duthost.shell("sonic-db-cli CONFIG_DB del 'STATIC_ROUTE|{}'".format(prefix), module_ignore_errors=True)

        # Delete ipaddresses in ptf
        del_ipaddr(ptfhost, nexthop_addrs, prefix_len, nexthop_devs, ipv6=ipv6)

def get_vlan_info(duthost, tbinfo, ipv6=False):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vlan_intf = mg_facts['minigraph_vlan_interfaces'][1 if ipv6 else 0]
    prefix_len = vlan_intf['prefixlen']
    vlan_subnet = ipaddress.ip_network(vlan_intf['subnet'])
    return prefix_len, vlan_subnet

def test_static_route(duthost, ptfadapter, ptfhost, tbinfo):
    prefix_len, vlan_subnet = get_vlan_info(duthost, tbinfo)
    run_static_route_test(duthost, ptfadapter, ptfhost, "1.1.1.0/24", 
        [str(vlan_subnet[11])], prefix_len, [1])

def test_static_route_ecmp(duthost, ptfadapter, ptfhost, tbinfo):
    prefix_len, vlan_subnet = get_vlan_info(duthost, tbinfo)
    run_static_route_test(duthost, ptfadapter, ptfhost, "2.2.2.0/24", 
        [str(vlan_subnet[21]), str(vlan_subnet[22]), str(vlan_subnet[23])], prefix_len, [1, 2, 3])

def test_static_route_ipv6(duthost, ptfadapter, ptfhost, tbinfo):
    prefix_len, vlan_subnet = get_vlan_info(duthost, tbinfo, ipv6=True)
    run_static_route_test(duthost, ptfadapter, ptfhost, "2000:1::/64", 
        [str(vlan_subnet[11])], prefix_len, [1], ipv6=True)

def test_static_route_ecmp_ipv6(duthost, ptfadapter, ptfhost, tbinfo):
    prefix_len, vlan_subnet = get_vlan_info(duthost, tbinfo, ipv6=True)
    run_static_route_test(duthost, ptfadapter, ptfhost, "2000:2::/64", 
        [str(vlan_subnet[21]), str(vlan_subnet[22]), str(vlan_subnet[23])], prefix_len, [1, 2, 3], ipv6=True)
