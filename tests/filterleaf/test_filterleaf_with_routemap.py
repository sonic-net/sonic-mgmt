'''This script is to test the BGP Allow List feature of SONiC.
'''
import logging
import pytest
import ipaddress
import random

from tests.common.helpers.assertions import pytest_assert
import ptf.testutils as testutils
from ptf.mask import Mask
from scapy.all import Ether, IP, IPv6, Dot1Q
import ptf.packet as scapy
from filterleaf_helpers import (
    # Constants
    ALLOW_LIST_PREFIX_JSON_FILE, PREFIX_LISTS, TEST_COMMUNITY, DEFAULT,
    EXABGP_BASE_PORT, EXABGP_BASE_PORT_V6, VRF_NAME,
    # Functions
    apply_allow_list, remove_allow_list, check_routes_on_from_neighbor,
    get_vrf_route_json, get_exabgp_port,
    get_t2_ptf_intfs,

)


BASE_IP_ROUTE = '172.16.10.0/24'
BASE_IPV6_ROUTE = '2000:172:16:10::/64'
FUNCTION = "function"
FORWARD = "FORWARD"
DROP = "DROP"
IP_VER = 4
IPV6_VER = 6
TRAFFIC_WAIT_TIME = 0.1
SRC_IP = {
    4: "192.168.0.2",
    6: "fc02:1000::2"
}

pytestmark = [
    pytest.mark.topology('t1-filterleaf-lag')
]

logger = logging.getLogger(__name__)

DEPLOYMENT_ID = '0'
ALLOW_LIST = {
    'BGP_ALLOWED_PREFIXES': {
        'DEPLOYMENT_ID|{}|{}'.format(DEPLOYMENT_ID, TEST_COMMUNITY): {
            'prefixes_v4': PREFIX_LISTS['ALLOWED_WITH_COMMUNITY'],
            'prefixes_v6': PREFIX_LISTS['ALLOWED_WITH_COMMUNITY_V6'],
            'default_action': ''
        },
        'DEPLOYMENT_ID|{}'.format(DEPLOYMENT_ID): {
            'prefixes_v4': PREFIX_LISTS['ALLOWED'],
            'prefixes_v6': PREFIX_LISTS['ALLOWED_V6'],
            'default_action': ''
        }
    }
}


def get_first_ip(subnet):
    """
    Get the first IP address from the subnet
    """
    network = ipaddress.ip_network(subnet, strict=False)
    all_usable_ips = network.hosts()
    first_ip = next(all_usable_ips)
    return str(first_ip)


def generate_traffic_data(route_list, action):
    """
    Generate traffic data list
    Example:
    Input: route_list=['172.16.10.0', '172.16.20.0'], action='FORWARD'
    Output: [
                ('172.16.10.1', 'FORWARD'),
                ('172.16.20.1', 'FORWARD')
            ]
    """
    traffic_data_list = []
    for route in route_list:
        ipaddr = get_first_ip(route)
        traffic_data = (ipaddr, action)
        traffic_data_list.append(traffic_data)
    return traffic_data_list


@pytest.fixture(scope="function")
def get_exabgp_ptf_ports(duthost, nbrhosts, tbinfo, request):
    """
    Get ipv4 and ipv6 Exabgp port and ptf receive port
    """
    exabgp_port_list, ptf_recv_port_list = get_exabgp_port(duthost, nbrhosts, tbinfo, EXABGP_BASE_PORT)
    exabgp_port_list_v6, ptf_recv_port_list_v6 = get_exabgp_port(duthost, nbrhosts, tbinfo, EXABGP_BASE_PORT_V6
                                                                 )
    return [(exabgp_port, ptf_recv_port, exabgp_port_v6, ptf_recv_port_v6)
            for exabgp_port, ptf_recv_port, exabgp_port_v6, ptf_recv_port_v6 in zip(exabgp_port_list,
                                                                                    ptf_recv_port_list,
                                                                                    exabgp_port_list_v6,
                                                                                    ptf_recv_port_list_v6)]


@pytest.fixture(scope="function")
def prepare_param(duthost, tbinfo, get_exabgp_ptf_ports):
    """
    Prepare parameters
    """
    router_mac = duthost.facts["router_mac"]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_ip = tbinfo['ptf_ip']
    total_port_list = get_exabgp_ptf_ports
    exabgp_port_list, ptf_recv_port_list, exabgp_port_list_v6, ptf_recv_port_list_v6 = zip(*total_port_list)
    recv_port_list = [{4: ptf_recv_port, 6: ptf_recv_port_v6} for ptf_recv_port, ptf_recv_port_v6 in
                      zip(ptf_recv_port_list, ptf_recv_port_list_v6)]
    return router_mac, mg_facts, ptf_ip, exabgp_port_list, exabgp_port_list_v6, recv_port_list


@pytest.fixture(scope="module")
def generate_route_and_traffic_data():
    """
    Generate route and traffic data
    """
    ip_routes_ipv4 = generate_routes(BASE_IP_ROUTE)
    ip_routes_ipv6 = generate_routes(BASE_IPV6_ROUTE)

    route_and_traffic_data = {
        FUNCTION: [
            ip_routes_ipv4,
            ip_routes_ipv6,
            generate_traffic_data(ip_routes_ipv4, FORWARD),
            generate_traffic_data(ip_routes_ipv6, FORWARD),
            generate_traffic_data(['172.16.30.0/24'], DROP),
            generate_traffic_data(['2000:172:16:30::/64'], DROP)
        ]
    }

    return route_and_traffic_data


def generate_routes(start_ip, count=1):
    """
    Generate a number of IP routes
    """
    route_list = [start_ip]
    for _ in range(count - 1):
        start_ip = ip_address_incr(start_ip)
        route_list.append(start_ip)
    return route_list


def ip_address_incr(ip_str):
    """
    Increment an IP subnet prefix by 1
    """
    net = ipaddress.ip_network(ip_str, strict=False)
    next_net_addr = net.network_address + net.num_addresses
    return f"{next_net_addr}/{net.prefixlen}"


def validate_traffic(ptfadapter, traffic_data_list, router_mac, ptf_interfaces, recv_port):
    """
    Verify traffic is forwarded/forwarded back/drop as expected
    """
    for traffic_data in traffic_data_list:
        tx_port, ip_ver_list, pkt_list, exp_pkt_list, exp_res_list = prepare_traffic(traffic_data, router_mac,
                                                                                     ptf_interfaces, recv_port)
        if ptf_interfaces is recv_port:
            send_and_verify_packet(ptfadapter, pkt_list, exp_pkt_list, tx_port, tx_port, exp_res_list)
        else:
            send_and_verify_packet(ptfadapter, pkt_list, exp_pkt_list, tx_port, recv_port, exp_res_list, ip_ver_list)


def prepare_traffic(traffic_data, router_mac, ptf_interfaces, recv_port):
    ip_ver_list, pkt_list, exp_pkt_list, exp_res_list = [], [], [], []
    tx_port = random.choice(ptf_interfaces)

    for test_item in traffic_data:
        dst_ip = test_item[0]
        exp_res = test_item[1]
        ip_ver = ipaddress.ip_network(dst_ip.encode().decode(), False).version
        pkt, exp_pkt = generate_packet(SRC_IP[ip_ver], dst_ip, router_mac)
        if ptf_interfaces is recv_port:
            rx_port = ptf_interfaces
        else:
            rx_port = recv_port[ip_ver]
        logger.info("Expected packet:\n dst_mac:{} - src_ip:{} - dst_ip:{} - ptf tx_port:{} - ptf rx_port:{} - "
                    "expected_result = {}".format(router_mac, SRC_IP[ip_ver], dst_ip, tx_port, rx_port, exp_res))

        ip_ver_list.append(ip_ver)
        pkt_list.append(pkt)
        exp_pkt_list.append(exp_pkt)
        exp_res_list.append(exp_res)

    return tx_port, ip_ver_list, pkt_list, exp_pkt_list, exp_res_list


def send_and_verify_packet(ptfadapter, pkt_list, exp_pkt_list, tx_port, rx_ports, exp_action_list, ip_ver_list=None):
    """
    Send packet with ptfadapter and verify if packet is forwarded or dropped as expected
    """
    ptfadapter.dataplane.flush()
    for pkt, exp_pkt, exp_action, ip_ver in zip(pkt_list, exp_pkt_list, exp_action_list, ip_ver_list):
        rx_port = rx_ports[ip_ver] if ip_ver else rx_ports

        if exp_action == FORWARD:
            testutils.send(ptfadapter, pkt=pkt, port_id=tx_port)
            testutils.verify_packet(ptfadapter, pkt=exp_pkt, port_id=rx_port, timeout=TRAFFIC_WAIT_TIME)
        else:
            testutils.send(ptfadapter, pkt=pkt, port_id=rx_port)
            testutils.verify_no_packet(ptfadapter, pkt=exp_pkt, port_id=tx_port, timeout=TRAFFIC_WAIT_TIME)


def generate_packet(src_ip, dst_ip, dst_mac):
    """
    Build ipv4 and ipv6 packets/expected_packets for testing
    """
    if ipaddress.ip_network(src_ip.encode().decode(), False).version == 4:
        pkt = testutils.simple_ip_packet(eth_dst=dst_mac, ip_src=src_ip, ip_dst=dst_ip)
        ether = pkt[Ether]
        ip = pkt[IP]
        vlan_pkt = Ether(src=ether.dst, dst=ether.src, type=0x8100) / Dot1Q(vlan=7) / ip

        exp_pkt = Mask(vlan_pkt)
        exp_pkt.set_do_not_care_packet(scapy.IP, "ttl")
        exp_pkt.set_do_not_care_packet(scapy.IP, "chksum")
    else:
        pkt = testutils.simple_tcpv6_packet(eth_dst=dst_mac, ipv6_src=src_ip, ipv6_dst=dst_ip)
        ether = pkt[Ether]
        ipv6 = pkt[IPv6]

        vlan_pkt = Ether(src=ether.dst, dst=ether.src, type=0x8100) / Dot1Q(vlan=7) / ipv6
        exp_pkt = Mask(vlan_pkt)
        exp_pkt.set_do_not_care_packet(scapy.IPv6, "hlim")

    exp_pkt.set_do_not_care_packet(scapy.Ether, "dst")
    exp_pkt.set_do_not_care_packet(scapy.Ether, "src")

    return pkt, exp_pkt


@pytest.fixture
def load_remove_allow_list(duthosts, bgp_allow_list_setup, rand_one_dut_hostname, request):     # noqa F811
    allowed_list_prefixes = ALLOW_LIST['BGP_ALLOWED_PREFIXES']
    for _, value in list(allowed_list_prefixes.items()):
        value['default_action'] = request.param

    duthost = duthosts[rand_one_dut_hostname]
    namespace = bgp_allow_list_setup['downstream_namespace']
    apply_allow_list(duthost, namespace, ALLOW_LIST, ALLOW_LIST_PREFIX_JSON_FILE)

    yield request.param

    remove_allow_list(duthost, namespace, ALLOW_LIST_PREFIX_JSON_FILE)


def check_routes_on_dut(duthost, namespace):
    """
    Verify routes on dut
    """
    for prefixes in list(PREFIX_LISTS.values()):
        for prefix in prefixes:
            dut_route = duthost.get_route(prefix, namespace)
            pytest_assert(dut_route, 'Route {} is not found on DUT'.format(prefix))


def validate_route_states(duthost, ipv4_route_list, vrf=DEFAULT):
    """
    Verify ipv4 and ipv6 routes install status
    """
    for prefixes in ipv4_route_list:
        for route in prefixes:
            ip_ver = ipaddress.ip_network(route).version
            get_vrf_route_json(duthost, route, vrf=vrf, ip_ver=ip_ver)


@pytest.mark.parametrize('load_remove_allow_list', ["permit", "deny"], indirect=['load_remove_allow_list'])
def test_bgp_ddos_v4_comm_default_vrf(duthosts, rand_one_dut_hostname, bgp_allow_list_setup, nbrhosts,    # noqa F811
                                      load_remove_allow_list, ptfhost,
                                      ptfadapter, prepare_param, generate_route_and_traffic_data):
    permit = True if load_remove_allow_list == "permit" else False
    duthost = duthosts[rand_one_dut_hostname]
    # All routes should be found on from neighbor.
    check_routes_on_from_neighbor(bgp_allow_list_setup, nbrhosts)
    # All routes should be found in dut.
    check_routes_on_dut(duthost, bgp_allow_list_setup['downstream_namespace'])
    # If permit is True, all routes should be forwarded.
    # If permit is False, Routes in allow_list should be forwarded , routes not in allow_list
    router_mac, mg_facts, ptf_ip, exabgp_port_list, exabgp_port_list_v6, recv_port_list = prepare_param
    ipv4_route_list, ipv6_route_list, traffic_data_ipv4_forward, traffic_data_ipv6_forward, \
        traffic_data_ipv4_drop, traffic_data_ipv6_drop = generate_route_and_traffic_data[FUNCTION]
    for exabgp_port, exabgp_port_v6, recv_port in zip(exabgp_port_list, exabgp_port_list_v6, recv_port_list):
        ptf_interfaces = get_t2_ptf_intfs(mg_facts)
        if permit:
            validate_traffic(ptfadapter, [traffic_data_ipv4_forward, traffic_data_ipv6_forward], router_mac,
                             ptf_interfaces, recv_port)
        else:
            validate_traffic(ptfadapter, [traffic_data_ipv4_drop, traffic_data_ipv6_drop], router_mac,
                             ptf_interfaces, recv_port)


@pytest.mark.parametrize('load_remove_allow_list', ["permit", "deny"], indirect=['load_remove_allow_list'])
def test_bgp_ddos_v4_comm_non_default_vrf(duthosts, rand_one_dut_hostname, bgp_allow_list_setup, nbrhosts,    # noqa F811
                                          load_remove_allow_list, ptfhost, ptfadapter,
                                          prepare_param, generate_route_and_traffic_data):
    permit = True if load_remove_allow_list == "permit" else False
    duthost = duthosts[rand_one_dut_hostname]
    # All routes should be found on from neighbor.
    check_routes_on_from_neighbor(bgp_allow_list_setup, nbrhosts)
    # All routes should be found in dut with specified vrf.
    validate_route_states(duthost, list(PREFIX_LISTS.values()), vrf=VRF_NAME)
    check_routes_on_dut(duthost, bgp_allow_list_setup['downstream_namespace'])
    # If permit is True, all routes should be forwarded.
    # If permit is False, Routes in allow_list should be forwarded , routes not in allow_list

    router_mac, mg_facts, ptf_ip, exabgp_port_list, exabgp_port_list_v6, recv_port_list = prepare_param
    ipv4_route_list, ipv6_route_list, traffic_data_ipv4_forward, traffic_data_ipv6_forward, \
        traffic_data_ipv4_drop, traffic_data_ipv6_drop = generate_route_and_traffic_data[FUNCTION]
    for exabgp_port, exabgp_port_v6, recv_port in zip(exabgp_port_list, exabgp_port_list_v6, recv_port_list):
        ptf_interfaces = get_t2_ptf_intfs(mg_facts)
        if permit:
            validate_traffic(ptfadapter, [traffic_data_ipv4_forward, traffic_data_ipv6_forward], router_mac,
                             ptf_interfaces, recv_port)
        else:
            validate_traffic(ptfadapter, [traffic_data_ipv4_drop, traffic_data_ipv6_drop], router_mac,
                             ptf_interfaces, recv_port)
