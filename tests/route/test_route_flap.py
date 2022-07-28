import requests
import json
import logging
import time
from collections import namedtuple
import pytest
import ptf.testutils as testutils
import ptf.packet as scapy

from ptf.mask import Mask
from natsort import natsorted
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

LOOP_TIMES_LEVEL_MAP = {
    'debug': 1,
    'basic': 3,
    'confident': 10,
    'thorough': 20,
    'diagnose': 50
}

WAIT_EXPECTED_PACKET_TIMEOUT = 5
EXABGP_BASE_PORT = 5000
NHIPV4 = '10.10.246.254'
WITHDRAW = 'withdraw'
ANNOUNCE = 'announce'


@pytest.fixture(scope="module")
def announce_default_routes(localhost, tbinfo):
    """
    Fixture that will withdraw and announce default routes at teardown
    """
    yield

    ptf_ip = tbinfo["ptf_ip"]
    topo_name = tbinfo["topo"]["name"]
    logger.info("withdraw and announce default ipv4 and ipv6 routes for {}".format(topo_name))
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action=WITHDRAW, path="../ansible/")
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action=ANNOUNCE, path="../ansible/")


def change_route(operation, ptfip, route, nexthop, port, aspath):
    url = "http://%s:%d" % (ptfip, port)
    data = {"command": "%s route %s next-hop %s as-path [ %s ]" % (operation, route, nexthop, aspath)}
    r = requests.post(url, data=data)
    assert r.status_code == 200


def announce_route(ptfip, route, nexthop, port, aspath):
    change_route(ANNOUNCE, ptfip, route, nexthop, port, aspath)


def withdraw_route(ptfip, route, nexthop, port, aspath):
    change_route(WITHDRAW, ptfip, route, nexthop, port, aspath)


def get_ptf_recv_ports(duthost, tbinfo):
    """The collector IP is a destination reachable by default.
    So we need to collect the uplink ports to do a packet capture
    """
    recv_ports = []
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for ptf_idx in mg_facts["minigraph_ptf_indices"].values():
        recv_ports.append(ptf_idx)
    return recv_ports


def get_ptf_send_ports(duthost, tbinfo, dev_port):
    if tbinfo['topo']['name'] in ['t0', 't1-lag']:
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        member_port = mg_facts['minigraph_portchannels'][dev_port]['members']
        send_port = mg_facts['minigraph_ptf_indices'][member_port[0]]
    else:
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ports = natsorted(mg_facts['minigraph_ports'].keys())
        send_port = mg_facts['minigraph_ptf_indices'][ports[0]]
    return send_port


def check_route(duthost, route, dev_port, operation):
    out = json.loads(duthost.shell('vtysh -c "show ip route {} json"'.format(route), verbose=False)['stdout'])
    result = [nexthop['interfaceName'] for nexthop in out[route][0]['nexthops']]
    if operation == WITHDRAW:
        pytest_assert(dev_port not in result, "Route {} was not withdraw {}".format(route, result))
    else:
        pytest_assert(dev_port in result, "Route {} was not announced {}".format(route, result))


def send_recv_ping_packet(ptfadapter, ptf_send_port, ptf_recv_ports, dst_mac, src_ip, dst_ip):
    pkt = testutils.simple_icmp_packet(eth_dst = dst_mac, ip_src = src_ip, ip_dst = dst_ip, icmp_type=8, icmp_data="")

    ext_pkt = pkt.copy()
    ext_pkt['Ether'].src = dst_mac

    masked_exp_pkt = Mask(ext_pkt)
    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "tos")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "id")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP,"flags")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP,"frag")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP,"ttl")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")

    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "code")
    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "chksum")
    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "id")
    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "seq")

    logger.info('send ping request packet send port {}, recv port {}, dmac: {}, dip: {}'.format(ptf_send_port, ptf_recv_ports, dst_mac, dst_ip))
    testutils.send(ptfadapter, ptf_send_port, pkt)
    testutils.verify_packet_any_port(ptfadapter, masked_exp_pkt, ptf_recv_ports, timeout=WAIT_EXPECTED_PACKET_TIMEOUT)


def get_ip_route_info(duthost):
    output = json.loads(duthost.shell('vtysh -c "show ip bgp ipv4 json"', verbose=False)['stdout'])
    return output['routes']


def get_exabgp_port(duthost, tbinfo, dev_port):
    tor1 = duthost.shell("show ip int | grep -w {} | awk '{{print $4}}'".format(dev_port))['stdout']
    tor1_offset = tbinfo['topo']['properties']['topology']['VMs'][tor1]['vm_offset']
    tor1_exabgp_port = EXABGP_BASE_PORT + tor1_offset
    return tor1_exabgp_port


def test_route_flap(duthost, tbinfo, ptfhost, ptfadapter,
                    get_function_conpleteness_level, announce_default_routes):
    ptf_ip = tbinfo['ptf_ip']
    common_config = tbinfo['topo']['properties']['configuration_properties'].get('common', {})
    nexthop = common_config.get('nhipv4', NHIPV4)
    dut_mac = duthost.facts['router_mac']

    #get dst_prefix_list and aspath
    routes = namedtuple('routes', ['route', 'aspath'])
    iproute_info = get_ip_route_info(duthost)
    dst_prefix_list = []
    for route_prefix in iproute_info:
        if "/25" in route_prefix:
            # Use only multipath routes, othervise there will be announced new routes to T0 neigbours on t1 topo
            multipath = iproute_info[route_prefix][0].get('multipath', False)
            if multipath:
                out = iproute_info[route_prefix][0].get('path').split(' ')
                aspath = out[1:]
                entry = routes(route_prefix, ' '.join(aspath))
                dst_prefix_list.append(entry)

    route_to_ping = dst_prefix_list[0].route
    dev = json.loads(duthost.shell('vtysh -c "show ip route {} json"'.format(route_to_ping))['stdout'])
    dev_port = dev[route_to_ping][0]['nexthops'][0]['interfaceName']

    route_nums = len(dst_prefix_list)
    logger.info("route_nums = %d" % route_nums)

    #choose one ptf port to send msg
    ptf_send_port = get_ptf_send_ports(duthost, tbinfo, dev_port)
    ptf_recv_ports = get_ptf_recv_ports(duthost, tbinfo)

    exabgp_port = get_exabgp_port(duthost, tbinfo, dev_port)
    logger.info("exabgp_port = %d" % exabgp_port)
    ping_ip = route_to_ping.strip('/25')

    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = 'basic'

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    while loop_times > 0:
        logger.info("Round %s" % loop_times)
        route_index = 1
        while route_index < route_nums/10:
            dst_prefix = dst_prefix_list[route_index].route
            aspath = dst_prefix_list[route_index].aspath

            #test link status
            send_recv_ping_packet(ptfadapter, ptf_send_port, ptf_recv_ports, dut_mac, ptf_ip, ping_ip)

            withdraw_route(ptf_ip, dst_prefix, nexthop, exabgp_port, aspath)
            # Check if route is withdraw with first 3 routes
            if route_index < 4:
                time.sleep(1)
                check_route(duthost, dst_prefix, dev_port, WITHDRAW)
            send_recv_ping_packet(ptfadapter, ptf_send_port, ptf_recv_ports, dut_mac, ptf_ip, ping_ip)

            announce_route(ptf_ip, dst_prefix, nexthop, exabgp_port, aspath)
            # Check if route is announced with first 3 routes
            if route_index < 4:
                time.sleep(1)
                check_route(duthost, dst_prefix, dev_port, ANNOUNCE)
            send_recv_ping_packet(ptfadapter, ptf_send_port, ptf_recv_ports, dut_mac, ptf_ip, ping_ip)

            route_index += 1

        loop_times -= 1

    logger.info("End")
