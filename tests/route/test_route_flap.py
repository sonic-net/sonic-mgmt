import requests
import json
import logging
import time
import math
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
# Refer to announce_routes.py, which is called in add-topo period
TOR_SUBNET_SIZE = 128
M0_SUBNET_SIZE = 64
MX_SUBNET_SIZE = 64


def get_prefix_len_by_net_size(net_size):
    return 32 - int(math.log(net_size, 2))


def get_route_prefix_len(tbinfo, common_config):
    if tbinfo["topo"]["name"] == "m0":
        subnet_size = common_config.get("m0_subnet_size", M0_SUBNET_SIZE)
    elif tbinfo["topo"]["name"] == "mx":
        subnet_size = common_config.get("mx_subnet_size", MX_SUBNET_SIZE)
    else:
        subnet_size = common_config.get("tor_subnet_size", TOR_SUBNET_SIZE)
    return get_prefix_len_by_net_size(subnet_size)


@pytest.fixture(scope="module")
def announce_default_routes(localhost, tbinfo):
    """
    Fixture that will withdraw and announce default routes at teardown
    """
    yield

    ptf_ip = tbinfo["ptf_ip"]
    topo_name = tbinfo["topo"]["name"]
    if topo_name not in ['t0', 'm0', 'mx']:
        return
    logger.info(
        "withdraw and announce default ipv4 and ipv6 routes for {}".format(topo_name))
    localhost.announce_routes(
        topo_name=topo_name, ptf_ip=ptf_ip, action=WITHDRAW, path="../ansible/")
    localhost.announce_routes(
        topo_name=topo_name, ptf_ip=ptf_ip, action=ANNOUNCE, path="../ansible/")


def change_route(operation, ptfip, route, nexthop, port, aspath):
    url = "http://%s:%d" % (ptfip, port)
    data = {
        "command": "%s route %s next-hop %s as-path [ %s ]" % (operation, route, nexthop, aspath)}
    r = requests.post(url, data=data)
    assert r.status_code == 200


def announce_route(ptfip, route, nexthop, port, aspath):
    change_route(ANNOUNCE, ptfip, route, nexthop, port, aspath)


def withdraw_route(ptfip, route, nexthop, port, aspath):
    change_route(WITHDRAW, ptfip, route, nexthop, port, aspath)


def get_ptf_recv_ports(asichost, tbinfo):
    """The collector IP is a destination reachable by default.
    So we need to collect the uplink ports to do a packet capture
    """
    recv_ports = []
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)
    for ptf_idx in list(mg_facts["minigraph_ptf_indices"].values()):
        recv_ports.append(ptf_idx)
    return recv_ports


def get_ptf_send_ports(asichost, tbinfo, dev_port):
    if tbinfo['topo']['name'] in ['t0', 't1-lag', 'm0']:
        mg_facts = asichost.get_extended_minigraph_facts(tbinfo)
        member_port = mg_facts['minigraph_portchannels'][dev_port]['members']
        send_port = mg_facts['minigraph_ptf_indices'][member_port[0]]
    else:
        mg_facts = asichost.get_extended_minigraph_facts(tbinfo)
        ports = natsorted(list(mg_facts['minigraph_ports'].keys()))
        send_port = mg_facts['minigraph_ptf_indices'][ports[0]]
    return send_port


def check_route(asichost, route, dev_port, operation):
    cmd = ' -c "show ip route {} json"'.format(route)
    out = json.loads(asichost.run_vtysh(cmd)['stdout'])
    nexthops = out[route][0]['nexthops']
    result = [hop['interfaceName'] for hop in nexthops if 'interfaceName' in hop.keys()]
    if operation == WITHDRAW:
        pytest_assert(dev_port not in result,
                      "Route {} was not withdraw {}".format(route, result))
    else:
        pytest_assert(dev_port in result,
                      "Route {} was not announced {}".format(route, result))

def send_recv_ping_packet(ptfadapter, ptf_send_port, ptf_recv_ports, dst_mac, exp_src_mac, src_ip, dst_ip):
    # use ptf sender interface mac for easy identify testing packets
    src_mac = ptfadapter.dataplane.get_mac(0, ptf_send_port)
    pkt = testutils.simple_icmp_packet(
        eth_dst=dst_mac, eth_src=src_mac, ip_src=src_ip, ip_dst=dst_ip, icmp_type=8, icmp_code=0)

    ext_pkt = pkt.copy()
    ext_pkt['Ether'].src = exp_src_mac

    masked_exp_pkt = Mask(ext_pkt)
    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "tos")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "id")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "flags")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "frag")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")

    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "code")
    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "chksum")
    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "id")
    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "seq")

    logger.info('send ping request packet send port {}, recv port {}, dmac: {}, dip: {}'.format(
        ptf_send_port, ptf_recv_ports, dst_mac, dst_ip))
    testutils.send(ptfadapter, ptf_send_port, pkt)
    testutils.verify_packet_any_port(ptfadapter, masked_exp_pkt, ptf_recv_ports, timeout=WAIT_EXPECTED_PACKET_TIMEOUT)


def get_ip_route_info(asichost):
    cmd = " -c 'show ip bgp ipv4 json'"
    output = json.loads(asichost.run_vtysh(cmd)['stdout'])
    return output['routes']


def get_exabgp_port(duthost, tbinfo, dev_port):
    tor1 = duthost.shell(
        "show ip int | grep -w {} | awk '{{print $4}}'".format(dev_port))['stdout']
    tor1_offset = tbinfo['topo']['properties']['topology']['VMs'][tor1]['vm_offset']
    tor1_exabgp_port = EXABGP_BASE_PORT + tor1_offset
    return tor1_exabgp_port


def is_dualtor(tbinfo):
    """Check if the testbed is dualtor."""
    return "dualtor" in tbinfo["topo"]["name"]


def test_route_flap(duthosts, tbinfo, ptfhost, ptfadapter,
                    get_function_conpleteness_level, announce_default_routes, 
                    enum_rand_one_per_hwsku_frontend_hostname, enum_rand_one_frontend_asic_index):
    ptf_ip = tbinfo['ptf_ip']
    common_config = tbinfo['topo']['properties']['configuration_properties'].get(
        'common', {})
    nexthop = common_config.get('nhipv4', NHIPV4)
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    # On dual-tor, unicast upstream l3 packet destination mac should be vlan mac
    # After routing, output packet source mac will be replaced with port-channel mac (same as dut_mac)
    # On dual-tor, vlan mac is different with dut_mac. U0/L0 use same vlan mac for AR response
    # On single tor, vlan mac (if exists) is same as dut_mac
    dut_mac = duthost.facts['router_mac']
    vlan_mac = ""
    if is_dualtor(tbinfo):
        # Just let it crash if missing vlan configs on dual-tor
        vlan_cfgs = tbinfo['topo']['properties']['topology']['DUT']['vlan_configs']

        if vlan_cfgs and 'default_vlan_config' in vlan_cfgs:
            default_vlan_name = vlan_cfgs['default_vlan_config']
            if default_vlan_name:
                for vlan in list(vlan_cfgs[default_vlan_name].values()):
                    if 'mac' in vlan and vlan['mac']:
                        vlan_mac = vlan['mac']
                        break
        pytest_assert(vlan_mac, 'dual-tor without vlan mac !!!')
    else:
        vlan_mac = dut_mac

    # get dst_prefix_set and aspath
    routes = namedtuple('routes', ['route', 'aspath'])
    iproute_info = get_ip_route_info(asichost)
    dst_prefix_set = set()
    route_prefix_len = get_route_prefix_len(tbinfo, common_config)
    
    for route_prefix in iproute_info:
        if "/{}".format(route_prefix_len) in route_prefix:
            # multi-asics can have more than 1 routes in iproute_info[route_prefix], even single-asics have only 1
            for route_per_prefix in iproute_info[route_prefix]:
                route_type = route_per_prefix.get('pathFrom', 'external')
                if route_type == 'internal':
                    continue
                # Use only multipath routes, othervise there will be announced new routes to T0 neigbours on t1 topo
                multipath = route_per_prefix.get('multipath', False)
                if multipath:
                    out = route_per_prefix.get('path').split(' ')
                    aspath = out[1:]
                    entry = routes(route_prefix, ' '.join(aspath))
                    dst_prefix_set.add(entry)
    pytest_assert(dst_prefix_set, "dst_prefix_set is empty")

    dev_port = None
    for dst_prefix in dst_prefix_set:
        if dev_port:
            break
        route_to_ping = dst_prefix.route
        cmd = '-c "show ip route {} json"'.format(route_to_ping)
        dev = json.loads(asichost.run_vtysh(cmd)['stdout'])
        dev_port = dev[route_to_ping][0]['nexthops'][0]['interfaceName']

    pytest_assert(dev_port, "dev_port not exist")
    route_nums = len(dst_prefix_set)
    logger.info("route_nums = %d" % route_nums)

    # choose one ptf port to send msg
    ptf_send_port = get_ptf_send_ports(asichost, tbinfo, dev_port)
    ptf_recv_ports = get_ptf_recv_ports(asichost, tbinfo)

    exabgp_port = get_exabgp_port(duthost, tbinfo, dev_port)
    logger.info("exabgp_port = %d" % exabgp_port)
    ping_ip = route_to_ping.strip('/{}'.format(route_prefix_len))

    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = 'basic'

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    # accommadate for multi-asic which could have ~5k routes
    divisor = 100 if duthost.is_multi_asic else 10
    while loop_times > 0:
        logger.info("Round %s" % loop_times)
        route_index = 1
        while route_index < route_nums/divisor:
            dst_prefix = list(dst_prefix_set)[route_index].route
            aspath = list(dst_prefix_set)[route_index].aspath

            # test link status
            send_recv_ping_packet(
                ptfadapter, ptf_send_port, ptf_recv_ports, vlan_mac, dut_mac, ptf_ip, ping_ip)
            withdraw_route(ptf_ip, dst_prefix, nexthop, exabgp_port, aspath)
            # Check if route is withdraw with first 3 routes
            if route_index < 4:
                time.sleep(1)
                check_route(asichost, dst_prefix, dev_port, WITHDRAW)
            send_recv_ping_packet(
                ptfadapter, ptf_send_port, ptf_recv_ports, vlan_mac, dut_mac, ptf_ip, ping_ip)

            announce_route(ptf_ip, dst_prefix, nexthop, exabgp_port, aspath)
            # Check if route is announced with first 3 routes
            if route_index < 4:
                time.sleep(1)
                check_route(asichost, dst_prefix, dev_port, ANNOUNCE)
            send_recv_ping_packet(
                ptfadapter, ptf_send_port, ptf_recv_ports, vlan_mac, dut_mac, ptf_ip, ping_ip)
            route_index += 1

        loop_times -= 1

    logger.info("End")
