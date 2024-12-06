import requests
import json
import logging
import time
import math
from collections import namedtuple
import pytest
import ptf.testutils as testutils
import ptf.packet as scapy
from tests.common.dualtor.mux_simulator_control import \
            toggle_all_simulator_ports_to_enum_rand_one_per_hwsku_frontend_host_m   # noqa F401

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

WAIT_EXPECTED_PACKET_TIMEOUT = 15
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
    r = requests.post(url, data=data, proxies={"http": None, "https": None})
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
    for ptf_idx in list(mg_facts["minigraph_ptf_indices"].values()):
        recv_ports.append(ptf_idx)
    return recv_ports


def get_neighbor_info(duthost, dev_port, tbinfo):
    """
    This function returns the neighbor type of
    the chosen dev_port based on route info

    Args:
        duthost: DUT belong to the testbed.
        dev_port: Chosen dev_port based on route info
        tbinfo: A fixture to gather information about the testbed.
    """
    neighbor_type = ''
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    neighs = config_facts['BGP_NEIGHBOR']
    dev_neigh_mdata = config_facts['DEVICE_NEIGHBOR_METADATA'] if 'DEVICE_NEIGHBOR_METADATA' in config_facts else {}
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    nbr_port_map = mg_facts['minigraph_port_name_to_alias_map'] \
        if 'minigraph_port_name_to_alias_map' in mg_facts else {}
    for neighbor in neighs:
        local_ip = neighs[neighbor]['local_addr']
        nbr_port = get_port_by_ip(config_facts, local_ip)
        if 'Ethernet' in nbr_port:
            for p_key, p_value in nbr_port_map.items():
                if p_value == nbr_port:
                    nbr_port = p_key
        if dev_port == nbr_port:
            neighbor_name = neighs[neighbor]['name']
    for k, v in dev_neigh_mdata.items():
        if k == neighbor_name:
            neighbor_type = v['type']
    return neighbor_type


def get_port_by_ip(config_facts, ipaddr):
    """
    This function returns port name based on ip address
    """
    if ':' in ipaddr:
        iptype = "ipv6"
    else:
        iptype = "ipv4"

    intf = {}
    intf.update(config_facts.get('INTERFACE', {}))
    if "PORTCHANNEL_INTERFACE" in config_facts:
        intf.update(config_facts['PORTCHANNEL_INTERFACE'])
    for a_intf in intf:
        for addrs in intf[a_intf]:
            intf_ip = addrs.split('/')
            if iptype == 'ipv6' and ':' in intf_ip[0] and intf_ip[0].lower() == ipaddr.lower():
                return a_intf
            elif iptype == 'ipv4' and ':' not in intf_ip[0] and intf_ip[0] == ipaddr:
                return a_intf

    raise Exception("Did not find port for IP %s" % ipaddr)


def get_all_ptf_recv_ports(duthosts, tbinfo, recv_neigh_list):
    """
    This function returns all the ptf ports of
    all the duts w.r.t received neighbors' list, even for multi dut chassis
    """
    recv_ports = []
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        for interface, neighbor in mg_facts["minigraph_neighbors"].items():
            if neighbor['name'] in recv_neigh_list and interface in mg_facts["minigraph_ptf_indices"]:
                ptf_idx = mg_facts["minigraph_ptf_indices"][interface]
                recv_ports.append(ptf_idx)
    return recv_ports


def get_all_recv_neigh(duthosts, neigh_type):
    """
    This function returns all the neighbors of
    same type for dut, including multi dut chassis
    """
    recv_neigh_list = []
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        device_neighbor_metadata = config_facts['DEVICE_NEIGHBOR_METADATA']
        for k, v in device_neighbor_metadata.items():
            if v['type'] == neigh_type:
                recv_neigh_list.append(k)
    return recv_neigh_list


def get_ptf_send_ports(duthost, tbinfo, dev_port):
    if tbinfo['topo']['name'] in ['t0', 't1-lag', 'm0']:
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        member_port = mg_facts['minigraph_portchannels'][dev_port]['members']
        send_port = mg_facts['minigraph_ptf_indices'][member_port[0]]
    else:
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ports = natsorted(list(mg_facts['minigraph_ports'].keys()))
        send_port = mg_facts['minigraph_ptf_indices'][ports[0]]
    return send_port


def check_route(duthost, route, dev_port, operation):
    result = []
    if duthost.is_multi_asic:
        cmd = ' -c "show ip route {} json"'.format(route)
        for asichost in duthost.frontend_asics:
            out = json.loads(asichost.run_vtysh(cmd)['stdout'])
            if len(out) == 0:
                logger.info("Route table empty on asic {}, check other asic".format(asichost.asic_index))
                continue
            nexthops = out[route][0]['nexthops']
            routes_per_asic = [hop['interfaceName'] for hop in nexthops if 'interfaceName' in hop.keys()]
            result.extend(routes_per_asic)
    else:
        cmd = 'vtysh -c "show ip route {} json"'.format(route)
        out = json.loads(duthost.shell(cmd, verbose=False)['stdout'])
        nexthops = out[route][0]['nexthops']
        result = [hop['interfaceName'] for hop in nexthops if 'interfaceName' in hop.keys()]
    if operation == WITHDRAW:
        pytest_assert(dev_port not in result,
                      "Route {} was not withdraw {}".format(route, result))
    else:
        pytest_assert(dev_port in result,
                      "Route {} was not announced {}".format(route, result))


def send_recv_ping_packet(ptfadapter, ptf_send_port, ptf_recv_ports, dst_mac, exp_src_mac, src_ip, dst_ip, tbinfo):
    # use ptf sender interface mac for easy identify testing packets
    src_mac = ptfadapter.dataplane.get_mac(0, ptf_send_port)
    pkt = testutils.simple_icmp_packet(
        eth_dst=dst_mac, eth_src=src_mac, ip_src=src_ip, ip_dst=dst_ip, icmp_type=8, icmp_code=0)

    ext_pkt = pkt.copy()
    ext_pkt['Ether'].src = exp_src_mac

    masked_exp_pkt = Mask(ext_pkt)
    # Mask src_mac for T2 multi-dut chassis, since the packet can be received on any of the dut's ptf-ports
    if 't2' in tbinfo["topo"]["name"]:
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
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
    testutils.verify_packet_any_port(
        ptfadapter, masked_exp_pkt, ptf_recv_ports, timeout=WAIT_EXPECTED_PACKET_TIMEOUT)


def filter_routes(iproute_info, route_prefix_len):
    # Note that here iproute_info is a list of one dictionary
    filtered_iproutes = {}
    for route_prefix in iproute_info:
        if "/{}".format(route_prefix_len) not in route_prefix:
            continue
        # multi-asics can have more than 1 routes in iproute_info[route_prefix], even single-asics have only 1
        for route_per_prefix in iproute_info[route_prefix]:
            route_type = route_per_prefix.get('pathFrom', 'external')
            if route_type == 'internal':
                continue
            # Use only multipath routes, othervise there will be announced new routes to T0 neigbours on t1 topo
            multipath = route_per_prefix.get('multipath', False)
            if not multipath:
                continue
            filtered_iproutes[route_prefix] = iproute_info[route_prefix]
    return filtered_iproutes


def get_filtered_iproute_info(duthost, route_prefix_len):
    dev = {}
    if duthost.is_multi_asic:
        cmd = " -c 'show ip bgp ipv4 json'"
        for asic in duthost.frontend_asics:
            output = json.loads(asic.run_vtysh(cmd)['stdout'])
            dev.update(filter_routes(output['routes'], route_prefix_len))
    else:
        output = json.loads(duthost.shell('vtysh -c "show ip bgp ipv4 json"', verbose=False)['stdout'])
        dev = filter_routes(output['routes'], route_prefix_len)
    return dev


def get_exabgp_port(duthost, tbinfo, dev_port):
    tor1 = duthost.shell(
        "show ip int | grep -w {} | awk '{{print $4}}'".format(dev_port))['stdout']
    tor1_offset = tbinfo['topo']['properties']['topology']['VMs'][tor1]['vm_offset']
    tor1_exabgp_port = EXABGP_BASE_PORT + tor1_offset
    return tor1_exabgp_port


def is_dualtor(tbinfo):
    """Check if the testbed is dualtor."""
    return "dualtor" in tbinfo["topo"]["name"]


def get_internal_interfaces(duthost):
    """
    This function returns internal interfaces for any
    multi-asic dut, including voq/packet chassis
    """
    internal_intfs = []

    # First check for packet chassis, or any dut that has PORTCHANNEL_MEMBER in config db
    pcs = duthost.get_portchannel_member()
    for pc in pcs:
        """
        For packet chassis, 'pcs' looks like:
        ["PortChannel101|Ethernet104", "PortChannel01|Ethernet-BPxx",...]
        """
        if 'IB' in pc or 'BP' in pc:
            internal_intfs.append(pc)

    # Then check for voq chassis: get voq inband interface for later filtering
    voq_inband_interfaces = duthost.get_voq_inband_interfaces()
    internal_intfs += voq_inband_interfaces

    return internal_intfs


def get_dev_port_and_route(duthost, asichost, dst_prefix_set):
    dev_port = None
    route_to_ping = None
    # Get internal interfaces for later filtering
    internal_intfs = get_internal_interfaces(duthost)
    for dst_prefix in dst_prefix_set:
        if dev_port:
            break
        route_to_ping = dst_prefix.route
        cmd = ' -c "show ip route {} json"'.format(route_to_ping)
        if duthost.is_multi_asic:
            for asic in duthost.frontend_asics:
                if dev_port:
                    break
                dev = json.loads(asic.run_vtysh(cmd)['stdout'])
                for per_hop in dev[route_to_ping][0]['nexthops']:
                    if dev_port:
                        break
                    if 'interfaceName' not in per_hop.keys():
                        continue
                    if 'ip' not in per_hop.keys():
                        continue
                    if per_hop['interfaceName'] in internal_intfs:
                        continue
                    port = per_hop['interfaceName']
                    neigh = duthost.shell("show ip int | grep -w {}".format(port), module_ignore_errors=True)['stdout']
                    if neigh == '':
                        logger.info("{} is still internal interface, skipping".format(port))
                    else:
                        dev_port = port
        else:
            dev = json.loads(asichost.run_vtysh(cmd)['stdout'])
            for per_hop in dev[route_to_ping][0]['nexthops']:
                if dev_port:
                    break
                if 'interfaceName' not in per_hop.keys():
                    continue
                # For chassis, even single-asic linecard could have internal interface
                if per_hop['interfaceName'] in internal_intfs:
                    continue
                if 'IB' in per_hop['interfaceName'] or 'BP' in per_hop['interfaceName']:
                    continue
                dev_port = per_hop['interfaceName']
    pytest_assert(dev_port, "dev_port not exist")
    return dev_port, route_to_ping


def test_route_flap(duthosts, tbinfo, ptfhost, ptfadapter,
                    get_function_completeness_level, announce_default_routes,
                    enum_rand_one_per_hwsku_frontend_hostname,
                    enum_upstream_dut_hostname, enum_rand_one_frontend_asic_index,
                    setup_standby_ports_on_non_enum_rand_one_per_hwsku_frontend_host_m,                     # noqa F811
                    toggle_all_simulator_ports_to_enum_rand_one_per_hwsku_frontend_host_m, loganalyzer):    # noqa F811
    ptf_ip = tbinfo['ptf_ip']
    common_config = tbinfo['topo']['properties']['configuration_properties'].get(
        'common', {})
    nexthop = common_config.get('nhipv4', NHIPV4)
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    duthost_upstream = duthosts[enum_upstream_dut_hostname]
    if loganalyzer:
        ignoreRegex = [
            ".*ERR.*\"missed_FRR_routes\".*"
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)

    # On dual-tor, unicast upstream l3 packet destination mac should be vlan mac
    # After routing, output packet source mac will be replaced with port-channel mac (same as dut_mac)
    # On dual-tor, vlan mac is different with dut_mac. U0/L0 use same vlan mac for AR response
    # On single tor, vlan mac (if exists) is same as dut_mac
    dut_mac = duthost.facts['router_mac']
    # Each Asic has different MAC in multi-asic system. Traffic should be sent with asichost DMAC
    # in multi-asic scenarios
    if duthost.is_multi_asic:
        dut_mac = asichost.get_router_mac().lower()
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
    route_prefix_len = get_route_prefix_len(tbinfo, common_config)
    routes = namedtuple('routes', ['route', 'aspath'])
    filtered_iproute_info = get_filtered_iproute_info(duthost, route_prefix_len)
    if not filtered_iproute_info:
        pytest.skip("Skip this test for current topo.\
                    At least 1 multipath route coming from ebgp is needed!")

    dst_prefix_set = set()
    for route_prefix in filtered_iproute_info:
        # multi-asics can have more than 1 routes in iproute_info[route_prefix], even single-asics have only 1
        for route_per_prefix in filtered_iproute_info[route_prefix]:
            out = route_per_prefix.get('path').split(' ')
            aspath = out[1:]
            entry = routes(route_prefix, ' '.join(aspath))
            dst_prefix_set.add(entry)
    pytest_assert(dst_prefix_set, "dst_prefix_set is empty")

    dev_port, route_to_ping = get_dev_port_and_route(duthost, asichost, dst_prefix_set)
    route_nums = len(dst_prefix_set)
    logger.info("route_nums = %d" % route_nums)

    # choose one ptf port to send msg
    ptf_send_port = get_ptf_send_ports(duthost, tbinfo, dev_port)

    # Get the list of ptf ports to receive msg, even for multi-dut scenario
    neighbor_type = get_neighbor_info(duthost, dev_port, tbinfo)
    recv_neigh_list = get_all_recv_neigh(duthosts, neighbor_type)
    logger.info("Receiving ports neighbor list : {}".format(recv_neigh_list))
    if 't2' in tbinfo["topo"]["type"] and duthost == duthost_upstream:
        ptf_recv_ports = get_ptf_recv_ports(duthost, tbinfo)
    else:
        ptf_recv_ports = get_all_ptf_recv_ports(duthosts, tbinfo, recv_neigh_list)
    logger.info("Receiving ptf ports list : {}".format(ptf_recv_ports))

    exabgp_port = get_exabgp_port(duthost, tbinfo, dev_port)
    logger.info("exabgp_port = %d" % exabgp_port)
    ping_ip = route_to_ping.strip('/{}'.format(route_prefix_len))

    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = 'debug'

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    # accommadate for t2 chassis which could have 30k~50k routes
    def switch(x):
        return {
            't2': 1000,
            't1': 100,
        }.get(x, 10)
    divisor = switch(tbinfo["topo"]["name"])
    while loop_times > 0:
        logger.info("Round %s" % loop_times)
        route_index = 1
        while route_index < route_nums/divisor:
            dst_prefix = list(dst_prefix_set)[route_index].route
            aspath = list(dst_prefix_set)[route_index].aspath

            # test link status
            send_recv_ping_packet(
                ptfadapter, ptf_send_port, ptf_recv_ports, vlan_mac, dut_mac, ptf_ip, ping_ip, tbinfo)

            withdraw_route(ptf_ip, dst_prefix, nexthop, exabgp_port, aspath)
            # Check if route is withdraw with first 3 routes
            if route_index < 4:
                time.sleep(1)
                check_route(duthost, dst_prefix, dev_port, WITHDRAW)
            send_recv_ping_packet(
                ptfadapter, ptf_send_port, ptf_recv_ports, vlan_mac, dut_mac, ptf_ip, ping_ip, tbinfo)

            announce_route(ptf_ip, dst_prefix, nexthop, exabgp_port, aspath)
            # Check if route is announced with first 3 routes
            if route_index < 4:
                time.sleep(1)
                check_route(duthost, dst_prefix, dev_port, ANNOUNCE)
            send_recv_ping_packet(
                ptfadapter, ptf_send_port, ptf_recv_ports, vlan_mac, dut_mac, ptf_ip, ping_ip, tbinfo)

            route_index += 1

        loop_times -= 1

    logger.info("End")
