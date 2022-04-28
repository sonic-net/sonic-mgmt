import re
import os
import json
import time
import logging
import ipaddress

import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

from tests.common.helpers.assertions import pytest_assert
from collections import OrderedDict

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
PTF_NN_AGENT_TEMPLATE = 'ptf_nn_agent.conf.ptf.j2'
PTF_SCRIPT_TEMP = 'ptf_portchannel.j2'
RENDERED_SCRIPT_PATH = '/tmp/ptf_portchannel.sh'
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
CONFIG_DB_TEMP = '/etc/sonic/config_db.json'
CONFIG_DB_BACKUP = '/etc/sonic/config_db.json.bak'
PC_NAME_TEMPLATE = 'PortChannel{0:04d}'
MCLAG_LOCAL_IP = ipaddress.IPv4Interface(u"10.100.1.1/30")
MCLAG_PEER_IP = ipaddress.IPv4Interface(u"{}/{}".format(MCLAG_LOCAL_IP.ip + 1, MCLAG_LOCAL_IP._prefixlen))
MCLAG_PEER_LINK_IP_ACTIVE = ipaddress.IPv4Interface(u"13.1.1.1/30")
MCLAG_PEER_LINK_IP_STANDBY = ipaddress.IPv4Interface(u"{}/{}".format(MCLAG_PEER_LINK_IP_ACTIVE.ip + 1, MCLAG_PEER_LINK_IP_ACTIVE._prefixlen))
PEER_LINK_NAME = PC_NAME_TEMPLATE.format(100)
SUBNET_CHECK = u'192.168.0.0/16'
ACTION_FORWARD = 'FORWARD'
ACTION_DROP = 'DROP'
MCLAG_DOMAINE_ID = 100
DUT1_INDEX = 0
DUT2_INDEX = 1
TCP_SPORT = 3300
TCP_DPORT = 3320
MAX_MCLAG_INTF = 24
TTL = 64
DEFAULT_SESSION_TIMEOUT = 15
NEW_SESSION_TIMEOUT = 25


def parse_vm_vlan_port(vlan):
    if isinstance(vlan, int):
        dut_index = 0
        vlan_index = vlan
        ptf_index = vlan
    else:
        m = re.match("(\d+)\.(\d+)@(\d+)", vlan)
        (dut_index, vlan_index, ptf_index) = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return (dut_index, vlan_index, ptf_index)


def get_team_port(duthost, pc):
    """
    Dump teamd info
    Args:
        duthost: DUT host object
        pc: PortChannel name
    """
    dut_team_cfg = duthost.shell("teamdctl {} config dump".format(pc))['stdout']
    dut_team_port = json.loads(dut_team_cfg)['ports'].keys()
    return dut_team_port[0]


def get_member_ptf_map(duthost, member, mg_facts, collect):
    """
    Get ptf index of PortChannel member
    Args:
        duthost: DUT host object
        member: PortChannel member name
        mg_facts: Dict with minigraph facts for each DUT
        collect: Fixture which collects main info about link connection
    """
    res = mg_facts[duthost.hostname]['minigraph_port_indices'][member]
    return collect[duthost.hostname]['ptf_map'][str(res)]


def check_lags_on_ptf(ptfhost, mclag_interfaces):
    """
    Check that lags on PTF were created and are UP
    Args:
        ptfhost: PTF host object
        mclag_interfaces: List of all mclag interfaces
    """
    out = ptfhost.shell('ip link show up type bond')['stdout']
    res = re.findall(r'PortChannel\d+', out)
    pytest_assert(len(res) == len(mclag_interfaces), "Not all PortChannels are up on PTF, {}".format(','.join(res)))

def get_vm_links(tbinfo, dut_index):
    """
    Collect info about links that lead to VMs on each DUT from Testbed info
    Args:
        tbinfo: Testbed object
        dut_index: Duthost index
    """
    result = []
    vms = tbinfo['topo']['properties']['topology']['VMs'].keys()
    for vm in vms:
        vlans = tbinfo['topo']['properties']['topology']['VMs'][vm]['vlans']
        for vlan in vlans:
            (dut_indx, vlan_indx, _) = parse_vm_vlan_port(vlan)
            if dut_indx == dut_index:
                result.append(str(vlan_indx))
    return result

def check_partner_lag_member(ptfhost, mclag_info, state='UP'):
    """
    Check partner oper state of memeber's on PTF
    Args:
        ptfhost: PTF host object
        mclag_info: Dict with information about mclag interfaces
        state: State to check, could be UP or DOWN
    """
    pytest_assert(state in ['UP', 'DOWN'], 'State to check should be UP or DOWN, not {}'.format(state))
    result = set()
    id_to_check = '61' if state == 'UP' else '1'
    for pc in mclag_info:
        member = mclag_info[pc].get('member_on_ptf', '')
        if str(member).isdigit():
            res = ptfhost.shell("cat /sys/class/net/{}/lower_eth{}/bonding_slave/ad_partner_oper_port_state".format(pc, member))['stdout']
            result.add(res)
    if id_to_check in result and len(result) == 1:
        logger.info("Partner lag member status = {}, expected {}".format(result, id_to_check))
        return True
    logger.info("Partner lag member status = {}, expected {}".format(result, id_to_check))
    return False


def get_interconnected_links(tbinfo, dut_index):
    """
    Collect infomation from Testbed info about interconnected links on each DUT
    Args:
        tbinfo: Testbed object
        dut_index: Duthost index
    """
    result = []
    devices_interconnect_interfaces = tbinfo['topo']['properties']['topology']['devices_interconnect_interfaces']
    for i in devices_interconnect_interfaces:
        for vlan in devices_interconnect_interfaces[i]:
            (dut_indx, vlan_indx, _) = parse_vm_vlan_port(vlan)
            if dut_indx == dut_index:
                result.append(str(vlan_indx))
    return result


def get_port_number(ptfhost, src_port):
    """
    Get port number of interface
    Args:
        ptfhost: PTF host object
        src_port: Port name
    """
    map = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")
    reversed_map = {map[k]:k for k in map}
    if not str(src_port).isdigit():
        return int(reversed_map[src_port])
    return int(src_port)


def get_dst_port(duthost1, duthost2, get_routes, dst_ip, collect):
    """
    Determine destination port
    Args:
        duthost1: DUT host object
        duthost2: DUT host object
        get_routes: Dict with advertised routes for each DUT
        dst_ip: Destination ip address
        collect: Fixture which collects main info about link connection
    """
    dst_ip = ipaddress.IPv4Address(dst_ip)
    for route1, route2 in zip(get_routes[duthost1.hostname], get_routes[duthost2.hostname]):
        if dst_ip in ipaddress.IPv4Network(route1):
            dst_port = collect[duthost1.hostname]['vm_link_on_ptf']
            return dst_port
        elif dst_ip in ipaddress.IPv4Network(route2):
            dst_port = collect[duthost2.hostname]['vm_link_on_ptf']
            return dst_port

def generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, src_port, dst_ip, router_mac, get_routes,
                                collect, down_link_on_dut=None, pkt_action=ACTION_FORWARD):
    """
    Generate traffic, send and verify it
    Args:
        duthost1: DUT host object
        duthost2: DUT host object
        ptfadapter: PTF adapter
        ptfhost: PTF host object
        src_port: Source port from which pkt will be sent
        dst_ip: Destination ip address
        get_routes: Dict with routes for each DUT
        collect: Fixture which collects main info about link connection
        down_link_on_dut: Name of DUT on which link is down
        pkt_action: Action to verify, forward or drop
    """
    router1_mac = duthost1.facts["router_mac"]
    router2_mac = duthost2.facts["router_mac"]
    dst_ports = get_dst_port(duthost1, duthost2, get_routes, dst_ip, collect)
    src_port = get_port_number(ptfhost, src_port)
    pkt = craft_pkt(ptfadapter, router_mac, src_port, dst_ip)
    expected_src_mac = router1_mac if dst_ports == collect[duthost1.hostname]['vm_link_on_ptf'] else router2_mac

    exp_pkt = pkt.copy()
    if down_link_on_dut:
        exp_ttl = predict_exp_ttl(duthost1, duthost2, dst_ip, down_link_on_dut)
        exp_pkt[packet.IP].ttl = exp_ttl
    exp_pkt[packet.Ether].src = unicode(expected_src_mac)

    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(packet.IP, "id")
    exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")
    exp_pkt.set_do_not_care_scapy(packet.TCP, "chksum")
    if not down_link_on_dut:
        exp_pkt.set_do_not_care_scapy(packet.IP, "ttl")

    ptfadapter.dataplane.flush()
    time.sleep(2)

    logger.info("Sending pkt from port {} to dst_ip = {}, expected dst_port = {}".format(src_port, dst_ip, dst_ports))
    logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
    testutils.send(ptfadapter, src_port, pkt)

    if pkt_action == ACTION_FORWARD:
        testutils.verify_packet(ptfadapter, exp_pkt, dst_ports)
    elif pkt_action == ACTION_DROP:
        testutils.verify_no_packet(ptfadapter, exp_pkt, dst_ports)


def craft_pkt(ptfadapter, dst_mac, src_port, dst_ip, ip_src=u'2.2.2.1', ttl=TTL, pktlen=100):
    """
    Generate packet to send
    Args:
        ptfadapter: PTF adapter
        router1_mac: MAC of DUT
        router2_mac: MAC of DUT
        src_port: Port of PTF
        dst_ip: Destination IP of pkt
        ip_src: Source IP of pkt
        ttl: Time to live
        pktlen: packet length
    """
    src_mac = ptfadapter.dataplane.get_mac(0, src_port)
    pkt = testutils.simple_tcp_packet(eth_src=src_mac,
                                      eth_dst=dst_mac,
                                      ip_src=ip_src,
                                      ip_dst=dst_ip,
                                      ip_ttl=ttl,
                                      pktlen=pktlen,
                                      tcp_sport=TCP_SPORT,
                                      tcp_dport=TCP_DPORT)
    return pkt


def predict_exp_ttl(duthost1, duthost2, dst_ip, link_down_on_dut):
    """
    Predict expected ttl of received pkt
    Args:
        duthost1: DUT host object
        duthost2: DUT host object
        dst_ip: destination ip address
        link_down_on_dut: DUT hostname
    """
    dut = duthost2 if link_down_on_dut == duthost1.hostname else duthost1
    nexthop = dut.get_ip_route_info(ipaddress.ip_address(unicode(dst_ip)))['nexthops']
    ttl = TTL - 2  if PEER_LINK_NAME in nexthop[0] else TTL - 1
    return ttl


def get_dut_routes(duthost, collect, mg_facts):
    """
    Get advertised bgp routes from DUTs
    Args:
        duthost: DUT host object
        collect: Fixture which collects main info about link connection
        mg_facts: Dict with minigraph facts for each DUT
    """
    port_indices = {mg_facts[duthost.hostname]['minigraph_port_indices'][k]:k for k in mg_facts[duthost.hostname]['minigraph_port_indices']}
    vm_link = collect[duthost.hostname]['vm_links'][0]
    vm_interface_name = port_indices[int(vm_link)]
    ip = duthost.show_ip_interface()['ansible_facts']['ip_interfaces'][vm_interface_name]['peer_ipv4']
    bgp_routes = duthost.bgp_route(neighbor=ip, direction="adv")['ansible_facts']['bgp_route_neiadv'].keys()
    return bgp_routes


def add_mclag_and_orphan_ports(duthost, collect, mg_facts, ip_base=0):
    """
    Configure mclag interfaces and orphan interfaces
    Args:
        duthost: DUT host object
        collect: Fixture which collects main info about link connection
        mg_facts: Dict with minigraph facts for each DUT
        ip_base: ip base index to be used
    """
    port_indices = {mg_facts[duthost.hostname]['minigraph_port_indices'][k]:k for k in mg_facts[duthost.hostname]['minigraph_port_indices']}
    cmds = []
    for indx, link in enumerate(collect[duthost.hostname]['host_interfaces']):
        index = indx + 1
        ip = '172.16.{}.1/24'
        if indx < len(collect[duthost.hostname]['host_interfaces'][:-2]):
            pc_name = PC_NAME_TEMPLATE.format(index)
            cmds.append('config portchannel add {}'.format(pc_name))
            cmds.append('config portchannel member add {} {}'.format(pc_name, port_indices[int(link)]))
            cmds.append('config interface ip add {} {}'.format(pc_name, ip.format(index)))
            cmds.append('config interface startup {}'.format(port_indices[int(link)]))
        else:
            cmds.append("config interface ip add {} {}".format(port_indices[int(link)], ip.format(index + ip_base)))
            cmds.append('config interface startup {}'.format(port_indices[int(link)]))
    duthost.shell_cmds(cmds=cmds)


def config_peer_link_and_keep_alive(duthost, keep_and_peer_link_member, mclag_local_ip,
                                    mclag_peer_link_ip):
    """
    Configure peer_link and keep_alive link on DUT
    Args:
        duthost: DUT host object
        collect: Fixture which collects main info about link connection
        mg_facts: Dict with minigraph facts for each DUT
        mclag_local_ip: MClag local ip address
        mclag_peer_link_ip: MClag peer ip address
    """
    cmds = []
    keep_alive_interface = keep_and_peer_link_member[duthost.hostname]['keepalive']
    peer_link_member = keep_and_peer_link_member[duthost.hostname]['peerlink']
    cmds.append('config interface ip add {} {}'.format(keep_alive_interface, mclag_local_ip))
    cmds.append("config interface startup {}".format(keep_alive_interface))

    cmds.append('config portchannel add {}'.format(PEER_LINK_NAME))
    cmds.append('config portchannel member add {} {}'.format(PEER_LINK_NAME, peer_link_member))
    cmds.append("config interface ip add {} {}".format(PEER_LINK_NAME, mclag_peer_link_ip))
    cmds.append("config interface startup {}".format(peer_link_member))
    duthost.shell_cmds(cmds=cmds)


def apply_mclag(duthost, collect, mclag_id, mclag_local_ip, mclag_peer_ip):
    """
    Enable iccpd and apply mclag configuration
    Args:
        duthost: DUT host object
        collect: Fixture which collects main info about link connection
        mclag_id: MClag domaine id number
        mclag_local_ip: MClag local ip address
        mclag_peer_ip: MClag peer ip address
    """
    cmds = []
    cmds.append('config feature state iccpd enabled')
    cmds.append('sleep 60')
    cmds.append("config mclag add {} {} {}".format(mclag_id, mclag_local_ip, mclag_peer_ip))
    cmds.append("config mclag member add {} {}".format(mclag_id, ','.join(collect[duthost.hostname]['mclag_interfaces'])))
    duthost.shell_cmds(cmds=cmds)


def remove_vlan_members(duthost, mg_facts):
    """
    Remove ports from Vlan
    Args:
        duthost: DUT host object
        mg_facts: Dict with minigraph facts for each DUT
    """
    cmd = []
    vlan = mg_facts[duthost.hostname]['minigraph_vlans'].keys()[0]
    for i in mg_facts[duthost.hostname]['minigraph_vlans'][vlan]['members']:
        cmd.append("config interface shutdown {}".format(i))
        cmd.append("sleep 1")
        cmd.append("config vlan member del {} {}".format(mg_facts[duthost.hostname]['minigraph_vlans'][vlan]['vlanid'], i))
    duthost.shell_cmds(cmds=cmd)


def mclag_intf_to_shutdown(duthost1, duthost2, mg_facts, collect, num_intf=6):
    """
    Generate a Dict with info which mclag interfaces will be shut down and on which DUTs
    Args:
        duthost1: DUT host object
        duthost2: DUT host object
        mg_facts: Dict with minigraph facts for each DUT
        collect: Fixture which collects main info about link connection
    """
    result = OrderedDict()
    for indx, pc in enumerate(collect[duthost1.hostname]['mclag_interfaces'][:num_intf]):
        member = get_team_port(duthost1, pc)
        result[pc] = {}
        if indx < (num_intf / 2):
            result[pc]['link_down_on_dut'] = duthost1.hostname
            result[pc]['member_to_shut'] = member
            result[pc]['member_on_ptf'] = get_member_ptf_map(duthost1, member, mg_facts, collect)
        else:
            result[pc]['link_down_on_dut'] = duthost2.hostname
            result[pc]['member_to_shut'] = member
            result[pc]['member_on_ptf'] = get_member_ptf_map(duthost2, member, mg_facts, collect)
    return result


def check_keepalive_link(duthost1, duthost2, status):
    """
    Check keepalive link status
    Args:
        duthost1: DUT host object
        duthost2: DUT host object
        status: Expected status of keepalive link OK or ERROR
    """
    dut1_keepalive_status = duthost1.shell("mclagdctl dump state|grep keepalive")['stdout'].split(":")[-1].strip()
    dut2_keepalive_status = duthost2.shell("mclagdctl dump state|grep keepalive")['stdout'].split(":")[-1].strip()
    pytest_assert(dut1_keepalive_status == dut2_keepalive_status == status,
                  "Keepalive status should be {} not {}, {}".format(status, dut1_keepalive_status, dut2_keepalive_status))


def gen_list_pcs_to_check(duthost, mg_facts, collect):
    """
    Generate list of mclag interfaces to check
    Args:
        duthost: DUT host object
        mg_facts: Dict with minigraph facts for each DUT
        collect: Fixture which collects main info about link connection
    """
    result = OrderedDict()
    for pc in collect[duthost.hostname]['mclag_interfaces']:
        member = get_team_port(duthost, pc)
        result[pc] = {}
        result[pc]['member_to_shut'] = member
        result[pc]['member_on_ptf'] = get_member_ptf_map(duthost, member, mg_facts, collect)
    return result
