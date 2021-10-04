import os
import time
import random

from collections import OrderedDict

import pytest

import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.common.pkt_filter.filter_pkt_in_buffer import FilterPktBuffer
from tests.common import constants


BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = os.path.join('tmp', os.path.basename(BASE_DIR))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
SUB_PORTS_TEMPLATE = 'sub_port_config.j2'
TUNNEL_TEMPLATE = 'tunnel_config.j2'
ACTION_FWD = 'fwd'
ACTION_DROP = 'drop'
TCP_PORT = 80
UDP_PORT = 161


def create_packet(eth_dst, eth_src, ip_dst, ip_src, vlan_vid, tr_type, ttl, dl_vlan_enable=False, icmp_type=8, pktlen=100, ip_tunnel=None):
    """
    Generate packet to send.

    Args:
        eth_dst: Destination Ethernet address
        eth_src: Source Ethernet address
        ip_dst: Destination IP address
        ip_src: Source IP address
        vlan_vid: VLAN ID
        tr_type: Type of traffic
        ttl: Time to live
        dl_vlan_enable: True if the packet is with vlan, False otherwise
        icmp_type: ICMP type
        pktlen: packet length
        ip_tunnel: Tunnel IP address of DUT

    Returns: simple packet
    """
    if 'TCP' in tr_type:
        return testutils.simple_tcp_packet(eth_dst=eth_dst, eth_src=eth_src, ip_dst=ip_dst, ip_src=ip_src, tcp_sport=TCP_PORT, tcp_dport=TCP_PORT,
                                           vlan_vid=vlan_vid, dl_vlan_enable=dl_vlan_enable, ip_ttl=ttl, pktlen=pktlen)
    elif 'UDP' in tr_type:
        return testutils.simple_udp_packet(eth_dst=eth_dst, eth_src=eth_src, ip_dst=ip_dst, ip_src=ip_src, udp_sport=UDP_PORT, udp_dport=UDP_PORT,
                                           vlan_vid=vlan_vid, dl_vlan_enable=dl_vlan_enable, ip_ttl=ttl, pktlen=pktlen)
    elif 'ICMP' in tr_type:
        return testutils.simple_icmp_packet(eth_dst=eth_dst, eth_src=eth_src, ip_dst=ip_dst, ip_src=ip_src, icmp_type=icmp_type, vlan_vid=vlan_vid,
                                            dl_vlan_enable=dl_vlan_enable, ip_ttl=ttl, pktlen=pktlen)
    elif 'decap' in tr_type:
        inner_dscp = random.choice(range(0, 33))
        inner_ttl = random.choice(range(3, 65))

        inner_packet = testutils.simple_tcp_packet(ip_dst=ip_dst, ip_src=ip_src, tcp_sport=TCP_PORT, tcp_dport=TCP_PORT, ip_ttl=inner_ttl,
                                                   ip_tos=inner_dscp)[packet.IP]

        return testutils.simple_ipv4ip_packet(eth_dst=eth_dst, eth_src=eth_src, ip_src='1.1.1.1', ip_dst=ip_tunnel, ip_dscp=inner_dscp, ip_ttl=64,
                                              vlan_vid=vlan_vid, dl_vlan_enable=dl_vlan_enable, inner_frame=inner_packet)

    return None

def generate_and_verify_traffic(duthost, ptfadapter, src_port, dst_port, ip_src, ip_dst, pkt_action=None,
                                type_of_traffic=None, ttl=64, pktlen=100, ip_tunnel=None):
    """
    Send packet from PTF to DUT and
    verify that DUT sends/doesn't packet to PTF.

    Args:
        duthost: DUT host object
        ptfadapter: PTF adapter
        src_port: Port of PTF
        dst_port: Port of DUT
        ip_src: Source IP address of PTF
        ip_dst: Destination IP address of DUT
        pkt_action: Packet action (forwarded or drop)
        type_of_traffic: Type of traffic
        ttl: Time to live
        pktlen: packet length
        ip_tunnel: Tunnel IP address of DUT
    """
    if not type_of_traffic:
        type_of_traffic = ['ICMP',]

    for tr_type in type_of_traffic:
        if 'TCP' in tr_type or 'UDP' in tr_type:
            generate_and_verify_tcp_udp_traffic(duthost, ptfadapter, src_port, dst_port, ip_src, ip_dst, tr_type, pktlen, ttl)
        elif 'ICMP' in tr_type:
            generate_and_verify_icmp_traffic(duthost, ptfadapter, src_port, dst_port, ip_src, ip_dst, pkt_action, tr_type, ttl)
        elif 'decap' in tr_type:
            generate_and_verify_decap_traffic(duthost, ptfadapter, src_port, dst_port, ip_src, ip_dst, tr_type, ip_tunnel)
        else:
            pytest.skip('Unsupported type of traffic')


def generate_and_verify_tcp_udp_traffic(duthost, ptfadapter, src_port, dst_port, ip_src, ip_dst, tr_type, pktlen, ttl):
    """
    Send TCP/UDP packet from PTF to DUT and
    verify that DUT sends/doesn't send TCP/UDP packet to PTF.

    Args:
        duthost: DUT host object
        ptfadapter: PTF adapter
        src_port: Port of PTF
        dst_port: Port of DUT
        ip_src: Source IP address of PTF
        ip_dst: Destination IP address of DUT
        pkt_action: Packet action (forwarded or drop)
        tr_type: Type of traffic (TCP or UDP)
        pktlen: packet length
        ttl: Time to live
    """
    src_vlan_vid = None
    dst_vlan_vid = None
    src_dl_vlan_enable = False
    dst_dl_vlan_enable = False
    router_mac = duthost.facts['router_mac']
    src_port_number = int(get_port_number(src_port))
    dst_port_number = int(get_port_number(dst_port))
    src_mac = ptfadapter.dataplane.get_mac(0, src_port_number)
    dst_mac = ptfadapter.dataplane.get_mac(0, dst_port_number)
    # Get VLAN ID from name of sub-port
    if '.' in src_port:
        src_vlan_vid = int(src_port.split('.')[1])
        src_dl_vlan_enable = True
    if '.' in dst_port:
        dst_vlan_vid = int(dst_port.split('.')[1])
        dst_dl_vlan_enable = True

    ip_src = ip_src.split('/')[0]
    ip_dst = ip_dst.split('/')[0]

    pkt = create_packet(eth_src=src_mac,
                        eth_dst=router_mac,
                        ip_src=ip_src,
                        ip_dst=ip_dst,
                        vlan_vid=src_vlan_vid,
                        dl_vlan_enable=src_dl_vlan_enable,
                        tr_type=tr_type,
                        ttl=64)

    exp_pkt = create_packet(eth_src=router_mac,
                            eth_dst=dst_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            vlan_vid=dst_vlan_vid,
                            dl_vlan_enable=dst_dl_vlan_enable,
                            tr_type=tr_type,
                            ttl=ttl,
                            pktlen=pktlen)

    ptfadapter.dataplane.flush()
    testutils.send_packet(ptfadapter, src_port_number, pkt)

    pkt_filter = FilterPktBuffer(ptfadapter=ptfadapter,
                                 exp_pkt=exp_pkt,
                                 dst_port_number=dst_port_number,
                                 match_fields=[("802.1Q", "vlan"), ("Ethernet", "src"), ("Ethernet", "dst"), ("IP", "src"), ("IP", "dst"), (tr_type, "dport")],
                                 ignore_fields=[])

    pkt_in_buffer = pkt_filter.filter_pkt_in_buffer()

    pytest_assert(pkt_in_buffer is True, "Expected packet not available:\n{}".format(pkt_in_buffer))


def generate_and_verify_icmp_traffic(duthost, ptfadapter, src_port, dst_port, ip_src, ip_dst, pkt_action, tr_type, ttl=64):
    """
    Send ICMP request packet from PTF to DUT and
    verify that DUT sends/doesn't send ICMP reply packet to PTF.

    Args:
        duthost: DUT host object
        ptfadapter: PTF adapter
        src_port: Port of PTF
        dst_port: Port of DUT
        ip_src: Source IP address of PTF
        ip_dst: Destination IP address of DUT
        pkt_action: Packet action (forwarded or drop)
        tr_type: Type of traffic (TCP or UDP)
        ttl: Time to live
    """
    vlan_vid = None
    dl_vlan_enable = False
    router_mac = duthost.facts['router_mac']
    src_port_number = int(get_port_number(src_port))
    src_mac = ptfadapter.dataplane.get_mac(0, src_port_number)
    # Get VLAN ID from name of sub-port
    if '.' in src_port:
        vlan_vid = int(src_port.split('.')[1])
        dl_vlan_enable = True

    ip_src = ip_src.split('/')[0]
    ip_dst = ip_dst.split('/')[0]

    # Create ICMP request packet
    pkt = create_packet(eth_dst=router_mac,
                        eth_src=src_mac,
                        ip_src=ip_src,
                        ip_dst=ip_dst,
                        vlan_vid=vlan_vid,
                        dl_vlan_enable=dl_vlan_enable,
                        tr_type=tr_type,
                        ttl=64)

    # Define ICMP reply packet
    exp_pkt = create_packet(eth_src=router_mac,
                            eth_dst=src_mac,
                            ip_src=ip_dst,
                            ip_dst=ip_src,
                            vlan_vid=vlan_vid,
                            dl_vlan_enable=dl_vlan_enable,
                            icmp_type=0,
                            tr_type=tr_type,
                            ttl=ttl)

    masked_exp_pkt = mask.Mask(exp_pkt)
    masked_exp_pkt.set_do_not_care_scapy(packet.IP, "id")
    masked_exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")
    masked_exp_pkt.set_do_not_care_scapy(packet.ICMP, "chksum")

    ptfadapter.dataplane.flush()
    testutils.send_packet(ptfadapter, src_port_number, pkt)

    dst_port_list = [src_port_number]

    if pkt_action == ACTION_FWD:
        testutils.verify_packet_any_port(ptfadapter, masked_exp_pkt, dst_port_list)
    elif pkt_action == ACTION_DROP:
        testutils.verify_no_packet_any(ptfadapter, masked_exp_pkt, dst_port_list)


def generate_and_verify_decap_traffic(duthost, ptfadapter, src_port, dst_port, ip_src, ip_dst, tr_type, ip_tunnel=None):
    """
    Send encapsulated packet from PTF to DUT and
    verify that DUT sends/doesn't send TCP/UDP packet to PTF.

    Args:
        duthost: DUT host object
        ptfadapter: PTF adapter
        src_port: Source port of PTF
        dst_port: Destination port of PTF
        ip_src: Source IP address of PTF
        ip_dst: Destination IP address of PTF
        tr_type: Type of traffic (TCP or UDP)
        ip_tunnel: Tunnel IP address of DUT
    """
    router_mac = duthost.facts['router_mac']
    src_port_number = int(get_port_number(src_port))
    dst_port_number = int(get_port_number(dst_port))

    ip_src = ip_src.split('/')[0]
    ip_dst = ip_dst.split('/')[0]
    ip_tunnel = ip_tunnel.split('/')[0]

    # Define encapsulated packet
    pkt = create_packet(eth_dst=router_mac,
                        eth_src=ptfadapter.dataplane.get_mac(0, src_port_number),
                        ip_src=ip_src,
                        ip_dst=ip_dst,
                        ip_tunnel=ip_tunnel,
                        vlan_vid=int(src_port.split('.')[1]),
                        dl_vlan_enable=True,
                        tr_type=tr_type,
                        ttl=64)

    # Build expected packet
    inner_packet = pkt[packet.IP].payload[packet.IP].copy()
    exp_pkt = Ether(src=router_mac, dst=ptfadapter.dataplane.get_mac(0, dst_port_number)) / Dot1Q(vlan=int(dst_port.split('.')[1])) / inner_packet
    exp_pkt['IP'].ttl -= 1

    update_dut_arp_table(duthost, ip_dst)
    ptfadapter.dataplane.flush()

    testutils.send_packet(ptfadapter, src_port_number, pkt)

    pkt_filter = FilterPktBuffer(ptfadapter=ptfadapter,
                                 exp_pkt=exp_pkt,
                                 dst_port_number=dst_port_number,
                                 match_fields=[("802.1Q", "vlan"), ("Ethernet", "src"), ("Ethernet", "dst"), ("IP", "src"), ("IP", "dst")],
                                 ignore_fields=[])

    pkt_in_buffer = pkt_filter.filter_pkt_in_buffer()

    pytest_assert(pkt_in_buffer is True, "Expected packet not available:\n{}".format(pkt_in_buffer))


def shutdown_port(duthost, interface):
    """
    Shutdown port on the DUT

    Args:
        duthost: DUT host object
        interface: Interface of DUT
    """
    duthost.shutdown(interface)
    pytest_assert(wait_until(3, 1, __check_interface_state, duthost, interface, 'down'),
                  "DUT's port {} didn't go down as expected".format(interface))


def startup_port(duthost, interface):
    """
    Startup port on the DUT

    Args:
        duthost: DUT host object
        interface: Interface of DUT
    """
    duthost.no_shutdown(interface)
    pytest_assert(wait_until(3, 1, __check_interface_state, duthost, interface),
                  "DUT's port {} didn't go up as expected".format(interface))


def __check_interface_state(duthost, interface, state='up'):
    """
    Check interface status

    Args:
        duthost: DUT host object
        interface: Interface of DUT
        state: state of DUT's interface

    Returns:
        Bool value which confirm port state
    """
    ports_down = duthost.interface_facts(up_ports=[interface])['ansible_facts']['ansible_interface_link_down_ports']

    if 'down' in state:
        return interface in ports_down

    return interface not in ports_down


def setup_vlan(duthost, vlan_id):
    """
    Setup VLAN's configuraation to DUT

    Args:
        duthost: DUT host object
        vlan_id: VLAN id
    """
    duthost.shell('config vlan add %s' % vlan_id)

    pytest_assert(wait_until(3, 1, __check_vlan, duthost, vlan_id),
                  "VLAN RIF Vlan{} didn't create as expected".format(vlan_id))


def __check_vlan(duthost, vlan_id, removed=False):
    """
    Check availability of VLAN in redis-db

    Args:
        duthost: DUT host object
        vlan_id: VLAN id
        removed: Bool value which show availability of VLAN

    Returns:
        Bool value which confirm availability of VLAN in redis-db
    """
    vlan_name = 'Vlan{}'.format(vlan_id)
    out = duthost.shell('redis-cli -n 4 keys "VLAN|{}"'.format(vlan_name))["stdout"]

    if removed:
        return vlan_name not in out

    return vlan_name in out


def __check_vlan_member(duthost, vlan_id, vlan_member, removed=False):
    """
    Check that VLAN member is available in redis-db

    Args:
        duthost: DUT host object
        vlan_id: VLAN id
        vlan_member: VLAN member
        removed: Bool value which show availability of member in VLAN

    Returns:
        Bool value which confirm availability of VLAN member in redis-db
    """
    vlan_name = 'Vlan{}'.format(vlan_id)
    out = duthost.shell('redis-cli -n 4 keys "VLAN_MEMBER|{}|{}"'.format(vlan_name, vlan_member))["stdout"]

    if removed:
        return vlan_name not in out

    return vlan_name in out


def remove_vlan(duthost, vlan_id):
    """
    Remove VLANs configuraation on DUT

    Args:
        duthost: DUT host object
        vlan_id: VLAN id
    """
    duthost.shell('config vlan del {}'.format(vlan_id))

    pytest_assert(wait_until(3, 1, __check_vlan, duthost, vlan_id, True),
                  "VLAN RIF Vlan{} didn't remove as expected".format(vlan_id))


def remove_member_from_vlan(duthost, vlan_id, vlan_member):
    """
    Remove members of VLAN on DUT

    Args:
        duthost: DUT host object
        vlan_id: VLAN id
        vlan_member: VLAN member
    """
    if __check_vlan_member(duthost, vlan_id, vlan_member):
        duthost.shell('config vlan member del {} {}'.format(vlan_id, vlan_member))
        pytest_assert(wait_until(3, 1, __check_vlan_member, duthost, vlan_id, vlan_member, True),
                      "VLAN RIF Vlan{} have {} member".format(vlan_id, vlan_member))


def check_sub_port(duthost, sub_port, removed=False):
    """
    Check that sub-port is available in redis-db

    Args:
        duthost: DUT host object
        sub_port: Sub-port interface of DUT
        removed: Bool value which show availability of sub-port on the DUT

    Returns:
        Bool value which confirm availability of sub-port in redis-db
    """
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    sub_ports = set(config_facts.get('VLAN_SUB_INTERFACE', {}).keys())
    if not isinstance(sub_port, list):
        sub_port = [sub_port]

    if removed:
        return sub_ports.isdisjoint(set(sub_port))

    return sub_ports.issuperset(set(sub_port))


def get_mac_dut(duthost, interface):
    """
    Get MAC address of DUT interface

    Args:
        duthost: DUT host object
        interface: Interface of DUT

    Returns: MAC address
    """
    return duthost.setup()['ansible_facts']['ansible_{}'.format(interface)]['macaddress']


def get_port_number(interface):
    """
    Get number of port from interface name

    Args:
        interface: Full interface name

    Returns: Number of port
    """
    return ''.join([i for i in interface.split('.')[0] if i.isdigit()])


def get_port_mtu(duthost, interface):
    """
    Get MTU of port from interface name

    Args:
        duthost: DUT host object
        interface: Full interface name

    Returns: MTU
    """
    out = ''

    if '.' in interface:
        out = duthost.show_and_parse("show subinterface status {}".format(interface))
        return out[0]['mtu']

    out = duthost.show_and_parse("show interface status {}".format(interface))
    return out[0]['mtu']


def create_lag_port(duthost, config_port_indices):
    """
    Create lag ports on the DUT

    Args:
        duthost: DUT host object
        config_port_indices: Dictionary of port on the DUT

    Returns:
        Dictonary of lag ports on the DUT
    """
    lag_port_map = {}
    portchannels = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts'].get('PORTCHANNEL', {}).keys()
    port_list_idx = 0
    port_list = list(config_port_indices.values())

    for portchannel_idx in range(1, 10000): # Max len of portchannel index can be '9999'
        lag_port = 'PortChannel{}'.format(portchannel_idx)

        if lag_port not in portchannels:
            port_name = port_list[port_list_idx]
            remove_ip_from_port(duthost, port_name)
            remove_member_from_vlan(duthost, '1000', port_name)
            duthost.shell('config portchannel add {}'.format(lag_port))
            duthost.shell('config portchannel member add {} {}'.format(lag_port, port_name))
            lag_port_map[portchannel_idx] = lag_port
            port_list_idx += 1

        if len(lag_port_map) == len(config_port_indices):
            break

    return lag_port_map


def create_bond_port(ptfhost, ptf_ports):
    """
    Create bond ports on the PTF

    Args:
        ptfhost: PTF host object
        ptf_ports: List of ports on the PTF

    Returns:
        Dictonary of bond ports and slave ports on the PTF
    """
    bond_port_map = OrderedDict()
    for port_index, port_name in ptf_ports.items():
        bond_port = 'bond{}'.format(port_index)
        ptfhost.shell("ip link add {} type bond".format(bond_port))
        ptfhost.shell("ip link set {} type bond miimon 100 mode 802.3ad".format(bond_port))
        ptfhost.shell("ip link set {} down".format(port_name))
        ptfhost.shell("ip link set {} master {}".format(port_name, bond_port))
        ptfhost.shell("ip link set dev {} up".format(bond_port))
        ptfhost.shell("ifconfig {} mtu 9216 up".format(bond_port))

        bond_port_map[bond_port] = port_name

    ptfhost.shell("supervisorctl restart ptf_nn_agent")
    time.sleep(5)

    return bond_port_map


def create_sub_port_on_ptf(ptfhost, sub_port_name, sub_port_ip):
    """
    Create sub-port on the PTF

    Args:
        ptfhost: PTF host object
        sub_port_name: Sub-port name
        sub_port_ip: IP address of sub-port
    """
    port, vlan = sub_port_name.split(".")
    ptfhost.shell("ip link add link {} name {} type vlan id {}".format(port, sub_port_name, vlan))
    ptfhost.shell("ip address add {} dev {}".format(sub_port_ip, sub_port_name))
    ptfhost.shell("ip link set {} up".format(sub_port_name))


def add_port_to_namespace(ptfhost, name_of_namespace, port_name, port_ip):
    """
    Add port to namespace of the PTF

    Args:
        ptfhost: PTF host object
        name_of_namespace: Name of namespace
        port_name: Port of the PTF
        port_ip: IP address of the port
    """
    if not check_namespace(ptfhost, name_of_namespace):
        ptfhost.shell('ip netns add {}'.format(name_of_namespace))
        ptfhost.shell('ip -n {} link set lo up'.format(name_of_namespace))

    ptfhost.shell('ip link set {} netns {}'.format(port_name, name_of_namespace))
    ptfhost.shell('ip -n {} addr add {} dev {}'.format(name_of_namespace, port_ip, port_name))
    ptfhost.shell('ip -n {} link set {} up'.format(name_of_namespace, port_name))


def add_static_route(ptfhost, network_ip, next_hop_ip, name_of_namespace=None):
    """
    Add static route on the PTF

    Args:
        ptfhost: PTF host object
        network_ip: Network IP address
        next_hop_ip: Next hop IP address
        name_of_namespace: Name of namespace
    """
    next_hop_ip = next_hop_ip.split('/')[0]
    if name_of_namespace:
        ptfhost.shell('ip netns exec {} ip route add {} nexthop via {}'
                      .format(name_of_namespace, network_ip, next_hop_ip))
    else:
        ptfhost.shell('ip route add {} nexthop via {}'
                      .format(network_ip, next_hop_ip))


def check_namespace(ptfhost, name_of_namespace):
    """
    Check that namespace is available on the PTF

    Args:
        ptfhost: PTF host object
        name_of_namespace: Name of namespace

    Returns:
        Bool value which confirm availability of namespace on the PTF
    """
    out = ptfhost.shell('ip netns list')["stdout"]
    return name_of_namespace in out


def get_port(duthost, ptfhost, interface_num, port_type, ports_to_exclude=None, exclude_sub_interface_ports=False):
    """
    Get port configurations from DUT and PTF

    Args:
        duthost: DUT host object
        ptfhost: PTF host object
        interface_num: number of ports
        port_type: Type of port
        ports_to_exclude: Ports that cannot be members of LAG
        exclude_sub_interface_ports: Exclude ports that has sub interfaces if True

    Returns:
        Tuple with port configurations of DUT and PTF
    """
    if ports_to_exclude is None:
        ports_to_exclude = []

    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

    # if port_type is port channel, filter out those ports that has vlan sub interface
    sub_interface_ports = set([_.split(constants.VLAN_SUB_INTERFACE_SEPARATOR)[0] for _ in cfg_facts.get('VLAN_SUB_INTERFACE', {}).keys()])

    portchannel_members = []
    for member in cfg_facts.get('PORTCHANNEL_MEMBER', {}).values():
        portchannel_members += member.keys()

    config_vlan_members = cfg_facts['port_index_map']
    port_status = cfg_facts['PORT']
    config_port_indices = {}
    for port, port_id in config_vlan_members.items():
        if ((port not in portchannel_members) and
            (not (('port_in_lag' in port_type or exclude_sub_interface_ports) and port in sub_interface_ports)) and
            (port_status[port].get('admin_status', 'down') == 'up') and
            (port not in ports_to_exclude)):
            config_port_indices[port_id] = port
            if len(config_port_indices) == interface_num:
                break

    pytest_require(len(config_port_indices) == interface_num, "No port for testing")

    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")
    ptf_ports = {}
    for port_id in config_port_indices:
        ptf_ports[port_id] = ptf_ports_available_in_topo[port_id]

    if 'port_in_lag' in port_type:
        lag_port_map = create_lag_port(duthost, config_port_indices)
        bond_port_map = create_bond_port(ptfhost, ptf_ports)

        return (lag_port_map, bond_port_map)

    return (config_port_indices, ptf_ports.values())


def remove_sub_port(duthost, sub_port, ip):
    """
    Remove sub-port from redis-db

    Args:
        duthost: DUT host object
        sub_port: Sub-port name
        ip: IP address of port
    """
    duthost.shell('config interface ip remove {} {}'.format(sub_port, ip))
    duthost.shell('redis-cli -n 4 del "VLAN_SUB_INTERFACE|{}"'.format(sub_port))


def remove_lag_port(duthost, cfg_facts, lag_port):
    """
    Remove lag-port from DUT

    Args:
        duthost: DUT host object
        cfg_facts: Ansible config_facts
        lag_port: lag-port name
    """
    lag_members = cfg_facts['PORTCHANNEL_MEMBER'][lag_port].keys()
    for port in lag_members:
        duthost.shell('config portchannel member del {} {}'.format(lag_port, port))
    duthost.shell('config portchannel del {}'.format(lag_port))


def remove_bond_port(ptfhost, bond_port, port_name):
    """
    Remove bond-port from DUT

    Args:
        ptfhost: PTF host object
        bond_port: bond-port name
        port_name: member name of bond-port
    """
    ptfhost.shell("ip link set {} nomaster".format(bond_port))
    ptfhost.shell("ip link set {} nomaster".format(port_name))
    ptfhost.shell("ip link set {} up".format(port_name))
    ptfhost.shell("ip link del {}".format(bond_port))


def remove_ip_from_port(duthost, port, ip=None):
    """
    Remove ip addresses from port

    Args:
        duthost: DUT host object
        port: port name
        ip: IP address
    """
    ip_addresses = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts'].get('INTERFACE', {}).get(port, {})
    if ip_addresses:
        for ip in ip_addresses:
            duthost.shell('config interface ip remove {} {}'.format(port, ip))
    elif ip:
        duthost.shell('config interface ip remove {} {}'.format(port, ip))


def remove_namespace(ptfhost, name_of_namespace):
    """
    Remove namespace from the PTF

    Args:
        ptfhost: PTF host object
        name_of_namespace: Name of namespace
    """
    if check_namespace(ptfhost, name_of_namespace):
        ptfhost.shell('ip -n {} link set lo down'.format(name_of_namespace))
        ptfhost.shell('ip netns del {}'.format(name_of_namespace))


def remove_static_route(ptfhost, network_ip, next_hop_ip, name_of_namespace=None):
    """
    Remove static route from the PTF

    Args:
        ptfhost: PTF host object
        network_ip: Network IP address
        next_hop_ip: Next hop IP address
        name_of_namespace: Name of namespace
    """
    next_hop_ip = next_hop_ip.split('/')[0]
    if name_of_namespace:
        ptfhost.shell('ip netns exec {} ip route del {} nexthop via {}'
                      .format(name_of_namespace, network_ip, next_hop_ip))
    else:
        ptfhost.shell('ip route del {} nexthop via {}'
                      .format(network_ip, next_hop_ip))


def get_ptf_port_list(ptfhost):
    """
    Get list of ports of the PTF

    Args:
        ptfhost: PTF host object

    Returns:
        List with ports available on the PTF
    """
    out = ptfhost.shell("ls /sys/class/net")['stdout']
    return out.split('\n')


def add_ip_to_dut_port(duthost, port, ip):
    """
    Add ip addresses to DUT's port

    Args:
        duthost: DUT host object
        port: port name
        ip: IP address
    """
    duthost.shell("config interface ip add {} {}".format(port, ip))


def add_ip_to_ptf_port(ptfhost, port, ip):
    """
    Add ip addresses to PTF's port

    Args:
        ptfhost: PTF host object
        port: port name
        ip: IP address
    """
    ptfhost.shell("ip address add {} dev {}".format(ip, port))


def remove_ip_from_ptf_port(ptfhost, port, ip):
    """
    Remove ip addresses from port

    Args:
        ptfhost: PTF host object
        port: port name
        ip: IP address
    """
    ptfhost.shell("ip address del {} dev {}".format(ip, port))


def add_member_to_vlan(duthost, vlan_id, vlan_member):
    """
    Add members of VLAN on DUT

    Args:
        duthost: DUT host object
        vlan_id: VLAN id
        vlan_member: VLAN member
    """
    if not __check_vlan_member(duthost, vlan_id, vlan_member):
        duthost.shell('config vlan member add {} {}'.format(vlan_id, vlan_member))
        pytest_assert(wait_until(3, 1, __check_vlan_member, duthost, vlan_id, vlan_member),
                      "VLAN RIF Vlan{} doesn't have {} member".format(vlan_id, vlan_member))


def remove_sub_port_from_ptf(ptfhost, sub_port, ip):
    """
    Remove sub-port from PTF

    Args:
        ptfhost: PTF host object
        sub_port: Sub-port name
        ip: IP address of port
    """
    ptfhost.shell("ip address del {} dev {}".format(ip, sub_port))
    ptfhost.shell("ip link del {}".format(sub_port))


def update_dut_arp_table(duthost, ip):
    """
    Add entry to DUT ARP table

    Args:
        duthost: DUT host object
        ip: IP address of directly connected interface
    """
    duthost.command("ping {} -c 3".format(ip), module_ignore_errors=True)
