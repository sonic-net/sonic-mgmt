import os
import re

import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = os.path.join('tmp', os.path.basename(BASE_DIR))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
SUB_PORTS_TEMPLATE = 'sub_port_config.j2'
ACTION_FWD = 'fwd'
ACTION_DROP = 'drop'


def create_packet(eth_dst, eth_src, ip_dst, ip_src, vlan_vid, dl_vlan_enable=False, icmp_type=8):
    """
    Generate packet to send.

    Args:
        eth_dst: Destination Ethernet address
        eth_src: Source Ethernet address
        ip_dst: Destination IP address
        ip_src: Source IP address
        vlan_vid: VLAN ID
        dl_vlan_enable: True if the packet is with vlan, False otherwise
        icmp_type: ICMP type

    Returns: simple ICMP packet
    """
    return testutils.simple_icmp_packet(eth_dst=eth_dst, eth_src=eth_src, ip_dst=ip_dst, ip_src=ip_src, icmp_type=icmp_type, vlan_vid=vlan_vid,
                                        pktlen=104, dl_vlan_enable=dl_vlan_enable)


def generate_and_verify_traffic(duthost, ptfadapter, src_port, dst_port, ip_src, ip_dst, pkt_action):
    """
    Send ICMP request packet from PTF to DUT and
    verify that DUT sends/doesn't sends ICMP reply packet to PTF.

    Args:
        duthost: DUT host object
        ptfadapter: PTF adapter
        src_port: Port of PTF
        dst_port: Port of DUT
        ip_src: Source IP address of PTF
        ip_dst: Destination IP address of DUT
        pkt_action: Packet action (forwarded or drop)

    """
    router_mac = get_mac_dut(duthost, dst_port)
    src_port_number = int(get_port_number(src_port))
    src_mac = ptfadapter.dataplane.get_mac(0, src_port_number)
    # Get VLAN ID from name of sub-port
    vlan_vid = int(src_port.split('.')[1])

    ip_src = ip_src.split('/')[0]
    ip_dst = ip_dst.split('/')[0]

    # Create ICMP request packet
    pkt = create_packet(eth_dst=router_mac,
                        eth_src=src_mac,
                        ip_src=ip_src,
                        ip_dst=ip_dst,
                        vlan_vid=vlan_vid,
                        dl_vlan_enable=True)

    # Define ICMP reply packet
    exp_pkt = create_packet(eth_src=router_mac,
                            eth_dst=src_mac,
                            ip_src=ip_dst,
                            ip_dst=ip_src,
                            vlan_vid=vlan_vid,
                            dl_vlan_enable=True,
                            icmp_type=0)

    masked_exp_pkt = mask.Mask(exp_pkt)
    masked_exp_pkt.set_do_not_care_scapy(packet.IP, "id")
    masked_exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")
    masked_exp_pkt.set_do_not_care_scapy(packet.IP, "ttl")
    masked_exp_pkt.set_do_not_care_scapy(packet.ICMP, "chksum")

    testutils.send_packet(ptfadapter, src_port_number, pkt)
    dst_port_list = [src_port_number]

    if pkt_action == ACTION_FWD:
        testutils.verify_packet_any_port(ptfadapter, masked_exp_pkt, dst_port_list)
    elif pkt_action == ACTION_DROP:
        testutils.verify_no_packet_any(ptfadapter, masked_exp_pkt, dst_port_list)


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
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    portchannel_interfaces = cfg_facts.get('PORTCHANNEL_INTERFACE', {})

    duthost.shell('config vlan add %s' % vlan_id)
    for portchannel, ips in portchannel_interfaces.items():
        duthost.shell('config interface shutdown {}'.format(portchannel))
        for ip in ips:
            duthost.shell('config interface ip remove {} {}'.format(portchannel, ip))

        duthost.shell('config vlan member add --untagged {} {}'.format(vlan_id, portchannel))

    pytest_assert(wait_until(3, 1, __check_vlan, duthost, vlan_id),
                  "VLAN RIF Vlan{} didn't create as expected".format(vlan_id))

    for portchannel in portchannel_interfaces.keys():
        pytest_assert(wait_until(3, 1, __check_vlan_member, duthost, vlan_id, portchannel),
                      "VLAN RIF Vlan{} doesn't have {} member as expected".format(vlan_id, portchannel))


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


def __check_vlan_member(duthost, vlan_id, vlan_member):
    """
    Check that VLAN member is available in redis-db

    Args:
        duthost: DUT host object
        vlan_id: VLAN id
        vlan_member: VLAN member

    Returns:
        Bool value which confirm availability of VLAN member in redis-db
    """
    vlan_name = 'Vlan{}'.format(vlan_id)
    out = duthost.shell('redis-cli -n 4 keys "VLAN_MEMBER|{}|{}"'.format(vlan_name, vlan_member))["stdout"]
    return vlan_name in out


def remove_vlan(duthost, vlan_id):
    """
    Remove VLAN's configuraation on DUT

    Args:
        duthost: DUT host object
        vlan_id: VLAN id
    """
    duthost.shell('config vlan del {}'.format(vlan_id))

    pytest_assert(wait_until(3, 1, __check_vlan, duthost, vlan_id, True),
                  "VLAN RIF Vlan{} didn't remove as expected".format(vlan_id))


def check_sub_port(duthost, sub_port):
    """
    Check that sub-port is available in redis-db

    Args:
        duthost: DUT host object
        interface: Interface of DUT
        state: state of DUT's interface
    """
    out = duthost.shell('redis-cli -n 4 keys "VLAN_SUB_INTERFACE|{}"'.format(sub_port))["stdout"]
    return sub_port in out


def check_sub_ports_creation(duthost, sub_ports):
    """
    """
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    return set(sub_ports) == set(config_facts['VLAN_SUB_INTERFACE'].keys())


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
    pattern = ''
    out = ''

    if '.' in interface:
        out = duthost.show_and_parse("show subinterface status {}".format(interface))
        return out[0]['mtu']

    out = duthost.show_and_parse("show interface status {}".format(interface))
    return out[0]['mtu']
