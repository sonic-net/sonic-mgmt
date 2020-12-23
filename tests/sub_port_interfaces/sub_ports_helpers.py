import os

import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

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
