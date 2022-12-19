import logging
import ptf.testutils as testutils
import pytest
import ptf.mask as mask
import ptf.packet as packet

from scapy.all import Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, \
                      ICMPv6NDOptSrcLLAddr, in6_getnsmac, \
                      in6_getnsma, inet_pton, inet_ntop, socket
from tests.arp.arp_utils import clear_dut_arp_cache, increment_ipv6_addr, increment_ipv4_addr
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.ptfhost_utils import change_mac_addresses

pytestmark = [
    pytest.mark.topology('t0', 'dualtor')
]

logger = logging.getLogger(__name__)

def test_arp_garp_enabled(rand_selected_dut, garp_enabled, ip_and_intf_info, intfs_for_test, config_facts, ptfadapter):
    """
    Send a gratuitous ARP (GARP) packet from the PTF to the DUT

    The DUT should learn the (previously unseen) ARP info from the packet
    """
    pytest_require(garp_enabled, 'Gratuitous ARP not enabled for this device')
    duthost = rand_selected_dut
    ptf_intf_ipv4_addr = ip_and_intf_info[0]

    arp_request_ip = increment_ipv4_addr(ptf_intf_ipv4_addr)
    arp_src_mac = '00:00:07:08:09:0a'
    _, _, intf1_index, _, = intfs_for_test

    pkt = testutils.simple_arp_packet(pktlen=60,
                                eth_dst='ff:ff:ff:ff:ff:ff',
                                eth_src=arp_src_mac,
                                vlan_pcp=0,
                                arp_op=2,
                                ip_snd=arp_request_ip,
                                ip_tgt=arp_request_ip,
                                hw_snd=arp_src_mac,
                                hw_tgt='ff:ff:ff:ff:ff:ff'
                            )

    clear_dut_arp_cache(duthost)

    logger.info("Sending GARP for target {} from PTF interface {}".format(arp_request_ip, intf1_index))
    testutils.send_packet(ptfadapter, intf1_index, pkt)

    vlan_intfs = config_facts['VLAN_INTERFACE'].keys()

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4'][arp_request_ip]['macaddress'].lower() == arp_src_mac.lower())
    pytest_assert(switch_arptable['arptable']['v4'][arp_request_ip]['interface'] in vlan_intfs)

def generate_link_local_addr(mac):
    parts = mac.split(":")
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = "{:x}".format(int(parts[0], 16) ^ 2)

    ipv6Parts = []
    for i in range(0, len(parts), 2):
        ipv6Parts.append("".join(parts[i:i+2]))
    ipv6 = "fe80::{}".format(":".join(ipv6Parts))
    return ipv6

@pytest.fixture(params=['v4', 'v6'])
def packets_for_test(request, ptfadapter, duthost, config_facts, tbinfo, ip_and_intf_info):
    ip_version = request.param
    src_addr_v4, _, src_addr_v6, _, ptf_intf_index = ip_and_intf_info
    ptf_intf_mac = ptfadapter.dataplane.get_mac(0, ptf_intf_index)
    vlans = config_facts['VLAN']
    topology = tbinfo['topo']['name']
    dut_mac = ''
    for vlan_details in vlans.values():
        if 'dualtor' in topology:
            dut_mac = vlan_details['mac'].lower()
        else:
            dut_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")
        break

    if ip_version == 'v4':
        tgt_addr = increment_ipv4_addr(src_addr_v4)
        out_pkt = testutils.simple_arp_packet(
                                eth_dst='ff:ff:ff:ff:ff:ff',
                                eth_src=ptf_intf_mac,
                                ip_snd=src_addr_v4,
                                ip_tgt=tgt_addr,
                                arp_op=1,
                                hw_snd=ptf_intf_mac
                            )
        exp_pkt = testutils.simple_arp_packet(
                                eth_dst=ptf_intf_mac,
                                eth_src=dut_mac,
                                ip_snd=tgt_addr,
                                ip_tgt=src_addr_v4,
                                arp_op=2,
                                hw_snd=dut_mac,
                                hw_tgt=ptf_intf_mac
        )
    elif ip_version == 'v6':
        tgt_addr = increment_ipv6_addr(src_addr_v6)
        ll_src_addr = generate_link_local_addr(ptf_intf_mac)
        multicast_tgt_addr = in6_getnsma(inet_pton(socket.AF_INET6, tgt_addr))
        multicast_tgt_mac = in6_getnsmac(multicast_tgt_addr)
        out_pkt = Ether(src=ptf_intf_mac, dst=multicast_tgt_mac) 
        out_pkt /= IPv6(dst=inet_ntop(socket.AF_INET6, multicast_tgt_addr), src=ll_src_addr)
        out_pkt /= ICMPv6ND_NS(tgt=tgt_addr) 
        out_pkt /= ICMPv6NDOptSrcLLAddr(lladdr=ptf_intf_mac)

        exp_pkt = Ether(src=dut_mac, dst=ptf_intf_mac) 
        exp_pkt /= IPv6(dst=ll_src_addr, src=generate_link_local_addr(dut_mac))
        exp_pkt /= ICMPv6ND_NA(tgt=tgt_addr, S=1, R=1, O=0)
        exp_pkt /= ICMPv6NDOptSrcLLAddr(type=2, lladdr=dut_mac)
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.IPv6, 'fl')

    return ip_version, out_pkt, exp_pkt

def test_proxy_arp(proxy_arp_enabled, ip_and_intf_info, ptfadapter, packets_for_test):
    """
    Send an ARP request or neighbor solicitation (NS) to the DUT for an IP address within the subnet of the DUT's VLAN.

    DUT should reply with an ARP reply or neighbor advertisement (NA) containing the DUT's own MAC
    """
    pytest_require(proxy_arp_enabled, 'Proxy ARP not enabled for all VLANs')

    ptf_intf_ipv4_addr, _, ptf_intf_ipv6_addr, _, ptf_intf_index  = ip_and_intf_info

    ip_version, outgoing_packet, expected_packet = packets_for_test

    if ip_version == 'v4':
        pytest_require(ptf_intf_ipv4_addr is not None, 'No IPv4 VLAN address configured on device')
    elif ip_version == 'v6':
        pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')

    ptfadapter.dataplane.flush()
    testutils.send_packet(ptfadapter, ptf_intf_index, outgoing_packet)
    testutils.verify_packet(ptfadapter, expected_packet, ptf_intf_index, timeout=10)
