import os
import ptf
import ptf.packet as scapy
from ptf.testutils import *
from ptf.mask import Mask
from ptf import config
from ptf.base_tests import BaseTest
import ptf.testutils as testutils
from scapy.all import Ether
from scapy.layers.l2 import Dot1Q
from scapy.layers.inet6 import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr

import logging

logger = logging.getLogger(__name__)


def make_ndp_grat_ndp_packet(pktlen=64,
                             eth_dst='00:01:02:03:04:05',
                             eth_src='00:06:07:08:09:0a',
                             dl_vlan_enable=False,
                             vlan_vid=0,
                             vlan_pcp=0,
                             ipv6_src='2001:db8:85a3::8a2e:370:7334',
                             ipv6_dst='2001:db8:85a3::8a2e:370:7335',
                             ipv6_tc=0,
                             ipv6_ecn=None,
                             ipv6_dscp=None,
                             ipv6_hlim=255,
                             ipv6_fl=0,
                             ipv6_tgt='2001:db8:85a3::8a2e:370:7334',
                             hw_tgt='00:06:07:08:09:0a', ):
    """
    Generates a simple NDP advertisement similar to PTF testutils simple_arp_packet.

    Args:
        pktlen: length of packet
        eth_dst: etheret destination address.
        eth_src: ethernet source address
        dl_vlan_enable: True to add vlan header.
        vlan_vid: vlan ID
        vlan_pcp: vlan priority
        ipv6_src: IPv6 source address
        ipv6_dst: IPv6 destination address
        ipv6_tc: IPv6 traffic class
        ipv6_ecn: IPv6 traffic class ECN
        ipv6_dscp: IPv6 traffic class DSCP
        ipv6_hlim: IPv6 hop limit/ttl
        ipv6_fl: IPv6 flow label
        ipv6_tgt: ICMPv6 ND advertisement target address.
        hw_tgt: IPv6 ND advertisement destination link-layer address.

    Returns:
        Crafted scapy packet for using with send_packet().
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    ipv6_tc = ip_make_tos(ipv6_tc, ipv6_ecn, ipv6_dscp)

    pkt = Ether(dst=eth_dst, src=eth_src)
    if dl_vlan_enable or vlan_vid or vlan_pcp:
        pkt /= Dot1Q(vlan=vlan_vid, prio=vlan_pcp)
    pkt /= IPv6(src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim)
    pkt /= ICMPv6ND_NA(R=0, S=0, O=1, tgt=ipv6_tgt)
    pkt /= ICMPv6NDOptDstLLAddr(lladdr=hw_tgt)
    pkt /= ("D" * (pktlen - len(pkt)))

    return pkt


class DataplaneTest(BaseTest):
    """
    Base class for tests
    """

    def setUp(self):
        BaseTest.setUp(self)

        self.test_params = test_params_get()
        logger.info("You specified the following test-params when invoking ptf:")
        logger.info(self.test_params)

        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] is not None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] is not None:
            self.dataplane.stop_pcap()
        reset_filters()
        BaseTest.tearDown(self)


class GARP(DataplaneTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()

    def runTest(self):
        """
        For test_voq_nbr test_gratarp_macchange, sends an unsolicited ARP
        """
        pkt = simple_arp_packet(
            eth_dst='ff:ff:ff:ff:ff:ff',
            eth_src=self.test_params['vm_mac'],
            arp_op=1,
            ip_snd=self.test_params['vmip'],
            ip_tgt=self.test_params['vmip'],
            hw_snd=self.test_params['vm_mac'],
            hw_tgt='ff:ff:ff:ff:ff:ff',
        )

        send_packet(self, self.test_params['port'], pkt)


class GNDP(DataplaneTest):

    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()

    def runTest(self):
        """
        For test_voq_nbr test_gratarp_macchange, sends an unsolicited NDP
        """
        pkt = make_ndp_grat_ndp_packet(eth_dst='33:33:00:00:00:01',
                                       eth_src=self.test_params['vm_mac'],
                                       ipv6_src=self.test_params['vmip'],
                                       ipv6_dst="ff02::1",
                                       ipv6_tgt=self.test_params['vmip'],
                                       hw_tgt=self.test_params['vm_mac'],
                                       )

        send_packet(self, self.test_params['port'], pkt)


def build_ttl0_pkts(version, dst_mac, dst_ip, vm_mac, vm_ip, dut_lb):
    """
    Builds ttl0 packet to send and ICMP TTL exceeded packet to expect back.

    Args:
        version: 4 or 6 for
        dst_mac: Destination MAC, of DUT port.
        dst_ip: Destination IP, a farend VM interface.
        vm_mac: Source MAC, of VM port that packets are sent out.
        vm_ip: Source IP, of the VM port.
        dut_lb: Loopback of DUT, source of the ICMP packets returned to the VM.

    Returns:
        3 packets, one with ttl0 to send, one as the ICMP expected packet, and one to check for TTL wrapping.

    """
    if version == 4:
        send_pkt = simple_udp_packet(eth_dst=dst_mac,  # mac address of dut
                                     eth_src=vm_mac,  # mac address of vm1
                                     ip_src=str(vm_ip),
                                     ip_dst=str(dst_ip),
                                     ip_ttl=0,
                                     pktlen=100)

        exp_pkt255 = simple_udp_packet(eth_dst=dst_mac,  # mac address of dut
                                       eth_src=vm_mac,  # mac address of vm1
                                       ip_src=str(vm_ip),
                                       ip_dst=str(dst_ip),
                                       ip_ttl=255,
                                       pktlen=100)
        v4_pktsz = 128
        exp_pkt = simple_icmp_packet(eth_dst=vm_mac,
                                     # mac address of vm1
                                     eth_src=dst_mac,  # mac address of dut
                                     ip_src=dut_lb,
                                     ip_dst=vm_ip,
                                     ip_ttl=64,
                                     icmp_code=0,
                                     icmp_type=11,
                                     pktlen=v4_pktsz,
                                     )

        masked_pkt = Mask(exp_pkt)
        masked_pkt.set_do_not_care_scapy(scapy.IP, "tos")
        masked_pkt.set_do_not_care_scapy(scapy.IP, "len")
        masked_pkt.set_do_not_care_scapy(scapy.IP, "id")
        masked_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_pkt.set_do_not_care_scapy(scapy.ICMP, "chksum")
        masked_pkt.set_do_not_care(304, v4_pktsz * 8 - 304)  # ignore icmp data

    else:
        send_pkt = simple_udpv6_packet(eth_dst=dst_mac,  # mac address of dut
                                       eth_src=vm_mac,  # mac address of vm1
                                       ipv6_src=str(vm_ip),
                                       ipv6_dst=str(dst_ip),
                                       ipv6_hlim=0,
                                       pktlen=100)

        exp_pkt255 = simple_udpv6_packet(eth_dst=dst_mac,  # mac address of dut
                                         eth_src=vm_mac,  # mac address of vm1
                                         ipv6_src=str(vm_ip),
                                         ipv6_dst=str(dst_ip),
                                         ipv6_hlim=255,
                                         pktlen=100)

        v6_pktsz = 148
        exp_pkt = simple_icmpv6_packet(eth_dst=vm_mac,  # mac address of vm1
                                       eth_src=dst_mac,  # mac address of dut
                                       ipv6_src=str(dut_lb),
                                       ipv6_dst=str(vm_ip),
                                       ipv6_hlim=64,
                                       icmp_code=0,
                                       icmp_type=3,
                                       pktlen=v6_pktsz,
                                       )
        #
        masked_pkt = Mask(exp_pkt)
        masked_pkt.set_do_not_care_scapy(scapy.IPv6, "tc")
        masked_pkt.set_do_not_care_scapy(scapy.IPv6, "fl")
        masked_pkt.set_do_not_care_scapy(scapy.IPv6, "plen")
        masked_pkt.set_do_not_care_scapy(scapy.ICMPv6Unknown, "cksum")
        masked_pkt.set_do_not_care(456, v6_pktsz * 8 - 456)  # ignore icmp data

    return send_pkt, masked_pkt, exp_pkt255


class TTL0(DataplaneTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()

    def runTest(self):
        """
        For test_voq_ipfwd - test_ipforwarding_ttl0, sends a ttl0 and verifies it is not forwarded and
        time exceeded message is received.

        """
        vm_mac = self.test_params['vm_mac']
        vm_ip = self.test_params['vm_ip']
        dut_lb = self.test_params['dut_lb']
        version = self.test_params['version']
        dst_mac = self.test_params['dst_mac']
        dst_ip = self.test_params['dst_ip']

        src_port = self.test_params['src_port']
        src_rx_ports = self.test_params['src_rx_ports']
        dst_rx_ports = self.test_params['dst_rx_ports']

        send_pkt, masked_pkt, exp_pkt255 = build_ttl0_pkts(version, dst_mac, dst_ip, vm_mac, vm_ip, dut_lb)
        logger.info("sending packet to port %s", src_port)
        send(self, src_port, send_pkt)
        print("masked packet matched port: %s" % src_port)

        result = dp_poll(self, device_number=0, exp_pkt=masked_pkt, timeout=2)
        self.at_receive(result.packet, device_number=result.device, port_number=result.port)

        print("Found %s ICMP ttl expired packets on ports: %s" % (result, str(src_rx_ports)))
        logger.info("Found %s ICMP ttl expired packets on ports: %s" % (result, str(src_rx_ports)))
        print("port: %s" % result.port)
        if result.port not in src_rx_ports:
            self.fail("Port %s not in %s" % (result.port, src_rx_ports))

        verify_no_packet_any(self, send_pkt, dst_rx_ports)
        verify_no_packet_any(self, exp_pkt255, dst_rx_ports)
        logger.info("Ran to completion.")


class MtuTest(BaseTest):
    """
    For jumbo packet test in voq/test_voq_ipfwd.py

    Test through multiple cards and ICMP to linecard host CPU.

    Modified from mtu_test.py
    """

    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = test_params_get()

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac_src_side']
        self.router_mac_dst = self.test_params['router_mac_dst_side']
        self.pktlen = self.test_params['pktlen']
        self.src_host_ip = self.test_params.get('src_host_ip')
        self.src_router_ip = self.test_params.get('src_router_ip')
        self.dst_host_ip = self.test_params.get('dst_host_ip')
        self.src_ptf_port_list = self.test_params.get('src_ptf_port_list')
        self.dst_ptf_port_list = self.test_params.get('dst_ptf_port_list')
        self.version = self.test_params.get('version')
        self.ignore_ttl = self.test_params.get('ignore_ttl')

    def check_icmp_mtu(self):
        """Check ICMP/Ping to DUT works for MAX MTU. """

        ip_src = self.src_host_ip
        ip_dst = self.src_router_ip
        src_mac = self.dataplane.get_mac(0, self.src_ptf_port_list[0])
        pktlen = self.pktlen

        if self.version == 4:
            pkt = simple_icmp_packet(pktlen=pktlen,
                                     eth_dst=self.router_mac,
                                     eth_src=src_mac,
                                     ip_src=ip_src,
                                     ip_dst=ip_dst,
                                     ip_ttl=64)

            exp_pkt = simple_icmp_packet(pktlen=pktlen,
                                         eth_src=self.router_mac,
                                         ip_src=ip_dst,
                                         ip_dst=ip_src,
                                         icmp_type=0)

            masked_exp_pkt = Mask(exp_pkt)
            masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "id")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
            masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "chksum")

        else:
            pkt = simple_icmpv6_packet(pktlen=pktlen,
                                       eth_dst=self.router_mac,
                                       eth_src=src_mac,
                                       ipv6_src=ip_src,
                                       ipv6_dst=ip_dst,
                                       ipv6_hlim=64,
                                       icmp_code=0,
                                       icmp_type=128)

            exp_pkt = simple_icmpv6_packet(pktlen=pktlen,
                                           eth_src=self.router_mac,
                                           ipv6_src=ip_dst,
                                           ipv6_dst=ip_src,
                                           icmp_type=129,
                                           icmp_code=0)

            masked_exp_pkt = Mask(exp_pkt)
            masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "id")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "tc")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "fl")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "plen")
            masked_exp_pkt.set_do_not_care_scapy(scapy.ICMPv6Unknown, "chksum")

        src_port = self.src_ptf_port_list[0]
        send_packet(self, src_port, pkt)
        logging.info("Sending packet from port " + str(src_port) + " address " + ip_src)
        logging.info("To MAC %s, dst_ip: %s", self.router_mac, ip_dst)
        dst_port_list = self.src_ptf_port_list
        logging.info("Expect packet on port: %s of len %s, eth: %s, ipsrc: %s, ipdst: %s",
                     str(dst_port_list), pktlen, self.router_mac, ip_dst, ip_src)

        (matched_index, received) = verify_packet_any_port(self, masked_exp_pkt, dst_port_list)

        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))

        return

    def check_ip_mtu(self):
        """Check unicast IP forwarding in DUT works for MAX MTU."""

        ip_src = self.src_host_ip
        ip_dst = self.dst_host_ip
        src_mac = self.dataplane.get_mac(0, self.src_ptf_port_list[0])

        if self.version == 4:
            pkt = simple_ip_packet(pktlen=self.pktlen,
                                   eth_dst=self.router_mac,
                                   eth_src=src_mac,
                                   ip_src=ip_src,
                                   ip_dst=ip_dst,
                                   ip_ttl=64)

            exp_pkt = simple_ip_packet(pktlen=self.pktlen,
                                       eth_src=self.router_mac_dst,
                                       ip_src=ip_src,
                                       ip_dst=ip_dst,
                                       ip_ttl=63)

            masked_exp_pkt = Mask(exp_pkt)
            masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
            if self.ignore_ttl:
                masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
                masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")

        else:
            pkt = simple_ipv6ip_packet(pktlen=self.pktlen,
                                       eth_dst=self.router_mac,
                                       eth_src=src_mac,
                                       ipv6_src=ip_src,
                                       ipv6_dst=ip_dst,
                                       ipv6_hlim=64)

            exp_pkt = simple_ipv6ip_packet(pktlen=self.pktlen,
                                           eth_src=self.router_mac_dst,
                                           ipv6_src=ip_src,
                                           ipv6_dst=ip_dst,
                                           ipv6_hlim=63)

            masked_exp_pkt = Mask(exp_pkt)
            masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
            if self.ignore_ttl:
                masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
                masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "chksum")

        src_port = self.src_ptf_port_list[0]
        send_packet(self, src_port, pkt)

        dst_port_list = self.dst_ptf_port_list
        logging.info("Sending packet from port " + str(src_port) + " to " + ip_dst + " expected ports " + str(dst_port_list))
        (matched_index, received) = verify_packet_any_port(self, masked_exp_pkt, dst_port_list)

        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))

        return

    def runTest(self):
        """
        Send MAX MTU packet to and through DUT.
        """
        self.check_icmp_mtu()
        self.check_ip_mtu()
