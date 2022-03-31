# Packet Test Framework imports
import logging

import ptf
import ptf.testutils as testutils
import scapy.layers.inet6 as inet6
import scapy.layers.l2 as l2
from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask
import scapy.all as scapy2
Ether = l2.Ether
IPv6 = inet6.IPv6
RA = inet6.ICMPv6ND_RA
RS = inet6.ICMPv6ND_RS
PrefixInfo = inet6.ICMPv6NDOptPrefixInfo

ALL_NODES_MULTICAST_MAC_ADDRESS = '33:33:00:00:00:01'
ALL_ROUTERS_MULTICAST_MAC_ADDRESS = '33:33:00:00:00:02'
ALL_NODES_IPV6_MULTICAST_ADDRESS = 'ff02::1'
ALL_ROUTERS_IPV6_MULTICAST_ADDRESS = 'ff02::2'
ICMPV6_SOLICITED_RA_TIMEOUT_SECS = 1

class DataplaneBaseTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)

    def setUp(self):
        # Filter for ICMPv6 RA packets
        def is_icmpv6_ra(pkt_str):
            try:
                pkt = Ether(pkt_str)
                return (IPv6 in pkt and RA in pkt)
            except Exception:
                return False

        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        testutils.add_filter(is_icmpv6_ra)

        if config["log_dir"] is not None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] is not None:
            self.dataplane.stop_pcap()
        testutils.reset_filters()

    """
    @summary: Creates an ICMPv6 router advertisement packet with ICMPv6 prefix option

    """
    def create_icmpv6_router_advertisement_packet_send(self, dst_mac, dst_ip, src_mac, src_ip):
        ether = Ether(dst=dst_mac, src=src_mac)
        ip6 = IPv6(src=src_ip, dst=dst_ip, fl=0, tc=0, hlim=255)
        icmp6 = RA(code=0,M=1,O=0)
        #NOTE: Test expects RA packet to contain route prefix as the first option
        icmp6 /= PrefixInfo(type=3, len=4)
        rapkt = ether / ip6 / icmp6
        scapy2.sendp(rapkt, iface="eth1")
        logging.info(scapy2.sniff(iface='eth1',timeout=10))
        return rapkt

    """
    @summary: Mask off fields we don't care about matching in RA packet
    Match following fields of RA packet:-
        1. Eth src and dest
        2. Link local IPv6 src and dest
        3. IP6 hop limit = 255
        4. ICMPv6 RA type == 134 and code == 0
        5. Flag M == 1 and O == 0
        6. ICMPv6 prefix option (i.e type == 3 and len == 4)

    """
    def mask_off_dont_care_ra_packet_fields(self, rapkt):
        masked_rapkt = Mask(rapkt)
        masked_rapkt.set_ignore_extra_bytes()

        masked_rapkt.set_do_not_care_scapy(IPv6, "tc")
        masked_rapkt.set_do_not_care_scapy(IPv6, "fl")
        masked_rapkt.set_do_not_care_scapy(IPv6, "plen")
        masked_rapkt.set_do_not_care_scapy(IPv6, "nh")

        masked_rapkt.set_do_not_care_scapy(RA, "cksum")
        masked_rapkt.set_do_not_care_scapy(RA, "chlim")
        masked_rapkt.set_do_not_care_scapy(RA, "H")
        masked_rapkt.set_do_not_care_scapy(RA, "prf")
        masked_rapkt.set_do_not_care_scapy(RA, "P")
        masked_rapkt.set_do_not_care_scapy(RA, "res")
        masked_rapkt.set_do_not_care_scapy(RA, "routerlifetime")
        masked_rapkt.set_do_not_care_scapy(RA, "reachabletime")
        masked_rapkt.set_do_not_care_scapy(RA, "retranstimer")

        masked_rapkt.set_do_not_care_scapy(PrefixInfo, "prefixlen")
        masked_rapkt.set_do_not_care_scapy(PrefixInfo, "L")
        masked_rapkt.set_do_not_care_scapy(PrefixInfo, "A")
        masked_rapkt.set_do_not_care_scapy(PrefixInfo, "R")
        masked_rapkt.set_do_not_care_scapy(PrefixInfo, "res1")
        masked_rapkt.set_do_not_care_scapy(PrefixInfo, "validlifetime")
        masked_rapkt.set_do_not_care_scapy(PrefixInfo, "preferredlifetime")
        masked_rapkt.set_do_not_care_scapy(PrefixInfo, "res2")
        masked_rapkt.set_do_not_care_scapy(PrefixInfo, "prefix")

        return masked_rapkt

"""
@summary: This test is to validate the unsolicted router advertisements sent on
the VLAN network of the ToR. In this test we listen on the first PTF port
(Eg eth0) for any RA messages.

"""

class RadvUnSolicitedRATest(DataplaneBaseTest):
    def __init__(self):
        DataplaneBaseTest.__init__(self)

    def setUp(self):
        DataplaneBaseTest.setUp(self)

        self.test_params = testutils.test_params_get()

        self.hostname = self.test_params['hostname']
        self.downlink_vlan_mac = self.test_params['downlink_vlan_mac']
        self.downlink_vlan_ip6 = self.test_params['downlink_vlan_ip6']
        self.ptf_port_index = int(self.test_params['ptf_port_index'])
        self.ptf_port_mac = self.dataplane.get_mac(0, self.ptf_port_index)
        self.radv_max_ra_interval = int(self.test_params['max_ra_interval'])

        rapkt = self.create_icmpv6_router_advertisement_packet_send(
                                                src_mac=self.downlink_vlan_mac,
                                                dst_mac=ALL_NODES_MULTICAST_MAC_ADDRESS,
                                                src_ip=self.downlink_vlan_ip6,
                                                dst_ip=ALL_NODES_IPV6_MULTICAST_ADDRESS)
        self.masked_rapkt = self.mask_off_dont_care_ra_packet_fields(rapkt)


    def tearDown(self):
        DataplaneBaseTest.tearDown(self)

    """
    @summary: Verify received RA packet

    """

    def verify_periodic_router_advertisement_with_m_flag(self):
        testutils.verify_packet(self,
                                self.masked_rapkt,
                                self.ptf_port_index,
                                self.radv_max_ra_interval)
        logging.info("Received unsolicited RA from:%s on PTF eth%d having M=1",
                     self.downlink_vlan_ip6,
                     self.ptf_port_index)


    def runTest(self):
        self.verify_periodic_router_advertisement_with_m_flag()
        

"""
@summary: This test validates the solicited router advertisement sent on the VLAN network of the ToR
We simulate the ToR sending the ICMPv6 router solicitation packet through one of the PTF port (eg eth0)

"""

class RadvSolicitedRATest(DataplaneBaseTest):
    def __init__(self):
        DataplaneBaseTest.__init__(self)

    def setUp(self):
        DataplaneBaseTest.setUp(self)

        self.test_params = testutils.test_params_get()

        self.hostname = self.test_params['hostname']
        self.downlink_vlan_mac = self.test_params['downlink_vlan_mac']
        self.downlink_vlan_ip6 = self.test_params['downlink_vlan_ip6']
        self.ptf_port_index = int(self.test_params['ptf_port_index'])
        self.ptf_port_mac = self.dataplane.get_mac(0, self.ptf_port_index)
        self.ptf_port_ip6 = self.test_params['ptf_port_ip6']
        self.radv_max_ra_interval = int(self.test_params['max_ra_interval'])

        rapkt = self.create_icmpv6_router_advertisement_packet_send(
                                    src_mac=self.downlink_vlan_mac,
                                    dst_mac=self.ptf_port_mac,
                                    src_ip=self.downlink_vlan_ip6,
                                    dst_ip=self.ptf_port_ip6)

        self.masked_rapkt = self.mask_off_dont_care_ra_packet_fields(rapkt)
        self.rs_packet = self.create_icmpv6_router_solicitation_packet()

    def tearDown(self):
        DataplaneBaseTest.tearDown(self)


    """
    @summary: Creates a solicited RA packet originating from PTF port

    """
    def create_icmpv6_router_solicitation_packet(self):
        ether = Ether(dst=ALL_ROUTERS_MULTICAST_MAC_ADDRESS,
                      src=self.ptf_port_mac)
        ip6 = IPv6(dst=ALL_ROUTERS_IPV6_MULTICAST_ADDRESS,
                   src=self.ptf_port_ip6,
                   fl=0,
                   tc=0,
                   hlim=255)
        icmp6 = RS(code=0, res=0)
        rspkt = ether / ip6 / icmp6
        return rspkt

    """
    @summary: Sends ICMPv6 router solicitation packet on PTF port

    """
    def ptf_send_icmpv6_router_solicitation(self):
        logging.info("Sending ICMPv6 router solicitation on PTF port:eth%s",
                     self.ptf_port_index)
        ret = testutils.send_packet(self, self.ptf_port_index, self.rs_packet)
        assert len(self.rs_packet) == ret, \
               "Failed to send ICMPv6 router solicitation on PTF eth%s".format(self.ptf_port_index)

    """
    @summary: Verify the received solicited RA packet from the router/DUT

    """
    def verify_solicited_router_advertisement_with_m_flag(self):
        testutils.verify_packet(self,
                                self.masked_rapkt,
                                self.ptf_port_index,
                                ICMPV6_SOLICITED_RA_TIMEOUT_SECS)
        logging.info("Received solicited RA from:%s on PTF eth%d having M=1",
                     self.downlink_vlan_ip6,
                     self.ptf_port_index)
        
    def runTest(self):
        count = 5
        while count > 0:
            self.ptf_send_icmpv6_router_solicitation()
            self.verify_solicited_router_advertisement_with_m_flag()
            count = count - 1
