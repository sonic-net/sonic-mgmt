'''
Test correct kernel ARP behavior
'''
import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane
from ptf.testutils import *
from ptf.mask import Mask
from ptf import config
from ptf.base_tests import BaseTest
#import ptf.testutils as testutils


class ACSDataplaneTest(BaseTest):

    def setUp(self):
        BaseTest.setUp(self)

        self.test_params = test_params_get()
        print "You specified the following test-params when invoking ptf:"
        print self.test_params

        # shows how to use a filter on all our tests
        add_filter(not_ipv6_filter)

        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        reset_filters()
        BaseTest.tearDown(self)

class ExpectReply(ACSDataplaneTest):
    '''
    Test correct ARP behavior, make sure SONiC is replying ARP request for local interface IP address
    SONiC switch should reply ARP and update ARP table entry to correct peer MAC address
    '''
    def runTest(self):
            acs_mac = self.test_params['acs_mac']
            pkt = simple_arp_packet(pktlen=60,
                      eth_dst='ff:ff:ff:ff:ff:ff',
                      eth_src='00:06:07:08:09:0a',
                      vlan_vid=0,
                      vlan_pcp=0,
                      arp_op=1,
                      ip_snd='10.10.1.3',
                      ip_tgt='10.10.1.2',
                      hw_snd='00:06:07:08:09:0a',
                      hw_tgt='ff:ff:ff:ff:ff:ff',
                      )
            exp_pkt = simple_arp_packet(eth_dst='00:06:07:08:09:0a',
                      eth_src=acs_mac,
                      arp_op=2,
                      ip_snd='10.10.1.2',
                      ip_tgt='10.10.1.3',
                      hw_tgt='00:06:07:08:09:0a',
                      hw_snd=acs_mac,
                      )
            send_packet(self, self.test_params['port'], pkt)
            verify_packet(self, exp_pkt, self.test_params['port'])

class VerifyUnicastARPReply(ACSDataplaneTest):
    '''
    Test correct ARP behavior, make sure SONiC is replying Unicast ARP request for local interface IP address
    SONiC switch should reply ARP and update ARP table entry to correct peer MAC address
    '''
    def runTest(self):
            acs_mac = self.test_params['acs_mac']
            pkt = simple_arp_packet(pktlen=60,
                      eth_dst=acs_mac,
                      eth_src='00:06:07:08:09:00',
                      vlan_vid=0,
                      vlan_pcp=0,
                      arp_op=1,
                      ip_snd='10.10.1.3',
                      ip_tgt='10.10.1.2',
                      hw_snd='00:06:07:08:09:00',
                      hw_tgt=acs_mac,
                      )
            exp_pkt = simple_arp_packet(eth_dst='00:06:07:08:09:00',
                      eth_src=acs_mac,
                      arp_op=2,
                      ip_snd='10.10.1.2',
                      ip_tgt='10.10.1.3',
                      hw_tgt='00:06:07:08:09:00',
                      hw_snd=acs_mac,
                      )
            send_packet(self, self.test_params['port'], pkt)
            verify_packet(self, exp_pkt, self.test_params['port'])


class WrongIntNoReply(ACSDataplaneTest):
    '''
    Test ARP packet from other(wrong) interface with dest IP address as local interface IP address
    SONiC should not reply to such ARP request
    '''
    def runTest(self):
            acs_mac = self.test_params['acs_mac']
            pkt = simple_arp_packet(pktlen=60,
                      eth_dst='ff:ff:ff:ff:ff:ff',
                      eth_src='00:02:07:08:09:0a',
                      vlan_vid=0,
                      vlan_pcp=0,
                      arp_op=1,
                      ip_snd='10.10.1.4',
                      ip_tgt='10.10.1.2',
                      hw_snd='00:02:07:08:09:0a',
                      hw_tgt='ff:ff:ff:ff:ff:ff',
                      )
            exp_pkt = simple_arp_packet(eth_dst='00:02:07:08:09:0a',
                        eth_src=acs_mac,
                        arp_op=2,
                        ip_snd='10.10.1.2',
                        ip_tgt='10.10.1.4',
                        hw_tgt='00:02:07:08:09:0a',
                        hw_snd=acs_mac,
                      )
            send_packet(self, self.test_params['port'], pkt)
            ports = ptf_ports()
            verify_no_packet_any(self, exp_pkt, ports)

class SrcOutRangeNoReply(ACSDataplaneTest):
    '''
    Test incoming ARP request src IP address is not within local interface subnet, even the destination address match
    SONiC should not reply such ARP request and should not add ARP table entry either
    '''
    def runTest(self):
        acs_mac = self.test_params['acs_mac']
        pkt = simple_arp_packet(pktlen=60,
                      eth_dst='ff:ff:ff:ff:ff:ff',
                      eth_src='00:03:07:08:09:0a',
                      vlan_vid=0,
                      vlan_pcp=0,
                      arp_op=1,
                      ip_snd='10.10.1.22',
                      ip_tgt='10.10.1.2',
                      hw_snd='00:03:07:08:09:0a',
                      hw_tgt='ff:ff:ff:ff:ff:ff',
                      )
        exp_pkt = simple_arp_packet(eth_dst='00:03:07:08:09:0a',
                        eth_src=acs_mac,
                        arp_op=2,
                        ip_snd='10.10.1.22',
                        ip_tgt='10.10.1.20',
                        hw_tgt='00:03:07:08:09:0a',
                        hw_snd=acs_mac,
                   )
        send_packet(self, self.test_params['port'], pkt)
        verify_no_packet(self, exp_pkt, self.test_params['port'])

class GarpNoUpdate(ACSDataplaneTest):
    '''
    When receiving gratuitous ARP packet, if it was not resolved in ARP table before,
    SONiC should discard the request and won't add ARP entry for the GARP
    '''
    def runTest(self):
        acs_mac = self.test_params['acs_mac']
        pkt = simple_arp_packet(pktlen=60,
                      eth_dst='ff:ff:ff:ff:ff:ff',
                      eth_src='00:05:07:08:09:0a',
                      vlan_vid=0,
                      vlan_pcp=0,
                      arp_op=1,
                      ip_snd='10.10.1.7',
                      ip_tgt='10.10.1.7',
                      hw_snd='00:05:07:08:09:0a',
                      hw_tgt='ff:ff:ff:ff:ff:ff',
                      )
        exp_pkt = simple_arp_packet(eth_dst='00:05:07:08:09:0a',
                        eth_src=acs_mac,
                        arp_op=2,
                        ip_snd='10.10.1.2',
                        ip_tgt='10.10.1.7',
                        hw_tgt='00:05:07:08:09:0a',
                        hw_snd=acs_mac,
                   )
        send_packet(self, self.test_params['port'], pkt)
        verify_no_packet(self, exp_pkt, self.test_params['port'])


class GarpUpdate(ACSDataplaneTest):
    '''
    When receiving gratuitous ARP packet, if it was resolved in ARP table before,
    SONiC should update ARP entry with new mac
    '''
    def runTest(self):
        acs_mac = self.test_params['acs_mac']
        pkt = simple_arp_packet(pktlen=60,
                      eth_dst='ff:ff:ff:ff:ff:ff',
                      eth_src='00:00:07:08:09:0a',
                      vlan_vid=0,
                      vlan_pcp=0,
                      arp_op=1,
                      ip_snd='10.10.1.3',
                      ip_tgt='10.10.1.3',
                      hw_snd='00:00:07:08:09:0a',
                      hw_tgt='ff:ff:ff:ff:ff:ff',
                      )
        exp_pkt = simple_arp_packet(eth_dst='00:00:07:08:09:0a',
                        eth_src=acs_mac,
                        arp_op=2,
                        ip_snd='10.10.1.2',
                        ip_tgt='10.10.1.3',
                        hw_tgt='00:00:07:08:09:0a',
                        hw_snd=acs_mac,
                   )
        send_packet(self, self.test_params['port'], pkt)
        verify_no_packet(self, exp_pkt, self.test_params['port'])
