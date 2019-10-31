'''
Description:    This file contains the EVERFLOW neighbor test
'''


import time
import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane
import ptf.testutils as testutils
from ptf.base_tests import BaseTest
from ptf.mask import Mask

class EverflowNeighborTest(BaseTest):

    GRE_PROTOCOL_NUMBER = 47

    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()


    def greFilter(self, pkt_str):
        '''
        @summaty: Filter GRE packets
        '''
        try:
            pkt = scapy.Ether(pkt_str)

            if scapy.IP not in pkt:
                return False

            return pkt[scapy.IP].proto == self.GRE_PROTOCOL_NUMBER
        except:
            return False


    def setUp(self):
        '''
        @summary: Setup the test
        '''
        print ""

        self.dataplane = ptf.dataplane_instance
        self.hwsku = self.test_params['hwsku']
        self.asic_type = self.test_params['asic_type']
        self.router_mac = self.test_params['router_mac']
        self.session_src_ip = "1.1.1.1"
        self.session_dst_ip = "2.2.2.2"
        self.session_ttl = 1
        self.session_dscp = 8
        self.src_port = int(self.test_params['src_port'])
        self.dst_mirror_ports = [int(p) for p in self.test_params['dst_mirror_ports'].split(",") if p]
        self.dst_ports = [int(p) for p in self.test_params['dst_ports'].split(",")]

        self.base_pkt = testutils.simple_arp_packet(
                eth_dst = self.router_mac,
                eth_src = self.dataplane.get_mac(0, 0)
                )

        self.basev6_pkt = testutils.simple_icmpv6_packet(
                eth_dst = self.router_mac,
                eth_src = self.dataplane.get_mac(0, 0),
                icmp_type=135
                )

    def checkMirroredPacket(self, ipv4=True):
        """
        @summary: Send traffic & check if packets are get received

        Note:
        Mellanox crafts the GRE packets with extra information:
        That is: 22 bytes extra information after the GRE header
        """
        if ipv4:
            pkt = self.base_pkt
        else:
            pkt = self.basev6_pkt

        payload = pkt.copy()
        payload_mask = Mask(payload)

        if self.mirror_stage == "egress":
            payload['Ethernet'].src = self.router_mac
            payload['IP'].ttl -= 1
            payload_mask.set_do_not_care_scapy(scapy.Ether, "dst")
            payload_mask.set_do_not_care_scapy(scapy.IP, "chksum")

        if self.asic_type in ["mellanox"]:
            import binascii
            payload = binascii.unhexlify("0"*44) + str(payload) # Add the padding

        exp_pkt = testutils.simple_gre_packet(
                eth_src = self.router_mac,
                ip_src = self.session_src_ip,
                ip_dst = self.session_dst_ip,
                ip_dscp = self.session_dscp,
                ip_id = 0,
                #ip_flags = 0x10, # need to upgrade ptf version to support it
                ip_ttl = self.session_ttl,
                inner_frame = payload)

        if self.asic_type in ["mellanox"]:
            exp_pkt['GRE'].proto = 0x8949 # Mellanox specific
        else:
            exp_pkt['GRE'].proto = 0x88be

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "flags")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care(38*8, len(payload)*8)  # don't match payload, payload will be matched by match_payload(pkt)

        def match_payload(pkt):
            pkt = scapy.Ether(pkt).load
            if self.asic_type in ["mellanox"]:
                pkt = pkt[22:] # Mask the Mellanox specific inner header
            pkt = scapy.Ether(pkt)

            return dataplane.match_exp_pkt(payload_mask, pkt)

        self.dataplane.flush()

        testutils.send_packet(self, self.src_port, pkt)
        (rcv_device, rcv_port, rcv_pkt, pkt_time) = testutils.dp_poll(self, timeout=0.1, exp_pkt=masked_exp_pkt)
        if rcv_pkt is not None and match_payload(rcv_pkt):
            print "Pass mirroring"
        else:
            assert False

    def runTest(self):
        """
        @summary: Run EVERFLOW Neighbor Test
        """

        testutils.add_filter(self.greFilter)
        self.checkMirroredPacket(ipv4=True)
        self.checkMirroredPacket(ipv4=False)

