'''
Description:    This file contains the EVERFLOW policer test

Usage:          Examples of how to use:
                ptf --test-dir acstests everflow_policer_test.EverflowPolicerTest --platform remote -t 'router_mac="00:02:03:04:05:00";src_port="20";dst_ports="21,22";verbose=True' --relax
'''


import sys
import time
import logging

import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane
import ptf.testutils as testutils
from ptf.base_tests import BaseTest
from ptf.mask import Mask

logger = logging.getLogger('EverflowPolicerTest')

class EverflowPolicerTest(BaseTest):

    GRE_PROTOCOL_NUMBER = 47
    NUM_OF_TOTAL_PACKETS = 500
    METER_TYPES = ['packets', 'bytes']


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


    def getCBSRefillTime(self):
        '''
        @summary: Gets Committed Burst Size (CBS) bucket refill time

        Note:
        Committed Burst Size (CBS) refills at Committed Information Rate (CIR) speed.
        Example: meter_type=packets, CBS=100 pkts, CIR=100 pkt/sec
        refill_time = CBS/CIR = 100 pkts / 100 pkt/sec = 1 sec
        '''

        return self.cbs / self.cir


    def setupLogging(self):
        handler = logging.StreamHandler(sys.stdout)
        logger.addHandler(handler)


    def logParams(self):
        '''
        @summary: Pretty prints test parameters
        '''

        logger.info("#")
        logger.info("# Params")
        logger.info("#")

        msg = "hwsku={}".format(self.hwsku)
        logger.info(msg)
        msg = "asic_type={}".format(self.asic_type)
        logger.info(msg)
        msg = "router_mac={}".format(self.router_mac)
        logger.info(msg)
        msg = "mirror_stage={}".format(self.mirror_stage)
        logger.info(msg)
        msg = "session_src_ip={}".format(self.session_src_ip)
        logger.info(msg)
        msg = "session_dst_ip={}".format(self.session_dst_ip)
        logger.info(msg)
        msg = "session_ttl={}".format(self.session_ttl)
        logger.info(msg)
        msg = "session_dscp={}".format(self.session_dscp)
        logger.info(msg)
        msg = "src_port={}".format(self.src_port)
        logger.info(msg)
        msg = "dst_mirror_ports={}".format(str(self.dst_mirror_ports))
        logger.info(msg)
        msg = "dst_ports={}".format(str(self.dst_ports))
        logger.info(msg)
        msg = "meter_type={}".format(self.meter_type)
        logger.info(msg)
        msg = "cir={}".format(self.cir)
        logger.info(msg)
        msg = "cbs={}".format(self.cbs)
        logger.info(msg)
        msg = "tolerance={}".format(self.tolerance)
        logger.info(msg)
        msg = "min_range={}".format(self.min_range)
        logger.info(msg)
        msg = "max_range={}".format(self.max_range)
        logger.info(msg)


    def setUp(self):
        '''
        @summary: Setup the test
        '''
        print ""

        self.dataplane = ptf.dataplane_instance
        self.hwsku = self.test_params['hwsku']
        self.asic_type = self.test_params['asic_type']
        self.router_mac = self.test_params['router_mac']
        self.mirror_stage = self.test_params['mirror_stage']
        self.session_src_ip = self.test_params['session_src_ip']
        self.session_dst_ip = self.test_params['session_dst_ip']
        self.session_ttl = int(self.test_params['session_ttl'])
        self.session_dscp = int(self.test_params['session_dscp'])
        self.src_port = int(self.test_params['src_port'])
        self.dst_mirror_ports = [int(p) for p in self.test_params['dst_mirror_ports'].split(",") if p]
        self.dst_ports = [int(p) for p in self.test_params['dst_ports'].split(",")]
        self.meter_type = self.test_params['meter_type']
        self.cir = int(self.test_params['cir'])
        self.cbs = int(self.test_params['cbs'])
        self.tolerance = int(self.test_params['tolerance'])

        assert_str = "meter_type({0}) not in {1}".format(self.meter_type, str(self.METER_TYPES))
        assert self.meter_type in self.METER_TYPES, assert_str
        assert_str = "cir({}) > 0".format(self.cir)
        assert self.cir > 0, assert_str
        assert_str = "cbs({}) > 0".format(self.cbs)
        assert self.cbs > 0, assert_str

        self.min_range = self.cbs - (self.cbs / 100) * self.tolerance
        self.max_range = self.cbs + (self.cbs / 100) * self.tolerance

        self.base_pkt = testutils.simple_tcp_packet(
                eth_dst = self.router_mac,
                eth_src = self.dataplane.get_mac(0, 0),
                ip_src = "20.0.0.1",
                ip_dst = "30.0.0.1",
                tcp_sport = 0x1234,
                tcp_dport = 0x50,
                ip_dscp = 9,
                ip_ttl = 64)

        self.setupLogging()
        self.logParams()

    def checkOriginalFlow(self):
        """
        @summary: Send traffic & check how many original packets are received
        @return: count: number of original packets received
        """
        exp_pkt = self.base_pkt.copy()
        exp_pkt['Ethernet'].src = self.router_mac
        exp_pkt['IP'].ttl = self.base_pkt['IP'].ttl - 1

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")

        self.dataplane.flush()

        count = 0
        for i in range(0, self.NUM_OF_TOTAL_PACKETS):
            testutils.send_packet(self, self.src_port, self.base_pkt)
            (rcv_device, rcv_port, rcv_pkt, pkt_time) = testutils.dp_poll(self, timeout=0.1, exp_pkt=masked_exp_pkt)
            if rcv_pkt is not None:
                count += 1
            elif count == 0:
                assert_str = "The first original packet is not recieved"
                assert count > 0, assert_str # Fast failure without waiting for full iteration

        logger.info("Recieved {} original packets".format(count))

        return count

    def checkMirroredFlow(self):
        """
        @summary: Send traffic & check how many mirrored packets are received
        @return: count: number of mirrored packets received

        Note:
        Mellanox crafts the GRE packets with extra information:
        That is: 22 bytes extra information after the GRE header
        """
        payload = self.base_pkt.copy()
        payload_mask = Mask(payload)

        if self.mirror_stage == "egress":
            payload['Ethernet'].src = self.router_mac
            payload['IP'].ttl -= 1
            payload_mask.set_do_not_care_scapy(scapy.Ether, "dst")
            payload_mask.set_do_not_care_scapy(scapy.IP, "chksum")

        if self.asic_type in ["mellanox"]:
            import binascii
            payload = binascii.unhexlify("0"*44) + str(payload) # Add the padding

        if self.asic_type in ["barefoot"]:
            import binascii
            payload = binascii.unhexlify("0"*24) + str(payload) # Add the padding

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
        elif self.asic_type in ["barefoot"]:
            exp_pkt['GRE'].proto = 0x22eb # Barefoot specific
        else:
            exp_pkt['GRE'].proto = 0x88be

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "flags")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care(38*8, len(payload)*8)  # don't match payload, payload will be matched by match_payload(pkt)

        def match_payload(pkt):
            if self.asic_type in ["mellanox"]:
                pkt = scapy.Ether(pkt).load
                pkt = pkt[22:] # Mask the Mellanox specific inner header
                pkt = scapy.Ether(pkt)
            else:
                pkt = scapy.Ether(pkt)[scapy.GRE].payload

            return dataplane.match_exp_pkt(payload_mask, pkt)

        self.dataplane.flush()

        count = 0
        testutils.send_packet(self, self.src_port, self.base_pkt, count=self.NUM_OF_TOTAL_PACKETS)
        for i in range(0,self.NUM_OF_TOTAL_PACKETS):
            (rcv_device, rcv_port, rcv_pkt, pkt_time) = testutils.dp_poll(self, timeout=0.1, exp_pkt=masked_exp_pkt)
            if rcv_pkt is not None and match_payload(rcv_pkt):
                count += 1
            elif count == 0:
                assert_str = "The first mirrored packet is not recieved"
                assert count > 0, assert_str # Fast failure without waiting for full iteration
            else:
                break # No more packets available

        logger.info("Received {} mirrored packets after rate limiting".format(count))

        return count


    def runTest(self):
        """
        @summary: Run EVERFLOW Policer Test
        """

        logger.info("#")
        logger.info("# Run test")
        logger.info("#")

        # Send traffic and verify the original traffic is not rate limited
        count = self.checkOriginalFlow()
        assert count == self.NUM_OF_TOTAL_PACKETS

        # Verify packet policing is used
        assert_str = "Non packet policing is not supported"
        assert self.meter_type == "packets", assert_str

        # Sleep for t=CBS/CIR to refill CBS capacity after checkOriginalFlow()
        # otherwise we can have first mirrored packet dropped by policer in checkMirroredFlow()
        time.sleep(self.getCBSRefillTime())

        testutils.add_filter(self.greFilter)

        # Send traffic and verify the mirroed traffic is rate limited
        count = self.checkMirroredFlow()
        assert_str = "min({1}) <= count({0}) <= max({2})".format(count, self.min_range, self.max_range)
        assert count >= self.min_range and count <= self.max_range, assert_str
