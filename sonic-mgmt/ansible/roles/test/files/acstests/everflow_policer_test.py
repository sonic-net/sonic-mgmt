'''
Description:    This file contains the EVERFLOW policer test

Usage:          Examples of how to use:
                ptf --test-dir acstests everflow_policer_test.EverflowPolicerTest --platform remote -t 'router_mac="00:02:03:04:05:00";src_port="20";dst_ports="21,22";verbose=True' --relax
'''


import sys
import time
import datetime
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
    NUM_OF_TOTAL_PACKETS = 10000
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
        msg = "send_time={}".format(self.send_time)
        logger.info(msg)
        msg = "tolerance={}".format(self.tolerance)
        logger.info(msg)
        msg = "min_range={}".format(self.min_rx_pps)
        logger.info(msg)
        msg = "max_range={}".format(self.max_rx_pps)
        logger.info(msg)
        msg = "check_ttl={}".format(self.check_ttl)
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
        self.send_time = int(self.test_params['send_time'])
        self.tolerance = int(self.test_params['tolerance'])
        self.check_ttl = self.test_params['check_ttl']

        assert_str = "meter_type({0}) not in {1}".format(self.meter_type, str(self.METER_TYPES))
        assert self.meter_type in self.METER_TYPES, assert_str
        assert_str = "cir({}) > 0".format(self.cir)
        assert self.cir > 0, assert_str
        assert_str = "cbs({}) > 0".format(self.cbs)
        assert self.cbs > 0, assert_str

        self.min_rx_pps, self.max_rx_pps = self.cbs * (1 - self.tolerance/100.), self.cbs * (1 + self.tolerance/100.)

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
        if self.check_ttl == 'False':
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")

        self.dataplane.flush()

        count = 0
        testutils.send_packet(self, self.src_port, str(self.base_pkt), count=self.NUM_OF_TOTAL_PACKETS)
        for i in range(0, self.NUM_OF_TOTAL_PACKETS):
            (rcv_device, rcv_port, rcv_pkt, pkt_time) = testutils.dp_poll(self, timeout=0.1, exp_pkt=masked_exp_pkt)
            if rcv_pkt is not None:
                count += 1
            elif count == 0:
                assert_str = "The first original packet is not recieved"
                assert count > 0, assert_str # Fast failure without waiting for full iteration
            else:
                break # No more packets available

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
            exp_pkt = testutils.ipv4_erspan_pkt(
                eth_src = self.router_mac,
                ip_src = self.session_src_ip,
                ip_dst = self.session_dst_ip,
                ip_dscp = self.session_dscp,
                ip_ttl = self.session_ttl,
                inner_frame = str(payload),
                ip_id = 0,
                sgt_other=0x4)
        else:
            exp_pkt['GRE'].proto = 0x88be

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "flags")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")

        if exp_pkt.haslayer(scapy.ERSPAN_III):
            masked_exp_pkt.set_do_not_care_scapy(scapy.ERSPAN_III, "span_id")
            masked_exp_pkt.set_do_not_care_scapy(scapy.ERSPAN_III, "timestamp")

        # don't match payload, payload will be matched by match_payload(pkt)
        payload_offset = len(exp_pkt) - len(payload)
        masked_exp_pkt.set_do_not_care(payload_offset*8, len(payload)*8)

        if self.check_ttl == 'False':
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")

        def match_payload(pkt):
            if self.asic_type in ["mellanox"]:
                pkt = scapy.Ether(pkt).load
                pkt = pkt[22:] # Mask the Mellanox specific inner header
                pkt = scapy.Ether(pkt)
            elif self.asic_type == "barefoot":
                pkt = scapy.Ether(pkt).load
            else:
                pkt = scapy.Ether(pkt)[scapy.GRE].payload

            return dataplane.match_exp_pkt(payload_mask, pkt)

        # send some amount to absorb CBS capacity
        testutils.send_packet(self, self.src_port, str(self.base_pkt), count=self.NUM_OF_TOTAL_PACKETS)
        self.dataplane.flush()

        end_time = datetime.datetime.now() + datetime.timedelta(seconds=self.send_time)
        tx_pkts = 0
        while datetime.datetime.now() < end_time:
            testutils.send_packet(self, self.src_port, str(self.base_pkt))
            tx_pkts += 1

        rx_pkts = 0
        while True:
            (rcv_device, rcv_port, rcv_pkt, pkt_time) = testutils.dp_poll(self, timeout=0.1, exp_pkt=masked_exp_pkt)
            if rcv_pkt is not None and match_payload(rcv_pkt):
                rx_pkts += 1
            else:
                break # No more packets available

        tx_pps = tx_pkts / self.send_time
        rx_pps = rx_pkts / self.send_time

        logger.info("Sent {} packets".format(tx_pkts))
        logger.info("Received {} mirrored packets after rate limiting".format(rx_pkts))
        logger.info("TX PPS {}".format(tx_pps))
        logger.info("RX PPS {}".format(rx_pps))

        return rx_pkts, tx_pps, rx_pps


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
        rx_pkts, tx_pps, rx_pps = self.checkMirroredFlow()

        assert_str = "Transmition rate is lower then policer rate limiting." \
                     "Most probably slow testbed server issue: tx_pps({}) <= rx_pps_max({})".format(tx_pps, self.max_rx_pps)
        assert tx_pps > self.max_rx_pps, assert_str

        assert_str = "min({1}) <= pps({0}) <= max({2})".format(rx_pps, self.min_rx_pps, self.max_rx_pps)
        assert rx_pps >= self.min_rx_pps and rx_pps <= self.max_rx_pps, assert_str
