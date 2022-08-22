# ptf --test-dir saitests copp_tests --qlen=100000 --platform nn -t "verbose=True;target_port=3" --device-socket 0-3@tcp://127.0.0.1:10900 --device-socket 1-3@tcp://10.3.147.47:10900
# or
# ptf --test-dir saitests copp_tests --qlen=100000 --platform nn -t "verbose=True;target_port=10" --device-socket 0-10@tcp://127.0.0.1:10900 --device-socket 1-10@tcp://10.3.147.47:10900
#
# copp_test.${name_test}
#
# ARPTest
# DHCPTest
# DHCPTopoT1Test
# DHCP6Test
# LLDPTest
# BGPTest
# LACPTest
# SNMPTest
# SSHTest
# IP2METest
# DefaultTest

import datetime
import os
import ptf
import signal
import threading
import time

import ptf.testutils as testutils

from ptf.base_tests import BaseTest
from ptf import config


class ControlPlaneBaseTest(BaseTest):
    MAX_PORTS = 128
    PPS_LIMIT = 600
    PPS_LIMIT_MIN = PPS_LIMIT * 0.9
    PPS_LIMIT_MAX = PPS_LIMIT * 1.3
    NO_POLICER_LIMIT = PPS_LIMIT * 1.4
    TARGET_PORT = "3"  # Historically we have port 3 as a target port
    TASK_TIMEOUT = 600  # Wait up to 10 minutes for tasks to complete

    DEFAULT_PRE_SEND_INTERVAL_SEC = 1
    DEFAULT_SEND_INTERVAL_SEC = 30
    DEFAULT_RECEIVE_WAIT_TIME = 3

    def __init__(self):
        BaseTest.__init__(self)
        self.log_fp = open('/tmp/copp.log', 'a')
        test_params = testutils.test_params_get()
        self.verbose = 'verbose' in test_params and test_params['verbose']

        target_port_str = test_params.get('target_port', self.TARGET_PORT)
        self.target_port = int(target_port_str)

        self.timeout_thr = None

        self.myip = test_params.get('myip', None)
        self.peerip = test_params.get('peerip', None)
        self.default_server_send_rate_limit_pps = test_params.get('send_rate_limit', 2000)

        self.needPreSend = None
        self.has_trap = test_params.get('has_trap', True)

    def log(self, message, debug=False):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if (debug and self.verbose) or (not debug):
            print("%s : %s" % (current_time, message))
        self.log_fp.write("%s : %s\n" % (current_time, message))

    def setUp(self):
        self.dataplane = ptf.dataplane_instance

        self.my_mac = {}
        self.peer_mac = {}
        for port_id, port in self.dataplane.ports.iteritems():
            if port_id[0] == 0:
                self.my_mac[port_id[1]] = port.mac()
            elif port_id[0] == 1:
                self.peer_mac[port_id[1]] = port.mac()
            else:
                assert True

        self.dataplane.flush()

        if config["log_dir"] is not None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] is not None:
            self.dataplane.stop_pcap()

        self.log_fp.close()

    def timeout(self, seconds, message):
        def timeout_exception(self, message):
            self.log('Timeout is reached: %s' % message)
            self.tearDown()
            os.kill(os.getpid(), signal.SIGINT)

        if self.timeout_thr is None:
            self.timeout_thr = threading.Timer(seconds, timeout_exception, args=(self, message))
            self.timeout_thr.start()
        else:
            raise Exception("Timeout already set")

    def cancel_timeout(self):
        if self.timeout_thr is not None:
            self.timeout_thr.cancel()
            self.timeout_thr = None

    def copp_test(self, packet, send_intf, recv_intf):
        '''
        Pre-send some packets for a second to absorb the CBS capacity.
        '''
        if self.needPreSend:
            pre_send_count = 0
            end_time = datetime.datetime.now() + datetime.timedelta(seconds=self.DEFAULT_PRE_SEND_INTERVAL_SEC)
            while datetime.datetime.now() < end_time:
                testutils.send_packet(self, send_intf, packet)
                pre_send_count += 1

            rcv_pkt_cnt = testutils.count_matched_packets_all_ports(self, packet, [recv_intf[1]], recv_intf[0], timeout=5)
            self.log("Send %d and receive %d packets in the first second (PolicyTest)" % (pre_send_count, rcv_pkt_cnt))


        pre_test_ptf_tx_counter = self.dataplane.get_counters(*send_intf)
        pre_test_ptf_rx_counter = self.dataplane.get_counters(*recv_intf)
        pre_test_nn_tx_counter = self.dataplane.get_nn_counters(*send_intf)
        pre_test_nn_rx_counter = self.dataplane.get_nn_counters(*recv_intf)

        start_time = datetime.datetime.now()
        end_time = datetime.datetime.now() + datetime.timedelta(seconds=self.DEFAULT_SEND_INTERVAL_SEC)

        send_count = 0
        self.dataplane.flush()
        while datetime.datetime.now() < end_time:
            testutils.send_packet(self, send_intf, packet)
            send_count += 1

            # Depending on the server/platform combination it is possible for the server to
            # overwhelm the DUT, so we add an artificial delay here to rate-limit the server.
            time.sleep(1.0 / float(self.default_server_send_rate_limit_pps))

        self.log("Sent out %d packets in %ds" % (send_count, self.DEFAULT_SEND_INTERVAL_SEC))

        time.sleep(self.DEFAULT_RECEIVE_WAIT_TIME)  # Wait a little bit for all the packets to make it through
        recv_count = testutils.count_matched_packets_all_ports(self, packet, [recv_intf[1]], recv_intf[0], timeout=10)
        self.log("Received %d packets after sleep %ds" % (recv_count, self.DEFAULT_RECEIVE_WAIT_TIME))

        post_test_ptf_tx_counter = self.dataplane.get_counters(*send_intf)
        post_test_ptf_rx_counter = self.dataplane.get_counters(*recv_intf)
        post_test_nn_tx_counter = self.dataplane.get_nn_counters(*send_intf)
        post_test_nn_rx_counter = self.dataplane.get_nn_counters(*recv_intf)

        ptf_tx_count = int(post_test_ptf_tx_counter[1] - pre_test_ptf_tx_counter[1])
        nn_tx_count = int(post_test_nn_tx_counter[1] - pre_test_nn_tx_counter[1])
        ptf_rx_count = int(post_test_ptf_rx_counter[0] - pre_test_ptf_rx_counter[0])
        nn_rx_count = int(post_test_nn_rx_counter[0] - pre_test_nn_rx_counter[0])

        self.log("", True)
        self.log("Counters before the test:", True)
        self.log("If counter (0, n): %s" % str(pre_test_ptf_tx_counter), True)
        self.log("NN counter (0, n): %s" % str(pre_test_nn_tx_counter), True)
        self.log("If counter (1, n): %s" % str(pre_test_ptf_rx_counter), True)
        self.log("NN counter (1, n): %s" % str(pre_test_nn_rx_counter), True)
        self.log("", True)
        self.log("Counters after the test:", True)
        self.log("If counter (0, n): %s" % str(post_test_ptf_tx_counter), True)
        self.log("NN counter (0, n): %s" % str(post_test_nn_tx_counter), True)
        self.log("If counter (1, n): %s" % str(post_test_ptf_rx_counter), True)
        self.log("NN counter (1, n): %s" % str(post_test_nn_rx_counter), True)
        self.log("")
        self.log("Sent through NN to local ptf_nn_agent:    %d" % ptf_tx_count)
        self.log("Sent through If to remote ptf_nn_agent:   %d" % nn_tx_count)
        self.log("Recv from If on remote ptf_nn_agent:      %d" % ptf_rx_count)
        self.log("Recv from NN on from remote ptf_nn_agent: %d" % nn_rx_count)

        time_delta = end_time - start_time
        time_delta_ms = (time_delta.microseconds + time_delta.seconds * 10**6) / 1000
        tx_pps = int(send_count / (float(time_delta_ms) / 1000))
        rx_pps = int(recv_count / (float(time_delta_ms) / 1000))

        return send_count, recv_count, time_delta, time_delta_ms, tx_pps, rx_pps

    def contruct_packet(self, port_number):
        raise NotImplementedError

    def check_constraints(self, send_count, recv_count, time_delta_ms, rx_pps):
        raise NotImplementedError

    def one_port_test(self, port_number):
        packet = self.contruct_packet(port_number)
        send_count, recv_count, time_delta, time_delta_ms, tx_pps, rx_pps = \
            self.copp_test(str(packet), (0, port_number), (1, port_number))

        self.printStats(send_count, recv_count, time_delta, tx_pps, rx_pps)
        self.check_constraints(send_count, recv_count, time_delta_ms, rx_pps)

    # FIXME: better make it decorator
    def run_suite(self):
        self.timeout(self.TASK_TIMEOUT, "The test case hasn't been completed in %d seconds" % self.TASK_TIMEOUT)
        self.one_port_test(self.target_port)
        self.cancel_timeout()

    def printStats(self, pkt_send_count, recv_count, time_delta, tx_pps, rx_pps):
        self.log("")
        self.log('test stats')
        self.log('Packet sent = %10d' % pkt_send_count)
        self.log('Packet rcvd = %10d' % recv_count)
        self.log('Test time = %s' % str(time_delta))
        self.log('TX PPS = %d' % tx_pps)
        self.log('RX PPS = %d' % rx_pps)


class NoPolicyTest(ControlPlaneBaseTest):
    def __init__(self):
        ControlPlaneBaseTest.__init__(self)
        self.needPreSend = False

    def check_constraints(self, send_count, recv_count, time_delta_ms, rx_pps):
        pkt_rx_limit = send_count * 0.90

        self.log("")
        self.log("Checking constraints (NoPolicy):")
        self.log(
            "rx_pps (%d) > NO_POLICER_LIMIT (%d): %s" %
            (int(rx_pps), int(self.NO_POLICER_LIMIT), str(rx_pps > self.NO_POLICER_LIMIT))
        )
        self.log(
            "recv_count (%d) > pkt_rx_limit (%d): %s" %
            (int(recv_count), int(pkt_rx_limit), str(recv_count > pkt_rx_limit))
        )

        if self.has_trap:
            assert (rx_pps > self.NO_POLICER_LIMIT)
            assert (recv_count > pkt_rx_limit)
        else:
            assert (rx_pps < self.NO_POLICER_LIMIT)
            assert (recv_count < pkt_rx_limit)


class PolicyTest(ControlPlaneBaseTest):
    def __init__(self):
        ControlPlaneBaseTest.__init__(self)
        self.needPreSend = True

    def check_constraints(self, send_count, recv_count, time_delta_ms, rx_pps):
        self.log("")
        self.log("Checking constraints (PolicyApplied):")
        self.log(
            "PPS_LIMIT_MIN (%d) <= rx_pps (%d) <= PPS_LIMIT_MAX (%d): %s" %
            (int(self.PPS_LIMIT_MIN),
             int(rx_pps),
             int(self.PPS_LIMIT_MAX),
             str(self.PPS_LIMIT_MIN <= rx_pps <= self.PPS_LIMIT_MAX))
        )

        assert self.PPS_LIMIT_MIN <= rx_pps <= self.PPS_LIMIT_MAX, "rx_pps {}".format(rx_pps)


# SONIC config contains policer CIR=600 for ARP
class ARPTest(PolicyTest):
    def __init__(self):
        PolicyTest.__init__(self)

    def runTest(self):
        self.log("ARPTest")
        self.run_suite()

    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]
        src_ip = self.myip
        dst_ip = self.peerip

        packet = testutils.simple_arp_packet(
            eth_dst='ff:ff:ff:ff:ff:ff',
            eth_src=src_mac,
            arp_op=1,
            ip_snd=src_ip,
            ip_tgt=dst_ip,
            hw_snd=src_mac,
            hw_tgt='ff:ff:ff:ff:ff:ff'
        )

        return packet


# SONIC configuration has no packets to CPU for DHCP-T1 Topo
class DHCPTopoT1Test(PolicyTest):
    def __init__(self):
        PolicyTest.__init__(self)
        # T1 DHCP no packet to packet to CPU so police rate is 0
        self.PPS_LIMIT_MIN = 0
        self.PPS_LIMIT_MAX = 0

    def runTest(self):
        self.log("DHCPTopoT1Test")
        self.run_suite()

    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]

        packet = testutils.simple_udp_packet(
            pktlen=100,
            eth_dst='ff:ff:ff:ff:ff:ff',
            eth_src=src_mac,
            dl_vlan_enable=False,
            vlan_vid=0,
            vlan_pcp=0,
            dl_vlan_cfi=0,
            ip_src='0.0.0.0',
            ip_dst='255.255.255.255',
            ip_tos=0,
            ip_ttl=64,
            udp_sport=68,
            udp_dport=67,
            ip_ihl=None,
            ip_options=False,
            with_udp_chksum=True
        )

        return packet


# SONIC configuration has no policer limiting for DHCP
class DHCPTest(NoPolicyTest):
    def __init__(self):
        NoPolicyTest.__init__(self)

    def runTest(self):
        self.log("DHCPTest")
        self.run_suite()

    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]

        packet = testutils.simple_udp_packet(
            pktlen=100,
            eth_dst='ff:ff:ff:ff:ff:ff',
            eth_src=src_mac,
            dl_vlan_enable=False,
            vlan_vid=0,
            vlan_pcp=0,
            dl_vlan_cfi=0,
            ip_src='0.0.0.0',
            ip_dst='255.255.255.255',
            ip_tos=0,
            ip_ttl=64,
            udp_sport=68,
            udp_dport=67,
            ip_ihl=None,
            ip_options=False,
            with_udp_chksum=True
        )

        return packet


# SONIC configuration has no policer limiting for DHCPv6
class DHCP6Test(NoPolicyTest):
    def __init__(self):
        NoPolicyTest.__init__(self)

    def runTest(self):
        self.log("DHCP6Test")
        self.run_suite()

    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]

        packet = testutils.simple_udpv6_packet(
            pktlen=100,
            eth_dst='33:33:00:01:00:02',
            eth_src=src_mac,
            ipv6_src='::1',
            ipv6_dst='ff02::1:2',
            udp_sport=546,
            udp_dport=547
        )

        return packet
    
 #SONIC configuration has no packets to CPU for DHCPv6-T1 Topo
class DHCP6TopoT1Test(PolicyTest):
    def __init__(self):
        PolicyTest.__init__(self)
        # T1 DHCP6 no packet to packet to CPU so police rate is 0
        self.PPS_LIMIT_MIN = 0
        self.PPS_LIMIT_MAX = 0

    def runTest(self):
        self.log("DHCP6TopoT1Test")
        self.run_suite()

    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]

        packet = testutils.simple_udpv6_packet(
            pktlen=100,
            eth_dst='33:33:00:01:00:02',
            eth_src=src_mac,
            ipv6_src='::1',
            ipv6_dst='ff02::1:2',
            udp_sport=546,
            udp_dport=547
        )

        return packet

# SONIC configuration has no policer limiting for LLDP
class LLDPTest(NoPolicyTest):
    def __init__(self):
        NoPolicyTest.__init__(self)

    def runTest(self):
        self.log("LLDPTest")
        self.run_suite()

    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]

        packet = testutils.simple_eth_packet(
            eth_dst='01:80:c2:00:00:0e',
            eth_src=src_mac,
            eth_type=0x88cc
        )

        return packet


# SONIC configuration has no policer limiting for UDLD
class UDLDTest(NoPolicyTest):
    def __init__(self):
        NoPolicyTest.__init__(self)

    def runTest(self):
        self.log("UDLDTest")
        self.run_suite()

    # UDLD uses Ethernet multicast address 01-00-0c-cc-cc-cc
    # as its destination MAC address. eth_type is to indicate
    # the length of the data in Ethernet 802.3 frame. pktlen
    # = 117 = 103 (0x67) + 6 (dst MAC) + 6 (dst MAC) + 2 (len)
    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]

        packet = testutils.simple_eth_packet(
            pktlen=117,
            eth_dst='01:00:0c:cc:cc:cc',
            eth_src=src_mac,
            eth_type=0x0067
        )

        return packet


# SONIC configuration has no policer limiting for BGP
class BGPTest(NoPolicyTest):
    def __init__(self):
        NoPolicyTest.__init__(self)

    def runTest(self):
        self.log("BGPTest")
        self.run_suite()

    def contruct_packet(self, port_number):
        dst_mac = self.peer_mac[port_number]
        dst_ip = self.peerip

        packet = testutils.simple_tcp_packet(
            eth_dst=dst_mac,
            ip_dst=dst_ip,
            ip_ttl=1,
            tcp_dport=179
        )

        return packet


# SONIC configuration has no policer limiting for LACP
class LACPTest(NoPolicyTest):
    def __init__(self):
        NoPolicyTest.__init__(self)

    def runTest(self):
        self.log("LACPTest")
        self.run_suite()

    def contruct_packet(self, port_number):
        packet = testutils.simple_eth_packet(
            pktlen=14,
            eth_dst='01:80:c2:00:00:02',
            eth_type=0x8809
        ) / (chr(0x01)*50)

        return packet


# SNMP packets are trapped as IP2ME packets.
# IP2ME configuration in SONIC contains policer CIR=600
class SNMPTest(PolicyTest):  # FIXME: trapped as ip2me. mellanox should add support for SNMP trap
    def __init__(self):
        PolicyTest.__init__(self)

    def runTest(self):
        self.log("SNMPTest")
        self.run_suite()

    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]
        dst_mac = self.peer_mac[port_number]
        dst_ip = self.peerip

        packet = testutils.simple_udp_packet(
            eth_dst=dst_mac,
            ip_dst=dst_ip,
            eth_src=src_mac,
            udp_dport=161
        )

        return packet


# SONIC config contains policer CIR=600 for SSH
class SSHTest(PolicyTest):
    def __init__(self):
        PolicyTest.__init__(self)

    def runTest(self):
        self.log("SSHTest")
        self.run_suite()

    def contruct_packet(self, port_number):
        dst_mac = self.peer_mac[port_number]
        src_ip = self.myip
        dst_ip = self.peerip

        packet = testutils.simple_tcp_packet(
            eth_dst=dst_mac,
            ip_dst=dst_ip,
            ip_src=src_ip,
            tcp_flags='F',
            tcp_sport=22,
            tcp_dport=22
        )

        return packet


# IP2ME configuration in SONIC contains policer CIR=600
class IP2METest(PolicyTest):
    def __init__(self):
        PolicyTest.__init__(self)

    def runTest(self):
        self.log("IP2METest")
        self.run_suite()

    def one_port_test(self, port_number):
        for port in self.dataplane.ports.iterkeys():
            if port[0] == 0:
                continue

            packet = self.contruct_packet(port[1])
            send_count, recv_count, time_delta, time_delta_ms, tx_pps, rx_pps = \
                self.copp_test(str(packet), (0, port_number), (1, port_number))

            self.printStats(send_count, recv_count, time_delta, tx_pps, rx_pps)
            self.check_constraints(send_count, recv_count, time_delta_ms, rx_pps)

    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]
        dst_mac = self.peer_mac[port_number]
        dst_ip = self.peerip

        packet = testutils.simple_tcp_packet(
            eth_src=src_mac,
            eth_dst=dst_mac,
            ip_dst=dst_ip
        )

        return packet


class DefaultTest(PolicyTest):
    def __init__(self):
        PolicyTest.__init__(self)

    def runTest(self):
        self.log("DefaultTest")
        self.run_suite()

    def contruct_packet(self, port_number):
        dst_mac = self.peer_mac[port_number]
        src_ip = self.myip
        dst_ip = self.peerip

        packet = testutils.simple_tcp_packet(
            eth_dst=dst_mac,
            ip_dst=dst_ip,
            ip_src=src_ip,
            tcp_sport=10000,
            tcp_dport=10000,
            ip_ttl=1
        )

        return packet
