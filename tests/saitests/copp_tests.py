# ptf --test-dir saitests copp_tests  --qlen=100000 --platform nn -t "verbose=True" --device-socket 0-3@tcp://127.0.0.1:10900 --device-socket 1-3@tcp://10.3.147.47:10900
#
# copp_test.${name_test}
#
# ARPTest
# DHCPTest
# LLDPTest
# BGPTest
# LACPTest
# SNMPTest
# SSHTest
# IP2METest
# DefaultTest

import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.testutils as testutils
from ptf.testutils import *
from ptf.dataplane import match_exp_pkt
import datetime
import subprocess


class ControlPlaneBaseTest(BaseTest):
    MAX_PORTS = 32
    PPS_LIMIT = 600
    PPS_LIMIT_MIN = PPS_LIMIT * 0.9
    PPS_LIMIT_MAX = PPS_LIMIT * 1.1
    NO_POLICER_LIMIT = PPS_LIMIT * 1.4
    PKT_TX_COUNT = 100000
    PKT_RX_LIMIT = PKT_TX_COUNT * 0.90

    def __init__(self):
        BaseTest.__init__(self)
        test_params = testutils.test_params_get()
        self.verbose = 'verbose' in test_params and test_params['verbose']

        self.myip = {}
        self.peerip = {}
        for i in xrange(self.MAX_PORTS):
            self.myip[i] = "10.0.0.%d" % (i*2+1)
            self.peerip[i] = "10.0.0.%d" % (i*2)

        return

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
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()

    def copp_test(self, packet, count, send_intf, recv_intf):
        if self.verbose:
            b_c_0 = self.dataplane.get_counters(*send_intf)
            b_c_1 = self.dataplane.get_counters(*recv_intf)
            b_n_0 = self.dataplane.get_nn_counters(*send_intf)
            b_n_1 = self.dataplane.get_nn_counters(*recv_intf)

        start_time=datetime.datetime.now()

        for i in xrange(count):
            testutils.send_packet(self, send_intf, packet)

        end_time=datetime.datetime.now()

        total_rcv_pkt_cnt = testutils.count_matched_packets(self, packet, recv_intf[1], recv_intf[0])

        if self.verbose:
            e_c_0 = self.dataplane.get_counters(*send_intf)
            e_c_1 = self.dataplane.get_counters(*recv_intf)
            e_n_0 = self.dataplane.get_nn_counters(*send_intf)
            e_n_1 = self.dataplane.get_nn_counters(*recv_intf)
            print
            print
            print "Counters before the test:"
            print "If counter (0, n): ", b_c_0
            print "NN counter (0, n): ", b_n_0
            print "If counter (1, n): ", b_c_1
            print "NN counter (1, n): ", b_n_1
            print
            print "Counters after the test:"
            print "If counter (0, n): ", e_c_0
            print "NN counter (0, n): ", e_n_0
            print "If counter (1, n): ", e_c_1
            print "NN counter (1, n): ", e_n_1
            print
            print "Sent through NN to local ptf_nn_agent:    ", e_c_0[1] - b_c_0[1]
            print "Sent through If to remote ptf_nn_agent:   ", e_n_0[1] - b_n_0[1]
            print "Recv from If on remote ptf_nn_agent:      ", e_c_1[0] - b_c_1[0]
            print "Recv from NN on from remote ptf_nn_agent: ", e_n_1[0] - b_n_1[0]

        time_delta = end_time - start_time
        time_delta_ms = (time_delta.microseconds + time_delta.seconds * 10**6) / 10**3
        tx_pps = int(count/(float(time_delta_ms)/1000))
        rx_pps = int(total_rcv_pkt_cnt/(float(time_delta_ms)/1000))

        return total_rcv_pkt_cnt, time_delta, time_delta_ms, tx_pps, rx_pps

    def contruct_packet(self, port_number):
        raise NotImplemented

    def check_constraints(self, total_rcv_pkt_cnt, time_delta_ms, rx_pps):
        raise NotImplemented

    def one_port_test(self, port_number):
        packet = self.contruct_packet(port_number)
        total_rcv_pkt_cnt, time_delta, time_delta_ms, tx_pps, rx_pps = self.copp_test(str(packet), self.PKT_TX_COUNT, (0, port_number), (1, port_number))
        self.printStats(self.PKT_TX_COUNT, total_rcv_pkt_cnt, time_delta, tx_pps, rx_pps)
        self.check_constraints(total_rcv_pkt_cnt, time_delta_ms, rx_pps)

        return

    def run_suite(self):
        self.one_port_test(3)

    def printStats(self, pkt_send_count, total_rcv_pkt_cnt, time_delta, tx_pps, rx_pps):
        if not self.verbose:
            return
        print
        print 'test stats'
        print 'Packet sent = %10d' % pkt_send_count
        print 'Packet rcvd = %10d' % total_rcv_pkt_cnt
        print 'Test time = %s' % str(time_delta)
        print 'TX PPS = %d' % tx_pps
        print 'RX PPS = %d' % rx_pps

        return

class NoPolicyTest(ControlPlaneBaseTest):
    def __init__(self):
        ControlPlaneBaseTest.__init__(self)

    def check_constraints(self, total_rcv_pkt_cnt, time_delta_ms, rx_pps):
        assert(rx_pps > self.NO_POLICER_LIMIT)
        assert(total_rcv_pkt_cnt > self.PKT_RX_LIMIT)

class PolicyTest(ControlPlaneBaseTest):
    def __init__(self):
        ControlPlaneBaseTest.__init__(self)

    def check_constraints(self, total_rcv_pkt_cnt, time_delta_ms, rx_pps):
        assert(self.PPS_LIMIT_MIN <= rx_pps <= self.PPS_LIMIT_MAX)


# SONIC config contains policer CIR=600 for ARP
class ARPTest(PolicyTest):
    def __init__(self):
        PolicyTest.__init__(self)

    def runTest(self):
        self.run_suite()

    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]
        src_ip = self.myip[port_number]
        dst_ip = self.peerip[port_number]

        packet = simple_arp_packet(
                       eth_dst='ff:ff:ff:ff:ff:ff',
                       eth_src=src_mac,
                       arp_op=1,
                       ip_snd=src_ip,
                       ip_tgt=dst_ip,
                       hw_snd=src_mac,
                       hw_tgt='ff:ff:ff:ff:ff:ff')

        return packet

# SONIC configuration has no policer limiting for DHCP
class DHCPTest(NoPolicyTest):
    def __init__(self):
        NoPolicyTest.__init__(self)

    def runTest(self):
        self.run_suite()

    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]
        packet = simple_udp_packet(pktlen=100,
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


# SONIC configuration has no policer limiting for LLDP
class LLDPTest(NoPolicyTest):
    def __init__(self):
        NoPolicyTest.__init__(self)

    def runTest(self):
        self.run_suite()

    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]
        packet = simple_eth_packet(
                       eth_dst='01:80:c2:00:00:0e',
                       eth_src=src_mac,
                       eth_type=0x88cc
                 )

        return packet

# SONIC configuration has no policer limiting for BGP
class BGPTest(NoPolicyTest):
    def __init__(self):
        NoPolicyTest.__init__(self)

    def runTest(self):
        self.run_suite()

    def contruct_packet(self, port_number):
        dst_mac = self.peer_mac[port_number]
        dst_ip = self.peerip[port_number]
        packet = simple_tcp_packet(
                      eth_dst=dst_mac,
                      ip_dst=dst_ip,
                      tcp_dport=179
                      )
        return packet

# SONIC configuration has no policer limiting for LACP
class LACPTest(NoPolicyTest):
    def __init__(self):
        NoPolicyTest.__init__(self)

    def runTest(self):
        self.run_suite()

    def contruct_packet(self, port_number):
        packet = simple_eth_packet(
               pktlen=14,
               eth_dst='01:80:c2:00:00:02',
               eth_type=0x8809
               ) / (chr(0x01)+(chr(0x01)))

        return packet

# SNMP packets are trapped as IP2ME packets.
# IP2ME configuration in SONIC contains policer CIR=600
class SNMPTest(PolicyTest): #FIXME: trapped as ip2me. mellanox should add support for SNMP trap
    def __init__(self):
        PolicyTest.__init__(self)

    def runTest(self):
        self.run_suite()

    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]
        dst_mac = self.peer_mac[port_number]
        dst_ip = self.peerip[port_number]
        packet = simple_udp_packet(
                          eth_dst=dst_mac,
                          ip_dst=dst_ip,
                          eth_src=src_mac,
                          udp_dport=161
                          )
        return packet

# SONIC configuration has no policer limiting for SSH
class SSHTest(PolicyTest): # FIXME: ssh is policed now
    def __init__(self):
        PolicyTest.__init__(self)

    def runTest(self):
        self.run_suite()

    def contruct_packet(self, port_number):
        dst_mac = self.peer_mac[port_number]
        src_ip = self.myip[port_number]
        dst_ip = self.peerip[port_number]

        packet = simple_tcp_packet(
                eth_dst=dst_mac,
                ip_dst=dst_ip,
                ip_src=src_ip,
                tcp_sport=22,
                tcp_dport=22)

        return packet

# IP2ME configuration in SONIC contains policer CIR=600
class IP2METest(PolicyTest):
    def __init__(self):
        PolicyTest.__init__(self)

    def runTest(self):
        self.run_suite()

    def one_port_test(self, port_number):
        for port in self.dataplane.ports.iterkeys():
            if port[0] == 0:
                continue
            packet = self.contruct_packet(port[1])
            total_rcv_pkt_cnt, time_delta, time_delta_ms, tx_pps, rx_pps = self.copp_test(str(packet), self.PKT_TX_COUNT, (0, port_number), (1, port_number))
            self.printStats(self.PKT_TX_COUNT, total_rcv_pkt_cnt, time_delta, tx_pps, rx_pps)
            self.check_constraints(total_rcv_pkt_cnt, time_delta_ms, rx_pps)

        return

    def contruct_packet(self, port_number):
        src_mac = self.my_mac[port_number]
        dst_mac = self.peer_mac[port_number]
        dst_ip = self.peerip[port_number]

        packet = simple_tcp_packet(
                      eth_src=src_mac,
                      eth_dst=dst_mac,
                      ip_dst=dst_ip
                      )

        return packet


class DefaultTest(PolicyTest):
    def __init__(self):
        PolicyTest.__init__(self)

    def runTest(self):
        self.run_suite()

    def contruct_packet(self, port_number):
        dst_mac = self.peer_mac[port_number]
        src_ip = self.myip[port_number]
        dst_port_number = (port_number + 1) % self.MAX_PORTS
        dst_ip = self.peerip[dst_port_number]

        packet = simple_tcp_packet(
                eth_dst=dst_mac,
                ip_dst=dst_ip,
                ip_src=src_ip,
                tcp_sport=10000,
                tcp_dport=10000,
                ip_ttl=1)

        return packet
