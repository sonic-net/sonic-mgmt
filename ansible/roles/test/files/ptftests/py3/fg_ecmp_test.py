# PTF test contains the test cases for fine grained ecmp, the scenarios of test are as follows:
# create_flows: Sends NUM_FLOWS flows with varying src_Ip and creates a tuple to port map
# initial_hash_check: Checks the the flows from create_flows still end up at the same port
# hash_check_warm_boot: Similar to initial hash check but this is run during warm boot, accounts for possible flooding during warm boot
# bank_check: Check that the flows end up on the same bank as before
# withdraw_nh: Withdraw next-hop in one fg nhg bank, and make sure flow redistributes to ports in the fg nhg bank
# add_nh: Add next-hop in one fg nhg bank, and make sure flow redistributes to from ports in same fg nhg bank to added port
# withdraw_bank: Withdraw all next-hops which constitue a bank, and make sure that flows migrate to using the other bank
# add_first_nh: Add 1st next-hop from previously withdrawn bank, and make sure that some flow migrate back to using the next-hop in old bank
# net_port_hashing: Verify hashing of packets to the T1(network) ports such that the packet came from the server



import ipaddress
import logging
import random
import time
import os
import json

import ptf
import ptf.packet as scapy

from ptf.base_tests import BaseTest
from ptf.mask import Mask
import ptf.testutils as testutils
from ptf.testutils import *

import lpm

IPV4_SRC_IP_RANGE = ['8.0.0.0', '8.255.255.255']
IPV6_SRC_IP_RANGE = ['20D0:A800:0:00::', '20D0:FFFF:0:00::FFFF']

PERSIST_MAP = '/tmp/fg_ecmp_persist_map.json'
MAX_ONE_PERCENT_LOSS = 0.01

def verify_packet_warm(test, pkt, port, device_number=0, timeout=None, n_timeout=None):
    # This packet verification function accounts for possible flood during warm boot
    # We ensure that packets are received on the expected port, and return a special
    # return value of -1 to denote that a flood had occured. The caller can use the 
    # special return value to identify how many packets were flooded. 

    if timeout is None:
        timeout = ptf.ptfutils.default_timeout
    if n_timeout is None:
        n_timeout = ptf.ptfutils.default_negative_timeout
    logging.debug("Checking for pkt on device %d, port %r", device_number, port)
    result = dp_poll(test, device_number=device_number, timeout=timeout, exp_pkt=pkt)
    verify_no_other_packets(test, device_number=device_number, timeout=n_timeout)

    if isinstance(result, test.dataplane.PollSuccess):
        if result.port != port:
            # Flood case, check if packet rcvd on expected port as well
            verify_packet(test, pkt, port)
            return (-1, None)
        else:
            return (port, result.packet)

    assert(isinstance(result, test.dataplane.PollFailure))
    test.fail("Did not receive expected packet on any of ports %r for device %d.\n%s"
                % (ports, device_number, result.format()))
    return (0, None)

def verify_packet_any_port_lossy(test, pkt, ports=[], device_number=0, timeout=None, n_timeout=None):
    # This packet verification function accounts for possible loss of packet due to route table change
    # We ensure that packets are received on the expected ports, and return a special
    # return value of -1 to denote that a packet loss occured. The caller can use the 
    # special return value to identify how many packets were lost and check if loss is within acceptable range

    if timeout is None:
        timeout = ptf.ptfutils.default_timeout
    if n_timeout is None:
        n_timeout = ptf.ptfutils.default_negative_timeout
    logging.debug("Checking for pkt on device %d, port %r", device_number, ports)
    result = dp_poll(test, device_number=device_number, timeout=timeout, exp_pkt=pkt)
    verify_no_other_packets(test, device_number=device_number, timeout=n_timeout)

    if isinstance(result, test.dataplane.PollSuccess):
        if result.port in ports:
            return (ports.index(result.port), result.packet)
        else:
            test.fail(
                "Received expected packet on port %r for device %d, but "
                "it should have arrived on one of these ports: %r.\n%s"
                % (result.port, device_number, ports, result.format())
            )
            return (0, None)

    if isinstance(result, test.dataplane.PollFailure):
        return (-1, None)

    return (0, None)

class FgEcmpTest(BaseTest):

    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = test_params_get()

    #---------------------------------------------------------------------
    def log(self, message):
        logging.info(message)


    def trigger_mac_learning(self, serv_ports):
        for src_port in serv_ports:
            pkt = simple_eth_packet(
                eth_dst=self.router_mac,
                eth_src=self.dataplane.get_mac(0, src_port),
                eth_type=0x1234)

            send_packet(self, src_port, pkt) 


    def setUp(self):
        '''
        @summary: Setup for the test
        '''
        self.dataplane = ptf.dataplane_instance
        self.test_params = testutils.test_params_get()
        self.max_deviation = 0.25
        if 'test_case' in self.test_params:
            self.test_case = self.test_params['test_case']
        else:
            raise Exception("Need a test case param")

        if self.test_case == 'withdraw_nh':
            self.withdraw_nh_port = self.test_params['withdraw_nh_port']
        elif self.test_case == 'add_nh':
            self.add_nh_port = self.test_params['add_nh_port']
        elif self.test_case == 'withdraw_bank':
            self.withdraw_nh_bank = self.test_params['withdraw_nh_bank']
        elif self.test_case == 'add_first_nh':
            self.first_nh = self.test_params['first_nh'] 

        if 'config_file' not in self.test_params:
            raise Exception("required parameter 'config_file' is not present")
        config = self.test_params['config_file']

        if 'exp_flow_count' not in self.test_params:
            raise Exception("required parameter 'exp_flow_count' is not present")
        self.exp_flow_count = self.test_params['exp_flow_count']

        if 'dst_ip' not in self.test_params:
            raise Exception("required parameter 'dst_ip' is not present")
        self.dst_ip = self.test_params['dst_ip']

        if not os.path.isfile(config):
            raise Exception("the config file %s doesn't exist" % config)

        with open(config) as fp:
            graph = json.load(fp)

        self.net_ports = graph['net_ports']
        self.serv_ports = graph['serv_ports']
        self.exp_port_set_one = graph['bank_0_port']
        self.exp_port_set_two = graph['bank_1_port']
        self.router_mac = graph['dut_mac']
        self.num_flows = graph['num_flows']
        self.inner_hashing = graph['inner_hashing']
        self.src_ipv4_interval = lpm.LpmDict.IpInterval(ipaddress.ip_address(str(IPV4_SRC_IP_RANGE[0])), ipaddress.ip_address(str(IPV4_SRC_IP_RANGE[1])))
        self.src_ipv6_interval = lpm.LpmDict.IpInterval(ipaddress.ip_address(str(IPV6_SRC_IP_RANGE[0])), ipaddress.ip_address(str(IPV6_SRC_IP_RANGE[1])))
        self.vxlan_port = graph['vxlan_port']

        self.log(self.net_ports)
        self.log(self.serv_ports)
        self.log(self.exp_port_set_one)
        self.log(self.exp_port_set_two)
        self.log(self.dst_ip)
        self.log(self.router_mac)
        self.log(self.test_case)
        self.log(self.num_flows)
        self.log(self.inner_hashing)
        self.log(self.exp_flow_count)
        self.log(self.vxlan_port)

        if self.test_case != 'hash_check_warm_boot':
            # We send bi-directional traffic during warm boot due to
            # fdb clear, so no need to trigger mac learning
            # during warm boot.
            self.trigger_mac_learning(self.serv_ports)
            time.sleep(3)


    #---------------------------------------------------------------------
    def test_balancing(self, hit_count_map):
        for port, exp_flows in list(self.exp_flow_count.items()):
            assert port in hit_count_map
            num_flows = hit_count_map[port]
            deviation = float(num_flows)/float(exp_flows)
            deviation = abs(1-deviation)
            self.log("port "+ str(port) + " exp_flows " + str(exp_flows) + 
                    " num_flows " + str(num_flows) + " deviation " + str(deviation))
            assert deviation <= self.max_deviation


    def fg_ecmp(self):
        ipv4 = isinstance(ipaddress.ip_address(self.dst_ip),
                ipaddress.IPv4Address)
        # initialize all parameters
        if self.inner_hashing:
            dst_ip = '5.5.5.5'
        else:
            dst_ip = self.dst_ip
        src_port = 20000
        dst_port = 30000

        tuple_to_port_map ={}
        hit_count_map = {}

        if not os.path.exists(PERSIST_MAP) and self.test_case == 'create_flows':
            with open(PERSIST_MAP, 'w'): pass
        elif not self.test_case == 'verify_packets_received':
            with open(PERSIST_MAP) as fp:
                try:
                    tuple_to_port_map = json.load(fp)
                except ValueError:
                    print('Decoding JSON failed for persist map')
                    assert False

        if tuple_to_port_map is None or self.dst_ip not in tuple_to_port_map:
            tuple_to_port_map[self.dst_ip] = {}

        if self.test_case == 'create_flows':
            # Send packets with varying src_ips to create NUM_FLOWS unique flows
            # and generate a flow to port map
            self.log("Creating flow to port map ...")
            for i in range(0, self.num_flows):
                if ipv4 or self.inner_hashing:
                    src_ip = self.src_ipv4_interval.get_random_ip()
                else:
                    src_ip = self.src_ipv6_interval.get_random_ip()

                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.serv_ports, ipv4)
                hit_count_map[port_idx] = hit_count_map.get(port_idx, 0) + 1
                tuple_to_port_map[self.dst_ip][src_ip] = port_idx

        elif self.test_case == 'initial_hash_check':
            self.log("Ensure that flow to port map is maintained when the same flow is re-sent...")
            for src_ip, port in tuple_to_port_map[self.dst_ip].items():
                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.serv_ports, ipv4)
                assert port_idx == port
                tuple_to_port_map[self.dst_ip][src_ip] = port_idx
            return

        elif self.test_case == 'hash_check_warm_boot':
            self.log("Ensure that flow to port map is maintained when the same flow is re-sent...")
            total_flood_pkts = 0
            for src_ip, port in tuple_to_port_map[self.dst_ip].items():
                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt_warm(
                    in_port, src_port, dst_port, src_ip, dst_ip, port, ipv4)
                if port_idx == -1:
                    total_flood_pkts = total_flood_pkts + 1
            # Ensure that flooding duration in warm reboot is less than 10% of total packet count
            self.log("Number of flood packets were: " + str(total_flood_pkts))
            assert (total_flood_pkts < (0.1 * len(tuple_to_port_map[self.dst_ip])))
            return

        elif self.test_case == 'verify_packets_received':
            self.log("Ensure that all packets were received ...")
            total_num_pkts_lost = 0
            for i in range(0, self.num_flows):
                if ipv4 or self.inner_hashing:
                    src_ip = self.src_ipv4_interval.get_random_ip()
                else:
                    src_ip = self.src_ipv6_interval.get_random_ip()

                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt_lossy(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.serv_ports, ipv4)
                if port_idx == -1:
                    total_num_pkts_lost = total_num_pkts_lost + 1

            self.log("Number of lost packets were: " + str(total_num_pkts_lost))
            # Ensure less than 1% packet loss
            assert (total_num_pkts_lost < (MAX_ONE_PERCENT_LOSS * self.num_flows))
            return

        elif self.test_case == 'bank_check':
            self.log("Send the same flows once again and verify that they end up on the same bank...")
            for src_ip, port in tuple_to_port_map[self.dst_ip].items():
                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.serv_ports, ipv4)
                if port in self.exp_port_set_one:
                    assert port_idx in self.exp_port_set_one
                if port in self.exp_port_set_two:
                    assert port_idx in self.exp_port_set_two
                hit_count_map[port_idx] = hit_count_map.get(port_idx, 0) + 1
                tuple_to_port_map[self.dst_ip][src_ip] = port_idx

        elif self.test_case == 'withdraw_nh':
            self.log("Withdraw next-hop " + str(self.withdraw_nh_port) + " and ensure hash redistribution within correct bank")
            if self.withdraw_nh_port in self.exp_port_set_one:
                withdraw_port_grp = self.exp_port_set_one
            else:
                withdraw_port_grp = self.exp_port_set_two
            for src_ip, port in tuple_to_port_map[self.dst_ip].items():
                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.serv_ports, ipv4)
                hit_count_map[port_idx] = hit_count_map.get(port_idx, 0) + 1
                assert port_idx != self.withdraw_nh_port
                if port == self.withdraw_nh_port:
                    assert port_idx != self.withdraw_nh_port
                    assert (port_idx in withdraw_port_grp)
                    tuple_to_port_map[self.dst_ip][src_ip] = port_idx
                else:
                    assert port_idx == port

        elif self.test_case == 'add_nh':
            self.log("Add next-hop " + str(self.add_nh_port) + " and ensure hash redistribution within correct bank")
            if self.add_nh_port in self.exp_port_set_one:
                add_port_grp = self.exp_port_set_one
            else:
                add_port_grp = self.exp_port_set_two
            for src_ip, port in tuple_to_port_map[self.dst_ip].items():
                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.serv_ports, ipv4)
                hit_count_map[port_idx] = hit_count_map.get(port_idx, 0) + 1
                if port_idx == self.add_nh_port:
                    assert (port in add_port_grp)
                    tuple_to_port_map[self.dst_ip][src_ip] = port_idx
                else:
                    assert port_idx == port

        elif self.test_case == 'withdraw_bank':
            self.log("Withdraw bank " + str(self.withdraw_nh_bank) + " and ensure hash redistribution is as expected")
            if self.withdraw_nh_bank[0] in self.exp_port_set_one:
                active_port_grp = self.exp_port_set_two
            else:
                active_port_grp = self.exp_port_set_one
            for src_ip, port in tuple_to_port_map[self.dst_ip].items():
                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.serv_ports, ipv4)
                hit_count_map[port_idx] = hit_count_map.get(port_idx, 0) + 1
                if port in self.withdraw_nh_bank:
                    assert (port_idx in active_port_grp)
                    tuple_to_port_map[self.dst_ip][src_ip] = port_idx
                else:
                    assert port_idx == port

        elif self.test_case == 'add_first_nh':
            self.log("Add 1st next-hop " + str(self.first_nh) + " and ensure hash redistribution is as expected")
            if self.first_nh in self.exp_port_set_one:
                active_port_grp = self.exp_port_set_two
            else:
                active_port_grp = self.exp_port_set_one

            for src_ip, port in tuple_to_port_map[self.dst_ip].items():
                if self.inner_hashing:
                    in_port = random.choice(self.net_ports)
                else:
                    in_port = self.net_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.serv_ports, ipv4)
                hit_count_map[port_idx] = hit_count_map.get(port_idx, 0) + 1
                flow_redistribution_in_correct_grp = False
                if port_idx in active_port_grp:
                    assert port_idx == port
                    flow_redistribution_in_correct_grp = True
                elif port_idx == self.first_nh:
                    flow_redistribution_in_correct_grp = True
                    tuple_to_port_map[self.dst_ip][src_ip] = port_idx
                assert flow_redistribution_in_correct_grp == True

        elif self.test_case == 'net_port_hashing':
            self.log("Send packets destined to network ports and ensure hash distribution is as expected")

            for src_ip, port in tuple_to_port_map[self.dst_ip].items():
                if self.inner_hashing:
                    in_port = random.choice(self.serv_ports)
                else:
                    in_port = self.serv_ports[0]
                (port_idx, _) = self.send_rcv_ip_pkt(
                    in_port, src_port, dst_port, src_ip, dst_ip, self.net_ports, ipv4)
                hit_count_map[port_idx] = hit_count_map.get(port_idx, 0) + 1

            self.test_balancing(hit_count_map)
            return

        else:
            self.log("Unsupported testcase " + self.test_case)
            return

        self.test_balancing(hit_count_map)
        json.dump(tuple_to_port_map, open(PERSIST_MAP,"w"))
        return


    def send_rcv_ip_pkt_lossy(self, in_port, sport, dport, src_ip_addr, dst_ip_addr,
                            exp_port, ipv4=True):

        if ipv4:
            (matched_index, received) = self.send_rcv_ipv4_pkt(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, exp_port, verify_packet_any_port_lossy)
        else:
            (matched_index, received) = self.send_rcv_ipv6_pkt(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, exp_port, verify_packet_any_port_lossy)

        return (matched_index, received)


    def send_rcv_ip_pkt_warm(self, in_port, sport, dport, src_ip_addr, dst_ip_addr,
                            exp_port, ipv4=True):

        # Simulate bidirectional traffic for mac learning, since mac learning(fdb) is flushed
        # as part of warm reboot
        self.trigger_mac_learning([exp_port])

        if ipv4:
            (matched_index, received) = self.send_rcv_ipv4_pkt(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, exp_port, verify_packet_warm)
        else:
            (matched_index, received) = self.send_rcv_ipv6_pkt(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, exp_port, verify_packet_warm)

        return (matched_index, received)


    def send_rcv_ip_pkt(self, in_port, sport, dport, src_ip_addr, dst_ip_addr,
                       dst_port_list, ipv4=True):

        if ipv4:
            (matched_index, received) = self.send_rcv_ipv4_pkt(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, dst_port_list, verify_packet_any_port)
        else:
            (matched_index, received) = self.send_rcv_ipv6_pkt(in_port, sport, dport,
                    src_ip_addr, dst_ip_addr, dst_port_list, verify_packet_any_port)

        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))

        return (matched_port, received)


    def send_rcv_ipv4_pkt(self, in_port, sport, dport,
                         ip_src, ip_dst, dst_port_list, verify_fn):
        src_mac = self.dataplane.get_mac(0, in_port)
        rand_int = random.randint(1, 254)

        pkt = simple_tcp_packet(
                            eth_dst=self.router_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=64)
        if self.inner_hashing:
            pkt = simple_vxlan_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ip_id=0,
                    ip_src='2.2.2.' + str(rand_int),
                    ip_dst=self.dst_ip,
                    ip_ttl=64,
                    udp_sport=rand_int,
                    udp_dport=self.vxlan_port,
                    vxlan_vni=20000+rand_int,
                    with_udp_chksum=False,
                    inner_frame=pkt)

        send_packet(self, in_port, pkt)

        masked_exp_pkt = Mask(pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")

        return verify_fn(self, masked_exp_pkt, dst_port_list)


    def send_rcv_ipv6_pkt(self, in_port, sport, dport,
                         ip_src, ip_dst, dst_port_list, verify_fn):
        src_mac = self.dataplane.get_mac(0, in_port)
        rand_int = random.randint(1, 254)

        if self.inner_hashing:
            pkt = simple_tcp_packet(
                            eth_dst=self.router_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=64)
            pkt = simple_vxlanv6_packet(
                    eth_dst=self.router_mac,
                    eth_src=src_mac,
                    ipv6_src='2:2:2::' + str(rand_int),
                    ipv6_dst=self.dst_ip,
                    udp_sport=rand_int,
                    udp_dport=self.vxlan_port,
                    vxlan_vni=20000+rand_int,
                    with_udp_chksum=False,
                    inner_frame=pkt)
        else:
            pkt = simple_tcpv6_packet(
                        eth_dst=self.router_mac,
                        eth_src=src_mac,
                        ipv6_dst=ip_dst,
                        ipv6_src=ip_src,
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=64)

        send_packet(self, in_port, pkt)

        masked_exp_pkt = Mask(pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

        return verify_fn(self, masked_exp_pkt,dst_port_list)

    def runTest(self):
        # Main function which triggers all the tests
        self.fg_ecmp()
