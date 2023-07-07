"""
SONiC Dataplane Qos tests
"""
import time
import logging
import ptf.packet as scapy
import socket
import ptf.dataplane as dataplane
import sai_base_test
import operator
import sys
import texttable
import math
from ptf.testutils import (ptf_ports,
                           simple_arp_packet,
                           send_packet,
                           simple_tcp_packet,
                           simple_udp_packet,
                           simple_qinq_tcp_packet,
                           simple_ip_packet,
                           simple_ipv4ip_packet)
from ptf.mask import Mask
from switch import (switch_init,
                    sai_thrift_create_scheduler_profile,
                    sai_thrift_clear_all_counters,
                    sai_thrift_read_port_counters,
                    sai_port_list,
                    port_list,
                    sai_thrift_read_port_watermarks,
                    sai_thrift_read_pg_counters,
                    sai_thrift_read_pg_drop_counters,
                    sai_thrift_read_pg_shared_watermark,
                    sai_thrift_read_buffer_pool_watermark,
                    sai_thrift_read_headroom_pool_watermark,
                    sai_thrift_read_queue_occupancy)
from switch_sai_thrift.ttypes import (sai_thrift_attribute_value_t,
                                      sai_thrift_attribute_t)
from switch_sai_thrift.sai_headers import (SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID,
                                           SAI_PORT_ATTR_PKT_TX_ENABLE)

# Counters
# The index number comes from the append order in sai_thrift_read_port_counters
EGRESS_DROP = 0
INGRESS_DROP = 1
PFC_PRIO_0 = 2
PFC_PRIO_1 = 3
PFC_PRIO_2 = 4
PFC_PRIO_3 = 5
PFC_PRIO_4 = 6
PFC_PRIO_5 = 7
PFC_PRIO_6 = 8
PFC_PRIO_7 = 9
TRANSMITTED_OCTETS = 10
TRANSMITTED_PKTS = 11
INGRESS_PORT_BUFFER_DROP = 12
EGRESS_PORT_BUFFER_DROP = 13
RECEIVED_PKTS = 14
RECEIVED_NON_UC_PKTS = 15
TRANSMITTED_NON_UC_PKTS = 16
EGRESS_PORT_QLEN = 17
port_counter_fields = ['0 OutDiscard',
                       '1 InDiscard',
                       '2 Pfc0TxPkt',
                       '3 Pfc1TxPkt',
                       '4 Pfc2TxPkt',
                       '5 Pfc3TxPkt',
                       '6 Pfc4TxPkt',
                       '7 Pfc5TxPkt',
                       '8 Pfc6TxPkt',
                       '9 Pfc7TxPkt',
                       '10 OutOct',
                       '11 OutUcPkt',
                       '12 InDropPkt',
                       '13 OutDropPkt',
                       '14 InUcPkt',
                       '15 InNonUcPkt',
                       '16 OutNonUcPkt',
                       '17 OutQlen']
QUEUE_0 = 0
QUEUE_1 = 1
QUEUE_2 = 2
QUEUE_3 = 3
QUEUE_4 = 4
QUEUE_5 = 5
QUEUE_6 = 6
QUEUE_7 = 7
PG_NUM = 8
QUEUE_NUM = 8

# Constants
STOP_PORT_MAX_RATE = 1
RELEASE_PORT_MAX_RATE = 0
ECN_INDEX_IN_HEADER = 53  # Fits the ptf hex_dump_buffer() parse function
DSCP_INDEX_IN_HEADER = 52  # Fits the ptf hex_dump_buffer() parse function
COUNTER_MARGIN = 2  # Margin for counter check


def check_leackout_compensation_support(asic, hwsku):
    if 'broadcom' in asic.lower():
        return True
    return False


def get_ip_addr():
    val = 1
    while True:
        val = max(val, (val+1)%250)
        yield "192.0.0.{}".format(val)


def get_tcp_port():
    val = 1234
    while True:
        if val == 65535:
            raise RuntimeError("We ran out of tcp ports!")
        val = max(val, (val+10)%65535)
        yield val


TCP_PORT_GEN = get_tcp_port()
IP_ADDR = get_ip_addr()

def construct_tcp_pkt(pkt_len, dst_mac, src_mac, src_ip, dst_ip, dscp, src_vlan, tcp_sport, tcp_dport, **kwargs):
    ecn = kwargs.get('ecn', 1)
    ip_id = kwargs.get('ip_id', None)
    ttl = kwargs.get('ttl', None)
    exp_pkt = kwargs.get('exp_pkt', False)

    tos = (dscp << 2) | ecn
    pkt_args = {
        'pktlen': pkt_len,
        'eth_dst': dst_mac,
        'eth_src': src_mac,
        'ip_src': src_ip,
        'ip_dst': dst_ip,
        'ip_tos': tos,
        'tcp_sport':tcp_sport,
        'tcp_dport':tcp_dport
    }
    if ip_id is not None:
        pkt_args['ip_id'] = ip_id

    if ttl is not None:
        pkt_args['ip_ttl'] = ttl

    if src_vlan is not None:
        pkt_args['dl_vlan_enable'] = True
        pkt_args['vlan_vid'] = int(src_vlan)
        pkt_args['vlan_pcp'] = dscp

    pkt = simple_tcp_packet(**pkt_args)

    if exp_pkt:
        masked_exp_pkt = Mask(pkt, ignore_extra_bytes=True)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")
        if src_vlan is not None:
            masked_exp_pkt.set_do_not_care_scapy(scapy.Dot1Q, "vlan")
        return masked_exp_pkt
    else:
        return pkt


def get_multiple_flows(dp, dst_mac, dst_id, dst_ip, src_vlan, dscp, ecn, ttl, pkt_len, src_details, packets_per_port=1):
    '''
        Returns a dict of format:
        src_id : [list of (pkt, exp_pkt) pairs that go to the given dst_id]
    '''

    def get_rx_port_pkt(dp, src_port_id, pkt, exp_pkt):
        send_packet(dp, src_port_id, pkt, 1)

        result = dp.dataplane.poll(
            device_number=0, exp_pkt=exp_pkt, timeout=3)
        if isinstance(result, dp.dataplane.PollFailure):
            dp.fail("Expected packet was not received. Received on port:{} {}".format(
                result.port, result.format()))

        return result.port

    print ("Need : {} flows total, {} sources, {} packets per port".format(len(src_details)*packets_per_port, len(src_details), packets_per_port))
    all_pkts = {}
    for src_tuple in src_details:
        num_of_pkts = 0
        while (num_of_pkts < packets_per_port):
            ip_Addr = next(IP_ADDR)
            print("Trying {} => {}, src_ip:{} dstip:{}".format(src_tuple[0], dst_id, ip_Addr, dst_ip), file=sys.stderr)
            pkt_args = {
                'ip_ecn':ecn,
                'ip_ttl':ttl,
                'pktlen':pkt_len,
                'eth_dst':dst_mac or dp.dataplane.get_mac(0, dst_id),
                'eth_src':dp.dataplane.get_mac(0, src_tuple[0]),
                'ip_src':ip_Addr,
                'ip_dst':dst_ip,
                'ip_dscp':dscp,
                'tcp_sport':1234,
                'tcp_dport':next(TCP_PORT_GEN)}
            if src_vlan:
                pkt_args.update({dl_vlan_enable:True})
                pkt_args.update({vlan_vid:src_vlan})
            pkt = simple_tcp_packet(**pkt_args)

            masked_exp_pkt = Mask(pkt, ignore_extra_bytes=True)
            masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
            masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")

            if src_vlan is not None:
                masked_exp_pkt.set_do_not_care_scapy(scapy.Dot1Q, "vlan")
            if get_rx_port_pkt(dp, src_tuple[0], pkt, masked_exp_pkt) == dst_id:
                try:
                    all_pkts[src_tuple[0]].append((pkt, masked_exp_pkt))
                    num_of_pkts+=1
                except KeyError:
                    all_pkts[src_tuple[0]] = []
                    all_pkts[src_tuple[0]].append((pkt, masked_exp_pkt.exp_pkt))
                    num_of_pkts+=1
    return all_pkts


def dynamically_compensate_leakout(thrift_client, asic_type, counter_checker, check_port, check_field, base, ptf_test, compensate_port, compensate_pkt, max_retry):
    prev = base
    time.sleep(1.5)
    curr, _ = counter_checker(thrift_client, asic_type, check_port)
    leakout_num = curr[check_field] - prev[check_field]
    retry = 0
    num = 0
    while leakout_num > 0 and retry < max_retry:
        send_packet(ptf_test, compensate_port, compensate_pkt, leakout_num)
        num += leakout_num
        prev = curr
        curr, _ = counter_checker(thrift_client, asic_type, check_port)
        leakout_num = curr[check_field] - prev[check_field]
        retry += 1
    sys.stderr.write('Compensate {} packets to port {}, and retry {} times\n'.format(num, compensate_port, retry))
    return num

def construct_ip_pkt(pkt_len, dst_mac, src_mac, src_ip, dst_ip, dscp, src_vlan, **kwargs):
    ecn = kwargs.get('ecn', 1)
    ip_id = kwargs.get('ip_id', None)
    ttl = kwargs.get('ttl', None)
    exp_pkt = kwargs.get('exp_pkt', False)

    tos = (dscp << 2) | ecn
    pkt_args = {
        'pktlen': pkt_len,
        'eth_dst': dst_mac,
        'eth_src': src_mac,
        'ip_src': src_ip,
        'ip_dst': dst_ip,
        'ip_tos': tos
    }
    if ip_id is not None:
        pkt_args['ip_id'] = ip_id

    if ttl is not None:
        pkt_args['ip_ttl'] = ttl

    if src_vlan is not None:
        pkt_args['dl_vlan_enable'] = True
        pkt_args['vlan_vid'] = int(src_vlan)
        pkt_args['vlan_pcp'] = dscp

    pkt = simple_ip_packet(**pkt_args)

    if exp_pkt:
        masked_exp_pkt = Mask(pkt, ignore_extra_bytes=True)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")

        if src_vlan is not None:
            masked_exp_pkt.set_do_not_care_scapy(scapy.Dot1Q, "vlan")
        return masked_exp_pkt
    else:
        return pkt


def construct_arp_pkt(eth_dst, eth_src, arp_op, src_ip, dst_ip, hw_dst, src_vlan):
    pkt_args = {
        'eth_dst': eth_dst,
        'eth_src': eth_src,
        'arp_op': arp_op,
        'ip_snd': src_ip,
        'ip_tgt': dst_ip,
        'hw_snd': eth_src,
        'hw_tgt': hw_dst
    }

    if src_vlan is not None:
        pkt_args['vlan_vid'] = int(src_vlan)
        pkt_args['vlan_pcp'] = 0

    pkt = simple_arp_packet(**pkt_args)
    return pkt


def get_rx_port(dp, device_number, src_port_id, dst_mac, dst_ip, src_ip, src_vlan=None):
    ip_id = 0xBABE
    src_port_mac = dp.dataplane.get_mac(device_number, src_port_id)
    pkt = construct_ip_pkt(64, dst_mac, src_port_mac,
                           src_ip, dst_ip, 0, src_vlan, ip_id=ip_id)
    send_packet(dp, src_port_id, pkt, 1)

    masked_exp_pkt = construct_ip_pkt(
        48, dst_mac, src_port_mac, src_ip, dst_ip, 0, src_vlan, ip_id=ip_id, exp_pkt=True)

    result = dp.dataplane.poll(
        device_number=0, exp_pkt=masked_exp_pkt, timeout=3)
    if isinstance(result, dp.dataplane.PollFailure):
        dp.fail("Expected packet was not received. Received on port:{} {}".format(
            result.port, result.format()))

    return result.port


def get_counter_names(sonic_version):
    ingress_counters = [INGRESS_DROP]
    egress_counters = [EGRESS_DROP]

    if '201811' not in sonic_version:
        ingress_counters.append(INGRESS_PORT_BUFFER_DROP)
        egress_counters.append(EGRESS_PORT_BUFFER_DROP)

    return ingress_counters, egress_counters


def fill_leakout_plus_one(
        test_case, src_port_id, dst_port_id, pkt, queue, asic_type):
    # Attempts to queue 1 packet while compensating for a varying packet leakout.
    # Returns whether 1 packet was successfully enqueued.
    if asic_type in ['cisco-8000']:
        queue_counters_base = sai_thrift_read_queue_occupancy(
            test_case.dst_client, "dst", dst_port_id)
        max_packets = 500
        for packet_i in range(max_packets):
            send_packet(test_case, src_port_id, pkt, 1)
            queue_counters = sai_thrift_read_queue_occupancy(
                test_case.clients['dst'], "dst", dst_port_id)
            if queue_counters[queue] > queue_counters_base[queue]:
                print("fill_leakout_plus_one: Success, sent %d packets, "
                      "queue occupancy bytes rose from %d to %d" % (
                       packet_i + 1,
                       queue_counters_base[queue], queue_counters[queue]),
                       file=sys.stderr)
                return True
        raise RuntimeError("fill_leakout_plus_one: Fail: src_port_id:{}"
            " dst_port_id:{}, pkt:{}, queue:{}".format(
            src_port_id, dst_port_id, pkt.__repr__()[0:180], queue))
    return False

def get_peer_addresses(data):
    def get_peer_addr(data, addr):
        if isinstance(data, dict) and 'peer_addr' in data:
            addr.add(data['peer_addr'])
        elif isinstance(data, dict):
            for val in data.values():
                get_peer_addr(val, addr)
    addresses = set()
    get_peer_addr(data, addresses)
    return list(addresses)

class ARPpopulate(sai_base_test.ThriftInterfaceDataPlane):
    def setUp(self):
        sai_base_test.ThriftInterfaceDataPlane.setUp(self)
        time.sleep(5)
        switch_init(self.clients)

        # Parse input parameters
        self.router_mac = self.test_params['router_mac']
        self.dst_port_id = int(self.test_params['dst_port_id'])
        self.dst_port_ip = self.test_params['dst_port_ip']
        self.dst_port_mac = self.dataplane.get_mac(0, self.dst_port_id)
        self.dst_vlan = self.test_params['dst_port_vlan']
        self.src_port_id = int(self.test_params['src_port_id'])
        self.src_port_ip = self.test_params['src_port_ip']
        self.src_port_mac = self.dataplane.get_mac(0, self.src_port_id)
        self.src_vlan = self.test_params['src_port_vlan']
        self.dst_port_2_id = int(self.test_params['dst_port_2_id'])
        self.dst_port_2_ip = self.test_params['dst_port_2_ip']
        self.dst_port_2_mac = self.dataplane.get_mac(0, self.dst_port_2_id)
        self.dst_vlan_2 = self.test_params['dst_port_2_vlan']
        self.dst_port_3_id = int(self.test_params['dst_port_3_id'])
        self.dst_port_3_ip = self.test_params['dst_port_3_ip']
        self.dst_port_3_mac = self.dataplane.get_mac(0, self.dst_port_3_id)
        self.dst_vlan_3 = self.test_params['dst_port_3_vlan']
        self.test_port_ids = self.test_params.get("testPortIds", None)
        self.test_port_ips = self.test_params.get("testPortIps", None)

    def tearDown(self):
        sai_base_test.ThriftInterfaceDataPlane.tearDown(self)

    def runTest(self):
         # ARP Populate
        arpreq_pkt = construct_arp_pkt('ff:ff:ff:ff:ff:ff', self.src_port_mac,
                                       1, self.src_port_ip, '192.168.0.1', '00:00:00:00:00:00', self.src_vlan)

        send_packet(self, self.src_port_id, arpreq_pkt)
        arpreq_pkt = construct_arp_pkt('ff:ff:ff:ff:ff:ff', self.dst_port_mac,
                                       1, self.dst_port_ip, '192.168.0.1', '00:00:00:00:00:00', self.dst_vlan)
        send_packet(self, self.dst_port_id, arpreq_pkt)
        arpreq_pkt = construct_arp_pkt('ff:ff:ff:ff:ff:ff', self.dst_port_2_mac, 1,
                                       self.dst_port_2_ip, '192.168.0.1', '00:00:00:00:00:00', self.dst_vlan_2)
        send_packet(self, self.dst_port_2_id, arpreq_pkt)
        arpreq_pkt = construct_arp_pkt('ff:ff:ff:ff:ff:ff', self.dst_port_3_mac, 1,
                                       self.dst_port_3_ip, '192.168.0.1', '00:00:00:00:00:00', self.dst_vlan_3)
        send_packet(self, self.dst_port_3_id, arpreq_pkt)

        # ptf don't know the address of neighbor, use ping to learn relevant arp entries instead of send arp request
        if self.test_port_ips:
            for ip in get_peer_addresses(self.test_port_ips):
                self.exec_cmd_on_dut(self.server, self.test_params['dut_username'], self.test_params['dut_password'],
                    'ping -q -c 3 {}'.format(ip))

        time.sleep(8)


class ARPpopulatePTF(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        # ARP Populate
        index = 0
        for port in ptf_ports():
            arpreq_pkt = simple_arp_packet(
                          eth_dst='ff:ff:ff:ff:ff:ff',
                          eth_src=self.dataplane.get_mac(port[0], port[1]),
                          arp_op=1,
                          ip_snd='10.0.0.%d' % (index * 2 + 1),
                          ip_tgt='10.0.0.%d' % (index * 2),
                          hw_snd=self.dataplane.get_mac(port[0], port[1]),
                          hw_tgt='ff:ff:ff:ff:ff:ff')
            send_packet(self, port[1], arpreq_pkt)
            index += 1


class ReleaseAllPorts(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.clients)

        asic_type = self.test_params['sonic_asic_type']

        for target, a_client in self.clients.items():
            self.sai_thrift_port_tx_enable(a_client, asic_type, list(port_list[target].keys()), target=target)

# DSCP to queue mapping


class DscpMappingPB(sai_base_test.ThriftInterfaceDataPlane):

    def get_port_id(self, client, port_name):
        sai_port_id = client.sai_thrift_get_port_id_by_front_port(
            port_name
        )
        print("Port name {}, SAI port id {}".format(
            port_name, sai_port_id
        ), file=sys.stderr)
        return sai_port_id

    def runTest(self):
        switch_init(self.clients)

        router_mac = self.test_params['router_mac']
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        dual_tor_scenario = self.test_params.get('dual_tor_scenario', None)
        dual_tor = self.test_params.get('dual_tor', None)
        leaf_downstream = self.test_params.get('leaf_downstream', None)
        asic_type = self.test_params['sonic_asic_type']
        exp_ip_id = 101
        exp_ttl = 63
        pkt_dst_mac = router_mac if router_mac != '' else dst_port_mac
        print("dst_port_id: %d, src_port_id: %d" %
              (dst_port_id, src_port_id), file=sys.stderr)

        # in case dst_port_id is part of LAG, find out the actual dst port
        # for given IP parameters
        dst_port_id = get_rx_port(
            self, 0, src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip
        )
        print("actual dst_port_id: %d" % (dst_port_id), file=sys.stderr)
        print("dst_port_mac: %s, src_port_mac: %s, src_port_ip: %s, dst_port_ip: %s" % (
            dst_port_mac, src_port_mac, src_port_ip, dst_port_ip), file=sys.stderr)
        print("port list {}".format(port_list), file=sys.stderr)
        # Get a snapshot of counter values

        # Destination port on a backend ASIC is provide as a port name
        test_dst_port_name = self.test_params.get("test_dst_port_name")
        sai_dst_port_id = None
        if test_dst_port_name is not None:
            sai_dst_port_id = self.get_port_id(self.dst_client, test_dst_port_name)
        else:
            sai_dst_port_id = port_list['dst'][dst_port_id]

        time.sleep(10)
        # port_results is not of our interest here
        port_results, queue_results_base = sai_thrift_read_port_counters(self.dst_client, asic_type, sai_dst_port_id)
        masic = self.clients['src'] != self.clients['dst']

        # DSCP Mapping test
        try:
            ip_ttl = exp_ttl + 1 if router_mac != '' else exp_ttl
            # TTL changes on multi ASIC platforms,
            # add 2 for additional backend and frontend routing
            ip_ttl = ip_ttl if test_dst_port_name is None else ip_ttl + 2
            if asic_type in ["cisco-8000"] and masic:
                ip_ttl = ip_ttl + 1 if masic else ip_ttl

            for dscp in range(0, 64):
                tos = (dscp << 2)
                tos |= 1
                pkt = simple_ip_packet(pktlen=64,
                                        eth_dst=pkt_dst_mac,
                                        eth_src=src_port_mac,
                                        ip_src=src_port_ip,
                                        ip_dst=dst_port_ip,
                                        ip_tos=tos,
                                        ip_id=exp_ip_id,
                                        ip_ttl=ip_ttl)
                send_packet(self, src_port_id, pkt, 1)
                print("dscp: %d, calling send_packet()" %
                      (tos >> 2), file=sys.stderr)

                cnt = 0
                dscp_received = False
                while not dscp_received:
                    result = self.dataplane.poll(
                        device_number=0, port_number=dst_port_id, timeout=3)
                    if isinstance(result, self.dataplane.PollFailure):
                        self.fail("Expected packet was not received on port %d. Total received: %d.\n%s" % (
                            dst_port_id, cnt, result.format()))

                    recv_pkt = scapy.Ether(result.packet)
                    cnt += 1

                    # Verify dscp flag
                    try:
                        if (recv_pkt.payload.tos == tos and
                            recv_pkt.payload.src == src_port_ip and
                            recv_pkt.payload.dst == dst_port_ip and
                            recv_pkt.payload.ttl == exp_ttl and
                            recv_pkt.payload.id == exp_ip_id):
                            dscp_received = True
                            print("dscp: %d, total received: %d" %
                                  (tos >> 2, cnt), file=sys.stderr)
                    except AttributeError:
                        print("dscp: %d, total received: %d, attribute error!" % (
                            tos >> 2, cnt), file=sys.stderr)
                        continue

            # Read Counters
            time.sleep(3)
            port_results, queue_results = sai_thrift_read_port_counters(self.dst_client, asic_type, sai_dst_port_id)

            print(list(map(operator.sub, queue_results,
                  queue_results_base)), file=sys.stderr)
            # dual_tor_scenario: represents whether the device is deployed into a dual ToR scenario
            # dual_tor: represents whether the source and destination ports are configured with additional lossless queues
            # According to SONiC configuration all dscp are classified to queue 1 except:
            #            Normal scenario   Dual ToR scenario                                               Leaf router with separated DSCP_TO_TC_MAP
            #            All ports         Normal ports    Ports with additional lossless queues           downstream (source is T2)                upstream (source is T0)
            # dscp  8 -> queue 0           queue 0         queue 0                                         queue 0                                  queue 0
            # dscp  5 -> queue 2           queue 1         queue 1                                         queue 1                                  queue 1
            # dscp  3 -> queue 3           queue 3         queue 3                                         queue 3                                  queue 3
            # dscp  4 -> queue 4           queue 4         queue 4                                         queue 4                                  queue 4
            # dscp 46 -> queue 5           queue 5         queue 5                                         queue 5                                  queue 5
            # dscp 48 -> queue 6           queue 7         queue 7                                         queue 7                                  queue 7
            # dscp  2 -> queue 1           queue 1         queue 2                                         queue 1                                  queue 2
            # dscp  6 -> queue 1           queue 1         queue 6                                         queue 1                                  queue 6
            # rest 56 dscps -> queue 1
            # So for the 64 pkts sent the mapping should be the following:
            # queue 1    56 + 2 = 58       56 + 3 = 59     56 + 1 = 57                                     59                                        57                         # noqa E501
            # queue 2/6  1                 0               1                                                0                                         0                         # noqa E501
            # queue 3/4  1                 1               1                                                1                                         1                         # noqa E501
            # queue 5    1                 1               1                                                1                                         1                         # noqa E501
            # queue 7    0                 1               1                                                1                                         1                         # noqa E501
            assert (queue_results[QUEUE_0] == 1 + queue_results_base[QUEUE_0])
            assert (queue_results[QUEUE_3] == 1 + queue_results_base[QUEUE_3])
            assert (queue_results[QUEUE_4] == 1 + queue_results_base[QUEUE_4])
            assert (queue_results[QUEUE_5] == 1 + queue_results_base[QUEUE_5])
            if dual_tor or (dual_tor_scenario is False) or (leaf_downstream is False):
                assert (queue_results[QUEUE_2] == 1 +
                        queue_results_base[QUEUE_2])
                assert (queue_results[QUEUE_6] == 1 +
                        queue_results_base[QUEUE_6])
            else:
                assert(queue_results[QUEUE_2] == queue_results_base[QUEUE_2])
                assert(queue_results[QUEUE_6] == queue_results_base[QUEUE_6])
            if dual_tor_scenario:
                if (dual_tor == False) or leaf_downstream:
                    assert(queue_results[QUEUE_1] == 59 + queue_results_base[QUEUE_1])
                else:
                    assert (queue_results[QUEUE_1] ==
                            57 + queue_results_base[QUEUE_1])
                # LAG ports can have LACP packets on queue 7, hence using >= comparison
                assert (queue_results[QUEUE_7] >= 1 +
                        queue_results_base[QUEUE_7])
            else:
                assert (queue_results[QUEUE_1] == 58 +
                        queue_results_base[QUEUE_1])
                # LAG ports can have LACP packets on queue 7, hence using >= comparison
                assert (queue_results[QUEUE_7] >= queue_results_base[QUEUE_7])

        finally:
            print("END OF TEST", file=sys.stderr)

# DOT1P to queue mapping


class Dot1pToQueueMapping(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.clients)

        # Parse input parameters
        router_mac = self.test_params['router_mac']
        print("router_mac: %s" % (router_mac), file=sys.stderr)

        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        print("dst_port_id: %d, src_port_id: %d" %
              (dst_port_id, src_port_id), file=sys.stderr)
        print("dst_port_mac: %s, src_port_mac: %s, src_port_ip: %s, dst_port_ip: %s" % (
            dst_port_mac, src_port_mac, src_port_ip, dst_port_ip), file=sys.stderr)
        vlan_id = int(self.test_params['vlan_id'])
        asic_type = self.test_params['sonic_asic_type']

        exp_ip_id = 102
        exp_ttl = 63

        # According to SONiC configuration dot1ps are classified as follows:
        # dot1p 0 -> queue 1
        # dot1p 1 -> queue 0
        # dot1p 2 -> queue 2
        # dot1p 3 -> queue 3
        # dot1p 4 -> queue 4
        # dot1p 5 -> queue 5
        # dot1p 6 -> queue 6
        # dot1p 7 -> queue 7
        queue_dot1p_map = {
            0: [1],
            1: [0],
            2: [2],
            3: [3],
            4: [4],
            5: [5],
            6: [6],
            7: [7]
        }
        print(queue_dot1p_map, file=sys.stderr)

        try:
            for queue, dot1ps in list(queue_dot1p_map.items()):
                port_results, queue_results_base = sai_thrift_read_port_counters(
                    self.dst_client, asic_type, port_list['dst'][dst_port_id])

                # send pkts with dot1ps that map to the same queue
                for dot1p in dot1ps:
                    # ecn marked
                    tos = 1
                    # Note that vlan tag can be stripped by a switch.
                    # To embrace this situation, we assemble a q-in-q double-tagged packet,
                    # and write the dot1p info into both vlan tags so that
                    # when we receive the packet we do not need to make any assumption
                    # on whether the outer tag is stripped by the switch or not, or
                    # more importantly, we do not need to care about, as in the single-tagged
                    # case, whether the immediate payload is the vlan tag or the ip
                    # header to determine the valid fields for receive validation
                    # purpose. With a q-in-q packet, we are sure that the next layer of
                    # header in either switching behavior case is still a vlan tag
                    pkt = simple_qinq_tcp_packet(pktlen=64,
                                            eth_dst=router_mac if router_mac != '' else dst_port_mac,
                                            eth_src=src_port_mac,
                                            dl_vlan_outer=vlan_id,
                                            dl_vlan_pcp_outer=dot1p,
                                            vlan_vid=vlan_id,
                                            vlan_pcp=dot1p,
                                            ip_src=src_port_ip,
                                            ip_dst=dst_port_ip,
                                            ip_tos=tos,
                                            ip_ttl=exp_ttl + 1 if router_mac != '' else exp_ttl)
                    send_packet(self, src_port_id, pkt, 1)
                    print("dot1p: %d, calling send_packet" %
                          (dot1p), file=sys.stderr)

                # validate queue counters increment by the correct pkt num
                time.sleep(8)
                port_results, queue_results = sai_thrift_read_port_counters(
                    self.dst_client, asic_type, port_list['dst'][dst_port_id])
                print(queue_results_base, file=sys.stderr)
                print(queue_results, file=sys.stderr)
                print(list(map(operator.sub, queue_results,
                      queue_results_base)), file=sys.stderr)
                for i in range(0, QUEUE_NUM):
                    if i == queue:
                        assert(
                            queue_results[queue] == queue_results_base[queue] + len(dot1ps))
                    else:
                        assert(queue_results[i] == queue_results_base[i])

                # confirm that dot1p pkts sent are received
                total_recv_cnt = 0
                dot1p_recv_cnt = 0
                while dot1p_recv_cnt < len(dot1ps):
                    result = self.dataplane.poll(
                        device_number=0, port_number=dst_port_id, timeout=3)
                    if isinstance(result, self.dataplane.PollFailure):
                        self.fail("Expected packet was not received on port %d. Total received: %d.\n%s" % (
                            dst_port_id, total_recv_cnt, result.format()))
                    recv_pkt = scapy.Ether(result.packet)
                    total_recv_cnt += 1

                    # verify dot1p priority
                    dot1p = dot1ps[dot1p_recv_cnt]
                    try:
                        if (recv_pkt.payload.prio == dot1p) and (recv_pkt.payload.vlan == vlan_id):

                            dot1p_recv_cnt += 1
                            print("dot1p: %d, total received: %d" %
                                  (dot1p, total_recv_cnt), file=sys.stderr)

                    except AttributeError:
                        print("dot1p: %d, total received: %d, attribute error!" % (
                            dot1p, total_recv_cnt), file=sys.stderr)
                        continue

        finally:
            print("END OF TEST", file=sys.stderr)

# DSCP to pg mapping


class DscpToPgMapping(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.clients)

        # Parse input parameters
        router_mac = self.test_params['router_mac']
        print("router_mac: %s" % (router_mac), file=sys.stderr)

        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        dscp_to_pg_map = self.test_params.get('dscp_to_pg_map', None)
        pkt_dst_mac = router_mac if router_mac != '' else dst_port_mac
        asic_type = self.test_params.get("sonic_asic_type")

        print("dst_port_id: %d, src_port_id: %d" %
              (dst_port_id, src_port_id), file=sys.stderr)
        print("dst_port_mac: %s, src_port_mac: %s, src_port_ip: %s, dst_port_ip: %s" % (
            dst_port_mac, src_port_mac, src_port_ip, dst_port_ip), file=sys.stderr)

        exp_ip_id = 100
        exp_ttl = 63

        if not dscp_to_pg_map:
            # According to SONiC configuration all dscps are classified to pg 0 except:
            # dscp  3 -> pg 3
            # dscp  4 -> pg 4
            # So for the 64 pkts sent the mapping should be -> 62 pg 0, 1 for pg 3, and 1 for pg 4
            lossy_dscps = list(range(0, 64))
            lossy_dscps.remove(3)
            lossy_dscps.remove(4)
            pg_dscp_map = {
                3: [3],
                4: [4],
                0: lossy_dscps
            }
        else:
            pg_dscp_map = {}
            for dscp, pg in dscp_to_pg_map.items():
                if pg in pg_dscp_map:
                    pg_dscp_map[int(pg)].append(int(dscp))
                else:
                    pg_dscp_map[int(pg)] = [int(dscp)]

        print(pg_dscp_map, file=sys.stderr)
        all_pkts = {}
        ttl = exp_ttl + 1 if router_mac != '' else exp_ttl
        if asic_type == "cisco-8000" and self.src_client != self.dst_client:
            ttl = exp_ttl + 2
        dst_port_id = get_rx_port(
            self, 0, src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip)
        print("actual dst_port_id: %d" % (dst_port_id), file=sys.stderr)

        try:
            for pg, dscps in list(pg_dscp_map.items()):
                pg_cntrs_base = sai_thrift_read_pg_counters(
                    self.src_client, port_list['src'][src_port_id])

                # send pkts with dscps that map to the same pg
                for dscp in dscps:
                    tos = (dscp << 2)
                    tos |= 1
                    pkt = simple_ip_packet(pktlen=64,
                                            eth_dst=pkt_dst_mac,
                                            eth_src=src_port_mac,
                                            ip_src=src_port_ip,
                                            ip_dst=dst_port_ip,
                                            ip_tos=tos,
                                            ip_id=exp_ip_id,
                                            ip_ttl=ttl)
                    send_packet(self, src_port_id, pkt, 1)
                    print("dscp: %d, calling send_packet" %
                          (tos >> 2), file=sys.stderr)

                # validate pg counters increment by the correct pkt num
                time.sleep(8)
                pg_cntrs = sai_thrift_read_pg_counters(
                    self.src_client, port_list['src'][src_port_id])
                print(pg_cntrs_base, file=sys.stderr)
                print(pg_cntrs, file=sys.stderr)
                print(list(map(operator.sub, pg_cntrs, pg_cntrs_base)),
                      file=sys.stderr)
                for i in range(0, PG_NUM):
                    if i == pg:
                        if i == 0 or i == 4:
                            assert (pg_cntrs[pg] >= pg_cntrs_base[pg] + len(dscps))
                        else:
                            assert (pg_cntrs[pg] == pg_cntrs_base[pg] + len(dscps))
                    else:
                        # LACP packets are mapped to queue0 and tcp syn packets for BGP to queue4
                        # So for those queues the count could be more
                        if i == 0 or i == 4:
                            assert(pg_cntrs[i] >= pg_cntrs_base[i])
                        else:
                            assert (pg_cntrs[i] == pg_cntrs_base[i])

                # confirm that dscp pkts are received
                total_recv_cnt = 0
                dscp_recv_cnt = 0
                while dscp_recv_cnt < len(dscps):
                    result = self.dataplane.poll(
                        device_number=0, port_number=dst_port_id, timeout=3)
                    if isinstance(result, self.dataplane.PollFailure):
                        self.fail("Expected packet was not received on port %d. Total received: %d.\n%s" % (
                            dst_port_id, total_recv_cnt, result.format()))
                    recv_pkt = scapy.Ether(result.packet)
                    total_recv_cnt += 1

                    # verify dscp flag
                    tos = dscps[dscp_recv_cnt] << 2
                    tos |= 1
                    try:
                        if (recv_pkt.payload.tos == tos) and (recv_pkt.payload.src == src_port_ip) and \
                            (recv_pkt.payload.dst == dst_port_ip) and \
                           (recv_pkt.payload.ttl == exp_ttl) and (recv_pkt.payload.id == exp_ip_id):

                            dscp_recv_cnt += 1
                            print("dscp: %d, total received: %d" %
                                  (tos >> 2, total_recv_cnt), file=sys.stderr)

                    except AttributeError:
                        print("dscp: %d, total received: %d, attribute error!" % (
                            tos >> 2, total_recv_cnt), file=sys.stderr)
                        continue

        finally:
            print("END OF TEST", file=sys.stderr)


# Tunnel DSCP to PG mapping test
class TunnelDscpToPgMapping(sai_base_test.ThriftInterfaceDataPlane):

    def _build_testing_pkt(self, active_tor_mac, standby_tor_mac, active_tor_ip, standby_tor_ip, inner_dscp,
                           outer_dscp, dst_ip, ecn=1):
        pkt = simple_tcp_packet(
                eth_dst=standby_tor_mac,
                ip_src='1.1.1.1',
                ip_dst=dst_ip,
                ip_dscp=inner_dscp,
                ip_ecn=ecn,
                ip_ttl=64
                )

        ipinip_packet = simple_ipv4ip_packet(
                            eth_dst=active_tor_mac,
                            eth_src=standby_tor_mac,
                            ip_src=standby_tor_ip,
                            ip_dst=active_tor_ip,
                            ip_dscp=outer_dscp,
                            ip_ecn=ecn,
                            inner_frame=pkt[scapy.IP]
                            )
        return ipinip_packet

    def runTest(self):
        """
        This test case is to tx some ip_in_ip packet from Mux tunnel, and check if the traffic is
        mapped to expected PGs.
        """
        switch_init(self.clients)

        # Parse input parameters
        active_tor_mac = self.test_params['active_tor_mac']
        active_tor_ip = self.test_params['active_tor_ip']
        standby_tor_mac = self.test_params['standby_tor_mac']
        standby_tor_ip = self.test_params['standby_tor_ip']
        src_port_id = self.test_params['src_port_id']
        dst_port_id = self.test_params['dst_port_id']
        dst_port_ip = self.test_params['dst_port_ip']

        dscp_to_pg_map = self.test_params['inner_dscp_to_pg_map']
        asic_type = self.test_params['sonic_asic_type']
        cell_size = self.test_params['cell_size']
        PKT_NUM = 100
        # There is background traffic during test, so we need to add error tolerance to ignore such pakcets
        ERROR_TOLERANCE = {
            0: 10,
            1: 0,
            2: 0,
            3: 0,
            4: 0,
            5: 0,
            6: 0,
            7: 0
        }

        try:
            # Disable tx on EGRESS port so that headroom buffer cannot be free
            self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])

            # There are packet leak even port tx is disabled (18 packets leak on TD3 found)
            # Hence we send some packet to fill the leak before testing
            for dscp, _ in dscp_to_pg_map.items():
                pkt = self._build_testing_pkt(
                                            active_tor_mac=active_tor_mac,
                                            standby_tor_mac=standby_tor_mac,
                                            active_tor_ip=active_tor_ip,
                                            standby_tor_ip=standby_tor_ip,
                                            inner_dscp=dscp,
                                            outer_dscp=0,
                                            dst_ip=dst_port_ip
                                        )
                send_packet(self, src_port_id, pkt, 20)
            time.sleep(10)

            for dscp, pg in dscp_to_pg_map.items():
                # Build and send packet to active tor.
                # The inner DSCP is set to testing value, and the outer DSCP is set to 0 as it has no impact on remapping
                pkt = self._build_testing_pkt(
                                            active_tor_mac=active_tor_mac,
                                            standby_tor_mac=standby_tor_mac,
                                            active_tor_ip=active_tor_ip,
                                            standby_tor_ip=standby_tor_ip,
                                            inner_dscp=dscp,
                                            outer_dscp=0,
                                            dst_ip=dst_port_ip
                                        )
                pg_shared_wm_res_base = sai_thrift_read_pg_shared_watermark(self.src_client, asic_type,
                                                                            port_list['src'][src_port_id])
                send_packet(self, src_port_id, pkt, PKT_NUM)
                # validate pg counters increment by the correct pkt num
                time.sleep(8)
                pg_shared_wm_res = sai_thrift_read_pg_shared_watermark(self.src_client, asic_type,
                                                                       port_list['src'][src_port_id])

                assert(pg_shared_wm_res[pg] - pg_shared_wm_res_base[pg] <= (PKT_NUM + ERROR_TOLERANCE[pg]) * cell_size)
                assert(pg_shared_wm_res[pg] - pg_shared_wm_res_base[pg] >= (PKT_NUM - ERROR_TOLERANCE[pg]) * cell_size)
        finally:
            # Enable tx on dest port
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])


# DOT1P to pg mapping
class Dot1pToPgMapping(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.clients)

        # Parse input parameters
        router_mac = self.test_params['router_mac']
        print("router_mac: %s" % (router_mac), file=sys.stderr)

        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        print("dst_port_id: %d, src_port_id: %d" %
              (dst_port_id, src_port_id), file=sys.stderr)
        print("dst_port_mac: %s, src_port_mac: %s, src_port_ip: %s, dst_port_ip: %s" % (
            dst_port_mac, src_port_mac, src_port_ip, dst_port_ip), file=sys.stderr)
        vlan_id = int(self.test_params['vlan_id'])

        # exp_ip_id = 103 # not used
        exp_ttl = 63

        # According to SONiC configuration dot1ps are classified as follows:
        # dot1p 0 -> pg 0
        # dot1p 1 -> pg 0
        # dot1p 2 -> pg 0
        # dot1p 3 -> pg 3
        # dot1p 4 -> pg 4
        # dot1p 5 -> pg 0
        # dot1p 6 -> pg 0
        # dot1p 7 -> pg 7
        pg_dot1p_map = {
            0: [0, 1, 2, 5, 6],
            3: [3],
            4: [4],
            7: [7]
        }
        print(pg_dot1p_map, file=sys.stderr)

        try:
            for pg, dot1ps in list(pg_dot1p_map.items()):
                pg_cntrs_base = sai_thrift_read_pg_counters(
                    self.src_client, port_list['src'][src_port_id])

                # send pkts with dot1ps that map to the same pg
                for dot1p in dot1ps:
                    # ecn marked
                    tos = 1
                    # Note that vlan tag can be stripped by a switch.
                    # To embrace this situation, we assemble a q-in-q double-tagged packet,
                    # and write the dot1p info into both vlan tags so that
                    # when we receive the packet we do not need to make any assumption
                    # on whether the outer tag is stripped by the switch or not, or
                    # more importantly, we do not need to care about, as in the single-tagged
                    # case, whether the immediate payload is the vlan tag or the ip
                    # header to determine the valid fields for receive validation
                    # purpose. With a q-in-q packet, we are sure that the next layer of
                    # header in either switching behavior case is still a vlan tag
                    pkt = simple_qinq_tcp_packet(pktlen=64,
                                            eth_dst=router_mac if router_mac != '' else dst_port_mac,
                                            eth_src=src_port_mac,
                                            dl_vlan_outer=vlan_id,
                                            dl_vlan_pcp_outer=dot1p,
                                            vlan_vid=vlan_id,
                                            vlan_pcp=dot1p,
                                            ip_src=src_port_ip,
                                            ip_dst=dst_port_ip,
                                            ip_tos=tos,
                                            ip_ttl=exp_ttl + 1 if router_mac != '' else exp_ttl)
                    send_packet(self, src_port_id, pkt, 1)
                    print("dot1p: %d, calling send_packet" %
                          (dot1p), file=sys.stderr)

                # validate pg counters increment by the correct pkt num
                time.sleep(8)
                pg_cntrs = sai_thrift_read_pg_counters(
                    self.src_client, port_list['src'][src_port_id])
                print(pg_cntrs_base, file=sys.stderr)
                print(pg_cntrs, file=sys.stderr)
                print(list(map(operator.sub, pg_cntrs, pg_cntrs_base)),
                      file=sys.stderr)
                for i in range(0, PG_NUM):
                    if i == pg:
                        assert(pg_cntrs[pg] == pg_cntrs_base[pg] + len(dot1ps))
                    else:
                        assert(pg_cntrs[i] == pg_cntrs_base[i])

                # confirm that dot1p pkts sent are received
                total_recv_cnt = 0
                dot1p_recv_cnt = 0
                while dot1p_recv_cnt < len(dot1ps):
                    result = self.dataplane.poll(
                        device_number=0, port_number=dst_port_id, timeout=3)
                    if isinstance(result, self.dataplane.PollFailure):
                        self.fail("Expected packet was not received on port %d. Total received: %d.\n%s" % (
                            dst_port_id, total_recv_cnt, result.format()))
                    recv_pkt = scapy.Ether(result.packet)
                    total_recv_cnt += 1

                    # verify dot1p priority
                    dot1p = dot1ps[dot1p_recv_cnt]
                    try:
                        if (recv_pkt.payload.prio == dot1p) and (recv_pkt.payload.vlan == vlan_id):

                            dot1p_recv_cnt += 1
                            print("dot1p: %d, total received: %d" %
                                  (dot1p, total_recv_cnt), file=sys.stderr)

                    except AttributeError:
                        print("dot1p: %d, total received: %d, attribute error!" % (
                            dot1p, total_recv_cnt), file=sys.stderr)
                        continue

        finally:
            print("END OF TEST", file=sys.stderr)

# This test is to measure the Xoff threshold, and buffer limit


class PFCtest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        time.sleep(5)
        switch_init(self.clients)

        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        sonic_version = self.test_params['sonic_version']
        # The pfc counter index starts from index 2 in sai_thrift_read_port_counters
        pg = int(self.test_params['pg']) + 2
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        max_buffer_size = int(self.test_params['buffer_max_size'])
        max_queue_size = int(self.test_params['queue_max_size'])
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_vlan = self.test_params['src_port_vlan']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        asic_type = self.test_params['sonic_asic_type']
        pkts_num_leak_out = int(self.test_params['pkts_num_leak_out'])
        pkts_num_trig_pfc = int(self.test_params['pkts_num_trig_pfc'])
        pkts_num_trig_ingr_drp = int(
            self.test_params['pkts_num_trig_ingr_drp'])
        hwsku = self.test_params['hwsku']
        platform_asic = self.test_params['platform_asic']

        pkt_dst_mac = router_mac if router_mac != '' else dst_port_mac
        # get counter names to query
        ingress_counters, egress_counters = get_counter_names(sonic_version)

        # get a snapshot of PG drop packets counter
        if '201811' not in sonic_version and ('mellanox' in asic_type or 'cisco-8000' in asic_type):
            # According to SONiC configuration lossless dscps are classified as follows:
            # dscp  3 -> pg 3
            # dscp  4 -> pg 4
            pg_dropped_cntrs_old = sai_thrift_read_pg_drop_counters(
                self.src_client, port_list['src'][src_port_id])

        # Prepare IP packet data
        ttl = 64
        if 'packet_size' in list(self.test_params.keys()):
            packet_length = int(self.test_params['packet_size'])
        else:
            packet_length = 64
        if 'cell_size' in self.test_params:
            cell_size = self.test_params['cell_size']
            cell_occupancy = (packet_length + cell_size - 1) // cell_size
        else:
            cell_occupancy = 1

        is_dualtor = self.test_params.get('is_dualtor', False)
        def_vlan_mac = self.test_params.get('def_vlan_mac', None)
        if is_dualtor and def_vlan_mac != None:
            pkt_dst_mac = def_vlan_mac

        pkt = construct_ip_pkt(packet_length,
                               pkt_dst_mac,
                               src_port_mac,
                               src_port_ip,
                               dst_port_ip,
                               dscp,
                               src_port_vlan,
                               ecn=ecn,
                               ttl=ttl)

        print("test dst_port_id: {}, src_port_id: {}, src_vlan: {}".format(
            dst_port_id, src_port_id, src_port_vlan
        ), file=sys.stderr)
        # in case dst_port_id is part of LAG, find out the actual dst port
        # for given IP parameters
        dst_port_id = get_rx_port(
            self, 0, src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip, src_port_vlan
        )
        print("actual dst_port_id: {}".format(dst_port_id), file=sys.stderr)

        # get a snapshot of counter values at recv and transmit ports
        # queue_counters value is not of our interest here
        recv_counters_base, _ = sai_thrift_read_port_counters(
            self.src_client, asic_type, port_list['src'][src_port_id])
        xmit_counters_base, _ = sai_thrift_read_port_counters(
            self.dst_client, asic_type, port_list['dst'][dst_port_id])
        # Add slight tolerance in threshold characterization to consider
        # the case that cpu puts packets in the egress queue after we pause the egress
        # or the leak out is simply less than expected as we have occasionally observed
        if 'pkts_num_margin' in list(self.test_params.keys()):
            margin = int(self.test_params['pkts_num_margin'])
        else:
            margin = 2

        # For TH3, some packets stay in egress memory and doesn't show up in shared buffer or leakout
        if 'pkts_num_egr_mem' in list(self.test_params.keys()):
            pkts_num_egr_mem = int(self.test_params['pkts_num_egr_mem'])

        self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])

        try:
            # Since there is variability in packet leakout in hwsku Arista-7050CX3-32S-D48C8 and
            # Arista-7050CX3-32S-C32. Starting with zero pkts_num_leak_out and trying to find
            # actual leakout by sending packets and reading actual leakout from HW.
            # And apply dynamically compensation to all device using Broadcom ASIC.
            if check_leackout_compensation_support(asic_type, hwsku):
                pkts_num_leak_out = 0

            # send packets short of triggering pfc
            if hwsku == 'DellEMC-Z9332f-M-O16C64' or hwsku == 'DellEMC-Z9332f-O32':
                # send packets short of triggering pfc
                send_packet(self, src_port_id, pkt, (pkts_num_egr_mem +
                            pkts_num_leak_out + pkts_num_trig_pfc) // cell_occupancy - 1 - margin)
            elif 'cisco-8000' in asic_type:
                fill_leakout_plus_one(self, src_port_id, dst_port_id,
                       pkt, int(self.test_params['pg']), asic_type)
                # Send 1 less packet due to leakout filling
                send_packet(self, src_port_id, pkt, (pkts_num_leak_out +
                            pkts_num_trig_pfc) // cell_occupancy - 2 - margin)
            else:
                # send packets short of triggering pfc
                send_packet(self, src_port_id, pkt, (pkts_num_leak_out +
                            pkts_num_trig_pfc) // cell_occupancy - 1 - margin)

            # allow enough time for the dut to sync up the counter values in counters_db
            time.sleep(8)

            if check_leackout_compensation_support(asic_type, hwsku):
                dynamically_compensate_leakout(self.dst_client, asic_type, sai_thrift_read_port_counters,
                                               port_list['dst'][dst_port_id], TRANSMITTED_PKTS,
                                               xmit_counters_base, self, src_port_id, pkt, 10)

            # get a snapshot of counter values at recv and transmit ports
            # queue counters value is not of our interest here
            recv_counters, _ = sai_thrift_read_port_counters(
                self.src_client, asic_type, port_list['src'][src_port_id])
            xmit_counters, _ = sai_thrift_read_port_counters(
                self.dst_client, asic_type, port_list['dst'][dst_port_id])
            test_stage = 'after send packets short of triggering PFC'
            sys.stderr.write('{}:\n\trecv_counters {}\n\trecv_counters_base {}\n\t' + \
                             'xmit_counters {}\n\txmit_counters_base {}\n'.format(
                test_stage, recv_counters, recv_counters_base, xmit_counters, xmit_counters_base))
            # recv port no pfc
            assert(recv_counters[pg] == recv_counters_base[pg]), \
                'unexpectedly PFC counter increase, {}'.format(test_stage)
            # recv port no ingress drop
            for cntr in ingress_counters:
                assert(recv_counters[cntr] == recv_counters_base[cntr]), \
                    'unexpectedly RX drop counter increase, {}'.format(test_stage)
            # xmit port no egress drop
            for cntr in egress_counters:
                assert(xmit_counters[cntr] == xmit_counters_base[cntr]), \
                    'unexpectedly TX drop counter increase, {}'.format(test_stage)

            # send 1 packet to trigger pfc
            send_packet(self, src_port_id, pkt, 1 + 2 * margin)
            # allow enough time for the dut to sync up the counter values in counters_db
            time.sleep(8)
            # get a snapshot of counter values at recv and transmit ports
            # queue counters value is not of our interest here
            recv_counters_base = recv_counters
            recv_counters, _ = sai_thrift_read_port_counters(
                self.src_client, asic_type, port_list['src'][src_port_id])
            xmit_counters, _ = sai_thrift_read_port_counters(
                self.dst_client, asic_type, port_list['dst'][dst_port_id])
            test_stage = 'after send a few packets to trigger PFC'
            sys.stderr.write('{}:\n\trecv_counters {}\n\trecv_counters_base {}\n\txmit_counters {}\n\txmit_counters_base {}\n'.format(test_stage, recv_counters, recv_counters_base, xmit_counters, xmit_counters_base))
            # recv port pfc
            assert(recv_counters[pg] > recv_counters_base[pg]), \
                'unexpectedly PFC counter not increase, {}'.format(test_stage)
            # recv port no ingress drop
            for cntr in ingress_counters:
                assert(recv_counters[cntr] == recv_counters_base[cntr]), \
                    'unexpectedly RX drop counter increase, {}'.format(test_stage)
            # xmit port no egress drop
            for cntr in egress_counters:
                assert(xmit_counters[cntr] == xmit_counters_base[cntr]), \
                    'unexpectedly TX drop counter increase, {}'.format(test_stage)

            # send packets short of ingress drop
            send_packet(self, src_port_id, pkt, (pkts_num_trig_ingr_drp -
                        pkts_num_trig_pfc) // cell_occupancy - 1 - 2 * margin)
            # allow enough time for the dut to sync up the counter values in counters_db
            time.sleep(8)
            # get a snapshot of counter values at recv and transmit ports
            # queue counters value is not of our interest here
            recv_counters_base = recv_counters
            recv_counters, _ = sai_thrift_read_port_counters(
                self.src_client, asic_type, port_list['src'][src_port_id])
            xmit_counters, _ = sai_thrift_read_port_counters(
                self.dst_client, asic_type, port_list['dst'][dst_port_id])
            test_stage = 'after send packets short of ingress drop'
            sys.stderr.write('{}:\n\trecv_counters {}\n\trecv_counters_base {}\n\t' + \
                             'xmit_counters {}\n\txmit_counters_base {}\n'.format(
                                 test_stage, recv_counters, recv_counters_base, xmit_counters, xmit_counters_base))
            # recv port pfc
            assert(recv_counters[pg] > recv_counters_base[pg]), \
                'unexpectedly PFC counter not increase, {}'.format(test_stage)
            # recv port no ingress drop
            for cntr in ingress_counters:
                assert(recv_counters[cntr] == recv_counters_base[cntr]), \
                    'unexpectedly RX drop counter increase, {}'.format(test_stage)
            # xmit port no egress drop
            for cntr in egress_counters:
                assert(xmit_counters[cntr] == xmit_counters_base[cntr]), \
                    'unexpectedly TX drop counter increase, {}'.format(test_stage)

            # send 1 packet to trigger ingress drop
            send_packet(self, src_port_id, pkt, 1 + 2 * margin)
            # allow enough time for the dut to sync up the counter values in counters_db
            time.sleep(8)
            # get a snapshot of counter values at recv and transmit ports
            # queue counters value is not of our interest here
            recv_counters_base = recv_counters
            recv_counters, _ = sai_thrift_read_port_counters(
                self.src_client, asic_type, port_list['src'][src_port_id])
            xmit_counters, _ = sai_thrift_read_port_counters(
                self.dst_client, asic_type, port_list['dst'][dst_port_id])
            test_stage = 'after send a few packets to trigger drop'
            sys.stderr.write('{}:\n\trecv_counters {}\n\trecv_counters_base {}\n\t' + \
                             'xmit_counters {}\n\txmit_counters_base {}\n'.format(
                                 test_stage, recv_counters, recv_counters_base, xmit_counters, xmit_counters_base))
            # recv port pfc
            assert(recv_counters[pg] > recv_counters_base[pg]), \
                'unexpectedly PFC counter not increase, {}'.format(test_stage)
            # recv port ingress drop
            if platform_asic and platform_asic == "broadcom-dnx":
                logging.info ("On J2C+ don't support port level drop counters - so ignoring this step for now")
            else:
                # recv port ingress drop
                for cntr in ingress_counters:
                    assert(recv_counters[cntr] > recv_counters_base[cntr]), 'unexpectedly RX drop counter not increase, {}'.format(test_stage)
                # xmit port no egress drop
                for cntr in egress_counters:
                    assert(xmit_counters[cntr] == xmit_counters_base[cntr]), 'unexpectedly TX drop counter increase, {}'.format(test_stage)

            if '201811' not in sonic_version and 'mellanox' in asic_type:
                pg_dropped_cntrs = sai_thrift_read_pg_drop_counters(
                    self.src_client, port_list['src'][src_port_id])
                logging.info("Dropped packet counters on port #{} :{} {} packets, current dscp: {}".format(
                    src_port_id, pg_dropped_cntrs[dscp], pg_dropped_cntrs_old[dscp], dscp))
                # Check that counters per lossless PG increased
                assert pg_dropped_cntrs[dscp] > pg_dropped_cntrs_old[dscp]
            if '201811' not in sonic_version and 'cisco-8000' in asic_type:
                pg_dropped_cntrs = sai_thrift_read_pg_drop_counters(
                    self.src_client, port_list['src'][src_port_id])
                logging.info("Dropped packet counters on port #{} :{} {} packets, current dscp: {}".format(
                    src_port_id, pg_dropped_cntrs[dscp], pg_dropped_cntrs_old[dscp], dscp))
                # check that counters per lossless PG increased
                # Also make sure only relevant dropped pg counter increased and no other pg's
                for i in range(len(pg_dropped_cntrs)):
                    if i == dscp:
                        assert pg_dropped_cntrs[i] > pg_dropped_cntrs_old[i]
                    else:
                        assert pg_dropped_cntrs[i] == pg_dropped_cntrs_old[i]

        finally:
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])


class LosslessVoq(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        time.sleep(5)
        switch_init(self.clients)

        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        sonic_version = self.test_params['sonic_version']
        cli_pg = int(self.test_params['pg'])
        # The pfc counter index starts from index 2 in sai_thrift_read_port_counters
        pg = cli_pg + 2
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_1_id = int(self.test_params['src_port_1_id'])
        src_port_1_ip = self.test_params['src_port_1_ip']
        src_port_1_mac = self.dataplane.get_mac(0, src_port_1_id)
        src_port_2_id = int(self.test_params['src_port_2_id'])
        src_port_2_ip = self.test_params['src_port_2_ip']
        src_port_2_mac = self.dataplane.get_mac(0, src_port_2_id)
        num_of_flows = self.test_params['num_of_flows']
        asic_type = self.test_params['sonic_asic_type']
        pkts_num_leak_out = int(self.test_params['pkts_num_leak_out'])
        pkts_num_trig_pfc = int(self.test_params['pkts_num_trig_pfc'])

        pkt_dst_mac = router_mac if router_mac != '' else dst_port_mac
        # get counter names to query
        ingress_counters, egress_counters = get_counter_names(sonic_version)

        # Prepare IP packet data
        ttl = 64
        if 'packet_size' in self.test_params.keys():
            packet_length = int(self.test_params['packet_size'])
        else:
            packet_length = 64
        src_details = []
        src_details.append((int(self.test_params['src_port_1_id']),
            self.test_params['src_port_1_ip'],
            self.dataplane.get_mac(0, int(self.test_params['src_port_1_id']))))
        src_details.append((int(self.test_params['src_port_2_id']),
            self.test_params['src_port_2_ip'],
            self.dataplane.get_mac(0, int(self.test_params['src_port_2_id']))))

        all_pkts = get_multiple_flows(
                self,
                pkt_dst_mac,
                dst_port_id,
                dst_port_ip,
                None,
                dscp,
                ecn,
                ttl,
                packet_length,
                src_details,
                packets_per_port=2)

        # get a snapshot of counter values at recv and transmit ports
        def collect_counters():
            counter_details = []
            for src_tuple in src_details:
                counter_details.append(sai_thrift_read_port_counters(
                    self.src_client, asic_type, port_list['src'][src_tuple[0]]))
            counter_details.append(sai_thrift_read_port_counters(
                self.dst_client, asic_type, port_list['dst'][dst_port_id]))
            return counter_details
        counter_details_before = collect_counters()

        # Add slight tolerance in threshold characterization to consider
        # the case that cpu puts packets in the egress queue after we pause the egress
        # or the leak out is simply less than expected as we have occasionally observed
        if 'pkts_num_margin' in self.test_params.keys():
            margin = int(self.test_params['pkts_num_margin'])
        else:
            margin = 2

        self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])
        try:
            fill_leakout_plus_one(self, src_port_1_id,
                    dst_port_id, all_pkts[src_port_1_id][0][0], cli_pg, asic_type)
            fill_leakout_plus_one(self, src_port_2_id,
                    dst_port_id, all_pkts[src_port_2_id][0][0], cli_pg, asic_type)

            # send packets short of triggering pfc
            # Send 1 less packet due to leakout filling
            if num_of_flows == 'multiple':
                npkts = pkts_num_leak_out + (pkts_num_trig_pfc // 2) - 2 - margin
                print("Sending 4 flows, {} packets".format(npkts))
                for src_id in all_pkts.keys():
                    for pkt_tuple in all_pkts[src_id]:
                        send_packet(self, src_id, pkt_tuple[0], npkts)
            else:
                npkts = pkts_num_leak_out + pkts_num_trig_pfc - 2 - margin
                print("Sending 2 flows, {} packets".format(npkts))
                for i in range(2):
                    send_packet(self, src_details[i][0],
                                all_pkts[src_details[i][0]][0][0], npkts)
            # allow enough time for counters to update
            time.sleep(2)

            # get a snapshot of counter values at recv and transmit ports
            # queue counters value is not of our interest here
            counter_details_after = collect_counters()

            for i in range(2):
                # recv port no pfc
                pfc_txd = counter_details_after[i][0][pg] - counter_details_before[i][0][pg]
                assert pfc_txd == 0, "Unexpected PFC TX {} on port {} for pg:{}".format(pfc_txd, src_details[i][0], pg-2)
                # recv port no ingress drop
                for cntr in ingress_counters:
                    diff = counter_details_after[i][0][cntr] - counter_details_before[i][0][cntr]
                    assert diff == 0, "Unexpected ingress drop {} on port {}".format(diff, src_details[i])

            # xmit port no egress drop
            for cntr in egress_counters:
                diff = counter_details_after[2][0][cntr] - counter_details_before[2][0][cntr]
                assert diff == 0, "Unexpected egress drops {} on port {}".format(diff, dst_port_id)

            # send 1 packet to trigger pfc
            npkts = 1 + 2 * margin
            if num_of_flows == "multiple":
                print("Sending {} packets to trigger PFC from 4 flows".format(npkts))
                for i in range(2):
                    for src_id in all_pkts.keys():
                        for pkt_tuple in all_pkts[src_id]:
                            send_packet(self, src_id, pkt_tuple[0], npkts)
            else:
                print("Sending {} packets to trigger PFC from 2 flows".format(npkts))
                for i in range(2):
                    send_packet(self, src_details[i][0], all_pkts[src_details[i][0]][0][0], npkts)

            # allow enough time for counters to update
            time.sleep(8)
            # get a snapshot of counter values at recv and transmit ports
            # queue counters value is not of our interest here
            counter_details_3 = collect_counters()
            # recv port pfc

            for i in range(2):
                # recv port Starts PFC:
                pfc_txd = counter_details_3[i][0][pg] - counter_details_before[i][0][pg]
                assert pfc_txd > 0, "PFC TX didn't start on port {} for pg:{}".format(src_details[i][0], pg-2)
                # recv port no ingress drop
                for cntr in ingress_counters:
                    diff = counter_details_3[i][0][cntr] - counter_details_before[i][0][cntr]
                    assert diff == 0, "Unexpected ingress drop {} on port {}".format(diff, src_details[i])

            # xmit port no egress drop
            for cntr in egress_counters:
                diff = counter_details_3[2][0][cntr] - counter_details_before[2][0][cntr]
                assert diff == 0, "Unexpected egress drops {} on port {}".format(diff, dst_port_id)

        finally:
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])

# Base class used for individual PTF runs used in the following: testPfcStormWithSharedHeadroomOccupancy


class PfcStormTestWithSharedHeadroom(sai_base_test.ThriftInterfaceDataPlane):

    def parse_test_params(self):
        # Parse pkt construction related input parameters
        self.dscp = int(self.test_params['dscp'])
        self.ecn = int(self.test_params['ecn'])
        self.sonic_version = self.test_params['sonic_version']
        self.router_mac = self.test_params['router_mac']
        self.asic_type = self.test_params['sonic_asic_type']

        self.pg_id = int(self.test_params['pg'])
        # The pfc counter index starts from index 2 in sai_thrift_read_port_counters
        self.pg = self.pg_id + 2

        self.src_port_id = int(self.test_params['src_port_id'])
        self.src_port_ip = self.test_params['src_port_ip']
        self.src_port_vlan = self.test_params['src_port_vlan']
        self.src_port_mac = self.dataplane.get_mac(0, self.src_port_id)

        self.dst_port_id = int(self.test_params['dst_port_id'])
        self.dst_port_ip = self.test_params['dst_port_ip']
        self.dst_port_mac = self.dataplane.get_mac(0, self.dst_port_id)

        self.ttl = 64
        if 'packet_size' in self.test_params:
            self.default_packet_length = self.test_params['packet_size']
        else:
            self.default_packet_length = 64

        if 'cell_size' in self.test_params:
            cell_size = self.test_params['cell_size']
            self.cell_occupancy = (
                self.default_packet_length + cell_size - 1) // cell_size
        else:
            self.cell_occupancy = 1
        #  Margin used to while crossing the shared headrooom boundary
        self.margin = 2

        # get counter names to query
        self.ingress_counters, self.egress_counters = get_counter_names(
            self.sonic_version)


class PtfFillBuffer(PfcStormTestWithSharedHeadroom):

    def runTest(self):

        time.sleep(5)
        switch_init(self.clients)

        self.parse_test_params()
        pkts_num_trig_pfc = int(self.test_params['pkts_num_trig_pfc'])
        pkts_num_private_headrooom = int(
            self.test_params['pkts_num_private_headrooom'])

        # Draft packets
        pkt_dst_mac = self.router_mac if self.router_mac != '' else self.dst_port_mac
        pkt = construct_ip_pkt(self.default_packet_length,
                               pkt_dst_mac,
                               self.src_port_mac,
                               self.src_port_ip,
                               self.dst_port_ip,
                               self.dscp,
                               self.src_port_vlan,
                               ecn=self.ecn,
                               ttl=self.ttl)

        # get a snapshot of counter values at recv and transmit ports
        # queue_counters value is not of our interest here
        recv_counters_base, queue_counters = sai_thrift_read_port_counters(
            self.src_client, self.asic_type, port_list['src'][self.src_port_id]
        )

        logging.info("Disabling xmit ports: {}".format(self.dst_port_id))
        self.sai_thrift_port_tx_disable(self.dst_client, self.asic_type, [self.dst_port_id])

        xmit_counters_base, queue_counters = sai_thrift_read_port_counters(
            self.dst_client, self.asic_type, port_list['dst'][self.dst_port_id]
        )
        num_pkts = (pkts_num_trig_pfc + pkts_num_private_headrooom) // self.cell_occupancy
        logging.info("Send {} pkts to egress out of {}".format(num_pkts, self.dst_port_id))
        # send packets to dst port 1, to cross into shared headrooom
        send_packet(self, self.src_port_id, pkt, num_pkts)

        # allow enough time for the dut to sync up the counter values in counters_db
        time.sleep(8)
        # get a snapshot of counter values at recv and transmit ports
        # queue counters value is not of our interest here
        recv_counters, queue_counters = sai_thrift_read_port_counters(
            self.src_client, self.asic_type, port_list['src'][self.src_port_id])
        xmit_counters, queue_counters = sai_thrift_read_port_counters(
            self.dst_client, self.asic_type, port_list['dst'][self.dst_port_id])

        logging.debug("Recv Counters: {}, Base: {}".format(recv_counters, recv_counters_base))
        logging.debug("Xmit Counters: {}, Base: {}".format(xmit_counters, xmit_counters_base))

        # recv port pfc
        assert(recv_counters[self.pg] > recv_counters_base[self.pg])
        # recv port no ingress drop
        for cntr in self.ingress_counters:
            assert(recv_counters[cntr] == recv_counters_base[cntr])
        # xmit port no egress drop
        for cntr in self.egress_counters:
            assert(xmit_counters[cntr] == xmit_counters_base[cntr])


class PtfReleaseBuffer(PfcStormTestWithSharedHeadroom):

    def runTest(self):
        time.sleep(1)
        switch_init(self.clients)

        self.parse_test_params()

        # get a snapshot of counter values at recv and transmit ports
        # queue_counters value is not of our interest here
        recv_counters_base, queue_counters = sai_thrift_read_port_counters(
            self.src_client, self.asic_type, port_list['src'][self.src_port_id]
        )

        xmit_counters_base, queue_counters = sai_thrift_read_port_counters(
            self.dst_client, self.asic_type, port_list['dst'][self.dst_port_id]
        )

        logging.info("Enable xmit ports: {}".format(self.dst_port_id))
        self.sai_thrift_port_tx_enable(self.dst_client, self.asic_type, [self.dst_port_id])

        # allow enough time for the dut to sync up the counter values in counters_db
        time.sleep(8)

        # get new base counter values at recv ports
        recv_counters, queue_counters = sai_thrift_read_port_counters(
            self.src_client, self.asic_type, port_list['src'][self.src_port_id])
        # no ingress drop
        for cntr in self.ingress_counters:
            assert(recv_counters[cntr] == recv_counters_base[cntr])
        recv_counters_base = recv_counters

        # allow enough time for the test to check if no PFC frame was sent from Recv port
        time.sleep(30)

        # get the current snapshot of counter values at recv and transmit ports
        recv_counters, queue_counters = sai_thrift_read_port_counters(
            self.src_client, self.asic_type, port_list['src'][self.src_port_id])
        xmit_counters, queue_counters = sai_thrift_read_port_counters(
            self.dst_client, self.asic_type, port_list['dst'][self.dst_port_id])

        logging.debug("Recv Counters: {}, Base: {}".format(
            recv_counters, recv_counters_base))
        logging.debug("Xmit Counters: {}, Base: {}".format(
            xmit_counters, xmit_counters_base))

        # recv port pfc should not be incremented
        assert(recv_counters[self.pg] == recv_counters_base[self.pg])
        # recv port no ingress drop
        for cntr in self.ingress_counters:
            assert(recv_counters[cntr] == recv_counters_base[cntr])
        # xmit port no egress drop
        for cntr in self.egress_counters:
            assert(xmit_counters[cntr] == xmit_counters_base[cntr])


class PtfEnableDstPorts(PfcStormTestWithSharedHeadroom):

    def runTest(self):
        time.sleep(1)
        switch_init(self.clients)
        self.parse_test_params()
        self.sai_thrift_port_tx_enable(self.dst_client, self.asic_type, [self.dst_port_id])


# This test looks to measure xon threshold (pg_reset_floor)
class PFCXonTest(sai_base_test.ThriftInterfaceDataPlane):

    def get_rx_port(self, src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip, dst_port_id, src_vlan):
        print("dst_port_id:{}, src_port_id:{}".format(
            dst_port_id, src_port_id), file=sys.stderr)
        # in case dst_port_id is part of LAG, find out the actual dst port
        # for given IP parameters
        dst_port_id = get_rx_port(
            self, 0, src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip, src_vlan
        )
        print("actual dst_port_id: {}".format(dst_port_id), file=sys.stderr)
        return dst_port_id

    def runTest(self):
        time.sleep(5)
        switch_init(self.clients)
        last_pfc_counter = 0
        recv_port_counters = []
        transmit_port_counters = []

        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        sonic_version = self.test_params['sonic_version']
        router_mac = self.test_params['router_mac']
        max_buffer_size = int(self.test_params['buffer_max_size'])

        # The pfc counter index starts from index 2 in sai_thrift_read_port_counters
        pg = int(self.test_params['pg']) + 2

        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_vlan = self.test_params['src_port_vlan']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        asic_type = self.test_params['sonic_asic_type']

        ttl = 64

        # TODO: pass in dst_port_id and _ip as a list
        dst_port_2_id = int(self.test_params['dst_port_2_id'])
        dst_port_2_ip = self.test_params['dst_port_2_ip']
        dst_port_2_mac = self.dataplane.get_mac(0, dst_port_2_id)
        dst_port_3_id = int(self.test_params['dst_port_3_id'])
        dst_port_3_ip = self.test_params['dst_port_3_ip']
        dst_port_3_mac = self.dataplane.get_mac(0, dst_port_3_id)
        pkts_num_leak_out = int(self.test_params['pkts_num_leak_out'])
        pkts_num_trig_pfc = int(self.test_params['pkts_num_trig_pfc'])
        pkts_num_dismiss_pfc = int(self.test_params['pkts_num_dismiss_pfc'])
        if 'pkts_num_hysteresis' in list(self.test_params.keys()):
            hysteresis = int(self.test_params['pkts_num_hysteresis'])
        else:
            hysteresis = 0
        hwsku = self.test_params['hwsku']

        # get a snapshot of counter values at recv and transmit ports
        # queue_counters value is not of our interest here
        recv_counters_base, _ = sai_thrift_read_port_counters(
            self.src_client, asic_type, port_list['src'][src_port_id]
        )

        # The number of packets that will trek into the headroom space;
        # We observe in test that if the packets are sent to multiple destination ports,
        # the ingress may not trigger PFC sharp at its boundary
        if 'pkts_num_margin' in list(self.test_params.keys()):
            margin = int(self.test_params['pkts_num_margin'])
        else:
            margin = 1

        # get counter names to query
        ingress_counters, egress_counters = get_counter_names(sonic_version)

        port_counter_indexes = [pg]
        port_counter_indexes += ingress_counters
        port_counter_indexes += egress_counters
        port_counter_indexes += [TRANSMITTED_PKTS, RECEIVED_PKTS, RECEIVED_NON_UC_PKTS, TRANSMITTED_NON_UC_PKTS, EGRESS_PORT_QLEN]

        # create packet
        pkt_dst_mac = router_mac if router_mac != '' else dst_port_mac
        if 'packet_size' in self.test_params:
            packet_length = self.test_params['packet_size']
        else:
            packet_length = 64
        if 'cell_size' in self.test_params:
            cell_size = self.test_params['cell_size']
            cell_occupancy = (packet_length + cell_size - 1) // cell_size
        else:
            cell_occupancy = 1

        pkt_dst_mac2 = router_mac if router_mac != '' else dst_port_2_mac
        pkt_dst_mac3 = router_mac if router_mac != '' else dst_port_3_mac

        is_dualtor = self.test_params.get('is_dualtor', False)
        def_vlan_mac = self.test_params.get('def_vlan_mac', None)
        if is_dualtor and def_vlan_mac != None:
            pkt_dst_mac = def_vlan_mac
            pkt_dst_mac2 = def_vlan_mac
            pkt_dst_mac3 = def_vlan_mac

        pkt = construct_ip_pkt(packet_length,
                               pkt_dst_mac,
                               src_port_mac,
                               src_port_ip,
                               dst_port_ip,
                               dscp,
                               src_port_vlan,
                               ecn=ecn,
                               ttl=ttl)
        dst_port_id = self.get_rx_port(
            src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip, dst_port_id, src_port_vlan
        )

        # create packet
        pkt2 = construct_ip_pkt(packet_length,
                                pkt_dst_mac2,
                                src_port_mac,
                                src_port_ip,
                                dst_port_2_ip,
                                dscp,
                                src_port_vlan,
                                ecn=ecn,
                                ttl=ttl)
        dst_port_2_id = self.get_rx_port(
            src_port_id, pkt_dst_mac2, dst_port_2_ip, src_port_ip, dst_port_2_id, src_port_vlan
        )

        # create packet
        pkt3 = construct_ip_pkt(packet_length,
                                pkt_dst_mac3,
                                src_port_mac,
                                src_port_ip,
                                dst_port_3_ip,
                                dscp,
                                src_port_vlan,
                                ecn=ecn,
                                ttl=ttl)
        dst_port_3_id = self.get_rx_port(
            src_port_id, pkt_dst_mac3, dst_port_3_ip, src_port_ip, dst_port_3_id, src_port_vlan
        )

        # For TH3, some packets stay in egress memory and doesn't show up in shared buffer or leakout
        if 'pkts_num_egr_mem' in list(self.test_params.keys()):
            pkts_num_egr_mem = int(self.test_params['pkts_num_egr_mem'])

        step_id = 1
        step_desc = 'disable TX for dst_port_id, dst_port_2_id, dst_port_3_id'
        sys.stderr.write('step {}: {}\n'.format(step_id, step_desc))
        self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id, dst_port_2_id, dst_port_3_id])

        try:
            '''
            Send various numbers of pkts to each dst port to occupy PG buffer, as below:

                                                                                                          shared buffer theshold
                                                                         xon offset                            |
                                                                             |                                 |
            PG config:                                                       +                                 +
            -----------------------------------------------------------------*---------------------------------*----------------------
            pkts in each port:                                          +                                            +
                                                                        |                                            |
            |<--- pkts_num_trig_pfc - pkts_num_dismiss_pfc - margin --->|                                            |
                                 in dst port 1                          |                                            |
                                                                        |<---   pkts_num_dismiss_pfc + margin*2  --->|
                                                                                         in dst port 2               |
                                                                                                                     |<--- X pkts --->|
                                                                                                                       in dst port 3
            '''
            # send packets to dst port 1, occupying the "xon"
            step_id += 1
            step_desc = 'send packets to dst port 1, occupying the xon'
            sys.stderr.write('step {}: {}\n'.format(step_id, step_desc))

            xmit_counters_base, _ = sai_thrift_read_port_counters(
                self.dst_client, asic_type, port_list['dst'][dst_port_id]
            )

            # Since there is variability in packet leakout in hwsku Arista-7050CX3-32S-D48C8 and
            # Arista-7050CX3-32S-C32. Starting with zero pkts_num_leak_out and trying to find
            # actual leakout by sending packets and reading actual leakout from HW.
            # And apply dynamically compensation to all device using Broadcom ASIC.
            if check_leackout_compensation_support(asic_type, hwsku):
                pkts_num_leak_out = 0

            if hwsku == 'DellEMC-Z9332f-M-O16C64' or hwsku == 'DellEMC-Z9332f-O32':
                send_packet(
                    self, src_port_id, pkt,
                    (pkts_num_egr_mem + pkts_num_leak_out + pkts_num_trig_pfc -
                     pkts_num_dismiss_pfc - hysteresis) // cell_occupancy
                )
            elif 'cisco-8000' in asic_type:
                fill_leakout_plus_one(self, src_port_id, dst_port_id,
                       pkt, int(self.test_params['pg']), asic_type)
                send_packet(
                    self, src_port_id, pkt,
                    (pkts_num_leak_out + pkts_num_trig_pfc -
                     pkts_num_dismiss_pfc - hysteresis) // cell_occupancy - 1
                )
            else:
                send_packet(
                    self, src_port_id, pkt,
                    (pkts_num_leak_out + pkts_num_trig_pfc -
                     pkts_num_dismiss_pfc - hysteresis) // cell_occupancy - margin
                )
                sys.stderr.write('send_packet(src_port_id, pkt, ({} + {} - {} - {}) // {})\n'.format(pkts_num_leak_out, pkts_num_trig_pfc, pkts_num_dismiss_pfc, hysteresis, cell_occupancy))

            if check_leackout_compensation_support(asic_type, hwsku):
                dynamically_compensate_leakout(self.dst_client, asic_type, sai_thrift_read_port_counters,
                                               port_list['dst'][dst_port_id], TRANSMITTED_PKTS,
                                               xmit_counters_base, self, src_port_id, pkt, 40)

            # send packets to dst port 2, occupying the shared buffer
            step_id += 1
            step_desc = 'send packets to dst port 2, occupying the shared buffer'
            sys.stderr.write('step {}: {}\n'.format(step_id, step_desc))

            xmit_2_counters_base, _ = sai_thrift_read_port_counters(
                self.dst_client, asic_type, port_list['dst'][dst_port_2_id]
            )
            if hwsku == 'DellEMC-Z9332f-M-O16C64' or hwsku == 'DellEMC-Z9332f-O32':
                send_packet(
                    self, src_port_id, pkt2,
                    (pkts_num_egr_mem + pkts_num_leak_out + pkts_num_dismiss_pfc +
                     hysteresis) // cell_occupancy + margin - 1
                )
            elif 'cisco-8000' in asic_type:
                fill_leakout_plus_one(self, src_port_id, dst_port_2_id,
                       pkt2, int(self.test_params['pg']), asic_type)
                send_packet(
                    self, src_port_id, pkt2,
                    (pkts_num_leak_out + pkts_num_dismiss_pfc +
                     hysteresis) // cell_occupancy + margin - 2
                )
            else:
                send_packet(
                    self, src_port_id, pkt2,
                    (pkts_num_leak_out + pkts_num_dismiss_pfc +
                     hysteresis) // cell_occupancy + margin * 2 - 1
                )
                sys.stderr.write('send_packet(src_port_id, pkt2, ({} + {} + {}) // {} + {} - 1)\n'.format(pkts_num_leak_out, pkts_num_dismiss_pfc, hysteresis, cell_occupancy, margin))

            if check_leackout_compensation_support(asic_type, hwsku):
                dynamically_compensate_leakout(self.dst_client, asic_type, sai_thrift_read_port_counters,
                                               port_list['dst'][dst_port_2_id], TRANSMITTED_PKTS,
                                               xmit_2_counters_base, self, src_port_id, pkt2, 40)

            # send 1 packet to dst port 3, triggering PFC
            step_id += 1
            step_desc = 'send 1 packet to dst port 3, triggering PFC'
            sys.stderr.write('step {}: {}\n'.format(step_id, step_desc))
            xmit_3_counters_base, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_3_id])
            if hwsku == 'DellEMC-Z9332f-M-O16C64' or hwsku == 'DellEMC-Z9332f-O32':
                send_packet(self, src_port_id, pkt3,
                            pkts_num_egr_mem + pkts_num_leak_out + 1)
            elif 'cisco-8000' in asic_type:
                fill_leakout_plus_one(self, src_port_id, dst_port_3_id,
                       pkt3, int(self.test_params['pg']), asic_type)
                send_packet(self, src_port_id, pkt3, pkts_num_leak_out)
            else:
                send_packet(self, src_port_id, pkt3, pkts_num_leak_out + 1)
                sys.stderr.write('send_packet(src_port_id, pkt3, ({} + 1)\n'.format(pkts_num_leak_out))

            if check_leackout_compensation_support(asic_type, hwsku):
                dynamically_compensate_leakout(self.dst_client, asic_type, sai_thrift_read_port_counters,
                                               port_list['dst'][dst_port_3_id], TRANSMITTED_PKTS,
                                               xmit_3_counters_base, self, src_port_id, pkt3, 40)

            # allow enough time for the dut to sync up the counter values in counters_db
            time.sleep(8)
            # get a snapshot of counter values at recv and transmit ports
            # queue counters value is not of our interest here
            recv_counters, _ = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
            xmit_counters, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
            xmit_2_counters, _ = sai_thrift_read_port_counters(
                self.dst_client, asic_type, port_list['dst'][dst_port_2_id])
            xmit_3_counters, _ = sai_thrift_read_port_counters(
                self.dst_client, asic_type, port_list['dst'][dst_port_3_id])

            port_cnt_tbl = texttable.TextTable([''] + [port_counter_fields[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['recv_counters_base'] + [recv_counters_base[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['recv_counters'] + [recv_counters[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_counters_base'] + [xmit_counters_base[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_counters'] + [xmit_counters[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_2_counters_base'] + [xmit_2_counters_base[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_2_counters'] + [xmit_2_counters[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_3_counters_base'] + [xmit_3_counters_base[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_3_counters'] + [xmit_3_counters[idx] for idx in port_counter_indexes])
            sys.stderr.write('{}\n'.format(port_cnt_tbl))

            # recv port pfc
            assert(recv_counters[pg] > recv_counters_base[pg]), 'unexpectedly not trigger PFC for PG {} (counter: {}), at step {} {}'.format(pg, port_counter_fields[pg], step_id, step_desc)
            # recv port no ingress drop
            for cntr in ingress_counters:
                assert(recv_counters[cntr] == recv_counters_base[cntr]), 'unexpectedly ingress drop on recv port (counter: {}), at step {} {}'.format(port_counter_fields[cntr], step_id, step_desc)
            # xmit port no egress drop
            for cntr in egress_counters:
                assert(xmit_counters[cntr] == xmit_counters_base[cntr]), 'unexpectedly egress drop on xmit port 1 (counter: {}, at step {} {})'.format(port_counter_fields[cntr], step_id, step_desc)
                assert(xmit_2_counters[cntr] == xmit_2_counters_base[cntr]), 'unexpectedly egress drop on xmit port 2 (counter: {}, at step {} {})'.format(port_counter_fields[cntr], step_id, step_desc)
                assert(xmit_3_counters[cntr] == xmit_3_counters_base[cntr]), 'unexpectedly egress drop on xmit port 3 (counter: {}, at step {} {})'.format(port_counter_fields[cntr], step_id, step_desc)

            step_id += 1
            step_desc = 'enable TX for dst_port_2_id, to drain off buffer in dst_port_2'
            sys.stderr.write('step {}: {}\n'.format(step_id, step_desc))
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_2_id], last_port=False)

            # allow enough time for the dut to sync up the counter values in counters_db
            time.sleep(8)
            # get a snapshot of counter values at recv and transmit ports
            # queue counters value is not of our interest here
            recv_counters_base = recv_counters
            recv_counters, _ = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
            xmit_counters, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
            xmit_2_counters, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_2_id])
            xmit_3_counters, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_3_id])
            port_cnt_tbl = texttable.TextTable([''] + [port_counter_fields[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['recv_counters_base'] + [recv_counters_base[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['recv_counters'] + [recv_counters[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_counters_base'] + [xmit_counters_base[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_counters'] + [xmit_counters[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_2_counters_base'] + [xmit_2_counters_base[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_2_counters'] + [xmit_2_counters[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_3_counters_base'] + [xmit_3_counters_base[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_3_counters'] + [xmit_3_counters[idx] for idx in port_counter_indexes])
            sys.stderr.write('{}\n'.format(port_cnt_tbl))

            # recv port pfc
            assert(recv_counters[pg] > recv_counters_base[pg]), 'unexpectedly not trigger PFC for PG {} (counter: {}), at step {} {}'.format(pg, port_counter_fields[pg], step_id, step_desc)
            # recv port no ingress drop
            for cntr in ingress_counters:
                assert (recv_counters[cntr] <= recv_counters_base[cntr] + COUNTER_MARGIN),\
                    'unexpectedly ingress drop on recv port (counter: {}), at step {} {}'.format(
                    port_counter_fields[cntr], step_id, step_desc)
            # xmit port no egress drop
            for cntr in egress_counters:
                assert(xmit_counters[cntr] == xmit_counters_base[cntr]), 'unexpectedly egress drop on xmit port 1 (counter: {}), at step {} {}'.format(port_counter_fields[cntr], step_id, step_desc)
                assert(xmit_2_counters[cntr] == xmit_2_counters_base[cntr]), 'unexpectedly egress drop on xmit port 2 (counter: {}), at step {} {}'.format(port_counter_fields[cntr], step_id, step_desc)
                assert(xmit_3_counters[cntr] == xmit_3_counters_base[cntr]), 'unexpectedly egress drop on xmit port 3 (counter: {}), at step {} {}'.format(port_counter_fields[cntr], step_id, step_desc)

            step_id += 1
            step_desc = 'enable TX for dst_port_3_id, to drain off buffer in dst_port_3'
            sys.stderr.write('step {}: {}\n'.format(step_id, step_desc))
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_3_id], last_port=False)

            # allow enough time for the dut to sync up the counter values in counters_db
            time.sleep(8)
            # get new base counter values at recv ports
            # queue counters value is not of our interest here
            recv_counters, _ = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])

            port_cnt_tbl = texttable.TextTable([''] + [port_counter_fields[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['recv_counters_base'] + [recv_counters_base[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['recv_counters'] + [recv_counters[idx] for idx in port_counter_indexes])
            sys.stderr.write('{}\n'.format(port_cnt_tbl))

            for cntr in ingress_counters:
                assert (recv_counters[cntr] <= recv_counters_base[cntr] + COUNTER_MARGIN),\
                    'unexpectedly ingress drop on recv port (counter: {}), at step {} {}'.format(
                    port_counter_fields[cntr], step_id, step_desc)
            recv_counters_base = recv_counters

            step_id += 1
            step_desc = 'sleep 30 seconds'
            sys.stderr.write('step {}: {}\n'.format(step_id, step_desc))

            time.sleep(30)
            # get a snapshot of counter values at recv and transmit ports
            # queue counters value is not of our interest here
            recv_counters, _ = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
            xmit_counters, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
            xmit_2_counters, _ = sai_thrift_read_port_counters(
                self.dst_client, asic_type, port_list['dst'][dst_port_2_id])
            xmit_3_counters, _ = sai_thrift_read_port_counters(
                self.dst_client, asic_type, port_list['dst'][dst_port_3_id])

            port_cnt_tbl = texttable.TextTable([''] + [port_counter_fields[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['recv_counters_base'] + [recv_counters_base[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['recv_counters'] + [recv_counters[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_counters_base'] + [xmit_counters_base[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_counters'] + [xmit_counters[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_2_counters_base'] + [xmit_2_counters_base[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_2_counters'] + [xmit_2_counters[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_3_counters_base'] + [xmit_3_counters_base[idx] for idx in port_counter_indexes])
            port_cnt_tbl.add_row(['xmit_3_counters'] + [xmit_3_counters[idx] for idx in port_counter_indexes])
            sys.stderr.write('{}\n'.format(port_cnt_tbl))

           # recv port no pfc
            assert(recv_counters[pg] == recv_counters_base[pg]), 'unexpectedly trigger PFC for PG {} (counter: {}), at step {} {}'.format(pg, port_counter_fields[pg], step_id, step_desc)
            # recv port no ingress drop
            for cntr in ingress_counters:
                assert (recv_counters[cntr] <= recv_counters_base[cntr] + COUNTER_MARGIN),\
                    'unexpectedly ingress drop on recv port (counter: {}), at step {} {}'.format(
                    port_counter_fields[cntr], step_id, step_desc)
            # xmit port no egress drop
            for cntr in egress_counters:
                assert(xmit_counters[cntr] == xmit_counters_base[cntr]), 'unexpectedly egress drop on xmit port 1 (counter: {}), at step {} {}'.format(port_counter_fields[cntr], step_id, step_desc)
                assert(xmit_2_counters[cntr] == xmit_2_counters_base[cntr]), 'unexpectedly egress drop on xmit port 2 (counter: {}), at step {} {}'.format(port_counter_fields[cntr], step_id, step_desc)
                assert(xmit_3_counters[cntr] == xmit_3_counters_base[cntr]), 'unexpectedly egress drop on xmit port 3 (counter: {}), at step {} {}'.format(port_counter_fields[cntr], step_id, step_desc)

        finally:
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id, dst_port_2_id, dst_port_3_id])


class HdrmPoolSizeTest(sai_base_test.ThriftInterfaceDataPlane):
    def setUp(self):
        sai_base_test.ThriftInterfaceDataPlane.setUp(self)
        time.sleep(5)
        switch_init(self.clients)

        # Parse input parameters
        self.testbed_type = self.test_params['testbed_type']
        self.dscps = self.test_params['dscps']
        self.ecn = self.test_params['ecn']
        self.router_mac = self.test_params['router_mac']
        self.sonic_version = self.test_params['sonic_version']
        # The pfc counter index starts from index 2 in sai_thrift_read_port_counters
        self.pgs = [pg + 2 for pg in self.test_params['pgs']]
        self.src_port_ids = self.test_params['src_port_ids']
        self.src_port_ips = self.test_params['src_port_ips']
        print(self.src_port_ips, file=sys.stderr)
        sys.stderr.flush()
        # get counter names to query
        self.ingress_counters, self.egress_counters = get_counter_names(
            self.sonic_version)

        self.dst_port_id = self.test_params['dst_port_id']
        self.dst_port_ip = self.test_params['dst_port_ip']
        self.pgs_num = self.test_params['pgs_num']
        self.asic_type = self.test_params['sonic_asic_type']
        self.pkts_num_leak_out = self.test_params['pkts_num_leak_out']
        self.pkts_num_trig_pfc = self.test_params.get('pkts_num_trig_pfc')
        if not self.pkts_num_trig_pfc:
            self.pkts_num_trig_pfc_shp = self.test_params.get(
                'pkts_num_trig_pfc_shp')
        self.pkts_num_hdrm_full = self.test_params['pkts_num_hdrm_full']
        self.pkts_num_hdrm_partial = self.test_params['pkts_num_hdrm_partial']
        packet_size = self.test_params.get('packet_size')

        if packet_size:
            self.pkt_size = packet_size
            cell_size = self.test_params.get('cell_size')
            self.pkt_size_factor = int(math.ceil(float(packet_size)/cell_size))
        else:
            self.pkt_size = 64
            self.pkt_size_factor = 1

        if self.pkts_num_trig_pfc:
            print(("pkts num: leak_out: %d, trig_pfc: %d, hdrm_full: %d, hdrm_partial: %d, pkt_size %d" % (
                self.pkts_num_leak_out, self.pkts_num_trig_pfc, self.pkts_num_hdrm_full,
                self.pkts_num_hdrm_partial, self.pkt_size)), file=sys.stderr)
        elif self.pkts_num_trig_pfc_shp:
            print(("pkts num: leak_out: {}, trig_pfc: {}, hdrm_full: {}, hdrm_partial: {}, pkt_size {}".format(
                self.pkts_num_leak_out, self.pkts_num_trig_pfc_shp, self.pkts_num_hdrm_full,
                self.pkts_num_hdrm_partial, self.pkt_size)), file=sys.stderr)

        # used only for headroom pool watermark
        if all(key in self.test_params for key in [
            'hdrm_pool_wm_multiplier', 'buf_pool_roid', 'cell_size', 'max_headroom']):
           self.cell_size = int(self.test_params['cell_size'])
           self.wm_multiplier = self.test_params['hdrm_pool_wm_multiplier']
           print("Wm multiplier: %d buf_pool_roid: %s" % (
               self.wm_multiplier, self.test_params['buf_pool_roid']), file=sys.stderr)
           self.buf_pool_roid = int(self.test_params['buf_pool_roid'], 0)
           print("buf_pool_roid: 0x%lx" %
                 (self.buf_pool_roid), file=sys.stderr)
           self.max_headroom = int(self.test_params['max_headroom'])
        else:
           self.wm_multiplier = None

        sys.stderr.flush()

        self.dst_port_mac = self.dataplane.get_mac(0, self.dst_port_id)
        self.src_port_macs = [self.dataplane.get_mac(
            0, ptid) for ptid in self.src_port_ids]

        if self.testbed_type in ['dualtor', 'dualtor-56', 't0', 't0-64', 't0-116']:
            # populate ARP
            # sender's MAC address is corresponding PTF port's MAC address
            # sender's IP address is caculated in tests/qos/qos_sai_base.py::QosSaiBase::__assignTestPortIps()
            # for dualtor: sender_IP_address = DUT_default_VLAN_interface_IP_address + portIndex + 1
            for idx, ptid in enumerate(self.src_port_ids):

                arpreq_pkt = simple_arp_packet(
                              eth_dst='ff:ff:ff:ff:ff:ff',
                              eth_src=self.src_port_macs[idx],
                              arp_op=1,
                              ip_snd=self.src_port_ips[idx],
                              ip_tgt='192.168.0.1',
                              hw_snd=self.src_port_macs[idx],
                              hw_tgt='00:00:00:00:00:00')
                send_packet(self, ptid, arpreq_pkt)
            arpreq_pkt = simple_arp_packet(
                          eth_dst='ff:ff:ff:ff:ff:ff',
                          eth_src=self.dst_port_mac,
                          arp_op=1,
                          ip_snd=self.dst_port_ip,
                          ip_tgt='192.168.0.1',
                          hw_snd=self.dst_port_mac,
                          hw_tgt='00:00:00:00:00:00')
            send_packet(self, self.dst_port_id, arpreq_pkt)
        time.sleep(8)

        # for dualtor, need to change test traffic's dest MAC address to point DUT's default VLAN interface
        # and then DUT is able to correctly forward test traffic to dest PORT on PTF
        # Reminder: need to change this dest MAC address after above ARP population to avoid corrupt ARP packet
        is_dualtor = self.test_params.get('is_dualtor', False)
        def_vlan_mac = self.test_params.get('def_vlan_mac', None)
        if is_dualtor and def_vlan_mac != None:
            self.dst_port_mac = def_vlan_mac

    def tearDown(self):
        sai_base_test.ThriftInterfaceDataPlane.tearDown(self)

    def show_port_counter(self, asic_type, rx_base, tx_base, banner):
        port_counter_indexes = [pg for pg in self.pgs]
        port_counter_indexes += self.ingress_counters
        port_counter_indexes += self.egress_counters
        port_counter_indexes += [TRANSMITTED_PKTS, RECEIVED_PKTS, RECEIVED_NON_UC_PKTS, TRANSMITTED_NON_UC_PKTS, EGRESS_PORT_QLEN]
        port_cnt_tbl = texttable.TextTable([''] + [port_counter_fields[fieldIdx] for fieldIdx in port_counter_indexes])
        for srcPortIdx, srcPortId in enumerate(self.src_port_ids):
            port_cnt_tbl.add_row(['base src_port{}_id{}'.format(srcPortIdx, srcPortId)] + [rx_base[srcPortIdx][fieldIdx] for fieldIdx in port_counter_indexes])
            rx_curr, _ = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][srcPortId])
            port_cnt_tbl.add_row(['     src_port{}_id{}'.format(srcPortIdx, srcPortId)] + [rx_curr[fieldIdx] for fieldIdx in port_counter_indexes])
        port_cnt_tbl.add_row(['base dst_port_id{}'.format(self.dst_port_id)] + [tx_base[fieldIdx] for fieldIdx in port_counter_indexes])
        tx_curr, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][self.dst_port_id])
        port_cnt_tbl.add_row(['     dst_port_id{}'.format(self.dst_port_id)] + [tx_curr[fieldIdx] for fieldIdx in port_counter_indexes])
        sys.stderr.write('{}\n{}\n'.format(banner, port_cnt_tbl))

    def runTest(self):
        platform_asic = self.test_params['platform_asic']

        margin = self.test_params.get('margin')
        if not margin:
            margin = 0
        sidx_dscp_pg_tuples = [(sidx, dscp, self.pgs[pgidx]) for sidx, sid in enumerate(
            self.src_port_ids) for pgidx, dscp in enumerate(self.dscps)]
        assert(len(sidx_dscp_pg_tuples) >= self.pgs_num)
        print(sidx_dscp_pg_tuples, file=sys.stderr)
        sys.stderr.flush()

        # get a snapshot of counter values at recv and transmit ports
        # queue_counters value is not of our interest here
        recv_counters_bases = [sai_thrift_read_port_counters(self.src_client, self.asic_type, port_list['src'][sid])[0] for sid in self.src_port_ids]
        xmit_counters_base, _ = sai_thrift_read_port_counters(self.dst_client, self.asic_type, port_list['dst'][self.dst_port_id])

        # For TH3, some packets stay in egress memory and doesn't show up in shared buffer or leakout
        if 'pkts_num_egr_mem' in list(self.test_params.keys()):
            pkts_num_egr_mem = int(self.test_params['pkts_num_egr_mem'])

        # Pause egress of dut xmit port
        self.sai_thrift_port_tx_disable(self.dst_client, self.asic_type, [self.dst_port_id])

        try:
            # send packets to leak out
            sidx = 0
            pkt = simple_tcp_packet(pktlen=self.pkt_size,
                        eth_dst=self.router_mac if self.router_mac != '' else self.dst_port_mac,
                        eth_src=self.src_port_macs[sidx],
                        ip_src=self.src_port_ips[sidx],
                        ip_dst=self.dst_port_ip,
                        ip_ttl=64)

            hwsku = self.test_params['hwsku']
            if (hwsku == 'DellEMC-Z9332f-M-O16C64' or hwsku == 'DellEMC-Z9332f-O32'):
                send_packet(
                    self, self.src_port_ids[sidx], pkt, pkts_num_egr_mem + self.pkts_num_leak_out)
            else:
                send_packet(
                    self, self.src_port_ids[sidx], pkt, self.pkts_num_leak_out)

            # send packets to all pgs to fill the service pool
            # and trigger PFC on all pgs
            for i in range(0, self.pgs_num):
                # Prepare TCP packet data
                tos = sidx_dscp_pg_tuples[i][1] << 2
                tos |= self.ecn
                ttl = 64
                default_packet_length = self.pkt_size
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                                        eth_dst=self.router_mac if self.router_mac != '' else self.dst_port_mac,
                                        eth_src=self.src_port_macs[sidx_dscp_pg_tuples[i][0]],
                                        ip_src=self.src_port_ips[sidx_dscp_pg_tuples[i][0]],
                                        ip_dst=self.dst_port_ip,
                                        ip_tos=tos,
                                        ip_ttl=ttl)
                if self.pkts_num_trig_pfc:
                    pkts_num_trig_pfc = self.pkts_num_trig_pfc
                else:
                    pkts_num_trig_pfc = self.pkts_num_trig_pfc_shp[i]

                pkt_cnt = pkts_num_trig_pfc // self.pkt_size_factor
                send_packet(
                    self, self.src_port_ids[sidx_dscp_pg_tuples[i][0]], pkt, int(pkt_cnt))

                time.sleep(8)   # wait pfc counter refresh
                self.show_port_counter(self.asic_type, recv_counters_bases, xmit_counters_base,
                    'To fill service pool, send {} pkt with DSCP {} PG {} from src_port{} to dst_port'.format(pkt_cnt, sidx_dscp_pg_tuples[i][1], sidx_dscp_pg_tuples[i][2], sidx_dscp_pg_tuples[i][0]))

            print("Service pool almost filled", file=sys.stderr)
            sys.stderr.flush()
            # allow enough time for the dut to sync up the counter values in counters_db
            time.sleep(8)

            for i in range(0, self.pgs_num):
                # Prepare TCP packet data
                tos = sidx_dscp_pg_tuples[i][1] << 2
                tos |= self.ecn
                ttl = 64
                default_packet_length = self.pkt_size
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                                        eth_dst=self.router_mac if self.router_mac != '' else self.dst_port_mac,
                                        eth_src=self.src_port_macs[sidx_dscp_pg_tuples[i][0]],
                                        ip_src=self.src_port_ips[sidx_dscp_pg_tuples[i][0]],
                                        ip_dst=self.dst_port_ip,
                                        ip_tos=tos,
                                        ip_ttl=ttl)
                pkt_cnt = 0

                recv_counters, _ = sai_thrift_read_port_counters(
                    self.src_client, self.asic_type, port_list['src'][self.src_port_ids[sidx_dscp_pg_tuples[i][0]]])
                while (recv_counters[sidx_dscp_pg_tuples[i][2]] ==
                       recv_counters_bases[sidx_dscp_pg_tuples[i][0]][sidx_dscp_pg_tuples[i][2]]) and (pkt_cnt < 10):
                    send_packet(
                        self, self.src_port_ids[sidx_dscp_pg_tuples[i][0]], pkt, 1)
                    pkt_cnt += 1
                    # allow enough time for the dut to sync up the counter values in counters_db
                    time.sleep(8)

                    # get a snapshot of counter values at recv and transmit ports
                    # queue_counters value is not of our interest here
                    recv_counters, _ = sai_thrift_read_port_counters(
                        self.src_client, self.asic_type, port_list['src'][self.src_port_ids[sidx_dscp_pg_tuples[i][0]]])
                time.sleep(8)   # wait pfc counter refresh
                self.show_port_counter(self.asic_type, recv_counters_bases, xmit_counters_base,
                    'To trigger PFC, send {} pkt with DSCP {} PG {} from src_port{} to dst_port'.format(pkt_cnt, sidx_dscp_pg_tuples[i][1], sidx_dscp_pg_tuples[i][2], sidx_dscp_pg_tuples[i][0]))

                if pkt_cnt == 10:
                    sys.exit("Too many pkts needed to trigger pfc: %d" %
                             (pkt_cnt))
                assert(recv_counters[sidx_dscp_pg_tuples[i][2]] >
                       recv_counters_bases[sidx_dscp_pg_tuples[i][0]][sidx_dscp_pg_tuples[i][2]])
                print("%d packets for sid: %d, pg: %d to trigger pfc" % (
                    pkt_cnt, self.src_port_ids[sidx_dscp_pg_tuples[i][0]], sidx_dscp_pg_tuples[i][2] - 2),
                      file=sys.stderr)
                sys.stderr.flush()

            print("PFC triggered", file=sys.stderr)
            sys.stderr.flush()

            upper_bound = 2 * margin + 1
            if self.wm_multiplier:
                hdrm_pool_wm = sai_thrift_read_headroom_pool_watermark(
                    self.src_client, self.buf_pool_roid)
                print("Actual headroom pool watermark value to start: %d" %
                      hdrm_pool_wm, file=sys.stderr)
                assert (hdrm_pool_wm <= (upper_bound *
                        self.cell_size * self.wm_multiplier))

            expected_wm = 0
            wm_pkt_num = 0
            upper_bound_wm = 0
            # send packets to all pgs to fill the headroom pool
            for i in range(0, self.pgs_num):
                # Prepare TCP packet data
                tos = sidx_dscp_pg_tuples[i][1] << 2
                tos |= self.ecn
                ttl = 64
                default_packet_length = self.pkt_size
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                                        eth_dst=self.router_mac if self.router_mac != '' else self.dst_port_mac,
                                        eth_src=self.src_port_macs[sidx_dscp_pg_tuples[i][0]],
                                        ip_src=self.src_port_ips[sidx_dscp_pg_tuples[i][0]],
                                        ip_dst=self.dst_port_ip,
                                        ip_tos=tos,
                                        ip_ttl=ttl)

                pkt_cnt = self.pkts_num_hdrm_full // self.pkt_size_factor if i != self.pgs_num - 1 else self.pkts_num_hdrm_partial // self.pkt_size_factor
                send_packet(self, self.src_port_ids[sidx_dscp_pg_tuples[i][0]], pkt, pkt_cnt)
                # allow enough time for the dut to sync up the counter values in counters_db
                time.sleep(8)

                self.show_port_counter(self.asic_type, recv_counters_bases, xmit_counters_base,
                    'To fill headroom pool, send {} pkt with DSCP {} PG {} from src_port{} to dst_port'.format(pkt_cnt, sidx_dscp_pg_tuples[i][1], sidx_dscp_pg_tuples[i][2], sidx_dscp_pg_tuples[i][0]))

                recv_counters, _ = sai_thrift_read_port_counters(
                    self.src_client, self.asic_type, port_list['src'][self.src_port_ids[sidx_dscp_pg_tuples[i][0]]])
                # assert no ingress drop
                for cntr in self.ingress_counters:
                    # corner case: in previous step in which trigger PFC, a few packets were dropped, and dropping don't keep increasing constantaly.
                    # workaround: tolerates a few packet drop here, and output relevant information for offline analysis, to know if it's an issue
                    if recv_counters[cntr] != recv_counters_bases[sidx_dscp_pg_tuples[i][0]][cntr]:
                        sys.stderr.write('There are some unexpected {} packet drop\n'.format(recv_counters[cntr] - recv_counters_bases[sidx_dscp_pg_tuples[i][0]][cntr]))
                    assert(recv_counters[cntr] - recv_counters_bases[sidx_dscp_pg_tuples[i][0]][cntr] <= margin)

                if self.wm_multiplier:
                    wm_pkt_num += (self.pkts_num_hdrm_full if i !=
                                   self.pgs_num - 1 else self.pkts_num_hdrm_partial)
                    hdrm_pool_wm = sai_thrift_read_headroom_pool_watermark(
                        self.src_client, self.buf_pool_roid)
                    expected_wm = wm_pkt_num * self.cell_size * self.wm_multiplier
                    upper_bound_wm = expected_wm + \
                        (upper_bound * self.cell_size * self.wm_multiplier)
                    if upper_bound_wm > self.max_headroom:
                        upper_bound_wm = self.max_headroom

                    print("pkts sent: %d, lower bound: %d, actual headroom pool watermark: %d, upper_bound: %d" % (
                        wm_pkt_num, expected_wm, hdrm_pool_wm, upper_bound_wm), file=sys.stderr)
                    if 'innovium' not in self.asic_type:
                        assert(expected_wm <= hdrm_pool_wm)
                    assert(hdrm_pool_wm <= upper_bound_wm)

            print("all but the last pg hdrms filled", file=sys.stderr)
            sys.stderr.flush()

            # last pg
            i = self.pgs_num - 1
            # send 1 packet on last pg to trigger ingress drop
            pkt_cnt = 1 + 2 * margin
            send_packet(self, self.src_port_ids[sidx_dscp_pg_tuples[i][0]], pkt, pkt_cnt)
            # allow enough time for the dut to sync up the counter values in counters_db
            time.sleep(8)

            self.show_port_counter(self.asic_type, recv_counters_bases, xmit_counters_base,
                'To fill last PG and trigger ingress drop, send {} pkt with DSCP {} PG {} from src_port{} to dst_port'.format(pkt_cnt, sidx_dscp_pg_tuples[i][1], sidx_dscp_pg_tuples[i][2], sidx_dscp_pg_tuples[i][0]))

            recv_counters, _ = sai_thrift_read_port_counters(
                self.src_client, self.asic_type, port_list['src'][self.src_port_ids[sidx_dscp_pg_tuples[i][0]]])
            if platform_asic and platform_asic == "broadcom-dnx":
                logging.info("On J2C+ don't support port level drop counters - so ignoring this step for now")
            else:
                # assert ingress drop
                for cntr in self.ingress_counters:
                    assert(recv_counters[cntr] > recv_counters_bases[sidx_dscp_pg_tuples[i][0]][cntr])

            # assert no egress drop at the dut xmit port
            xmit_counters, _ = sai_thrift_read_port_counters(
                self.dst_client, self.asic_type, port_list['dst'][self.dst_port_id])

            if platform_asic and platform_asic == "broadcom-dnx":
                logging.info("On J2C+ don't support port level drop counters - so ignoring this step for now")
            else:
                for cntr in self.egress_counters:
                    assert(xmit_counters[cntr] == xmit_counters_base[cntr])

            print("pg hdrm filled", file=sys.stderr)
            if self.wm_multiplier:
                # assert hdrm pool wm still remains the same
                hdrm_pool_wm = sai_thrift_read_headroom_pool_watermark(self.src_client, self.buf_pool_roid)
                sys.stderr.write('After PG headroom filled, actual headroom pool watermark {}, upper_bound {}\n'.format(hdrm_pool_wm, upper_bound_wm))
                if 'innovium' not in self.asic_type:
                    assert(expected_wm <= hdrm_pool_wm)
                assert(hdrm_pool_wm <= upper_bound_wm)
                # at this point headroom pool should be full. send few more packets to continue causing drops
                print("overflow headroom pool", file=sys.stderr)
                send_packet(self, self.src_port_ids[sidx_dscp_pg_tuples[i][0]], pkt, 10)
                hdrm_pool_wm = sai_thrift_read_headroom_pool_watermark(self.src_client, self.buf_pool_roid)
                assert(hdrm_pool_wm <= self.max_headroom)
            sys.stderr.flush()

        finally:
            self.sai_thrift_port_tx_enable(self.dst_client, self.asic_type, [self.dst_port_id])


class SharedResSizeTest(sai_base_test.ThriftInterfaceDataPlane):
    def setUp(self):
        sai_base_test.ThriftInterfaceDataPlane.setUp(self)
        time.sleep(5)
        switch_init(self.clients)

         # Parse input parameters
        self.testbed_type = self.test_params['testbed_type']
        self.dscps = self.test_params['dscps']
        self.ecn = self.test_params['ecn']
        self.router_mac = self.test_params['router_mac']
        self.sonic_version = self.test_params['sonic_version']
        self.pgs = self.test_params['pgs']
        self.pg_cntr_indices = [pg + 2 for pg in self.pgs]
        self.queues = self.test_params['queues']
        self.src_port_ids = self.test_params['src_port_ids']
        self.src_port_ips = self.test_params['src_port_ips']
        print(self.src_port_ips, file=sys.stderr)
        sys.stderr.flush()
        # get counter names to query
        self.ingress_counters, self.egress_counters = get_counter_names(
            self.sonic_version)

        self.dst_port_ids = self.test_params['dst_port_ids']
        self.dst_port_ips = self.test_params['dst_port_ips']
        self.asic_type = self.test_params['sonic_asic_type']
        self.pkt_counts = self.test_params['pkt_counts']
        self.shared_limit_bytes = self.test_params['shared_limit_bytes']

        # LACP causes slow increase in memory consumption over duration of the test, thus
        # a margin may be needed.
        if 'pkts_num_margin' in self.test_params:
            self.margin = int(self.test_params['pkts_num_margin'])
        else:
            self.margin = 0

        if 'packet_size' in self.test_params:
            self.packet_size = self.test_params['packet_size']
            self.cell_size = self.test_params['cell_size']
        else:
            self.packet_size = 64
            self.cell_size = 350

        self.dst_port_macs = [self.dataplane.get_mac(
            0, ptid) for ptid in self.dst_port_ids]
        self.src_port_macs = [self.dataplane.get_mac(
            0, ptid) for ptid in self.src_port_ids]

        # Correct any destination ports that may be in a lag
        for i in range(len(self.dst_port_ids)):
            src_port_id = self.src_port_ids[i]
            dst_port_id = self.dst_port_ids[i]
            dst_port_mac = self.dst_port_macs[i]
            src_port_ip = self.src_port_ips[i]
            dst_port_ip = self.dst_port_ips[i]
            real_dst_port_id = get_rx_port(
                self,
                0,
                src_port_id,
                self.router_mac if self.router_mac != '' else dst_port_mac,
                dst_port_ip, src_port_ip
            )
            if real_dst_port_id != dst_port_id:
                print("Corrected dst port from {} to {}".format(dst_port_id, real_dst_port_id), file=sys.stderr)
                self.dst_port_ids[i] = real_dst_port_id

        time.sleep(8)

    def tearDown(self):
        sai_base_test.ThriftInterfaceDataPlane.tearDown(self)

    def runTest(self):
        assert len(self.dscps) == len(self.pgs) == len(
            self.src_port_ids) == len(self.dst_port_ids) == len(self.pkt_counts)

        # Need at least 2 packet send instructions
        assert len(self.pkt_counts) >= 2

        # Reservation limit should be indicated by single packet, which is then modified
        # by the given margin
        assert self.pkt_counts[-1] == 1
        self.pkt_counts[-1] += 2 * self.margin

        # Second to last pkt count instruction needs to be reduced by margin to avoid
        # triggering XOFF early.
        assert self.pkt_counts[-2] >= self.margin
        self.pkt_counts[-2] -= self.margin

        # Test configuration packet counts and sizing should accurately trigger shared limit
        cell_occupancy = (self.packet_size +
                          self.cell_size - 1) // self.cell_size
        assert sum(self.pkt_counts[:-1]) * cell_occupancy * \
                   self.cell_size < self.shared_limit_bytes
        assert sum(self.pkt_counts) * cell_occupancy * \
                   self.cell_size >= self.shared_limit_bytes

        # get a snapshot of counter values at recv and transmit ports
        recv_counters_bases = [sai_thrift_read_port_counters(
            self.src_client, self.asic_type, port_list['src'][sid])[0] for sid in self.src_port_ids]
        xmit_counters_bases = [sai_thrift_read_port_counters(
            self.dst_client, self.asic_type, port_list['dst'][sid])[0] for sid in self.dst_port_ids]

        # Disable all dst ports
        uniq_dst_ports = list(set(self.dst_port_ids))
        self.sai_thrift_port_tx_disable(self.dst_client, self.asic_type, uniq_dst_ports)

        try:
            for i in range(len(self.src_port_ids)):
                dscp = self.dscps[i]
                pg = self.pgs[i]
                queue = self.queues[i]
                src_port_id = self.src_port_ids[i]
                dst_port_id = self.dst_port_ids[i]
                src_port_mac = self.src_port_macs[i]
                dst_port_mac = self.dst_port_macs[i]
                src_port_ip = self.src_port_ips[i]
                dst_port_ip = self.dst_port_ips[i]
                pkt_count = self.pkt_counts[i]

                ttl = 64
                pkt = construct_ip_pkt(self.packet_size,
                                       self.router_mac if self.router_mac != '' else dst_port_mac,
                                       src_port_mac,
                                       src_port_ip,
                                       dst_port_ip,
                                       dscp,
                                       None,
                                       ecn=self.ecn,
                                       ttl=64)

                if i == len(self.src_port_ids) - 1:
                    # Verify XOFF has not been triggered on final port before sending traffic
                    print(
                        "Verifying XOFF hasn't been triggered yet on final iteration", file=sys.stderr)
                    sys.stderr.flush()
                    time.sleep(8)
                    recv_counters = sai_thrift_read_port_counters(
                        self.src_client, self.asic_type, port_list['src'][src_port_id])[0]
                    xoff_txd = recv_counters[self.pg_cntr_indices[i]] - \
                        recv_counters_bases[i][self.pg_cntr_indices[i]]
                    assert xoff_txd == 0, "XOFF triggered too early on final iteration, XOFF count is %d" % xoff_txd

                # Send requested number of packets
                print("Sending %d packets for dscp=%d, pg=%d, src_port_id=%d, dst_port_id=%d" % (
                    pkt_count, dscp, pg, src_port_id, dst_port_id), file=sys.stderr)
                sys.stderr.flush()
                if 'cisco-8000' in self.asic_type:
                    fill_leakout_plus_one(self, src_port_id,
                           dst_port_id, pkt, queue, self.asic_type)
                    pkt_count -= 1  # leakout adds 1 packet, subtract from current iteration

                send_packet(self, src_port_id, pkt, pkt_count)

                if i == len(self.src_port_ids) - 1:
                    # Verify XOFF has now been triggered on final port
                    print(
                        "Verifying XOFF has now been triggered on final iteration", file=sys.stderr)
                    sys.stderr.flush()
                    time.sleep(8)
                    recv_counters = sai_thrift_read_port_counters(
                        self.src_client, self.asic_type, port_list['src'][src_port_id])[0]
                    xoff_txd = recv_counters[self.pg_cntr_indices[i]] - \
                        recv_counters_bases[i][self.pg_cntr_indices[i]]
                    assert xoff_txd > 0, "Failed to trigger XOFF on final iteration"

            # Verify no ingress/egress drops for all ports
            recv_counters_list = [sai_thrift_read_port_counters(self.src_client, self.asic_type, port_list['src'][sid])[
                                                                0] for sid in self.src_port_ids]
            xmit_counters_list = [sai_thrift_read_port_counters(self.dst_client, self.asic_type, port_list['dst'][sid])[
                                                                0] for sid in self.dst_port_ids]
            for i in range(len(self.src_port_ids)):
                for cntr in self.ingress_counters:
                    drops = recv_counters_list[i][cntr] - \
                        recv_counters_bases[i][cntr]
                    assert drops == 0, "Detected %d ingress drops" % drops
                for cntr in self.egress_counters:
                    drops = xmit_counters_list[i][cntr] - \
                        xmit_counters_bases[i][cntr]
                    assert drops == 0, "Detected %d egress drops" % drops

        finally:
            self.sai_thrift_port_tx_enable(self.dst_client, self.asic_type, uniq_dst_ports)

# TODO: remove sai_thrift_clear_all_counters and change to use incremental counter values


class DscpEcnSend(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.clients)

        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        sonic_version = self.test_params['sonic_version']
        default_packet_length = 64
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        num_of_pkts = self.test_params['num_of_pkts']
        limit = self.test_params['limit']
        min_limit = self.test_params['min_limit']
        cell_size = self.test_params['cell_size']
        asic_type = self.test_params['sonic_asic_type']
        # get counter names to query
        ingress_counters, egress_counters = get_counter_names(sonic_version)

        # STOP PORT FUNCTION
        sched_prof_id = sai_thrift_create_scheduler_profile(
            self.src_client, STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(
            id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.dst_client.sai_thrift_set_port_attribute(port_list['dst'][dst_port_id], attr)

        # Clear Counters
        sai_thrift_clear_all_counters(self.src_client, 'src')
        sai_thrift_clear_all_counters(self.dst_client, 'dst')

        # send packets
        try:
            tos = dscp << 2
            tos |= ecn
            ttl = 64
            for i in range(0, num_of_pkts):
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)
                send_packet(self, 0, pkt)

            leaking_pkt_number = 0
            for (rcv_port_number, pkt_str, pkt_time) in self.dataplane.packets(0, 1):
                leaking_pkt_number += 1
            print("leaking packet %d" % leaking_pkt_number)

            # Read Counters
            print("DST port counters: ")
            port_counters, queue_counters = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
            print(port_counters)
            print(queue_counters)

            # Clear Counters
            sai_thrift_clear_all_counters(self.src_client, 'src')
            sai_thrift_clear_all_counters(self.dst_client, 'dst')

            # Set receiving socket buffers to some big value
            for p in list(self.dataplane.ports.values()):
                p.socket.setsockopt(socket.SOL_SOCKET,
                                    socket.SO_RCVBUF, 41943040)

            # RELEASE PORT
            sched_prof_id = sai_thrift_create_scheduler_profile(
                self.src_client, RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(
                id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.dst_client.sai_thrift_set_port_attribute(
                port_list['dst'][dst_port_id], attr)

            # if (ecn == 1) - capture and parse all incoming packets
            marked_cnt = 0
            not_marked_cnt = 0
            if (ecn == 1):
                print("")
                print(
                    "ECN capable packets generated, releasing dst_port and analyzing traffic -")

                cnt = 0
                pkts = []
                for i in range(num_of_pkts):
                    (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(
                        self, device_number=0, port_number=dst_port_id, timeout=0.2)
                    if rcv_pkt is not None:
                        cnt += 1
                        pkts.append(rcv_pkt)
                    else:  # Received less packets then expected
                        assert (cnt == num_of_pkts)
                print("    Received packets:    " + str(cnt))

                for pkt_to_inspect in pkts:
                    pkt_str = hex_dump_buffer(pkt_to_inspect)

                    # Count marked and not marked amount of packets
                    if ((int(pkt_str[ECN_INDEX_IN_HEADER]) & 0x03) == 1):
                        not_marked_cnt += 1
                    elif ((int(pkt_str[ECN_INDEX_IN_HEADER]) & 0x03) == 3):
                        assert (not_marked_cnt == 0)
                        marked_cnt += 1

                print("    ECN non-marked pkts: " + str(not_marked_cnt))
                print("    ECN marked pkts:     " + str(marked_cnt))
                print("")

            time.sleep(5)
            # Read Counters
            print("DST port counters: ")
            port_counters, queue_counters = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
            print(port_counters)
            print(queue_counters)
            if (ecn == 0):
                # num_of_pkts*pkt_size_in_cells*cell_size
                transmitted_data = port_counters[TRANSMITTED_PKTS] * \
                    2 * cell_size
                assert (port_counters[TRANSMITTED_OCTETS] <= limit * 1.05)
                assert (transmitted_data >= min_limit)
                assert (marked_cnt == 0)
            elif (ecn == 1):
                non_marked_data = not_marked_cnt * 2 * cell_size
                assert (non_marked_data <= limit*1.05)
                assert (non_marked_data >= limit*0.95)
                assert (marked_cnt == (num_of_pkts - not_marked_cnt))
                for cntr in egress_counters:
                    assert (port_counters[cntr] == 0)
                for cntr in ingress_counters:
                    assert (port_counters[cntr] == 0)

        finally:
            # RELEASE PORT
            sched_prof_id = sai_thrift_create_scheduler_profile(
                self.src_client, RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(
                id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.dst_client.sai_thrift_set_port_attribute(
                port_list['dst'][dst_port_id], attr)
            print("END OF TEST")


class WRRtest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.clients)

        # Parse input parameters
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_vlan = self.test_params['src_port_vlan']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        qos_remap_enable = bool(self.test_params.get('qos_remap_enable', False))
        print("dst_port_id: %d, src_port_id: %d qos_remap_enable: %d" %
              (dst_port_id, src_port_id, qos_remap_enable))
        print("dst_port_mac: %s, src_port_mac: %s, src_port_ip: %s, dst_port_ip: %s" % (
            dst_port_mac, src_port_mac, src_port_ip, dst_port_ip))
        asic_type = self.test_params['sonic_asic_type']
        default_packet_length = 1500
        exp_ip_id = 110
        queue_0_num_of_pkts = int(self.test_params.get('q0_num_of_pkts', 0))
        queue_1_num_of_pkts = int(self.test_params.get('q1_num_of_pkts', 0))
        queue_2_num_of_pkts = int(self.test_params.get('q2_num_of_pkts', 0))
        queue_3_num_of_pkts = int(self.test_params.get('q3_num_of_pkts', 0))
        queue_4_num_of_pkts = int(self.test_params.get('q4_num_of_pkts', 0))
        queue_5_num_of_pkts = int(self.test_params.get('q5_num_of_pkts', 0))
        queue_6_num_of_pkts = int(self.test_params.get('q6_num_of_pkts', 0))
        queue_7_num_of_pkts = int(self.test_params.get('q7_num_of_pkts', 0))
        limit = int(self.test_params['limit'])
        pkts_num_leak_out = int(self.test_params['pkts_num_leak_out'])
        topo = self.test_params['topo']
        hwsku = self.test_params['hwsku']
        platform_asic = self.test_params['platform_asic']

        if 'backend' not in topo:
            if not qos_remap_enable:
                # When qos_remap is disabled, the map is as below
                # DSCP TC QUEUE
                # 3    3    3
                # 4    4    4
                # 8    0    0
                # 0    1    1
                # 5    2    2
                # 46   5    5
                # 48   6    6
                prio_list = [3, 4, 8, 0, 5, 46, 48]
                q_pkt_cnt = [queue_3_num_of_pkts, queue_4_num_of_pkts, queue_0_num_of_pkts,
                             queue_1_num_of_pkts, queue_2_num_of_pkts, queue_5_num_of_pkts, queue_6_num_of_pkts]
            else:
                # When qos_remap is enabled, the map is as below
                # DSCP TC QUEUE
                # 3    3    3
                # 4    4    4
                # 8    0    0
                # 0    1    1
                # 46   5    5
                # 48   7    7
                prio_list = [3, 4, 8, 0, 46, 48]
                q_pkt_cnt = [queue_3_num_of_pkts, queue_4_num_of_pkts, queue_0_num_of_pkts,
                             queue_1_num_of_pkts, queue_5_num_of_pkts, queue_7_num_of_pkts]
        else:
            prio_list = [3, 4, 1, 0, 2, 5, 6]
            q_pkt_cnt = [queue_3_num_of_pkts, queue_4_num_of_pkts, queue_1_num_of_pkts,
                         queue_0_num_of_pkts, queue_2_num_of_pkts, queue_5_num_of_pkts, queue_6_num_of_pkts]
        q_cnt_sum = sum(q_pkt_cnt)
        # Send packets to leak out
        pkt_dst_mac = router_mac if router_mac != '' else dst_port_mac

        is_dualtor = self.test_params.get('is_dualtor', False)
        def_vlan_mac = self.test_params.get('def_vlan_mac', None)
        if is_dualtor and def_vlan_mac != None:
            sys.stderr.write("Since it's dual-TOR testbed, modify pkt_dst_mac from {} to {}\n".format(pkt_dst_mac, def_vlan_mac))
            pkt_dst_mac = def_vlan_mac

        pkt = construct_ip_pkt(64,
                               pkt_dst_mac,
                               src_port_mac,
                               src_port_ip,
                               dst_port_ip,
                               0,
                               src_port_vlan,
                               ttl=64)

        print("dst_port_id: %d, src_port_id: %d, src_port_vlan: %s" %
              (dst_port_id, src_port_id, src_port_vlan), file=sys.stderr)
        # in case dst_port_id is part of LAG, find out the actual dst port
        # for given IP parameters
        dst_port_id = get_rx_port(
            self, 0, src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip, src_port_vlan
        )
        print("actual dst_port_id: {}".format(dst_port_id), file=sys.stderr)

        self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])

        send_packet(self, src_port_id, pkt, pkts_num_leak_out)

        # Get a snapshot of counter values
        port_counters_base, queue_counters_base = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])

        # Send packets to each queue based on priority/dscp field
        for prio, pkt_cnt in zip(prio_list, q_pkt_cnt):
            pkt = construct_ip_pkt(default_packet_length,
                                   pkt_dst_mac,
                                   src_port_mac,
                                   src_port_ip,
                                   dst_port_ip,
                                   prio,
                                   src_port_vlan,
                                   ip_id=exp_ip_id,
                                   ecn=ecn,
                                   ttl=64)
            send_packet(self, src_port_id, pkt, pkt_cnt)

        # Set receiving socket buffers to some big value
        for p in list(self.dataplane.ports.values()):
            p.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 41943040)

        # Release port
        self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])

        cnt = 0
        pkts = []
        recv_pkt = scapy.Ether()

        while recv_pkt:
            received = self.dataplane.poll(
                device_number=0, port_number=dst_port_id, timeout=2)
            if isinstance(received, self.dataplane.PollFailure):
                recv_pkt = None
                break
            recv_pkt = scapy.Ether(received.packet)

            try:
                if recv_pkt[scapy.IP].src == src_port_ip and recv_pkt[scapy.IP].dst == dst_port_ip and recv_pkt[scapy.IP].id == exp_ip_id:
                    cnt += 1
                    pkts.append(recv_pkt)
            except AttributeError:
                continue
            except IndexError:
                # Ignore captured non-IP packet
                continue

        queue_pkt_counters = [0] * (prio_list[-1] + 1)
        queue_num_of_pkts = [0] * (prio_list[-1] + 1)
        for prio, q_cnt in zip(prio_list, q_pkt_cnt):
            queue_num_of_pkts[prio] = q_cnt

        total_pkts = 0

        diff_list = []

        for pkt_to_inspect in pkts:
            if 'backend' in topo:
                dscp_of_pkt = pkt_to_inspect[scapy.Dot1Q].prio
            else:
                dscp_of_pkt = pkt_to_inspect.payload.tos >> 2
            total_pkts += 1

            # Count packet ordering

            queue_pkt_counters[dscp_of_pkt] += 1
            if queue_pkt_counters[dscp_of_pkt] == queue_num_of_pkts[dscp_of_pkt]:
                 diff_list.append((dscp_of_pkt, q_cnt_sum - total_pkts))

            print(queue_pkt_counters, file=sys.stderr)

        print("Difference for each dscp: ", file=sys.stderr)
        print(diff_list, file=sys.stderr)

        for dscp, diff in diff_list:
           if platform_asic and platform_asic == "broadcom-dnx":
                logging.info("On J2C+ can't control how packets are dequeued (CS00012272267) - so ignoring diff check now")
           else:
                assert diff < limit, "Difference for %d is %d which exceeds limit %d" % (dscp, diff, limit)

        # Read counters
        print("DST port counters: ")
        port_counters, queue_counters = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
        print(list(map(operator.sub, queue_counters,
              queue_counters_base)), file=sys.stderr)

        # All packets sent should be received intact
        assert(q_cnt_sum == total_pkts)


class LossyQueueTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.clients)

        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        # The pfc counter index starts from index 2 in sai_thrift_read_port_counters
        pg = int(self.test_params['pg']) + 2
        sonic_version = self.test_params['sonic_version']
        router_mac = self.test_params['router_mac']
        max_buffer_size = int(self.test_params['buffer_max_size'])
        headroom_size = int(self.test_params['headroom_size'])
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        dst_port_2_id = int(self.test_params['dst_port_2_id'])
        dst_port_2_ip = self.test_params['dst_port_2_ip']
        dst_port_2_mac = self.dataplane.get_mac(0, dst_port_2_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_vlan = self.test_params['src_port_vlan']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        asic_type = self.test_params['sonic_asic_type']
        hwsku = self.test_params['hwsku']
        platform_asic = self.test_params['platform_asic']

        # get counter names to query
        ingress_counters, egress_counters = get_counter_names(sonic_version)

        # prepare tcp packet data
        ttl = 64

        pkts_num_leak_out = int(self.test_params['pkts_num_leak_out'])
        pkts_num_trig_egr_drp = int(self.test_params['pkts_num_trig_egr_drp'])
        if 'packet_size' in list(self.test_params.keys()):
            packet_length = int(self.test_params['packet_size'])
            cell_size = int(self.test_params['cell_size'])
            if packet_length != 64:
                cell_occupancy = (packet_length + cell_size - 1) // cell_size
                pkts_num_trig_egr_drp //= cell_occupancy
                # It is possible that pkts_num_trig_egr_drp * cell_occupancy < original pkts_num_trig_egr_drp,
                # which probably can fail the assert(xmit_counters[EGRESS_DROP] > xmit_counters_base[EGRESS_DROP])
                # due to not sending enough packets.
                # To avoid that we need a larger margin
        else:
            packet_length = 64

        pkt_dst_mac = router_mac if router_mac != '' else dst_port_mac
        pkt = construct_ip_pkt(packet_length,
                               pkt_dst_mac,
                               src_port_mac,
                               src_port_ip,
                               dst_port_ip,
                               dscp,
                               src_port_vlan,
                               ecn=ecn,
                               ttl=ttl)
        print("dst_port_id: %d, src_port_id: %d src_port_vlan: %s" %
              (dst_port_id, src_port_id, src_port_vlan), file=sys.stderr)
        # in case dst_port_id is part of LAG, find out the actual dst port
        # for given IP parameters
        dst_port_id = get_rx_port(
            self, 0, src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip, src_port_vlan
        )
        print("actual dst_port_id: %d" % (dst_port_id), file=sys.stderr)

        # get a snapshot of counter values at recv and transmit ports
        # queue_counters value is not of our interest here
        recv_counters_base, queue_counters = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
        xmit_counters_base, queue_counters = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
        # add slight tolerance in threshold characterization to consider
        # the case that cpu puts packets in the egress queue after we pause the egress
        # or the leak out is simply less than expected as we have occasionally observed
        if 'pkts_num_margin' in list(self.test_params.keys()):
            margin = int(self.test_params['pkts_num_margin'])
        else:
            margin = 2

        # For TH3, some packets stay in egress memory and doesn't show up in shared buffer or leakout
        if 'pkts_num_egr_mem' in list(self.test_params.keys()):
            pkts_num_egr_mem = int(self.test_params['pkts_num_egr_mem'])

        self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])

        try:
            # Since there is variability in packet leakout in hwsku Arista-7050CX3-32S-D48C8 and
            # Arista-7050CX3-32S-C32. Starting with zero pkts_num_leak_out and trying to find
            # actual leakout by sending packets and reading actual leakout from HW
            if hwsku == 'Arista-7050CX3-32S-D48C8' or hwsku == 'Arista-7050CX3-32S-C32' or \
                    hwsku == 'DellEMC-Z9332f-O32' or hwsku == 'DellEMC-Z9332f-M-O16C64':
                pkts_num_leak_out = 0

            if asic_type == 'cisco-8000':
                fill_leakout_plus_one(self, src_port_id, dst_port_id,
                       pkt, int(self.test_params['pg']), asic_type)

           # send packets short of triggering egress drop
            if hwsku == 'DellEMC-Z9332f-O32' or hwsku == 'DellEMC-Z9332f-M-O16C64':
               # send packets short of triggering egress drop
                send_packet(self, src_port_id, pkt, pkts_num_egr_mem +
                            pkts_num_leak_out + pkts_num_trig_egr_drp - 1 - margin)
            else:
               # send packets short of triggering egress drop
                send_packet(self, src_port_id, pkt, pkts_num_leak_out +
                            pkts_num_trig_egr_drp - 1 - margin)


            if hwsku == 'Arista-7050CX3-32S-D48C8' or hwsku == 'Arista-7050CX3-32S-C32' or \
                    hwsku == 'DellEMC-Z9332f-O32' or hwsku == 'DellEMC-Z9332f-M-O16C64':
                xmit_counters, queue_counters = sai_thrift_read_port_counters(
                    self.dst_client, asic_type, port_list['dst'][dst_port_id])
                actual_pkts_num_leak_out = xmit_counters[TRANSMITTED_PKTS] - xmit_counters_base[TRANSMITTED_PKTS]
                send_packet(self, src_port_id, pkt, actual_pkts_num_leak_out)

            # allow enough time for the dut to sync up the counter values in counters_db
            time.sleep(8)
            # get a snapshot of counter values at recv and transmit ports
            # queue counters value is not of our interest here
            recv_counters, queue_counters = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
            xmit_counters, queue_counters = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
            # recv port no pfc
            assert(recv_counters[pg] == recv_counters_base[pg])
            # recv port no ingress drop
            for cntr in ingress_counters:
                assert(recv_counters[cntr] == recv_counters_base[cntr])
            # xmit port no egress drop
            for cntr in egress_counters:
                assert(xmit_counters[cntr] == xmit_counters_base[cntr])

            # send 1 packet to trigger egress drop
            send_packet(self, src_port_id, pkt, 1 + 2 * margin)
            # allow enough time for the dut to sync up the counter values in counters_db
            time.sleep(8)
            # get a snapshot of counter values at recv and transmit ports
            # queue counters value is not of our interest here
            recv_counters, queue_counters = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
            xmit_counters, queue_counters = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
            # recv port no pfc
            assert(recv_counters[pg] == recv_counters_base[pg])
            # recv port no ingress drop
            for cntr in ingress_counters:
                if platform_asic and platform_asic == "broadcom-dnx" and cntr == 1:
                    assert (recv_counters[cntr] > recv_counters_base[cntr])
                else:
                    assert (recv_counters[cntr] == recv_counters_base[cntr])

            # xmit port egress drop
            if platform_asic and platform_asic == "broadcom-dnx":
                logging.info("On J2C+ don't support egress drop stats - so ignoring this step for now")
            else:
                for cntr in egress_counters:
                    assert(xmit_counters[cntr] > xmit_counters_base[cntr])

        finally:
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])


class LossyQueueVoqTest(sai_base_test.ThriftInterfaceDataPlane):
    def setUp(self):
        sai_base_test.ThriftInterfaceDataPlane.setUp(self)
        time.sleep(5)
        switch_init(self.clients)
        # Parse input parameters
        self.dscp = int(self.test_params['dscp'])
        self.ecn = int(self.test_params['ecn'])
        # The pfc counter index starts from index 2 in sai_thrift_read_port_counters
        self.pg = int(self.test_params['pg']) + 2
        self.sonic_version = self.test_params['sonic_version']
        self.dst_port_id = int(self.test_params['dst_port_id'])
        self.dst_port_ip = self.test_params['dst_port_ip']
        self.dst_port_mac = self.dataplane.get_mac(0, self.dst_port_id)
        router_mac = self.test_params['router_mac']
        if router_mac != '':
            self.dst_port_mac = router_mac
        self.dst_port_mac = router_mac if router_mac != '' else self.dst_port_mac
        self.src_port_id = int(self.test_params['src_port_id'])
        self.src_port_ip = self.test_params['src_port_ip']
        self.src_port_mac = self.dataplane.get_mac(0, self.src_port_id)
        self.asic_type = self.test_params['sonic_asic_type']
        self.flow_config = self.test_params['flow_config']
        self.pkts_num_leak_out = int(self.test_params['pkts_num_leak_out'])
        self.pkts_num_trig_egr_drp = int(self.test_params['pkts_num_trig_egr_drp'])
        if 'packet_size' in self.test_params.keys():
            self.packet_length = int(self.test_params['packet_size'])
            cell_size = int(self.test_params['cell_size'])
            if self.packet_length != 64:
                cell_occupancy = (self.packet_length + cell_size - 1) // cell_size
                self.pkts_num_trig_egr_drp //= cell_occupancy
        else:
            self.packet_length = 64
        self.ttl = 64

    def _build_testing_pkt(self, udp_dport):
        return simple_udp_packet(pktlen=self.packet_length,
                                 eth_dst=self.dst_port_mac,
                                 eth_src=self.src_port_mac,
                                 ip_src=self.src_port_ip,
                                 ip_dst=self.dst_port_ip,
                                 ip_tos=((self.dscp << 2) | self.ecn),
                                 udp_sport=1024,
                                 udp_dport=udp_dport,
                                 ip_ecn=self.ecn,
                                 ip_ttl=self.ttl)

    def runTest(self):
        print("dst_port_id: {}, src_port_id: {}".format(self.dst_port_id, self.src_port_id), file=sys.stderr)
        # get counter names to query
        ingress_counters, egress_counters = get_counter_names(self.sonic_version)

        # craft first udp packet with unique udp_dport for traffic to go through different flows
        flow_1_udp = 2048
        pkt = self._build_testing_pkt(flow_1_udp)

        xmit_counters_base, _ = sai_thrift_read_port_counters(self.dst_client, self.asic_type,
                                                              port_list['dst'][self.dst_port_id])
        # add slight tolerance in threshold characterization to consider
        # the case that npu puts packets in the egress queue after we pause the egress
        # or the leak out is simply less than expected as we have occasionally observed
        if 'pkts_num_margin' in self.test_params.keys():
            margin = int(self.test_params['pkts_num_margin'])
        else:
            margin = 2

        self.sai_thrift_port_tx_disable(self.dst_client, self.asic_type, [self.dst_port_id])

        try:
            # send packets to begin egress drop on flow1, requires sending the "single"
            # flow packet count to cause a drop with 1 flow.
            fill_leakout_plus_one(self, self.src_port_id, self.dst_port_id, pkt,
                                  int(self.test_params['pg']), self.asic_type)
            send_packet(self, self.src_port_id, pkt, self.pkts_num_trig_egr_drp)
            time.sleep(2)
            # Verify egress drop
            xmit_counters, _ = sai_thrift_read_port_counters(self.dst_client, self.asic_type,
                                                             port_list['dst'][self.dst_port_id])
            for cntr in egress_counters:
                diff = xmit_counters[cntr] - xmit_counters_base[cntr]
                assert diff > 0, "Failed to cause TX drop on port {}".format(self.dst_port_id)
            xmit_counters_base = xmit_counters
            # Find a separate flow that uses alternate queue
            max_iters = 50
            for i in range(max_iters):
                 # Start out with i=0 to match flow_1 to confirm drop
                flow_2_udp = flow_1_udp + (10 * i)
                pkt2 = self._build_testing_pkt(flow_2_udp)
                xmit_counters_base = xmit_counters
                send_packet(self, self.src_port_id, pkt2, 1)
                time.sleep(2)
                xmit_counters, _ = sai_thrift_read_port_counters(self.dst_client, self.asic_type,
                                                                 port_list['dst'][self.dst_port_id])
                drop_counts = [xmit_counters[cntr] - xmit_counters_base[cntr] for cntr in egress_counters]
                assert len(set(drop_counts)) == 1, \
                    "Egress drop counters were different at port {}, counts: {}".format(self.dst_port_id, drop_counts)
                drop_count = drop_counts[0]
                if flow_2_udp == flow_1_udp:
                    assert drop_count == 1, "Failed to reproduce drop to detect alternate flow"
                else:
                    assert drop_count in [0, 1], \
                        "Unexpected drop count when sending a single packet, drops {}".format(drop_count)
                    if drop_count == 0:
                        print("Second flow detected on udp_dport {} in mode '{}'".format(flow_2_udp, self.flow_config), file=sys.stderr)
                        assert self.flow_config == "separate", "Identified a second flow despite being in mode '{}'".format(flow_config)
                        break
            else:
                print("Did not find a second flow in mode '{}'".format(self.flow_config), file=sys.stderr)
                assert self.flow_config == "shared", "Failed to find a flow that uses a second queue despite being in mode '{}'".format(self.flow_config)
            # Cleanup for multi-flow test
            self.sai_thrift_port_tx_enable(self.dst_client, self.asic_type, [self.dst_port_id])
            time.sleep(2)
            # Test multi-flow with detected multi-flow udp ports
            self.sai_thrift_port_tx_disable(self.dst_client, self.asic_type, [self.dst_port_id])
            recv_counters_base, _ = sai_thrift_read_port_counters(self.src_client, self.asic_type,
                                                                  port_list['src'][self.src_port_id])
            xmit_counters_base, _ = sai_thrift_read_port_counters(self.dst_client, self.asic_type,
                                                                  port_list['dst'][self.dst_port_id])
            fill_leakout_plus_one(self, self.src_port_id, self.dst_port_id, pkt,
                                  int(self.test_params['pg']), self.asic_type)
            multi_flow_drop_pkt_count = self.pkts_num_trig_egr_drp
            if self.flow_config == 'shared':
                # When sharing queueing space for multiple flows, divide by the number of flows
                multi_flow_drop_pkt_count //= 2
            # send packets short of triggering egress drop on both flows, uses the
            # "multiple" packet count to cause a drop when 2 flows are present.
            short_of_drop_npkts = self.pkts_num_leak_out + multi_flow_drop_pkt_count - 1 - margin
            print("Sending {} packets on each of 2 streams to approach drop".format(short_of_drop_npkts), file=sys.stderr)
            send_packet(self, self.src_port_id, pkt, short_of_drop_npkts)
            send_packet(self, self.src_port_id, pkt2, short_of_drop_npkts)
            # allow enough time for counters to update
            time.sleep(2)
            recv_counters, _ = sai_thrift_read_port_counters(self.src_client, self.asic_type,
                                                             port_list['src'][self.src_port_id])
            xmit_counters, _ = sai_thrift_read_port_counters(self.dst_client, self.asic_type,
                                                             port_list['dst'][self.dst_port_id])
            # recv port no pfc
            diff = recv_counters[self.pg] - recv_counters_base[self.pg]
            assert diff == 0, "Unexpected PFC frames {}".format(diff)
            # recv port no ingress drop
            for cntr in ingress_counters:
                diff = recv_counters[cntr] - recv_counters_base[cntr]
                assert diff == 0, "Unexpected ingress drop {} on port {}".format(diff, self.src_port_id)
            # xmit port no egress drop
            for cntr in egress_counters:
                diff = xmit_counters[cntr] - xmit_counters_base[cntr]
                assert diff == 0, "Unexpected TX drop {} on port {}".format(diff, self.dst_port_id)

            # send 1 packet to trigger egress drop
            npkts = 1 + 2 * margin
            print("Sending {} packets on 2 streams to trigger drop".format(npkts), file=sys.stderr)
            send_packet(self, self.src_port_id, pkt, npkts)
            send_packet(self, self.src_port_id, pkt2, npkts)
            # allow enough time for counters to update
            time.sleep(2)
            recv_counters, _ = sai_thrift_read_port_counters(self.src_client, self.asic_type, port_list['src'][self.src_port_id])
            xmit_counters, _ = sai_thrift_read_port_counters(self.dst_client, self.asic_type, port_list['dst'][self.dst_port_id])
            # recv port no pfc
            diff = recv_counters[self.pg] - recv_counters_base[self.pg]
            assert diff == 0, "Unexpected PFC frames {}".format(diff)
            # recv port no ingress drop
            for cntr in ingress_counters:
                diff = recv_counters[cntr] - recv_counters_base[cntr]
                assert diff == 0, "Unexpected ingress drop {} on port {}".format(diff, self.src_port_id)
            # xmit port egress drop
            for cntr in egress_counters:
                drops = xmit_counters[cntr] - xmit_counters_base[cntr]
                assert drops > 0, "Failed to detect egress drops ({})".format(drops)
            print("Successfully dropped {} packets".format(drops), file=sys.stderr)
        finally:
            self.sai_thrift_port_tx_enable(self.dst_client, self.asic_type, [self.dst_port_id])


# pg shared pool applied to both lossy and lossless traffic


class PGSharedWatermarkTest(sai_base_test.ThriftInterfaceDataPlane):

    def show_stats(self, banner,
                   asic_type, pg, src_port_id, dst_port_id, ingress_counters, egress_counters,
                   sport_cntr_base, sport_pg_cntr_base, sport_pg_share_wm_base,
                   dport_cntr_base, dport_pg_cntr_base, dport_pg_share_wm_base,
                   sport_cntr, sport_pg_cntr, sport_pg_share_wm,
                   dport_cntr, dport_pg_cntr, dport_pg_share_wm):
        port_counter_indexes = [pg + 2]
        port_counter_indexes += ingress_counters
        port_counter_indexes += egress_counters
        port_counter_indexes += [TRANSMITTED_PKTS, RECEIVED_PKTS, RECEIVED_NON_UC_PKTS, TRANSMITTED_NON_UC_PKTS, EGRESS_PORT_QLEN]
        stats_tbl = texttable.TextTable(['']
                                      + [port_counter_fields[fieldIdx] for fieldIdx in port_counter_indexes]
                                      + ['Ing Pg{} Pkt'.format(pg)]
                                      + ['Ing Pg{} Share Wm'.format(pg)])
        if sport_cntr == None:
            sport_cntr, _ = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
        if sport_pg_cntr == None:
            sport_pg_cntr = sai_thrift_read_pg_counters(self.src_client, port_list['src'][src_port_id])
        if sport_pg_share_wm == None:
            sport_pg_share_wm = sai_thrift_read_pg_shared_watermark(self.src_client, asic_type, port_list['src'][src_port_id])
        if dport_cntr == None:
            dport_cntr, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
        if dport_pg_cntr == None:
            dport_pg_cntr = sai_thrift_read_pg_counters(self.dst_client, port_list['dst'][dst_port_id])
        if dport_pg_share_wm == None:
            dport_pg_share_wm = sai_thrift_read_pg_shared_watermark(self.dst_client, asic_type, port_list['dst'][dst_port_id])
        stats_tbl.add_row(['base src port']
                        + [sport_cntr_base[fieldIdx] for fieldIdx in port_counter_indexes]
                        + [sport_pg_cntr_base[pg]]
                        + [sport_pg_share_wm_base[pg]])
        stats_tbl.add_row(['     src port']
                        + [sport_cntr[fieldIdx] for fieldIdx in port_counter_indexes]
                        + [sport_pg_cntr[pg]]
                        + [sport_pg_share_wm[pg]])
        stats_tbl.add_row(['base dst port']
                        + [dport_cntr_base[fieldIdx] for fieldIdx in port_counter_indexes]
                        + [dport_pg_cntr_base[pg]]
                        + [dport_pg_share_wm_base[pg]])
        stats_tbl.add_row(['     dst port']
                        + [dport_cntr[fieldIdx] for fieldIdx in port_counter_indexes]
                        + [dport_pg_cntr[pg]]
                        + [dport_pg_share_wm[pg]])
        sys.stderr.write('{}\n{}\n'.format(banner, stats_tbl))

    def runTest(self):
        time.sleep(5)
        switch_init(self.clients)

        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        print("router_mac: %s" % (router_mac), file=sys.stderr)
        pg = int(self.test_params['pg'])
        ingress_counters, egress_counters = get_counter_names(self.test_params['sonic_version'])
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_vlan = self.test_params['src_port_vlan']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)

        asic_type = self.test_params['sonic_asic_type']
        pkts_num_leak_out = int(self.test_params['pkts_num_leak_out'])
        pkts_num_fill_min = int(self.test_params['pkts_num_fill_min'])
        pkts_num_fill_shared = int(self.test_params['pkts_num_fill_shared'])
        cell_size = int(self.test_params['cell_size'])
        hwsku = self.test_params['hwsku']
        internal_hdr_size = self.test_params.get('internal_hdr_size', 0)
        platform_asic = self.test_params['platform_asic']

        if 'packet_size' in list(self.test_params.keys()):
            packet_length = int(self.test_params['packet_size'])
        else:
            packet_length = 64

        cell_occupancy = (packet_length + cell_size - 1) // cell_size

        # Prepare TCP packet data
        ttl = 64
        pkt_dst_mac = router_mac if router_mac != '' else dst_port_mac
        pkt = construct_ip_pkt(packet_length,
                               pkt_dst_mac,
                               src_port_mac,
                               src_port_ip,
                               dst_port_ip,
                               dscp,
                               src_port_vlan,
                               ecn=ecn,
                               ttl=ttl)

        print("dst_port_id: %d, src_port_id: %d src_port_vlan: %s" %
              (dst_port_id, src_port_id, src_port_vlan), file=sys.stderr)
        # in case dst_port_id is part of LAG, find out the actual dst port
        # for given IP parameters
        dst_port_id = get_rx_port(
            self, 0, src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip, src_port_vlan
        )
        print("actual dst_port_id: %d" % (dst_port_id), file=sys.stderr)

        # Add slight tolerance in threshold characterization to consider
        # the case that cpu puts packets in the egress queue after we pause the egress
        # or the leak out is simply less than expected as we have occasionally observed
        if hwsku == 'DellEMC-Z9332f-O32' or hwsku == 'DellEMC-Z9332f-M-O16C64':
            margin = int(self.test_params['pkts_num_margin'])
        else:
            margin = int(self.test_params['pkts_num_margin']) if self.test_params.get(
                "pkts_num_margin") else 2

        # Get a snapshot of counter values
        recv_counters_base, _ = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
        xmit_counters_base, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])

        # For TH3, some packets stay in egress memory and doesn't show up in shared buffer or leakout
        if 'pkts_num_egr_mem' in list(self.test_params.keys()):
            pkts_num_egr_mem = int(self.test_params['pkts_num_egr_mem'])

        self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])
        pg_cntrs_base = sai_thrift_read_pg_counters(self.src_client, port_list['src'][src_port_id])
        dst_pg_cntrs_base = sai_thrift_read_pg_counters(self.dst_client, port_list['dst'][dst_port_id])
        pg_shared_wm_res_base = sai_thrift_read_pg_shared_watermark(self.src_client, asic_type, port_list['src'][src_port_id])
        dst_pg_shared_wm_res_base = sai_thrift_read_pg_shared_watermark(self.dst_client, asic_type, port_list['dst'][dst_port_id])

        # send packets
        try:
            # Since there is variability in packet leakout in hwsku Arista-7050CX3-32S-D48C8 and
            # Arista-7050CX3-32S-C32. Starting with zero pkts_num_leak_out and trying to find
            # actual leakout by sending packets and reading actual leakout from HW
            if check_leackout_compensation_support(asic_type, hwsku):
                pkts_num_leak_out = 0

            xmit_counters_history, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
            pg_min_pkts_num = 0

            # send packets to fill pg min but not trek into shared pool
            # so if pg min is zero, it directly treks into shared pool by 1
            # this is the case for lossy traffic
            if hwsku == 'DellEMC-Z9332f-O32' or hwsku == 'DellEMC-Z9332f-M-O16C64':
                pg_min_pkts_num = pkts_num_egr_mem + pkts_num_leak_out + pkts_num_fill_min + margin
                send_packet(self, src_port_id, pkt, pg_min_pkts_num)
            elif 'cisco-8000' in asic_type:
                fill_leakout_plus_one(
                    self, src_port_id, dst_port_id, pkt, pg, asic_type)
            else:
                pg_min_pkts_num = pkts_num_leak_out + pkts_num_fill_min
                send_packet(self, src_port_id, pkt, pg_min_pkts_num)

            # allow enough time for the dut to sync up the counter values in counters_db
            time.sleep(8)

            if pg_min_pkts_num > 0 and check_leackout_compensation_support(asic_type, hwsku):
                dynamically_compensate_leakout(self.src_client, asic_type, sai_thrift_read_port_counters, port_list['dst'][dst_port_id], TRANSMITTED_PKTS, xmit_counters_history, self, src_port_id, pkt, 40)

            pg_cntrs = sai_thrift_read_pg_counters(
                self.src_client, port_list['src'][src_port_id])
            pg_shared_wm_res = sai_thrift_read_pg_shared_watermark(
                self.src_client, asic_type, port_list['src'][src_port_id])
            print("Received packets: %d" %
                  (pg_cntrs[pg] - pg_cntrs_base[pg]), file=sys.stderr)
            print("Init pkts num sent: %d, min: %d, actual watermark value to start: %d" % (
                pg_min_pkts_num, pkts_num_fill_min, pg_shared_wm_res[pg]), file=sys.stderr)

            self.show_stats('Filled PG min',
                   asic_type, pg, src_port_id, dst_port_id, ingress_counters, egress_counters,
                   recv_counters_base, pg_cntrs_base, pg_shared_wm_res_base,
                   xmit_counters_base, dst_pg_cntrs_base, dst_pg_shared_wm_res_base,
                   None, pg_cntrs, pg_shared_wm_res,
                   None, None, None)

            if pkts_num_fill_min:
                if platform_asic and platform_asic == "broadcom-dnx":
                    assert(pg_shared_wm_res[pg] <=
                           ((pkts_num_leak_out + pkts_num_fill_min) * (packet_length + internal_hdr_size)))
                else:
                    assert(pg_shared_wm_res[pg] == 0)
            else:
                # on t1-lag, we found vm will keep sending control
                # packets, this will cause the watermark to be 2 * 208 bytes
                # as all lossy packets are now mapped to single pg 0
                # so we remove the strict equity check, and use upper bound
                # check instead
                assert(pg_shared_wm_res[pg] <= margin * cell_size)

            # send packet batch of fixed packet numbers to fill pg shared
            # first round sends only 1 packet
            expected_wm = 0
            total_shared = pkts_num_fill_shared - pkts_num_fill_min
            pkts_inc = (total_shared // cell_occupancy) >> 2
            if 'cisco-8000' in asic_type:
                # No additional packet margin needed while sending,
                # but small margin still needed during boundary checks below
                pkts_num = 1
            else:
                pkts_num = 1 + margin
            fragment = 0
            while (expected_wm < total_shared - fragment):
                expected_wm += pkts_num * cell_occupancy
                if (expected_wm > total_shared):
                    diff = (expected_wm - total_shared +
                            cell_occupancy - 1) // cell_occupancy
                    pkts_num -= diff
                    expected_wm -= diff * cell_occupancy
                    fragment = total_shared - expected_wm
                print("pkts num to send: %d, total pkts: %d, pg shared: %d" %
                      (pkts_num, expected_wm, total_shared), file=sys.stderr)

                send_packet(self, src_port_id, pkt,int(pkts_num))
                time.sleep(8)

                if pg_min_pkts_num == 0 and pkts_num <= 1 + margin and check_leackout_compensation_support(asic_type, hwsku):
                    dynamically_compensate_leakout(self.src_client, asic_type, sai_thrift_read_port_counters, port_list['dst'][dst_port_id], TRANSMITTED_PKTS, xmit_counters_history, self, src_port_id, pkt, 40)

                # these counters are clear on read, ensure counter polling
                # is disabled before the test

                pg_shared_wm_res = sai_thrift_read_pg_shared_watermark(
                    self.src_client, asic_type, port_list['src'][src_port_id])
                pg_cntrs = sai_thrift_read_pg_counters(
                    self.src_client, port_list['src'][src_port_id])
                print("Received packets: %d" %
                      (pg_cntrs[pg] - pg_cntrs_base[pg]), file=sys.stderr)


                self.show_stats('To fill PG share pool, send {} pkt'.format(pkts_num),
                    asic_type, pg, src_port_id, dst_port_id, ingress_counters, egress_counters,
                    recv_counters_base, pg_cntrs_base, pg_shared_wm_res_base,
                    xmit_counters_base, dst_pg_cntrs_base, dst_pg_shared_wm_res_base,
                    None, pg_cntrs, pg_shared_wm_res,
                    None, None, None)

                if platform_asic and platform_asic == "broadcom-dnx":
                    print("lower bound: %d, actual value: %d, upper bound (+%d): %d" % (expected_wm * cell_size,
                                pg_shared_wm_res[pg], margin, (expected_wm + margin) * (packet_length + internal_hdr_size)),file=sys.stderr)
                    assert (pg_shared_wm_res[pg] <=
                            ((pkts_num_leak_out + pkts_num_fill_min + expected_wm + margin) * (packet_length + internal_hdr_size)))
                else:
                    print("lower bound: %d, actual value: %d, upper bound (+%d): %d" % (expected_wm * cell_size,
                                 pg_shared_wm_res[pg], margin, (expected_wm + margin) * cell_size),file=sys.stderr)
                    assert(pg_shared_wm_res[pg] <= (
                            expected_wm + margin) * cell_size)
                    assert(expected_wm * cell_size <= pg_shared_wm_res[pg])

                pkts_num = pkts_inc

            # overflow the shared pool
            send_packet(self, src_port_id, pkt, pkts_num)
            time.sleep(8)
            pg_shared_wm_res = sai_thrift_read_pg_shared_watermark(
                self.src_client, asic_type, port_list['src'][src_port_id])
            pg_cntrs = sai_thrift_read_pg_counters(
                self.src_client, port_list['src'][src_port_id])
            print("Received packets: %d" %
                  (pg_cntrs[pg] - pg_cntrs_base[pg]), file=sys.stderr)

            self.show_stats('To overflow PG share pool, send {} pkt'.format(pkts_num),
                asic_type, pg, src_port_id, dst_port_id, ingress_counters, egress_counters,
                recv_counters_base, pg_cntrs_base, pg_shared_wm_res_base,
                xmit_counters_base, dst_pg_cntrs_base, dst_pg_shared_wm_res_base,
                None, pg_cntrs, pg_shared_wm_res,
                None, None, None)

            assert(fragment < cell_occupancy)

            if platform_asic and platform_asic == "broadcom-dnx":
                print("exceeded pkts num sent: %d, expected watermark: %d, actual value: %d" % (
                    pkts_num, ((expected_wm + cell_occupancy) * (packet_length + internal_hdr_size)), pg_shared_wm_res[pg]), file=sys.stderr)
                assert (expected_wm * (packet_length + internal_hdr_size) <= (
                        expected_wm + margin + cell_occupancy) * (packet_length + internal_hdr_size))
            else:
                print("exceeded pkts num sent: %d, expected watermark: %d, actual value: %d" % (
                    pkts_num, ((expected_wm + cell_occupancy) * cell_size), pg_shared_wm_res[pg]), file=sys.stderr)
                assert (expected_wm * cell_size <= pg_shared_wm_res[pg] <= (
                        expected_wm + margin + cell_occupancy) * cell_size)
        finally:
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])

# pg headroom is a notion for lossless traffic only


class PGHeadroomWatermarkTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        time.sleep(5)
        switch_init(self.clients)

        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        print("router_mac: %s" % (router_mac), file=sys.stderr)
        pg = int(self.test_params['pg'])
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_vlan = self.test_params['src_port_vlan']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)

        asic_type = self.test_params['sonic_asic_type']
        pkts_num_leak_out = int(self.test_params['pkts_num_leak_out'])
        pkts_num_trig_pfc = int(self.test_params['pkts_num_trig_pfc'])
        pkts_num_trig_ingr_drp = int(
            self.test_params['pkts_num_trig_ingr_drp'])
        cell_size = int(self.test_params['cell_size'])
        hwsku = self.test_params['hwsku']
        platform_asic = self.test_params['platform_asic']

        # Prepare TCP packet data
        ttl = 64
        if 'packet_size' in self.test_params:
            default_packet_length = self.test_params['packet_size']
        else:
            default_packet_length = 64

        cell_occupancy = (default_packet_length + cell_size - 1) // cell_size
        pkt_dst_mac = router_mac if router_mac != '' else dst_port_mac
        is_dualtor = self.test_params.get('is_dualtor', False)
        def_vlan_mac = self.test_params.get('def_vlan_mac', None)
        if is_dualtor and def_vlan_mac != None:
            pkt_dst_mac = def_vlan_mac
        pkt = construct_ip_pkt(default_packet_length,
                               pkt_dst_mac,
                               src_port_mac,
                               src_port_ip,
                               dst_port_ip,
                               dscp,
                               src_port_vlan,
                               ecn=ecn,
                               ttl=ttl)

        print("dst_port_id: %d, src_port_id: %d, src_port_vlan: %s" %
              (dst_port_id, src_port_id, src_port_vlan), file=sys.stderr)
        # in case dst_port_id is part of LAG, find out the actual dst port
        # for given IP parameters
        dst_port_id = get_rx_port(
            self, 0, src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip, src_port_vlan
        )
        print("actual dst_port_id: %d" % (dst_port_id), file=sys.stderr)

        # Add slight tolerance in threshold characterization to consider
        # the case that cpu puts packets in the egress queue after we pause the egress
        # or the leak out is simply less than expected as we have occasionally observed
        if 'pkts_num_margin' in list(self.test_params.keys()):
            margin = int(self.test_params['pkts_num_margin'])
        else:
            margin = 0

        # For TH3, some packets stay in egress memory and doesn't show up in shared buffer or leakout
        if 'pkts_num_egr_mem' in list(self.test_params.keys()):
            pkts_num_egr_mem = int(self.test_params['pkts_num_egr_mem'])

        self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])

        xmit_counters_base, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])

        # send packets
        try:
            # Starting with zero pkts_num_leak_out and trying to find
            # actual leakout by sending packets and reading actual leakout from HW.
            if check_leackout_compensation_support(asic_type, hwsku):
                pkts_num_leak_out = 0

            # send packets to trigger pfc but not trek into headroom
            if hwsku == 'DellEMC-Z9332f-O32' or hwsku == 'DellEMC-Z9332f-M-O16C64':
                send_packet(self, src_port_id, pkt, (pkts_num_egr_mem +
                            pkts_num_leak_out + pkts_num_trig_pfc) // cell_occupancy - margin)
            else:
                send_packet(self, src_port_id, pkt, (pkts_num_leak_out +
                            pkts_num_trig_pfc) // cell_occupancy - margin)

            time.sleep(8)

            if check_leackout_compensation_support(asic_type, hwsku):
                dynamically_compensate_leakout(self.dst_client, asic_type, sai_thrift_read_port_counters, port_list['dst'][dst_port_id], TRANSMITTED_PKTS, xmit_counters_base, self, src_port_id, pkt, 30)

            q_wm_res, pg_shared_wm_res, pg_headroom_wm_res = sai_thrift_read_port_watermarks(self.src_client, port_list['src'][src_port_id])
            if platform_asic and platform_asic == "broadcom-dnx":
                logging.info ("On J2C+ don't support SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES " + \
                              "stat - so ignoring this step for now")
            else:
                assert(pg_headroom_wm_res[pg] == 0)

            send_packet(self, src_port_id, pkt, margin)

            # send packet batch of fixed packet numbers to fill pg headroom
            # first round sends only 1 packet
            expected_wm = 0
            total_hdrm = (pkts_num_trig_ingr_drp -
                          pkts_num_trig_pfc) // cell_occupancy - 1
            pkts_inc = total_hdrm >> 2
            pkts_num = 1 + margin
            while (expected_wm < total_hdrm):
                expected_wm += pkts_num
                if (expected_wm > total_hdrm):
                    pkts_num -= (expected_wm - total_hdrm)
                    expected_wm = total_hdrm
                print("pkts num to send: %d, total pkts: %d, pg headroom: %d" %
                      (pkts_num, expected_wm, total_hdrm), file=sys.stderr)

                send_packet(self, src_port_id, pkt, pkts_num)
                time.sleep(8)
                # these counters are clear on read, ensure counter polling
                # is disabled before the test
                q_wm_res, pg_shared_wm_res, pg_headroom_wm_res = sai_thrift_read_port_watermarks(
                    self.src_client, port_list['src'][src_port_id])

                print("lower bound: %d, actual value: %d, upper bound: %d" % ((expected_wm - margin) * cell_size *
                      cell_occupancy, pg_headroom_wm_res[pg], ((expected_wm + margin) * cell_size * cell_occupancy)), file=sys.stderr)

                if platform_asic and platform_asic == "broadcom-dnx":
                    logging.info("On J2C+ don't support SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES " + \
                                 "stat - so ignoring this step for now")
                else:
                    assert(pg_headroom_wm_res[pg] <= (
                         expected_wm + margin) * cell_size * cell_occupancy)
                    assert((expected_wm - margin) * cell_size *
                         cell_occupancy <= pg_headroom_wm_res[pg])

                pkts_num = pkts_inc

            # overflow the headroom
            send_packet(self, src_port_id, pkt, pkts_num)
            time.sleep(8)
            q_wm_res, pg_shared_wm_res, pg_headroom_wm_res = sai_thrift_read_port_watermarks(
                self.src_client, port_list['src'][src_port_id])
            print("exceeded pkts num sent: %d" % (pkts_num), file=sys.stderr)
            print("lower bound: %d, actual value: %d, upper bound: %d" %
                  ((expected_wm - margin) * cell_size * cell_occupancy, pg_headroom_wm_res[pg],
                   ((expected_wm + margin) * cell_size * cell_occupancy)), file=sys.stderr)
            assert(expected_wm == total_hdrm)

            if platform_asic and platform_asic == "broadcom-dnx":
                logging.info("On J2C+ don't support SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES " + \
                             "stat - so ignoring this step for now")
            else:
                assert(pg_headroom_wm_res[pg] <= (
                    expected_wm + margin) * cell_size * cell_occupancy)
                assert((expected_wm - margin) * cell_size *
                    cell_occupancy <= pg_headroom_wm_res[pg])

        finally:
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])

class PGDropTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        time.sleep(5)
        switch_init(self.clients)

        # Parse input parameters
        dscp=int(self.test_params['dscp'])
        ecn=int(self.test_params['ecn'])
        router_mac=self.test_params['router_mac']
        pg=int(self.test_params['pg'])
        queue=int(self.test_params['queue'])
        dst_port_id=int(self.test_params['dst_port_id'])
        dst_port_ip=self.test_params['dst_port_ip']
        dst_port_mac=self.dataplane.get_mac(0, dst_port_id)
        src_port_id=int(self.test_params['src_port_id'])
        src_port_ip=self.test_params['src_port_ip']
        src_port_vlan=self.test_params['src_port_vlan']
        src_port_mac=self.dataplane.get_mac(0, src_port_id)
        asic_type=self.test_params['sonic_asic_type']
        pkts_num_trig_pfc=int(self.test_params['pkts_num_trig_pfc'])
        # Should be set to cause at least 1 drop at ingress
        pkts_num_trig_ingr_drp=int(self.test_params['pkts_num_trig_ingr_drp'])
        iterations=int(self.test_params['iterations'])
        margin=int(self.test_params['pkts_num_margin'])

        pkt_dst_mac=router_mac if router_mac != '' else dst_port_mac
        dst_port_id=get_rx_port(
            self, 0, src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip
        )

        # Prepare IP packet data
        ttl=64
        packet_length=64
        pkt=construct_ip_pkt(packet_length,
                               pkt_dst_mac,
                               src_port_mac,
                               src_port_ip,
                               dst_port_ip,
                               dscp,
                               src_port_vlan,
                               ecn=ecn,
                               ttl=ttl)

        print("test dst_port_id: {}, src_port_id: {}, src_vlan: {}".format(
            dst_port_id, src_port_id, src_port_vlan
        ), file=sys.stderr)

        try:
            pass_iterations=0
            assert iterations > 0, "Need at least 1 iteration"
            for test_i in range(iterations):
                self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])

                pg_dropped_cntrs_base=sai_thrift_read_pg_drop_counters(
                    self.src_client, port_list['src'][src_port_id])

                # Send packets to trigger PFC
                print("Iteration {}/{}, sending {} packets to trigger PFC".format(
                    test_i + 1, iterations, pkts_num_trig_pfc), file=sys.stderr)
                send_packet(self, src_port_id, pkt, pkts_num_trig_pfc)

                # Account for leakout
                if 'cisco-8000' in asic_type:
                    queue_counters=sai_thrift_read_queue_occupancy(
                        self.dst_client, "dst", dst_port_id)
                    occ_pkts=queue_counters[queue] // (packet_length + 24)
                    leaked_pkts=pkts_num_trig_pfc - occ_pkts
                    print("resending leaked packets {}".format(
                        leaked_pkts))
                    send_packet(self, src_port_id, pkt, leaked_pkts)

                # Trigger drop
                pkt_inc=pkts_num_trig_ingr_drp + margin - pkts_num_trig_pfc
                print("sending {} additional packets to trigger ingress drop".format(
                    pkt_inc), file=sys.stderr)
                send_packet(self, src_port_id, pkt, pkt_inc)

                pg_dropped_cntrs=sai_thrift_read_pg_drop_counters(
                    self.src_client, port_list['src'][src_port_id])
                pg_drops=pg_dropped_cntrs[pg] - pg_dropped_cntrs_base[pg]

                actual_num_trig_ingr_drp=pkts_num_trig_ingr_drp + \
                    margin - (pg_drops - 1)
                ingr_drop_diff=actual_num_trig_ingr_drp - pkts_num_trig_ingr_drp
                if abs(ingr_drop_diff) < margin:
                    pass_iterations += 1
                print("expected trig drop: {}, actual trig drop: {}, diff: {}".format(
                    pkts_num_trig_ingr_drp, actual_num_trig_ingr_drp, ingr_drop_diff), file=sys.stderr)

                self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])

            print("pass iterations: {}, total iterations: {}, margin: {}".format(
                pass_iterations, iterations, margin), file=sys.stderr)
            assert pass_iterations >= int(
                0.75 * iterations), "Passed iterations {} insufficient to meet minimum required iterations {}".format(
                pass_iterations, int(0.75 * iterations))

        finally:
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])

class QSharedWatermarkTest(sai_base_test.ThriftInterfaceDataPlane):

    def show_stats(self, banner, asic_type,
                   que, src_port_id, dst_port_id, ingress_counters, egress_counters,
                   sport_cntr_base, sport_pg_cntr_base, sport_pg_share_wm_base, sport_pg_headroom_wm_base, sport_que_share_wm_base,
                   dport_cntr_base, dport_pg_cntr_base, dport_pg_share_wm_base, dport_pg_headroom_wm_base, dport_que_share_wm_base,
                   sport_cntr, sport_pg_cntr, sport_pg_share_wm, sport_pg_headroom_wm, sport_que_share_wm,
                   dport_cntr, dport_pg_cntr, dport_pg_share_wm, dport_pg_headroom_wm, dport_que_share_wm):
        port_counter_indexes = [que + 2]
        port_counter_indexes += ingress_counters
        port_counter_indexes += egress_counters
        port_counter_indexes += [TRANSMITTED_PKTS, RECEIVED_PKTS, RECEIVED_NON_UC_PKTS, TRANSMITTED_NON_UC_PKTS, EGRESS_PORT_QLEN]
        stats_tbl = texttable.TextTable(['']
                                      + [port_counter_fields[fieldIdx] for fieldIdx in port_counter_indexes]
                                      + ['Ing Pg{} Pkt'.format(que)]
                                      + ['Ing Pg{} Share Wm'.format(que)]
                                      + ['Ing Pg{} headroom Wm'.format(que)]
                                      + ['Que{} Share Wm'.format(que)])

        if sport_cntr == None:
            sport_cntr, _ = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
        if sport_pg_cntr == None:
            sport_pg_cntr = sai_thrift_read_pg_counters(self.src_client, port_list['src'][src_port_id])
        if None in [sport_pg_share_wm, sport_pg_headroom_wm, sport_que_share_wm]:
            sport_que_share_wm, sport_pg_share_wm, sport_pg_headroom_wm = \
                sai_thrift_read_port_watermarks(self.src_client, port_list['src'][src_port_id])

        if dport_cntr == None:
            dport_cntr, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
        if dport_pg_cntr == None:
            dport_pg_cntr = sai_thrift_read_pg_counters(self.dst_client, port_list['dst'][dst_port_id])
        if None in [dport_pg_share_wm, dport_pg_headroom_wm, dport_que_share_wm]:
            dport_que_share_wm, dport_pg_share_wm, dport_pg_headroom_wm = \
                sai_thrift_read_port_watermarks(self.src_client, port_list['dst'][dst_port_id])

        stats_tbl.add_row(['base src port']
                        + [sport_cntr_base[fieldIdx] for fieldIdx in port_counter_indexes]
                        + [sport_pg_cntr_base[que]]
                        + [sport_pg_share_wm_base[que]]
                        + [sport_pg_headroom_wm_base[que]]
                        + [sport_que_share_wm_base[que]])
        stats_tbl.add_row(['     src port']
                        + [sport_cntr[fieldIdx] for fieldIdx in port_counter_indexes]
                        + [sport_pg_cntr[que]]
                        + [sport_pg_share_wm[que]]
                        + [sport_pg_headroom_wm[que]]
                        + [sport_que_share_wm[que]])
        stats_tbl.add_row(['base dst port']
                        + [dport_cntr_base[fieldIdx] for fieldIdx in port_counter_indexes]
                        + [dport_pg_cntr_base[que]]
                        + [dport_pg_share_wm_base[que]]
                        + [dport_pg_headroom_wm_base[que]]
                        + [dport_que_share_wm_base[que]])
        stats_tbl.add_row(['     dst port']
                        + [dport_cntr[fieldIdx] for fieldIdx in port_counter_indexes]
                        + [dport_pg_cntr[que]]
                        + [dport_pg_share_wm[que]]
                        + [dport_pg_headroom_wm[que]]
                        + [dport_que_share_wm[que]])
        sys.stderr.write('{}\n{}\n'.format(banner, stats_tbl))

    def runTest(self):
        time.sleep(5)
        switch_init(self.clients)

        # Parse input parameters
        ingress_counters, egress_counters = get_counter_names(self.test_params['sonic_version'])
        dscp=int(self.test_params['dscp'])
        ecn=int(self.test_params['ecn'])
        router_mac=self.test_params['router_mac']
        print("router_mac: %s" % (router_mac), file=sys.stderr)
        queue=int(self.test_params['queue'])
        dst_port_id=int(self.test_params['dst_port_id'])
        dst_port_ip=self.test_params['dst_port_ip']
        dst_port_mac=self.dataplane.get_mac(0, dst_port_id)
        src_port_id=int(self.test_params['src_port_id'])
        src_port_ip=self.test_params['src_port_ip']
        src_port_vlan=self.test_params['src_port_vlan']
        src_port_mac=self.dataplane.get_mac(0, src_port_id)

        asic_type=self.test_params['sonic_asic_type']
        pkts_num_leak_out=int(self.test_params['pkts_num_leak_out'])
        pkts_num_fill_min=int(self.test_params['pkts_num_fill_min'])
        pkts_num_trig_drp=int(self.test_params['pkts_num_trig_drp'])
        cell_size=int(self.test_params['cell_size'])
        hwsku=self.test_params['hwsku']
        platform_asic = self.test_params['platform_asic']

        if 'packet_size' in list(self.test_params.keys()):
            packet_length=int(self.test_params['packet_size'])
        else:
            packet_length=64

        cell_occupancy=(packet_length + cell_size - 1) // cell_size

        # Prepare TCP packet data
        ttl=64
        pkt_dst_mac=router_mac if router_mac != '' else dst_port_mac

        is_dualtor = self.test_params.get('is_dualtor', False)
        def_vlan_mac = self.test_params.get('def_vlan_mac', None)
        if is_dualtor and def_vlan_mac != None:
            pkt_dst_mac = def_vlan_mac

        pkt=construct_ip_pkt(packet_length,
                               pkt_dst_mac,
                               src_port_mac,
                               src_port_ip,
                               dst_port_ip,
                               dscp,
                               src_port_vlan,
                               ecn=ecn,
                               ttl=ttl)

        print("dst_port_id: %d, src_port_id: %d, src_port_vlan: %s" %
              (dst_port_id, src_port_id, src_port_vlan), file=sys.stderr)
        # in case dst_port_id is part of LAG, find out the actual dst port
        # for given IP parameters
        dst_port_id=get_rx_port(
            self, 0, src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip, src_port_vlan
        )
        print("actual dst_port_id: %d" % (dst_port_id), file=sys.stderr)

        # Add slight tolerance in threshold characterization to consider
        # the case that cpu puts packets in the egress queue after we pause the egress
        # or the leak out is simply less than expected as we have occasionally observed
        #
        # On TH2 using scheduler-based TX enable, we find the Q min being inflated
        # to have 0x10 = 16 cells. This effect is captured in lossy traffic queue
        # shared test, so the margin here actually means extra capacity margin
        margin=int(self.test_params['pkts_num_margin']) if self.test_params.get(
            'pkts_num_margin') else 8

        # For TH3, some packets stay in egress memory and doesn't show up in shared buffer or leakout
        if 'pkts_num_egr_mem' in list(self.test_params.keys()):
            pkts_num_egr_mem=int(self.test_params['pkts_num_egr_mem'])

        recv_counters_base, _ = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
        xmit_counters_base, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
        self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])
        pg_cntrs_base = sai_thrift_read_pg_counters(self.src_client, port_list['src'][src_port_id])
        dst_pg_cntrs_base = sai_thrift_read_pg_counters(self.dst_client, port_list['dst'][dst_port_id])
        q_wm_res_base, pg_shared_wm_res_base, pg_headroom_wm_res_base = sai_thrift_read_port_watermarks(self.src_client, port_list['src'][src_port_id])
        dst_q_wm_res_base, dst_pg_shared_wm_res_base, dst_pg_headroom_wm_res_base = sai_thrift_read_port_watermarks(self.dst_client, port_list['dst'][dst_port_id])

        # send packets
        try:
            # Since there is variability in packet leakout in hwsku Arista-7050CX3-32S-D48C8 and
            # Arista-7050CX3-32S-C32. Starting with zero pkts_num_leak_out and trying to find
            # actual leakout by sending packets and reading actual leakout from HW
            if check_leackout_compensation_support(asic_type, hwsku):
                pkts_num_leak_out = 0

            xmit_counters_history, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
            que_min_pkts_num = 0

            # send packets to fill queue min but not trek into shared pool
            # so if queue min is zero, it will directly trek into shared pool by 1
            # TH2 uses scheduler-based TX enable, this does not require sending packets
            # to leak out
            if hwsku == 'DellEMC-Z9332f-O32' or hwsku == 'DellEMC-Z9332f-M-O16C64':
                que_min_pkts_num = pkts_num_egr_mem + pkts_num_leak_out + pkts_num_fill_min
                send_packet(self, src_port_id, pkt, que_min_pkts_num)
            else:
                que_min_pkts_num = pkts_num_leak_out + pkts_num_fill_min
                send_packet(self, src_port_id, pkt, que_min_pkts_num)

            # allow enough time for the dut to sync up the counter values in counters_db
            time.sleep(8)

            if que_min_pkts_num > 0 and check_leackout_compensation_support(asic_type, hwsku):
                dynamically_compensate_leakout(self.dst_client, asic_type, sai_thrift_read_port_counters,
                                               port_list['dst'][dst_port_id], TRANSMITTED_PKTS,
                                               xmit_counters_history, self, src_port_id, pkt, 40)

            q_wm_res, pg_shared_wm_res, pg_headroom_wm_res=sai_thrift_read_port_watermarks(
                self.dst_client, port_list['dst'][dst_port_id])
            pg_cntrs=sai_thrift_read_pg_counters(
                self.src_client, port_list['src'][src_port_id])
            print("Init pkts num sent: %d, min: %d, actual watermark value to start: %d" % (
                que_min_pkts_num, pkts_num_fill_min, q_wm_res[queue]), file=sys.stderr)
            print("Received packets: %d" %
                  (pg_cntrs[queue] - pg_cntrs_base[queue]), file=sys.stderr)

            self.show_stats('Filled queue min', asic_type,
                   queue, src_port_id, dst_port_id, ingress_counters, egress_counters,
                   recv_counters_base, pg_cntrs_base, pg_shared_wm_res_base, pg_headroom_wm_res_base, q_wm_res_base,
                   xmit_counters_base, dst_pg_cntrs_base, dst_pg_shared_wm_res_base, dst_pg_headroom_wm_res_base, dst_q_wm_res_base,
                   None, pg_cntrs, None, None, None,
                   None, None, pg_shared_wm_res, pg_headroom_wm_res, q_wm_res)

            if pkts_num_fill_min:
                assert(q_wm_res[queue] == 0)
            elif 'cisco-8000' in asic_type:
                assert(q_wm_res[queue] <= (margin + 1) * cell_size)
            else:
                if platform_asic and platform_asic == "broadcom-dnx":
                    logging.info("On J2C+ don't support SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES " + \
                                 "stat - so ignoring this step for now")
                else:
                    assert(q_wm_res[queue] <= 1 * cell_size)

            # send packet batch of fixed packet numbers to fill queue shared
            # first round sends only 1 packet
            expected_wm=0
            total_shared=pkts_num_trig_drp - pkts_num_fill_min - 1
            pkts_inc=(total_shared // cell_occupancy) >> 2
            if 'cisco-8000' in asic_type:
                pkts_total=0  # track total desired queue fill level
                pkts_num=1
            else:
                pkts_num=1 + margin
            fragment=0
            while (expected_wm < total_shared - fragment):
                expected_wm += pkts_num * cell_occupancy
                if (expected_wm > total_shared):
                    diff=(expected_wm - total_shared + \
                          cell_occupancy - 1) // cell_occupancy
                    pkts_num -= diff
                    expected_wm -= diff * cell_occupancy
                    fragment=total_shared - expected_wm

                if 'cisco-8000' in asic_type:
                    self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])
                    fill_leakout_plus_one(
                        self, src_port_id, dst_port_id, pkt, queue, asic_type)
                    pkts_total += pkts_num
                    pkts_num=pkts_total - 1

                print("pkts num to send: %d, total pkts: %d, queue shared: %d" % (
                    pkts_num, expected_wm, total_shared), file=sys.stderr)

                send_packet(self, src_port_id, pkt, pkts_num)

                if 'cisco-8000' in asic_type:
                    self.sai_thrift_port_tx_enable(
                        self.dst_client, asic_type, [dst_port_id])

                time.sleep(8)

                if que_min_pkts_num == 0 and pkts_num <= 1 + margin and check_leackout_compensation_support(asic_type, hwsku):
                    dynamically_compensate_leakout(self.dst_client, asic_type, sai_thrift_read_port_counters,
                                                   port_list['dst'][dst_port_id], TRANSMITTED_PKTS,
                                                   xmit_counters_history, self, src_port_id, pkt, 40)

                # these counters are clear on read, ensure counter polling
                # is disabled before the test
                q_wm_res, pg_shared_wm_res, pg_headroom_wm_res=sai_thrift_read_port_watermarks(
                    self.dst_client, port_list['dst'][dst_port_id])
                pg_cntrs=sai_thrift_read_pg_counters(
                    self.src_client, port_list['src'][src_port_id])
                print("Received packets: %d" %
                      (pg_cntrs[queue] - pg_cntrs_base[queue]), file=sys.stderr)
                print("lower bound: %d, actual value: %d, upper bound: %d" % ((expected_wm - margin)
                      * cell_size, q_wm_res[queue], (expected_wm + margin) * cell_size), file=sys.stderr)

                self.show_stats('Fill queue shared', asic_type,
                       queue, src_port_id, dst_port_id, ingress_counters, egress_counters,
                       recv_counters_base, pg_cntrs_base, pg_shared_wm_res_base, pg_headroom_wm_res_base, q_wm_res_base,
                       xmit_counters_base, dst_pg_cntrs_base, dst_pg_shared_wm_res_base, dst_pg_headroom_wm_res_base, dst_q_wm_res_base,
                       None, pg_cntrs, None, None, None,
                       None, None, pg_shared_wm_res, pg_headroom_wm_res, q_wm_res)

                if platform_asic and platform_asic == "broadcom-dnx":
                    logging.info("On J2C+ don't support SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES " + \
                                 "stat - so ignoring this step for now")
                else:
                    assert(q_wm_res[queue] <= (expected_wm + margin) * cell_size)
                    assert((expected_wm - margin) * cell_size <= q_wm_res[queue])

                pkts_num=pkts_inc

            if 'cisco-8000' in asic_type:
                self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])
                fill_leakout_plus_one(self, src_port_id,
                       dst_port_id, pkt, queue, asic_type)
                pkts_total += pkts_num
                pkts_num=pkts_total - 1

            # overflow the shared pool
            send_packet(self, src_port_id, pkt, pkts_num)

            if 'cisco-8000' in asic_type:
                self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])

            time.sleep(8)
            q_wm_res, pg_shared_wm_res, pg_headroom_wm_res=sai_thrift_read_port_watermarks(
                self.dst_client, port_list['dst'][dst_port_id])
            pg_cntrs=sai_thrift_read_pg_counters(
                self.src_client, port_list['src'][src_port_id])
            print("Received packets: %d" %
                  (pg_cntrs[queue] - pg_cntrs_base[queue]), file=sys.stderr)
            print("exceeded pkts num sent: %d, actual value: %d, lower bound: %d, upper bound: %d" % (
                pkts_num, q_wm_res[queue], expected_wm * cell_size, (expected_wm + margin) * cell_size), file=sys.stderr)

            self.show_stats('Overflow queue shared', asic_type,
                   queue, src_port_id, dst_port_id, ingress_counters, egress_counters,
                   recv_counters_base, pg_cntrs_base, pg_shared_wm_res_base, pg_headroom_wm_res_base, q_wm_res_base,
                   xmit_counters_base, dst_pg_cntrs_base, dst_pg_shared_wm_res_base, dst_pg_headroom_wm_res_base, dst_q_wm_res_base,
                   None, pg_cntrs, None, None, None,
                   None, None, pg_shared_wm_res, pg_headroom_wm_res, q_wm_res)

            assert(fragment < cell_occupancy)

            if platform_asic and platform_asic == "broadcom-dnx":
                logging.info("On J2C+ don't support SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES " + \
                             "stat - so ignoring this step for now")
            else:
                assert(expected_wm * cell_size <= q_wm_res[queue])
                assert(q_wm_res[queue] <= (expected_wm + margin) * cell_size)

        finally:
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])

# TODO: buffer pool roid should be obtained via rpc calls
# based on the pg or queue index
# rather than fed in as test parameters due to the lack in SAI implement
class BufferPoolWatermarkTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        time.sleep(5)
        switch_init(self.clients)

        # Parse input parameters
        dscp=int(self.test_params['dscp'])
        ecn=int(self.test_params['ecn'])
        router_mac=self.test_params['router_mac']
        print("router_mac: %s" % (router_mac), file=sys.stderr)
        pg=self.test_params['pg']
        queue=self.test_params['queue']
        print("pg: %s, queue: %s, buffer pool type: %s" %
              (pg, queue, 'egress' if not pg else 'ingress'), file=sys.stderr)
        dst_port_id=int(self.test_params['dst_port_id'])
        dst_port_ip=self.test_params['dst_port_ip']
        dst_port_mac=self.dataplane.get_mac(0, dst_port_id)
        src_port_id=int(self.test_params['src_port_id'])
        src_port_ip=self.test_params['src_port_ip']
        src_port_mac=self.dataplane.get_mac(0, src_port_id)

        asic_type=self.test_params['sonic_asic_type']
        pkts_num_leak_out=int(self.test_params['pkts_num_leak_out'])
        pkts_num_fill_min=int(self.test_params['pkts_num_fill_min'])
        pkts_num_fill_shared=int(self.test_params['pkts_num_fill_shared'])
        cell_size=int(self.test_params['cell_size'])

        print("buf_pool_roid: %s" %
              (self.test_params['buf_pool_roid']), file=sys.stderr)
        buf_pool_roid=int(self.test_params['buf_pool_roid'], 0)
        print("buf_pool_roid: 0x%lx" % (buf_pool_roid), file=sys.stderr)

        buffer_pool_wm_base=0
        if 'cisco-8000' in asic_type:
            # Some small amount of memory is always occupied
            buffer_pool_wm_base=sai_thrift_read_buffer_pool_watermark(
                self.src_client, buf_pool_roid)

        # Prepare TCP packet data
        tos=dscp << 2
        tos |= ecn
        ttl=64

        if 'packet_size' in list(self.test_params.keys()):
            packet_length=int(self.test_params['packet_size'])
        else:
            packet_length=64

        cell_occupancy=(packet_length + cell_size - 1) // cell_size

        pkt=simple_tcp_packet(pktlen=packet_length,
                                eth_dst=router_mac if router_mac != '' else dst_port_mac,
                                eth_src=src_port_mac,
                                ip_src=src_port_ip,
                                ip_dst=dst_port_ip,
                                ip_tos=tos,
                                ip_ttl=ttl)
        # Add slight tolerance in threshold characterization to consider
        # the case that cpu puts packets in the egress queue after we pause the egress
        # or the leak out is simply less than expected as we have occasionally observed
        upper_bound_margin=2 * cell_occupancy
        if 'cisco-8000' in asic_type:
            lower_bound_margin=2 * cell_occupancy
        else:
            # On TD2, we found the watermark value is always short of the expected
            # value by 1
            lower_bound_margin=1

        # On TH2 using scheduler-based TX enable, we find the Q min being inflated
        # to have 0x10 = 16 cells. This effect is captured in lossy traffic ingress
        # buffer pool test and lossy traffic egress buffer pool test to illusively
        # have extra capacity in the buffer pool space
        extra_cap_margin=8 * cell_occupancy

        # Adjust the methodology to enable TX for each incremental watermark value test
        # To this end, send the total # of packets instead of the incremental amount
        # to refill the buffer to the exepected level
        pkts_num_to_send=0
        # send packets
        try:
            # send packets to fill min but not trek into shared pool
            # so if min is zero, it directly treks into shared pool by 1
            # this is the case for lossy traffic at ingress and lossless traffic at egress (on td2)
            # Because lossy and lossless traffic use the same pool at ingress, even if
            # lossless traffic has pg min not equal to zero, we still need to consider
            # the impact caused by lossy traffic
            #
            # TH2 uses scheduler-based TX enable, this does not require sending packets to leak out
            self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])
            pkts_num_to_send += (pkts_num_leak_out + pkts_num_fill_min)
            send_packet(self, src_port_id, pkt, pkts_num_to_send)
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])
            time.sleep(8)
            buffer_pool_wm=sai_thrift_read_buffer_pool_watermark(
                self.src_client, buf_pool_roid) - buffer_pool_wm_base
            print("Init pkts num sent: %d, min: %d, actual watermark value to start: %d" % (
                (pkts_num_leak_out + pkts_num_fill_min), pkts_num_fill_min, buffer_pool_wm), file=sys.stderr)
            if pkts_num_fill_min:
                assert(buffer_pool_wm <= upper_bound_margin * cell_size)
            else:
                # on t1-lag, we found vm will keep sending control
                # packets, this will cause the watermark to be 2 * 208 bytes
                # as all lossy packets are now mapped to single pg 0
                # so we remove the strict equity check, and use upper bound
                # check instead
                assert(buffer_pool_wm <= upper_bound_margin * cell_size)

            # send packet batch of fixed packet numbers to fill shared
            # first round sends only 1 packet
            expected_wm=0
            total_shared=(pkts_num_fill_shared - \
                          pkts_num_fill_min) * cell_occupancy
            pkts_inc=(total_shared >> 2) // cell_occupancy
            if 'cisco-8000' in asic_type:
                # No additional packet margin needed while sending,
                # but small margin still needed during boundary checks below
                pkts_num=1
            else:
                pkts_num=(1 + upper_bound_margin) // cell_occupancy
            while (expected_wm < total_shared):
                expected_wm += pkts_num * cell_occupancy
                if (expected_wm > total_shared):
                    pkts_num -= (expected_wm - total_shared + \
                                 cell_occupancy - 1) // cell_occupancy
                    expected_wm=total_shared
                print("pkts num to send: %d, total pkts: %d, shared: %d" %
                      (pkts_num, expected_wm, total_shared), file=sys.stderr)

                self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])
                pkts_num_to_send += pkts_num
                if 'cisco-8000' in asic_type:
                    fill_leakout_plus_one(self, src_port_id,
                           dst_port_id, pkt, queue, asic_type)
                    send_packet(self, src_port_id, pkt, pkts_num_to_send - 1)
                else:
                    send_packet(self, src_port_id, pkt, pkts_num_to_send)
                self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])
                time.sleep(8)
                buffer_pool_wm=sai_thrift_read_buffer_pool_watermark(
                    self.src_client, buf_pool_roid) - buffer_pool_wm_base
                print("lower bound (-%d): %d, actual value: %d, upper bound (+%d): %d" % (lower_bound_margin, (expected_wm - lower_bound_margin)
                      * cell_size, buffer_pool_wm, upper_bound_margin, (expected_wm + upper_bound_margin) * cell_size), file=sys.stderr)
                assert(buffer_pool_wm <= (expected_wm + \
                       upper_bound_margin) * cell_size)
                assert((expected_wm - lower_bound_margin)
                       * cell_size <= buffer_pool_wm)

                pkts_num=pkts_inc

            # overflow the shared pool
            self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])
            pkts_num_to_send += pkts_num
            if 'cisco-8000' in asic_type:
                fill_leakout_plus_one(self, src_port_id,
                       dst_port_id, pkt, queue, asic_type)
                send_packet(self, src_port_id, pkt, pkts_num_to_send - 1)
            else:
                send_packet(self, src_port_id, pkt, pkts_num_to_send)

            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])
            time.sleep(8)
            buffer_pool_wm=sai_thrift_read_buffer_pool_watermark(
                self.src_client, buf_pool_roid) - buffer_pool_wm_base
            print("exceeded pkts num sent: %d, expected watermark: %d, actual value: %d" % (
                pkts_num, (expected_wm * cell_size), buffer_pool_wm), file=sys.stderr)
            assert(expected_wm == total_shared)
            assert((expected_wm - lower_bound_margin)
                   * cell_size <= buffer_pool_wm)
            assert(buffer_pool_wm <= (expected_wm + extra_cap_margin) * cell_size)

        finally:
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])


class PacketTransmit(sai_base_test.ThriftInterfaceDataPlane):
    """
    Transmit packets from a given source port to destination port. If no
    packet count is provided, default_count is used
    """

    def runTest(self):
        default_count=300

        # Parse input parameters
        router_mac=self.test_params['router_mac']
        dst_port_id=int(self.test_params['dst_port_id'])
        dst_port_ip=self.test_params['dst_port_ip']
        dst_port_mac=self.dataplane.get_mac(0, dst_port_id)
        src_port_id=int(self.test_params['src_port_id'])
        src_port_ip=self.test_params['src_port_ip']
        src_port_mac=self.dataplane.get_mac(0, src_port_id)
        packet_count=self.test_params.get("count", default_count)

        print("dst_port_id: {}, src_port_id: {}".format(
            dst_port_id, src_port_id
        ), file=sys.stderr)
        print(("dst_port_mac: {}, src_port_mac: {},"
            "src_port_ip: {}, dst_port_ip: {}").format(
                dst_port_mac, src_port_mac, src_port_ip, dst_port_ip
            ), file=sys.stderr)

        # Send packets to leak out
        pkt_dst_mac=router_mac if router_mac != '' else dst_port_mac
        pkt=simple_ip_packet(pktlen=64,
                    eth_dst=pkt_dst_mac,
                    eth_src=src_port_mac,
                    ip_src=src_port_ip,
                    ip_dst=dst_port_ip,
                    ip_ttl=64)

        print("Sending {} packets to port {}".format(
            packet_count, src_port_id
        ), file=sys.stderr)
        send_packet(self, src_port_id, pkt, packet_count)


# PFC test on tunnel traffic (dualtor specific test case)
class PCBBPFCTest(sai_base_test.ThriftInterfaceDataPlane):

    def _build_testing_ipinip_pkt(self, active_tor_mac, standby_tor_mac, active_tor_ip, standby_tor_ip, inner_dscp, outer_dscp, dst_ip, ecn=1, packet_size=64):
        pkt = simple_tcp_packet(
                pktlen=packet_size,
                eth_dst=standby_tor_mac,
                ip_src='1.1.1.1',
                ip_dst=dst_ip,
                ip_dscp=inner_dscp,
                ip_ecn=ecn,
                ip_ttl=64
                )
        # The pktlen is ignored if inner_frame is not None
        ipinip_packet = simple_ipv4ip_packet(
                            eth_dst=active_tor_mac,
                            eth_src=standby_tor_mac,
                            ip_src=standby_tor_ip,
                            ip_dst=active_tor_ip,
                            ip_dscp=outer_dscp,
                            ip_ecn=ecn,
                            inner_frame=pkt[scapy.IP]
                            )
        return ipinip_packet

    def _build_testing_pkt(self, active_tor_mac, dscp, dst_ip, ecn=1, packet_size=64):
        pkt = simple_tcp_packet(
                pktlen=packet_size,
                eth_dst=active_tor_mac,
                ip_src='1.1.1.1',
                ip_dst=dst_ip,
                ip_dscp=dscp,
                ip_ecn=ecn,
                ip_ttl=64
                )
        return pkt

    def runTest(self):
        """
        This test case is to verify PFC for tunnel traffic.
        Traffic is ingressed from IPinIP tunnel(LAG port), and then being decaped at active tor, and then egress to server.
        Tx is disabled on the egress port to trigger PFC pause.
        """
        switch_init(self.clients)

        # Parse input parameters
        active_tor_mac = self.test_params['active_tor_mac']
        active_tor_ip = self.test_params['active_tor_ip']
        standby_tor_mac = self.test_params['standby_tor_mac']
        standby_tor_ip = self.test_params['standby_tor_ip']
        src_port_id = self.test_params['src_port_id']
        dst_port_id = self.test_params['dst_port_id']
        dst_port_ip = self.test_params['dst_port_ip']

        inner_dscp = int(self.test_params['dscp'])
        tunnel_traffic_test = False
        if 'outer_dscp' in self.test_params:
            outer_dscp = int(self.test_params['outer_dscp'])
            tunnel_traffic_test = True
        ecn = int(self.test_params['ecn'])
        pkts_num_trig_pfc = int(self.test_params['pkts_num_trig_pfc'])
        # The pfc counter index starts from index 2 in sai_thrift_read_port_counters
        pg = int(self.test_params['pg']) + 2

        asic_type = self.test_params['sonic_asic_type']
        if 'packet_size' in list(self.test_params.keys()):
            packet_size = int(self.test_params['packet_size'])
        else:
            packet_size = 64
        if 'pkts_num_margin' in list(self.test_params.keys()):
            pkts_num_margin = int(self.test_params['pkts_num_margin'])
        else:
            pkts_num_margin = 2

        try:
            # Disable tx on EGRESS port so that headroom buffer cannot be free
            self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port_id])
            # Make a snapshot of transmitted packets
            tx_counters_base, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
            # Make a snapshot of received packets
            rx_counters_base, _ = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
            if tunnel_traffic_test:
                # Build IPinIP packet for testing
                pkt = self._build_testing_ipinip_pkt(active_tor_mac=active_tor_mac,
                                                    standby_tor_mac=standby_tor_mac,
                                                    active_tor_ip=active_tor_ip,
                                                    standby_tor_ip=standby_tor_ip,
                                                    inner_dscp=inner_dscp,
                                                    outer_dscp=outer_dscp,
                                                    dst_ip=dst_port_ip,
                                                    ecn=ecn,
                                                    packet_size=packet_size
                                                    )
            else:
                # Build regular packet
                pkt = self._build_testing_pkt(active_tor_mac=active_tor_mac,
                                            dscp=inner_dscp,
                                            dst_ip=dst_port_ip,
                                            ecn=ecn,
                                            packet_size=packet_size)

            # Send packets short of triggering pfc
            send_packet(self, src_port_id, pkt, pkts_num_trig_pfc)
            time.sleep(8)
            # Read TX_OK again to calculate leaked packet number
            tx_counters, _ = sai_thrift_read_port_counters(self.dst_client, asic_type, port_list['dst'][dst_port_id])
            leaked_packet_number = tx_counters[TRANSMITTED_PKTS] - tx_counters_base[TRANSMITTED_PKTS]
            # Send packets to compensate the leaked packets
            send_packet(self, src_port_id, pkt, leaked_packet_number)
            time.sleep(8)
            # Read rx counter again. No PFC pause frame should be triggered
            rx_counters, _ = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
            # Verify no pfc
            assert(rx_counters[pg] == rx_counters_base[pg])
            rx_counters_base = rx_counters
            # Send some packets to trigger PFC
            send_packet(self, src_port_id, pkt, 1 + 2 * pkts_num_margin)
            time.sleep(8)
            rx_counters, _ = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
            # Verify PFC pause frame is generated on expected PG
            assert(rx_counters[pg] > rx_counters_base[pg])
        finally:
            # Enable tx on dest port
            self.sai_thrift_port_tx_enable(
                self.client, asic_type, [dst_port_id])


class QWatermarkAllPortTest(sai_base_test.ThriftInterfaceDataPlane):

    def runTest(self):
        time.sleep(5)
        switch_init(self.clients)
        # Parse input parameters
        ingress_counters, egress_counters = get_counter_names(self.test_params['sonic_version'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_vlan = self.test_params['src_port_vlan']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        dst_port_ids = self.test_params['dst_port_ids']
        dst_port_ips = self.test_params['dst_port_ips']
        dst_port_macs = [self.dataplane.get_mac(
            0, ptid) for ptid in dst_port_ids]

        asic_type = self.test_params['sonic_asic_type']
        pkt_count = int(self.test_params['pkt_count'])
        cell_size = int(self.test_params['cell_size'])
        prio_list = [2, 3, 4, 8, 5, 46, 48]
        queue_list = [1, 3, 4, 0, 2, 5, 6]
        if 'packet_size' in list(self.test_params.keys()):
            packet_length = int(self.test_params['packet_size'])
        else:
            packet_length = 64

        cell_occupancy = (packet_length + cell_size - 1) // cell_size
        ttl = 64
        assert(router_mac != '')
        pkt_dst_mac = router_mac

        # Correct any destination ports that may be in a lag
        pkts = {}
        for i in range(len(dst_port_ids)):
            pkts[dst_port_ids[i]] = []
            for pri in prio_list:
                pkts[dst_port_ids[i]].append(get_multiple_flows(self,
                    router_mac,
                    dst_port_ids[i],
                    dst_port_ips[i],
                    src_port_vlan,
                    pri,
                    ecn,
                    ttl,
                    packet_length,
                    [(src_port_id, src_port_ip)],
                    packets_per_port=1)[src_port_id][0][0])

        margin = int(self.test_params['pkts_num_margin']) if self.test_params.get(
            'pkts_num_margin') else 8

        recv_counters_base, _ = sai_thrift_read_port_counters(self.src_client, asic_type, port_list['src'][src_port_id])
        dst_q_wm_res_bases = [sai_thrift_read_port_watermarks(self.dst_client, port_list['dst'][sid])[0] for sid in dst_port_ids]
        print("queue watermark base for all port is {}".format(dst_q_wm_res_bases), file=sys.stderr)

        try:
            for i in range(len(prio_list)):
                dscp = prio_list[i]
                queue = queue_list[i]
                for p_cnt in range(len(dst_port_ids)):
                    dst_port = dst_port_ids[p_cnt]
                    self.sai_thrift_port_tx_disable(self.dst_client, asic_type, [dst_port])

                    # leakout
                    if 'cisco-8000' in asic_type:
                        fill_leakout_plus_one(self, src_port_id,
                               dst_port, pkts[dst_port][i], queue, asic_type)

                    # send packet
                    send_packet(self, src_port_id, pkts[dst_port][i], pkt_count)
                    self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port])

            time.sleep(2)
            # get all q_wm values for all port
            dst_q_wm_res_all_port = [sai_thrift_read_port_watermarks(self.dst_client, port_list['dst'][sid])[0]
                                     for sid in dst_port_ids]
            print("queue watermark for all port is {}".format(dst_q_wm_res_all_port), file=sys.stderr)
            expected_wm = pkt_count * cell_occupancy
            # verification of queue watermark for all ports
            for qwms in dst_q_wm_res_all_port:
                for qwm in qwms[:-1]:
                    msg = "queue_wm value is {}, lower limit:{}, upper limit:{}".format(
                            qwm,
                            (expected_wm - margin) * cell_size,
                            (expected_wm + margin) * cell_size)

                    assert (expected_wm - margin) * cell_size <= qwm\
                            <= (expected_wm + margin) * cell_size, msg

        finally:
            self.sai_thrift_port_tx_enable(self.dst_client, asic_type, dst_port_ids)
