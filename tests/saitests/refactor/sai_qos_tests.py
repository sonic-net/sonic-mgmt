"""
SONiC Dataplane Qos tests
"""
import time
import ptf.packet as scapy
from scapy.all import Ether, IP
import sai_base_test
from ptf.testutils import (ptf_ports,
                           simple_arp_packet,
                           send_packet)
from ptf.mask import Mask
from switch import (switch_init,
                    port_list)


def qos_test_assert(ptftest, condition, message=None):
    try:
        assert condition, message
    except AssertionError:
        summarize_diag_counter(ptftest)
        raise  # Re-raise the assertion error to maintain the original assert behavior


################################ keep legecy code for demo purpose ################################

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
        self.src_dut_index = self.test_params['src_dut_index']
        self.src_asic_index = self.test_params.get('src_asic_index', None)
        self.dst_dut_index = self.test_params['dst_dut_index']
        self.dst_asic_index = self.test_params.get('dst_asic_index', None)
        self.testbed_type = self.test_params['testbed_type']


    def tearDown(self):
        sai_base_test.ThriftInterfaceDataPlane.tearDown(self)


    def runTest(self):
        # ARP Populate
        # Ping only  required for testports
        if 't2' in self.testbed_type:
            src_is_multi_asic = self.test_params['src_is_multi_asic']
            dst_is_multi_asic = self.test_params['dst_is_multi_asic']
            dst_port_ips = [self.dst_port_ip, self.dst_port_2_ip, self.dst_port_3_ip]
            for ip in dst_port_ips:
                if dst_is_multi_asic:
                    stdOut, stdErr, retValue = self.exec_cmd_on_dut(self.dst_server_ip,
                                                                    self.test_params['dut_username'],
                                                                    self.test_params['dut_password'],
                                                                    'sudo ip netns exec asic{} ping -q -c 3 {}'.format(
                                                                        self.dst_asic_index, ip))
                    assert ' 0% packet loss' in stdOut[3], "Ping failed for IP:'{}' on asic '{}' on Dut '{}'".format(
                        ip, self.dst_asic_index, self.dst_server_ip)
                else:
                    stdOut, stdErr, retValue = self.exec_cmd_on_dut(self.dst_server_ip,
                                                                    self.test_params['dut_username'],
                                                                    self.test_params['dut_password'],
                                                                    'ping -q -c 3 {}'.format(ip))
                    assert ' 0% packet loss' in stdOut[3], "Ping failed for IP:'{}' on Dut '{}'".format(
                        ip, self.dst_server_ip)
            if src_is_multi_asic:
                stdOut, stdErr, retValue = self.exec_cmd_on_dut(self.src_server_ip, self.test_params['dut_username'],
                                                                self.test_params['dut_password'],
                                                                'sudo ip netns exec asic{} ping -q -c 3 {}'.format(
                                                                    self.src_asic_index, self.src_port_ip))
                assert ' 0% packet loss' in stdOut[3], "Ping failed for IP:'{}' on asic '{}' on Dut '{}'".format(
                    self.src_port_ip, self.src_asic_index, self.src_server_ip)
            else:
                stdOut, stdErr, retValue = self.exec_cmd_on_dut(self.src_server_ip, self.test_params['dut_username'],
                                                                self.test_params['dut_password'],
                                                                'ping -q -c 3 {}'.format(self.src_port_ip))
                assert ' 0% packet loss' in stdOut[3], "Ping failed for IP:'{}' on Dut '{}'".format(
                    self.src_port_ip, self.src_server_ip)
        else:
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

            for dut_i in self.test_port_ids:
                for asic_i in self.test_port_ids[dut_i]:
                    for dst_port_id in self.test_port_ids[dut_i][asic_i]:
                        dst_port_ip = self.test_port_ips[dut_i][asic_i][dst_port_id]
                        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
                        arpreq_pkt = construct_arp_pkt('ff:ff:ff:ff:ff:ff', dst_port_mac,
                                                       1, dst_port_ip['peer_addr'], '192.168.0.1',
                                                       '00:00:00:00:00:00', None)
                        send_packet(self, dst_port_id, arpreq_pkt)

            # ptf don't know the address of neighbor, use ping to learn relevant arp entries instead of send arp request
            if self.test_port_ips:
                ips = [ip for ip in get_peer_addresses(self.test_port_ips)]
                if ips:
                    cmd = 'for ip in {}; do ping -c 4 -i 0.2 -W 1 -q $ip > /dev/null 2>&1 & done'.format(' '.join(ips))
                    self.exec_cmd_on_dut(self.server, self.test_params['dut_username'],
                                         self.test_params['dut_password'], cmd)

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

################################ keep legecy code for demo purpose ################################


from qos_helper import log_message
from testcase_qos_base import TestcaseQosBase
from counter_collector import CounterCollector, initialize_diag_counter, capture_diag_counter, summarize_diag_counter
from saitests_decorators import saitests_decorator, diag_counter, step_result, step_banner


class PFCtest(TestcaseQosBase):

    #
    # PTF methods
    #

    def runTest(self):
        self.step_build_param()

        self.pkt = self.step_build_packet(self.packet_size, self.pkt_dst_mac, self.src_port_mac, self.src_port_ip,
                                          self.dst_port_ip, self.dscp, self.src_port_vlan, ecn=self.ecn, ttl=self.ttl)

        self.step_detect_rx_port()

        self.step_disable_port_transmit(self.dst_client, self.asic_type, [self.dst_port_id])

        self.step_read_counter_base()

        try:
            leakout_overflow = self.step_fill_leakout(self.src_port_id, self.dst_port_id, self.pkt, self.pg,
                                                      self.asic_type, self.pkts_num_egr_mem)

            self.step_short_of_pfc(self.src_port_id, self.pkt,  (self.pkts_num_leak_out + self.pkts_num_trig_pfc) // self.cell_occupancy - \
                                   leakout_overflow - 1 - self.pkts_num_margin)

            self.step_compensate_leakout()

            self.step_check_short_of_pfc()

            self.step_trigger_pfc()

            self.step_check_trigger_pfc()

            self.step_short_of_ingress_drop()

            self.step_check_short_of_ingress_drop()

            self.step_trigger_ingress_drop()

            self.step_check_trigger_ingress_drop()

        finally:
            self.step_enable_port_transmit(self.dst_client, self.asic_type, [self.dst_port_id])


    #
    # specific steps
    #

    def step_build_param(self):
        super().step_build_param()
        self.dst_port_mac = self.dataplane.get_mac(0, self.dst_port_id)
        self.src_port_mac = self.dataplane.get_mac(0, self.src_port_id)
        self.pkt_dst_mac = self.router_mac if self.router_mac != '' else self.dst_port_mac

        # Add slight tolerance in threshold characterization to consider
        # the case that cpu puts packets in the egress queue after we pause the egress
        # or the leak out is simply less than expected as we have occasionally observed
        if not hasattr(self, 'pkts_num_margin'):
            self.pkts_num_margin = 2

        self.ttl = 64
        if not hasattr(self, 'packet_size'):
            self.packet_size = 64
        if hasattr(self, 'cell_size'):
            self.cell_occupancy = (self.packet_size + self.cell_size - 1) // self.cell_size
        else:
            self.cell_occupancy = 1

        if not hasattr(self, 'is_dualtor'):
            self.is_dualtor = False

        if not hasattr(self, 'def_vlan_mac'):
            self.def_vlan_mac = None
        if self.is_dualtor and self.def_vlan_mac is not None:
            self.pkt_dst_mac = self.def_vlan_mac

        self.pkts_num_egr_mem = None


    def step_read_counter_base(self):
        self.recv_port_counter = CounterCollector(self, 'PortCnt', port_ids=[self.src_port_id])
        self.xmit_port_counter = CounterCollector(self, 'PortCnt', port_ids=[self.dst_port_id])
        self.recv_port_counter.collect_counter('base', compare=True)
        self.xmit_port_counter.collect_counter('base', compare=True)


    @saitests_decorator(func=step_banner, param='Banner', enter=True, exit=False)
    @saitests_decorator(func=step_result, param='Result', enter=False, exit=True)
    @saitests_decorator(func=diag_counter, param='capture', enter=False, exit=True)
    def step_short_of_pfc(self, port, packet, packet_number):
        #
        # In previous step, we have already sent packets to fill leakout in some platform,
        # so in this step, we need to send ${leakout_overflow} less packet to trigger pfc
        #
        self.platform.send_packet(port, packet, packet_number)
        # allow enough time for the dut to sync up the counter values in counters_db
        time.sleep(8)


    def step_check_short_of_pfc(self):
        self.recv_port_counter.collect_counter('short_of_pfc', compare=True)
        self.xmit_port_counter.collect_counter('short_of_pfc', compare=True)

        recv_port_pg_delta = self.recv_port_counter.get_counter_delta('short_of_pfc', 'base', self.src_port_id, f'Pfc{self.pg}TxPkt')
        # recv port no pfc
        qos_test_assert(self, recv_port_pg_delta == 0, f'unexpectedly PFC counter increase, short_of_pfc')

        # recv port no ingress drop
        # For dnx few extra ipv6 NS/RA pkt received from VM, adding to counter value
        # & may give inconsistent test results
        # Adding COUNTER_MARGIN to provide room to 2 pkt incase, extra traffic received
        recv_port_rx_discard_delta = self.recv_port_counter.get_counter_delta('short_of_pfc', 'base', self.src_port_id, 'InDiscard')
        qos_test_assert(self, recv_port_rx_discard_delta <= self.counter_margin, 'unexpectedly RX drop counter increase, short_of_pfc')
        recv_port_rx_drop_delta = self.recv_port_counter.get_counter_delta('short_of_pfc', 'base', self.src_port_id, 'InDropPkt')
        qos_test_assert(self, recv_port_rx_drop_delta <= self.counter_margin, 'unexpectedly RX drop counter increase, short_of_pfc')

        # xmit port no egress drop
        xmit_port_tx_discard_delta = self.xmit_port_counter.get_counter_delta('short_of_pfc', 'base', self.dst_port_id, 'OutDiscard')
        qos_test_assert(self, xmit_port_tx_discard_delta == 0, 'unexpectedly TX drop counter increase, short_of_pfc')
        xmit_port_tx_drop_delta = self.xmit_port_counter.get_counter_delta('short_of_pfc', 'base', self.dst_port_id, 'OutDropPkt')
        qos_test_assert(self, xmit_port_tx_drop_delta == 0, 'unexpectedly TX drop counter increase, short_of_pfc')


    @saitests_decorator(func=step_banner, param='Banner', enter=True, exit=False)
    @saitests_decorator(func=step_result, param='Result', enter=False, exit=True)
    @saitests_decorator(func=diag_counter, param='capture', enter=False, exit=True)
    def step_trigger_pfc(self):
        # send 1 packet to trigger pfc
        self.platform.send_packet(self.src_port_id, self.pkt, 1 + 2 * self.pkts_num_margin)
        # allow enough time for the dut to sync up the counter values in counters_db
        time.sleep(8)


    def step_check_trigger_pfc(self):
        self.recv_port_counter.collect_counter('trigger_pfc', compare=True)
        self.xmit_port_counter.collect_counter('trigger_pfc', compare=True)

        # recv port no pfc
        recv_port_pg_delta = self.recv_port_counter.get_counter_delta('trigger_pfc', 'short_of_pfc', self.src_port_id, f'Pfc{self.pg}TxPkt')
        qos_test_assert(self, recv_port_pg_delta > 0, f'unexpectedly PFC counter not increase, trigger_pfc')

        # recv port no ingress drop
        # For dnx few extra ipv6 NS/RA pkt received from VM, adding to counter value
        # & may give inconsistent test results
        # Adding COUNTER_MARGIN to provide room to 2 pkt incase, extra traffic received
        recv_port_rx_discard_delta = self.recv_port_counter.get_counter_delta('trigger_pfc', 'short_of_pfc', self.src_port_id, 'InDiscard')
        qos_test_assert(self, recv_port_rx_discard_delta <= self.counter_margin, 'unexpectedly RX drop counter increase, trigger_pfc')
        recv_port_rx_drop_delta = self.recv_port_counter.get_counter_delta('trigger_pfc', 'short_of_pfc', self.src_port_id, 'InDropPkt')
        qos_test_assert(self, recv_port_rx_drop_delta <= self.counter_margin, 'unexpectedly RX drop counter increase, trigger_pfc')

        # xmit port no egress drop
        xmit_port_tx_discard_delta = self.xmit_port_counter.get_counter_delta('trigger_pfc', 'short_of_pfc', self.dst_port_id, 'OutDiscard')
        qos_test_assert(self, xmit_port_tx_discard_delta == 0, 'unexpectedly TX drop counter increase, trigger_pfc')
        xmit_port_tx_drop_delta = self.xmit_port_counter.get_counter_delta('trigger_pfc', 'short_of_pfc', self.dst_port_id, 'OutDropPkt')
        qos_test_assert(self, xmit_port_tx_drop_delta == 0, 'unexpectedly TX drop counter increase, trigger_pfc')


    @saitests_decorator(func=step_banner, param='Banner', enter=True, exit=False)
    @saitests_decorator(func=step_result, param='Result', enter=False, exit=True)
    @saitests_decorator(func=diag_counter, param='capture', enter=False, exit=True)
    def step_short_of_ingress_drop(self):
        # send packets short of ingress drop
        self.platform.send_packet(self.src_port_id, self.pkt, (self.pkts_num_trig_ingr_drp -
                                self.pkts_num_trig_pfc) // self.cell_occupancy - 1 - 2 * self.pkts_num_margin)
        # allow enough time for the dut to sync up the counter values in counters_db
        time.sleep(8)


    def step_check_short_of_ingress_drop(self):
        self.recv_port_counter.collect_counter('short_of_ingress_drop', compare=True)
        self.xmit_port_counter.collect_counter('short_of_ingress_drop', compare=True)

        # recv port no pfc
        recv_port_pg_delta = self.recv_port_counter.get_counter_delta('short_of_ingress_drop', 'trigger_pfc', self.src_port_id, f'Pfc{self.pg}TxPkt')
        qos_test_assert(self, recv_port_pg_delta > 0, f'unexpectedly PFC counter not increase, short_of_ingress_drop')

        # recv port no ingress drop
        # For dnx few extra ipv6 NS/RA pkt received from VM, adding to counter value
        # & may give inconsistent test results
        # Adding COUNTER_MARGIN to provide room to 2 pkt incase, extra traffic received
        recv_port_rx_discard_delta = self.recv_port_counter.get_counter_delta('short_of_ingress_drop', 'trigger_pfc', self.src_port_id, 'InDiscard')
        qos_test_assert(self, recv_port_rx_discard_delta <= self.counter_margin, 'unexpectedly RX drop counter increase, short_of_ingress_drop')
        recv_port_rx_drop_delta = self.recv_port_counter.get_counter_delta('short_of_ingress_drop', 'trigger_pfc', self.src_port_id, 'InDropPkt')
        qos_test_assert(self, recv_port_rx_drop_delta <= self.counter_margin, 'unexpectedly RX drop counter increase, short_of_ingress_drop')

        # xmit port no egress drop
        xmit_port_tx_discard_delta = self.xmit_port_counter.get_counter_delta('short_of_ingress_drop', 'trigger_pfc', self.dst_port_id, 'OutDiscard')
        qos_test_assert(self, xmit_port_tx_discard_delta == 0, 'unexpectedly TX drop counter increase, short_of_ingress_drop')
        xmit_port_tx_drop_delta = self.xmit_port_counter.get_counter_delta('short_of_ingress_drop', 'trigger_pfc', self.dst_port_id, 'OutDropPkt')
        qos_test_assert(self, xmit_port_tx_drop_delta == 0, 'unexpectedly TX drop counter increase, short_of_ingress_drop')


    @saitests_decorator(func=step_banner, param='Banner', enter=True, exit=False)
    @saitests_decorator(func=step_result, param='Result', enter=False, exit=True)
    @saitests_decorator(func=diag_counter, param='capture', enter=False, exit=True)
    def step_trigger_ingress_drop(self):
        # send 1 packet to trigger pfc
        self.platform.send_packet(self.src_port_id, self.pkt, 1 + 2 * self.pkts_num_margin)
        # allow enough time for the dut to sync up the counter values in counters_db
        time.sleep(8)
        capture_diag_counter(self, 'TrigPfc')


    def step_check_trigger_ingress_drop(self):
        self.recv_port_counter.collect_counter('trigger_ingress_drop', compare=True)
        self.xmit_port_counter.collect_counter('trigger_ingress_drop', compare=True)

        # recv port no pfc
        recv_port_pg_delta = self.recv_port_counter.get_counter_delta('trigger_ingress_drop', 'short_of_ingress_drop', self.src_port_id, f'Pfc{self.pg}TxPkt')
        qos_test_assert(self, recv_port_pg_delta > 0, f'unexpectedly PFC counter not increase, short_of_ingress_drop')

        # recv port no ingress drop
        # For dnx few extra ipv6 NS/RA pkt received from VM, adding to counter value
        # & may give inconsistent test results
        # Adding COUNTER_MARGIN to provide room to 2 pkt incase, extra traffic received
        recv_port_rx_discard_delta = self.recv_port_counter.get_counter_delta('trigger_ingress_drop', 'short_of_ingress_drop', self.src_port_id, 'InDiscard')
        qos_test_assert(self, recv_port_rx_discard_delta > 0, 'unexpectedly RX drop counter increase, trigger_ingress_drop')
        recv_port_rx_drop_delta = self.recv_port_counter.get_counter_delta('trigger_ingress_drop', 'short_of_ingress_drop', self.src_port_id, 'InDropPkt')
        qos_test_assert(self, recv_port_rx_drop_delta > 0, 'unexpectedly RX drop counter increase, trigger_ingress_drop')

        # xmit port no egress drop
        xmit_port_tx_discard_delta = self.xmit_port_counter.get_counter_delta('trigger_ingress_drop', 'short_of_ingress_drop', self.dst_port_id, 'OutDiscard')
        qos_test_assert(self, xmit_port_tx_discard_delta == 0, 'unexpectedly TX drop counter increase, trigger_ingress_drop')
        xmit_port_tx_drop_delta = self.xmit_port_counter.get_counter_delta('trigger_ingress_drop', 'short_of_ingress_drop', self.dst_port_id, 'OutDropPkt')
        qos_test_assert(self, xmit_port_tx_drop_delta == 0, 'unexpectedly TX drop counter increase, trigger_ingress_drop')
