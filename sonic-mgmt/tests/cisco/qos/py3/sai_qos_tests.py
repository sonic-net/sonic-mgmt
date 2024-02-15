import sys
import time
import ptf.packet as scapy
from scapy.all import Ether, IP
from ptf.testutils import (send_packet,
                           simple_tcp_packet)
from ptf.mask import Mask

ROOT_DIR = "/root"
sys.path.append("{}/saitests/py3".format(ROOT_DIR))
import sai_base_test
from switch import (switch_init,
                    sai_thrift_read_port_counters,
                    port_list)

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

def get_counter_names(sonic_version):
    ingress_counters = [INGRESS_DROP]
    egress_counters = [EGRESS_DROP]

    if '201811' not in sonic_version:
        ingress_counters.append(INGRESS_PORT_BUFFER_DROP)
        egress_counters.append(EGRESS_PORT_BUFFER_DROP)

    return ingress_counters, egress_counters

def get_tcp_port():
    val = 1234
    while True:
        if val == 65535:
            raise RuntimeError("We ran out of tcp ports!")
        val += 1
        yield val

TCP_PORT_GEN = get_tcp_port()


def generate_multiple_flows(dp, dst_mac, dst_id, dst_ip, src_vlan, dscp, ecn, ttl, pkt_len, src_details, packets_per_port=1):
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

    print("Need : {} flows total, {} sources, {} packets per port".format(
        len(src_details)*packets_per_port, len(src_details), packets_per_port))
    all_pkts = {}
    for src_tuple in src_details:
        num_of_pkts = 0
        while (num_of_pkts < packets_per_port):
            tcp_dport = next(TCP_PORT_GEN)
            pkt_args = {
                'ip_ecn': ecn,
                'ip_ttl': ttl,
                'pktlen': pkt_len,
                'eth_dst': dst_mac or dp.dataplane.get_mac(0, dst_id),
                'eth_src': dp.dataplane.get_mac(0, src_tuple[0]),
                'ip_src': src_tuple[1],
                'ip_dst': dst_ip,
                'ip_dscp': dscp,
                'tcp_sport': 1234,
                'tcp_dport': tcp_dport}
            if src_vlan:
                pkt_args.update({'dl_vlan_enable': True})
                pkt_args.update({'vlan_vid': int(src_vlan)})
            pkt = simple_tcp_packet(**pkt_args)

            masked_exp_pkt = Mask(pkt, ignore_extra_bytes=True)
            masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
            masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
            masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")

            if src_vlan is not None:
                masked_exp_pkt.set_do_not_care_scapy(scapy.Dot1Q, "vlan")
            try:
                all_pkts[src_tuple[0]]
            except KeyError:
                all_pkts[src_tuple[0]] = []
            all_pkts[src_tuple[0]].append((pkt, masked_exp_pkt, dst_id))
            num_of_pkts += 1
            print("ip_src {}, ip_dst {}, tcp_dport {}".format(src_tuple[1], dst_ip, tcp_dport))

    return all_pkts

class ReleaseAllPorts(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.clients)

        asic_type = self.test_params['sonic_asic_type']

        for target, a_client in self.clients.items():
            self.sai_thrift_port_tx_enable(a_client, asic_type, list(port_list[target].keys()), target=target)

class Memorytest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
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
        src_port_2_id = int(self.test_params['src_port_2_id'])
        num_of_flows = self.test_params['num_of_flows']
        asic_type = self.test_params['sonic_asic_type']
        pkts_num_trig_pfc = int(self.test_params['pkts_num_trig_pfc'])
        cell_size = int(self.test_params['cell_size'])

        pkt_dst_mac = router_mac if router_mac != '' else dst_port_mac
        # get counter names to query
        ingress_counters, egress_counters = get_counter_names(sonic_version)
        
        self.sai_thrift_port_tx_enable(self.dst_client, asic_type, [dst_port_id])
        time.sleep(2)

        # Prepare IP packet data
        ttl = 64
        if 'packet_size' in self.test_params.keys():
            packet_length = int(self.test_params['packet_size'])
        else:
            packet_length = 64
        
        src_details = []
        src_details.append((
            int(self.test_params['src_port_1_id']),
            self.test_params['src_port_1_ip'],
            self.dataplane.get_mac(0, int(self.test_params['src_port_1_id']))))
        src_details.append((
            int(self.test_params['src_port_2_id']),
            self.test_params['src_port_2_ip'],
            self.dataplane.get_mac(0, int(self.test_params['src_port_2_id']))))

        all_pkts = generate_multiple_flows(
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
                packets_per_port=num_of_flows)

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

        # send packets short of triggering pfc
        # Send 1 less packet due to leakout filling
        npkts = (pkts_num_trig_pfc // num_of_flows) - 2 - margin
        print("Sending {} flows, {} packets for each flow".format(num_of_flows * 2, npkts))
        total_pkts = [npkts * num_of_flows] * 2
        for src_id in all_pkts.keys():
            for pkt_tuple in all_pkts[src_id]:
                send_packet(self, src_id, pkt_tuple[0], npkts)

        # allow enough time for counters to update
        time.sleep(2)

        # get a snapshot of counter values at recv and transmit ports
        # queue counters value is not of our interest here
        counter_details_after = collect_counters()

        for i in range(2):
            # recv port no pfc
            pfc_txd = counter_details_after[i][0][pg] - counter_details_before[i][0][pg]
            assert pfc_txd == 0, \
                "Unexpected PFC TX {} on port {} for pg:{}".format(
                    pfc_txd, src_details[i][0], pg-2)
            # recv port no ingress drop
            for cntr in ingress_counters:
                diff = counter_details_after[i][0][cntr] - counter_details_before[i][0][cntr]
                assert diff == 0, "Unexpected ingress drop {} on port {}".format(diff, src_details[i])

        # xmit port no egress drop
        for cntr in egress_counters:
            diff = counter_details_after[2][0][cntr] - counter_details_before[2][0][cntr]
            assert diff == 0, "Unexpected egress drops {} on port {}".format(diff, dst_port_id)

        # Keep sending packets until PFC is triggerred
        npkts = 200 // num_of_flows
        print("Keep sending {} packets per flow until PFC is triggered".format(npkts))
        pfc_is_triggered = [False, False]
        src_port_ids = [src_port_1_id, src_port_2_id]
        while False in pfc_is_triggered:
            for i in range(2):
                if not pfc_is_triggered[i]:
                    for pkt_tuple in all_pkts[src_port_ids[i]]:
                        send_packet(self, src_port_ids[i], pkt_tuple[0], npkts)
                        total_pkts[i] += npkts
                    print("Totally {} packets sent to src port {}".format(total_pkts[i], i))

            # allow enough time for counters to update
            time.sleep(2)
            # get a snapshot of counter values at recv and transmit ports
            # queue counters value is not of our interest here
            counter_details_3 = collect_counters()

            for i in range(2):
                # recv port Starts PFC:
                pfc_txd = counter_details_3[i][0][pg] - counter_details_before[i][0][pg]
                if pfc_txd > 0:
                    pfc_is_triggered[i] = True
