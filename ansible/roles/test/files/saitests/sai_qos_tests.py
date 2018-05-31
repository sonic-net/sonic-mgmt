"""
SONiC Dataplane Qos tests
"""

import time
import logging
import ptf.packet as scapy
import socket
import ptf.dataplane as dataplane
import sai_base_test
from ptf.testutils import (ptf_ports,
                           simple_arp_packet,
                           send_packet,
                           simple_tcp_packet)
from ptf.mask import Mask
from switch import (switch_init,
                    sai_thrift_create_scheduler_profile,
                    sai_thrift_clear_all_counters,
                    sai_thrift_read_port_counters,
                    sai_port_list,
                    port_list)
from switch_sai_thrift.ttypes import (sai_thrift_attribute_value_t,
                                      sai_thrift_attribute_t)
from switch_sai_thrift.sai_headers import SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID

# Counters
# The index number comes from the append order in sai_thrift_read_port_counters
EGRESS_DROP = 0
INGRESS_DROP = 1
PFC_PRIO_3 = 5
PFC_PRIO_4 = 6
TRANSMITTED_OCTETS = 10
TRANSMITTED_PKTS = 11
QUEUE_0 = 0
QUEUE_1 = 1
QUEUE_3 = 3
QUEUE_4 = 4

# Constants
STOP_PORT_MAX_RATE = 1
RELEASE_PORT_MAX_RATE = 0
ECN_INDEX_IN_HEADER = 53 # Fits the ptf hex_dump_buffer() parse function
DSCP_INDEX_IN_HEADER = 52 # Fits the ptf hex_dump_buffer() parse function


class ARPpopulate(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        router_mac = self.test_params['router_mac']
        ## ARP Populate
        index = 0
        for port in ptf_ports():
            arpreq_pkt = simple_arp_packet(
                          eth_dst='ff:ff:ff:ff:ff:ff',
                          eth_src=self.dataplane.get_mac(port[0],port[1]),
                          arp_op=1,
                          ip_snd='10.0.0.%d' % (index * 2 + 1),
                          ip_tgt='10.0.0.%d' % (index * 2),
                          hw_snd=self.dataplane.get_mac(port[0], port[1]),
                          hw_tgt='00:00:00:00:00:00')
            send_packet(self, port[1], arpreq_pkt)
            index += 1

class ReleaseAllPorts(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        sched_prof_id=sai_thrift_create_scheduler_profile(self.client, RELEASE_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        for port in sai_port_list:
            self.client.sai_thrift_set_port_attribute(port, attr)

class DscpMappingPB(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        
        router_mac = self.test_params['router_mac']        
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        exp_ip_id = 101
        exp_ttl = 63

        # Clear switch counters
        # sai_thrift_clear_all_counters(self.client)
        # Get a snapshot of counter values
        # port_results is not of our interest here
        port_results, queue_results_base = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])

        # DSCP Mapping test
        try:
            for dscp in range(0,64):
                tos = dscp << 2
                pkt = simple_tcp_packet(eth_dst=router_mac,
                                        eth_src=src_port_mac,
                                        ip_src=src_port_ip,
                                        ip_dst=dst_port_ip,
                                        ip_tos=tos,
                                        ip_id=exp_ip_id,
                                        ip_ttl=64)

                send_packet(self, src_port_id, pkt)

                dscp_received = False

                while not dscp_received:
                    result = self.dataplane.poll(device_number=0, port_number=dst_port_id, timeout=3)
                    if isinstance(result, self.dataplane.PollFailure):
                        self.fail("Expected packet was not received on port %d.\n%s"
                            % (dst_port_id, result.format()))
                    recv_pkt = scapy.Ether(result.packet)

                    # Verify dscp flag
                    try:
                        dscp_received = recv_pkt.payload.tos == tos and recv_pkt.payload.src == src_port_ip and recv_pkt.payload.dst == dst_port_ip and \
                            recv_pkt.payload.ttl == exp_ttl and recv_pkt.payload.id == exp_ip_id
                    except AttributeError:
                        continue

            # Read Counters
            port_results, queue_results = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])

            # According to SONiC configuration all dscp are classified to queue 0 except:
            # dscp 3 -> queue 3
            # dscp 4 -> queue 4
            # dscp 8 -> queue 1
            # So for the 64 pkts sent the mapping should be -> 61 queue 0, and 1 for queue1, queue3 and queue4
            # Check results
            assert(queue_results[QUEUE_0] == 61 + queue_results_base[QUEUE_0])
            assert(queue_results[QUEUE_1] == 1 + queue_results_base[QUEUE_1])
            assert(queue_results[QUEUE_3] == 1 + queue_results_base[QUEUE_3])
            assert(queue_results[QUEUE_4] == 1 + queue_results_base[QUEUE_4])

        finally:
            print "END OF TEST"

# This test is to measure the Xoff threshold, and buffer limit
class PFCtest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        time.sleep(5)
        switch_init(self.client)
        
        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        pg = int(self.test_params['pg']) + 2 #The pfc counter index starts from index 2
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        max_buffer_size = int(self.test_params['buffer_max_size'])
        max_queue_size = int(self.test_params['queue_max_size']) 
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        
        # Prepare TCP packet data
        tos = dscp << 2
        tos |= ecn
        ttl = 64        
        default_packet_length = 72
        # Calculate the max number of packets which port buffer can consists
        # Increase the number of packets on 25% for a oversight of translating packet size to cells
        pkts_max = (max_buffer_size / default_packet_length + 1) * 1.3
            
        # Clear counters
        # sai_thrift_clear_all_counters(self.client)

        # Close DST port
        sched_prof_id = sai_thrift_create_scheduler_profile(self.client, STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)

        # Send packets
        try:
            src_port_index = -1
            pkts_bunch_size = 70 # Number of packages to send to DST port
            pkts_count = 0 # Total number of shipped packages
            port_pg_counter = 0
            
            # Send the packets untill PFC counter will be trigerred or max pkts reached
            pkt = simple_tcp_packet(pktlen=default_packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)
            while port_pg_counter == 0 and pkts_count < pkts_max:
                send_packet(self, src_port_id, pkt, pkts_bunch_size)
                pkts_count += pkts_bunch_size
                time.sleep(8)

                drop_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
                assert(drop_counters[EGRESS_DROP] == 0)

                port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
                port_pg_counter = port_counters[pg]

            # PFC must be triggered and PFC counters must increment
            assert(port_counters[pg] != 0)
            # No egress drop
            assert(port_counters[EGRESS_DROP] == 0)
            # No ingress drop
            assert(port_counters[INGRESS_DROP] == 0)

            # Send the packages till ingress drop on src port
            pkts_bunch_size = 70
            # Increase the number of packets on 25% for a oversight of translating packet size to cells
            pkts_max = ((max_buffer_size + max_queue_size) / default_packet_length) * 1.3
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
            ingress_counter = port_counters[INGRESS_DROP]            
            while ingress_counter == 0 and pkts_count < pkts_max:
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                                        eth_dst=router_mac,
                                        eth_src=src_port_mac,
                                        ip_src=src_port_ip,
                                        ip_dst=dst_port_ip,
                                        ip_tos=tos,
                                        ip_ttl=ttl)
                send_packet(self, src_port_id, pkt, pkts_bunch_size)
                pkts_count += pkts_bunch_size
                time.sleep(8)

                port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
                ingress_counter = port_counters[INGRESS_DROP]

            # No egress drop
            assert(port_counters[EGRESS_DROP] == 0)
            # Must have ingress drop
            assert(port_counters[INGRESS_DROP] != 0)
            # PFC must be triggered and PFC counters must increment
            assert(port_counters[pg] != 0)

        finally:
            # Release port
            sched_prof_id = sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id],attr)
            print "END OF TEST"

# This test looks to measure xon (pg_reset_floor)
class PFCXonTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        time.sleep(5)
        switch_init(self.client)
        last_pfc_counter = 0
        recv_port_counters = []
        transmit_port_counters = []
        
        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        max_buffer_size = int(self.test_params['buffer_max_size'])
        pg = int(self.test_params['pg']) + 2 # The pfc counter index starts from index 2 in sai_thrift_read_port_counters
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)

        # Stop dst port function
        sched_prof_id = sai_thrift_create_scheduler_profile(self.client, STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)

        # Clear Counters
        # sai_thrift_clear_all_counters(self.client)
        # Get a snapshot of counter values
        # queue_counters is not of our interest here
        recv_port_counters_base, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
        transmit_port_counters_base, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])

        try:
            tos = dscp << 2
            tos |= ecn
            ttl=64
            default_packet_length = 72
            # Calculate the max number of packets which port buffer can consists
            pkts_max = (max_buffer_size / default_packet_length) * 1.3
            pkts_bunch_size = 70 # Number of packages to send to DST port
            pkts_count = 0 # Total number of shipped packages
            port_pg_counter = recv_port_counters_base[pg]
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
            
            # Send the packets untill PFC counter will be trigerred or max pkts reached
            pkt = simple_tcp_packet(pktlen=default_packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)
            while port_pg_counter == recv_port_counters_base[pg] and pkts_count < pkts_max:
                send_packet(self, src_port_id, pkt, pkts_bunch_size)
                pkts_count += pkts_bunch_size
                time.sleep(8)
                
                recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
                port_pg_counter = recv_port_counters[pg]

            # src port PFC must be triggered and PFC counters must increment
            assert(recv_port_counters[pg] != recv_port_counters_base[pg])
            # src port no egress drop (no need to assert this, because it is not the dst port)
            assert(recv_port_counters[EGRESS_DROP] == recv_port_counters_base[EGRESS_DROP])
            # src port no ingress drop
            assert(recv_port_counters[INGRESS_DROP] == recv_port_counters_base[INGRESS_DROP])

            # Release dst port
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id],attr)            
            time.sleep(10)
            
            # After release, send the packets and verify if no drops on port
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
            last_pfc_counter = recv_port_counters[pg]
            non_xoff_pkts_num = pkts_count - pkts_bunch_size
            send_packet(self, src_port_id, pkt, non_xoff_pkts_num)
            time.sleep(5)

            # Read counters
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
            transmit_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])

            # src port no egress drop (no need to assert this, because it is not the dst port)
            assert(recv_port_counters[EGRESS_DROP] == recv_port_counters_base[EGRESS_DROP])
            # src port no ingress drop
            assert(recv_port_counters[INGRESS_DROP] == recv_port_counters_base[INGRESS_DROP])
            # src port PFC must be triggered and PFC counters must increment
            assert(recv_port_counters[pg] != recv_port_counters_base[pg])
            assert(transmit_port_counters[TRANSMITTED_PKTS] != transmit_port_counters_base[TRANSMITTED_PKTS])
            # src port PFC counters remain the same value as sampled immediately after release
            assert(recv_port_counters[pg] == last_pfc_counter)

        finally:
            # Release port
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id],attr)
            print "END OF TEST"

class DscpEcnSend(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        
        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
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

        #STOP PORT FUNCTION
        sched_prof_id=sai_thrift_create_scheduler_profile(self.client,STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #send packets
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
            print "leaking packet %d" % leaking_pkt_number

            # Read Counters
            print "DST port counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
            print port_counters
            print queue_counters

            # Clear Counters
            sai_thrift_clear_all_counters(self.client)

            # Set receiving socket buffers to some big value
            for p in self.dataplane.ports.values():
                p.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 41943040)

            # RELEASE PORT
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id],attr)

            # if (ecn == 1) - capture and parse all incoming packets
            marked_cnt = 0
            not_marked_cnt = 0
            if (ecn == 1):
                print ""
                print "ECN capable packets generated, releasing dst_port and analyzing traffic -"

                cnt = 0
                pkts = []
                for i in xrange(num_of_pkts):
                    (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(self, device_number=0, port_number=dst_port_id, timeout=0.2)
                    if rcv_pkt is not None:
                        cnt += 1
                        pkts.append(rcv_pkt)
                    else:  # Received less packets then expected
                        assert (cnt == num_of_pkts)
                print "    Received packets:    " + str(cnt)

                for pkt_to_inspect in pkts:
                    pkt_str = hex_dump_buffer(pkt_to_inspect)

                    # Count marked and not marked amount of packets
                    if ( (int(pkt_str[ECN_INDEX_IN_HEADER]) & 0x03)  == 1 ):
                        not_marked_cnt += 1
                    elif ( (int(pkt_str[ECN_INDEX_IN_HEADER]) & 0x03) == 3 ):
                        assert (not_marked_cnt == 0)
                        marked_cnt += 1

                print "    ECN non-marked pkts: " + str(not_marked_cnt)
                print "    ECN marked pkts:     " + str(marked_cnt)
                print ""

            time.sleep(5)
            # Read Counters
            print "DST port counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
            print port_counters
            print queue_counters
            if (ecn == 0):
                transmitted_data = port_counters[TRANSMITTED_PKTS] * 2 * cell_size #num_of_pkts*pkt_size_in_cells*cell_size
                assert (port_counters[TRANSMITTED_OCTETS] <= limit * 1.05)
                assert (transmitted_data >= min_limit)
                assert (marked_cnt == 0)
            elif (ecn == 1):
                non_marked_data = not_marked_cnt * 2 * cell_size
                assert (non_marked_data <= limit*1.05)
                assert (non_marked_data >= limit*0.95)
                assert (marked_cnt == (num_of_pkts - not_marked_cnt))
                assert (port_counters[EGRESS_DROP]  == 0)
                assert (port_counters[INGRESS_DROP] == 0)

        finally:
            # RELEASE PORT
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id],attr)
            print "END OF TEST"

class WRRtest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)        
        
        # Parse input parameters
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']       
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        default_packet_length = 1500
        exp_ip_id = 110
        queue_0_num_of_pkts = int(self.test_params['q0_num_of_pkts'])
        queue_1_num_of_pkts = int(self.test_params['q1_num_of_pkts'])
        queue_3_num_of_pkts = int(self.test_params['q3_num_of_pkts'])
        queue_4_num_of_pkts = int(self.test_params['q4_num_of_pkts'])

        #STOP PORT FUNCTION
        sched_prof_id=sai_thrift_create_scheduler_profile(self.client, STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #send packets to each queue based on dscp field
        try:
            for i in range(0, queue_0_num_of_pkts):
                dscp = 0
                tos = dscp << 2
                tos |= ecn
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                            eth_dst=router_mac,
                            eth_src=src_port_mac,
                            ip_src=src_port_ip,
                            ip_dst=dst_port_ip,
                            ip_tos=tos,
                            ip_id=exp_ip_id,
                            ip_ttl=64)
                send_packet(self, src_port_id, pkt)

            for i in range(0, queue_1_num_of_pkts):
                dscp = 8
                tos = dscp << 2
                tos |= ecn
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                            eth_dst=router_mac,
                            eth_src=src_port_mac,
                            ip_src=src_port_ip,
                            ip_dst=dst_port_ip,
                            ip_tos=tos,
                            ip_id=exp_ip_id,
                            ip_ttl=64)
                send_packet(self, src_port_id, pkt)

            for i in range(0, queue_3_num_of_pkts):
                dscp = 3
                tos = dscp << 2
                tos |= ecn
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                            eth_dst=router_mac,
                            eth_src=src_port_mac,
                            ip_src=src_port_ip,
                            ip_dst=dst_port_ip,
                            ip_tos=tos,
                            ip_id=exp_ip_id,
                            ip_ttl=64)
                send_packet(self, src_port_id, pkt)

            for i in range(0, queue_4_num_of_pkts):
                dscp = 4
                tos = dscp << 2
                tos |= ecn
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                            eth_dst=router_mac,
                            eth_src=src_port_mac,
                            ip_src=src_port_ip,
                            ip_dst=dst_port_ip,
                            ip_tos=tos,
                            ip_id=exp_ip_id,
                            ip_ttl=64)
                send_packet(self, src_port_id, pkt)

            # Set receiving socket buffers to some big value
            for p in self.dataplane.ports.values():
                p.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 41943040)

            # RELEASE PORT
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)

            cnt = 0
            pkts = []
            recv_pkt = scapy.Ether()

            while recv_pkt:
                received = self.dataplane.poll(device_number=0, port_number=dst_port_id, timeout=2)
                if isinstance(received, self.dataplane.PollFailure):
                    recv_pkt = None
                    break
                recv_pkt = scapy.Ether(received.packet)

                try:
                    if recv_pkt.payload.src == src_port_ip and recv_pkt.payload.dst == dst_port_ip and recv_pkt.payload.id == exp_ip_id:
                        cnt += 1
                        pkts.append(recv_pkt)
                except AttributeError:
                    continue

            queue_pkt_counters = [0,0,0,0,0,0,0,0,0]
            queue_num_of_pkts  = [queue_0_num_of_pkts, 0, 0, queue_3_num_of_pkts, queue_4_num_of_pkts, 0, 0, 0, 0, queue_1_num_of_pkts]
            total_pkts = 0
            limit = self.test_params['limit']

            for pkt_to_inspect in pkts:
                dscp_of_pkt = pkt_to_inspect.payload.tos >> 2
                total_pkts += 1

                # Count packet oredering

                queue_pkt_counters[dscp_of_pkt] += 1
                if queue_pkt_counters[dscp_of_pkt] == queue_num_of_pkts[dscp_of_pkt]:
                     assert ( (queue_0_num_of_pkts+queue_1_num_of_pkts+queue_3_num_of_pkts+queue_4_num_of_pkts) - total_pkts < limit)

                print queue_pkt_counters

            # Read Counters
            print "DST port counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
            print port_counters
            print queue_counters

        finally:
            # RELEASE PORT
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client, RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)

class LossyQueueTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        
        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
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
        src_port_mac = self.dataplane.get_mac(0, src_port_id)

        #STOP PORT FUNCTION
        sched_prof_id=sai_thrift_create_scheduler_profile(self.client, STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)
        self.client.sai_thrift_set_port_attribute(port_list[dst_port_2_id], attr)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #send packets
        try:
            tos = dscp << 2
            tos |= ecn
            ttl=64
            default_packet_length = 64
            # Calculate the max number of packets which port buffer can consists
            pkts_max = (max_buffer_size / default_packet_length) * 1.25
            pkts_bunch_size = 200 # Number of packages to send to DST port
            pkts_count = 0 # Total number of shipped packages
            egress_drop_counter = 0
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
            
            pkt = simple_tcp_packet(pktlen=default_packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)
            # Send packets till egress drop or max number of packages is reached
            while egress_drop_counter == 0 and pkts_count < pkts_max:
                send_packet(self, src_port_id, pkt, pkts_bunch_size)
                pkts_count += pkts_bunch_size
                time.sleep(5)
                
                port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
                egress_drop_counter = port_counters[EGRESS_DROP]
            
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
            assert (port_counters[EGRESS_DROP] != 0)

            # Send N packets to another port to fill the headroom and check if no drops
            pkt = simple_tcp_packet(pktlen=default_packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_2_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)
            no_drop_pkts_max = headroom_size / default_packet_length * 0.9

            if no_drop_pkts_max > 0:
                send_packet(self, src_port_id, pkt, no_drop_pkts_max)
                time.sleep(5)
            
                port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
                assert (port_counters[EGRESS_DROP] != 0)
            
                port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_2_id])
                assert (port_counters[EGRESS_DROP] == 0)
            
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])            
            assert (port_counters[INGRESS_DROP] == 0)

        finally:
            # RELEASE PORTS
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_2_id], attr)
