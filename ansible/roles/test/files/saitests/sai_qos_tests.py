"""
ACS Dataplane Qos tests
"""

import time
import logging
import ptf.packet as scapy
import socket
import ptf.dataplane as dataplane
import sai_base_test
from ptf.testutils import *
from ptf.mask import Mask
from switch import *

# Counters
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
SRC_PORT  = 0  # eth0
DST_PORT  = 1  # eth1
DST_PORT2 = 2  # eth2
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
                          hw_tgt='ff:ff:ff:ff:ff:ff')
            send_packet(self, port[1], arpreq_pkt)
            index += 1

#This test is to measure the Xoff threshold, and buffer limit
class PFCtest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        time.sleep(5)
        switch_init(self.client)
        num_of_extra_pkts=0

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #STOP PORT FUNCTION
        sched_prof_id=sai_thrift_create_scheduler_profile(self.client, STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)

        #send packets
        src_mac = [None, None]
        src_mac[0] = self.dataplane.get_mac(0, 0)
        router_mac = self.test_params['router_mac']
        dscp = self.test_params['dscp']
        ecn = 0
        tos = dscp << 2
        tos |= ecn
        ip_src = '10.0.0.1'
        ip_dst = '10.0.0.3'
        xoff_th_pkts = self.test_params['xoff_th_pkts']
        fill_buffer_pkts = self.test_params['fill_buffer_pkts']
        pg = self.test_params['pg'] + 2 #The pfc counter index starts from index 2

        try:
            for i in range(0, xoff_th_pkts):
                pkt = simple_tcp_packet(eth_dst=router_mac,
                                eth_src=src_mac[0],
                                ip_src=ip_src,
                                ip_dst=ip_dst,
                                ip_tos=tos,
                                ip_id=i,
                                ip_ttl=64)
                send_packet(self, 0, pkt)

            leaking_pkt_number = 0
            for (rcv_port_number, pkt_str, pkt_time) in self.dataplane.packets(0, 1):
                leaking_pkt_number += 1
            print "leaking packet %d" % leaking_pkt_number

            time.sleep(5)
            # Read Counters
            print "NO DROPS, NO PFCs, edge of xoff th"
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[SRC_PORT])
            print "PORT #"+str(hex(port_list[SRC_PORT]))+":"
            print port_counters
            print queue_counters
            assert(port_counters[EGRESS_DROP] == 0)
            assert(port_counters[INGRESS_DROP] == 0)
            assert(port_counters[pg] == 0)

            send_packet(self, 0, pkt)
            time.sleep(5)

            print "sent 1 more packet - NO DROPS, with PFC"
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[SRC_PORT])
            print "PORT #"+str(hex(port_list[SRC_PORT]))+":"
            print port_counters
            print queue_counters
            assert(port_counters[EGRESS_DROP] == 0)
            assert(port_counters[INGRESS_DROP] == 0)
            assert(port_counters[pg] != 0)

            for i in range(0, fill_buffer_pkts):
                pkt = simple_tcp_packet(eth_dst=router_mac,
                            eth_src=src_mac[0],
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            ip_tos=tos,
                            ip_id=i,
                            ip_ttl=64)
                send_packet(self, 0, pkt)

            time.sleep(5)
            print "sent pkts to max buff size - NO DROPS, with more PFC"
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[SRC_PORT])
            print "PORT #"+str(hex(port_list[SRC_PORT]))+":"
            print port_counters
            print queue_counters
            assert(port_counters[EGRESS_DROP] == 0)
            assert(port_counters[INGRESS_DROP] == 0)
            assert(port_counters[pg] != 0)

            send_packet(self, 0, pkt)
            time.sleep(5)

            # Read Counters
            print "sent 1 more packet - 1 ingress drop, no egress drop and with pfc"
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            print "PORT #"+str(hex(port_list[DST_PORT]))+":"
            print port_counters
            print queue_counters
            assert (port_counters[EGRESS_DROP] == 0)

            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[SRC_PORT])
            print "PORT #"+str(hex(port_list[SRC_PORT]))+":"
            print port_counters
            print queue_counters
            assert(port_counters[EGRESS_DROP] == 0)
            assert(port_counters[INGRESS_DROP] == 1)
            assert(port_counters[pg] != 0)

            # RELEASE PORT
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)

            time.sleep(5)

            # Read Counters
            print "AFTER RELEASE - max buffer size transmitted"
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            print "PORT #"+str(hex(port_list[DST_PORT]))+":"
            print port_counters
            print queue_counters

        finally:
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)
            print "END OF TEST"


class PFCXonTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        time.sleep(5)
        switch_init(self.client)
        last_pfc_counter = 0
        recv_port_counters = []
        transmit_port_counters = []
        transmit_port2_counters = []
        num_of_extra_pkts=0

        #STOP PORT FUNCTION
        sched_prof_id=sai_thrift_create_scheduler_profile(self.client,STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)
        self.client.sai_thrift_set_port_attribute(port_list[DST_PORT2],attr)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #send packets
        src_mac = [None, None]
        src_mac[0] = self.dataplane.get_mac(0, 0)
        router_mac = self.test_params['router_mac']
        dscp = self.test_params['dscp']
        ecn = 0
        tos = dscp << 2
        tos |= ecn
        ip_src  = '10.0.0.1'
        ip_dst  = '10.0.0.3'
        ip_dst2 = '10.0.0.5'
        xon_th_pkts = self.test_params['xon_th_pkts']
        xoff_th_pkts = self.test_params['xoff_th_pkts']
        pg = self.test_params['pg'] + 2 # The PFC counter index starts from index 2

        try:
            for i in range(0, xon_th_pkts):
                pkt = simple_tcp_packet(eth_dst=router_mac,
                                eth_src=src_mac[0],
                                ip_src=ip_src,
                                ip_dst=ip_dst,
                                ip_tos=tos,
                                ip_id=i,
                                ip_ttl=64)
                send_packet(self, 0, pkt)


            leaking_pkt_number = 0
            for (rcv_port_number, pkt_str, pkt_time) in self.dataplane.packets(0, 1):
                leaking_pkt_number += 1
            print "leaking packet %d" % leaking_pkt_number

            time.sleep(5)
            # Read Counters
            print "NO DROPS, NO PFCs"
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[SRC_PORT])
            transmit_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            transmit_port2_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT2])
            print "PORT #"+str(hex(port_list[SRC_PORT]))+":"
            print recv_port_counters
            assert (recv_port_counters[EGRESS_DROP] == 0)
            assert (recv_port_counters[INGRESS_DROP] == 0)
            assert (recv_port_counters[pg] == 0)

            pkt = simple_tcp_packet (eth_dst=router_mac,
                            eth_src=src_mac[0],
                            ip_src=ip_src,
                            ip_dst=ip_dst2,
                            ip_tos=tos,
                            ip_id=i,
                            ip_ttl=64)

            for i in range (0,xoff_th_pkts):
                send_packet(self, 0, pkt)
            time.sleep(5)

            print "send more packets up to Xoff th - NO DROPS, no PFC"
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[SRC_PORT])
            transmit_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            transmit_port2_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT2])
            print "PORT #"+str(hex(port_list[SRC_PORT]))+":"
            print recv_port_counters
            assert (recv_port_counters[EGRESS_DROP] == 0)
            assert (recv_port_counters[INGRESS_DROP] == 0)
            assert (recv_port_counters[pg] == 0)

            send_packet(self, 0, pkt)
            time.sleep(5)

            print "send 1 more packet to generate Xoff - NO DROPS, with PFC"
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[SRC_PORT])
            transmit_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            transmit_port2_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT2])
            print "PORT #"+str(hex(port_list[SRC_PORT]))+":"
            print recv_port_counters
            assert (recv_port_counters[EGRESS_DROP] == 0)
            assert (recv_port_counters[INGRESS_DROP] == 0)
            assert (recv_port_counters[pg] != 0)

            # RELEASE PORT
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT2],attr)
            time.sleep(8)

            # Read Counters
            print "AFTER first RELEASE - port2 packets transmitted, PFCs should stop from now"
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[SRC_PORT])
            transmit_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            transmit_port2_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT2])
            print "PORT #"+str(hex(port_list[SRC_PORT]))+":"
            print recv_port_counters
            assert (recv_port_counters[EGRESS_DROP] == 0)
            assert (recv_port_counters[INGRESS_DROP] == 0)
            assert (recv_port_counters[pg] != 0)
            last_pfc_counter = recv_port_counters[pg]
            assert (transmit_port2_counters[TRANSMITTED_PKTS] != 0)

            time.sleep(5)
            # Read Counters
            print "AFTER sleep -PFCs should stay the same"
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[SRC_PORT])
            transmit_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            transmit_port2_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT2])
            print "PORT #"+str(hex(port_list[SRC_PORT]))+":"
            print recv_port_counters
            assert (recv_port_counters[pg] == last_pfc_counter)

            # RELEASE PORT
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)
            time.sleep(5)

            # Read Counters
            print "AFTER second RELEASE - all buffer size transmitted"
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[SRC_PORT])
            transmit_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            transmit_port2_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT2])
            print recv_port_counters
            print transmit_port_counters
            print transmit_port2_counters

        finally:
            # RELEASE PORT
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT2],attr)
            print "END OF TEST"

class DscpEcnSend(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)

        #STOP PORT FUNCTION
        sched_prof_id=sai_thrift_create_scheduler_profile(self.client,STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #send packets
        src_mac = [None, None]
        src_mac[0] = self.dataplane.get_mac(0, 0)
        router_mac = self.test_params['router_mac']
        dscp = self.test_params['dscp']
        ecn = self.test_params['ecn']
        num_of_pkts = self.test_params['num_of_pkts']
        tos = dscp << 2
        tos |= ecn
        ip_src = '10.0.0.1'
        ip_dst = '10.0.0.3'

        try:
            for i in range(0, num_of_pkts):
                pkt = simple_tcp_packet(eth_dst=router_mac,
                            eth_src=src_mac[0],
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            ip_tos=tos,
                            ip_id=i,
                            ip_ttl=64)
                send_packet(self, 0, pkt)

            leaking_pkt_number = 0
            for (rcv_port_number, pkt_str, pkt_time) in self.dataplane.packets(0, 1):
                leaking_pkt_number += 1
            print "leaking packet %d" % leaking_pkt_number

            # Read Counters
            print "DST port counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
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
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)

            # if (ecn == 1) - capture and parse all incoming packets
            marked_cnt = 0
            not_marked_cnt = 0
            if (ecn == 1):
                print ""
                print "ECN capable packets generated, releasing dst_port and analyzing traffic -"

                cnt = 0
                pkts = []
                for i in xrange(num_of_pkts):
                    (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(self, device_number=0, port_number=1, timeout=0.2)
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
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            print port_counters
            print queue_counters
            limit = self.test_params['limit']
            min_limit = self.test_params['min_limit']
            cell_size = self.test_params['cell_size']
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
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)
            print "END OF TEST"

class DscpMappingPB(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        router_mac = self.test_params['router_mac']

        ## Clear Switch Counters
        sai_thrift_clear_all_counters(self.client)

        ## DSCP Mapping test
        try:
            src_mac = [None, None]
            src_mac[0] = self.dataplane.get_mac(0,0)
            src_mac[1] = self.dataplane.get_mac(0,1)
            for dscp in range(0,64):
                tos = dscp << 2
                pkt = simple_tcp_packet(eth_dst=router_mac,
                                        eth_src=src_mac[0],
                                        ip_src='10.0.0.1',
                                        ip_dst='10.0.0.3',
                                        ip_tos=tos,
                                        ip_id=101,
                                        ip_ttl=64)

                exp_pkt = simple_tcp_packet(eth_dst=src_mac[1],
                                        eth_src=router_mac,
                                        ip_src='10.0.0.1',
                                        ip_dst='10.0.0.3',
                                        ip_tos=tos,
                                        ip_id=101,
                                        ip_ttl=63)
                send_packet(self, 0, pkt)
                verify_packets(self, exp_pkt, [1])

            ## Read Counters
            port_results, queue_results = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])

            ## According to SONiC configuration all dscp are classified to queue 0 except:
            ## dscp 3 -> queue 3
            ## dscp 4 -> queue 4
            ## dscp 8 -> queue 1
            ## So for the 64 pkts sent the mapping should be -> 61 queue 0, and 1 for queue1, queue3 and queue4
            ## Check results
            assert (queue_results[QUEUE_0] == 61)
            assert (queue_results[QUEUE_1] == 1)
            assert (queue_results[QUEUE_3] == 1)
            assert (queue_results[QUEUE_4] == 1)

        finally:
            print "END OF TEST"



class ReleaseAllPorts(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        for port in port_list:
            self.client.sai_thrift_set_port_attribute(port,attr)

class WRRtest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)

        #STOP PORT FUNCTION
        sched_prof_id=sai_thrift_create_scheduler_profile(self.client,STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #send packets
        src_mac = [None, None]
        src_mac[0] = self.dataplane.get_mac(0, 0)
        router_mac = self.test_params['router_mac']
        ecn = 1
        ip_src = '10.0.0.1'
        ip_dst = '10.0.0.3'
        queue_0_num_of_pkts = self.test_params['q0_num_of_pkts']
        queue_1_num_of_pkts = self.test_params['q1_num_of_pkts']
        queue_3_num_of_pkts = self.test_params['q3_num_of_pkts']
        queue_4_num_of_pkts = self.test_params['q4_num_of_pkts']

        try:
            for i in range(0, queue_0_num_of_pkts):
                dscp = 0
                tos = dscp << 2
                tos |= ecn
                pkt = simple_tcp_packet(pktlen=1500,eth_dst=router_mac,
                            eth_src=src_mac[0],
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            ip_tos=tos,
                            ip_id=i,
                            ip_ttl=64)
                send_packet(self, 0, pkt)

            for i in range(0, queue_1_num_of_pkts):
                dscp = 8
                tos = dscp << 2
                tos |= ecn
                pkt = simple_tcp_packet(pktlen=1500,eth_dst=router_mac,
                            eth_src=src_mac[0],
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            ip_tos=tos,
                            ip_id=i,
                            ip_ttl=64)
                send_packet(self, 0, pkt)

            for i in range(0, queue_3_num_of_pkts):
                dscp = 3
                tos = dscp << 2
                tos |= ecn
                pkt = simple_tcp_packet(pktlen=1500,eth_dst=router_mac,
                            eth_src=src_mac[0],
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            ip_tos=tos,
                            ip_id=i,
                            ip_ttl=64)
                send_packet(self, 0, pkt)

            for i in range(0, queue_4_num_of_pkts):
                dscp = 4
                tos = dscp << 2
                tos |= ecn
                pkt = simple_tcp_packet(pktlen=1500,eth_dst=router_mac,
                            eth_src=src_mac[0],
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            ip_tos=tos,
                            ip_id=i,
                            ip_ttl=64)
                send_packet(self, 0, pkt)

            leaking_pkt_number = 0
            for (rcv_port_number, pkt_str, pkt_time) in self.dataplane.packets(0, 1):
                leaking_pkt_number += 1
            print "leaking packet %d" % leaking_pkt_number

            # Set receiving socket buffers to some big value
            for p in self.dataplane.ports.values():
                p.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 41943040)

            # RELEASE PORT
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)

            cnt = 0
            pkts = []
            for i in xrange(queue_0_num_of_pkts+queue_1_num_of_pkts+queue_3_num_of_pkts+queue_4_num_of_pkts):
                (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(self, device_number=0, port_number=1, timeout=0.2)
                if rcv_pkt is not None:
                    cnt += 1
                    pkts.append(rcv_pkt)
            print "    Received packets:    " + str(cnt)

            queue_pkt_counters = [0,0,0,0,0,0,0,0,0]
            queue_num_of_pkts  = [queue_0_num_of_pkts, 0, 0, queue_3_num_of_pkts, queue_4_num_of_pkts, 0, 0, 0, 0, queue_1_num_of_pkts]
            total_pkts = 0
            limit = self.test_params['limit']

            for pkt_to_inspect in pkts:
                pkt_str = hex_dump_buffer(pkt_to_inspect)
                dscp_of_pkt = int ( ( (int(pkt_str[DSCP_INDEX_IN_HEADER],16) << 4) | int(pkt_str[ECN_INDEX_IN_HEADER],16)) >> 2 )
                total_pkts += 1

                # Count packet oredering

                queue_pkt_counters[dscp_of_pkt] += 1
                if queue_pkt_counters[dscp_of_pkt] == queue_num_of_pkts[dscp_of_pkt]:
                     assert ( (queue_0_num_of_pkts+queue_1_num_of_pkts+queue_3_num_of_pkts+queue_4_num_of_pkts) - total_pkts < limit)

                print queue_pkt_counters

            # Read Counters
            print "DST port counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            print port_counters
            print queue_counters

        finally:
            # RELEASE PORT
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)

class LossyQueueTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)

        #STOP PORT FUNCTION
        sched_prof_id=sai_thrift_create_scheduler_profile(self.client,STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)
        self.client.sai_thrift_set_port_attribute(port_list[DST_PORT2],attr)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #send packets
        src_mac = [None, None]
        src_mac[0] = self.dataplane.get_mac(0, 0)
        router_mac = self.test_params['router_mac']
        ecn = 1
        dscp = self.test_params['dscp']
        tos = dscp << 2
        tos |= ecn
        num_of_pkts = self.test_params['num_of_pkts']
        ip_src = '10.0.0.1'
        ip_dst = '10.0.0.3'
        ip_dst2 = '10.0.0.5'

        try:
            for i in range(0, num_of_pkts):
                pkt = simple_tcp_packet(eth_dst=router_mac,
                            eth_src=src_mac[0],
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            ip_tos=tos,
                            ip_id=i,
                            ip_ttl=64)
                send_packet(self, 0, pkt)

            leaking_pkt_number = 0
            for (rcv_port_number, pkt_str, pkt_time) in self.dataplane.packets(0, 1):
                leaking_pkt_number += 1
            print "leaking packet %d" % leaking_pkt_number

            # Read Counters
            print "DST port counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            print port_counters
            print queue_counters
            assert (port_counters[EGRESS_DROP] == 0)


            send_packet(self, 0, pkt)


            # Read Counters
            print "DST port counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            print port_counters
            print queue_counters
            assert (port_counters[EGRESS_DROP] == 1)

            pkt = simple_tcp_packet(eth_dst=router_mac,
                        eth_src=src_mac[0],
                        ip_src=ip_src,
                        ip_dst=ip_dst2,
                        ip_tos=tos,
                        ip_id=i,
                        ip_ttl=64)

            send_packet(self, 0, pkt)

            # Read Counters
            print "DST port counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            print port_counters
            print queue_counters
            assert (port_counters[EGRESS_DROP] == 1)

            # Read Counters
            print "DST port2 counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT2])
            print port_counters
            print queue_counters
            assert (port_counters[EGRESS_DROP] == 0)

            # Read Counters
            print "SRC port counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[SRC_PORT])
            print port_counters
            print queue_counters
            assert (port_counters[INGRESS_DROP] == 0)

            # RELEASE PORTS
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT2],attr)

            # Read Counters
            print "DST port counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT])
            print port_counters
            print queue_counters

            # Read Counters
            print "DST port2 counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[DST_PORT2])
            print port_counters
            print queue_counters

            # Read Counters
            print "SRC port counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[SRC_PORT])
            print port_counters
            print queue_counters

        finally:
            # RELEASE PORTS
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT],attr)
            self.client.sai_thrift_set_port_attribute(port_list[DST_PORT2],attr)
