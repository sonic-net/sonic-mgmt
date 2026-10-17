#
# Copyright 2021-present Intel Corporation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# The below software in this distribution may have been modified
# by Centec . All Centec Modifications
# are copyright © Centec(Suzhou) Technology Limited.
#

"""
Thrift SAI interface PBH tests
"""
from sai_thrift.sai_headers import *

from ptf.mask import Mask
from ptf.packet import *
from ptf.testutils import *
from ptf.thriftutils import *

from sai_base_test import *
import random
import binascii
import ctypes

MAX_ITRS = 12
TEST_ECMP_SEED = 211  # test default ECMP seed value
TEST_ECMP_SEED1 = 411  # ecmp seed tests second value

def nhg_members_count(client,next_hop_group):
    """
    Gets nexthop group members counter value

    Args:
        client (sai_thrift.sai_rpc.Client): RPC client
        next_hop_group (oid): next hop group object ID

    Returns:
        int: ngh members counter
    """
    attr_list = sai_thrift_get_next_hop_group_attribute(client,
                                                        next_hop_group,
                                                        next_hop_count=True)
    next_hop_count = attr_list["SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_COUNT"]
    return next_hop_count

def generate_random_ip():
    ip_segments = [str(random.randint(0,255)) for _ in range(4)]
    ip = ".".join(ip_segments)

    invalid_ips = {"0.0.0.0","255.255.255.255"}

    if 224<=int(ip_segments[0])<=239:
        return generate_random_ip()

    if ip in invalid_ips:
        return generate_random_ip()

    if int(ip_segments[0]) == 0:
        return generate_random_ip()

    if int(ip_segments[3]) == 0:
        return generate_random_ip()
    return ip

def batch_generate_unicast_ips(count):
    if count <= 0:
        raise ValueError("生成数量必须为正整数")
    ips = []
    while len(ips) < count:
        ip = generate_random_ip()

        if  ip in ips: #去重
            continue

        ips.append(ip)
    return ips

def get_pbh_enable_status(self,port,nexthop_group):

    ppn_enable_status = []
    switch_lvl0_ppn_enable = False
    switch_lvl1_ppn_enable = False
    port_lvl0_ppn_enable   = False
    port_lvl1_ppn_enable   = False
    port_lbid              = 0
    ecmp_lvl0_ppn_enable   = False
    ecmp_lvl1_ppn_enable   = False

    switch_ppn_attr = sai_thrift_get_switch_attribute(self.client,custom_ecmp_lvl0_ppn_enable=True,custom_ecmp_lvl1_ppn_enable=True)
    switch_lvl0_ppn_enable = switch_ppn_attr['custom_ecmp_lvl0_ppn_enable']
    switch_lvl1_ppn_enable = switch_ppn_attr['custom_ecmp_lvl1_ppn_enable']
    port_ppn_attr = sai_thrift_get_port_attribute(self.client,port_oid=port,ppn_l0_enable=True,ppn_l1_enable=True,lbid=True)
    port_lvl0_ppn_enable   = port_ppn_attr["ppn_l0_enable"]
    port_lvl1_ppn_enable   = port_ppn_attr["ppn_l1_enable"]
    port_lbid              = (ctypes.c_uint8(port_ppn_attr["lbid"])).value
    ecmp_ppn_attr = sai_thrift_get_next_hop_group_attribute(self.client,next_hop_group_oid=nexthop_group,custom_ecmp_lvl0_ppn_enable=True,custom_ecmp_lvl1_ppn_enable=True)
    ecmp_lvl0_ppn_enable   = ecmp_ppn_attr['custom_ecmp_lvl0_ppn_enable']
    ecmp_lvl1_ppn_enable   = ecmp_ppn_attr['custom_ecmp_lvl1_ppn_enable']

    ppn_enable_status = [switch_lvl0_ppn_enable,switch_lvl1_ppn_enable,port_lvl0_ppn_enable,port_lvl1_ppn_enable,port_lbid,ecmp_lvl0_ppn_enable,ecmp_lvl1_ppn_enable]

    print(f"\n{'='*80}")
    print("获取pbh各级开关使能情况")
    print(f"{'='*80}")

    print(" switch lvl0 ppn enable status is  {}".format(switch_lvl0_ppn_enable))
    print(" switch lvl1 ppn enable status is  {}".format(switch_lvl1_ppn_enable))
    print(" port lvl0 ppn enable status   is  {}".format(port_lvl0_ppn_enable))
    print(" port lvl1 ppn enable status   is  {}".format(port_lvl1_ppn_enable))
    print(" port lbid                     is  {}".format(port_lbid))
    print(" ecmp lvl0 ppn enable status   is  {}".format(ecmp_lvl0_ppn_enable))
    print(" ecmp lvl1 ppn enable status   is  {}".format(ecmp_lvl1_ppn_enable))

    return ppn_enable_status


def print_pbhtest_results(ecmp_pbh_test,results, title="PBH Test Results"):


    print(f"\n{'='*80}")
    print(f"{title:^80}")
    print("ecmp pbh profile status is {}".format(ecmp_pbh_test))
    print(f"{'='*80}")

    # # Print table header
    keys = list(results.keys())

    for i,index in enumerate(keys):
        print(f"{'':<20}{'switch':<20}{'port':<20}{'ecmp':<20}")
        print(f"{'-'*80}")
        print(f"{'lvl0 ppn enable':<20}{results[index].get('pbh enable status')[0]:<20}{results[index].get('pbh enable status')[2]:<20}{results[index].get('pbh enable status')[5]:<20}")
        print(f"{'lvl1 ppn enable':<20}{results[index].get('pbh enable status')[1]:<20}{results[index].get('pbh enable status')[3]:<20}{results[index].get('pbh enable status')[6]:<20}")
        print(f"{'lbid':<20}{'':<20}{results[index].get('pbh enable status')[4]:<20}{'':<20}")
        print(f"{'-'*80}")
        print("ecmp hash result  {}".format(results[index].get('count')))


def setupECMPHash(self, hash_field_list=None):
    """
    Setups ECMP  hash
    Args:
        hash_field_list (list): list of hash fields
    """
    print("Setting the ECMP  hash fields..")

    attr_list = sai_thrift_get_switch_attribute(self.client, ecmp_hash=True)
    self.ecmp_hash_id = attr_list['SAI_SWITCH_ATTR_ECMP_HASH']

    if hash_field_list is None:
        hash_field_list = [SAI_NATIVE_HASH_FIELD_DST_IP,SAI_NATIVE_HASH_FIELD_SRC_IP]

    hash_attr_list = sai_thrift_s32_list_t(
        count=len(hash_field_list),
        int32list=hash_field_list)
    status = sai_thrift_set_hash_attribute(
        self.client,
        self.ecmp_hash_id,
        native_hash_field_list=hash_attr_list)
    self.assertEqual(status, SAI_STATUS_SUCCESS)



class PBHBasicHelper(SaiHelperSimplified):
    """
    Basic PBH tests.
    Configuration
    +----------+-----------+
    | port0    | port0_rif |
    +----------+-----------+
    | port1    | port1_rif |
    +----------+-----------+
    | port2    | port2_rif |
    +----------+-----------+
    | port24    | port24_rif |
    """
    def __init__(self, ecmp_pbh_test=False):
        super(PBHBasicHelper, self).__init__()
        self.ecmp_pbh_test = ecmp_pbh_test

    def setUp(self):
        super(PBHBasicHelper, self).setUp()
        setupECMPHash(self)
        DEFAULT_IP_V4_PREFIX = '0.0.0.0/0'
        self.mac1 = '00:99:99:99:99:01'
        self.mac2 = '00:99:99:99:99:02'
        self.mac3 = '00:99:99:99:99:03'
        self.mac4 = '00:99:99:99:99:04'

        print("Step1.create rif ")
        self.create_routing_interfaces(ports=[0,1,2,24])

        print("Step2.create nhop")
        self.neighbor_entry1 = sai_thrift_neighbor_entry_t(
            rif_id=self.port0_rif, ip_address=sai_ipaddress('10.10.10.1'))
        sai_thrift_create_neighbor_entry(self.client, self.neighbor_entry1,
                                         dst_mac_address=self.mac1,no_host_route=True)
        self.nhop1 = sai_thrift_create_next_hop(self.client,
                                          ip=sai_ipaddress('10.10.10.1'),
                                          router_interface_id=self.port0_rif,
                                          type=SAI_NEXT_HOP_TYPE_IP)

        self.neighbor_entry2 = sai_thrift_neighbor_entry_t(
            rif_id=self.port1_rif, ip_address=sai_ipaddress('10.10.10.2'))
        sai_thrift_create_neighbor_entry(self.client, self.neighbor_entry2,
                                         dst_mac_address=self.mac2,no_host_route=True)
        self.nhop2 = sai_thrift_create_next_hop(self.client,
                                          ip=sai_ipaddress('10.10.10.2'),
                                          router_interface_id=self.port1_rif,
                                          type=SAI_NEXT_HOP_TYPE_IP)

        self.neighbor_entry3 = sai_thrift_neighbor_entry_t(
            rif_id=self.port2_rif, ip_address=sai_ipaddress('10.10.10.3'))
        sai_thrift_create_neighbor_entry(self.client, self.neighbor_entry3,
                                         dst_mac_address= self.mac3,no_host_route=True)
        self.nhop3 = sai_thrift_create_next_hop(self.client,
                                          ip=sai_ipaddress('10.10.10.3'),
                                          router_interface_id=self.port2_rif,
                                          type=SAI_NEXT_HOP_TYPE_IP)

        self.neighbor_entry4 = sai_thrift_neighbor_entry_t(
            rif_id=self.port24_rif, ip_address=sai_ipaddress('10.10.10.4'))
        sai_thrift_create_neighbor_entry(self.client, self.neighbor_entry4,
                                         dst_mac_address=self.mac4,no_host_route=True)
        self.nhop4 = sai_thrift_create_next_hop(self.client,
                                          ip=sai_ipaddress('10.10.10.4'),
                                          router_interface_id=self.port24_rif,
                                          type=SAI_NEXT_HOP_TYPE_IP)
        print("Step3.create ecmp group  ")
        self.nhop_group1 = sai_thrift_create_next_hop_group(
            self.client, type=SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_ORDERED_ECMP,custom_ecmp_lvl1_ppn_enable=False)
        self.nh_group_member1 = sai_thrift_create_next_hop_group_member(
            self.client,
            next_hop_group_id=self.nhop_group1,
            next_hop_id=self.nhop1,sequence_id=1)
        self.nh_group_member2 = sai_thrift_create_next_hop_group_member(
            self.client,
            next_hop_group_id=self.nhop_group1,
            next_hop_id=self.nhop2,sequence_id=2)
        self.nh_group_member3 = sai_thrift_create_next_hop_group_member(
            self.client,
            next_hop_group_id=self.nhop_group1,
            next_hop_id=self.nhop3,sequence_id=3)

        print("Step4.create default v4 route to Ecmp ")
        self.default_ipv4_route_entry = sai_thrift_route_entry_t(switch_id=self.switch_id,
                                                                 vr_id=self.default_vrf,
                                                                 destination=sai_ipprefix(DEFAULT_IP_V4_PREFIX))
        status = sai_thrift_create_route_entry(
            self.client,
            route_entry=self.default_ipv4_route_entry,
            next_hop_id=self.nhop_group1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

    def tearDown(self):
        sai_thrift_remove_neighbor_entry(self.client, self.neighbor_entry1)
        sai_thrift_remove_neighbor_entry(self.client, self.neighbor_entry2)
        sai_thrift_remove_neighbor_entry(self.client, self.neighbor_entry3)
        sai_thrift_remove_neighbor_entry(self.client, self.neighbor_entry4)
        sai_thrift_remove_next_hop_group_member(self.client,
                                                self.nh_group_member1)
        sai_thrift_remove_next_hop_group_member(self.client,
                                                self.nh_group_member2)
        sai_thrift_remove_next_hop_group_member(self.client,
                                                self.nh_group_member3)
        sai_thrift_remove_route_entry(self.client, self.default_ipv4_route_entry)
        self.assertEqual(nhg_members_count(self.client,self.nhop_group1), 0)
        sai_thrift_remove_next_hop_group(self.client, self.nhop_group1)
        sai_thrift_remove_next_hop(self.client, self.nhop1)
        sai_thrift_remove_next_hop(self.client, self.nhop2)
        sai_thrift_remove_next_hop(self.client, self.nhop3)
        sai_thrift_remove_next_hop(self.client, self.nhop4)

        self.destroy_routing_interfaces()
        sai_thrift_set_switch_attribute(self.client, custom_ecmp_lvl1_ppn_enable=False,custom_ecmp_lvl0_ppn_enable=False,)
        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=False,ppn_l0_enable=False,lbid=0)
        super(PBHBasicHelper, self).tearDown()

    def TrafficTest(self,pkt_params):
        '''
        For sending traffic
        Returns:
            int: pkts count
        '''
        print('Sending Traffic')


        ports = list(pkt_params.keys())

        count = len(ports)*[0]
        dst_ip_list = batch_generate_unicast_ips(count=MAX_ITRS)
        src_mac_start = '00:22:22:22:22:'
        for i,dst_ip_addr in enumerate(dst_ip_list):
            print("dst_ip is %s"%dst_ip_addr)
            exp_pkts = []
            src_mac = src_mac_start + str(i % 99).zfill(2)
            pkt = simple_tcp_packet(eth_dst=ROUTER_MAC,
                                    eth_src=src_mac,
                                    ip_dst=dst_ip_addr,
                                    ip_src='192.168.8.1',
                                    ip_id=106,
                                    ip_ttl=64)

            for port in pkt_params:
                exp_pkt = simple_tcp_packet(eth_dst=pkt_params[port]["dmac"],
                                            eth_src=ROUTER_MAC,
                                            ip_dst=dst_ip_addr,
                                            ip_src='192.168.8.1',
                                            ip_id=106,
                                            ip_ttl=63)
                exp_pkts.append(exp_pkt)

            send_packet(self, self.dev_port24, pkt)
            rcv_idx = verify_any_packet_any_port(
                self,exp_pkts,ports)
            count[rcv_idx] += 1

        return count




class PBHBasicfunctionTest(PBHBasicHelper):
    '''
    验证普通三层转发场景下pbh功能,支持乱序下配置
    '''
    def __init__(self):
        super(PBHBasicfunctionTest, self).__init__(
            ecmp_pbh_test=True)

    def setUp(self):
        super(PBHBasicfunctionTest, self).setUp()


    def runTest(self):
        print("PBHBasicfunctionTest")

        pkt_params = {
            self.dev_port0: {
                "dmac": self.mac1
            },
            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            }
        }

        nhg_member_count = nhg_members_count( self.client,self.nhop_group1)
        self.results_dict = {}
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)

        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        for i in range(nhg_member_count):
            self.assertTrue((count[i] >= ((MAX_ITRS / nhg_member_count) * 0.2)),
                            'Not all paths are equally balanced, %s'% count)
        self.results_dict[0] = {
            'pbh enable status': pbh_status,
            'count': count
        }


        print("enable switch pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=True)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        for i in range(nhg_member_count):
            self.assertTrue((count[i] >= ((MAX_ITRS / nhg_member_count) * 0.2)),
                            'Not all paths are equally balanced, %s'% count)
        self.results_dict[1] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("enable port24 pbh,LBID=0")
        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=True,lbid=0)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        if self.ecmp_pbh_test == True:
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            for i in range(nhg_member_count):
                self.assertTrue((count[i] >= ((MAX_ITRS / nhg_member_count) * 0.2)),
                                'Not all paths are equally balanced, %s'% count)
        else:
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            self.assertTrue((count[0] == MAX_ITRS),
                                    ' all pkts to port0 , %s'% count)

        self.results_dict[2] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("enable Ecmp pbh")
        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)
        ecmp_ppn_attr = sai_thrift_get_next_hop_group_attribute(self.client,next_hop_group_oid=self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)
        ecmp_lvl1_ppn_enable   = ecmp_ppn_attr['custom_ecmp_lvl1_ppn_enable']
        if self.ecmp_pbh_test == True:
            self.assertTrue(ecmp_lvl1_ppn_enable == True)
        else:
            self.assertTrue(ecmp_lvl1_ppn_enable == False)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[0] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)
        self.results_dict[3] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("set port24 pbh LBID=1")
        sai_thrift_set_port_attribute(self.client,self.port24,lbid=1)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[1] == MAX_ITRS),
                                ' all pkts to port1 , %s'% count)

        self.results_dict[4] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("set port24 pbh LBID=11")
        sai_thrift_set_port_attribute(self.client,self.port24,lbid=11)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[2] == MAX_ITRS),
                                ' all pkts to port1 , %s'% count)
        self.results_dict[5] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("disable switch pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=False)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        for i in range(nhg_member_count):
            self.assertTrue((count[i] >= ((MAX_ITRS / nhg_member_count) * 0.2)),
                            'Not all paths are equally balanced, %s'% count)
        self.results_dict[6] = {
            'pbh enable status': pbh_status,
            'count': count
        }


        print("enable switch pbh,disable ecmp pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=True)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[2] == MAX_ITRS),
                                ' all pkts to port1 , %s'% count)
        self.results_dict[7] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=False)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        if self.ecmp_pbh_test == True:
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            for i in range(nhg_member_count):
                self.assertTrue((count[i] >= ((MAX_ITRS / nhg_member_count) * 0.2)),
                                'Not all paths are equally balanced, %s'% count)
        else:
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            self.assertTrue((count[2] == MAX_ITRS),
                                    ' all pkts to port1 , %s'% count)

        self.results_dict[8] = {
            'pbh enable status': pbh_status,
            'count': count
        }


        print("enable ecmp pbh,disable port pbh")
        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[2] == MAX_ITRS),
                                ' all pkts to port1 , %s'% count)

        self.results_dict[9] = {
            'pbh enable status': pbh_status,
            'count': count
        }


        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=False)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        for i in range(nhg_member_count):
            self.assertTrue((count[i] >= ((MAX_ITRS / nhg_member_count) * 0.2)),
                            'Not all paths are equally balanced, %s'% count)
        self.results_dict[10] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("enable port pbh")
        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=True)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[2] == MAX_ITRS),
                                ' all pkts to port1 , %s'% count)
        self.results_dict[11] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print_pbhtest_results(self.ecmp_pbh_test,self.results_dict, "PBh Test Results")

    def tearDown(self):
        super(PBHBasicfunctionTest, self).tearDown()



class _pbhecmpSequenceTest1(PBHBasicHelper):
    '''
    Verify pbh for the following sequence of objects creation:
    port pbh enable-> switch pbh enabele ->ecmp pbh enable
    '''
    def __init__(self):
        super(_pbhecmpSequenceTest1, self).__init__(
            ecmp_pbh_test=True)

    def setUp(self):
        super(_pbhecmpSequenceTest1, self).setUp()


    def runTest(self):

        self.results_dict = {}
        print("enable port3 pbh")

        lbid_index = random.randint(0,127)
        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=True,lbid=lbid_index)
        export_index = lbid_index % nhg_members_count(self.client,self.nhop_group1)

        print("enable switch pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=True)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        print("enable Ecmp pbh")
        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)

        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)

        pkt_params = {
            self.dev_port0: {
                "dmac": self.mac1
            },
            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            }
        }

        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)

        self.results_dict[0] = {
            'pbh enable status': pbh_status,
            'count': count
        }
        print_pbhtest_results(self.ecmp_pbh_test,self.results_dict, "PBh ECMP  sequence 1 Results")

    def tearDown(self):
        super(_pbhecmpSequenceTest1, self).tearDown()


class _pbhecmpSequenceTest2(PBHBasicHelper):
    '''
    Verify pbh for the following sequence of objects creation:
    port pbh enable-> ecmp pbh enabele ->switch pbh enable
    '''
    def __init__(self):
        super(_pbhecmpSequenceTest2, self).__init__(
            ecmp_pbh_test=True)

    def setUp(self):
        super(_pbhecmpSequenceTest2, self).setUp()

    def runTest(self):

        print("PBH  ECMP  sequence 2")
        self.results_dict = {}
        print("enable port24 pbh")
        lbid_index = random.randint(0,127)
        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=True,lbid=lbid_index)
        export_index = lbid_index % nhg_members_count(self.client,self.nhop_group1)

        print("enable Ecmp pbh")
        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)

        print("enable switch pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=True)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        pkt_params = {
            self.dev_port0: {
                "dmac": self.mac1
            },
            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            }
        }
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port1, %s'% count)
        self.results_dict[0] = {
            'pbh enable status': pbh_status,
            'count': count
        }
        print_pbhtest_results(self.ecmp_pbh_test,self.results_dict, "PBh ECMP  sequence 2 Results")

    def tearDown(self):
        super(_pbhecmpSequenceTest2, self).tearDown()


class _pbhecmpSequenceTest3(PBHBasicHelper):
    '''
    Verify pbh for the following sequence of objects creation:
    switch pbh enable-> ecmp pbh enabele ->port pbh enable
    '''
    def __init__(self):
        super(_pbhecmpSequenceTest3, self).__init__(
            ecmp_pbh_test=True)

    def setUp(self):
        super(_pbhecmpSequenceTest3, self).setUp()

    def runTest(self):
        print("PBH  ECMP  sequence 3")
        self.results_dict = {}
        print("enable switch pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=True)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        print("enable Ecmp pbh")
        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)

        print("enable port24 pbh")
        lbid_index = random.randint(0,127)
        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=True,lbid=lbid_index)
        export_index = lbid_index % nhg_members_count(self.client,self.nhop_group1)




        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        pkt_params = {
            self.dev_port0: {
                "dmac": self.mac1
            },
            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            }
        }
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port2 , %s'% count)
        self.results_dict[0] = {
            'pbh enable status': pbh_status,
            'count': count
        }
        print_pbhtest_results(self.ecmp_pbh_test,self.results_dict, "PBh ECMP  sequence 3 Results")

    def tearDown(self):
        super(_pbhecmpSequenceTest3, self).tearDown()


class _pbhecmpSequenceTest4(PBHBasicHelper):
    '''
    Verify pbh for the following sequence of objects creation:
    ecmp pbh enable-> switch pbh enabele ->port pbh enable
    '''
    def __init__(self):
        super(_pbhecmpSequenceTest4, self).__init__(
            ecmp_pbh_test=True)

    def setUp(self):
        super(_pbhecmpSequenceTest4, self).setUp()

    def runTest(self):
        print("PBH  ECMP  sequence 4")

        self.results_dict = {}

        print("enable Ecmp pbh")
        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)

        print("enable switch pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=True)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        print("enable port24 pbh")
        lbid_index = random.randint(0,127)
        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=True,lbid=lbid_index)
        export_index = lbid_index % nhg_members_count(self.client,self.nhop_group1)

        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        pkt_params = {
            self.dev_port0: {
                "dmac": self.mac1
            },
            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            }
        }
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)
        self.results_dict[0] = {
            'pbh enable status': pbh_status,
            'count': count
        }
        print_pbhtest_results(self.ecmp_pbh_test,self.results_dict, "PBh ECMP  sequence 4 Results")

    def tearDown(self):
        super(_pbhecmpSequenceTest4, self).tearDown()


class _pbhecmpSequenceTest5(PBHBasicHelper):
    '''
    Verify pbh for the following sequence of objects creation:
    ecmp pbh enable-> port pbh enabele ->switch pbh enable
    '''
    def __init__(self):
        super(_pbhecmpSequenceTest5, self).__init__(
            ecmp_pbh_test=True)

    def setUp(self):
        super(_pbhecmpSequenceTest5, self).setUp()

    def runTest(self):
        print("PBH  ECMP  sequence 5")
        self.results_dict = {}


        print("enable Ecmp pbh")
        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)
        print("enable port24 pbh")

        lbid_index = random.randint(0,255)
        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=True,lbid=(ctypes.c_int8(lbid_index)).value)
        export_index = lbid_index % nhg_members_count(self.client,self.nhop_group1)

        print("enable switch pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=True)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)

        pkt_params = {
            self.dev_port0: {
                "dmac": self.mac1
            },
            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            }
        }

        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[export_index] == MAX_ITRS))

        self.results_dict[0] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("disable Ecmp pbh")
        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=False)

        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        # self.assertTrue((count[export_index] == MAX_ITRS))
        if self.ecmp_pbh_test == True:
            for i in range(nhg_members_count( self.client,self.nhop_group1)):
                self.assertTrue((count[i] >= ((MAX_ITRS / nhg_members_count( self.client,self.nhop_group1)) * 0.2)),
                                'Not all paths are equally balanced, %s'% count)
        else:
            self.assertTrue((count[export_index] == MAX_ITRS),
                                    ' all pkts to port1 , %s'% count)
        self.results_dict[1] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("enable Ecmp pbh")
        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)

        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[export_index] == MAX_ITRS))

        self.results_dict[2] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print_pbhtest_results(self.ecmp_pbh_test,self.results_dict, "PBh ECMP  sequence 5 Results")

    def tearDown(self):
        super(_pbhecmpSequenceTest5, self).tearDown()


class _pbhecmpEcmpAddRemoveNhopTest(PBHBasicHelper):
    '''
    Verify pbh  with removal of a nexthop member
    '''
    def __init__(self):
        super(_pbhecmpEcmpAddRemoveNhopTest, self).__init__(
            ecmp_pbh_test=True)

    def setUp(self):
        super(_pbhecmpEcmpAddRemoveNhopTest, self).setUp()


    def runTest(self):

        self.results_dict = {}
        print("enable port24 pbh")
        lbid_index = random.randint(0,127)
        print(" port24 pbh lbid %s"%lbid_index)
        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=True,lbid=lbid_index)
        export_index = lbid_index % nhg_members_count(self.client,self.nhop_group1)

        print("enable switch pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=True)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        print("enable Ecmp pbh")
        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)

        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)

        pkt_params = {
            self.dev_port0: {
                "dmac": self.mac1
            },
            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            }
        }
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)

        self.results_dict[0] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("Add new nhg member")
        self.create_routing_interfaces(ports=[3])
        dmac4 = '00:77:77:77:77:77'
        nhop_new_ip = '10.10.10.5'
        neighbor_entry = sai_thrift_neighbor_entry_t(
            self.switch_id, rif_id=self.port3_rif, ip_address=sai_ipaddress(nhop_new_ip))
        sai_thrift_create_neighbor_entry(
            self.client, neighbor_entry, dst_mac_address=dmac4)
        new_next_hop = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_IP,
            router_interface_id=self.port3_rif,
            ip=sai_ipaddress(nhop_new_ip))
        new_nhg1_member = sai_thrift_create_next_hop_group_member(
            self.client,
            next_hop_group_id=self.nhop_group1,
            next_hop_id=new_next_hop,sequence_id=4)

        export_index = lbid_index % nhg_members_count(self.client,self.nhop_group1)

        pkt_params = {
            self.dev_port0: {
                "dmac": self.mac1
            },
            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            },
            self.dev_port3: {
                "dmac": dmac4
            }
        }
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)

        self.results_dict[1] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        sai_thrift_remove_neighbor_entry(self.client, neighbor_entry)
        sai_thrift_remove_next_hop_group_member(self.client,
                                                new_nhg1_member)
        sai_thrift_remove_next_hop(self.client, new_next_hop)
        export_index = lbid_index % nhg_members_count(self.client,self.nhop_group1)
        pkt_params = {
            self.dev_port0: {
                "dmac": self.mac1
            },
            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            }
        }
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))

        self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)

        self.results_dict[2] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        sai_thrift_remove_neighbor_entry(self.client, self.neighbor_entry1)
        sai_thrift_remove_next_hop_group_member(self.client,
                                                self.nh_group_member1)
        sai_thrift_remove_next_hop(self.client, self.nhop1)
        export_index = lbid_index % nhg_members_count(self.client,self.nhop_group1)
        pkt_params = {

            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            }
        }
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))

        self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)

        self.results_dict[3] = {
            'pbh enable status': pbh_status,
            'count': count
        }
        print_pbhtest_results(self.ecmp_pbh_test,self.results_dict, "PBh ECMP  Results")


    def tearDown(self):
        super(_pbhecmpEcmpAddRemoveNhopTest, self).tearDown()


class L3IPv6EcmpPbhHelper(PlatformSaiHelper):

    def setUp(self):

        super(L3IPv6EcmpPbhHelper, self).setUp()

        ip_addr1 = '5000:1:1:0:0:0:0:1'
        ip_addr2 = '5000:1:1:0:0:0:0:2'
        dmac1 = '00:11:22:33:44:55'
        dmac2 = '00:11:22:33:44:56'

        sai_thrift_set_switch_attribute(self.client, src_mac_address=ROUTER_MAC)
        setupECMPHash(self)
        # test neighbor creation
        self.neighbor_entry1 = sai_thrift_neighbor_entry_t(
            self.switch_id, rif_id=self.port11_rif, ip_address=sai_ipaddress(ip_addr1))
        sai_thrift_create_neighbor_entry(
            self.client, self.neighbor_entry1, dst_mac_address=dmac1,no_host_route=True)
        self.neighbor_entry2 = sai_thrift_neighbor_entry_t(
            self.switch_id, rif_id=self.port12_rif, ip_address=sai_ipaddress(ip_addr2))
        sai_thrift_create_neighbor_entry(
            self.client, self.neighbor_entry2, dst_mac_address=dmac2,no_host_route=True)
        self.nhop1 = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_IP,
            router_interface_id=self.port11_rif,
            ip=sai_ipaddress(ip_addr1))
        self.nhop2 = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_IP,
            router_interface_id=self.port12_rif,
            ip=sai_ipaddress(ip_addr2))
        self.nhop_group1 = sai_thrift_create_next_hop_group(
            self.client, type=SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_ORDERED_ECMP)
        self.nh_group_member1 = sai_thrift_create_next_hop_group_member(
            self.client,
            next_hop_group_id=self.nhop_group1,
            next_hop_id=self.nhop1,sequence_id=1)
        self.nh_group_member2 = sai_thrift_create_next_hop_group_member(
            self.client,
            next_hop_group_id=self.nhop_group1,
            next_hop_id=self.nhop2,sequence_id=2)
        # create route entries
        self.route0 = sai_thrift_route_entry_t(
            switch_id=self.switch_id,
            destination=sai_ipprefix(f'{ip_addr1}/64'),
            vr_id=self.default_vrf)
        status = sai_thrift_create_route_entry(
            self.client, self.route0, next_hop_id=self.nhop_group1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

    def tearDown(self):
        sai_thrift_remove_neighbor_entry(self.client, self.neighbor_entry1)
        sai_thrift_remove_neighbor_entry(self.client, self.neighbor_entry2)
        sai_thrift_remove_next_hop_group_member(self.client,
                                                self.nh_group_member1)
        sai_thrift_remove_next_hop_group_member(self.client,
                                                self.nh_group_member2)
        sai_thrift_remove_route_entry(self.client, self.route0)
        self.assertEqual(nhg_members_count(self.client, self.nhop_group1), 0)
        sai_thrift_remove_next_hop_group(self.client, self.nhop_group1)
        sai_thrift_remove_next_hop(self.client, self.nhop1)
        sai_thrift_remove_next_hop(self.client, self.nhop2)


        super(L3IPv6EcmpPbhHelper, self).tearDown()


    def TrafficTestV6(self):

        count = [0,0]
        for i in range(0, MAX_ITRS):
            host_ip = f'5000:1:1:0:0:0:0:{random.randint(3, 1000)}'
            pkt = simple_tcpv6_packet(eth_dst=ROUTER_MAC,
                                        eth_src='00:22:22:22:22:22',
                                        ipv6_dst=host_ip,
                                        ipv6_src='2000:1:1:0:0:0:0:1',
                                        tcp_sport=0x1234,
                                        ipv6_hlim=64)
            exp_pkt1 = simple_tcpv6_packet(eth_dst='00:11:22:33:44:55',
                                            eth_src=ROUTER_MAC,
                                            ipv6_dst=host_ip,
                                            ipv6_src='2000:1:1:0:0:0:0:1',
                                            tcp_sport=0x1234,
                                            ipv6_hlim=63)
            exp_pkt2 = simple_tcpv6_packet(eth_dst='00:11:22:33:44:56',
                                            eth_src=ROUTER_MAC,
                                            ipv6_dst=host_ip,
                                            ipv6_src='2000:1:1:0:0:0:0:1',
                                            tcp_sport=0x1234,
                                            ipv6_hlim=63)
            print("Sending packet port %d -> port [%d,%d]"
              "(2000:1:1:0:0:0:0:1 -> %s [id = 101])" % (
                  self.dev_port13, self.dev_port11, self.dev_port12, host_ip))
            send_packet(self, self.dev_port13, pkt)
            rcv_idx = verify_any_packet_any_port(self, [exp_pkt1, exp_pkt2], [self.dev_port11, self.dev_port12])
            count[rcv_idx] += 1

        return count


class L3IPv6EcmpPbhTest(L3IPv6EcmpPbhHelper):

    def setUp(self):
        super(L3IPv6EcmpPbhTest, self).setUp()

    def runTest(self):
        print("L3IPv6EcmpPbhTest")

        print("enable port13 pbh,LBID=0")
        lbid_index = random.randint(0,127)
        sai_thrift_set_port_attribute(self.client,self.port13,ppn_l1_enable=True,lbid=lbid_index)
        export_index = lbid_index % nhg_members_count(self.client,self.nhop_group1)

        print("enable switch pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=True)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        print("enable Ecmp pbh")
        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)

        get_pbh_enable_status(self,port=self.port13,nexthop_group=self.nhop_group1)

        count =  self.TrafficTestV6()
        print('Traffic distribution ports [11,12]  --> %s' % (count))
        self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)


    def tearDown(self):
        super(L3IPv6EcmpPbhTest, self).tearDown()


class _pbhecmpEcmpHashSeedTest(PBHBasicHelper):
    '''
    Verify pbh  ecmp with  varing seed values
    '''
    def __init__(self):
        super(_pbhecmpEcmpHashSeedTest, self).__init__(
            ecmp_pbh_test=True)

    def setUp(self):
        super(_pbhecmpEcmpHashSeedTest, self).setUp()


    def runTest(self):

        self.results_dict = {}
        print("enable port24 pbh")
        lbid_index = random.randint(0,127)
        print(" port24 pbh lbid %s"%lbid_index)
        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=True,lbid=lbid_index)
        export_index = lbid_index % nhg_members_count(self.client,self.nhop_group1)

        print("enable switch pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=True)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        print("enable Ecmp pbh")
        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)

        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)

        pkt_params = {
            self.dev_port0: {
                "dmac": self.mac1
            },
            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            }
        }

        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)

        self.results_dict[0] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("set  ecmp hash seed")
        sai_thrift_set_switch_attribute(self.client, ecmp_default_hash_seed=TEST_ECMP_SEED)

        pkt_params = {
            self.dev_port0: {
                "dmac": self.mac1
            },
            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            }
        }
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)
        self.results_dict[1] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("set  ecmp hash seed1")
        sai_thrift_set_switch_attribute(self.client, ecmp_default_hash_seed=TEST_ECMP_SEED1)

        pkt_params = {
            self.dev_port0: {
                "dmac": self.mac1
            },
            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            }
        }
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)
        self.results_dict[2] = {
            'pbh enable status': pbh_status,
            'count': count
        }
        print_pbhtest_results(self.ecmp_pbh_test,self.results_dict, "PBh ECMP  Results")

    def tearDown(self):
        sai_thrift_set_switch_attribute(self.client, ecmp_default_hash_seed=0)
        super(_pbhecmpEcmpHashSeedTest, self).tearDown()



class PBHStressTest(SaiHelperSimplified):


    def setUp(self):
        super(PBHStressTest, self).setUp()
        setupECMPHash(self)
        self.ecmp_pbh_test = True
        ecmp_mem_count = 4
        self.nhop_group_list = []

        self.dst_ip_list = []
        self.src_mac_list = []
        dst_ip = int(binascii.hexlify(socket.inet_aton('20.20.20.1')), 16)
        src_mac_start = '00:22:22:22:{0}:{1}'

        for i in range(0, len(self.dev_port_list)):
            dst_ip_addr = socket.inet_ntoa(binascii.unhexlify(hex(dst_ip)[2:].zfill(8)))
            src_mac = src_mac_start.format(
                str(i).zfill(4)[:2],
                str(i).zfill(4)[2:])
            dst_ip += 1
            self.dst_ip_list.append(dst_ip_addr)
            self.src_mac_list.append(src_mac)


        print("Step1.create rif ")
        for port_dev in self.dev_port_list:
            self.create_routing_interfaces(ports=[port_dev])

        print("Step2.create nhop")
        for i,port in enumerate(self.dev_port_list):
            neighbor_entry = sai_thrift_neighbor_entry_t(
                rif_id=getattr(self,"port%s_rif" % i), ip_address=sai_ipaddress(self.dst_ip_list[i]))
            sai_thrift_create_neighbor_entry(self.client, neighbor_entry,
                                            dst_mac_address=self.src_mac_list[i],no_host_route=True)
            nhop = sai_thrift_create_next_hop(self.client,
                                            ip=sai_ipaddress(self.dst_ip_list[i]),
                                            router_interface_id=getattr(self,"port%s_rif" % i),
                                            type=SAI_NEXT_HOP_TYPE_IP)
            setattr(self, "neighbor_entry%s" % i, neighbor_entry)
            setattr(self, "nhop%s" % i, nhop)

        print("Step3.create ecmp group ")
        for i in range(len(self.dev_port_list)//ecmp_mem_count):
            self.nhop_group = sai_thrift_create_next_hop_group(
                self.client, type=SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_ORDERED_ECMP,custom_ecmp_lvl1_ppn_enable=False)
            nh_group_member1 = sai_thrift_create_next_hop_group_member(
                self.client,
                next_hop_group_id=self.nhop_group,
                next_hop_id=getattr(self,"nhop%s" %(i*4)),sequence_id=1)
            nh_group_member2 = sai_thrift_create_next_hop_group_member(
                self.client,
                next_hop_group_id=self.nhop_group,
                next_hop_id=getattr(self,"nhop%s" %(i*4+1)),sequence_id=2)
            nh_group_member3 = sai_thrift_create_next_hop_group_member(
                self.client,
                next_hop_group_id=self.nhop_group,
                next_hop_id=getattr(self,"nhop%s" %(i*4+2)),sequence_id=3)
            nh_group_member4 = sai_thrift_create_next_hop_group_member(
                self.client,
                next_hop_group_id=self.nhop_group,
                next_hop_id=getattr(self,"nhop%s" %(i*4+3)),sequence_id=4)
            setattr(self, "nh_group_member%s_1" %i, nh_group_member1)
            setattr(self, "nh_group_member%s_2" %i, nh_group_member2)
            setattr(self, "nh_group_member%s_3" %i, nh_group_member3)
            setattr(self, "nh_group_member%s_4" %i, nh_group_member4)
            setattr(self, "nhop_group%s" % i, self.nhop_group)
            self.nhop_group_list.append(self.nhop_group)


        print("Step4.create v4 route to Ecmp ")

        for i in range(len(self.dev_port_list)//ecmp_mem_count):
            self.route = sai_thrift_route_entry_t(switch_id=self.switch_id,
                                                vr_id=self.default_vrf,
                                                destination=sai_ipprefix(self.dst_ip_list[i]+str('/32')))
            status = sai_thrift_create_route_entry(
                self.client,
                route_entry=self.route,
                next_hop_id=getattr(self,"nhop_group%s" % i))
            self.assertEqual(status, SAI_STATUS_SUCCESS)
            setattr(self, "route%s" % i, self.route)

        self.pkt_params_list = {}
        for i in range(len(self.dev_port_list)//ecmp_mem_count):
            self.pkt_params_list [i] = {
                "dst_ip": self.dst_ip_list[i],
                "port0" : getattr(self,"dev_port%s" %(i*4)),
                "dmac0" : self.src_mac_list[i*4],
                "port1" : getattr(self,"dev_port%s" %(i*4+1)),
                "dmac1" : self.src_mac_list[i*4+1],
                "port2" : getattr(self,"dev_port%s" %(i*4+2)),
                "dmac2" : self.src_mac_list[i*4+2],
                "port3" : getattr(self,"dev_port%s" %(i*4+3)),
                "dmac3" : self.src_mac_list[i*4+3]
            }


    def runTest(self):

        print("PBHStressTest")

        print("enable switch pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=True)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        print("enable port pbh")
        export_index_list = []
        for index,port in enumerate(self.dev_port_list):
            sai_thrift_set_port_attribute(self.client,getattr(self,"port%s" % index),ppn_l1_enable=True,lbid=index)
            export_index = port % nhg_members_count(self.client,self.nhop_group1)
            export_index_list.append(export_index)


        print("enable Ecmp pbh")

        for nhp_ecmp in self.nhop_group_list:
            sai_thrift_set_next_hop_group_attribute(self.client,nhp_ecmp,custom_ecmp_lvl1_ppn_enable=True)


        port_ecmp_dict1={}
        for i,dev_port in enumerate(self.dev_port_list):
            print('send port is port%s ' % dev_port)
            count = self.TrafficTest(self.pkt_params_list,dev_port)
            port_ecmp_dict1[i] = {
                'port':dev_port,
                'ecmp_count':count
            }
            for j in range(len(self.nhop_group_list)):
                self.assertTrue((count[j][export_index_list[i]] == MAX_ITRS))
                print('Traffic distribution nhop_group%s  --> %s' % (j,count[j]))

        keys = list(port_ecmp_dict1.keys())
        for index in keys:
            print('send port is port%s ' % port_ecmp_dict1[index].get('port'))
            for j in range(len(self.nhop_group_list)):
                print('Traffic distribution nhop_group%s  --> %s' % (j,port_ecmp_dict1[index].get('ecmp_count')[j]))

        print("disable port pbh")
        port =  random.choice(self.port_list)
        sai_thrift_set_port_attribute(self.client,port,ppn_l1_enable=False)

        port_ecmp_dict2={}
        for i,dev_port in enumerate(self.dev_port_list):
            count = self.TrafficTest(self.pkt_params_list,dev_port)
            port_ecmp_dict2[i] = {
                'port':dev_port,
                'ecmp_count':count
            }
            for j,nhop_group_index in enumerate(self.nhop_group_list):
                if getattr(self,"port%s" % i) != port:
                    self.assertTrue((count[j][export_index_list[i]] == MAX_ITRS))
                    print('Traffic distribution nhop_group%s  --> %s' % (j,count[j]))
                # else:
                #     for k in range(0, 4):
                #         self.assertTrue((count[j][k] >= ((MAX_ITRS / 4) * 0.2)),
                #                         "Ecmp paths are not equally balanced")

        keys = list(port_ecmp_dict2.keys())
        for index in keys:
            print('send port is port%s ' % port_ecmp_dict2[index].get('port'))
            for j in range(len(self.nhop_group_list)):
                print('Traffic distribution nhop_group%s  --> %s' % (j,port_ecmp_dict2[index].get('ecmp_count')[j]))



        if self.ecmp_pbh_test == True:
            print("disable nhp_group3 pbh")
            nhp_group =  random.choice(self.nhop_group_list)
            sai_thrift_set_next_hop_group_attribute(self.client,nhp_group,custom_ecmp_lvl1_ppn_enable=False)

            port_ecmp_dict3={}
            for i,dev_port in enumerate(self.dev_port_list):
                count = self.TrafficTest(self.pkt_params_list,dev_port)
                port_ecmp_dict3[i] = {
                    'port':dev_port,
                    'ecmp_count':count
                }
                for j,nhop_group_index in enumerate(self.nhop_group_list):
                    if getattr(self,"port%s" % i) != port:
                        if nhop_group_index != nhp_group:
                            self.assertTrue((count[j][export_index_list[i]] == MAX_ITRS))
                            print('Traffic distribution nhop_group%s  --> %s' % (j,count[j]))
                    #     else:
                    #         for k in range(0, 4):
                    #             self.assertTrue((count[j][k] >= ((MAX_ITRS / 4) * 0.2)),
                    #                             "Ecmp paths are not equally balanced")
                    # else:
                    #     for k in range(0, 4):
                    #         self.assertTrue((count[j][k] >= ((MAX_ITRS / 4) * 0.2)),
                    #                         "Ecmp paths are not equally balanced")

            keys = list(port_ecmp_dict3.keys())
            for index in keys:
                print('send port is port%s ' % port_ecmp_dict3[index].get('port'))
                for j in range(len(self.nhop_group_list)):
                    print('Traffic distribution nhop_group%s  --> %s' % (j,port_ecmp_dict3[index].get('ecmp_count')[j]))



        print("disable switch pbh")
        sai_thrift_set_switch_attribute(self.client, custom_ecmp_lvl1_ppn_enable=False)
        port_ecmp_dict4 = {}
        for i,dev_port in enumerate(self.dev_port_list):
            count = self.TrafficTest(self.pkt_params_list,dev_port)
            port_ecmp_dict[i] = {
                'port':dev_port,
                'ecmp_count':count
            }
            # for j,nhop_group_index in enumerate(self.nhop_group_list):
            #     for k in range(0, 4):
            #         self.assertTrue((count[j][k] >= ((MAX_ITRS / 4) * 0.2)),
            #                         "Ecmp paths are not equally balanced")

        keys = list(port_ecmp_dict4.keys())
        for index in keys:
            print('send port is port%s ' % port_ecmp_dict4[index].get('port'))
            for j in range(len(self.nhop_group_list)):
                print('Traffic distribution nhop_group%s  --> %s' % (j,port_ecmp_dict4[index].get('ecmp_count')[j]))



    def TrafficTest(self,pkt_params_list,send_port):
        '''
        For sending traffic
        Returns:
            int: pkts count
        '''
        print('Sending Traffic')


        src_mac = '00:22:22:22:22:22'
        src_ip_list = batch_generate_unicast_ips(count=MAX_ITRS)
        count = {}
        for i in range(len(pkt_params_list)):
            count[i] = [0,0,0,0]
            dst_ip_addr = pkt_params_list[i].get('dst_ip')
            print("dst_ip is %s"%dst_ip_addr)

            for src_ip_addr in src_ip_list:
                print("src_ip is %s"%src_ip_addr)

                pkt = simple_tcp_packet(eth_dst=ROUTER_MAC,
                                        eth_src=src_mac,
                                        ip_dst=dst_ip_addr,
                                        ip_src=src_ip_addr,
                                        ip_id=106,
                                        ip_ttl=64)


                exp_pkt1 = simple_tcp_packet(eth_dst=pkt_params_list[i].get('dmac0'),
                                            eth_src=ROUTER_MAC,
                                            ip_dst=dst_ip_addr,
                                            ip_src=src_ip_addr,
                                            ip_id=106,
                                            ip_ttl=63)
                exp_pkt2 = simple_tcp_packet(eth_dst=pkt_params_list[i].get('dmac1'),
                                            eth_src=ROUTER_MAC,
                                            ip_dst=dst_ip_addr,
                                            ip_src=src_ip_addr,
                                            ip_id=106,
                                            ip_ttl=63)
                exp_pkt3 = simple_tcp_packet(eth_dst=pkt_params_list[i].get('dmac2'),
                                            eth_src=ROUTER_MAC,
                                            ip_dst=dst_ip_addr,
                                            ip_src=src_ip_addr,
                                            ip_id=106,
                                            ip_ttl=63)
                exp_pkt4 = simple_tcp_packet(eth_dst=pkt_params_list[i].get('dmac3'),
                                            eth_src=ROUTER_MAC,
                                            ip_dst=dst_ip_addr,
                                            ip_src=src_ip_addr,
                                            ip_id=106,
                                            ip_ttl=63)

                send_packet(self, send_port, pkt)
                rcv_idx = verify_any_packet_any_port(
                    self,[exp_pkt1,exp_pkt2,exp_pkt3,exp_pkt4],[pkt_params_list[i].get('port0'),pkt_params_list[i].get('port1'),pkt_params_list[i].get('port2'),pkt_params_list[i].get('port3')])
                count[i][rcv_idx]  += 1

        return count


    def tearDown(self):
        for i in self.dev_port_list:
            sai_thrift_remove_neighbor_entry(self.client, getattr(self,"neighbor_entry%s" %i))
        for i in range(8):
            sai_thrift_remove_next_hop_group_member(self.client, getattr(self,"nh_group_member%s_1" %i))
            sai_thrift_remove_next_hop_group_member(self.client, getattr(self,"nh_group_member%s_2" %i))
            sai_thrift_remove_next_hop_group_member(self.client, getattr(self,"nh_group_member%s_3" %i))
            sai_thrift_remove_next_hop_group_member(self.client, getattr(self,"nh_group_member%s_4" %i))
            sai_thrift_remove_route_entry(self.client, getattr(self,"route%s" %i))
            self.assertEqual(nhg_members_count( self.client, getattr(self,"nhop_group%s" %i)), 0)
            sai_thrift_remove_next_hop_group(self.client,  getattr(self,"nhop_group%s" %i))


        for i in self.dev_port_list:
            sai_thrift_remove_next_hop(self.client,  getattr(self,"nhop%s" %i))

        self.destroy_routing_interfaces()
        sai_thrift_set_switch_attribute(self.client, custom_ecmp_lvl1_ppn_enable=False,custom_ecmp_lvl0_ppn_enable=False,)
        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=False,ppn_l0_enable=False,lbid=0)
        super(PBHStressTest, self).tearDown()



class PBHStressNewTest(SaiHelperSimplified):

    def setUp(self):
        super(PBHStressNewTest, self).setUp()
        setupECMPHash(self)
        self.ecmp_pbh_test = False
        ecmp_mem_count = 4
        self.nhop_group_list = []

        self.dst_ip_list = []
        self.src_mac_list = []
        dst_ip = int(binascii.hexlify(socket.inet_aton('20.20.20.1')), 16)
        src_mac_start = '00:22:22:22:{0}:{1}'

        for i in range(0, len(self.dev_port_list)):
            dst_ip_addr = socket.inet_ntoa(binascii.unhexlify(hex(dst_ip)[2:].zfill(8)))
            src_mac = src_mac_start.format(
                str(i).zfill(4)[:2],
                str(i).zfill(4)[2:])
            dst_ip += 1
            self.dst_ip_list.append(dst_ip_addr)
            self.src_mac_list.append(src_mac)


        print("Step1.create rif ")
        for port_dev in self.dev_port_list:
            self.create_routing_interfaces(ports=[port_dev])

        print("Step2.create nhop")
        for i,port in enumerate(self.dev_port_list):
            neighbor_entry = sai_thrift_neighbor_entry_t(
                rif_id=getattr(self,"port%s_rif" % i), ip_address=sai_ipaddress(self.dst_ip_list[i]))
            sai_thrift_create_neighbor_entry(self.client, neighbor_entry,
                                            dst_mac_address=self.src_mac_list[i],no_host_route=True)
            nhop = sai_thrift_create_next_hop(self.client,
                                            ip=sai_ipaddress(self.dst_ip_list[i]),
                                            router_interface_id=getattr(self,"port%s_rif" % i),
                                            type=SAI_NEXT_HOP_TYPE_IP)
            setattr(self, "neighbor_entry%s" % i, neighbor_entry)
            setattr(self, "nhop%s" % i, nhop)

        print("Step3.create ecmp group ")
        for i in range(0,4):
            for j in range(0,32):
                self.nhop_group = sai_thrift_create_next_hop_group(
                    self.client, type=SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_ORDERED_ECMP,custom_ecmp_lvl1_ppn_enable=False)
                if j <= 30:
                    nh_group_member1 = sai_thrift_create_next_hop_group_member(
                        self.client,
                        next_hop_group_id=self.nhop_group,
                        next_hop_id=getattr(self,"nhop%s" %(j)),sequence_id=1)
                    nh_group_member2 = sai_thrift_create_next_hop_group_member(
                        self.client,
                        next_hop_group_id=self.nhop_group,
                        next_hop_id=getattr(self,"nhop%s" %(j+1)),sequence_id=2)
                if j == 31:
                    nh_group_member1 = sai_thrift_create_next_hop_group_member(
                        self.client,
                        next_hop_group_id=self.nhop_group,
                        next_hop_id=self.nhop31,sequence_id=1)
                    nh_group_member2 = sai_thrift_create_next_hop_group_member(
                        self.client,
                        next_hop_group_id=self.nhop_group,
                        next_hop_id=self.nhop0,sequence_id=2)

                setattr(self, "nh_group_member%s_1" %(i*32+j), nh_group_member1)
                setattr(self, "nh_group_member%s_2" %(i*32+j), nh_group_member2)
                setattr(self, "nhop_group%s" % (i*32+j), self.nhop_group)
                self.nhop_group_list.append(self.nhop_group)



        print("Step4.create v4 route to Ecmp ")
        self.ecmp_dst_ip_list = batch_generate_unicast_ips(count=len(self.nhop_group_list))
        for i in range(len(self.nhop_group_list)):
            self.route = sai_thrift_route_entry_t(switch_id=self.switch_id,
                                                vr_id=self.default_vrf,
                                                destination=sai_ipprefix(self.ecmp_dst_ip_list[i]+str('/32')))
            status = sai_thrift_create_route_entry(
                self.client,
                route_entry=self.route,
                next_hop_id=getattr(self,"nhop_group%s" % i))
            self.assertEqual(status, SAI_STATUS_SUCCESS)
            setattr(self, "route%s" % i, self.route)

        self.pkt_params_list = {}
        for i in range(0,4):
            for j in range(0,32):
                if j <= 30:
                    self.pkt_params_list [i*32+j] = {
                        "dst_ip": self.ecmp_dst_ip_list[i*32+j],
                        "port0" : getattr(self,"dev_port%s" %(j)),
                        "dmac0" : self.src_mac_list[j],
                        "port1" : getattr(self,"dev_port%s" %(j+1)),
                        "dmac1" : self.src_mac_list[j+1]
                    }
                if j == 31:
                    self.pkt_params_list [i*32+j] = {
                        "dst_ip": self.ecmp_dst_ip_list[i*32+j],
                        "port0" : getattr(self,"dev_port%s" %(j)),
                        "dmac0" : self.src_mac_list[j],
                        "port1" : getattr(self,"dev_port%s" %(0)),
                        "dmac1" : self.src_mac_list[0]
                    }

    def runTest(self):

        print("PBHStressNewTest")

        print("enable switch pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=True)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        print("enable port pbh")
        export_index_list = []
        for index,port in enumerate(self.dev_port_list):
            sai_thrift_set_port_attribute(self.client,getattr(self,"port%s" % index),ppn_l1_enable=True,lbid=index)
            export_index = index % 2
            export_index_list.append(export_index)


        print("enable Ecmp pbh")
        for nhp_ecmp in self.nhop_group_list:
            sai_thrift_set_next_hop_group_attribute(self.client,nhp_ecmp,custom_ecmp_lvl1_ppn_enable=True)


        port_ecmp_dict1={}
        for i,dev_port in enumerate(self.dev_port_list):
            print('send port is port%s ' % dev_port)
            count = self.TrafficTest(self.pkt_params_list,dev_port)
            port_ecmp_dict1[i] = {
                'port':dev_port,
                'ecmp_count':count
            }
            for j in range(len(self.nhop_group_list)):
                self.assertTrue((count[j][export_index_list[i]] == MAX_ITRS))
                print('Traffic distribution nhop_group%s  --> %s' % (j,count[j]))

        keys = list(port_ecmp_dict1.keys())
        for index in keys:
            print('send port is port%s ' % port_ecmp_dict1[index].get('port'))
            for j in range(len(self.nhop_group_list)):
                print('Traffic distribution nhop_group%s  --> %s' % (j,port_ecmp_dict1[index].get('ecmp_count')[j]))


        print("disable port pbh")
        port =  random.choice(self.port_list)
        sai_thrift_set_port_attribute(self.client,port,ppn_l1_enable=False)

        port_ecmp_dict2={}
        for i,dev_port in enumerate(self.dev_port_list):
            count = self.TrafficTest(self.pkt_params_list,dev_port)
            port_ecmp_dict2[i] = {
                'port':dev_port,
                'ecmp_count':count
            }
            for j,nhop_group_index in enumerate(self.nhop_group_list):
                if getattr(self,"port%s" % i) != port:
                    self.assertTrue((count[j][export_index_list[i]] == MAX_ITRS))
                    print('Traffic distribution nhop_group%s  --> %s' % (j,count[j]))
                else:
                    for k in range(0, 2):
                        self.assertTrue((count[j][k] >= ((MAX_ITRS / 2) * 0.2)),
                                        "Ecmp paths are not equally balanced")

        keys = list(port_ecmp_dict2.keys())
        for index in keys:
            print('send port is port%s ' % port_ecmp_dict2[index].get('port'))
            for j in range(len(self.nhop_group_list)):
                print('Traffic distribution nhop_group%s  --> %s' % (j,port_ecmp_dict2[index].get('ecmp_count')[j]))


        if self.ecmp_pbh_test == True:
            print("disable nhp_group3 pbh")
            nhp_group =  random.choice(self.nhop_group_list)
            sai_thrift_set_next_hop_group_attribute(self.client,nhp_group,custom_ecmp_lvl1_ppn_enable=False)

            port_ecmp_dict3={}
            for i,dev_port in enumerate(self.dev_port_list):
                count = self.TrafficTest(self.pkt_params_list,dev_port)
                port_ecmp_dict3[i] = {
                    'port':dev_port,
                    'ecmp_count':count
                }
                for j,nhop_group_index in enumerate(self.nhop_group_list):
                    if getattr(self,"port%s" % i) != port:
                        if nhop_group_index != nhp_group:
                            self.assertTrue((count[j][export_index_list[i]] == MAX_ITRS))
                            print('Traffic distribution nhop_group%s  --> %s' % (j,count[j]))
                        else:
                            for k in range(0, 2):
                                self.assertTrue((count[j][k] >= ((MAX_ITRS / 2) * 0.2)),
                                                "Ecmp paths are not equally balanced")
                    else:
                        for k in range(0, 2):
                            self.assertTrue((count[j][k] >= ((MAX_ITRS / 2) * 0.2)),
                                            "Ecmp paths are not equally balanced")

            keys = list(port_ecmp_dict3.keys())
            for index in keys:
                print('send port is port%s ' % port_ecmp_dict3[index].get('port'))
                for j in range(len(self.nhop_group_list)):
                    print('Traffic distribution nhop_group%s  --> %s' % (j,port_ecmp_dict3[index].get('ecmp_count')[j]))



        print("disable switch pbh")
        port_ecmp_dict4={}
        sai_thrift_set_switch_attribute(self.client, custom_ecmp_lvl1_ppn_enable=False)

        for i,dev_port in enumerate(self.dev_port_list):
            count = self.TrafficTest(self.pkt_params_list,dev_port)
            port_ecmp_dict4[i] = {
                'port':dev_port,
                'ecmp_count':count
            }
            for j,nhop_group_index in enumerate(self.nhop_group_list):
                for k in range(0, 2):
                    self.assertTrue((count[j][k] >= ((MAX_ITRS / 2) * 0.2)),
                                    "Ecmp paths are not equally balanced")

        keys = list(port_ecmp_dict4.keys())
        for index in keys:
            print('send port is port%s ' % port_ecmp_dict4[index].get('port'))
            for j in range(len(self.nhop_group_list)):
                print('Traffic distribution nhop_group%s  --> %s' % (j,port_ecmp_dict4[index].get('ecmp_count')[j]))


    def TrafficTest(self,pkt_params_list,send_port):
        '''
        For sending traffic
        Returns:
            int: pkts count
        '''
        print('Sending Traffic')


        src_mac = '00:22:22:22:22:22'
        src_ip_list = batch_generate_unicast_ips(count=MAX_ITRS)
        count = {}
        for i in range(len(pkt_params_list)):
            count[i] = [0,0]
            dst_ip_addr = pkt_params_list[i].get('dst_ip')
            print("dst_ip is %s"%dst_ip_addr)

            for src_ip_addr in src_ip_list:
                print("src_ip is %s"%src_ip_addr)

                pkt = simple_tcp_packet(eth_dst=ROUTER_MAC,
                                        eth_src=src_mac,
                                        ip_dst=dst_ip_addr,
                                        ip_src=src_ip_addr,
                                        ip_id=106,
                                        ip_ttl=64)


                exp_pkt1 = simple_tcp_packet(eth_dst=pkt_params_list[i].get('dmac0'),
                                            eth_src=ROUTER_MAC,
                                            ip_dst=dst_ip_addr,
                                            ip_src=src_ip_addr,
                                            ip_id=106,
                                            ip_ttl=63)
                exp_pkt2 = simple_tcp_packet(eth_dst=pkt_params_list[i].get('dmac1'),
                                            eth_src=ROUTER_MAC,
                                            ip_dst=dst_ip_addr,
                                            ip_src=src_ip_addr,
                                            ip_id=106,
                                            ip_ttl=63)

                send_packet(self, send_port, pkt)
                rcv_idx = verify_any_packet_any_port(
                    self,[exp_pkt1,exp_pkt2],[pkt_params_list[i].get('port0'),pkt_params_list[i].get('port1')],timeout=10)

                count[i][rcv_idx]  += 1

        return count


    def tearDown(self):
        for i in self.dev_port_list:
            sai_thrift_remove_neighbor_entry(self.client, getattr(self,"neighbor_entry%s" %i))
        for i in range(8):
            sai_thrift_remove_next_hop_group_member(self.client, getattr(self,"nh_group_member%s_1" %i))
            sai_thrift_remove_next_hop_group_member(self.client, getattr(self,"nh_group_member%s_2" %i))
            sai_thrift_remove_next_hop_group_member(self.client, getattr(self,"nh_group_member%s_3" %i))
            sai_thrift_remove_next_hop_group_member(self.client, getattr(self,"nh_group_member%s_4" %i))
            sai_thrift_remove_route_entry(self.client, getattr(self,"route%s" %i))
            self.assertEqual(nhg_members_count( self.client, getattr(self,"nhop_group%s" %i)), 0)
            sai_thrift_remove_next_hop_group(self.client,  getattr(self,"nhop_group%s" %i))


        for i in self.dev_port_list:
            sai_thrift_remove_next_hop(self.client,  getattr(self,"nhop%s" %i))

        self.destroy_routing_interfaces()
        sai_thrift_set_switch_attribute(self.client, custom_ecmp_lvl1_ppn_enable=False,custom_ecmp_lvl0_ppn_enable=False,)
        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=False,ppn_l0_enable=False,lbid=0)
        super(PBHStressNewTest, self).tearDown()




class TunnelPBHTestBase(SaiHelper):
    '''
    Tests regarding different cases of nexthop resolution

    '''
    def __init__(self, ecmp_pbh_test=False):
        super(TunnelPBHTestBase, self).__init__()
        self.ecmp_pbh_test = ecmp_pbh_test

        self.tun_ip1 = "10.10.10.1"
        self.tun_ip2 = "10.10.10.2"
        self.tun_ip3 = "10.10.10.3"
        self.lpb_ip = "10.10.10.10"
        self.tun_ip_mask = "/32"
        self.tun_ip_mask2 = "/24"
        self.tun_ip_mask3 = "/16"

    def setUp(self):
        super(TunnelPBHTestBase, self).setUp()
        setupECMPHash(self)

        self.oport = self.port24
        self.oport_dev = self.dev_port24

        self.vni = 1000
        self.vm_ip1 = "100.100.1.1"
        self.vm_ip2 = "100.100.1.2"
        self.customer_ip = "100.100.3.1"
        self.inner_dmac1 = "00:11:11:11:11:11"
        self.inner_dmac2 = "00:11:11:11:11:22"
        self.inner_dmac3 = "00:11:11:11:11:33"
        self.customer_mac = "00:22:22:22:22:22"
        self.unbor_mac1 = "00:33:33:33:33:11"
        self.unbor_mac2 = "00:33:33:33:33:22"
        self.unbor_mac3 = "00:33:33:33:33:33"

        # underlay configuration
        if get_platform() !='ctc':
            self.uvrf = sai_thrift_create_virtual_router(self.client)
        else:
            self.uvrf = self.default_vrf
        # overlay configuraion
        self.ovrf = sai_thrift_create_virtual_router(self.client)
        tunnel_type = SAI_TUNNEL_TYPE_VXLAN
        ttl_mode = SAI_TUNNEL_TTL_MODE_PIPE_MODEL

        # underlay loopback RIF for tunnel
        self.urif_lpb = sai_thrift_create_router_interface(
            self.client,
            type=SAI_ROUTER_INTERFACE_TYPE_LOOPBACK,
            virtual_router_id=self.uvrf)

        self.orif = sai_thrift_create_router_interface(
            self.client,
            type=SAI_ROUTER_INTERFACE_TYPE_PORT,
            virtual_router_id=self.ovrf,
            port_id=self.oport)

        # encap/decap mappers
        self.encap_tunnel_map = sai_thrift_create_tunnel_map(
            self.client, type=SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI)

        self.decap_tunnel_map = sai_thrift_create_tunnel_map(
            self.client, type=SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID)

        # encap/decap mapper entries
        self.encap_tunnel_map_entry = sai_thrift_create_tunnel_map_entry(
            self.client,
            tunnel_map=self.encap_tunnel_map,
            tunnel_map_type=SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI,
            virtual_router_id_key=self.ovrf,
            vni_id_value=self.vni)

        self.decap_tunnel_map_entry = sai_thrift_create_tunnel_map_entry(
            self.client,
            tunnel_map=self.decap_tunnel_map,
            tunnel_map_type=SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID,
            virtual_router_id_value=self.ovrf,
            vni_id_key=self.vni)

        encap_maps = sai_thrift_object_list_t(count=1,
                                              idlist=[self.encap_tunnel_map])
        decap_maps = sai_thrift_object_list_t(count=1,
                                              idlist=[self.decap_tunnel_map])

        # tunnel
        self.tunnel = sai_thrift_create_tunnel(
            self.client,
            type=tunnel_type,
            encap_src_ip=sai_ipaddress(self.lpb_ip),
            encap_mappers=encap_maps,
            decap_mappers=decap_maps,
            encap_ttl_mode=ttl_mode,
            decap_ttl_mode=ttl_mode,
            underlay_interface=self.urif_lpb)



    def tearDown(self):
        sai_thrift_remove_tunnel(self.client, self.tunnel)
        sai_thrift_remove_tunnel_map_entry(
            self.client, self.decap_tunnel_map_entry)
        sai_thrift_remove_tunnel_map_entry(
            self.client, self.encap_tunnel_map_entry)
        sai_thrift_remove_tunnel_map(self.client, self.decap_tunnel_map)
        sai_thrift_remove_tunnel_map(self.client, self.encap_tunnel_map)
        sai_thrift_remove_router_interface(self.client, self.orif)
        sai_thrift_remove_router_interface(self.client, self.urif_lpb)
        sai_thrift_remove_virtual_router(self.client, self.ovrf)
        sai_thrift_remove_virtual_router(self.client, self.uvrf)

        super(TunnelPBHTestBase, self).tearDown()
    # Helper functions for traffic verification
    def _TrafficEcmpTest(self, pkt_params):

        ports = list(pkt_params.keys())
        count = len(ports)*[0]
        src_ip_list = batch_generate_unicast_ips(count=MAX_ITRS)
        for i,src_ip_addr in enumerate(src_ip_list):
            print("src_ip is %s"%src_ip_addr)
            exp_pkts = []
            pkt = simple_udp_packet(eth_dst=ROUTER_MAC,
                                    eth_src=self.customer_mac,
                                    ip_dst=self.vm_ip1,
                                    ip_src=src_ip_addr,
                                    ip_id=108,
                                    ip_ttl=64)
            for port in pkt_params:
                inner_pkt = simple_udp_packet(eth_dst=pkt_params[port]["idmac"],
                                            eth_src=ROUTER_MAC,
                                            ip_dst=self.vm_ip1,
                                            ip_src=src_ip_addr,
                                            ip_id=108,
                                            ip_ttl=63)
                vxlan_pkt = Mask(
                    simple_vxlan_packet(eth_dst=pkt_params[port]["dmac"],
                                        eth_src=ROUTER_MAC,
                                        ip_dst=pkt_params[port]["tun_ip"],
                                        ip_src=self.lpb_ip,
                                        ip_id=0,
                                        dl_vlan_enable=False,
                                        ip_ttl=64,
                                        ip_flags=0x2,
                                        with_udp_chksum=False,
                                        vxlan_vni=self.vni,
                                        inner_frame=inner_pkt))
                vxlan_pkt.set_do_not_care_scapy(UDP, 'sport')
                if get_platform() == 'ctc':
                    vxlan_pkt.set_do_not_care_scapy(ptf.packet.IP, 'id')
                    vxlan_pkt.set_do_not_care_scapy(ptf.packet.IP, 'flags')
                    vxlan_pkt.set_do_not_care_scapy(ptf.packet.IP, 'chksum')
                    vxlan_pkt.set_do_not_care_scapy(ptf.packet.IP, 'ttl')

                exp_pkts.append(vxlan_pkt)
            send_packet(self, self.oport_dev, pkt)
            rcv_idx = verify_any_packet_any_port(
                self,exp_pkts,ports)
            count[rcv_idx] += 1

        return count


    def OverlayEcmpPBHTunnelTest(self):
        '''
        Nexthop resolution tests with underlay ECMP
        '''
        print("\OverlayecmpTunnelTest()")

        uport1 = self.port25
        uport1_dev = self.dev_port25
        uport2 = self.port26
        uport2_dev = self.dev_port26
        uport3 = self.port27
        uport3_dev = self.dev_port27

        try:
            self.results_dict = {}

            urif1 = sai_thrift_create_router_interface(
                self.client,
                type=SAI_ROUTER_INTERFACE_TYPE_PORT,
                virtual_router_id=self.uvrf,
                port_id=uport1)

            urif2 = sai_thrift_create_router_interface(
                self.client,
                type=SAI_ROUTER_INTERFACE_TYPE_PORT,
                virtual_router_id=self.uvrf,
                port_id=uport2)

            urif3 = sai_thrift_create_router_interface(
                self.client,
                type=SAI_ROUTER_INTERFACE_TYPE_PORT,
                virtual_router_id=self.uvrf,
                port_id=uport3)

            tunnel_nhop1 = sai_thrift_create_next_hop(
                            self.client,
                            type=SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP,
                            tunnel_id=self.tunnel,
                            ip=sai_ipaddress(self.tun_ip1),
                            tunnel_mac=self.inner_dmac1,
                            tunnel_vni=self.vni)

            tunnel_nhop2 = sai_thrift_create_next_hop(
                self.client,
                type=SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP,
                tunnel_id=self.tunnel,
                ip=sai_ipaddress(self.tun_ip2),
                tunnel_mac=self.inner_dmac2,
                tunnel_vni=self.vni)

            tunnel_nhop3 = sai_thrift_create_next_hop(
                self.client,
                type=SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP,
                tunnel_id=self.tunnel,
                ip=sai_ipaddress(self.tun_ip3),
                tunnel_mac=self.inner_dmac3,
                tunnel_vni=self.vni)

            tunnel_ecmp = sai_thrift_create_next_hop_group(
                self.client, type=SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_ORDERED_ECMP,hierarchical_nexthop=True)

            tunnel_ecmp_member1 = sai_thrift_create_next_hop_group_member(
                self.client,
                next_hop_group_id=tunnel_ecmp,
                next_hop_id=tunnel_nhop1,
                sequence_id=1)

            tunnel_ecmp_member2 = sai_thrift_create_next_hop_group_member(
                self.client,
                next_hop_group_id=tunnel_ecmp,
                next_hop_id=tunnel_nhop2,
                sequence_id=2)

            tunnel_ecmp_member3 = sai_thrift_create_next_hop_group_member(
                self.client,
                next_hop_group_id=tunnel_ecmp,
                next_hop_id=tunnel_nhop3,
                sequence_id=3)

            vm_route = sai_thrift_route_entry_t(
                vr_id=self.ovrf, destination=sai_ipprefix(self.vm_ip1 + '/32'))
            sai_thrift_create_route_entry(self.client,
                                          vm_route,
                                          next_hop_id=tunnel_ecmp)

            unhop1 = sai_thrift_create_next_hop(self.client,
                                                ip=sai_ipaddress(self.tun_ip1),
                                                router_interface_id=urif1,
                                                type=SAI_NEXT_HOP_TYPE_IP)

            unbor1 = sai_thrift_neighbor_entry_t(
                rif_id=urif1, ip_address=sai_ipaddress(self.tun_ip1))
            sai_thrift_create_neighbor_entry(self.client,
                                             unbor1,
                                             dst_mac_address=self.unbor_mac1,
                                             no_host_route=True)

            tunnel_route1 = sai_thrift_route_entry_t(
                vr_id=self.uvrf,
                destination=sai_ipprefix(self.tun_ip1 + self.tun_ip_mask))
            sai_thrift_create_route_entry(self.client,
                                          tunnel_route1,
                                          next_hop_id=unhop1)

            unhop2 = sai_thrift_create_next_hop(self.client,
                                                ip=sai_ipaddress(self.tun_ip2),
                                                router_interface_id=urif2,
                                                type=SAI_NEXT_HOP_TYPE_IP)

            unbor2 = sai_thrift_neighbor_entry_t(
                rif_id=urif2, ip_address=sai_ipaddress(self.tun_ip2))
            sai_thrift_create_neighbor_entry(self.client,
                                             unbor2,
                                             dst_mac_address=self.unbor_mac2,
                                             no_host_route=True)

            tunnel_route2 = sai_thrift_route_entry_t(
                vr_id=self.uvrf,
                destination=sai_ipprefix(self.tun_ip2 + self.tun_ip_mask))
            sai_thrift_create_route_entry(self.client,
                                          tunnel_route2,
                                          next_hop_id=unhop2)

            unhop3 = sai_thrift_create_next_hop(self.client,
                                                ip=sai_ipaddress(self.tun_ip3),
                                                router_interface_id=urif3,
                                                type=SAI_NEXT_HOP_TYPE_IP)

            unbor3 = sai_thrift_neighbor_entry_t(
                rif_id=urif3, ip_address=sai_ipaddress(self.tun_ip3))
            sai_thrift_create_neighbor_entry(self.client,
                                             unbor3,
                                             dst_mac_address=self.unbor_mac3,
                                             no_host_route=True)

            tunnel_route3 = sai_thrift_route_entry_t(
                vr_id=self.uvrf,
                destination=sai_ipprefix(self.tun_ip3 + self.tun_ip_mask))
            sai_thrift_create_route_entry(self.client,
                                          tunnel_route3,
                                          next_hop_id=unhop3)

            pkt_params = {
                uport1_dev: {
                    "dmac": self.unbor_mac1,
                    "idmac": self.inner_dmac1,
                    "tun_ip": self.tun_ip1
                },
                uport2_dev: {
                    "dmac": self.unbor_mac2,
                    "idmac": self.inner_dmac2,
                    "tun_ip": self.tun_ip2
                },
                uport3_dev: {
                    "dmac": self.unbor_mac3,
                    "idmac": self.inner_dmac3,
                    "tun_ip": self.tun_ip3
                }
            }

            count = self._TrafficEcmpTest(pkt_params)
            pbh_status = get_pbh_enable_status(self,port=self.oport,nexthop_group=tunnel_ecmp)
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            for i in range(nhg_members_count(self.client,tunnel_ecmp)):
                self.assertTrue((count[i] >= ((MAX_ITRS / nhg_members_count(self.client,tunnel_ecmp)) * 0.2)),
                                'Not all paths are equally balanced, %s'% count)

            self.results_dict[0] = {
                'pbh enable status': pbh_status,
                'count': count
            }


            lbid_index = random.randint(0,127)
            print(" overlayport pbh lbid %s"%lbid_index)
            sai_thrift_set_port_attribute(self.client,self.oport,ppn_l0_enable=True,lbid=lbid_index)
            export_index = lbid_index % nhg_members_count(self.client,tunnel_ecmp)

            print("enable switch pbh")
            status = sai_thrift_set_switch_attribute(
                self.client, custom_ecmp_lvl0_ppn_enable=True)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            pbh_status = get_pbh_enable_status(self,port=self.oport,nexthop_group=tunnel_ecmp)
            count = self._TrafficEcmpTest(pkt_params)
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))

            if self.ecmp_pbh_test == True:
                for i in range(nhg_members_count(self.client,tunnel_ecmp)):
                    self.assertTrue((count[i] >= ((MAX_ITRS / nhg_members_count(self.client,tunnel_ecmp)) * 0.2)),
                                    'Not all paths are equally balanced, %s'% count)
            else:
                self.assertTrue((count[export_index] == MAX_ITRS),
                                        ' all pkts to port0 , %s'% count)

            self.results_dict[1] = {
                'pbh enable status': pbh_status,
                'count': count
            }

            print("enable Ecmp pbh")

            sai_thrift_set_next_hop_group_attribute(self.client,tunnel_ecmp,custom_ecmp_lvl0_ppn_enable=True)
            pbh_status = get_pbh_enable_status(self,port=self.oport,nexthop_group=tunnel_ecmp)
            count = self._TrafficEcmpTest(pkt_params)

            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)

            self.results_dict[2] = {
                'pbh enable status': pbh_status,
                'count': count
            }

            lbid_index = random.randint(0,127)
            print(" overlayport pbh lbid %s"%lbid_index)
            sai_thrift_set_port_attribute(self.client,self.oport,lbid=lbid_index)
            pbh_status = get_pbh_enable_status(self,port=self.oport,nexthop_group=tunnel_ecmp)
            export_index = lbid_index % nhg_members_count(self.client,tunnel_ecmp)

            count = self._TrafficEcmpTest(pkt_params)
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)

            self.results_dict[3] = {
                'pbh enable status': pbh_status,
                'count': count
            }

            # print("disable Ecmp pbh")
            # sai_thrift_set_next_hop_group_attribute(self.client,tunnel_ecmp,custom_ecmp_lvl0_ppn_enable=False)
            # pbh_status = get_pbh_enable_status(self,port=self.oport,nexthop_group=tunnel_ecmp)
            # count = self._TrafficEcmpTest(pkt_params)

            # print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))

            # if self.ecmp_pbh_test == True:
            #     for i in range(nhg_members_count(self.client,tunnel_ecmp)):
            #         self.assertTrue((count[i] >= ((MAX_ITRS / nhg_members_count(self.client,tunnel_ecmp)) * 0.2)),
            #                         'Not all paths are equally balanced, %s'% count)
            # else:
            #     self.assertTrue((count[export_index] == MAX_ITRS),
            #                             ' all pkts to port0 , %s'% count)

            # self.results_dict[4] = {
            #     'pbh enable status': pbh_status,
            #     'count': count
            # }

            # print("enbale Ecmp pbh")
            # sai_thrift_set_next_hop_group_attribute(self.client,tunnel_ecmp,custom_ecmp_lvl0_ppn_enable=True)
            # pbh_status = get_pbh_enable_status(self,port=self.oport,nexthop_group=tunnel_ecmp)
            # count = self._TrafficEcmpTest(pkt_params)

            # print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            # self.assertTrue((count[export_index] == MAX_ITRS),
            #                         ' all pkts to port0 , %s'% count)

            # self.results_dict[5] = {
            #     'pbh enable status': pbh_status,
            #     'count': count
            # }


            print("remove Ecmp member")
            sai_thrift_remove_next_hop_group_member(self.client, tunnel_ecmp_member1)
            export_index = lbid_index % nhg_members_count(self.client,tunnel_ecmp)

            pkt_params = {
                uport2_dev: {
                    "dmac": self.unbor_mac2,
                    "idmac": self.inner_dmac2,
                    "tun_ip": self.tun_ip2
                },
                uport3_dev: {
                    "dmac": self.unbor_mac3,
                    "idmac": self.inner_dmac3,
                    "tun_ip": self.tun_ip3
                }
            }


            count = self._TrafficEcmpTest(pkt_params)
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            self.assertTrue((count[export_index] == MAX_ITRS),
                                    ' all pkts to port0 , %s'% count)

            self.results_dict[6] = {
                'pbh enable status': pbh_status,
                'count': count
            }

            print("add Ecmp member")
            tunnel_ecmp_member1 = sai_thrift_create_next_hop_group_member(
                self.client,
                next_hop_group_id=tunnel_ecmp,
                next_hop_id=tunnel_nhop1,
                sequence_id=1)

            export_index = lbid_index % nhg_members_count(self.client,tunnel_ecmp)

            pkt_params = {
                uport1_dev: {
                    "dmac": self.unbor_mac1,
                    "idmac": self.inner_dmac1,
                    "tun_ip": self.tun_ip1
                },
                uport2_dev: {
                    "dmac": self.unbor_mac2,
                    "idmac": self.inner_dmac2,
                    "tun_ip": self.tun_ip2
                },
                uport3_dev: {
                    "dmac": self.unbor_mac3,
                    "idmac": self.inner_dmac3,
                    "tun_ip": self.tun_ip3
                }
            }

            count = self._TrafficEcmpTest(pkt_params)
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            self.assertTrue((count[export_index] == MAX_ITRS),
                                    ' all pkts to port0 , %s'% count)

            self.results_dict[7] = {
                'pbh enable status': pbh_status,
                'count': count
            }

            print_pbhtest_results(self.ecmp_pbh_test,self.results_dict, "PBh overlay Ecmp Results")


        finally:
            sai_thrift_remove_route_entry(self.client, tunnel_route3)
            sai_thrift_remove_neighbor_entry(self.client, unbor3)
            sai_thrift_remove_next_hop(self.client, unhop3)
            sai_thrift_remove_route_entry(self.client, tunnel_route2)
            sai_thrift_remove_neighbor_entry(self.client, unbor2)
            sai_thrift_remove_next_hop(self.client, unhop2)
            sai_thrift_remove_route_entry(self.client, tunnel_route1)
            sai_thrift_remove_neighbor_entry(self.client, unbor1)
            sai_thrift_remove_next_hop(self.client, unhop1)
            sai_thrift_remove_route_entry(self.client, vm_route)
            sai_thrift_remove_next_hop_group_member(self.client,
                                                    tunnel_ecmp_member3)
            sai_thrift_remove_next_hop_group_member(self.client,
                                                    tunnel_ecmp_member2)
            sai_thrift_remove_next_hop_group_member(self.client,
                                                    tunnel_ecmp_member1)
            sai_thrift_remove_next_hop_group(self.client, tunnel_ecmp)
            sai_thrift_remove_next_hop(self.client, tunnel_nhop3)
            sai_thrift_remove_next_hop(self.client, tunnel_nhop2)
            sai_thrift_remove_next_hop(self.client, tunnel_nhop1)

            sai_thrift_remove_router_interface(self.client, urif3)
            sai_thrift_remove_router_interface(self.client, urif2)
            sai_thrift_remove_router_interface(self.client, urif1)


    def underlayEcmpPBHTunnelTest(self):
        '''
        Verify tunnel underlay nexthop resolution with underlay ECMP
        '''
        print("\nunderlayEcmpTunnelTest()")

        uport = self.port25
        uport_dev = self.dev_port25
        uport2 = self.port26
        uport2_dev = self.dev_port26
        uport3 = self.port27
        uport3_dev = self.dev_port27

        try:
            urif = sai_thrift_create_router_interface(
                self.client,
                type=SAI_ROUTER_INTERFACE_TYPE_PORT,
                virtual_router_id=self.uvrf,
                port_id=uport)

            urif2 = sai_thrift_create_router_interface(
                self.client,
                type=SAI_ROUTER_INTERFACE_TYPE_PORT,
                virtual_router_id=self.uvrf,
                port_id=uport2)

            urif3 = sai_thrift_create_router_interface(
                self.client,
                type=SAI_ROUTER_INTERFACE_TYPE_PORT,
                virtual_router_id=self.uvrf,
                port_id=uport3)

            unhop = sai_thrift_create_next_hop(self.client,
                                               ip=sai_ipaddress(self.tun_ip1),
                                               router_interface_id=urif,
                                               type=SAI_NEXT_HOP_TYPE_IP)

            unbor = sai_thrift_neighbor_entry_t(
                rif_id=urif, ip_address=sai_ipaddress(self.tun_ip1))
            sai_thrift_create_neighbor_entry(self.client,
                                             unbor,
                                             dst_mac_address=self.unbor_mac1,
                                             no_host_route=True)
            tunnel_route1 = sai_thrift_route_entry_t(
                vr_id=self.uvrf,
                destination=sai_ipprefix(self.tun_ip1 + self.tun_ip_mask))
            sai_thrift_create_route_entry(self.client,
                                          tunnel_route1,
                                          next_hop_id=unhop)


            unhop2 = sai_thrift_create_next_hop(self.client,
                                                ip=sai_ipaddress(self.tun_ip2),
                                                router_interface_id=urif2,
                                                type=SAI_NEXT_HOP_TYPE_IP)

            unbor2 = sai_thrift_neighbor_entry_t(
                rif_id=urif2, ip_address=sai_ipaddress(self.tun_ip2))
            sai_thrift_create_neighbor_entry(self.client,
                                             unbor2,
                                             dst_mac_address=self.unbor_mac2,
                                             no_host_route=True)

            tunnel_route2 = sai_thrift_route_entry_t(
                vr_id=self.uvrf,
                destination=sai_ipprefix(self.tun_ip2 + self.tun_ip_mask))
            sai_thrift_create_route_entry(self.client,
                                          tunnel_route2,
                                          next_hop_id=unhop2)

            unhop3 = sai_thrift_create_next_hop(self.client,
                                                ip=sai_ipaddress(self.tun_ip3),
                                                router_interface_id=urif3,
                                                type=SAI_NEXT_HOP_TYPE_IP)

            unbor3 = sai_thrift_neighbor_entry_t(
                rif_id=urif3, ip_address=sai_ipaddress(self.tun_ip3))
            sai_thrift_create_neighbor_entry(self.client,
                                             unbor3,
                                             dst_mac_address=self.unbor_mac3,
                                             no_host_route=True)

            tunnel_route3 = sai_thrift_route_entry_t(
                vr_id=self.uvrf,
                destination=sai_ipprefix(self.tun_ip3 + self.tun_ip_mask))
            sai_thrift_create_route_entry(self.client,
                                          tunnel_route3,
                                          next_hop_id=unhop3)

            uecmp = sai_thrift_create_next_hop_group(
                self.client, type=SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_ORDERED_ECMP)

            uecmp_member1 = sai_thrift_create_next_hop_group_member(
                self.client, next_hop_group_id=uecmp, next_hop_id=unhop,sequence_id=1)
            uecmp_member2 = sai_thrift_create_next_hop_group_member(
                self.client, next_hop_group_id=uecmp, next_hop_id=unhop2,sequence_id=2)
            uecmp_member3 = sai_thrift_create_next_hop_group_member(
                self.client, next_hop_group_id=uecmp, next_hop_id=unhop3,sequence_id=3)

            tunnel_nhop = sai_thrift_create_next_hop(
                self.client,
                type=SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP,
                tunnel_id=self.tunnel,
                ip=sai_ipaddress(self.customer_ip),
                tunnel_mac=self.inner_dmac1,
                tunnel_vni=self.vni)

            vm_route = sai_thrift_route_entry_t(
                vr_id=self.ovrf, destination=sai_ipprefix(self.vm_ip1 + '/32'))
            sai_thrift_create_route_entry(self.client,
                                          vm_route,
                                          next_hop_id=tunnel_nhop)

            tunnel_route = sai_thrift_route_entry_t(
                vr_id=self.uvrf,
                destination=sai_ipprefix(self.customer_ip + self.tun_ip_mask))
            sai_thrift_create_route_entry(self.client,
                                          tunnel_route,
                                          next_hop_id=uecmp)

            pkt_params = {
                uport_dev: {
                    "dmac": self.unbor_mac1,
                    "idmac": self.inner_dmac1,
                    "tun_ip": self.customer_ip
                },
                uport2_dev: {
                    "dmac": self.unbor_mac2,
                    "idmac": self.inner_dmac1,
                    "tun_ip": self.customer_ip
                },
                uport3_dev: {
                    "dmac": self.unbor_mac3,
                    "idmac": self.inner_dmac1,
                    "tun_ip": self.customer_ip
                }
            }


            self.results_dict = {}
            count = self._TrafficEcmpTest(pkt_params)
            pbh_status = get_pbh_enable_status(self,port=self.oport,nexthop_group=uecmp)
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            for i in range(nhg_members_count(self.client,uecmp)):
                self.assertTrue((count[i] >= ((MAX_ITRS / nhg_members_count(self.client,uecmp)) * 0.2)),
                                'Not all paths are equally balanced, %s'% count)

            self.results_dict[0] = {
                'pbh enable status': pbh_status,
                'count': count
            }

            lbid_index = random.randint(0,127)

            print(" overlayport pbh lbid %s"%lbid_index)
            sai_thrift_set_port_attribute(self.client,self.oport,ppn_l1_enable=True,lbid=lbid_index)
            sai_thrift_set_port_attribute(self.client,uport,ppn_l1_enable=True,lbid=lbid_index)
            sai_thrift_set_port_attribute(self.client,uport2,ppn_l1_enable=True,lbid=lbid_index)
            sai_thrift_set_port_attribute(self.client,uport3,ppn_l1_enable=True,lbid=lbid_index)
            export_index = lbid_index % nhg_members_count(self.client,uecmp)

            print("enable switch pbh")
            status = sai_thrift_set_switch_attribute(
                self.client, custom_ecmp_lvl1_ppn_enable=True)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            pbh_status = get_pbh_enable_status(self,port=self.oport,nexthop_group=uecmp)
            count = self._TrafficEcmpTest(pkt_params)
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))

            if self.ecmp_pbh_test == True:
                for i in range(nhg_members_count(self.client,uecmp)):
                    self.assertTrue((count[i] >= ((MAX_ITRS / nhg_members_count(self.client,uecmp)) * 0.2)),
                                    'Not all paths are equally balanced, %s'% count)
            else:
                self.assertTrue((count[export_index] == MAX_ITRS),
                                        ' all pkts to port0 , %s'% count)

            self.results_dict[1] = {
                'pbh enable status': pbh_status,
                'count': count
            }


            print("enable Ecmp pbh")
            sai_thrift_set_next_hop_group_attribute(self.client,uecmp,custom_ecmp_lvl1_ppn_enable=True)
            pbh_status = get_pbh_enable_status(self,port=self.oport,nexthop_group=uecmp)

            count = self._TrafficEcmpTest(pkt_params)

            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)

            self.results_dict[2] = {
                'pbh enable status': pbh_status,
                'count': count
            }

            lbid_index = random.randint(0,127)
            print(" overlayport pbh lbid %s"%lbid_index)
            sai_thrift_set_port_attribute(self.client,self.oport,lbid=lbid_index)
            export_index = lbid_index % nhg_members_count(self.client,uecmp)

            count = self._TrafficEcmpTest(pkt_params)
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            self.assertTrue((count[export_index] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)

            self.results_dict[3] = {
                'pbh enable status': pbh_status,
                'count': count
            }

            print("disable Ecmp pbh")
            sai_thrift_set_next_hop_group_attribute(self.client,tunnel_uecmpecmp,custom_ecmp_lvl1_ppn_enable=False)
            pbh_status = get_pbh_enable_status(self,port=self.oport,nexthop_group=uecmp)
            count = self._TrafficEcmpTest(pkt_params)

            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))

            if self.ecmp_pbh_test == True:
                for i in range(nhg_members_count(self.client,uecmp)):
                    self.assertTrue((count[i] >= ((MAX_ITRS / nhg_members_count(self.client,uecmp)) * 0.2)),
                                    'Not all paths are equally balanced, %s'% count)
            else:
                self.assertTrue((count[export_index] == MAX_ITRS),
                                        ' all pkts to port0 , %s'% count)

            self.results_dict[4] = {
                'pbh enable status': pbh_status,
                'count': count
            }

            print("enbale Ecmp pbh")
            sai_thrift_set_next_hop_group_attribute(self.client,uecmp,custom_ecmp_lvl1_ppn_enable=True)
            pbh_status = get_pbh_enable_status(self,port=self.oport,nexthop_group=uecmp)
            count = self._TrafficEcmpTest(pkt_params)

            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            self.assertTrue((count[export_index] == MAX_ITRS),
                                    ' all pkts to port0 , %s'% count)

            self.results_dict[5] = {
                'pbh enable status': pbh_status,
                'count': count
            }

            print("remove Ecmp member")
            sai_thrift_remove_next_hop_group_member(self.client, uecmp_member1)
            export_index = lbid_index % nhg_members_count(self.client,uecmp)

            pkt_params = {
                uport2_dev: {
                    "dmac": self.unbor_mac2,
                    "idmac": self.inner_dmac1,
                    "tun_ip": self.customer_ip
                },
                uport3_dev: {
                    "dmac": self.unbor_mac3,
                    "idmac": self.inner_dmac1,
                    "tun_ip": self.customer_ip
                }
            }

            count = self._TrafficEcmpTest(pkt_params)
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            self.assertTrue((count[export_index] == MAX_ITRS),
                                    ' all pkts to port0 , %s'% count)

            self.results_dict[6] = {
                'pbh enable status': pbh_status,
                'count': count
            }

            print("add Ecmp member")
            uecmp = sai_thrift_create_next_hop_group_member(
                self.client,
                next_hop_group_id=uecmp,
                next_hop_id=unhop,
                sequence_id=1)

            export_index = lbid_index % nhg_members_count(self.client,uecmp)

            pkt_params = {
                uport_dev: {
                    "dmac": self.unbor_mac1,
                    "idmac": self.inner_dmac1,
                    "tun_ip": self.customer_ip
                },
                uport2_dev: {
                    "dmac": self.unbor_mac2,
                    "idmac": self.inner_dmac1,
                    "tun_ip": self.customer_ip
                },
                uport3_dev: {
                    "dmac": self.unbor_mac3,
                    "idmac": self.inner_dmac1,
                    "tun_ip": self.customer_ip
                }
            }

            count = self._TrafficEcmpTest(pkt_params)
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            self.assertTrue((count[export_index] == MAX_ITRS),
                                    ' all pkts to port0 , %s'% count)

            self.results_dict[7] = {
                'pbh enable status': pbh_status,
                'count': count
            }

            print_pbhtest_results(self.ecmp_pbh_test,self.results_dict, "PBh underlay Ecmp Results")






        finally:
            sai_thrift_remove_route_entry(self.client, tunnel_route3)
            sai_thrift_remove_neighbor_entry(self.client, unbor3)
            sai_thrift_remove_next_hop(self.client, unhop3)
            sai_thrift_remove_route_entry(self.client, tunnel_route2)
            sai_thrift_remove_neighbor_entry(self.client, unbor2)
            sai_thrift_remove_next_hop(self.client, unhop2)
            sai_thrift_remove_route_entry(self.client, tunnel_route)
            sai_thrift_remove_route_entry(self.client, tunnel_route1)
            sai_thrift_remove_neighbor_entry(self.client, unbor)
            sai_thrift_remove_next_hop(self.client, unhop)
            sai_thrift_remove_route_entry(self.client, vm_route)
            sai_thrift_remove_next_hop(self.client, tunnel_nhop)
            sai_thrift_remove_next_hop_group_member(self.client, uecmp_member1)
            sai_thrift_remove_next_hop_group_member(self.client, uecmp_member2)
            sai_thrift_remove_next_hop_group_member(self.client, uecmp_member3)
            sai_thrift_remove_next_hop_group(self.client, uecmp)
            sai_thrift_remove_router_interface(self.client, urif3)
            sai_thrift_remove_router_interface(self.client, urif2)
            sai_thrift_remove_router_interface(self.client, urif)



class TunnelPBHTest(TunnelPBHTestBase):
    '''
    Tests regarding different cases of nexthop resolution cases with
    IPv4 underlay
    '''
    def __init__(self):
        super(TunnelPBHTest, self).__init__(ecmp_pbh_test=False)

    def runTest(self):
        self.OverlayEcmpPBHTunnelTest()
        self.underlayEcmpPBHTunnelTest()


class vxlanPktPBHTest(PBHBasicHelper):

    def __init__(self):
        super(vxlanPktPBHTest, self).__init__(
            ecmp_pbh_test=False)

    def setUp(self):
        super(vxlanPktPBHTest, self).setUp()

    def TrafficTest(self,pkt_params):
        '''
        For sending traffic
        Returns:
            int: pkts count
        '''
        print('Sending Traffic')


        ports = list(pkt_params.keys())

        count = len(ports)*[0]
        dst_ip_list = batch_generate_unicast_ips(count=MAX_ITRS)

        for i,dst_ip_addr in enumerate(dst_ip_list):
            print("dst_ip is %s"%dst_ip_addr)
            exp_pkts = []
            inner_pkt = simple_udp_packet(eth_dst=ROUTER_MAC,
                                      eth_src="00:11:11:11:11:11",
                                      ip_dst="100.100.1.2",
                                      ip_src="100.100.1.1",
                                      ip_id=108,
                                      ip_ttl=63)
            vxlan_pkt = simple_vxlan_packet(eth_dst=ROUTER_MAC,
                                            eth_src="00:33:33:33:33:33",
                                            ip_dst=dst_ip_addr,
                                            ip_src="10.10.10.1",
                                            ip_id=0,
                                            ip_ttl=64,
                                            ip_flags=0x2,
                                            udp_sport=11638,
                                            with_udp_chksum=False,
                                            vxlan_vni=1000,
                                            inner_frame=inner_pkt)

            for port in pkt_params:
                exp_pkt = simple_vxlan_packet(eth_dst=pkt_params[port]["dmac"],
                                            eth_src=ROUTER_MAC,
                                            ip_dst=dst_ip_addr,
                                            ip_src="10.10.10.1",
                                            ip_id=0,
                                            ip_ttl=63,
                                            ip_flags=0x2,
                                            udp_sport=11638,
                                            with_udp_chksum=False,
                                            vxlan_vni=1000,
                                            inner_frame=inner_pkt)
                exp_pkts.append(exp_pkt)

            send_packet(self, self.dev_port24, vxlan_pkt)
            rcv_idx = verify_any_packet_any_port(
                self,exp_pkts,ports)
            count[rcv_idx] += 1




        return count


    def runTest(self):
        print("vxlanPktPBHTest")

        pkt_params = {
            self.dev_port0: {
                "dmac": self.mac1
            },
            self.dev_port1: {
                "dmac": self.mac2
            },
            self.dev_port2: {
                "dmac": self.mac3
            }
        }
        hash_field_list = [SAI_NATIVE_HASH_FIELD_DST_IP]
        setupECMPHash(self,hash_field_list=hash_field_list)

        nhg_member_count = nhg_members_count( self.client,self.nhop_group1)
        self.results_dict = {}
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)

        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        for i in range(nhg_member_count):
            self.assertTrue((count[i] >= ((MAX_ITRS / nhg_member_count) * 0.2)),
                            'Not all paths are equally balanced, %s'% count)
        self.results_dict[0] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("enable switch pbh")
        status = sai_thrift_set_switch_attribute(
            self.client, custom_ecmp_lvl1_ppn_enable=True)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        for i in range(nhg_member_count):
            self.assertTrue((count[i] >= ((MAX_ITRS / nhg_member_count) * 0.2)),
                            'Not all paths are equally balanced, %s'% count)
        self.results_dict[1] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("enable port24 pbh,LBID=0")
        sai_thrift_set_port_attribute(self.client,self.port24,ppn_l1_enable=True,lbid=0)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        if self.ecmp_pbh_test == True:
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            for i in range(nhg_member_count):
                self.assertTrue((count[i] >= ((MAX_ITRS / nhg_member_count) * 0.2)),
                                'Not all paths are equally balanced, %s'% count)
        else:
            print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
            self.assertTrue((count[0] == MAX_ITRS),
                                    ' all pkts to port0 , %s'% count)

        self.results_dict[2] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("enable Ecmp pbh")
        sai_thrift_set_next_hop_group_attribute(self.client,self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)
        ecmp_ppn_attr = sai_thrift_get_next_hop_group_attribute(self.client,next_hop_group_oid=self.nhop_group1,custom_ecmp_lvl1_ppn_enable=True)
        ecmp_lvl1_ppn_enable   = ecmp_ppn_attr['custom_ecmp_lvl1_ppn_enable']
        if self.ecmp_pbh_test == True:
            self.assertTrue(ecmp_lvl1_ppn_enable == True)
        else:
            self.assertTrue(ecmp_lvl1_ppn_enable == False)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[0] == MAX_ITRS),
                                ' all pkts to port0 , %s'% count)
        self.results_dict[3] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print("set port24 pbh LBID=1")
        sai_thrift_set_port_attribute(self.client,self.port24,lbid=1)
        pbh_status = get_pbh_enable_status(self,port=self.port24,nexthop_group=self.nhop_group1)
        count = self.TrafficTest(pkt_params)
        print('Traffic distribution ports %s  --> %s' % (list(pkt_params.keys()),count))
        self.assertTrue((count[1] == MAX_ITRS),
                                ' all pkts to port1 , %s'% count)

        self.results_dict[4] = {
            'pbh enable status': pbh_status,
            'count': count
        }

        print_pbhtest_results(self.ecmp_pbh_test,self.results_dict, "PBh Test Results")

    def tearDown(self):
        super(vxlanPktPBHTest, self).tearDown()
