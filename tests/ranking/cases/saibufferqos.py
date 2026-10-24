# Copyright 2021-present Intel Corporation.
#
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
#
# The below software in this distribution may have been modified
# by Clounix ("Clounix Modifications"). All Clounix Modifications
# are copyright © Clounix(Shanghai) Technology Limited.
#
# The below software in this distribution may have been modified
# by Centec . All Centec Modifications
# are copyright © Centec(Suzhou) Technology Limited.
#

"""
Thrift SAI interface Buffer tests
"""
from multiprocessing import Process, Manager
from sai_thrift.sai_headers import *
from sai_base_test import *
import time

class SaiHelperScaleTM(SaiHelperUtilsMixin, SaiHelperBase):
    """
    Set common base ports configuration for tests

    Common ports configuration:
    * U/T = untagged/tagged VLAN member
    +--------+------+-----------+-------------+--------+------------+------------+
    | Port   | LAG  | _member   | Bridge port | VLAN   | _member    | RIF        |
    +========+======|===========+=============+========+============+============+
    | port0  |      |           | port0_bp    | vlan10 | _member0 T |            |
    | port1  |      |           | port1_bp    |        | _member1 T |            |
    | port2  |      |           | port2_bp    |        | _member2 T |            |
    | port3  |      |           | port3_bp    |        | _member3 T |            |
    | port4  |      |           | port4_bp    |        | _member4 T |            |
    | port5  |      |           | port5_bp    |        | _member5 T |            |
    | port6  |      |           | port6_bp    |        | _member6 T |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port7  | lag2 | _member7  | lag2_bp     | vlan20 | _member2 T |            |
    | port8  |      | _member8  |             |        |            |            |
    | port9  |      | _member9  |             |        |            |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port10 |      |           |             |        |            | port10_rif |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port11 |      |           |             |        |            | port11_rif |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port12 |      |           |             |        |            | port12_rif |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port13 |      |           |             |        |            | port13_rif |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port14 | lag3 | _member14 |             |        |            | lag3_rif   |
    | port15 |      | _member15 |             |        |            |            |
    | port16 |      | _member16 |             |        |            |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port17 | lag4 | _member17 |             |        |            | lag4_rif   |
    | port18 |      | _member18 |             |        |            |            |
    | port19 |      | _member19 |             |        |            |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port20 |      |           | port20_bp   | vlan10 | _member7 T |            |
    | port21 |      |           | port21_bp   |        | _member8 T |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port22 | lag5 | _member22 | lag5_bp     | vlan30 | _member2 T |            |
    | port23 |      | _member23 |             |        |            |            |
    +--------+------+-----------+-------------+--------+------------+------------+
    | port24 |                                                                   |
    | port25 |                                                                   |
    | port26 |                                                                   |
    | port27 |                            UNASSIGNED                             |
    | port28 |                                                                   |
    | port29 |                                                                   |
    | port30 |                                                                   |
    | port31 |                                                                   |
    +--------+-------------------------------------------------------------------+
    """
    def create_default_v4_v6_route_entry(self):
        """
        Create default v4 and v6 route entry.
        """
        DEFAULT_IP_V4_PREFIX = '0.0.0.0/0'
        DEFAULT_IP_V6_PREFIX = '0000:0000:0000:0000:0000:0000:0000:0000'
        print("Create default v4&v6 route entry...")
        v6_default = sai_thrift_ip_prefix_t(addr_family=1,
                                            addr=sai_thrift_ip_addr_t(
                                                ip6=DEFAULT_IP_V6_PREFIX),
                                            mask=sai_thrift_ip_addr_t(ip6=DEFAULT_IP_V6_PREFIX))
        self.default_ipv6_route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                                 destination=v6_default)
        status = sai_thrift_create_route_entry(
            self.client,
            route_entry=self.default_ipv6_route_entry,
            packet_action=SAI_PACKET_ACTION_DROP)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        self.default_ipv4_route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                                 destination=sai_ipprefix(DEFAULT_IP_V4_PREFIX))
        status = sai_thrift_create_route_entry(
            self.client,
            route_entry=self.default_ipv4_route_entry,
            packet_action=SAI_PACKET_ACTION_DROP)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

    def destroy_default_v4_v6_route_entry(self):
        DEFAULT_IP_V4_PREFIX = '0.0.0.0/0'
        DEFAULT_IP_V6_PREFIX = '0000:0000:0000:0000:0000:0000:0000:0000'
        print("Remove default v4&v6 route entry...")
        v6_default = sai_thrift_ip_prefix_t(addr_family=1,
                                            addr=sai_thrift_ip_addr_t(
                                                ip6=DEFAULT_IP_V6_PREFIX),
                                            mask=sai_thrift_ip_addr_t(ip6=DEFAULT_IP_V6_PREFIX))
        self.default_ipv6_route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                                 destination=v6_default)
        status = sai_thrift_remove_route_entry(
            self.client,
            route_entry=self.default_ipv6_route_entry)

        self.default_ipv4_route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf,
                                                                 destination=sai_ipprefix(DEFAULT_IP_V4_PREFIX))
        status = sai_thrift_remove_route_entry(
            self.client,
            route_entry=self.default_ipv4_route_entry)

    def create_and_verify_qos_map(self, map_type):

        key_list=[0,1,2,3,4,5,6,7]
        data_list=[0,1,2,3,4,5,6,7]
        QOS_TYPE_DICT = {
            SAI_QOS_MAP_TYPE_DSCP_TO_TC: (
                "dscp", "tc"),
            SAI_QOS_MAP_TYPE_DSCP_TO_COLOR: (
                "dscp", "color"),
            SAI_QOS_MAP_TYPE_TC_TO_QUEUE: (
                "tc", "queue_index"),
            SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR: (
                "dot1p", "color"),
            SAI_QOS_MAP_TYPE_DOT1P_TO_TC: (
                "dot1p", "tc"),
            SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_QUEUE: (
                "prio", "queue_index"),
            SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_PRIORITY_GROUP: (
                "prio", "pg"),
            SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP: (
                "tc", "pg"),
            SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DOT1P: (
                "tc", "dot1p", "color"),
            SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP: (
                "tc", "dscp", "color")}
        map_list = []
        i = 0
        if len(key_list) != len(data_list):
            print("WARNING length of both lists should be equal")
            return 0
        for qos_type_dict_key in QOS_TYPE_DICT:
            if ((map_type == qos_type_dict_key) and
                    (len(QOS_TYPE_DICT[qos_type_dict_key]) == 2)):
                for key_list_data in key_list:
                    value_list_data = data_list[i]
                    mapping = sai_thrift_qos_map_t(
                        key=sai_thrift_qos_map_params_t(
                            **{QOS_TYPE_DICT[qos_type_dict_key][0]:
                            key_list_data}),
                        value=sai_thrift_qos_map_params_t(
                            **{QOS_TYPE_DICT[qos_type_dict_key][1]:
                            value_list_data}))
                    map_list.append(mapping)
                    i += 1
            elif ((map_type == qos_type_dict_key) and
                (len(QOS_TYPE_DICT[qos_type_dict_key]) == 3)):
                for key_list_data1, key_list_data2 in key_list:
                    value_list_data = data_list[i]
                    mapping = sai_thrift_qos_map_t(
                        key=sai_thrift_qos_map_params_t(
                            **{QOS_TYPE_DICT[qos_type_dict_key][0]:
                            key_list_data1,
                            QOS_TYPE_DICT[qos_type_dict_key][2]:
                            key_list_data2}),
                        value=sai_thrift_qos_map_params_t(
                            **{QOS_TYPE_DICT[qos_type_dict_key][1]:
                            value_list_data}))
                    map_list.append(mapping)
                    i += 1
        qos_map_list = sai_thrift_qos_map_list_t(count=len(map_list),
                                                maplist=map_list)

        qos_map_id = sai_thrift_create_qos_map(self.client,
                                            type=int(map_type),
                                            map_to_value_list=qos_map_list)
        return qos_map_id

    def setUp(self, skip_reason = None):
        super(SaiHelperScaleTM, self).setUp(skip_reason = skip_reason)
        ## Create Buffer Profile
        self.reserved_buf_size = 9000
        self.xoff_th = 50000
        self.xon_offset_th = 9000
        self.shared_buf_size = self.reserved_buf_size * 4
        self.buf_size = 50000000
        self.headroom_size = 10000000
        self.alpha1=3
        self.alpha2=-1
        self.ingr_pool = sai_thrift_create_buffer_pool(
            self.client, type=SAI_BUFFER_POOL_TYPE_INGRESS, size=self.buf_size, xoff_size=self.headroom_size)
        self.assertGreater(self.ingr_pool, 0)

        self.egr_pool = sai_thrift_create_buffer_pool(
            self.client, type=SAI_BUFFER_POOL_TYPE_EGRESS, size=self.buf_size)
        self.assertGreater(self.egr_pool, 0)

        self.buffer_profile_pg1 = sai_thrift_create_buffer_profile(
            self.client, pool_id=self.ingr_pool,
            reserved_buffer_size=self.reserved_buf_size,
            shared_dynamic_th=self.alpha1,
            xoff_th=self.xoff_th,
            xon_offset_th=self.xon_offset_th,
            threshold_mode=SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC)
        self.assertGreater(self.buffer_profile_pg1, 0)

        self.buffer_profile_q1 = sai_thrift_create_buffer_profile(
            self.client, pool_id=self.egr_pool,
            reserved_buffer_size=self.reserved_buf_size,
            shared_static_th=self.buf_size,
            threshold_mode=SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC)
        self.assertGreater(self.buffer_profile_q1, 0)

        self.buffer_profile_pg2 = sai_thrift_create_buffer_profile(
            self.client, pool_id=self.ingr_pool,
            reserved_buffer_size=self.reserved_buf_size,
            shared_static_th=self.buf_size,
            threshold_mode=SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC)
        self.assertGreater(self.buffer_profile_pg2, 0)

        self.buffer_profile_q2 = sai_thrift_create_buffer_profile(
            self.client, pool_id=self.egr_pool,
            reserved_buffer_size=self.reserved_buf_size,
            shared_dynamic_th=self.alpha1,
            threshold_mode=SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC)
        self.assertGreater(self.buffer_profile_q2, 0)

        self.buffer_profile_pg3 = sai_thrift_create_buffer_profile(
            self.client, pool_id=self.ingr_pool,
            reserved_buffer_size=self.reserved_buf_size,
            shared_static_th=self.shared_buf_size,
            threshold_mode=SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC)
        self.assertGreater(self.buffer_profile_pg3, 0)

        self.buffer_profile_q3 = sai_thrift_create_buffer_profile(
            self.client, pool_id=self.egr_pool,
            reserved_buffer_size=self.reserved_buf_size,
            shared_dynamic_th=self.alpha2,
            threshold_mode=SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC)
        self.assertGreater(self.buffer_profile_q3, 0)


        attr = sai_thrift_get_port_attribute(
            self.client, self.port1, number_of_ingress_priority_groups=True)
        self.assertNotEqual(attr['number_of_ingress_priority_groups'], 0)
        ipg_num = attr["number_of_ingress_priority_groups"]
        sai_list = sai_thrift_u32_list_t(count=ipg_num, uint32list=[])
        attr = sai_thrift_get_port_attribute(
            self.client, self.port1, ingress_priority_group_list=sai_list)
        self.assertEqual(attr['ingress_priority_group_list'].count, ipg_num)
        idlist = attr['ingress_priority_group_list'].idlist
        self.ipg_idx1 = idlist

        attr = sai_thrift_get_port_attribute(
            self.client, self.port2, number_of_ingress_priority_groups=True)
        self.assertNotEqual(attr['number_of_ingress_priority_groups'], 0)
        ipg_num = attr["number_of_ingress_priority_groups"]

        sai_list = sai_thrift_u32_list_t(count=ipg_num, uint32list=[])
        attr = sai_thrift_get_port_attribute(
            self.client, self.port2, ingress_priority_group_list=sai_list)
        self.assertEqual(attr['ingress_priority_group_list'].count, ipg_num)
        idlist = attr['ingress_priority_group_list'].idlist
        self.ipg_idx2 = idlist

        attr = sai_thrift_get_port_attribute(
            self.client, self.port3, number_of_ingress_priority_groups=True)
        self.assertNotEqual(attr['number_of_ingress_priority_groups'], 0)
        ipg_num = attr["number_of_ingress_priority_groups"]

        sai_list = sai_thrift_u32_list_t(count=ipg_num, uint32list=[])
        attr = sai_thrift_get_port_attribute(
            self.client, self.port3, ingress_priority_group_list=sai_list)
        self.assertEqual(attr['ingress_priority_group_list'].count, ipg_num)
        idlist = attr['ingress_priority_group_list'].idlist
        self.ipg_idx3 = idlist

        sai_list = sai_thrift_u32_list_t(count=ipg_num, uint32list=[])
        attr = sai_thrift_get_port_attribute(
            self.client, self.port4, ingress_priority_group_list=sai_list)
        self.assertEqual(attr['ingress_priority_group_list'].count, ipg_num)
        idlist = attr['ingress_priority_group_list'].idlist
        self.ipg_idx4 = idlist

        sai_list = sai_thrift_u32_list_t(count=ipg_num, uint32list=[])
        attr = sai_thrift_get_port_attribute(
            self.client, self.port5, ingress_priority_group_list=sai_list)
        self.assertEqual(attr['ingress_priority_group_list'].count, ipg_num)
        idlist = attr['ingress_priority_group_list'].idlist
        self.ipg_idx5 = idlist

        sai_list = sai_thrift_u32_list_t(count=ipg_num, uint32list=[])
        attr = sai_thrift_get_port_attribute(
            self.client, self.port6, ingress_priority_group_list=sai_list)
        self.assertEqual(attr['ingress_priority_group_list'].count, ipg_num)
        idlist = attr['ingress_priority_group_list'].idlist
        self.ipg_idx6 = idlist

        sai_list = sai_thrift_u32_list_t(count=ipg_num, uint32list=[])
        attr = sai_thrift_get_port_attribute(
            self.client, self.port20, ingress_priority_group_list=sai_list)
        self.assertEqual(attr['ingress_priority_group_list'].count, ipg_num)
        idlist = attr['ingress_priority_group_list'].idlist
        self.ipg_idx20 = idlist

        sai_list = sai_thrift_u32_list_t(count=ipg_num, uint32list=[])
        attr = sai_thrift_get_port_attribute(
            self.client, self.port21, ingress_priority_group_list=sai_list)
        self.assertEqual(attr['ingress_priority_group_list'].count, ipg_num)
        idlist = attr['ingress_priority_group_list'].idlist
        self.ipg_idx21 = idlist
        sai_thrift_set_port_attribute(self.client, self.port1,
            priority_flow_control_mode=SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_SEPARATE)
        sai_thrift_set_port_attribute(self.client, self.port2,
            priority_flow_control_mode=SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_SEPARATE)
        sai_thrift_set_port_attribute(self.client, self.port6,
            priority_flow_control_mode=SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_SEPARATE)

        sai_thrift_set_port_attribute(self.client, self.port1, priority_flow_control_rx=0x0e)
        sai_thrift_set_port_attribute(self.client, self.port1, priority_flow_control_tx=0x02)
        sai_thrift_set_port_attribute(self.client, self.port2, priority_flow_control_rx=0x0e)
        sai_thrift_set_port_attribute(self.client, self.port2, priority_flow_control_tx=0x02)
        sai_thrift_set_port_attribute(self.client, self.port6, priority_flow_control_rx=0x0e)

        #all PORT DSCP to TC, TC to PG, TC to QUEUE map 1:1
        self.qos_dscp_to_tc_map_id = self.create_and_verify_qos_map(SAI_QOS_MAP_TYPE_DSCP_TO_TC)
        self.assertGreater(self.qos_dscp_to_tc_map_id, 0)

        self.qos_tc_to_pg_map_id = self.create_and_verify_qos_map(SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP)
        self.assertGreater(self.qos_tc_to_pg_map_id, 0)

        self.qos_tc_to_queue_map_id = self.create_and_verify_qos_map(SAI_QOS_MAP_TYPE_TC_TO_QUEUE)
        self.assertGreater(self.qos_tc_to_queue_map_id, 0)

        for port in self.port_list:
            status = sai_thrift_set_port_attribute(
                self.client,
                port,
                qos_dscp_to_tc_map=self.qos_dscp_to_tc_map_id)
            self.assertEqual(status, SAI_STATUS_SUCCESS)
            status = sai_thrift_set_port_attribute(
                self.client,
                port,
                qos_tc_to_priority_group_map=self.qos_tc_to_pg_map_id)
            self.assertEqual(status, SAI_STATUS_SUCCESS)
            status = sai_thrift_set_port_attribute(
                self.client,
                port,
                qos_tc_to_queue_map=self.qos_tc_to_queue_map_id)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

        queue_list = sai_thrift_object_list_t(count=20)
        attr = sai_thrift_get_port_attribute(
            self.client, self.port1, qos_queue_list=queue_list)
        self.queues1 = attr["SAI_PORT_ATTR_QOS_QUEUE_LIST"].idlist
        queue_list = sai_thrift_object_list_t(count=20)
        attr = sai_thrift_get_port_attribute(
            self.client, self.port2, qos_queue_list=queue_list)
        self.queues2 = attr["SAI_PORT_ATTR_QOS_QUEUE_LIST"].idlist
        queue_list = sai_thrift_object_list_t(count=20)
        attr = sai_thrift_get_port_attribute(
            self.client, self.port3, qos_queue_list=queue_list)
        self.queues3 = attr["SAI_PORT_ATTR_QOS_QUEUE_LIST"].idlist
        queue_list = sai_thrift_object_list_t(count=20)
        attr = sai_thrift_get_port_attribute(
            self.client, self.port4, qos_queue_list=queue_list)
        self.queues4 = attr["SAI_PORT_ATTR_QOS_QUEUE_LIST"].idlist
        queue_list = sai_thrift_object_list_t(count=20)
        attr = sai_thrift_get_port_attribute(
            self.client, self.port5, qos_queue_list=queue_list)
        self.queues5 = attr["SAI_PORT_ATTR_QOS_QUEUE_LIST"].idlist
        attr = sai_thrift_get_port_attribute(
            self.client, self.port6, qos_queue_list=queue_list)
        self.queues6 = attr["SAI_PORT_ATTR_QOS_QUEUE_LIST"].idlist

        status = sai_thrift_set_ingress_priority_group_attribute(
            self.client, self.ipg_idx1[1], buffer_profile=self.buffer_profile_pg1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = sai_thrift_set_ingress_priority_group_attribute(
            self.client, self.ipg_idx1[2], buffer_profile=self.buffer_profile_pg2)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = sai_thrift_set_ingress_priority_group_attribute(
            self.client, self.ipg_idx1[3], buffer_profile=self.buffer_profile_pg3)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = sai_thrift_set_ingress_priority_group_attribute(
            self.client, self.ipg_idx2[1], buffer_profile=self.buffer_profile_pg1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = sai_thrift_set_ingress_priority_group_attribute(
            self.client, self.ipg_idx2[2], buffer_profile=self.buffer_profile_pg2)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = sai_thrift_set_ingress_priority_group_attribute(
            self.client, self.ipg_idx2[3], buffer_profile=self.buffer_profile_pg3)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues1[1], buffer_profile_id=self.buffer_profile_q1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues1[2], buffer_profile_id=self.buffer_profile_q2)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues1[3], buffer_profile_id=self.buffer_profile_q3)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues2[1], buffer_profile_id=self.buffer_profile_q1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues2[2], buffer_profile_id=self.buffer_profile_q2)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues2[3], buffer_profile_id=self.buffer_profile_q3)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        ##########################
        # Configure WRED profiles
        ##########################
        print("Create WRED profiles...")
        green_max_thr = 10001000
        green_min_thr = 10000000
        yellow_max_thr = 10008000
        yellow_min_thr = 10000000
        red_max_thr = 10001000
        red_min_thr = 10000000
        self.wred1 = sai_thrift_create_wred(
            self.client,
            green_enable=True,
            ecn_mark_mode=SAI_ECN_MARK_MODE_ALL,
            green_min_threshold=green_min_thr,
            green_max_threshold=green_max_thr,
            green_drop_probability=100,
            yellow_enable=True,
            yellow_min_threshold=yellow_min_thr,
            yellow_max_threshold=yellow_max_thr,
            yellow_drop_probability=100,
            red_enable=True,
            red_min_threshold=red_min_thr,
            red_max_threshold=red_max_thr,
            red_drop_probability=100)
        self.assertTrue(self.wred1 != 0)

        green_max_thr = 4001000
        green_min_thr = 4000000
        yellow_max_thr = 4008000
        yellow_min_thr = 4000000
        red_max_thr = 4001000
        red_min_thr = 4000000
        self.wred2 = sai_thrift_create_wred(
            self.client,
            green_enable=True,
            ecn_mark_mode=SAI_ECN_MARK_MODE_ALL,
            green_min_threshold=green_min_thr,
            green_max_threshold=green_max_thr,
            green_drop_probability=100,
            yellow_enable=True,
            yellow_min_threshold=yellow_min_thr,
            yellow_max_threshold=yellow_max_thr,
            yellow_drop_probability=100,
            red_enable=True,
            red_min_threshold=red_min_thr,
            red_max_threshold=red_max_thr,
            red_drop_probability=100)
        self.assertTrue(self.wred2 != 0)

        green_max_thr = 3001000
        green_min_thr = 3000000
        yellow_max_thr = 3008000
        yellow_min_thr = 3000000
        red_max_thr = 3001000
        red_min_thr = 3000000
        self.wred3 = sai_thrift_create_wred(
            self.client,
            green_enable=True,
            ecn_mark_mode=SAI_ECN_MARK_MODE_ALL,
            green_min_threshold=green_min_thr,
            green_max_threshold=green_max_thr,
            green_drop_probability=100,
            yellow_enable=True,
            yellow_min_threshold=yellow_min_thr,
            yellow_max_threshold=yellow_max_thr,
            yellow_drop_probability=100,
            red_enable=True,
            red_min_threshold=red_min_thr,
            red_max_threshold=red_max_thr,
            red_drop_probability=100)
        self.assertTrue(self.wred3 != 0)
        print("-----------------------")

        # status = sai_thrift_set_queue_attribute(
        #             self.client, self.queues1[1], wred_profile_id=self.wred1)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)
        # status = sai_thrift_set_queue_attribute(
        #             self.client, self.queues1[2], wred_profile_id=self.wred2)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)
        # status = sai_thrift_set_queue_attribute(
        #             self.client, self.queues1[3], wred_profile_id=self.wred3)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)

        # status = sai_thrift_set_queue_attribute(
        #             self.client, self.queues2[1], wred_profile_id=self.wred1)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)
        # status = sai_thrift_set_queue_attribute(
        #             self.client, self.queues2[2], wred_profile_id=self.wred2)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)
        # status = sai_thrift_set_queue_attribute(
        #             self.client, self.queues2[3], wred_profile_id=self.wred3)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)

        cir = 1000000
        pir = 1000000
        self.sched1 = sai_thrift_create_scheduler(
                    self.client,
                    meter_type=SAI_METER_TYPE_BYTES,
                    scheduling_type=SAI_SCHEDULING_TYPE_DWRR,
                    scheduling_weight=60,
                    min_bandwidth_rate=cir,
                    max_bandwidth_rate=pir)
        self.sched2 = sai_thrift_create_scheduler(
                    self.client,
                    meter_type=SAI_METER_TYPE_BYTES,
                    scheduling_type=SAI_SCHEDULING_TYPE_DWRR,
                    scheduling_weight=60,
                    min_bandwidth_rate=cir,
                    max_bandwidth_rate=pir)
        self.sched3 = sai_thrift_create_scheduler(
                    self.client,
                    meter_type=SAI_METER_TYPE_BYTES,
                    scheduling_type=SAI_SCHEDULING_TYPE_DWRR,
                    scheduling_weight=15,
                    min_bandwidth_rate=cir,
                    max_bandwidth_rate=pir)

        attr = sai_thrift_get_queue_attribute(
                self.client, self.queues1[1], parent_scheduler_node=True)
        self.assertNotEqual(attr['parent_scheduler_node'], 0)
        self.queues1_1_parent_sch_grp = attr["parent_scheduler_node"]
        status = sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues1_1_parent_sch_grp, scheduler_profile_id=self.sched1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        attr = sai_thrift_get_queue_attribute(
                self.client, self.queues1[2], parent_scheduler_node=True)
        self.assertNotEqual(attr['parent_scheduler_node'], 0)
        self.queues1_2_parent_sch_grp = attr["parent_scheduler_node"]
        status = sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues1_2_parent_sch_grp, scheduler_profile_id=self.sched2)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        attr = sai_thrift_get_queue_attribute(
                self.client, self.queues1[3], parent_scheduler_node=True)
        self.assertNotEqual(attr['parent_scheduler_node'], 0)
        self.queues1_3_parent_sch_grp = attr["parent_scheduler_node"]
        status = sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues1_3_parent_sch_grp, scheduler_profile_id=self.sched3)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        attr = sai_thrift_get_queue_attribute(
                self.client, self.queues2[1], parent_scheduler_node=True)
        self.assertNotEqual(attr['parent_scheduler_node'], 0)
        self.queues2_1_parent_sch_grp = attr["parent_scheduler_node"]
        status = sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues2_1_parent_sch_grp, scheduler_profile_id=self.sched1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        attr = sai_thrift_get_queue_attribute(
                self.client, self.queues2[2], parent_scheduler_node=True)
        self.assertNotEqual(attr['parent_scheduler_node'], 0)
        self.queues2_2_parent_sch_grp = attr["parent_scheduler_node"]
        status = sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues2_2_parent_sch_grp, scheduler_profile_id=self.sched2)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        attr = sai_thrift_get_queue_attribute(
                self.client, self.queues2[3], parent_scheduler_node=True)
        self.assertNotEqual(attr['parent_scheduler_node'], 0)
        self.queues2_3_parent_sch_grp = attr["parent_scheduler_node"]
        status = sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues2_3_parent_sch_grp, scheduler_profile_id=self.sched3)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        self.sched4 = sai_thrift_create_scheduler(
                    self.client,
                    meter_type=SAI_METER_TYPE_BYTES,
                    scheduling_type=SAI_SCHEDULING_TYPE_DWRR,
                    scheduling_weight=60)
        self.sched5 = sai_thrift_create_scheduler(
                    self.client,
                    meter_type=SAI_METER_TYPE_BYTES,
                    scheduling_type=SAI_SCHEDULING_TYPE_DWRR,
                    scheduling_weight=60)
        self.sched6 = sai_thrift_create_scheduler(
                    self.client,
                    meter_type=SAI_METER_TYPE_BYTES,
                    scheduling_type=SAI_SCHEDULING_TYPE_DWRR,
                    scheduling_weight=15)

        attr = sai_thrift_get_queue_attribute(
                self.client, self.queues4[1], parent_scheduler_node=True)
        self.assertNotEqual(attr['parent_scheduler_node'], 0)
        self.queues4_1_parent_sch_grp = attr["parent_scheduler_node"]
        status = sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues4_1_parent_sch_grp, scheduler_profile_id=self.sched4)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        attr = sai_thrift_get_queue_attribute(
                self.client, self.queues4[2], parent_scheduler_node=True)
        self.assertNotEqual(attr['parent_scheduler_node'], 0)
        self.queues4_2_parent_sch_grp = attr["parent_scheduler_node"]
        status = sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues4_2_parent_sch_grp, scheduler_profile_id=self.sched5)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        attr = sai_thrift_get_queue_attribute(
                self.client, self.queues4[3], parent_scheduler_node=True)
        self.assertNotEqual(attr['parent_scheduler_node'], 0)
        self.queues4_3_parent_sch_grp = attr["parent_scheduler_node"]
        status = sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues4_3_parent_sch_grp, scheduler_profile_id=self.sched6)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        attr_list = sai_thrift_get_switch_attribute(
        self.client, ecmp_hash=True, lag_hash=True)
        self.lag_hash_id = attr_list['SAI_SWITCH_ATTR_LAG_HASH']
        self.ecmp_hash_id = attr_list['SAI_SWITCH_ATTR_ECMP_HASH']
        self.assertNotEqual(self.lag_hash_id, 0)

        field_list = [SAI_NATIVE_HASH_FIELD_DST_IP,SAI_NATIVE_HASH_FIELD_SRC_IP,SAI_NATIVE_HASH_FIELD_SRC_MAC]

        hash_attr_list = sai_thrift_s32_list_t(
            count=len(field_list),
            int32list=field_list)
        status = sai_thrift_set_hash_attribute(
            self.client,
            self.lag_hash_id,
            native_hash_field_list=hash_attr_list)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        #self.ecmp_hash_id = 0x1C
        field_list = [SAI_NATIVE_HASH_FIELD_DST_IP,SAI_NATIVE_HASH_FIELD_SRC_IP,SAI_NATIVE_HASH_FIELD_SRC_MAC]
        hash_attr_list = sai_thrift_s32_list_t(
            count=len(field_list),
            int32list=field_list)
        status = sai_thrift_set_hash_attribute(
            self.client,
            self.ecmp_hash_id,
            native_hash_field_list=hash_attr_list)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        # lists of default objects
        self.def_bridge_port_list = []
        self.def_lag_list = []
        self.def_lag_member_list = []
        self.def_vlan_list = []
        self.def_vlan_member_list = []
        self.def_rif_list = []

        # create bridge ports
        self.create_bridge_ports(ports=[0, 1, 2, 3, 4, 5, 6, 20, 21])

        #self.create_lag_with_members(1, ports=[4, 5, 6])
        self.create_lag_with_members(2, ports=[7, 8, 9])

        # L3 lags
        self.create_lag_with_members(3, ports=[14, 15, 16])
        self.create_lag_with_members(4, ports=[17, 18, 19])
        self.create_lag_with_members(5, ports=[22, 23])

        # create vlan 10 with port0~port6
        self.create_vlan_with_members(10, {self.port0_bp: 'tagged',
                                           self.port1_bp: 'tagged',
                                           self.port2_bp: 'tagged',
                                           self.port3_bp: 'tagged',
                                           self.port4_bp: 'tagged',
                                           self.port5_bp: 'tagged',
                                           self.port6_bp: 'tagged',
                                           self.port20_bp: 'tagged',
                                           self.port21_bp: 'tagged'})

        # create vlan 20 with port2, port3 and lag2
        self.create_vlan_with_members(20, {self.port2_bp: 'untagged',
                                           self.port3_bp: 'tagged',
                                           self.lag2_bp: 'tagged'})

        # create vlan 30 with port20, port21 and lag5
        self.create_vlan_with_members(30, {self.port20_bp: 'untagged',
                                           self.port21_bp: 'untagged',
                                           self.lag5_bp: 'tagged'})

        # setup untagged ports
        status = sai_thrift_set_port_attribute(self.client, self.port0, port_vlan_id=10, mtu=9000)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_port_attribute(self.client, self.port1, port_vlan_id=10, mtu=9000)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_port_attribute(self.client, self.port2, port_vlan_id=10, mtu=9000)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_port_attribute(self.client, self.port3, port_vlan_id=10, mtu=9000)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_port_attribute(self.client, self.port4, port_vlan_id=10, mtu=9000)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_port_attribute(self.client, self.port5, port_vlan_id=10, mtu=9000)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_port_attribute(self.client, self.port6, port_vlan_id=10, mtu=9000)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_port_attribute(self.client, self.port20, port_vlan_id=30, mtu=9000)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_port_attribute(self.client, self.port21, port_vlan_id=30, mtu=9000)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        self.fdb_entry1 = sai_thrift_fdb_entry_t(
            switch_id=self.switch_id,
            mac_address="00:01:02:03:04:01",
            bv_id=self.vlan10)

        self.fdb_entry2 = sai_thrift_fdb_entry_t(
            switch_id=self.switch_id,
            mac_address="00:01:02:03:04:02",
            bv_id=self.vlan10)

        self.fdb_entry3 = sai_thrift_fdb_entry_t(
            switch_id=self.switch_id,
            mac_address="00:01:02:03:04:03",
            bv_id=self.vlan10)

        self.fdb_entry4 = sai_thrift_fdb_entry_t(
            switch_id=self.switch_id,
            mac_address="00:01:02:03:04:04",
            bv_id=self.vlan10)

        self.fdb_entry5 = sai_thrift_fdb_entry_t(
            switch_id=self.switch_id,
            mac_address="00:01:02:03:04:05",
            bv_id=self.vlan10)

        self.fdb_entry6 = sai_thrift_fdb_entry_t(
            switch_id=self.switch_id,
            mac_address="00:01:02:03:04:06",
            bv_id=self.vlan10)

        self.fdb_entry_cpu = sai_thrift_fdb_entry_t(
            switch_id=self.switch_id,
            mac_address="00:01:02:03:04:aa",
            bv_id=self.vlan10)

        sai_thrift_create_fdb_entry(self.client,
                                    self.fdb_entry1,
                                    type=SAI_FDB_ENTRY_TYPE_STATIC,
                                    bridge_port_id=self.port1_bp)

        sai_thrift_create_fdb_entry(self.client,
                                    self.fdb_entry2,
                                    type=SAI_FDB_ENTRY_TYPE_STATIC,
                                    bridge_port_id=self.port2_bp)

        sai_thrift_create_fdb_entry(self.client,
                                    self.fdb_entry3,
                                    type=SAI_FDB_ENTRY_TYPE_STATIC,
                                    bridge_port_id=self.port3_bp)

        sai_thrift_create_fdb_entry(self.client,
                                    self.fdb_entry4,
                                    type=SAI_FDB_ENTRY_TYPE_STATIC,
                                    bridge_port_id=self.port4_bp)

        sai_thrift_create_fdb_entry(self.client,
                                    self.fdb_entry5,
                                    type=SAI_FDB_ENTRY_TYPE_STATIC,
                                    bridge_port_id=self.port5_bp)

        sai_thrift_create_fdb_entry(self.client,
                                    self.fdb_entry6,
                                    type=SAI_FDB_ENTRY_TYPE_STATIC,
                                    bridge_port_id=self.port6_bp)

        # create L3 configuration
        self.create_routing_interfaces(vlans=[30])
        self.create_routing_interfaces(lags=[3, 4])
        self.create_routing_interfaces(ports=[10, 11, 12, 13])

        # # Create default route for default VRF is mandartory.
        # # Issue #1606(https://github.com/opencomputeproject/SAI/issues/1606)
        # # Creating route in default VRF will failed if there aren't default routes.
        # # Solution
        # # Create default route before create route in detaul VRF
        self.create_default_v4_v6_route_entry()

        wait_sec = 2
        print("Waiting for switch to get ready before test, {} seconds ...".format(
            wait_sec))
        time.sleep(wait_sec)

    def tearDown(self):
        self.destroy_default_v4_v6_route_entry()
        sai_thrift_set_port_attribute(self.client, self.port1, priority_flow_control_rx=0)
        sai_thrift_set_port_attribute(self.client, self.port1, priority_flow_control_tx=0)
        sai_thrift_set_port_attribute(self.client, self.port2, priority_flow_control_rx=0)
        sai_thrift_set_port_attribute(self.client, self.port2, priority_flow_control_tx=0)
        sai_thrift_set_port_attribute(self.client, self.port6, priority_flow_control_rx=0)

        for port in self.port_list:
            status = sai_thrift_set_port_attribute(self.client,port,qos_dscp_to_tc_map=0)
            status = sai_thrift_set_port_attribute(self.client,port,qos_tc_to_priority_group_map=0)
            status = sai_thrift_set_port_attribute(self.client,port,qos_tc_to_queue_map=0)

        sai_thrift_remove_qos_map(self.client, self.qos_dscp_to_tc_map_id)
        sai_thrift_remove_qos_map(self.client, self.qos_tc_to_pg_map_id)
        sai_thrift_remove_qos_map(self.client, self.qos_tc_to_queue_map_id)

        sai_thrift_set_ingress_priority_group_attribute(
                self.client, self.ipg_idx1[1], buffer_profile=0)
        sai_thrift_set_ingress_priority_group_attribute(
                self.client, self.ipg_idx1[2], buffer_profile=0)
        sai_thrift_set_ingress_priority_group_attribute(
                self.client, self.ipg_idx1[3], buffer_profile=0)
        sai_thrift_set_ingress_priority_group_attribute(
                self.client, self.ipg_idx2[1], buffer_profile=0)
        sai_thrift_set_ingress_priority_group_attribute(
                self.client, self.ipg_idx2[2], buffer_profile=0)
        sai_thrift_set_ingress_priority_group_attribute(
                self.client, self.ipg_idx2[3], buffer_profile=0)
        sai_thrift_set_queue_attribute(
                    self.client, self.queues1[1], buffer_profile_id=0)
        sai_thrift_set_queue_attribute(
                    self.client, self.queues1[2], buffer_profile_id=0)
        sai_thrift_set_queue_attribute(
                    self.client, self.queues1[3], buffer_profile_id=0)
        sai_thrift_set_queue_attribute(
                    self.client, self.queues2[1], buffer_profile_id=0)
        sai_thrift_set_queue_attribute(
                    self.client, self.queues2[2], buffer_profile_id=0)
        sai_thrift_set_queue_attribute(
                    self.client, self.queues2[3], buffer_profile_id=0)

        sai_thrift_remove_buffer_profile(self.client, self.buffer_profile_pg1)
        sai_thrift_remove_buffer_profile(self.client, self.buffer_profile_pg2)
        sai_thrift_remove_buffer_profile(self.client, self.buffer_profile_pg3)
        sai_thrift_remove_buffer_profile(self.client, self.buffer_profile_q1)
        sai_thrift_remove_buffer_profile(self.client, self.buffer_profile_q2)
        sai_thrift_remove_buffer_profile(self.client, self.buffer_profile_q3)
        sai_thrift_set_queue_attribute(
                    self.client, self.queues1[1], wred_profile_id=0)
        sai_thrift_set_queue_attribute(
                    self.client, self.queues1[2], wred_profile_id=0)
        sai_thrift_set_queue_attribute(
                    self.client, self.queues1[3], wred_profile_id=0)
        sai_thrift_set_queue_attribute(
                    self.client, self.queues2[2], wred_profile_id=0)
        sai_thrift_set_queue_attribute(
                    self.client, self.queues2[3], wred_profile_id=0)
        sai_thrift_set_queue_attribute(
                    self.client, self.queues2[1], wred_profile_id=0)
        sai_thrift_remove_wred(self.client,self.wred1)
        sai_thrift_remove_wred(self.client,self.wred2)
        sai_thrift_remove_wred(self.client,self.wred3)

        sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues2_3_parent_sch_grp, scheduler_profile_id=0)
        sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues2_2_parent_sch_grp, scheduler_profile_id=0)
        sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues2_1_parent_sch_grp, scheduler_profile_id=0)
        sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues1_3_parent_sch_grp, scheduler_profile_id=0)
        sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues1_2_parent_sch_grp, scheduler_profile_id=0)
        sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues1_1_parent_sch_grp, scheduler_profile_id=0)
        sai_thrift_remove_scheduler(self.client, self.sched3)
        sai_thrift_remove_scheduler(self.client, self.sched2)
        sai_thrift_remove_scheduler(self.client, self.sched1)
        sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues4_3_parent_sch_grp, scheduler_profile_id=0)
        sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues4_2_parent_sch_grp, scheduler_profile_id=0)
        sai_thrift_set_scheduler_group_attribute(
                self.client, self.queues4_1_parent_sch_grp, scheduler_profile_id=0)
        sai_thrift_remove_scheduler(self.client, self.sched6)
        sai_thrift_remove_scheduler(self.client, self.sched5)
        sai_thrift_remove_scheduler(self.client, self.sched4)
        sai_thrift_remove_fdb_entry(self.client,self.fdb_entry6)
        sai_thrift_remove_fdb_entry(self.client,self.fdb_entry5)
        sai_thrift_remove_fdb_entry(self.client,self.fdb_entry4)
        sai_thrift_remove_fdb_entry(self.client,self.fdb_entry3)
        sai_thrift_remove_fdb_entry(self.client,self.fdb_entry2)
        sai_thrift_remove_fdb_entry(self.client,self.fdb_entry1)
        self.destroy_vlans_with_members()
        self.destroy_bridge_ports()
        self.destroy_lags_with_members()
        self.destroy_routing_interfaces()
        sai_thrift_remove_buffer_pool(self.client, self.ingr_pool)
        sai_thrift_remove_buffer_pool(self.client, self.egr_pool)

        super(SaiHelperScaleTM, self).tearDown()

@group("draft")
class LossyAlphaTest(SaiHelperScaleTM):
    """
    Verify transitioning between different buffer profiles and modyfing buffer
    profile does not break forwarding for ingress priority group.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """

    def setUp(self):
        super(LossyAlphaTest, self).setUp()

        self.tx_cnt = 100000
        self.pkt_len = 9000
        self.pkt = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            pktlen=self.pkt_len - 4)  # account for 4B FCS

        self.pkt2 = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=3,
            pktlen=self.pkt_len - 4)

    def runTest(self):

        try:
            print("\n")
            print("Verify forwarding works with default buffer profile")
            print("Send {} pkts, pkt size: {} B".format(self.tx_cnt, self.pkt_len))
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port6, self.pkt)

            print("Verify traffic\n")
            stats_p = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.egr_pool)

            print("LossyAlphaTest egr pool SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES",
                stats_p["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"])

            stats_q = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[2])

            print("LossyAlphaTest queue 2 SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES",
                stats_q["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"])

            abs_value = abs(float(self.buf_size)*(2**self.alpha1)/(1+2**self.alpha1)-stats_q["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"])
            print("abs_value is {} should less than {}:".format(abs_value, float(self.buf_size)*(2**self.alpha1)/(1+2**self.alpha1)*0.05))

            self.assertLessEqual(abs_value, float(self.buf_size)*(2**self.alpha1)/(1+2**self.alpha1)*0.05)

            #queue stats equal pool stats
            self.assertEqual(stats_q["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"], stats_p["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"])

            time.sleep(60)

            stats_p2 = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.egr_pool)

            print("SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES ",
                stats_p2["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"])

            self.assertEqual(stats_p2["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)

            stats_q2 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[2])

            print("SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES ",
                stats_q2["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"])

            self.assertEqual(stats_q2["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"], 0)

            #queue watermark stats equeal pool watermark stats. note
            # self.assertEqual(stats_q2["SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES"], stats_p2["SAI_BUFFER_POOL_STAT_WATERMARK_BYTES"])

            #clear queue stats
            sai_thrift_clear_queue_stats(self.client, self.queues2[2])
            sai_thrift_clear_buffer_pool_stats(self.client, self.egr_pool)

            #double check queue and pool stats, should equeal zero
            stats_q2 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[2])
            stats_p2 = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.egr_pool)
            self.assertEqual(stats_q2["SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES"],0)
            self.assertEqual(stats_p2["SAI_BUFFER_POOL_STAT_WATERMARK_BYTES"],0)


            print("-------------------- Queue 3 Test -------------------")
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port6, self.pkt2)

            print("Verify traffic\n")
            stats_p3 = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.egr_pool)

            print("LossyAlphaTest egr pool SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES",
                stats_p3["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"])

            stats_q3 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[3])

            print("LossyAlphaTest queue 3 SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES",
                stats_q3["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"])

            abs_value = abs(float(self.buf_size)*(2**self.alpha2)/(1+2**self.alpha2)-stats_q3["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"])
            print("abs_value is {} should less than {}:".format(abs_value, float(self.buf_size)*(2**self.alpha2)/(1+2**self.alpha2)*0.05))

            self.assertLessEqual(abs_value, float(self.buf_size)*(2**self.alpha2)/(1+2**self.alpha2)*0.05)

            #ctc note: dynamic flow env, queue stats maybe not equal to pool stats
            self.assertEqual(stats_q3["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"], stats_p3["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"])

            time.sleep(60)

            stats_p4 = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.egr_pool)

            print("SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES ",
                stats_p4["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"])

            self.assertEqual(stats_p4["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)

            stats_q4 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[3])

            print("SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES ",
                stats_q4["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"])

            self.assertEqual(stats_q4["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"], 0)

            #queue watermark stats equeal pool watermark stats. note
            # self.assertEqual(stats_q4["SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES"], stats_p4["SAI_BUFFER_POOL_STAT_WATERMARK_BYTES"])

            #clear queue stats
            sai_thrift_clear_queue_stats(self.client, self.queues2[3])
            sai_thrift_clear_buffer_pool_stats(self.client, self.egr_pool)

            #double check queue and pool stats, should equeal zero
            stats_q5 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[2])
            stats_p5 = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.egr_pool)
            self.assertEqual(stats_q5["SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES"],0)
            self.assertEqual(stats_p5["SAI_BUFFER_POOL_STAT_WATERMARK_BYTES"],0)

        finally:
            sai_thrift_clear_queue_stats(self.client, self.queues2[2])
            sai_thrift_clear_queue_stats(self.client, self.queues2[3])

    def tearDown(self):

        super(LossyAlphaTest, self).tearDown()

@group("draft")
class LossyEcnTest(SaiHelperScaleTM):
    """
    Verify the occurrence of congestion in network traffic,
    the concatenated packets can be marked.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """

    def setUp(self):
        super(LossyEcnTest, self).setUp()

        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues1[1], wred_profile_id=self.wred1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues1[2], wred_profile_id=self.wred2)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues1[3], wred_profile_id=self.wred3)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues2[1], wred_profile_id=self.wred1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues2[2], wred_profile_id=self.wred2)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues2[3], wred_profile_id=self.wred3)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        self.tx_cnt = 100000
        self.pkt_len = 4096
        self.pkt_ect1 = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            ip_ecn=1,
            pktlen=self.pkt_len - 4)  # account for 4B FCS

        self.pkt_ect2 = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            ip_ecn=2,
            pktlen=self.pkt_len - 4)

        self.pkt_ect0 = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            ip_ecn=0,
            pktlen=self.pkt_len - 4)

        self.pkt_p6_ect1 = simple_udp_packet(
            eth_dst='00:01:02:03:04:06',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            ip_ecn=1,
            pktlen=self.pkt_len - 4)

        self.pkt_p6_ect2 = simple_udp_packet(
            eth_dst='00:01:02:03:04:06',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            ip_ecn=1,
            pktlen=self.pkt_len - 4)

        self.pkt_p6_ect3 = simple_udp_packet(
            eth_dst='00:01:02:03:04:06',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            ip_ecn=3,
            pktlen=self.pkt_len - 4)

        self.rev_pkt = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            ip_ecn=3,
            pktlen=self.pkt_len - 4)


    def runTest(self):
        print("\n")
        print("Verify forwarding works with default buffer profile")

        try:
            print("----------------- send pkt ect1 ---------------------")
            print("Send {} pkts, pkt size: {} B".format(self.tx_cnt, self.pkt_len))
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port6, self.pkt_ect1)

            print("Verify traffic\n")
            stats_q = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[2])

            print("port 2 queue 2 SAI_QUEUE_STAT_PACKETS is {} should more than 0".format(stats_q["SAI_QUEUE_STAT_PACKETS"]))
            self.assertGreater(stats_q["SAI_QUEUE_STAT_PACKETS"], 0)
            print("port 2 queue 2 SAI_QUEUE_STAT_DROPPED_PACKETS is {} should more than 0".format(stats_q["SAI_QUEUE_STAT_DROPPED_PACKETS"]))
            self.assertGreater(stats_q["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)
            print("port 2 queue 2 SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS is {} should more than 0".format(stats_q["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"]))
            self.assertGreater(stats_q["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"], 0)

            verify_packet(self, self.rev_pkt, self.dev_port2)
            time.sleep(60)
            stats_p = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)

            self.assertEqual(stats_p["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)

            sai_thrift_clear_queue_stats(self.client, self.queues2[2])

            print("----------------- send pkt ect2 ---------------------")

            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port6, self.pkt_ect2)

            print("Verify traffic\n")

            stats_q1 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[2])

            print("port 2 queue 2 SAI_QUEUE_STAT_PACKETS is {} should more than 0".format(stats_q1["SAI_QUEUE_STAT_PACKETS"]))
            self.assertGreater(stats_q1["SAI_QUEUE_STAT_PACKETS"], 0)
            print("port 2 queue 2 SAI_QUEUE_STAT_DROPPED_PACKETS is {} should more than 0".format(stats_q1["SAI_QUEUE_STAT_DROPPED_PACKETS"]))
            self.assertGreater(stats_q1["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)
            print("port 2 queue 2 SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS is {} should more than 0".format(stats_q1["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"]))
            self.assertGreater(stats_q1["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"], 0)

            verify_packet(self, self.rev_pkt, self.dev_port2)
            time.sleep(60)

            stats_p = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)

            self.assertEqual(stats_p["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)
            sai_thrift_clear_queue_stats(self.client, self.queues2[2])

            print("----------------- send pkt ect0 ---------------------")

            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port6, self.pkt_ect0)

            print("Verify traffic\n")

            stats_q2 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[2])

            print("port 2 queue 2 SAI_QUEUE_STAT_PACKETS is {} should more than 0".format(stats_q2["SAI_QUEUE_STAT_PACKETS"]))
            self.assertGreater(stats_q2["SAI_QUEUE_STAT_PACKETS"], 0)
            print("port 2 queue 2 SAI_QUEUE_STAT_DROPPED_PACKETS is {} should more than 0".format(stats_q2["SAI_QUEUE_STAT_DROPPED_PACKETS"]))
            self.assertGreater(stats_q2["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)
            print("port 2 queue 2 SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS is {} should equal 0".format(stats_q2["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"]))
            self.assertEqual(stats_q2["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"], 0)
            #check rev pkt ecn = 0
            verify_packet(self, self.pkt_ect0, self.dev_port2)
            time.sleep(60)

            stats_p = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)

            self.assertEqual(stats_p["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)
            sai_thrift_clear_queue_stats(self.client, self.queues2[2])

            print("----------------- send p6_pkt ect1 ---------------------")

            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port1, self.pkt_p6_ect1)

            print("Verify traffic\n")

            stats_q3 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues6[2])

            print("port 6 queue 2 SAI_QUEUE_STAT_PACKETS is {} should equal to packet tx cnt {}".format(stats_q3["SAI_QUEUE_STAT_PACKETS"],self.tx_cnt))
            self.assertEqual(stats_q3["SAI_QUEUE_STAT_PACKETS"], self.tx_cnt)
            print("port 6 queue 2 SAI_QUEUE_STAT_DROPPED_PACKETS is {} should equal to 0".format(stats_q3["SAI_QUEUE_STAT_DROPPED_PACKETS"]))
            self.assertEqual(stats_q3["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)
            print("port 6 queue 2 SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS is {} should equal to 0".format(stats_q3["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"]))
            self.assertEqual(stats_q3["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"], 0)

            verify_packet(self, self.pkt_p6_ect1, self.dev_port6)

            stats_p = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)

            self.assertEqual(stats_p["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)
            sai_thrift_clear_queue_stats(self.client, self.queues6[2])

            print("----------------- send p6_pkt ect2 ---------------------")
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port1, self.pkt_p6_ect2)

            print("Verify traffic\n")

            stats_q4 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues6[2])

            print("port 6 queue 2 SAI_QUEUE_STAT_PACKETS is {} should equal to packet tx cnt {}".format(stats_q4["SAI_QUEUE_STAT_PACKETS"],self.tx_cnt))
            self.assertEqual(stats_q4["SAI_QUEUE_STAT_PACKETS"], self.tx_cnt)
            print("port 6 queue 2 SAI_QUEUE_STAT_DROPPED_PACKETS is {} equal to 0".format(stats_q4["SAI_QUEUE_STAT_DROPPED_PACKETS"]))
            self.assertEqual(stats_q4["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)
            print("port 6 queue 2 SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS is {} equal to 0".format(stats_q4["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"]))
            self.assertEqual(stats_q4["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"], 0)

            verify_packet(self, self.pkt_p6_ect2, self.dev_port6)

            stats_p = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)

            self.assertEqual(stats_p["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)
            sai_thrift_clear_queue_stats(self.client, self.queues6[2])

            print("----------------- send p6_pkt ect3 ---------------------")
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port1, self.pkt_p6_ect3)

            print("Verify traffic\n")

            stats_q5 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues6[2])

            print("port 6 queue 2 SAI_QUEUE_STAT_PACKETS is {} should equal to packet tx cnt {}".format(stats_q5["SAI_QUEUE_STAT_PACKETS"],self.tx_cnt))
            self.assertEqual(stats_q5["SAI_QUEUE_STAT_PACKETS"], self.tx_cnt)

            print("port 6 queue 2 SAI_QUEUE_STAT_DROPPED_PACKETS is {} equal to 0".format(stats_q5["SAI_QUEUE_STAT_DROPPED_PACKETS"]))
            self.assertEqual(stats_q5["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)

            print("port 6 queue 2 SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS is {} equal to 0".format(stats_q5["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"]))
            self.assertEqual(stats_q5["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"], 0)

            verify_packet(self, self.pkt_p6_ect3, self.dev_port6)

            stats_p = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)

            self.assertEqual(stats_p["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)
            sai_thrift_clear_queue_stats(self.client, self.queues6[2])

        finally:
            sai_thrift_set_queue_attribute(self.client, self.queues2[2], wred_profile_id=0)

    def tearDown(self):

        sai_thrift_set_queue_attribute(self.client, self.queues1[1], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues1[2], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues1[3], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues2[1], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues2[2], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues2[3], wred_profile_id=0)
        super(LossyEcnTest, self).tearDown()

@group("draft")
class LossyWredTest(SaiHelperScaleTM):
    """
    Verify the occurrence of congestion in network traffic,
    the drop probability follows the WRED profile.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """

    def setUp(self):
        super(LossyWredTest, self).setUp()

        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues1[1], wred_profile_id=self.wred1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues1[2], wred_profile_id=self.wred2)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues1[3], wred_profile_id=self.wred3)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues2[1], wred_profile_id=self.wred1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues2[2], wred_profile_id=self.wred2)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues2[3], wred_profile_id=self.wred3)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        self.tx_cnt = 100000
        self.pkt_len = 9000
        self.pkt_pcp2 = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            pktlen=self.pkt_len - 4)

        self.pkt_pcp3 = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=3,
            pktlen=self.pkt_len - 4)


    def runTest(self):
        print("\n")
        print("Verify forwarding works with default buffer profile")

        try:
            print("Send pkt from {} to {} , ip_dscp = 2".format(self.dev_port3, self.dev_port2))
            print("Send {} pkts, pkt size: {} B".format(self.tx_cnt, self.pkt_len))
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port3, self.pkt_pcp2)

            print("Verify traffic\n")

            stats_p = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[2])

            print("port 2 queue 2 SAI_QUEUE_STAT_PACKETS",
                stats_p["SAI_QUEUE_STAT_PACKETS"])
            self.assertGreater(stats_p["SAI_QUEUE_STAT_PACKETS"], 0)

            print("port 2 queue 2 SAI_QUEUE_STAT_DROPPED_PACKETS",
                stats_p["SAI_QUEUE_STAT_DROPPED_PACKETS"])
            self.assertGreater(stats_p["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)

            print("port 2 queue 2 SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES should between 3800000 and 4200000")
            self.assertGreaterEqual(stats_p["SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES"], 4000000*0.95)
            self.assertLessEqual(stats_p["SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES"], 4000000*1.05)

            print("Send pkt from {} to {} , ip_dscp = 3".format(self.dev_port3, self.dev_port2))
            print("Send {} pkts, pkt size: {} B".format(self.tx_cnt, self.pkt_len))
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port3, self.pkt_pcp3)

            print("Verify traffic\n")

            stats_p2 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[3])

            print("port 2 queue 3 SAI_QUEUE_STAT_PACKETS",
                stats_p2["SAI_QUEUE_STAT_PACKETS"])
            self.assertGreater(stats_p2["SAI_QUEUE_STAT_PACKETS"], 0)

            print("port 2 queue 3 SAI_QUEUE_STAT_DROPPED_PACKETS",
                stats_p2["SAI_QUEUE_STAT_DROPPED_PACKETS"])
            self.assertGreater(stats_p2["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)

            print("port 2 queue 3 SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES should between 2850000 and 3150000")
            self.assertGreaterEqual(stats_p2["SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES"], 3000000*0.95)
            self.assertLessEqual(stats_p2["SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES"], 3000000*1.05)

        finally:

            sai_thrift_clear_queue_stats(self.client, self.queues2[2])
            sai_thrift_clear_queue_stats(self.client, self.queues2[3])

    def tearDown(self):
        sai_thrift_set_queue_attribute(self.client, self.queues1[1], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues1[2], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues1[3], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues2[1], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues2[2], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues2[3], wred_profile_id=0)
        super(LossyWredTest, self).tearDown()

@group("draft")
class LossyMinGarenteeTest(SaiHelperScaleTM):
    """
    Verify transitioning between different buffer profiles and modyfing buffer
    profile does not break forwarding for ingress priority group.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """

    def setUp(self):
        super(LossyMinGarenteeTest, self).setUp()

        self.tx_cnt = 10
        self.pkt_len = 9000

        self.pkt_p5_l = simple_udp_packet(
            eth_dst='00:01:02:03:04:05', dl_vlan_enable=True, vlan_vid=10, ip_dscp=2, ip_ecn=1,
            pktlen=self.pkt_len - 4)

        self.pkt_p6_l = simple_udp_packet(
            eth_dst='00:01:02:03:04:06', dl_vlan_enable=True, vlan_vid=10, ip_dscp=2, ip_ecn=1,
            pktlen=self.pkt_len - 4)


    def runTest(self):
        print("\n")
        print("Verify forwarding works with default buffer profile")

        try:
            sai_thrift_clear_queue_stats(self.client, self.queues5[2])
            sai_thrift_clear_ingress_priority_group_stats(self.client, self.ipg_idx6[2])
            buffer_profile_pg4 = sai_thrift_create_buffer_profile(
                self.client, pool_id=self.ingr_pool,
                reserved_buffer_size=20480,
                shared_static_th=0,
                threshold_mode=SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC)
            self.assertGreater(buffer_profile_pg4, 0)

            #ctc note: port speed is 10Gb, default port-min is 80 * 256
            buffer_profile_q4 = sai_thrift_create_buffer_profile(
                self.client, pool_id=self.egr_pool,
                reserved_buffer_size=20480,
                shared_static_th=0,
                threshold_mode=SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC)
            self.assertGreater(buffer_profile_q4, 0)

            status = sai_thrift_set_ingress_priority_group_attribute(
                self.client, self.ipg_idx6[2], buffer_profile=buffer_profile_pg4)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            status = sai_thrift_set_queue_attribute(
                        self.client, self.queues6[2], buffer_profile_id=buffer_profile_q4)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            sched4 = sai_thrift_create_scheduler(
                        self.client,
                        meter_type=SAI_METER_TYPE_BYTES,
                        min_bandwidth_rate=0,
                        max_bandwidth_rate=0)

            attr = sai_thrift_get_queue_attribute(
                    self.client, self.queues6[2], parent_scheduler_node=True)
            self.assertNotEqual(attr['parent_scheduler_node'], 0)

            self.queues6_2_parent_sch_grp = attr["parent_scheduler_node"]
            status = sai_thrift_set_scheduler_group_attribute(
                    self.client, self.queues6_2_parent_sch_grp, scheduler_profile_id=sched4)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_queue_attribute(
                    self.client, self.queues5[2], parent_scheduler_node=True)
            self.assertNotEqual(attr['parent_scheduler_node'], 0)

            self.queues5_2_parent_sch_grp = attr["parent_scheduler_node"]
            status = sai_thrift_set_scheduler_group_attribute(
                    self.client, self.queues5_2_parent_sch_grp, scheduler_profile_id=sched4)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            print("Send {} pkts, pkt size: {} B test egress queue-min".format(self.tx_cnt, self.pkt_len))
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port5, self.pkt_p6_l)

            print("Verify traffic\n")
            stats_q6 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues6[2])

            print("SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES",
                stats_q6["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"])
            self.assertGreater(stats_q6["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"], 0)

            print("SAI_QUEUE_STAT_DROPPED_PACKETS",
                stats_q6["SAI_QUEUE_STAT_DROPPED_PACKETS"])
            #check four pkts in queue. one for shaping. three for dequeue
            self.assertEqual(stats_q6["SAI_QUEUE_STAT_DROPPED_PACKETS"], self.tx_cnt-4)

            #cancel shaping, let four pkts out of queue
            sai_thrift_set_scheduler_group_attribute(self.client, self.queues6_2_parent_sch_grp, scheduler_profile_id=0)

            stats_q6_post = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues6[2])
            self.assertEqual(stats_q6_post["SAI_QUEUE_STAT_PACKETS"], 4)

            sai_thrift_clear_queue_stats(self.client, self.queues6[2])

            print("Send {} pkts, pkt size: {} B test ingress pg-min".format(self.tx_cnt, self.pkt_len))
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port6, self.pkt_p5_l)

            print("Verify traffic\n")

            stats_pg = query_counter(
                            self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx6[2])

            print("SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS",
                stats_pg["SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS"])

            print("SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS",
                stats_pg["SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS"])

            self.assertEqual(stats_pg["SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS"], 4)
            sai_thrift_clear_ingress_priority_group_stats(self.client, self.ipg_idx6[2])

            #cancel shaping, let four pkts out of queue
            sai_thrift_set_scheduler_group_attribute(self.client, self.queues5_2_parent_sch_grp, scheduler_profile_id=0)

            stats_q5_post = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues5[2])
            self.assertEqual(stats_q5_post["SAI_QUEUE_STAT_PACKETS"], 4)

        finally:
            sai_thrift_clear_queue_stats(self.client, self.queues6[2])
            sai_thrift_clear_queue_stats(self.client, self.queues5[2])
            sai_thrift_clear_ingress_priority_group_stats(self.client, self.ipg_idx6[2])
            sai_thrift_remove_buffer_profile(self.client, buffer_profile_pg4)
            sai_thrift_remove_buffer_profile(self.client, buffer_profile_q4)
            sai_thrift_set_ingress_priority_group_attribute(self.client, self.ipg_idx6[2], buffer_profile=0)
            sai_thrift_set_queue_attribute(self.client, self.queues6[2], buffer_profile_id=0)
            sai_thrift_remove_scheduler(self.client,sched4)
            sai_thrift_set_scheduler_group_attribute(self.client, self.queues6_2_parent_sch_grp, scheduler_profile_id=0)
            sai_thrift_set_scheduler_group_attribute(self.client, self.queues5_2_parent_sch_grp, scheduler_profile_id=0)

    def tearDown(self):

        super(LossyMinGarenteeTest, self).tearDown()

@group("draft")
class LossyCPUTest(SaiHelperScaleTM):
    """
    Verify network traffic congestion, it does not affect the messages to the CPU.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """
    def setUp(self):
        super(LossyCPUTest, self).setUp()

        self.tx_cnt = 50000
        self.pkt_len = 9000
        self.pkt = simple_udp_packet(
            eth_dst='00:01:02:03:04:05',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            pktlen=self.pkt_len - 4)

    def runTest(self):

        print("\n")
        print("Verify forwarding works with default buffer profile")

        try:
            lldp_mac = "01:80:c2:00:00:0e"
            lldp_pkt = simple_eth_packet(eth_dst=lldp_mac,
                                            pktlen=self.pkt_len - 4,
                                            eth_type=0x88cc)

            sched = sai_thrift_create_scheduler(
                        self.client,
                        meter_type=SAI_METER_TYPE_BYTES,
                        min_bandwidth_rate=0,
                        max_bandwidth_rate=0)

            attr = sai_thrift_get_queue_attribute(
                    self.client, self.queues5[2], parent_scheduler_node=True)
            self.assertNotEqual(attr['parent_scheduler_node'], 0)

            self.queues5_2_parent_sch_grp = attr["parent_scheduler_node"]
            status = sai_thrift_set_scheduler_group_attribute(
                    self.client, self.queues5_2_parent_sch_grp, scheduler_profile_id=sched)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            status = sai_thrift_set_queue_attribute(
                        self.client, self.queues5[2], buffer_profile_id=self.buffer_profile_q2)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            test_trap = sai_thrift_create_hostif_trap(
                self.client,
                packet_action=SAI_PACKET_ACTION_TRAP,
                trap_type=SAI_HOSTIF_TRAP_TYPE_LLDP)
            self.assertNotEqual(test_trap, 0)

            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port6, self.pkt)

            q_stats = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues5[2])
            #make sure queue drop stats more than zero
            self.assertGreater(q_stats["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)

            for _ in range(10):
                send_packet(self, self.dev_port6, lldp_pkt)

            post_stats = query_counter(self, sai_thrift_get_queue_stats, self.cpu_queue0)
            self.assertEqual(post_stats["SAI_QUEUE_STAT_PACKETS"], 10)
            self.assertEqual(post_stats["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)
            print("\tOK")

        finally:
            sai_thrift_clear_queue_stats(self.client, self.queues5[2])
            sai_thrift_clear_queue_stats(self.client, self.cpu_queue0)
            status = sai_thrift_set_scheduler_group_attribute(self.client, self.queues5_2_parent_sch_grp, scheduler_profile_id=0)
            sai_thrift_set_queue_attribute(self.client, self.queues5[2], buffer_profile_id=0)
            sai_thrift_remove_hostif_trap(self.client, test_trap)
            sai_thrift_remove_scheduler(self.client, sched)

    def tearDown(self):

        super(LossyCPUTest, self).tearDown()

@group("draft")
class LossyPfcRxTest(SaiHelperScaleTM):
    """
    Verify transitioning between different buffer profiles and modyfing buffer
    profile does not break forwarding for ingress priority group.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """
    def setUp(self):

        if get_platform() in ['ctc']:
            super().setUp(skip_reason = f"[ALI] SKIP test on [{get_platform()}], temporarily can not support pfc pkt transit in test environment")
        else:
            super(LossyPfcRxTest, self).setUp()

        self.tx_cnt = 100000
        self.pkt_len = 9000
        self.pkt_p6 = simple_udp_packet(
            eth_dst='00:01:02:03:04:06',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            ip_ecn=1,
            pktlen=self.pkt_len - 4)

        self.pkt_pfc = simple_eth_packet(
            eth_dst='01:80:c2:00:00:01',
            eth_src='00:01:02:03:04:05',
            eth_type=34824,
            pktlen=64,
            inner_frame='0101000400000000ffff000000000000000000000000000000000000000000000000000000000000000000000000'
            )

    def runTest(self):
        print("\n")
        print("Verify forwarding works with default buffer profile")

        for _ in range(self.tx_cnt):
            send_packet(self, self.dev_port6, self.pkt_pfc)
            send_packet(self, self.dev_port5, self.pkt_p6)

        print("Verify traffic\n")
        stats_q = query_counter(
                        self, sai_thrift_get_queue_stats, self.queues6[2])

        print("SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES",
            stats_q["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"])
        self.assertGreater(stats_q["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"], 0)

        print("SAI_QUEUE_STAT_DROPPED_PACKETS",
            stats_q["SAI_QUEUE_STAT_DROPPED_PACKETS"])
        self.assertGreater(stats_q["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)

    def tearDown(self):

        super(LossyPfcRxTest, self).tearDown()

@group("draft")
class LossySrcBalancingTest(SaiHelperScaleTM):
    """
    Verify transitioning between different buffer profiles and modyfing buffer
    profile does not break forwarding for ingress priority group.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """
    def setUp(self):

        if get_platform() in ['ctc']:
            super().setUp(skip_reason = f"[ALI] SKIP test on [{get_platform()}], temporarily can not support LossySrcBalancingTest")
        else:
            super(LossySrcBalancingTest, self).setUp()

        self.tx_cnt = 50000
        self.pkt_len = 9000
        self.pkt_p1 = simple_udp_packet(
            eth_dst='00:01:02:03:04:01',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            ip_ecn=1,
            pktlen=self.pkt_len - 4)

    def runTest(self):
        print("\n")
        print("Verify forwarding works with default buffer profile")
        try:
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port6, self.pkt_p1)
                send_packet(self, self.dev_port5, self.pkt_p1)
                send_packet(self, self.dev_port4, self.pkt_p1)
                send_packet(self, self.dev_port3, self.pkt_p1)
                send_packet(self, self.dev_port2, self.pkt_p1)
                send_packet(self, self.dev_port20, self.pkt_p1)
                send_packet(self, self.dev_port21, self.pkt_p1)

            print("Verify traffic\n")

            stats_q = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues1[2])

            print("SAI_QUEUE_STAT_DROPPED_PACKETS",
                stats_q["SAI_QUEUE_STAT_DROPPED_PACKETS"])
            self.assertGreater(stats_q["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)

            stats2 = query_counter(
                            self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx2[2])
            stats3 = query_counter(
                            self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx3[2])
            stats4 = query_counter(
                            self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx4[2])
            stats5 = query_counter(
                            self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx5[2])
            stats6 = query_counter(
                            self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx6[2])
            stats20 = query_counter(
                            self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx20[2])
            stats21 = query_counter(
                            self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx21[2])

            print("port 2 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES",
                stats2["SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES"])
            print("port 3 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES",
                stats3["SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES"])
            print("port 4 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES",
                stats4["SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES"])
            print("port 5 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES",
                stats5["SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES"])
            print("port 6 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES",
                stats6["SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES"])
            print("port 20 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES",
                stats20["SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES"])
            print("port 21 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES",
                stats21["SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES"])

            print("port 2 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES",
                stats2["SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES"])
            print("port 3 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES",
                stats3["SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES"])
            print("port 4 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES",
                stats4["SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES"])
            print("port 5 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES",
                stats5["SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES"])
            print("port 6 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES",
                stats6["SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES"])
            print("port 20 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES",
                stats20["SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES"])
            print("port 21 ingress pg2 SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES",
                stats21["SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES"])

        finally:
            sai_thrift_clear_queue_stats(self.client, self.queues1[2])
            sai_thrift_clear_ingress_priority_group_stats(self.client, self.ipg_idx2[2])
            sai_thrift_clear_ingress_priority_group_stats(self.client, self.ipg_idx3[2])
            sai_thrift_clear_ingress_priority_group_stats(self.client, self.ipg_idx4[2])
            sai_thrift_clear_ingress_priority_group_stats(self.client, self.ipg_idx5[2])
            sai_thrift_clear_ingress_priority_group_stats(self.client, self.ipg_idx6[2])
            sai_thrift_clear_ingress_priority_group_stats(self.client, self.ipg_idx20[2])
            sai_thrift_clear_ingress_priority_group_stats(self.client, self.ipg_idx21[2])

    def tearDown(self):

        super(LossySrcBalancingTest, self).tearDown()

@group("draft")
class LosslessAlphaTest(SaiHelperScaleTM):
    """
    Verify transitioning between different buffer profiles and modyfing buffer
    profile does not break forwarding for ingress priority group.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """

    def setUp(self):
        super(LosslessAlphaTest, self).setUp()

        self.tx_cnt = 100000
        self.pkt_len = 9000
        self.pkt = simple_udp_packet(
            eth_dst='00:01:02:03:04:01',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=1,
            pktlen=self.pkt_len - 4)  # account for 4B FCS

    def runTest(self):

        print("\n")
        print("Verify forwarding works with default buffer profile")

        try:
            sai_thrift_clear_buffer_pool_stats(self.client, self.ingr_pool)
            print("Send {} pkts, pkt size: {} B".format(self.tx_cnt, self.pkt_len))
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port2, self.pkt)
                if _ == 80000:
                    stats_q = query_counter(
                                    self, sai_thrift_get_queue_stats, self.queues1[1])
                    stats_pg = query_counter(
                                    self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx2[1])

            print("Verify traffic\n")

            print("port 1 queue 1 SAI_QUEUE_STAT_SHARED_CURR_OCCUPANCY_BYTES",
                    stats_q["SAI_QUEUE_STAT_SHARED_CURR_OCCUPANCY_BYTES"])
            print("port 2 ingress pg1 SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES",
                    stats_pg["SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES"])

            stats_pool = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)

            print("SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES ",
                stats_pool["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"])

            stats1 = stats_pool["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"]

            abs_value = abs(float(self.buf_size-self.headroom_size)*(2**self.alpha1)/(1+2**self.alpha1)-stats_pg["SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES"])
            print("abs_value is {} should less than {}:".format(abs_value, float(self.buf_size-self.headroom_size)*(2**self.alpha1)/(1+2**self.alpha1)*0.05))

            self.assertLessEqual(abs_value, float(self.buf_size-self.headroom_size)*(2**self.alpha1)/(1+2**self.alpha1)*0.05)

            stats_pg = query_counter(
                            self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx2[1])

            stats2 = stats_pg["SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES"]

            time.sleep(60)
            # check buffer stats equeal zero
            stats_pool = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)

            print("SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES ",
                stats_pool["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"])

            self.assertEqual(stats_pool["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)

            stats_pg2 = query_counter(
                            self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx2[1])

            print("SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES ",
                stats_pg2["SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES"])

            self.assertEqual(stats_pg2["SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES"], 0)
            self.assertEqual(stats_pool["SAI_BUFFER_POOL_STAT_WATERMARK_BYTES"], stats_pg2["SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES"])

        finally:
            sai_thrift_clear_ingress_priority_group_stats(self.client, self.ipg_idx2[1])
            sai_thrift_clear_queue_stats(self.client, self.queues1[1])

    def tearDown(self):

        super(LosslessAlphaTest, self).tearDown()

@group("draft")
class LosslessEcnTest(SaiHelperScaleTM):
    """
    Verify the occurrence of congestion in network traffic,
    the concatenated packets can be marked.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """

    def setUp(self):
        super(LosslessEcnTest, self).setUp()
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues1[1], wred_profile_id=self.wred1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues1[2], wred_profile_id=self.wred2)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues1[3], wred_profile_id=self.wred3)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues2[1], wred_profile_id=self.wred1)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues2[2], wred_profile_id=self.wred2)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_queue_attribute(
                    self.client, self.queues2[3], wred_profile_id=self.wred3)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        self.tx_cnt = 100000
        self.pkt_len = 4096
        self.pkt_ect1 = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=1,
            ip_ecn=1,
            pktlen=self.pkt_len - 4)  # account for 4B FCS

        self.pkt_ect2 = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=1,
            ip_ecn=2,
            pktlen=self.pkt_len - 4)

        self.pkt_ect0 = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=1,
            ip_ecn=0,
            pktlen=self.pkt_len - 4)

        self.pkt_ect3 = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=1,
            ip_ecn=3,
            pktlen=self.pkt_len - 4)

        self.pkt_p6 = simple_udp_packet(
            eth_dst='00:01:02:03:04:06',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=1,
            ip_ecn=1,
            pktlen=self.pkt_len - 4)

        self.rev_pkt = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=1,
            ip_ecn=3,
            pktlen=self.pkt_len - 4)


    def runTest(self):
        print("\n")
        print("Verify forwarding works with default buffer profile")

        try:
            print("Send {} pkts, pkt size: {} B".format(self.tx_cnt, self.pkt_len))
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port1, self.pkt_ect1)

            print("Verify traffic\n")

            stats_q = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[1])

            print("port 2 queue 1 SAI_QUEUE_STAT_PACKETS is {} should more than 0".format(stats_q["SAI_QUEUE_STAT_PACKETS"]))
            self.assertGreater(stats_q["SAI_QUEUE_STAT_PACKETS"], 0)

            print("port 2 queue 1 SAI_QUEUE_STAT_DROPPED_PACKETS is {} should more than 0".format(stats_q["SAI_QUEUE_STAT_DROPPED_PACKETS"]))
            self.assertGreater(stats_q["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)

            print("port 2 queue 1 SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS is {} should more than 0".format(stats_q["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"]))
            self.assertGreater(stats_q["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"], 0)

            verify_packet(self, self.rev_pkt, self.dev_port2)

            time.sleep(60)

            stats_p = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)

            self.assertEqual(stats_p["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)

            sai_thrift_clear_queue_stats(self.client, self.queues2[1])

            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port1, self.pkt_ect2)

            print("Verify traffic\n")

            stats_q2 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[1])

            print("port 2 queue 1 SAI_QUEUE_STAT_PACKETS is {} should more than 0".format(stats_q2["SAI_QUEUE_STAT_PACKETS"]))
            self.assertGreater(stats_q2["SAI_QUEUE_STAT_PACKETS"], 0)

            print("port 2 queue 1 SAI_QUEUE_STAT_DROPPED_PACKETS is {} should more than 0".format(stats_q2["SAI_QUEUE_STAT_DROPPED_PACKETS"]))
            self.assertGreater(stats_q2["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)

            print("port 2 queue 1 SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS is {} should more than 0".format(stats_q2["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"]))
            self.assertGreater(stats_q2["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"], 0)

            verify_packet(self, self.rev_pkt, self.dev_port2)

            time.sleep(60)

            stats_p2 = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)
            self.assertEqual(stats_p2["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)

            sai_thrift_clear_queue_stats(self.client, self.queues2[1])

            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port1, self.pkt_ect3)

            print("Verify traffic\n")

            stats_q3 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[1])

            print("port 2 queue 1 SAI_QUEUE_STAT_PACKETS is {} should more than 0".format(stats_q3["SAI_QUEUE_STAT_PACKETS"]))
            self.assertGreater(stats_q3["SAI_QUEUE_STAT_PACKETS"], 0)

            print("port 2 queue 1 SAI_QUEUE_STAT_DROPPED_PACKETS is {} should more than 0".format(stats_q3["SAI_QUEUE_STAT_DROPPED_PACKETS"]))
            self.assertGreater(stats_q3["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)

            print("port 2 queue 1 SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS is {} should equal 0".format(stats_q3["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"]))
            self.assertEqual(stats_q3["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"], 0)

            verify_packet(self, self.pkt_ect3, self.dev_port2)

            time.sleep(60)

            stats_p3 = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)
            self.assertEqual(stats_p3["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)

            sai_thrift_clear_queue_stats(self.client, self.queues2[1])

            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port1, self.pkt_ect0)

            print("Verify traffic\n")

            stats_q4 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues2[1])

            print("port 2 queue 1 SAI_QUEUE_STAT_PACKETS is {} should more than 0".format(stats_q4["SAI_QUEUE_STAT_PACKETS"]))
            self.assertGreater(stats_q4["SAI_QUEUE_STAT_PACKETS"], 0)

            print("port 2 queue 1 SAI_QUEUE_STAT_DROPPED_PACKETS is {} should more than 0".format(stats_q4["SAI_QUEUE_STAT_DROPPED_PACKETS"]))
            self.assertGreater(stats_q4["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)

            print("port 2 queue 1 SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS is {} should equal 0".format(stats_q4["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"]))
            self.assertEqual(stats_q4["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"], 0)

            verify_packet(self, self.pkt_ect0, self.dev_port2)

            time.sleep(60)

            stats_p4 = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)
            self.assertEqual(stats_p4["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)

            sai_thrift_clear_queue_stats(self.client, self.queues2[1])

            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port1, self.pkt_p6)

            print("Verify traffic\n")

            stats_q5 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues6[1])

            print("SAI_QUEUE_STAT_PACKETS",
                stats_q5["SAI_QUEUE_STAT_PACKETS"])
            self.assertEqual(stats_q5["SAI_QUEUE_STAT_PACKETS"], self.tx_cnt)

            print("SAI_QUEUE_STAT_DROPPED_PACKETS",
                stats_q5["SAI_QUEUE_STAT_DROPPED_PACKETS"])
            self.assertEqual(stats_q5["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)

            print("SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS",
                stats_q5["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"])
            self.assertEqual(stats_q5["SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"], 0)
            sai_thrift_clear_queue_stats(self.client, self.queues6[1])

            verify_packet(self, self.pkt_p6, self.dev_port6)

            stats_p5 = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)

            self.assertEqual(stats_p5["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)

        finally:
            sai_thrift_clear_queue_stats(self.client, self.queues6[1])

    def tearDown(self):
        sai_thrift_set_queue_attribute(self.client, self.queues1[1], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues1[2], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues1[3], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues2[1], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues2[2], wred_profile_id=0)
        sai_thrift_set_queue_attribute(self.client, self.queues2[3], wred_profile_id=0)
        super(LosslessEcnTest, self).tearDown()

@group("draft")
class LosslessCPUTest(SaiHelperScaleTM):
    """
    Verify network traffic congestion, it does not affect the messages to the CPU.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """
    def setUp(self):
        super(LosslessCPUTest, self).setUp()

        self.tx_cnt = 100000
        self.pkt_len = 9000
        self.pkt = simple_udp_packet(
            eth_dst='00:01:02:03:04:05',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=1,
            pktlen=self.pkt_len - 4)

    def runTest(self):

        print("\n")
        print("Verify forwarding works with default buffer profile")

        try:
            lldp_mac = "01:80:c2:00:00:0e"
            lldp_pkt = simple_eth_packet(eth_dst=lldp_mac,
                                            pktlen=self.pkt_len - 4,
                                            eth_type=0x88cc)

            sched = sai_thrift_create_scheduler(
                        self.client,
                        meter_type=SAI_METER_TYPE_BYTES,
                        min_bandwidth_rate=0,
                        max_bandwidth_rate=0)

            attr = sai_thrift_get_queue_attribute(
                    self.client, self.queues5[1], parent_scheduler_node=True)
            self.assertNotEqual(attr['parent_scheduler_node'], 0)

            self.queues5_1_parent_sch_grp = attr["parent_scheduler_node"]
            status = sai_thrift_set_scheduler_group_attribute(
                    self.client, self.queues5_1_parent_sch_grp, scheduler_profile_id=sched)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            status = sai_thrift_set_queue_attribute(
                        self.client, self.queues5[1], buffer_profile_id=self.buffer_profile_q1)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            status = sai_thrift_set_ingress_priority_group_attribute(
                self.client, self.ipg_idx6[1], buffer_profile=self.buffer_profile_pg1)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            sai_thrift_set_port_attribute(self.client, self.port6,
                priority_flow_control_mode=SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_SEPARATE)

            sai_thrift_set_port_attribute(self.client, self.port6, priority_flow_control_tx=0x02)

            test_trap = sai_thrift_create_hostif_trap(
                self.client,
                packet_action=SAI_PACKET_ACTION_TRAP,
                trap_type=SAI_HOSTIF_TRAP_TYPE_LLDP)
            self.assertNotEqual(test_trap, 0)

            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port6, self.pkt)

            pg_stats = query_counter(
                            self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx6[1])

            self.assertGreater(pg_stats["SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS"], 0)

            for _ in range(10):
                send_packet(self, self.dev_port6, lldp_pkt)

            post_stats = query_counter(self, sai_thrift_get_queue_stats, self.cpu_queue0)
            self.assertEqual(post_stats["SAI_QUEUE_STAT_PACKETS"], 10)
            self.assertEqual(post_stats["SAI_QUEUE_STAT_DROPPED_PACKETS"], 0)
            print("\tOK")

        finally:
            sai_thrift_set_port_attribute(self.client, self.port6, priority_flow_control_tx=0)
            sai_thrift_clear_queue_stats(self.client, self.cpu_queue0)
            sai_thrift_clear_ingress_priority_group_stats(self.client, self.ipg_idx6[1])
            sai_thrift_set_queue_attribute(self.client, self.queues5[1], buffer_profile_id=0)
            sai_thrift_set_scheduler_group_attribute(self.client, self.queues5_1_parent_sch_grp, scheduler_profile_id=0)
            sai_thrift_set_ingress_priority_group_attribute(self.client, self.ipg_idx6[1], buffer_profile=0)
            sai_thrift_remove_hostif_trap(self.client, test_trap)
            sai_thrift_remove_scheduler(self.client, sched)
            sai_thrift_clear_queue_stats(self.client, self.queues5[1])

    def tearDown(self):

        super(LosslessCPUTest, self).tearDown()

@group("draft")
class LosslessPfcRxTxTest(SaiHelperScaleTM):
    """
    Verify transitioning between different buffer profiles and modyfing buffer
    profile does not break forwarding for ingress priority group.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """
    def setUp(self):
        super(LosslessPfcRxTxTest, self).setUp()
        self.tx_cnt = 100000
        self.pkt_len = 9000
        self.pkt_p2 = simple_udp_packet(
            eth_dst='00:01:02:03:04:02',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=1,
            ip_ecn=1,
            pktlen=self.pkt_len - 4)

    def runTest(self):
        print("\n")
        print("Verify forwarding works with default buffer profile")
        try:
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port1, self.pkt_p2)

            print("Verify traffic\n")
            stats_port = query_counter(
                            self, sai_thrift_get_port_stats, self.port1)


            print("SAI_PORT_STAT_PFC_1_TX_PKTS",
                stats_port["SAI_PORT_STAT_PFC_1_TX_PKTS"])
            self.assertGreater(stats_port["SAI_PORT_STAT_PFC_1_TX_PKTS"], 0)

        finally:
            sai_thrift_clear_port_stats(self.client, self.port1)

    def tearDown(self):

        super(LosslessPfcRxTxTest, self).tearDown()

@group("draft")
class SchedulerTest(SaiHelperScaleTM):
    """
    Verify traffic forwarding according to the scheduler profile.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """

    def setUp(self):
        super(SchedulerTest, self).setUp()

        self.tx_cnt = 50000
        self.pkt_len = 900
        self.pkt_pcp1 = simple_udp_packet(
            eth_dst='00:01:02:03:04:04',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=1,
            pktlen=self.pkt_len - 4)  # account for 4B FCS

        self.pkt_pcp2 = simple_udp_packet(
            eth_dst='00:01:02:03:04:04',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            pktlen=self.pkt_len - 4)

        self.pkt_pcp3 = simple_udp_packet(
            eth_dst='00:01:02:03:04:04',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=3,
            pktlen=self.pkt_len - 4)

    def runTest(self):
        print("\n")
        print("Verify forwarding works with default buffer profile")

        try:
            cir = 100000
            pir = 100000
            sched4 = sai_thrift_create_scheduler(
                        self.client,
                        meter_type=SAI_METER_TYPE_BYTES,
                        min_bandwidth_rate=cir,
                        max_bandwidth_rate=pir)

            status = sai_thrift_set_port_attribute(
                self.client, self.port4, qos_scheduler_profile_id=sched4)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            print("Send {} pkts, pkt size: {} B".format(self.tx_cnt, self.pkt_len))
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port5, self.pkt_pcp1)
                send_packet(self, self.dev_port5, self.pkt_pcp2)
                send_packet(self, self.dev_port5, self.pkt_pcp3)

            print("Verify traffic\n")
            stats_q1 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues4[1])
            stats_q2 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues4[2])
            stats_q3 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues4[3])

            print("port 4 queue 1 SAI_QUEUE_STAT_PACKETS",
                stats_q1["SAI_QUEUE_STAT_PACKETS"])
            print("port 4 queue 2 SAI_QUEUE_STAT_PACKETS",
                stats_q2["SAI_QUEUE_STAT_PACKETS"])
            print("port 4 queue 3 SAI_QUEUE_STAT_PACKETS",
                stats_q3["SAI_QUEUE_STAT_PACKETS"])

            self.assertGreater(stats_q1["SAI_QUEUE_STAT_PACKETS"], stats_q3["SAI_QUEUE_STAT_PACKETS"]*3)
            self.assertGreater(stats_q2["SAI_QUEUE_STAT_PACKETS"], stats_q3["SAI_QUEUE_STAT_PACKETS"]*3)
            self.assertLess(stats_q1["SAI_QUEUE_STAT_PACKETS"], stats_q3["SAI_QUEUE_STAT_PACKETS"]*5)
            self.assertLess(stats_q2["SAI_QUEUE_STAT_PACKETS"], stats_q3["SAI_QUEUE_STAT_PACKETS"]*5)

        finally:
            sai_thrift_clear_queue_stats(self.client, self.queues4[1])
            sai_thrift_clear_queue_stats(self.client, self.queues4[2])
            sai_thrift_clear_queue_stats(self.client, self.queues4[3])
            sai_thrift_set_port_attribute(self.client, self.port4, qos_scheduler_profile_id=0)
            sai_thrift_remove_scheduler(self.client, sched4)

    def tearDown(self):

        super(SchedulerTest, self).tearDown()

@group("draft")
class PfcWD(SaiHelperScaleTM):
    """
    Verify transitioning between different buffer profiles and modyfing buffer
    profile does not break forwarding for ingress priority group.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """

    def setUp(self):
        if get_platform() in ['ctc']:
            super().setUp(skip_reason = f"[ALI] SKIP test on [{get_platform()}], temporarily can not support pfc pkt transit in test environment")
        else:
            super(PfcWD, self).setUp()

    def runTest(self):
        print("\n")
        print("Verify forwarding works with default buffer profile")

    def tearDown(self):

        super(PfcWD, self).tearDown()

@group("draft")
class CpuQueue(SaiHelperScaleTM):
    """
    Verify CPU send messages,
    the traffic should be forwarded from queue 7.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """

    def setUp(self):
        if get_platform() in ['ctc']:
            super().setUp(skip_reason = f"[ALI] SKIP test on [{get_platform()}], temporarily can not verify the packet from hostif cross device, the test logic is designed correctly")
        else:
            super(CpuQueue, self).setUp()

    def runTest(self):
        print("\n")
        print("Verify forwarding works with default buffer profile")
        test_port = self.port0
        test_dev_port = self.dev_port0
        hostif_name = "hostif"

        test_ip = "10.10.10.1"

        pkt = simple_udp_packet(ip_dst=test_ip)

        try:
            hostif = sai_thrift_create_hostif(self.client,
                                              name=hostif_name,
                                              obj_id=test_port,
                                              type=SAI_HOSTIF_TYPE_NETDEV)
            self.assertNotEqual(hostif, 0)

            hif_socket = open_packet_socket(hostif_name)

            print("Sending packet via port hostif")
            hif_socket.send(bytes(pkt))
            print("\tOK")

            print("Verifying packet on port")
            verify_packet(self, pkt, test_dev_port)
            print("\tOK")

            queue_list = sai_thrift_object_list_t(count=20)
            attr = sai_thrift_get_port_attribute(
                self.client, test_port, qos_queue_list=queue_list)
            queues10 = attr["SAI_PORT_ATTR_QOS_QUEUE_LIST"].idlist
            stats_q7 = query_counter(
                            self, sai_thrift_get_queue_stats, queues10[7])

            self.assertEqual(stats_q7["SAI_QUEUE_STAT_PACKETS"],1)

        finally:
            sai_thrift_clear_queue_stats(self.client, self.queues10[7])
            sai_thrift_remove_hostif(self.client, hostif)

    def tearDown(self):

        super(CpuQueue, self).tearDown()

@group("draft")
class MirrorBufferIsolateTest(SaiHelperScaleTM):
    """
    Verify transitioning between different buffer profiles and modyfing buffer
    profile does not break forwarding for ingress priority group.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """

    def setUp(self):
        super(MirrorBufferIsolateTest, self).setUp()

        self.tx_cnt = 100000
        self.pkt_len = 4096
        self.pkt = simple_udp_packet(
            eth_dst='00:01:02:03:04:05',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            pktlen=self.pkt_len - 4)  # account for 4B FCS

        self.pkt6 = simple_udp_packet(
            eth_dst='00:01:02:03:04:06',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=2,
            pktlen=self.pkt_len - 4)  # account for 4B FCS

    def runTest(self):
        print("\n")
        print("Verify forwarding works with default buffer profile")

        try:
            sai_thrift_clear_port_stats(self.client, self.port6)
            span_id_ingress = sai_thrift_create_mirror_session(
                self.client,
                monitor_port=self.port6,
                type=SAI_MIRROR_SESSION_TYPE_LOCAL)

            obj_list = sai_thrift_object_list_t(count=1, idlist=[span_id_ingress])
            sai_thrift_set_port_attribute(self.client,
                                        self.port4,
                                        ingress_mirror_session=obj_list)

            sched4 = sai_thrift_create_scheduler(
                        self.client,
                        meter_type=SAI_METER_TYPE_BYTES,
                        min_bandwidth_rate=0,
                        max_bandwidth_rate=0)

            status = sai_thrift_set_port_attribute(
                self.client, self.port6, qos_scheduler_profile_id=sched4)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            status = sai_thrift_set_queue_attribute(
                        self.client, self.queues6[2], buffer_profile_id=self.buffer_profile_q1)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            print("Send {} pkts, pkt size: {} B".format(self.tx_cnt, self.pkt_len))
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port4, self.pkt)

            print("Verify traffic\n")

            stats_q8 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues6[8])
            print("Mirror pkt SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES", stats_q8["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"])
            self.assertGreater(stats_q8["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"], 0)

            stats_igr_pool = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)
            self.assertEqual(stats_igr_pool["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)

            stats_egr_pool = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.egr_pool)
            self.assertEqual(stats_egr_pool["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)

            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port4, self.pkt6)

            stats_q2 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues6[2])
            print("queue 2 pkt SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES should occupy all share buffer")
            self.assertGreater(stats_q2["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"], self.buf_size - 4096)

            sai_thrift_set_port_attribute(self.client, self.port6, qos_scheduler_profile_id=0)
            time.sleep(1)
            stats_q2 = query_counter(self, sai_thrift_get_queue_stats, self.queues6[2])
            stats_port6 = query_counter(self, sai_thrift_get_port_stats, self.port6)
            self.assertGreater(stats_port6["SAI_PORT_STAT_ETHER_STATS_TX_NO_ERRORS"], stats_q2["SAI_QUEUE_STAT_PACKETS"])


        finally:
            sai_thrift_clear_queue_stats(self.client, self.queues6[2])
            sai_thrift_clear_queue_stats(self.client, self.queues6[8])
            obj_list = sai_thrift_object_list_t(count=0, idlist=[span_id_ingress])
            sai_thrift_set_port_attribute(self.client, self.port4, ingress_mirror_session=obj_list)
            sai_thrift_remove_mirror_session(self.client, span_id_ingress)
            sai_thrift_set_port_attribute(self.client, self.port6, qos_scheduler_profile_id=0)
            sai_thrift_remove_scheduler(self.client, sched4)

    def tearDown(self):

        super(MirrorBufferIsolateTest, self).tearDown()

@group("draft")
class FloodBufferIsolateTest(SaiHelperScaleTM):
    """
    Verify transitioning between different buffer profiles and modyfing buffer
    profile does not break forwarding for ingress priority group.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """

    def setUp(self):
        super(FloodBufferIsolateTest, self).setUp()

        self.tx_cnt = 100000
        self.pkt_len = 9000
        self.pkt_flood = simple_udp_packet(
            eth_dst='00:01:02:03:04:0A',
            dl_vlan_enable=True,
            vlan_vid=40,
            ip_dscp=1,
            pktlen=self.pkt_len - 4)  # account for 4B FCS

        self.pkt_fwd = simple_udp_packet(
            eth_dst='00:01:02:03:04:05',
            dl_vlan_enable=True,
            vlan_vid=10,
            ip_dscp=1,
            pktlen=self.pkt_len - 4)  # account for 4B FCS

    def runTest(self):
        print("\n")
        print("Verify forwarding works with default buffer profile")

        try:
            sai_thrift_clear_port_stats(self.client, self.port5)
            # create vlan 40 with
            self.create_vlan_with_members(40, {self.port4_bp: 'tagged',
                                            self.port5_bp: 'tagged'})

            status = sai_thrift_set_queue_attribute(
                        self.client, self.queues5[1], buffer_profile_id=self.buffer_profile_q1)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

            sched4 = sai_thrift_create_scheduler(
                        self.client,
                        meter_type=SAI_METER_TYPE_BYTES,
                        min_bandwidth_rate=0,
                        max_bandwidth_rate=0)

            status = sai_thrift_set_port_attribute(
                self.client, self.port5, qos_scheduler_profile_id=sched4)
            self.assertEqual(status, SAI_STATUS_SUCCESS)
            print("Send {} pkts, pkt size: {} B".format(self.tx_cnt, self.pkt_len))
            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port4, self.pkt_flood)

            print("Verify traffic\n")
            stats_q8 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues5[8])
            print("flood pkt SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES", stats_q8["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"])
            self.assertGreater(stats_q8["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"], 0)

            stats_igr_pool = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)
            self.assertEqual(stats_igr_pool["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)

            stats_egr_pool = query_counter(
                            self, sai_thrift_get_buffer_pool_stats, self.egr_pool)
            self.assertEqual(stats_egr_pool["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"], 0)

            for _ in range(self.tx_cnt):
                send_packet(self, self.dev_port4, self.pkt_fwd)

            print("Verify traffic\n")
            stats_q1 = query_counter(
                            self, sai_thrift_get_queue_stats, self.queues5[1])
            print("queue 1 pkt SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES should occupy all share buffer")
            self.assertGreater(stats_q1["SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES"], self.buf_size - 4096)
            sai_thrift_set_port_attribute(self.client, self.port5, qos_scheduler_profile_id=0)
            time.sleep(1)
            stats_q1 = query_counter(self, sai_thrift_get_queue_stats, self.queues5[1])
            stats_port5 = query_counter(self, sai_thrift_get_port_stats, self.port5)
            self.assertGreater(stats_port5["SAI_PORT_STAT_ETHER_STATS_TX_NO_ERRORS"], stats_q1["SAI_QUEUE_STAT_PACKETS"])

        finally:
            sai_thrift_clear_queue_stats(self.client, self.queues5[1])
            sai_thrift_clear_queue_stats(self.client, self.queues5[8])
            sai_thrift_set_queue_attribute(self.client, self.queues5[1], buffer_profile_id=0)
            sai_thrift_set_ingress_priority_group_attribute(self.client, self.ipg_idx4[1], buffer_profile=0)
            sai_thrift_set_port_attribute(self.client, self.port5, qos_scheduler_profile_id=0)
            sai_thrift_remove_scheduler(self.client, sched4)

    def tearDown(self):

        super(FloodBufferIsolateTest, self).tearDown()
