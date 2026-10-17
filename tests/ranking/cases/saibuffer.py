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

@group("draft")
class BufferStatistics(MinimalPortVlanConfig):
    """
    Test buffer pool and ingress priority group statictics.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """

    def __init__(self):
        super(BufferStatistics, self).__init__(port_num=3)

    def setUp(self):
        super(BufferStatistics, self).setUp()

        self.tx_cnt = 10000
        self.pkt_len = 700
        self.reserved_buf_size = 1270
        self.shared_buf_size = self.reserved_buf_size * 4
        self.buf_size = self.reserved_buf_size * 1000
        self.sleep_time = 2
        self.pkt = simple_udp_packet(
            pktlen=self.pkt_len - 4)  # account for 4B FCS
        self.max_rate = 10

        if get_platform() == 'clx':
            self.pkt = simple_udp_packet(eth_dst='00:22:22:22:22:22', eth_src='00:44:44:44:44:44',
                                        pktlen=self.pkt_len - 4)  # account for 4B FCS

            self.pkt_learn_mac = simple_udp_packet(eth_dst='00:44:44:44:44:44',
                                                eth_src='00:22:22:22:22:22',
                                                pktlen=self.pkt_len - 4)

        ## Create Buffer Profile
        self.ingr_pool = sai_thrift_create_buffer_pool(
            self.client, type=SAI_BUFFER_POOL_TYPE_INGRESS, size=self.buf_size)
        self.assertGreater(self.ingr_pool, 0)

        self.buffer_profile = sai_thrift_create_buffer_profile(
            self.client, pool_id=self.ingr_pool,
            reserved_buffer_size=self.reserved_buf_size,
            shared_static_th=self.shared_buf_size,
            threshold_mode=SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC)
        self.assertGreater(self.buffer_profile, 0)

        # unsupported api create_ingress_priority_group
        # self.ipg_idx = 7
        # self.ipg = sai_thrift_create_ingress_priority_group(
        #    self.client, port=self.port0, index=self.ipg_idx,
        #    buffer_profile=self.buffer_profile)
        # self.assertGreater(self.ipg, 0)

        attr = sai_thrift_get_port_attribute(
            self.client, self.port4, number_of_ingress_priority_groups=True)
        self.assertNotEqual(attr['number_of_ingress_priority_groups'], 0)
        ipg_num = attr["number_of_ingress_priority_groups"]

        sai_list = sai_thrift_u32_list_t(count=ipg_num, uint32list=[])
        attr = sai_thrift_get_port_attribute(
            self.client, self.port4, ingress_priority_group_list=sai_list)
        self.assertEqual(attr['ingress_priority_group_list'].count,
                         ipg_num)
        idlist = attr['ingress_priority_group_list'].idlist
        self.ipg_idx = idlist[7]
        if get_platform() == 'clx':
            # not support set SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP
            self.ipg_idx = idlist[0]

        status = sai_thrift_set_ingress_priority_group_attribute(
            self.client, self.ipg_idx, buffer_profile=self.buffer_profile)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        ## Create QoS Map
        tc_to_pg = sai_thrift_qos_map_t(
           key=sai_thrift_qos_map_params_t(prio=0),
           value=sai_thrift_qos_map_params_t(pg=7))

        qos_map_list = sai_thrift_qos_map_list_t(maplist=[tc_to_pg], count=1)

        self.qos_map = sai_thrift_create_qos_map(
           self.client, type=SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP,
           map_to_value_list=qos_map_list)
        self.assertGreater(self.qos_map, 0)

        status = sai_thrift_set_port_attribute(
           self.client, self.port4,
           qos_tc_to_priority_group_map=self.qos_map)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        # configure exit port speed limit, in order to get buffer occupancy
        if get_platform() == 'clx':
            self.sched = sai_thrift_create_scheduler(
                self.client,
                meter_type=SAI_METER_TYPE_BYTES,
                max_bandwidth_rate=1000,
                scheduling_type=SAI_SCHEDULING_TYPE_STRICT)
        else:
            self.sched = sai_thrift_create_scheduler(
                self.client,
                meter_type=SAI_METER_TYPE_PACKETS,
                max_bandwidth_rate=100,
                scheduling_type=SAI_SCHEDULING_TYPE_STRICT)
        self.assertNotEqual(self.sched, 0)
        status = sai_thrift_set_port_attribute(
            self.client, self.port5,
            qos_scheduler_profile_id=self.sched)
        self.assertEqual(status, SAI_STATUS_SUCCESS)


    def sendTraffic(self):
        """
        Send traffic.
        """
        print()
        print("Send {} pkts, pkt size: {} B".format(self.tx_cnt, self.pkt_len))
        for _ in range(self.tx_cnt):
            send_packet(self, self.dev_port4, self.pkt)
        print("Send done")
        print()

    def monitor_stats(self):
        while True:
            # SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES, this statistic is wrong by muliply by number of xpes
            stats = query_counter(
                    self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)
            self.shared_stats["bp_curr_occupancy_bytes"] = max(
                self.shared_stats["bp_curr_occupancy_bytes"],
                stats["SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES"] //2
            )

            stats = query_counter(
                    self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx)
            self.shared_stats["ipg_curr_occupancy_bytes"] = max(
                self.shared_stats["ipg_curr_occupancy_bytes"],
                stats["SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES"]
            )
            self.shared_stats["ipg_shared_curr_occupancy_bytes"] = max(
                self.shared_stats["ipg_shared_curr_occupancy_bytes"],
                stats["SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES"]
            )

            # print(f"Updated stats: {self.shared_stats}")
            # time.sleep(1)
            if self.shared_stats.get("stop_monitoring", False):
                break

    def sendVerify(self, expected_drops, verify_reserved_buffer_size):
        """
        Send traffic in parallel while polling for current occupancy stats.
        Once traffic is sent verifies other stats.

        Args:
            expected_drops (int): Number of expected dropped packets.
            verify_reserved_buffer_size (bool): Whether to verify
                SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE.
        """
        num_processes = 5
        processes = []
        manager = Manager()
        self.shared_stats = manager.dict({
            "bp_curr_occupancy_bytes": 0,
            "ipg_curr_occupancy_bytes": 0,
            "ipg_shared_curr_occupancy_bytes": 0,
            "stop_monitoring": False
        })

        try:
            for i in range(num_processes):
                traffic = Process(target=self.sendTraffic)
                traffic.start()
                processes.append(traffic)

            monitor_thread = Process(target=self.monitor_stats)
            monitor_thread.start()

            for p in processes:
                p.join()

            self.shared_stats["stop_monitoring"] = True
            monitor_thread.join()

            time.sleep(self.sleep_time)

            stats = query_counter(
                        self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)

            if verify_reserved_buffer_size:
                # if pkt_len is larger than reserved buffer size, we need to set the expected watermark to zero
                expected_watermark = 0
                # expected_watermark = self.reserved_buf_size
            else:
                expected_watermark = self.pkt_len

            print("SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES (max measured)",
                self.shared_stats["bp_curr_occupancy_bytes"])
            print("SAI_BUFFER_POOL_STAT_WATERMARK_BYTES",
                stats["SAI_BUFFER_POOL_STAT_WATERMARK_BYTES"])

            if verify_reserved_buffer_size:
                # if test pkt lens is larger than reserved buffer size, there won't be any pkts in the buffer pool, thus the occupancy should be 0
                self.assertEqual(self.shared_stats["bp_curr_occupancy_bytes"], 0)
            else:
                self.assertGreater(self.shared_stats["bp_curr_occupancy_bytes"], 0)
            self.assertGreaterEqual(
                stats["SAI_BUFFER_POOL_STAT_WATERMARK_BYTES"], expected_watermark)

            stats = query_counter(
                        self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx)

            print("SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES "
                "(max measured)", self.shared_stats["ipg_curr_occupancy_bytes"])
            print("SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES "
                "(max measured)", self.shared_stats["ipg_shared_curr_occupancy_bytes"])
            print("SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES",
                stats["SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES"])
            print("SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS",
                stats["SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS"])
            print("SAI_INGRESS_PRIORITY_GROUP_STAT_BYTES",
                stats["SAI_INGRESS_PRIORITY_GROUP_STAT_BYTES"])
            print("SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS",
                stats["SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS"])

            self.assertGreaterEqual(self.shared_stats["ipg_curr_occupancy_bytes"], 0)
            self.assertGreaterEqual(self.shared_stats["ipg_shared_curr_occupancy_bytes"], 0)
            self.assertGreaterEqual(
                stats["SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES"],
                expected_watermark)
            if get_platform() != 'clx':
                self.assertEqual(
                    stats["SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS"], self.tx_cnt * num_processes)
                self.assertEqual(
                    stats["SAI_INGRESS_PRIORITY_GROUP_STAT_BYTES"],
                    self.tx_cnt * self.pkt_len * num_processes)
                self.assertEqual(
                    stats["SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS"],
                    expected_drops * num_processes)

        finally:
            for p in processes:
                if p.is_alive():
                    p.terminate()
            if monitor_thread.is_alive():
                monitor_thread.terminate()

    def clearVerify(self):
        """
        Clear bufer pool and ingress priority group stats.
        Verify they are cleared.
        """
        print()
        print("Clear bufer pool and ingress priority group stats")
        if get_platform() == 'clx':
            sai_thrift_set_port_attribute(
                self.client, self.port5, qos_scheduler_profile_id=0)
        status = clear_counter(
                    self, sai_thrift_clear_buffer_pool_stats, self.ingr_pool)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = clear_counter(
                    self, sai_thrift_clear_ingress_priority_group_stats, self.ipg_idx)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)

        print("Get stats and verify they are cleared")

        stats = query_counter(
                    self, sai_thrift_get_buffer_pool_stats, self.ingr_pool)

        self.assertEqual(
            stats["SAI_BUFFER_POOL_STAT_WATERMARK_BYTES"], 0)

        stats = query_counter(
                    self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx)

        self.assertEqual(
            stats["SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS"], 0)
        self.assertEqual(
            stats["SAI_INGRESS_PRIORITY_GROUP_STAT_BYTES"], 0)
        self.assertEqual(
            stats["SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES"], 0)
        self.assertEqual(
            stats["SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS"], 0)
        if get_platform() == 'clx':
            status = sai_thrift_set_port_attribute(
                self.client, self.port5,
                qos_scheduler_profile_id=self.sched)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

    def runTest(self):
        print()

        if get_platform() == 'clx':
            send_packet(self, self.dev_port5, self.pkt_learn_mac)
            verify_packet(self, self.pkt_learn_mac, self.dev_port4)

        # Make sure test starts with cleared counters.
        status = clear_counter(
                    self, sai_thrift_clear_buffer_pool_stats, self.ingr_pool)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = clear_counter(
                    self, sai_thrift_clear_ingress_priority_group_stats, self.ipg_idx)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)

        print("Buffer pool size:", self.buf_size)
        print("Buffer profile reserved_buffer_size:", self.reserved_buf_size)
        print("Buffer profile shared_static_th:", self.shared_buf_size)

        self.sendVerify(expected_drops=0, verify_reserved_buffer_size=False)
        time.sleep(3)
        self.clearVerify()

        self.pkt_len = 1500
        self.pkt = simple_udp_packet(
            pktlen=self.pkt_len - 4)  # account for 4B FCS

        print()
        print("Send pkts ({} B) larger than reserved buffer ({} B)".format(
            self.pkt_len, self.reserved_buf_size))

        # if you expect to drop all pkts, you need to set the shared buffer size to 0, and make sure the reserved buffer size is less than the pkt size
        status = sai_thrift_set_ingress_priority_group_attribute(self.client, self.ipg_idx, buffer_profile=0)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        if get_platform() != 'ctc':
            sai_thrift_remove_buffer_profile(self.client, self.buffer_profile)

        self.reserved_buf_size = 0
        if get_platform() != 'ctc':
            self.shared_buf_size = 0
        else:
            self.shared_buf_size = 100

        self.buffer_profile = sai_thrift_create_buffer_profile(
            self.client, pool_id=self.ingr_pool,
            reserved_buffer_size=self.reserved_buf_size,
            shared_static_th=self.shared_buf_size,
            threshold_mode=SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC)
        self.assertGreater(self.buffer_profile, 0)
        status = sai_thrift_set_ingress_priority_group_attribute(
            self.client, self.ipg_idx, buffer_profile=self.buffer_profile)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        attr = sai_thrift_get_buffer_profile_attribute(
            self.client, self.buffer_profile, reserved_buffer_size=True,
            shared_static_th=True)
        print(f"now buffer profile:{attr}")
        self.assertEqual(attr["reserved_buffer_size"], 0)
        if get_platform() != 'ctc':
            self.assertEqual(attr["shared_static_th"], 0)
        else:
            self.assertEqual(attr["shared_static_th"], 100)

        print("Buffer pool size:", self.buf_size)
        print("Buffer profile reserved_buffer_size:", self.reserved_buf_size)
        print("Buffer profile shared_static_th:", self.shared_buf_size)

        self.sendVerify(
            expected_drops=self.tx_cnt, verify_reserved_buffer_size=True)
        time.sleep(5)
        self.clearVerify()

    def tearDown(self):
        sai_thrift_set_port_attribute(
           self.client, self.port5, qos_scheduler_profile_id=0)
        sai_thrift_set_port_attribute(
           self.client, self.port4, qos_tc_to_priority_group_map=0)
        sai_thrift_remove_scheduler(self.client, self.sched)
        sai_thrift_remove_qos_map(self.client, self.qos_map)
        # sai_thrift_remove_ingress_priority_group(self.client, self.ipg)
        sai_thrift_set_ingress_priority_group_attribute(self.client, self.ipg_idx, buffer_profile=0)
        sai_thrift_remove_buffer_profile(self.client, self.buffer_profile)
        sai_thrift_remove_buffer_pool(self.client, self.ingr_pool)

        super(BufferStatistics, self).tearDown()


@group("draft")
class Forwarding(MinimalPortVlanConfig):
    """
    Verify transitioning between different buffer profiles and modyfing buffer
    profile does not break forwarding for ingress priority group.
    To observe the proper counting of buffer statistics,
    it is recommended to run the test on hardware.
    """

    def __init__(self):
        super(Forwarding, self).__init__(port_num=3)

    def setUp(self):
        super(Forwarding, self).setUp()

        self.tx_cnt = 10
        self.pkt_len = 1500
        self.reserved_buf_size = 3200
        self.buf_size = self.reserved_buf_size * 1000
        self.pkt = simple_udp_packet(
            pktlen=self.pkt_len - 4)  # account for 4B FCS

        ## Do not support sai_thrift_create_ingress_priority_group besides creating switch, so we directly get the pg from switch

        # self.ipg_idx = 0
        # self.ipg = sai_thrift_create_ingress_priority_group(
        #    self.client, port=self.port0, index=self.ipg_idx)
        # self.assertGreater(self.ipg, 0)

        attr = sai_thrift_get_port_attribute(
            self.client, self.port4, number_of_ingress_priority_groups=True)
        self.assertNotEqual(attr['number_of_ingress_priority_groups'], 0)
        ipg_num = attr["number_of_ingress_priority_groups"]

        sai_list = sai_thrift_u32_list_t(count=ipg_num, uint32list=[])
        attr = sai_thrift_get_port_attribute(
            self.client, self.port4, ingress_priority_group_list=sai_list)
        self.assertEqual(attr['ingress_priority_group_list'].count,
                         ipg_num)
        idlist = attr['ingress_priority_group_list'].idlist
        self.ipg_idx = idlist[0]

        attr = sai_thrift_get_ingress_priority_group_attribute(
            self.client, self.ipg_idx, buffer_profile=True)
        print(f"Default buffer profile:{attr}")

        ## Create Buffer Profile
        self.ingr_pool = sai_thrift_create_buffer_pool(
            self.client, type=SAI_BUFFER_POOL_TYPE_INGRESS, size=self.buf_size)
        self.assertGreater(self.ingr_pool, 0)

        self.buffer_profile = sai_thrift_create_buffer_profile(
            self.client, pool_id=self.ingr_pool,
            reserved_buffer_size=self.reserved_buf_size, shared_dynamic_th=3,
            threshold_mode=SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC)
        self.assertGreater(self.buffer_profile, 0)

        print(f"Setup buffer_profile: {self.buffer_profile} \n")

        ## Create QoS Map
        tc_to_pg = sai_thrift_qos_map_t(
           key=sai_thrift_qos_map_params_t(prio=0),
           value=sai_thrift_qos_map_params_t(pg=0))

        qos_map_list = sai_thrift_qos_map_list_t(maplist=[tc_to_pg], count=1)

        self.qos_map = sai_thrift_create_qos_map(
           self.client, type=SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP,
           map_to_value_list=qos_map_list)
        self.assertGreater(self.qos_map, 0)

        status = sai_thrift_set_port_attribute(
           self.client, self.port4,
           qos_tc_to_priority_group_map=self.qos_map)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

    def clearSendVerify(self):
        """
        Clear counters, send traffic, verify counters.
        """

        # therefore, we need to change the port ids if the test is run on a different topology
        status = clear_counter(
                self, sai_thrift_clear_port_stats, self.port4)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = clear_counter(
                self, sai_thrift_clear_port_stats, self.port10)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = clear_counter(
                self, sai_thrift_clear_port_stats, self.port11)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = clear_counter(
                    self, sai_thrift_clear_ingress_priority_group_stats, self.ipg_idx)
        # self.assertEqual(status, SAI_STATUS_SUCCESS)

        print("Send {} pkts, pkt size: {} B".format(self.tx_cnt, self.pkt_len))
        for _ in range(self.tx_cnt):
            send_packet(self, self.dev_port4, self.pkt)

        print("Verify traffic\n")
        time.sleep(2)

        stats_ipg = query_counter(
                    self, sai_thrift_get_ingress_priority_group_stats, self.ipg_idx)
        stats_p1 = query_counter(
                    self, sai_thrift_get_port_stats, self.port10)
        stats_p2 = query_counter(
                    self, sai_thrift_get_port_stats, self.port11)
        if get_platform() == 'clx':
            print('get ipg packets stats is not supported on clx platform')
            pass
        else:
            # print("stats_ipg: {} \n stats_p1:{} \n stats_p2: {} ".format(stats_ipg, stats_p1, stats_p2))

            self.assertEqual(
                    stats_ipg["SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS"], self.tx_cnt)
        # it seems like that get_port_stats have some problem with SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS attr
        # the stats we get is not pkts num instead of bytes num, thus we temporarily uses bytes num for verification
        self.assertEqual(
            stats_p1["SAI_PORT_STAT_IF_OUT_UCAST_PKTS"], (self.tx_cnt))
        self.assertEqual(
            stats_p2["SAI_PORT_STAT_IF_OUT_UCAST_PKTS"], (self.tx_cnt))

    def runTest(self):
        print("\n")
        print("Verify forwarding works with default buffer profile")

        status = sai_thrift_set_ingress_priority_group_attribute(
            self.client, self.ipg_idx, buffer_profile=self.buffer_profile)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        attr = sai_thrift_get_ingress_priority_group_attribute(
            self.client, self.ipg_idx, buffer_profile=True)
        self.assertEqual(attr["buffer_profile"], self.buffer_profile)

        self.clearSendVerify()

        print("Verify forwarding works with custom buffer profile")

        status = sai_thrift_set_ingress_priority_group_attribute(
            self.client, self.ipg_idx, buffer_profile=self.buffer_profile)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        attr = sai_thrift_get_ingress_priority_group_attribute(
            self.client, self.ipg_idx, buffer_profile=True)
        self.assertEqual(attr["buffer_profile"], self.buffer_profile)

        self.clearSendVerify()

        print("Verify forwarding works with updated custom buffer profile")

        status = sai_thrift_set_buffer_profile_attribute(
            self.client, self.buffer_profile, reserved_buffer_size=1600)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        status = sai_thrift_set_buffer_profile_attribute(
            self.client, self.buffer_profile, shared_dynamic_th=2)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        attr = sai_thrift_get_buffer_profile_attribute(
            self.client, self.buffer_profile, reserved_buffer_size=True,
            shared_dynamic_th=True)
        self.assertEqual(attr["reserved_buffer_size"], 1600)
        self.assertEqual(attr["shared_dynamic_th"], 2)

        self.clearSendVerify()

        print("Verify forwarding works with default buffer profile")

        status = sai_thrift_set_ingress_priority_group_attribute(
            self.client, self.ipg_idx, buffer_profile=0)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        attr = sai_thrift_get_ingress_priority_group_attribute(
            self.client, self.ipg_idx, buffer_profile=True)
        self.assertEqual(attr["buffer_profile"], 0)

        self.clearSendVerify()

    def tearDown(self):
        sai_thrift_set_port_attribute(
           self.client, self.port4, qos_tc_to_priority_group_map=0)
        sai_thrift_remove_qos_map(self.client, self.qos_map)
        # sai_thrift_remove_ingress_priority_group(self.client, self.ipg)
        sai_thrift_set_ingress_priority_group_attribute(self.client, self.ipg_idx, buffer_profile=0)
        sai_thrift_remove_buffer_profile(self.client, self.buffer_profile)
        sai_thrift_remove_buffer_pool(self.client, self.ingr_pool)

        super(Forwarding, self).tearDown()


@group("draft")
class BufferPoolNumber(MinimalPortVlanConfig):
    """
    Verify buffer pool creation count:
     * Ingress = SAI_SWITCH_ATTR_INGRESS_BUFFER_POOL_NUM,
     * Egress = SAI_SWITCH_ATTR_EGRESS_BUFFER_POOL_NUM.

    Verify pools creation with traffic and stats by binding pool to buffer
    profile then binding buffer profile to ingress priority group / queue.
    """

    def __init__(self):
        super(BufferPoolNumber, self).__init__(port_num=2)

    def setUp(self):
        super(BufferPoolNumber, self).setUp()

        self.ingr_pools = []
        self.egr_pools = []
        self.ingr_profiles = []
        self.egr_profiles = []
        self.ipgs = []
        self.queues = []

        self.dscp_to_tc_map = None
        self.tc_to_ipg_map = None
        self.prio_to_ipg_map = None
        self.tc_to_q_map = None

        self.buf_size = 1024 * 80
        self.profile_buf_size = self.buf_size // 10

    def runTest(self):
        print()

        sw_attrs = sai_thrift_get_switch_attribute(
            self.client, ingress_buffer_pool_num=True,
            egress_buffer_pool_num=True,
            total_buffer_size=True)
        ingr_pool_num = sw_attrs["ingress_buffer_pool_num"]
        egr_pool_num = sw_attrs["egress_buffer_pool_num"]

        if get_platform() == 'clx':
            ingr_pool_num = 6
            egr_pool_num = 4

        print("total_buffer_size:", sw_attrs["total_buffer_size"])
        print("ingress_buffer_pool_num:", ingr_pool_num)
        print("egress_buffer_pool_num:", egr_pool_num)

        print("Create {} ingress buffer pools".format(ingr_pool_num))
        for i in range(ingr_pool_num):
            print("Create ingr_pool", i)

            ingr_pool = sai_thrift_create_buffer_pool(
                self.client, type=SAI_BUFFER_POOL_TYPE_INGRESS,
                size=self.buf_size + i)
            self.assertGreater(ingr_pool, 0)
            self.ingr_pools.append(ingr_pool)
        print("OK")

        print("Create {} egress buffer pools".format(egr_pool_num))
        for i in range(egr_pool_num):
            print("Create egr_pool", i)

            egr_pool = sai_thrift_create_buffer_pool(
                self.client, type=SAI_BUFFER_POOL_TYPE_EGRESS,
                size=self.buf_size + i)
            self.assertGreater(egr_pool, 0)
            self.egr_pools.append(egr_pool)
        print("OK")

        print("Create {0} ingress buffer profiles and {0} IPGs".format(
            ingr_pool_num))

        if get_platform() == 'clx':
            attr = sai_thrift_get_port_attribute(self.client, self.port0, number_of_ingress_priority_groups=True)
            nbr_groups = attr['number_of_ingress_priority_groups']
            ingress_priority_group_list = sai_thrift_u32_list_t(count=nbr_groups, uint32list=[])
            attr = sai_thrift_get_port_attribute(self.client,
                                                self.port0,
                                                ingress_priority_group_list=ingress_priority_group_list)
            self.ipgs = attr['ingress_priority_group_list'].idlist

        for i in range(ingr_pool_num):
            profile = sai_thrift_create_buffer_profile(
                self.client, pool_id=self.ingr_pools[i],
                reserved_buffer_size=self.profile_buf_size,
                shared_static_th=self.profile_buf_size,
                threshold_mode=SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC)
            self.assertGreater(profile, 0)
            self.ingr_profiles.append(profile)

            if get_platform() == 'clx':
                status = sai_thrift_set_ingress_priority_group_attribute(self.client, self.ipgs[i], buffer_profile=profile)
                self.assertEqual(status, SAI_STATUS_SUCCESS)
            else:
                ipg = sai_thrift_create_ingress_priority_group(
                    self.client, port=self.port0, index=i, buffer_profile=profile)
                self.assertGreater(ipg, 0)
                self.ipgs.append(ipg)
        print("OK")

        print("Create {} egress buffer profiles and bind each to queue".format(
            egr_pool_num))

        attr = sai_thrift_get_port_attribute(
            self.client, self.port1, qos_number_of_queues=True)

        q_list = sai_thrift_object_list_t(count=attr["qos_number_of_queues"])
        attr = sai_thrift_get_port_attribute(
            self.client, self.port1, qos_queue_list=q_list)
        self.queues = attr["qos_queue_list"].idlist

        for i in range(egr_pool_num):
            profile = sai_thrift_create_buffer_profile(
                self.client, pool_id=self.egr_pools[i],
                reserved_buffer_size=self.profile_buf_size,
                shared_static_th=self.profile_buf_size,
                threshold_mode=SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC)
            self.assertGreater(profile, 0)
            self.egr_profiles.append(profile)

            status = sai_thrift_set_queue_attribute(
                self.client, self.queues[i], buffer_profile_id=profile)
            self.assertEqual(status, SAI_STATUS_SUCCESS)
        print("OK")

        # Configure QoS maps.
        dscp_to_tc = []
        tc_to_ipg = []
        prio_to_ipg = []
        tc_to_q = []

        for i in range(8):
            dscp_to_tc.append(
                sai_thrift_qos_map_t(
                    key=sai_thrift_qos_map_params_t(dscp=i),
                    value=sai_thrift_qos_map_params_t(tc=i)))

        for i in range(ingr_pool_num):
            tc_to_ipg.append(
                sai_thrift_qos_map_t(
                    key=sai_thrift_qos_map_params_t(tc=i),
                    value=sai_thrift_qos_map_params_t(pg=i)))

            prio_to_ipg.append(
                sai_thrift_qos_map_t(
                    key=sai_thrift_qos_map_params_t(prio=i),
                    value=sai_thrift_qos_map_params_t(pg=i)))

        for i in range(egr_pool_num):
            tc_to_q.append(
                sai_thrift_qos_map_t(
                    key=sai_thrift_qos_map_params_t(tc=i),
                    value=sai_thrift_qos_map_params_t(queue_index=i)))

        print("Create DSCP to TC map")
        qos_map_list = sai_thrift_qos_map_list_t(
            maplist=dscp_to_tc, count=len(dscp_to_tc))

        self.dscp_to_tc_map = sai_thrift_create_qos_map(
            self.client, type=SAI_QOS_MAP_TYPE_DSCP_TO_TC,
            map_to_value_list=qos_map_list)
        self.assertGreater(self.dscp_to_tc_map, 0)

        status = sai_thrift_set_port_attribute(
            self.client, self.port0, qos_dscp_to_tc_map=self.dscp_to_tc_map)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        status = sai_thrift_set_port_attribute(
            self.client, self.port1, qos_dscp_to_tc_map=self.dscp_to_tc_map)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        print("OK")

        print("Create TC to iCoS map")
        qos_map_list = sai_thrift_qos_map_list_t(
            maplist=tc_to_ipg, count=len(tc_to_ipg))

        self.tc_to_ipg_map = sai_thrift_create_qos_map(
            self.client, type=SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP,
            map_to_value_list=qos_map_list)
        self.assertGreater(self.tc_to_ipg_map, 0)

        status = sai_thrift_set_port_attribute(
            self.client, self.port0,
            qos_tc_to_priority_group_map=self.tc_to_ipg_map)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        print("OK")

        print("Create iCoS to IPG map")
        qos_map_list = sai_thrift_qos_map_list_t(
            maplist=prio_to_ipg, count=len(prio_to_ipg))

        self.prio_to_ipg_map = sai_thrift_create_qos_map(
            self.client, type=SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_PRIORITY_GROUP,
            map_to_value_list=qos_map_list)
        self.assertGreater(self.prio_to_ipg_map, 0)

        status = sai_thrift_set_port_attribute(
            self.client, self.port0,
            qos_pfc_priority_to_priority_group_map=self.prio_to_ipg_map)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        print("OK")

        print("Create TC to queue map")
        qos_map_list = sai_thrift_qos_map_list_t(
            maplist=tc_to_q, count=len(tc_to_q))

        self.tc_to_q_map = sai_thrift_create_qos_map(
            self.client, type=SAI_QOS_MAP_TYPE_TC_TO_QUEUE,
            map_to_value_list=qos_map_list)
        self.assertGreater(self.tc_to_q_map, 0)

        status = sai_thrift_set_port_attribute(
            self.client, self.port1, qos_tc_to_queue_map=self.tc_to_q_map)
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        print("OK")

        before_stats = query_counter(
                    self, sai_thrift_get_queue_stats, self.queues[i])

        if get_platform() == 'clx':
            #send packet port1 -> port0 for mac learn,use unicast pkt for queue stat
            learn_mac_pkt = simple_udpv6_packet(eth_dst='00:33:33:33:33:11', eth_src='00:33:33:33:33:00')
            send_packet(self, self.dev_port1, learn_mac_pkt)
            verify_packet(self, learn_mac_pkt, self.dev_port0)
            time.sleep(1)

        print("Send 1 packet to each IPG and queue")
        for i in range(ingr_pool_num):
            if get_platform() == 'clx':
                pkt = simple_udpv6_packet(eth_dst='00:33:33:33:33:00', eth_src='00:33:33:33:33:11', ipv6_dscp=i)
            else:
                pkt = simple_udpv6_packet(ipv6_dscp=i)
            send_packet(self, self.dev_port0, pkt)

        for i in range(egr_pool_num):
            pkt = simple_udpv6_packet(ipv6_dscp=i)
            send_packet(self, self.dev_port1, pkt)

        print("Verify traffic")
        time.sleep(2)

        for i in range(ingr_pool_num):
            if get_platform() != 'clx':
                stats = query_counter(
                        self, sai_thrift_get_ingress_priority_group_stats, self.ipgs[i])
                self.assertEqual(
                    stats["SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS"], 1)
        for i in range(egr_pool_num):
            stats = query_counter(
                    self, sai_thrift_get_queue_stats, self.queues[i])
            self.assertEqual(stats["SAI_QUEUE_STAT_PACKETS"]-before_stats["SAI_QUEUE_STAT_PACKETS"], 1)

    def tearDown(self):
        # Unset QoS maps.
        sai_thrift_set_port_attribute(
            self.client, self.port1, qos_tc_to_queue_map=0)
        sai_thrift_set_port_attribute(
            self.client, self.port1, qos_dscp_to_tc_map=0)

        sai_thrift_set_port_attribute(
            self.client, self.port0, qos_pfc_priority_to_priority_group_map=0)
        sai_thrift_set_port_attribute(
            self.client, self.port0, qos_tc_to_priority_group_map=0)
        sai_thrift_set_port_attribute(
            self.client, self.port0, qos_dscp_to_tc_map=0)

        # Remove QoS maps.
        sai_thrift_remove_qos_map(self.client, self.tc_to_q_map)
        sai_thrift_remove_qos_map(self.client, self.prio_to_ipg_map)
        sai_thrift_remove_qos_map(self.client, self.tc_to_ipg_map)
        sai_thrift_remove_qos_map(self.client, self.dscp_to_tc_map)

        # Unbind buffer profile from queues.
        for q in self.queues:
            sai_thrift_set_queue_attribute(self.client, q, buffer_profile_id=0)

        # Remove IPGs.
        for ipg in self.ipgs:
            if get_platform() == 'clx':
                status = sai_thrift_set_ingress_priority_group_attribute(self.client, ipg, buffer_profile=0)
                self.assertEqual(status, SAI_STATUS_SUCCESS)
            else:
                sai_thrift_remove_ingress_priority_group(self.client, ipg)

        # Remove buffer profiles.
        for profile in self.egr_profiles:
            sai_thrift_remove_buffer_profile(self.client, profile)

        for profile in self.ingr_profiles:
            sai_thrift_remove_buffer_profile(self.client, profile)

        # Remove buffer pools.
        for pool in self.egr_pools:
            sai_thrift_remove_buffer_pool(self.client, pool)

        for pool in self.ingr_pools:
            sai_thrift_remove_buffer_pool(self.client, pool)

        super(BufferPoolNumber, self).tearDown()
