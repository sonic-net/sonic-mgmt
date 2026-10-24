# Copyright (c) 2025 Centec Technology Limited.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
#    THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
#    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
#    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
#    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
#
#    See the Apache Version 2.0 License for specific language governing
#    permissions and limitations under the License.
#
#    The below software in this distribution may have been modified by
#    Clounix (Shanghai) Technology Limited. All Clounix Modifications
#    are copyright © Clounix (Shanghai) Technology Limited.
#


"""
SAI Counter Stress Test  Module
"""

from sai_thrift.sai_headers import *
from ptf.testutils import *
from sai_base_test import *
import time
import random
import ipaddress
from collections import namedtuple
from ext_sai_l3_scale_base import SaiHelperScaleL3

import threading


def _counter_runtime_control():
    return RuntimeControl(test_params_get())


def _find_saiserver_pid(output):
    for line in output.splitlines()[1:]:
        fields = line.split(None, 1)
        if len(fields) == 2 and '/usr/sbin/saiserver' in fields[1]:
            return fields[0]
    raise RuntimeError('saiserver process was not found')


def start_saiserver():
    control = _counter_runtime_control()
    profile = '/etc/sai/profile.ini' if get_platform() == 'clx' \
        else '/etc/sai.d/sai.profile'
    control.run_remote([
        'docker', 'exec', '-d', control.container(), '/usr/sbin/saiserver',
        '-p', profile, '-f', '/usr/share/sonic/hwsku/port_config.ini'])
    result = control.run_remote([
        'docker', 'top', control.container(), '-eo', 'pid,args'])
    host_pid = _find_saiserver_pid(result.stdout)
    time.sleep(10)
    return host_pid


def kill_saiserver():
    control = _counter_runtime_control()
    result = control.run_container(['ps', '-eo', 'pid,args'])
    container_pid = _find_saiserver_pid(result.stdout)
    print(f"saiserver PID:{container_pid}")
    control.run_container(['kill', '-9', container_pid])


class CollectPortCountersTest(SaiHelperScaleL3):

    def setUp(self):
        # kill_saiserver()
        # print(f"killed\n" + "-"*50)
        # time.sleep(10)
        # self.remove_timetxt()
        # self.pid = start_saiserver()
        # time.sleep(10)
        # print(f"saiserver start PID:{self.pid}")
        super(CollectPortCountersTest, self).setUp()
        self.expected_perf = 0.1

    def runTest(self):
        print("Starting port counter test...")
        PORT_STAT_COUNTER = [
            SAI_PORT_STAT_PFC_1_RX_PKTS,
            SAI_PORT_STAT_PFC_1_TX_PKTS,
            SAI_PORT_STAT_IF_IN_MULTICAST_PKTS,
            SAI_PORT_STAT_IF_IN_MEMORY_DISCARDS,
            SAI_PORT_STAT_IF_IN_BROADCAST_PKTS,
            SAI_PORT_STAT_IF_OUT_ERRORS,
            SAI_PORT_STAT_IF_IN_ERRORS,
            SAI_PORT_STAT_IF_OUT_OCTETS,
            SAI_PORT_STAT_IF_OUT_QLEN,
            SAI_PORT_STAT_IF_IN_DISCARDS,
            SAI_PORT_STAT_IF_OUT_UCAST_PKTS,
            SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS,
            SAI_PORT_STAT_IF_IN_UCAST_PKTS,
            SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS,
            SAI_PORT_STAT_IP_IN_NON_UCAST_PKTS,
            SAI_PORT_STAT_IF_IN_OCTETS,
            SAI_PORT_STAT_IP_OUT_NON_UCAST_PKTS,
            SAI_PORT_STAT_IF_OUT_DISCARDS,
            SAI_PORT_STAT_IPV6_IN_UCAST_PKTS,
            SAI_PORT_STAT_IF_OUT_MEMORY_DISCARDS,
            SAI_PORT_STAT_IF_IN_PIPELINE_DISCARDS,
            SAI_PORT_STAT_IF_OUT_PIPELINE_DISCARDS,
            SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS,
            SAI_PORT_STAT_IF_OUT_MULTICAST_PKTS,
            SAI_PORT_STAT_IPV6_IN_NON_UCAST_PKTS,
            SAI_PORT_STAT_IPV6_OUT_NON_UCAST_PKTS,
            SAI_PORT_STAT_ECN_MARKED_PACKETS,
            SAI_PORT_STAT_IPV6_OUT_UCAST_PKTS,
            SAI_PORT_STAT_IF_IN_UNKNOWN_PROTOS,
            SAI_PORT_STAT_IP_IN_UCAST_PKTS,
            SAI_PORT_STAT_IP_OUT_UCAST_PKTS]

        if get_platform() == 'clx':
            PORT_STAT_COUNTER.remove(SAI_PORT_STAT_IF_IN_PIPELINE_DISCARDS)
            PORT_STAT_COUNTER.remove(SAI_PORT_STAT_IF_OUT_PIPELINE_DISCARDS)


        attr = sai_thrift_get_switch_attribute(self.client,
                                        number_of_active_ports=True)
        print(attr)
        self.assertNotEqual(attr["number_of_active_ports"], 0)
        self.assertNotEqual(attr["SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS"], 0)
        active_ports = attr["number_of_active_ports"]

        attr = sai_thrift_get_switch_attribute(
            self.client,
            port_list=sai_thrift_object_list_t(idlist=[], count=active_ports))
        print(attr)
        self.assertNotEqual(attr["port_list"].count, 0)
        self.assertNotEqual(attr["SAI_SWITCH_ATTR_PORT_LIST"].count, 0)

        result = {}
        test_count = 10
        test_time = []
        for i in range(test_count):
            if self.get_timetxt() :
                time1 = int(self.get_timetxt())
            else:
                time1 = 0.0
            sai_time = 0.0
            real_time = 0.0
            for port in self.port_list:
                try:
                    batch_start = time.perf_counter()
                    self.client.sai_thrift_get_port_stats(port,PORT_STAT_COUNTER)
                    batch_end = time.perf_counter()
                    sai_time += (batch_end - batch_start)
                except Exception as e:
                    print(f"get port {port} stats fail {str(e)}")
            # print(f"ptf time {sai_time} s")

            time2 = int(self.get_timetxt())
            real_time = (time2 - time1)/1000000
            test_time.append(real_time)

            print(f"sai real time {real_time} s ")
        print(f"sai test time {test_time} s ")
        real_time = sum(test_time)/len(test_time)
        print(f"sai average test time {real_time} s ")

        perf = self._report_counter_perf( active_ports ,real_time)

        self.record_spec("port_counter_read", "read", count=active_ports,
                         actual_value=round(perf, 6),
                         duration=round(real_time, 3))

        result = {
            'count': len(self.port_list),
            'sai_real_time':real_time,
            'ptf_time':sai_time,
            'perf':perf
        }

        self.print_time_result(result, f"get  {len(self.port_list)} port counter Test result")

        # self.remove_timetxt()
        print("\tok")



class CollectQueueCountersTest(SaiHelperScaleL3):


    def setUp(self):
        # kill_saiserver()
        # print(f"killed\n" + "-"*50)
        # time.sleep(10)
        # pid = start_saiserver()
        # self.remove_timetxt()
        # print(f"saiserver start PID:{pid}")

        super(CollectQueueCountersTest, self).setUp()
        self.queue_list = []
        self.queue_list_pop_id = []
        self.queue_list_new = []
        self.expected_perf = 0.1

    def runTest(self):
        print("Starting queue counter test...")
        QUEUE_STAT_COUNTER = [
            SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS,
            SAI_QUEUE_STAT_PIPELINE_DROPPED_PACKETS,
            SAI_QUEUE_STAT_MEMORY_DROPPED_PACKETS,
            SAI_QUEUE_STAT_BYTES,
            SAI_QUEUE_STAT_PACKETS]

        if get_platform() == 'clx':
            QUEUE_STAT_COUNTER.remove(SAI_QUEUE_STAT_PIPELINE_DROPPED_PACKETS)
            QUEUE_STAT_COUNTER.remove(SAI_QUEUE_STAT_MEMORY_DROPPED_PACKETS)


        attr = sai_thrift_get_switch_attribute(self.client,
                                        number_of_active_ports=True)
        print(attr)
        self.assertNotEqual(attr["number_of_active_ports"], 0)
        self.assertNotEqual(attr["SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS"], 0)
        active_ports = attr["number_of_active_ports"]

        attr = sai_thrift_get_switch_attribute(
            self.client,
            port_list=sai_thrift_object_list_t(idlist=[], count=active_ports))
        print(attr)
        self.assertNotEqual(attr["port_list"].count, 0)
        self.assertNotEqual(attr["SAI_SWITCH_ATTR_PORT_LIST"].count, 0)


        attr = sai_thrift_get_switch_attribute(self.client,
                                        number_of_queues=True)
        print(attr)
        self.assertNotEqual(attr["number_of_queues"], 0)
        self.assertNotEqual(attr["SAI_SWITCH_ATTR_NUMBER_OF_QUEUES"], 0)
        port_queue_num = attr["number_of_queues"]

        for port in self.port_list:
            try:
                attr = sai_thrift_get_port_attribute(
                    self.client, port, qos_number_of_queues=True)
                qos_number_of_queues = attr['qos_number_of_queues']

                sai_list = sai_thrift_u32_list_t(count=20, uint32list=[])
                attr = sai_thrift_get_port_attribute(
                    self.client, port, qos_queue_list=sai_list)
                self.assertEqual(
                    attr['qos_queue_list'].count,
                    qos_number_of_queues)

                self.queue_list.extend(attr['qos_queue_list'].idlist)

            except Exception as e:
                print(f"get port {port} queue_list fail {str(e)}")

        for i,queue_id in enumerate(self.queue_list):
            try:
                self.client.sai_thrift_get_queue_stats(queue_id, QUEUE_STAT_COUNTER)
                self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            except Exception as e:
                print(f"get queue {queue_id} stats fail {str(e)}")
                self.queue_list_pop_id.append(queue_id)

        self.queue_list_new = [x for x in self.queue_list if x not in self.queue_list_pop_id]

        result = {}
        test_count = 10
        test_time = []
        for i in range(test_count):
            if self.get_timetxt() :
                time1 = int(self.get_timetxt())
            else:
                time1 = 0.0
            sai_time = 0.0
            real_time = 0.0
            for queue_id in self.queue_list_new:
                try:
                    batch_start = time.perf_counter()
                    self.client.sai_thrift_get_queue_stats(queue_id,QUEUE_STAT_COUNTER)
                    batch_end = time.perf_counter()
                    sai_time += (batch_end - batch_start)
                except Exception as e:
                    print(f"get queue {queue_id} stats fail {str(e)}")

            # print(f"ptf time {sai_time} s")

            time2 = int(self.get_timetxt())
            real_time = (time2 - time1)/1000000

            print(f"sai real time {real_time} s ")
            test_time.append(real_time)

        print(f"sai test time {test_time} s ")
        real_time = sum(test_time)/len(test_time)
        print(f"sai average test time {real_time} s ")

        perf = self._report_counter_perf( len(self.queue_list_new) ,real_time)

        self.record_spec("queue_counter_read", "read",
                         count=len(self.queue_list_new),
                         actual_value=round(perf, 6),
                         duration=round(real_time, 3))

        result = {
            'count': len(self.queue_list_new),
            'sai_real_time':real_time,
            'ptf_time':sai_time,
            'perf':perf
        }

        self.print_time_result(result, f"get  {len(self.queue_list_new)} queue counter Test result")
        print("\tok")



class CollectQueueWaterMarkCountersTest(SaiHelperScaleL3):


    def setUp(self):
        # kill_saiserver()
        # print(f"killed\n" + "-"*50)

        # time.sleep(10)

        # pid = start_saiserver()
        # print(f"saiserver start PID:{pid}")
        # self.remove_timetxt()
        super(CollectQueueWaterMarkCountersTest, self).setUp()
        self.queue_list = []
        self.queue_list_pop_id = []
        self.queue_list_new = []
        self.expected_perf = 0.1

    def runTest(self):
        print("Starting queue WaterMark counter test...")
        QUEUE_WATERMARK_STAT_COUNTER = [
            SAI_QUEUE_STAT_WATERMARK_BYTES]

        attr = sai_thrift_get_switch_attribute(self.client,
                                        number_of_active_ports=True)
        print(attr)
        self.assertNotEqual(attr["number_of_active_ports"], 0)
        self.assertNotEqual(attr["SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS"], 0)
        active_ports = attr["number_of_active_ports"]

        attr = sai_thrift_get_switch_attribute(
            self.client,
            port_list=sai_thrift_object_list_t(idlist=[], count=active_ports))
        print(attr)
        self.assertNotEqual(attr["port_list"].count, 0)
        self.assertNotEqual(attr["SAI_SWITCH_ATTR_PORT_LIST"].count, 0)


        attr = sai_thrift_get_switch_attribute(self.client,
                                        number_of_queues=True)
        print(attr)
        self.assertNotEqual(attr["number_of_queues"], 0)
        self.assertNotEqual(attr["SAI_SWITCH_ATTR_NUMBER_OF_QUEUES"], 0)

        for port in self.port_list:
            try:
                attr = sai_thrift_get_port_attribute(
                    self.client, port, qos_number_of_queues=True)
                qos_number_of_queues = attr['qos_number_of_queues']

                sai_list = sai_thrift_u32_list_t(count=20, uint32list=[])
                attr = sai_thrift_get_port_attribute(
                    self.client, port, qos_queue_list=sai_list)
                self.assertEqual(
                    attr['qos_queue_list'].count,
                    qos_number_of_queues)

                self.queue_list.extend(attr['qos_queue_list'].idlist)

            except Exception as e:
                print(f"get port {port}queue_list fail {str(e)}")
        for i,queue_id in enumerate(self.queue_list):
            try:
                self.client.sai_thrift_get_queue_stats(queue_id,QUEUE_WATERMARK_STAT_COUNTER)
                self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            except Exception as e:
                print(f"get queue {queue_id} stats fail {str(e)}")
                self.queue_list_pop_id.append(queue_id)

        self.queue_list_new = [x for x in self.queue_list if x not in self.queue_list_pop_id]
        result = {}
        test_count = 10
        test_time = []
        for i in range(test_count):

            if self.get_timetxt() :
                time1 = int(self.get_timetxt())
            else:
                time1 = 0.0

            sai_read_time = 0.0
            real_read_time = 0.0
            for queue_id in self.queue_list_new:
                try:
                    batch_start = time.perf_counter()
                    self.client.sai_thrift_get_queue_stats(queue_id,QUEUE_WATERMARK_STAT_COUNTER)
                    batch_end = time.perf_counter()
                    sai_read_time += (batch_end - batch_start)
                except Exception as e:
                    print(f"get queue {queue_id} stats fail {str(e)}")
            # print(f" ptf_read_time {sai_read_time} s")

            time2 = int(self.get_timetxt())
            real_read_time = (time2 - time1)/1000000
            test_time.append(real_read_time)
            print(f"sai real read time {real_read_time} s ")
        print(f"sai test time {test_time} s ")
        real_read_time = sum(test_time)/len(test_time)
        print(f"sai average test time {real_read_time} s ")

        perf = self._report_counter_perf( len(self.queue_list_new) ,real_read_time)

        self.record_spec("queue_watermark_counter_read", "read",
                         count=len(self.queue_list_new),
                         actual_value=round(perf, 6),
                         duration=round(real_read_time, 3))

        result = {
            'count': len(self.queue_list_new),
            'sai_real_time':real_read_time,
            'ptf_time':sai_read_time,
            'perf':perf
        }

        self.print_time_result(result, f"get  {len(self.queue_list_new)}queue WaterMark counter Test result")

        result = {}
        test_count = 10
        test_time = []
        for i in range(test_count):

            if self.get_timetxt() :
                time1 = int(self.get_timetxt())
            else:
                time1 = 0.0
            real_clear_time = 0.0
            sai_clear_time = 0.0
            for queue_id in self.queue_list_new:
                try:
                    batch_start = time.perf_counter()
                    self.client.sai_thrift_clear_queue_stats(queue_id,QUEUE_WATERMARK_STAT_COUNTER)
                    batch_end = time.perf_counter()
                    sai_clear_time += (batch_end - batch_start)
                except Exception as e:
                    print(f"get queue {queue_id} stats fail {str(e)}")

            # print(f"ptf clear time {sai_clear_time} s")
            time2 = int(self.get_timetxt())
            real_clear_time = (time2 - time1)/1000000
            test_time.append(real_clear_time)
            print(f"sai real clear time {real_clear_time} s ")

        print(f"sai test time {test_time} s ")
        real_clear_time = sum(test_time)/len(test_time)
        print(f"sai average test time {real_clear_time} s ")

        perf = self._report_counter_perf(len(self.queue_list_new) ,(real_read_time+real_clear_time))

        # "clear" here is the full read+clear cycle per queue, matching the
        # existing perf computation and the registry description.
        self.record_spec("queue_watermark_counter_read", "clear",
                         count=len(self.queue_list_new),
                         actual_value=round(perf, 6),
                         duration=round(real_read_time + real_clear_time, 3))

        result = {
            'count': len(self.queue_list_new),
            'sai_real_time':(real_read_time+real_clear_time),
            'ptf_time':(sai_clear_time+sai_read_time),
            'perf':perf
        }

        self.print_time_result(result, f"read and clear {len(self.queue_list_new)} queue WaterMark counter Test result")

        self.remove_timetxt()
        print("\tok")


class CollectPGCountersTest(SaiHelperScaleL3):


    def setUp(self):
        # kill_saiserver()
        # print(f"killed\n" + "-"*50)

        # time.sleep(10)

        # pid = start_saiserver()
        # print(f"saiserver start PID:{pid}")
        # self.remove_timetxt()
        super(CollectPGCountersTest, self).setUp()
        self.ingress_priority_group_list = []
        self.ingress_priority_group_list_pop_id = []
        self.ingress_priority_group_list_new = []
        self.expected_perf = 0.1

    def runTest(self):
        print("Starting PG counter test...")
        PG_STAT_COUNTER = [
            SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS,
            SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS]

        if get_platform() == 'clx':
            PG_STAT_COUNTER.remove(SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS)

        attr = sai_thrift_get_switch_attribute(self.client,
                                        number_of_active_ports=True)
        print(attr)
        self.assertNotEqual(attr["number_of_active_ports"], 0)
        self.assertNotEqual(attr["SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS"], 0)
        active_ports = attr["number_of_active_ports"]

        attr = sai_thrift_get_switch_attribute(
            self.client,
            port_list=sai_thrift_object_list_t(idlist=[], count=active_ports))
        print(attr)
        self.assertNotEqual(attr["port_list"].count, 0)
        self.assertNotEqual(attr["SAI_SWITCH_ATTR_PORT_LIST"].count, 0)

        for port in self.port_list:
            try:
                attr = sai_thrift_get_port_attribute(
                            self.client,
                            port,
                            number_of_ingress_priority_groups=True)
                number_of_pg = attr['number_of_ingress_priority_groups']

                attr = sai_thrift_get_port_attribute(
                            self.client, port,
                            ingress_priority_group_list=sai_thrift_object_list_t(idlist=[], count=number_of_pg))
                self.assertEqual(attr['ingress_priority_group_list'].count,
                                number_of_pg)

                self.ingress_priority_group_list.extend(attr['ingress_priority_group_list'].idlist)

            except Exception as e:
                print(f"get port {port} pg list fail {str(e)}")
        for i,pg_id in enumerate(self.ingress_priority_group_list):
            try:
                self.client.sai_thrift_get_ingress_priority_group_stats(pg_id,PG_STAT_COUNTER)
                self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            except Exception as e:
                print(f"get priority group {pg_id} stats fail {str(e)}")
                self.ingress_priority_group_list_pop_id.append(pg_id)

        self.ingress_priority_group_list_news = [x for x in self.ingress_priority_group_list if x not in self.ingress_priority_group_list_pop_id]

        result = {}
        test_count = 10
        test_time = []
        for i in range(test_count):
            if self.get_timetxt() :
                time1 = int(self.get_timetxt())
            else:
                time1 = 0.0
            sai_time = 0.0
            real_time = 0.0
            for pg_id in self.ingress_priority_group_list_news:
                try:
                    batch_start = time.perf_counter()
                    self.client.sai_thrift_get_ingress_priority_group_stats(pg_id,PG_STAT_COUNTER)
                    batch_end = time.perf_counter()
                    sai_time += (batch_end - batch_start)
                except Exception as e:
                    print(f"get priority group {pg_id} stats fail {str(e)}")


            # print(f"ptf time {sai_time} s")

            time2 = int(self.get_timetxt())
            real_time = (time2 - time1)/1000000
            test_time.append(real_time)
            print(f"sai real time {real_time} s ")

        print(f"sai test time {test_time} s ")
        real_time = sum(test_time)/len(test_time)
        print(f"sai average test time {real_time} s ")

        perf = self._report_counter_perf( len( self.ingress_priority_group_list_news) ,real_time)

        self.record_spec("pg_counter_read", "read",
                         count=len(self.ingress_priority_group_list_news),
                         actual_value=round(perf, 6),
                         duration=round(real_time, 3))

        result = {
            'count': len( self.ingress_priority_group_list_news),
            'sai_real_time':real_time,
            'ptf_time':sai_time,
            'perf':perf
        }

        self.print_time_result(result, f"get {len( self.ingress_priority_group_list_news)} ingress priority group counter Test result")

        print("\tok")

class CollectPGWaterMarkCountersTest(SaiHelperScaleL3):


    def setUp(self):
        # kill_saiserver()
        # print(f"killed\n" + "-"*50)

        # time.sleep(10)

        # pid = start_saiserver()
        # print(f"saiserver start PID:{pid}")
        # self.remove_timetxt()
        super(CollectPGWaterMarkCountersTest, self).setUp()
        self.ingress_priority_group_list = []
        self.ingress_priority_group_list_pop_id = []
        self.ingress_priority_group_list_new = []
        self.expected_perf = 0.1

    def runTest(self):
        print("Starting PG WaterMark counter test...")
        PG_WATERMARK_STAT_COUNTER = [
            SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES,
            SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES]


        attr = sai_thrift_get_switch_attribute(self.client,
                                        number_of_active_ports=True)
        print(attr)
        self.assertNotEqual(attr["number_of_active_ports"], 0)
        self.assertNotEqual(attr["SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS"], 0)
        active_ports = attr["number_of_active_ports"]

        attr = sai_thrift_get_switch_attribute(
            self.client,
            port_list=sai_thrift_object_list_t(idlist=[], count=active_ports))
        print(attr)
        self.assertNotEqual(attr["port_list"].count, 0)
        self.assertNotEqual(attr["SAI_SWITCH_ATTR_PORT_LIST"].count, 0)

        for port in self.port_list:
            try:
                attr = sai_thrift_get_port_attribute(
                            self.client,
                            port,
                            number_of_ingress_priority_groups=True)
                number_of_pg = attr['number_of_ingress_priority_groups']

                attr = sai_thrift_get_port_attribute(
                            self.client, port,
                            ingress_priority_group_list=sai_thrift_object_list_t(idlist=[], count=number_of_pg))
                self.assertEqual(attr['ingress_priority_group_list'].count,
                                number_of_pg)

                self.ingress_priority_group_list.extend(attr['ingress_priority_group_list'].idlist)

            except Exception as e:
                print(f"get port {port} pg list fail {str(e)}")
        for i,pg_id in enumerate(self.ingress_priority_group_list):
            try:
                self.client.sai_thrift_get_ingress_priority_group_stats(pg_id,PG_WATERMARK_STAT_COUNTER)
                self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            except Exception as e:
                print(f"get priority group {pg_id} stats fail {str(e)}")
                self.ingress_priority_group_list_pop_id.append(pg_id)

        self.ingress_priority_group_list_news = [x for x in self.ingress_priority_group_list if x not in self.ingress_priority_group_list_pop_id]

        result = {}
        test_count = 10
        test_time = []
        for i in range(test_count):
            if self.get_timetxt() :
                time1 = int(self.get_timetxt())
            else:
                time1 = 0.0

            sai_read_time = 0.0
            real_read_time = 0.0

            for pg_id in self.ingress_priority_group_list_news:
                try:
                    batch_start = time.perf_counter()
                    self.client.sai_thrift_get_ingress_priority_group_stats(pg_id,PG_WATERMARK_STAT_COUNTER)
                    batch_end = time.perf_counter()
                    sai_read_time += (batch_end - batch_start)
                except Exception as e:
                    print(f"get priority group {pg_id} stats fail {str(e)}")

            # print(f"ptf read  time {sai_read_time}")
            time2 = int(self.get_timetxt())
            real_read_time = (time2 - time1)/1000000
            test_time.append(real_read_time)
            print(f"sai real read time {real_read_time} s ")
        print(f"sai test time {test_time} s ")
        real_read_time = sum(test_time)/len(test_time)
        print(f"sai average test time {real_read_time} s ")

        perf = self._report_counter_perf(len(self.ingress_priority_group_list_news)  ,real_read_time)

        self.record_spec("pg_watermark_counter_read", "read",
                         count=len(self.ingress_priority_group_list_news),
                         actual_value=round(perf, 6),
                         duration=round(real_read_time, 3))

        result = {
            'count': len(self.ingress_priority_group_list_news) ,
            'sai_real_time':real_read_time,
            'ptf_time':sai_read_time,
            'perf':perf
        }

        self.print_time_result(result, f"get {len(self.ingress_priority_group_list_news)} PG WaterMark counter Test result")
        result = {}
        test_count = 10
        test_time = []
        for i in range(test_count):
            if self.get_timetxt() :
                time1 = int(self.get_timetxt())
            else:
                time1 = 0.0
            real_clear_time = 0.0
            sai_clear_time = 0.0
            for pg_id in self.ingress_priority_group_list_news:
                try:
                    batch_start = time.perf_counter()
                    self.client.sai_thrift_clear_ingress_priority_group_stats(pg_id,PG_WATERMARK_STAT_COUNTER)
                    batch_end = time.perf_counter()
                    sai_clear_time += (batch_end - batch_start)
                except Exception as e:
                    print(f"get priority group {pg_id} stats fail {str(e)}")

            # print(f"ptf clear time {sai_clear_time} s")
            time2 = int(self.get_timetxt())
            real_clear_time = (time2 - time1)/1000000
            test_time.append(real_clear_time)
            print(f"sai real clear time {real_clear_time} s ")

        print(f"sai test time {test_time} s ")
        real_clear_time = sum(test_time)/len(test_time)
        print(f"sai average test time {real_clear_time} s ")

        perf = self._report_counter_perf(len(self.ingress_priority_group_list_news) ,(real_read_time+real_clear_time))

        # "clear" here is the full read+clear cycle per PG, matching the
        # existing perf computation and the registry description.
        self.record_spec("pg_watermark_counter_read", "clear",
                         count=len(self.ingress_priority_group_list_news),
                         actual_value=round(perf, 6),
                         duration=round(real_read_time + real_clear_time, 3))

        result = {
            'count': len(self.ingress_priority_group_list_news),
            'sai_real_time':(real_read_time+real_clear_time),
            'ptf_time':(sai_clear_time+sai_read_time),
            'perf':perf
        }

        self.print_time_result(result, f"read and clear  {len(self.ingress_priority_group_list_news) }PG WaterMarkcounter Test result")

        print("\tok")


class CollectPolicerCountersTest(SaiHelperScaleL3):


    def setUp(self):
        # kill_saiserver()
        # print(f"killed\n" + "-"*50)

        # time.sleep(10)

        # pid = start_saiserver()
        # print(f"saiserver start PID:{pid}")
        # self.remove_timetxt()
        super(CollectPolicerCountersTest, self).setUp()
        self.expected_perf = 0.1

    def runTest(self):
        print("Starting Policer counter test...")
        POLICER_STAT_COUNTER = [
            SAI_POLICER_STAT_PACKETS,
            SAI_POLICER_STAT_ATTR_BYTES,
            SAI_POLICER_STAT_GREEN_PACKETS,
            SAI_POLICER_STAT_GREEN_BYTES,
            SAI_POLICER_STAT_YELLOW_PACKETS,
            SAI_POLICER_STAT_YELLOW_BYTES,
            SAI_POLICER_STAT_RED_PACKETS,
            SAI_POLICER_STAT_RED_BYTES]
        if get_platform() == 'mlnx':
            # MLNX guarantees only the aggregate packet counter here.
            POLICER_STAT_COUNTER = [SAI_POLICER_STAT_PACKETS]

        self.table_stage = (SAI_ACL_STAGE_INGRESS if get_platform() == 'brcm'
                            else SAI_ACL_STAGE_EGRESS)
        bind_points = [SAI_ACL_BIND_POINT_TYPE_PORT]
        action_types = [SAI_ACL_ACTION_TYPE_PACKET_ACTION,SAI_ACL_ACTION_TYPE_SET_POLICER,SAI_ACL_ACTION_TYPE_COUNTER]

        bind_points_list = sai_thrift_s32_list_t(count=len(bind_points),
                                            int32list=bind_points)

        action_types_list = sai_thrift_s32_list_t(count=len(action_types),
                                                    int32list=action_types)

        self.group_type = SAI_ACL_TABLE_GROUP_TYPE_PARALLEL
        self.acl_table_group_Egr = sai_thrift_create_acl_table_group(self.client, self.table_stage,bind_points_list, self.group_type)
        assert(self.acl_table_group_Egr != SAI_NULL_OBJECT_ID)

        acl_table = sai_thrift_create_acl_table(
            self.client,
            acl_stage=self.table_stage,
            acl_bind_point_type_list=bind_points_list,
            acl_action_type_list=action_types_list,
            size=256,
            field_ip_protocol=True,
            field_acl_ip_type=True,
            field_src_ip=True,
            field_dst_ip=True,
            field_l4_src_port=True,
            field_l4_dst_port=True,
            field_dscp=True,
            field_ecn=True,
            field_tcp_flags=True,
            field_acl_ip_frag=True,
            field_outer_vlan_id=True,
            field_out_port=True)

        L3Egr_group_member_priority = 100
        #Create L3Egr_acl_table as ACL table group member
        L3Egr_acl_table_group_member = sai_thrift_create_acl_table_group_member(
            self.client,
            self.acl_table_group_Egr,
            acl_table,
            L3Egr_group_member_priority)

        mode_list = [SAI_POLICER_MODE_SR_TCM]
        cir_list = [10,12,14,16,18]
        pir_list = [20,22,24,26,28]
        cbs_list = [40]
        pbs_list = [60]

        TestCase = namedtuple(
            "TestCase", ["mode", "meter_type", "color_source","cir","pir","pbs","cbs"])

        test_cases = [
            TestCase(mode, meter_type, color_source,cir,pir,pbs,cbs)
            for mode in mode_list
            for meter_type in range(SAI_METER_TYPE_BYTES + 1)
            for color_source in range(SAI_POLICER_COLOR_SOURCE_AWARE + 1)
            for cir in cir_list
            for pir in pir_list
            for cbs in cbs_list
            for pbs in pbs_list]

        action_list = [SAI_PACKET_ACTION_DROP]
        counter_packet_action_list = sai_thrift_s32_list_t(count=len(action_list),
                                                            int32list=action_list)

        pol_ids = []
        acl_entry_ids = []
        for test_case in test_cases:
            print("Create policer for", test_case)

            policer_attrs = dict(
                mode=test_case.mode,
                meter_type=test_case.meter_type,
                color_source=test_case.color_source,
                cir=test_case.cir,
                cbs=test_case.cbs,
                pbs=test_case.pbs)
            if (get_platform() == 'mlnx' and
                    test_case.meter_type == SAI_METER_TYPE_BYTES):
                # Preserve the test values using MLNX rate/burst granularity.
                policer_attrs.update(
                    cir=test_case.cir * 125,
                    cbs=test_case.cbs * 64,
                    pbs=test_case.pbs * 64)
            # MLNX and BRCM reject this optional counter-selection attribute.
            if get_platform() not in ('mlnx', 'brcm'):
                policer_attrs["enable_counter_packet_action_list"] = \
                    counter_packet_action_list
            # SAI_POLICER_ATTR_PIR is valid only for TR_TCM mode.
            if test_case.mode == SAI_POLICER_MODE_TR_TCM:
                policer_attrs["pir"] = test_case.pir
            pol_id = sai_thrift_create_policer(
                self.client, **policer_attrs)

            pol_ids.append(pol_id)

            print("Created policer with id:", pol_id)
            self.assertNotEqual(pol_id, SAI_NULL_OBJECT_ID)

        ip_type = SAI_ACL_IP_TYPE_IPV4ANY
        ip_type_t = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(s32=ip_type),
            mask=sai_thrift_acl_field_data_mask_t(s32=-1))

        for i,pol_id in enumerate(pol_ids):
            print("Create ACL entry with action_set_policer")
            param = sai_thrift_acl_action_parameter_t(oid=pol_id)
            obj_acl_action_data = sai_thrift_acl_action_data_t(enable=True,parameter=param)

            src_l4_port = sai_thrift_acl_field_data_t(
                enable=True,
                data=sai_thrift_acl_field_data_data_t(u16=3000+i),
                mask=sai_thrift_acl_field_data_mask_t(u16=32767))

            acl_entry_id = sai_thrift_create_acl_entry(
                self.client, table_id=acl_table, priority=10,field_l4_src_port=src_l4_port,field_acl_ip_type=ip_type_t,
                action_set_policer=obj_acl_action_data)
            self.assertNotEqual(acl_entry_id, SAI_NULL_OBJECT_ID)
            acl_entry_ids.append(acl_entry_id)
        print("Bind ACL table to port")
        if self.table_stage == SAI_ACL_STAGE_INGRESS:
            status = sai_thrift_set_port_attribute(
                self.client, self.port_list[0],
                ingress_acl=self.acl_table_group_Egr)
        else:
            status = sai_thrift_set_port_attribute(
                self.client, self.port_list[0],
                egress_acl=self.acl_table_group_Egr)
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        result = {}

        test_count = 10
        test_time = []
        for i in range(test_count):

            if self.get_timetxt() :
                time1 = int(self.get_timetxt())
            else:
                time1 = 0.0
            sai_time = 0.0
            real_time = 0.0
            for i,pol_id in enumerate(pol_ids):
                try:
                    batch_start = time.perf_counter()
                    sai_thrift_get_policer_stats(self.client,pol_id,POLICER_STAT_COUNTER)
                    batch_end = time.perf_counter()
                    sai_time += (batch_end - batch_start)

                except Exception as e:
                    print(f"get policer  {pol_id}）stats fail {str(e)}")

            # print(f"ptf time {sai_time} s")

            time2 = int(self.get_timetxt())
            real_time = (time2 - time1)/1000000
            test_time.append(real_time)
            print(f"sai real time {real_time} s ")

        print(f"sai test time {test_time} s ")
        real_time = sum(test_time)/len(test_time)
        print(f"sai average test time {real_time} s ")

        perf = self._report_counter_perf( len(pol_ids) ,real_time)

        self.record_spec("policer_counter_read", "read", count=len(pol_ids),
                         actual_value=round(perf, 6),
                         duration=round(real_time, 3))

        result = {
            'count': len(pol_ids),
            'sai_real_time':real_time,
            'ptf_time':sai_time,
            'perf':perf
        }

        self.print_time_result(result, f"get  {len(pol_ids)}policer counter Test result")
        print("\tok")

        if self.table_stage == SAI_ACL_STAGE_INGRESS:
            sai_thrift_set_port_attribute(
                self.client, self.port_list[0], ingress_acl=0)
        else:
            sai_thrift_set_port_attribute(
                self.client, self.port_list[0], egress_acl=0)
        for acl_entry in acl_entry_ids:
            sai_thrift_remove_acl_entry(self.client, acl_entry)
        sai_thrift_remove_acl_table(self.client, acl_table)
        for pol_id in pol_ids:
            sai_thrift_remove_policer(self.client, pol_id)


class CollectACLCountersTest(SaiHelperScaleL3):
    def setUp(self):
        #kill_saiserver()
        #print(f"killed\n" + "-"*50)

        #time.sleep(10)

        #pid = start_saiserver()
        #print(f"saiserver start PID:{pid}")
        #self.remove_timetxt()
        super(CollectACLCountersTest, self).setUp()
        self.expected_perf = 0.1

    def runTest(self):
        print("\CollectACLCountersTest()")
        COUNTER_STAT = [
            SAI_COUNTER_STAT_PACKETS,
            SAI_COUNTER_STAT_BYTES]


        group_stage = SAI_ACL_STAGE_INGRESS
        group_bind_points = [SAI_ACL_BIND_POINT_TYPE_PORT]
        group_bind_point_type_list = sai_thrift_s32_list_t(
            count=len(group_bind_points), int32list=group_bind_points)
        group_type = SAI_ACL_TABLE_GROUP_TYPE_PARALLEL

        acl_group = sai_thrift_create_acl_table_group(
            self.client,
            acl_stage=group_stage,
            acl_bind_point_type_list=group_bind_point_type_list,
            type=group_type)

        self.table_entry_num = 512
        self.egress_table_entry_num = 256


        stage = SAI_ACL_STAGE_INGRESS
        bind_point = SAI_ACL_BIND_POINT_TYPE_PORT

        acl_table_l3 = sai_thrift_create_acl_table(
            self.client,
            acl_stage=stage,
            size = self.table_entry_num,
            acl_bind_point_type_list=sai_thrift_s32_list_t(
                count=1, int32list=[bind_point]),
            acl_action_type_list=sai_thrift_s32_list_t(
                count=2, int32list=[SAI_ACL_ACTION_TYPE_PACKET_ACTION,
                                    SAI_ACL_ACTION_TYPE_COUNTER]),
            field_l4_src_port=True,
            field_l4_dst_port=True,
            field_acl_ip_type=True,
            field_ip_protocol=True,
            field_src_ip=True,
            field_dst_ip=True,
            field_dscp=True,
            field_ecn=True,
            field_tcp_flags=True,
            field_in_ports=True,
            field_acl_ip_frag=True)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)


        if  stage == SAI_ACL_STAGE_EGRESS:
            acl_table = sai_thrift_create_acl_table(
                self.client,
                acl_stage=stage,
                size = self.egress_table_entry_num,
                acl_bind_point_type_list=sai_thrift_s32_list_t(
                    count=1, int32list=[bind_point]),
                field_l4_src_port=True,
                field_l4_dst_port=True,
                field_acl_ip_type=True,
                field_src_ip=True,
                field_dst_ip=True,
                field_dscp=True,
                field_ecn=True,
                field_tcp_flags=True,
                field_out_ports=True)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)


        acl_table_group_member = sai_thrift_create_acl_table_group_member(
            self.client,
            acl_table_group_id=acl_group,
            acl_table_id=acl_table_l3,
            priority = 100)

        acl_entry_list = []
        acl_counter_list = []
        ip_type = SAI_ACL_IP_TYPE_IPV4ANY
        ip_type_mask = -1

        for counter in range(0,512):

            self.l4_dst_port = random.randint(0, 4096)
            self.l4_src_port = random.randint(0, 4096)

            l4_dst_port_mask = 32759
            l4_dst_port_t = sai_thrift_acl_field_data_t(
                enable=True,
                data=sai_thrift_acl_field_data_data_t(u16=self.l4_dst_port),
                mask=sai_thrift_acl_field_data_mask_t(u16=l4_dst_port_mask))

            l4_src_port_mask = 32759
            l4_src_port_t = sai_thrift_acl_field_data_t(
                enable=True,
                data=sai_thrift_acl_field_data_data_t(u16=self.l4_src_port),
                mask=sai_thrift_acl_field_data_mask_t(u16=l4_src_port_mask))

            acl_ip_type  = sai_thrift_acl_field_data_t(
                enable=True,
                data=sai_thrift_acl_field_data_data_t(s32=ip_type),
                mask=sai_thrift_acl_field_data_mask_t(s32=ip_type_mask))


            packet_action = sai_thrift_acl_action_data_t(
                enable=True,
                parameter=sai_thrift_acl_action_parameter_t(
                    s32=SAI_PACKET_ACTION_DROP))


            acl_entry_id = sai_thrift_create_acl_entry(
                self.client,
                table_id=acl_table_l3,
                action_packet_action=packet_action,
                field_l4_dst_port=l4_dst_port_t,
                field_l4_src_port=l4_src_port_t,
                field_acl_ip_type = acl_ip_type)
            acl_entry_list.append(acl_entry_id)


            # create ACL counter
            acl_counter_ingress = sai_thrift_create_acl_counter(
                self.client, table_id=acl_table_l3,enable_packet_count=True, enable_byte_count=True)

            if acl_counter_ingress != 0:
                # attach ACL counter to ACL entry
                action_counter_ingress = sai_thrift_acl_action_data_t(
                    parameter=sai_thrift_acl_action_parameter_t(
                        oid=acl_counter_ingress),
                    enable=True)
                sai_thrift_set_acl_entry_attribute(
                    self.client, acl_entry_id,
                    action_counter=action_counter_ingress)
                acl_counter_list.append(acl_counter_ingress)

            else:
                break

        status = sai_thrift_set_port_attribute(
            self.client, self.port_list[0], ingress_acl=acl_group)

        result = {}
        test_count = 10
        test_time = []
        for i in range(test_count):

            if self.get_timetxt() :
                time1 = int(self.get_timetxt())
            else:
                time1 = 0.0

            sai_read_time = 0.0
            real_read_time = 0.0

            for index, acl_counter in enumerate(acl_counter_list):

                batch_start = time.perf_counter()
                sai_thrift_get_acl_counter_attribute(self.client, acl_counter, packets=True,bytes=True)
                batch_end = time.perf_counter()
                sai_read_time += (batch_end - batch_start)

            time2 = int(self.get_timetxt())
            real_read_time = (time2 - time1)/1000000
            print(f"sai read  time {real_read_time}")
            test_time.append(real_read_time)

        print(f"sai test time {test_time} s ")
        real_read_time = sum(test_time)/len(test_time)
        print(f"sai average test time {real_read_time} s ")

        perf = self._report_counter_perf( len(acl_counter_list) ,real_read_time)

        self.record_spec("acl_counter_read", "read",
                         count=len(acl_counter_list),
                         actual_value=round(perf, 6),
                         duration=round(real_read_time, 3))

        result = {
            'count': len(acl_counter_list) ,
            'sai_real_time':real_read_time,
            'ptf_time':sai_read_time,
            'perf':perf
        }

        self.print_time_result(result, f"get {len(acl_counter_list)} acl counter Test result")

        sai_thrift_set_port_attribute(
            self.client, self.port_list[0], ingress_acl=0)
        for acl_counter in acl_counter_list:
            sai_thrift_remove_acl_counter(self.client, acl_counter)
        for acl_entry in acl_entry_list:
            sai_thrift_remove_acl_entry(self.client, acl_entry)
        sai_thrift_remove_acl_table_group_member(self.client, acl_table_group_member)
        sai_thrift_remove_acl_table(self.client, acl_table_l3)
        sai_thrift_remove_acl_table_group(self.client, acl_group)
