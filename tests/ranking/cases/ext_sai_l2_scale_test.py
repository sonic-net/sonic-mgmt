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
SAI L2 Scale Test  Module
"""

from sai_thrift.sai_headers import *
from ptf.testutils import *
from sai_base_test import *
import time
import random
import ipaddress


class L2VlanStressTest(SaiHelperScaleL2):

    def setUp(self):
        super(L2VlanStressTest, self).setUp()

    def runTest(self):
        print("Starting L2 Vlan Stress test...")
        self.vlan = []
        self.vlan_member = []

        print(f"\n[ CREATE  Vlan- Performance Test]")
        start_time = time.perf_counter()
        sai_time = 0.0
        # compatible with 32/64 ptf ports config json
        max_ptf_port = len(self.port_list) - 1
        for vlan_id in range(max_ptf_port+4,4004):
            batch_start = time.perf_counter()
            vlan = sai_thrift_create_vlan(self.client, vlan_id=vlan_id)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
            batch_end = time.perf_counter()
            sai_time += (batch_end - batch_start)
            self.vlan.append(vlan)

        total_count = len(self.vlan)
        total_time = time.perf_counter() - start_time
        overall_perf, sai_perf = self._calc_and_report_perf(
            "vlans created", total_count, total_time, sai_time)
        self.record_spec("vlan_scale", "create", count=total_count,
                         actual_value=round(overall_perf, 2),
                         duration=round(total_time, 3))

        print(f"\n[ CREATE  Vlan member- Performance Test]")
        start_time = time.perf_counter()
        sai_time = 0.0
        for vlan_idx in self.vlan:
            for port_id in range(0, min(len(self.def_bridge_port_list), 64)):
                batch_start = time.perf_counter()
                vlan_member = sai_thrift_create_vlan_member(
                    self.client,
                    vlan_id=vlan_idx,
                    bridge_port_id=self.def_bridge_port_list[port_id],
                    vlan_tagging_mode=SAI_VLAN_TAGGING_MODE_TAGGED)
                batch_end = time.perf_counter()
                sai_time += (batch_end - batch_start)
                self.vlan_member.append(vlan_member)
        total_count = len(self.vlan_member)
        total_time = time.perf_counter() - start_time
        overall_perf, sai_perf = self._calc_and_report_perf(
            "vlan_members created", total_count, total_time, sai_time)
        self.record_spec("vlan_member_scale", "create", count=total_count,
                         actual_value=round(overall_perf, 2),
                         duration=round(total_time, 3))

        print(f"\n[ Remove  Vlan member- Performance Test]")
        start_time = time.perf_counter()
        sai_time = 0.0
        total_count = len(self.vlan_member)
        for vlan_member in self.vlan_member:
            batch_start = time.perf_counter()
            sai_thrift_remove_vlan_member(self.client, vlan_member)
            batch_end = time.perf_counter()
            sai_time += (batch_end - batch_start)

        total_time = time.perf_counter() - start_time
        overall_perf, sai_perf = self._calc_and_report_perf(
            "vlan_members removed", total_count, total_time, sai_time)
        self.record_spec("vlan_member_scale", "remove", count=total_count,
                         actual_value=round(overall_perf, 2),
                         duration=round(total_time, 3))

        print(f"\n[ Remove  Vlan - Performance Test]")
        start_time = time.perf_counter()
        sai_time = 0.0
        total_count = len(self.vlan)
        for vlan_oid in self.vlan:
            batch_start = time.perf_counter()
            sai_thrift_remove_vlan(self.client, vlan_oid)
            batch_end = time.perf_counter()
            sai_time += (batch_end - batch_start)

        total_time = time.perf_counter() - start_time
        overall_perf, sai_perf = self._calc_and_report_perf(
            "vlans removed", total_count, total_time, sai_time)
        self.record_spec("vlan_scale", "remove", count=total_count,
                         actual_value=round(overall_perf, 2),
                         duration=round(total_time, 3))


        print("\nAll L2 Vlan Stress tests completed successfully!")

    def tearDown(self):
        super(L2VlanStressTest, self).tearDown()


class L2FdbBurstTest(SaiHelperScaleL2):

    def setUp(self):
        super(L2FdbBurstTest, self).setUp()

    def runTest(self):

        self.expected_fill_rate = 0.95

        print("Starting L2 Fdb Burst Stress test...")
        test_count = self.get_available_fdb_entry()
        print(f"获取芯片最大可配置FDB条目数N: {test_count}")

        try:
            self.configure_bum_behavior()
            print("全局BUM行为配置为Drop")
        except Exception as e:
            print(f"配置BUM行为失败: {str(e)}")
            return

        dev_port = random.choice(self.dev_port_list)

        self.learn_pkt_list = []
        self.verfiy_pkt_list = []
        #  Generate src mac starting start_mac_addr
        #  构造并发送UDP报文
        source_mac_base = "00:00:00:00:00:01"
        source_mac_list = []
        step = 1
        # 生成 N 个源MAC，基于 "00:00:00:00:00:01" 递增
        print(f"\nGenerating {test_count} srcmac /(start: {source_mac_base}, step: {step})")
        for i in range(test_count):
            parts = list(map(lambda x: int(x, 16), source_mac_base.split(":")))
            mac_int = int.from_bytes(bytes(parts), byteorder="big")
            mac_int += i
            new_parts = list(mac_int.to_bytes(6, byteorder="big"))
            mac_addr =  ":".join(f"{b:02x}" for b in new_parts)
            source_mac_list.append(mac_addr)

        print(f"Generated {len(source_mac_list)} srcmac / (range: {source_mac_base} - {mac_addr})")

        for src_mac in source_mac_list:
            # 发送目的MAC为源MAC的UDP报文
            learn_pkt = simple_udp_packet(eth_dst='00:77:77:77:77:77',
                                            eth_src=src_mac,
                                            pktlen=100)
            verfiy_pkt = simple_udp_packet(eth_dst=src_mac,
                                        eth_src='00:77:77:77:77:77',
                                        pktlen=100)
            self.learn_pkt_list.append(learn_pkt)
            self.verfiy_pkt_list.append(verfiy_pkt)


        for pkt in self.learn_pkt_list:
            send_packet(self, dev_port, pkt)

        wait_sec = 5
        print("Waiting for switch to get ready before test, {} seconds ...".format(
            wait_sec))
        time.sleep(wait_sec)
        #  从另一个随机端口发送目的MAC报文并统计
        self.dataplane.flush()
        print(f"send {test_count} pkt for verify")

        exp_port = random.choice(list(filter(lambda item: item != dev_port, self.dev_port_list)))  # 选不同端口
        success_count = 0
        for pkt in self.verfiy_pkt_list:
            try:
                # 发送目的MAC为源MAC的UDP报文
                send_packet(self, exp_port, pkt)
                verify_packet(self, pkt, dev_port)
                success_count += 1
            except Exception as e:
                print(f"验证报文(目的MAC: {src_mac}）发送/接收失败: {str(e)}")

        print(f"\nFill Rate Results: expected_fill_rate: {self.expected_fill_rate*100}%")

        learn_ratio = success_count / test_count
        print(f"学习比例计算结果: {learn_ratio}({success_count}/{test_count})")
        if test_count > 0:
            status = "PASS" if learn_ratio >= self.expected_fill_rate else "WARNING"
            print(f"fdb fill rate: {learn_ratio*100:.3f}% - {status} fdb_total_count: {test_count}, fdb_success_cnt: {success_count}")

        print(f"actually fill rate: {learn_ratio*100:.3f}%")

        self.record_spec("fdb_entry", "", count=0, actual_value=test_count)

        print(f"flush {test_count} fdb ")
        sai_thrift_flush_fdb_entries(
            self.client,
            bv_id=self.vlan2,
            entry_type=SAI_FDB_FLUSH_ENTRY_TYPE_ALL)

        available_fdb_count_after_flush = self.get_available_fdb_entry()

        self.assertEqual(available_fdb_count_after_flush, test_count)
        print("\nAll L2 FDB Burst tests completed successfully!")

    def tearDown(self):
        super(L2FdbBurstTest, self).tearDown()


class L2FdbStressTest(SaiHelperScaleL2):

    def setUp(self):
        super(L2FdbStressTest, self).setUp()
        self.expected_fill_rate = 0.95
        self.expected_perf = 10000

    def send_at_rate(self,ports, pkts, rate):
        """按速率循环发包"""
        total = len(pkts)
        sent = 0
        sai_time = 0.0
        start = time.perf_counter()
        while sent < total:
            elapsed = time.perf_counter() - start
            expected = int(rate * elapsed)
            to_send = expected - sent
            # print(f"to send {to_send}")
            if to_send > 0:
                for _ in range(to_send):
                    port = ports[sent % len(ports)]  # 顺序轮询端口
                    pkt = pkts[sent % len(pkts)]
                    send_packet(self, port, pkt)
                    sent += 1
                    if sent > total:
                        break
            time.sleep(0.001)  # 速率微调

        sai_time = time.perf_counter() - start
        print(f"time {sai_time}")

    # def batch_generate_unicast_macs(self,count):
    #     """生成非组播MAC（避免第1字节最低位为1）"""
    #     macs = []
    #     base = [0, 0, 0, 0, 0, 1]  # 00:00:00:00:00:00
    #     for i in range(count):
    #         base[0] = i & 0xFE  # 确保非组播
    #         mac_str = ":".join(f"{b:02x}" for b in base)
    #         if mac_str not in macs:
    #             macs.append(mac_str)
    #         # MAC递增逻辑
    #         base[-1] += 1
    #         for j in range(5, -1, -1):
    #             if base[j] > 255:
    #                 base[j] = 1
    #                 base[j-1] += 1 if j > 0 else 0
    #             else:
    #                 break
    #     return macs

    def generate_unicast_mac(self):
        """生成一个随机的非组播MAC地址"""
        mac_bytes = []
        while True:
            first_byte = random.randint(0, 255)  # 0-255（0x00-0xFF）
            if (first_byte & 1) == 0:
                mac_bytes.append(first_byte)
                break

        # 生成剩余5个字节（无限制，0-255任意值）
        for _ in range(5):
            mac_bytes.append(random.randint(0, 255))

        return ':'.join(f'{b:02X}' for b in mac_bytes)


    def batch_generate_unicast_macs(self,count):

        if count <= 0:
            raise ValueError("生成数量必须为正整数")
        macs = []
        while len(macs) < count:
            mac = self.generate_unicast_mac()

            if  mac in macs: #去重
                continue

            macs.append(mac)

        return macs

    def runTest(self):

        wait_sec = 5
        print("Starting L2 Fdb Burst Stress test...")
        test_count = self.get_available_fdb_entry()
        print(f"获取芯片最大可配置FDB条目数N: {test_count}")

        try:
            self.configure_bum_behavior()
            print("全局BUM行为配置为Drop")
        except Exception as e:
            print(f"配置BUM行为失败: {str(e)}")
            return

        print("----------------------burst场景（100pps，源MAC递增） ----------------------")
        self.learn_pkt_list = []
        self.verfiy_pkt_list = []
        #  Generate src mac starting start_mac_addr
        #  构造并发送UDP报文
        source_mac_base = "00:00:00:00:00:01"
        source_mac_list = []
        # 生成 N 个源MAC，基于 "00:00:00:00:00:01" 递增

        for i in range(test_count):
            parts = list(map(lambda x: int(x, 16), source_mac_base.split(":")))
            mac_int = int.from_bytes(bytes(parts), byteorder="big")
            mac_int += i
            new_parts = list(mac_int.to_bytes(6, byteorder="big"))
            mac_addr =  ":".join(f"{b:02x}" for b in new_parts)
            source_mac_list.append(mac_addr)

        print(f"Generated {len(source_mac_list)} srcmac / (range: {source_mac_base} - {mac_addr})")
        for src_mac in source_mac_list:

            learn_pkt = simple_udp_packet(eth_dst='00:77:77:77:77:77',
                                            eth_src=src_mac,
                                            pktlen=100)
            verfiy_pkt = simple_udp_packet(eth_dst=src_mac,
                                        eth_src='00:77:77:77:77:77',
                                        pktlen=100)
            self.learn_pkt_list.append(learn_pkt)
            self.verfiy_pkt_list.append(verfiy_pkt)

        print(f"send {test_count} pkt at 100pps for learning")
        self.send_at_rate(self.dev_port_list, self.learn_pkt_list, rate=100)


        print("Waiting for switch to get ready before test, {} seconds ...".format(
            wait_sec))
        time.sleep(wait_sec)

        success_count = 0
        fail_count = 0
        self.dataplane.flush()
        print(f"send {test_count} pkt for verify")
        for i,pkt in enumerate(self.verfiy_pkt_list):
            try:
                # 从另一个随机端口发送目的MAC报文并统计
                exp_port = random.choice(list(filter(lambda item: item != self.dev_port_list[i%len(self.dev_port_list)],
                                         self.dev_port_list)))  # 选不同端口
                # 发送目的MAC为源MAC的UDP报文
                send_packet(self, exp_port, pkt)
                verify_packet(self, pkt, self.dev_port_list[i%len(self.dev_port_list)])
                success_count += 1
            except Exception as e:
                fail_count+=1
                print(f"验证报文(目的MAC: {pkt[Ether].dst}）发送/接收失败")


        print(f"\nFill Rate Results: expected_fill_rate: {self.expected_fill_rate*100}%")

        learn_ratio = success_count / test_count
        print(f"学习比例计算结果: {learn_ratio}({success_count}/{test_count})")
        if test_count > 0:
            status = "PASS" if learn_ratio >= self.expected_fill_rate else "WARNING"
            print(f"fdb fill rate: {learn_ratio*100:.3f}% - {status} fdb_total_count: {test_count}, fdb_success_cnt: {success_count}")

        print(f"actually fill rate: {learn_ratio*100:.3f}%")

        self.record_spec("fdb_entry", "", count=0, actual_value=test_count)
        self.record_spec("fdb_fill_rate", "learn", count=test_count,
                         actual_value=round(learn_ratio * 100, 2),
                         extra={"success_count": success_count,
                                "expected_fill_rate": self.expected_fill_rate})

        print(f"flush {test_count} fdb ")

        sai_time = 0.0
        start = time.perf_counter()
        sai_thrift_flush_fdb_entries(self.client,
                                     bv_id=self.vlan2,
                                     entry_type=SAI_FDB_FLUSH_ENTRY_TYPE_ALL)
        sai_time = time.perf_counter() - start
        available_fdb_count_after_flush = self.get_available_fdb_entry()

        self.assertEqual(available_fdb_count_after_flush, test_count)

        overall_perf, _sai_perf = self._calc_and_report_perf(
            "fdb flush", success_count, sai_time, sai_time)
        perf = overall_perf

        expected_perf = getattr(self, 'expected_perf', None)
        if expected_perf:
            print(f"\n{'Performance Validation':^80}")
            print(f"{'Expected Performance: ' + str(expected_perf) + ' r/s':^80}")
            print(f"{'-'*80}")

            print(f"Average Performance:")
            if perf > 0:
                status = "PASS" if perf >= expected_perf else "WARNING"
                print(f"Flush: {perf:.2f} /s - {status}")

        print("ok")
        # print("---------------------- 非组播MAC（LISTA，缓慢发包） ----------------------")
        # N_after_flush1 = self.get_available_fdb_entry()
        # try:
        #     self.assertEqual(N_after_flush1, test_count)
        # except Exception as e:
        #     print(f"fdb count {N_after_flush1} not equal {test_count}")

        # self.learn_pkt_list = []
        # self.verfiy_pkt_list = []
        # # 步骤8：生成非组播MAC LISTA
        # # N_after_flush1 = 128
        # print(f"Generated {N_after_flush1} random srcmac in LISTA")
        # LISTA = self.batch_generate_unicast_macs(N_after_flush1)
        # for src_mac in LISTA:
        #     learn_pkt = simple_udp_packet(eth_dst='00:77:77:77:77:77',
        #                                     eth_src=src_mac,
        #                                     pktlen=100)
        #     verfiy_pkt = simple_udp_packet(eth_dst=src_mac,
        #                                 eth_src='00:77:77:77:77:77',
        #                                 pktlen=100)
        #     self.learn_pkt_list.append(learn_pkt)
        #     self.verfiy_pkt_list.append(verfiy_pkt)

        # print(f"send {N_after_flush1} pkt at 50pps for learning")
        # self.send_at_rate(self.dev_port_list, self.learn_pkt_list, rate=50)

        # print("Waiting for switch to get ready before test, {} seconds ...".format(
        #     wait_sec))
        # time.sleep(wait_sec)

        # success_count = 0
        # fail_count = 0
        # print(f"send pkts for verify")
        # exp_port2 = random.choice(self.dev_port_list)
        # for i,pkt in enumerate(self.verfiy_pkt_list):
        #     try:
        #         # 发送目的MAC为源MAC的UDP报文
        #         send_packet(self, exp_port2, pkt)
        #         verify_packet(self, pkt, self.dev_port_list[i%len(self.dev_port_list)],timeout=0.1)
        #         success_count += 1
        #     except Exception as e:
        #         fail_count+=1
        #         print(f"fail count {fail_count}")
        #         # print(f"验证报文(目的MAC: {pkt[Ether].dst}）发送/接收失败")

        # learn_ratio = success_count / N_after_flush1
        # print(f"学习比例计算结果: {learn_ratio}({success_count}/{N_after_flush1})")
        # if N_after_flush1 > 0:
        #     status = "PASS" if learn_ratio >= self.expected_fill_rate else "WARNING"
        #     print(f"fdb fill rate: {learn_ratio*100:.3f}% - {status} fdb_total_count: {test_count}, fdb_success_cnt: {success_count}")

        # print(f"actually fill rate: {learn_ratio*100:.3f}%")

        # print(f"flush {N_after_flush1} fdb ")

        # sai_time = 0.0
        # start = time.perf_counter()
        # sai_thrift_flush_fdb_entries(self.client,
        #                              bv_id=self.vlan2,
        #                              entry_type=SAI_FDB_FLUSH_ENTRY_TYPE_ALL)
        # sai_time = time.perf_counter() - start

        # perf = self._calc_and_report_perf(
        #     "fdb flush", success_count, sai_time, sai_time)

        # expected_perf = getattr(self, 'expected_perf', None)
        # if expected_perf:
        #     print(f"\n{'Performance Validation':^80}")
        #     print(f"{'Expected Performance: ' + str(expected_perf) + ' r/s':^80}")
        #     print(f"{'-'*80}")

        #     print(f"Average Performance:")
        #     if perf > 0:
        #         status = "PASS" if perf >= expected_perf else "WARNING"
        #         print(f"Flush: {perf:.2f} /s - {status}")

        # print("ok")

        # print("---------------------- 带VLAN场景（随机VLAN V） ----------------------")

        # N_after_flush2 = self.get_available_fdb_entry()
        # try:
        #     self.assertEqual(N_after_flush2, test_count)
        # except Exception as e:
        #     print(f"fdb count {N_after_flush2}not equal {test_count}")
        # # 随机选VLAN V（3-66）
        # vlan_id = random.randint(3, 66)

        # ports_list = self.vlan_port_map_dict[vlan_id]['dev_port']
        # print(f"choice vlan {vlan_id} port {ports_list} for test")

        # if (self.vlan_port_map_dict[vlan_id]['vlan']  != vlan_id) or (len(ports_list) < 2):
        #     raise ValueError(f"VLAN{vlan_id}端口不正确")

        # portA, portB = random.sample(ports_list, 2)
        # self.learn_pkt_list = []
        # self.verfiy_pkt_list = []
        # # 缓慢发包（带VLAN tag）
        # for src_mac in LISTA:

        #     learn_pkt = simple_udp_packet(eth_dst='00:77:77:77:77:77',
        #                                 eth_src=src_mac,
        #                                 dl_vlan_enable=True,
        #                                 vlan_vid=vlan_id,
        #                                 pktlen=100)
        #     verfiy_pkt = simple_udp_packet(eth_dst=src_mac,
        #                                 eth_src='00:77:77:77:77:77',
        #                                 dl_vlan_enable=True,
        #                                 vlan_vid=vlan_id,
        #                                 pktlen=100)
        #     self.learn_pkt_list.append(learn_pkt)
        #     self.verfiy_pkt_list.append(verfiy_pkt)

        # print(f"send {test_count} pkt at 50pps from dev_port {portA}for learning")
        # for pkt in self.learn_pkt_list:
        #     send_packet(self, portA, pkt)
        #     time.sleep(0.02)

        # print("Waiting for switch to get ready before test, {} seconds ...".format(
        #     wait_sec))
        # time.sleep(wait_sec)
        # # 步骤11：统计X2
        # print(f"send {test_count} pkt from dev_port {portB}for verify")
        # success_count = 0
        # fail_count =0
        # for i,pkt in enumerate(self.verfiy_pkt_list):
        #     try:
        #         # 发送目的MAC为源MAC的UDP报文
        #         send_packet(self, portB, pkt)
        #         verify_packet(self, pkt, portA,timeout=0.1)
        #         success_count += 1
        #     except Exception as e:
        #         fail_count+=1
        #         print(f"fail count {fail_count}")
        #         # print(f"验证报文(目的MAC: {pkt[Ether].dst}）发送/接收失败")


        # learn_ratio = success_count / N_after_flush2
        # print(f"学习比例计算结果: {learn_ratio}({success_count}/{N_after_flush2})")
        # if N_after_flush2 > 0:
        #     status = "PASS" if learn_ratio >= self.expected_fill_rate else "WARNING"
        #     print(f"fdb fill rate: {learn_ratio*100:.3f}% - {status} fdb_total_count: {test_count}, fdb_success_cnt: {success_count}")

        # print(f"actually fill rate: {learn_ratio*100:.3f}%")

        # print(f"flush {N_after_flush2} fdb ")

        # sai_time = 0.0
        # start = time.perf_counter()
        # sai_thrift_flush_fdb_entries(self.client,
        #                              bv_id= getattr(self, "vlan%s" % vlan_id),
        #                              entry_type=SAI_FDB_FLUSH_ENTRY_TYPE_ALL)
        # sai_time = time.perf_counter() - start

        # perf = self._calc_and_report_perf(
        #     "fdb flush", success_count, sai_time, sai_time)
        # expected_perf = getattr(self, 'expected_perf', None)
        # if expected_perf:
        #     print(f"\n{'Performance Validation':^80}")
        #     print(f"{'Expected Performance: ' + str(expected_perf) + ' r/s':^80}")
        #     print(f"{'-'*80}")

        #     print(f"Average Performance:")
        #     if perf > 0:
        #         status = "PASS" if perf >= expected_perf else "WARNING"
        #         print(f"Flush: {perf:.2f} /s - {status}")

        # print("ok")

        # print(" ----------------------多VLAN遍历验证 ----------------------")
        # #遍历VLAN3-66，记录MAC/VLAN-端口映射
        # N_after_flush3 = self.get_available_fdb_entry()
        # try:
        #     self.assertEqual(N_after_flush3, test_count)
        # except Exception as e:
        #     print(f"fdb count {N_after_flush3}not equal {test_count}")

        # mac_vlan_port_map: Dict[Tuple[str, int], str] = {}
        # send_port_list = []
        # vlan_list = []
        # for vlan_id in range(3, 67):
        #     ports_list = self.vlan_port_map_dict[vlan_id]['dev_port']

        #     send_port_list.append(ports_list[0])
        #     vlan_list.append(vlan_id)
        #     send_port_list.append(ports_list[1])
        #     vlan_list.append(vlan_id)

        # self.learn_pkt_list = []

        # for i,src_mac in enumerate(LISTA):

        #     learn_pkt = simple_udp_packet(eth_dst='00:77:77:77:77:77',
        #                                 eth_src=src_mac,
        #                                 dl_vlan_enable=True,
        #                                 vlan_vid=vlan_list[i%len(vlan_list)],
        #                                 pktlen=100)
        #     mac_vlan_port_map[(src_mac, vlan_list[i%len(vlan_list)])] = send_port_list[i%len(send_port_list)]

        #     self.learn_pkt_list.append(learn_pkt)

        # print(f"send {N_after_flush3} pkt for learning")
        # for pkt in self.learn_pkt_list:
        #     send_packet(self, mac_vlan_port_map[(pkt[Ether].src, pkt[Dot1Q].vlan)], pkt)

        # # 步骤20：等待5s
        # time.sleep(5)
        # # 步骤21：验证所有MAC，统计X4
        # success_count = 0
        # fail_count = 0
        # print(f"send pkt for verify")

        # for (src_mac, vlan), port_a in mac_vlan_port_map.items():
        #     try:
        #         ports_list = self.vlan_port_map_dict[vlan]['dev_port']
        #         port_b = next(p for p in ports_list if p != port_a)
        #         verfiy_pkt = simple_udp_packet(eth_dst=src_mac,
        #                         eth_src='00:77:77:77:77:77',
        #                         dl_vlan_enable=True,
        #                         vlan_vid=vlan,
        #                         pktlen=100)
        #         send_packet(self, port_b, verfiy_pkt)
        #         verify_packet(self, verfiy_pkt, port_a,timeout=0.1)
        #         success_count += 1
        #     except Exception as e:
        #         fail_count+=1
        #         print(f"fail count {fail_count}")
        #         # print(f"验证报文(目的MAC: {pkt[Ether].dst}）发送/接收失败")


        # learn_ratio = success_count / N_after_flush3
        # print(f"学习比例计算结果: {learn_ratio}({success_count}/{N_after_flush3})")
        # if N_after_flush3 > 0:
        #     status = "PASS" if learn_ratio >= self.expected_fill_rate else "WARNING"
        #     print(f"fdb fill rate: {learn_ratio*100:.3f}% - {status} fdb_total_count: {N_after_flush3}, fdb_success_cnt: {success_count}")

        # print(f"actually fill rate: {learn_ratio*100:.3f}%")

        # print(f"flush fdb ")

        # sai_time = 0.0
        # for vlan_id in range(3, 67):
        #     batch_start = time.perf_counter()
        #     sai_thrift_flush_fdb_entries(self.client,
        #                                 bv_id=getattr(self, "vlan%s" % vlan_id),
        #                                 entry_type=SAI_FDB_FLUSH_ENTRY_TYPE_ALL)
        #     batch_end = time.perf_counter()
        #     sai_time += (batch_end - batch_start)

        # perf = self._calc_and_report_perf(
        #     "fdb flush", success_count, sai_time, sai_time)

        # expected_perf = getattr(self, 'expected_perf', None)
        # if expected_perf:
        #     print(f"\n{'Performance Validation':^80}")
        #     print(f"{'Expected Performance: ' + str(expected_perf) + ' r/s':^80}")
        #     print(f"{'-'*80}")

        #     print(f"Average Performance:")
        #     if perf > 0:
        #         status = "PASS" if perf >= expected_perf else "WARNING"
        #         print(f"Flush: {perf:.2f} /s - {status}")

        # print("ok")

        # N_after_flush4 = self.get_available_fdb_entry()
        # try:
        #     self.assertEqual(N_after_flush4, test_count)
        # except Exception as e:
        #     print(f"fdb count {N_after_flush4}not equal {test_count}")

        # print("\nAll L2 FDB Stress tests completed successfully!")

    def tearDown(self):
        super(L2FdbStressTest, self).tearDown()
