#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

import sai_base_test
from switch import switch_init

from platform_qos_base import PlatformQosBase
from topology_qos_base import TopologyQosBase
from qos_helper import QosHelper, instantiate_helper, log_message
from counter_collector import CounterCollector, initialize_diag_counter, capture_diag_counter, summarize_diag_counter
from saitests_decorators import saitests_decorator, diag_counter, step_result, step_banner


class TestcaseQosBase(sai_base_test.ThriftInterfaceDataPlane):


    #
    # PTF methods
    #

    def setUp(self):
        sai_base_test.ThriftInterfaceDataPlane.setUp(self)
        time.sleep(5)
        switch_init(self.clients)
        hwsku_name = self.test_params.get('hwsku', 'Unknown HwSKU')
        topology_name = self.test_params.get('testbed_type', 'Unknown Topolog')
        self.helper = instantiate_helper(self, hwsku_name, topology_name)


    def tearDown(self):
        sai_base_test.ThriftInterfaceDataPlane.tearDown(self)


    #
    # common steps
    #

    @saitests_decorator(func=step_banner, param='Banner', enter=True, exit=False)
    @saitests_decorator(func=step_result, param='Result', enter=False, exit=True)
    @saitests_decorator(func=diag_counter, param='initialize', enter=False, exit=True)
    def step_build_param(self):
        for key, value in self.test_params.items():
            if isinstance(value, str) and value.isdigit():
                setattr(self, key, int(value))
            else:
                setattr(self, key, value)
        self.asic_type = self.sonic_asic_type

        # Usually, we invoke platform related function in TestcaseQosBase class, 
        # to make testcase specific class see less platform related activity.
        # But, in some corner case, we also can invoke platform related function in 
        # testcase specific class, to make code simple and easy to understand.
        self.helper.build_param()

        # todo: to move to platform specific class
        self.counter_margin = 0  # COUNTER_MARGIN = 2  # Margin for counter check


    def step_build_packet(self, pkt_len, dst_mac, src_mac, src_ip, dst_ip, dscp, src_vlan, **kwargs):
        return self.helper.build_packet(pkt_len, dst_mac, src_mac, src_ip, dst_ip, dscp, src_vlan, **kwargs)


    @saitests_decorator(func=step_banner, param='Banner', enter=True, exit=False)
    @saitests_decorator(func=step_result, param='Result', enter=False, exit=True)
    @saitests_decorator(func=diag_counter, param='capture', enter=False, exit=True)
    def step_detect_rx_port(self):
        return self.helper.detect_rx_port()


    def step_disable_port_transmit(self, client, asic_type, port_list):
        self.helper.disable_port_transmit(client, asic_type, port_list)


    @saitests_decorator(func=step_banner, param='Banner', enter=True, exit=False)
    @saitests_decorator(func=step_result, param='Result', enter=False, exit=True)
    @saitests_decorator(func=diag_counter, param='summarize', enter=True, exit=False)
    def step_enable_port_transmit(self, client, asic_type, port_list):
        self.helper.enable_port_transmit(client, asic_type, port_list)


    @saitests_decorator(func=step_banner, param='Banner', enter=True, exit=False)
    @saitests_decorator(func=step_result, param='Result', enter=False, exit=True)
    @saitests_decorator(func=diag_counter, param='capture', enter=False, exit=True)
    def step_fill_leakout(self, src_port_id, dst_port_id, packet, pg, asic_type, pkts_num_egr_mem):
        #
        # before sending packets short of triggering pfc
        # For some platform, prefer handle leakout before send_packet
        #
        return self.helper.fill_leakout(src_port_id, dst_port_id, packet, pg, asic_type, pkts_num_egr_mem)


    @saitests_decorator(func=step_banner, param='Banner', enter=True, exit=False)
    @saitests_decorator(func=step_result, param='Result', enter=False, exit=True)
    @saitests_decorator(func=diag_counter, param='capture', enter=False, exit=True)
    def step_compensate_leakout(self):
        #
        # For some platform, prefer to handler leackout after send_packet
        #
        self.helper.compensate_leakout()
