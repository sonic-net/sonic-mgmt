#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

import os
import sys

# The modules sai_base_test.py, switch.py, and texttable.py are already available in the legacy directory (../py3).
# To avoid maintaining duplicate files in the refactor directory, we import these modules from the legacy directory.
# Once the refactor directory is stable and the migration is complete, we can consider moving these files to the
# refactor directory.
# Somehow, relative paths may not be correctly resolved, leading to modules not being found.
# Using absolute paths ensures that the paths are correctly resolved, allowing the modules to be imported.
current_dir = os.path.dirname(os.path.abspath(__file__))
legacy_dir = os.path.abspath(os.path.join(current_dir, "../py3"))
sys.path.append(legacy_dir)

import sai_base_test
from switch import switch_init

from platform_qos_base import PlatformQosBase
from topology_qos_base import TopologyQosBase
from qos_helper import instantiate_helper, log_message
from counter_collector import CounterCollector, initialize_diag_counter, capture_diag_counter, summarize_diag_counter
from saitests_decorators import SaitestsDecorator, diag_counter, show_result, show_banner


class TestcaseQosBase(sai_base_test.ThriftInterfaceDataPlane):

    #
    # PTF methods
    #

    def setUp(self):
        sai_base_test.ThriftInterfaceDataPlane.setUp(self)
        time.sleep(5)
        switch_init(self.clients)
        hwsku_name = self.test_params.get("hwsku", "Unknown HwSKU")
        topology_name = self.test_params.get("testbed_type", "Unknown Topolog")
        instantiate_helper(self, hwsku_name, topology_name)

    def tearDown(self):
        sai_base_test.ThriftInterfaceDataPlane.tearDown(self)

    #
    # common steps
    #

    @SaitestsDecorator(func=show_banner, param="banner", enter=True, exit=False)
    @SaitestsDecorator(func=show_result, param="result", enter=False, exit=True)
    @SaitestsDecorator(func=diag_counter, param="initialize", enter=False, exit=True)
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
        self.platform.build_param()

        # todo: to move to platform specific class
        self.counter_margin = 0  # COUNTER_MARGIN = 2  # Margin for counter check

    def step_build_packet(self, pkt_len, dst_mac, src_mac, src_ip, dst_ip, dscp, src_vlan, **kwargs):
        return self.platform.build_packet(pkt_len, dst_mac, src_mac, src_ip, dst_ip, dscp, src_vlan, **kwargs)

    @SaitestsDecorator(func=show_banner, param="banner", enter=True, exit=False)
    @SaitestsDecorator(func=show_result, param="result", enter=False, exit=True)
    @SaitestsDecorator(func=diag_counter, param="capture", enter=False, exit=True)
    def step_detect_rx_port(self):
        return self.topology.detect_rx_port()

    def step_disable_port_transmit(self, client, asic_type, port_list):
        self.platform.disable_port_transmit(client, asic_type, port_list)

    @SaitestsDecorator(func=show_banner, param="banner", enter=True, exit=False)
    @SaitestsDecorator(func=show_result, param="result", enter=False, exit=True)
    @SaitestsDecorator(func=diag_counter, param="summarize", enter=True, exit=False)
    def step_enable_port_transmit(self, client, asic_type, port_list):
        self.platform.enable_port_transmit(client, asic_type, port_list)

    @SaitestsDecorator(func=show_banner, param="banner", enter=True, exit=False)
    @SaitestsDecorator(func=show_result, param="result", enter=False, exit=True)
    @SaitestsDecorator(func=diag_counter, param="capture", enter=False, exit=True)
    def step_fill_leakout(self, src_port_id, dst_port_id, packet, pg, asic_type, pkts_num_egr_mem):
        #
        # before sending packets short of triggering pfc
        # For some platform, prefer handle leakout before send_packet
        #
        return self.platform.fill_leakout(src_port_id, dst_port_id, packet, pg, asic_type, pkts_num_egr_mem)

    @SaitestsDecorator(func=show_banner, param="banner", enter=True, exit=False)
    @SaitestsDecorator(func=show_result, param="result", enter=False, exit=True)
    @SaitestsDecorator(func=diag_counter, param="capture", enter=False, exit=True)
    def step_compensate_leakout(self):
        #
        # For some platform, prefer to handler leackout after send_packet
        #
        self.platform.compensate_leakout()
