"""
SONiC Dataplane Qos tests
"""

import time
import ptf.packet as scapy
from scapy.all import Ether, IP

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
from ptf.testutils import ptf_ports, simple_arp_packet, send_packet
from ptf.mask import Mask
from switch import switch_init, port_list


from qos_helper import log_message, qos_test_assert
from testcase_qos_base import TestcaseQosBase
from counter_collector import CounterCollector, initialize_diag_counter, capture_diag_counter, summarize_diag_counter
from saitests_decorators import SaitestsDecorator, diag_counter, show_result, show_banner, check_counter


class PFCtest(TestcaseQosBase):

    #
    # PTF methods
    #

    def runTest(self):
        self.step_build_param()

        self.pkt = self.step_build_packet(
            self.packet_size,
            self.pkt_dst_mac,
            self.src_port_mac,
            self.src_port_ip,
            self.dst_port_ip,
            self.dscp,
            self.src_port_vlan,
            ecn=self.ecn,
            ttl=self.ttl,
        )

        self.step_detect_rx_port()

        self.step_disable_port_transmit(self.dst_client, self.asic_type, [self.dst_port_id])

        try:
            self.step_short_of_pfc(self.src_port_id, self.pkt)

            self.step_trigger_pfc()

            self.step_short_of_ingress_drop()

            self.step_trigger_ingress_drop()

        finally:
            self.step_enable_port_transmit(self.dst_client, self.asic_type, [self.dst_port_id])

    #
    # specific steps
    #

    @SaitestsDecorator(func=show_banner, param="banner", enter=True, exit=False)
    @SaitestsDecorator(func=show_result, param="result", enter=False, exit=True)
    @SaitestsDecorator(func=diag_counter, param="initialize", enter=False, exit=True)
    def step_build_param(self):
        super().step_build_param()
        self.dst_port_mac = self.dataplane.get_mac(0, self.dst_port_id)
        self.src_port_mac = self.dataplane.get_mac(0, self.src_port_id)
        self.pkt_dst_mac = self.router_mac if self.router_mac != "" else self.dst_port_mac

        # Add slight tolerance in threshold characterization to consider
        # the case that cpu puts packets in the egress queue after we pause the egress
        # or the leak out is simply less than expected as we have occasionally observed
        if not hasattr(self, "pkts_num_margin"):
            self.pkts_num_margin = 2

        self.ttl = 64
        if not hasattr(self, "packet_size"):
            self.packet_size = 64
        if hasattr(self, "cell_size"):
            self.cell_occupancy = (self.packet_size + self.cell_size - 1) // self.cell_size
        else:
            self.cell_occupancy = 1

        if not hasattr(self, "is_dualtor"):
            self.is_dualtor = False

        if not hasattr(self, "def_vlan_mac"):
            self.def_vlan_mac = None
        if self.is_dualtor and self.def_vlan_mac is not None:
            self.pkt_dst_mac = self.def_vlan_mac

        self.pkts_num_egr_mem = None

        # for short_of_pfc_check_rules, must assign static value for decorator's parameter during decorator function definition
        # so the checking field name was stored in to instance property, and assign property name to decorator function's param
        self.PfcPgxTxPkt = f"Pfc{self.pg}TxPkt"

    # Regarding to check recv port no ingress drop
    # For dnx few extra ipv6 NS/RA pkt received from VM, adding to counter value
    # & may give inconsistent test results
    # Adding counter_margin to provide room to 2 pkt incase, extra traffic received
    short_of_pfc_check_rules = {
        "src_port_id": {
            "PortCnt": {
                "InDiscard": {
                    "operate": "<=",
                    "target": "counter_margin",
                    "error": "src port's ingress discard counter increase unexpectedly",
                },
                "InDropPkt": {
                    "operate": "<=",
                    "target": "counter_margin",
                    "error": "src port's ingress drop counter increase unexpectedly",
                },
            },
        },
        "dst_port_id": {
            "PortCnt": {
                "OutDiscard": {
                    "operate": "==",
                    "target": 0,
                    "error": "dst port's egress discard counter increase unexpectedly",
                },
                "OutDropPkt": {
                    "operate": "==",
                    "target": 0,
                    "error": "dst port's egress drop counter increase unexpectedly",
                },
            },
        },
    }

    @SaitestsDecorator(func=show_banner, param="banner", enter=True, exit=False)
    @SaitestsDecorator(func=show_result, param="result", enter=False, exit=True)
    @SaitestsDecorator(func=diag_counter, param="capture", enter=False, exit=True)
    @SaitestsDecorator(func=check_counter, param=short_of_pfc_check_rules, enter=True, exit=True)
    def step_short_of_pfc(self, port, packet):
        leakout_overflow = self.platform.fill_leakout(
            port, self.dst_port_id, packet, self.pg, self.asic_type, self.pkts_num_egr_mem
        )

        # In previous line, we have already sent packets to fill leakout in some platform,
        # so in this line, we need to send ${leakout_overflow} less packet to trigger pfc
        self.platform.send_packet(
            port,
            packet,
            (self.pkts_num_leak_out + self.pkts_num_trig_pfc) // self.cell_occupancy
            - 1
            - self.pkts_num_margin
            - leakout_overflow,
        )
        # allow enough time for the dut to sync up the counter values in counters_db
        time.sleep(8)

        self.platform.compensate_leakout()

    trigger_pfc_check_rules = {
        "src_port_id": {
            "PortCnt": {
                "PfcPgxTxPkt": {
                    "operate": ">",
                    "target": 0,
                    "error": "src port's PFC counter don't increase unexpectedly",
                },
                "InDiscard": {
                    "operate": "<=",
                    "target": "counter_margin",
                    "error": "src port's ingress discard counter increase unexpectedly",
                },
                "InDropPkt": {
                    "operate": "<=",
                    "target": "counter_margin",
                    "error": "src port's ingress drop counter increase unexpectedly",
                },
            },
        },
        "dst_port_id": {
            "PortCnt": {
                "OutDiscard": {
                    "operate": "==",
                    "target": 0,
                    "error": "dst port's egress discard counter increase unexpectedly",
                },
                "OutDropPkt": {
                    "operate": "==",
                    "target": 0,
                    "error": "dst port's egress drop counter increase unexpectedly",
                },
            },
        },
    }

    @SaitestsDecorator(func=show_banner, param="banner", enter=True, exit=False)
    @SaitestsDecorator(func=show_result, param="result", enter=False, exit=True)
    @SaitestsDecorator(func=diag_counter, param="capture", enter=False, exit=True)
    @SaitestsDecorator(func=check_counter, param=trigger_pfc_check_rules, enter=True, exit=True)
    def step_trigger_pfc(self):
        # send 1 packet to trigger pfc
        self.platform.send_packet(self.src_port_id, self.pkt, 1 + 2 * self.pkts_num_margin)
        # allow enough time for the dut to sync up the counter values in counters_db
        time.sleep(8)

    short_of_ingress_drop_check_rules = {
        "src_port_id": {
            "PortCnt": {
                "PfcPgxTxPkt": {
                    "operate": ">",
                    "target": 0,
                    "error": "src port's PFC counter don't increase unexpectedly",
                },
                "InDiscard": {
                    "operate": "<=",
                    "target": "counter_margin",
                    "error": "src port's ingress discard counter increase unexpectedly",
                },
                "InDropPkt": {
                    "operate": "<=",
                    "target": "counter_margin",
                    "error": "src port's ingress drop counter increase unexpectedly",
                },
            },
        },
        "dst_port_id": {
            "PortCnt": {
                "OutDiscard": {
                    "operate": "==",
                    "target": 0,
                    "error": "dst port's egress discard counter increase unexpectedly",
                },
                "OutDropPkt": {
                    "operate": "==",
                    "target": 0,
                    "error": "dst port's egress drop counter increase unexpectedly",
                },
            },
        },
    }

    @SaitestsDecorator(func=show_banner, param="banner", enter=True, exit=False)
    @SaitestsDecorator(func=show_result, param="result", enter=False, exit=True)
    @SaitestsDecorator(func=diag_counter, param="capture", enter=False, exit=True)
    @SaitestsDecorator(func=check_counter, param=short_of_ingress_drop_check_rules, enter=True, exit=True)
    def step_short_of_ingress_drop(self):
        # send packets short of ingress drop
        self.platform.send_packet(
            self.src_port_id,
            self.pkt,
            (self.pkts_num_trig_ingr_drp - self.pkts_num_trig_pfc) // self.cell_occupancy
            - 1
            - 2 * self.pkts_num_margin,
        )
        # allow enough time for the dut to sync up the counter values in counters_db
        time.sleep(8)

    trigger_ingress_drop_check_rules = {
        "src_port_id": {
            "PortCnt": {
                "PfcPgxTxPkt": {
                    "operate": ">",
                    "target": 0,
                    "error": "src port's PFC counter don't increase unexpectedly",
                },
                "InDiscard": {
                    "operate": ">",
                    "target": 0,
                    "error": "src port's ingress discard counter don't increase unexpectedly",
                },
                "InDropPkt": {
                    "operate": ">",
                    "target": 0,
                    "error": "src port's ingress drop counter don't increase unexpectedly",
                },
            },
        },
        "dst_port_id": {
            "PortCnt": {
                "OutDiscard": {
                    "operate": "==",
                    "target": 0,
                    "error": "dst port's egress discard counter increase unexpectedly",
                },
                "OutDropPkt": {
                    "operate": "==",
                    "target": 0,
                    "error": "dst port's egress drop counter increase unexpectedly",
                },
            },
        },
    }

    @SaitestsDecorator(func=show_banner, param="banner", enter=True, exit=False)
    @SaitestsDecorator(func=show_result, param="result", enter=False, exit=True)
    @SaitestsDecorator(func=diag_counter, param="capture", enter=False, exit=True)
    @SaitestsDecorator(func=check_counter, param=trigger_ingress_drop_check_rules, enter=True, exit=True)
    def step_trigger_ingress_drop(self):
        # send 1 packet to trigger pfc
        self.platform.send_packet(self.src_port_id, self.pkt, 1 + 2 * self.pkts_num_margin)
        # allow enough time for the dut to sync up the counter values in counters_db
        time.sleep(8)
        capture_diag_counter(self, "TrigPfc")
