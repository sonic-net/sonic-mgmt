
# This test verifies three things:
#   Phase 1 – Range:  every encapsulated packet's outer UDP source port
#                      falls within [base, upper_bound].
#   Phase 2 – Consistency:  re-sending the same inner flow produces the
#                            same outer source port every time.
#   Phase 3 – Coverage:  all ports in the range receive at least some traffic
#                        (i.e., the hash function utilizes the entire range).

import json
import os
import logging
from collections import defaultdict

import scapy.all as scapy
import ptf
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import (
    simple_tcp_packet,
    simple_vxlan_packet,
    verify_packet_any_port,
    send_packet,
    test_params_get,
)

logger = logging.getLogger(__name__)

HASH_CHECK_FLOWS = 10
HASH_CHECK_REPEATS = 5


class VxlanSportRangeTest(BaseTest):

    def setUp(self):
        self.dataplane = ptf.dataplane_instance

        params = test_params_get()
        if "params_file" in params:
            with open(params["params_file"], "r") as f:
                params = json.load(f)

        self.dst_ip = params["dst_ip"]
        self.src_ip = params["ptf_src_ip"]
        self.dut_vtep = params["dut_vtep"]
        self.router_mac = params["router_mac"]
        self.vxlan_port = int(params.get("vxlan_port", 4789))
        self.vni = int(params.get("vni", 10000))
        self.send_port = int(params.get("ptf_ingress_port", 0))
        self.num_flows = int(params.get("num_flows", 1000))

        if "endpoints_file" in params and os.path.exists(params["endpoints_file"]):
            with open(params["endpoints_file"], "r") as f:
                self.endpoints = json.load(f)
        else:
            self.endpoints = params.get("endpoints", [])
            
        self.source_port = int(params.get("source_port", 32768))
        self.source_port_mask = int(params.get("source_port_mask", 4))

        self.range_lower = self.source_port
        self.range_upper = self.source_port | (0xFF >> (8 - self.source_port_mask))
        self.range_size = self.range_upper - self.range_lower + 1

        self.random_mac = "00:aa:bb:cc:dd:ee"

        self.dataplane.flush()
        self.all_ports = [p for (d, p) in self.dataplane.ports.keys() if d == 0]

        logger.info("=== VXLAN Source-Port Range Test Setup ===")
        logger.info(f"  Source port base : {self.source_port}")
        logger.info(f"  Source port mask : {self.source_port_mask}")
        logger.info(f"  Valid range      : {self.range_lower} – {self.range_upper} "
                     f"({self.range_size} ports)")
        logger.info(f"  Num flows        : {self.num_flows}")
        logger.info(f"  Endpoints        : {self.endpoints}")
        logger.info(f"  DUT VTEP         : {self.dut_vtep}")
        logger.info(f"  Dst IP / Src IP  : {self.dst_ip} / {self.src_ip}")
        logger.info(f"  VXLAN UDP dport  : {self.vxlan_port}")
        logger.info(f"  Ingress port     : {self.send_port}")
        logger.info(f"  PTF ports        : {self.all_ports}")
        logger.info("==========================================")

    def tearDown(self):
        self.dataplane.flush()

    def _generate_flow_packet(self, flow_index):
        src_mac = self.dataplane.get_mac(0, self.send_port)
        return simple_tcp_packet(
            eth_src=src_mac,
            eth_dst=self.router_mac,
            ip_dst=self.dst_ip,
            ip_src=self.src_ip,
            ip_id=105,
            ip_ttl=64,
            tcp_sport=10000 + flow_index,
            tcp_dport=20000 + flow_index,
            pktlen=100,
        )

    def _build_masked_expected(self, inner_pkt):
        inner_exp = inner_pkt.copy()
        inner_exp[scapy.Ether].src = self.router_mac
        inner_exp[scapy.IP].ttl = inner_exp[scapy.IP].ttl - 1

        encap = simple_vxlan_packet(
            eth_src=self.router_mac,
            eth_dst=self.random_mac,
            ip_src=self.dut_vtep,
            ip_dst=self.endpoints[0] if self.endpoints else "0.0.0.0",
            ip_id=0,
            ip_ttl=128,
            udp_sport=0,
            udp_dport=self.vxlan_port,
            with_udp_chksum=False,
            vxlan_vni=self.vni,
            inner_frame=inner_exp,
        )
        encap[scapy.IP].flags = 0x2

        m = Mask(encap)
        m.set_ignore_extra_bytes()
        m.set_do_not_care_scapy(scapy.Ether, "src")
        m.set_do_not_care_scapy(scapy.Ether, "dst")
        m.set_do_not_care_scapy(scapy.IP, "dst")
        m.set_do_not_care_scapy(scapy.IP, "ttl")
        m.set_do_not_care_scapy(scapy.IP, "id")
        m.set_do_not_care_scapy(scapy.IP, "chksum")
        m.set_do_not_care_scapy(scapy.UDP, "sport")

        # Byte layout: outer Ether(14) + IP(20) + UDP(8) + VXLAN(8) = 50
        # Inner frame starts at byte 50.
        INNER_START = 14 + 20 + 8 + 8  # = 50
        # Inner Ether dst: 6 bytes at offset 50
        m.set_do_not_care(INNER_START * 8, 6 * 8)
        # Inner IP checksum: 2 bytes at offset 50 + Ether(14) + 10
        m.set_do_not_care((INNER_START + 14 + 10) * 8, 2 * 8)

        return m

    def _send_and_capture(self, pkt, expected_mask):
        send_packet(self, self.send_port, pkt)
        (_port_idx, received_pkt) = verify_packet_any_port(
            self, expected_mask, self.all_ports, timeout=5,
        )
        parsed = scapy.Ether(received_pkt)
        return parsed[scapy.UDP].sport

    def runTest(self):
        # Send self.num_flows unique flows.  For every captured response,
        # assert the outer UDP source port is inside the configured range.
        logger.info("=== Phase 1: Source-port RANGE verification ===")

        flow_to_sport = {}          
        port_counts = defaultdict(int)  

        for i in range(self.num_flows):
            pkt = self._generate_flow_packet(i)
            mask = self._build_masked_expected(pkt)
            outer_sport = self._send_and_capture(pkt, mask)

            assert self.range_lower <= outer_sport <= self.range_upper, (
                f"Flow {i}: outer UDP sport {outer_sport} is outside the "
                f"configured range [{self.range_lower}, {self.range_upper}]"
            )

            flow_to_sport[i] = outer_sport
            port_counts[outer_sport] += 1

            if (i + 1) % 200 == 0:
                logger.info(f"  Phase 1 progress: {i + 1}/{self.num_flows} packets OK")

        logger.info(f"Phase 1 PASSED — all {self.num_flows} packets within range "
                     f"[{self.range_lower}, {self.range_upper}]")

        # Re-send a small number of flows multiple times.  The DUT must
        # produce the same outer source port every time for a given 5-tuple.
        logger.info("=== Phase 2: Hash CONSISTENCY verification ===")

        step = max(1, self.num_flows // HASH_CHECK_FLOWS)
        check_indices = list(range(0, self.num_flows, step))[:HASH_CHECK_FLOWS]

        for flow_idx in check_indices:
            expected_sport = flow_to_sport[flow_idx]
            pkt = self._generate_flow_packet(flow_idx)
            mask = self._build_masked_expected(pkt)

            for repeat in range(HASH_CHECK_REPEATS):
                outer_sport = self._send_and_capture(pkt, mask)
                assert outer_sport == expected_sport, (
                    f"Flow {flow_idx} repeat {repeat}: outer sport {outer_sport} "
                    f"differs from first observation {expected_sport} — hash "
                    f"is not consistent for the same 5-tuple"
                )

        logger.info(f"Phase 2 PASSED — {len(check_indices)} flows × "
                     f"{HASH_CHECK_REPEATS} repeats all consistent")

        # Using the port_counts collected in Phase 1, check that all ports
        # in the configured range receive at least some traffic (coverage).
        logger.info("=== Phase 3: PORT COVERAGE verification ===")

        logger.info(f"  Range size  : {self.range_size}")
        logger.info(f"  Port counts : {dict(port_counts)}")

        for port_val in range(self.range_lower, self.range_upper + 1):
            actual = port_counts.get(port_val, 0)
            assert actual > 0, (
                f"Port {port_val} received 0 flows. "
                f"Not all ports in the range [{self.range_lower}, {self.range_upper}] are being used."
            )

        logger.info(f"Phase 3 PASSED — all {self.range_size} ports in range are utilized")

        logger.info("=== ALL PHASES PASSED ===")
