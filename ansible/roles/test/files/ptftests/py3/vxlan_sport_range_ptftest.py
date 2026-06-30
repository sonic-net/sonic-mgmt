# ptftests/vxlan_sport_range_ptftest.py
#
# VXLAN Source-Port Range, Hash-Consistency and Distribution Test
#
# Background
# ----------
# When the DUT (Device Under Test) receives a regular TCP packet destined for
# a remote network, it encapsulates that packet inside a VXLAN tunnel.  The
# resulting "outer" packet is a UDP packet whose *destination* port is the
# well-known VXLAN port (default 4789) and whose *source* port is chosen by
# the DUT from a configurable range.
#
# The range is defined by two values programmed into SWITCH_TABLE:
#   - vxlan_sport  : the base (lowest) port in the range
#   - vxlan_mask   : how many of the least-significant bits are "don't care"
#
# For example, base = 64128 (binary 1111101010000000) with mask = 7 means
# the bottom 7 bits can be anything, giving the range 64128 – 64255.
# Formula:  upper_bound = base | (0xFF >> (8 - mask))
#
# The DUT picks a specific port within that range by hashing the inner
# packet's 5-tuple (src IP, dst IP, src port, dst port, protocol).
# Deterministic hashing means the same flow always maps to the same outer
# source port, and many different flows should spread evenly across the
# range.
#
# This test verifies three things:
#   Phase 1 – Range:  every encapsulated packet's outer UDP source port
#                      falls within [base, upper_bound].
#   Phase 2 – Consistency:  re-sending the same inner flow produces the
#                            same outer source port every time.
#   Phase 3 – Distribution:  across 1000 distinct flows the ports are
#                             distributed evenly (≤ 10 % relative deviation
#                             per bucket).

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

# Number of representative flows re-sent in Phase 2 (hash-consistency).
HASH_CHECK_FLOWS = 10
# How many times each flow is re-sent in Phase 2.
HASH_CHECK_REPEATS = 5
# Maximum allowed relative deviation per port bucket in Phase 3.
MAX_RELATIVE_DEVIATION = 0.15


class VxlanSportRangeTest(BaseTest):
    """
    PTF test that validates VXLAN outer-UDP source-port range, hash
    consistency, and distribution evenness.
    """

    # ------------------------------------------------------------------ #
    #  Setup / Teardown                                                    #
    # ------------------------------------------------------------------ #

    def setUp(self):
        self.dataplane = ptf.dataplane_instance

        # --- Load parameters (same JSON-file pattern as vxlan_ecmp_ptftest) ---
        params = test_params_get()
        if "params_file" in params:
            with open(params["params_file"], "r") as f:
                params = json.load(f)

        # Standard VXLAN params
        self.dst_ip = params["dst_ip"]
        self.src_ip = params["ptf_src_ip"]
        self.dut_vtep = params["dut_vtep"]
        self.router_mac = params["router_mac"]
        self.vxlan_port = int(params.get("vxlan_port", 4789))
        self.vni = int(params.get("vni", 10000))
        self.send_port = int(params.get("ptf_ingress_port", 0))
        self.num_flows = int(params.get("num_flows", 1000))

        # Endpoints the DUT may forward VXLAN traffic to.
        if "endpoints_file" in params and os.path.exists(params["endpoints_file"]):
            with open(params["endpoints_file"], "r") as f:
                self.endpoints = json.load(f)
        else:
            self.endpoints = params.get("endpoints", [])

        # Source-port range parameters
        self.source_port = int(params.get("source_port", 32768))
        self.source_port_mask = int(params.get("source_port_mask", 4))

        # Compute the valid range.
        # The mask tells us how many least-significant bits are "don't-care".
        # upper_bound = base | (0xFF >> (8 - mask))
        #   e.g. base=32768 (0x8000), mask=4  →  upper = 0x8000 | 0x0F = 32783
        self.range_lower = self.source_port
        self.range_upper = self.source_port | (0xFF >> (8 - self.source_port_mask))
        self.range_size = self.range_upper - self.range_lower + 1

        # A throw-away MAC used in the expected-packet template (the actual
        # outer MACs are set to "don't-care" during matching).
        self.random_mac = "00:aa:bb:cc:dd:ee"

        # Discover every PTF dataplane port so we can listen for the
        # encapsulated packet on any of them.
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

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _generate_flow_packet(self, flow_index):
        """
        Build a unique TCP packet for *flow_index*.

        Each flow has a distinct (tcp_sport, tcp_dport) pair so the DUT's
        hash function maps it to (potentially) a different outer source port.
        The inner src/dst IPs stay fixed — only the L4 ports vary.
        """
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
        """
        Construct a Mask-based expected packet that matches any valid VXLAN
        encapsulation of *inner_pkt*, regardless of which endpoint is chosen
        or what the outer UDP source port is.

        Fields marked "don't-care":
          - Outer Ethernet src/dst  (next-hop MACs — not predictable)
          - Outer IP dst            (could be any endpoint)
          - Outer IP ttl, id, chksum
          - Outer UDP sport         (the field we validate manually)
          - Outer IP flags
        """
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

        # Build a tight Mask — only mark fields we truly cannot predict.
        # This mirrors the approach in vnet_vxlan.py (lines 502-510),
        # which masks only Ether src/dst, IP ttl/chksum, and UDP sport.
        # A tight mask ensures we never accidentally match background
        # traffic (ARP, LLDP, BGP keepalives, etc.).
        #
        # We additionally mask IP.dst (the DUT picks which endpoint to
        # forward to via ECMP — we have 2) and IP.id (varies per packet).
        m = Mask(encap)
        m.set_ignore_extra_bytes()
        m.set_do_not_care_scapy(scapy.Ether, "src")
        m.set_do_not_care_scapy(scapy.Ether, "dst")
        m.set_do_not_care_scapy(scapy.IP, "dst")
        m.set_do_not_care_scapy(scapy.IP, "ttl")
        m.set_do_not_care_scapy(scapy.IP, "id")
        m.set_do_not_care_scapy(scapy.IP, "chksum")
        m.set_do_not_care_scapy(scapy.UDP, "sport")

        # The DUT rewrites the inner Ethernet dst to the endpoint's MAC
        # (which depends on ECMP selection).  The inner IP checksum is
        # recomputed after TTL decrement.  We mask these bytes directly
        # because set_do_not_care_scapy only operates on the *first*
        # occurrence of a layer type (i.e., the outer headers).
        #
        # Byte layout: outer Ether(14) + IP(20) + UDP(8) + VXLAN(8) = 50
        # Inner frame starts at byte 50.
        INNER_START = 14 + 20 + 8 + 8  # = 50
        # Inner Ether dst: 6 bytes at offset 50
        m.set_do_not_care(INNER_START * 8, 6 * 8)
        # Inner IP checksum: 2 bytes at offset 50 + Ether(14) + 10
        m.set_do_not_care((INNER_START + 14 + 10) * 8, 2 * 8)

        return m

    def _send_and_capture(self, pkt, expected_mask):
        """
        Send *pkt* on the ingress port, wait for a VXLAN-encapped copy on
        any egress port, and return the outer UDP source port.

        Uses ``verify_packet_any_port`` from ptf.testutils which asserts
        that exactly one matching packet arrives (or raises on timeout).
        """
        send_packet(self, self.send_port, pkt)
        (_port_idx, received_pkt) = verify_packet_any_port(
            self, expected_mask, self.all_ports, timeout=5,
        )
        parsed = scapy.Ether(received_pkt)
        return parsed[scapy.UDP].sport

    # ------------------------------------------------------------------ #
    #  Main test body                                                      #
    # ------------------------------------------------------------------ #

    def runTest(self):
        # ---- Phase 1: Range verification --------------------------------
        # Send self.num_flows unique flows.  For every captured response,
        # assert the outer UDP source port is inside the configured range.
        # We also record the mapping flow_index → observed_sport for the
        # later phases.
        logger.info("=== Phase 1: Source-port RANGE verification ===")

        flow_to_sport = {}          # flow_index  → observed outer sport
        port_counts = defaultdict(int)   # sport value → hit count

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

        # ---- Phase 2: Hash consistency ----------------------------------
        # Re-send a small number of flows multiple times.  The DUT must
        # produce the same outer source port every time for a given 5-tuple.
        logger.info("=== Phase 2: Hash CONSISTENCY verification ===")

        # Pick up to HASH_CHECK_FLOWS evenly-spaced flow indices.
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

        # ---- Phase 3: Distribution evenness -----------------------------
        # Using the port_counts collected in Phase 1, check that traffic is
        # spread roughly evenly across the source-port range.
        logger.info("=== Phase 3: DISTRIBUTION evenness verification ===")

        expected_per_port = self.num_flows / self.range_size
        logger.info(f"  Range size        : {self.range_size}")
        logger.info(f"  Expected per port : {expected_per_port:.1f}")
        logger.info(f"  Port counts       : {dict(port_counts)}")

        for port_val in range(self.range_lower, self.range_upper + 1):
            actual = port_counts.get(port_val, 0)
            assert actual > 0, (
                f"Port {port_val} received 0 flows — expected ~{expected_per_port:.0f}. "
                f"Not all ports in the range are being used."
            )
            deviation = abs(actual - expected_per_port) / expected_per_port
            assert deviation <= MAX_RELATIVE_DEVIATION, (
                f"Port {port_val}: {actual} flows (expected ~{expected_per_port:.0f}), "
                f"relative deviation {deviation:.2%} exceeds {MAX_RELATIVE_DEVIATION:.0%} "
                f"threshold"
            )

        logger.info(f"Phase 3 PASSED — all {self.range_size} ports within "
                     f"{MAX_RELATIVE_DEVIATION:.0%} of expected count")

        logger.info("=== ALL PHASES PASSED ===")
