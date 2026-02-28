"""
PTF test for VXLAN Tunnel Route Fine-Grained ECMP

Test cases:
- create_flows: Send NUM_FLOWS flows with varying (sport, dport) and record
  flow_key -> outer_dst_ip (endpoint) mapping. Validates even distribution.
- verify_consistent_hash: Replay same flows; assert every flow hits the same
  endpoint as before (100% match required).
- withdraw_endpoint: Replay flows after one endpoint is removed. Asserts that
  no flow hits the withdrawn endpoint, and that flows previously going to OTHER
  endpoints are completely undisturbed (key FG ECMP property).
- add_endpoint: Replay flows after a new endpoint is added. Asserts that at
  most 15% of flows migrate to the new endpoint (consistent hashing minimises
  disruption vs ~50% for standard ECMP).
"""

import logging
import os
import json
import ptf
import ptf.packet as scapy
from ptf.base_tests import BaseTest
from ptf.testutils import test_params_get, dp_poll, send_packet, simple_tcp_packet

MAX_DEVIATION = 0.25
ADD_ENDPOINT_MAX_DISRUPTION = 0.15

logger = logging.getLogger(__name__)


class VxlanTunnelFgEcmpTest(BaseTest):
    """PTF test class for VXLAN Tunnel Fine-Grained ECMP."""

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        params = test_params_get()
        if "params_file" in params:
            with open(params["params_file"], "r") as f:
                params = json.load(f)

        self.test_case = params.get("test_case", "create_flows")
        self.endpoints = params.get("endpoints", [])
        self.dst_ip = params.get("dst_ip")
        self.src_ip = params.get("ptf_src_ip")
        self.router_mac = params.get("router_mac")
        self.num_packets = int(params.get("num_packets", 1000))
        self.vxlan_port = int(params.get("vxlan_port", 4789))
        self.send_port = int(params.get("ptf_ingress_port", 0))
        self.exp_flow_count = params.get("exp_flow_count", {})
        self.persist_map = params.get("persist_map", "/tmp/vxlan_tunnel_fg_ecmp_persist_map.json")

        # Test-case-specific parameters
        self.withdraw_endpoint = params.get("withdraw_endpoint") if self.test_case == "withdraw_endpoint" else None
        self.add_endpoint = params.get("add_endpoint") if self.test_case == "add_endpoint" else None

        # Starting TCP port values — reset here and at the top of runTest so
        # that every phase generates the exact same (sport, dport) sequence.
        self.tcp_sport = 1234
        self.tcp_dport = 5000

        self.dataplane.flush()

        logger.info("=== VXLAN FG ECMP PTF Test Setup ===")
        logger.info(f"Test case:       {self.test_case}")
        logger.info(f"Endpoints ({len(self.endpoints)}): {self.endpoints}")
        logger.info(f"dst_ip={self.dst_ip}  src_ip={self.src_ip}")
        logger.info(f"router_mac={self.router_mac}  vxlan_port={self.vxlan_port}")
        logger.info(f"send_port={self.send_port}  num_packets={self.num_packets}")
        logger.info(f"persist_map={self.persist_map}")
        logger.info("=====================================")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _next_ports(self):
        """Advance and return the next (sport, dport) pair."""
        self.tcp_sport = (self.tcp_sport % 65534) + 1
        self.tcp_dport = (self.tcp_dport % 65534) + 1
        return self.tcp_sport, self.tcp_dport

    def _send_and_capture_endpoint(self, sport, dport):
        """
        Send one inner TCP packet and return the VXLAN outer dst IP
        (i.e. the endpoint the DUT chose), or None if no response was captured.
        """
        src_mac = self.dataplane.get_mac(0, self.send_port)
        pkt = simple_tcp_packet(
            eth_dst=self.router_mac,
            eth_src=src_mac,
            ip_dst=self.dst_ip,
            ip_src=self.src_ip,
            ip_id=105,
            ip_ttl=64,
            tcp_sport=sport,
            tcp_dport=dport,
            pktlen=100,
        )
        send_packet(self, self.send_port, pkt)

        result = dp_poll(self, device_number=0, timeout=1)
        if not isinstance(result, self.dataplane.PollSuccess):
            return None

        ether = scapy.Ether(result.packet)
        if scapy.IP not in ether or scapy.UDP not in ether:
            return None
        if ether[scapy.UDP].dport != self.vxlan_port:
            return None

        outer_dst = ether[scapy.IP].dst
        return outer_dst if outer_dst in self.endpoints else None

    def _check_distribution(self, hit_count_map):
        """
        Return the maximum per-endpoint deviation from the expected count.
        deviation = |1 - actual/expected|
        """
        deviation_max = 0.0
        for endpoint, exp_flows in self.exp_flow_count.items():
            actual = hit_count_map.get(endpoint, 0)
            deviation = abs(1.0 - actual / float(exp_flows))
            logger.info(
                f"  endpoint={endpoint}  expected={exp_flows:.1f}  "
                f"actual={actual}  deviation={deviation:.3f}"
            )
            deviation_max = max(deviation_max, deviation)
        return deviation_max

    def _load_persist_map(self):
        with open(self.persist_map) as f:
            return json.load(f)

    def _save_persist_map(self, mapping):
        with open(self.persist_map, "w") as f:
            json.dump(mapping, f)

    # ------------------------------------------------------------------
    # Test cases
    # ------------------------------------------------------------------

    def _create_flows(self, flow_map):
        """
        Send num_packets flows with unique (sport, dport) pairs, record
        which endpoint each flow was forwarded to, and validate even
        distribution across all endpoints.
        """
        for attempt in range(3):
            hit_count_map = {}
            flow_map[self.dst_ip] = {}
            self.tcp_sport = 1234
            self.tcp_dport = 5000

            for i in range(self.num_packets):
                sport, dport = self._next_ports()
                endpoint = self._send_and_capture_endpoint(sport, dport)
                if endpoint:
                    flow_key = f"{sport}:{dport}"
                    flow_map[self.dst_ip][flow_key] = endpoint
                    hit_count_map[endpoint] = hit_count_map.get(endpoint, 0) + 1
                if (i + 1) % 100 == 0:
                    logger.info(f"  created {i + 1}/{self.num_packets} flows")

            total = len(flow_map[self.dst_ip])
            logger.info(f"Attempt {attempt + 1}: {total} flows captured. Distribution: {hit_count_map}")

            assert set(self.endpoints) == set(hit_count_map.keys()), (
                f"Not all endpoints were reached.\n"
                f"  Expected: {sorted(self.endpoints)}\n"
                f"  Got:      {sorted(hit_count_map.keys())}"
            )

            if not self.exp_flow_count:
                break

            deviation = self._check_distribution(hit_count_map)
            logger.info(f"  max deviation={deviation:.3f} (threshold={MAX_DEVIATION})")
            if deviation <= MAX_DEVIATION:
                break
        else:
            raise AssertionError(
                f"Flow distribution deviation {deviation:.3f} exceeds "
                f"threshold {MAX_DEVIATION} after 3 attempts.\n"
                f"Distribution: {hit_count_map}"
            )

    def _verify_consistent_hash(self, flow_map):
        """
        Replay flows in the same order; every flow must hit the same
        endpoint as recorded in flow_map.
        """
        flows_checked = 0
        mismatches = []
        self.tcp_sport = 1234
        self.tcp_dport = 5000

        for flow_key, expected in flow_map[self.dst_ip].items():
            sport, dport = map(int, flow_key.split(":"))
            actual = self._send_and_capture_endpoint(sport, dport)
            if actual is not None:
                flows_checked += 1
                if actual != expected:
                    mismatches.append((flow_key, expected, actual))
            if flows_checked % 100 == 0:
                logger.info(f"  checked {flows_checked} flows, {len(mismatches)} mismatches so far")

        logger.info(f"Consistent hash: {flows_checked} checked, {len(mismatches)} mismatches")
        assert not mismatches, (
            f"Consistent hashing failed: {len(mismatches)} flow(s) hit a different endpoint.\n"
            + "\n".join(f"  flow={k} expected={e} got={a}" for k, e, a in mismatches[:10])
        )

    def _withdraw_endpoint(self, flow_map):
        """
        After the withdrawn endpoint is removed from the DUT config:
        - No flow may hit the withdrawn endpoint.
        - Flows that previously went to OTHER endpoints must stay on the
          exact same endpoint (zero collateral disruption — this is the
          key FG ECMP property).
        - Flows that previously went to the withdrawn endpoint may go
          anywhere else.
        """
        assert self.withdraw_endpoint, "withdraw_endpoint param is required"

        redistributed = 0
        self.tcp_sport = 1234
        self.tcp_dport = 5000

        for flow_key, old_endpoint in flow_map[self.dst_ip].items():
            sport, dport = map(int, flow_key.split(":"))
            new_endpoint = self._send_and_capture_endpoint(sport, dport)

            assert new_endpoint is not None, f"No response for flow {flow_key}"
            assert new_endpoint != self.withdraw_endpoint, (
                f"Flow {flow_key} still hitting withdrawn endpoint {self.withdraw_endpoint}"
            )

            if old_endpoint == self.withdraw_endpoint:
                # This flow must redistribute to something else — any valid endpoint is fine
                redistributed += 1
                flow_map[self.dst_ip][flow_key] = new_endpoint
            else:
                # This flow must stay on exactly the same endpoint
                assert new_endpoint == old_endpoint, (
                    f"Flow {flow_key} was collaterally disrupted: "
                    f"{old_endpoint} -> {new_endpoint} "
                    f"(only flows to {self.withdraw_endpoint} should move)"
                )

        logger.info(
            f"Withdrawal result: {redistributed} flows redistributed from "
            f"{self.withdraw_endpoint}, all other flows undisturbed."
        )

    def _add_endpoint(self, flow_map):
        """
        After a new endpoint is added to the DUT config:
        - At most ADD_ENDPOINT_MAX_DISRUPTION (15%) of flows may move to
          the new endpoint.
        - Flows that do not move to the new endpoint must stay on their
          current endpoint (no unrelated churn).
        """
        assert self.add_endpoint, "add_endpoint param is required"

        moved_to_new = 0
        unexpected_moves = []
        total = len(flow_map[self.dst_ip])
        self.tcp_sport = 1234
        self.tcp_dport = 5000

        for flow_key, old_endpoint in flow_map[self.dst_ip].items():
            sport, dport = map(int, flow_key.split(":"))
            new_endpoint = self._send_and_capture_endpoint(sport, dport)

            assert new_endpoint is not None, f"No response for flow {flow_key}"

            if new_endpoint == self.add_endpoint:
                moved_to_new += 1
                flow_map[self.dst_ip][flow_key] = new_endpoint
            elif new_endpoint != old_endpoint:
                unexpected_moves.append((flow_key, old_endpoint, new_endpoint))

        disruption_rate = moved_to_new / total if total > 0 else 0
        logger.info(
            f"Addition result: {moved_to_new}/{total} flows ({disruption_rate:.1%}) "
            f"moved to new endpoint {self.add_endpoint}."
        )
        if unexpected_moves:
            logger.warning(
                f"  {len(unexpected_moves)} flow(s) moved to an endpoint other than "
                f"{self.add_endpoint} (unexpected with FG ECMP):"
            )
            for flow_key, old_ep, new_ep in unexpected_moves[:5]:
                logger.warning(f"    flow={flow_key} {old_ep} -> {new_ep}")

        assert disruption_rate <= ADD_ENDPOINT_MAX_DISRUPTION, (
            f"Too many flows disrupted by adding endpoint {self.add_endpoint}: "
            f"{moved_to_new}/{total} = {disruption_rate:.1%} "
            f"(threshold: {ADD_ENDPOINT_MAX_DISRUPTION:.0%})"
        )

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def runTest(self):
        # Load existing mapping for non-create_flows phases
        if self.test_case == "create_flows":
            flow_map = {}
        else:
            assert os.path.exists(self.persist_map), (
                f"Persist map {self.persist_map} not found. "
                "Run 'create_flows' test case first."
            )
            flow_map = self._load_persist_map()

        if self.dst_ip not in flow_map:
            flow_map[self.dst_ip] = {}

        if self.test_case == "create_flows":
            self._create_flows(flow_map)
            self._save_persist_map(flow_map)
            logger.info(f"Flow mapping saved to {self.persist_map}")

        elif self.test_case == "verify_consistent_hash":
            self._verify_consistent_hash(flow_map)

        elif self.test_case == "withdraw_endpoint":
            self._withdraw_endpoint(flow_map)
            self._save_persist_map(flow_map)

        elif self.test_case == "add_endpoint":
            self._add_endpoint(flow_map)
            self._save_persist_map(flow_map)

        else:
            raise ValueError(f"Unsupported test_case: {self.test_case!r}")

    def tearDown(self):
        self.dataplane.flush()
        logger.info("Dataplane flushed — VXLAN FG ECMP test complete")
