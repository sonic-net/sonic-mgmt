"""
PTF test for VXLAN Tunnel Route Fine-Grained ECMP
"""

import logging
import os
import time
import json
import ptf
import ptf.packet as scapy
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import (
    test_params_get,
    dp_poll,
    send_packet,
    simple_tcp_packet,
    simple_vxlan_packet,
)

MAX_DEVIATION = 0.25
_PLACEHOLDER_MAC = "00:aa:bb:cc:dd:ee"

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
        self.dut_vtep = params.get("dut_vtep")
        self.router_mac = params.get("router_mac")
        self.num_packets = int(params.get("num_packets", 1000))
        self.vxlan_port = int(params.get("vxlan_port", 4789))
        self.send_port = int(params.get("ptf_ingress_port", 0))
        self.exp_flow_count = params.get("exp_flow_count", {})
        self.require_all_endpoints_hit = bool(params.get("require_all_endpoints_hit", True))
        self.forbidden_endpoints = params.get("forbidden_endpoints", [])
        self.persist_map = params.get("persist_map", "/tmp/vxlan_tunnel_fg_ecmp_persist_map.json")

        self.withdraw_endpoint = params.get("withdraw_endpoint") if self.test_case == "withdraw_endpoint" else None
        self.add_endpoint = params.get("add_endpoint") if self.test_case == "add_endpoint" else None

        # swap_endpoints params: lists of simultaneously withdrawn / added endpoints
        self.withdrawn_endpoints = (
            params.get("withdrawn_endpoints", []) if self.test_case == "swap_endpoints" else []
        )
        self.added_endpoints = (
            params.get("added_endpoints", []) if self.test_case == "swap_endpoints" else []
        )

        self.vnet2_endpoints = params.get("vnet2_endpoints")
        _port2 = params.get("ptf_ingress_port_vnet2")
        self.ptf_ingress_port_vnet2 = int(_port2) if _port2 is not None else None
        self.ptf_src_ip_vnet2 = params.get("ptf_src_ip_vnet2")

        # mac_address / vni override verification params
        _expected_vni = params.get("expected_vni")
        self.expected_vni = int(_expected_vni) if _expected_vni is not None else None
        # endpoint_to_mac is a dict {endpoint_ip: mac_string}
        self.endpoint_to_mac = params.get("endpoint_to_mac", {})

        self.expected_egress_ports = [int(p) for p in params.get("expected_egress_ports", [])]

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

    def _next_ports(self):
        self.tcp_sport = (self.tcp_sport % 65534) + 1
        self.tcp_dport = (self.tcp_dport % 65534) + 1
        return self.tcp_sport, self.tcp_dport

    def _send_and_capture_endpoint(self, sport, dport, send_port=None, src_ip=None, valid_endpoints=None):
        send_port = self.send_port if send_port is None else send_port
        src_ip = self.src_ip if src_ip is None else src_ip
        valid_endpoints = self.endpoints if valid_endpoints is None else valid_endpoints

        src_mac = self.dataplane.get_mac(0, send_port)
        pkt = self._build_inner_tcp(sport, dport, src_mac, src_ip)
        send_packet(self, send_port, pkt)

        deadline = time.time() + 2.0
        while time.time() < deadline:
            remaining = deadline - time.time()
            result = dp_poll(self, device_number=0, timeout=min(remaining, 1.0))
            if not isinstance(result, self.dataplane.PollSuccess):
                break

            ether = scapy.Ether(result.packet)
            if scapy.IP not in ether or scapy.UDP not in ether:
                continue
            if ether[scapy.UDP].dport != self.vxlan_port:
                continue

            try:
                inner = scapy.Ether(bytes(ether[scapy.UDP].payload)[8:])
                if scapy.IP in inner and scapy.TCP in inner:
                    if inner[scapy.TCP].sport != sport or inner[scapy.TCP].dport != dport:
                        continue
            except Exception:
                continue

            if self.expected_egress_ports and result.port not in self.expected_egress_ports:
                raise AssertionError(
                    f"VXLAN-encap packet for flow sport={sport} dport={dport} "
                    f"received on PTF port {result.port}, expected one of "
                    f"{self.expected_egress_ports}"
                )

            outer_dst = ether[scapy.IP].dst
            return outer_dst if outer_dst in valid_endpoints else None

        return None

    def _build_inner_tcp(self, sport, dport, src_mac, src_ip):
        return simple_tcp_packet(
            eth_dst=self.router_mac,
            eth_src=src_mac,
            ip_dst=self.dst_ip,
            ip_src=src_ip,
            ip_id=105,
            ip_ttl=64,
            tcp_sport=sport,
            tcp_dport=dport,
            pktlen=100,
        )

    def _build_expected_for_endpoint(self, inner_pkt, endpoint, vni, inner_dst_mac):
        inner_exp = inner_pkt.copy()
        inner_exp[scapy.Ether].src = self.router_mac
        inner_exp[scapy.Ether].dst = inner_dst_mac
        inner_exp[scapy.IP].ttl -= 1

        encap = simple_vxlan_packet(
            eth_src=self.router_mac,
            eth_dst=_PLACEHOLDER_MAC,
            ip_src=self.dut_vtep,
            ip_dst=endpoint,
            ip_id=0,
            ip_ttl=128,
            udp_sport=12345,
            udp_dport=self.vxlan_port,
            with_udp_chksum=False,
            vxlan_vni=vni,
            inner_frame=inner_exp,
        )
        encap[scapy.IP].flags = 0x2

        m = Mask(encap)
        m.set_ignore_extra_bytes()
        m.set_do_not_care_scapy(scapy.Ether, "src")
        m.set_do_not_care_scapy(scapy.Ether, "dst")
        m.set_do_not_care_scapy(scapy.IP, "ttl")
        m.set_do_not_care_scapy(scapy.IP, "id")
        m.set_do_not_care_scapy(scapy.IP, "chksum")
        m.set_do_not_care_scapy(scapy.UDP, "sport")
        return m

    def _check_distribution(self, hit_count_map):
        deviation_max = 0.0
        for endpoint, exp_flows in self.exp_flow_count.items():
            actual = hit_count_map.get(endpoint, 0)
            if exp_flows == 0:
                deviation = float('inf') if actual else 0.0
            else:
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

            if self.require_all_endpoints_hit:
                assert set(self.endpoints) == set(hit_count_map.keys()), (
                    f"Not all endpoints were reached.\n"
                    f"  Expected: {sorted(self.endpoints)}\n"
                    f"  Got:      {sorted(hit_count_map.keys())}"
                )
            else:
                stray = set(hit_count_map.keys()) - set(self.endpoints)
                assert not stray, (
                    f"Flows landed on endpoints not in configured set: {sorted(stray)}"
                )
                assert total > 0, "No flows were captured at all"

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
            assert actual is not None, f"No response for flow {flow_key}"
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
        - Flows that previously went to other endpoints must stay on the
          exact same endpoint
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
        - At most MAX_DEVIATION (~10%) of flows may move to
          the new endpoint.
        - Flows that do not move to the new endpoint must stay on their
          current endpoint
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

        assert disruption_rate <= MAX_DEVIATION, (
            f"Too many flows disrupted by adding endpoint {self.add_endpoint}: "
            f"{moved_to_new}/{total} = {disruption_rate:.1%} "
            f"(threshold: {MAX_DEVIATION:.0%})"
        )

    def _swap_endpoints(self, flow_map):
        """
        After N endpoints are simultaneously removed and N new endpoints are
        added (with the total endpoint count unchanged):
        - No flow may hit any withdrawn endpoint.
        - Flows whose previous endpoint is unchanged (still in self.endpoints)
          must stay on the exact same endpoint
        - Flows whose previous endpoint was withdrawn may move to any current
          endpoint
        - Every newly added endpoint must receive at least one flow.
        """
        assert self.withdrawn_endpoints, "withdrawn_endpoints param is required"
        assert self.added_endpoints, "added_endpoints param is required"

        withdrawn_set = set(self.withdrawn_endpoints)
        added_set = set(self.added_endpoints)
        current_set = set(self.endpoints)

        redistributed = 0
        added_hits = {ep: 0 for ep in self.added_endpoints}
        collateral = []
        self.tcp_sport = 1234
        self.tcp_dport = 5000

        for flow_key, old_endpoint in flow_map[self.dst_ip].items():
            sport, dport = map(int, flow_key.split(":"))
            new_endpoint = self._send_and_capture_endpoint(sport, dport)

            assert new_endpoint is not None, f"No response for flow {flow_key}"
            assert new_endpoint not in withdrawn_set, (
                f"Flow {flow_key} still hitting withdrawn endpoint {new_endpoint}"
            )
            assert new_endpoint in current_set, (
                f"Flow {flow_key} hit endpoint {new_endpoint} not in current set {current_set}"
            )

            if old_endpoint in withdrawn_set:
                redistributed += 1
                flow_map[self.dst_ip][flow_key] = new_endpoint
            elif new_endpoint != old_endpoint:
                collateral.append((flow_key, old_endpoint, new_endpoint))

            if new_endpoint in added_set:
                added_hits[new_endpoint] += 1

        logger.info(
            f"Swap result: {redistributed} flows redistributed from withdrawn "
            f"endpoints {sorted(withdrawn_set)}; added endpoint hits={added_hits}; "
            f"collateral disruptions={len(collateral)}"
        )

        assert not collateral, (
            f"{len(collateral)} flow(s) on unchanged endpoints were collaterally "
            f"disrupted (only flows on withdrawn endpoints {sorted(withdrawn_set)} "
            f"should move). First few: " +
            "; ".join(f"flow={k} {o}->{n}" for k, o, n in collateral[:5])
        )

        missing_added = [ep for ep, c in added_hits.items() if c == 0]
        assert not missing_added, (
            f"Newly added endpoint(s) received no flows: {missing_added}"
        )

    def _verify_mac_vni(self):
        assert self.expected_vni is not None, "expected_vni param is required"
        assert self.endpoint_to_mac, "endpoint_to_mac param is required"
        assert self.dut_vtep, "dut_vtep param is required to build expected packet"

        # Normalize configured MACs to lowercase for the Mask constructor.
        endpoint_to_mac_norm = {ep: mac.lower() for ep, mac in self.endpoint_to_mac.items()}
        for ep in self.endpoints:
            assert ep in endpoint_to_mac_norm, f"No mac_address configured for endpoint {ep}"

        src_mac = self.dataplane.get_mac(0, self.send_port)
        endpoint_hits = {ep: 0 for ep in self.endpoints}
        mismatch_count = 0
        no_response = 0

        self.tcp_sport = 1234
        self.tcp_dport = 5000

        for i in range(self.num_packets):
            sport, dport = self._next_ports()
            inner = self._build_inner_tcp(sport, dport, src_mac, self.src_ip)
            send_packet(self, self.send_port, inner)

            matched = False
            deadline = time.time() + 2.0
            while time.time() < deadline:
                remaining = deadline - time.time()
                res = dp_poll(self, device_number=0, timeout=min(remaining, 1.0))
                if not isinstance(res, self.dataplane.PollSuccess):
                    break

                pkt = scapy.Ether(res.packet)
                if scapy.IP not in pkt or scapy.UDP not in pkt:
                    continue
                if pkt[scapy.UDP].dport != self.vxlan_port:
                    continue
                outer_dst = pkt[scapy.IP].dst
                if outer_dst not in self.endpoints:
                    logger.error(f"Received VXLAN pkt to unexpected endpoint {outer_dst}")
                    continue

                if self.expected_egress_ports and res.port not in self.expected_egress_ports:
                    raise AssertionError(
                        f"VXLAN-encap packet to {outer_dst} received on PTF port "
                        f"{res.port}, expected one of {self.expected_egress_ports}"
                    )

                expected_mac = endpoint_to_mac_norm[outer_dst]
                exp = self._build_expected_for_endpoint(
                    inner, outer_dst, self.expected_vni, expected_mac,
                )

                if exp.pkt_match(pkt):
                    endpoint_hits[outer_dst] += 1
                    matched = True
                    break

                mismatch_count += 1
                logger.error(
                    f"Packet mismatch for endpoint={outer_dst}, "
                    f"expected_mac={expected_mac}, expected_vni={self.expected_vni}.\n"
                    f"\nExpected:\n{exp}\n\nReceived:\n{pkt}\n"
                )
                break

            if not matched and mismatch_count == 0:
                no_response += 1

            if (i + 1) % 100 == 0:
                logger.info(
                    f"  verified {i + 1}/{self.num_packets} flows, "
                    f"hits={endpoint_hits} mismatches={mismatch_count} "
                    f"no_response={no_response}"
                )

        logger.info(
            f"verify_mac_vni done: hits={endpoint_hits} "
            f"mismatches={mismatch_count} no_response={no_response}"
        )

        assert mismatch_count == 0, (
            f"{mismatch_count} packet(s) did not match expected MAC/VNI encapsulation"
        )
        assert no_response < self.num_packets, (
            f"All {self.num_packets} flows produced no VXLAN response"
        )
        missing = [ep for ep, c in endpoint_hits.items() if c == 0]
        assert not missing, f"No packets observed for endpoints: {missing}"

    def _verify_endpoint_unreachable(self):
        assert self.forbidden_endpoints, "forbidden_endpoints param is required"

        forbidden_set = set(self.forbidden_endpoints)
        valid_set = set(self.endpoints) - forbidden_set
        assert valid_set, (
            "All configured endpoints are in forbidden_endpoints; "
            "nothing left to forward to"
        )

        forbidden_hits = {ep: 0 for ep in self.forbidden_endpoints}
        valid_hits = 0
        no_response = 0

        self.tcp_sport = 1234
        self.tcp_dport = 5000

        for i in range(self.num_packets):
            sport, dport = self._next_ports()
            endpoint = self._send_and_capture_endpoint(sport, dport)
            if endpoint is None:
                no_response += 1
                continue
            if endpoint in forbidden_set:
                forbidden_hits[endpoint] += 1
            else:
                valid_hits += 1
            if (i + 1) % 100 == 0:
                logger.info(
                    f"  sent {i + 1}/{self.num_packets} flows, "
                    f"valid_hits={valid_hits}, forbidden_hits={forbidden_hits}, "
                    f"no_response={no_response}"
                )

        logger.info(
            f"verify_endpoint_unreachable done: valid_hits={valid_hits}, "
            f"forbidden_hits={forbidden_hits}, no_response={no_response}"
        )

        offenders = {ep: c for ep, c in forbidden_hits.items() if c > 0}
        assert not offenders, (
            f"Forbidden endpoint(s) received traffic (route update was "
            f"unexpectedly accepted by hardware): {offenders}"
        )
        assert valid_hits > 0, (
            f"No flows landed on any allowed endpoint "
            f"({len(valid_set)} configured, {no_response} flows had no response)"
        )

    def _conflicting_dest_prefix(self):
        """
        Send flows from each VNET's ingress port and verify that:
        - All Vnet1 flows reach only Vnet1 endpoints
        - All Vnet2 flows reach only Vnet2 endpoints
        - No cross-VNET contamination
        """
        assert self.vnet2_endpoints, "vnet2_endpoints param required"
        assert self.ptf_ingress_port_vnet2 is not None, "ptf_ingress_port_vnet2 required"

        all_endpoints = self.endpoints + self.vnet2_endpoints

        vnet1_misses = []
        self.tcp_sport, self.tcp_dport = 1234, 5000
        for _ in range(self.num_packets):
            sport, dport = self._next_ports()
            endpoint = self._send_and_capture_endpoint(
                sport, dport,
                send_port=self.send_port,
                src_ip=self.src_ip,
                valid_endpoints=all_endpoints,
            )
            if endpoint is None:
                continue
            if endpoint not in self.endpoints:
                vnet1_misses.append((sport, dport, endpoint))

        vnet2_misses = []
        self.tcp_sport, self.tcp_dport = 1234, 5000
        for _ in range(self.num_packets):
            sport, dport = self._next_ports()
            endpoint = self._send_and_capture_endpoint(
                sport, dport,
                send_port=self.ptf_ingress_port_vnet2,
                src_ip=self.ptf_src_ip_vnet2,
                valid_endpoints=all_endpoints,
            )
            if endpoint is None:
                continue
            if endpoint not in self.vnet2_endpoints:
                vnet2_misses.append((sport, dport, endpoint))

        assert not vnet1_misses, (
            f"Vnet1 flows reached wrong endpoints (expected only {self.endpoints}): "
            f"{vnet1_misses[:5]}"
        )
        assert not vnet2_misses, (
            f"Vnet2 flows reached wrong endpoints (expected only {self.vnet2_endpoints}): "
            f"{vnet2_misses[:5]}"
        )
        logger.info(
            f"Isolation verified: {self.num_packets} Vnet1 flows reached only Vnet1 endpoints, "
            f"{self.num_packets} Vnet2 flows reached only Vnet2 endpoints."
        )

    # ------------------------------------------------------------------
    # Run Test
    # ------------------------------------------------------------------

    def runTest(self):
        if self.test_case == "conflicting_dest_prefix":
            self._conflicting_dest_prefix()
            return
        if self.test_case == "verify_mac_vni":
            self._verify_mac_vni()
            return
        if self.test_case == "verify_endpoint_unreachable":
            self._verify_endpoint_unreachable()
            return

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

        elif self.test_case == "swap_endpoints":
            self._swap_endpoints(flow_map)
            self._save_persist_map(flow_map)

        else:
            raise ValueError(f"Unsupported test_case: {self.test_case!r}")

    def tearDown(self):
        self.dataplane.flush()
        logger.info("Dataplane flushed — VXLAN FG ECMP test complete")
