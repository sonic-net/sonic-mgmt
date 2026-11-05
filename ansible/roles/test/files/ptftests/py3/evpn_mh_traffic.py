"""Native PTF executor for semantic EVPN-MH traffic profiles."""

import errno
import math
import os
import socket
import struct
import threading
import time

import ptf
import ptf.packet as packet
import ptf.testutils as testutils
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from scapy.config import conf
from scapy.layers.inet6 import (ICMPv6ND_NA, ICMPv6ND_NS,
                                ICMPv6NDOptDstLLAddr,
                                ICMPv6NDOptSrcLLAddr, IPv6, in6_getnsmac,
                                in6_getnsma)
from scapy.layers.l2 import Dot1Q, Ether
from scapy.packet import Raw


class EvpnMhTraffic(BaseTest):
    def setUp(self):
        BaseTest.setUp(self)
        params = testutils.test_params_get()
        self.profile = params["profile"]
        self.port_map = params["port_map"]
        self.dataplane = ptf.dataplane_instance
        self.tx_sockets = {}
        self.dataplane.flush()

    def tearDown(self):
        for tx_socket in self.tx_sockets.values():
            tx_socket.close()
        BaseTest.tearDown(self)

    def _endpoint_ports(self, endpoint):
        bond = self.profile.get("bond_endpoints", {}).get(endpoint)
        if bond:
            return [int(self.port_map[role]) for role in bond["member_roles"]]
        return [int(self.port_map[endpoint])]

    def _packet(self, spec, defaults):
        size = int(spec.get("frame_size", defaults["frame_size"]))
        kind = spec["kind"]
        vlan_id = int(spec.get("vlan_id", 0))
        vlan_pcp = int(spec.get("vlan_pcp", 0))
        if kind == "ipv6_ns":
            target = socket.inet_pton(socket.AF_INET6, spec["target_ip"])
            multicast = in6_getnsma(target)
            pkt = Ether(src=spec["src_mac"], dst=in6_getnsmac(multicast))
            if vlan_id:
                pkt /= Dot1Q(vlan=vlan_id, prio=vlan_pcp)
            pkt /= IPv6(
                src=spec["src_ip"],
                dst=socket.inet_ntop(socket.AF_INET6, multicast),
                hlim=int(spec.get("hlim", 255)))
            pkt /= ICMPv6ND_NS(tgt=spec["target_ip"])
            pkt /= ICMPv6NDOptSrcLLAddr(lladdr=spec["src_mac"])
            padding = max(0, size - len(pkt))
            if padding:
                # Serialize first so IPv6 plen and the ICMPv6 checksum cover
                # only the valid ND payload.  Appending Raw directly to pkt
                # puts Ethernet padding inside IPv6, where receivers parse
                # the zero bytes as malformed ND options and discard it.
                return Ether(bytes(pkt) + (b"\x00" * padding))
            return pkt
        if kind == "ipv6_na":
            pkt = Ether(src=spec["src_mac"], dst=spec["dst_mac"])
            if vlan_id:
                pkt /= Dot1Q(vlan=vlan_id, prio=vlan_pcp)
            pkt /= IPv6(
                src=spec["src_ip"], dst=spec["dst_ip"],
                hlim=int(spec.get("hlim", 255)))
            pkt /= ICMPv6ND_NA(
                tgt=spec["target_ip"], R=0,
                S=int(spec.get("solicited", 1)),
                O=int(spec.get("override", 1)))
            pkt /= ICMPv6NDOptDstLLAddr(lladdr=spec["src_mac"])
            padding = max(0, size - len(pkt))
            if padding:
                return Ether(bytes(pkt) + (b"\x00" * padding))
            return pkt
        if kind in ("arp_reply", "arp_request"):
            is_reply = kind == "arp_reply"
            return testutils.simple_arp_packet(
                pktlen=size, eth_dst=spec["dst_mac"], eth_src=spec["src_mac"],
                vlan_vid=vlan_id, vlan_pcp=vlan_pcp,
                arp_op=(2 if is_reply else 1),
                ip_snd=spec["src_ip"], ip_tgt=spec["dst_ip"],
                hw_snd=spec["src_mac"],
                hw_tgt=(spec["dst_mac"] if is_reply else "00:00:00:00:00:00"))
        if kind == "ethernet":
            if vlan_id:
                pkt = Ether(src=spec["src_mac"], dst=spec["dst_mac"])
                pkt /= Dot1Q(
                    vlan=vlan_id, prio=vlan_pcp,
                    type=int(spec.get("ether_type", defaults.get("ether_type", 0x88B5))))
                padding = max(0, size - len(pkt))
                return pkt / Raw(load=b"\x00" * padding)
            return testutils.simple_eth_packet(
                pktlen=size, eth_src=spec["src_mac"], eth_dst=spec["dst_mac"],
                eth_type=int(spec.get("ether_type", defaults.get("ether_type", 0x88B5))))
        if kind == "ipv4_udp":
            return testutils.simple_udp_packet(
                pktlen=size, eth_src=spec["src_mac"], eth_dst=spec["dst_mac"],
                dl_vlan_enable=bool(vlan_id), vlan_vid=vlan_id, vlan_pcp=vlan_pcp,
                ip_src=spec["src_ip"], ip_dst=spec["dst_ip"],
                udp_sport=int(spec["udp_src"]), udp_dport=int(spec["udp_dst"]),
                ip_ttl=int(spec.get("ttl", 64)))
        if kind == "ipv4_icmp":
            return testutils.simple_icmp_packet(
                pktlen=size, eth_src=spec["src_mac"], eth_dst=spec["dst_mac"],
                dl_vlan_enable=bool(vlan_id), vlan_vid=vlan_id, vlan_pcp=vlan_pcp,
                ip_src=spec["src_ip"], ip_dst=spec["dst_ip"],
                icmp_type=int(spec.get("icmp_type", 8)))
        if kind == "ipv6_udp":
            return testutils.simple_udpv6_packet(
                pktlen=size, eth_src=spec["src_mac"], eth_dst=spec["dst_mac"],
                dl_vlan_enable=bool(vlan_id), vlan_vid=vlan_id, vlan_pcp=vlan_pcp,
                ipv6_src=spec["src_ip"], ipv6_dst=spec["dst_ip"],
                udp_sport=int(spec["udp_src"]), udp_dport=int(spec["udp_dst"]),
                ipv6_hlim=int(spec.get("hlim", 64)))
        raise ValueError("unsupported packet kind {}".format(kind))

    @staticmethod
    def _expected_spec(packet, expected):
        spec = dict(packet)
        spec.update(expected or {})
        return spec

    def _expected_by_observation(self, flow, defaults, observations):
        expected_spec = self._expected_spec(
            flow["packet"], flow.get("expected_packet"))
        expected = {}
        for observation in observations:
            spec = dict(expected_spec)
            # The expected tag is a property of the receiving endpoint, not
            # of the ingress packet.  A value of zero deliberately models
            # tag removal on an access/bond endpoint.
            spec["vlan_id"] = int(observation[1])
            if "frame_size" not in (flow.get("expected_packet") or {}):
                # frame_size includes the Ethernet/VLAN headers. Adding or
                # removing a tag changes the wire length by four bytes while
                # preserving the carried payload. Honor an explicit expected
                # frame size, and retain Ethernet's minimum frame padding.
                ingress_vlan = int(flow["packet"].get("vlan_id", 0))
                ingress_size = int(flow["packet"].get(
                    "frame_size", defaults["frame_size"]))
                spec["frame_size"] = max(
                    60, ingress_size + 4 * (
                        bool(spec["vlan_id"]) - bool(ingress_vlan)))
            expected[observation] = self._packet(spec, defaults)
        return expected

    def _poll_counts(self, expected_by_observation, timeout, identity=None,
                     allowed_identities=None):
        """Count copies and unique identities independently.

        Observation keys are ``(port, vlan)`` tuples.  Keeping the semantic
        VLAN in the key lets H3 and H4 share the PTF backplane port without a
        VLAN10 packet being mistaken for a forbidden VLAN20 copy.
        """
        counts = {observation: 0 for observation in expected_by_observation}
        unique = {observation: set() for observation in expected_by_observation}
        deadline = time.time() + timeout
        while time.time() < deadline:
            result = testutils.dp_poll(self, device_number=0, timeout=0.1)
            if not isinstance(result, self.dataplane.PollSuccess):
                continue
            for observation, expected in expected_by_observation.items():
                if (result.port != observation[0]
                        or not ptf.dataplane.match_exp_pkt(
                            expected, result.packet)):
                    continue
                counts[observation] += 1
                if identity is not None:
                    value = identity(result.packet)
                    if self._identity_is_allowed(value, allowed_identities):
                        unique[observation].add(value)
                break
        return counts, unique

    @staticmethod
    def _identity_is_allowed(value, allowed_identities):
        return (
            value is not None
            and (allowed_identities is None or value in allowed_identities)
        )

    def _endpoint_observations(self, endpoint):
        vlan = int(self.profile.get("endpoint_vlans", {}).get(endpoint, 0))
        return [(port, vlan) for port in self._endpoint_ports(endpoint)]

    def _resolve_observations(self, flow):
        runtime = self.profile.get("runtime", {})
        overrides = runtime.get("flow_overrides", {}).get(flow["name"], {})
        groups = overrides.get("receive_groups", flow["receive_groups"])
        forbidden = overrides.get(
            "forbidden_endpoints", flow.get("forbidden_endpoints", []))
        resolved_groups = []
        for group in groups:
            resolved_groups.append(sorted({
                observation
                for endpoint in group
                for observation in self._endpoint_observations(endpoint)
            }))
        forbidden_observations = sorted({
            observation
            for endpoint in forbidden
            for observation in self._endpoint_observations(endpoint)
        })
        return resolved_groups, forbidden_observations

    def _resolve_groups(self, flow):
        """Compatibility view used by older focused unit tests."""
        groups, forbidden = self._resolve_observations(flow)
        return ([[observation[0] for observation in group] for group in groups],
                [observation[0] for observation in forbidden])

    def _flow_value(self, flow, name, default=None):
        """Return a runtime override without changing the stored profile."""
        overrides = self.profile.get("runtime", {}).get(
            "flow_overrides", {}).get(flow["name"], {})
        return overrides.get(name, flow.get(name, default))

    def _resolve_tx_target(self, flow):
        runtime = self.profile.get("runtime", {})
        overrides = runtime.get("flow_overrides", {}).get(flow["name"], {})
        endpoint = overrides.get("tx_endpoint", flow["tx_endpoint"])
        interface = overrides.get("tx_interface", flow.get("tx_interface"))
        if interface is None and endpoint in self.profile.get("bond_endpoints", {}):
            # H2 is a real 802.3ad endpoint.  Transmit through its topology-
            # owned macvlan above the bond so Linux/LACP selects a member.
            # A testcase that intentionally targets one physical member must
            # provide an explicit ``tx_interface`` override.
            interface = self.profile["bond_endpoints"][endpoint]["host_interface"]
        return (self._endpoint_ports(endpoint)[0], interface)

    def _send(self, tx_port, tx_interface, pkt, count=1):
        if tx_interface:
            tx_socket = self.tx_sockets.get(tx_interface)
            if tx_socket is None:
                tx_socket = conf.L2socket(iface=tx_interface)
                self.tx_sockets[tx_interface] = tx_socket
            for _ in range(count):
                for attempt in range(3):
                    try:
                        tx_socket.send(pkt)
                        break
                    except OSError as error:
                        if error.errno != errno.ENOBUFS or attempt == 2:
                            raise
                        time.sleep(0.05)
        else:
            testutils.send_packet(self, tx_port, pkt, count=count)

    def _prime_neighbors(self):
        """Teach directly connected IPv4/IPv6 host neighbors before routed flows."""
        for endpoint, host in self.profile.get("neighbors", {}).items():
            mac = host["mac"]
            vlan_id = int(host.get("tagged_vlan", 0) or 0)
            ports = self._endpoint_ports(endpoint)
            host_interface = (
                self.profile["bond_endpoints"][endpoint]["host_interface"]
                if endpoint in self.profile.get("bond_endpoints", {}) else None)
            tx_targets = ([(ports[0], host_interface)] if host_interface else
                          [(port, None) for port in ports])
            for port, interface in tx_targets:
                arp = testutils.simple_arp_packet(
                    pktlen=60, eth_dst="ff:ff:ff:ff:ff:ff", eth_src=mac,
                    vlan_vid=vlan_id,
                    arp_op=1, ip_snd=host["ipv4"], ip_tgt=host["gateway_ipv4"],
                    hw_snd=mac)
                self._send(port, interface, arp)

                target = socket.inet_pton(socket.AF_INET6, host["gateway_ipv6"])
                multicast = in6_getnsma(target)
                ns = Ether(src=mac, dst=in6_getnsmac(multicast))
                if vlan_id:
                    ns /= Dot1Q(vlan=vlan_id)
                ns /= IPv6(src=host["ipv6"],
                           dst=socket.inet_ntop(socket.AF_INET6, multicast),
                           hlim=255)
                ns /= ICMPv6ND_NS(tgt=host["gateway_ipv6"])
                ns /= ICMPv6NDOptSrcLLAddr(lladdr=mac)
                self._send(port, interface, ns)
        time.sleep(1)
        self.dataplane.flush()

    def _send_for_duration(self, tx_port, tx_interface, pkt, duration,
                           packets_per_second, sent):
        interval = 1.0 / packets_per_second
        deadline = time.time() + duration
        while time.time() < deadline:
            self._send(tx_port, tx_interface, pkt)
            sent[0] += 1
            time.sleep(interval)

    @staticmethod
    def _vary_udp_ports(pkt, offset, source_count, destination_count, step):
        varied = pkt.copy()
        sport = (int(varied[packet.UDP].sport)
                 + (offset % source_count) * step)
        dport = (int(varied[packet.UDP].dport)
                 + (offset % destination_count) * step)
        if sport > 65535 or dport > 65535:
            raise ValueError("varied UDP port exceeds 65535")
        varied[packet.UDP].sport = sport
        varied[packet.UDP].dport = dport
        varied[packet.UDP].chksum = None
        if packet.IP in varied:
            varied[packet.IP].chksum = None
        return varied

    @staticmethod
    def _mask_udp_ports(expected):
        masked = Mask(expected)
        masked.set_do_not_care_scapy(packet.UDP, "sport")
        masked.set_do_not_care_scapy(packet.UDP, "dport")
        masked.set_do_not_care_scapy(packet.UDP, "chksum")
        if packet.IP in expected:
            masked.set_do_not_care_scapy(packet.IP, "chksum")
        return masked

    @staticmethod
    def _udp_tuple(raw_packet):
        parsed = Ether(bytes(raw_packet))
        if packet.UDP not in parsed:
            return None
        return (int(parsed[packet.UDP].sport), int(parsed[packet.UDP].dport))

    @staticmethod
    def _mask_expected_fields(expected, fields):
        masked = Mask(expected)
        supported = {
            "ethernet.src": (packet.Ether, "src"),
            "ipv4.id": (packet.IP, "id"),
            "ipv4.ttl": (packet.IP, "ttl"),
            "ipv4.checksum": (packet.IP, "chksum"),
            "ipv6.hlim": (packet.IPv6, "hlim"),
            "icmp.checksum": (packet.ICMP, "chksum"),
            "payload": (Raw, "load"),
        }
        for field in fields:
            if field == "payload":
                if Raw not in expected:
                    raise ValueError("expected packet has no Raw payload to mask")
                raw_payload = expected[Raw]
                payload_offset = (
                    len(bytes(expected)) - len(bytes(raw_payload))) * 8
                masked.set_do_not_care(
                    payload_offset, len(bytes(raw_payload.load)) * 8)
                continue
            if field not in supported:
                raise ValueError("unsupported ignored packet field {}".format(field))
            layer, attribute = supported[field]
            masked.set_do_not_care_scapy(layer, attribute)
        return masked

    @staticmethod
    def _sequence_packet(pkt, sequence, field):
        varied = pkt.copy()
        if field == "udp_src":
            varied[packet.UDP].sport = int(pkt[packet.UDP].sport) + sequence
            if int(varied[packet.UDP].sport) > 65535:
                raise ValueError("continuous UDP sequence exceeds port range")
            varied[packet.UDP].chksum = None
            if packet.IP in varied:
                varied[packet.IP].chksum = None
            return varied
        if field == "raw":
            payload = bytes(varied[Raw].load) if Raw in varied else b""
            encoded = struct.pack("!Q", sequence)
            if Raw in varied:
                varied[Raw].load = encoded + payload[len(encoded):]
            else:
                varied /= Raw(load=encoded)
            if packet.UDP in varied:
                varied[packet.UDP].chksum = None
            if packet.IP in varied:
                varied[packet.IP].chksum = None
            return varied
        raise ValueError("unsupported sequence field {}".format(field))

    @staticmethod
    def _sequence_value(raw_packet, field, base_udp_source=0):
        parsed = Ether(bytes(raw_packet))
        if field == "udp_src" and packet.UDP in parsed:
            return int(parsed[packet.UDP].sport) - int(base_udp_source)
        if field == "raw" and Raw in parsed and len(bytes(parsed[Raw].load)) >= 8:
            return struct.unpack("!Q", bytes(parsed[Raw].load)[:8])[0]
        return None

    def _assert_delivery(self, flow, sent, counts, groups, forbidden,
                         unique_by_port=None):
        if self._flow_value(flow, "transmit_only", False):
            return
        loss = float(self._flow_value(
            flow, "max_loss_percent", self.profile["defaults"]["max_loss_percent"]))
        duplicate = float(self._flow_value(
            flow, "max_duplicate_percent",
            self.profile["defaults"].get("max_duplicate_percent", 0)))
        minimum = int(math.ceil(sent * (100.0 - loss) / 100.0))
        maximum = int(math.floor(sent * (100.0 + duplicate) / 100.0))
        for group in groups:
            received = sum(counts.get(port, 0) for port in group)
            delivered = received
            if unique_by_port is not None:
                delivered = len(set().union(
                    *(unique_by_port.get(port, set()) for port in group)))
            if delivered < minimum:
                raise AssertionError(
                    "{} delivered {} unique packets on {}, expected at least {}".format(
                        flow["name"], delivered, group, minimum))
            if received > maximum:
                raise AssertionError(
                    "{} received {} copies on {}, maximum {} for {} sent".format(
                        flow["name"], received, group, maximum, sent))
            minimum_share = float(self._flow_value(
                flow, "min_port_share_percent", 0))
            if minimum_share:
                for port in group:
                    share_count = counts.get(port, 0)
                    if unique_by_port is not None:
                        share_count = len(unique_by_port.get(port, set()))
                    if share_count < int(sent * minimum_share / 100.0):
                        raise AssertionError(
                            "{} did not exercise ECMP port {}: {} packets".format(
                                flow["name"], port, share_count))
        forbidden_percent = float(self._flow_value(
            flow, "forbidden_max_percent",
            self.profile["defaults"].get("forbidden_max_percent", 0)))
        maximum_forbidden = int(sent * forbidden_percent / 100.0)
        for port in forbidden:
            if counts.get(port, 0) > maximum_forbidden:
                raise AssertionError(
                    "{} received {} packets on forbidden port {}, maximum {}".format(
                        flow["name"], counts[port], port, maximum_forbidden))

    @staticmethod
    def _valid_sequences(state, port):
        sent = int(state.get("sent", 0))
        return {
            sequence for sequence in state["unique_by_port"].get(port, set())
            if isinstance(sequence, int) and 0 <= sequence < sent
        }

    @classmethod
    def _continuous_barrier_reached(cls, states, barrier_packets):
        return all(
            all(len(set().union(
                *(cls._valid_sequences(state, port) for port in group)))
                >= barrier_packets for group in state["groups"])
            for state in states)

    @staticmethod
    def _assert_continuous_contract(state):
        flow = state["flow"]
        minimum_packets = int(flow.get("minimum_packets", 1))
        if state["sent"] < minimum_packets:
            raise AssertionError(
                "{} sent {} packets, below minimum continuous contract {}".format(
                    flow["name"], state["sent"], minimum_packets))
        minimum_duration = float(flow.get("minimum_duration_seconds", 0))
        elapsed = float(state.get("ended_at", 0)) - float(
            state.get("started_at", 0))
        if elapsed < minimum_duration:
            raise AssertionError(
                "{} ran {:.3f}s, below minimum continuous contract {:.3f}s".format(
                    flow["name"], elapsed, minimum_duration))

    def _continuous_state(self, flow, defaults):
        packet_to_send = self._packet(flow["packet"], defaults)
        sequence_field = self._flow_value(flow, "sequence_field")
        ignored = list(flow.get("ignore_expected_fields", []))
        groups, forbidden = self._resolve_observations(flow)
        observed = sorted({item for group in groups for item in group} | set(forbidden))
        expected_by_observation = self._expected_by_observation(
            flow, defaults, observed)
        for observation, expected_packet in expected_by_observation.items():
            if sequence_field == "udp_src":
                masked = self._mask_expected_fields(
                    expected_packet, ignored + ["ipv4.checksum"])
                masked.set_do_not_care_scapy(packet.UDP, "sport")
                masked.set_do_not_care_scapy(packet.UDP, "chksum")
            elif sequence_field == "raw":
                fields = ignored + ["payload"]
                if packet.IP in expected_packet:
                    fields.append("ipv4.checksum")
                masked = self._mask_expected_fields(expected_packet, fields)
                if packet.UDP in expected_packet:
                    masked.set_do_not_care_scapy(packet.UDP, "chksum")
            else:
                raise ValueError(
                    "continuous flow {} requires sequence_field".format(
                        flow["name"]))
            expected_by_observation[observation] = masked
        tx_port, tx_interface = self._resolve_tx_target(flow)
        return {
            "flow": flow,
            "packet": packet_to_send,
            "expected_by_observation": expected_by_observation,
            "sequence_field": sequence_field,
            "base_udp_source": (int(packet_to_send[packet.UDP].sport)
                                if sequence_field == "udp_src" else 0),
            "groups": groups,
            "forbidden": forbidden,
            "observed": observed,
            "tx_port": tx_port,
            "tx_interface": tx_interface,
            "sent": 0,
            "counts": {item: 0 for item in observed},
            "unique_by_port": {item: set() for item in observed},
            "copies_by_port": {item: [] for item in observed},
            "event_sent_start": None,
            "event_sent_end": None,
            "sender_error": None,
            "started_at": None,
            "ended_at": None,
        }

    def _continuous_sender(self, state, start_event, sender_failed=None):
        start_event.wait()
        state["started_at"] = time.monotonic()
        try:
            flow = state["flow"]
            interval = 1.0 / float(self._flow_value(
                flow, "packets_per_second", 100))
            deadline = time.monotonic() + float(self._flow_value(
                flow, "duration_seconds", 0))
            stop_file = self.profile.get("stop_file")
            while (time.monotonic() < deadline
                   and not (stop_file and os.path.exists(stop_file))
                   and not (sender_failed and sender_failed.is_set())):
                sequence = state["sent"]
                current = self._sequence_packet(
                    state["packet"], sequence, state["sequence_field"])
                # Publish the upper sequence bound before sending.  The
                # receiver thread can otherwise observe a fast loopback copy
                # before ``sent`` advances and incorrectly discard it.
                state["sent"] += 1
                try:
                    self._send(
                        state["tx_port"], state["tx_interface"], current)
                except Exception:
                    state["sent"] -= 1
                    raise
                time.sleep(interval)
        except Exception as error:  # Propagated by the owning PTF thread.
            state["sender_error"] = error
            if sender_failed:
                sender_failed.set()
        finally:
            state["ended_at"] = time.monotonic()

    def _update_event_window(self, states):
        start_file = self.profile.get("event_start_file")
        end_file = self.profile.get("event_end_file")
        if (start_file and os.path.exists(start_file)):
            observed_start = False
            for state in states:
                if state["event_sent_start"] is None:
                    state["event_sent_start"] = int(state["sent"])
                    observed_start = True
            if observed_start:
                ack_file = self.profile.get("event_start_ack_file")
                if ack_file:
                    with open(ack_file, "w", encoding="utf-8") as stream:
                        stream.write("observed\n")
        if (end_file and os.path.exists(end_file)):
            observed_end = False
            for state in states:
                if state["event_sent_end"] is None:
                    state["event_sent_end"] = int(state["sent"])
                    observed_end = True
            if observed_end:
                ack_file = self.profile.get("event_end_ack_file")
                if ack_file:
                    with open(ack_file, "w", encoding="utf-8") as stream:
                        stream.write("observed\n")

    def _run_continuous_parallel(self, flows, defaults):
        if self.profile.get("prime_neighbors", True):
            self._prime_neighbors()
        self.dataplane.flush()
        states = [self._continuous_state(flow, defaults) for flow in flows]
        start_event = threading.Event()
        sender_failed = threading.Event()
        threads = [threading.Thread(
            target=self._continuous_sender,
            args=(state, start_event, sender_failed))
            for state in states]
        for thread in threads:
            thread.daemon = True
            thread.start()
        start_event.set()

        barrier_file = self.profile.get("barrier_file")
        barrier_packets = int(self.profile.get("barrier_packets", 1))
        barrier_written = False
        while any(thread.is_alive() for thread in threads):
            self._update_event_window(states)
            result = testutils.dp_poll(self, device_number=0, timeout=0.1)
            if not isinstance(result, self.dataplane.PollSuccess):
                continue
            for state in states:
                matched = None
                for observation, expected in state[
                        "expected_by_observation"].items():
                    if (result.port == observation[0]
                            and ptf.dataplane.match_exp_pkt(
                                expected, result.packet)):
                        matched = observation
                        break
                if matched is not None:
                    state["counts"][matched] += 1
                    sequence = self._sequence_value(
                        result.packet, state["sequence_field"],
                        state["base_udp_source"])
                    if (isinstance(sequence, int)
                            and 0 <= sequence < state["sent"]):
                        state["unique_by_port"][matched].add(sequence)
                        state["copies_by_port"][matched].append(sequence)
                    break
            if (not barrier_written
                    and self._continuous_barrier_reached(
                        states, barrier_packets)):
                if barrier_file:
                    with open(barrier_file, "w", encoding="utf-8") as stream:
                        stream.write("ready\n")
                barrier_written = True

        for thread in threads:
            thread.join()
        drain_deadline = time.time() + 2
        while time.time() < drain_deadline:
            self._update_event_window(states)
            result = testutils.dp_poll(self, device_number=0, timeout=0.1)
            if not isinstance(result, self.dataplane.PollSuccess):
                continue
            for state in states:
                for observation, expected in state[
                        "expected_by_observation"].items():
                    if (result.port != observation[0]
                            or not ptf.dataplane.match_exp_pkt(
                                expected, result.packet)):
                        continue
                    state["counts"][observation] += 1
                    sequence = self._sequence_value(
                        result.packet, state["sequence_field"],
                        state["base_udp_source"])
                    if (isinstance(sequence, int)
                            and 0 <= sequence < state["sent"]):
                        state["unique_by_port"][observation].add(sequence)
                        state["copies_by_port"][observation].append(sequence)
                    break
        sender_errors = [
            state for state in states if state.get("sender_error") is not None]
        if sender_errors:
            failed = sender_errors[0]
            raise RuntimeError(
                "continuous sender {} failed: {}".format(
                    failed["flow"]["name"], failed["sender_error"])) \
                from failed["sender_error"]
        if not barrier_written:
            raise AssertionError("continuous traffic never reached receive barrier")
        for state in states:
            self._assert_continuous_contract(state)
            sent = int(state["sent"])
            counts = state["counts"]
            valid_sequences = {
                port: self._valid_sequences(state, port)
                for port in state["unique_by_port"]}
            if self.profile.get("event_start_file"):
                start = state.get("event_sent_start")
                end = state.get("event_sent_end")
                if start is None or end is None or end <= start:
                    raise AssertionError(
                        "continuous event window markers were not observed")
                sent = end - start
                valid_sequences = {
                    port: {
                        sequence for sequence in sequences
                        if start <= sequence < end
                    }
                    for port, sequences in
                    state["unique_by_port"].items()
                }
                counts = {
                    port: sum(
                        1 for sequence in sequences
                        if start <= sequence < end)
                    for port, sequences in state["copies_by_port"].items()
                }
            self._assert_delivery(
                state["flow"], sent, counts,
                state["groups"], state["forbidden"], valid_sequences)

    def runTest(self):
        defaults = self.profile["defaults"]
        if self.profile.get("continuous_parallel", False):
            self._run_continuous_parallel(self.profile["flows"], defaults)
            return
        for flow in self.profile["flows"]:
            # PTF models hosts with finite packet bursts rather than a
            # background ARP/ND responder. Refresh semantic host neighbors
            # before every flow so a multi-flow routed profile cannot lose a
            # destination to NUD between earlier and later bursts. Mobility
            # profiles disable priming because they own attachment changes.
            if self.profile.get("prime_neighbors", True):
                self._prime_neighbors()
            pkt = self._packet(flow["packet"], defaults)
            count = int(self._flow_value(flow, "packet_count", defaults["packet_count"]))
            groups, forbidden = self._resolve_observations(flow)
            observations = sorted({
                item for group in groups for item in group
            } | set(forbidden))
            expected_by_observation = self._expected_by_observation(
                flow, defaults, observations)

            tx_port, tx_interface = self._resolve_tx_target(flow)
            self.dataplane.flush()
            duration = float(self._flow_value(flow, "duration_seconds", 0))
            unique_by_observation = None
            if duration:
                sent = [0]
                sender = threading.Thread(
                    target=self._send_for_duration,
                    args=(tx_port, tx_interface, pkt, duration,
                          float(self._flow_value(flow, "packets_per_second", 100)), sent))
                sender.daemon = True
                sender.start()
                counts, _ = self._poll_counts(
                    expected_by_observation, timeout=duration + 5)
                sender.join()
                count = sent[0]
            else:
                source_count = int(self._flow_value(
                    flow, "udp_src_count", 0))
                destination_count = int(self._flow_value(
                    flow, "udp_dst_count", 0))
                port_step = int(self._flow_value(flow, "udp_port_step", 0))
                variation = bool(source_count or destination_count or port_step)
                if variation and not all(
                        value > 0
                        for value in (source_count, destination_count, port_step)):
                    raise ValueError(
                        "{} requires positive UDP source/destination counts "
                        "and step".format(flow["name"]))
                packets_per_second = float(self._flow_value(
                    flow, "packets_per_second", defaults.get("packets_per_second", 0)))
                interval = 1.0 / packets_per_second if packets_per_second else 0
                ignored = list(flow.get("ignore_expected_fields", []))
                if variation:
                    expected_by_observation = {
                        observation: self._mask_udp_ports(expected)
                        for observation, expected in
                        expected_by_observation.items()
                    }
                    identity = self._udp_tuple
                elif self._flow_value(flow, "transmit_only", False):
                    if ignored:
                        expected_by_observation = {
                            observation: self._mask_expected_fields(
                                expected, ignored)
                            for observation, expected in
                            expected_by_observation.items()
                        }
                    identity = None
                else:
                    # Every graded bounded packet carries an independent raw
                    # sequence.  Delivery is graded on unique sequences while
                    # duplicate limits are graded on total copies, so loss and
                    # replication cannot cancel each other numerically.
                    fields = ignored + ["payload"]
                    expected_by_observation = {
                        observation: self._mask_expected_fields(
                            expected,
                            fields + (["ipv4.checksum"]
                                      if packet.IP in expected else []))
                        for observation, expected in
                        expected_by_observation.items()
                    }
                    for expected in expected_by_observation.values():
                        if packet.UDP in expected.exp_pkt:
                            expected.set_do_not_care_scapy(
                                packet.UDP, "chksum")

                    def identity(raw):
                        return self._sequence_value(raw, "raw")
                generated = set()
                if variation or identity is not None or interval:
                    for index in range(count):
                        if variation:
                            current = self._vary_udp_ports(
                                pkt, index, source_count,
                                destination_count, port_step)
                            generated.add((
                                int(current[packet.UDP].sport),
                                int(current[packet.UDP].dport)))
                        elif identity is not None:
                            current = self._sequence_packet(
                                pkt, index, "raw")
                            generated.add(index)
                        else:
                            current = pkt
                        self._send(tx_port, tx_interface, current)
                        if interval:
                            time.sleep(interval)
                else:
                    self._send(tx_port, tx_interface, pkt, count=count)
                if variation and len(generated) != count:
                    raise AssertionError(
                        "{} generated {} unique UDP tuples for {} packets".format(
                            flow["name"], len(generated), count))
                counts, unique_by_observation = self._poll_counts(
                    expected_by_observation,
                    timeout=float(self._flow_value(flow, "timeout", 3)),
                    identity=identity,
                    allowed_identities=(
                        generated
                        if variation or identity is not None else None))

            post_send_delay = float(self._flow_value(flow, "post_send_delay_seconds", 0))
            if post_send_delay:
                time.sleep(post_send_delay)

            self._assert_delivery(
                flow, count, counts, groups, forbidden,
                unique_by_observation)
