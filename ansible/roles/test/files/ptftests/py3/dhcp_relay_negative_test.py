"""
DHCPv4 relay negative tests (dhcp4relay). PTF: dhcp_relay_negative_test.py;
pytest: tests/dhcp_relay/test_dhcp_relay_negative.py.

1) Hop limit — DHCPDISCOVER with BOOTP hops >= max_hop_count (default 16);
   no relay toward servers. Syslog: hop count exceeds max (pytest).

2) Option 82 without circuit ID — DHCPOFFER from server with Option 82 containing
   only remote-ID sub-option; no relay to client. Syslog: missing circuit id (pytest).

3) Discard mode relay-from-relay — DHCPDISCOVER with non-zero giaddr and pre-existing
   Option 82 (simulates prior relay). With agent_relay_mode discard (default), packet
   must not be relayed. Syslog: agent relay mode is discard (pytest).

4) Bad IP/UDP checksums — corrupt L3/L4 checksum on DISCOVER; relay drops before forward.
   Syslog: Checksum failed for IP / UDP checksum validation (pytest). Frame built as raw
   bytes so checksums are not auto-fixed by Scapy (untagged Ethernet: eth_header_len=14).

5) Unknown giaddr from server — DHCPOFFER with giaddr not on the DUT (default 99.99.99.99)
   and no Option 82 so VLAN cannot be resolved from circuit ID. to_client() drops after
   failing giaddr→interface match. Syslog: Failed to find interface attached to address (pytest).

6) Malformed Option 82 TLV — DHCPOFFER with Option 82 body shorter than sub-option length
   (circuit-id type 1, declared len 10, only 2 bytes in option). decode_tlv() logs then
   to_client() drops. Syslog: DHCPV4_INFO Failed to decode realy agent sub-option … exceeded
   total option len (pytest; typos match dhcp4relay.cpp).

7) Malformed client frames — class DHCPRelayMalformedClientFrameTest; param
   malformed_client_frame = l2_only | partial_udp (sync with pytest module
   test_dhcp_relay_negative.py: test_dhcp_relay_negative_malformed_client_frame_*). Kernel BPF
   (ether_relay_filter) drops l2_only before userspace (no Invalid IP syslog). partial_udp:
   IPv4 tot_len IHL+4, Invalid UDP syslog. Padded to 60 B min TX. L2 runt: pytest.skip
   test_dhcp_relay_negative_malformed_client_frame_l2_runt.

Builds on dhcp_relay_test.DHCPTest.
"""

import binascii
import struct
import time

import ptf.testutils as testutils
import ptf.packet as scapy
from ptf.mask import Mask
from scapy.packet import Raw

from dhcp_relay_test import DHCPTest


class DHCPRelayHopLimitTest(DHCPTest):
    """
    Negative test: excessive BOOTP hops must not be relayed toward servers.
    """

    def _masked_relayed_discover(self):
        dhcp_discover_relayed = self.create_dhcp_discover_relayed_packet()
        masked_discover = Mask(dhcp_discover_relayed)
        masked_discover.set_do_not_care_scapy(scapy.Ether, "dst")

        masked_discover.set_do_not_care_scapy(scapy.IP, "version")
        masked_discover.set_do_not_care_scapy(scapy.IP, "ihl")
        masked_discover.set_do_not_care_scapy(scapy.IP, "tos")
        masked_discover.set_do_not_care_scapy(scapy.IP, "len")
        masked_discover.set_do_not_care_scapy(scapy.IP, "id")
        masked_discover.set_do_not_care_scapy(scapy.IP, "flags")
        masked_discover.set_do_not_care_scapy(scapy.IP, "frag")
        masked_discover.set_do_not_care_scapy(scapy.IP, "ttl")
        masked_discover.set_do_not_care_scapy(scapy.IP, "proto")
        masked_discover.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_discover.set_do_not_care_scapy(scapy.IP, "src")
        masked_discover.set_do_not_care_scapy(scapy.IP, "dst")
        masked_discover.set_do_not_care_scapy(scapy.IP, "options")

        masked_discover.set_do_not_care_scapy(scapy.UDP, "chksum")
        masked_discover.set_do_not_care_scapy(scapy.UDP, "len")

        masked_discover.set_do_not_care_scapy(scapy.BOOTP, "sname")
        masked_discover.set_do_not_care_scapy(scapy.BOOTP, "file")
        return masked_discover

    def runTest(self):
        hops = int(self.test_params.get("bootp_hops", 255))
        wait_sec = float(self.test_params.get("relay_wait_sec", 3))

        dhcp_discover = self.create_dhcp_discover_packet(
            self.dest_mac_address, self.client_udp_src_port)
        dhcp_discover[scapy.BOOTP].hops = hops

        self.dataplane.flush()
        testutils.send_packet(self, self.client_port_index, dhcp_discover)
        time.sleep(wait_sec)

        masked_discover = self._masked_relayed_discover()
        discover_count = testutils.count_matched_packets_all_ports(
            self, masked_discover, self.server_port_indices)

        self.assertTrue(
            discover_count == 0,
            "Expected no relayed DISCOVER on server ports for hops=%s, saw %s packet(s)" % (
                hops, discover_count))


class DHCPRelayMissingCircuitIdTest(DHCPTest):
    """
    DHCPOFFER from server port with Option 82: remote-ID only, no circuit-ID sub-option.
    Expect no relayed OFFER on client PTF port.
    """

    _VENDOR_CLS_ID = (
        "http://0.0.0.0/this_is_a_very_very_long_path/test.bin".encode("utf-8")
    )

    def create_dhcp_offer_option82_no_circuit_id(self):
        my_chaddr = binascii.unhexlify(self.client_mac.replace(":", ""))
        my_chaddr += b"\x00\x00\x00\x00\x00\x00"

        remote_id_string = self.relay_iface_mac.strip()
        opt82 = struct.pack("BB", self.REMOTE_ID_SUBOPTION, len(remote_id_string))
        opt82 += remote_id_string.encode("utf-8")

        ip_dst = self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip
        giaddr = self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip

        pkt = scapy.Ether(
            dst=self.uplink_mac,
            src=self.server_iface_mac,
            type=self.DHCP_ETHER_TYPE_IP,
        )
        pkt /= scapy.IP(src=self.server_ip[0], dst=ip_dst, ttl=128, id=0)
        pkt /= scapy.UDP(
            sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT
        )
        pkt /= scapy.BOOTP(
            op=self.DHCP_BOOTP_OP_REPLY,
            htype=self.DHCP_BOOTP_HTYPE_ETHERNET,
            hlen=self.DHCP_BOOTP_HLEN_ETHERNET,
            hops=0,
            xid=0,
            secs=0,
            flags=self.DHCP_BOOTP_FLAGS_BROADCAST_REPLY,
            ciaddr=self.DEFAULT_ROUTE_IP,
            yiaddr=self.client_ip,
            siaddr=self.server_ip[0],
            giaddr=giaddr,
            chaddr=my_chaddr,
        )
        pkt /= scapy.DHCP(
            options=[
                ("message-type", "offer"),
                ("server_id", self.server_ip[0]),
                ("lease_time", self.LEASE_TIME),
                ("subnet_mask", self.client_subnet),
                (82, opt82),
                ("vendor_class_id", self._VENDOR_CLS_ID),
                ("end"),
            ]
        )
        return pkt

    def _masked_relayed_offer(self):
        dhcp_offer = self.create_dhcp_offer_relayed_packet()
        masked_offer = Mask(dhcp_offer)

        masked_offer.set_do_not_care_scapy(scapy.IP, "version")
        masked_offer.set_do_not_care_scapy(scapy.IP, "ihl")
        masked_offer.set_do_not_care_scapy(scapy.IP, "tos")
        masked_offer.set_do_not_care_scapy(scapy.IP, "len")
        masked_offer.set_do_not_care_scapy(scapy.IP, "id")
        masked_offer.set_do_not_care_scapy(scapy.IP, "flags")
        masked_offer.set_do_not_care_scapy(scapy.IP, "frag")
        masked_offer.set_do_not_care_scapy(scapy.IP, "ttl")
        masked_offer.set_do_not_care_scapy(scapy.IP, "proto")
        masked_offer.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_offer.set_do_not_care_scapy(scapy.IP, "options")

        masked_offer.set_do_not_care_scapy(scapy.UDP, "len")
        masked_offer.set_do_not_care_scapy(scapy.UDP, "chksum")

        masked_offer.set_do_not_care_scapy(scapy.BOOTP, "sname")
        masked_offer.set_do_not_care_scapy(scapy.BOOTP, "file")
        return masked_offer

    def runTest(self):
        wait_sec = float(self.test_params.get("offer_wait_sec", 3))

        self.dataplane.flush()
        bad_offer = self.create_dhcp_offer_option82_no_circuit_id()
        testutils.send_packet(self, self.server_port_indices[0], bad_offer)
        time.sleep(wait_sec)

        masked_offer = self._masked_relayed_offer()
        offer_count = testutils.count_matched_packets_all_ports(
            self, masked_offer, [self.client_port_index]
        )

        self.assertTrue(
            offer_count == 0,
            "Expected no relayed OFFER on client port when Option 82 lacks "
            "circuit ID; saw %s packet(s)" % offer_count,
        )


class DHCPRelayUnknownGiaddrFromServerTest(DHCPRelayMissingCircuitIdTest):
    """
    DHCPOFFER from server with bogus giaddr (default 99.99.99.99). No Option 82 so the
    relay cannot map VLAN via circuit ID and must match giaddr to a local interface.
    """

    def create_dhcp_offer_unknown_giaddr(self):
        my_chaddr = binascii.unhexlify(self.client_mac.replace(":", ""))
        my_chaddr += b"\x00\x00\x00\x00\x00\x00"
        giaddr = self.test_params.get("bogus_server_giaddr", "99.99.99.99")
        ip_dst = self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip

        pkt = scapy.Ether(
            dst=self.uplink_mac,
            src=self.server_iface_mac,
            type=self.DHCP_ETHER_TYPE_IP,
        )
        pkt /= scapy.IP(src=self.server_ip[0], dst=ip_dst, ttl=128, id=0)
        pkt /= scapy.UDP(
            sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT
        )
        pkt /= scapy.BOOTP(
            op=self.DHCP_BOOTP_OP_REPLY,
            htype=self.DHCP_BOOTP_HTYPE_ETHERNET,
            hlen=self.DHCP_BOOTP_HLEN_ETHERNET,
            hops=0,
            xid=0,
            secs=0,
            flags=self.DHCP_BOOTP_FLAGS_BROADCAST_REPLY,
            ciaddr=self.DEFAULT_ROUTE_IP,
            yiaddr=self.client_ip,
            siaddr=self.server_ip[0],
            giaddr=giaddr,
            chaddr=my_chaddr,
        )
        pkt /= scapy.DHCP(
            options=[
                ("message-type", "offer"),
                ("server_id", self.server_ip[0]),
                ("lease_time", self.LEASE_TIME),
                ("subnet_mask", self.client_subnet),
                ("vendor_class_id", self._VENDOR_CLS_ID),
                ("end"),
            ]
        )
        return pkt

    def runTest(self):
        wait_sec = float(self.test_params.get("offer_wait_sec", 3))

        self.dataplane.flush()
        offer = self.create_dhcp_offer_unknown_giaddr()
        testutils.send_packet(self, self.server_port_indices[0], offer)
        time.sleep(wait_sec)

        masked_offer = self._masked_relayed_offer()
        offer_count = testutils.count_matched_packets_all_ports(
            self, masked_offer, [self.client_port_index]
        )

        self.assertTrue(
            offer_count == 0,
            "Expected no relayed OFFER on client port for unknown giaddr from server; "
            "saw %s packet(s)" % offer_count,
        )


class DHCPRelayMalformedOption82TlvTest(DHCPRelayMissingCircuitIdTest):
    """
    DHCPOFFER with valid giaddr but Option 82 TLV truncated: sub-option 1 (circuit ID)
    declares length 10 while the option 82 value is only 2 bytes (type + len).
    """

    def create_dhcp_offer_malformed_option82_tlv(self):
        my_chaddr = binascii.unhexlify(self.client_mac.replace(":", ""))
        my_chaddr += b"\x00\x00\x00\x00\x00\x00"
        giaddr = self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip
        ip_dst = self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip

        declared_len = int(self.test_params.get("malformed_opt82_declared_len", 10))
        opt82 = struct.pack("BB", self.CIRCUIT_ID_SUBOPTION, declared_len)

        pkt = scapy.Ether(
            dst=self.uplink_mac,
            src=self.server_iface_mac,
            type=self.DHCP_ETHER_TYPE_IP,
        )
        pkt /= scapy.IP(src=self.server_ip[0], dst=ip_dst, ttl=128, id=0)
        pkt /= scapy.UDP(
            sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT
        )
        pkt /= scapy.BOOTP(
            op=self.DHCP_BOOTP_OP_REPLY,
            htype=self.DHCP_BOOTP_HTYPE_ETHERNET,
            hlen=self.DHCP_BOOTP_HLEN_ETHERNET,
            hops=0,
            xid=0,
            secs=0,
            flags=self.DHCP_BOOTP_FLAGS_BROADCAST_REPLY,
            ciaddr=self.DEFAULT_ROUTE_IP,
            yiaddr=self.client_ip,
            siaddr=self.server_ip[0],
            giaddr=giaddr,
            chaddr=my_chaddr,
        )
        pkt /= scapy.DHCP(
            options=[
                ("message-type", "offer"),
                ("server_id", self.server_ip[0]),
                ("lease_time", self.LEASE_TIME),
                ("subnet_mask", self.client_subnet),
                (82, opt82),
                ("vendor_class_id", self._VENDOR_CLS_ID),
                ("end"),
            ]
        )
        return pkt

    def runTest(self):
        wait_sec = float(self.test_params.get("offer_wait_sec", 3))

        self.dataplane.flush()
        offer = self.create_dhcp_offer_malformed_option82_tlv()
        testutils.send_packet(self, self.server_port_indices[0], offer)
        time.sleep(wait_sec)

        masked_offer = self._masked_relayed_offer()
        offer_count = testutils.count_matched_packets_all_ports(
            self, masked_offer, [self.client_port_index]
        )

        self.assertTrue(
            offer_count == 0,
            "Expected no relayed OFFER on client port for malformed Option 82 TLV; "
            "saw %s packet(s)" % offer_count,
        )


class DHCPRelayDiscardRelayFromRelayTest(DHCPRelayHopLimitTest):
    """
    DISCOVER from client port with giaddr set (relay-from-relay) and Option 82 already
    present. dhcp4relay from_client() uses discard when agent_relay_mode is not append/replace.
    Expect no relay toward servers.
    """

    def create_discover_relay_from_relay(self):
        my_chaddr = binascii.unhexlify(self.client_mac.replace(":", ""))
        my_chaddr += b"\x00\x00\x00\x00\x00\x00"
        giaddr = self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip
        hops = int(self.test_params.get("relay_from_relay_hops", 1))

        pkt = scapy.Ether(
            dst=self.dest_mac_address,
            src=self.client_mac,
            type=self.DHCP_ETHER_TYPE_IP,
        )
        pkt /= scapy.IP(src=self.DEFAULT_ROUTE_IP, dst=self.BROADCAST_IP, ttl=64, id=1)
        pkt /= scapy.UDP(
            sport=self.client_udp_src_port, dport=self.DHCP_SERVER_PORT
        )

        bootp = scapy.BOOTP(
            op=1,
            htype=self.DHCP_BOOTP_HTYPE_ETHERNET,
            hlen=self.DHCP_BOOTP_HLEN_ETHERNET,
            hops=hops,
            xid=0xAABBCCDD,
            secs=0,
            flags=self.DHCP_BOOTP_FLAGS_BROADCAST_REPLY,
            ciaddr=self.DEFAULT_ROUTE_IP,
            yiaddr=self.DEFAULT_ROUTE_IP,
            siaddr=self.DEFAULT_ROUTE_IP,
            giaddr=giaddr,
            chaddr=my_chaddr,
        )
        bootp /= scapy.DHCP(
            options=[
                ("message-type", "discover"),
                (82, self.option82),
                ("end"),
            ]
        )
        pad_bytes = self.DHCP_PKT_BOOTP_MIN_LEN - len(bootp)
        if pad_bytes > 0:
            bootp /= scapy.PADDING("\x00" * pad_bytes)
        pkt /= bootp
        return pkt

    def runTest(self):
        wait_sec = float(self.test_params.get("relay_wait_sec", 3))

        self.dataplane.flush()
        pkt = self.create_discover_relay_from_relay()
        testutils.send_packet(self, self.client_port_index, pkt)
        time.sleep(wait_sec)

        masked_discover = self._masked_relayed_discover()
        discover_count = testutils.count_matched_packets_all_ports(
            self, masked_discover, self.server_port_indices
        )

        self.assertTrue(
            discover_count == 0,
            "Expected no relayed DISCOVER on server ports for relay-from-relay "
            "(giaddr + Option 82) in discard mode; saw %s packet(s)" % discover_count,
        )


class DHCPRelayBadChecksumTest(DHCPRelayHopLimitTest):
    """
    DHCPDISCOVER with invalid IPv4 or UDP checksum (wire bytes flipped after build).
    dhcp4relay validates checksums before relay; expect no server-side relay.
    """

    def _discover_wire_bytes(self):
        pkt = self.create_dhcp_discover_packet(
            self.dest_mac_address, self.client_udp_src_port)
        return bytearray(bytes(pkt))

    @staticmethod
    def _corrupt_ip_checksum(data, eth_len):
        """IPv4 header checksum at offset eth_len + 10."""
        off = eth_len + 10
        data[off] ^= 0xFF
        data[off + 1] ^= 0xFF
        return bytes(data)

    @staticmethod
    def _corrupt_udp_checksum(data, eth_len):
        """UDP checksum at eth_len + ihl*4 + 6 (IPv4 options assumed none)."""
        ip_start = eth_len
        ihl = (data[ip_start] & 0x0F) * 4
        udp_start = ip_start + ihl
        data[udp_start + 6] ^= 0xAB
        data[udp_start + 7] ^= 0xCD
        return bytes(data)

    def runTest(self):
        layer = self.test_params.get("bad_checksum_layer", "ip")
        eth_len = int(self.test_params.get("eth_header_len", 14))
        wait_sec = float(self.test_params.get("relay_wait_sec", 3))

        buf = self._discover_wire_bytes()
        if layer == "ip":
            wire = self._corrupt_ip_checksum(buf, eth_len)
        elif layer == "udp":
            wire = self._corrupt_udp_checksum(buf, eth_len)
        else:
            raise ValueError(
                "bad_checksum_layer must be 'ip' or 'udp', got %r" % layer)

        self.dataplane.flush()
        pkt = scapy.Ether(wire)
        testutils.send_packet(self, self.client_port_index, pkt)
        time.sleep(wait_sec)

        masked_discover = self._masked_relayed_discover()
        discover_count = testutils.count_matched_packets_all_ports(
            self, masked_discover, self.server_port_indices
        )

        self.assertTrue(
            discover_count == 0,
            "Expected no relayed DISCOVER on server ports for bad %s checksum; "
            "saw %s packet(s)" % (layer.upper(), discover_count),
        )


class DHCPRelayMalformedClientFrameTest(DHCPRelayBadChecksumTest):
    """
    Malformed DHCP client-side DISCOVER frames (param malformed_client_frame).

    dhcp4relay attaches SO_ATTACH_FILTER (UDP/67); packets that fail the filter never reach
    pkt_in_callback. l2_only: Ethernet (+ optional Q-tag) only — kernel drop, no syslog.
    partial_udp: IPv4 tot_len IHL+4, IP checksum fixed, pad to 60 B — BPF passes, Pcpp has no
    complete UDP layer -> Invalid UDP syslog.
    """

    # Linux AF_PACKET / veth often rejects transmits shorter than IEEE 802.3 min frame.
    _MIN_ETH_TX_OCTETS = 60

    @classmethod
    def _pad_min_eth_tx(cls, buf):
        buf = bytes(buf)
        if len(buf) < cls._MIN_ETH_TX_OCTETS:
            buf += b"\x00" * (cls._MIN_ETH_TX_OCTETS - len(buf))
        return buf

    @staticmethod
    def _set_ipv4_total_length_and_checksum(buf, ip_start, ihl, ip_total_len):
        """Set IPv4 total length (header + payload) and recompute header checksum."""
        struct.pack_into("!H", buf, ip_start + 2, ip_total_len)
        struct.pack_into("!H", buf, ip_start + 10, 0)
        csum = 0
        for off in range(ip_start, ip_start + ihl, 2):
            csum += (buf[off] << 8) + buf[off + 1]
        while csum > 0xFFFF:
            csum = (csum & 0xFFFF) + (csum >> 16)
        struct.pack_into("!H", buf, ip_start + 10, (~csum) & 0xFFFF)

    def runTest(self):
        case = self.test_params.get("malformed_client_frame", "l2_only")
        eth_len = int(self.test_params.get("eth_header_len", 14))
        wait_sec = float(self.test_params.get("relay_wait_sec", 3))

        full = self._discover_wire_bytes()
        if case == "l2_only":
            # L2 only: kernel BPF drops (no IPv4 at fixed offsets) — no dhcp4relay syslog.
            wire = self._pad_min_eth_tx(full[:eth_len])
        elif case == "partial_udp":
            ip_start = eth_len
            ihl = (full[ip_start] & 0x0F) * 4
            buf = bytearray(full[: ip_start + ihl + 4])
            # Shrink IPv4 tot_len to IHL+4 so only partial UDP is inside the IP datagram; min
            # Ethernet padding then lies outside IP (avoids Pcpp treating pad as UDP len/cs).
            self._set_ipv4_total_length_and_checksum(buf, ip_start, ihl, ihl + 4)
            wire = self._pad_min_eth_tx(bytes(buf))
        else:
            raise ValueError(
                "malformed_client_frame must be 'l2_only' or 'partial_udp', got %r" % case)

        self.dataplane.flush()
        testutils.send_packet(self, self.client_port_index, Raw(load=wire))
        time.sleep(wait_sec)

        masked_discover = self._masked_relayed_discover()
        discover_count = testutils.count_matched_packets_all_ports(
            self, masked_discover, self.server_port_indices
        )

        self.assertTrue(
            discover_count == 0,
            "Expected no relayed DISCOVER on server ports for malformed_client_frame=%s; "
            "saw %s packet(s)" % (case, discover_count),
        )
