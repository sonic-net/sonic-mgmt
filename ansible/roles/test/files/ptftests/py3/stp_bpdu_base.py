# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Shared PTF scaffolding for spanning-tree BPDU tests (PVST and MSTP).

`StpBpduBase` holds the mode-independent plumbing — param access, packet send,
threaded sniff-and-parse capture, MAC helpers, and a `test_scenarios`-keyed
`runTest` dispatcher. A subclass supplies:

  * `BPDU_DST_MAC`        — the L2 multicast the capture filter watches;
  * `parse_bpdu_packet()` — decode a captured scapy packet -> dict (or None);
  * `scenarios()`         — {scenario_name: handler} for `runTest` dispatch.

The concrete send/build/validate logic is mode-specific and lives in the
subclass (`PvstBpduTest`, `MstpBpduTest`).
"""
import logging
from threading import Thread

import ptf
import ptf.testutils as testutils
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import test_params_get
from scapy.all import Ether
import scapy.all as scapy2


class StpBpduBase(BaseTest):

    # Subclasses override.
    BPDU_DST_MAC = None

    def __init__(self):
        BaseTest.__init__(self)
        self.captured_bpdus = []
        self.capture_thread = None
        self.logger = logging.getLogger(self.__class__.__name__)

    def setUp(self):
        self.test_params = test_params_get()
        self.dataplane = ptf.dataplane_instance
        self.logger.info("Setting up %s", self.__class__.__name__)

    # ------------------------------------------------------------------ params
    def param(self, name, default=None):
        return self.test_params.get(name, default)

    # ------------------------------------------------------------------- utils
    @staticmethod
    def mac_to_bytes(mac):
        return bytes.fromhex(mac.replace(':', ''))

    @staticmethod
    def bytes_to_mac(raw):
        return ':'.join('{:02x}'.format(b) for b in raw)

    @staticmethod
    def iface_for_port(port):
        """PTF injects/receives DUT port N on host interface `ethN`."""
        return "eth{}".format(port)

    # -------------------------------------------------------------------- send
    def send_bpdu(self, port, packet):
        testutils.send_packet(self, port, packet)
        self.logger.info("Sent BPDU on port %s", port)

    # ----------------------------------------------------------------- capture
    def start_capture(self, port, count=3, timeout=15):
        """Sniff up to `count` BPDUs (dst == BPDU_DST_MAC) on `port` in a
        daemon thread, parsing each via the subclass `parse_bpdu_packet`."""
        self.captured_bpdus = []
        iface = self.iface_for_port(port)
        bpdu_filter = "ether dst {}".format(self.BPDU_DST_MAC)

        def _cb(packet):
            data = self.parse_bpdu_packet(packet)
            if data:
                self.captured_bpdus.append(data)

        def _worker():
            try:
                scapy2.sniff(iface=iface, filter=bpdu_filter, prn=_cb,
                             count=count, store=0, timeout=timeout)
            except Exception as e:   # noqa: BLE001 — capture thread must not crash the test
                self.logger.error("capture error on %s: %s", iface, e)

        self.logger.info("Capturing up to %d BPDU(s) on %s (%ds)", count, iface, timeout)
        self.capture_thread = Thread(target=_worker)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_capture(self, join_timeout=20):
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=join_timeout)
        return self.captured_bpdus

    def capture_one(self, port, timeout=15):
        """Convenience: capture a single BPDU on `port` and return it (or None)."""
        self.start_capture(port, count=1, timeout=timeout)
        self.stop_capture(join_timeout=timeout + 5)
        return self.captured_bpdus[0] if self.captured_bpdus else None

    # ----------------------------------------------------- L2 data-plane (shared)
    # Mode-independent: an untagged/tagged L2 frame on `send_port` should (or
    # should not) egress `receive_port` depending on the STP port states. Mirrors
    # `PvstBpduTest.test_validate_l2_packet` so PVST and MST assert identically.
    L2_SRC_PREFIX = "00:11:22:33:55"

    # Minimum Ethernet payload, also used as the 802.3 length field: a frame with
    # length/ethertype 0x0000 declares an empty payload and the ASIC drops it -
    # measured 0/20 delivered at 0x0000 vs 20/20 with a correct length.
    L2_PAYLOAD_LEN = 46

    @classmethod
    def _l2_payload(cls, vlan_id):
        payload = "Hello VLAN {}".format(vlan_id).encode()
        return payload + b"\x00" * (cls.L2_PAYLOAD_LEN - len(payload))

    def create_l2_packet(self, send_port, vlan_id):
        """Untagged L2 probe frame -- the VLAN members are untagged access
        ports, so a Dot1Q-tagged frame keeps its tag through the flood and is
        dropped by the next hop. Measured: tagged 0/20, untagged 20/20."""
        self.dataplane.flush()
        return Ether(dst="ff:ff:ff:ff:ff:ff",
                     src="{}:{:02x}".format(self.L2_SRC_PREFIX, send_port & 0xFF),
                     type=self.L2_PAYLOAD_LEN) / self._l2_payload(vlan_id)

    def _expected_l2_packet(self, vlan_id, send_port):
        return Ether(dst="ff:ff:ff:ff:ff:ff",
                     src="{}:{:02x}".format(self.L2_SRC_PREFIX, send_port & 0xFF),
                     type=self.L2_PAYLOAD_LEN) / self._l2_payload(vlan_id)

    def scenario_validate_l2_packet(self):
        send_port = int(self.param("send_port"))
        recv_port = int(self.param("receive_port"))
        vlan_id = int(self.param("vlan_id", 1))
        verify_packet = self.param("verify_packet", True)

        l2_packet = self.create_l2_packet(send_port, vlan_id)
        expected_pkt = self._expected_l2_packet(vlan_id, send_port)
        masked = Mask(expected_pkt)
        # Mask offsets are in *bits*, not bytes - match on dst+src MAC only.
        masked.set_do_not_care(12 * 8, (len(expected_pkt) - 12) * 8)

        count_to_send = 100
        self.dataplane.flush()
        for _ in range(count_to_send):
            testutils.send_packet(self, port_id=send_port, pkt=l2_packet)

        matched = testutils.count_matched_packets_all_ports(self, masked, [recv_port], timeout=5)
        self.logger.info("validate_l2_packet: matched %d (verify_packet=%s)", matched, verify_packet)
        expected = count_to_send if verify_packet else 0
        assert matched == expected, "expected {} packets on port {}, got {}".format(
            expected, recv_port, matched)

    # -------------------------------------------------------------------- hooks
    def parse_bpdu_packet(self, packet):
        raise NotImplementedError

    def create_bpdu_packet(self):
        raise NotImplementedError

    def scenarios(self):
        """{scenario_name: bound-handler}. Subclasses override."""
        return {}

    # ----------------------------------------------------------------- dispatch
    def runTest(self):
        scenario = self.param('test_scenarios', 'send')
        self.logger.info("Running %s scenario: %s", self.__class__.__name__, scenario)
        handler = self.scenarios().get(scenario)
        if handler is None:
            self.logger.warning("Unknown test scenario: %s", scenario)
            return
        handler()
        self.logger.info("%s scenario %s completed", self.__class__.__name__, scenario)
