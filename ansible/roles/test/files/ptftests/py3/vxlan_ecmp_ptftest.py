# ptftests/vxlan_ecmp_ptftest.py
from datetime import datetime
import time
import json
import os
import scapy.all as scapy
import ptf
import logging
from ptf.base_tests import BaseTest
from ptf.testutils import (
    simple_tcp_packet,
    send_packet,
    test_params_get,
    dp_poll
)

logger = logging.getLogger(__name__)


class VxlanEcmpTest(BaseTest):
    """
    Generic VXLAN ECMP PTF test:
      - Takes 'endpoints', 'dst_ip', 'src_ip', 'dut_vtep', 'router_mac', 'num_packets'
      - Sends packets toward DUT
      - Captures VXLAN packets and verifies each endpoint is used
    """

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        params = test_params_get()
        if "params_file" in params:
            with open(params["params_file"], "r") as f:
                params = json.load(f)

        if "endpoints_file" in params and os.path.exists(params["endpoints_file"]):
            with open(params["endpoints_file"], "r") as f:
                self.endpoints = json.load(f)
        else:
            self.endpoints = params.get("endpoints", [])

        self.dst_ip = params.get("dst_ip")
        self.src_ip = params.get("ptf_src_ip")
        self.dut_vtep = params.get("dut_vtep")
        self.router_mac = params.get("router_mac")
        self.num_packets = int(params.get("num_packets", 6))
        self.vxlan_port = int(params.get("vxlan_port", 4789))
        self.send_port = int(params.get("ptf_ingress_port", 0))
        self.tcp_sport = 1234
        self.tcp_dport = 5000
        self.batch_size = 200

        self.dataplane.flush()

        logger.info("=== VXLAN ECMP PTF Test Setup ===")
        logger.info(f"Endpoints: {len(self.endpoints)}")
        logger.info(f"Destination IP: {self.dst_ip}, Source IP: {self.src_ip}")
        logger.info(f"DUT VTEP: {self.dut_vtep}, Router MAC: {self.router_mac}")
        logger.info(f"Packets to send: {self.num_packets}, Ingress port: {self.send_port}")
        logger.info(f"VXLAN UDP Port: {self.vxlan_port}")
        logger.info("=================================")

    def _next_port(self, key="sport"):
        """Simple port generator for varying TCP ports."""
        if key == "sport":
            self.tcp_sport = (self.tcp_sport + 1) % 65535 or 1234
            return self.tcp_sport
        else:
            self.tcp_dport = (self.tcp_dport + 1) % 65535 or 5000
            return self.tcp_dport

    def runTest(self):
        counts = {}
        src_mac = self.dataplane.get_mac(0, self.send_port)

        total_sent = 0
        logger.info(f"Starting VXLAN ECMP test: {self.num_packets} packets total, {self.batch_size} per batch")
        logger.info(f"Source {self.src_ip} → Destination {self.dst_ip}, ingress port {self.send_port}")

        # --- Send & capture in batches ---
        while total_sent < self.num_packets:
            send_now = min(self.batch_size, self.num_packets - total_sent)
            logger.info(f"--- Sending batch {total_sent + 1} to {total_sent + send_now} ---")

            # Send packets for this batch
            for _ in range(send_now):
                sport = self._next_port("sport")
                dport = self._next_port("dport")
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

            total_sent += send_now
            logger.info(f"Batch sent ({total_sent}/{self.num_packets}). Polling for VXLAN packets...")

            # Poll for VXLAN packets from this batch
            poll_start = datetime.now()
            poll_timeout = 8  # seconds per batch
            while (datetime.now() - poll_start).total_seconds() < poll_timeout:
                res = dp_poll(self, timeout=2)
                if not isinstance(res, self.dataplane.PollSuccess):
                    continue

                ether = scapy.Ether(res.packet)
                if scapy.IP in ether and scapy.UDP in ether and ether[scapy.UDP].dport == self.vxlan_port:
                    vtep_dst = ether[scapy.IP].dst
                    if vtep_dst in self.endpoints:
                        counts[vtep_dst] = counts.get(vtep_dst, 0) + 1

            logger.info(f"Completed batch {total_sent}/{self.num_packets}.")
            time.sleep(0.3)  # small pause before next burst

        # --- Post-send validation ---
        total_received = sum(counts.values())
        logger.info(f"VXLAN packets received: {total_received} / {self.num_packets}")
        logger.info(f"Endpoints hit: {len(counts)} / {len(self.endpoints)}")
        logger.info(f"Count per endpoint : {counts}")

        # --- Validation ---
        if total_received == 0:
            raise AssertionError("No VXLAN packets captured (tunnel not active or misconfigured)")

        if total_received < self.num_packets:
            drop_pct = 100.0 * (self.num_packets - total_received) / self.num_packets
            raise AssertionError(
                f"Packet loss detected: sent={self.num_packets}, received={total_received} ({drop_pct:.2f}% loss)"
            )

        missing = set(self.endpoints) - set(counts.keys())
        if missing:
            logger.error(f"Missing endpoints ({len(missing)}): {sorted(list(missing))[:10]} ...")
            raise AssertionError(f"Endpoints not used in ECMP: {len(missing)}")

        logger.info(
            f"VXLAN ECMP test passed: all {len(self.endpoints)} endpoints hit, "
            f"{total_received}/{self.num_packets} packets received, no loss."
        )

    def tearDown(self):
        self.dataplane.flush()
        logger.info("Dataplane flushed — VXLAN ECMP test complete")
