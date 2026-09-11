# ars_ecmp_test.py

import logging
import json
import time
import subprocess
from scapy.utils import wrpcap
import ptf
from scapy.all import sendp

from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.packet import Ether, IP
from ptf.testutils import (
    send_packet,
    verify_packet_any_port,
    simple_tcp_packet,
    test_params_get,
)

RESULT_FILE = "/tmp/ars_ptf_result.json"

# Idle time between burst of packets.
FLOWLET_IDLE_TIME_SECONDS = 0.1


class ArsTest(BaseTest):
    """
    ARS ECMP Test with FLOWLET behavior:

        Burst1 → should stick to one port
        Idle time → new flowlet
        Burst2 → MUST switch to a DIFFERENT port
    """

    def __init__(self):
        BaseTest.__init__(self)

    def setUp(self):
        BaseTest.setUp(self)
        self.dataplane = ptf.dataplane_instance
        self.params = test_params_get()

        self.router_mac = self.params["router_mac"]
        self.packet_count = int(self.params.get("packet_count"))
        self.test_case = self.params.get("test_case")

        self.ingress_port = int(self.params.get("ingress_port"))
        self.egress_ports = self.params.get("egress_ports")
        self.negative = self.params.get("negative")

        # Detect mode automatically
        self.mode = "flowlet" if "flowlet" in self.test_case.lower() else "per_packet"

        logging.info(f"=== ARS Test Case: {self.test_case} ===")
        logging.info(f"Mode: {self.mode}")
        logging.info(f"Packets per flowlet: {self.packet_count}")
        logging.info(f"Ingress port: {self.ingress_port}")
        logging.info(f"Egress ports: {self.egress_ports}")

        # Counters
        self.rx_counters = {str(p): 0 for p in self.egress_ports}

        # For flowlet tracking (Burst1_port, Burst2_port)
        self.flowlet_ports = []

    # ----------------------------------------------------------
    # Fixed-flow packet generator
    # ----------------------------------------------------------
    def _generate_packet(self):
        src_ip = "10.3.3.2"
        sport = 4000
        dst_ip = "193.1.176.10"
        dport = 5000

        src_mac = self.dataplane.get_mac(0, self.ingress_port)

        return simple_tcp_packet(
            eth_dst=self.router_mac,
            eth_src=src_mac,
            ip_src=src_ip,
            ip_dst=dst_ip,
            tcp_sport=sport,
            tcp_dport=dport,
            ip_ttl=64,
        )

    # ----------------------------------------------------------
    # MASK + verify any port for per-packet
    # ----------------------------------------------------------
    def _verify_and_record(self, pkt):
        masked = Mask(pkt)
        masked.set_do_not_care_scapy(Ether, "src")
        masked.set_do_not_care_scapy(Ether, "dst")
        masked.set_do_not_care_scapy(IP, "ttl")
        masked.set_do_not_care_scapy(IP, "chksum")
        masked.set_do_not_care_scapy(IP, "tos")
        masked.set_do_not_care_scapy(IP, "id")
        masked.set_do_not_care_scapy(IP, "flags")
        masked.set_do_not_care_scapy(IP, "frag")
        masked.set_do_not_care_scapy(IP, "len")

        rv = verify_packet_any_port(
            self, masked, ports=self.egress_ports, timeout=1
        )

        if isinstance(rv, tuple):
            idx, _ = rv
            if idx >= 0:
                port = self.egress_ports[idx]
                self.rx_counters[str(port)] += 1

    # ----------------------------------------------------------
    # sendpfast burst sender for per-flowlet
    # ----------------------------------------------------------
    def _send_flowlet_burst(self, pkt, count=5000, pps=10000):
        pcap = "/tmp/flowlet_burst.pcap"
        wrpcap(pcap, [pkt] * count)
        iface = f"eth{self.ingress_port}"

        sendp([pkt] * count, iface=iface, inter=1 / pps, verbose=False)

        # short delay for counters to update
        time.sleep(0.1)

    def runTest(self):
        if self.mode == "per_packet":
            self._run_per_packet()
        else:
            self._run_flowlet()

        # Save PTF result
        result = {
            "test_case": self.test_case,
            "mode": self.mode,
            "flowlet_ports": self.flowlet_ports,
        }
        with open(RESULT_FILE, "w") as fp:
            json.dump(result, fp)

        logging.info(f"Saved → {RESULT_FILE}")

    # ----------------------------------------------------------
    # PER-PACKET LB
    # ----------------------------------------------------------
    def _run_per_packet(self):
        logging.info("=== PER-PACKET test ===")
        for _ in range(self.packet_count):
            pkt = self._generate_packet()
            send_packet(self, self.ingress_port, pkt)
            self._verify_and_record(pkt)
        self._check_per_packet_balancing()

    # ----------------------------------------------------------
    # PER-PACKET Validation
    # ----------------------------------------------------------
    def _check_per_packet_balancing(self):
        total = sum(self.rx_counters[str(p)] for p in self.egress_ports)
        expected = total / len(self.egress_ports)
        tolerance = expected * 0.40

        for p in self.egress_ports:
            r = self.rx_counters[str(p)]
            if abs(r - expected) > tolerance:
                if self.negative:
                    logging.warning(
                        f"[PER-PACKET][NEGATIVE] Port {p} unbalanced as expected: {r}"
                    )
                    return  # do NOT assert, test passes
                else:
                    raise AssertionError(f"[PER-PACKET] Port {p} unbalanced: {r}")

        logging.info("[PER-PACKET] Load-balancing OK")

    # ----------------------------------------------------------
    # FLOWLET MODE (with TX counter detection)
    # ----------------------------------------------------------
    def _run_flowlet(self):
        pkt = self._generate_packet()

        # -------------------------
        # Flowlet Burst 1
        # -------------------------

        tx_before = {p: ArsTest.get_tx_count(f"eth{p}") for p in self.egress_ports}

        logging.info("[FLOWLET] >>> Burst 1")
        self._send_flowlet_burst(pkt, count=self.packet_count, pps=10000)

        p1, counts = ArsTest.get_flowlet_port(self.egress_ports, tx_before)
        self.flowlet_ports.append(p1)
        logging.info(f"[FLOWLET] Burst finished, port used: {p1}, counts: {counts}")

        idle = FLOWLET_IDLE_TIME_SECONDS
        logging.info(f"[FLOWLET] Sleeping {idle}s for new flowlet")
        time.sleep(idle)

        # -------------------------
        # Flowlet Burst 2
        # -------------------------
        tx_before = {p: ArsTest.get_tx_count(f"eth{p}") for p in self.egress_ports}
        logging.info("[FLOWLET] >>> Burst 2")
        self._send_flowlet_burst(pkt, count=self.packet_count, pps=10000)
        p2, counts = ArsTest.get_flowlet_port(self.egress_ports, tx_before)
        self.flowlet_ports.append(p2)
        logging.info(f"[FLOWLET] Burst finished, port used: {p2}, counts: {counts}")

        self._check_flowlet_switch(p1, p2)

    def _check_flowlet_switch(self, p1, p2):
        if p1 == p2:
            raise AssertionError(f"[FLOWLET] NO SWITCH: Both flowlets used port {p1}")
        logging.info(f"[FLOWLET] SUCCESS — switched ports {p1} → {p2}")

    @staticmethod
    def get_tx_count(iface):
        cmd = f"cat /sys/class/net/{iface}/statistics/rx_packets"
        output = subprocess.check_output(cmd, shell=True)
        return int(output)

    @staticmethod
    def get_flowlet_port(egress_ports, tx_before):
        port_counts = {}
        for port in egress_ports:
            iface = f"eth{port}"  # adjust if your port naming differs
            tx_after = ArsTest.get_tx_count(iface)
            port_counts[port] = tx_after - tx_before.get(port, 0)

        best_port = max(port_counts, key=lambda k: port_counts[k])
        logging.info(f"[FLOWLET] Burst went out port {best_port}, count={port_counts[best_port]}")
        return best_port, port_counts
