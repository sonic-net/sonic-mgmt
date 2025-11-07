# ptftests/vxlan_ecmp_ptftest.py
from datetime import datetime
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
        self.endpoints = params.get("endpoints", [])
        self.dst_ip = params.get("dst_ip")
        self.src_ip = params.get("src_ip")
        self.dut_vtep = params.get("dut_vtep")
        self.router_mac = params.get("router_mac")
        self.num_packets = int(params.get("num_packets", 6))
        self.vxlan_port = params.get("vxlan_port", 4789)
        self.send_port = params.get("ptf_ingress_port")
        self.tcp_sport = 1234
        self.tcp_dport = 5000
        self.dataplane.flush()

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
        logger.info(f"Sending {self.num_packets} packets on port {self.send_port}, "
                    f"hashing over unique TCP ports")

        # --- Send packets ---
        for _ in range(self.num_packets):
            sport = self._next_port("sport")
            dport = self._next_port("dport")
            pkt_opts = {
                "eth_dst": self.router_mac,
                "eth_src": src_mac,
                "ip_dst": self.dst_ip,
                "ip_src": self.src_ip,
                "ip_id": 105,
                "ip_ttl": 64,
                "tcp_sport": sport,
                "tcp_dport": dport,
                "pktlen": 100,
            }
            inner_pkt = simple_tcp_packet(**pkt_opts)
            send_packet(self, self.send_port, inner_pkt)

        # --- Capture VXLAN traffic ---
        timeout = 8
        start = datetime.now()
        while (datetime.now() - start).total_seconds() < timeout:
            res = dp_poll(self, timeout=1)
            if not isinstance(res, self.dataplane.PollSuccess):
                continue
            ether = scapy.Ether(res.packet)
            if scapy.IP in ether and scapy.UDP in ether and ether[scapy.UDP].dport == self.vxlan_port:
                vtep_dst = ether[scapy.IP].dst
                if vtep_dst in self.endpoints:
                    counts[vtep_dst] = counts.get(vtep_dst, 0) + 1

        if not counts:
            raise AssertionError("No VXLAN packets captured")

        missing = set(self.endpoints) - set(counts.keys())
        if missing:
            raise AssertionError(f"Missing {len(missing)} endpoints: {list(missing)[:10]} ...")

        logger.info(f"VXLAN ECMP test passed: {len(counts)} / {len(self.endpoints)} endpoints used")

    def tearDown(self):
        self.dataplane.flush()
