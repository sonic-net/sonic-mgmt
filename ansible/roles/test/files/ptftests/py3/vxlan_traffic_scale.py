import ptf
from ptf.base_tests import BaseTest
from ptf.mask import Mask
import random
import logging
import ptf.packet as scapy
from ptf.testutils import (
    simple_tcp_packet,
    simple_vxlan_packet,
    verify_packet_any_port,
    send_packet,
    test_params_get,
)


class VXLANScaleTest(BaseTest):
    """
    Scaled VXLAN route verification test.
    Builds TCP packets per sampled /32 route per VNET and verifies
    VXLAN-encapsulated packets egress on any of the expected uplink ports.
    """

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.test_params = test_params_get()

        self.dut_vtep = self.test_params["dut_vtep"]
        self.ptf_vtep = self.test_params["ptf_vtep"]
        self.vnet_base = int(self.test_params["vnet_base"])
        self.num_vnets = int(self.test_params["num_vnets"])
        self.routes_per_vnet = int(self.test_params["routes_per_vnet"])
        self.samples_per_vnet = int(self.test_params.get("samples_per_vnet", 100))
        self.vnet_ptf_map = self.test_params["vnet_ptf_map"]

        # egress interfaces can be list or single int (for backward compat)
        egress_param = self.test_params.get("egress_ptf_if", [])
        if isinstance(egress_param, str):
            # Could be comma-separated list passed as string
            self.egress_ptf_if = [int(x) for x in egress_param.split(",") if x.strip()]
        elif isinstance(egress_param, list):
            self.egress_ptf_if = [int(x) for x in egress_param]
        else:
            self.egress_ptf_if = [int(egress_param)]

        self.router_mac = self.test_params.get("router_mac")
        self.mac_switch = self.test_params.get("mac_switch")
        self.random_mac = "00:aa:bb:cc:dd:ee"
        self.tcp_sport = 1234
        self.tcp_dport = 5000
        self.vxlan_port = self.test_params['vxlan_port']
        self.udp_sport = 49366

        self.logger = logging.getLogger("VXLANScaleTest")
        self.logger.setLevel(logging.INFO)

        self.logger.info(
            f"VXLANScaleTest params: vnets={self.num_vnets}, routes_per_vnet={self.routes_per_vnet}, "
            f"samples_per_vnet={self.samples_per_vnet}, egress_ptf_if={self.egress_ptf_if}"
        )

    def _next_port(self, key="sport"):
        """Simple port generator for varying TCP ports."""
        if key == "sport":
            self.tcp_sport = (self.tcp_sport + 1) % 65535 or 1234
            return self.tcp_sport
        else:
            self.tcp_dport = (self.tcp_dport + 1) % 65535 or 5000
            return self.tcp_dport

    def build_masked_encap(self, inner_exp_pkt, vni):
        """
        Construct VXLAN-encapsulated expected packet and apply mask.
        """
        encap_pkt = simple_vxlan_packet(
            eth_src=self.router_mac,
            eth_dst=self.random_mac,
            ip_id=0,
            ip_src=self.dut_vtep,
            ip_dst=self.ptf_vtep,
            ip_ttl=128,
            udp_sport=self.udp_sport,
            udp_dport=self.vxlan_port,
            with_udp_chksum=False,
            vxlan_vni=vni,
            inner_frame=inner_exp_pkt,
        )
        encap_pkt[scapy.IP].flags = 0x2

        m = Mask(encap_pkt)
        m.set_ignore_extra_bytes()
        # don't care about dynamic fields
        m.set_do_not_care_scapy(scapy.Ether, "src")
        m.set_do_not_care_scapy(scapy.Ether, "dst")
        m.set_do_not_care_scapy(scapy.IP, "ttl")
        m.set_do_not_care_scapy(scapy.IP, "chksum")
        m.set_do_not_care_scapy(scapy.IP, "id")
        m.set_do_not_care_scapy(scapy.UDP, "sport")
        return m

    def runTest(self):
        self.logger.info("Starting VXLAN scale TCP verification test...")
        self.dataplane.flush()

        total_failures = 0

        for vnet_name, mapping in self.vnet_ptf_map.items():
            vnet_id = mapping["vnet_id"]
            vni = self.vnet_base + vnet_id
            ingress_port = int(mapping["ptf_ifindex"])
            ptf_intf_name = mapping["ptf_intf"]
            dut_intf_name = mapping["dut_intf"]

            self.logger.info(
                f"Testing {vnet_name}: ingress={ptf_intf_name} (index {ingress_port}), "
                f"DUT intf={dut_intf_name}, VNI={vni}"
            )

            indices = random.sample(
                range(self.routes_per_vnet),
                min(self.samples_per_vnet, self.routes_per_vnet),
            )

            for i in indices:
                dst_ip = f"30.{vnet_id}.{i // 256}.{i % 256}"
                ip_src = f"201.0.{vnet_id}.101"

                tcp_sport = self._next_port("sport")
                tcp_dport = self._next_port("dport")
                src_mac = self.dataplane.get_mac(0, ingress_port)

                pkt_opts = {
                    "eth_dst": self.router_mac,
                    "eth_src": src_mac,
                    "ip_dst": dst_ip,
                    "ip_src": ip_src,
                    "ip_id": 105,
                    "ip_ttl": 64,
                    "tcp_sport": tcp_sport,
                    "tcp_dport": tcp_dport,
                    "pktlen": 100,
                }
                inner_pkt = simple_tcp_packet(**pkt_opts)

                # Expected inner after routing
                pkt_opts["ip_ttl"] = 63
                pkt_opts["eth_src"] = self.router_mac
                pkt_opts["eth_dst"] = self.mac_switch
                inner_exp_pkt = simple_tcp_packet(**pkt_opts)

                masked_exp_pkt = self.build_masked_encap(inner_exp_pkt, vni)

                try:
                    send_packet(self, ingress_port, inner_pkt)
                    verify_packet_any_port(
                        self, masked_exp_pkt, self.egress_ptf_if, timeout=2
                    )
                except Exception as e:
                    total_failures += 1
                    self.logger.error(
                        f"[FAIL] {vnet_name}: dst={dst_ip}, ingress={ptf_intf_name}, "
                        f"vni={vni}, error={repr(e)}"
                    )

        if total_failures > 0:
            self.fail(f"{total_failures} VXLAN route verifications failed")

        self.logger.info("VXLANScaleTest completed successfully.")
