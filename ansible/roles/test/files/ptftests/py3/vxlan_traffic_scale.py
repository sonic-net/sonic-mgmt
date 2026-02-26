import json
import ptf
from ptf.base_tests import BaseTest
from ptf.mask import Mask
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
        self.vnet_base = int(self.test_params["vnet_base"])
        self.num_vnets = int(self.test_params["num_vnets"])
        self.routes_per_vnet = int(self.test_params["routes_per_vnet"])
        self.samples_per_vnet = int(self.test_params.get("samples_per_vnet", -1))
        self.vnet_ptf_map = self.test_params["vnet_ptf_map"]
        self.mac_vni_per_vnet = self.test_params.get("mac_vni_per_vnet", "")
        self.routes_per_vni = self.test_params.get("vni_batch_size", 1000)
        self.routes_to_test_file_paths = self.test_params.get("routes_to_test_file_paths", {})

        if self.samples_per_vnet < 0:
            self.samples_per_vnet = self.routes_per_vnet

        self.routes_to_test = {}
        for vnet_name, mappings in self.vnet_ptf_map.items():
            with open(self.routes_to_test_file_paths[vnet_name], "r") as f:
                self.routes_to_test[vnet_name] = json.load(f)

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

    def build_masked_encap(self, inner_exp_pkt, vni, endpoint):
        """
        Construct VXLAN-encapsulated expected packet and apply mask.
        """
        encap_pkt = simple_vxlan_packet(
            eth_src=self.router_mac,
            eth_dst=self.random_mac,
            ip_id=0,
            ip_src=self.dut_vtep,
            ip_dst=endpoint,
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

    def _build_packets_for_test(self, ingress_port, dst_ip, src_ip, programmed_mac, vni, endpoint):
        """
        Returns: (inner_packet, masked_expected_encap)
        """

        src_mac = self.dataplane.get_mac(0, ingress_port)

        # Base inner packet
        inner = simple_tcp_packet(
            eth_dst=self.router_mac,
            eth_src=src_mac,
            ip_dst=dst_ip,
            ip_src=src_ip,
            ip_id=105,
            ip_ttl=64,
            tcp_sport=self._next_port("sport"),
            tcp_dport=self._next_port("dport"),
            pktlen=100,
        )

        # Expected inner after DUT rewrite
        inner_exp = inner.copy()
        inner_exp[scapy.Ether].src = self.router_mac
        inner_exp[scapy.Ether].dst = programmed_mac
        inner_exp[scapy.IP].ttl = 63

        # Masked expected encap
        masked = self.build_masked_encap(inner_exp, vni, endpoint)
        return inner, masked

    def _send_and_verify(self, vnet_name, ingress_port, inner_pkt, exp_pkt, failures, log_prefix):
        try:
            send_packet(self, ingress_port, inner_pkt)
            verify_packet_any_port(self, exp_pkt, self.egress_ptf_if, timeout=3)
            self.logger.info(f"[{log_prefix}] {vnet_name} PASSED")
        except Exception as e:
            failures[vnet_name] += 1
            self.logger.error(
                f"[{log_prefix} FAIL] {vnet_name}: ingress={ingress_port}, error={repr(e)}"
            )

    def run_mac_vni_per_vnet_test(self):
        self.logger.info("=== Running deterministic MAC+VNI validation ===")

        failures = {v: 0 for v in self.vnet_ptf_map}

        for vnet_name, mapping in self.vnet_ptf_map.items():
            vnet_id = mapping["vnet_id"]
            ingress = int(mapping["ptf_ifindex"])

            for idx in range(self.samples_per_vnet):
                dst_ip = self.routes_to_test[vnet_name][idx]["route"]
                src_ip = f"201.0.{vnet_id}.101"

                mac = self.routes_to_test[vnet_name][idx]["mac_address"]
                vni = self.routes_to_test[vnet_name][idx]["vni"]
                endpoint = self.routes_to_test[vnet_name][idx]["endpoint"]

                inner, exp = self._build_packets_for_test(
                    ingress, dst_ip, src_ip, mac, vni, endpoint
                )

                self._send_and_verify(vnet_name, ingress, inner, exp,
                                      failures, "MAC+VNI")

        # Summary
        total = sum(failures.values())
        for n, f in failures.items():
            self.logger.info(f"{n}: {f} failures")

        if total > 0:
            self.fail(f"MAC+VNI validation failed ({total} failures).")

    def run_endpoint_test(self):
        # Track failures per VNET
        failures = {vnet_name: 0 for vnet_name in self.vnet_ptf_map}

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

            for i in range(self.samples_per_vnet):
                dst_ip = self.routes_to_test[vnet_name][i]["route"]
                ip_src = f"201.0.{vnet_id}.101"

                endpoint = self.routes_to_test[vnet_name][i]["endpoint"]

                inner, masked = self._build_packets_for_test(
                    ingress_port, dst_ip, ip_src, self.mac_switch, vni, endpoint
                )

                self._send_and_verify(vnet_name, ingress_port, inner, masked,
                                      failures, "SCALE")

        # ---- Summary ----
        self.logger.info("---- VXLAN Scale Test Failure Summary ----")
        for vnet_name, count in failures.items():
            self.logger.info(f"{vnet_name}: {count} failures")

        total_failures = sum(failures.values())
        self.logger.info(f"TOTAL FAILURES: {total_failures}")

        if total_failures > 0:
            self.fail(f"VXLAN verification failed with {total_failures} packet misses")
        else:
            self.logger.info("VXLANScaleTest completed successfully.")

    def runTest(self):
        self.logger.info("Starting VXLAN scale TCP verification test...")
        self.dataplane.flush()
        if self.mac_vni_per_vnet:
            return self.run_mac_vni_per_vnet_test()
        else:
            return self.run_endpoint_test()        
