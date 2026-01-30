import ptf
import logging
from ptf.base_tests import BaseTest
import ptf.packet as scapy
from ptf.testutils import (
    simple_tcp_packet,
    send_packet,
    verify_packet_any_port,
    test_params_get,
)
from ptf.mask import Mask

logger = logging.getLogger(__name__)


class VnetBgpScaleDataplane(BaseTest):
    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        params = test_params_get()

        self.vnet_count = int(params["vnet_count"])
        self.subifs_per_vnet = int(params["subif_per_vnet"])
        self.base_vlan_id = int(params["base_vlan_id"])
        self.ptf_port_index = int(params["ptf_port_index"])
        self.dut_mac = params["router_mac"]

        self.ptf_mac = self.dataplane.get_mac(0, self.ptf_port_index)
        self.dataplane.flush()

        # Build (vnet, subif, sid, dst_ip)
        self.test_routes = []
        for vnet_id in range(1, self.vnet_count + 1):
            for subif_index in range(self.subifs_per_vnet):
                sid = (vnet_id - 1) * self.subifs_per_vnet + subif_index
                high = sid // 256
                low = sid % 256
                dst_ip = f"50.{high}.{low}.1"
                self.test_routes.append((vnet_id, subif_index, sid, dst_ip))

    def _ptf_ip_for_sid(self, sid):
        base = sid * 4
        return f"10.1.{base // 256}.{(base % 256) + 2}"

    def build_expected_packet(self, vlan_id, src_ip, dst_ip):
        exp = simple_tcp_packet(
            eth_src=self.dut_mac,
            eth_dst=self.ptf_mac,
            dl_vlan_enable=True,
            vlan_vid=vlan_id,
            ip_src=src_ip,
            ip_dst=dst_ip,
            tcp_sport=12345,
            tcp_dport=5000,
        )

        m = Mask(exp)
        m.set_do_not_care_scapy(scapy.IP, "ttl")
        m.set_do_not_care_scapy(scapy.IP, "chksum")
        m.set_do_not_care_scapy(scapy.IP, "id")
        m.set_do_not_care_scapy(scapy.IP, "len")
        m.set_do_not_care_scapy(scapy.IP, "tos")
        m.set_do_not_care_scapy(scapy.TCP, "chksum")
        return m

    def runTest(self):
        failures = []
        successes = 0

        logger.info("Starting VNET BGP dataplane routing test")

        for vnet_id, egress_subif, sid, dst_ip in self.test_routes:
            # ---- EGRESS ----
            egress_vlan = self.base_vlan_id + sid

            # ---- INGRESS (different subif, same VNET) ----
            ingress_subif = (egress_subif + 1) % self.subifs_per_vnet
            ingress_sid = (vnet_id - 1) * self.subifs_per_vnet + ingress_subif
            ingress_vlan = self.base_vlan_id + ingress_sid
            ingress_ptf_ip = self._ptf_ip_for_sid(ingress_sid)

            tx_pkt = simple_tcp_packet(
                eth_src=self.ptf_mac,
                eth_dst=self.dut_mac,
                dl_vlan_enable=True,
                vlan_vid=ingress_vlan,
                ip_src=ingress_ptf_ip,
                ip_dst=dst_ip,
                tcp_sport=12345,
                tcp_dport=5000,
            )

            exp_pkt = self.build_expected_packet(
                egress_vlan, ingress_ptf_ip, dst_ip
            )

            try:
                send_packet(self, self.ptf_port_index, tx_pkt)
                verify_packet_any_port(
                    self, exp_pkt, ports=[self.ptf_port_index], timeout=2
                )
                successes += 1
            except Exception as e:
                logger.warning(
                    "FAILED dst=%s VNET=%d ingress_vlan=%d egress_vlan=%d: %s",
                    dst_ip, vnet_id, ingress_vlan, egress_vlan, e,
                )
                failures.append(dst_ip)

        logger.info("========================================")
        logger.info("Dataplane summary: %d passed, %d failed",
                    successes, len(failures))
        logger.info("========================================")

        if failures:
            self.fail(f"{len(failures)} routes failed dataplane validation")
