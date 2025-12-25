import ptf
import logging
from ptf.base_tests import BaseTest
from ptf.testutils import (
    simple_ip_packet,
    send_packet,
    verify_packet,
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
        self.dut_mac = params.get("router_mac")
        self.ptf_src_mac = self.dataplane.get_mac(0, self.ptf_port_index)
        self.dataplane.flush()

        # Build test prefixes 50.high.low.1
        self.test_routes = []
        for v in range(1, self.vnet_count + 1):
            for s in range(self.subifs_per_vnet):
                sid = (v - 1) * self.subifs_per_vnet + s
                high = sid // 256
                low = sid % 256
                prefix = f"50.{high}.{low}.1"
                self.test_routes.append((v, s, sid, prefix))

    def build_expected_packet(self, vlan_id, src_ip, dst_ip):
        """
        Expected output packet from DUT → PTF (same VLAN, MAC swapped).
        """
        pkt = simple_ip_packet(
            eth_src=self.dut_mac,
            eth_dst=self.ptf_src_mac,
            ip_src=src_ip,
            ip_dst=dst_ip,
            vlan_vid=vlan_id
        )

        m = Mask(pkt)
        m.set_do_not_care_scapy("IP", "ttl")
        m.set_do_not_care_scapy("IP", "chksum")
        m.set_do_not_care_scapy("IP", "id")
        return m

    def runTest(self):
        failures = []
        successes = 0

        logger.info("Starting dataplane verification with send_packet()...")

        for vnet_id, subif_index, sid, dst_ip in self.test_routes:
            vlan_id = self.base_vlan_id + sid
            base = sid * 4
            ptf_ip = f"10.1.{base//256}.{(base%256)+2}"

            tx_pkt = simple_ip_packet(
                eth_src=self.ptf_src_mac,
                eth_dst=self.dut_mac,
                ip_src=ptf_ip,
                ip_dst=dst_ip,
                vlan_vid=vlan_id
            )

            exp_pkt = self.build_expected_packet(vlan_id, ptf_ip, dst_ip)

            try:
                send_packet(self, self.ptf_port_index, tx_pkt)
                verify_packet(self, exp_pkt, self.ptf_port_index)
                successes += 1
            except Exception as e:
                logger.warning(
                    "FAILED: %s (VNET %d, subif %d, VLAN %d): %s",
                    dst_ip, vnet_id, subif_index, vlan_id, e
                )
                failures.append(dst_ip)

        # ---------- Summary ----------
        total = len(self.test_routes)
        logger.info("\n================ Summary ================")
        logger.info("Routes tested : %d", total)
        logger.info("Successes     : %d", successes)
        logger.info("Failures      : %d", len(failures))
        logger.info("========================================")

        if failures:
            for r in failures:
                logger.error("  FAILED prefix: %s", r)
            self.fail(f"{len(failures)} dataplane checks FAILED")

        logger.info("All routes passed dataplane verification!")
