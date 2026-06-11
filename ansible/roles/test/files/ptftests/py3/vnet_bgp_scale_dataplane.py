import logging
from collections import Counter

import ptf
import ptf.packet as scapy
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import (
    send_packet,
    simple_tcp_packet,
    simple_vxlan_packet,
    test_params_get,
    verify_packet_any_port,
)

logger = logging.getLogger(__name__)
VNI_BASE = 10000


class VnetBgpScaleDataplane(BaseTest):
    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        params = test_params_get()

        self.vnet_count = int(params["vnet_count"])
        self.subifs_per_vnet = int(params["subif_per_vnet"])
        self.base_vlan_id = int(params["base_vlan_id"])

        self.wl_ptf_port_indices = [
            int(port_index)
            for port_index in str(params["wl_ptf_port_indices"]).split(",")
            if str(port_index).strip()
        ]
        self.t1_ptf_port_index = int(params["t1_ptf_port_index"])

        self.dut_mac = params["router_mac"]
        self.dut_vtep = params["dut_vtep"]
        self.vxlan_port = int(params["vxlan_port"])

        self.ingress_port = self.t1_ptf_port_index

        all_ports = set(self.wl_ptf_port_indices + [self.t1_ptf_port_index])
        self.ptf_macs = {
            port_index: self.dataplane.get_mac(0, port_index)
            for port_index in all_ports
        }
        self.dataplane.flush()

    def _vlan_for_vnet(self, vnet_id):
        return self.base_vlan_id + (vnet_id - 1)

    def _ptf_ip_for(self, vnet_id, subif_index):
        block_size = 4
        global_index = (vnet_id - 1) * self.subifs_per_vnet + subif_index
        base_offset = global_index * block_size
        third_octet = base_offset // 256
        fourth_octet = base_offset % 256
        return "100.1.{}.{}".format(third_octet, fourth_octet + 2)

    def _shared_route_ip(self, vnet_id):
        route_id = vnet_id - 1
        high = route_id // 256
        low = route_id % 256
        return "50.{}.{}.1".format(high, low)

    def _build_expected_packet(self, vnet_id, inner_src_ip, inner_dst_ip):
        pkt = simple_tcp_packet(
            eth_src=self.dut_mac,
            eth_dst="aa:bb:cc:dd:ee:ff",
            dl_vlan_enable=True,
            vlan_vid=self._vlan_for_vnet(vnet_id),
            ip_src=inner_src_ip,
            ip_dst=inner_dst_ip,
            tcp_sport=12345,
            tcp_dport=5000,
            pktlen=104,
        )

        masked = Mask(pkt)
        masked.set_ignore_extra_bytes()
        masked.set_do_not_care_packet(scapy.Ether, "dst")
        masked.set_do_not_care_packet(scapy.IP, "ttl")
        masked.set_do_not_care_packet(scapy.IP, "chksum")
        masked.set_do_not_care_packet(scapy.IP, "id")
        masked.set_do_not_care_packet(scapy.TCP, "sport")
        masked.set_do_not_care_packet(scapy.TCP, "chksum")
        return masked

    def _build_vxlan_packet(self, vnet_id, inner_src_ip, inner_dst_ip, flow_id):
        ingress_mac = self.ptf_macs[self.ingress_port]

        inner_pkt = simple_tcp_packet(
            eth_src=self.dut_mac,
            eth_dst="aa:bb:cc:dd:ee:ff",
            ip_src=inner_src_ip,
            ip_dst=inner_dst_ip,
            tcp_sport=12345 + flow_id,
            tcp_dport=5000,
        )

        return simple_vxlan_packet(
            eth_src=ingress_mac,
            eth_dst=self.dut_mac,
            ip_src="8.8.8.8",
            ip_dst=self.dut_vtep,
            udp_sport=1234 + flow_id + 1,
            udp_dport=self.vxlan_port,
            with_udp_chksum=False,
            vxlan_vni=VNI_BASE + vnet_id,
            inner_frame=inner_pkt,
        )

    def runTest(self):
        flow_count = self.subifs_per_vnet * 10
        all_failures = []
        per_vnet_distribution = {}

        logger.info(
            "Starting VXLAN decap + ECMP dataplane validation for VNETs 1..%d from T1 port %s to WL ports %s",
            self.vnet_count,
            self.t1_ptf_port_index,
            self.wl_ptf_port_indices,
        )

        for vnet_id in range(1, self.vnet_count + 1):
            shared_dst_ip = self._shared_route_ip(vnet_id)
            distribution = Counter()
            failures = []

            logger.info(
                "Validating VNET %d: dst=%s, vlan=%d, vni=%d",
                vnet_id,
                shared_dst_ip,
                self._vlan_for_vnet(vnet_id),
                VNI_BASE + vnet_id,
            )

            for flow_id in range(flow_count):
                inner_src_ip = "192.0.2.{}".format((flow_id % 250) + 1)

                tx_pkt = self._build_vxlan_packet(
                    vnet_id,
                    inner_src_ip,
                    shared_dst_ip,
                    flow_id,
                )

                exp_pkt = self._build_expected_packet(
                    vnet_id,
                    inner_src_ip,
                    shared_dst_ip,
                )

                try:
                    send_packet(self, self.ingress_port, tx_pkt)

                    match_index, rcv_pkt = verify_packet_any_port(
                        self,
                        exp_pkt,
                        ports=self.wl_ptf_port_indices,
                        timeout=2,
                    )

                    matched_port = self.wl_ptf_port_indices[match_index]
                    distribution[matched_port] += 1

                    logger.info(
                        "VNET %d flow %d PASSED: src=%s dst=%s matched index=%s egress port=%s",
                        vnet_id,
                        flow_id,
                        inner_src_ip,
                        shared_dst_ip,
                        match_index,
                        matched_port,
                    )

                except Exception as exc:
                    logger.warning(
                        "VNET %d flow %d FAILED: src=%s dst=%s error=%s",
                        vnet_id,
                        flow_id,
                        inner_src_ip,
                        shared_dst_ip,
                        exc,
                    )
                    failures.append(
                        {
                            "vnet_id": vnet_id,
                            "flow_id": flow_id,
                            "src_ip": inner_src_ip,
                            "dst_ip": shared_dst_ip,
                            "error": str(exc),
                        }
                    )

            missing_ports = [
                port_index
                for port_index in self.wl_ptf_port_indices
                if distribution[port_index] == 0
            ]

            per_vnet_distribution[vnet_id] = dict(distribution)

            logger.info("========================================")
            logger.info("VXLAN dataplane summary for VNET %d", vnet_id)
            logger.info("Total flows sent: %d", flow_count)
            logger.info("Flows passed: %d", flow_count - len(failures))
            logger.info("Flows failed: %d", len(failures))
            logger.info("ECMP distribution: %s", dict(distribution))
            logger.info("Missing egress ports: %s", missing_ports)
            logger.info("========================================")

            if failures:
                all_failures.extend(failures)

            if missing_ports:
                all_failures.append(
                    {
                        "vnet_id": vnet_id,
                        "flow_id": "N/A",
                        "src_ip": "N/A",
                        "dst_ip": shared_dst_ip,
                        "error": "No traffic observed on WL port(s): {}".format(missing_ports),
                    }
                )

        if all_failures:
            failure_lines = [
                "VXLAN dataplane validation failed for {} issue(s) across {} VNET(s)".format(
                    len(all_failures), self.vnet_count
                )
            ]

            for entry in all_failures[:20]:
                failure_lines.append(
                    "vnet={vnet_id} flow_id={flow_id} src={src_ip} dst={dst_ip} error={error}".format(**entry)
                )

            if len(all_failures) > 20:
                failure_lines.append(
                    "... {} more failures omitted".format(len(all_failures) - 20)
                )

            failure_lines.append("Per-VNET ECMP distribution: {}".format(per_vnet_distribution))
            self.fail("\n".join(failure_lines))
