import logging
from collections import Counter
import random
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
        self.traffic_test_type = params.get("traffic_test_type", "vxlan")
        self.test_vnet_id = int(params.get("test_vnet_id", 1))
        self.packets_per_path = int(params.get("packets_per_path", 100))
        self.ecmp_deviation_pct = int(params.get("ecmp_deviation_pct", 50))

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

        logger.info(
            "Traffic type: %s, VNET: %d, packets_per_path=%d, deviation=%d%%",
            self.traffic_test_type,
            self.test_vnet_id,
            self.packets_per_path,
            self.ecmp_deviation_pct,
        )

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

    def _check_ecmp_distribution(self, distribution, total_packets, failures, context, vnet_id):
        missing_ports = [
            port for port in self.wl_ptf_port_indices
            if distribution[port] == 0
        ]

        expected = float(total_packets) / len(self.wl_ptf_port_indices)
        allowed_delta = expected * self.ecmp_deviation_pct / 100.0

        bad_ports = []
        for port in self.wl_ptf_port_indices:
            count = distribution[port]
            if abs(count - expected) > allowed_delta:
                bad_ports.append(
                    "port {} count {} expected {:.2f} allowed +/- {:.2f}".format(
                        port, count, expected, allowed_delta
                    )
                )

        logger.info("========================================")
        logger.info("%s dataplane summary for VNET %d", context, vnet_id)
        logger.info("Total flows sent: %d", total_packets)
        logger.info("Flows passed: %d", total_packets - len(failures))
        logger.info("Flows failed: %d", len(failures))
        logger.info("ECMP distribution: %s", dict(distribution))
        logger.info("Missing egress ports: %s", missing_ports)
        logger.info("Bad ECMP distribution ports: %s", bad_ports)
        logger.info("Expected packets per port: %.2f", expected)
        logger.info(
            "Allowed deviation: +/- %.2f packets (%d%%)",
            allowed_delta,
            self.ecmp_deviation_pct,
        )
        logger.info("========================================")

        if failures or missing_ports or bad_ports:
            self.fail(
                "{} ECMP test failed for VNET {}. failures={}, missing_ports={}, "
                "bad_ports={}, distribution={}".format(
                    context,
                    vnet_id,
                    failures,
                    missing_ports,
                    bad_ports,
                    dict(distribution),
                )
            )

    def _run_vxlan_decap_ecmp_test(self):
        vnet_id = self.test_vnet_id
        shared_dst_ip = self._shared_route_ip(vnet_id)

        total_packets = self.packets_per_path * self.subifs_per_vnet
        distribution = Counter()
        failures = []

        logger.info(
            "VXLAN ECMP test: vnet=%d dst=%s total_packets=%d",
            vnet_id,
            shared_dst_ip,
            total_packets,
        )

        for flow_id in range(total_packets):
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

            send_packet(self, self.ingress_port, tx_pkt)

            try:
                match_index, _ = verify_packet_any_port(
                    self,
                    exp_pkt,
                    ports=self.wl_ptf_port_indices,
                    timeout=2,
                )

                matched_port = self.wl_ptf_port_indices[match_index]
                distribution[matched_port] += 1

                logger.info(
                    "VNET %d VXLAN flow %d PASSED: src=%s dst=%s matched index=%s egress port=%s",
                    vnet_id,
                    flow_id,
                    inner_src_ip,
                    shared_dst_ip,
                    match_index,
                    matched_port,
                )
            except Exception as e:
                failure = "VNET {} VXLAN flow {} FAILED: src={} dst={} error={}".format(
                    vnet_id,
                    flow_id,
                    inner_src_ip,
                    shared_dst_ip,
                    e,
                )
                logger.error(failure)
                failures.append(failure)

        logger.info("VXLAN distribution: %s", dict(distribution))
        self._check_ecmp_distribution(
            distribution,
            total_packets,
            failures,
            "VXLAN",
            vnet_id,
        )

    def _run_regular_tcp_ecmp_test(self):
        vnet_id = self.test_vnet_id
        dst_ip = self._shared_route_ip(vnet_id)

        ingress_port = self.wl_ptf_port_indices[0]
        total_packets = self.packets_per_path * self.subifs_per_vnet

        distribution = Counter()
        failures = []

        logger.info(
            "Regular TCP ECMP test: vnet=%d dst=%s ingress_port=%s total_packets=%d",
            vnet_id,
            dst_ip,
            ingress_port,
            total_packets,
        )

        for flow_id in range(total_packets):
            src_ip = "192.0.2.{}".format(random.randint(1, 250))

            tx_pkt = simple_tcp_packet(
                eth_src=self.ptf_macs[ingress_port],
                eth_dst=self.dut_mac,
                dl_vlan_enable=True,
                vlan_vid=self._vlan_for_vnet(vnet_id),
                ip_src=src_ip,
                ip_dst=dst_ip,
                tcp_sport=10000 + flow_id,
                tcp_dport=5000,
                pktlen=104,
            )

            exp_pkt = self._build_expected_packet(
                vnet_id,
                src_ip,
                dst_ip,
            )

            send_packet(self, ingress_port, tx_pkt)

            try:
                match_index, _ = verify_packet_any_port(
                    self,
                    exp_pkt,
                    ports=self.wl_ptf_port_indices,
                    timeout=2,
                )

                matched_port = self.wl_ptf_port_indices[match_index]
                distribution[matched_port] += 1

                logger.info(
                    "VNET %d regular TCP flow %d PASSED: src=%s dst=%s matched index=%s egress port=%s",
                    vnet_id,
                    flow_id,
                    src_ip,
                    dst_ip,
                    match_index,
                    matched_port,
                )
            except Exception as e:
                failure = "VNET {} regular TCP flow {} FAILED: src={} dst={} error={}".format(
                    vnet_id,
                    flow_id,
                    src_ip,
                    dst_ip,
                    e,
                )
                logger.error(failure)
                failures.append(failure)

        logger.info("Regular TCP distribution: %s", dict(distribution))
        self._check_ecmp_distribution(
            distribution,
            total_packets,
            failures,
            "Regular TCP",
            vnet_id,
        )

    def runTest(self):
        if self.traffic_test_type == "vxlan":
            self._run_vxlan_decap_ecmp_test()
        elif self.traffic_test_type == "regular_tcp":
            self._run_regular_tcp_ecmp_test()
        else:
            self.fail("Unsupported traffic_test_type: {}".format(self.traffic_test_type))
