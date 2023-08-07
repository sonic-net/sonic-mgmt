"""
Test cases for testing DSCP to Queue mapping for IP-IP packets in SONiC.
"""

import logging
import pytest
import ptf.testutils as testutils
import ptf.packet as scapy
from ptf import mask
from scapy.all import Ether, IP
from tabulate import tabulate

from tests.common.utilities import wait_until, is_ipv4_address, get_ipv4_loopback_ip, get_dscp_to_queue_value,\
    get_dut_pair_port_from_ptf_port
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from abc import abstractmethod
from tests.common.fixtures.duthost_utils import dut_qos_maps, separated_dscp_to_tc_map_on_uplink
from tests.common.snappi_tests.common_helpers import get_egress_queue_count
from tests.common.fixtures.duthost_utils import dut_qos_maps # noqa F811
from tests.qos.qos_sai_base import QosSaiBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1'),
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
]

DEFAULT_TTL = 64
DEFAULT_ECN = 1
DEFAULT_PKT_COUNT = 100
output_table = []


def create_ipip_packet(outer_src_mac,
                       outer_dst_mac,
                       outer_src_pkt_ip,
                       outer_dst_pkt_ip,
                       outer_dscp,
                       inner_src_mac,
                       inner_dst_mac,
                       inner_src_pkt_ip,
                       inner_dst_pkt_ip,
                       inner_dscp):
    """
    Generate IPV4 IP-IP packets.

    Args:
        outer_src_mac: Outer source MAC address
        outer_dst_mac: Outer destination MAC address
        outer_src_pkt_ip: Outer source IP address
        outer_dst_pkt_ip: Outer destination IP address
        outer_dscp: Outer DSCP value
        inner_src_mac: Inner source MAC address
        inner_dst_mac: Inner destination MAC address
        inner_src_pkt_ip: Inner source IP address
        inner_dst_pkt_ip: Inner destination IP address
        inner_dscp: Inner DSCP value

    Returns:
        IP-IP packet, expected packet
    """

    inner_pkt = testutils.simple_tcp_packet(eth_src=inner_src_mac,
                                            eth_dst=inner_dst_mac,
                                            ip_src=inner_src_pkt_ip,
                                            ip_dst=inner_dst_pkt_ip,
                                            ip_dscp=inner_dscp,
                                            ip_ecn=DEFAULT_ECN,
                                            ip_ttl=DEFAULT_TTL)

    inner_pkt.ttl -= 1

    outer_pkt = testutils.simple_ipv4ip_packet(eth_src=outer_src_mac,
                                               eth_dst=outer_dst_mac,
                                               ip_src=outer_src_pkt_ip,
                                               ip_dst=outer_dst_pkt_ip,
                                               ip_dscp=outer_dscp,
                                               ip_ecn=DEFAULT_ECN,
                                               inner_frame=inner_pkt[scapy.IP])

    inner_pkt += 1

    exp_pkt = mask.Mask(inner_pkt)
    exp_pkt.set_do_not_care_scapy(Ether, 'src')
    exp_pkt.set_do_not_care_scapy(Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(IP, 'id')
    exp_pkt.set_do_not_care_scapy(IP, 'ttl')
    exp_pkt.set_do_not_care_scapy(IP, 'chksum')

    return outer_pkt, exp_pkt


def send_and_verify_traffic(duthost,
                            ptfadapter,
                            pkt,
                            exp_pkt,
                            ptf_src_port_id,
                            ptf_dst_port_id,
                            dut_egress_port,
                            egress_queue,
                            inner_dscp,
                            asic_type="broadcom"):
    """
    Send traffic and verify that traffic was received

    Args:
        duthost: DUT host object
        ptfadapter: PTF adapter
        pkt: Packet that should be sent
        exp_pkt: Expected packet
        ptf_src_port_id: Source port of ptf
        ptf_dst_port_id: Destination port of ptf
        dut_egress_port: Egress port of DUT ex. Ethernet0
        egress_queue: Egress queue number on DUT
        inner_dscp: Inner DSCP value
        asic_type: ASIC type of DUT
    """

    ptfadapter.dataplane.flush()
    logger.info("Send packet from port {} to port {}".format(ptf_src_port_id, ptf_dst_port_id))
    global output_table
    testutils.send(ptfadapter, ptf_src_port_id, pkt, count=DEFAULT_PKT_COUNT)

    testutils.verify_packet(ptfadapter, exp_pkt, ptf_dst_port_id)
    egress_queue_count, _ = get_egress_queue_count(duthost, dut_egress_port, egress_queue)
    verification_success = egress_queue_count == DEFAULT_PKT_COUNT

    if asic_type == "broadcom" and verification_success:
        logger.info("Received expected number of packets on queue {}".format(egress_queue))
        output_table.append([inner_dscp, egress_queue, egress_queue_count])
    else:
        logger.info("Received {} packets on queue {} instead of {}".format(egress_queue_count, egress_queue,
                                                                           DEFAULT_PKT_COUNT))
        output_table.append([inner_dscp, egress_queue, egress_queue_count])


class TestQoSSaiDSCPQueueMapping_IPIP_Base(QosSaiBase):
    """
    Base class
    """

    def _run_test(self,
                  ptfadapter,
                  duthost,
                  tbinfo,
                  dutTestParams,
                  dutConfig,
                  dut_qos_maps): # noqa F811
        """
            Test QoS SAI DSCP to queue mapping for IP-IP packets
            Args:
                ptfadapter (PtfAdapter): PTF adapter
                duthost (AnsibleHost): The DUT host
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dut_qos_maps(Fixture): A fixture, return qos maps on DUT host
            Returns:
                None
            Raises:
                RunAnsibleModuleFail if ptf test fails
        """

        if "backend" in dutTestParams["topo"]:
            pytest.skip("Dscp-queue mapping is not supported on {}".format(dutTestParams["topo"]))

        loopback_ip = get_ipv4_loopback_ip(duthost)
        pytest_assert(loopback_ip, "No loopback ip found")

        DUMMY_IP = '8.8.8.8'

        router_mac = dutTestParams["basicParams"]['router_mac']
        test_port_ids = dutConfig["testPortIds"]
        outer_dst_port_id = dutConfig["testPorts"]["dst_port_id"]
        outer_dst_pkt_ip = loopback_ip
        outer_src_port_id = dutConfig["testPorts"]["src_port_id"]
        outer_src_pkt_ip = dutConfig["testPorts"]["src_port_ip"]
        inner_dst_port_id = dutConfig["testPorts"]["dst_port_id"]
        inner_dst_pkt_ip = dutConfig["testPorts"]["dst_port_ip"]
        inner_src_port_id = dutConfig["testPorts"]["src_port_id"]
        inner_src_pkt_ip = DUMMY_IP
        ptf_src_mac = ptfadapter.dataplane.get_mac(0, outer_src_port_id)
        ptf_dst_mac = ptfadapter.dataplane.get_mac(0, inner_dst_port_id)
        outer_dscp = 4

        pytest_assert(dut_qos_maps.get("dscp_to_tc_map") and dut_qos_maps.get("tc_to_queue_map"),
                      "No QoS map found on DUT")

        for inner_dscp in range(0, 64):
            pkt, exp_pkt = create_ipip_packet(outer_src_mac=ptf_src_mac,
                                              outer_dst_mac=router_mac,
                                              outer_src_pkt_ip=outer_src_pkt_ip,
                                              outer_dst_pkt_ip=outer_dst_pkt_ip,
                                              outer_dscp=outer_dscp,
                                              inner_src_mac=router_mac,
                                              inner_dst_mac=ptf_dst_mac,
                                              inner_src_pkt_ip=inner_src_pkt_ip,
                                              inner_dst_pkt_ip=inner_dst_pkt_ip,
                                              inner_dscp=inner_dscp)

            queue_val = get_dscp_to_queue_value(inner_dscp, dut_qos_maps.get("dscp_to_tc_map"),
                                                dut_qos_maps.get("tc_to_queue_map"))
            dut_egress_port = get_dut_pair_port_from_ptf_port(duthost, tbinfo, inner_dst_port_id)
            pytest_assert(dut_egress_port, "No egress port on DUT found for ptf port {}".format(inner_dst_port_id))

            # Clear queue counters
            duthost.command("sonic-clear queuecounters")
            global output_table

            if queue_val is None:
                logger.info("No queue found for dscp {} on DUT".format(inner_dscp))
                output_table.append([inner_dscp, "No queue found", "N/A"])
                continue

            try:
                send_and_verify_traffic(duthost=duthost,
                                        ptfadapter=ptfadapter,
                                        pkt=pkt,
                                        exp_pkt=exp_pkt,
                                        ptf_src_port_id=outer_src_port_id,
                                        ptf_dst_port_id=inner_dst_port_id,
                                        dut_egress_port=dut_egress_port,
                                        egress_queue=queue_val,
                                        inner_dscp=inner_dscp,
                                        asic_type=dutTestParams["asic_type"])

            except Exception as e:
                raise (e)

        logger.info("DSCP to queue mapping test results:\n{}"
                    .format(tabulate(output_table,
                                     headers=["Inner Packet DSCP Value", "Egress Queue", "Egress Queue Count"])))

    def test_dscp_to_queue_mapping(self, ptfadapter, duthost, tbinfo, dutTestParams, dutConfig, dut_qos_maps): # noqa F811
        """
            Test QoS SAI DSCP to queue mapping for IP-IP packets
        """
        self._run_test(ptfadapter, duthost, tbinfo, dutTestParams, dutConfig, dut_qos_maps)
