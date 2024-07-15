"""
Test cases for testing DSCP to Queue mapping for IP-IP packets in SONiC.
"""

import logging
import pytest
import time
import ptf.testutils as testutils
import ptf.packet as scapy
from ptf import mask
from scapy.all import Ether, IP
from tabulate import tabulate

from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor # noqa F401
from tests.common.helpers.ptf_tests_helper import downstream_links, upstream_links, select_random_link,\
    get_stream_ptf_ports, get_dut_pair_port_from_ptf_port, apply_dscp_cfg_setup, apply_dscp_cfg_teardown # noqa F401
from tests.common.utilities import get_ipv4_loopback_ip, get_dscp_to_queue_value, find_egress_queue,\
    get_egress_queue_pkt_count_all_prio, wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.duthost_utils import dut_qos_maps_module # noqa F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1')
]

DEFAULT_DSCP = 4
DEFAULT_TTL = 64
DEFAULT_ECN = 1
DEFAULT_PKT_COUNT = 2000
DUMMY_OUTER_SRC_IP = '8.8.8.8'
DUMMY_INNER_SRC_IP = '9.9.9.9'
DUMMY_INNER_DST_IP = '10.10.10.10'
output_table = []
packet_egressed_success = False


def create_ipip_packet(outer_src_mac,
                       outer_dst_mac,
                       outer_src_pkt_ip,
                       outer_dst_pkt_ip,
                       outer_dscp,
                       inner_src_pkt_ip,
                       inner_dst_pkt_ip,
                       inner_dscp,
                       decap_mode):
    """
    Generate IPV4 IP-IP packets.

    Args:
        outer_src_mac: Outer source MAC address
        outer_dst_mac: Outer destination MAC address
        outer_src_pkt_ip: Outer source IP address
        outer_dst_pkt_ip: Outer destination IP address
        outer_dscp: Outer DSCP value
        inner_src_pkt_ip: Inner source IP address
        inner_dst_pkt_ip: Inner destination IP address
        inner_dscp: Inner DSCP value
        decap_mode: DSCP decap mode

    Returns:
        IP-IP packet, expected packet
    """

    inner_pkt = testutils.simple_tcp_packet(ip_src=inner_src_pkt_ip,
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

    inner_pkt.ttl += 1

    if decap_mode == "uniform":
        exp_dscp = outer_dscp
    elif decap_mode == "pipe":
        exp_dscp = inner_dscp

    exp_pkt = testutils.simple_tcp_packet(ip_src=inner_src_pkt_ip,
                                          ip_dst=inner_dst_pkt_ip,
                                          ip_dscp=exp_dscp,
                                          ip_ecn=DEFAULT_ECN,
                                          ip_ttl=DEFAULT_TTL)

    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(Ether, 'src')
    exp_pkt.set_do_not_care_scapy(Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(IP, 'id')
    exp_pkt.set_do_not_care_scapy(IP, 'ttl')
    exp_pkt.set_do_not_care_scapy(IP, 'chksum')

    return outer_pkt, exp_pkt


def send_and_verify_traffic(ptfadapter,
                            pkt,
                            exp_pkt,
                            ptf_src_port_id,
                            ptf_dst_port_ids):
    """
    Send traffic and verify that traffic was received

    Args:
        ptfadapter: PTF adapter
        pkt: Packet that should be sent
        exp_pkt: Expected packet
        ptf_src_port_id: Source port of ptf
        ptf_dst_port_ids: Possible destination ports of ptf
    """

    ptfadapter.dataplane.flush()
    logger.info("Send packet(s) from port {} upstream".format(ptf_src_port_id))
    testutils.send(ptfadapter, ptf_src_port_id, pkt, count=DEFAULT_PKT_COUNT)

    try:
        port_index, _ = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=ptf_dst_port_ids)
        logger.info("Received packet(s) on port {}".format(ptf_dst_port_ids[port_index]))
        global packet_egressed_success
        packet_egressed_success = True
        return ptf_dst_port_ids[port_index]

    except AssertionError as detail:
        if "Did not receive expected packet on any of ports" in str(detail):
            logger.error("Expected packet(s) was not received on any of the ports -> {}".format(ptf_dst_port_ids))


def find_queue_count_and_value(duthost, queue_val, dut_egress_port):
    egress_queue_counts_all_queues = get_egress_queue_pkt_count_all_prio(duthost, dut_egress_port)
    egress_queue_count = egress_queue_counts_all_queues[queue_val]
    egress_queue_val = find_egress_queue(egress_queue_counts_all_queues, DEFAULT_PKT_COUNT)

    return egress_queue_count, egress_queue_val


class TestQoSSaiDSCPQueueMapping_IPIP_Base():
    """
    Test class for DSCP to Queue Mapping for IP-IP packets.
    """
    def _setup_test_params(self,
                           duthost,
                           downstream_links, # noqa F811
                           upstream_links, # noqa F811
                           decap_mode):
        """
        Set up test parameters for the DSCP to Queue mapping test for IP-IP packets.

        Args:
            duthost (fixture): DUT fixture
            downstream_links (fixture): Dictionary of downstream links info for DUT
            upstream_links (fixture): Dictionary of upstream links info for DUT
            decap_mode (str): DSCP mode
        """
        test_params = {}
        downlink = select_random_link(downstream_links)
        uplink_ptf_ports = get_stream_ptf_ports(upstream_links)
        loopback_ip = get_ipv4_loopback_ip(duthost)
        router_mac = duthost.facts["router_mac"]

        # Setup DSCP decap config on DUT
        apply_dscp_cfg_setup(duthost, decap_mode)

        pytest_assert(downlink is not None, "No downlink found")
        pytest_assert(uplink_ptf_ports is not None, "No uplink found")
        pytest_assert(loopback_ip is not None, "No loopback IP found")
        pytest_assert(router_mac is not None, "No router MAC found")

        test_params["ptf_downlink_port"] = downlink.get("ptf_port_id")
        test_params["ptf_uplink_ports"] = uplink_ptf_ports
        test_params["outer_src_ip"] = '8.8.8.8'
        test_params["outer_dst_ip"] = loopback_ip
        test_params["router_mac"] = router_mac

        return test_params

    def _run_test(self,
                  ptfadapter,
                  duthost,
                  tbinfo,
                  test_params,
                  dut_qos_maps_module, # noqa F811
                  decap_mode): # noqa F811
        """
            Test QoS SAI DSCP to queue mapping for IP-IP packets
            Args:
                ptfadapter (PtfAdapter): PTF adapter
                duthost (AnsibleHost): The DUT host
                tbinfo (fixture): Testbed info
                test_params (dict): Dictionary of test parameters - initialized in _setup_test_params()
                dut_qos_maps_module (Fixture): A module level fixture, return qos maps on DUT host
                decap_mode (str): DSCP mode
            Returns:
                None
            Raises:
                RunAnsibleModuleFail if ptf test fails
        """

        if "backend" in tbinfo["topo"]["type"]:
            pytest.skip("Dscp-queue mapping is not supported on {}".format(tbinfo["topo"]["type"]))

        router_mac = test_params['router_mac']
        ptf_src_port_id = test_params['ptf_downlink_port']
        ptf_dst_port_ids = test_params['ptf_uplink_ports']
        outer_dst_pkt_ip = test_params['outer_dst_ip']
        outer_src_pkt_ip = DUMMY_OUTER_SRC_IP
        inner_dst_pkt_ip = DUMMY_INNER_DST_IP
        inner_src_pkt_ip = DUMMY_INNER_SRC_IP
        ptf_src_mac = ptfadapter.dataplane.get_mac(0, ptf_src_port_id)
        failed_once = False

        # Log packet information
        logger.info("Outer Pkt Src IP: {}".format(outer_src_pkt_ip))
        logger.info("Outer Pkt Dst IP: {}".format(outer_dst_pkt_ip))
        logger.info("Inner Pkt Src IP: {}".format(inner_src_pkt_ip))
        logger.info("Inner Pkt Dst IP: {}".format(inner_dst_pkt_ip))
        logger.info("Pkt Src MAC: {}".format(ptf_src_mac))
        logger.info("Pkt Dst MAC: {}".format(router_mac))

        pytest_assert(dut_qos_maps_module.get("dscp_to_tc_map") and dut_qos_maps_module.get("tc_to_queue_map"),
                      "No QoS map found on DUT")

        for rotating_dscp in range(0, 64):
            if decap_mode == "uniform":
                outer_dscp = rotating_dscp
                inner_dscp = DEFAULT_DSCP
                logger.info("Uniform mode: outer_dscp = {}, inner_dscp = {}".format(outer_dscp, inner_dscp))
            elif decap_mode == "pipe":
                outer_dscp = DEFAULT_DSCP
                inner_dscp = rotating_dscp
                logger.info("Pipe mode: outer_dscp = {}, inner_dscp = {}".format(outer_dscp, inner_dscp))

            pkt, exp_pkt = create_ipip_packet(outer_src_mac=ptf_src_mac,
                                              outer_dst_mac=router_mac,
                                              outer_src_pkt_ip=outer_src_pkt_ip,
                                              outer_dst_pkt_ip=outer_dst_pkt_ip,
                                              outer_dscp=outer_dscp,
                                              inner_src_pkt_ip=inner_src_pkt_ip,
                                              inner_dst_pkt_ip=inner_dst_pkt_ip,
                                              inner_dscp=inner_dscp,
                                              decap_mode=decap_mode)

            queue_val = get_dscp_to_queue_value(rotating_dscp, dut_qos_maps_module.get("dscp_to_tc_map").get("AZURE"),
                                                dut_qos_maps_module.get("tc_to_queue_map").get("AZURE"))

            global output_table

            if queue_val is None:
                logger.info("No queue found for dscp {} on DUT".format(inner_dscp))
                output_table.append([rotating_dscp, "No queue found", "N/A", "N/A"])
                continue

            # Clear queue counters
            duthost.command("sonic-clear queuecounters")
            time.sleep(2)

            try:
                dst_ptf_port_id = send_and_verify_traffic(ptfadapter=ptfadapter,
                                                          pkt=pkt,
                                                          exp_pkt=exp_pkt,
                                                          ptf_src_port_id=ptf_src_port_id,
                                                          ptf_dst_port_ids=ptf_dst_port_ids)

            except ConnectionError as e:
                # Sending large number of packets can cause socket buffer to be full and leads connection timeout.
                logger.error("{}: Try reducing DEFAULT_PKT_COUNT value".format(str(e)))
                failed_once = True

            global packet_egressed_success
            if packet_egressed_success:
                dut_egress_port = get_dut_pair_port_from_ptf_port(duthost, tbinfo, dst_ptf_port_id)
                pytest_assert(dut_egress_port, "No egress port on DUT found for ptf port {}".format(dst_ptf_port_id))
                # Wait for the queue counters to be populated.
                verification_success = wait_until(60, 2, 0, lambda: find_queue_count_and_value(duthost,
                                                  queue_val, dut_egress_port)[0] >= DEFAULT_PKT_COUNT)
                egress_queue_count, egress_queue_val = find_queue_count_and_value(duthost, queue_val, dut_egress_port)
                if verification_success:
                    logger.info("SUCCESS: Received expected number of packets on queue {}".format(queue_val))
                    output_table.append([rotating_dscp, queue_val, egress_queue_count, "SUCCESS", queue_val])
                else:
                    if queue_val == egress_queue_val:
                        # If the queue value is correct, but the packet count is incorrect, then the DUT poll failed
                        logger.info("FAILURE: Not all packets received on queue {}. DUT poll failure."
                                    .format(queue_val))
                        logger.info("Received {} packets instead".format(egress_queue_count))
                        output_table.append([rotating_dscp, queue_val, egress_queue_count,
                                             "FAILURE - INCORRECT PACKET COUNT", egress_queue_val])
                    else:
                        if egress_queue_val == -1:
                            logger.info("FAILURE: Packets not received on any queue. DUT poll failure.")
                            output_table.append([rotating_dscp, queue_val, egress_queue_count,
                                                 "FAILURE - DUT POLL FAILURE", egress_queue_val])
                        else:
                            logger.info("FAILURE: Received {} packets on queue {} instead of queue {}."
                                        .format(DEFAULT_PKT_COUNT, egress_queue_val, queue_val))
                            output_table.append([rotating_dscp, queue_val, egress_queue_count,
                                                 "FAILURE - INCORRECT QUEUE", egress_queue_val])
                    failed_once = True
            else:
                output_table.append([rotating_dscp, queue_val, 0, "FAILURE - NO PACKETS EGRESSED", "N/A"])
                failed_once = True

            # Reset packet egress status
            packet_egressed_success = False

        logger.info("DSCP to queue mapping test results:\n{}"
                    .format(tabulate(output_table,
                                     headers=["Inner Packet DSCP Value", "Expected Egress Queue",
                                              "Egress Queue Count", "Result", "Actual Egress Queue"])))
        # Clear the output_table (for next test functions).
        output_table = []

        pytest_assert(not failed_once, "FAIL: Test failed. Please check table for details.")

    def _teardown_test(self, duthost):
        """
        Test teardown

        Args:
            duthost (AnsibleHost): The DUT host
        """
        apply_dscp_cfg_teardown(duthost)

    def test_dscp_to_queue_mapping_pipe_mode(self, ptfadapter, rand_selected_dut,
                                             toggle_all_simulator_ports_to_rand_selected_tor, # noqa F811
                                             setup_standby_ports_on_rand_unselected_tor,
                                             tbinfo, downstream_links, upstream_links, dut_qos_maps_module): # noqa F811
        """
            Test QoS SAI DSCP to queue mapping for IP-IP packets in DSCP "pipe" mode
        """
        duthost = rand_selected_dut
        test_params = self._setup_test_params(duthost, downstream_links, upstream_links, "pipe")
        self._run_test(ptfadapter, duthost, tbinfo, test_params, dut_qos_maps_module, "pipe")
        self._teardown_test(duthost)

    def test_dscp_to_queue_mapping_uniform_mode(self, ptfadapter, rand_selected_dut,
                                                toggle_all_simulator_ports_to_rand_selected_tor, # noqa F811
                                                setup_standby_ports_on_rand_unselected_tor,
                                                tbinfo, downstream_links, upstream_links, dut_qos_maps_module): # noqa F811
        """
            Test QoS SAI DSCP to queue mapping for IP-IP packets in DSCP "uniform" mode
        """
        duthost = rand_selected_dut
        test_params = self._setup_test_params(duthost, downstream_links, upstream_links, "uniform")
        self._run_test(ptfadapter, duthost, tbinfo, test_params, dut_qos_maps_module, "uniform")
        self._teardown_test(duthost)
