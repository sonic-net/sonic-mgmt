"""
Test cases for testing TC to DSCP mapping for packets in SONiC.
"""

import logging
import time
from typing import Any

import ptf.packet as scapy
import ptf.testutils as testutils
import pytest
from ptf import mask
from scapy.all import IP, Ether
from tabulate import tabulate

from tests.common.dualtor.mux_simulator_control import (
    toggle_all_simulator_ports_to_rand_selected_tor,
)  # noqa F401
from tests.common.helpers.dut_utils import check_config_table_presence
from tests.common.fixtures.duthost_utils import dut_qos_maps_module  # noqa F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.ptf_tests_helper import (
    apply_dscp_cfg_setup,
    apply_dscp_cfg_teardown,
    downstream_links,
    get_dut_pair_port_from_ptf_port,
    get_stream_ptf_ports,
    select_random_link,
    upstream_links,
)  # noqa F401
from tests.common.utilities import (
    find_egress_queue,
    get_dscp_to_queue_value,
    get_egress_queue_pkt_count_all_prio,
    get_ipv4_loopback_ip,
    wait_until,
)

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("t0", "t1")]

DEFAULT_DSCP = 4
DEFAULT_TTL = 64
DEFAULT_ECN = 1
DEFAULT_PKT_COUNT = 2000
DUMMY_OUTER_SRC_IP = "8.8.8.8"
DUMMY_INNER_SRC_IP = "9.9.9.9"
DUMMY_INNER_DST_IP = "10.10.10.10"
output_table = []
packet_egressed_success = False


def create_ip_packet(
    src_mac,
    dst_mac,
    src_pkt_ip,
    dst_pkt_ip,
    dscp,
    exp_dscp,
):
    """
    Generate IPV4 IP packets.

    Args:
        src_mac: source MAC address
        dst_mac: destination MAC address
        src_pkt_ip: source IP address
        dst_pkt_ip: destination IP address
        dscp: DSCP value
        exp_dscp: expected DSCP value of egressed packet

    Returns:
        IP packet, expected packet
    """

    pkt = testutils.simple_ipv4ip_packet(
        eth_src=src_mac,
        eth_dst=dst_mac,
        ip_src=src_pkt_ip,
        ip_dst=dst_pkt_ip,
        ip_dscp=dscp,
        ip_ecn=DEFAULT_ECN,
    )

    exp_pkt = testutils.simple_tcp_packet(
        ip_src=src_pkt_ip,
        ip_dst=dst_pkt_ip,
        ip_dscp=exp_dscp,
        ip_ecn=DEFAULT_ECN,
    )

    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(Ether, "src")
    exp_pkt.set_do_not_care_scapy(Ether, "dst")
    exp_pkt.set_do_not_care_scapy(IP, "id")
    exp_pkt.set_do_not_care_scapy(IP, "ttl")
    exp_pkt.set_do_not_care_scapy(IP, "chksum")

    return pkt, exp_pkt


def send_and_verify_traffic(
    ptfadapter, pkt, exp_pkt, ptf_src_port_id, ptf_dst_port_ids
):
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
        result = testutils.verify_packet_any_port(
            ptfadapter, exp_pkt, ports=ptf_dst_port_ids
        )
        if isinstance(result, bool):
            logger.info("Return a dummy value for VS platform")
            port_index = 0
        else:
            port_index, _ = result
        logger.info(
            "Received packet(s) on port {}".format(ptf_dst_port_ids[port_index])
        )
        global packet_egressed_success
        packet_egressed_success = True
        return ptf_dst_port_ids[port_index]

    except AssertionError as detail:
        if "Did not receive expected packet on any of ports" in str(detail):
            logger.error(
                "Expected packet(s) was not received on any of the ports -> {}".format(
                    ptf_dst_port_ids
                )
            )


def find_queue_count_and_value(duthost, queue_val, dut_egress_port):
    egress_queue_counts_all_queues = get_egress_queue_pkt_count_all_prio(
        duthost, dut_egress_port
    )
    egress_queue_count = egress_queue_counts_all_queues[queue_val]
    egress_queue_val = find_egress_queue(
        egress_queue_counts_all_queues, DEFAULT_PKT_COUNT
    )

    return egress_queue_count, egress_queue_val


class TestQoSSai_TC_TO_DSCP_Mapping_Base:
    """
    Test class for TC to DSCP Mapping for IP packets.
    """

    def _setup_test_params(
        self,
        duthost,
        downstream_links,  # noqa F811
        upstream_links,  # noqa F811
        test_mode,
    ):
        """
        Set up test parameters for the TC to DSCP mapping packets.

        Args:
            duthost (fixture): DUT fixture
            downstream_links (fixture): Dictionary of downstream links info for DUT
            upstream_links (fixture): Dictionary of upstream links info for DUT
            test_mode (str): Type of test i.e. correct mapping, invalid mapping, missing mapping, etc
        """
        test_params: dict[str, Any] = {}
        downlink = select_random_link(downstream_links)
        uplink_ptf_ports = get_stream_ptf_ports(upstream_links)
        loopback_ip = get_ipv4_loopback_ip(duthost)
        router_mac = duthost.facts["router_mac"]
        import pdb; pdb.set_trace()
        
        tc_to_dscp_map_present = check_config_table_presence(duthost, table_name="TC_TO_DSCP_MAP")
        if tc_to_dscp_map_present:
            pass

        pytest_assert(downlink is not None, "No downlink found")
        pytest_assert(uplink_ptf_ports is not None, "No uplink found")
        pytest_assert(loopback_ip is not None, "No loopback IP found")
        pytest_assert(router_mac is not None, "No router MAC found")

        test_params["ptf_downlink_port"] = downlink.get("ptf_port_id")
        test_params["ptf_uplink_ports"] = uplink_ptf_ports
        test_params["outer_src_ip"] = "8.8.8.8"
        test_params["outer_dst_ip"] = loopback_ip
        test_params["router_mac"] = router_mac

        return test_params

    def _run_test(
        self,
        ptfadapter,
        duthost,
        tbinfo,
        test_params,
        dut_qos_maps_module,  # noqa F811
    ):  # noqa F811
        """
        Test QoS SAI TC to DSCP mapping for IP packets
        Args:
            ptfadapter (PtfAdapter): PTF adapter
            duthost (AnsibleHost): The DUT host
            tbinfo (fixture): Testbed info
            test_params (dict): Dictionary of test parameters - initialized in _setup_test_params()
            dut_qos_maps_module (Fixture): A module level fixture, return qos maps on DUT host
        Returns:
            None
        Raises:
            RunAnsibleModuleFail if ptf test fails
        """
        asic_type = duthost.facts["asic_type"]
        router_mac = test_params["router_mac"]
        ptf_src_port_id = test_params["ptf_downlink_port"]
        ptf_dst_port_ids = test_params["ptf_uplink_ports"]
        outer_dst_pkt_ip = test_params["outer_dst_ip"]
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

        pytest_assert(
            dut_qos_maps_module.get("dscp_to_tc_map")
            and dut_qos_maps_module.get("tc_to_queue_map"),
            "No QoS map found on DUT",
        )

        for rotating_dscp in range(0, 64):
            pkt, exp_pkt = create_ip_packet(
                src_mac=ptf_src_mac,
                dst_mac=router_mac,
                src_pkt_ip=outer_src_pkt_ip,
                dst_pkt_ip=outer_dst_pkt_ip,
                dscp=rotating_dscp,
                exp_dscp=mapped_dscp,
            )

            queue_val = get_dscp_to_queue_value(
                rotating_dscp,
                dut_qos_maps_module.get("dscp_to_tc_map").get("AZURE"),
                dut_qos_maps_module.get("tc_to_queue_map").get("AZURE"),
            )

            global output_table

            if queue_val is None:
                logger.info("No queue found for dscp {} on DUT".format(inner_dscp))
                output_table.append([rotating_dscp, "No queue found", "N/A", "N/A"])
                continue

            # Clear queue counters
            duthost.command("sonic-clear queuecounters")
            time.sleep(2)

            try:
                dst_ptf_port_id = send_and_verify_traffic(
                    ptfadapter=ptfadapter,
                    pkt=pkt,
                    exp_pkt=exp_pkt,
                    ptf_src_port_id=ptf_src_port_id,
                    ptf_dst_port_ids=ptf_dst_port_ids,
                )

            except ConnectionError as e:
                # Sending large number of packets can cause socket buffer to be full and leads connection timeout.
                logger.error("{}: Try reducing DEFAULT_PKT_COUNT value".format(str(e)))
                failed_once = True

            if asic_type == "vs":
                logger.info("Skipping queue verification for VS platform")
                continue
            global packet_egressed_success
            if packet_egressed_success:
                dut_egress_port = get_dut_pair_port_from_ptf_port(
                    duthost, tbinfo, dst_ptf_port_id
                )
                pytest_assert(
                    dut_egress_port,
                    "No egress port on DUT found for ptf port {}".format(
                        dst_ptf_port_id
                    ),
                )
                # Wait for the queue counters to be populated.
                verification_success = wait_until(
                    60,
                    2,
                    0,
                    lambda: find_queue_count_and_value(
                        duthost, queue_val, dut_egress_port
                    )[0]
                    >= DEFAULT_PKT_COUNT,
                )
                egress_queue_count, egress_queue_val = find_queue_count_and_value(
                    duthost, queue_val, dut_egress_port
                )
                if verification_success:
                    logger.info(
                        "SUCCESS: Received expected number of packets on queue {}".format(
                            queue_val
                        )
                    )
                    output_table.append(
                        [
                            rotating_dscp,
                            queue_val,
                            egress_queue_count,
                            "SUCCESS",
                            queue_val,
                        ]
                    )
                else:
                    if queue_val == egress_queue_val:
                        # If the queue value is correct, but the packet count is incorrect, then the DUT poll failed
                        logger.info(
                            "FAILURE: Not all packets received on queue {}. DUT poll failure.".format(
                                queue_val
                            )
                        )
                        logger.info(
                            "Received {} packets instead".format(egress_queue_count)
                        )
                        output_table.append(
                            [
                                rotating_dscp,
                                queue_val,
                                egress_queue_count,
                                "FAILURE - INCORRECT PACKET COUNT",
                                egress_queue_val,
                            ]
                        )
                    else:
                        if egress_queue_val == -1:
                            logger.info(
                                "FAILURE: Packets not received on any queue. DUT poll failure."
                            )
                            output_table.append(
                                [
                                    rotating_dscp,
                                    queue_val,
                                    egress_queue_count,
                                    "FAILURE - DUT POLL FAILURE",
                                    egress_queue_val,
                                ]
                            )
                        else:
                            logger.info(
                                "FAILURE: Received {} packets on queue {} instead of queue {}.".format(
                                    DEFAULT_PKT_COUNT, egress_queue_val, queue_val
                                )
                            )
                            output_table.append(
                                [
                                    rotating_dscp,
                                    queue_val,
                                    egress_queue_count,
                                    "FAILURE - INCORRECT QUEUE",
                                    egress_queue_val,
                                ]
                            )
                    failed_once = True
            else:
                output_table.append(
                    [
                        rotating_dscp,
                        queue_val,
                        0,
                        "FAILURE - NO PACKETS EGRESSED",
                        "N/A",
                    ]
                )
                failed_once = True

            # Reset packet egress status
            packet_egressed_success = False

        # Clear the output_table (for next test functions).
        output_table = []

        pytest_assert(
            not failed_once, "FAIL: Test failed."
        )

    def _teardown_test(self, duthost):
        """
        Test teardown

        Args:
            duthost (AnsibleHost): The DUT host
        """
        apply_dscp_cfg_teardown(duthost)

    def test_tc_to_dscp_map_valid_table_valid_map(
        self,
        ptfadapter,
        rand_selected_dut,
        toggle_all_simulator_ports_to_rand_selected_tor,  # noqa F811
        setup_standby_ports_on_rand_unselected_tor,
        tbinfo,
        downstream_links,  # noqa F811
        upstream_links,  # noqa F811
        dut_qos_maps_module,  # noqa F811
    ):  # noqa F811
        """
        Test TC to DSCP mapping for TC TO DSCP mapping on egress is correct
        when table and mapping are both present so packet will egress with
        newly mapped DSCP.
        """
        duthost = rand_selected_dut
        import pdb; pdb.set_trace()
        test_params = self._setup_test_params(
            duthost, downstream_links, upstream_links, "pipe"
        )
        self._run_test(
            ptfadapter, duthost, tbinfo, test_params, dut_qos_maps_module,
        )
        self._teardown_test(duthost)
