"""
Test cases for testing QoS remapping functionality in SONiC.
This module tests DSCP to TC mapping, TC to priority mapping, and TC to DSCP mapping.
"""

import logging
import pytest
import ipaddress

from tests.common.helpers.ptf_tests_helper import (
    select_test_interface_and_ptf_port
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from .qos_helpers import (
    update_tc_to_dscp_map,
    remove_qos_map,
    clear_queue_counters,
    get_queue_counter,
    get_dscp_for_tc,
    get_outgoing_dscp
)
from ptf import testutils
from scapy.all import IP, Ether

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

# Default Azure DSCP to TC mapping
DEFAULT_AZURE_DSCP_TO_TC = {
    "0": "1", "3": "3", "4": "4", "5": "2", "8": "0", "46": "5", "48": "6"
}

# Default Azure TC to Queue mapping
DEFAULT_AZURE_TC_TO_QUEUE = {
    "0": "0", "1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "7": "7"
}

# Custom TC to DSCP mapping
CUSTOM_TC_TO_DSCP = {
    "0": "1", "1": "10", "2": "12", "3": "14", "4": "16", "5": "18", "6": "20", "7": "22"
}

# Global variables for packet counts - easy to change for testing
QUEUE_COUNTER_VERIFICATION_PACKETS = 1000
DSCP_REMAPPING_VERIFICATION_PACKETS = 100


class TestQosRemap:
    """Test class for QoS remapping functionality"""

    @pytest.fixture(autouse=True)
    def cleanup_qos_maps(self, duthost):
        """
        Fixture to cleanup QoS maps after each test.

        This fixture:
        1. Runs after each test method
        2. Removes TC_TO_DSCP_MAP from DUT
        3. Ensures clean state for next test
        """
        yield  # Run test first

        # Cleanup after test
        logger.info("Cleaning up QoS maps after test")
        try:
            # Remove only TC_TO_DSCP_MAP
            result = remove_qos_map(duthost, 'TC_TO_DSCP_MAP', 'REMAP_TEST')
            if result:
                logger.info("✓ Cleaned up TC_TO_DSCP_MAP 'REMAP_TEST'")
            else:
                logger.warning("Failed to cleanup TC_TO_DSCP_MAP 'REMAP_TEST'")

            logger.info("Cleanup completed")
        except Exception as e:
            logger.error("Error during cleanup: {}".format(str(e)))

    def setup_qos_mappings(self, duthost, tbinfo):
        """Setup QoS mappings on DUT.

        Apply tc_to_dscp_map.
        """
        interface_name, ptf_port_index = select_test_interface_and_ptf_port(duthost, tbinfo)
        if not interface_name or not ptf_port_index:
            logger.error("Could not find interface with PTF port mapping")
            return None, None

        logger.info("Selected interface: {} (PTF port: {})".format(interface_name, ptf_port_index))

        # Apply tc_to_dscp_map
        logger.info("Applying tc_to_dscp_map (custom), using default Azure for dscp_to_tc and tc_to_queue")

        if not update_tc_to_dscp_map(duthost, CUSTOM_TC_TO_DSCP, map_name='REMAP_TEST', interface=interface_name):
            logger.error("Failed to apply TC_TO_DSCP_MAP to {}".format(interface_name))
            return None, None
        logger.info("✓ TC_TO_DSCP_MAP applied")

        logger.info("QoS mappings setup complete")
        return interface_name, ptf_port_index

    def test_qos_mappings(self, duthost, tbinfo, ptfadapter):
        """Setup and test QoS mappings with queue counter verification and DSCP remapping with dataplane poll."""

        # Check if DUT is running supported Broadcom ASIC
        if duthost.facts["asic_type"].lower() != "broadcom":
            pytest.skip(f"Test only supports Broadcom ASICs. Current ASIC: {duthost.facts['asic_type']}")

        interface_name, ptf_port_index = self.setup_qos_mappings(duthost, tbinfo)

        pytest_assert(interface_name and ptf_port_index,
                      "Failed to setup QoS mappings")

        logger.info("Starting QoS mapping verification for interface: {}".format(interface_name))

        # Get interface IP from minigraph
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        interface_ip = next((intf['addr'] for intf in mg_facts.get('minigraph_interfaces', [])
                            if intf['attachto'] == interface_name), None)
        pytest_assert(interface_ip, "Could not find IP address for interface {}".format(interface_name))

        # Setup packet IPs in same subnet
        interface_network = ipaddress.ip_interface(interface_ip)
        src_ip = str(interface_network.ip - 1)
        dst_ip = str(interface_network.ip + 1)

        # Get MACs and mappings
        router_mac = duthost.facts["router_mac"]
        ptf_mac = ptfadapter.dataplane.get_mac(0, ptf_port_index)

        # Verify that interface has DSCP_TO_TC and TC_TO_QUEUE set to AZURE
        config_facts = duthost.asic_instance().config_facts(source="running")["ansible_facts"]
        port_qos_map = config_facts.get('PORT_QOS_MAP', {})
        pytest_assert(port_qos_map, "PORT_QOS_MAP not found in DUT config")

        interface_qos_map = port_qos_map.get(interface_name, {})
        pytest_assert(interface_qos_map, "Interface {} not found in PORT_QOS_MAP".format(interface_name))

        dscp_to_tc_profile = interface_qos_map.get('dscp_to_tc_map')
        tc_to_queue_profile = interface_qos_map.get('tc_to_queue_map')

        pytest_assert(dscp_to_tc_profile == 'AZURE',
                      "Interface {} dscp_to_tc_map is '{}', expected 'AZURE'".format(
                          interface_name, dscp_to_tc_profile))
        pytest_assert(tc_to_queue_profile == 'AZURE',
                      "Interface {} tc_to_queue_map is '{}', expected 'AZURE'".format(
                          interface_name, tc_to_queue_profile))

        logger.info("✓ Interface {} has DSCP_TO_TC_MAP='AZURE' and TC_TO_QUEUE_MAP='AZURE'".format(interface_name))

        # Use default Azure profile for dscp_to_tc and tc_to_queue in all phases
        dscp_to_tc_map = DEFAULT_AZURE_DSCP_TO_TC
        tc_to_queue_map = DEFAULT_AZURE_TC_TO_QUEUE

        # Use custom tc_to_dscp mapping in all phases
        tc_to_dscp_map = CUSTOM_TC_TO_DSCP

        logger.info("Interface: {} IP: {}".format(interface_name, interface_ip))
        logger.info("Packet IPs: {} -> {}".format(src_ip, dst_ip))
        logger.info("Router MAC: {}, PTF MAC: {}".format(router_mac, ptf_mac))

        # ========== PHASE 1: Queue Counter Verification ==========
        logger.info("\n" + "="*80)
        logger.info("PHASE 1: Queue Counter Verification (1000 packets per TC)")
        logger.info("="*80)

        for tc_value in range(7):
            logger.info("\n=== Queue Verification TC={} ===".format(tc_value))

            # Clear counters and get expected queue
            pytest_assert(clear_queue_counters(duthost), "Failed to clear queue counters")
            expected_queue = int(tc_to_queue_map.get(str(tc_value), tc_value))

            # Get DSCP for this TC and send packets
            incoming_dscp = get_dscp_for_tc(dscp_to_tc_map, tc_value)
            pytest_assert(incoming_dscp is not None, "Could not find DSCP for TC {}".format(tc_value))

            pkt = testutils.simple_tcp_packet(
                eth_dst=router_mac, eth_src=ptf_mac, ip_src=src_ip, ip_dst=dst_ip,
                ip_dscp=incoming_dscp, tcp_sport=1234, tcp_dport=80)

            for _ in range(QUEUE_COUNTER_VERIFICATION_PACKETS):
                testutils.send_packet(ptfadapter, ptf_port_index, pkt)

            logger.info("Sent {} packets with DSCP={} (TC={})".format(
                QUEUE_COUNTER_VERIFICATION_PACKETS, incoming_dscp, tc_value))

            # Wait for packets to be processed and queue counter to reach expected count
            def check_queue_counter():
                counter = get_queue_counter(duthost, interface_name, expected_queue)
                if counter >= QUEUE_COUNTER_VERIFICATION_PACKETS:
                    logger.info("✓ Queue {} received {} packets".format(expected_queue, counter))
                    return True
                else:
                    logger.debug("Queue {} received {} packets, waiting for more...".format(expected_queue, counter))
                    return False

            wait_until(timeout=30, interval=1, delay=1, condition=check_queue_counter)

            # Final verification
            queue_counter = get_queue_counter(duthost, interface_name, expected_queue)
            pytest_assert(
                queue_counter >= QUEUE_COUNTER_VERIFICATION_PACKETS,
                "Queue {} received {} packets, expected >= {}".format(
                    expected_queue, queue_counter, QUEUE_COUNTER_VERIFICATION_PACKETS))

        logger.info("\n=== Phase 1 Complete ===\n")

        # ========== PHASE 2: DSCP Remapping ==========
        logger.info("="*80)
        logger.info("PHASE 2: DSCP Remapping Verification")
        logger.info("="*80)

        # Increase buffer size for PTF dataplane to handle more packets
        logger.info("Increasing dataplane queue length for packet buffering")
        ptfadapter.dataplane.qlen = 10000

        for tc_value in range(7):
            logger.info("\n=== DSCP Remapping Verification TC={} ===".format(tc_value))

            # Get incoming and outgoing DSCP
            incoming_dscp = get_dscp_for_tc(dscp_to_tc_map, tc_value)
            pytest_assert(incoming_dscp is not None, "Could not find DSCP for TC {}".format(tc_value))

            outgoing_dscp = get_outgoing_dscp(incoming_dscp, dscp_to_tc_map, tc_to_dscp_map)
            logger.info("DSCP remapping: {} -> {}".format(incoming_dscp, outgoing_dscp))

            # Send test packets
            pkt = testutils.simple_tcp_packet(
                eth_dst=router_mac, eth_src=ptf_mac, ip_src=src_ip, ip_dst=dst_ip,
                ip_dscp=incoming_dscp, tcp_sport=1234, tcp_dport=80)

            for _ in range(DSCP_REMAPPING_VERIFICATION_PACKETS):
                testutils.send_packet(ptfadapter, ptf_port_index, pkt)

            logger.info("Sent {} packets with DSCP={}".format(DSCP_REMAPPING_VERIFICATION_PACKETS, incoming_dscp))

            # Poll dataplane for packets and verify DSCP remapping
            captured_packet_count = 0

            def check_captured_packets():
                nonlocal captured_packet_count

                # Poll all available packets from dataplane
                while True:
                    result = ptfadapter.dataplane.poll(
                        device_number=0,
                        port_number=ptf_port_index,
                        timeout=1
                    )

                    if isinstance(result, ptfadapter.dataplane.PollFailure):
                        # No more packets available
                        break

                    if isinstance(result, ptfadapter.dataplane.PollSuccess):
                        rcv_pkt = Ether(result.packet)

                        # Extract IP layer and check DSCP
                        if IP in rcv_pkt:
                            ip_layer = rcv_pkt[IP]
                            packet_dscp = ip_layer.tos >> 2  # Extract DSCP from TOS field

                            # Check if packet matches expected criteria
                            if (ip_layer.src == src_ip and
                                    ip_layer.dst == dst_ip and
                                    packet_dscp == outgoing_dscp):
                                captured_packet_count += 1

                if captured_packet_count >= DSCP_REMAPPING_VERIFICATION_PACKETS:
                    logger.info("✓ Captured {} packets with correct DSCP={}".format(
                        captured_packet_count, outgoing_dscp))
                    return True
                else:
                    logger.debug("Captured {} packets with DSCP={}, waiting for more...".format(
                        captured_packet_count, outgoing_dscp))
                    return False

            wait_until(timeout=30, interval=1, delay=1, condition=check_captured_packets)

            # Final verification
            pytest_assert(
                captured_packet_count >= DSCP_REMAPPING_VERIFICATION_PACKETS,
                "Expected >= {} packets with DSCP={}, got {}".format(
                    DSCP_REMAPPING_VERIFICATION_PACKETS, outgoing_dscp, captured_packet_count))

        logger.info("\n" + "="*80)
        logger.info("All QoS mapping tests complete!")
        logger.info("="*80)
