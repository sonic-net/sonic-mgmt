"""
Strict Priority Rate Limiting QoS Test - Direct PTF Traffic Generation

This test validates CIR/PIR rate limiting configuration using STRICT priority scheduler
with direct PTF traffic generation at specific speeds.

Flow:
1. Choose interface and get DSCP to queue mapping from DUT facts
2. Find DSCP value that maps to target queue
3. Get interface IP configuration
4. Create packet that will go through chosen interface TX and target queue
5. Send high speed traffic WITHOUT rate limiting - validate no drops
6. Configure CIR and PIR rate limiting with STRICT priority scheduler
7. Send low speed traffic WITH rate limiting - validate drops occur
8. Send high speed traffic WITH rate limiting - validate drops occur
9. Cleanup configuration

Traffic is generated at specific bytes per second rates, automatically calculating
packets per second based on packet size to achieve the desired bandwidth.
"""

import ipaddress
import json
import logging
import pytest
import random
import time

from tests.common.helpers.assertions import pytest_assert
import ptf.testutils as testutils
from tests.qos.qos_helpers import find_dscp_for_queue
from tests.common.helpers.ptf_tests_helper import get_dut_to_ptf_port_mapping

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def load_test_config():
    """Load test configuration from JSON file."""
    config_file = "qos/files/strict_priority_params.json"
    with open(config_file, 'r') as f:
        config_data = json.load(f)

    return config_data["strict_priority_test"]


# Load test configuration
TEST_CONFIG = load_test_config()


class StrictPriorityRateLimitingDriver:
    """Strict priority rate limiting test driver with direct PTF traffic generation and validation."""

    def __init__(self, duthost, ptf_adapter=None, testbed_info=None):
        """Initialize the strict priority rate limiting test driver."""
        self.duthost = duthost
        self.ptf_adapter = ptf_adapter
        self.testbed_info = testbed_info
        self.target_queue = TEST_CONFIG['queue']

        # Step 1: Choose interface and get PTF port mapping
        self.test_interface, self.ptf_port_index = self._select_test_interface_and_ptf_port()

        # Step 2: Find correct DSCP for target queue
        self.dscp_value = find_dscp_for_queue(duthost, self.target_queue)

        # Step 3: Get interface IP configuration for packet creation
        self.source_ip, self.destination_ip = self._get_test_packet_ips()

        # Step 4: Create the packet template
        self.test_packet_template = self._create_test_packet_template()

        logger.info(f"Initialized Strict Priority Rate Limiting Test Driver for DUT: {duthost.hostname}")
        logger.info(f"Test interface: {self.test_interface}, Target queue: {self.target_queue}")
        logger.info(f"PTF port index: {self.ptf_port_index}")
        logger.info(f"DSCP: {self.dscp_value} (maps to Queue {self.target_queue})")
        logger.info(f"Packet IPs: {self.source_ip} -> {self.destination_ip}")
        logger.info(f"Test config: {TEST_CONFIG}")

    def _select_test_interface_and_ptf_port(self):
        """
        Select test interface and find corresponding PTF port

        Returns:
            tuple: (interface_name, ptf_port_index)
        """
        try:
            # Get DUT to PTF port mapping
            dut_to_ptf_mapping = get_dut_to_ptf_port_mapping(self.duthost, self.testbed_info)

            if not dut_to_ptf_mapping:
                raise Exception("No DUT to PTF port mapping available")

            # Use a random available interface/port pair
            interface_name = random.choice(list(dut_to_ptf_mapping.keys()))
            ptf_port_index = dut_to_ptf_mapping[interface_name]

            logger.info(f"Chosen interface: {interface_name} (PTF port: {ptf_port_index})")
            return interface_name, ptf_port_index

        except Exception as e:
            logger.error(f"Error choosing interface and PTF port: {e}")
            raise

    def _get_test_packet_ips(self):
        """
        Step 3: Get IP configuration for packet creation that will go through chosen interface TX

        Returns:
            tuple: (src_ip, dst_ip) for packet creation
        """
        try:
            # Get interface IP configuration from minigraph
            mg_facts = self.duthost.get_extended_minigraph_facts(self.testbed_info)

            # Look for interface IP in minigraph
            interface_ip = None
            for intf_info in mg_facts.get('minigraph_interfaces', []):
                if intf_info['attachto'] == self.test_interface:
                    interface_ip = intf_info['addr']
                    break

            if not interface_ip:
                raise Exception(f"Could not find IP address for interface {self.test_interface}")

            # Create IPs in same subnet to ensure routing through this interface
            interface_network = ipaddress.ip_interface(interface_ip)

            # Source IP: Use an IP from the interface subnet (PTF side)
            source_ip = str(interface_network.ip - 1)

            # Destination IP: Use next IP in subnet to force routing back out same interface
            destination_ip = str(interface_network.ip + 1)

            logger.info(f"Interface {self.test_interface} IP: {interface_ip}")
            logger.info(f"Packet IPs: {source_ip} -> {destination_ip} (will route through {self.test_interface})")
            return source_ip, destination_ip

        except Exception as e:
            logger.error(f"Error getting packet IPs for interface {self.test_interface}: {e}")
            raise Exception(f"Cannot proceed without valid IP configuration for interface {self.test_interface}: {e}")

    def _create_test_packet_template(self):
        """
        Step 4: Create packet template that will go through chosen interface TX and target queue

        Returns:
            packet: PTF packet template
        """
        try:
            router_mac = self.duthost.facts["router_mac"]
            ptf_mac = self.ptf_adapter.dataplane.get_mac(0, self.ptf_port_index)

            # Create packet with correct DSCP for target queue
            test_packet = testutils.simple_tcp_packet(
                pktlen=TEST_CONFIG['packet_size'],
                eth_dst=router_mac,  # Send to DUT's router MAC for L3 routing
                eth_src=ptf_mac,     # PTF port MAC
                ip_src=self.source_ip,  # Source IP in interface subnet
                ip_dst=self.destination_ip,  # Destination IP that will route through target interface
                ip_tos=self.dscp_value << 2,  # DSCP is upper 6 bits of ToS field
                ip_ttl=64,
                tcp_sport=1234,
                tcp_dport=80
            )

            logger.info(f"Created packet template: {self.source_ip} -> {self.destination_ip}, DSCP {self.dscp_value}")
            return test_packet

        except Exception as e:
            logger.error(f"Error creating packet template: {e}")
            raise

    def _generate_test_traffic(self, traffic_rate_bytes_per_sec, test_duration_seconds):
        """
        Send direct PTF traffic at specified speed using pre-configured packet template.

        This method uses the packet template created in initialization to send traffic
        at the specified speed through the chosen interface to the target queue.

        Skips test if actual traffic rate is below 90% of target rate.

        Args:
            traffic_rate_bytes_per_sec: Traffic rate in bytes per second
            test_duration_seconds: Duration to send traffic

        Returns:
            int: Number of packets actually sent
        """
        if not self.ptf_adapter or self.ptf_port_index is None:
            logger.warning("PTF adapter or port index not available, skipping PTF traffic generation")
            return 0

        try:
            # Calculate packets per second and timing
            packet_size_bytes = TEST_CONFIG['packet_size']
            packets_per_second_float = traffic_rate_bytes_per_sec / packet_size_bytes
            packets_per_second = max(1, round(packets_per_second_float))
            total_packets = packets_per_second * test_duration_seconds
            packet_interval = 1.0 / packets_per_second if packets_per_second > 0 else 1.0
            rate_mbps = (traffic_rate_bytes_per_sec * 8) / 1000000

            logger.info(f"Sending PTF traffic: {traffic_rate_bytes_per_sec} bytes/s "
                        f"({rate_mbps:.1f} Mbps, {packets_per_second} pps) for {test_duration_seconds}s")
            logger.info(f"Interface: {self.test_interface} (PTF port {self.ptf_port_index}), "
                        f"DSCP: {self.dscp_value} -> Queue {self.target_queue}")

            # Flush any existing packets
            self.ptf_adapter.dataplane.flush()

            # Send continuous traffic at specified rate
            start_time = time.time()
            packets_sent = 0
            next_send_time = start_time

            for i in range(total_packets):
                # Send packet
                testutils.send_packet(self.ptf_adapter, self.ptf_port_index, self.test_packet_template)
                packets_sent += 1

                # Calculate next send time
                next_send_time += packet_interval

                # Sleep only if we're ahead of schedule
                current_time = time.time()
                if current_time < next_send_time:
                    sleep_time = next_send_time - current_time
                    if sleep_time > 0:
                        time.sleep(sleep_time)

                # Log progress every 5000 packets
                if (i + 1) % 5000 == 0:
                    elapsed = time.time() - start_time
                    current_rate_pps = (i + 1) / elapsed if elapsed > 0 else 0
                    logger.info(f"Progress: {i + 1}/{total_packets} packets ({current_rate_pps:.0f} pps)")

                # Early exit if we've exceeded the target duration significantly
                elapsed = time.time() - start_time
                if elapsed > test_duration_seconds * 1.5:  # 50% tolerance
                    logger.warning(f"Stopping early due to timing: sent {packets_sent}/{total_packets} "
                                   f"packets in {elapsed:.2f}s")
                    break

            end_time = time.time()
            actual_duration = end_time - start_time
            actual_rate_pps = packets_sent / actual_duration if actual_duration > 0 else 0
            actual_rate_bytes_per_sec = actual_rate_pps * packet_size_bytes  # Convert to bytes per second
            actual_rate_mbps = (actual_rate_bytes_per_sec * 8) / 1000000     # Convert to Mbps for display
            logger.info(f"Traffic completed: {packets_sent} packets in {actual_duration:.2f}s")
            logger.info(f"Actual rate: {actual_rate_bytes_per_sec:.0f} bytes/s "
                        f"({actual_rate_mbps:.1f} Mbps, {actual_rate_pps:.1f} pps)")

            # Calculate accuracy and validate bandwidth achievement
            if traffic_rate_bytes_per_sec > 0:
                accuracy_percent = (actual_rate_bytes_per_sec / traffic_rate_bytes_per_sec) * 100
                logger.info(f"Rate accuracy: {accuracy_percent:.1f}% of target")

                # Check if we achieved acceptable bandwidth
                if accuracy_percent < TEST_CONFIG['bandwidth_tolerance_min']:
                    target_mbps = (traffic_rate_bytes_per_sec * 8) / 1000000
                    logger.error(f"Failed to achieve target bandwidth: {actual_rate_mbps:.1f} Mbps "
                                 f"vs target {target_mbps:.1f} Mbps ({accuracy_percent:.1f}%)")
                    pytest.skip(f"Cannot achieve desired bandwidth: got {accuracy_percent:.1f}% of target rate")

            time.sleep(2)

            return packets_sent

        except Exception as e:
            logger.error(f"Error sending PTF traffic: {e}")
            raise

    def execute_strict_priority_rate_limiting_test(self):
        """
        Execute the complete strict priority rate limiting test flow using direct PTF traffic generation.
        """
        logger.info("Starting strict priority rate limiting test flow...")

        try:
            # Clear interface counters
            self._reset_interface_counters()

            # Generate high traffic WITHOUT rate limiting - should have no drops
            logger.info("Testing baseline traffic without rate limiting...")
            initial_counters = self._retrieve_interface_counters()

            # Send high rate traffic for test duration
            packets_sent = self._generate_test_traffic(
                traffic_rate_bytes_per_sec=TEST_CONFIG['high_traffic_bytes_per_sec'],
                test_duration_seconds=TEST_CONFIG['traffic_duration']
            )

            final_counters = self._retrieve_interface_counters()

            # Validate no drops without rate limiting
            pytest_assert('TX_DRP' in initial_counters, "Failed to get initial TX_DRP counter")
            pytest_assert('TX_DRP' in final_counters, "Failed to get final TX_DRP counter")

            initial_drops = initial_counters['TX_DRP']
            final_drops = final_counters['TX_DRP']
            actual_drops = final_drops - initial_drops

            logger.info(f"Baseline drops: {actual_drops} (threshold: {TEST_CONFIG['drop_threshold_low']})")
            logger.info(f"Packets sent: {packets_sent}")

            pytest_assert(actual_drops < TEST_CONFIG['drop_threshold_low'],
                          f"Baseline traffic had unexpected drops: {actual_drops}")

            # Configure CIR/PIR rate limiting
            logger.info("Configuring strict priority rate limiting...")
            self._apply_strict_priority_rate_limiting_config()

            # Clear counters and test low traffic
            self._reset_interface_counters()
            logger.info("Testing low traffic with rate limiting...")
            initial_counters = self._retrieve_interface_counters()

            # Send low rate traffic for test duration
            packets_sent = self._generate_test_traffic(
                traffic_rate_bytes_per_sec=TEST_CONFIG['low_traffic_bytes_per_sec'],
                test_duration_seconds=TEST_CONFIG['traffic_duration']
            )

            final_counters = self._retrieve_interface_counters()

            # Validate no drops for low traffic
            pytest_assert('TX_DRP' in initial_counters, "Failed to get initial TX_DRP counter")
            pytest_assert('TX_DRP' in final_counters, "Failed to get final TX_DRP counter")

            initial_drops = initial_counters['TX_DRP']
            final_drops = final_counters['TX_DRP']
            actual_drops = final_drops - initial_drops

            logger.info(f"Low traffic drops: {actual_drops} (threshold: {TEST_CONFIG['drop_threshold_low']})")
            logger.info(f"Packets sent: {packets_sent}")

            pytest_assert(actual_drops < TEST_CONFIG['drop_threshold_low'],
                          f"Low traffic had unexpected drops: {actual_drops}")

            # Clear counters and test high traffic
            self._reset_interface_counters()
            logger.info("Testing high traffic with rate limiting...")
            initial_counters = self._retrieve_interface_counters()

            # Send high rate traffic for test duration
            packets_sent = self._generate_test_traffic(
                traffic_rate_bytes_per_sec=TEST_CONFIG['high_traffic_bytes_per_sec'],
                test_duration_seconds=TEST_CONFIG['traffic_duration']
            )

            final_counters = self._retrieve_interface_counters()

            # Validate drops for high traffic
            pytest_assert('TX_DRP' in initial_counters, "Failed to get initial TX_DRP counter")
            pytest_assert('TX_DRP' in final_counters, "Failed to get final TX_DRP counter")

            initial_drops = initial_counters['TX_DRP']
            final_drops = final_counters['TX_DRP']
            actual_drops = final_drops - initial_drops

            logger.info(f"High traffic drops: {actual_drops} (threshold: {TEST_CONFIG['drop_threshold_high']})")
            logger.info(f"Packets sent: {packets_sent}")

            pytest_assert(actual_drops > TEST_CONFIG['drop_threshold_high'],
                          f"High traffic had insufficient drops: {actual_drops}")

            # Cleanup configuration
            logger.info("Cleaning up...")
            self._reload_qos_configuration()

            logger.info("Strict priority rate limiting test flow completed successfully")
            return True

        except Exception as e:
            logger.error(f"Strict priority rate limiting test flow failed: {e}")
            # Attempt cleanup even if test failed
            try:
                self._reload_qos_configuration()
            except Exception as cleanup_error:
                logger.error(f"Cleanup also failed: {cleanup_error}")
            return False

    def cleanup_configuration(self):
        """Clean up strict priority rate limiting test configuration."""
        logger.info("Cleaning up configuration...")
        self._reload_qos_configuration()

    def _apply_strict_priority_rate_limiting_config(self):
        """Configure CIR and PIR rate limiting with STRICT priority scheduler on the specified queue."""
        logger.info(f"Configuring rate limiting on {self.test_interface} queue {self.target_queue} via Redis")

        # Log the rates for clarity
        cir_mbps = (TEST_CONFIG['cir_bytes_per_sec'] * 8) / 1000000  # Convert to Mbps for display
        pir_mbps = (TEST_CONFIG['pir_bytes_per_sec'] * 8) / 1000000  # Convert to Mbps for display
        logger.info(f"Setting rate limits: CIR={cir_mbps:.1f} Mbps ({TEST_CONFIG['cir_bytes_per_sec']} bytes/s), "
                    f"PIR={pir_mbps:.1f} Mbps ({TEST_CONFIG['pir_bytes_per_sec']} bytes/s)")

        try:
            # Create scheduler policy
            policy_name = TEST_CONFIG['scheduler_policy']
            scheduler_key = f"SCHEDULER|{policy_name}"

            # Set scheduler parameters (rates in bytes per second)
            self.duthost.shell(f"redis-cli -n 4 HSET '{scheduler_key}' 'type' 'STRICT'")
            self.duthost.shell(f"redis-cli -n 4 HSET '{scheduler_key}' 'cir' '{TEST_CONFIG['cir_bytes_per_sec']}'")
            self.duthost.shell(f"redis-cli -n 4 HSET '{scheduler_key}' 'pir' '{TEST_CONFIG['pir_bytes_per_sec']}'")

            # Apply scheduler policy to queue
            queue_key = f"QUEUE|{self.test_interface}|{self.target_queue}"
            self.duthost.shell(f"redis-cli -n 4 HSET '{queue_key}' 'scheduler' '{policy_name}'")

            # Show the queue configuration after setting scheduler
            queue_config = self.duthost.shell(f"redis-cli -n 4 HGETALL '{queue_key}'")
            logger.info("Queue configuration after setting scheduler:")
            logger.info(f"  {queue_config['stdout']}")

            logger.info(f"Rate limiting configured on {self.test_interface} queue {self.target_queue}")

        except Exception as e:
            logger.error(f"Error configuring rate limiting: {e}")
            raise

    def _reset_interface_counters(self):
        """Clear interface counters using portstat command."""
        try:
            # Use portstat -c which is the underlying command for sonic-clear counters
            self.duthost.command("portstat -c", module_ignore_errors=True)
            time.sleep(5)

        except Exception as e:
            logger.error(f"Error clearing interface counters: {e}")
            raise

    def _retrieve_interface_counters(self):
        """Get interface counters for drop calculation using Ansible module."""
        try:
            # Use show_interface Ansible module to get counters
            result = self.duthost.show_interface(command='counter', interfaces=[self.test_interface])

            if 'ansible_facts' in result and 'int_counter' in result['ansible_facts']:
                interface_counters = result['ansible_facts']['int_counter'].get(self.test_interface, {})

                if interface_counters:
                    # Extract counter values for the interface
                    tx_drp = 0
                    rx_ok = 0

                    # Convert string values to integers, handling commas
                    if 'TX_DRP' in interface_counters:
                        tx_drp = int(str(interface_counters['TX_DRP']).replace(',', ''))
                    if 'RX_OK' in interface_counters:
                        rx_ok = int(str(interface_counters['RX_OK']).replace(',', ''))

                    return {
                        'TX_DRP': tx_drp,
                        'RX_OK': rx_ok,
                        'timestamp': time.time(),
                        'raw_data': interface_counters
                    }
                else:
                    logger.warning(f"Interface {self.test_interface} not found in counters output")
                    return {}
            else:
                logger.warning("Failed to get interface counters from Ansible module")
                return {}

        except Exception as e:
            logger.error(f"Error getting interface counters: {e}")
            return {}

    def _reload_qos_configuration(self):
        """Reload QoS configuration to restore original state."""
        logger.info("Reloading QoS configuration to restore original state...")

        try:
            cmd = "config qos reload"
            result = self.duthost.shell(cmd, module_ignore_errors=True)

            if result['rc'] == 0:
                logger.info("✓ QoS configuration reloaded successfully")
                logger.info("All QoS tables restored to original state")
            else:
                logger.warning(f"QoS reload had issues: {result.get('stderr', 'Unknown error')}")
                logger.info(f"QoS reload output: {result.get('stdout', 'No output')}")

        except Exception as e:
            logger.error(f"Error during QoS reload: {e}")
            raise


def test_rate_limiting_flow(duthosts, rand_one_dut_hostname, ptfadapter, tbinfo):
    """
    Rate limiting test with direct PTF traffic generation at specific speeds.

    Flow:
    1. Choose interface and get DSCP to queue mapping from DUT facts
    2. Find DSCP value that maps to target queue (fails if not found)
    3. Get interface IP configuration (fails if not found)
    4. Create packet that will go through chosen interface TX and target queue
    5. Send high speed traffic WITHOUT rate limiting - validate no drops
    6. Configure CIR and PIR rate limiting
    7. Send low speed traffic WITH rate limiting - validate no drops
    8. Send high speed traffic WITH rate limiting - validate drops occur
    9. Cleanup configuration

    This test uses speed-based traffic generation (bytes per second), automatically
    calculating the required packet rate based on packet size to achieve the desired
    bandwidth. DSCP value is dynamically determined from DUT's QoS configuration.

    Traffic rates (all in bytes per second):
    - CIR: 500,000 bytes/s (500 KBps, 4.0 Mbps) - rate limiting threshold
    - PIR: 750,000 bytes/s (750 KBps, 6.0 Mbps) - rate limiting threshold
    - Low traffic: 500,000 bytes/s (500 KBps, 4.0 Mbps, at CIR, should pass)
    - High traffic: 1,500,000 bytes/s (1.5 MBps, 12.0 Mbps, above PIR, should be dropped)

    Args:
        duthosts: DUT hosts fixture
        rand_one_dut_hostname: Random DUT hostname fixture
        ptfadapter: PTF adapter for direct traffic generation
        tbinfo: Testbed info for PTF port mapping
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Check if DUT is running supported Broadcom TH5 ASIC
    if duthost.facts["asic_type"].lower() != "broadcom":
        pytest.skip(f"Test only supports Broadcom ASICs. Current ASIC: {duthost.facts['asic_type']}")

    # Check if DUT is running TH5 platform
    asic_name = duthost.get_asic_name().lower()
    if "th5" not in asic_name:
        pytest.skip(f"Test only supports Broadcom TH5 platform. Current ASIC: {asic_name}")

    logger.info("=" * 80)
    logger.info("RATE LIMITING TEST - TRAFFIC GENERATION AND DROP VALIDATION")
    logger.info("=" * 80)
    logger.info(f"Test Configuration: {TEST_CONFIG}")
    logger.info("=" * 80)

    # Initialize the strict priority rate limiting test driver
    strict_priority_driver = StrictPriorityRateLimitingDriver(duthost, ptfadapter, tbinfo)

    try:
        # Execute the complete test flow
        test_success = strict_priority_driver.execute_strict_priority_rate_limiting_test()
        pytest_assert(test_success, "Strict priority rate limiting test should succeed")

        logger.info("✓ Strict priority rate limiting test completed successfully")

    finally:
        # Ensure cleanup even if test fails
        try:
            strict_priority_driver.cleanup_configuration()
        except Exception as cleanup_error:
            logger.warning(f"Cleanup error: {cleanup_error}")

    logger.info("=" * 80)
