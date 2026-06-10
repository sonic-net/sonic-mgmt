"""
Strict Priority Rate Limiting QoS Test - Using TAI Framework

This test validates CIR/PIR rate limiting configuration using STRICT priority scheduler
with direct PTF traffic generation at specific speeds.

This version uses the TAI (Test Abstraction Interface) framework to eliminate platform-specific
if/else clutter and make the test cleaner and more maintainable.

Flow:
1. Choose interface and get DSCP to queue mapping from DUT facts
2. Find DSCP value that maps to target queue
3. Get interface IP configuration
4. Create packet that will go through chosen interface TX and target queue
5. Send high speed traffic WITHOUT rate limiting - validate no drops
6. Configure CIR and PIR rate limiting with STRICT priority scheduler (using TAI)
7. Send low speed traffic WITH rate limiting - validate drops occur
8. Send high speed traffic WITH rate limiting - validate drops occur
9. Cleanup configuration
"""

import ipaddress
import json
import logging
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
import ptf.testutils as testutils
from tests.qos.qos_helpers import find_dscp_for_queue
from tests.common.helpers.ptf_tests_helper import (
    select_test_interface_and_ptf_port,
    get_interface_ip_address,
    detect_portchannel_egress_member
)
# Import TAI framework
from TAI import PlatformAdapter

DNX_CREDIT_TABLE = 'SCH_PORT_CREDIT_CONFIGURATION'
DNX_CREDIT_FIELD = 'CREDIT_WORTH'

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


class StrictPriorityRateLimitingDriverTAI:
    """
    Strict priority rate limiting test driver using TAI framework.

    This version uses TAI Facade pattern to eliminate platform-specific code:
    - platform.discover_queue_key() - Automatically handles queue key format
    - platform.apply_scheduler() - Automatically handles platform-specific scheduler config
    - platform.get_interface_drop_count() - Automatically selects correct drop counter

    All methods are called directly on the facade (platform) instead of getting adapters.
    """

    def __init__(self, duthost, ptf_adapter=None, testbed_info=None):
        """Initialize the strict priority rate limiting test driver with TAI."""
        self.duthost = duthost
        self.ptf_adapter = ptf_adapter
        self.testbed_info = testbed_info
        self.target_queue = TEST_CONFIG['queue']

        self._scheduler_key = None
        self._queue_key = None
        self._prev_scheduler = None
        self._prev_credit_worth = None

        # Initialize TAI Platform Adapter (Facade)
        self.platform = PlatformAdapter(duthost)

        # Check that all required TAI features are supported
        required_features = [
            'discover_queue_key',
            'create_scheduler',
            'apply_scheduler',
            'read_queue_scheduler',
            'revert_scheduler',
            'get_interface_drop_count',
        ]

        if not self.platform.require_features(required_features):
            missing = self.platform.get_missing_features(required_features)
            pytest.skip(f"Required TAI features not supported. Missing features: {missing}")

        # Step 1: Choose interface/PortChannel and get PTF port mapping
        self.test_interface, self.ptf_port_index = select_test_interface_and_ptf_port(duthost, testbed_info)
        if not self.test_interface or self.ptf_port_index is None:
            raise Exception("Could not find interface with PTF port mapping")

        # Step 2: Find correct DSCP for target queue
        self.dscp_value = find_dscp_for_queue(duthost, self.target_queue)

        # Step 3: Get interface IP and calculate source/destination IPs
        mg_facts = duthost.get_extended_minigraph_facts(testbed_info)
        self.interface_ip = get_interface_ip_address(self.test_interface, mg_facts)
        if not self.interface_ip:
            raise Exception(f"Could not find IP address for interface {self.test_interface}")

        interface_network = ipaddress.ip_interface(self.interface_ip)
        self.source_ip = str(interface_network.ip - 1)
        self.destination_ip = str(interface_network.ip + 1)

        self.test_packet_template = self._create_test_packet_template()

        # Step 4: If PortChannel, detect actual egress member
        portchannels = mg_facts.get('minigraph_portchannels', {})
        if self.test_interface in portchannels:
            logger.info(f"{self.test_interface} is a PortChannel, detecting egress member")

            # Detect actual egress member
            detected_interface, detected_ptf_port = detect_portchannel_egress_member(
                duthost, testbed_info, ptf_adapter, self.test_interface, self.test_packet_template
            )
            if detected_interface and detected_ptf_port is not None:
                logger.info(f"Detected egress member: {detected_interface} (PTF port {detected_ptf_port})")
                self.test_interface = detected_interface
                self.ptf_port_index = detected_ptf_port
            else:
                raise Exception(f"Could not detect egress member for PortChannel {self.test_interface}")

        logger.info(f"Initialized Strict Priority Rate Limiting Test Driver (TAI) for DUT: {duthost.hostname}")
        logger.info(f"Test interface: {self.test_interface}, Target queue: {self.target_queue}")
        logger.info(f"PTF port index: {self.ptf_port_index}")
        logger.info(f"DSCP: {self.dscp_value} (maps to Queue {self.target_queue})")
        logger.info(f"Packet IPs: {self.source_ip} -> {self.destination_ip}")
        logger.info(f"TAI Platform: {self.platform.get_platform_info()}")
        logger.info(f"Test config: {TEST_CONFIG}")

    def _create_test_packet_template(self):
        """
        Create packet template that will go through chosen interface TX and target queue.

        Returns:
            packet: PTF packet template
        """
        try:
            router_mac = self.duthost.facts["router_mac"]

            # Create packet with correct DSCP for target queue
            test_packet = testutils.simple_tcp_packet(
                pktlen=TEST_CONFIG['packet_size'],
                eth_dst=router_mac,  # Send to DUT's router MAC for L3 routing
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
                        f"({rate_mbps: .1f} Mbps, {packets_per_second} pps) for {test_duration_seconds}s")
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
                    logger.info(f"Progress: {i + 1}/{total_packets} packets ({current_rate_pps: .0f} pps)")

                # Early exit if we've exceeded the target duration significantly
                elapsed = time.time() - start_time
                if elapsed > test_duration_seconds * 1.5:  # 50% tolerance
                    logger.warning(f"Stopping early due to timing: sent {packets_sent}/{total_packets} "
                                   f"packets in {elapsed: .2f}s")
                    break

            end_time = time.time()
            actual_duration = end_time - start_time
            actual_rate_pps = packets_sent / actual_duration if actual_duration > 0 else 0
            actual_rate_bytes_per_sec = actual_rate_pps * packet_size_bytes
            actual_rate_mbps = (actual_rate_bytes_per_sec * 8) / 1000000
            logger.info(f"Traffic completed: {packets_sent} packets in {actual_duration: .2f}s")
            logger.info(f"Actual rate: {actual_rate_bytes_per_sec: .0f} bytes/s "
                        f"({actual_rate_mbps: .1f} Mbps, {actual_rate_pps: .1f} pps)")

            # Calculate accuracy and validate bandwidth achievement
            if traffic_rate_bytes_per_sec > 0:
                accuracy_percent = (actual_rate_bytes_per_sec / traffic_rate_bytes_per_sec) * 100
                logger.info(f"Rate accuracy: {accuracy_percent: .1f}% of target")

                # Check if we achieved acceptable bandwidth
                if accuracy_percent < TEST_CONFIG['bandwidth_tolerance_min']:
                    target_mbps = (traffic_rate_bytes_per_sec * 8) / 1000000
                    logger.error(f"Failed to achieve target bandwidth: {actual_rate_mbps: .1f} Mbps "
                                 f"vs target {target_mbps: .1f} Mbps ({accuracy_percent: .1f}%)")
                    pytest.skip(f"Cannot achieve desired bandwidth: got {accuracy_percent: .1f}% of target rate")

            time.sleep(2)

            return packets_sent

        except Exception as e:
            logger.error(f"Error sending PTF traffic: {e}")
            raise

    def _apply_strict_priority_rate_limiting_config(self):
        """
        Configure CIR and PIR rate limiting with STRICT priority scheduler using TAI.

        This method uses TAI framework to eliminate platform-specific code:
        - discover_queue_key: Automatically uses correct format for platform
        - apply_scheduler: Automatically handles platform-specific requirements (e.g., DNX credit)
        """
        logger.info(f"Configuring rate limiting on {self.test_interface} queue {self.target_queue} via TAI")

        # Log the rates for clarity
        cir_mbps = (TEST_CONFIG['cir_bytes_per_sec'] * 8) / 1000000
        pir_mbps = (TEST_CONFIG['pir_bytes_per_sec'] * 8) / 1000000
        logger.info(f"Setting rate limits: CIR={cir_mbps: .1f} Mbps ({TEST_CONFIG['cir_bytes_per_sec']} bytes/s), "
                    f"PIR={pir_mbps: .1f} Mbps ({TEST_CONFIG['pir_bytes_per_sec']} bytes/s)")

        try:
            # Resolve queue and scheduler keys
            queue_key = self.platform.discover_queue_key(self.test_interface, self.target_queue)
            logger.info(f"Discovered queue key: {queue_key}")

            policy_name = TEST_CONFIG['scheduler_policy']
            scheduler_key = f"SCHEDULER|{policy_name}"

            # Cache pre-test state so cleanup can revert without a config reload
            self._queue_key = queue_key
            self._scheduler_key = scheduler_key
            self._prev_scheduler = self.platform.read_queue_scheduler(queue_key)
            self._prev_credit_worth = self.platform.read_dbal_field(
                DNX_CREDIT_TABLE, DNX_CREDIT_FIELD
            )
            logger.info(f"Cached pre-test state: prev_scheduler={self._prev_scheduler}, "
                        f"prev_credit_worth={self._prev_credit_worth}")

            # Configure CREDIT_WORTH directly (no-op on non-Q3D)
            credit_worth = TEST_CONFIG.get('dnx_credit_worth', 4096)
            if not self.platform.apply_dbal_field(
                DNX_CREDIT_TABLE, DNX_CREDIT_FIELD, credit_worth
            ):
                raise Exception(
                    f"Failed to configure {DNX_CREDIT_TABLE}.{DNX_CREDIT_FIELD}={credit_worth}"
                )

            # Create the STRICT scheduler policy and bind it to the queue
            scheduler_config = {
                'type': 'STRICT',
                'cir': str(TEST_CONFIG['cir_bytes_per_sec']),
                'pir': str(TEST_CONFIG['pir_bytes_per_sec']),
            }
            if not self.platform.create_scheduler(scheduler_key, scheduler_config):
                raise Exception("Failed to create scheduler policy")
            logger.info(f"Scheduler policy created: {scheduler_key}")

            if not self.platform.apply_scheduler(scheduler_key, queue_key):
                raise Exception("Failed to apply scheduler to queue")
            logger.info(f"Rate limiting configured on {self.test_interface} queue {self.target_queue}")

        except Exception as e:
            logger.error(f"Error configuring rate limiting: {e}")
            raise

    def _reset_interface_counters(self):
        """Clear interface counters using portstat command."""
        try:
            self.duthost.command("portstat -c", module_ignore_errors=True)
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error clearing interface counters: {e}")
            raise

    def _revert_configuration(self):
        """
        Restore pre-test state via TAI without a full config reload.

        Revert CREDIT_WORTH first. If that fails we exit early and leave the
        SCHEDULER state untouched, which guarantees the framework CONFIG_DB
        diff check will fire a config reload and reset SDK state.
        """
        if self._scheduler_key is None or self._queue_key is None:
            logger.info("No scheduler was applied. Nothing to revert.")
            return

        # Revert CREDIT_WORTH first. On failure leave SCHEDULER state intact so
        # the framework CONFIG_DB diff check triggers a config reload.
        if self._prev_credit_worth is not None:
            logger.info(f"Reverting CREDIT_WORTH to {self._prev_credit_worth}")
            if not self.platform.apply_dbal_field(
                DNX_CREDIT_TABLE, DNX_CREDIT_FIELD, self._prev_credit_worth
            ):
                logger.error("CREDIT_WORTH revert failed. Relying on framework reload.")
                return

        # Restore previous queue scheduler and delete the test policy
        if not self.platform.revert_scheduler(
            self._scheduler_key, self._queue_key, self._prev_scheduler
        ):
            logger.error("Scheduler revert failed. Framework cleanup will compensate.")

        # Clear cached state so a second invocation is a no-op
        self._scheduler_key = None
        self._queue_key = None
        self._prev_scheduler = None
        self._prev_credit_worth = None

    def execute_strict_priority_rate_limiting_test(self):
        """
        Execute the complete strict priority rate limiting test flow using TAI framework.

        This version uses TAI to eliminate platform-specific code for:
        - Queue key discovery
        - Scheduler configuration
        - Drop counter selection (via get_interface_drop_count)
        """
        logger.info("Starting strict priority rate limiting test flow (TAI version)...")

        try:
            # Clear interface counters
            self._reset_interface_counters()

            # Generate high traffic WITHOUT rate limiting - should have no drops
            logger.info("Testing baseline traffic without rate limiting...")
            initial_drops = self.platform.get_interface_drop_count(self.test_interface)

            # Send high rate traffic for test duration
            packets_sent = self._generate_test_traffic(
                traffic_rate_bytes_per_sec=TEST_CONFIG['high_traffic_bytes_per_sec'],
                test_duration_seconds=TEST_CONFIG['traffic_duration']
            )

            final_drops = self.platform.get_interface_drop_count(self.test_interface)
            actual_drops = final_drops - initial_drops

            logger.info(f"Baseline drops: {actual_drops} (threshold: {TEST_CONFIG['drop_threshold_low']})")
            logger.info(f"Packets sent: {packets_sent}")

            pytest_assert(actual_drops < TEST_CONFIG['drop_threshold_low'],
                          f"Baseline traffic had unexpected drops: {actual_drops}")

            # Configure CIR/PIR rate limiting using TAI
            logger.info("Configuring strict priority rate limiting (using TAI)...")
            self._apply_strict_priority_rate_limiting_config()

            # Clear counters and test low traffic
            self._reset_interface_counters()
            logger.info("Testing low traffic with rate limiting...")
            initial_drops = self.platform.get_interface_drop_count(self.test_interface)

            # Send low rate traffic for test duration
            packets_sent = self._generate_test_traffic(
                traffic_rate_bytes_per_sec=TEST_CONFIG['low_traffic_bytes_per_sec'],
                test_duration_seconds=TEST_CONFIG['traffic_duration']
            )

            final_drops = self.platform.get_interface_drop_count(self.test_interface)
            actual_drops = final_drops - initial_drops

            logger.info(f"Low traffic drops: {actual_drops} (threshold: {TEST_CONFIG['drop_threshold_low']})")
            logger.info(f"Packets sent: {packets_sent}")

            pytest_assert(actual_drops < TEST_CONFIG['drop_threshold_low'],
                          f"Low traffic had unexpected drops: {actual_drops}")

            # Clear counters and test high traffic
            self._reset_interface_counters()
            logger.info("Testing high traffic with rate limiting...")
            initial_drops = self.platform.get_interface_drop_count(self.test_interface)

            # Send high rate traffic for test duration
            packets_sent = self._generate_test_traffic(
                traffic_rate_bytes_per_sec=TEST_CONFIG['high_traffic_bytes_per_sec'],
                test_duration_seconds=TEST_CONFIG['traffic_duration']
            )

            final_drops = self.platform.get_interface_drop_count(self.test_interface)
            actual_drops = final_drops - initial_drops

            logger.info(f"High traffic drops: {actual_drops} (threshold: {TEST_CONFIG['drop_threshold_high']})")
            logger.info(f"Packets sent: {packets_sent}")

            pytest_assert(actual_drops > TEST_CONFIG['drop_threshold_high'],
                          f"High traffic had insufficient drops: {actual_drops}")

            logger.info("✓ Strict priority rate limiting test flow (TAI) completed successfully")
            return True

        except Exception as e:
            logger.error(f"Strict priority rate limiting test flow failed: {e}")
            return False

    def cleanup_configuration(self):
        """Clean up strict priority rate limiting test configuration."""
        logger.info("Cleaning up configuration...")
        self._revert_configuration()


def test_rate_limiting_flow_tai(duthosts, rand_one_dut_hostname, ptfadapter, tbinfo):
    """
    Rate limiting test using TAI framework - eliminates platform-specific if/else clutter.

    This test uses the TAI (Test Abstraction Interface) framework to automatically handle
    platform-specific differences:

    TAI Features Used:
    - discover_queue_key: Automatically uses correct queue key format (Tomahawk vs Qumran)
    - apply_scheduler: Automatically handles platform-specific scheduler config (DNX credit for Qumran)
    - get_interface_drop_count: Automatically selects correct drop counter (TX_DRP vs RX_DRP)
    - require_features: Automatically skips test if platform doesn't support required features

    Flow:
    1. Initialize TAI Platform Adapter and check feature support
    2. Choose interface and get DSCP to queue mapping from DUT facts
    3. Find DSCP value that maps to target queue (fails if not found)
    4. Get interface IP configuration (fails if not found)
    5. Create packet that will go through chosen interface TX and target queue
    6. Send high speed traffic WITHOUT rate limiting - validate no drops
    7. Configure CIR and PIR rate limiting using TAI (platform-specific handling automatic)
    8. Send low speed traffic WITH rate limiting - validate no drops
    9. Send high speed traffic WITH rate limiting - validate drops occur
    10. Cleanup configuration

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

    # Skip test for multi-ASIC platforms
    if duthost.is_multi_asic:
        pytest.skip("Test does not support multi-ASIC platforms")

    logger.info("=" * 80)
    logger.info("RATE LIMITING TEST (TAI VERSION) - PLATFORM-AGNOSTIC")
    logger.info("=" * 80)
    logger.info(f"Test Configuration: {TEST_CONFIG}")
    logger.info("=" * 80)

    # Initialize the strict priority rate limiting test driver with TAI
    # TAI will automatically check feature support and skip if not available
    strict_priority_driver = StrictPriorityRateLimitingDriverTAI(duthost, ptfadapter, tbinfo)

    try:
        # Execute the complete test flow
        test_success = strict_priority_driver.execute_strict_priority_rate_limiting_test()
        pytest_assert(test_success, "Strict priority rate limiting test should succeed")

        logger.info("✓ Strict priority rate limiting test (TAI) completed successfully")

    finally:
        # Ensure cleanup even if test fails
        try:
            strict_priority_driver.cleanup_configuration()
        except Exception as cleanup_error:
            logger.warning(f"Cleanup error: {cleanup_error}")

    logger.info("=" * 80)
