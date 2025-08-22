import pytest
import logging
import time

from tests.common.helpers.assertions import pytest_assert
from tests.high_frequency_telemetry.utilities import (
    setup_hft_profile,
    setup_hft_group,
    cleanup_hft_config,
    run_countersyncd_and_capture_output,
    run_continuous_countersyncd_with_state_changes,
    run_continuous_countersyncd_with_config_changes,
    run_continuous_countersyncd_with_port_state_changes,
    validate_stream_state_transitions,
    validate_config_state_transitions,
    validate_port_state_transitions,
    validate_counter_output,
    get_available_ports
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def test_hft_port_counters(duthosts, enum_rand_one_per_hwsku_hostname,
                           disable_flex_counters, tbinfo):
    """Test high frequency telemetry for port counters.

    This test:
    1. Sets up a high frequency telemetry profile for ports
    2. Configures specific ports and counters to monitor
    3. Runs countersyncd to capture telemetry data
    4. Verifies that counter values are greater than 0
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "port_profile"
    group_name = "PORT"

    # Get available ports from topology (try for 2 ports, min 1 required)
    test_ports = get_available_ports(duthost, tbinfo, desired_ports=2,
                                     min_ports=1)

    logger.info(f"Using ports for testing: {test_ports}")

    try:
        # Step 1: Set up high frequency telemetry profile
        setup_hft_profile(
            duthost=duthost,
            profile_name=profile_name,
            poll_interval=10000,
            stream_state="enabled"  # Changed from "disabled" to "enabled"
        )

        # Step 2: Configure port group with specific ports and counters
        setup_hft_group(
            duthost=duthost,
            profile_name=profile_name,
            group_name=group_name,
            object_names=test_ports,
            object_counters=["IF_IN_OCTETS"]
        )

        logger.info("High frequency telemetry configuration completed")

        # Step 3: Run countersyncd and capture output
        result = run_countersyncd_and_capture_output(duthost, timeout=120)

        # Step 4: Parse and verify counter values
        validation_results = validate_counter_output(
            output=result['stdout'],
            expected_objects=test_ports,
            min_counter_value=0,
            expected_poll_interval=10000  # 10ms poll interval
        )

        logger.info(f"Test completed successfully. "
                    f"Total counters verified: "
                    f"{validation_results['total_counters']} "
                    f"(from {validation_results['stable_reports_count']} "
                    f"stable reports)")

        # Log Msg/s validation results if available
        if validation_results['msg_per_sec_validation'] is not None:
            if validation_results['msg_per_sec_validation']:
                logger.info("Msg/s validation: PASSED - "
                            "polling frequency matches expected interval")
            else:
                logger.warning("Msg/s validation: "
                               "No Msg/s data found in stable output")

    finally:
        # Clean up: Remove high frequency telemetry configuration
        cleanup_hft_config(duthost, profile_name, [group_name])


@pytest.mark.xfail(reason="Queue-based high frequency telemetry "
                           "not yet supported")
def test_hft_queue_counters(duthosts, enum_rand_one_per_hwsku_hostname,
                            disable_flex_counters, tbinfo):
    """
    Test high frequency telemetry for queue counters.

    This test demonstrates a different configuration with queue objects.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "queue_profile"
    group_name = "QUEUE"

    # Get available ports from topology (try for 2 ports, min 1 required)
    test_ports = get_available_ports(duthost, tbinfo, desired_ports=2,
                                     min_ports=1)
    # Format queue objects with index
    queue_objects = [f"{port}|0" for port in test_ports]

    logger.info(f"Using queue objects for testing: {queue_objects}")

    try:
        # Set up profile with different poll interval
        setup_hft_profile(
            duthost=duthost,
            profile_name=profile_name,
            poll_interval=10000,  # Different poll interval
            stream_state="enabled"  # Changed from "disabled" to "enabled"
        )

        # Configure queue group - using object_name with index format
        setup_hft_group(
            duthost=duthost,
            profile_name=profile_name,
            group_name=group_name,
            object_names=queue_objects,  # Queue objects with index
            object_counters=["QUEUE_STAT_PACKETS"]
        )

        logger.info("Queue high frequency telemetry configuration completed")

        # Run countersyncd and validate
        result = run_countersyncd_and_capture_output(duthost, timeout=120)
        validation_results = validate_counter_output(
            output=result['stdout'],
            min_counter_value=0,
            expected_poll_interval=10000  # 10ms poll interval
        )

        logger.info(
            f"Queue test completed. Total counters verified: "
            f"{validation_results['total_counters']}"
        )

    finally:
        cleanup_hft_config(duthost, profile_name)


def test_hft_full_port_counters(duthosts, enum_rand_one_per_hwsku_hostname,
                                 disable_flex_counters, tbinfo):
    """
    Test high frequency telemetry with all available ports and all
    available counter types.

    This test monitors all available counter types for all available ports:
    - Uses all available ports in the topology
    - Tests all supported port counters: IF_IN_OCTETS, IF_IN_UCAST_PKTS,
      IF_IN_DISCARDS,
      IF_IN_ERRORS, IN_CURR_OCCUPANCY_BYTES, IF_OUT_OCTETS, IF_OUT_DISCARDS,
      IF_OUT_ERRORS, IF_OUT_UCAST_PKTS, OUT_CURR_OCCUPANCY_BYTES
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "full_port_counter_profile"
    group_name = "PORT"

    # Get all available ports from topology (minimum 1 required)
    all_available_ports = get_available_ports(
        duthost, tbinfo, desired_ports=None, min_ports=1
    )

    # All available port counters
    all_port_counters = [
        "IF_IN_OCTETS",
        "IF_IN_UCAST_PKTS",
        "IF_IN_DISCARDS",
        "IF_IN_ERRORS",
        "IN_CURR_OCCUPANCY_BYTES",
        "IF_OUT_OCTETS",
        "IF_OUT_DISCARDS",
        "IF_OUT_ERRORS",
        "IF_OUT_UCAST_PKTS",
        "OUT_CURR_OCCUPANCY_BYTES",
        "TRIM_PACKETS"
    ]

    logger.info(
            f"Testing all {len(all_available_ports)} available ports: "
            f"{all_available_ports}"
        )
    logger.info(
            f"Testing all {len(all_port_counters)} available counters: "
            f"{all_port_counters}"
        )

    try:
        # Set up profile
        setup_hft_profile(
            duthost=duthost,
            profile_name=profile_name,
            poll_interval=10000,
            stream_state="enabled"
        )

        # Configure with all available ports and all counter types
        setup_hft_group(
            duthost=duthost,
            profile_name=profile_name,
            group_name=group_name,
            object_names=all_available_ports,  # All available ports
            object_counters=all_port_counters  # All counters
            # separated by ,
        )

        logger.info(
            "Full port counter high frequency telemetry "
            "configuration completed"
        )

        # Run countersyncd and validate
        result = run_countersyncd_and_capture_output(duthost, timeout=120)
        validation_results = validate_counter_output(
            output=result['stdout'],
            expected_objects=all_available_ports,
            min_counter_value=0,
            expected_poll_interval=10000  # 10ms poll interval
        )

        # Verify we get counters (may not be exactly
        # num_ports * num_counters if some counter types are not supported)
        min_expected_counters = len(all_available_ports)  # At least one
        # counter per port
        pytest_assert(
            validation_results['total_counters'] >= min_expected_counters,
            f"Expected at least {min_expected_counters} counters, "
            f"got {actual_counters}"
        )

        # Log actual vs expected for debugging
        max_expected_counters = (
            len(all_available_ports) * len(all_port_counters)
        )
        actual_counters = validation_results['total_counters']

        logger.info(
            f"Counter coverage: {actual_counters} counters verified "
            f"({actual_counters/max_expected_counters*100:.1f}%)"
        )

        if actual_counters < max_expected_counters:
            logger.warning(
                f"Got {actual_counters} counters, "
                f"expected {max_expected_counters}. "
                f"Some counter types may not be supported on this platform."
            )
        else:
            logger.info("✓ All counter types are supported on this platform!")

        logger.info(f"Full port counter test completed successfully. "
                   f"Total counters verified: {validation_results['total_counters']} "
                   f"across {len(all_available_ports)} ports")

    finally:
        cleanup_hft_config(duthost, profile_name)


def test_hft_disabled_stream(duthosts, enum_rand_one_per_hwsku_hostname,
                             disable_flex_counters, tbinfo):
    """
    Test high frequency telemetry with disabled stream state transitions.

    This test runs a continuous countersyncd process while dynamically changing
    stream states: enabled -> disabled -> enabled, and validates that Msg/s
    changes accordingly in each phase:
    1. Phase 1 (enabled): Msg/s > 0
    2. Phase 2 (disabled): Msg/s = 0
    3. Phase 3 (enabled): Msg/s > 0 again
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "state_transition_profile"
    group_name = "PORT"

    # Get available ports from topology (try for 2 ports, warn if only 1)
    available_ports = get_available_ports(duthost, tbinfo, desired_ports=2, min_ports=1)
    test_ports = available_ports

    logger.info(f"Using ports for testing: {test_ports}")

    try:
        # Initial setup: Configure the telemetry group (starts disabled, will be enabled in first phase)
        logger.info("Setting up high frequency telemetry group configuration")
        setup_hft_group(
            duthost=duthost,
            profile_name=profile_name,
            group_name=group_name,
            object_names=test_ports,
            object_counters=["IF_IN_OCTETS"]
        )

        # Define state sequence: enabled -> disabled -> enabled
        state_sequence = [
            ("enabled", 60),   # Phase 1: 60 seconds enabled
            ("disabled", 60),  # Phase 2: 60 seconds disabled
            ("enabled", 60)    # Phase 3: 60 seconds enabled again
        ]

        logger.info("Starting continuous countersyncd monitoring with state transitions...")

        # Run continuous monitoring with state changes
        phase_results = run_continuous_countersyncd_with_state_changes(
            duthost=duthost,
            profile_name=profile_name,
            state_sequence=state_sequence
        )

        # Analyze results for each phase using the new validation function
        validation_results = validate_stream_state_transitions(
            phase_results=phase_results,
            state_sequence=state_sequence,
            validation_objects=test_ports
        )

        # Verify the expected state transition pattern
        phase_names = [f"phase_{i+1}_{state}" for i, (state, _) in enumerate(state_sequence)]

        if len(phase_names) >= 3:
            phase1_key, phase2_key, phase3_key = phase_names[:3]

            # Phase 1 (enabled): Should have active messages
            if phase1_key in validation_results:
                phase1_has_msgs = validation_results[phase1_key]['has_active_msgs']
                pytest_assert(
                    phase1_has_msgs,
                    f"Phase 1 (enabled): Expected Msg/s > 0, got {validation_results[phase1_key]['actual_msg_per_sec']}"
                )
                logger.info("✓ Phase 1 validation passed: Stream enabled, Msg/s > 0")

            # Phase 2 (disabled): Should have no active messages
            if phase2_key in validation_results:
                phase2_no_msgs = not validation_results[phase2_key]['has_active_msgs']
                pytest_assert(
                    phase2_no_msgs,
                    f"Phase 2 (disabled): Expected Msg/s = 0, got {validation_results[phase2_key]['actual_msg_per_sec']}"
                )
                logger.info("✓ Phase 2 validation passed: Stream disabled, Msg/s = 0")

            # Phase 3 (re-enabled): Should have active messages again
            if phase3_key in validation_results:
                phase3_has_msgs = validation_results[phase3_key]['has_active_msgs']
                pytest_assert(
                    phase3_has_msgs,
                    f"Phase 3 (re-enabled): Expected Msg/s > 0, got {validation_results[phase3_key]['actual_msg_per_sec']}"
                )
                logger.info("✓ Phase 3 validation passed: Stream re-enabled, Msg/s > 0")

        logger.info("🎉 Stream state transition test completed successfully!")
        logger.info("Summary of phases:")
        for phase_name, result in validation_results.items():
            logger.info(f"  {phase_name}: {result['state']} -> "
                       f"Msg/s: {result['actual_msg_per_sec']} -> "
                       f"Active: {result['has_active_msgs']}")

    finally:
        # Clean up: Remove high frequency telemetry configuration
        cleanup_hft_config(duthost, profile_name, [group_name])


def test_hft_config_deletion_stream(duthosts, enum_rand_one_per_hwsku_hostname,
                                    disable_flex_counters, tbinfo):
    """
    Test high frequency telemetry with configuration deletion transitions.

    This test runs a continuous countersyncd process while dynamically changing
    configuration: create -> delete -> create, and validates that Msg/s
    changes accordingly in each phase:
    1. Phase 1 (create): Create profile and group, expect Msg/s > 0
    2. Phase 2 (delete): Delete configuration, expect Msg/s = 0
    3. Phase 3 (create): Re-create configuration, expect Msg/s > 0 again
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "config_deletion_profile"
    group_name = "PORT"

    # Get available ports from topology (try for 2 ports, warn if only 1)
    available_ports = get_available_ports(duthost, tbinfo, desired_ports=2, min_ports=1)
    test_ports = available_ports
    object_counters = ["IF_IN_OCTETS"]

    logger.info(f"Using ports for testing: {test_ports}")

    try:
        # Define configuration sequence: create -> delete -> create
        config_sequence = [
            ("create", 60),   # Phase 1: 60 seconds with configuration
            ("delete", 60),   # Phase 2: 60 seconds without configuration
            ("create", 60)    # Phase 3: 60 seconds with configuration again
        ]

        logger.info("Starting continuous countersyncd monitoring with configuration transitions...")

        # Run continuous monitoring with configuration changes
        phase_results = run_continuous_countersyncd_with_config_changes(
            duthost=duthost,
            profile_name=profile_name,
            group_name=group_name,
            object_names=test_ports,
            object_counters=object_counters,
            config_sequence=config_sequence
        )

        # Analyze results for each phase using the new validation function
        validation_results = validate_config_state_transitions(
            phase_results=phase_results,
            config_sequence=config_sequence,
            validation_objects=test_ports
        )

        # Verify the expected configuration transition pattern
        phase_names = [f"phase_{i+1}_{action}" for i, (action, _) in enumerate(config_sequence)]

        if len(phase_names) >= 3:
            phase1_key, phase2_key, phase3_key = phase_names[:3]

            # Phase 1 (create): Should have active messages
            if phase1_key in validation_results:
                phase1_has_msgs = validation_results[phase1_key]['has_active_msgs']
                pytest_assert(
                    phase1_has_msgs,
                    f"Phase 1 (create): Expected Msg/s > 0, got {validation_results[phase1_key]['actual_msg_per_sec']}"
                )
                logger.info("✓ Phase 1 validation passed: Configuration created, Msg/s > 0")

            # Phase 2 (delete): Should have no active messages
            if phase2_key in validation_results:
                phase2_no_msgs = not validation_results[phase2_key]['has_active_msgs']
                pytest_assert(
                    phase2_no_msgs,
                    f"Phase 2 (delete): Expected Msg/s = 0, got {validation_results[phase2_key]['actual_msg_per_sec']}"
                )
                logger.info("✓ Phase 2 validation passed: Configuration deleted, Msg/s = 0")

            # Phase 3 (re-create): Should have active messages again
            if phase3_key in validation_results:
                phase3_has_msgs = validation_results[phase3_key]['has_active_msgs']
                pytest_assert(
                    phase3_has_msgs,
                    f"Phase 3 (re-create): Expected Msg/s > 0, got {validation_results[phase3_key]['actual_msg_per_sec']}"
                )
                logger.info("✓ Phase 3 validation passed: Configuration re-created, Msg/s > 0")

        logger.info("🎉 Configuration deletion transition test completed successfully!")
        logger.info("Summary of phases:")
        for phase_name, result in validation_results.items():
            logger.info(f"  {phase_name}: {result['action']} -> "
                       f"Msg/s: {result['actual_msg_per_sec']} -> "
                       f"Active: {result['has_active_msgs']}")

    finally:
        # Clean up: Remove any remaining high frequency telemetry configuration
        cleanup_hft_config(duthost, profile_name, [group_name])


@pytest.mark.parametrize("poll_interval_us,expected_msg_per_sec", [
    (1000, 1000),      # 1ms -> 1000 Msg/s
    (10000, 100),      # 10ms -> 100 Msg/s
    (100000, 10),      # 100ms -> 10 Msg/s
    (1000000, 1),      # 1000ms -> 1 Msg/s
    (10000000, 0.1),   # 10000ms -> 0.1 Msg/s
])
def test_hft_poll_interval_validation(duthosts, enum_rand_one_per_hwsku_hostname,
                                      disable_flex_counters, tbinfo,
                                      poll_interval_us, expected_msg_per_sec):
    """Test high frequency telemetry with different poll intervals.

    Validates Msg/s output.

    This test uses pytest parametrize to test multiple poll intervals:
    - 1ms (1000 μs) -> expects ~1000 Msg/s
    - 10ms (10000 μs) -> expects ~100 Msg/s
    - 100ms (100000 μs) -> expects ~10 Msg/s
    - 1000ms (1000000 μs) -> expects ~1 Msg/s
    - 10000ms (10000000 μs) -> expects ~0.1 Msg/s

    The test validates that the actual Msg/s values are within an acceptable range
    of the expected frequency based on the configured poll interval.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = f"poll_interval_profile_{poll_interval_us}"
    group_name = "PORT"

    # Get available ports from topology (try to get 2 ports, minimum 1 required)
    test_ports = get_available_ports(duthost, tbinfo, desired_ports=2, min_ports=1)

    logger.info(f"Testing poll interval: {poll_interval_us} μs (expected Msg/s: {expected_msg_per_sec})")
    logger.info(f"Using ports for testing: {test_ports}")

    try:
        # Step 1: Set up high frequency telemetry profile with specific poll interval
        setup_hft_profile(
            duthost=duthost,
            profile_name=profile_name,
            poll_interval=poll_interval_us,
            stream_state="enabled"
        )

        # Step 2: Configure port group with specific ports and counters
        setup_hft_group(
            duthost=duthost,
            profile_name=profile_name,
            group_name=group_name,
            object_names=test_ports,
            object_counters=["IF_IN_OCTETS"]
        )

        logger.info(f"HFT group configuration completed for {poll_interval_us} μs poll interval")

        # Verify the configuration is actually applied by checking Redis
        logger.info("Verifying HFT configuration in Redis...")
        verify_cmd = "redis-cli -n 4 HGETALL 'HFT_PROFILE|" + profile_name + "'"
        config_result = duthost.shell(verify_cmd, module_ignore_errors=True)
        if config_result['rc'] == 0 and config_result['stdout']:
            logger.info(f"HFT profile configuration: {config_result['stdout']}")
        else:
            logger.warning(f"Could not verify HFT profile configuration: {config_result}")

        verify_group_cmd = "redis-cli -n 4 HGETALL 'HFT_GROUP|" + profile_name + "|" + group_name + "'"
        group_result = duthost.shell(verify_group_cmd, module_ignore_errors=True)
        if group_result['rc'] == 0 and group_result['stdout']:
            logger.info(f"HFT group configuration: {group_result['stdout']}")
        else:
            logger.warning(f"Could not verify HFT group configuration: {group_result}")

        # Give some time for the configuration to be applied
        logger.info("Waiting 10 seconds for HFT configuration to take effect...")
        time.sleep(10)

        # Step 3: Run countersyncd and capture output for sufficient time to get stable measurements
        # Use longer timeout for slower poll intervals to ensure we get enough samples
        timeout = max(120, int(10 / expected_msg_per_sec) + 60) if expected_msg_per_sec > 0 else 180
        logger.info(f"Running countersyncd for {timeout} seconds to capture stable measurements")

        result = run_countersyncd_and_capture_output(duthost, timeout=timeout)

        # Step 4: Parse and verify counter values and Msg/s
        validation_results = validate_counter_output(
            output=result['stdout'],
            expected_objects=test_ports,
            min_counter_value=0,
            expected_poll_interval=poll_interval_us
        )

        # Step 5: Validate Msg/s matches expected frequency based on poll interval
        if validation_results['msg_per_sec_validation'] is True:
            actual_msg_per_sec = validation_results.get('actual_msg_per_sec', [])

            if actual_msg_per_sec:
                # Calculate average Msg/s from stable measurements
                avg_msg_per_sec = sum(actual_msg_per_sec) / len(actual_msg_per_sec)

                # Define acceptable tolerance based on expected frequency
                # For high frequencies (>= 10 Msg/s): ±20% tolerance
                # For medium frequencies (1-10 Msg/s): ±30% tolerance
                # For low frequencies (< 1 Msg/s): ±50% tolerance
                if expected_msg_per_sec >= 10:
                    tolerance = 0.20  # ±20%
                elif expected_msg_per_sec >= 1:
                    tolerance = 0.30  # ±30%
                else:
                    tolerance = 0.50  # ±50%

                min_expected = expected_msg_per_sec * (1 - tolerance)
                max_expected = expected_msg_per_sec * (1 + tolerance)

                logger.info(f"Poll interval validation:")
                logger.info(f"  Poll interval: {poll_interval_us} μs")
                logger.info(f"  Expected Msg/s: {expected_msg_per_sec}")
                logger.info(f"  Actual Msg/s: {avg_msg_per_sec:.2f} (range: {min(actual_msg_per_sec):.2f}-{max(actual_msg_per_sec):.2f})")
                logger.info(f"  Acceptable range: {min_expected:.2f} - {max_expected:.2f} (±{tolerance*100:.0f}%)")

                # Validate that average Msg/s is within acceptable range
                pytest_assert(
                    min_expected <= avg_msg_per_sec <= max_expected,
                    f"Poll interval {poll_interval_us} μs: Expected Msg/s {min_expected:.2f}-{max_expected:.2f}, "
                    f"got {avg_msg_per_sec:.2f}. Individual measurements: {actual_msg_per_sec}"
                )

                logger.info(f"✓ Poll interval validation PASSED: {poll_interval_us} μs -> {avg_msg_per_sec:.2f} Msg/s")

            else:
                pytest.fail(f"Msg/s validation returned True but no actual measurements found for poll interval {poll_interval_us} μs")
        elif validation_results['msg_per_sec_validation'] is False:
            pytest.fail(f"No Msg/s measurements found for poll interval {poll_interval_us} μs")
        else:
            pytest.fail(f"Msg/s validation failed - unexpected validation state for poll interval {poll_interval_us} μs")

        logger.info(f"Poll interval test completed successfully. "
                   f"Poll interval: {poll_interval_us} μs, "
                   f"Total counters verified: {validation_results['total_counters']} "
                   f"(from {validation_results['stable_reports_count']} stable reports)")

    finally:
        # Clean up: Remove high frequency telemetry configuration
        cleanup_hft_config(duthost, profile_name, [group_name])


def test_hft_port_shutdown_stream(duthosts, enum_rand_one_per_hwsku_hostname,
                                  disable_flex_counters, tbinfo, ptfadapter):
    """
    Test high frequency telemetry with port shutdown/startup transitions during continuous traffic.

    This test runs a continuous countersyncd process while dynamically shutting down and
    starting up monitored ports with continuous PTF traffic injection, and validates that
    counter behavior changes accordingly in each phase:
    1. Phase 1 (port up): Port is up, continuous traffic sent, expect counters increasing
    2. Phase 2 (port down): Port shutdown, traffic still sent, expect counters stable (no increase)
    3. Phase 3 (port up): Port startup, traffic continues, expect counters increasing again
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "port_shutdown_profile"
    group_name = "PORT"

    # Get available ports from topology (need at least 1 port for monitoring)
    available_ports = get_available_ports(duthost, tbinfo, desired_ports=1, min_ports=1)
    test_port = available_ports[0]  # Use first available port
    object_counters = ["IF_IN_OCTETS"]

    logger.info(f"Using port for testing: {test_port}")

    # Get PTF port mapping for traffic injection
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_port_index = mg_facts['minigraph_ptf_indices'][test_port]

    logger.info(f"Test port {test_port} maps to PTF port index {ptf_port_index}")

    # Get router MAC for creating proper packets
    router_mac = duthost.facts['router_mac']

    try:
        # Setup high frequency telemetry configuration first
        logger.info("Setting up high frequency telemetry configuration")
        setup_hft_profile(
            duthost=duthost,
            profile_name=profile_name,
            poll_interval=10000,  # 10ms poll interval
            stream_state="enabled"
        )

        setup_hft_group(
            duthost=duthost,
            profile_name=profile_name,
            group_name=group_name,
            object_names=[test_port],
            object_counters=object_counters
        )

        # Define port state sequence: up -> down -> up
        port_state_sequence = [
            ("up", 60),     # Phase 1: 60 seconds with port up
            ("down", 60),   # Phase 2: 60 seconds with port down
            ("up", 60)      # Phase 3: 60 seconds with port up again
        ]

        logger.info("Starting continuous countersyncd monitoring with port state transitions and PTF traffic...")

        # Run continuous monitoring with port state changes and traffic injection
        phase_results = run_continuous_countersyncd_with_port_state_changes(
            duthost=duthost,
            profile_name=profile_name,
            ptfadapter=ptfadapter,
            test_port=test_port,
            ptf_port_index=ptf_port_index,
            router_mac=router_mac,
            port_state_sequence=port_state_sequence
        )

        # Analyze results for each phase
        validation_results = validate_port_state_transitions(
            phase_results=phase_results,
            port_state_sequence=port_state_sequence,
            validation_objects=[test_port]
        )

        # Verify the expected port state transition pattern
        phase_names = [f"phase_{i+1}_{state}" for i, (state, _) in enumerate(port_state_sequence)]

        if len(phase_names) >= 3:
            phase1_key, phase2_key, phase3_key = phase_names[:3]

            # Phase 1 (port up): Should have increasing counters
            if phase1_key in validation_results:
                phase1_increasing = validation_results[phase1_key]['counters_increasing']
                pytest_assert(
                    phase1_increasing,
                    f"Phase 1 (port up): Expected counters to increase with traffic, "
                    f"got counter trend: {validation_results[phase1_key]['counter_trend']}"
                )
                logger.info("✓ Phase 1 validation passed: Port up, counters increasing with traffic")

            # Phase 2 (port down): Should have stable counters (not increasing)
            if phase2_key in validation_results:
                phase2_stable = not validation_results[phase2_key]['counters_increasing']
                pytest_assert(
                    phase2_stable,
                    f"Phase 2 (port down): Expected counters to be stable (no increase), "
                    f"got counter trend: {validation_results[phase2_key]['counter_trend']}"
                )
                logger.info("✓ Phase 2 validation passed: Port down, counters stable despite traffic")

            # Phase 3 (port up again): Should have increasing counters again
            if phase3_key in validation_results:
                phase3_increasing = validation_results[phase3_key]['counters_increasing']
                pytest_assert(
                    phase3_increasing,
                    f"Phase 3 (port up again): Expected counters to increase with traffic, "
                    f"got counter trend: {validation_results[phase3_key]['counter_trend']}"
                )
                logger.info("✓ Phase 3 validation passed: Port up again, counters increasing with traffic")

        logger.info("🎉 Port shutdown/startup transition test completed successfully!")
        logger.info("Summary of phases:")
        for phase_name, result in validation_results.items():
            logger.info(f"  {phase_name}: port {result['port_state']} -> "
                       f"Counter trend: {result['counter_trend']} -> "
                       f"Increasing: {result['counters_increasing']}")

    finally:
        # Ensure port is up before cleanup
        logger.info(f"Ensuring {test_port} is up before cleanup")
        duthost.shell(f"config interface startup {test_port}", module_ignore_errors=True)

        # Clean up: Remove high frequency telemetry configuration
        cleanup_hft_config(duthost, profile_name, [group_name])
