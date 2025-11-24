"""
Utilities for high frequency telemetry testing.

This module contains common functions and classes used across
high frequency telemetry test cases.
"""

import itertools
import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
import ptf.testutils as testutils
from natsort import natsorted

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)


def get_available_ports(duthost, tbinfo, desired_ports=2, min_ports=None):
    """
    Get available ports from topology configuration.

    Args:
        duthost: DUT host object
        tbinfo: testbed info
        desired_ports: desired number of ports (default: 2). If None,
                       return all available ports
        min_ports: minimum number of ports required (default: None,
                   means no minimum requirement)

    Returns:
        list: List of available port names (e.g., ['Ethernet0', 'Ethernet16'])

    Raises:
        pytest.skip: If not enough ports available to meet min_ports
                     requirement
    """
    cfg_facts = duthost.config_facts(
        host=duthost.hostname, source="persistent")['ansible_facts']
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # Get ports that are up and available
    config_ports = {
        k: v for k, v in list(cfg_facts['PORT'].items())
        if v.get('admin_status', 'down') == 'up'
    }
    config_port_indices = {
        k: v for k, v in list(mg_facts['minigraph_ptf_indices'].items())
        if k in config_ports
    }
    ptf_ports_available_in_topo = {
        port_index: 'eth{}'.format(port_index)
        for port_index in list(config_port_indices.values())
    }

    # Exclude port channel member ports
    config_portchannels = cfg_facts.get('PORTCHANNEL_MEMBER', {})
    config_port_channel_members = [
        list(port_channel.keys())
        for port_channel in list(config_portchannels.values())
    ]
    config_port_channel_member_ports = list(
        itertools.chain.from_iterable(config_port_channel_members)
    )

    # Filter available ports
    available_ports = [
        port for port in config_ports
        if config_port_indices.get(port) in ptf_ports_available_in_topo and
        config_ports[port].get('admin_status', 'down') == 'up' and
        port not in config_port_channel_member_ports
    ]

    # Sort ports naturally (e.g., Ethernet2 before Ethernet10)
    available_ports = natsorted(available_ports)

    logger.info(f"Found {len(available_ports)} available ports: "
                f"{available_ports}")

    # Check minimum requirement first
    if min_ports is not None and len(available_ports) < min_ports:
        pytest.skip(
            f"Not enough ports available. Required minimum: {min_ports}, "
            f"Available: {len(available_ports)}")

    # If desired_ports is None, return all available ports
    if desired_ports is None:
        logger.info(f"Returning all {len(available_ports)} available ports")
        return available_ports

    # Try to get desired number of ports
    if len(available_ports) >= desired_ports:
        selected_ports = available_ports[:desired_ports]
        logger.info(f"Successfully got {len(selected_ports)} desired ports: "
                    f"{selected_ports}")
        return selected_ports
    else:
        # Less than desired, but still some available
        logger.warning(
            f"Warning: Only {len(available_ports)} ports available, "
            f"less than desired {desired_ports} ports. "
            f"Using all available ports: {available_ports}")
        return available_ports


def setup_hft_profile(duthost, profile_name, poll_interval=10000,
                      stream_state="enabled", otel_endpoint=None,
                      otel_certs=None):
    """
    Set up a high frequency telemetry profile.

    Args:
        duthost: DUT host object
        profile_name: Name of the profile
        poll_interval: Polling interval in microseconds (default: 30000)
        stream_state: enabled/disabled (default: enabled)
        otel_endpoint: OpenTelemetry endpoint (optional)
        otel_certs: Path to certificates (optional)
    """
    profile_config = {
        "poll_interval": str(poll_interval),
        "stream_state": stream_state
    }

    if otel_endpoint:
        profile_config["otel_endpoint"] = otel_endpoint
    if otel_certs:
        profile_config["otel_certs"] = otel_certs

    # Build the HSET command
    config_parts = []
    for key, value in profile_config.items():
        config_parts.extend([f'"{key}"', f'"{value}"'])

    profile_cmd = (
        f'redis-cli -n 4 HSET "HIGH_FREQUENCY_TELEMETRY_PROFILE|'
        f'{profile_name}" {" ".join(config_parts)}'
    )

    result = duthost.shell(profile_cmd, module_ignore_errors=False)
    logger.info(f"Created high frequency telemetry profile '{profile_name}': "
                f"{profile_config}")
    return result


def setup_hft_group(duthost, profile_name, group_name,
                    object_names, object_counters):
    """
    Set up a high frequency telemetry group.

    Args:
        duthost: DUT host object
        profile_name: Name of the profile
        group_name: Name of the group (e.g., "port", "queue", "buffer")
        object_names: List of object names or comma-separated string
        object_counters: List of counter names or comma-separated string
    """
    if isinstance(object_names, list):
        object_names = ",".join(object_names)
    if isinstance(object_counters, list):
        object_counters = ",".join(object_counters)

    group_cmd = (
        f'redis-cli -n 4 HSET "HIGH_FREQUENCY_TELEMETRY_GROUP|'
        f'{profile_name}|{group_name}" '
        f'"object_names" "{object_names}" '
        f'"object_counters" "{object_counters}"'
    )

    result = duthost.shell(group_cmd, module_ignore_errors=False)
    logger.info(f"Created high frequency telemetry group '{group_name}' "
                f"for profile '{profile_name}': "
                f"objects={object_names}, counters={object_counters}")
    return result


def cleanup_hft_config(duthost, profile_name, group_names=None):
    """
    Clean up high frequency telemetry configuration.

    Args:
        duthost: DUT host object
        profile_name: Name of the profile to clean up
        group_names: List of group names to clean up (optional, if None,
                     will clean all groups for the profile)
    """
    cleanup_commands = []

    # Clean up profile
    cleanup_commands.append(
        f'redis-cli -n 4 DEL "HIGH_FREQUENCY_TELEMETRY_PROFILE|{profile_name}"'
    )

    # Clean up groups
    if group_names:
        if isinstance(group_names, str):
            group_names = [group_names]
        for group_name in group_names:
            cleanup_commands.append(
                f'redis-cli -n 4 DEL "HIGH_FREQUENCY_TELEMETRY_GROUP|'
                f'{profile_name}|{group_name}"'
            )
    else:
        # Clean up all groups for this profile (use pattern matching)
        pattern_cmd = (
            f'redis-cli -n 4 KEYS "HIGH_FREQUENCY_TELEMETRY_GROUP|'
            f'{profile_name}|*"'
        )
        result = duthost.shell(pattern_cmd, module_ignore_errors=True)
        if result['rc'] == 0 and result['stdout_lines']:
            for key in result['stdout_lines']:
                if key.strip():
                    cleanup_commands.append(
                        f'redis-cli -n 4 DEL "{key.strip()}"'
                    )

    # Execute cleanup commands
    for cmd in cleanup_commands:
        duthost.shell(cmd, module_ignore_errors=True)

    logger.info(f"Cleaned up high frequency telemetry configuration "
                f"for profile '{profile_name}'")


def run_countersyncd_and_capture_output(duthost, timeout=120, stats_interval=10):
    """
    Run countersyncd command and capture output.

    Args:
        duthost: DUT host object
        timeout: Timeout in seconds (default: 120)
        stats_interval: Stats reporting interval in seconds (default: 10)

    Returns:
        dict: Command result with stdout, stderr, rc
    """
    countersyncd_cmd = (
        f'timeout {timeout} docker exec swss countersyncd -e '
        f'--max-stats-per-report 0 '
        f'--stats-interval {stats_interval} '
    )
    result = duthost.shell(countersyncd_cmd, module_ignore_errors=True)

    # Check if command completed successfully (timeout is expected)
    pytest_assert(
        result['rc'] in [0, 124, 137],  # 124: timeout, 137: SIGKILL
        f"countersyncd command failed with unexpected return code: "
        f"{result['rc']}")

    logger.info(f"countersyncd output captured (exit code: {result['rc']})")
    return result


class CountersyncdMonitor:
    """A class to continuously monitor countersyncd output.

    Allows dynamic stream state changes using background process
    and file-based output capture.
    """

    def __init__(self, duthost):
        self.duthost = duthost
        self.is_running = False
        self.output_file = "/tmp/countersyncd_continuous_output.log"
        self.process_started = False

    def start_monitoring(self):
        """Start countersyncd monitoring in background."""
        if self.is_running:
            logger.warning("Monitoring is already running")
            return

        # Clean up any previous output file
        cleanup_cmd = f"rm -f {self.output_file}"
        self.duthost.shell(cleanup_cmd, module_ignore_errors=True)

        # Start countersyncd in background and redirect output to file
        countersyncd_cmd = (
            f'nohup docker exec swss countersyncd -e --max-stats-per-report 0 --stats-interval 60 '
            f' > {self.output_file} 2>&1 &'
        )
        logger.info(
            "Starting continuous countersyncd monitoring in background...")

        result = self.duthost.shell(
            countersyncd_cmd, module_ignore_errors=True
        )

        if result['rc'] == 0:
            self.is_running = True
            self.process_started = True
            # Give it a moment to start
            time.sleep(3)
            logger.info("Countersyncd monitoring started successfully")
        else:
            logger.error(f"Failed to start countersyncd monitoring: {result}")
            raise Exception("Failed to start countersyncd monitoring")

    def stop_monitoring(self):
        """Stop countersyncd monitoring."""
        if not self.is_running:
            logger.warning("Monitoring is not running")
            return

        logger.info("Stopping countersyncd monitoring...")

        # Kill countersyncd process
        kill_cmd = "docker exec swss pkill -f countersyncd || true"
        self.duthost.shell(kill_cmd, module_ignore_errors=True)

        # Wait a bit for process to terminate
        time.sleep(2)

        self.is_running = False
        logger.info("Countersyncd monitoring stopped")

    def get_output_since_position(self, start_position=0):
        """Get output from file starting from given position."""
        if not self.process_started:
            return "", 0

        # Get file content from specified position
        read_cmd = (
            f"tail -c +{start_position + 1} {self.output_file} "
            f"2>/dev/null || echo ''")
        result = self.duthost.shell(read_cmd, module_ignore_errors=True)

        if result['rc'] == 0:
            content = result['stdout']
            new_position = start_position + len(content.encode('utf-8'))
            return content, new_position
        else:
            return "", start_position

    def get_current_file_size(self):
        """Get current size of output file."""
        size_cmd = f"wc -c < {self.output_file} 2>/dev/null || echo '0'"
        result = self.duthost.shell(size_cmd, module_ignore_errors=True)

        if result['rc'] == 0:
            try:
                return int(result['stdout'].strip())
            except ValueError:
                return 0
        return 0

    def wait_for_output(self, duration=5, check_interval=1):
        """Wait for output to accumulate for specified duration."""
        start_time = time.time()
        while time.time() - start_time < duration:
            if not self.is_running:
                break
            time.sleep(check_interval)


def run_continuous_countersyncd_with_state_changes(duthost, profile_name,
                                                   state_sequence,
                                                   phase_duration=60):
    """Run countersyncd continuously while changing stream states.

    Uses file-based output capture.

    Args:
        duthost: DUT host object
        profile_name: Name of the telemetry profile
        state_sequence: List of (state, duration) tuples,
            e.g., [("enabled", 60), ("disabled", 60), ("enabled", 60)]
        phase_duration: Default duration for each phase if not specified

    Returns:
        dict: Results with output for each phase
    """
    monitor = CountersyncdMonitor(duthost)
    results = {}
    current_position = 0

    try:
        # Start continuous monitoring
        monitor.start_monitoring()

        # Wait a bit for initial startup and some initial output
        logger.info("Waiting for initial countersyncd startup...")
        time.sleep(8)

        # Get initial position to skip startup messages
        current_position = monitor.get_current_file_size()
        logger.info(f"Initial file position: {current_position}")

        for i, state_info in enumerate(state_sequence):
            if isinstance(state_info, tuple):
                state, duration = state_info
            else:
                state = state_info
                duration = phase_duration

            phase_name = f"phase_{i+1}_{state}"
            logger.info(f"Starting {phase_name}: Setting stream to '{state}' "
                        f"for {duration} seconds")

            # Mark the start position for this phase
            phase_start_position = monitor.get_current_file_size()

            # Change stream state
            setup_hft_profile(
                duthost=duthost,
                profile_name=profile_name,
                poll_interval=10000,
                stream_state=state
            )

            # Wait for the state change to take effect
            time.sleep(3)

            # Wait for this phase duration
            logger.info(f"Collecting data for {duration} seconds...")
            monitor.wait_for_output(duration=duration)

            # Get output for this phase
            phase_end_position = monitor.get_current_file_size()
            phase_output, _ = monitor.get_output_since_position(
                phase_start_position
            )

            results[phase_name] = {
                'state': state,
                'duration': duration,
                'output': phase_output,
                'start_position': phase_start_position,
                'end_position': phase_end_position,
                'output_length': len(phase_output)
            }

            logger.info(f"Completed {phase_name}. "
                        f"Output length: {len(phase_output)} chars, "
                        f"File positions: {phase_start_position} -> "
                        f"{phase_end_position}")

            # Show a snippet of the output for debugging
            if phase_output:
                snippet = (
                    phase_output[:200] + "..." if len(phase_output) > 200
                    else phase_output
                )
                logger.info(f"Phase output snippet: {snippet}")
            else:
                logger.warning(f"No output captured for {phase_name}")

    finally:
        # Always stop monitoring
        monitor.stop_monitoring()

    return results


def run_continuous_countersyncd_with_config_changes(duthost, profile_name,
                                                    group_name,
                                                    object_names,
                                                    object_counters,
                                                    config_sequence,
                                                    phase_duration=60):
    """
    Run countersyncd continuously while changing configuration
    (create/delete) using file-based output capture.

    Args:
        duthost: DUT host object
        profile_name: Name of the telemetry profile
        group_name: Name of the telemetry group
        object_names: Object names for the group
        object_counters: Object counters for the group
        config_sequence: List of (action, duration) tuples,
                         e.g., [("create", 60), ("delete", 60), ("create", 60)]
        phase_duration: Default duration for each phase if not specified

    Returns:
        dict: Results with output for each phase
    """
    monitor = CountersyncdMonitor(duthost)
    results = {}
    current_position = 0

    try:
        # Start continuous monitoring
        monitor.start_monitoring()

        # Wait a bit for initial startup and some initial output
        logger.info("Waiting for initial countersyncd startup...")
        time.sleep(8)

        # Get initial position to skip startup messages
        current_position = monitor.get_current_file_size()
        logger.info(f"Initial file position: {current_position}")

        for i, config_info in enumerate(config_sequence):
            if isinstance(config_info, tuple):
                action, duration = config_info
            else:
                action = config_info
                duration = phase_duration

            phase_name = f"phase_{i+1}_{action}"
            logger.info(
                f"Starting {phase_name}: {action} configuration "
                f"for {duration} seconds")

            # Mark the start position for this phase
            phase_start_position = monitor.get_current_file_size()

            # Apply configuration change
            if action == "create":
                # Create profile and group
                setup_hft_profile(
                    duthost=duthost,
                    profile_name=profile_name,
                    poll_interval=10000,
                    stream_state="enabled")
                setup_hft_group(
                    duthost=duthost,
                    profile_name=profile_name,
                    group_name=group_name,
                    object_names=object_names,
                    object_counters=object_counters
                )
            elif action == "delete":
                # Delete configuration
                cleanup_hft_config(duthost, profile_name, [group_name])
            else:
                logger.warning(f"Unknown action: {action}")
                continue

            # Wait for the configuration change to take effect
            time.sleep(3)

            # Wait for this phase duration
            logger.info(f"Collecting data for {duration} seconds...")
            monitor.wait_for_output(duration=duration)

            # Get output for this phase
            phase_end_position = monitor.get_current_file_size()
            phase_output, _ = monitor.get_output_since_position(
                phase_start_position
            )

            results[phase_name] = {
                'action': action,
                'duration': duration,
                'output': phase_output,
                'start_position': phase_start_position,
                'end_position': phase_end_position,
                'output_length': len(phase_output)
            }

            logger.info(f"Completed {phase_name}. "
                        f"Output length: {len(phase_output)} chars, "
                        f"File positions: {phase_start_position} -> "
                        f"{phase_end_position}")

            # Show a snippet of the output for debugging
            if phase_output:
                snippet = (
                    phase_output[:200] + "..." if len(phase_output) > 200
                    else phase_output
                )
                logger.info(f"Phase output snippet: {snippet}")
            else:
                logger.warning(f"No output captured for {phase_name}")

    finally:
        # Always stop monitoring
        monitor.stop_monitoring()

    return results


def validate_stream_state_transitions(
    phase_results, state_sequence, validation_objects=None
):
    """
    Validate the stream state transition results.

    Args:
        phase_results: Results from
                       run_continuous_countersyncd_with_state_changes
        state_sequence: The original state sequence used
        validation_objects: Objects to validate (optional)

    Returns:
        dict: Validation results for each phase
    """
    validation_results = {}

    for i, (state, _) in enumerate(state_sequence):
        phase_name = f"phase_{i+1}_{state}"

        if phase_name not in phase_results:
            logger.warning(f"Phase {phase_name} not found in results")  # noqa: E713
            continue

        phase_data = phase_results[phase_name]
        output = phase_data['output']

        logger.info(f"Analyzing {phase_name} (state: {state})")

        if not output or output.strip() == "":
            logger.warning(f"No output captured for {phase_name}")
            validation_results[phase_name] = {
                'actual_msg_per_sec': [],
                'has_active_msgs': False,
                'validation_passed': state == "disabled"  # No output OK
            }
            continue

        # Validate the output based on expected state
        expect_disabled = (state == "disabled")
        validation = validate_counter_output(
            output=output,
            expected_objects=validation_objects,
            min_counter_value=0,
            expected_poll_interval=10000,
            expect_disabled=expect_disabled
        )

        # Determine if this phase has active messages
        has_active_msgs = (
            len(validation['actual_msg_per_sec']) > 0 and
            any(m > 0 for m in validation['actual_msg_per_sec'])
        )

        validation_results[phase_name] = {
            'state': state,
            'actual_msg_per_sec': validation['actual_msg_per_sec'],
            'has_active_msgs': has_active_msgs,
            'total_reports': validation['total_reports_count'],
            'stable_reports': validation['stable_reports_count'],
            'validation_passed': validation['msg_per_sec_validation']
        }

        logger.info(f"{phase_name} analysis: "
                    f"Msg/s values: {validation['actual_msg_per_sec']}, "
                    f"Active msgs: {has_active_msgs}, "
                    f"Reports: {validation['stable_reports_count']}"
                    f"/{validation['total_reports_count']}")

    return validation_results


def validate_config_state_transitions(
    phase_results, config_sequence, validation_objects=None
):
    """
    Validate the configuration state transition results.

    Args:
        phase_results: Results from
                       run_continuous_countersyncd_with_config_changes
        config_sequence: The original config sequence used
        validation_objects: Objects to validate (optional)

    Returns:
        dict: Validation results for each phase
    """
    validation_results = {}

    for i, (action, _) in enumerate(config_sequence):
        phase_name = f"phase_{i+1}_{action}"

        if phase_name not in phase_results:
            logger.warning(f"Phase {phase_name} not found in results")  # noqa: E713
            continue

        phase_data = phase_results[phase_name]
        output = phase_data['output']

        logger.info(f"Analyzing {phase_name} (action: {action})")

        if not output or output.strip() == "":
            logger.warning(f"No output captured for {phase_name}")
            validation_results[phase_name] = {
                'actual_msg_per_sec': [],
                'has_active_msgs': False,
                'validation_passed': action == "delete"  # No output OK
            }
            continue

        # Validate the output based on expected configuration state
        expect_disabled = (action == "delete")
        validation = validate_counter_output(
            output=output,
            expected_objects=validation_objects,
            min_counter_value=0,
            expected_poll_interval=10000,
            expect_disabled=expect_disabled
        )

        # Determine if this phase has active messages
        has_active_msgs = (
            len(validation['actual_msg_per_sec']) > 0 and
            any(m > 0 for m in validation['actual_msg_per_sec'])
        )

        validation_results[phase_name] = {
            'action': action,
            'actual_msg_per_sec': validation['actual_msg_per_sec'],
            'has_active_msgs': has_active_msgs,
            'total_reports': validation['total_reports_count'],
            'stable_reports': validation['stable_reports_count'],
            'validation_passed': validation['msg_per_sec_validation']
        }

        logger.info(f"{phase_name} analysis: "
                    f"Msg/s values: {validation['actual_msg_per_sec']}, "
                    f"Active msgs: {has_active_msgs}, "
                    f"Reports: {validation['stable_reports_count']}"
                    f"/{validation['total_reports_count']}")

    return validation_results


def validate_counter_output(
    output, expected_objects=None, min_counter_value=0,
    expected_poll_interval=None, expect_disabled=False
):
    """
    Validate countersyncd output for expected patterns and counter values.

    Args:
        output: String output from countersyncd
        expected_objects: List of object names to check for (optional)
        min_counter_value: Minimum expected counter value (default: 0)
        expected_poll_interval: Expected poll interval in microseconds
                                (optional)
        expect_disabled: If True, expect counters and Msg/s to be 0
                         (for disabled stream testing)

    Returns:
        dict: Validation results with counter values and object matches
    """
    # First check if we have any meaningful output
    if not output or output.strip() == "":
        pytest_assert(False, "countersyncd output is empty")

    # "No statistics data available yet" is normal -
    # stream might need time to start
    if "No statistics data available yet" in output:
        logger.info(
            "Stream is starting up - 'No statistics data available yet' "
            "is expected initially")

    if expect_disabled:
        return validate_disabled_stream_output(
            output, expected_objects
        )
    else:
        return validate_enabled_stream_output(
            output, expected_objects, min_counter_value,
            expected_poll_interval
        )


def validate_enabled_stream_output(
    output, expected_objects, min_counter_value, expected_poll_interval
):
    """
    Validate output for enabled streams - expect active data flow.
    """
    # Split output into reports to analyze the last stable ones
    reports = re.split(r'\[Report #\d+\]', output)
    reports = [r.strip() for r in reports if r.strip()]  # Remove empty reports

    if len(reports) == 0:
        pytest_assert(
            False,
            f"No valid reports found in output. "
            f"Output snippet: {output[:500]}...")

    # Use the last 3 reports for stable sampling (or all if less than 3)
    stable_reports_count = min(3, len(reports))
    stable_reports = reports[-stable_reports_count:]
    stable_output = '\n'.join(stable_reports)

    logger.info(
            f"Analyzing last {len(stable_reports)} reports for stable data "
            f"(total reports: {len(reports)})")

    # Look for patterns like "Counter:             832" in stable reports
    counter_pattern = r'Counter:\s+(\d+)'
    counter_matches = re.findall(counter_pattern, stable_output)

    pytest_assert(
        len(counter_matches) > 0,
        f"No counter values found in stable reports. "
        f"Stable output snippet: {stable_output[:500]}...")

    # Verify counter values - expect them to be greater than min_counter_value
    counter_values = []
    for counter_value_str in counter_matches:
        counter_value = int(counter_value_str)
        counter_values.append(counter_value)
        pytest_assert(
            counter_value >= min_counter_value,
            f"Counter value {counter_value} should be greater "
            f"than {min_counter_value}")

    logger.info(
            f"Successfully verified {len(counter_matches)} counter values "
            f"are > {min_counter_value}")

    # Validate Msg/s if poll_interval is provided
    msg_per_sec_matches = []
    msg_validation_result = None

    if expected_poll_interval:
        msg_pattern = r'Msg/s:\s+(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)'
        msg_per_sec_matches = re.findall(msg_pattern, stable_output)

        if msg_per_sec_matches:
            msg_values = [float(m) for m in msg_per_sec_matches]

            # Calculate expected Msg/s from poll_interval (microseconds)
            expected_msg_per_sec = 1000000.0 / expected_poll_interval

            # Validate each Msg/s value (allow 15% tolerance)
            tolerance = 0.15  # 15% tolerance (85% accuracy)
            min_acceptable = expected_msg_per_sec * (1 - tolerance)
            max_acceptable = expected_msg_per_sec * (1 + tolerance)

            # Calculate average Msg/s for validation (data may be uneven)
            avg_msg_per_sec = sum(msg_values) / len(msg_values)

            # Log individual values and average for debugging
            logger.info(f"Individual Msg/s values: {msg_values}")
            logger.info(f"Average Msg/s: {avg_msg_per_sec: .2f}, Expected: {expected_msg_per_sec: .2f}")

            # Validate the average against expected range
            if min_acceptable <= avg_msg_per_sec <= max_acceptable:
                logger.info(
                    f"Msg/s validation PASSED: Average {avg_msg_per_sec: .2f} is within "
                    f"expected range {min_acceptable: .2f} - {max_acceptable: .2f}")
                msg_validation_result = True
            else:
                pytest_assert(False,
                              f"Average Msg/s {avg_msg_per_sec: .2f} is outside expected range: "
                              f"{min_acceptable: .2f} - {max_acceptable: .2f}. "
                              f"Individual values: {msg_values}")

            logger.info(
                f"Successfully verified {len(msg_per_sec_matches)} Msg/s values. "
                f"Expected: {expected_msg_per_sec: .2f}, "
                f"Average: {avg_msg_per_sec: .2f}, "
                f"Individual range: {min(msg_values): .2f} - {max(msg_values): .2f}")
        else:
            # Debug logging to help diagnose Msg/s issues
            logger.warning(
                "No Msg/s values found in stable output")
            logger.info(f"Searching for Msg/s pattern: {msg_pattern}")
            logger.info(f"Stable output length: {len(stable_output)} characters")
            if "Msg/s" in stable_output:
                logger.info("Found 'Msg/s' text in stable output")
                # Show a snippet around each Msg/s occurrence
                msg_positions = []
                start = 0
                while True:
                    pos = stable_output.find("Msg/s", start)
                    if pos == -1:
                        break
                    msg_positions.append(pos)
                    start = pos + 1

                for i, pos in enumerate(msg_positions[:3]):  # Show first 3 occurrences
                    snippet_start = max(0, pos - 50)
                    snippet_end = min(len(stable_output), pos + 50)
                    snippet = stable_output[snippet_start:snippet_end]
                    logger.info(f"Msg/s occurrence {i+1}: ...{snippet}...")
            else:
                logger.warning("No 'Msg/s' text found in stable output")
                # Show a sample of the stable output for debugging
                sample_length = min(500, len(stable_output))
                logger.info(f"Stable output sample (first {sample_length} chars): {stable_output[:sample_length]}")
            msg_validation_result = False

    # Check for specific objects if provided
    object_matches = {}
    if expected_objects:
        for obj_name in expected_objects:
            obj_pattern = rf'Object: {re.escape(obj_name)}\s+.*?Counter:\s+(\d+)'  # noqa: E231
            obj_matches = re.findall(obj_pattern, stable_output)

            pytest_assert(
                len(obj_matches) > 0,
                f"No counter reports found for {obj_name} in stable data")

            object_matches[obj_name] = [int(val) for val in obj_matches]
            logger.info(f"Successfully verified counters for {obj_name}: {object_matches[obj_name]}")

    # Validate LastTime timestamps - expect them to be close to current UTC time
    lasttime_pattern = r'LastTime: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) UTC'
    lasttime_matches = re.findall(lasttime_pattern, stable_output)
    lasttime_validation_result = True

    if lasttime_matches:
        current_utc = datetime.now(timezone.utc)
        tolerance_minutes = 60
        min_acceptable_time = current_utc - timedelta(minutes=tolerance_minutes)
        max_acceptable_time = current_utc + timedelta(minutes=tolerance_minutes)

        valid_timestamps = []
        invalid_timestamps = []

        for timestamp_str in lasttime_matches:
            try:
                # Parse timestamp (format: 1970-01-02 02:08:37.307033444)
                timestamp = datetime.strptime(timestamp_str[:26], '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)

                if min_acceptable_time <= timestamp <= max_acceptable_time:
                    valid_timestamps.append(timestamp_str)
                else:
                    invalid_timestamps.append(timestamp_str)
                    logger.warning(f"Invalid timestamp {timestamp_str}: outside {tolerance_minutes}-minute window")
            except ValueError as e:
                invalid_timestamps.append(timestamp_str)
                logger.warning(f"Failed to parse timestamp {timestamp_str}: {e}")

        if invalid_timestamps:
            lasttime_validation_result = False
            pytest_assert(False,
                          f"Found {len(invalid_timestamps)} invalid timestamps outside "
                          f"{tolerance_minutes}-minute window. Current UTC: {current_utc}, "
                          f"Invalid timestamps: {invalid_timestamps[:5]}")  # Show first 5

        logger.info(f"LastTime validation PASSED: {len(valid_timestamps)} timestamps within "
                    f"{tolerance_minutes}-minute window of current UTC time {current_utc}")
    else:
        logger.warning("No LastTime timestamps found in stable output")
        lasttime_validation_result = False

    return {
        "counter_values": counter_values,
        "object_matches": object_matches,
        "total_counters": len(counter_matches),
        "actual_msg_per_sec": [float(m) for m in msg_per_sec_matches] if msg_per_sec_matches else [],
        "msg_per_sec_validation": msg_validation_result,
        "lasttime_validation": lasttime_validation_result,
        "lasttime_matches": lasttime_matches if lasttime_matches else [],
        "stable_reports_count": len(stable_reports),
        "total_reports_count": len(reports)
    }


def validate_disabled_stream_output(output, expected_objects):
    """
    Validate output for disabled streams - expect no active data flow or zero values.
    """
    # Split output into reports to analyze the last stable ones
    reports = re.split(r'\[Report #\d+\]', output)
    reports = [r.strip() for r in reports if r.strip()]  # Remove empty reports

    logger.info(f"Found {len(reports)} reports in disabled stream output")

    # For disabled streams, we might have no
    # reports at all, or reports with zero values
    if len(reports) == 0:
        logger.info("No reports found - this is expected for disabled streams")
        return {
            "counter_values": [],
            "object_matches": {},
            "total_counters": 0,
            "actual_msg_per_sec": [],
            "msg_per_sec_validation": True,  # No data is expected, so validation passes
            "stable_reports_count": 0,
            "total_reports_count": 0
        }

    # Use the last 3 reports for stable sampling (or all if less than 3)
    stable_reports_count = min(3, len(reports))
    stable_reports = reports[-stable_reports_count:]
    stable_output = '\n'.join(stable_reports)

    logger.info(f"Analyzing last {len(stable_reports)} reports for disabled stream verification")

    # Look for counter patterns -
    # but don't validate values for disabled streams
    counter_pattern = r'Counter:\s+(\d+)'
    counter_matches = re.findall(counter_pattern, stable_output)

    counter_values = []
    if counter_matches:
        # For disabled streams, counter values
        # may remain unchanged from last active state
        # We don't validate the values, just record them
        for counter_value_str in counter_matches:
            counter_value = int(counter_value_str)
            counter_values.append(counter_value)

        logger.info(
            f"Found {len(counter_matches)} counter values in disabled stream "
            f"(values preserved from last active state)")
    else:
        logger.info("No counter values found - this is expected for disabled streams")

    # Validate Msg/s values
    msg_per_sec_matches = []
    msg_validation_passed = True

    msg_pattern = r'Msg/s:\s+(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)'
    msg_per_sec_matches = re.findall(msg_pattern, stable_output)

    if msg_per_sec_matches:
        msg_values = [float(m) for m in msg_per_sec_matches]
        non_zero_msg_rates = [m for m in msg_values if m > 0]

        pytest_assert(
            len(non_zero_msg_rates) == 0,
            f"Expected all Msg/s to be 0 for disabled stream, but found: {non_zero_msg_rates}")
        logger.info(f"Successfully verified {len(msg_per_sec_matches)} Msg/s values are 0 (stream disabled)")
    else:
        logger.info("No Msg/s values found - this is expected for disabled streams")

    # Check for specific objects - they
    # might not appear at all in disabled streams
    object_matches = {}
    if expected_objects:
        for obj_name in expected_objects:
            obj_pattern = rf'Object: {re.escape(obj_name)}\s+.*?Counter:\s+(\d+)'  # noqa: E231
            obj_matches = re.findall(obj_pattern, stable_output)

            if obj_matches:
                # If object appears, record its
                # counter values (don't validate for disabled streams)
                object_values = [int(val) for val in obj_matches]
                object_matches[obj_name] = object_values
                logger.info(f"Found counters for {obj_name} in disabled stream: {object_values} (values preserved)")
            else:
                logger.info(f"Object {obj_name} not found in disabled stream output - this is expected")  # noqa: E713

    return {
        "counter_values": counter_values,
        "object_matches": object_matches,
        "total_counters": len(counter_matches),
        "actual_msg_per_sec": [float(m) for m in msg_per_sec_matches] if msg_per_sec_matches else [],
        "msg_per_sec_validation": msg_validation_passed,
        "stable_reports_count": len(stable_reports),
        "total_reports_count": len(reports)
    }


def run_continuous_countersyncd_with_port_state_changes(duthost, profile_name, ptfadapter,
                                                        test_port, ptf_port_index, router_mac,
                                                        port_state_sequence):
    """
    Run countersyncd continuously while changing port states (up/down) and injecting PTF traffic.

    Args:
        duthost: DUT host object
        profile_name: Name of the telemetry profile (should already be configured)
        ptfadapter: PTF adapter for traffic injection
        test_port: DUT port to monitor (e.g., "Ethernet0")
        ptf_port_index: PTF port index corresponding to test_port
        router_mac: Router MAC address for packet crafting
        port_state_sequence: List of (state, duration) tuples, e.g., [("up", 60), ("down", 60), ("up", 60)]

    Returns:
        dict: Results with output for each phase
    """
    # Traffic control
    traffic_running = threading.Event()
    traffic_thread = None

    def send_continuous_traffic():
        """Send continuous traffic to the test port"""
        logger.info(f"Starting continuous traffic injection to PTF port {ptf_port_index}")
        packet_count = 0

        while traffic_running.is_set():
            try:
                # Create a simple IP
                # packet destined to trigger interface counters
                pkt = testutils.simple_ip_packet(
                    eth_dst=router_mac,
                    eth_src="00:01:02:03:04:05",  # Dummy source MAC
                    ip_src="10.0.0.1",
                    ip_dst="10.0.0.2",
                    ip_ttl=64
                )

                # Send packet
                testutils.send(ptfadapter, ptf_port_index, pkt)
                packet_count += 1

                # Send packets at a moderate rate (100 packets per second)
                time.sleep(0.01)

                # Log progress every 1000 packets
                if packet_count % 1000 == 0:
                    logger.debug(f"Sent {packet_count} packets to PTF port {ptf_port_index}")

            except Exception as e:
                logger.warning(f"Error sending traffic: {e}")
                time.sleep(0.1)  # Brief pause on error

        logger.info(f"Stopped traffic injection. Total packets sent: {packet_count}")

    monitor = CountersyncdMonitor(duthost)
    results = {}

    try:
        # Start continuous monitoring
        monitor.start_monitoring()

        # Start continuous traffic injection
        traffic_running.set()
        traffic_thread = threading.Thread(target=send_continuous_traffic, daemon=True)
        traffic_thread.start()

        # Wait for initial startup
        logger.info("Waiting for initial countersyncd startup and traffic to begin...")
        time.sleep(10)

        # Get initial position to skip startup messages
        current_position = monitor.get_current_file_size()
        logger.info(f"Initial file position: {current_position}")

        for i, (state, duration) in enumerate(port_state_sequence):
            phase_name = f"phase_{i+1}_{state}"
            logger.info(f"Starting {phase_name}: port {state} for {duration} seconds")

            # Mark the start position for this phase
            phase_start_position = monitor.get_current_file_size()

            # Change port state
            if state == "down":
                logger.info(f"Shutting down port {test_port}")
                duthost.shell(f"config interface shutdown {test_port}")
            elif state == "up":
                logger.info(f"Starting up port {test_port}")
                duthost.shell(f"config interface startup {test_port}")
            else:
                logger.warning(f"Unknown port state: {state}")
                continue

            # Wait for the port state change to take effect
            time.sleep(5)

            # Wait for this phase duration while traffic continues
            logger.info(f"Collecting data for {duration} seconds with traffic...")
            monitor.wait_for_output(duration=duration)

            # Get output for this phase
            phase_end_position = monitor.get_current_file_size()
            phase_output, _ = monitor.get_output_since_position(

                phase_start_position

            )

            results[phase_name] = {
                'port_state': state,
                'duration': duration,
                'output': phase_output,
                'start_position': phase_start_position,
                'end_position': phase_end_position,
                'output_length': len(phase_output)
            }

            logger.info(f"Completed {phase_name}. "
                        f"Output length: {len(phase_output)} chars, "
                        f"File positions: {phase_start_position} -> "
                        f"{phase_end_position}")

            # Show a snippet of the output for debugging
            if phase_output:
                snippet = (
                    phase_output[:200] + "..." if len(phase_output) > 200
                    else phase_output
                )
                logger.info(f"Phase output snippet: {snippet}")
            else:
                logger.warning(f"No output captured for {phase_name}")

    finally:
        # Stop traffic injection
        if traffic_running.is_set():
            logger.info("Stopping traffic injection...")
            traffic_running.clear()

        if traffic_thread and traffic_thread.is_alive():
            traffic_thread.join(timeout=5)

        # Always stop monitoring
        monitor.stop_monitoring()

    return results


def validate_port_state_transitions(phase_results, port_state_sequence, validation_objects=None):
    """
    Validate the port state transition results by analyzing counter trends.

    Args:
        phase_results: Results from run_continuous_countersyncd_with_port_state_changes
        port_state_sequence: The original port state sequence used
        validation_objects: Objects to validate (optional)

    Returns:
        dict: Validation results for each phase
    """
    validation_results = {}

    for i, (state, _) in enumerate(port_state_sequence):
        phase_name = f"phase_{i+1}_{state}"

        if phase_name not in phase_results:
            logger.warning(f"Phase {phase_name} not found in results")  # noqa: E713
            continue

        phase_data = phase_results[phase_name]
        output = phase_data['output']

        logger.info(f"Analyzing {phase_name} (port state: {state})")

        if not output or output.strip() == "":
            logger.warning(f"No output captured for {phase_name}")
            validation_results[phase_name] = {
                'counters_increasing': False,
                'counter_trend': 'no_data',
                'port_state': state
            }
            continue

        # Analyze counter trends in this phase
        counter_trend = analyze_counter_trend(output)

        # Determine if counters are increasing based on port state expectations
        if state == "up":
            # Port is up, expect counters to increase with traffic
            counters_increasing = (counter_trend == 'increasing')
        elif state == "down":
            # Port is down, expect counters to remain stable despite traffic
            counters_increasing = False  # Should not be increasing when port is down
        else:
            logger.warning(f"Unknown port state: {state}")
            counters_increasing = False

        validation_results[phase_name] = {
            'counters_increasing': counters_increasing,
            'counter_trend': counter_trend,
            'port_state': state
        }

        logger.info(f"Phase {phase_name}: port {state} -> trend: {counter_trend} -> increasing: {counters_increasing}")

    return validation_results


def analyze_counter_trend(output):
    """
    Analyze the trend of counter values in the output.

    Args:
        output: countersyncd output text

    Returns:
        str: 'increasing', 'stable', 'decreasing', or 'no_pattern'
    """
    # Extract counter values with timestamps/order
    counter_pattern = r'Counter:\s+(\d+)'
    counter_matches = re.findall(counter_pattern, output)

    if len(counter_matches) < 2:
        logger.info("Not enough counter samples to determine trend")
        return 'no_pattern'

    # Convert to integers
    counter_values = [int(val) for val in counter_matches]

    # Take a sample from the middle portion to avoid startup/ending effects
    sample_size = min(10, len(counter_values))
    start_idx = max(0, (len(counter_values) - sample_size) // 2)
    end_idx = start_idx + sample_size
    sample_values = counter_values[start_idx:end_idx]

    logger.info(f"Analyzing counter trend with {len(sample_values)} samples: {sample_values}")

    if len(sample_values) < 2:
        return 'no_pattern'

    # Compare first and last values in the sample
    first_val = sample_values[0]
    last_val = sample_values[-1]

    # Calculate the difference and percentage change
    diff = last_val - first_val
    pct_change = (diff / first_val * 100) if first_val > 0 else 0

    logger.info(f"Counter trend analysis: first={first_val}, last={last_val}, "
                f"diff={diff}, pct_change={pct_change: .2f}%")

    # Determine trend based on percentage change
    if pct_change > 5:  # More than 5% increase
        return 'increasing'
    elif pct_change < -5:  # More than 5% decrease
        return 'decreasing'
    else:  # Within 5% change
        return 'stable'
