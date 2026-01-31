"""
Test cases for console monitor DCE/DTE functionality.

These tests verify:
1. Console monitor heartbeat detection (DCE side on DUT, DTE side on fanout)
2. Console line status reporting via 'show line -b'
3. Data passthrough when connected to console line
"""
import logging
import time

import pytest
from typing import Dict, Optional
from typing_extensions import TypedDict

from tests.common.devices.sonic import SonicHost
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


class LineStatus(TypedDict):
    """Type definition for console line status."""
    oper_state: str
    state_duration: str


pytestmark = [pytest.mark.topology("c0")]

logger = logging.getLogger(__name__)

# Constants
HEARTBEAT_TIMEOUT_SEC = 15  # Time for heartbeat to timeout and line status to become 'Unknown'
HEARTBEAT_DETECT_SEC = 2    # Time for heartbeat to be detected and line status to become 'Up'


# ==================== Fixtures ====================

@pytest.fixture(scope="module")
def console_fanout(duthosts, fanouthosts):
    """
    Find the console fanout host in the testbed.

    Returns:
        FanoutHost: The first console fanout found that is a SonicHost
    """
    console_fanouts = [
        fanout for fanout in fanouthosts.values()
        if isinstance(fanout.host, SonicHost) and fanout.host.is_console_switch()
    ]

    if not console_fanouts:
        pytest.skip("No console fanout found in testbed - test requires physical hardware")

    fanout = console_fanouts[0]
    logger.info(f"Found console fanout: {fanout.hostname}")
    return fanout


@pytest.fixture(scope="module")
def dut_console_lines(duthosts, console_fanout):
    """
    Get the console line mappings between DUT and fanout.

    Returns:
        list: List of tuples (fanout_port, dut_port, baud_rate) for lines connected to the DUT
    """
    dut_host = duthosts[0]
    lines = [
        (fanout_port, mapping.dut_port, mapping.baud_rate)
        for fanout_port, mapping in console_fanout.serial_port_map.items()
        if mapping is not None and mapping.dut_name == dut_host.hostname
    ]

    if not lines:
        pytest.skip(f"No console lines found between DUT {dut_host.hostname} and fanout {console_fanout.hostname}")

    logger.info(f"Found {len(lines)} console lines: {lines}")
    return lines


@pytest.fixture(scope="function")
def dce_service_is_running(duthosts):
    """
    Verify console-monitor-dce service is running on DUT.

    This fixture:
    1. Verifies console feature is enabled in CONFIG_DB
    2. Verifies console lines are configured
    3. Verifies console-monitor-dce.service is running
    """
    duthost = duthosts[0]

    # Check if console feature is enabled in CONFIG_DB
    console_switch_config = duthost.shell(
        "sonic-db-cli CONFIG_DB HGET 'CONSOLE_SWITCH|console_mgmt' 'enabled'",
        module_ignore_errors=True
    )
    pytest_assert(
        console_switch_config['rc'] == 0 and console_switch_config['stdout'].strip().lower() == 'yes',
        "Console feature is not enabled in CONFIG_DB (CONSOLE_SWITCH|console_mgmt enabled != yes)"
    )
    logger.info("Console feature is enabled in CONFIG_DB")

    # Check console lines are configured (at least 1 line)
    console_facts = duthost.console_facts()['ansible_facts']['console_facts']
    configured_lines = console_facts.get('lines', {})
    pytest_assert(
        len(configured_lines) > 0,
        "No console lines configured on DUT"
    )
    logger.info(f"Found {len(configured_lines)} configured console lines: {list(configured_lines.keys())}")

    # Check console-monitor-dce service is running
    pytest_assert(
        duthost.is_host_service_running("console-monitor-dce"),
        "console-monitor-dce.service is not running on DUT"
    )
    logger.info("console-monitor-dce.service is running")

    yield

    # Cleanup: ensure no active console sessions after test
    logger.info("Cleaning up console sessions after test")


@pytest.fixture(scope="function")
def cleanup_console_sessions(duthosts, console_fanout):
    """
    Cleanup fixture to ensure console sessions are cleaned up after each test.
    """
    yield

    # Cleanup on fanout side
    try:
        if isinstance(console_fanout.host, SonicHost):
            console_fanout.host.cleanup_all_console_sessions()
            logger.info("Cleaned up all console sessions on fanout")
    except Exception as e:
        logger.warning(f"Failed to cleanup console sessions on fanout: {e}")

    # Cleanup on DUT side - clear any active lines
    duthost = duthosts[0]
    try:
        console_facts = duthost.console_facts()['ansible_facts']['console_facts']
        for line_id, line_info in console_facts.get('lines', {}).items():
            if line_info.get('state') == 'BUSY':
                duthost.shell(f"sudo consutil clear {line_id}", module_ignore_errors=True)
                logger.info(f"Cleared busy line {line_id} on DUT")
    except Exception as e:
        logger.warning(f"Failed to cleanup console lines on DUT: {e}")


# ==================== Helper Functions ====================

def parse_show_line_output(output: str) -> Dict[str, LineStatus]:
    """
    Parse the output of 'show line' command.

    Example output:
      Line    Baud    Flow Control    PID    Start Time      Device    Oper State    State Duration
    ------  ------  --------------  -----  ------------  ----------  ------------  ----------------
         1    9600        Disabled      -             -   Terminal1       Unknown          3h20m26s
         2    9600        Disabled      -             -   Terminal2       Unknown          3h32m59s

    Returns:
        Dict[str, LineStatus]: {line_id: {'oper_state': str, 'state_duration': str}} for all lines
    """
    result: Dict[str, LineStatus] = {}
    lines = output.strip().split('\n')

    # Find the header line to determine column positions
    header_line = None
    for i, line in enumerate(lines):
        if 'Line' in line and 'Oper State' in line:
            header_line = line
            data_start = i + 2  # Skip header and separator line
            break

    if header_line is None:
        return result

    # Parse data lines
    for line in lines[data_start:]:
        if not line.strip():
            continue

        # Split by multiple spaces to handle the tabular format
        parts = line.split()
        if len(parts) >= 8:
            # Line ID is the first column, Oper State is the 7th column (index 6)
            # State Duration is the 8th column (index 7)
            # Format: Line, Baud, Flow Control (2 words), PID, Start Time, Device, Oper State, State Duration
            line_id = parts[0]
            oper_state = parts[6]
            state_duration = parts[7]
            result[line_id] = LineStatus(
                oper_state=oper_state,
                state_duration=state_duration
            )

    return result


def get_line_status(duthost, line_id) -> Optional[str]:
    """
    Get the status of a specific console line using 'show line' command.

    Args:
        duthost: DUT host object
        line_id: Console line ID (e.g., "1", "2")

    Returns:
        str: Line status ('Up', 'Unknown', 'Down', etc.) or None if not found
    """
    output = duthost.shell("show line -b")['stdout']
    all_statuses = parse_show_line_output(output)
    line_info = all_statuses.get(str(line_id))
    return line_info['oper_state'] if line_info else None


def get_all_line_statuses(duthost) -> Dict[str, LineStatus]:
    """
    Get status of all console lines using 'show line' command.

    Returns:
        Dict[str, LineStatus]: {line_id: {'oper_state': str, 'state_duration': str}} for all lines
    """
    output = duthost.shell("show line -b")['stdout']
    return parse_show_line_output(output)


def wait_for_line_status(duthost, line_id, expected_status, timeout=20):
    """
    Wait for a console line to reach expected status.

    Args:
        duthost: DUT host object
        line_id: Console line ID
        expected_status: Expected status string
        timeout: Maximum wait time in seconds

    Returns:
        bool: True if status reached, False if timeout
    """
    def check_status():
        status = get_line_status(duthost, line_id)
        logger.debug(f"Line {line_id} status: {status}")
        return status == expected_status

    return wait_until(timeout, 1, 0, check_status)


# ==================== Test Cases ====================

def test_oper_state_transition(
    duthosts, console_fanout, dut_console_lines,
    dce_service_is_running, cleanup_console_sessions
):
    """
    Test console monitor heartbeat detection functionality.

    Test steps:
    1. Wait for heartbeat timeout, verify all lines show 'Unknown' status
    2. Enable heartbeat on fanout side for line 1
    3. Verify line 1 status changes to 'Up', other lines remain 'Unknown'
    4. Disable heartbeat on fanout side
    5. Verify line 1 remains 'Up' briefly (grace period)
    6. Wait for heartbeat timeout, verify line 1 returns to 'Unknown'
    """
    duthost = duthosts[0]
    fanout_host = console_fanout.host

    # Get first available line for testing
    fanout_port, dut_port, baud_rate = dut_console_lines[0]
    target_line = str(dut_port)
    logger.info(f"Testing with line {target_line} (fanout port {fanout_port}, baud rate {baud_rate})")

    # Step 1: Wait for heartbeat timeout and verify all lines show 'Unknown'
    logger.info(f"Step 1: Waiting {HEARTBEAT_TIMEOUT_SEC}s for heartbeat timeout...")
    time.sleep(HEARTBEAT_TIMEOUT_SEC)

    all_statuses = get_all_line_statuses(duthost)
    logger.info(f"All line statuses after timeout: {all_statuses}")

    for line_id, line_info in all_statuses.items():
        pytest_assert(
            line_info['oper_state'] == 'Unknown',
            f"Line {line_id} should be 'Unknown' after heartbeat timeout, but got '{line_info['oper_state']}'"
        )

    # Step 2: Enable heartbeat on fanout side for target line
    logger.info(f"Step 2: Enabling heartbeat on fanout for line {target_line}...")
    fanout_host.shell("sudo config console heartbeat enable", module_ignore_errors=False)

    # Start console-monitor in DTE mode on fanout
    device_path = fanout_host._get_serial_device_path(fanout_port)
    fanout_host.shell(
        f"sudo console-monitor dte {device_path} &",
        module_ignore_errors=False
    )
    logger.info(f"Started console-monitor DTE on {device_path}")

    # Step 3: Wait and verify line status changes to 'Up'
    logger.info(f"Step 3: Waiting for line {target_line} to become 'Up'...")
    pytest_assert(
        wait_for_line_status(duthost, target_line, 'Up', timeout=HEARTBEAT_DETECT_SEC + 3),
        f"Line {target_line} did not change to 'Up' status after enabling heartbeat"
    )

    # Verify other lines remain 'Unknown'
    all_statuses = get_all_line_statuses(duthost)
    logger.info(f"Line statuses after heartbeat enabled: {all_statuses}")
    for line_id, line_info in all_statuses.items():
        if line_id == target_line:
            pytest_assert(
                line_info['oper_state'] == 'Up',
                f"Target line {line_id} should be 'Up', got '{line_info['oper_state']}'"
            )
        else:
            pytest_assert(
                line_info['oper_state'] == 'Unknown',
                f"Line {line_id} should remain 'Unknown', got '{line_info['oper_state']}'"
            )

    # Step 4: Disable heartbeat on fanout side
    logger.info("Step 4: Disabling heartbeat on fanout...")
    fanout_host.shell("sudo config console heartbeat disable", module_ignore_errors=False)
    fanout_host.shell(f"sudo pkill -f 'console-monitor.*{device_path}'", module_ignore_errors=False)

    # Step 5: Verify line remains 'Up' briefly (grace period)
    logger.info("Step 5: Verifying line remains 'Up' during grace period...")
    time.sleep(1)
    status = get_line_status(duthost, target_line)
    pytest_assert(
        status == 'Up',
        f"Line {target_line} should still be 'Up' during grace period, got '{status}'"
    )

    # Step 6: Wait for heartbeat timeout and verify status returns to 'Unknown'
    logger.info(f"Step 6: Waiting {HEARTBEAT_TIMEOUT_SEC}s for heartbeat timeout...")
    pytest_assert(
        wait_for_line_status(duthost, target_line, 'Unknown', timeout=HEARTBEAT_TIMEOUT_SEC + 5),
        f"Line {target_line} did not return to 'Unknown' status after heartbeat disabled"
    )

    logger.info("Test passed: Heartbeat detection working correctly")
