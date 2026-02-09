"""
Test cases for console monitor DCE/DTE functionality (v2).

These tests verify:
1. Console monitor heartbeat detection (DCE side on DUT, DTE side on neighbor VM)
2. Console line status reporting via 'show line -b'
3. Data passthrough when connected to console line

Testbed architecture:
    DUT (Console Switch, DCE) <--Serial--> Fanout <--socat/TCP--> VM Host <--virsh serial--> Neighbor VM (DTE)
"""
import logging
import pexpect
import re
import time
from typing import List, Optional
from dataclasses import dataclass

import pytest

from tests.common.devices.sonic import SonicHost
from tests.common.devices.fanout import FanoutHost
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("c0")]


# ==================== Constants ====================

HEARTBEAT_TIMEOUT_SEC = 15  # Time for heartbeat to timeout and line status to become 'Unknown'
HEARTBEAT_DETECT_SEC = 2    # Time for heartbeat to be detected and line status to become 'Up'
BRIDGE_BASE_PORT = 17000    # Base port for socat TCP bridge on VM host
SOCAT_STARTUP_DELAY = 1     # Delay after starting socat to ensure it's ready


# ==================== Type Definitions ====================

@dataclass
class ConsoleBridge:
    """Information about an established console bridge."""
    link_id: int
    vm_serial_port: int         # Port exposed by virsh for VM's serial console (e.g., 7080)
    bridge_port: int            # Socat bridge port on VM host (e.g., 17080)
    fanout_device_path: str     # Serial device path on fanout (e.g., /dev/C0-2)
    neighbor_name: str          # Neighbor VM name (e.g., ARISTA01T1)
    vm_name: str                # VM name in libvirt (e.g., VM04080)


# ==================== Helper Functions ====================

def wait_for_line_status(duthost, line_id: int, expected_status: str, timeout: int = 20) -> bool:
    """
    Wait for a console line to reach expected status.

    Args:
        duthost: DUT host object
        line_id: Console line ID
        expected_status: Expected status string ('Up', 'Unknown', etc.)
        timeout: Maximum wait time in seconds

    Returns:
        bool: True if status reached, False if timeout
    """
    def check_status():
        status = duthost.get_console_line_status(line_id)
        logger.debug(f"Line {line_id} status: {status}")
        return status == expected_status

    return wait_until(timeout, 3, 0, check_status)


def get_vm_serial_port(vmhost, vm_name: str) -> Optional[int]:
    """
    Get the TCP port exposed by virsh for VM's serial console.

    Uses: virsh dumpxml <vm_name> | grep -A5 serial
    Parses output like:
        <serial type='tcp'>
            <source mode='bind' host='127.0.0.1' service='7080' tls='no'/>
            ...
        </serial>

    Args:
        vmhost: VM host object (the server running libvirt/KVM)
        vm_name: VM name in libvirt (e.g., VM04080)

    Returns:
        int: Serial port number (e.g., 7080) or None if not found
    """
    try:
        result = vmhost.shell(f"sudo virsh dumpxml {vm_name} | grep -A5 serial", module_ignore_errors=True)
        if result['rc'] != 0:
            logger.warning(f"Failed to get serial port for VM {vm_name}: {result.get('stderr', '')}")
            return None

        # Parse the output to find service='<port>'
        match = re.search(r"service='(\d+)'", result['stdout'])
        if match:
            port = int(match.group(1))
            logger.info(f"Found serial port {port} for VM {vm_name}")
            return port

        logger.warning(f"No serial port found in virsh output for VM {vm_name}")
        return None
    except Exception as e:
        logger.error(f"Exception getting serial port for VM {vm_name}: {e}")
        return None


def get_vmhost_ip(vmhost) -> str:
    """
    Get the IP address of the VM host.

    Args:
        vmhost: VM host object

    Returns:
        str: IP address of the VM host
    """
    return vmhost.host.options['inventory_manager'].get_host(vmhost.hostname).vars.get('ansible_host', '')


def get_serial_fanout_for_line(
    fanouthosts: dict[str, FanoutHost],
    duthost: SonicHost,
    link_id: int,
    fail_on_not_found: bool = True
) -> tuple[FanoutHost, int]:
    """
    Find which fanout host has the serial connection for a given link_id.

    Args:
        fanouthosts: Dict of fanout hosts
        duthost: DUT host
        link_id: Console line ID on DUT
        fail_on_not_found: If True, pytest.fail when fanout not found

    Returns:
        Tuple[FanoutHost, int]: (fanout_host, fanout_port)
    """
    dut_hostname = duthost.hostname

    for fanout in fanouthosts.values():
        for fanout_port, mapping in fanout.serial_port_map.items():
            if mapping is not None and str(mapping.dut_name) == dut_hostname and int(mapping.dut_port) == link_id:
                logger.info(f"Found fanout {fanout.hostname} port {fanout_port} for link {link_id}")
                return fanout, fanout_port

    if fail_on_not_found:
        pytest.fail(f"No fanout found for link {link_id}")
    return None, None


def get_neighbor_by_name(
    nbrhosts: dict[str, dict],
    vm_name: str,
    fail_on_not_found: bool = True
) -> SonicHost:
    """
    Get neighbor SonicHost by VM name.

    Args:
        nbrhosts: Dict of neighbor hosts
        vm_name: VM name to find (e.g., 'VM0100')
        fail_on_not_found: If True, pytest.fail when neighbor not found

    Returns:
        SonicHost: The neighbor host
    """
    if not nbrhosts:
        if fail_on_not_found:
            pytest.fail("No neighbor hosts available")
        return None

    for neighbor_name, neighbor_device in nbrhosts.items():
        host_vm_name = neighbor_device['host'].hostname
        if host_vm_name and host_vm_name.upper() == vm_name.upper():
            nbr_host = neighbor_device['host']
            if not isinstance(nbr_host, SonicHost):
                if fail_on_not_found:
                    pytest.fail(f"Neighbor {neighbor_name} is not a SonicHost")
                return None
            logger.info(f"Found neighbor {neighbor_name} (VM: {vm_name})")
            return nbr_host

    if fail_on_not_found:
        pytest.fail(f"No neighbor found with VM name {vm_name}")
    return None


# ==================== Bridge Management ====================

class BridgeManager:
    """
    Manages socat bridges between DUT serial ports and neighbor VMs.

    Bridge architecture:
        DUT serial port <--physical--> Fanout serial port
        Fanout serial port <--socat--> VM Host TCP port
        VM Host TCP port <--socat--> VM serial console (virsh)
    """

    def __init__(
        self,
        duthost: SonicHost,
        fanouthosts: dict[str, FanoutHost],
        nbrhosts: dict[str, dict],
        vmhost
    ):
        """
        Initialize BridgeManager with testbed dependencies.

        Args:
            duthost: DUT host object
            fanouthosts: Dict of fanout hosts
            nbrhosts: Dict of neighbor hosts
            vmhost: VM host object
        """
        self._duthost = duthost
        self._fanouthosts = fanouthosts
        self._nbrhosts = nbrhosts
        self._vmhost = vmhost

        self.active_bridges: List[ConsoleBridge] = []
        self._current_fanout: Optional[FanoutHost] = None

    def build_console_bridge(self, link_id: int, neighbor_name: str) -> ConsoleBridge:
        """
        Build a complete console bridge from DUT to neighbor VM.

        Args:
            link_id: Console line ID on DUT
            neighbor_name: VM name of the neighbor (e.g., 'VM0100')

        Returns:
            ConsoleBridge: Bridge info (pytest.fail on error)
        """
        # Get fanout for this link
        fanout, fanout_port = get_serial_fanout_for_line(
            self._fanouthosts, self._duthost, link_id
        )
        self._current_fanout = fanout

        # Get VM's serial port from virsh
        vm_serial_port = get_vm_serial_port(self._vmhost, neighbor_name)
        if vm_serial_port is None:
            pytest.fail(f"Cannot get serial port for VM {neighbor_name}")

        # Calculate bridge port
        bridge_port = BRIDGE_BASE_PORT + link_id

        # Get VM host IP
        vmhost_ip = get_vmhost_ip(self._vmhost)
        if not vmhost_ip:
            pytest.fail(f"Cannot get IP for VM host {self._vmhost.hostname}")

        # Get serial device path
        fanout_device_path = fanout.host._get_serial_device_path(link_id)

        logger.info(f"Building bridge for link {link_id}: VM port={vm_serial_port}, bridge={bridge_port}")

        # Start socat on VM host
        vmhost_socat_cmd = (
            f"sudo socat -d -d TCP-LISTEN:{bridge_port},fork,reuseaddr "
            f"TCP:127.0.0.1:{vm_serial_port} &"
        )
        try:
            self._vmhost.shell(vmhost_socat_cmd)
            time.sleep(SOCAT_STARTUP_DELAY)
        except Exception as e:
            pytest.fail(f"Failed to start socat on VM host: {e}")

        # Connect fanout to VM host
        try:
            fanout.host.bridge_remote(link_id, vmhost_ip, bridge_port)
            time.sleep(SOCAT_STARTUP_DELAY)
        except Exception as e:
            self._cleanup_vmhost_socat(bridge_port)
            pytest.fail(f"Failed to start bridge_remote on fanout: {e}")

        bridge = ConsoleBridge(
            link_id=link_id,
            vm_serial_port=vm_serial_port,
            bridge_port=bridge_port,
            fanout_device_path=fanout_device_path,
            neighbor_name=neighbor_name,
            vm_name=neighbor_name
        )
        self.active_bridges.append(bridge)
        logger.info(f"Bridge established for link {link_id} -> {neighbor_name}")
        return bridge

    def get_neighbor_host(self, neighbor_name: str) -> SonicHost:
        """Get neighbor SonicHost by VM name."""
        return get_neighbor_by_name(self._nbrhosts, neighbor_name)

    def _cleanup_vmhost_socat(self, bridge_port: int):
        """Kill socat processes for a specific bridge port on VM host."""
        try:
            self._vmhost.shell(f"sudo pkill -f 'socat.*{bridge_port}'", module_ignore_errors=True)
        except Exception as e:
            logger.warning(f"Error cleaning up VM host socat: {e}")

    def cleanup_all_bridges(self):
        """Clean up all active bridges."""
        logger.info(f"Cleaning up {len(self.active_bridges)} bridges")

        for bridge in self.active_bridges:
            if self._current_fanout:
                self._current_fanout.host.unbridge_remote(bridge.link_id)
            self._cleanup_vmhost_socat(bridge.bridge_port)

        self.active_bridges.clear()
        logger.info("All bridges cleaned up")


# ==================== Fixtures ====================

@pytest.fixture(scope="module")
def serial_fanouts(fanouthosts, duthost):
    """
    Get list of fanout hosts that have serial port connections to the DUT.

    Returns:
        List[FanoutHost]: List of fanout hosts with serial connections
    """
    dut_hostname = duthost.hostname

    serial_fanout_list = []
    for fanout in fanouthosts.values():
        has_serial = any(
            mapping is not None and mapping.dut_name == dut_hostname
            for mapping in fanout.serial_port_map.values()
        )
        if has_serial:
            serial_fanout_list.append(fanout)
            logger.info(f"Found serial fanout: {fanout.hostname}")

    if not serial_fanout_list:
        pytest.skip("No serial fanouts found in testbed")

    return serial_fanout_list


@pytest.fixture(scope="function")
def ensure_dce_service_running(duthost, configured_lines: list[int]):
    """
    Ensure console-monitor-dce service is running on DUT before each test.

    This fixture:
    1. Verifies console feature is enabled in CONFIG_DB
    2. Verifies console lines are configured
    3. Verifies console-monitor-dce.service is running
    """
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

    # configured_lines fixture already asserts at least 1 line exists
    logger.info(f"Found {len(configured_lines)} configured console lines: {configured_lines}")

    # Check console-monitor-dce service is running
    pytest_assert(
        duthost.is_host_service_running("console-monitor-dce"),
        "console-monitor-dce.service is not running on DUT"
    )
    logger.info("console-monitor-dce.service is running")

    yield


@pytest.fixture(scope="function")
def bridge_manager(duthost, fanouthosts, nbrhosts, vmhost):
    """
    Fixture that provides a BridgeManager and ensures cleanup after test.
    """
    manager = BridgeManager(duthost, fanouthosts, nbrhosts, vmhost)
    yield manager
    manager.cleanup_all_bridges()


@pytest.fixture(scope="module")
def configured_lines(console_facts: dict) -> list[int]:
    """
    Get list of configured console line IDs from console_facts.

    Returns:
        list[int]: List of configured line IDs (e.g., [1, 2, 3])
    """
    lines = console_facts.get('lines', {})
    pytest_assert(len(lines) > 0, "No console lines configured on DUT")
    return [int(line_id) for line_id in lines.keys()]


@pytest.fixture(scope="function")
def cleanup_console_sessions(duthost, console_facts):
    """
    Cleanup fixture to clear all console sessions after each test.
    """
    yield

    # Cleanup on DUT side - clear any active lines
    try:
        for line_id, line_info in console_facts.get('lines', {}).items():
            if line_info.get('state') == 'BUSY':
                duthost.shell(f"sudo consutil clear {line_id}", module_ignore_errors=True)
                logger.info(f"Cleared busy line {line_id} on DUT")
    except Exception as e:
        logger.warning(f"Failed to cleanup console lines on DUT: {e}")


# ==================== Test Cases ====================

def test_dut_connected_to_fanout(duthost, fanouthosts, configured_lines: list[int]):
    """Verify DUT console line is connected to a fanout."""
    target_link_id = configured_lines[0]
    logger.info(f"Testing with link {target_link_id}")

    # Will pytest.fail if not found
    fanout, _ = get_serial_fanout_for_line(fanouthosts, duthost, target_link_id)
    logger.info(f"Link {target_link_id} connected to fanout {fanout.hostname}")


def test_oper_state_transition(
    duthost: SonicHost,
    tbinfo: dict,
    creds: dict[str, str],
    configured_lines: list[int],
    bridge_manager: BridgeManager,
    ensure_dce_service_running,
    cleanup_console_sessions
):
    """
    Test console monitor heartbeat detection and oper state transitions.

    Test steps:
    1. Verify initial state: all lines should be 'Unknown' (no heartbeat)
    2. Build console bridge to connect DUT to neighbor VM
    3. Start DTE heartbeat on neighbor VM
    4. Verify target line status changes to 'Up'
    5. Stop DTE heartbeat on neighbor VM
    6. Wait for heartbeat timeout, verify status returns to 'Unknown'
    """
    target_link_id = configured_lines[0]
    neighbor_name = tbinfo.get('vm_base', '')
    pytest_assert(neighbor_name, "No vm_base in tbinfo")
    logger.info(f"Testing with link {target_link_id}, neighbor {neighbor_name}")

    # Step 1: Verify initial state - all lines should be 'Unknown'
    logger.info("Step 1: Verifying initial state...")
    time.sleep(HEARTBEAT_TIMEOUT_SEC)

    all_statuses = duthost.get_console_line_statuses()
    for line_id, line_info in all_statuses.items():
        pytest_assert(
            line_info['oper_state'] == 'Unknown',
            f"Line {line_id} should be 'Unknown' initially, got '{line_info['oper_state']}'"
        )

    # Step 2: Build console bridge
    logger.info("Step 2: Building console bridge...")
    _ = bridge_manager.build_console_bridge(target_link_id, neighbor_name)
    nbr_host = bridge_manager.get_neighbor_host(neighbor_name)

    # Step 3: Enable heartbeat on neighbor VM
    logger.info("Step 3: Enabling heartbeat on neighbor VM...")
    nbr_host.enable_console_heartbeat()

    # Step 4: Verify line status changes to 'Up'
    logger.info(f"Step 4: Waiting for line {target_link_id} to become 'Up'...")

    time.sleep(HEARTBEAT_DETECT_SEC)

    # Verify target line is 'Up' and other lines remain 'Unknown'
    all_statuses = duthost.get_console_line_statuses()
    for line_id, line_info in all_statuses.items():
        if int(line_id) == target_link_id:
            pytest_assert(
                line_info['oper_state'] == 'Up',
                f"Target line {line_id} should be 'Up', got '{line_info['oper_state']}'"
            )
        else:
            pytest_assert(
                line_info['oper_state'] == 'Unknown',
                f"Line {line_id} should remain 'Unknown', got '{line_info['oper_state']}'"
            )

    # Step 4.1: Verify user can see the login prompt on the DCE side
    logger.info("Step 4.1: Verifying login prompt visibility on DCE side...")

    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser, dutpass = creds['sonicadmin_user'], creds['sonicadmin_password']

    try:
        client = pexpect.spawn(
            f"ssh {dutuser}@{dutip} -q -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"'sudo connect line {target_link_id}'"
        )
        client.expect('[Pp]assword:', timeout=10)
        client.sendline(dutpass)

        # Wait for login prompt from neighbor VM
        i = client.expect(['[Ll]ogin:', 'Cannot connect'], timeout=15)
        pytest_assert(i == 0, f"Failed to see login prompt on line {target_link_id}")
        logger.info("Successfully verified login prompt on DCE side")

    except pexpect.exceptions.EOF:
        pytest.fail("EOF reached while connecting to console line")
    except pexpect.exceptions.TIMEOUT:
        pytest.fail("Timeout reached while waiting for login prompt")
    except Exception as e:
        pytest.fail(f"Cannot connect to DUT host via SSH: {e}")
    finally:
        # Clear the console line after test
        duthost.shell(f"sudo consutil clear {target_link_id}", module_ignore_errors=True)

    # Step 5: Stop heartbeat and verify status returns to 'Unknown'
    logger.info("Step 5: Stopping heartbeat and waiting for timeout...")

    nbr_host.disable_console_heartbeat()

    # Cleanup the bridge to stop all socat processes
    bridge_manager.cleanup_all_bridges()

    # Wait for heartbeat timeout
    logger.info(f"Waiting {HEARTBEAT_TIMEOUT_SEC}s for heartbeat timeout...")
    pytest_assert(
        wait_for_line_status(duthost, target_link_id, 'Unknown', timeout=HEARTBEAT_TIMEOUT_SEC + 5),
        f"Line {target_link_id} did not return to 'Unknown' status after heartbeat stopped"
    )

    logger.info("Test passed: Heartbeat detection and oper state transitions working correctly")


def test_filter_timeout(
    duthost: SonicHost,
    tbinfo: dict,
    configured_lines: list[int],
    bridge_manager: BridgeManager,
    ensure_dce_service_running,
    cleanup_console_sessions
):
    """
    Test data pass-through after filter timeout.

    Verify user data passes through after filter timeout (when heartbeat is disabled).

    Test steps:
    1. Build console bridge and disable DTE heartbeat
    2. Send short string from DTE side
    3. Connect to DCE side and read output
    4. Verify DCE receives the exact string sent
    """

    target_link_id = configured_lines[0]
    neighbor_name = tbinfo.get('vm_base', '')
    pytest_assert(neighbor_name, "No vm_base in tbinfo")
    logger.info(f"Testing with link {target_link_id}, neighbor {neighbor_name}")

    # Build console bridge
    _ = bridge_manager.build_console_bridge(target_link_id, neighbor_name)
    nbr_host = bridge_manager.get_neighbor_host(neighbor_name)

    # Step 1: Disable DTE heartbeat to allow raw data pass-through
    logger.info("Step 1: Disabling DTE heartbeat...")
    nbr_host.disable_console_heartbeat()

    # Step 2: Send short string from DTE side (neighbor VM's serial console)
    test_string = "TEST_STRING_12345"
    console_output_file = "/tmp/console_output.txt"
    logger.info(f"Step 2: Sending test string from DTE side: {test_string}")

    # Step 3: Use script to capture console output on DCE side
    logger.info("Step 3: Starting script to capture console output...")

    try:
        # Start script in background to record console output
        # Using timeout to prevent infinite blocking, -q for quiet, -f for flush
        duthost.shell(
            f"timeout 15 script -q -f -c 'sudo connect line {target_link_id}' {console_output_file} &"
        )
        time.sleep(1)  # Wait for connection to establish

        # Send test string from DTE side while DCE is connected
        nbr_host.shell(f"sudo printf '{test_string}' > /dev/ttyS0", module_ignore_errors=True)
        time.sleep(1)  # Wait for data to be received and recorded

        # Step 4: Read the captured output and verify
        logger.info("Step 4: Verifying captured data...")
        result = duthost.shell(f"cat {console_output_file}", module_ignore_errors=True)
        captured_output = result.get('stdout', '')
        logger.info(f"Captured output: {captured_output[:200]}...")

        pytest_assert(
            test_string in captured_output,
            f"Failed to receive test string '{test_string}' on DCE side. Captured: {captured_output}"
        )

        logger.info(f"Successfully received test string on DCE side: {test_string}")
    finally:
        # Clear the console line and cleanup
        duthost.shell(f"sudo consutil clear {target_link_id}", module_ignore_errors=True)
        duthost.shell(f"rm -f {console_output_file}", module_ignore_errors=True)

    logger.info("Test passed: Data pass-through after filter timeout working correctly")


def test_filter_correctness(
    duthost: SonicHost,
    tbinfo: dict,
    configured_lines: list[int],
    bridge_manager: BridgeManager,
    ensure_dce_service_running,
    cleanup_console_sessions
):
    """
    Test that filter correctly passes user data while heartbeat is active.

    Verify that when DTE sends heartbeat continuously, user data passes through
    without non-printable characters being leaked to the DCE side.

    Test steps:
    1. Build console bridge and enable DTE heartbeat
    2. Wait for line status to become 'Up' (heartbeat detected)
    3. Send a long random printable string from DTE side
    4. Connect to DCE side and read output
    5. Verify DCE receives only printable characters (plus \\r\\n)
    """
    import string
    import random

    target_link_id = configured_lines[0]
    neighbor_name = tbinfo.get('vm_base', '')
    pytest_assert(neighbor_name, "No vm_base in tbinfo")
    logger.info(f"Testing filter correctness with link {target_link_id}, neighbor {neighbor_name}")

    # Build console bridge
    _ = bridge_manager.build_console_bridge(target_link_id, neighbor_name)
    nbr_host = bridge_manager.get_neighbor_host(neighbor_name)

    # Step 1: Enable DTE heartbeat
    logger.info("Step 1: Enabling DTE heartbeat...")
    nbr_host.enable_console_heartbeat()

    # Step 2: Wait for line status to become 'Up'
    logger.info(f"Step 2: Waiting for line {target_link_id} to become 'Up'...")
    pytest_assert(
        wait_for_line_status(duthost, target_link_id, 'Up', timeout=HEARTBEAT_DETECT_SEC + 5),
        f"Line {target_link_id} did not become 'Up' after enabling heartbeat"
    )
    logger.info(f"Line {target_link_id} is now 'Up'")

    # Step 3: Generate and send a long random printable string from DTE side
    # Use only alphanumeric characters to avoid shell escaping issues
    test_string = ''.join(random.choices(string.ascii_letters, k=256))

    logger.info(f"Step 3: Sending test string from DTE side (length={len(test_string)})")
    logger.debug(f"Test string: {test_string[:50]}...")

    console_output_file = "/tmp/filter_test_output.txt"

    try:
        # Step 4: Use script to capture console output on DCE side
        logger.info("Step 4: Starting script to capture console output on DCE side...")

        # Start script in background to record console output
        # Using timeout to prevent infinite blocking, -q for quiet, -f for flush
        duthost.shell(
            f"timeout 15 script -q -f -c 'sudo connect line {target_link_id}' {console_output_file} &"
        )
        time.sleep(1)  # Wait for connection to establish

        # Send test string from DTE side (neighbor VM's serial console)
        nbr_host.shell(f"printf '{test_string}' > /dev/ttyS0", module_ignore_errors=True)

        # Wait for data transmission and recording
        time.sleep(7)

        # Step 5: Read the captured output and verify
        logger.info("Step 5: Reading captured data and verifying...")
        result = duthost.shell(f"cat {console_output_file}", module_ignore_errors=True)
        captured_output = result.get('stdout', '')

        logger.info(f"Captured output length: {len(captured_output)}")
        logger.debug(f"Captured output: {captured_output[:500]}...")

        # Verify DCE receives only printable characters (plus \r\n\t)
        logger.info("Verifying no non-printable characters in output...")

        # Define allowed characters: printable ASCII + common whitespace
        allowed_chars = set(string.printable)  # includes \t\n\r\x0b\x0c and space

        non_printable_found = []
        for i, char in enumerate(captured_output):
            if char not in allowed_chars:
                non_printable_found.append((i, ord(char), repr(char)))

        if non_printable_found:
            logger.error(f"Found {len(non_printable_found)} non-printable characters:")
            for pos, code, char_repr in non_printable_found[:10]:  # Show first 10
                logger.error(f"  Position {pos}: code={code} ({char_repr})")

        pytest_assert(
            len(non_printable_found) == 0,
            f"DCE received {len(non_printable_found)} non-printable characters. "
            f"First few: {non_printable_found[:5]}"
        )

        # Verify the test marker was received (data actually passed through)
        pytest_assert(
            test_string in captured_output,
            f"Test string not found in captured output. "
            f"Data may not have passed through correctly. Captured: {captured_output[:200]}"
        )

        logger.info("Successfully verified: no non-printable characters leaked to DCE side")

    finally:
        # Cleanup
        duthost.shell(f"sudo consutil clear {target_link_id}", module_ignore_errors=True)
        duthost.shell(f"rm -f {console_output_file}", module_ignore_errors=True)
        nbr_host.disable_console_heartbeat()

    logger.info("Test passed: Filter correctly passes user data without non-printable characters")
