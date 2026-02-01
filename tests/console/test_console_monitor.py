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


def get_serial_fanout_for_line(fanouthosts, duthost, link_id: int):
    """
    Find which fanout host has the serial connection for a given link_id.

    Args:
        fanouthosts: Dict of fanout hosts
        duthost: DUT host
        link_id: Console line ID on DUT

    Returns:
        Tuple[FanoutHost, int]: (fanout_host, fanout_port) or (None, None) if not found
    """
    dut_hostname = duthost.hostname

    for fanout in fanouthosts.values():
        for fanout_port, mapping in fanout.serial_port_map.items():
            if mapping is not None and str(mapping.dut_name) == dut_hostname and int(mapping.dut_port) == link_id:
                logger.info(f"Found fanout {fanout.hostname} port {fanout_port} for link {link_id}")
                return fanout, fanout_port

    logger.warning(f"No fanout found for link {link_id}")
    return None, None


def get_vm_base_neighbor(nbrhosts, tbinfo):
    """
    Get the vm_base neighbor device from nbrhosts.

    Args:
        nbrhosts: Dict of neighbor hosts
        tbinfo: Testbed info

    Returns:
        Tuple[str, str, NeighborDevice]: (neighbor_name, vm_name, neighbor_device) or (None, None, None)
    """
    if not nbrhosts:
        return None, None, None

    vm_base = tbinfo.get('vm_base', '')
    if not vm_base:
        logger.warning("No vm_base in tbinfo")
        return None, None, None

    # Find neighbor that matches vm_base
    for neighbor_name, neighbor_device in nbrhosts.items():
        # Check if neighbor's vm_name matches vm_base
        vm_name = neighbor_device['host'].hostname
        if vm_name and vm_name.upper() == vm_base.upper():
            logger.info(f"Found neighbor {neighbor_name} matching vm_base {vm_base}")
            return neighbor_name, vm_base, neighbor_device

    logger.warning(f"No neighbor found matching vm_base {vm_base}")
    return None, None, None


# ==================== Bridge Management ====================

class BridgeManager:
    """
    Manages socat bridges between DUT serial ports and neighbor VMs.

    Bridge architecture:
        DUT serial port <--physical--> Fanout serial port
        Fanout serial port <--socat--> VM Host TCP port
        VM Host TCP port <--socat--> VM serial console (virsh)
    """

    def __init__(self):
        self.active_bridges: List[ConsoleBridge] = []
        self._vmhost = None
        self._fanout = None

    def build_console_bridge(
        self,
        duthost,
        fanout,
        fanout_port: int,
        vmhost,
        vm_name: str,
        neighbor_name: str,
        link_id: int
    ) -> Optional[ConsoleBridge]:
        """
        Build a complete console bridge from DUT to neighbor VM.

        Steps:
        1. Get VM's serial port from virsh
        2. Start socat on VM host: TCP-LISTEN:<bridge_port> <-> TCP:127.0.0.1:<vm_serial_port>
        3. Use fanout's bridge_remote() to connect fanout serial port to VM host

        Args:
            duthost: DUT host object
            fanout: Fanout host object
            fanout_port: Serial port number on fanout
            vmhost: VM host object
            vm_name: VM name in libvirt
            neighbor_name: Neighbor name
            link_id: Console line ID on DUT

        Returns:
            ConsoleBridge: Bridge info if successful, None otherwise
        """
        self._vmhost = vmhost
        self._fanout = fanout

        # Step 1: Get VM's serial port from virsh
        vm_serial_port = get_vm_serial_port(vmhost, vm_name)
        if vm_serial_port is None:
            logger.error(f"Cannot get serial port for VM {vm_name}")
            return None

        # Calculate bridge port (offset from base to avoid conflicts)
        bridge_port = BRIDGE_BASE_PORT + link_id

        # Get VM host IP
        vmhost_ip = get_vmhost_ip(vmhost)
        if not vmhost_ip:
            logger.error(f"Cannot get IP for VM host {vmhost.hostname}")
            return None

        # Get serial device path from fanout using SonicHost helper
        fanout_device_path = fanout.host._get_serial_device_path(link_id)

        logger.info(f"Building bridge for link {link_id}:")
        logger.info(f"  VM serial port: {vm_serial_port}")
        logger.info(f"  Bridge port: {bridge_port}")
        logger.info(f"  VM host IP: {vmhost_ip}")
        logger.info(f"  Fanout device: {fanout_device_path}")

        # Step 2: Start socat on VM host
        # TCP-LISTEN:<bridge_port>,fork,reuseaddr TCP:127.0.0.1:<vm_serial_port>
        vmhost_socat_cmd = (
            f"sudo socat -d -d TCP-LISTEN:{bridge_port},fork,reuseaddr "
            f"TCP:127.0.0.1:{vm_serial_port} &"
        )
        logger.info(f"Starting socat on VM host: {vmhost_socat_cmd}")

        try:
            vmhost.shell(vmhost_socat_cmd)
            time.sleep(SOCAT_STARTUP_DELAY)
        except Exception as e:
            logger.error(f"Failed to start socat on VM host: {e}")
            return None

        # Step 3: Use fanout's bridge_remote() to connect fanout serial port to VM host
        logger.info(f"Starting bridge_remote on fanout: port {link_id} -> {vmhost_ip}:{bridge_port}")

        try:
            fanout.host.bridge_remote(link_id, vmhost_ip, bridge_port)
            time.sleep(SOCAT_STARTUP_DELAY)
        except Exception as e:
            logger.error(f"Failed to start bridge_remote on fanout: {e}")
            self._cleanup_vmhost_socat(vmhost, bridge_port)
            return None

        bridge = ConsoleBridge(
            link_id=link_id,
            vm_serial_port=vm_serial_port,
            bridge_port=bridge_port,
            fanout_device_path=fanout_device_path,
            neighbor_name=neighbor_name,
            vm_name=vm_name
        )

        self.active_bridges.append(bridge)
        logger.info(f"Bridge established for link {link_id}")
        return bridge

    def _cleanup_vmhost_socat(self, vmhost, bridge_port: int):
        """Kill socat processes for a specific bridge port on VM host."""
        try:
            vmhost.shell(f"sudo pkill -f 'socat.*{bridge_port}'", module_ignore_errors=True)
        except Exception as e:
            logger.warning(f"Error cleaning up VM host socat: {e}")

    def cleanup_all_bridges(self):
        """Clean up all active bridges."""
        logger.info(f"Cleaning up {len(self.active_bridges)} bridges")

        for bridge in self.active_bridges:
            # Cleanup fanout bridge using unbridge_remote
            if self._fanout:
                self._fanout.host.unbridge_remote(bridge.link_id)

            # Cleanup VM host socat
            if self._vmhost:
                self._cleanup_vmhost_socat(self._vmhost, bridge.bridge_port)

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
def ensure_dce_service_running(duthost, console_facts):
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

    # Check console lines are configured (at least 1 line)
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


@pytest.fixture(scope="function")
def bridge_manager():
    """
    Fixture that provides a BridgeManager and ensures cleanup after test.
    """
    manager = BridgeManager()
    yield manager
    manager.cleanup_all_bridges()


@pytest.fixture(scope="function")
def cleanup_console_sessions(duthost):
    """
    Cleanup fixture to clear all console sessions after each test.
    """
    yield

    # Cleanup on DUT side - clear any active lines
    try:
        console_facts = duthost.console_facts()['ansible_facts']['console_facts']
        for line_id, line_info in console_facts.get('lines', {}).items():
            if line_info.get('state') == 'BUSY':
                duthost.shell(f"sudo consutil clear {line_id}", module_ignore_errors=True)
                logger.info(f"Cleared busy line {line_id} on DUT")
    except Exception as e:
        logger.warning(f"Failed to cleanup console lines on DUT: {e}")


# ==================== Test Cases ====================

def test_dut_connected_to_fanout(duthost, fanouthosts, console_facts):

    # Get the first configured console line for testing
    configured_lines = list(console_facts.get('lines', {}).keys())
    pytest_assert(len(configured_lines) > 0, "No console lines configured")

    target_link_id = int(configured_lines[0])
    logger.info(f"Testing with link {target_link_id}")

    fanout, fanout_port = get_serial_fanout_for_line(fanouthosts, duthost, target_link_id)
    pytest_assert(fanout is not None, f"No fanout found for link {target_link_id}")
    return


def test_oper_state_transition(
    duthost,
    fanouthosts,
    nbrhosts,
    tbinfo,
    vmhost,
    creds,
    console_facts,
    serial_fanouts,
    ensure_dce_service_running,
    bridge_manager: BridgeManager,
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

    # Get the first configured console line for testing
    configured_lines = list(console_facts.get('lines', {}).keys())
    pytest_assert(len(configured_lines) > 0, "No console lines configured")

    target_link_id = int(configured_lines[0])
    logger.info(f"Testing with link {target_link_id}")

    # Step 1: Verify initial state - all lines should be 'Unknown'
    logger.info("Step 1: Verifying initial state...")
    time.sleep(HEARTBEAT_TIMEOUT_SEC)  # Wait for any existing heartbeat to timeout

    all_statuses = duthost.get_console_line_statuses()
    logger.info(f"Initial line statuses: {all_statuses}")

    for line_id, line_info in all_statuses.items():
        pytest_assert(
            line_info['oper_state'] == 'Unknown',
            f"Line {line_id} should be 'Unknown' initially, got '{line_info['oper_state']}'"
        )

    # Step 2: Find fanout and neighbor for target link
    logger.info(f"Step 2: Finding fanout and neighbor for link {target_link_id}...")

    fanout, fanout_port = get_serial_fanout_for_line(fanouthosts, duthost, target_link_id)
    pytest_assert(fanout is not None, f"No fanout found for link {target_link_id}")

    neighbor_name, vm_name, neighbor_device = get_vm_base_neighbor(nbrhosts, tbinfo)
    pytest_assert(neighbor_name is not None, "No neighbor found in nbrhosts")

    nbr_host = neighbor_device['host']
    pytest_assert(isinstance(nbr_host, SonicHost), "Neighbor host is not a SonicHost")

    logger.info(f"Found fanout: {fanout.hostname}, port: {fanout_port}")
    logger.info(f"Found neighbor: {neighbor_name}, VM: {vm_name}")

    # Step 3: Build console bridge
    logger.info("Step 3: Building console bridge...")

    bridge = bridge_manager.build_console_bridge(
        duthost=duthost,
        fanout=fanout,
        fanout_port=fanout_port,
        vmhost=vmhost,
        vm_name=vm_name,
        neighbor_name=neighbor_name,
        link_id=target_link_id
    )
    pytest_assert(bridge is not None, "Failed to build console bridge")

    # Step 4: Ensure console-monitor-dte service is running and enable heartbeat on neighbor VM
    logger.info("Step 4: Ensuring console-monitor-dte service running and enabling heartbeat on neighbor VM...")

    nbr_host.enable_console_heartbeat()

    # Step 5: Verify line status changes to 'Up'
    logger.info(f"Step 5: Waiting for line {target_link_id} to become 'Up'...")

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

    # Step 5.1: Verify user can see the login prompt on the DCE side
    logger.info("Step 5.1: Verifying login prompt visibility on DCE side...")

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

    # Step 6: Stop heartbeat and verify status returns to 'Unknown'
    logger.info("Step 6: Stopping heartbeat and waiting for timeout...")

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
