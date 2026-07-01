#!/usr/bin/env python3
"""
ICMP Orchagent Test for Sonic-MGMT

This test validates the ICMP orchestrator functionality which:
1. Reads ICMP_ECHO_SESSION_TABLE entries from APP_DB
2. Programs them in ASIC
3. Updates STATE_DB with session state
4. Detects session state changes based on reply packets

Test Pattern based on dualtor tests with proper mocking.

IMPORTANT: RX StreamImplementation Note
===========================================
- Creates genuine ICMP Echo Reply packets (Type 0) with correct structure
- Maintains session GUID payload for orchestrator functionality
"""

import re
import pytest
import logging
import time
import struct
from contextlib import contextmanager
from pkg_resources import parse_version

# Minimum required versions for snappi and snappi_ixnetwork
MIN_SNAPPI_VERSION = "1.42.1"
MIN_SNAPPI_IXNETWORK_VERSION = "1.42.1"


def get_snappi_version():
    """Get the installed snappi version."""
    try:
        import snappi
        version = getattr(snappi, '__version__', None)
        if version:
            return version
        # Fallback to pkg_resources if __version__ not available
        import pkg_resources
        return pkg_resources.get_distribution("snappi").version
    except Exception:
        return None


def get_snappi_ixnetwork_version():
    """Get the installed snappi_ixnetwork version."""
    try:
        import snappi_ixnetwork
        version = getattr(snappi_ixnetwork, '__version__', None)
        if version:
            return version
        # Fallback to pkg_resources if __version__ not available
        import pkg_resources
        return pkg_resources.get_distribution("snappi_ixnetwork").version
    except Exception:
        return None


def check_snappi_versions():
    """
    Check if snappi and snappi_ixnetwork versions meet minimum requirements.

    Returns:
        tuple: (skip_required, reason) - skip_required is True if versions are too old
    """
    snappi_version = get_snappi_version()
    snappi_ixnetwork_version = get_snappi_ixnetwork_version()

    # Print current versions for debugging
    print("[SNAPPI VERSION CHECK] snappi version: {}".format(snappi_version))
    print("[SNAPPI VERSION CHECK] snappi_ixnetwork version: {}".format(snappi_ixnetwork_version))
    print("[SNAPPI VERSION CHECK] Minimum required snappi: {}".format(MIN_SNAPPI_VERSION))
    print("[SNAPPI VERSION CHECK] Minimum required snappi_ixnetwork: {}".format(MIN_SNAPPI_IXNETWORK_VERSION))

    if snappi_version is None:
        return True, "snappi package is not installed"

    if snappi_ixnetwork_version is None:
        return True, "snappi_ixnetwork package is not installed"

    if parse_version(snappi_version) < parse_version(MIN_SNAPPI_VERSION):
        return True, ("snappi version {} is older than required "
                      "minimum version {}".format(snappi_version, MIN_SNAPPI_VERSION))

    if parse_version(snappi_ixnetwork_version) < parse_version(MIN_SNAPPI_IXNETWORK_VERSION):
        return True, ("snappi_ixnetwork version {} is older than "
                      "required minimum version {}".format(
                          snappi_ixnetwork_version,
                          MIN_SNAPPI_IXNETWORK_VERSION))

    print("[SNAPPI VERSION CHECK] All version checks passed!")
    return False, None


# Check versions at module load time
_skip_required, _skip_reason = check_snappi_versions()

# Import dualtor mock fixtures for proper orchagent mocking
from tests.common.dualtor.dual_tor_mock import apply_mock_dual_tor_tables  # noqa: F401, E402
from tests.common.dualtor.dual_tor_mock import apply_mock_dual_tor_kernel_configs  # noqa: F401, E402
from tests.common.dualtor.dual_tor_mock import apply_active_state_to_orchagent  # noqa: F401, E402
from tests.common.dualtor.dual_tor_utils import tor_mux_intfs  # noqa: F401, E402

# Import Snappi/IXIA fixtures and utilities
from tests.common.snappi_tests.snappi_fixtures import (  # noqa: F401, E402
    snappi_api_serv_ip, snappi_api_serv_port,
    snappi_api, snappi_testbed_config)
from tests.common.snappi_tests.snappi_helpers import wait_for_arp  # noqa: E402
from tests.common.fixtures.conn_graph_facts import (  # noqa: F401, E402
    conn_graph_facts, fanout_graph_facts)
# Import general test utilities
from tests.common.helpers.assertions import pytest_assert  # noqa: E402

# ICMP orchestrator utility is handled by copying to DUT
# The icmporch_util.py will be copied to the DUT and executed there

logger = logging.getLogger(__name__)

# Test constants
RX_STREAM_NAME = "ICMP_RX_Stream"  # Only RX stream needed, normal uses IXIA host

# ICMP session constants from LinkProberHw implementation
ICMP_SESSION_COOKIE = "0x58767e7a"  # Default session cookie from implementation
ICMP_VRF_NAME = "default"  # Default VRF name
ICMP_SESSION_TYPE_NORMAL = "NORMAL"  # Self session type
ICMP_SESSION_TYPE_RX = "RX"  # Peer session type
ICMP_GUID_NORMAL = "0x55555556"  # Normal session ID
ICMP_GUID_DUMMY = "0x55555557"  # RX session ID (different)


pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.usefixtures('apply_mock_dual_tor_tables',
                            'apply_mock_dual_tor_kernel_configs')
]


class ICMPSessionManager:
    """Helper class to manage ICMP sessions in APP_DB and monitor STATE_DB"""

    def __init__(self, duthost):
        self.duthost = duthost
        self.created_sessions = []
        self.session_id_mapping = {}  # Maps ICMP identifier to session GUID

    def initialize_icmp_util(self):
        """Initialize ICMP utility on DUT"""
        # Copy icmporch_util.py to DUT if not already present
        import os
        util_path = os.path.join(os.path.dirname(__file__), 'files/icmporch_util.py')
        self.duthost.copy(src=util_path, dest='/tmp/icmporch_util.py')
        logger.info("Copied icmporch_util.py to DUT")

    def create_session(self, session_key, session_config):
        """Create ICMP session in APP_DB"""
        logger.info("Creating ICMP session: {}".format(session_key))

        # Build field-value pairs string for the utility
        fv_pairs = []
        for field, value in session_config.items():
            fv_pairs.append("{}:{}".format(field, value))
        fv_string = ','.join(fv_pairs)

        # Use the icmporch_util.py on DUT to create session
        cmd = "cd /tmp && python3 icmporch_util.py -c create -k '{}' -f '{}' -v".format(session_key, fv_string)
        result = self.duthost.shell(cmd)

        if result['rc'] != 0:
            logger.error("Failed to create session {}: {}".format(session_key, result['stderr']))
            return False

        self.created_sessions.append(session_key)
        logger.info("Successfully created session: {}".format(session_key))
        return True

    def remove_session(self, session_key):
        """Remove ICMP session from APP_DB"""
        logger.info("Removing ICMP session: {}".format(session_key))

        cmd = "cd /tmp && python3 icmporch_util.py -c remove -k '{}' -v".format(session_key)
        result = self.duthost.shell(cmd)

        if result['rc'] != 0:
            logger.error("Failed to remove session {}: {}".format(session_key, result['stderr']))
            return False

        if session_key in self.created_sessions:
            self.created_sessions.remove(session_key)
        logger.info("Successfully removed session: {}".format(session_key))
        return True

    def get_session_state(self, session_key):
        """Get session state from STATE_DB"""
        cmd = "cd /tmp && python3 icmporch_util.py -c show -k '{}'".format(session_key)
        result = self.duthost.shell(cmd, module_ignore_errors=True)

        if result['rc'] != 0:
            logger.warning("Could not retrieve state for session {}".format(session_key))
            return None

        output_lines = result['stdout'].strip().split('\n')

        # Convert session_key from colon format to pipe format for matching
        session_key_pipe = session_key.replace(':', '|')

        for line in output_lines:
            if line.startswith('Key') or line.startswith('---'):
                continue
            if session_key_pipe in line:
                parts = line.split()
                if len(parts) >= 7:  # Ensure we have enough columns
                    state = parts[-1]  # State is the last column
                    logger.info("Session {} state: {}".format(session_key, state))
                    return state

    def wait_for_session_state(self, session_key, expected_state, timeout_ms=100):
        """Wait for session state to change within specified timeout"""
        start_time = time.time()
        timeout_sec = timeout_ms / 1000.0

        logger.info("Waiting for session {} to reach state: {}".format(session_key, expected_state))

        while (time.time() - start_time) < timeout_sec:
            current_state = self.get_session_state(session_key)
            if current_state == expected_state:
                elapsed_ms = (time.time() - start_time) * 1000
                logger.info("Session {} reached state {} in {:.2f}ms".format(
                    session_key, expected_state, elapsed_ms))
                return True

            time.sleep(0.01)  # 10ms polling interval

        elapsed_ms = (time.time() - start_time) * 1000
        logger.warning("Session {} did not reach state {} within {:.2f}ms".format(
            session_key, expected_state, elapsed_ms))
        return False

    def cleanup_sessions(self):
        """Clean up all created sessions"""
        logger.info("Cleaning up ICMP sessions")
        for session_key in self.created_sessions[:]:  # Copy list to avoid modification during iteration
            self.remove_session(session_key)


def normalize_mac_address(mac_str):
    """
    Normalize MAC address format for Snappi compatibility.
    Ensures lowercase format with colons and validates format.
    """
    if not mac_str:
        return None

    try:
        from netaddr import EUI, mac_unix_expanded
        # Parse MAC address and convert to standard format with colons
        mac = EUI(mac_str.strip())
        mac.dialect = mac_unix_expanded  # Format: xx:xx:xx:xx:xx:xx
        return str(mac).lower()
    except ImportError:
        logger.error("netaddr library is not installed. Please install it with: pip install netaddr")
        raise
    except Exception as e:
        logger.error("Failed to normalize MAC address '{}': {}".format(mac_str, e))
        raise


def get_interface_config(duthost, port_config_list):
    """
    Get interface configuration from DUT and port config.

    Returns a dict with interface_name, dut_ip, subnet_mask, remote_ip,
    dut_interface_mac, and remote_mac.
    """

    # Extract DUT interface name from port config
    if hasattr(port_config_list[0], 'peer_port'):
        interface_name = port_config_list[0].peer_port
    elif hasattr(port_config_list[0], 'peer_device_port'):
        interface_name = port_config_list[0].peer_device_port
    else:
        pytest_assert(
            False,
            "Unable to determine DUT interface from port config - "
            "neither peer_port nor peer_device_port found")

    logger.info("Using DUT interface: {}".format(interface_name))

    # Get interface configuration
    show_ip_result = duthost.shell("show ip interfaces", module_ignore_errors=True)

    # Get interface MAC address
    mac_result = duthost.shell("sudo ifconfig {}".format(interface_name), module_ignore_errors=True)
    pytest_assert(mac_result['rc'] == 0 and mac_result['stdout'].strip(),
                  "Failed to get interface configuration for {}".format(interface_name))

    ifconfig_output = mac_result['stdout']
    mac_match = re.search(
        r'(?:ether|HWaddr)\s+([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:'
        r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', ifconfig_output)
    pytest_assert(mac_match,
                  "Failed to extract MAC address from ifconfig output for {}".format(interface_name))

    discovered_mac = mac_match.group(1)
    dut_interface_mac = normalize_mac_address(discovered_mac)
    pytest_assert(dut_interface_mac, "Failed to normalize MAC address: {}".format(discovered_mac))

    # Get existing IP configuration
    pytest_assert(show_ip_result['rc'] == 0, "Failed to get IP interface configuration")

    ip_output = show_ip_result.get('stdout', '')
    dut_ip = None
    subnet_mask = None

    for line in ip_output.split('\n'):
        if line.strip().startswith(interface_name):
            parts = line.split()
            if len(parts) >= 2:
                # IP address is in the second column (parts[1])
                ip_mask = parts[1]
                if '/' in ip_mask and ip_mask != 'N/A':
                    dut_ip, subnet_mask = ip_mask.split('/')
                    break

    pytest_assert(dut_ip and subnet_mask,
                  "Failed to find valid IP configuration for interface {}".format(interface_name))

    dut_ip_parts = dut_ip.split('.')
    remote_ip = "{}.{}.{}.100".format(dut_ip_parts[0], dut_ip_parts[1], dut_ip_parts[2])
    remote_mac = "02:42:f0:00:00:02"

    return {
        'interface_name': interface_name,
        'dut_ip': dut_ip,
        'subnet_mask': subnet_mask,
        'remote_ip': remote_ip,
        'dut_interface_mac': dut_interface_mac,
        'remote_mac': remote_mac
    }


def create_icmp_payload(session_guid, seq):
    """
    Create ICMP payload with exact structure from ICMP Echo Payload specification.

    Based on the payload structure shown in the screenshot:
    - Cookie (4 bytes): Device level configuration for ICMP hw offload packets
    - Version (4 bytes): Set to 0
    - GUID MSB (4 bytes): The probing session unique identifier upper 32 bits
    - GUID LSB (4 bytes): The probing session unique identifier lower 32 bits (ToR UUID Session.GUID)
    - Sequence (8 bytes): Set to 0 (generated packets will not increment sequence)
    - TLV Type (1 byte): SENTINAL: 0xFF
    - TLV Length (2 bytes): Set to 0
    - Padding to reach minimum payload size

    Total: 27 bytes + padding = 40+ bytes minimum
    """
    try:
        # Parse session GUID - handle both hex string and integer formats
        if isinstance(session_guid, str):
            if session_guid.startswith('0x'):
                # Remove 0x prefix and convert to integer
                guid_int = int(session_guid, 16)
            else:
                # Try to parse as hex without prefix, fallback to simple conversion
                try:
                    guid_int = int(session_guid, 16)
                except ValueError:
                    # Use hash of string as GUID
                    guid_int = hash(session_guid) & 0xFFFFFFFFFFFFFFFF
        else:
            guid_int = int(session_guid) & 0xFFFFFFFFFFFFFFFF

        logger.info("Using session GUID: {} -> 0x{:016x}".format(session_guid, guid_int))

        # Build ICMP Echo Payload structure according to specification
        payload_parts = []

        # 1. Cookie (4 bytes) - Device level configuration for ICMP hw offload packets
        # Use default cookie value from ICMP_SESSION_COOKIE
        cookie_value = (int(ICMP_SESSION_COOKIE, 16)
                        if isinstance(ICMP_SESSION_COOKIE, str) and
                        ICMP_SESSION_COOKIE.startswith('0x') else 0x58767e7a)
        payload_parts.append(struct.pack('>I', cookie_value))  # Big-endian 32-bit unsigned
        logger.debug("Cookie: 0x{:08x}".format(cookie_value))

        # 2. Version (4 bytes) - Set to 0
        version = 0
        payload_parts.append(struct.pack('>I', version))  # Big-endian 32-bit unsigned
        logger.debug("Version: {}".format(version))

        # 3. GUID MSB (4 bytes) - Upper 32 bits of session identifier
        guid_msb = (guid_int >> 32) & 0xFFFFFFFF  # Upper 32 bits
        payload_parts.append(struct.pack('>I', guid_msb))  # Big-endian 32-bit unsigned
        logger.debug("GUID MSB: 0x{:08x}".format(guid_msb))

        # 4. GUID LSB (4 bytes) - Lower 32 bits of session identifier (ToR UUID Session.GUID)
        guid_lsb = guid_int & 0xFFFFFFFF  # Lower 32 bits
        payload_parts.append(struct.pack('>I', guid_lsb))  # Big-endian 32-bit unsigned
        logger.debug("GUID LSB: 0x{:08x}".format(guid_lsb))

        # 5. Sequence (8 bytes) - Set to 0 (generated packets will not increment sequence)
        sequence = 0  # As per spec: "set to 0 (generated packets will not increment sequence)"
        payload_parts.append(struct.pack('>Q', sequence))  # Big-endian 64-bit unsigned
        logger.debug("Sequence: {}".format(sequence))

        # 6. TLV Type (1 byte) - SENTINAL: 0xFF
        tlv_type = 0xFF
        payload_parts.append(struct.pack('B', tlv_type))  # Unsigned byte
        logger.debug("TLV Type: 0x{:02x}".format(tlv_type))

        # 7. TLV Length (2 bytes) - Set to 0
        tlv_length = 0
        payload_parts.append(struct.pack('>H', tlv_length))  # Big-endian 16-bit unsigned
        logger.debug("TLV Length: {}".format(tlv_length))

        # Combine all parts
        payload = b''.join(payload_parts)

        # Add padding to reach minimum ICMP payload size (typically 40+ bytes)
        current_size = len(payload)  # Should be 27 bytes (4+4+4+4+8+1+2)
        min_size = 40
        if current_size < min_size:
            padding_needed = min_size - current_size
            payload += b'\x00' * padding_needed
            logger.debug("Added {} bytes of padding".format(padding_needed))

        logger.info("Created ICMP Echo Payload: {} bytes".format(len(payload)))
        logger.info("  - Cookie: 0x{:08x} (4 bytes)".format(cookie_value))
        logger.info("  - Version: {} (4 bytes)".format(version))
        logger.info("  - GUID MSB: 0x{:08x} (4 bytes)".format(guid_msb))
        logger.info("  - GUID LSB: 0x{:08x} (4 bytes)".format(guid_lsb))
        logger.info("  - Sequence: {} (8 bytes)".format(sequence))
        logger.info("  - TLV Type: 0x{:02x} (1 byte)".format(tlv_type))
        logger.info("  - TLV Length: {} (2 bytes)".format(tlv_length))
        logger.info("  - Padding: {} bytes".format(len(payload) - 27))
        logger.info("  - Total: {} bytes".format(len(payload)))
        logger.info("Payload hex: {}".format(payload.hex()))

        return payload

    except Exception as e:
        logger.error("Failed to create structured ICMP payload: {}".format(e))
        raise RuntimeError(
            "Unable to create ICMP payload with session GUID {}: {}".format(session_guid, e))


@contextmanager
def traffic_manager(snappi_api, testbed_config):  # noqa: F811
    """Context manager for traffic lifecycle management"""
    try:
        logger.info("=== IXIA Configuration Summary ===")

        # Log devices
        if hasattr(testbed_config, 'devices') and len(testbed_config.devices) > 0:
            for i, device in enumerate(testbed_config.devices):
                logger.info("Device {}: {}".format(i, device.name))
                if hasattr(device, 'ethernets'):
                    for j, eth in enumerate(device.ethernets):
                        port_name = (eth.connection.port_name
                                     if hasattr(eth, 'connection') and
                                     hasattr(eth.connection, 'port_name') else "unknown")
                        logger.info("  Ethernet {}: MAC={}, Port={}".format(j, eth.mac, port_name))
                        if hasattr(eth, 'ipv4_addresses'):
                            for k, ipv4 in enumerate(eth.ipv4_addresses):
                                logger.info("    IPv4 {}: {}/24, Gateway={}".format(
                                    k, ipv4.address, ipv4.gateway))
        else:
            logger.info("No devices configured")

        # Log flows
        if hasattr(testbed_config, 'flows') and len(testbed_config.flows) > 0:
            for i, flow in enumerate(testbed_config.flows):
                logger.info("Flow {}: {}".format(i, flow.name))
                if hasattr(flow, 'tx_rx') and hasattr(flow.tx_rx, 'port'):
                    logger.info("  TX Port: {}".format(flow.tx_rx.port.tx_name))
                    logger.info("  RX Port: {}".format(flow.tx_rx.port.rx_name))
                if hasattr(flow, 'rate'):
                    logger.info("  Rate: {} pps".format(flow.rate.pps))
                if hasattr(flow, 'packet'):
                    try:
                        # Try to access packet layers safely
                        if len(flow.packet) > 0:
                            packet = flow.packet[0]
                            if hasattr(packet, 'ethernet'):
                                eth = packet.ethernet
                                logger.info("  Ethernet: {} -> {}".format(
                                    eth.src.value, eth.dst.value))
                            if hasattr(packet, 'ipv4'):
                                ipv4 = packet.ipv4
                                protocol_name = ("ICMP (raw packet)"
                                                 if ipv4.protocol.value == 1 else "Other")
                                logger.info("  IPv4: {} -> {} (Protocol: {})".format(
                                    ipv4.src.value, ipv4.dst.value, protocol_name))
                            if hasattr(packet, 'custom'):
                                custom = packet.custom
                                logger.info("  Custom/Raw: {} bytes (Raw ICMP packet)".format(
                                    len(custom.bytes)))
                            elif hasattr(packet, 'udp'):
                                udp = packet.udp
                                logger.info("  UDP: Port {} -> {}".format(
                                    udp.src_port.value, udp.dst_port.value))
                            elif hasattr(packet, 'icmp'):
                                icmp = packet.icmp
                                logger.info("  ICMP: Type={}, ID={}".format(
                                    icmp.echo.type.value, icmp.echo.identifier.value))
                    except Exception as e:
                        logger.info("  Could not access packet details: {}".format(e))
        else:
            logger.info("No flows configured")

        logger.info("=== End Configuration Summary ===")

        logger.info("Applying IXIA configuration")
        snappi_api.set_config(testbed_config)

        logger.info("Waiting for ARP resolution")
        wait_for_arp(snappi_api, max_attempts=30, poll_interval_sec=2)

        yield snappi_api

    except Exception as e:
        logger.error("Error in traffic context: {}".format(e))
        raise
    finally:
        try:
            logger.info("Stopping all traffic streams")
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            snappi_api.set_control_state(cs)
        except Exception as cleanup_error:
            logger.warning("Error during traffic cleanup: {}".format(cleanup_error))


def configure_icmp_host(testbed_config, port_name, host_mac, host_ip, gateway_ip):
    """
    Configure IXIA port as a host that will automatically respond to ICMP requests.

    This creates an actual IXIA device/host that will automatically respond to
    ICMP echo requests from the DUT, eliminating the need for separate streams.
    Also ensures proper ARP handling.

    Args:
        port_name: IXIA port name
        host_mac: MAC address for the host
        host_ip: IP address for the host
        gateway_ip: Gateway IP (DUT IP)
    """
    logger.info("Configuring IXIA host on port {}".format(port_name))
    logger.info("Host IP: {}, MAC: {}, Gateway: {}".format(host_ip, host_mac, gateway_ip))

    try:
        # Normalize MAC addresses for Snappi compatibility
        normalized_host_mac = normalize_mac_address(host_mac) or "02:42:f0:00:00:02"

        # Create a device on the IXIA port using correct Snappi API pattern
        device = testbed_config.devices.device(name="ICMP_Host_{}".format(port_name))[-1]

        # Create Ethernet interface using add() method
        ethernet = device.ethernets.add()
        ethernet.name = "eth_{}".format(port_name)
        ethernet.connection.port_name = port_name
        ethernet.mac = normalized_host_mac
        ethernet.mtu = 1500

        # Create IPv4 interface using add() method
        ipv4 = ethernet.ipv4_addresses.add()
        ipv4.name = "ipv4_{}".format(port_name)
        ipv4.address = host_ip
        ipv4.gateway = gateway_ip
        ipv4.prefix = 24  # /24 subnet

        logger.info("Created IXIA host device:")
        logger.info("  - Device: ICMP_Host_{}".format(port_name))
        logger.info("  - MAC: {}".format(normalized_host_mac))
        logger.info("  - IP: {}/24".format(host_ip))
        logger.info("  - Gateway: {}".format(gateway_ip))
        logger.info("  - Port: {}".format(port_name))
        logger.info("  - MTU: 1500 (ARP enabled)")

        # The device will automatically respond to ICMP echo requests and handle ARP
        logger.info("IXIA host will automatically respond to ICMP echo requests from DUT and handle ARP")
        return device

    except Exception as e:
        logger.error("Failed to configure IXIA host: {}".format(e))
        logger.info("Will rely on RX stream for ICMP functionality")
        return None


def create_rx_icmp_stream(testbed_config, tx_port, rx_port, tx_mac, rx_mac,
                          tx_ip, rx_ip, session_guid):
    """
    Create RX ICMP reply stream using snappi ICMP echo flow.

    This stream simulates the remote host (192.16.2.100) sending unsolicited ICMP echo replies
    to DUT at interface IP (192.16.2.1) every few ms with a different GUID. The DUT doesn't send
    any requests for RX sessions - it only receives and processes these periodic replies.

    Uses snappi ICMP echo flow API for proper packet construction and compatibility.

    Flow: Remote (192.16.2.100) -> ICMP Echo Reply packet (every few ms) -> DUT (192.16.2.1)
          No requests from DUT for RX sessions

    Args:
        tx_mac: Remote/IXIA MAC (source of ICMP reply)
        rx_mac: DUT interface MAC (destination of ICMP reply)
        tx_ip: Remote IP 192.16.2.100 (source of ICMP reply)
        rx_ip: DUT IP 192.16.2.1 (destination of ICMP reply)
        session_guid: Session GUID for identification in payload
    """
    logger.info("Creating RX ICMP echo reply stream (snappi flow) from {} to {} with GUID {}".format(
        tx_port, rx_port, session_guid))
    logger.info("Remote IP {} -> DUT IP {} (Snappi ICMP Echo Reply)".format(tx_ip, rx_ip))

    # Create the flow for ICMP echo replies every 50ms
    flow = testbed_config.flows.flow(name=RX_STREAM_NAME)[-1]
    flow.tx_rx.port.tx_name = tx_port
    flow.tx_rx.port.rx_name = rx_port

    # Configure transmission rate (20 PPS = 1 packet every 50ms)
    flow.rate.pps = 20
    flow.duration.continuous.delay.microseconds = 0

    # Enable metrics
    flow.metrics.enable = False

    # Normalize MAC addresses
    normalized_tx_mac = normalize_mac_address(tx_mac) or "02:42:f0:00:00:02"
    normalized_rx_mac = normalize_mac_address(rx_mac) or "40:14:82:f7:55:90"

    logger.info("RX stream using normalized MACs - src: {}, dst: {}".format(
        normalized_tx_mac, normalized_rx_mac))

    try:
        # Use snappi ICMP flow API instead of raw packet construction
        eth, ipv4, icmp = flow.packet.ethernet().ipv4().icmp()

        # Configure Ethernet header
        eth.src.value = normalized_tx_mac
        eth.dst.value = normalized_rx_mac

        # Configure IPv4 header
        ipv4.src.value = tx_ip
        ipv4.dst.value = rx_ip
        ipv4.time_to_live.value = 64

        # Configure ICMP Echo Reply
        icmp.echo.type.value = 0     # Echo Reply
        icmp.echo.code.value = 0     # Code 0
        icmp.echo.identifier.value = 0  # Identifier set to 0 as specified
        icmp.echo.sequence_number.value = 0  # Sequence set to 0 as specified

        logger.info("✓ Successfully configured ICMP Echo Reply using snappi flow API")
        logger.info("  Type: {} (Echo Reply)".format(icmp.echo.type.value))
        logger.info("  Code: {}".format(icmp.echo.code.value))
        logger.info("  Identifier: {}".format(icmp.echo.identifier.value))
        logger.info("  Sequence: {}".format(icmp.echo.sequence_number.value))

        # Set custom ICMP payload with session GUID
        try:
            # Create structured ICMP payload with session GUID
            session_payload = create_icmp_payload(
                session_guid=session_guid,
                seq=4000  # Note: seq parameter not used in new structured format
            )
            logger.info("Created structured ICMP Echo payload: {} bytes with GUID '{}'".format(
                len(session_payload), session_guid))

            # Convert payload to hex string (uppercase for snappi compatibility)
            payload_hex = session_payload.hex().upper()

            # Use flow.payload.fixed to set custom frame payload at end of ICMP packet
            # This attaches the payload after the ICMP echo header
            flow.size.fixed = 72
            flow.payload.choice = "fixed"
            flow.payload.fixed.pattern = payload_hex
            flow.payload.fixed.repeat = False  # Use exact payload, don't repeat

            logger.info("  Payload hex: {}".format(payload_hex))
            logger.info("  Payload length: {} bytes".format(len(session_payload)))

        except Exception as e:
            logger.warning("Failed to set custom ICMP payload using flow.payload: {}".format(e))
            logger.info("ICMP packet will use default payload - session identification via other means")

    except Exception as e:
        logger.error("Failed to create snappi ICMP flow: {}".format(e))
        raise RuntimeError("Unable to create ICMP flow: {}".format(e))

    logger.info("Successfully created RX ICMP Echo Reply stream with GUID {}".format(session_guid))
    logger.info("Stream rate: 20 PPS (1 packet every 50ms)")
    logger.info("ICMP Type: 0 (Echo Reply), Code: 0, ID: 0, Seq: 0")

    # Return the ICMP identifier for session mapping (now 0)
    return 0


@pytest.fixture(scope="function")
def setup_icmp_sessions(duthost):
    """
    Setup fixture for ICMP session testing.

    This fixture:
    1. Initializes ICMP session manager
    2. Cleans up any existing sessions
    3. Prepares DUT for ICMP traffic tests

    Returns:
        ICMPSessionManager - The session manager instance
    """
    logger.info("Setting up ICMP session test environment")

    # Setup ICMP session configuration
    session_manager = ICMPSessionManager(duthost)
    session_manager.initialize_icmp_util()

    yield session_manager

    # Cleanup
    session_manager.cleanup_sessions()
    logger.info("ICMP session test environment cleanup completed")


@pytest.fixture(scope="function")
def create_test_sessions(setup_icmp_sessions, snappi_testbed_config):  # noqa: F811
    """
    Create test ICMP sessions in APP_DB for testing.

    Dynamically discovers DUT interface connected to IXIA port and uses its configuration:
    1. Normal session - DUT probes remote IP and expects ICMP replies
    2. RX session - Remote host sends unsolicited ICMP replies to DUT
    """
    session_manager = setup_icmp_sessions
    duthost = session_manager.duthost
    testbed_config, port_config_list = snappi_testbed_config

    # Verify we have at least one port, skip if not available
    if len(port_config_list) < 1:
        pytest.skip("This test requires at least 1 port for IXIA traffic")

    # Use helper function to get interface configuration
    config = get_interface_config(duthost, port_config_list)
    interface_name = config['interface_name']
    dut_ip = config['dut_ip']
    # subnet_mask = config['subnet_mask']  # Not used in session creation
    remote_ip = config['remote_ip']
    dut_interface_mac = config['dut_interface_mac']
    remote_mac = config['remote_mac']

    logger.info("Using DUT interface: {} connected to IXIA port".format(interface_name))
    logger.info("Configuration: Interface={}, DUT_IP={}, Remote_IP={}".format(
        interface_name, dut_ip, remote_ip))
    logger.info("MACs: DUT={}, Remote={}".format(dut_interface_mac, remote_mac))

    # Ensure interface is up (no IP configuration changes)
    logger.info("Ensuring {} is up".format(interface_name))
    duthost.shell("config interface startup {}".format(interface_name), module_ignore_errors=True)

    # Key format: vrf:interface:session_id:type (using colon separators)
    normal_session_key = "default:{}:{}:{}".format(  # noqa: E231
        interface_name, ICMP_GUID_NORMAL, ICMP_SESSION_TYPE_NORMAL)
    normal_session_config = {
        "tx_interval": "300",  # 300ms interval for ICMP requests
        "rx_interval": "1500",  # 1.5s timeout for replies
        "session_cookie": ICMP_SESSION_COOKIE,
        "src_ip": dut_ip,  # DUT interface IP (source of requests)
        "dst_ip": remote_ip,  # Remote IP (destination of requests)
        "src_mac": dut_interface_mac,  # DUT interface MAC
        "dst_mac": remote_mac  # Remote/IXIA MAC
    }

    # RX session: Remote host sends ICMP replies to DUT (unsolicited)
    rx_session_key = "default:{}:{}:{}".format(  # noqa: E231
        interface_name, ICMP_GUID_DUMMY, ICMP_SESSION_TYPE_RX)
    rx_session_config = {
        "tx_interval": "0",  # No TX for RX session
        "rx_interval": "1500",  # Same timeout as normal session
        "session_cookie": ICMP_SESSION_COOKIE,
        "src_ip": dut_ip,  # DUT interface IP (source of requests)
        "dst_ip": remote_ip,  # Remote IP (destination of requests)
        "src_mac": dut_interface_mac,  # DUT interface MAC
        "dst_mac": remote_mac  # Remote/IXIA MAC
    }

    # Create sessions
    pytest_assert(session_manager.create_session(normal_session_key, normal_session_config),
                  "Failed to create normal ICMP session")

    pytest_assert(session_manager.create_session(rx_session_key, rx_session_config),
                  "Failed to create RX ICMP session")

    logger.info("Created test ICMP sessions successfully")

    session_data = {
        'session_manager': session_manager,
        'interface_name': interface_name,
        'dut_ip': dut_ip,
        'remote_ip': remote_ip,
        'dut_interface_mac': dut_interface_mac,
        'remote_mac': remote_mac,
        'normal_session': {
            'key': normal_session_key,
            'config': normal_session_config,
            'src_ip': dut_ip,                # DUT IP (sends requests)
            'dst_ip': remote_ip,             # Remote IP (responds to requests)
            'src_mac': dut_interface_mac,    # DUT interface MAC
            'dst_mac': remote_mac,           # Remote/IXIA MAC
            'session_id': ICMP_GUID_NORMAL
        },
        'rx_session': {
            'key': rx_session_key,
            'config': rx_session_config,
            'src_ip': dut_ip,             # Remote IP (sends unsolicited replies)
            'dst_ip': remote_ip,                # DUT IP (receives replies)
            'src_mac': dut_interface_mac,    # DUT interface MAC
            'dst_mac': remote_mac,           # Remote/IXIA MAC
            'session_id': ICMP_GUID_DUMMY
        }
    }

    yield session_data

    # No cleanup needed - we use existing interface configuration


@pytest.mark.skipif(_skip_required, reason=_skip_reason or "snappi version check failed")
def test_icmp_orchestrator_session_creation_and_state_detection(
    snappi_api,  # noqa: F811
    snappi_testbed_config,  # noqa: F811
    conn_graph_facts,  # noqa: F811
    fanout_graph_facts,  # noqa: F811
    duthost,
    create_test_sessions
):
    """
    Test ICMP orchestrator functionality with session creation and state detection.

    This test validates:
    1. Creation of ICMP sessions in APP_DB
    2. Normal session state goes UP when IXIA host responds to DUT ICMP requests
    3. RX session state goes UP when traffic starts
    4. RX session state goes DOWN when traffic stops

    Test Flow:
    1. Create NORMAL and RX sessions
    2. Configure IXIA host to respond to DUT ICMP requests (for normal session)
    3. Configure IXIA RX stream to send ICMP echo replies (for RX session)
    4. Start traffic and verify both sessions come UP
    5. Stop traffic and verify RX session goes DOWN
    """
    logger.info("=== Starting ICMP Orchestrator Session and State Detection Test ===")

    # Get test configuration
    session_data = create_test_sessions
    session_manager = session_data['session_manager']
    normal_session = session_data['normal_session']
    rx_session = session_data['rx_session']
    interface_name = session_data['interface_name']
    testbed_config, port_config_list = snappi_testbed_config

    logger.info("Testing ICMP orchestrator on interface: {}".format(interface_name))
    logger.info("DUT IP: {}, Remote IP: {}".format(
        session_data['dut_ip'], session_data['remote_ip']))
    logger.info("Normal session: DUT {} -> Remote {}".format(
        normal_session['src_ip'], normal_session['dst_ip']))
    logger.info("RX session: Remote {} -> DUT {}".format(
        rx_session['src_ip'], rx_session['dst_ip']))

    # Verify we have sufficient ports
    pytest_assert(len(port_config_list) >= 1,
                  "This test requires at least 1 port for IXIA traffic")

    logger.info("Configuring IXIA traffic streams")

    # Get the port name for the first port
    port1_name = testbed_config.ports[0].name

    # Configure IXIA host device that will automatically respond to DUT ICMP requests
    icmp_host = configure_icmp_host(
        testbed_config=testbed_config,
        port_name=port1_name,
        host_mac=session_data['remote_mac'],
        host_ip=session_data['remote_ip'],
        gateway_ip=session_data['dut_ip']
    )

    if icmp_host:
        logger.info("IXIA host configured successfully - will automatically respond to DUT ICMP requests")
        logger.info("Normal session: DUT sends ICMP requests -> IXIA host sends automatic replies")
    else:
        logger.info("IXIA host configuration failed")
        pytest.fail("Failed to configure IXIA host for automatic ICMP responses")

    # Create ONLY the RX stream for unsolicited ICMP replies
    # Normal session relies on IXIA host automatic responses to DUT requests

    # Create RX ICMP echo reply stream with different GUID
    # Remote host sends unsolicited ICMP echo replies every 50ms TO DUT
    create_rx_icmp_stream(
        testbed_config=testbed_config,
        tx_port=port1_name,
        rx_port=port1_name,
        tx_mac=session_data['remote_mac'],  # Remote/IXIA MAC (sending reply)
        rx_mac=session_data['dut_interface_mac'],  # DUT interface MAC (receiving reply)
        rx_ip=session_data['dut_ip'],  # Remote IP (source of reply)
        tx_ip=session_data['remote_ip'],  # DUT IP (destination of reply)
        session_guid=rx_session['session_id']
    )

    # Verify initial session states
    logger.info("Verifying initial session states")

    initial_normal_state = session_manager.get_session_state(normal_session['key'])
    initial_rx_state = session_manager.get_session_state(rx_session['key'])
    logger.info("Initial normal session state: {}".format(initial_normal_state))
    logger.info("Initial RX session state: {}".format(initial_rx_state))

    # Start traffic and monitor state changes
    with traffic_manager(snappi_api, testbed_config) as api:
        logger.info("Starting traffic streams")

        cs = api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
        api.set_control_state(cs)

        # Wait for traffic to flow and sessions to come up
        logger.info("Waiting for sessions to come UP...")
        time.sleep(5)

        # Check normal session state - should be UP (IXIA host responds to DUT requests)
        normal_state_after_start = session_manager.get_session_state(normal_session['key'])
        logger.info("Normal session state after traffic start: {}".format(normal_state_after_start))

        pytest_assert(normal_state_after_start == 'Up',
                      "Normal session did not come UP after traffic start. State: {}".format(
                          normal_state_after_start))

        logger.info("Normal session is UP with IXIA host responding")

        # Check RX session state - should be UP
        rx_state_after_start = session_manager.get_session_state(rx_session['key'])
        logger.info("RX session state after traffic start: {}".format(rx_state_after_start))

        pytest_assert(rx_state_after_start == 'Up',
                      "RX session did not come UP after traffic start. State: {}".format(
                          rx_state_after_start))

        logger.info("RX session is UP with traffic running")

        # Let traffic run for a bit
        time.sleep(5)

        # Stop traffic
        logger.info("Stopping traffic streams")
        cs = api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
        api.set_control_state(cs)

        # Wait for session to detect traffic loss and go down
        logger.info("Waiting for RX session to go DOWN after traffic stops...")
        time.sleep(5)

    # Check RX session state after traffic stops - should be DOWN
    rx_state_after_stop = session_manager.get_session_state(rx_session['key'])
    logger.info("RX session state after traffic stop: {}".format(rx_state_after_stop))

    pytest_assert(rx_state_after_stop == 'Down',
                  "RX session did not go DOWN after traffic stop. State: {}".format(
                      rx_state_after_stop))

    logger.info("RX session is DOWN after traffic stopped")

    logger.info("=== ICMP Orchestrator Session and State Detection Test Completed Successfully ===")


@pytest.mark.skipif(_skip_required, reason=_skip_reason or "snappi version check failed")
def test_icmp_orchestrator_tx_interval_values(
    snappi_api,                    # noqa: F811
    snappi_testbed_config,         # noqa: F811
    conn_graph_facts,              # noqa: F811
    fanout_graph_facts,            # noqa: F811
    duthost,
    setup_icmp_sessions
):
    """
    Test ICMP orchestrator normal session with different tx_interval values.

    This test validates that normal sessions remain UP with different tx_interval values:
    1. tx_interval = 3ms (very fast)
    2. tx_interval = 1200ms (slow)

    Both sessions should remain UP as long as IXIA host responds to ICMP requests.
    """
    logger.info("=== Starting ICMP Orchestrator TX Interval Test ===")

    session_manager = setup_icmp_sessions
    testbed_config, port_config_list = snappi_testbed_config

    # Get interface configuration using helper function
    config = get_interface_config(duthost, port_config_list)
    interface_name = config['interface_name']
    dut_ip = config['dut_ip']
    # subnet_mask = config['subnet_mask']  # noqa: F841
    remote_ip = config['remote_ip']
    dut_interface_mac = config['dut_interface_mac']
    remote_mac = config['remote_mac']

    logger.info("Configuration: Interface={}, DUT_IP={}, Remote_IP={}".format(
        interface_name, dut_ip, remote_ip))

    # Get the port name for the first port
    port1_name = testbed_config.ports[0].name

    # Configure IXIA host device
    icmp_host = configure_icmp_host(
        testbed_config=testbed_config,
        port_name=port1_name,
        host_mac=remote_mac,
        host_ip=remote_ip,
        gateway_ip=dut_ip
    )

    pytest_assert(icmp_host, "Failed to configure IXIA host")
    logger.info("IXIA host configured successfully")

    # Test tx_interval values
    tx_interval_tests = [
        {"value": "3", "description": "3ms (fast)"},
        {"value": "1200", "description": "1200ms (slow)"}
    ]

    for test_config in tx_interval_tests:
        tx_interval = test_config["value"]
        description = test_config["description"]

        logger.info("--- Testing tx_interval = {} ---".format(description))

        # Create unique session key for this test
        session_guid = "0x5555555{}".format(tx_interval_tests.index(test_config) + 8)
        session_key = "default:{}:{}:{}".format(  # noqa: E231
            interface_name, session_guid, ICMP_SESSION_TYPE_NORMAL)

        session_config = {
            "tx_interval": tx_interval,
            "rx_interval": "1500",
            "session_cookie": ICMP_SESSION_COOKIE,
            "src_ip": dut_ip,
            "dst_ip": remote_ip,
            "src_mac": dut_interface_mac,
            "dst_mac": remote_mac
        }

        # Create session
        pytest_assert(session_manager.create_session(session_key, session_config),
                      "Failed to create session with tx_interval={}".format(tx_interval))

        logger.info("Created session with tx_interval={}".format(tx_interval))

        try:
            # Start traffic
            with traffic_manager(snappi_api, testbed_config) as api:
                logger.info("Starting traffic")

                cs = api.control_state()
                cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
                api.set_control_state(cs)

                # Wait for session to come up
                logger.info("Waiting for session with tx_interval={} to come UP...".format(description))
                time.sleep(5)

                # Check session state - should be UP
                session_state = session_manager.get_session_state(session_key)
                logger.info("Session state with tx_interval={}: {}".format(description, session_state))

                pytest_assert(session_state == 'Up',
                              "Session with tx_interval={} did not come UP. State: {}".format(
                                  description, session_state))

                logger.info("Session with tx_interval={} is UP".format(description))

                # Let it run for a bit longer to verify stability
                time.sleep(5)

                # Verify session is still UP
                session_state_after = session_manager.get_session_state(session_key)
                logger.info("Session state after 5 more seconds: {}".format(session_state_after))

                pytest_assert(
                    session_state_after == 'Up',
                    "Session with tx_interval={} went DOWN. State: {}".format(
                        description, session_state_after))

                logger.info("Session with tx_interval={} remained UP".format(description))

                # Stop traffic
                cs = api.control_state()
                cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
                api.set_control_state(cs)

        finally:
            # Cleanup this session
            session_manager.remove_session(session_key)
            logger.info("Cleaned up session with tx_interval={}".format(description))

    logger.info("=== ICMP Orchestrator TX Interval Test Completed Successfully ===")


def create_rx_icmp_stream_with_fps(testbed_config, tx_port, rx_port, tx_mac, rx_mac,
                                   tx_ip, rx_ip, session_guid, fps, stream_name):
    """
    Create RX ICMP reply stream with configurable fps.

    Args:
        fps: Frames per second for the stream
        stream_name: Unique name for this stream
    """
    logger.info(f"Creating RX ICMP stream '{stream_name}' with {fps} fps")

    flow = testbed_config.flows.flow(name=stream_name)[-1]
    flow.tx_rx.port.tx_name = tx_port
    flow.tx_rx.port.rx_name = rx_port

    # Configure transmission rate based on fps
    flow.rate.pps = fps
    flow.duration.continuous.delay.microseconds = 0

    # Disable metrics to avoid IXIA signature
    flow.metrics.enable = False

    # Normalize MAC addresses
    normalized_tx_mac = normalize_mac_address(tx_mac) or "02:42:f0:00:00:02"
    normalized_rx_mac = normalize_mac_address(rx_mac) or "40:14:82:f7:55:90"

    # Configure ICMP Echo Reply packet
    eth, ipv4, icmp = flow.packet.ethernet().ipv4().icmp()

    eth.src.value = normalized_tx_mac
    eth.dst.value = normalized_rx_mac

    ipv4.src.value = tx_ip
    ipv4.dst.value = rx_ip
    ipv4.time_to_live.value = 64

    icmp.echo.type.value = 0     # Echo Reply
    icmp.echo.code.value = 0
    icmp.echo.identifier.value = 0
    icmp.echo.sequence_number.value = 0

    # Set custom payload with session GUID
    try:
        session_payload = create_icmp_payload(session_guid=session_guid, seq=4000)
        payload_hex = session_payload.hex().upper()
        flow.size.fixed = 72
        flow.payload.choice = "fixed"
        flow.payload.fixed.pattern = payload_hex
        flow.payload.fixed.repeat = False
    except Exception as e:
        logger.warning(f"Failed to set payload: {e}")

    logger.info(f"Created RX stream '{stream_name}' at {fps} fps ")
    return 0


@pytest.mark.skipif(_skip_required, reason=_skip_reason or "snappi version check failed")
def test_icmp_orchestrator_rx_interval_with_fps(
    snappi_api,                    # noqa: F811
    snappi_testbed_config,         # noqa: F811
    conn_graph_facts,              # noqa: F811
    fanout_graph_facts,            # noqa: F811
    duthost,
    setup_icmp_sessions
):
    """
    Test ICMP orchestrator RX session state based on rx_interval and stream fps.

    This test validates that RX session state depends on the relationship between
    rx_interval timeout and the incoming packet rate (fps).

    """
    logger.info("=== Starting ICMP Orchestrator RX Interval with FPS Test ===")

    session_manager = setup_icmp_sessions
    testbed_config, port_config_list = snappi_testbed_config

    # Get interface configuration using helper function
    config = get_interface_config(duthost, port_config_list)
    interface_name = config['interface_name']
    dut_ip = config['dut_ip']
    # subnet_mask = config['subnet_mask']  # noqa: F841
    remote_ip = config['remote_ip']
    dut_interface_mac = config['dut_interface_mac']
    remote_mac = config['remote_mac']

    logger.info("Configuration: Interface={}, DUT_IP={}, Remote_IP={}".format(
        interface_name, dut_ip, remote_ip))

    port1_name = testbed_config.ports[0].name

    # Configure IXIA host device
    icmp_host = configure_icmp_host(
        testbed_config=testbed_config,
        port_name=port1_name,
        host_mac=remote_mac,
        host_ip=remote_ip,
        gateway_ip=dut_ip
    )
    pytest_assert(icmp_host, "Failed to configure IXIA host")

    # Test cases: (rx_interval_ms, fps, expected_state)
    test_cases = [
        {"rx_interval": "9", "fps": 111, "expected": "Up", "description": "rx_interval=9ms, fps=111"},
        {"rx_interval": "500", "fps": 2, "expected": "Up", "description": "rx_interval=500ms, fps=2"},
    ]

    test_index = 0
    for test_case in test_cases:
        rx_interval = test_case["rx_interval"]
        fps = test_case["fps"]
        expected_state = test_case["expected"]
        description = test_case["description"]

        logger.info("--- Test Case: {} -> expect {} ---".format(description, expected_state))

        # Create unique session key and stream name for this test
        session_guid = "0x5555556{}".format(test_index)
        session_key = "default:{}:{}:{}".format(  # noqa: E231
            interface_name, session_guid, ICMP_SESSION_TYPE_RX)
        stream_name = "RX_Stream_Test_{}".format(test_index)

        session_config = {
            "tx_interval": "0",  # No TX for RX session
            "rx_interval": rx_interval,
            "session_cookie": ICMP_SESSION_COOKIE,
            "src_ip": dut_ip,
            "dst_ip": remote_ip,
            "src_mac": dut_interface_mac,
            "dst_mac": remote_mac
        }

        # Create RX session
        pytest_assert(session_manager.create_session(session_key, session_config),
                      "Failed to create RX session for test: {}".format(description))

        logger.info("Created RX session with rx_interval={}ms".format(rx_interval))

        # Clear any existing flows and create new stream with specified fps
        testbed_config.flows.clear()
        create_rx_icmp_stream_with_fps(
            testbed_config=testbed_config,
            tx_port=port1_name,
            rx_port=port1_name,
            tx_mac=remote_mac,
            rx_mac=dut_interface_mac,
            tx_ip=remote_ip,
            rx_ip=dut_ip,
            session_guid=session_guid,
            fps=fps,
            stream_name=stream_name
        )

        try:
            with traffic_manager(snappi_api, testbed_config) as api:
                logger.info("Starting traffic at {} fps".format(fps))

                cs = api.control_state()
                cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
                api.set_control_state(cs)

                # Wait for session state to settle
                logger.info("Waiting for session state to settle...")
                time.sleep(5)

                # Check session state
                session_state = session_manager.get_session_state(session_key)
                logger.info("Session state: {} (expected: {})".format(session_state, expected_state))

                if expected_state == "Up":
                    pytest_assert(session_state == 'Up',
                                  "Test '{}': Expected UP but got {}".format(
                                      description, session_state))
                    logger.info("✓ Test PASSED: {} -> session is UP as expected".format(description))
                else:
                    pytest_assert(session_state == 'Down',
                                  "Test '{}': Expected DOWN but got {}".format(
                                      description, session_state))
                    logger.info("✓ Test PASSED: {} -> session is DOWN as expected".format(description))

                # Stop traffic
                cs = api.control_state()
                cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
                api.set_control_state(cs)

                # Wait for session to detect traffic loss
                time.sleep(5)

                # Verify RX session goes DOWN after traffic stops
                session_state_after_stop = session_manager.get_session_state(session_key)
                logger.info("Session state after traffic stop: {} (expected: Down)".format(
                    session_state_after_stop))

                pytest_assert(
                    session_state_after_stop == 'Down',
                    "Test '{}': RX session did not go DOWN after traffic stop. "
                    "State: {}".format(description, session_state_after_stop))
                logger.info("\u2713 RX session correctly went DOWN after traffic stopped")

        finally:
            # Cleanup session
            session_manager.remove_session(session_key)
            logger.info("Cleaned up session for test: {}".format(description))

        test_index += 1

    logger.info("=== ICMP Orchestrator RX Interval with FPS Test Completed Successfully ===")
