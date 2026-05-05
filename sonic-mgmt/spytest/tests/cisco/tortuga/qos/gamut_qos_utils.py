"""
Gamut (N9164E) QoS Utilities

This module provides platform-specific utilities for Gamut/N9164E systems,
including SDK dump generation and port mapping functions.

NOTE: The port mapping must be regenerated whenever:
  1. At startup (initial topology setup)
  2. After Dynamic Port Breakout (DPB) operations that create/remove ports
  Currently, re-generation after DPB is NOT automated - callers must
  explicitly call gamut_refresh_port_mapping() after DPB operations.
"""

import re
from spytest import st

# ---------------------------------------------------------------------------
# Module-level cache for port mappings
# ---------------------------------------------------------------------------
# Cache structure: {dut_key: {ethernet_name: port_id_hex, ...}}
_gamut_port_mapping_cache = {}

# Path where SDK dump is copied to on the DUT
SDKDUMP_PATH = "/tmp/eth.out"


# ---------------------------------------------------------------------------
# SDK Dump Generation
# ---------------------------------------------------------------------------

def gamut_generate_dump(dut):
    """
    Generate SDK debug dump on a Gamut (N9164E) system.

    Executes:
      1. docker exec -it syncd bash -c "sx_api_dbg_generate_dump.py"
      2. docker cp syncd:/var/log/sdk_dbg/sdkdump /tmp/sdkdump

    The port name to id file is copied to /tmp/eth.out on the DUT for parsing.

    Args:
        dut: DUT object

    Returns:
        bool: True if dump generation succeeded, False otherwise
    """
    st.log("Gamut: Generating SDK port name -> id mapping...")

    cmd1 = 'docker exec -t syncd bash -c "sx_api_dbg_generate_dump.py; grep Ethernet /var/log/sdk_dbg/sdkdump > /eth.out"'
    output1 = st.config(dut, cmd1, skip_error_check=True)
    if output1 is None:
        st.error("Gamut: Failed to execute sx_api_dbg_generate_dump.py to generate port map")
        return False

    st.log("Gamut: SDK dump generated port map table, copying to /eth.out")

    # Remove old dump file first (may have different ownership from previous run)
    st.config(dut, f'sudo rm -f {SDKDUMP_PATH}', skip_error_check=True, trace_log=1)

    # Copy dump file from container to host
    cmd2 = f'docker cp syncd:/eth.out {SDKDUMP_PATH}'
    output2 = st.config(dut, cmd2, skip_error_check=True, trace_log=1)
    if output2 is None:
        st.error("Gamut: Failed to copy port map to {SDKDUMP_PATH}")
        return False

    st.log(f"Gamut: SDK port map available at {SDKDUMP_PATH}")
    return True


# ---------------------------------------------------------------------------
# Port Mapping Parser
# ---------------------------------------------------------------------------

def _parse_port_mapping_from_dump(dump_content):
    """
    Parse Ethernet port to internal port ID mapping from SDK dump content.

    Looks for lines like:
        511        Ethernet1_35        0x10001       Physical    1        ...
        512        Ethernet1_36        0x10005       Physical    5        ...

    Args:
        dump_content: String content of the SDK dump file

    Returns:
        dict: Mapping of {ethernet_name: port_id_hex}
              e.g., {'Ethernet1_35': '0x10001', 'Ethernet1_36': '0x10005'}
    """
    port_mapping = {}

    # Pattern to match lines with Ethernet port info:
    # Ifindex    Name           LogPort       Type        ID       Ext-Info
    # 511        Ethernet1_35   0x10001       Physical    1        ...
    #
    # We capture: Name (Ethernet*) and LogPort (0x...)
    pattern = re.compile(
        r'^\s*\d+\s+'                    # Ifindex (digits)
        r'(Ethernet\S+)\s+'              # Name (capture group 1)
        r'(0x[0-9a-fA-F]+)\s+'           # LogPort hex (capture group 2)
        r'Physical',                      # Type must be Physical
        re.MULTILINE
    )

    for match in pattern.finditer(dump_content):
        port_name = match.group(1)
        port_id = match.group(2).lower()  # Normalize to lowercase hex
        port_mapping[port_name] = port_id

    return port_mapping


def gamut_build_port_mapping(dut):
    """
    Generate SDK dump and build Ethernet port to internal ID mapping.

    This function:
      1. Generates SDK dump and ethernet to logical port mapping in /tmp/eth.out
      2. Reads the dump file from /tmp/eth.out
      3. Parses Ethernet port mappings
      4. Caches the result for future use
      5. Logs the mapping to console

    NOTE: This must be called:
      - At startup during topology initialization
      - After any Dynamic Port Breakout (DPB) operation

    Args:
        dut: DUT object

    Returns:
        dict: Mapping of {ethernet_name: port_id_hex}, or empty dict on failure
    """
    dut_key = str(dut)
    st.banner(f"Gamut: Building port mapping for {dut_key}")

    # Step 1: Generate the dump
    if not gamut_generate_dump(dut):
        st.error(f"Gamut: Failed to generate dump for {dut_key}")
        _gamut_port_mapping_cache[dut_key] = {}
        return {}

    # Step 2: Read the dump file
    cmd = f'cat {SDKDUMP_PATH}'
    dump_content = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)
    if not dump_content:
        st.error(f"Gamut: Failed to read {SDKDUMP_PATH}")
        _gamut_port_mapping_cache[dut_key] = {}
        return {}

    # Step 3: Parse the mapping
    port_mapping = _parse_port_mapping_from_dump(dump_content)

    if not port_mapping:
        st.error("Gamut: No Ethernet ports found in SDK dump")
        _gamut_port_mapping_cache[dut_key] = {}
        return {}

    # Step 4: Cache the result
    _gamut_port_mapping_cache[dut_key] = port_mapping

    # Step 5: Log the mapping
    st.log(f"Gamut: Port mapping for {dut_key} ({len(port_mapping)} ports):")
    for port_name in sorted(port_mapping.keys(), key=_port_sort_key):
        st.log(f"  {port_name} -> {port_mapping[port_name]}")

    return port_mapping


def _port_sort_key(port_name):
    """
    Sort key for Ethernet port names to sort numerically.

    Handles formats like:
      - Ethernet1_35  -> (1, 35, 0)
      - Ethernet1_5_1 -> (1, 5, 1)
    """
    # Extract all numbers from port name
    nums = re.findall(r'\d+', port_name)
    # Pad to 3 elements for consistent sorting
    while len(nums) < 3:
        nums.append('0')
    return tuple(int(n) for n in nums[:3])


# ---------------------------------------------------------------------------
# Port Mapping Accessors
# ---------------------------------------------------------------------------

def gamut_get_port_mapping(dut):
    """
    Get the cached port mapping for a DUT.

    If mapping doesn't exist in cache, builds it first.

    Args:
        dut: DUT object

    Returns:
        dict: Mapping of {ethernet_name: port_id_hex}
    """
    dut_key = str(dut)
    if dut_key not in _gamut_port_mapping_cache:
        return gamut_build_port_mapping(dut)
    return _gamut_port_mapping_cache.get(dut_key, {})


def gamut_get_port_id(dut, port_name):
    """
    Get the internal port ID for a given Ethernet port.

    Args:
        dut: DUT object
        port_name: Ethernet port name (e.g., 'Ethernet1_35')

    Returns:
        str: Port ID in hex format (e.g., '0x10001'), or None if not found
    """
    mapping = gamut_get_port_mapping(dut)
    port_id = mapping.get(port_name)
    if port_id is None:
        st.log(f"Gamut: Port {port_name} not found in mapping")
    return port_id


def gamut_refresh_port_mapping(dut):
    """
    Force refresh of port mapping (e.g., after DPB operation).

    NOTE: Call this function after Dynamic Port Breakout operations
    to update the port mapping with newly created/removed ports.

    Args:
        dut: DUT object

    Returns:
        dict: Updated mapping of {ethernet_name: port_id_hex}
    """
    dut_key = str(dut)
    st.log(f"Gamut: Refreshing port mapping for {dut_key}")

    # Clear existing cache entry
    if dut_key in _gamut_port_mapping_cache:
        del _gamut_port_mapping_cache[dut_key]

    # Rebuild mapping
    return gamut_build_port_mapping(dut)


def gamut_clear_port_mapping_cache(dut=None):
    """
    Clear port mapping cache.

    Args:
        dut: DUT object to clear cache for, or None to clear all
    """
    global _gamut_port_mapping_cache
    if dut is None:
        _gamut_port_mapping_cache = {}
        st.log("Gamut: Cleared all port mapping caches")
    else:
        dut_key = str(dut)
        if dut_key in _gamut_port_mapping_cache:
            del _gamut_port_mapping_cache[dut_key]
            st.log(f"Gamut: Cleared port mapping cache for {dut_key}")


# ---------------------------------------------------------------------------
# Port Counter Utilities
# ---------------------------------------------------------------------------

# Path where port counters are dumped
PORT_COUNTERS_PATH = "/tmp/portcounters_all.txt"


def gamut_clear_port_counters(dut):
    """
    Clear all port counters on a Gamut (N9164E) system.

    Executes:
      docker exec -t syncd bash -c "sx_api_port_counter_clear_all.py --force"

    Args:
        dut: DUT object

    Returns:
        bool: True if command executed (always returns True)
    """
    st.log("Gamut: Clearing all port counters...")

    # Clear all port counters
    # Note: Using -t instead of -it since we're not interactive
    cmd = 'docker exec -t syncd bash -c "sx_api_port_counter_clear_all.py --force"'
    st.config(dut, cmd, skip_error_check=True)

    st.log("Gamut: Port counters cleared")
    return True


def gamut_dump_port_counters(dut):
    """
    Dump all port counters to a file on the Gamut system.

    This is used by gamut_get_ecn_counters() to get counter values.
    The counters are dumped to /tmp/portcounters_all.txt.

    Args:
        dut: DUT object

    Returns:
        str: Content of the port counters dump, or None on failure
    """
    st.log("Gamut: Dumping port counters...")

    # Remove old counter file
    st.config(dut, f'sudo rm -rf {PORT_COUNTERS_PATH}', skip_error_check=True)

    # Dump port counters - using the same script but for reading (not clearing)
    # The clear script also outputs the counters, so we can use it for reading
    # Or use a read-only variant if available
    cmd = f'docker exec -t syncd bash -c "sx_api_port_counter_dump_all.py -a " > {PORT_COUNTERS_PATH}'
    st.config(dut, cmd, skip_error_check=True)

    # Read the dump file
    read_cmd = f'cat {PORT_COUNTERS_PATH}'
    content = st.show(dut, read_cmd, skip_tmpl=True, skip_error_check=True)

    if content:
        st.log(f"Gamut: Port counters dumped ({len(content)} bytes)")
        return content
    else:
        st.error("Gamut: Failed to read port counters dump")
        return None


def _parse_ecn_counter_for_port_tc(dump_content, port_id, tc):
    """
    Parse ECN counter (tx_ecn_marked_tc) for a specific port and TC from dump.

    The dump format is:
        Port 0x10001 - PER TC Counters Group
        ==================================================

        TC 0
        ----------------------
        tx_bc_frames = 0
        tx_ecn_marked_tc = 0
        tx_frames = 0
        ...

        TC 1
        ----------------------
        ...

    Args:
        dump_content: String content of port counters dump
        port_id: Port ID in hex format (e.g., '0x10001')
        tc: Traffic class (0-7)

    Returns:
        dict: Counter values including 'tx_ecn_marked_tc', 'tx_wred_discard',
              'tx_frames', 'tx_uc_frames', etc. or empty dict if not found
    """
    counters = {}

    # Normalize port_id to lowercase for matching
    port_id = port_id.lower()

    # Find the section for this port
    # Pattern: "Port 0x10001 - PER TC Counters Group"
    port_section_pattern = re.compile(
        rf'Port\s+{re.escape(port_id)}\s+-\s+PER TC Counters Group.*?(?=Port\s+0x[0-9a-fA-F]+\s+-|$)',
        re.IGNORECASE | re.DOTALL
    )

    port_match = port_section_pattern.search(dump_content)
    if not port_match:
        st.log(f"Gamut: Port {port_id} not found in counters dump")
        return counters

    port_section = port_match.group(0)

    # Find the TC section within the port section
    # Pattern: "TC 0\n----------------------\n...counters..."
    tc_section_pattern = re.compile(
        rf'TC\s+{tc}\s*\n-+\s*\n(.*?)(?=TC\s+\d+|$)',
        re.IGNORECASE | re.DOTALL
    )

    tc_match = tc_section_pattern.search(port_section)
    if not tc_match:
        st.log(f"Gamut: TC {tc} not found for port {port_id}")
        return counters

    tc_section = tc_match.group(1)

    # Parse all counters in the TC section
    # Pattern: "counter_name = value"
    counter_pattern = re.compile(r'(\w+)\s*=\s*(\d+)')

    for match in counter_pattern.finditer(tc_section):
        counter_name = match.group(1)
        counter_value = int(match.group(2))
        counters[counter_name] = counter_value

    return counters


def gamut_get_ecn_counters(dut, port_name, tc=3):
    """
    Get ECN counters for a specific port and TC on Gamut.

    This function:
      1. Dumps port counters to file
      2. Looks up the port's internal ID from the mapping table
      3. Parses the dump to find ECN counter (tx_ecn_marked_tc) for the TC

    Args:
        dut: DUT object
        port_name: Ethernet port name (e.g., 'Ethernet1_35')
        tc: Traffic class (default 3)

    Returns:
        dict: Counter values with keys:
            - 'ecn_marked_packets': tx_ecn_marked_tc value
            - 'wred_dropped_packets': tx_wred_discard value
            - 'tx_frames': total TX frames
            - 'tx_uc_frames': unicast TX frames
            - 'port_id': the internal port ID used
            - 'tc': the traffic class queried
            Returns empty counters (0) if port not found or parsing fails.
    """
    result = {
        'ecn_marked_packets': 0,
        'wred_dropped_packets': 0,
        'tx_frames': 0,
        'tx_uc_frames': 0,
        'port_id': None,
        'tc': tc
    }

    # Step 1: Get port ID from mapping
    port_id = gamut_get_port_id(dut, port_name)
    if not port_id:
        st.error(f"Gamut: Cannot get ECN counters - port {port_name} not in mapping")
        return result

    result['port_id'] = port_id
    st.log(f"Gamut: Getting ECN counters for {port_name} (ID: {port_id}), TC {tc}")

    # Step 2: Dump port counters
    dump_content = gamut_dump_port_counters(dut)
    if not dump_content:
        st.error("Gamut: Failed to dump port counters")
        return result

    # Step 3: Parse counters for this port and TC
    counters = _parse_ecn_counter_for_port_tc(dump_content, port_id, tc)

    if counters:
        result['ecn_marked_packets'] = counters.get('tx_ecn_marked_tc', 0)
        result['wred_dropped_packets'] = counters.get('tx_wred_discard', 0)
        result['tx_frames'] = counters.get('tx_frames', 0)
        result['tx_uc_frames'] = counters.get('tx_uc_frames', 0)

        st.log(f"Gamut: ECN counters for {port_name} TC{tc}: "
               f"ecn_marked={result['ecn_marked_packets']}, "
               f"wred_dropped={result['wred_dropped_packets']}, "
               f"tx_frames={result['tx_frames']}")
    else:
        st.log(f"Gamut: No counters found for {port_name} TC{tc}")

    return result


def gamut_get_ecn_counters_multi(dut, port_names, tc=3):
    """
    Get ECN counters for multiple ports on Gamut (single dump, multiple parses).

    More efficient than calling gamut_get_ecn_counters() multiple times
    as it only dumps counters once.

    Args:
        dut: DUT object
        port_names: List of Ethernet port names
        tc: Traffic class (default 3)

    Returns:
        dict: {port_name: counter_dict} where counter_dict has same format
              as gamut_get_ecn_counters() return value
    """
    results = {}

    # Initialize results with zeros
    for port_name in port_names:
        results[port_name] = {
            'ecn_marked_packets': 0,
            'wred_dropped_packets': 0,
            'tx_frames': 0,
            'tx_uc_frames': 0,
            'port_id': None,
            'tc': tc
        }

    # Dump counters once
    dump_content = gamut_dump_port_counters(dut)
    if not dump_content:
        st.error("Gamut: Failed to dump port counters for multi-port query")
        return results

    # Parse for each port
    for port_name in port_names:
        port_id = gamut_get_port_id(dut, port_name)
        if not port_id:
            st.log(f"Gamut: Skipping {port_name} - not in mapping")
            continue

        results[port_name]['port_id'] = port_id
        counters = _parse_ecn_counter_for_port_tc(dump_content, port_id, tc)

        if counters:
            results[port_name]['ecn_marked_packets'] = counters.get('tx_ecn_marked_tc', 0)
            results[port_name]['wred_dropped_packets'] = counters.get('tx_wred_discard', 0)
            results[port_name]['tx_frames'] = counters.get('tx_frames', 0)
            results[port_name]['tx_uc_frames'] = counters.get('tx_uc_frames', 0)

    # Log summary
    st.log(f"Gamut: ECN counters for {len(port_names)} ports, TC{tc}:")
    for port_name in port_names:
        r = results[port_name]
        st.log(f"  {port_name}: ecn_marked={r['ecn_marked_packets']}, "
               f"wred_dropped={r['wred_dropped_packets']}")

    return results


def _parse_cli_counters_for_port(dump_content, port_id):
    """
    Parse CLI Counters Group for a specific port from dump.

    The dump format is:
        Port 0x10001 - CLI Counters Group
        ==================================================
        port_rx_frames = 8
        port_rx_multicast = 8
        port_rx_octets = 2112
        port_tx_frames = 8
        port_tx_multicast = 8
        port_tx_octets = 2112

    Args:
        dump_content: String content of port counters dump
        port_id: Port ID in hex format (e.g., '0x10001')

    Returns:
        dict: Counter values including 'port_rx_frames', 'port_tx_frames', etc.
              or empty dict if not found
    """
    counters = {}

    # Normalize port_id to lowercase for matching
    port_id = port_id.lower()

    # Find the CLI Counters Group section for this port
    # Pattern: "Port 0x10001 - CLI Counters Group"
    cli_section_pattern = re.compile(
        rf'Port\s+{re.escape(port_id)}\s+-\s+CLI Counters Group.*?(?=Port\s+0x[0-9a-fA-F]+\s+-|$)',
        re.IGNORECASE | re.DOTALL
    )

    section_match = cli_section_pattern.search(dump_content)
    if not section_match:
        st.log(f"Gamut: CLI Counters Group not found for port {port_id}")
        return counters

    section = section_match.group(0)

    # Parse all counters in the section
    # Pattern: "counter_name = value"
    counter_pattern = re.compile(r'(port_\w+)\s*=\s*(\d+)')

    for match in counter_pattern.finditer(section):
        counter_name = match.group(1)
        counter_value = int(match.group(2))
        counters[counter_name] = counter_value

    return counters


def gamut_get_interface_counters(dut, port_name):
    """
    Get real-time interface counters for a specific port on Gamut.

    This function reads counters directly from the ASIC via sx_api_port_counter_dump_all.py,
    bypassing the counterpoll cache that can be stale. Use this instead of
    'show interface counters' on Gamut when fresh counter values are needed.

    Args:
        dut: DUT object
        port_name: Ethernet port name (e.g., 'Ethernet1_58_1')

    Returns:
        dict: Counter values with keys:
            - 'rx_frames': Received frames (port_rx_frames)
            - 'tx_frames': Transmitted frames (port_tx_frames)
            - 'rx_octets': Received bytes (port_rx_octets)
            - 'tx_octets': Transmitted bytes (port_tx_octets)
            Returns None on failure.
    """
    result = {
        'rx_frames': 0,
        'tx_frames': 0,
        'rx_octets': 0,
        'tx_octets': 0,
    }

    # Get port mapping
    port_id = gamut_get_port_id(dut, port_name)
    if port_id is None:
        st.error(f"Gamut: Cannot get interface counters - port {port_name} not in mapping")
        return None

    # Dump port counters from ASIC
    dump_content = gamut_dump_port_counters(dut)
    if not dump_content:
        st.error(f"Gamut: Failed to dump port counters")
        return None

    # Parse CLI Counters Group
    counters = _parse_cli_counters_for_port(dump_content, port_id)
    if not counters:
        st.error(f"Gamut: Failed to parse CLI counters for port {port_name} ({port_id})")
        return None

    result['rx_frames'] = counters.get('port_rx_frames', 0)
    result['tx_frames'] = counters.get('port_tx_frames', 0)
    result['rx_octets'] = counters.get('port_rx_octets', 0)
    result['tx_octets'] = counters.get('port_tx_octets', 0)

    st.log(f"Gamut: {port_name} ({port_id}) counters: "
           f"rx_frames={result['rx_frames']}, tx_frames={result['tx_frames']}")

    return result
