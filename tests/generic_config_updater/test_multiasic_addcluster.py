"""Test adding a T1 neighbor cluster to multi-ASIC SONiC via Generic Config Updater (GCU).

This module tests the ability to add/configure a downstream T1 neighbor cluster on a
multi-ASIC chassis using GCU JSON patches. The test simulates a scenario where a T1
neighbor needs to be (re)configured on existing physical ports.

Key Design Notes:
-----------------
1. PORT ENTRIES ALWAYS EXIST: After `config load_minigraph`, all physical ports defined
   in platform.json exist in CONFIG_DB, regardless of device links. The test configures
   these existing ports rather than creating them from nothing.

2. ADMIN STATUS LIFECYCLE: When port interface definitions (PortChannels, IPInterfaces)
   are removed from minigraph, the affected ports revert to defaults from port_config.ini
   which sets admin_status=down. When GCU restores the configuration, admin_status
   transitions back to 'up'. This test verifies this lifecycle.

3. RFC 6902 "add" SEMANTICS: The generated patches use "add" operations which per RFC 6902
   mean "add or replace". For existing PORT entries, this replaces the platform-default
   config (e.g., 400G) with neighbor-specific config (e.g., 100G with FEC).

4. VALID PRODUCTION SCENARIO: This test validates a realistic datacenter expansion use
   case where physical ports exist but need to be configured for a new neighbor.

See test_addcluster_workflow() docstring for detailed explanation.
"""

import json
import logging
import os
import shutil
import time
import pytest

from datetime import datetime

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import create_checkpoint, delete_checkpoint
from tests.common.utilities import wait_until
from tests.generic_config_updater.util.generate_patch import generate_config_patch, is_front_panel_port

from .util.process_minigraph import MinigraphRefactor

# Multi-ASIC addcluster tests modify BGP and interface configurations across namespaces.
# disable_intf_up_check: Skip interface up verification during config reload - on multi-ASIC
#   chassis systems, interfaces may take extended time to come up after GCU changes.
# skip_config_db_check: Skip automatic config_db restoration in core_dump_and_config_check
#   fixture - this test handles its own cleanup via checkpoint/rollback mechanism.
pytestmark = [
    pytest.mark.topology('t2'),
    pytest.mark.disable_intf_up_check,
    pytest.mark.skip_config_db_check,
]

logger = logging.getLogger(__name__)

MINIGRAPH = "/etc/sonic/minigraph.xml"
MINIGRAPH_BACKUP = "/etc/sonic/minigraph.xml.backup"
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(THIS_DIR, "templates")
ADDCLUSTER_FILE = os.path.join(TEMPLATES_DIR, "addcluster.json")

# Configuration capture settings
# Set to True to save config_db.json files and generated patches for debugging/analysis.
# Captured files are saved to: tests/generic_config_updater/captures/<hostname>/<timestamp>/
CAPTURE_CONFIGS = True


def get_capture_dir(hostname):
    """Get the directory path for captured configuration files.

    Creates a timestamped directory for storing captured configs and patches.
    Only creates the directory if CAPTURE_CONFIGS is enabled.

    Args:
        hostname: DUT hostname for directory naming

    Returns:
        str: Path to capture directory, or None if capture is disabled
    """
    if not CAPTURE_CONFIGS:
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    captures_root = os.path.join(THIS_DIR, "captures")
    capture_dir = os.path.join(captures_root, hostname, timestamp)
    os.makedirs(capture_dir, exist_ok=True)

    # Create .gitignore to prevent accidental commit of debug captures
    gitignore_path = os.path.join(captures_root, ".gitignore")
    if not os.path.exists(gitignore_path):
        with open(gitignore_path, "w") as f:
            f.write("# Auto-generated: ignore captured config files\n*\n!.gitignore\n")

    logger.info(f"Configuration capture enabled. Saving to: {capture_dir}")
    return capture_dir


def capture_config_db(duthost, namespace, capture_dir, filename, description):
    """Capture config_db.json from the DUT and save locally.

    Exports the current CONFIG_DB from Redis for the specified namespace and saves
    it to the capture directory with the given filename. Uses sonic-cfggen to dump
    the running configuration since config_db.json files don't exist on disk for
    ASIC namespaces on multi-ASIC systems.

    Args:
        duthost: DUT host object
        namespace: ASIC namespace (e.g., 'asic0') or None for host config
        capture_dir: Local directory to save captured file
        filename: Name for the saved file (without path)
        description: Human-readable description for logging

    Returns:
        str: Path to saved file, or None if capture is disabled
    """
    if not capture_dir:
        return None

    # Build namespace argument for sonic-cfggen
    ns_arg = f"-n {namespace}" if namespace and duthost.is_multi_asic else ""
    remote_path = f"/tmp/capture_{filename}"

    local_path = os.path.join(capture_dir, filename)

    logger.info(f"Capturing {description} via sonic-cfggen {ns_arg}")
    try:
        # Export CONFIG_DB from Redis to JSON file
        duthost.shell(f"sonic-cfggen -d {ns_arg} --print-data > {remote_path}")
        duthost.fetch(src=remote_path, dest=local_path, flat=True)
        duthost.shell(f"rm -f {remote_path}")
        logger.info(f"Saved {description} to {local_path}")
        return local_path
    except Exception as e:
        logger.warning(f"Failed to capture {description}: {e}")
        return None


def capture_file(src_path, capture_dir, filename, description):
    """Copy a local file to the capture directory.

    Args:
        src_path: Source file path
        capture_dir: Destination capture directory
        filename: Name for the saved file
        description: Human-readable description for logging

    Returns:
        str: Path to saved file, or None if capture is disabled
    """
    if not capture_dir:
        return None

    dest_path = os.path.join(capture_dir, filename)
    logger.info(f"Capturing {description}: {src_path} -> {dest_path}")
    try:
        shutil.copy2(src_path, dest_path)
        logger.info(f"Saved {description} to {dest_path}")
        return dest_path
    except Exception as e:
        logger.warning(f"Failed to capture {description}: {e}")
        return None


def get_downstream_t1_neighbor(duthost):
    """Get a downstream T1 neighbor from minigraph facts.

    In T2 topology, T1 neighbors are downstream devices connected to linecards.
    This function finds a T1 neighbor and returns its name along with the
    ASIC namespace it's connected to.

    Args:
        duthost: DUT host object (should be a frontend/linecard node)

    Returns:
        tuple: (asic_namespace, neighbor_name) where:
               - asic_namespace is the ASIC namespace (e.g., 'asic0')
               - neighbor_name is the T1 device name (e.g., 'ARISTA01T1')
               Returns (None, None) if no T1 neighbor found.
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    minigraph_devices = mg_facts.get('minigraph_devices', {})
    minigraph_neighbors = mg_facts.get('minigraph_neighbors', {})

    # Find a T1 neighbor from the minigraph
    for neighbor_info in minigraph_neighbors.values():
        neighbor_name = neighbor_info.get('name')
        namespace = neighbor_info.get('namespace', '')

        # Check if neighbor is a T1 device in T2 topology
        device_info = minigraph_devices.get(neighbor_name, {})
        # "LeafRouter" is an ambiguous term among vendors, but we use it here to 
        # identify T1 devices. Do we need something more robust here?
        if device_info.get('type') == 'LeafRouter':
            # Determine the ASIC namespace for this neighbor
            # namespace is empty string for single-asic or 'asicN' for multi-asic
            asic_namespace = namespace if namespace else 'asic0'
            logger.info(f"Found downstream T1 neighbor: {neighbor_name} on {asic_namespace}")
            return (asic_namespace, neighbor_name)

    return (None, None)


def get_namespace_arg(duthost, namespace):
    """Build namespace argument for CLI commands.

    For multi-ASIC systems, returns '-n {namespace}' for commands that need it.
    For single-ASIC systems, returns empty string.

    Args:
        duthost: DUT host object
        namespace: Namespace string (e.g., 'asic0') or None

    Returns:
        str: Namespace argument string, or empty string if not needed
    """
    if duthost.is_multi_asic and namespace:
        return f"-n {namespace}"
    return ""


def get_asic_index_from_namespace(namespace):
    """Extract numeric ASIC index from namespace string.

    Some commands (like vtysh) use numeric index instead of full namespace.

    Args:
        namespace: Namespace string like 'asic0' or 'asic1'

    Returns:
        int: Numeric ASIC index, or 0 if not parseable
    """
    if namespace and namespace.startswith('asic'):
        try:
            return int(namespace.replace('asic', ''))
        except ValueError:
            pass
    return 0


def get_interfaces_for_neighbor(duthost, neighbor_name):
    """Get the list of interfaces connected to a specific neighbor.

    Args:
        duthost: DUT host object
        neighbor_name: Name of the neighbor device (e.g., 'ARISTA01T1')

    Returns:
        list: List of interface names connected to the neighbor
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    minigraph_neighbors = mg_facts.get('minigraph_neighbors', {})

    interfaces = []
    for interface, neighbor_info in minigraph_neighbors.items():
        if neighbor_info.get('name') == neighbor_name:
            interfaces.append(interface)

    return interfaces


def check_ports_require_dpb(duthost, interfaces, namespace):
    """Check if any interfaces are in a breakout configuration that would require DPB.

    When a neighbor is removed and minigraph is reloaded, ports may revert to their
    native lane configuration (e.g., 400G with 8 lanes). If the current configuration
    has ports in breakout mode (e.g., 4x100G with 2 lanes each), the GCU patch cannot
    restore them without Dynamic Port Breakout (DPB) commands.

    This function uses multiple heuristics to detect breakout configurations:
    1. Port index alignment - breakout ports often have non-standard spacing
    2. Sibling ports - multiple ports sharing the same physical lane group base
    3. Speed-to-lane ratio - comparing configured speed against lane count
    4. Lane count combined with other factors

    Args:
        duthost: DUT host object
        interfaces: List of interface names to check
        namespace: ASIC namespace (e.g., 'asic0')

    Returns:
        tuple: (requires_dpb, breakout_ports) where:
               - requires_dpb: True if any ports are in breakout configuration
               - breakout_ports: Dict of {port: {'lanes': str, 'lane_count': int, 'reason': str}}
    """
    if not interfaces:
        return False, {}

    ns_arg = get_namespace_arg(duthost, namespace)
    breakout_ports = {}

    # Collect port information for all interfaces
    port_info = {}
    for interface in interfaces:
        # Skip non-Ethernet interfaces (e.g., PortChannels)
        if not interface.startswith('Ethernet'):
            continue

        # Get port configuration from CONFIG_DB
        redis_cmd = f'sonic-db-cli {ns_arg} CONFIG_DB hgetall "PORT|{interface}"'
        result = duthost.shell(redis_cmd, module_ignore_errors=True)

        if result['rc'] != 0 or not result['stdout'].strip():
            logger.warning(f"Could not get config for {interface}")
            continue

        # Parse the redis output (format: {'key1': 'val1', 'key2': 'val2', ...})
        config_str = result['stdout'].strip()
        try:
            # Handle Python dict string format from redis
            config = eval(config_str)  # Safe here as we control the source
        except (SyntaxError, ValueError):
            logger.warning(f"Could not parse config for {interface}: {config_str}")
            continue

        lanes = config.get('lanes', '')
        speed = config.get('speed', '')
        lane_count = len(lanes.split(',')) if lanes else 0

        # Extract port index number
        try:
            port_index = int(interface.replace('Ethernet', ''))
        except ValueError:
            continue

        port_info[interface] = {
            'lanes': lanes,
            'lane_count': lane_count,
            'speed': speed,
            'port_index': port_index,
            'lane_start': int(lanes.split(',')[0]) if lanes else -1
        }

    # Analyze ports for breakout indicators
    for interface, info in port_info.items():
        reasons = []
        lane_count = info['lane_count']
        port_index = info['port_index']
        speed = info['speed']
        lane_start = info['lane_start']

        # Heuristic 1: Port index alignment
        # Native 8-lane ports typically align to multiples of 8 (Ethernet0, 8, 16, 24...)
        # Native 4-lane ports align to multiples of 4
        # Breakout ports often have indices like 2, 4, 6 within an 8-port group
        if lane_count <= 2:
            # For 1-2 lane ports, check if index suggests breakout
            # (not aligned to 8-port boundary AND not the base port of a group)
            group_base = (port_index // 8) * 8
            if port_index != group_base and port_index % 4 != 0:
                reasons.append(f"port index {port_index} suggests breakout (not aligned to 4/8 boundary)")
            elif port_index % 8 != 0:
                # Index like 4, 12, 20 - could be 2x breakout of 8-lane port
                reasons.append(f"port index {port_index} may be breakout of 8-lane native port")

        # Heuristic 2: Check for sibling ports in same lane group
        # If we see Ethernet0 and Ethernet2 both with 2 lanes starting near each other,
        # they're likely breakout ports from the same physical port
        if lane_count < 8:
            group_base = (lane_start // 8) * 8 if lane_start >= 0 else -1
            siblings = [
                p for p, i in port_info.items()
                if p != interface
                and i['lane_start'] >= 0
                and (i['lane_start'] // 8) * 8 == group_base
            ]
            if siblings:
                reasons.append(f"shares lane group with sibling ports: {siblings}")

        # Heuristic 3: Speed-to-lane ratio analysis
        # Common configurations:
        # - 400G: 8 lanes (50G/lane) or 4 lanes (100G/lane PAM4)
        # - 200G: 4 lanes (50G/lane) or 2 lanes (100G/lane PAM4)
        # - 100G: 4 lanes (25G/lane), 2 lanes (50G/lane), or 1 lane (100G/lane)
        # - 50G: 2 lanes (25G/lane) or 1 lane (50G/lane)
        # - 25G/10G: 1 lane
        if speed and speed.isdigit():
            speed_gbps = int(speed) // 1000
            if lane_count > 0:
                gbps_per_lane = speed_gbps / lane_count
                # Unusual ratios may indicate breakout
                # Standard ratios: 25, 50, 100 Gbps per lane
                if gbps_per_lane not in [10, 25, 50, 100]:
                    reasons.append(f"unusual speed/lane ratio: {speed_gbps}G / {lane_count} lanes = {gbps_per_lane}G/lane")

        # Heuristic 4: Low lane count with high speed (likely PAM4 breakout)
        # 2-lane 100G is often from 4x100G breakout of 400G port
        if lane_count == 2 and speed and int(speed) >= 100000:
            reasons.append(f"{lane_count} lanes at {int(speed)//1000}G suggests breakout configuration")

        # Heuristic 5: Lane count less than 4 is almost always breakout on modern platforms
        # (except for some 25G/10G single-lane ports which are typically native)
        if lane_count < 4 and speed and int(speed) >= 50000:
            reasons.append(f"low lane count ({lane_count}) with high speed ({int(speed)//1000}G)")

        # If we have multiple strong indicators, flag as breakout
        if len(reasons) >= 2 or (lane_count <= 2 and len(reasons) >= 1):
            breakout_ports[interface] = {
                'lanes': info['lanes'],
                'lane_count': lane_count,
                'speed': speed,
                'reasons': reasons
            }
            logger.info(f"Port {interface} detected as breakout: {'; '.join(reasons)}")
        elif reasons:
            # Single weak indicator - log but don't flag
            logger.debug(f"Port {interface} has possible breakout indicator: {reasons[0]}")

    requires_dpb = len(breakout_ports) > 0
    return requires_dpb, breakout_ports


def parse_mirror_acl_bindings(acl_table_output):
    """Parse 'show acl table' output to extract MIRROR/MIRRORV6 ACL bindings.

    Parses the output of 'show acl table' command and returns the set of ports/portchannels
    that are bound to MIRROR or MIRRORV6 type ACL tables.

    Example output format:
        admin@bjw-can-7250-lc2-1:~$ show acl table
        Name        Type       Binding         Description    Stage    Status
        ----------  ---------  --------------  -------------  -------  --------
        NTP_ACL     CTRLPLANE  NTP             NTP_ACL        ingress  Active
        DATAACL     L3         Ethernet48      DATAACL        ingress  Active
                               Ethernet208
                               PortChannel101
        EVERFLOW    MIRROR     Ethernet48      EVERFLOW       ingress  Active
                               Ethernet208
                               PortChannel101
        EVERFLOWV6  MIRRORV6   Ethernet48      EVERFLOWV6     ingress  Active
                               Ethernet208
                               PortChannel101

    Args:
        acl_table_output: String output from 'show acl table' command

    Returns:
        set: Set of port/portchannel names bound to MIRROR or MIRRORV6 ACL tables
    """
    current_table = None
    mirror_bindings = set()

    for line in acl_table_output.splitlines():
        if not line.strip() or '----' in line:
            continue

        # If line starts with name, it's a new table entry
        if not line.startswith(' '):
            fields = [f for f in line.split() if f]
            if len(fields) >= 2 and fields[1] in ('MIRROR', 'MIRRORV6'):
                current_table = fields[0]
                # Capture binding on the same line as the table name (field index 2)
                if len(fields) >= 3:
                    mirror_bindings.add(fields[2])
            else:
                current_table = None
        # If line starts with space and we're in a MIRROR table, it's a binding
        elif current_table:
            port = line.strip()
            if port:
                mirror_bindings.add(port)

    return mirror_bindings


# Timeout for waiting for operational status to converge after applying patches
OPER_STATUS_CONVERGENCE_TIMEOUT = 300


def parse_interface_status_output(output, interfaces_to_check=None):
    """Parse 'show interfaces status' output and extract operational status.

    Extracts the Oper (operational) status column from SONiC's interface status table.
    The Oper column indicates whether the interface is physically up or down,
    independent of the Admin (administrative) status configuration.

    Command: show interfaces status [-n <namespace>]

    Example output:
        Interface    Lanes    Speed    MTU    FEC    Alias    Vlan    Oper    Admin    Type
        Ethernet0    0,1,2,3  100G     9100   rs     Eth1/1   routed  up      up       QSFP28
        Ethernet4    4,5,6,7  100G     9100   rs     Eth1/2   routed  down    up       QSFP28

    Args:
        output: Raw stdout from 'show interfaces status' command.
        interfaces_to_check: Optional set/list of interface names to filter.
                             If None, parses all interfaces found.

    Returns:
        dict: Mapping of interface name to operational status ('up' or 'down').
              Returns empty dict if parsing fails or no interfaces match.

    Note:
        Field positions can vary based on SONiC version and enabled features.
        This parser looks for 'up'/'down' keywords at index >= 7 to avoid
        matching non-status fields that might contain these strings.
    """
    status = {}
    # Example format:
    #   Interface    Lanes    Speed    MTU    FEC    Alias    Vlan    Oper    Admin    Type    Asym PFC
    #   Ethernet0    0,1,2,3  100G     9100   rs     Eth1/1   routed  up      up       QSFP28  off
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 9:
            continue

        interface = fields[0]
        if interfaces_to_check is not None and interface not in interfaces_to_check:
            continue

        # Oper status is typically at index 7, but field positions can vary
        # Look for 'up'/'down' pattern starting from field index 7
        for i, field in enumerate(fields):
            if field.lower() in ('up', 'down') and i >= 7:
                status[interface] = field.lower()
                break

    return status


def parse_portchannel_status_output(output, portchannels_to_check=None):
    """Parse 'show interfaces portchannel' output and extract LACP operational status.

    Extracts the operational status of port channels by looking for LACP state
    indicators. Port channels use LACP (Link Aggregation Control Protocol) to
    manage member port bundling.

    Command: show interfaces portchannel [-n <namespace>]

    Example output:
        Flags: A - active, I - inactive, Up - up, Dw - Down, N/A - not available
        No.  Team Dev       Protocol    Ports
        101  PortChannel101 LACP(A)(Up) Ethernet32(S) Ethernet36(S)
        102  PortChannel102 LACP(A)(Dw) Ethernet40(D)

    Args:
        output: Raw stdout from 'show interfaces portchannel' command.
        portchannels_to_check: Optional set/list of portchannel names to filter.
                               If None, parses all portchannels found.

    Returns:
        dict: Mapping of portchannel name to operational status ('up' or 'down').
              Returns empty dict if parsing fails or no portchannels match.

    Note:
        Status is determined by LACP state indicators:
        - 'LACP(A)(Up)' or 'Up' in fields -> 'up'
        - 'LACP(A)(Dw)' or 'Down' in fields -> 'down'
    """
    status = {}
    for line in output.splitlines():
        # Find portchannel names in the line
        for word in line.split():
            if word.startswith('PortChannel'):
                pc_name = word
                if portchannels_to_check is not None and pc_name not in portchannels_to_check:
                    continue
                # Look for LACP status indicators
                if 'LACP(A)(Up)' in line or 'Up' in line.split():
                    status[pc_name] = 'up'
                elif 'Down' in line.split() or 'LACP(A)(Dw)' in line:
                    status[pc_name] = 'down'
                break
    return status


def parse_bgp_summary_json(output, neighbors_to_check=None):
    """Parse BGP summary JSON output and extract session states for neighbors.

    Extracts BGP session states from FRRouting's JSON-formatted BGP summary.
    Session states indicate the current phase of the BGP finite state machine.

    Command: vtysh -c 'show bgp summary json' (or vtysh -n <asic> for multi-ASIC)

    Common BGP session states:
        - 'Established': Session is up and exchanging routes (operational)
        - 'Idle': Not attempting to connect
        - 'Connect': TCP connection in progress
        - 'Active': Actively trying to establish TCP connection
        - 'OpenSent': TCP connected, BGP OPEN message sent
        - 'OpenConfirm': Waiting for KEEPALIVE or NOTIFICATION

    Args:
        output: Raw stdout from vtysh BGP summary JSON command.
        neighbors_to_check: Optional set/list of neighbor IPs to filter.
                            If None, parses all neighbors found.

    Returns:
        dict: Mapping of neighbor IP to session state string.
              Returns empty dict if JSON parsing fails or output is empty.

    Note:
        Parses both ipv4Unicast and ipv6Unicast address families.
        Only 'Established' state indicates a fully operational BGP session.
    """
    states = {}
    if not output or not output.strip():
        return states

    try:
        bgp_summary = json.loads(output)
        # BGP summary JSON has different structures for IPv4/IPv6
        for af_key in ['ipv4Unicast', 'ipv6Unicast']:
            if af_key in bgp_summary:
                peers = bgp_summary[af_key].get('peers', {})
                for neighbor_ip, peer_info in peers.items():
                    if neighbors_to_check is not None and neighbor_ip not in neighbors_to_check:
                        continue
                    states[neighbor_ip] = peer_info.get('state', 'Unknown')
    except json.JSONDecodeError:
        pass

    return states


def parse_acl_table_output(output, acl_tables_to_check=None):
    """Parse 'show acl table' output and extract ACL table operational status.

    Extracts the Status column from SONiC's ACL table listing. ACL tables can be
    Active (rules are being enforced) or Inactive (table exists but not applied).

    Command: show acl table [-n <namespace>]

    Example output:
        Name        Type        Binding          Description    Stage    Status
        ----------  ----------  ---------------  -------------  -------  --------
        DATAACL     L3          Ethernet0        Data ACL       ingress  Active
        EVERFLOW    MIRROR      Ethernet0,Eth4   Everflow       ingress  Active
        SNMP_ACL    CTRLPLANE   None             SNMP Control   ingress  Inactive

    Args:
        output: Raw stdout from 'show acl table' command.
        acl_tables_to_check: Optional set/list of ACL table names to filter.
                             If None, parses all ACL tables found.

    Returns:
        dict: Mapping of ACL table name to status ('Active' or 'Inactive').
              Returns empty dict if parsing fails or no tables match.

    Note:
        Skips header lines (containing dashes) and empty lines.
        ACL table names are expected to be the first field in each data row.
    """
    status = {}
    # Example format:
    #   Name        Type        Binding          Description    Stage    Status
    #   ----------  ----------  ---------------  -------------  -------  --------
    #   DATAACL     L3          Ethernet0        Data ACL       ingress  Active
    #   EVERFLOW    MIRROR      Ethernet0        Everflow       ingress  Active
    for line in output.splitlines():
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('-'):
            continue

        fields = line.split()
        if len(fields) < 2:
            continue

        acl_name = fields[0]
        if acl_tables_to_check is not None and acl_name not in acl_tables_to_check:
            continue

        # Status is typically the last field
        if 'Active' in fields:
            status[acl_name] = 'Active'
        elif 'Inactive' in fields:
            status[acl_name] = 'Inactive'

    return status


def get_all_oper_status(duthost, asic_id, items_by_type):
    """Query operational status for multiple item types from DUT in one call.

    Consolidates status queries for ports, portchannels, BGP neighbors, and ACL
    tables into a single function. This reduces code duplication and provides
    a consistent interface for status collection used by both pre-patch snapshot
    and post-patch verification.

    Supported item types and their operational states:
        - 'port': 'up' or 'down' (from show interfaces status)
        - 'portchannel': 'up' or 'down' (from show interfaces portchannel)
        - 'bgp_neighbor': 'Established', 'Idle', etc. (from vtysh BGP summary)
        - 'acl_table': 'Active' or 'Inactive' (from show acl table)

    Args:
        duthost: DUT host object (ansible host connection).
        asic_id: ASIC namespace identifier (e.g., 'asic0', 'asic1').
                 Used for multi-ASIC DUTs to query the correct namespace.
        items_by_type: Dict mapping item type to set of names to query.
                       Only queries are made for non-empty sets.
                       Example: {
                           'port': {'Ethernet0', 'Ethernet4'},
                           'portchannel': {'PortChannel101'},
                           'bgp_neighbor': {'10.0.0.1', 'fc00::1'},
                           'acl_table': {'EVERFLOW', 'DATAACL'}
                       }

    Returns:
        dict: Flat mapping of item name to its operational status.
              Status values vary by type (see supported types above).
              Items not found in command output will not appear in result.

    Note:
        Errors during individual queries are logged but do not raise exceptions.
        Partial results are returned if some queries succeed and others fail.
    """
    all_status = {}
    ns_arg = get_namespace_arg(duthost, asic_id)
    asic_index = get_asic_index_from_namespace(asic_id)

    # Query interface status for ports (and portchannels may also appear here)
    ports = items_by_type.get('port', set())
    if ports:
        try:
            result = duthost.shell(f"show interfaces status {ns_arg}", module_ignore_errors=True)
            if result['rc'] == 0:
                all_status.update(parse_interface_status_output(result['stdout'], ports))
        except Exception as e:
            logger.warning(f"Error querying interface status: {e}")

    # Query portchannel status
    portchannels = items_by_type.get('portchannel', set())
    if portchannels:
        try:
            result = duthost.shell(f"show interfaces portchannel {ns_arg}", module_ignore_errors=True)
            if result['rc'] == 0:
                all_status.update(parse_portchannel_status_output(result['stdout'], portchannels))
        except Exception as e:
            logger.warning(f"Error querying portchannel status: {e}")

    # Query BGP neighbor session states
    bgp_neighbors = items_by_type.get('bgp_neighbor', set())
    if bgp_neighbors:
        try:
            if duthost.is_multi_asic:
                vtysh_cmd = f"sudo vtysh -n {asic_index} -c 'show bgp summary json'"
            else:
                vtysh_cmd = "sudo vtysh -c 'show bgp summary json'"

            result = duthost.shell(vtysh_cmd, module_ignore_errors=True)
            if result['rc'] == 0:
                all_status.update(parse_bgp_summary_json(result['stdout'], bgp_neighbors))
        except Exception as e:
            logger.warning(f"Error querying BGP status: {e}")

    # Query ACL table status
    acl_tables = items_by_type.get('acl_table', set())
    if acl_tables:
        try:
            result = duthost.shell(f"show acl table {ns_arg}", module_ignore_errors=True)
            if result['rc'] == 0:
                all_status.update(parse_acl_table_output(result['stdout'], acl_tables))
        except Exception as e:
            logger.warning(f"Error querying ACL table status: {e}")

    return all_status


def collect_oper_status_from_patches(duthost, phase1_patch, phase2_patch, asic_id):
    """Collect operational status for items referenced in patches that have admin_status.

    This function queries the current operational status of ports, portchannels, and
    BGP neighbors that are mentioned in the patch files and have admin_status configured.
    This pre-patch snapshot is used to verify operational status convergence after patches
    are applied.

    Args:
        duthost: DUT host object
        phase1_patch: List of patch operations for phase 1
        phase2_patch: List of patch operations for phase 2
        asic_id: ASIC namespace (e.g., 'asic0')

    Returns:
        dict: Dictionary mapping item names to their pre-patch operational status
              Format: {
                  'Ethernet32': {'oper_status': 'up', 'admin_status': 'up', 'type': 'port'},
                  'PortChannel101': {'oper_status': 'down', 'admin_status': 'up', 'type': 'portchannel'},
                  '10.0.0.1': {'oper_status': 'Established', 'admin_status': 'up', 'type': 'bgp_neighbor'},
                  'EVERFLOW': {'oper_status': 'Active', 'admin_status': None, 'type': 'acl_table'},
              }
    """
    items_to_check = {}

    # Extract ports, portchannels, BGP neighbors, and ACL tables from patches
    for patch in phase1_patch + phase2_patch:
        path = patch.get('path', '')
        value = patch.get('value', {})

        if not isinstance(value, dict):
            continue

        # Extract PORT entries (require admin_status)
        if f'/{asic_id}/PORT/' in path:
            admin_status = value.get('admin_status')
            if admin_status:
                port = path.split('/')[-1]
                if is_front_panel_port(port):
                    items_to_check[port] = {
                        'admin_status': admin_status,
                        'type': 'port',
                        'oper_status': None
                    }

        # Extract PORTCHANNEL entries (require admin_status)
        elif f'/{asic_id}/PORTCHANNEL/' in path:
            admin_status = value.get('admin_status')
            if admin_status:
                portchannel = path.split('/')[-1]
                items_to_check[portchannel] = {
                    'admin_status': admin_status,
                    'type': 'portchannel',
                    'oper_status': None
                }

        # Extract BGP_NEIGHBOR entries (require admin_status)
        elif f'/{asic_id}/BGP_NEIGHBOR/' in path:
            admin_status = value.get('admin_status')
            if admin_status:
                neighbor_ip = path.split('/')[-1]
                items_to_check[neighbor_ip] = {
                    'admin_status': admin_status,
                    'type': 'bgp_neighbor',
                    'oper_status': None  # Will be BGP session state: Established, Idle, Active, etc.
                }

        # Extract ACL_TABLE entries (no admin_status, but has 'type' field)
        # ACL tables have operational status (Active/Inactive)
        elif f'/{asic_id}/ACL_TABLE/' in path or '/ACL_TABLE/' in path:
            acl_type = value.get('type')
            if acl_type:  # Valid ACL table entry has a 'type' field
                acl_name = path.split('/')[-1]
                # Handle paths like /asic0/ACL_TABLE/EVERFLOW/ports - skip sub-paths
                if acl_name != 'ports' and not acl_name.startswith('policy'):
                    items_to_check[acl_name] = {
                        'admin_status': None,  # ACL tables don't have admin_status
                        'type': 'acl_table',
                        'acl_type': acl_type,  # Store ACL type (MIRROR, L3, etc.)
                        'oper_status': None  # Will be Active/Inactive
                    }

    if not items_to_check:
        logger.info("No items found in patches - skipping oper status collection")
        return {}

    logger.info(f"Collecting pre-patch operational status for {len(items_to_check)} items")

    # Build items_by_type dict for get_all_oper_status
    items_by_type = {}
    for name, info in items_to_check.items():
        item_type = info['type']
        if item_type not in items_by_type:
            items_by_type[item_type] = set()
        items_by_type[item_type].add(name)

    # Query all operational statuses using consolidated helper
    oper_statuses = get_all_oper_status(duthost, asic_id, items_by_type)

    # Update items_to_check with the retrieved operational statuses
    for name, status in oper_statuses.items():
        if name in items_to_check:
            items_to_check[name]['oper_status'] = status
            logger.debug(f"Pre-patch oper status for {name}: {status}")

    # Log summary
    up_count = sum(1 for info in items_to_check.values()
                   if info['oper_status'] in ('up', 'Established', 'Active'))
    down_count = sum(1 for info in items_to_check.values()
                     if info['oper_status'] in ('down', 'Inactive') or
                     (info['type'] == 'bgp_neighbor' and info['oper_status'] not in (None, 'Established')))
    unknown_count = sum(1 for info in items_to_check.values() if info['oper_status'] is None)
    logger.info(f"Pre-patch oper status summary: {up_count} up/Established/Active, "
               f"{down_count} down/not-established/Inactive, {unknown_count} unknown")

    return items_to_check


def verify_oper_status_after_patches(duthost, pre_patch_status, asic_id, timeout=OPER_STATUS_CONVERGENCE_TIMEOUT):
    """Verify operational status converges correctly after patches are applied.

    This function waits for operational status to stabilize and then verifies:
    1. Items that were operationally 'up'/'Established' before AND have admin_status='up' should be up after
    2. Items that were operationally 'down'/not-Established before are checked but only logged (not failed)
       since external factors (e.g., far-end link down, peer not ready) may prevent them from coming up

    Args:
        duthost: DUT host object
        pre_patch_status: Dictionary from collect_oper_status_from_patches()
        asic_id: ASIC namespace (e.g., 'asic0')
        timeout: Seconds to wait for status convergence (default: 300)

    Returns:
        tuple: (success, failures, warnings) where:
               - success: True if all required items are operationally up/Established
               - failures: List of items that failed verification
               - warnings: List of items that were down before and still down
    """
    if not pre_patch_status:
        logger.info("No pre-patch status recorded - skipping oper status verification")
        return True, [], []

    failures = []
    warnings = []

    # Helper to check if an item was "up" (handles ports, BGP, and ACL tables)
    def was_operationally_up(info):
        if info['type'] == 'bgp_neighbor':
            return info['oper_status'] == 'Established'
        elif info['type'] == 'acl_table':
            return info['oper_status'] == 'Active'
        else:
            return info['oper_status'] == 'up'

    # Helper to check if an item was "down" (handles ports, BGP, and ACL tables)
    def was_operationally_down(info):
        if info['type'] == 'bgp_neighbor':
            # BGP states other than Established are considered "down"
            return info['oper_status'] is not None and info['oper_status'] != 'Established'
        elif info['type'] == 'acl_table':
            return info['oper_status'] == 'Inactive'
        else:
            return info['oper_status'] == 'down'

    # Items that MUST come up: were 'up'/'Established'/'Active' before
    # For ports/portchannels: also need admin_status='up'
    # For ACL tables: no admin_status, just check if was Active
    # For BGP: need admin_status='up' (from config)
    must_be_up = {
        name: info for name, info in pre_patch_status.items()
        if was_operationally_up(info) and (
            info['type'] == 'acl_table' or  # ACL tables don't have admin_status
            info['admin_status'] == 'up'
        )
    }

    # Items that MUST be down: configured with admin_status='down' in the patch
    # These items should be operationally down after patches are applied
    must_be_down = {
        name: info for name, info in pre_patch_status.items()
        if info.get('admin_status') == 'down' and info['type'] != 'acl_table'
    }

    # Items that were down before - we'll check but only warn
    # For ACL tables: was Inactive
    # For ports/portchannels: was down with admin_status='up'
    # For BGP: was not Established with admin_status='up'
    was_down = {
        name: info for name, info in pre_patch_status.items()
        if was_operationally_down(info) and (
            info['type'] == 'acl_table' or
            info['admin_status'] == 'up'
        )
    }

    # Categorize by type for logging
    port_must_up = sum(1 for info in must_be_up.values() if info['type'] == 'port')
    pc_must_up = sum(1 for info in must_be_up.values() if info['type'] == 'portchannel')
    bgp_must_up = sum(1 for info in must_be_up.values() if info['type'] == 'bgp_neighbor')
    acl_must_up = sum(1 for info in must_be_up.values() if info['type'] == 'acl_table')

    port_must_down = sum(1 for info in must_be_down.values() if info['type'] == 'port')
    pc_must_down = sum(1 for info in must_be_down.values() if info['type'] == 'portchannel')

    logger.info(f"Waiting up to {timeout}s for operational status to converge...")
    logger.info(f"  - {len(must_be_up)} items must be operationally up/Established/Active "
               f"(ports: {port_must_up}, portchannels: {pc_must_up}, BGP: {bgp_must_up}, ACL: {acl_must_up})")
    logger.info(f"  - {len(must_be_down)} items must be operationally down (admin_status='down') "
               f"(ports: {port_must_down}, portchannels: {pc_must_down})")
    logger.info(f"  - {len(was_down)} items were down/Inactive before with admin_status='up' (will check but only warn)")

    # Build items_by_type for status queries - include all items we need to check
    all_items_to_check = set(must_be_up.keys()) | set(must_be_down.keys()) | set(was_down.keys())
    items_by_type = {}
    for name in all_items_to_check:
        info = pre_patch_status.get(name, {})
        item_type = info.get('type')
        if item_type:
            if item_type not in items_by_type:
                items_by_type[item_type] = set()
            items_by_type[item_type].add(name)

    # Helper to get expected operational state based on item type
    def get_expected_state(info):
        if info['type'] == 'bgp_neighbor':
            return 'Established'
        elif info['type'] == 'acl_table':
            return 'Active'
        else:
            return 'up'

    def check_oper_status():
        """Check if all must_be_up items are up and must_be_down items are down."""
        current_status = get_all_oper_status(duthost, asic_id, items_by_type)

        # Check if all must_be_up items are up/Established/Active
        all_up = True
        for name, info in must_be_up.items():
            current = current_status.get(name)
            expected = get_expected_state(info)
            if current != expected:
                all_up = False

        # Check if all must_be_down items are down
        all_down = True
        for name in must_be_down.keys():
            if current_status.get(name) != 'down':
                all_down = False

        if not all_up:
            not_up = [name for name, info in must_be_up.items()
                      if current_status.get(name) != get_expected_state(info)]
            logger.debug(f"Still waiting for {len(not_up)} items to come up: {not_up[:5]}...")

        if not all_down:
            not_down = [name for name in must_be_down.keys() if current_status.get(name) != 'down']
            logger.debug(f"Still waiting for {len(not_down)} items to go down: {not_down[:5]}...")

        return all_up and all_down

    # Wait for convergence
    if must_be_up or must_be_down:
        converged = wait_until(timeout, 10, 30, check_oper_status)  # Check every 10s, initial delay 30s

        if not converged:
            logger.error(f"Operational status did not converge within {timeout}s")
    else:
        # If nothing must be up or down, just wait a bit for stability
        logger.info(f"No items required to be up or down - waiting 60s for stability")
        time.sleep(60)
        converged = True

    # Final status check and collect results
    logger.info("Performing final operational status verification...")
    final_status = get_all_oper_status(duthost, asic_id, items_by_type)

    # Verify must_be_up items
    for name, info in must_be_up.items():
        current = final_status.get(name)
        expected = get_expected_state(info)

        if current != expected:
            failures.append({
                'name': name,
                'type': info['type'],
                'pre_patch_oper': info['oper_status'],
                'post_patch_oper': current,
                'admin_status': info.get('admin_status')  # ACL tables don't have admin_status
            })
            admin_info = f"admin_status='{info['admin_status']}', " if info.get('admin_status') else ""
            logger.error(f"FAIL: {name} ({info['type']}) was operationally '{info['oper_status']}' before patch, "
                        f"{admin_info}but is now '{current}'")
        else:
            logger.info(f"PASS: {name} ({info['type']}) is operationally '{expected}' as expected")

    # Verify must_be_down items (configured with admin_status='down')
    for name, info in must_be_down.items():
        current = final_status.get(name)

        if current != 'down':
            failures.append({
                'name': name,
                'type': info['type'],
                'pre_patch_oper': info['oper_status'],
                'post_patch_oper': current,
                'admin_status': 'down'
            })
            logger.error(f"FAIL: {name} ({info['type']}) has admin_status='down' in patch, "
                        f"but oper_status is '{current}' (expected 'down')")
        else:
            logger.info(f"PASS: {name} ({info['type']}) is operationally 'down' as expected (admin_status='down')")

    # Check was_down items (warn only)
    for name, info in was_down.items():
        current = final_status.get(name)
        expected = get_expected_state(info)
        was_state = info['oper_status']

        if current != expected:
            warnings.append({
                'name': name,
                'type': info['type'],
                'pre_patch_oper': was_state,
                'post_patch_oper': current,
                'admin_status': info.get('admin_status')  # ACL tables don't have admin_status
            })
            logger.warning(f"INFO: {name} ({info['type']}) was operationally '{was_state}' before patch and "
                          f"is now '{current}'. This may be due to external factors.")
        else:
            logger.info(f"IMPROVED: {name} ({info['type']}) was '{was_state}' before but is now '{expected}'")

    success = len(failures) == 0
    total_checked = len(must_be_up) + len(must_be_down)
    logger.info(f"Oper status verification complete: {total_checked - len(failures)}/{total_checked} passed "
               f"({len(must_be_up)} must-be-up, {len(must_be_down)} must-be-down), "
               f"{len(warnings)} warnings for previously-down items")

    return success, failures, warnings


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_front_end_hostname):
    """Setup and teardown fixture using a frontend (linecard) DUT.

    Uses rand_one_dut_front_end_hostname to ensure we get a linecard in T2 topology,
    which is where downstream T1 neighbors are connected.

    Teardown Strategy:
    ------------------
    This test uses config_reload() instead of GCU rollback for cleanup because:

    1. The test modifies minigraph.xml (removes target_t1 neighbor)
    2. Reloads config from the modified minigraph
    3. Applies GCU patches on top of that modified config

    GCU rollback would need to compute a diff from this complex state back to the
    original checkpoint, which consistently fails due to:
    - YANG validation errors on intermediate states
    - Dependency ordering issues with the patch sorter
    - References to ports/interfaces that exist in checkpoint but not in current minigraph

    Since we backup the original minigraph before modification, restoring it and doing
    a config_reload reliably returns the DUT to its original state. This achieves the
    same cleanup goal without the fragility of GCU rollback.

    Note: This test validates GCU apply_patch functionality, not rollback. Rollback
    is tested separately in other GCU test modules.
    """
    duthost = duthosts[rand_one_dut_front_end_hostname]
    create_checkpoint(duthost)
    yield
    try:
        # Restore original minigraph if it was backed up during the test.
        # The test modifies minigraph.xml to remove target_t1, so we must
        # restore it before config_reload to get back to the original state.
        if duthost.stat(path=MINIGRAPH_BACKUP)["stat"]["exists"]:
            logger.info(f"Restoring original minigraph from {MINIGRAPH_BACKUP}")
            duthost.shell(f"sudo cp {MINIGRAPH_BACKUP} {MINIGRAPH}")
            duthost.shell(f"sudo rm -f {MINIGRAPH_BACKUP}")

        # Use config_reload instead of rollback_or_reload() for reliable cleanup.
        # See docstring above for detailed rationale.
        logger.info("Reloading minigraph to restore original configuration")
        config_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def test_addcluster_workflow(duthosts, rand_one_dut_front_end_hostname):
    """Test adding a downstream T1 neighbor cluster via GCU.

    This test validates that a T1 neighbor can be added to a multi-ASIC
    SONiC device using GCU JSON patches.

    Test Approach - Port Configuration vs Port Creation
    ---------------------------------------------------
    This test validates RECONFIGURING existing ports, not creating ports from nothing.
    After `config load_minigraph`, physical ports ALWAYS exist in CONFIG_DB because
    the minigraph parser generates PORT entries from platform.json/hwsku.json for ALL
    physical ports, regardless of whether they have device links defined.

    When the target neighbor is removed from the minigraph:
    - PORT entries remain (at platform defaults: e.g., 400G, 8-lane, admin_status=up)
    - DEVICE_NEIGHBOR entries are removed
    - BGP_NEIGHBOR entries are removed
    - PORT_QOS_MAP, PFC_WD entries are removed

    The generated patch uses RFC 6902 "add" operations which means "add or replace":
    - For PORT: Replaces existing 400G/8-lane config with neighbor-specific config (e.g., 100G/4-lane)
    - For other tables: Creates new entries that didn't exist

    This represents a valid production scenario: "Configuring existing but unused ports
    for a new T1 neighbor" - typical for datacenter expansion where physical ports exist
    but aren't yet configured for any neighbor.

    Note: True "add ports from nothing" would only apply to Dynamic Port Breakout (DPB)
    scenarios where ports are dynamically created/deleted, which requires different
    test design and DPB-capable platforms.

    The test:
    1. Uses a frontend/linecard DUT (rand_one_dut_front_end_hostname)
    2. Dynamically discovers a T1 neighbor from minigraph facts
    3. Tests on the specific ASIC where the T1 neighbor is connected

    Args:
        duthosts: DUT hosts fixture
        rand_one_dut_front_end_hostname: Fixture that provides a frontend DUT hostname
    """
    duthost = duthosts[rand_one_dut_front_end_hostname]

    # Dynamically discover a downstream T1 neighbor
    asic_id, target_t1 = get_downstream_t1_neighbor(duthost)
    if not target_t1:
        pytest.skip("No downstream T1 neighbor found in minigraph")

    # Build namespace argument for CLI commands (handles single-ASIC vs multi-ASIC)
    ns_arg = get_namespace_arg(duthost, asic_id)
    asic_index = get_asic_index_from_namespace(asic_id)
    logger.info(f"Testing with downstream T1 neighbor: {target_t1} on {asic_id} (ns_arg='{ns_arg}', index={asic_index})")

    # Step 0: Check for Dynamic Port Breakout (DPB) requirements
    # -------------------------------------------------------------------------
    # If any ports connected to the target neighbor are in breakout configuration,
    # removing the neighbor and reloading minigraph will revert those ports to their
    # native lane configuration. The GCU patch cannot restore breakout configurations
    # because it only handles CONFIG_DB changes, not hardware lane remapping.
    #
    # Skip the test if DPB would be required to restore the configuration.
    # -------------------------------------------------------------------------
    neighbor_interfaces = get_interfaces_for_neighbor(duthost, target_t1)
    logger.info(f"Interfaces connected to {target_t1}: {neighbor_interfaces}")

    requires_dpb, breakout_ports = check_ports_require_dpb(duthost, neighbor_interfaces, asic_id)
    if requires_dpb:
        # Build detailed skip message with detection reasons
        port_details = []
        for port, info in breakout_ports.items():
            reasons = info.get('reasons', [])
            reason_str = "; ".join(reasons) if reasons else "low lane count"
            port_details.append(f"{port} ({info['lane_count']} lanes, {info.get('speed', 'unknown')} speed): {reason_str}")
        breakout_info = "\n  - ".join(port_details)
        pytest.skip(
            f"Test requires Dynamic Port Breakout (DPB) which is not supported. "
            f"Ports detected as breakout configuration:\n  - {breakout_info}\n"
            f"These ports would revert to native lane config after minigraph reload."
        )

    # Initialize config capture directory (if enabled)
    capture_dir = None
    if CAPTURE_CONFIGS:
        capture_dir = get_capture_dir(duthost.hostname)
        logger.info(f"Config capture enabled. Saving snapshots to: {capture_dir}")

        # Capture initial CONFIG_DB state (before any test modifications)
        capture_config_db(duthost, asic_id, capture_dir,
                          "01_initial_config_db.json",
                          "Initial CONFIG_DB state before test modifications")

    # Step 1: Backup minigraph
    logger.info(f"Backing up current minigraph from {MINIGRAPH} to {MINIGRAPH_BACKUP}")
    if not duthost.stat(path=MINIGRAPH)["stat"]["exists"]:
        pytest.fail(f"{MINIGRAPH} not found on DUT")
    duthost.shell(f"sudo cp {MINIGRAPH} {MINIGRAPH_BACKUP}")

    # Step 1.1: Reload minigraph
    logger.info("Reloading minigraph using 'config load_minigraph -y'")
    duthost.shell("sudo config load_minigraph -y", module_ignore_errors=False)
    if not wait_until(300, 20, 0, duthost.critical_services_fully_started):
        logger.error("Not all critical services fully started!")
        pytest.fail("Critical services not fully started after minigraph reload")

    # Step 2: Capture full running configuration
    logger.info("Capturing full running configuration")
    dut_config_path = "/tmp/all.json"
    full_config_path = os.path.join(THIS_DIR, "backup", f"{duthost.hostname}-all.json")
    os.makedirs(os.path.dirname(full_config_path), exist_ok=True)
    duthost.shell(f"show runningconfiguration all > {dut_config_path}")

    duthost.fetch(src=dut_config_path, dest=full_config_path, flat=True)
    logger.info(f"Saved full configuration backup to {full_config_path}")
    duthost.shell(f"rm -f {dut_config_path}")

    # Step 3: Modify minigraph to remove target_t1
    # This removes the neighbor device AND all port interface definitions (PortChannels,
    # IPInterfaces) that use the ports connected to this neighbor. After minigraph reload,
    # these ports should have admin_status=down (defaults from port_config.ini).
    logger.info(f"Modifying minigraph to remove {target_t1}")
    local_dir = "/tmp/minigraph_modified"
    local_minigraph = os.path.join(local_dir, f"{duthost.hostname}-minigraph.xml")
    duthost.fetch(src=MINIGRAPH, dest=local_minigraph, flat=True)
    refactor = MinigraphRefactor(target_t1)
    success, affected_ports = refactor.process_minigraph(local_minigraph, local_minigraph)
    if not success:
        logger.info(f"Skipping test - testbed topology does not match required conditions for {target_t1}")
        pytest.skip(f"Testbed topology does not match required conditions for {target_t1}")
    logger.info(f"Minigraph modification complete. Affected ports: {sorted(affected_ports)}")
    duthost.copy(src=local_minigraph, dest=MINIGRAPH)

    # Step 4: Reload minigraph
    logger.info("Reloading minigraph using 'config load_minigraph -y'")
    duthost.shell("sudo config load_minigraph -y", module_ignore_errors=False)
    if not wait_until(300, 20, 0, duthost.critical_services_fully_started):
        logger.error("Not all critical services fully started!")
        pytest.fail("Critical services not fully started after minigraph reload")

    # Step 4.1: Verify affected ports have admin_status=down after minigraph reload
    # When port interface definitions are removed from minigraph, the ports should
    # fall back to defaults from port_config.ini which sets admin_status=down.
    if affected_ports:
        logger.info(f"Verifying admin_status=down for affected ports: {sorted(affected_ports)}")
        for port in affected_ports:
            redis_cmd = f'sonic-db-cli {ns_arg} CONFIG_DB hget "PORT|{port}" admin_status'
            result = duthost.shell(redis_cmd, module_ignore_errors=True)
            admin_status = result['stdout'].strip() if result['rc'] == 0 else "unknown"
            if admin_status != "down":
                logger.warning(f"Port {port} has admin_status={admin_status}, expected 'down'")
                # Note: We warn rather than fail because some platforms may have different defaults
            else:
                logger.info(f"Verified port {port} has admin_status=down (as expected)")

    # Capture pre-patch CONFIG_DB state (neighbor removed via minigraph)
    if CAPTURE_CONFIGS and capture_dir:
        capture_config_db(duthost, asic_id, capture_dir,
                          "02_pre_patch_config_db.json",
                          f"CONFIG_DB after minigraph reload without {target_t1}")

    # Step 5: Capture full running configuration without target_t1
    logger.info(f"Capturing full running configuration without {target_t1}")
    dut_config_path = "/tmp/all-without-t1.json"
    no_t1_config_path = os.path.join(THIS_DIR, "backup", f"{duthost.hostname}-all-without-t1.json")
    os.makedirs(os.path.dirname(no_t1_config_path), exist_ok=True)
    duthost.shell(f"show runningconfiguration all > {dut_config_path}")

    duthost.fetch(src=dut_config_path, dest=no_t1_config_path, flat=True)
    logger.info(f"Saved full configuration without {target_t1} backup to {no_t1_config_path}")
    duthost.shell(f"rm -f {dut_config_path}")

    # step 6: Generate patch files
    # NOTE: Patches are split into two phases due to a GCU sorter limitation/bug.
    # The GCU patch sorter fails with "'PortX' is not in list" when a PORT is being
    # added in the same batch as an ACL_TABLE that references that PORT.
    # Phase 1: Core config (PORT, INTERFACE, BGP_NEIGHBOR, etc.)
    # Phase 2: ACL_TABLE entries (applied after ports exist)
    logger.info("Generating patch files (two phases)")
    phase1_file, phase2_file = generate_config_patch(full_config_path, no_t1_config_path)

    # Capture the generated patch files
    if CAPTURE_CONFIGS and capture_dir:
        capture_file(phase1_file, capture_dir,
                     "03a_generated_patch_phase1.json",
                     f"Phase 1 GCU patch (core config) for {target_t1}")
        capture_file(phase2_file, capture_dir,
                     "03b_generated_patch_phase2.json",
                     f"Phase 2 GCU patch (ACL bindings) for {target_t1}")

    # Note: We don't need to pre-create tables - the main patch will create them
    # with actual data. ConfigDb doesn't allow empty tables anyway.

    # Step 7: Apply patches in two phases
    # Phase 1: Core configuration (PORT, INTERFACE, BGP_NEIGHBOR, etc.)
    logger.info("Applying Phase 1 patch (core configuration)")
    with open(phase1_file) as file:
        phase1_patch = json.load(file)

    # Load Phase 2 patch now as well so we can collect pre-patch operational status
    with open(phase2_file) as file:
        phase2_patch = json.load(file)

    # Step 7a: Collect pre-patch operational status for items with admin_status
    # -------------------------------------------------------------------------
    # Before applying any patches, record the operational status of ports/portchannels
    # that have admin_status configured. This allows us to verify that items that
    # were operationally 'up' before remain 'up' after patches are applied.
    # -------------------------------------------------------------------------
    logger.info("Collecting pre-patch operational status for items in patches")
    pre_patch_oper_status = collect_oper_status_from_patches(
        duthost, phase1_patch, phase2_patch, asic_id
    )

    # Extract information to check from phase 1 patch
    ports_to_check = set()
    portchannels_to_check = set()
    bgp_neighbors_to_check = set()
    # NOTE: BUFFER_PG is excluded because on dynamic buffer model platforms (like Cisco-8000),
    # buffer profiles are auto-generated by the buffer manager once PORT and CABLE_LENGTH are set.
    config_entries_to_check = {
        'DEVICE_NEIGHBOR_METADATA': set(),
        'CABLE_LENGTH': set(),
        'PORT_QOS_MAP': set(),
        'PFC_WD': set(),
        'PORTCHANNEL_MEMBER': set(),
        'DEVICE_NEIGHBOR': set()
    }
    for patch_entry in phase1_patch:
        path = patch_entry.get('path', '')
        if path.startswith(f'/{asic_id}/PORT/'):
            port = path.split('/')[-1]
            ports_to_check.add(port)
        elif path.startswith(f'/{asic_id}/PORTCHANNEL/'):
            portchannel = path.split('/')[-1]
            portchannels_to_check.add(portchannel)
        elif path.startswith(f'/{asic_id}/PORTCHANNEL_MEMBER/'):
            entry = path.split('/')[-1]
            config_entries_to_check['PORTCHANNEL_MEMBER'].add(f"PORTCHANNEL_MEMBER|{entry}")
        elif path.startswith(f'/{asic_id}/BGP_NEIGHBOR/'):
            neighbor = path.split('/')[-1]
            bgp_neighbors_to_check.add(neighbor)
        elif path.startswith(f'/{asic_id}/DEVICE_NEIGHBOR_METADATA/'):
            entry = path.split('/')[-1]
            config_entries_to_check['DEVICE_NEIGHBOR_METADATA'].add(f"DEVICE_NEIGHBOR_METADATA|{entry}")
        elif path.startswith(f'/{asic_id}/DEVICE_NEIGHBOR/'):
            entry = path.split('/')[-1]
            config_entries_to_check['DEVICE_NEIGHBOR'].add(f"DEVICE_NEIGHBOR|{entry}")
        elif path.startswith(f'/{asic_id}/CABLE_LENGTH/AZURE/'):
            entry = path.split('/')[-1]
            config_entries_to_check['CABLE_LENGTH'].add(f"{entry}")
        elif path.startswith(f'/{asic_id}/PORT_QOS_MAP/'):
            entry = path.split('/')[-1]
            config_entries_to_check['PORT_QOS_MAP'].add(f"PORT_QOS_MAP|{entry}")
        elif path.startswith(f'/{asic_id}/PFC_WD/'):
            entry = path.split('/')[-1]
            config_entries_to_check['PFC_WD'].add(f"PFC_WD|{entry}")

    # Apply Phase 1 patch (core configuration)
    tmpfile = generate_tmpfile(duthost)
    try:
        apply_patch_result = apply_patch(duthost, json_data=phase1_patch, dest_file=tmpfile)
        if apply_patch_result['rc'] != 0 or "Patch applied successfully" not in apply_patch_result['stdout']:
            pytest.fail(f"Failed to apply Phase 1 patch: {apply_patch_result['stdout']}")
        logger.info("Phase 1 patch applied successfully")
    finally:
        delete_tmpfile(duthost, tmpfile)

    # Step 7.1: Apply Phase 2 patch (ACL bindings)
    # This is done separately due to GCU sorter limitation - it cannot handle
    # PORT additions and ACL_TABLE updates referencing those ports in the same batch.
    logger.info("Applying Phase 2 patch (ACL bindings)")
    # Note: phase2_patch was already loaded earlier for pre-patch oper status collection

    # Extract ACL-bound ports from phase 2 patch for verification
    acl_bound_ports = set()
    for patch_entry in phase2_patch:
        path = patch_entry.get('path', '')
        if path.startswith(f'/{asic_id}/ACL_TABLE/'):
            value = patch_entry.get('value', {})
            if isinstance(value, dict):
                acl_type = value.get('type', '')
                if acl_type in ('MIRROR', 'MIRRORV6'):
                    ports_list = value.get('ports', [])
                    if isinstance(ports_list, list):
                        for port in ports_list:
                            if is_front_panel_port(port):
                                acl_bound_ports.add(port)

    if phase2_patch:
        tmpfile = generate_tmpfile(duthost)
        try:
            apply_patch_result = apply_patch(duthost, json_data=phase2_patch, dest_file=tmpfile)
            if apply_patch_result['rc'] != 0 or "Patch applied successfully" not in apply_patch_result['stdout']:
                pytest.fail(f"Failed to apply Phase 2 patch: {apply_patch_result['stdout']}")
            logger.info("Phase 2 patch applied successfully")
        finally:
            delete_tmpfile(duthost, tmpfile)
    else:
        logger.info("Phase 2 patch is empty (no ACL changes) - skipping")

    # Step 8: Verify operational status convergence
    # -------------------------------------------------------------------------
    # Wait for operational status to converge and verify that items which were
    # operationally 'up' before the patches AND have admin_status='up' in config
    # are also operationally 'up' after the patches are applied.
    #
    # For items that were operationally 'down' before patches:
    # - Only log a warning if still down (don't fail)
    # - External factors (e.g., far-end link down) may prevent them from coming up
    # -------------------------------------------------------------------------
    if pre_patch_oper_status:
        logger.info("Verifying operational status convergence after patches")
        oper_success, oper_failures, oper_warnings = verify_oper_status_after_patches(
            duthost, pre_patch_oper_status, asic_id, timeout=OPER_STATUS_CONVERGENCE_TIMEOUT
        )

        if not oper_success:
            failure_details = "\n".join([
                f"  - {f['name']} ({f['type']}): was '{f['pre_patch_oper']}' -> now '{f['post_patch_oper']}' "
                f"(admin_status={f['admin_status']})"
                for f in oper_failures
            ])
            pytest.fail(
                f"Operational status verification failed for {len(oper_failures)} item(s):\n{failure_details}\n"
                f"These items were operationally 'up' before patches and have admin_status='up', "
                f"but are not operationally 'up' after patches were applied."
            )

        if oper_warnings:
            logger.warning(f"{len(oper_warnings)} item(s) were down before and remain down - "
                          f"this may be due to external factors")
    else:
        logger.info("No pre-patch operational status recorded - skipping oper status verification")

    # Capture post-patch CONFIG_DB state
    if CAPTURE_CONFIGS and capture_dir:
        capture_config_db(duthost, asic_id, capture_dir,
                          "04_post_patch_config_db.json",
                          f"CONFIG_DB after GCU patches applied for {target_t1}")
        logger.info(f"Config capture complete. All snapshots saved to: {capture_dir}")

    # Step 9: Verify port configuration restoration
    # -------------------------------------------------------------------------
    # IMPORTANT: This test validates CONFIGURATION RESTORATION, not operational status.
    # We verify that ports which existed in the original configuration are correctly
    # restored by the GCU patch, with all configurable attributes matching the patch.
    #
    # What we check:
    # - Port exists in CONFIG_DB with correct attributes (admin_status, speed, etc.)
    # - Port is bound to appropriate ACL tables as specified in the patch
    # - Only front-panel ports are validated (internal/backplane ports are excluded)
    #
    # What we do NOT check:
    # - Operational status (link up/down) - this depends on cable/peer availability
    # - Traffic forwarding - out of scope for configuration validation
    # -------------------------------------------------------------------------
    if not ports_to_check:
        pytest.fail("No ports found in patch to verify")

    # Filter to only front-panel ports - internal ports (Ethernet-BP*, Ethernet-Rec*, etc.)
    # are not configurable via GCU patches and should not be validated
    front_panel_ports = {p for p in ports_to_check if is_front_panel_port(p)}
    skipped_ports = ports_to_check - front_panel_ports
    if skipped_ports:
        logger.info(f"Skipping internal/backplane ports (not configurable via patch): {sorted(skipped_ports)}")

    if not front_panel_ports:
        pytest.fail("No front-panel ports found in patch to verify")

    # Verify each port exists in CONFIG_DB with admin_status as specified in patch
    for port in front_panel_ports:
        logger.info(f"Verifying configuration restoration for port {port}")
        # Check port exists in CONFIG_DB
        redis_cmd = f'sonic-db-cli {ns_arg} CONFIG_DB hgetall "PORT|{port}"'
        redis_output = duthost.shell(redis_cmd, module_ignore_errors=False)['stdout']
        pytest_assert(redis_output.strip(), f"Port {port} not found in CONFIG_DB after patch")

        # Verify admin_status is 'up' (as expected from original config restoration)
        pytest_assert("'admin_status'" in redis_output and "'up'" in redis_output,
                      f"Port {port} admin_status is not 'up' in CONFIG_DB. Got: {redis_output}")
        logger.info(f"Verified port {port} exists in CONFIG_DB with admin_status=up")

    # Step 9.1: Check ports are bound to MIRROR ACL tables
    # Only verify ports that were explicitly added to MIRROR ACL tables in the patch.
    # Not all ports in the patch are necessarily MIRROR-bound.
    if acl_bound_ports:
        logger.info(f"Checking MIRROR ACL bindings for {len(acl_bound_ports)} ports from patch")
        result = duthost.shell("show acl table", module_ignore_errors=False)["stdout"]
        mirror_bindings = parse_mirror_acl_bindings(result)

        # Check ports that should be MIRROR-bound per the patch
        for port in acl_bound_ports:
            pytest_assert(port in mirror_bindings,
                          f"Port {port} is not bound to any MIRROR ACL table. "
                          f"Current bindings: {sorted(mirror_bindings)}")
            logger.info(f"Verified port {port} is bound to MIRROR ACL table")
    else:
        logger.info("No MIRROR ACL table entries in patch - skipping ACL binding verification")

    # Step 10: Verify PortChannel configuration restoration
    # We verify the PortChannel exists in CONFIG_DB with correct attributes.
    # Operational LACP status depends on peer availability and is not validated here.
    if portchannels_to_check:
        for portchannel in portchannels_to_check:
            logger.info(f"Verifying configuration restoration for PortChannel {portchannel}")

            # Verify PortChannel exists in CONFIG_DB
            redis_cmd = f'sonic-db-cli {ns_arg} CONFIG_DB hgetall "PORTCHANNEL|{portchannel}"'
            redis_output = duthost.shell(redis_cmd, module_ignore_errors=False)['stdout']
            pytest_assert(redis_output.strip(),
                          f"PortChannel {portchannel} not found in CONFIG_DB after patch")

            # Verify admin_status is 'up'
            pytest_assert("'admin_status'" in redis_output and "'up'" in redis_output,
                          f"PortChannel {portchannel} admin_status is not 'up' in CONFIG_DB. Got: {redis_output}")
            logger.info(f"Verified PortChannel {portchannel} exists in CONFIG_DB with admin_status=up")

    # Step 11: Verify BGP neighbor configuration restoration
    # We verify BGP neighbors exist in CONFIG_DB with correct attributes.
    # Session establishment depends on peer availability and is not validated here.
    if bgp_neighbors_to_check:
        for neighbor in bgp_neighbors_to_check:
            logger.info(f"Verifying configuration restoration for BGP neighbor {neighbor}")

            # Verify BGP neighbor exists in CONFIG_DB
            redis_cmd = f'sonic-db-cli {ns_arg} CONFIG_DB hgetall "BGP_NEIGHBOR|{neighbor}"'
            redis_output = duthost.shell(redis_cmd, module_ignore_errors=False)['stdout']
            pytest_assert(redis_output.strip(),
                          f"BGP neighbor {neighbor} not found in CONFIG_DB after patch")

            # Verify admin_status is 'up' (not shutdown)
            # Note: BGP neighbors use 'admin_status': 'up' when not shutdown
            if "'admin_status'" in redis_output:
                pytest_assert("'up'" in redis_output,
                              f"BGP neighbor {neighbor} admin_status is not 'up' in CONFIG_DB. Got: {redis_output}")
            logger.info(f"Verified BGP neighbor {neighbor} exists in CONFIG_DB")

    # Step 12: Verify all addcluster.json changes are reflected in CONFIG_DB
    for table, entries in config_entries_to_check.items():
        for entry in entries:
            if table == 'CABLE_LENGTH':
                redis_cmd = f'sonic-db-cli {ns_arg} CONFIG_DB hgetall "CABLE_LENGTH|AZURE"'
                redis_output = duthost.shell(redis_cmd, module_ignore_errors=False)['stdout']
                cable_lengths = json.loads(redis_output.replace("'", '"'))

                if entry not in cable_lengths:
                    pytest.fail(f"Key {entry} missing in CONFIG_DB. Got: {cable_lengths}")
            else:
                redis_key = f'sonic-db-cli {ns_arg} CONFIG_DB keys "{entry}"'
                redis_value = duthost.shell(redis_key, module_ignore_errors=False)['stdout'].strip()
                pytest_assert(redis_value == entry,
                              f"Key {entry} missing or incorrect in CONFIG_DB. Got: {redis_value}")
                logger.info(f"Verified {entry} exists in CONFIG_DB")

    # Step 13: capture full running configuration after applying addcluster.json
    logger.info("Capturing applied full running configuration")
    dut_config_path = "/tmp/applied.json"
    applied_config_path = os.path.join(THIS_DIR, "backup", f"{duthost.hostname}-applied.json")
    os.makedirs(os.path.dirname(applied_config_path), exist_ok=True)
    duthost.shell(f"show runningconfiguration all > {dut_config_path}")

    duthost.fetch(src=dut_config_path, dest=applied_config_path, flat=True)
    logger.info(f"Saved applied full configuration backup to {applied_config_path}")
    duthost.shell(f"rm -f {dut_config_path}")

    # -------------------------------------------------------------------------
    # Step 14: Compare full configuration before and after applying addcluster.json
    # -------------------------------------------------------------------------
    # COMPARISON STRATEGY:
    # We compare only the specific entries modified by the patch, not entire tables.
    # This avoids false-positive failures from unrelated differences in:
    # - Entries not touched by the patch
    # - Default values regenerated differently by minigraph reload
    #
    # NORMALIZATION:
    # The normalize_entry() function handles semantically equivalent values:
    # - admin_status='up' is equivalent to no admin_status field (implicit default)
    # - The GCU patch generator injects admin_status='up' to ensure resources come up,
    #   but minigraph-generated configs typically don't have this field explicitly set
    # - Without normalization, {'admin_status': 'up', 'asn': '65025', ...} would not
    #   match {'asn': '65025', ...} even though they're functionally identical
    # -------------------------------------------------------------------------
    logger.info("Comparing specific entries before and after applying addcluster.json")

    def get_table_data(config, table):
        """Extract table data from config."""
        return config.get(asic_id, {}).get(table, {})

    def normalize_entry(entry, table):
        """Normalize entry for comparison by handling semantically equivalent values.

        For BGP_NEIGHBOR, PORT, and PORTCHANNEL tables:
        - admin_status='up' is semantically equivalent to no admin_status field
        - The patch generator adds admin_status='up' to ensure resources come up,
          but minigraph-generated configs may not have this field explicitly set

        Args:
            entry: Configuration entry dict to normalize
            table: Table name (used to determine which normalizations apply)

        Returns:
            Normalized copy of the entry dict
        """
        if not isinstance(entry, dict):
            return entry

        normalized = dict(entry)

        # Tables where admin_status='up' is the implicit default
        admin_status_tables = ['BGP_NEIGHBOR', 'PORT', 'PORTCHANNEL']
        if table in admin_status_tables:
            # Remove admin_status if it's 'up' (the default) for comparison purposes
            if normalized.get('admin_status') == 'up':
                del normalized['admin_status']

        return normalized

    # Build a mapping of (table, key) -> expected value from the patches
    # This allows us to verify only the entries that were actually patched
    patched_entries = {}  # {(table, key): expected_value}
    for patch_entry in phase1_patch + phase2_patch:
        path = patch_entry.get('path', '')
        parts = path.split('/')
        # Path format: /asic_id/TABLE/key or /asic_id/TABLE/key/property
        if len(parts) >= 4:
            patch_asic = parts[1]
            table = parts[2]
            key = parts[3]
            # Only track entries for our target ASIC
            if patch_asic == asic_id:
                patched_entries[(table, key)] = True

    # Load configurations
    with open(full_config_path, 'r') as file:
        full_config = json.load(file)
    with open(applied_config_path, 'r') as file:
        applied_config = json.load(file)

    # Group patched entries by table for organized logging
    tables_with_entries = {}
    for (table, key) in patched_entries:
        if table not in tables_with_entries:
            tables_with_entries[table] = []
        tables_with_entries[table].append(key)

    # Compare only the specific entries that were patched
    for table, keys in tables_with_entries.items():
        logger.info(f"Comparing table: {table} ({len(keys)} entries)")
        original_table = get_table_data(full_config, table)
        applied_table = get_table_data(applied_config, table)

        mismatches = []
        for key in keys:
            original_entry = normalize_entry(original_table.get(key, {}), table)
            applied_entry = normalize_entry(applied_table.get(key, {}), table)

            if original_entry != applied_entry:
                mismatches.append({
                    'key': key,
                    'original': original_entry,
                    'applied': applied_entry
                })

        if mismatches:
            logger.error(f"Table {table} has {len(mismatches)} entry mismatches:")
            for m in mismatches:
                logger.error(f"  Entry '{m['key']}':")
                logger.error(f"    Original: {m['original']}")
                logger.error(f"    Applied:  {m['applied']}")
            pytest.fail(f"Configuration mismatch in table {table}: {len(mismatches)} entries differ")
        else:
            logger.info(f"Table {table} matches between configurations")
