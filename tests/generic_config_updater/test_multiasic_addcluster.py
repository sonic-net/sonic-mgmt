import json
import logging
import os
import shutil
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
    logger.info(f"Modifying minigraph to remove {target_t1}")
    local_dir = "/tmp/minigraph_modified"
    local_minigraph = os.path.join(local_dir, f"{duthost.hostname}-minigraph.xml")
    duthost.fetch(src=MINIGRAPH, dest=local_minigraph, flat=True)
    refactor = MinigraphRefactor(target_t1)
    if not refactor.process_minigraph(local_minigraph, local_minigraph):
        logger.info(f"Skipping test - testbed topology does not match required conditions for {target_t1}")
        pytest.skip(f"Testbed topology does not match required conditions for {target_t1}")
    duthost.copy(src=local_minigraph, dest=MINIGRAPH)

    # Step 4: Reload minigraph
    logger.info("Reloading minigraph using 'config load_minigraph -y'")
    duthost.shell("sudo config load_minigraph -y", module_ignore_errors=False)
    if not wait_until(300, 20, 0, duthost.critical_services_fully_started):
        logger.error("Not all critical services fully started!")
        pytest.fail("Critical services not fully started after minigraph reload")

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
    with open(phase2_file) as file:
        phase2_patch = json.load(file)

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
