"""Generate JSON patches for SONiC Generic Config Updater (GCU).

This module generates JSON patches (RFC 6902) to transform a "no-leaf" configuration
(without a specific T1 neighbor) into a "full" configuration (with the T1 neighbor).

Key Design Considerations:
--------------------------
1. YANG Validation: SONiC uses YANG models to validate configuration changes.
   Some tables have required fields (e.g., PORT requires 'lanes', ACL_TABLE requires 'type').
   Property-level patches like {"op": "add", "path": "/asic0/PORT/Ethernet168/fec"}
   fail YANG validation because the entry doesn't have all required fields.
   Solution: Coalesce property-level patches into complete entry-level patches.

2. Dependency Ordering: Some tables depend on others being configured first.
   - PORT must exist before INTERFACE entries referencing that port
   - INTERFACE base entries (Ethernet168) must exist before IP entries (Ethernet168|10.0.0.1/31)
   - BGP_NEIGHBOR entries require their associated INTERFACE to exist
   - ACL_TABLE binding updates must come last (they reference existing tables)

3. ACL_TABLE Bindings: When adding new ports, existing ACL_TABLE entries need their
   'ports' field updated to include the new ports. These patches must come last.
"""

import json
import jsonpatch
import logging
import os

logger = logging.getLogger(__name__)


def escape_json_pointer(s):
    """Escape special characters for JSON Pointer (RFC 6901).

    In JSON Pointer, '~' must be escaped as '~0' and '/' must be escaped as '~1'.
    """
    return s.replace('~', '~0').replace('/', '~1')


# Required fields for YANG validation by table type.
# When these tables are modified, YANG validation requires these fields to be present.
# If jsonpatch generates property-level patches for these tables, we must coalesce them
# into entry-level patches that include these required fields.
REQUIRED_FIELDS = {
    'PORT': ['lanes'],      # PORT entries must have 'lanes' field
    'ACL_TABLE': ['type'],  # ACL_TABLE entries must have 'type' field (e.g., 'MIRROR', 'L3')
}

# Patterns for non-front-panel ports that should be excluded from patches.
# These are internal ports (backplane, recycle, etc.) that should not be modified.
# - Ethernet-BPxx: Cisco backplane ports connecting ASICs
# - Ethernet-Rec: Recycle ports
# - EthernetBPxx: Alternative backplane port naming
NON_FRONT_PANEL_PORT_PATTERNS = [
    'Ethernet-BP',    # Cisco backplane ports (e.g., Ethernet-BP0, Ethernet-BP256)
    'EthernetBP',     # Alternative backplane naming
    'Ethernet-Rec',   # Recycle ports
    'Ethernet-IB',    # Inband ports
]


def is_front_panel_port(port_name):
    """Check if a port is a front panel port (not backplane/internal).

    Args:
        port_name: Port name string (e.g., 'Ethernet0', 'Ethernet-BP0')

    Returns:
        bool: True if this is a front panel port, False if it's a backplane/internal port
    """
    if not port_name:
        return False
    for pattern in NON_FRONT_PANEL_PORT_PATTERNS:
        if port_name.startswith(pattern):
            return False
    return True


def filter_non_front_panel_ports(ports):
    """Filter a collection of ports to only include front panel ports.

    Args:
        ports: Collection of port names (set, list, etc.)

    Returns:
        set: Set containing only front panel ports
    """
    return {p for p in ports if is_front_panel_port(p)}

# Known table names for detecting single-ASIC config structure
KNOWN_TABLES = {
    'ACL_TABLE', 'ACL_RULE', 'BGP_NEIGHBOR', 'BUFFER_PG', 'CABLE_LENGTH',
    'DEVICE_NEIGHBOR', 'DEVICE_NEIGHBOR_METADATA', 'INTERFACE', 'PFC_WD',
    'PORT', 'PORTCHANNEL', 'PORTCHANNEL_INTERFACE', 'PORTCHANNEL_MEMBER',
    'PORT_QOS_MAP', 'LOOPBACK_INTERFACE', 'VLAN', 'VLAN_MEMBER',
}


def is_multi_asic_config(config):
    """Detect if config is multi-ASIC (has asicN namespaces) or single-ASIC.

    Multi-ASIC config structure:
        {"localhost": {...}, "asic0": {"PORT": {...}}, "asic1": {...}}

    Single-ASIC config structure:
        {"localhost": {...}, "PORT": {...}, "ACL_TABLE": {...}}

    Returns:
        bool: True if multi-ASIC, False if single-ASIC
    """
    for key in config.keys():
        if key.startswith('asic'):
            return True
    # Also check if top-level keys are table names (single-ASIC)
    for key in config.keys():
        if key in KNOWN_TABLES:
            return False
    # Default to multi-ASIC if unclear
    return True


def parse_patch_path(path, is_multi_asic):
    """Parse a JSON patch path into components.

    For multi-ASIC: /asic0/PORT/Ethernet0/fec -> (asic0, PORT, Ethernet0, fec)
    For single-ASIC: /PORT/Ethernet0/fec -> (None, PORT, Ethernet0, fec)

    Args:
        path: JSON pointer path string
        is_multi_asic: Whether the config is multi-ASIC

    Returns:
        tuple: (namespace, table_name, key, property) - any can be None if not present
    """
    parts = path.split('/')
    # parts[0] is always '' (empty string before leading /)

    if is_multi_asic:
        # Multi-ASIC: /namespace/TABLE/key/property
        namespace = parts[1] if len(parts) > 1 else None
        table_name = parts[2] if len(parts) > 2 else None
        key = parts[3] if len(parts) > 3 else None
        prop = parts[4] if len(parts) > 4 else None
    else:
        # Single-ASIC: /TABLE/key/property (no namespace)
        namespace = None
        table_name = parts[1] if len(parts) > 1 else None
        key = parts[2] if len(parts) > 2 else None
        prop = parts[3] if len(parts) > 3 else None

    return (namespace, table_name, key, prop)


def build_patch_path(namespace, table_name, key, is_multi_asic):
    """Build a JSON patch path from components.

    Args:
        namespace: ASIC namespace (e.g., 'asic0') or None for single-ASIC
        table_name: Table name (e.g., 'PORT')
        key: Entry key (e.g., 'Ethernet0')
        is_multi_asic: Whether to include namespace in path

    Returns:
        str: JSON pointer path
    """
    escaped_key = escape_json_pointer(key)
    if is_multi_asic and namespace:
        return "/{}/{}/{}".format(namespace, table_name, escaped_key)
    else:
        return "/{}/{}".format(table_name, escaped_key)


def get_table_from_config(config, namespace, table_name, is_multi_asic):
    """Get a table from config, handling single vs multi-ASIC structure.

    Args:
        config: The configuration dictionary
        namespace: ASIC namespace or None
        table_name: Table name to retrieve
        is_multi_asic: Whether config is multi-ASIC

    Returns:
        dict: The table contents or empty dict
    """
    if is_multi_asic and namespace:
        return config.get(namespace, {}).get(table_name, {})
    else:
        return config.get(table_name, {})


def get_entry_from_config(config, namespace, table_name, key, is_multi_asic):
    """Get a specific entry from config table.

    Args:
        config: The configuration dictionary
        namespace: ASIC namespace or None
        table_name: Table name
        key: Entry key
        is_multi_asic: Whether config is multi-ASIC

    Returns:
        dict: The entry value or empty dict
    """
    table = get_table_from_config(config, namespace, table_name, is_multi_asic)
    return table.get(key, {})


def coalesce_property_patches(patches, full_config, no_leaf_config, tables_to_coalesce):
    """Coalesce property-level patches into entry-level patches.

    When jsonpatch generates patches like:
        {"op": "add", "path": "/asic1/PORT/Ethernet168/fec", "value": "rs"}
        {"op": "replace", "path": "/asic1/PORT/Ethernet168/lanes", "value": "..."}

    This function coalesces them into a single entry-level patch:
        {"op": "replace", "path": "/asic1/PORT/Ethernet168", "value": {...full entry...}}

    This is ALWAYS required for tables with YANG-required fields (PORT, ACL_TABLE)
    because the patch sorter on the DUT tries many different orderings and intermediate
    states may be missing required fields.

    Args:
        patches: List of patch operations from jsonpatch
        full_config: The full configuration dictionary (target state)
        no_leaf_config: The configuration without leaf (current state)
        tables_to_coalesce: List of table names to coalesce (e.g., ['PORT', 'INTERFACE'])

    Returns:
        tuple: (coalesced_patches, remaining_patches, is_multi_asic)
    """
    # Detect if this is multi-ASIC or single-ASIC config
    multi_asic = is_multi_asic_config(full_config)

    # Track entries that need coalescing: {(namespace, table, key): True}
    entries_to_coalesce = {}
    # Track property-level patches to remove
    patches_to_remove = set()

    # Determine minimum path components for property-level patch
    # Multi-ASIC: /asic0/TABLE/key/property = 5 components
    # Single-ASIC: /TABLE/key/property = 4 components
    min_property_components = 5 if multi_asic else 4

    for i, patch in enumerate(patches):
        path_components = patch['path'].split('/')

        if len(path_components) < min_property_components:
            continue

        namespace, table_name, key, prop = parse_patch_path(patch['path'], multi_asic)

        # Skip if no property (this is entry-level, not property-level)
        if prop is None:
            continue

        if table_name not in tables_to_coalesce:
            continue

        # ALWAYS coalesce property-level patches for tables with required YANG fields.
        if table_name in REQUIRED_FIELDS:
            entries_to_coalesce[(namespace, table_name, key)] = True
            patches_to_remove.add(i)
        else:
            # For other tables (INTERFACE, BGP_NEIGHBOR), only coalesce if entry is new
            no_leaf_table = get_table_from_config(no_leaf_config, namespace, table_name, multi_asic)
            if key not in no_leaf_table:
                entries_to_coalesce[(namespace, table_name, key)] = True
                patches_to_remove.add(i)

    # Build coalesced patches
    coalesced_patches = []

    for (namespace, table_name, key) in entries_to_coalesce:
        full_value = get_entry_from_config(full_config, namespace, table_name, key, multi_asic)
        if full_value:
            # Always use "add" operation for maximum compatibility.
            #
            # NOTE: We intentionally use "add" instead of "replace" even for existing entries.
            # Per RFC 6902, "add" will update if exists or create if not, while "replace" fails
            # if the target doesn't exist. Using "add" universally loses the following capabilities:
            #
            # 1. VALIDATION: "replace" would fail fast if an entry we expected to exist is missing,
            #    catching bugs where assumptions about the base config are incorrect.
            #
            # 2. DEBUGGING: The patch file becomes less self-documenting - we can no longer
            #    distinguish which entries were updates to existing config vs. new additions
            #    by inspecting the operation type.
            #
            # 3. ERROR LOCALIZATION: When "replace" fails, it points to the exact entry that
            #    violated assumptions. With "add", silent overwrites may mask configuration
            #    drift issues that only manifest later as test failures.
            #
            # This trade-off was made to avoid GCU patch application failures when the base
            # configuration state differs slightly from expectations (e.g., after partial
            # rollbacks or manual interventions).
            op = "add"

            coalesced_patches.append({
                "op": op,
                "path": build_patch_path(namespace, table_name, key, multi_asic),
                "value": full_value
            })

    # Remove the property-level patches that were coalesced
    remaining_patches = [p for i, p in enumerate(patches) if i not in patches_to_remove]

    return coalesced_patches, remaining_patches, multi_asic


def find_interface_entries_for_bgp(full_config, namespace, local_addr, is_multi_asic):
    """Find INTERFACE entries that match a BGP neighbor's local_addr.

    Args:
        full_config: The full configuration dictionary
        namespace: The ASIC namespace (e.g., 'asic0') or None for single-ASIC
        local_addr: The local IP address from BGP_NEIGHBOR entry
        is_multi_asic: Whether config uses multi-ASIC structure

    Returns:
        list: List of (interface_key, value) tuples for matching INTERFACE entries
    """
    interface_entries = []
    interface_table = get_table_from_config(full_config, namespace, "INTERFACE", is_multi_asic)

    base_interface = None
    for interface_key, value in interface_table.items():
        # Check if this interface key contains the local_addr
        # Keys are like "Ethernet96" or "Ethernet96|10.0.0.160/31"
        if '|' in interface_key and local_addr in interface_key:
            interface_entries.append((interface_key, value))
            # Extract base interface name
            base_interface = interface_key.split('|')[0]

    # Also add the base interface entry if found
    if base_interface and base_interface in interface_table:
        # Insert at beginning so base interface comes before IP entries
        interface_entries.insert(0, (base_interface, interface_table[base_interface]))

    return interface_entries


def find_acl_table_bindings_for_ports(full_config, no_leaf_config, namespace, ports, is_multi_asic):
    """Find ACL_TABLE entries that need port bindings updated.

    When ports are added, we need to update ACL_TABLE entries to include them
    in the 'ports' field if they were bound in the original config.

    Args:
        full_config: The full configuration dictionary (with all ports)
        no_leaf_config: The config without the leaf (missing ports)
        namespace: The ASIC namespace (e.g., 'asic0') or None for single-ASIC
        ports: Set of port names being added
        is_multi_asic: Whether config uses multi-ASIC structure

    Returns:
        list: List of patch operations to update ACL_TABLE bindings
    """
    patches = []
    full_acl_table = get_table_from_config(full_config, namespace, "ACL_TABLE", is_multi_asic)
    no_leaf_acl_table = get_table_from_config(no_leaf_config, namespace, "ACL_TABLE", is_multi_asic)

    for acl_name, full_acl_entry in full_acl_table.items():
        full_ports = full_acl_entry.get("ports", [])
        if not full_ports:
            continue

        # Get current ports in no_leaf config (may be empty or missing some ports)
        no_leaf_acl_entry = no_leaf_acl_table.get(acl_name, {})
        no_leaf_ports = no_leaf_acl_entry.get("ports", [])

        # Find ports that need to be added (in full but not in no_leaf)
        ports_to_add = []
        for port in full_ports:
            if port in ports and port not in no_leaf_ports:
                ports_to_add.append(port)

        # Generate patches to add each missing port to the ACL_TABLE binding
        for port in ports_to_add:
            escaped_acl_name = escape_json_pointer(acl_name)
            new_ports_list = list(no_leaf_ports) + [port]

            # Build path based on single-ASIC vs multi-ASIC
            if is_multi_asic:
                ports_path = "/{}/ACL_TABLE/{}/ports".format(namespace, escaped_acl_name)
            else:
                ports_path = "/ACL_TABLE/{}/ports".format(escaped_acl_name)

            # Check if we already have a patch for this ACL_TABLE's ports
            existing_patch = None
            for p in patches:
                if p['path'] == ports_path:
                    existing_patch = p
                    break

            if existing_patch:
                # Add to existing patch's value
                if port not in existing_patch['value']:
                    existing_patch['value'].append(port)
            else:
                # Use "add" instead of "replace" for ACL_TABLE port bindings.
                # This field should always exist in a valid ACL_TABLE entry, but using "add"
                # avoids failures if the 'ports' field is unexpectedly missing. See the
                # detailed comment in coalesce_property_patches() for trade-offs of this approach.
                patches.append({
                    "op": "add",
                    "path": ports_path,
                    "value": new_ports_list
                })

    return patches


def generate_config_patch(full_config_path, no_leaf_config_path):
    """
    Generate a JSON patch file by comparing two configuration files.

    This function:
    1. Coalesces property-level patches into entry-level patches for YANG validation
    2. Orders patches by dependency (PORT -> INTERFACE -> BGP_NEIGHBOR -> others)
    3. Generates ACL_TABLE binding updates for new ports

    Args:
        full_config_path (str): Path to the full configuration JSON file
        no_leaf_config_path (str): Path to the configuration JSON file without leaf

    Returns:
        str: Path to the generated patch file
    """
    # Load full configuration
    with open(full_config_path, 'r') as file:
        full_config = json.load(file)

    # Load configuration without leaf
    with open(no_leaf_config_path, 'r') as file:
        no_leaf_config = json.load(file)

    # Generate patches
    patches = jsonpatch.make_patch(no_leaf_config, full_config)

    # Add Cluster supported Tables (INTERFACE added for BGP_NEIGHBOR dependencies)
    # NOTE: BUFFER_PG and BUFFER_QUEUE are intentionally excluded because:
    # - On dynamic buffer model platforms (like Cisco-8000), buffer profiles are auto-generated
    # - Profiles like "pg_lossless_<speed>_<cable>_profile" are created by buffer manager
    # - YANG validation fails if we reference profiles that don't exist yet
    # - The buffer manager will auto-configure these once PORT and CABLE_LENGTH are set
    filtered_tables = [
        "ACL_TABLE", "BGP_NEIGHBOR", "CABLE_LENGTH", "DEVICE_NEIGHBOR",
        "DEVICE_NEIGHBOR_METADATA", "INTERFACE", "PFC_WD", "PORT", "PORTCHANNEL",
        "PORTCHANNEL_INTERFACE", "PORTCHANNEL_MEMBER", "PORT_QOS_MAP"
    ]
    admin_status_tables = ["BGP_NEIGHBOR", "PORT", "PORTCHANNEL"]

    # Coalesce property-level patches into entry-level patches for tables that need it.
    # Why each table is coalesced:
    # - PORT: Requires 'lanes' field for YANG validation ("Missing required element 'lanes'")
    # - INTERFACE: Needs proper ordering (base entry before IP entry)
    # - ACL_TABLE: Requires 'type' field for YANG validation ("Missing required element 'type'")
    # - BGP_NEIGHBOR: Needs complete entry to avoid "All Keys are not parsed in BGP_NEIGHBOR" error
    tables_to_coalesce = ["PORT", "INTERFACE", "ACL_TABLE", "BGP_NEIGHBOR"]
    coalesced_port_patches, remaining_patches, is_multi_asic = coalesce_property_patches(
        patches.patch, full_config, no_leaf_config, tables_to_coalesce
    )
    logger.info("Coalesced %d property-level patches into %d entry-level patches (multi_asic=%s)",
                len(patches.patch) - len(remaining_patches), len(coalesced_port_patches), is_multi_asic)

    # First pass: collect BGP_NEIGHBOR local_addr values and PORT entries being added
    bgp_local_addrs = {}  # {namespace: set of local_addr values}
    ports_being_added = {}  # {namespace: set of port names}

    # Check coalesced patches for ports being added (exclude backplane ports)
    for patch in coalesced_port_patches:
        namespace, table_name, key, _ = parse_patch_path(patch['path'], is_multi_asic)
        if table_name == 'PORT' and key and key.startswith('Ethernet'):
            # Skip backplane and other non-front-panel ports
            if not is_front_panel_port(key):
                continue
            if namespace not in ports_being_added:
                ports_being_added[namespace] = set()
            ports_being_added[namespace].add(key)

    for patch in remaining_patches:
        namespace, table_name, key, _ = parse_patch_path(patch['path'], is_multi_asic)

        if table_name is None or key is None:
            continue
        if namespace == "localhost":
            continue

        if patch['op'] == 'add' and table_name == 'BGP_NEIGHBOR':
            value = patch.get('value', {})
            if isinstance(value, dict):
                local_addr = value.get('local_addr')
                if local_addr:
                    if namespace not in bgp_local_addrs:
                        bgp_local_addrs[namespace] = set()
                    bgp_local_addrs[namespace].add(local_addr)

        # Track ports being added for ACL_TABLE binding updates (exclude backplane ports)
        if patch['op'] == 'add' and table_name == 'PORT' and key.startswith('Ethernet'):
            # Skip backplane and other non-front-panel ports
            if not is_front_panel_port(key):
                continue
            if namespace not in ports_being_added:
                ports_being_added[namespace] = set()
            ports_being_added[namespace].add(key)

    # Build set of required INTERFACE entries based on BGP_NEIGHBOR local_addr values
    required_interface_patches = []
    added_interface_keys = set()

    for namespace, local_addrs in bgp_local_addrs.items():
        for local_addr in local_addrs:
            interface_entries = find_interface_entries_for_bgp(full_config, namespace, local_addr, is_multi_asic)
            for interface_key, value in interface_entries:
                no_leaf_interface = get_table_from_config(no_leaf_config, namespace, "INTERFACE", is_multi_asic)
                patch_key = (namespace, interface_key)
                if interface_key not in no_leaf_interface and patch_key not in added_interface_keys:
                    escaped_key = escape_json_pointer(interface_key)
                    required_interface_patches.append({
                        "op": "add",
                        "path": build_patch_path(namespace, "INTERFACE", escaped_key, is_multi_asic),
                        "value": value
                    })
                    added_interface_keys.add(patch_key)

    # Track coalesced entry paths to avoid duplicate admin_status patches
    coalesced_entry_paths = set()
    for patch in coalesced_port_patches:
        namespace, table_name, key, _ = parse_patch_path(patch['path'], is_multi_asic)
        if table_name and key:
            entry_path = build_patch_path(namespace, table_name, key, is_multi_asic)
            coalesced_entry_paths.add(entry_path)

    filtered_patch_list = []
    for patch in remaining_patches:
        namespace, table_name, key, prop = parse_patch_path(patch['path'], is_multi_asic)

        if namespace == "localhost":  # internal to SONiC, do not update
            continue

        # Skip if table not supported
        if table_name not in filtered_tables:
            continue

        # Skip patches for backplane and other non-front-panel ports
        if key and not is_front_panel_port(key):
            logger.debug("Skipping non-front-panel port patch: %s", patch['path'])
            continue
        # Also skip patches that reference non-front-panel ports (e.g., INTERFACE entries)
        if key and '|' in key:
            base_port = key.split('|')[0]
            if not is_front_panel_port(base_port):
                logger.debug("Skipping non-front-panel port interface patch: %s", patch['path'])
                continue

        # Skip ACL_TABLE/ports patches - we generate our own complete replacement patches
        if table_name == 'ACL_TABLE' and prop == 'ports':
            continue
        # Also skip array index patches for ports (e.g., /ACL_TABLE/EVERFLOW/ports/0)
        path_components = patch['path'].split('/')
        if table_name == 'ACL_TABLE':
            if 'ports' in path_components:
                continue

        # For entry-level "add" patches, inject admin_status directly into the value
        if patch['op'] == 'add' and table_name in admin_status_tables and key:
            if prop is None and isinstance(patch.get('value'), dict):
                if 'admin_status' not in patch['value']:
                    new_value = dict(patch['value'])
                    new_value['admin_status'] = 'up'
                    patch = dict(patch)
                    patch['value'] = new_value

        filtered_patch_list.append(patch)

    # Build the final patch list with correct dependency order:
    # 1. PORT entries (coalesced) - must come first
    # 2. ACL_TABLE entries (coalesced) - need complete entries with "type" field
    # 3. INTERFACE base entries (e.g., Ethernet168) - before IP entries
    # 4. INTERFACE IP entries (e.g., Ethernet168|10.0.0.170/31)
    # 5. BGP_NEIGHBOR entries (coalesced) - need complete entries for YANG validation
    # 6. Other table entries
    # 7. ACL_TABLE binding updates - last

    def is_front_panel_patch(patch):
        """Check if a patch is for a front panel port (not backplane)."""
        _, table_name, key, _ = parse_patch_path(patch['path'], is_multi_asic)
        if not key:
            return True  # Not a port-related patch
        # Check the key directly for PORT table
        if table_name == 'PORT':
            return is_front_panel_port(key)
        # Check for INTERFACE entries like "Ethernet-BP0|10.0.0.1/31"
        if '|' in key:
            base_port = key.split('|')[0]
            return is_front_panel_port(base_port)
        # Check if key itself is a port name
        if key.startswith('Ethernet'):
            return is_front_panel_port(key)
        return True

    # Filter out backplane ports from coalesced patches
    coalesced_port_only = [p for p in coalesced_port_patches if '/PORT/' in p['path'] and is_front_panel_patch(p)]
    coalesced_acl_table = [p for p in coalesced_port_patches if '/ACL_TABLE/' in p['path']]
    coalesced_interface = [p for p in coalesced_port_patches if '/INTERFACE/' in p['path'] and is_front_panel_patch(p)]
    coalesced_bgp_neighbor = [p for p in coalesced_port_patches if '/BGP_NEIGHBOR/' in p['path']]

    # Log filtered backplane ports
    backplane_port_count = sum(1 for p in coalesced_port_patches if '/PORT/' in p['path'] and not is_front_panel_patch(p))
    if backplane_port_count > 0:
        logger.info("Filtered out %d backplane/non-front-panel PORT patches", backplane_port_count)

    # Sort INTERFACE patches: base entries before IP entries
    required_interface_patches.sort(key=lambda p: (p['path'].count('|'), p['path']))
    coalesced_interface.sort(key=lambda p: (p['path'].count('|'), p['path']))

    # Combine all INTERFACE patches and dedupe
    all_interface_patches = []
    seen_interface_paths = set()
    for p in required_interface_patches + coalesced_interface:
        if p['path'] not in seen_interface_paths:
            all_interface_patches.append(p)
            seen_interface_paths.add(p['path'])

    # Build final ordered list respecting all dependencies
    # NOTE: We split into two phases due to a GCU sorter limitation/bug.
    # The GCU patch sorter fails with "'PortX' is not in list" when:
    # - A PORT is being added/modified in the same batch as
    # - An ACL_TABLE that references that PORT in its 'ports' field
    # The sorter tries to analyze dependencies but doesn't understand that
    # the PORT will exist by the time the ACL_TABLE patch is applied.
    #
    # Phase 1: Core configuration (PORT, INTERFACE, BGP_NEIGHBOR, etc.)
    # Phase 2: ACL_TABLE entries (applied after ports exist)

    # Track coalesced ACL_TABLE entries
    coalesced_acl_tables = set()
    for patch in coalesced_acl_table:
        namespace, table_name, key, _ = parse_patch_path(patch['path'], is_multi_asic)
        if table_name == 'ACL_TABLE' and key:
            coalesced_acl_tables.add((namespace, key))

    # Generate ACL_TABLE binding patches for ports being added
    acl_binding_patches = []
    for namespace, ports in ports_being_added.items():
        acl_patches = find_acl_table_bindings_for_ports(
            full_config, no_leaf_config, namespace, ports, is_multi_asic
        )
        for patch in acl_patches:
            patch_namespace, patch_table, patch_acl_name, _ = parse_patch_path(patch['path'], is_multi_asic)
            if (patch_namespace, patch_acl_name) not in coalesced_acl_tables:
                acl_binding_patches.append(patch)

    # Phase 1: All non-ACL patches
    phase1_patch_list = (coalesced_port_only + all_interface_patches +
                         coalesced_bgp_neighbor + filtered_patch_list)

    # Phase 2: All ACL_TABLE patches (coalesced + binding updates)
    phase2_patch_list = coalesced_acl_table + acl_binding_patches

    # Combined list for metadata (but we write separate files)
    final_patch_list = phase1_patch_list + phase2_patch_list

    phase1_patch = jsonpatch.JsonPatch(phase1_patch_list)
    phase2_patch = jsonpatch.JsonPatch(phase2_patch_list)

    # Log the complete patch for diagnostic purposes
    logger.info("Generated patches with %d total operations (Phase 1: %d, Phase 2: %d):",
                len(final_patch_list), len(phase1_patch_list), len(phase2_patch_list))
    logger.info("  Phase 1 (core config):")
    logger.info("    - PORT entries: %d", len(coalesced_port_only))
    logger.info("    - INTERFACE entries: %d", len(all_interface_patches))
    logger.info("    - BGP_NEIGHBOR entries: %d", len(coalesced_bgp_neighbor))
    logger.info("    - Other entries: %d", len(filtered_patch_list))
    logger.info("  Phase 2 (ACL bindings):")
    logger.info("    - ACL_TABLE entries: %d", len(coalesced_acl_table))
    logger.info("    - ACL binding updates: %d", len(acl_binding_patches))

    logger.debug("Phase 1 patch content:\n%s", json.dumps(phase1_patch.patch, indent=2))
    logger.debug("Phase 2 patch content:\n%s", json.dumps(phase2_patch.patch, indent=2))

    # Generate output paths in same directory as full config
    output_dir = os.path.dirname(full_config_path)
    phase1_file = os.path.join(output_dir, 'generated_patch_phase1.json')
    phase2_file = os.path.join(output_dir, 'generated_patch_phase2.json')

    # Write phase 1 patch (core config)
    with open(phase1_file, 'w') as file:
        json.dump(phase1_patch.patch, file, indent=4)

    # Write phase 2 patch (ACL bindings)
    with open(phase2_file, 'w') as file:
        json.dump(phase2_patch.patch, file, indent=4)

    # Also write metadata file with information about patch generation
    metadata = {
        'total_patches': len(final_patch_list),
        'phase1_patches': len(phase1_patch_list),
        'phase2_patches': len(phase2_patch_list),
        'port_patches': len(coalesced_port_only),
        'acl_table_patches': len(coalesced_acl_table),
        'interface_patches': len(all_interface_patches),
        'bgp_neighbor_patches': len(coalesced_bgp_neighbor),
        'acl_binding_patches': len(acl_binding_patches),
        'is_multi_asic': is_multi_asic
    }
    metadata_file = os.path.join(output_dir, 'generated_patch_metadata.json')
    with open(metadata_file, 'w') as file:
        json.dump(metadata, file, indent=4)

    # Return tuple of (phase1_file, phase2_file)
    return phase1_file, phase2_file
