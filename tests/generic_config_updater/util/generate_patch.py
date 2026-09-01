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
    'ACL_TABLE', 'ACL_RULE', 'BGP_NEIGHBOR', 'BUFFER_PG', 'BUFFER_QUEUE',
    'CABLE_LENGTH', 'DEVICE_NEIGHBOR', 'DEVICE_NEIGHBOR_METADATA', 'INTERFACE',
    'PFC_WD', 'PORT', 'PORTCHANNEL', 'PORTCHANNEL_INTERFACE',
    'PORTCHANNEL_MEMBER', 'PORT_QOS_MAP', 'QUEUE', 'LOOPBACK_INTERFACE',
    'VLAN', 'VLAN_MEMBER',
}

# Tables always included in an add-cluster patch, on every platform.
BASE_FILTERED_TABLES = [
    "ACL_TABLE", "BGP_NEIGHBOR", "CABLE_LENGTH", "DEVICE_NEIGHBOR",
    "DEVICE_NEIGHBOR_METADATA", "INTERFACE", "PFC_WD", "PORT", "PORTCHANNEL",
    "PORTCHANNEL_INTERFACE", "PORTCHANNEL_MEMBER", "PORT_QOS_MAP"
]

# Buffer/queue tables. Valid only on traditional (static) buffer platforms.
#
# On dynamic buffer model platforms (e.g. Cisco-8000) the buffer manager
# auto-generates profiles such as "pg_lossless_<speed>_<cable>_profile" once
# PORT and CABLE_LENGTH are set. Emitting these tables there would reference
# profiles that do not exist yet and fail YANG validation.
#
# On traditional buffer platforms (Arista/Nokia LT2) the opposite is true:
# the buffer manager does not derive these entries, so omitting them leaves the
# new port with default buffering and no PFC.
STATIC_BUFFER_TABLES = ["BUFFER_PG", "BUFFER_QUEUE", "QUEUE"]

# Lossless PG entries are created by the buffer manager on link-up / cable
# length change, not by the config push. They must never appear in a generated
# patch even on traditional platforms: the profile name encodes port speed and
# cable length, so a pushed entry would reference a profile that may not exist.
AUTOGEN_BUFFER_PG_PROFILE_PREFIX = "pg_lossless_"


def get_buffer_model(config, is_multi_asic):
    """Determine the platform's buffer model from DEVICE_METADATA.

    SONiC sets DEVICE_METADATA|localhost|buffer_model to 'dynamic' on platforms
    using dynamic buffer calculation. Absence of the field means traditional
    (static) buffers.

    Args:
        config: Full configuration dict
        is_multi_asic: Whether the config is multi-ASIC

    Returns:
        str: 'dynamic' or 'traditional'
    """
    candidates = []
    if is_multi_asic:
        for ns_config in config.values():
            if isinstance(ns_config, dict):
                candidates.append(ns_config)
    else:
        candidates.append(config)

    for cfg in candidates:
        metadata = cfg.get('DEVICE_METADATA') or {}
        localhost = metadata.get('localhost') or {}
        model = localhost.get('buffer_model')
        if model:
            return model.lower()

    return 'traditional'


def is_autogenerated_buffer_pg(table_name, prop, value):
    """Check whether a BUFFER_PG patch refers to an auto-generated lossless PG.

    Args:
        table_name: Table the patch targets
        prop: Property name, or None for entry-level patches
        value: Patch value (dict for entry-level, scalar for property-level)

    Returns:
        bool: True if this entry is created by the buffer manager, not the push
    """
    if table_name != 'BUFFER_PG':
        return False

    if prop == 'profile':
        profile = value
    elif prop is None and isinstance(value, dict):
        profile = value.get('profile')
    else:
        return False

    return isinstance(profile, str) and profile.startswith(AUTOGEN_BUFFER_PG_PROFILE_PREFIX)


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

        # Emit one append op per port so existing bindings are preserved.
        patches.extend(
            build_acl_ports_append_patches(namespace, acl_name, ports_to_add, is_multi_asic)
        )

    return patches


def build_acl_ports_append_patches(namespace, acl_name, ports_to_add, is_multi_asic):
    """Build RFC 6902 append operations binding ports to an existing ACL_TABLE.

    Ports are bound with "add /ACL_TABLE/<name>/ports/-", an append. Replacing
    the whole 'ports' list instead would clobber bindings written concurrently
    by another process and would rewrite unrelated fields such as 'type',
    'stage' and 'policy_desc'.

    Args:
        namespace: The ASIC namespace or None for single-ASIC
        acl_name: ACL_TABLE entry name
        ports_to_add: Ordered list of port names to bind
        is_multi_asic: Whether config uses multi-ASIC structure

    Returns:
        list: One append patch operation per port
    """
    escaped_acl_name = escape_json_pointer(acl_name)
    if is_multi_asic and namespace:
        path = "/{}/ACL_TABLE/{}/ports/-".format(namespace, escaped_acl_name)
    else:
        path = "/ACL_TABLE/{}/ports/-".format(escaped_acl_name)

    return [{"op": "add", "path": path, "value": port} for port in ports_to_add]


def split_existing_acl_table_patches(acl_patches, no_leaf_config, is_multi_asic):
    """Split coalesced ACL_TABLE patches into whole-entry adds and port appends.

    A coalesced whole-entry "add" is necessary when the ACL_TABLE entry is new,
    because YANG requires the 'type' field to be present. When the entry already
    exists on the device only the new port bindings should be sent, so those
    patches are rewritten into "/ports/-" appends.

    Args:
        acl_patches: Coalesced entry-level ACL_TABLE patches
        no_leaf_config: The config without the leaf
        is_multi_asic: Whether config uses multi-ASIC structure

    Returns:
        tuple: (whole_entry_patches, append_patches)
    """
    whole_entry_patches = []
    append_patches = []

    for patch in acl_patches:
        namespace, _, key, prop = parse_patch_path(patch['path'], is_multi_asic)
        if prop is not None or not key:
            whole_entry_patches.append(patch)
            continue

        acl_name = key.replace('~1', '/').replace('~0', '~')
        existing_entry = get_entry_from_config(
            no_leaf_config, namespace, "ACL_TABLE", acl_name, is_multi_asic
        )
        if not existing_entry:
            # Genuinely new ACL_TABLE entry - the full entry must be sent.
            whole_entry_patches.append(patch)
            continue

        full_ports = (patch.get('value') or {}).get('ports', [])
        existing_ports = existing_entry.get('ports', [])
        ports_to_add = [p for p in full_ports if p not in existing_ports]
        if not ports_to_add:
            continue

        append_patches.extend(
            build_acl_ports_append_patches(namespace, acl_name, ports_to_add, is_multi_asic)
        )

    return whole_entry_patches, append_patches


def _acl_table_types(config_path):
    """Map ACL table name -> table type from a config_db JSON file."""
    with open(config_path) as config_file:
        config = json.load(config_file)

    tables = config.get('ACL_TABLE')
    if tables is None:
        # Multi-ASIC configs are namespaced; take the first namespace defining ACL_TABLE.
        for section in config.values():
            if isinstance(section, dict) and isinstance(section.get('ACL_TABLE'), dict):
                tables = section['ACL_TABLE']
                break

    return {name: entry.get('type', '')
            for name, entry in (tables or {}).items()
            if isinstance(entry, dict)}


def extract_mirror_acl_ports(patch_data, target_config_path):
    """Collect front-panel ports that the patch binds to MIRROR/MIRRORV6 ACL tables.

    ACL bindings appear in the patch in two shapes:

      whole-entry add, for an ACL table that does not exist yet:
          {"op": "add", "path": "/ACL_TABLE/EVERFLOW",
           "value": {"type": "MIRROR", "ports": ["PortChannel1015"], ...}}

      per-port append, for an ACL table that already exists:
          {"op": "add", "path": "/ACL_TABLE/EVERFLOW/ports/-",
           "value": "PortChannel1015"}

    The append form carries no table type, so the type is resolved from the
    target configuration.

    Args:
        patch_data: The generated patch, as a list of RFC 6902 operations
        target_config_path: Path to the target (with-T1) config_db JSON

    Returns:
        set: Port and PortChannel names bound to a MIRROR or MIRRORV6 table
    """
    acl_types = _acl_table_types(target_config_path)

    def acl_name_and_remainder(path):
        segments = [segment for segment in path.split('/') if segment]
        if 'ACL_TABLE' not in segments:
            return None, []
        index = segments.index('ACL_TABLE')
        if len(segments) <= index + 1:
            return None, []
        return segments[index + 1], segments[index + 2:]

    # A patch may create the ACL table itself, so learn types from it too.
    for entry in patch_data:
        name, remainder = acl_name_and_remainder(entry.get('path', ''))
        value = entry.get('value')
        if name and not remainder and isinstance(value, dict) and 'type' in value:
            acl_types.setdefault(name, value['type'])

    bound_ports = set()
    for entry in patch_data:
        name, remainder = acl_name_and_remainder(entry.get('path', ''))
        if not name or acl_types.get(name) not in ('MIRROR', 'MIRRORV6'):
            continue

        value = entry.get('value')
        if not remainder and isinstance(value, dict):
            candidates = value.get('ports', [])
        elif remainder and remainder[0] == 'ports':
            candidates = value if isinstance(value, list) else [value]
        else:
            continue

        for port in candidates:
            if isinstance(port, str) and is_front_panel_port(port):
                bound_ports.add(port)

    return bound_ports


def generate_config_patch(full_config_path, no_leaf_config_path, buffer_model=None,
                          split_phases=False):
    """
    Generate JSON patch file(s) that transform the "no leaf" configuration into
    the full configuration.

    Note on argument order: the patch produced is no_leaf -> full, i.e. it ADDS
    the leaf. The arguments are deliberately (full, no_leaf) rather than the
    jsonpatch.from_diff(src, dst) order, so read them as (target, current).

    This function:
    1. Coalesces property-level patches into entry-level patches for YANG validation
    2. Orders patches by dependency (PORT -> INTERFACE -> BGP_NEIGHBOR -> others)
    3. Generates ACL_TABLE binding updates for new ports
    4. Includes buffer/queue tables on traditional buffer platforms only

    Args:
        full_config_path (str): Path to the target configuration JSON file
        no_leaf_config_path (str): Path to the current configuration JSON file,
            without the leaf being added
        buffer_model (str): 'dynamic' or 'traditional'. Defaults to auto-detection
            from DEVICE_METADATA|localhost|buffer_model in the full config.
        split_phases (bool): When True, emit two patch files instead of one --
            core config first, ACL_TABLE bindings second. This works around a GCU
            sorter bug that fails with "'PortX' is not in list" when a PORT is
            added in the same batch as an ACL_TABLE referencing that PORT. Only
            needed when ACLs bind physical ports; when they bind a PortChannel
            created earlier in the same patch, a single patch applies cleanly.

    Returns:
        list[str]: Paths to the generated patch files, in the order they must be
            applied. One element when split_phases is False, two when it is True.
    """
    # Load full configuration
    with open(full_config_path, 'r') as file:
        full_config = json.load(file)

    # Load configuration without leaf
    with open(no_leaf_config_path, 'r') as file:
        no_leaf_config = json.load(file)

    # Generate patches
    patches = jsonpatch.make_patch(no_leaf_config, full_config)

    # Buffer/queue tables are platform-dependent. See STATIC_BUFFER_TABLES.
    if buffer_model is None:
        buffer_model = get_buffer_model(full_config, is_multi_asic_config(full_config))
    buffer_model = buffer_model.lower()

    filtered_tables = list(BASE_FILTERED_TABLES)
    if buffer_model == 'traditional':
        filtered_tables.extend(STATIC_BUFFER_TABLES)
    logger.info("Buffer model detected as '%s'; buffer/queue tables %s",
                buffer_model,
                "included" if buffer_model == 'traditional' else "excluded")

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

        # Skip lossless PG entries - the buffer manager creates these on link-up,
        # they are not part of the pushed configuration.
        if is_autogenerated_buffer_pg(table_name, prop, patch.get('value')):
            logger.debug("Skipping auto-generated lossless BUFFER_PG patch: %s", patch['path'])
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
    # Filter ACL_TABLE patches, excluding localhost namespace (multi-ASIC cross-namespace issue)
    # On multi-ASIC chassis, localhost ACL_TABLE entries reference ports only in ASIC namespaces
    coalesced_acl_table = [p for p in coalesced_port_patches
                           if '/ACL_TABLE/' in p['path'] and not p['path'].startswith('/localhost/')]
    localhost_acl_count = sum(1 for p in coalesced_port_patches
                              if '/ACL_TABLE/' in p['path'] and p['path'].startswith('/localhost/'))
    if localhost_acl_count > 0:
        logger.info("Filtered out %d localhost ACL_TABLE patches (multi-ASIC cross-namespace issue)",
                    localhost_acl_count)
    coalesced_interface = [p for p in coalesced_port_patches if '/INTERFACE/' in p['path'] and is_front_panel_patch(p)]
    coalesced_bgp_neighbor = [p for p in coalesced_port_patches if '/BGP_NEIGHBOR/' in p['path']]

    # Log filtered backplane ports
    backplane_port_count = sum(
        1 for p in coalesced_port_patches if '/PORT/' in p['path'] and not is_front_panel_patch(p))
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

    # Build final ordered list respecting all dependencies.
    # Order: PORT -> INTERFACE -> BGP_NEIGHBOR -> other tables -> ACL_TABLE (bindings last)
    # ACL_TABLE entries come last because their 'ports' field references PORTs that
    # must already exist in CONFIG_DB for GCU's dependency sorter to resolve them.

    # Track coalesced ACL_TABLE entries
    coalesced_acl_tables = set()
    for patch in coalesced_acl_table:
        namespace, table_name, key, _ = parse_patch_path(patch['path'], is_multi_asic)
        if table_name == 'ACL_TABLE' and key:
            coalesced_acl_tables.add((namespace, key))

    # Entries that already exist on the device only need their new port bindings
    # appended; whole-entry adds are reserved for genuinely new ACL_TABLE entries.
    coalesced_acl_table, coalesced_acl_appends = split_existing_acl_table_patches(
        coalesced_acl_table, no_leaf_config, is_multi_asic
    )

    # Generate ACL_TABLE binding patches for ports being added
    acl_binding_patches = []
    for namespace, ports in ports_being_added.items():
        # Skip localhost namespace - ACL bindings should be per-ASIC namespace
        if namespace == 'localhost':
            continue
        acl_patches = find_acl_table_bindings_for_ports(
            full_config, no_leaf_config, namespace, ports, is_multi_asic
        )
        for patch in acl_patches:
            patch_namespace, patch_table, patch_acl_name, _ = parse_patch_path(patch['path'], is_multi_asic)
            if (patch_namespace, patch_acl_name) not in coalesced_acl_tables:
                acl_binding_patches.append(patch)

    # Core config first, ACL entries last.
    core_patch_list = (coalesced_port_only + all_interface_patches +
                       coalesced_bgp_neighbor + filtered_patch_list)
    acl_patch_list = (coalesced_acl_table + coalesced_acl_appends +
                      acl_binding_patches)

    final_patch_list = core_patch_list + acl_patch_list

    # Log the complete patch for diagnostic purposes
    logger.info("Generated patch with %d total operations:", len(final_patch_list))
    logger.info("  - PORT entries: %d", len(coalesced_port_only))
    logger.info("  - INTERFACE entries: %d", len(all_interface_patches))
    logger.info("  - BGP_NEIGHBOR entries: %d", len(coalesced_bgp_neighbor))
    logger.info("  - Other entries: %d", len(filtered_patch_list))
    logger.info("  - ACL_TABLE entries: %d", len(coalesced_acl_table))
    logger.info("  - ACL binding appends: %d", len(coalesced_acl_appends))
    logger.info("  - ACL binding updates: %d", len(acl_binding_patches))

    logger.debug("Patch content:\n%s",
                 json.dumps(jsonpatch.JsonPatch(final_patch_list).patch, indent=2))

    # Generate output path in same directory as full config
    output_dir = os.path.dirname(full_config_path)

    if split_phases:
        patch_files = [os.path.join(output_dir, 'generated_patch_phase1.json'),
                       os.path.join(output_dir, 'generated_patch_phase2.json')]
        patch_lists = [core_patch_list, acl_patch_list]
        logger.info("Split into two phases (Phase 1: %d, Phase 2: %d)",
                    len(core_patch_list), len(acl_patch_list))
    else:
        patch_files = [os.path.join(output_dir, 'generated_patch.json')]
        patch_lists = [final_patch_list]

    for target_file, patch_list in zip(patch_files, patch_lists):
        with open(target_file, 'w') as file:
            json.dump(jsonpatch.JsonPatch(patch_list).patch, file, indent=4)

    # Also write metadata file with information about patch generation
    metadata = {
        'total_patches': len(final_patch_list),
        'port_patches': len(coalesced_port_only),
        'acl_table_patches': len(coalesced_acl_table),
        'interface_patches': len(all_interface_patches),
        'bgp_neighbor_patches': len(coalesced_bgp_neighbor),
        'acl_binding_patches': len(acl_binding_patches),
        'acl_append_patches': len(coalesced_acl_appends),
        'is_multi_asic': is_multi_asic,
        'split_phases': split_phases,
        'patch_files': [os.path.basename(path) for path in patch_files],
    }
    metadata_file = os.path.join(output_dir, 'generated_patch_metadata.json')
    with open(metadata_file, 'w') as file:
        json.dump(metadata, file, indent=4)

    return patch_files
