#!/usr/bin/env python3
"""
Determine the applicable ports2cable mapping for a SONiC device.

Replicates the Jinja2 logic in buffers_config.j2:
  1. Resolve the device role -> topology postfix (t0, t1, t2, etc.)
  2. Locate the platform-specific buffers_defaults_<postfix>.j2
  3. If that file defines ports2cable, parse and return it
  4. Otherwise, return the hardcoded defaults from buffers_config.j2

This module can be used standalone (CLI) or imported for per-port cable
length resolution from neighbor data.
"""

import json
import os
import re
import subprocess
import sys

HARDCODED_PORTS2CABLE = {
    'internal':                              '5m',
    'torrouter_server':                      '5m',
    'leafrouter_torrouter':                  '40m',
    'upperspinerouter_spinerouter':          '30m',
    'upperspinerouter_lowerspinerouter':     '30m',
    'spinerouter_leafrouter':                '300m',
    'lowerspinerouter_leafrouter':           '500m',
    'fabricspinerouter_lowerspinerouter':    '5m',
    'regionalhub_upperspinerouter':          '80000m',
    'regionalhub_spinerouter':              '80000m',
    'aznghub_upperspinerouter':             '80000m',
    'aznghub_spinerouter':                  '80000m',
}

# Map full SONiC role names to the simplified form used in ports2cable keys.
# Matching is done case-insensitively against the lowercased role string.
# Order matters — more specific patterns must come before general ones.
_ROLE_NORMALIZE_PATTERNS = [
    ('lowerspinerouter', 'lowerspinerouter'),
    ('upperspinerouter', 'upperspinerouter'),
    ('fabricspinerouter', 'fabricspinerouter'),
    ('regionalhub', 'regionalhub'),
    ('aznghub', 'aznghub'),
    ('torrouter', 'torrouter'),
    ('leafrouter', 'leafrouter'),
    ('spinerouter', 'spinerouter'),
    ('server', 'server'),
]


def normalize_role(role_type):
    """Normalize a SONiC device role to the simplified ports2cable key form.

    Examples:
        BackEndToRRouter   -> torrouter
        BackEndLeafRouter  -> leafrouter
        SpineRouter        -> spinerouter
        LowerSpineRouter   -> lowerspinerouter
        FabricSpineRouter  -> fabricspinerouter
        Server             -> server

    Args:
        role_type: device type string from DEVICE_METADATA or
            DEVICE_NEIGHBOR_METADATA (e.g. "BackEndToRRouter")

    Returns:
        Normalized role string, or the lowercased input if no pattern matches.
    """
    if not role_type:
        return ''
    lowered = role_type.lower()
    for pattern, normalized in _ROLE_NORMALIZE_PATTERNS:
        if pattern in lowered:
            return normalized
    return lowered


def resolve_ports2cable_key(my_role, neighbor_role):
    """Build a ports2cable lookup key from two normalized roles.

    Args:
        my_role: normalized role of the local device (e.g. "leafrouter")
        neighbor_role: normalized role of the neighbor (e.g. "torrouter")

    Returns:
        Key string like "leafrouter_torrouter"
    """
    return "{}_{}".format(my_role, neighbor_role)


def resolve_port_cable_lengths(port_names, neighbor_data, ports2cable,
                               my_role, cable_length_default="40m"):
    """Resolve per-port cable lengths using neighbor role data.

    For each port, looks up its neighbor's role in ``neighbor_data``,
    builds a ports2cable key from (my_role, neighbor_role), and looks up
    the cable length. Tries both key orderings since the ports2cable
    mapping may use either direction (e.g. "leafrouter_torrouter" vs
    "torrouter_leafrouter"). Falls back to ``cable_length_default`` when
    the neighbor or mapping is unknown.

    Args:
        port_names: list of port name strings
        neighbor_data: dict of port_name -> neighbor_type (role string,
            e.g. "BackEndLeafRouter"). Ports without an entry get the
            default cable length.
        ports2cable: dict of role_pair_key -> cable_length (e.g.
            {"leafrouter_torrouter": "40m"})
        my_role: normalized role of the local device (e.g. "torrouter")
        cable_length_default: fallback cable length string

    Returns:
        dict of port_name -> cable_length_string
    """
    result = {}
    for port in port_names:
        neighbor_type = neighbor_data.get(port)
        if not neighbor_type:
            result[port] = cable_length_default
            continue
        neighbor_normalized = normalize_role(neighbor_type)
        key_fwd = resolve_ports2cable_key(my_role, neighbor_normalized)
        key_rev = resolve_ports2cable_key(neighbor_normalized, my_role)
        if key_fwd in ports2cable:
            result[port] = ports2cable[key_fwd]
        elif key_rev in ports2cable:
            result[port] = ports2cable[key_rev]
        else:
            result[port] = cable_length_default
    return result


# ---------------------------------------------------------------------------
# Functions that read from the DUT filesystem / CLI (used by standalone mode
# and by the Ansible module which runs on the DUT)
# ---------------------------------------------------------------------------

def get_device_metadata():
    """Read DEVICE_METADATA from config DB via sonic-cfggen."""
    try:
        out = subprocess.check_output(
            ['sonic-cfggen', '-d', '--var-json', 'DEVICE_METADATA'],
            text=True, stderr=subprocess.DEVNULL
        )
        return json.loads(out)
    except Exception as e:
        print(f"Error reading DEVICE_METADATA: {e}", file=sys.stderr)
        sys.exit(1)


def get_platform_and_hwsku():
    """Return (platform, hwsku) from 'show platform summary'."""
    try:
        out = subprocess.check_output(
            ['show', 'platform', 'summary'], text=True, stderr=subprocess.DEVNULL
        )
        platform = hwsku = None
        for line in out.splitlines():
            if line.startswith('Platform:'):
                platform = line.split(':', 1)[1].strip()
            elif line.startswith('HwSKU:'):
                hwsku = line.split(':', 1)[1].strip()
        return platform, hwsku
    except Exception as e:
        print(f"Error reading platform summary: {e}", file=sys.stderr)
        sys.exit(1)


def resolve_topology_postfix(metadata):
    """
    Replicate the Jinja2 logic that maps device role/subrole
    to a filename postfix (t0, t1, t2, lt2, ft2, def).
    """
    localhost = metadata.get('localhost', {})
    switch_role = localhost.get('type', '').lower()
    switch_subrole = localhost.get('subtype', '').lower()

    if not switch_role:
        return 'def'

    if 'torrouter' in switch_role and 'mgmt' not in switch_role:
        return 't0'
    elif 'leafrouter' in switch_role and 'mgmt' not in switch_role:
        return 't1'
    elif 'lowerspinerouter' in switch_role and 'mgmt' not in switch_role:
        return 'lt2'
    elif 'spinerouter' in switch_role and 'mgmt' not in switch_role:
        if switch_subrole == 'lowerspinerouter':
            return 'lt2'
        elif switch_role == 'fabricspinerouter':
            return 'ft2'
        else:
            return 't2'
    else:
        return 'def'


def parse_ports2cable_from_j2(filepath):
    """
    Parse a ports2cable dict definition from a Jinja2 defaults file.
    Looks for: {%- set ports2cable = { ... } -%}
    Returns the dict if found, None otherwise.
    """
    try:
        with open(filepath, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        return None

    if 'ports2cable' not in content:
        return None

    # Extract the dict block between set ports2cable = { ... }
    pattern = r"set\s+ports2cable\s*=\s*\{([^}]+)\}"
    match = re.search(pattern, content, re.DOTALL)
    if not match:
        return None

    raw = match.group(1)
    result = {}
    for entry in re.finditer(r"'([^']+)'\s*:\s*'([^']+)'", raw):
        result[entry.group(1)] = entry.group(2)

    return result if result else None


def find_platform_defaults_file(platform, hwsku, postfix):
    """
    Locate the platform-specific buffers_defaults_<postfix>.j2 file.
    Search order matches SONiC template resolution.
    """
    base = '/usr/share/sonic/device'
    candidates = [
        os.path.join(base, platform, hwsku, f'buffers_defaults_{postfix}.j2'),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def resolve_ports2cable_dict(platform, hwsku, device_metadata):
    """Resolve the ports2cable mapping for a device.

    Tries platform-specific buffers_defaults file first, then falls back
    to hardcoded defaults. This is the importable equivalent of
    ``get_ports2cable()`` without subprocess calls — it only reads from
    the DUT filesystem to check for the platform-specific J2 file.

    Args:
        platform: platform string (e.g. "x86_64-arista_7060x6_64pe")
        hwsku: HwSKU string (e.g. "Arista-7060X6-64PE-O128S2")
        device_metadata: DEVICE_METADATA dict from config DB

    Returns:
        ports2cable dict (role_pair_key -> cable_length)
    """
    postfix = resolve_topology_postfix(device_metadata)
    if platform and hwsku:
        defaults_file = find_platform_defaults_file(platform, hwsku, postfix)
        if defaults_file:
            platform_ports2cable = parse_ports2cable_from_j2(defaults_file)
            if platform_ports2cable is not None:
                return platform_ports2cable
    return dict(HARDCODED_PORTS2CABLE)


def get_ports2cable():
    """Main logic: return the applicable ports2cable dict and its source."""
    metadata = get_device_metadata()
    platform, hwsku = get_platform_and_hwsku()
    postfix = resolve_topology_postfix(metadata)

    localhost = metadata.get('localhost', {})
    switch_role = localhost.get('type', 'unknown')

    print(f"Platform : {platform}")
    print(f"HwSKU    : {hwsku}")
    print(f"Role     : {switch_role}")
    print(f"Topology : {postfix}")
    print()

    defaults_file = find_platform_defaults_file(platform, hwsku, postfix)

    if defaults_file:
        print(f"Defaults file: {defaults_file}")
        platform_ports2cable = parse_ports2cable_from_j2(defaults_file)
        if platform_ports2cable is not None:
            print("Source   : platform-specific (from defaults file)\n")
            return platform_ports2cable
        else:
            print("ports2cable not defined in defaults file.")

    else:
        print("No platform-specific defaults file found.")

    print("Source   : hardcoded defaults (buffers_config.j2)\n")
    return HARDCODED_PORTS2CABLE


if __name__ == '__main__':
    ports2cable = get_ports2cable()
    print(json.dumps(ports2cable, indent=4))
