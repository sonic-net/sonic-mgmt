#!/usr/bin/env python3
"""
Update sonic_<lab>_links.csv for a generic HwSku breakout change.

This script remaps DUT port entries in links.csv from the current port layout
to a new breakout layout. It maps groups of ports from the source breakout
to the target breakout based on physical cage assignments.

Optionally updates the HwSku column in devices.csv when --hwsku is provided.

Supports uniform breakout (all cages same) and mixed breakout (different
breakout per port range).

Use --device-role fanout with --platform-json and explicit port ranges for
endpoint-aware remapping that preserves unselected cages and trunk connections.
This updates CSVs only, not the running device or its installed SKU files.

Usage:
    # Uniform breakout — all cages get the same mode
    python3 update_links_for_breakout.py \\
        --links-csv ansible/files/sonic_str4_links.csv \\
        --hostname str4-7060x6-64pe-11 \\
        --target-breakout 2x400G \\
        [--lanes-per-cage 8] \\
        [--mgmt-ports 512,513] \\
        [--dry-run]

    # Mixed breakout — different modes per port range
    python3 update_links_for_breakout.py \\
        --links-csv ansible/files/sonic_str4_links.csv \\
        --hostname str4-7060x6-64pe-11 \\
        --target-breakout "1x800G:0-255,2x400G:256-504" \\
        [--dry-run]

Examples:
    # Uniform: all cages to 2x400G
    python3 update_links_for_breakout.py \\
        --links-csv ansible/files/sonic_str4_links.csv \\
        --hostname str4-7060x6-64pe-11 \\
        --target-breakout 2x400G

    # Mixed: P32O64 — first 32 cages 1x800G, last 32 cages 2x400G
    python3 update_links_for_breakout.py \\
        --links-csv ansible/files/sonic_str4_links.csv \\
        --hostname str4-7060x6-64pe-11 \\
        --target-breakout "1x800G:0-255,2x400G:256-504"

    # Mixed: first half 4x200G, second half 8x100G
    python3 update_links_for_breakout.py \\
        --links-csv ansible/files/sonic_str4_links.csv \\
        --hostname str4-7060x6-64pe-11 \\
        --target-breakout "4x200G:0-255,8x100G:256-504"

    # Dry run to preview changes
    python3 update_links_for_breakout.py \\
        --links-csv ansible/files/sonic_str4_links.csv \\
        --hostname str4-7060x6-64pe-11 \\
        --target-breakout "1x800G:0-255,2x400G:256-504" \\
        --dry-run

    # Update both links.csv and devices.csv HwSku in one step
    python3 update_links_for_breakout.py \\
        --links-csv ansible/files/sonic_str4_links.csv \\
        --hostname str4-7060x6-64pe-11 \\
        --target-breakout 2x400G \\
        --hwsku Arista-7060X6-64PE-O128S2
"""

import argparse
from collections import defaultdict
import csv
import io
import json
import os
import re
import sys

from generate_port_config import find_matching_breakout_mode


def parse_breakout(breakout_str):
    """Parse breakout string like '2x400G' into (num_ports, speed_mbps)."""
    m = re.match(r'(\d+)x(\d+)G$', breakout_str)
    if not m:
        print(f"Error: Invalid breakout format '{breakout_str}'. Expected NxSPEEDG (e.g., 2x400G)")
        sys.exit(1)
    num_ports = int(m.group(1))
    speed_mbps = int(m.group(2)) * 1000
    return num_ports, speed_mbps


def parse_breakout_spec(spec_str):
    """Parse breakout specification into a list of (num_ports, speed_mbps, start, end) tuples.

    Supports:
      - Uniform:  "2x400G"  (applies to all non-mgmt ports)
      - Mixed:    "1x800G:0-255,2x400G:256-504"  (per port range)
    """
    ranges = []

    if ':' not in spec_str:
        # Uniform mode — single breakout for all ports
        num_ports, speed_mbps = parse_breakout(spec_str)
        ranges.append((num_ports, speed_mbps, 0, 511))
        return ranges

    for part in spec_str.split(','):
        part = part.strip()
        if ':' not in part:
            print(f"Error: Mixed breakout entry '{part}' must have format NxSPEEDG:START-END")
            sys.exit(1)
        brkout_str, range_str = part.split(':', 1)
        num_ports, speed_mbps = parse_breakout(brkout_str.strip())
        range_match = re.match(r'(\d+)-(\d+)', range_str.strip())
        if not range_match:
            print(f"Error: Invalid range '{range_str}'. Expected START-END (e.g., 0-255)")
            sys.exit(1)
        start = int(range_match.group(1))
        end = int(range_match.group(2))
        ranges.append((num_ports, speed_mbps, start, end))

    return ranges


def get_breakout_for_port(port_num, breakout_ranges, lanes_per_cage):
    """Find which breakout spec applies to this port number.

    Returns (num_ports, speed_mbps, lanes_per_port) or None if no range matches.
    """
    for num_ports, speed_mbps, start, end in breakout_ranges:
        if start <= port_num <= end:
            lanes_per_port = lanes_per_cage // num_ports
            return num_ports, speed_mbps, lanes_per_port
    return None


def get_cage_base(port_num, lanes_per_cage):
    """Get the base port number for the physical cage containing this port."""
    return (port_num // lanes_per_cage) * lanes_per_cage


def csv_split_line(line):
    """Split a CSV line respecting quoted fields (e.g. '\"100,200\"' stays as one field)."""
    reader = csv.reader(io.StringIO(line.rstrip('\n')))
    for row in reader:
        return row
    return []


def csv_join_line(parts, line_ending='\n'):
    """Join fields into a CSV line, quoting fields that contain commas."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator='')
    writer.writerow(parts)
    return buf.getvalue() + line_ending


def csv_line_ending(line):
    return line[len(line.rstrip('\r\n')):]


def parse_port_ranges(spec):
    """Parse comma-separated port numbers or inclusive numeric ranges."""
    ports = set()
    for part in spec.split(','):
        match = re.fullmatch(r'(\d+)(?:-(\d+))?', part.strip())
        if not match:
            raise ValueError("Invalid preserved port range {!r}".format(part))
        start = int(match[1])
        end = int(match[2] or match[1])
        if start > end:
            raise ValueError("Reversed preserved port range {!r}".format(part))
        ports.update(range(start, end + 1))
    return ports


def remap_fanout_links(lines, hostname, breakout_spec, platform_path, preserved_ports):
    """Remap declared fanout wiring without inventing peers or dropping assigned links."""
    if ':' not in breakout_spec:
        raise ValueError("Fanout mode requires explicit whole-cage ranges, e.g. 4x200G:0-7")
    if any(not re.fullmatch(r'\d+x\d+G\s*:\s*\d+-\d+', part.strip()) for part in breakout_spec.split(',')):
        raise ValueError("Fanout breakout entries must have format NxSPEEDG:START-END")
    ranges = parse_breakout_spec(breakout_spec)
    for num_ports, speed, start, end in ranges:
        if num_ports <= 0 or speed <= 0 or start > end:
            raise ValueError("Invalid fanout breakout range")
    ordered_ranges = sorted(ranges, key=lambda item: item[2])
    if any(left[3] >= right[2] for left, right in zip(ordered_ranges, ordered_ranges[1:])):
        raise ValueError("Fanout breakout ranges must not overlap")

    with open(platform_path) as stream:
        platform = json.load(stream)
    interfaces = platform.get('interfaces') if isinstance(platform, dict) else None
    if not isinstance(interfaces, dict) or not interfaces:
        raise ValueError("platform.json must contain a nonempty interfaces object")
    cages = {}
    platform_lanes = set()
    for name, info in interfaces.items():
        if not re.fullmatch(r'Ethernet\d+', name) or not isinstance(info, dict):
            raise ValueError("platform.json requires canonical Ethernet<N> cage definitions")
        lane_spec = info.get('lanes')
        if not isinstance(lane_spec, str):
            raise ValueError("Invalid platform lanes for {}".format(name))
        lanes = [lane.strip() for lane in lane_spec.split(',') if lane.strip()]
        if not lanes or len(lanes) != len(set(lanes)):
            raise ValueError("Invalid platform lanes for {}".format(name))
        if platform_lanes.intersection(lanes):
            raise ValueError("Platform cages have overlapping lanes")
        platform_lanes.update(lanes)
        if not isinstance(info.get('breakout_modes'), dict):
            raise ValueError("Invalid breakout_modes for {}".format(name))
        base = int(name[8:])
        cages[base] = (base + len(lanes) - 1, info)
    ordered_cages = sorted(cages)
    if any(cages[left][0] >= right for left, right in zip(ordered_cages, ordered_cages[1:])):
        raise ValueError("Overlapping platform cage address ranges")

    selected = {}
    for num_ports, speed, start, end in ranges:
        covered = 0
        for base, (last, _) in cages.items():
            if last < start or base > end:
                continue
            if base < start or last > end:
                raise ValueError("Range {}-{} splits cage Ethernet{}".format(start, end, base))
            selected[base] = (num_ports, speed)
            covered += last - base + 1
        if covered != end - start + 1:
            raise ValueError("Range {}-{} contains addresses absent from platform.json".format(start, end))

    if not lines:
        raise ValueError("Links CSV is empty")
    fields = csv_split_line(lines[0])
    required = ['StartDevice', 'StartPort', 'EndDevice', 'EndPort', 'BandWidth', 'VlanID', 'VlanMode']
    if any(fields.count(field) != 1 for field in required):
        raise ValueError("Links CSV requires unique columns: {}".format(', '.join(required)))
    columns = {field: fields.index(field) for field in required}
    connections = defaultdict(list)
    endpoints = defaultdict(int)
    seen_ports = set()
    for index, line in enumerate(lines[1:], 1):
        parts = csv_split_line(line)
        if not parts:
            continue
        if len(parts) <= max(columns.values()):
            raise ValueError("Incomplete links CSV row {}".format(index + 1))
        sides = []
        for side in ('Start', 'End'):
            device = parts[columns[side + 'Device']]
            port = parts[columns[side + 'Port']]
            endpoints[(device, port)] += 1
            if device == hostname:
                sides.append(side)
        if not sides:
            continue
        if len(sides) != 1:
            raise ValueError("Self connection for {}".format(hostname))
        side = sides[0]
        local_port = parts[columns[side + 'Port']]
        if not re.fullmatch(r'Ethernet\d+', local_port):
            raise ValueError("Fanout ports must use canonical Ethernet<N> names: {}".format(local_port))
        if local_port in seen_ports:
            raise ValueError("Duplicate fanout port {}".format(local_port))
        seen_ports.add(local_port)
        port_num = int(local_port[8:])
        bases = [base for base, (last, _) in cages.items() if base <= port_num <= last]
        if not bases:
            raise ValueError("{} is absent from platform.json".format(local_port))
        other = 'End' if side == 'Start' else 'Start'
        peer = (parts[columns[other + 'Device']], parts[columns[other + 'Port']])
        connections[bases[0]].append((index, parts, port_num, peer))
    if not seen_ports:
        raise ValueError("Hostname {!r} not found in links CSV".format(hostname))

    replacements = {}
    removed = set()
    protected = []
    processed = 0
    for base, (num_ports, speed) in selected.items():
        last, info = cages[base]
        rows = connections[base]
        if any(base <= port <= last for port in preserved_ports) or any(
                parts[columns['VlanMode']].strip().lower() == 'trunk' for _, parts, _, _ in rows):
            protected.append("Ethernet{}".format(base))
            continue
        width = last - base + 1
        mode, aliases = find_matching_breakout_mode(info.get('breakout_modes', {}), num_ports, speed)
        if width % num_ports or mode is None or not isinstance(aliases, list) or len(aliases) != num_ports:
            raise ValueError("Unsupported {}x{}G for Ethernet{}".format(num_ports, speed // 1000, base))
        targets = set(range(base, last + 1, width // num_ports))
        declared = {port for _, _, port, _ in rows}
        if targets - declared:
            missing = ', '.join("Ethernet{}".format(port) for port in sorted(targets - declared))
            raise ValueError(
                "Missing wiring for {}; supply reviewed graph entries, "
                "not inferred peers".format(missing))
        if len({peer[0] for _, _, _, peer in rows}) != 1:
            raise ValueError(
                "Cage Ethernet{} is shared between peer devices; "
                "review its wiring explicitly".format(base))
        for index, parts, port, peer in rows:
            if not all(peer) or endpoints[peer] != 1:
                raise ValueError("Missing or duplicate peer endpoint {}:{}".format(*peer))
            if port not in targets:
                if parts[columns['VlanID']].strip():
                    raise ValueError("Cannot remove VLAN-assigned link {} Ethernet{}".format(hostname, port))
                removed.add(index)
                continue
            if parts[columns['BandWidth']] != str(speed):
                parts[columns['BandWidth']] = str(speed)
                replacements[index] = csv_join_line(parts, csv_line_ending(lines[index]))
        processed += 1
    if not processed:
        raise ValueError("No unprotected cages selected")

    print("Fanout cages processed: {}; protected: {}".format(processed, ', '.join(protected) or 'none'))
    print("Updated link speeds: {}; removed unassigned graph links: {}".format(len(replacements), len(removed)))
    print("Peer endpoints, retained VLANs and all other rows are preserved.")
    return [replacements.get(index, line) for index, line in enumerate(lines) if index not in removed]


def parse_vlan_field(vlan_str):
    """Parse VLAN field like '1681', '1681-1712', or '1681,1690-1700' into a set of VLAN IDs."""
    vlans = set()
    if not vlan_str or not vlan_str.strip():
        return vlans
    cleaned = vlan_str.strip().strip('"')
    for part in cleaned.split(','):
        part = part.strip().strip('"')
        if '-' in part:
            start, end = part.split('-', 1)
            vlans.update(range(int(start.strip()), int(end.strip()) + 1))
        else:
            try:
                vlans.add(int(part))
            except ValueError:
                # Non-numeric VLAN fields (e.g. empty strings) are silently skipped
                pass
    return vlans


def format_vlan_range(vlans):
    """Format a set of VLAN IDs into a compact range string.

    Produces contiguous ranges separated by commas.
    E.g., {1, 2, 3, 5, 6, 8} -> '1-3,5-6,8'
    """
    if not vlans:
        return ''
    sorted_vlans = sorted(vlans)
    ranges = []
    start = end = sorted_vlans[0]
    for v in sorted_vlans[1:]:
        if v == end + 1:
            end = v
        else:
            ranges.append(str(start) if start == end else f'{start}-{end}')
            start = end = v
    ranges.append(str(start) if start == end else f'{start}-{end}')
    return ','.join(ranges)


def derive_devices_csv_path(links_csv_path):
    """Auto-derive devices.csv path from links.csv path.

    Only works for the main lab pattern: sonic_<lab>_links.csv -> sonic_<lab>_devices.csv.
    Returns None if the pattern doesn't match.
    """
    base = os.path.basename(links_csv_path)
    if re.match(r'^sonic_\w+_links\.csv$', base):
        devices_base = base.replace('_links.csv', '_devices.csv')
        devices_path = os.path.join(os.path.dirname(links_csv_path), devices_base)
        if os.path.isfile(devices_path):
            return devices_path
    return None


def preflight_devices_csv(csv_path, hostname):
    """Validate devices.csv before writing. Returns (rows, fieldnames) or raises SystemExit."""
    if not os.path.isfile(csv_path):
        print(f"Error: devices CSV not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    with open(csv_path, newline='') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        if not fieldnames or fieldnames.count('Hostname') != 1 or fieldnames.count('HwSku') != 1:
            print(f"Error: devices CSV requires unique columns 'Hostname' and 'HwSku': {csv_path}",
                  file=sys.stderr)
            sys.exit(1)
        rows = list(reader)

    matches = [r for r in rows if r['Hostname'] == hostname]
    if len(matches) == 0:
        print(f"Error: hostname '{hostname}' not found in {csv_path}", file=sys.stderr)
        sys.exit(1)
    if len(matches) > 1:
        print(f"Error: hostname '{hostname}' appears {len(matches)} times in {csv_path} (expected exactly 1)",
              file=sys.stderr)
        sys.exit(1)
    if matches[0]['HwSku'] is None:
        print(f"Error: hostname '{hostname}' has an incomplete HwSku field in {csv_path}", file=sys.stderr)
        sys.exit(1)

    return rows, fieldnames


def update_devices_csv(csv_path, hostname, new_hwsku, dry_run=False, preserve_format=False):
    """Update the HwSku column for hostname in devices.csv."""
    rows, fieldnames = preflight_devices_csv(csv_path, hostname)

    old_hwsku = None
    for row in rows:
        if row['Hostname'] == hostname:
            old_hwsku = row['HwSku']
            row['HwSku'] = new_hwsku
            break

    if old_hwsku == new_hwsku:
        print(f"\nDevices CSV: HwSku already '{new_hwsku}' for {hostname} — no change needed.")
        return

    print(f"\nDevices CSV update ({os.path.basename(csv_path)}):")
    print(f"  {hostname}: HwSku '{old_hwsku}' -> '{new_hwsku}'")

    if dry_run:
        print("  [DRY RUN] No changes written to devices CSV.")
    else:
        if preserve_format:
            with open(csv_path, newline='') as f:
                lines = f.readlines()
            hostname_column = fieldnames.index('Hostname')
            for index, line in enumerate(lines[1:], 1):
                parts = csv_split_line(line)
                if len(parts) > hostname_column and parts[hostname_column] == hostname:
                    parts[fieldnames.index('HwSku')] = new_hwsku
                    lines[index] = csv_join_line(parts, csv_line_ending(line))
            with open(csv_path, 'w', newline='') as f:
                f.writelines(lines)
        else:
            with open(csv_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
        print(f"  Written to {csv_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Update links.csv for generic HwSku breakout change',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Breakout spec can be uniform ("2x400G") or mixed ("1x800G:0-255,2x400G:256-504")')
    parser.add_argument('--links-csv', required=True, help='Path to sonic_<lab>_links.csv')
    parser.add_argument('--hostname', required=True, help='Device hostname (e.g., str4-7060x6-64pe-11)')
    parser.add_argument('--device-role', choices=('dut', 'fanout'), default='dut',
                        help='Use conservative, endpoint-aware CSV remapping for a fanout (default: dut)')
    parser.add_argument('--platform-json', help="Fanout's own platform.json; required for --device-role fanout")
    parser.add_argument('--preserve-ports',
                        help='Fanout port numbers/ranges whose entire cages must be preserved, e.g. 496-503,512,520')
    parser.add_argument('--target-breakout', required=True,
                        help='Target breakout: uniform "2x400G" or mixed "1x800G:0-255,2x400G:256-504"')
    parser.add_argument('--lanes-per-cage', type=int, default=8, help='Lanes per physical cage (default: 8)')
    parser.add_argument('--mgmt-ports', default='512,513',
                        help='Comma-separated management port numbers (default: 512,513)')
    parser.add_argument('--hwsku', default=None,
                        help='New HwSku name to set in devices.csv (e.g., Arista-7060X6-64PE-O128S2)')
    parser.add_argument('--devices-csv', default=None,
                        help='Path to sonic_<lab>_devices.csv (auto-derived from --links-csv if omitted)')
    parser.add_argument('--dry-run', action='store_true', help='Preview changes without writing')
    args = parser.parse_args()
    if args.device_role == 'fanout' and not args.platform_json:
        parser.error("--device-role fanout requires --platform-json")
    if args.device_role != 'fanout' and (args.platform_json or args.preserve_ports):
        parser.error("--platform-json and --preserve-ports require --device-role fanout")

    # Resolve devices.csv path and preflight if --hwsku is provided
    devices_csv_path = None
    if args.hwsku:
        devices_csv_path = args.devices_csv or derive_devices_csv_path(args.links_csv)
        if not devices_csv_path:
            print("Error: --hwsku requires --devices-csv (could not auto-derive from --links-csv path)",
                  file=sys.stderr)
            sys.exit(1)
        # Preflight before doing any work — fail early if devices.csv is invalid
        preflight_devices_csv(devices_csv_path, args.hostname)

    if args.device_role == 'fanout':
        try:
            preserved = parse_port_ranges(args.preserve_ports) if args.preserve_ports else set()
            preserved.update(parse_port_ranges(args.mgmt_ports))
            with open(args.links_csv, newline='') as f:
                lines = f.readlines()
            new_lines = remap_fanout_links(lines, args.hostname, args.target_breakout, args.platform_json, preserved)
        except (ValueError, OSError) as error:
            parser.error(str(error))
        if args.dry_run:
            print("[DRY RUN] No changes written.")
        else:
            with open(args.links_csv, 'w', newline='') as f:
                f.writelines(new_lines)
            print("Written to {}".format(args.links_csv))
        if args.hwsku:
            update_devices_csv(devices_csv_path, args.hostname, args.hwsku,
                               dry_run=args.dry_run, preserve_format=True)
        return

    breakout_ranges = parse_breakout_spec(args.target_breakout)
    mgmt_ports = set(int(p) for p in args.mgmt_ports.split(','))

    print(f"Target breakout: {args.target_breakout}")
    for num_ports, speed_mbps, start, end in breakout_ranges:
        lanes_per_port = args.lanes_per_cage // num_ports
        print(f"  Ethernet{start}-{end}: {num_ports}x{speed_mbps // 1000}G "
              f"({num_ports} ports/cage, {lanes_per_port} lanes/port)")
    print(f"  Management ports: {mgmt_ports}")
    print()

    with open(args.links_csv) as f:
        lines = f.readlines()

    # --- Pre-scan: collect existing VLANs and DUT fanout info ---
    all_vlans_in_file = set()
    old_fanout_vlans = defaultdict(set)

    for line in lines:
        parts = csv_split_line(line)
        if len(parts) > 5 and parts[5].strip():
            all_vlans_in_file.update(parse_vlan_field(parts[5]))
        if f'{args.hostname},' in line and len(parts) > 2:
            port_str = parts[1].strip()
            if port_str.startswith('Ethernet'):
                port_num = int(port_str.replace('Ethernet', ''))
                vlan_mode = parts[6].strip() if len(parts) > 6 else ''
                if port_num not in mgmt_ports and vlan_mode != 'Trunk':
                    if len(parts) > 5 and parts[2].strip():
                        old_fanout_vlans[parts[2].strip()].update(parse_vlan_field(parts[5]))

    max_vlan = max(all_vlans_in_file) if all_vlans_in_file else 0
    next_vlan = max_vlan + 1

    # --- Main processing: remap existing DUT entries ---
    new_lines = []
    seen_target_ports = set()
    cage_info = {}
    new_fanout_vlans = defaultdict(set)
    dut_lines_original = 0
    dut_lines_new = 0
    skipped = 0
    mgmt_kept = 0
    last_dut_access_idx = -1

    for line in lines:
        # Keep non-DUT lines unchanged
        if f'{args.hostname},' not in line:
            new_lines.append(line)
            continue

        dut_lines_original += 1
        parts = csv_split_line(line)
        dut_port = parts[1]
        port_num = int(dut_port.replace('Ethernet', ''))

        # Keep management ports unchanged
        if port_num in mgmt_ports:
            new_lines.append(line)
            dut_lines_new += 1
            mgmt_kept += 1
            continue

        # Find which breakout applies to this port
        brkout = get_breakout_for_port(port_num, breakout_ranges, args.lanes_per_cage)
        if brkout is None:
            skipped += 1
            continue
        num_ports, speed_mbps, lanes_per_port = brkout

        # Map source port to target port within the same cage
        cage_base = get_cage_base(port_num, args.lanes_per_cage)
        target_port_num = cage_base + ((port_num - cage_base) // lanes_per_port) * lanes_per_port

        # Track cage info for expansion
        if cage_base not in cage_info:
            all_targets = set(cage_base + i * lanes_per_port for i in range(num_ports))
            cage_info[cage_base] = {
                'template': parts[:],
                'covered': set(),
                'all_targets': all_targets,
                'speed_mbps': speed_mbps,
            }

        # Skip if we already have a link for this target port
        if target_port_num in seen_target_ports:
            skipped += 1
            continue

        seen_target_ports.add(target_port_num)
        cage_info[cage_base]['covered'].add(target_port_num)
        target_port = f'Ethernet{target_port_num}'

        # Update fanout port with the same delta as DUT port remapping
        fanout_port_str = parts[3].strip()
        if fanout_port_str.startswith('Ethernet'):
            fanout_num = int(fanout_port_str.replace('Ethernet', ''))
            parts[3] = f'Ethernet{fanout_num + (target_port_num - port_num)}'

        # Update: DUT port name and speed (VlanID preserved from source)
        parts[1] = target_port
        parts[4] = str(speed_mbps)
        if len(parts) > 5 and parts[5].strip() and parts[2].strip():
            new_fanout_vlans[parts[2].strip()].update(parse_vlan_field(parts[5]))

        last_dut_access_idx = len(new_lines)
        new_lines.append(csv_join_line(parts))
        dut_lines_new += 1

    # --- Generate expansion entries for target ports missing a source entry ---
    expansion_entries = []
    for cage_base in sorted(cage_info):
        info = cage_info[cage_base]
        missing = sorted(info['all_targets'] - info['covered'])
        for port_num in missing:
            entry = info['template'][:]
            entry[1] = f'Ethernet{port_num}'
            # Compute correct fanout port based on offset from template
            tpl_dut = info['template'][1].strip()
            tpl_fan = info['template'][3].strip()
            if tpl_dut.startswith('Ethernet') and tpl_fan.startswith('Ethernet'):
                tpl_dut_num = int(tpl_dut.replace('Ethernet', ''))
                tpl_fan_num = int(tpl_fan.replace('Ethernet', ''))
                entry[3] = f'Ethernet{tpl_fan_num + (port_num - tpl_dut_num)}'
            entry[4] = str(info['speed_mbps'])
            entry[5] = str(next_vlan)
            if len(entry) > 6:
                entry[6] = 'Access'
            new_fanout_vlans[entry[2].strip()].add(next_vlan)
            next_vlan += 1
            expansion_entries.append(csv_join_line(entry))
            dut_lines_new += 1

    # --- Generate entries for cages with no source entries at all ---
    # Enumerate all expected cages from breakout ranges and find ones not in cage_info
    for num_ports, speed_mbps, start, end in breakout_ranges:
        lanes_per_port = args.lanes_per_cage // num_ports
        # Find a donor template from the nearest populated cage in this range
        donor_base = None
        for cb in sorted(cage_info):
            if start <= cb <= end:
                donor_base = cb
                break
        if donor_base is None:
            continue
        donor = cage_info[donor_base]

        for cage_base in range(start, end + 1, args.lanes_per_cage):
            if cage_base in cage_info:
                continue
            # Generate all target ports for this empty cage
            for i in range(num_ports):
                port_num = cage_base + i * lanes_per_port
                if port_num > end:
                    break
                entry = donor['template'][:]
                entry[0] = args.hostname
                entry[1] = f'Ethernet{port_num}'
                # Compute fanout port from donor template offset
                tpl_dut = donor['template'][1].strip()
                tpl_fan = donor['template'][3].strip()
                if tpl_dut.startswith('Ethernet') and tpl_fan.startswith('Ethernet'):
                    tpl_dut_num = int(tpl_dut.replace('Ethernet', ''))
                    tpl_fan_num = int(tpl_fan.replace('Ethernet', ''))
                    entry[3] = f'Ethernet{tpl_fan_num + (port_num - tpl_dut_num)}'
                entry[4] = str(speed_mbps)
                entry[5] = str(next_vlan)
                if len(entry) > 6:
                    entry[6] = 'Access'
                new_fanout_vlans[entry[2].strip()].add(next_vlan)
                next_vlan += 1
                expansion_entries.append(csv_join_line(entry))
                dut_lines_new += 1

    if expansion_entries:
        insert_pos = last_dut_access_idx + 1 if last_dut_access_idx >= 0 else len(new_lines)
        for i, entry in enumerate(expansion_entries):
            new_lines.insert(insert_pos + i, entry)

    # --- Update trunk/root fanout VLAN range ---
    trunk_updated = False
    dut_fanout_devices = old_fanout_vlans.keys() | new_fanout_vlans.keys()
    if dut_fanout_devices:
        for i, line in enumerate(new_lines):
            parts = csv_split_line(line)
            if len(parts) > 6 and parts[6].strip() == 'Trunk':
                start_dev = parts[0].strip()
                end_dev = parts[2].strip()
                fanouts = {start_dev, end_dev} & dut_fanout_devices
                if fanouts:
                    trunk_vlans = parse_vlan_field(parts[5])
                    old_vlans = set()
                    new_vlans = set()
                    for fanout in fanouts:
                        old_vlans.update(old_fanout_vlans.get(fanout, ()))
                        new_vlans.update(new_fanout_vlans.get(fanout, ()))
                    updated_vlans = (trunk_vlans - old_vlans) | new_vlans
                    if updated_vlans != trunk_vlans:
                        parts[5] = format_vlan_range(updated_vlans)
                        new_lines[i] = csv_join_line(parts)
                        trunk_updated = True

    # Summary
    total_non_mgmt = dut_lines_new - mgmt_kept
    print("Results:")
    print(f"  Original DUT entries: {dut_lines_original}")
    print(f"  New DUT entries: {dut_lines_new} ({total_non_mgmt} ports + {mgmt_kept} mgmt)")
    print(f"  Removed (unmapped to target): {skipped}")
    if expansion_entries:
        vlan_start = next_vlan - len(expansion_entries)
        print(f"  Expansion: {len(expansion_entries)} new entries added "
              f"(VLANs {vlan_start}-{next_vlan - 1})")

    if trunk_updated:
        print("  Trunk VLAN range updated for root fanout")
    print()

    # Show sample entries
    dut_new = [line for line in new_lines if f'{args.hostname},' in line]
    print("Sample entries (first 5):")
    for line in dut_new[:5]:
        print(f"  {line.rstrip()}")
    print("Sample entries (last 3):")
    for line in dut_new[-3:]:
        print(f"  {line.rstrip()}")

    if args.dry_run:
        print("\n[DRY RUN] No changes written.")
    else:
        with open(args.links_csv, 'w') as f:
            f.writelines(new_lines)
        print(f"\nWritten to {args.links_csv}")

    # Update devices.csv if --hwsku was provided
    if args.hwsku and devices_csv_path:
        update_devices_csv(devices_csv_path, args.hostname, args.hwsku, dry_run=args.dry_run)


if __name__ == '__main__':
    main()
