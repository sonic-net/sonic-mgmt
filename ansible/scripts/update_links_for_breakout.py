#!/usr/bin/env python3
"""
Update sonic_<lab>_links.csv for a generic HwSku breakout change.

This script remaps DUT port entries in links.csv from the current port layout
to a new breakout layout. It maps groups of ports from the source breakout
to the target breakout based on physical cage assignments.

Supports uniform breakout (all cages same) and mixed breakout (different
breakout per port range).

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
"""

import argparse
import csv
import io
import re
import sys


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


def csv_join_line(parts):
    """Join fields into a CSV line, quoting fields that contain commas."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator='')
    writer.writerow(parts)
    return buf.getvalue() + '\n'


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


def main():
    parser = argparse.ArgumentParser(
        description='Update links.csv for generic HwSku breakout change',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Breakout spec can be uniform ("2x400G") or mixed ("1x800G:0-255,2x400G:256-504")')
    parser.add_argument('--links-csv', required=True, help='Path to sonic_<lab>_links.csv')
    parser.add_argument('--hostname', required=True, help='DUT hostname (e.g., str4-7060x6-64pe-11)')
    parser.add_argument('--target-breakout', required=True,
                        help='Target breakout: uniform "2x400G" or mixed "1x800G:0-255,2x400G:256-504"')
    parser.add_argument('--lanes-per-cage', type=int, default=8, help='Lanes per physical cage (default: 8)')
    parser.add_argument('--mgmt-ports', default='512,513',
                        help='Comma-separated management port numbers (default: 512,513)')
    parser.add_argument('--dry-run', action='store_true', help='Preview changes without writing')
    args = parser.parse_args()

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
    old_dut_vlans = set()
    dut_fanout_devices = set()

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
                    if len(parts) > 5:
                        old_dut_vlans.update(parse_vlan_field(parts[5]))
                    if parts[2].strip():
                        dut_fanout_devices.add(parts[2].strip())

    max_vlan = max(all_vlans_in_file) if all_vlans_in_file else 0
    next_vlan = max_vlan + 1

    # --- Main processing: remap existing DUT entries ---
    new_lines = []
    seen_target_ports = set()
    cage_info = {}
    new_dut_vlans = set()
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
        if len(parts) > 5 and parts[5].strip():
            new_dut_vlans.update(parse_vlan_field(parts[5]))

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
            new_dut_vlans.add(next_vlan)
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
                new_dut_vlans.add(next_vlan)
                next_vlan += 1
                expansion_entries.append(csv_join_line(entry))
                dut_lines_new += 1

    if expansion_entries:
        insert_pos = last_dut_access_idx + 1 if last_dut_access_idx >= 0 else len(new_lines)
        for i, entry in enumerate(expansion_entries):
            new_lines.insert(insert_pos + i, entry)

    # --- Update trunk/root fanout VLAN range ---
    trunk_updated = False
    if dut_fanout_devices and new_dut_vlans:
        for i, line in enumerate(new_lines):
            parts = csv_split_line(line)
            if len(parts) > 6 and parts[6].strip() == 'Trunk':
                start_dev = parts[0].strip()
                end_dev = parts[2].strip()
                if start_dev in dut_fanout_devices or end_dev in dut_fanout_devices:
                    trunk_vlans = parse_vlan_field(parts[5])
                    trunk_vlans -= old_dut_vlans
                    trunk_vlans |= new_dut_vlans
                    # Trunk lines use min-max range to avoid commas in CSV
                    vlan_min = min(trunk_vlans)
                    vlan_max = max(trunk_vlans)
                    parts[5] = f'{vlan_min}-{vlan_max}'
                    new_lines[i] = csv_join_line(parts)
                    trunk_updated = True

    # Summary
    total_non_mgmt = dut_lines_new - mgmt_kept
    print(f"Results:")
    print(f"  Original DUT entries: {dut_lines_original}")
    print(f"  New DUT entries: {dut_lines_new} ({total_non_mgmt} ports + {mgmt_kept} mgmt)")
    print(f"  Skipped duplicates: {skipped}")
    if expansion_entries:
        vlan_start = next_vlan - len(expansion_entries)
        print(f"  Expansion: {len(expansion_entries)} new entries added "
              f"(VLANs {vlan_start}-{next_vlan - 1})")
    if trunk_updated:
        print(f"  Trunk VLAN range updated for root fanout")
    print()

    # Show sample entries
    dut_new = [l for l in new_lines if f'{args.hostname},' in l]
    print("Sample entries (first 5):")
    for l in dut_new[:5]:
        print(f"  {l.rstrip()}")
    print("Sample entries (last 3):")
    for l in dut_new[-3:]:
        print(f"  {l.rstrip()}")

    if args.dry_run:
        print("\n[DRY RUN] No changes written.")
    else:
        with open(args.links_csv, 'w') as f:
            f.writelines(new_lines)
        print(f"\nWritten to {args.links_csv}")


if __name__ == '__main__':
    main()

