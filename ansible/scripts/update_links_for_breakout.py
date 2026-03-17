#!/usr/bin/env python3
"""
Update sonic_<lab>_links.csv for a generic HwSku breakout change.

This script remaps DUT port entries in links.csv from the current port layout
to a new breakout layout. It maps groups of ports from the source breakout
to the target breakout based on physical cage assignments.

Usage:
    python3 update_links_for_breakout.py \
        --links-csv ansible/files/sonic_str4_links.csv \
        --hostname str4-7060x6-64pe-11 \
        --target-breakout 2x400G \
        [--lanes-per-cage 8] \
        [--mgmt-ports 512,513] \
        [--dry-run]

Examples:
    # Remap from C256S2 (4x200G) to O128S2 (2x400G)
    python3 update_links_for_breakout.py \
        --links-csv ansible/files/sonic_str4_links.csv \
        --hostname str4-7060x6-64pe-11 \
        --target-breakout 2x400G

    # Remap to 4x200G breakout
    python3 update_links_for_breakout.py \
        --links-csv ansible/files/sonic_str4_links.csv \
        --hostname str4-7060x6-64pe-11 \
        --target-breakout 4x200G

    # Dry run to preview changes
    python3 update_links_for_breakout.py \
        --links-csv ansible/files/sonic_str4_links.csv \
        --hostname str4-7060x6-64pe-11 \
        --target-breakout 2x400G \
        --dry-run
"""

import argparse
import re
import sys


def parse_breakout(breakout_str):
    """Parse breakout string like '2x400G' into (num_ports, speed_mbps)."""
    m = re.match(r'(\d+)x(\d+)G', breakout_str)
    if not m:
        print(f"Error: Invalid breakout format '{breakout_str}'. Expected NxSPEEDG (e.g., 2x400G)")
        sys.exit(1)
    num_ports = int(m.group(1))
    speed_mbps = int(m.group(2)) * 1000
    return num_ports, speed_mbps


def get_cage_base(port_num, lanes_per_cage):
    """Get the base port number for the physical cage containing this port."""
    return (port_num // lanes_per_cage) * lanes_per_cage


def main():
    parser = argparse.ArgumentParser(description='Update links.csv for generic HwSku breakout change')
    parser.add_argument('--links-csv', required=True, help='Path to sonic_<lab>_links.csv')
    parser.add_argument('--hostname', required=True, help='DUT hostname (e.g., str4-7060x6-64pe-11)')
    parser.add_argument('--target-breakout', required=True, help='Target breakout mode (e.g., 2x400G, 4x200G)')
    parser.add_argument('--lanes-per-cage', type=int, default=8, help='Lanes per physical cage (default: 8)')
    parser.add_argument('--mgmt-ports', default='512,513', help='Comma-separated management port numbers (default: 512,513)')
    parser.add_argument('--dry-run', action='store_true', help='Preview changes without writing')
    args = parser.parse_args()

    num_ports, speed_mbps = parse_breakout(args.target_breakout)
    lanes_per_port = args.lanes_per_cage // num_ports
    mgmt_ports = set(int(p) for p in args.mgmt_ports.split(','))

    print(f"Target breakout: {args.target_breakout}")
    print(f"  Ports per cage: {num_ports}")
    print(f"  Lanes per port: {lanes_per_port}")
    print(f"  Speed: {speed_mbps}")
    print(f"  Management ports: {mgmt_ports}")
    print()

    with open(args.links_csv) as f:
        lines = f.readlines()

    new_lines = []
    seen_target_ports = set()
    dut_lines_original = 0
    dut_lines_new = 0
    skipped = 0

    for line in lines:
        # Keep non-DUT lines unchanged
        if f'{args.hostname},' not in line:
            new_lines.append(line)
            continue

        dut_lines_original += 1
        parts = line.rstrip('\n').split(',')
        dut_port = parts[1]
        port_num = int(dut_port.replace('Ethernet', ''))

        # Keep management ports unchanged
        if port_num in mgmt_ports:
            new_lines.append(line)
            dut_lines_new += 1
            continue

        # Map source port to target port within the same cage
        cage_base = get_cage_base(port_num, args.lanes_per_cage)

        # Generate the target port number within this cage
        # For each cage, generate ports at: cage_base, cage_base + lanes_per_port, ...
        # Map the source port to the nearest target port
        target_port_num = cage_base + ((port_num - cage_base) // lanes_per_port) * lanes_per_port

        # Skip if we already have a link for this target port
        if target_port_num in seen_target_ports:
            skipped += 1
            continue

        seen_target_ports.add(target_port_num)
        target_port = f'Ethernet{target_port_num}'

        # Update: DUT port name and speed
        parts[1] = target_port
        parts[4] = str(speed_mbps)
        new_lines.append(','.join(parts) + '\n')
        dut_lines_new += 1

    # Summary
    total_non_mgmt = len(seen_target_ports)
    total_with_mgmt = dut_lines_new
    print(f"Results:")
    print(f"  Original DUT entries: {dut_lines_original}")
    print(f"  New DUT entries: {dut_lines_new} ({total_non_mgmt} ports + {len(mgmt_ports)} mgmt)")
    print(f"  Skipped duplicates: {skipped}")
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