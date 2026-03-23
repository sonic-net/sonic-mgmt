#!/usr/bin/env python3
"""
Generate a PORT table JSON from links.csv + platform.json.

This script runs on the sonic-mgmt server and produces a config_db-compatible
PORT table JSON file that can be applied directly to a DUT — no port_config.ini,
hwsku.json, minigraph, or deploy-mg needed.

Data sources:
  - links.csv: provides port names and speeds (the "what")
  - platform.json: provides lanes, aliases, indices, breakout_modes (the "how")
  - devices.csv: provides hwsku for DEVICE_METADATA

Output:
  A JSON file with PORT and DEVICE_METADATA tables, suitable for:
    scp output.json dut:/etc/sonic/port_config_override.json
    ssh dut "sudo sonic-cfggen -j /etc/sonic/port_config_override.json --write-to-db"

Usage:
    python3 generate_port_config.py \\
        --links-csv ansible/files/sonic_str4_links.csv \\
        --devices-csv ansible/files/sonic_str4_devices.csv \\
        --platform-json /path/to/sonic-buildimage/device/<platform>/platform.json \\
        --hostname str4-7060x6-64pe-11 \\
        --output /tmp/port_config_override.json

    # Or auto-detect platform.json from sonic-buildimage repo:
    python3 generate_port_config.py \\
        --links-csv ansible/files/sonic_str4_links.csv \\
        --devices-csv ansible/files/sonic_str4_devices.csv \\
        --buildimage-root /home/user/sonic-buildimage \\
        --hostname str4-7060x6-64pe-11 \\
        --output /tmp/port_config_override.json

    # Apply on DUT:
    scp /tmp/port_config_override.json dut:/etc/sonic/
    ssh dut "sudo sonic-cfggen -j /etc/sonic/port_config_override.json --write-to-db && sudo config save -y"
"""

import argparse
import csv
import glob
import json
import os
import re
import sys


def read_links_csv(csv_path, hostname):
    """Extract {port_name: speed} for a given hostname from links.csv."""
    port_speeds = {}
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['StartDevice'] == hostname:
                port_speeds[row['StartPort']] = row['BandWidth']
            elif row['EndDevice'] == hostname:
                port_speeds[row['EndPort']] = row['BandWidth']
    return port_speeds


def read_devices_csv(csv_path, hostname):
    """Extract device info for a given hostname from devices.csv."""
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['Hostname'] == hostname:
                return row
    return None


def find_platform_json(buildimage_root, hwsku):
    """Auto-detect platform.json path from sonic-buildimage repo using hwsku."""
    pattern = os.path.join(buildimage_root, 'device', '*', '*', 'platform.json')
    for pj_path in glob.glob(pattern):
        platform_dir = os.path.dirname(pj_path)
        # Check if any hwsku dir under this platform matches (exact or base)
        for entry in os.listdir(platform_dir):
            entry_path = os.path.join(platform_dir, entry)
            if os.path.isdir(entry_path) and (entry == hwsku or hwsku.startswith(entry)):
                return pj_path
    return None


def find_matching_breakout_mode(breakout_modes, num_ports, speed_mbps):
    """Find matching breakout mode in platform.json's breakout_modes dict."""
    speed_g = speed_mbps // 1000
    for bmode_key, bmode_aliases in breakout_modes.items():
        bmode_clean = re.sub(r'\[.*\]', '', bmode_key)
        m = re.match(r'(\d+)x(\d+)G', bmode_clean)
        if not m or int(m.group(1)) != num_ports:
            continue
        default_speed_g = int(m.group(2))
        if default_speed_g == speed_g:
            return bmode_key, bmode_aliases
        bracket_match = re.search(r'\[(.*?)\]', bmode_key)
        if bracket_match:
            supported = [int(s.strip().replace('G', '')) for s in bracket_match.group(1).split(',')]
            if speed_g in supported:
                return bmode_key, bmode_aliases
    return None, None


def generate_port_table(port_speeds, platform_json_path):
    """
    Generate a PORT table from port names/speeds + platform.json.

    For each physical cage in platform.json, finds which ports from port_speeds
    belong to it, determines the breakout mode, and generates PORT entries with
    correct lanes, aliases, indices, speed, and FEC.
    """
    with open(platform_json_path) as f:
        platform_data = json.load(f)

    if 'interfaces' not in platform_data:
        print("Error: platform.json has no 'interfaces' section", file=sys.stderr)
        return None

    plat_intfs = platform_data['interfaces']
    port_table = {}

    for cage_name in sorted(plat_intfs.keys(), key=lambda x: int(x.replace('Ethernet', ''))):
        cage_info = plat_intfs[cage_name]
        cage_base = int(cage_name.replace('Ethernet', ''))
        lane_str = cage_info.get('lanes', '')
        lane_list = [l.strip() for l in lane_str.split(',') if l.strip()]
        total_lanes = len(lane_list)
        if total_lanes == 0:
            continue

        index_str = cage_info.get('index', '')
        index_list = [i.strip() for i in index_str.split(',') if i.strip()]
        breakout_modes = cage_info.get('breakout_modes', {})

        # Find which ports from port_speeds belong to this cage
        ports_in_cage = {}
        for pname, pspeed in port_speeds.items():
            if not pname.startswith('Ethernet') or not pname[8:].isdigit():
                continue
            pnum = int(pname[8:])
            if cage_base <= pnum < cage_base + total_lanes:
                ports_in_cage[pname] = int(pspeed)

        if not ports_in_cage:
            continue

        num_ports = len(ports_in_cage)
        speed_mbps = list(ports_in_cage.values())[0]

        # Find matching breakout mode for alias resolution
        bmode_key, aliases = find_matching_breakout_mode(breakout_modes, num_ports, speed_mbps)

        # Fallback alias generation
        if aliases is None:
            cage_idx = index_list[0] if index_list else str(cage_base // total_lanes + 1)
            if num_ports == 1:
                aliases = ['etp{}'.format(cage_idx)]
            else:
                aliases = ['etp{}{}'.format(cage_idx, chr(ord('a') + i)) for i in range(num_ports)]

        # Generate PORT entries
        lanes_per_port = total_lanes // num_ports
        sorted_port_names = sorted(ports_in_cage.keys(), key=lambda x: int(x[8:]))

        for sub_idx, port_name in enumerate(sorted_port_names):
            start_lane = sub_idx * lanes_per_port
            end_lane = start_lane + lanes_per_port
            sub_lanes = ','.join(lane_list[start_lane:end_lane])

            alias = aliases[sub_idx] if sub_idx < len(aliases) else port_name
            index = index_list[start_lane] if start_lane < len(index_list) else '1'

            port_entry = {
                'alias': alias,
                'lanes': sub_lanes,
                'speed': str(speed_mbps),
                'index': index,
                'admin_status': 'up',
                'mtu': '9100',
                'tpid': '0x8100',
                'pfc_asym': 'off'
            }

            if speed_mbps >= 200000:
                port_entry['fec'] = 'rs'

            port_table[port_name] = port_entry

    return port_table


def validate_port_config(port_speeds, platform_json_path, hwsku):
    """
    Validate that ports in links.csv match valid breakout modes in platform.json
    and are consistent with the HwSKU pattern.

    Known HwSKU patterns for 7060X6-64PE (64 cages, 8 lanes each):
      Uniform:  O128 → all 64 cages 2x, C256 → 32 odd cages 8x, 256x200G → all 64 cages 4x
      Split:    P32O64 → cages 1-32 1x + cages 33-64 2x
      Copper:   C* → only odd-numbered cages used (even cages skipped)

    Returns list of warning strings. Empty list = all good.
    """
    with open(platform_json_path) as f:
        platform_data = json.load(f)

    plat_intfs = platform_data.get('interfaces', {})
    warnings = []

    # Build per-cage port counts from links.csv
    cage_ports = {}
    cage_speeds = {}
    orphan_ports = []

    for pname, pspeed in port_speeds.items():
        if not pname.startswith('Ethernet') or not pname[8:].isdigit():
            continue
        pnum = int(pname[8:])

        # Find which cage this port belongs to
        matched_cage = None
        for cage_name, cage_info in plat_intfs.items():
            cage_base = int(cage_name.replace('Ethernet', ''))
            lane_str = cage_info.get('lanes', '')
            total_lanes = len([l for l in lane_str.split(',') if l.strip()])
            if total_lanes > 0 and cage_base <= pnum < cage_base + total_lanes:
                matched_cage = cage_name
                break

        if matched_cage is None:
            orphan_ports.append(pname)
            continue

        cage_ports.setdefault(matched_cage, []).append(pname)
        cage_speeds.setdefault(matched_cage, set()).add(int(pspeed))

    # Check 1: Orphan ports (not in any cage)
    if orphan_ports:
        warnings.append("Ports not in any platform.json cage: {}".format(
            ', '.join(sorted(orphan_ports, key=lambda x: int(x[8:])))))

    # Check 2: Mixed speeds within a cage
    for cage, speeds in cage_speeds.items():
        if len(speeds) > 1:
            warnings.append("Cage {} has mixed speeds: {} (all ports in a cage must have the same speed)".format(
                cage, ', '.join(str(s) for s in sorted(speeds))))

    # Check 3: Breakout mode exists in platform.json
    for cage_name, ports in cage_ports.items():
        cage_info = plat_intfs[cage_name]
        breakout_modes = cage_info.get('breakout_modes', {})
        num_ports = len(ports)
        speed_mbps = list(cage_speeds[cage_name])[0] if len(cage_speeds[cage_name]) == 1 else 0

        if speed_mbps > 0:
            bmode_key, _ = find_matching_breakout_mode(breakout_modes, num_ports, speed_mbps)
            if bmode_key is None:
                speed_g = speed_mbps // 1000
                available = ', '.join(sorted(breakout_modes.keys()))
                warnings.append("Cage {} ({}): no matching breakout mode for {}x{}G. Available: [{}]".format(
                    cage_name,
                    ', '.join(sorted(ports, key=lambda x: int(x[8:]))),
                    num_ports, speed_g, available))

    # Check 4: HwSKU-specific pattern validation
    if hwsku and hwsku != 'Unknown':
        total_non_mgmt = len([p for p in port_speeds if p.startswith('Ethernet') and
                              p[8:].isdigit() and int(p[8:]) < 512])
        total_cages = len(plat_intfs)
        non_mgmt_cages = len([k for k in plat_intfs if int(k.replace('Ethernet', '')) < 512])
        used_cages = len([c for c in cage_ports if int(c.replace('Ethernet', '')) < 512])

        # Detect copper pattern (C* HwSKUs use only odd cages)
        if re.search(r'-C\d+', hwsku):
            even_cages_used = []
            for cage in cage_ports:
                cage_num = int(cage.replace('Ethernet', ''))
                if cage_num < 512:
                    cage_index = cage_num // 8
                    if cage_index % 2 == 1:  # even-numbered cages (0-indexed odd = physical even)
                        even_cages_used.append(cage)
            if even_cages_used:
                warnings.append("HwSKU '{}' is copper (C*) but links.csv uses even-numbered cages: {}. "
                                "Copper HwSKUs typically use only odd-numbered cages.".format(
                                    hwsku, ', '.join(sorted(even_cages_used, key=lambda x: int(x[8:])))))

        # Detect split pattern (P* HwSKUs: first half 1x, second half broken out)
        if re.search(r'-P\d+', hwsku):
            first_half_breakouts = set()
            second_half_breakouts = set()
            for cage, ports in cage_ports.items():
                cage_num = int(cage.replace('Ethernet', ''))
                if cage_num < 512:
                    cage_index = cage_num // 8
                    if cage_index < non_mgmt_cages // 2:
                        first_half_breakouts.add(len(ports))
                    else:
                        second_half_breakouts.add(len(ports))
            if len(first_half_breakouts) > 1:
                warnings.append("HwSKU '{}' is split (P*) but first half cages have inconsistent breakout: {}".format(
                    hwsku, first_half_breakouts))
            if len(second_half_breakouts) > 1:
                warnings.append("HwSKU '{}' is split (P*) but second half cages have inconsistent breakout: {}".format(
                    hwsku, second_half_breakouts))

    return warnings


def main():
    parser = argparse.ArgumentParser(
        description='Generate PORT table JSON from links.csv + platform.json',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--links-csv', required=True,
                        help='Path to sonic_<lab>_links.csv')
    parser.add_argument('--devices-csv', required=True,
                        help='Path to sonic_<lab>_devices.csv')
    parser.add_argument('--hostname', required=True,
                        help='DUT hostname (e.g., str4-7060x6-64pe-11)')
    parser.add_argument('--platform-json', default=None,
                        help='Path to platform.json (from DUT or sonic-buildimage)')
    parser.add_argument('--buildimage-root', default=None,
                        help='Path to sonic-buildimage repo root (auto-detects platform.json)')
    parser.add_argument('--output', '-o', default=None,
                        help='Output JSON file path (default: stdout)')
    parser.add_argument('--full-config', action='store_true',
                        help='Include DEVICE_METADATA in output')
    args = parser.parse_args()

    # Read port speeds from links.csv
    port_speeds = read_links_csv(args.links_csv, args.hostname)
    if not port_speeds:
        print("Error: no ports found for hostname '{}' in {}".format(
            args.hostname, args.links_csv), file=sys.stderr)
        sys.exit(1)
    print("Found {} ports for {} in links.csv".format(len(port_speeds), args.hostname),
          file=sys.stderr)

    # Read device info from devices.csv
    device_info = read_devices_csv(args.devices_csv, args.hostname)
    if not device_info:
        print("Warning: hostname '{}' not found in {}".format(
            args.hostname, args.devices_csv), file=sys.stderr)
        device_info = {}

    hwsku = device_info.get('HwSku', 'Unknown')

    # Resolve platform.json path
    platform_json = args.platform_json
    if not platform_json and args.buildimage_root:
        platform_json = find_platform_json(args.buildimage_root, hwsku)
        if platform_json:
            print("Auto-detected platform.json: {}".format(platform_json), file=sys.stderr)
    if not platform_json:
        print("Error: --platform-json or --buildimage-root required", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(platform_json):
        print("Error: platform.json not found at {}".format(platform_json), file=sys.stderr)
        sys.exit(1)

    # Generate PORT table
    port_table = generate_port_table(port_speeds, platform_json)
    if not port_table:
        print("Error: failed to generate PORT table", file=sys.stderr)
        sys.exit(1)

    # Validate links.csv ports against platform.json and HwSKU pattern
    validation_warnings = validate_port_config(port_speeds, platform_json, hwsku)
    if validation_warnings:
        print("\nValidation warnings:", file=sys.stderr)
        for w in validation_warnings:
            print("  WARNING: {}".format(w), file=sys.stderr)
        print("", file=sys.stderr)

    # Build output config
    config = {"PORT": port_table}

    if args.full_config and device_info:
        config["DEVICE_METADATA"] = {
            "localhost": {
                "hwsku": hwsku,
                "hostname": args.hostname,
                "type": device_info.get('Type', 'LeafRouter'),
                "synchronous_mode": "enable",
                "yang_config_validation": "disable"
            }
        }

    # Summary
    print("Generated PORT table: {} entries".format(len(port_table)), file=sys.stderr)
    speeds = {}
    for p in port_table.values():
        s = int(p['speed']) // 1000
        speeds[s] = speeds.get(s, 0) + 1
    for s in sorted(speeds.keys(), reverse=True):
        print("  {}x {}G".format(speeds[s], s), file=sys.stderr)

    # Output
    output = json.dumps(config, indent=4, sort_keys=True)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output + '\n')
        print("Written to {}".format(args.output), file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
