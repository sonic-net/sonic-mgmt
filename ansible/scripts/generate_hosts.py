#!/usr/bin/env python3
"""
Generate hosts file from CSV device files

This script generates a hosts file by merging device information from CSV files with an existing
base hosts file. It preserves comments and empty lines from the base file while adding new entries
in a naturally sorted order.

Features:
- Merges multiple CSV device files into a single hosts file
- Preserves existing entries, comments, and formatting from base hosts file
- Detects and warns about duplicate hostname/IP mappings
- Supports interactive mode for handling conflicts
- Uses natural sorting for hostnames (e.g., str4-7060x6 comes before str4-7060x10)

CSV File Format:
The CSV files should contain at least these columns:
- ManagementIp: IP address with optional CIDR notation (e.g., "192.168.1.10/24")
- Hostname: Device hostname (e.g., "str4-7060x6")

Usage:
    # Basic usage - generate hosts file from CSV files
    ./generate_hosts.py -o /tmp/new_hosts

    # Use a specific base hosts file
    ./generate_hosts.py -b /etc/hosts -o /tmp/new_hosts

    # Use custom CSV file pattern
    ./generate_hosts.py -c "/path/to/device_*.csv" -o /tmp/new_hosts

    # Override mode - automatically add hostnames to existing IPs without prompting
    ./generate_hosts.py -b /etc/hosts -o /tmp/new_hosts --override

Examples:
    1. Generate a new hosts file from all sonic device CSV files:
       $ ./generate_hosts.py -o ./hosts

    2. Update existing /etc/hosts with new devices:
       $ sudo ./generate_hosts.py -b /etc/hosts -o /etc/hosts.new
       $ sudo mv /etc/hosts.new /etc/hosts

    3. Process specific CSV files:
       $ ./generate_hosts.py -c "../files/sonic_lab_devices.csv" -o ./lab_hosts

Arguments:
    -b, --base-hosts    Path to the base hosts file (default: /etc/hosts)
    -o, --output        Path to the output hosts file (required)
    -c, --csv-pattern   Glob pattern for CSV files (default: ../files/sonic_*_devices.csv)
    --override          Force override without prompting when IP conflicts occur

Output Format:
    The generated hosts file will:
    - Preserve all content from the base hosts file
    - Add new entries in IP-hostname format, aligned for readability
    - Include warning comments for IPs with multiple hostnames
    - Sort new entries by hostname in natural order

Author: Ze Gan
Version: 1.0
"""

import os
import csv
import glob
import argparse
from collections import defaultdict
import re


def load_existing_hosts(file_path):
    """Load existing hosts from the base hosts file, preserving comments and empty lines."""
    hosts_map = defaultdict(list)
    original_lines = []

    if file_path and os.path.exists(file_path):
        with open(file_path, 'r') as f:
            for line in f:
                stripped_line = line.strip()
                original_lines.append(line)
                if stripped_line and not stripped_line.startswith('#'):
                    parts = stripped_line.split()
                    if len(parts) == 2:
                        ip, hostname = parts
                        hosts_map[ip].append(hostname)

    return hosts_map, original_lines


def load_csv_devices(csv_pattern):
    """Load devices from all matching CSV files."""
    devices = {}
    warnings = []

    for csv_file in glob.glob(csv_pattern):
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row['ManagementIp'].split('/')[0]  # Extract IP without CIDR
                hostname = row['Hostname']
                if hostname in devices and devices[hostname] != ip:
                    warnings.append(f"Warning: Hostname "
                                    f"{hostname} is mapped to multiple IPs: "
                                    f"{devices[hostname]} and {ip}.")
                devices[hostname] = ip

    for warning in warnings:
        print(warning)

    return devices


def natural_sort_key(s):
    """Sort key for natural sorting (e.g., str4-7060x6 comes before str4-7060x10)."""
    return [int(text) if text.isdigit() else text.lower() for text in re.split('([0-9]+)', s)]


def write_hosts_file(file_path, hosts_map, original_lines):
    """Write the hosts map to the output file, preserving comments and empty lines."""
    # First, extract all existing IP-hostname pairs from original lines
    existing_pairs = set()
    for line in original_lines:
        stripped_line = line.strip()
        if stripped_line and not stripped_line.startswith('#'):
            parts = stripped_line.split()
            if len(parts) >= 2:
                ip = parts[0]
                hostname = parts[1]
                existing_pairs.add((ip, hostname))

    with open(file_path, 'w') as f:
        # Write original lines first
        for line in original_lines:
            f.write(line)

        # Sort by hostname (natural order)
        sorted_entries = sorted(
            [(ip, hostname) for ip, hostnames in hosts_map.items() for hostname in hostnames],
            key=lambda x: natural_sort_key(x[1])
        )

        # Determine the maximum IP length for alignment
        max_ip_length = max(len(ip) for ip, _ in sorted_entries) if sorted_entries else 0

        # Write only new entries (not already in original_lines)
        for ip, hostname in sorted_entries:
            # Check if this IP-hostname pair already exists in the original file
            if (ip, hostname) in existing_pairs:
                continue

            entry = f"{ip.ljust(max_ip_length)} {hostname}"
            if len(hosts_map[ip]) > 1:
                f.write(f"# Warning: IP {ip} is mapped to multiple hostnames: {', '.join(hosts_map[ip])}\n")
            f.write(f"{entry}\n")


def main(base_hosts, output_file, csv_pattern, override):
    # Load existing hosts and preserve original lines
    existing_hosts, original_lines = load_existing_hosts(base_hosts)

    # Load devices from CSV files
    devices = load_csv_devices(csv_pattern)

    # Merge devices into existing hosts
    for hostname, ip in devices.items():
        # Skip if the mapping already exists in the original file
        if ip in existing_hosts and hostname in existing_hosts[ip]:
            continue

        if hostname in [h for hosts in existing_hosts.values() for h in hosts]:
            print(f"Hostname {hostname} already exists and is mapped to an IP.")
            continue

        if ip in existing_hosts:
            if override:
                print(f"Adding hostname {hostname} to existing IP {ip}.")
                existing_hosts[ip].append(hostname)
            else:
                print(f"IP {ip} already exists with hostnames {existing_hosts[ip]}.")
                choice = input(f"Do you want to add hostname {hostname} to this IP? (y/n): ").strip().lower()
                if choice == 'y':
                    existing_hosts[ip].append(hostname)
        else:
            existing_hosts[ip].append(hostname)

    # Write the updated hosts to the output file
    write_hosts_file(output_file, existing_hosts, original_lines)
    print(f"Hosts file generated at {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a hosts file from CSV device files.")
    parser.add_argument("-b", "--base-hosts",
                        help="Path to the base hosts file. Can be empty if no base file.",
                        default="/etc/hosts")
    parser.add_argument("-o", "--output", required=True, help="Path to the new hosts file.")
    parser.add_argument("-c", "--csv-pattern",
                        help="Glob pattern for CSV files.",
                        default=os.path.join(os.path.dirname(os.path.dirname(__file__)), "files/sonic_*_devices.csv"))
    parser.add_argument("--override", action="store_true", help="Force override without prompting.")
    args = parser.parse_args()

    main(args.base_hosts, args.output, args.csv_pattern, args.override)
