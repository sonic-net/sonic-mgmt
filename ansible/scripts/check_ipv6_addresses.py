#!/usr/bin/env python3
"""
IPv6 Address Checker and Fixer for SONiC Test Infrastructure

This script checks and optionally fixes IPv6 addresses in YAML configuration files
based on their corresponding IPv4 addresses. It supports two types of files:

1. Lab inventory files (str*, bjw*, svc*): These files contain host definitions
   with ansible_host (IPv4) and ansible_hostv6 (IPv6) fields.

2. Testbed configuration files (testbed*.yaml): These files contain test configurations
   with ptf_ip (IPv4) and ptf_ipv6 (IPv6) fields.

The script uses a conversion function to calculate the expected IPv6 address based on
the IPv4 address and lab location, then compares it with the actual IPv6 address in
the file.

Usage:
    python check_ipv6_addresses.py [OPTIONS] FILE1 [FILE2 ...]

Options:
    -i, --inplace       Modify files in place (fix incorrect IPv6 addresses)
    -l, --lab-location  Specify lab location (str, bjw, bjw3, svc)
                        If not specified, will be auto-detected from filename
    -p, --pattern       Regex pattern to filter entries by conf-name (testbed files only)

Examples:
    # Check IPv6 addresses in a single file (dry run)
    python check_ipv6_addresses.py str-acs-serv-01.yml

    # Check multiple files
    python check_ipv6_addresses.py str*.yml bjw*.yml

    # Fix IPv6 addresses in place
    python check_ipv6_addresses.py -i str-acs-serv-01.yml

    # Check testbed file with pattern matching
    python check_ipv6_addresses.py -p "vms-kvm-t0" testbed.yaml

    # Fix testbed entries matching pattern
    python check_ipv6_addresses.py -i -p "vms-kvm-t1.*64" testbed.yaml

    # Override lab location detection
    python check_ipv6_addresses.py -l bjw str-acs-serv-01.yml

Output:
    - In check mode (default): Lists all IPv6 mismatches found
    - In fix mode (-i): Shows what was changed and updates the files

Exit codes:
    0: Success (no issues found or all issues fixed)
    1: Issues found (in check mode)

Note:
    The script preserves the original file formatting and only modifies the
    incorrect IPv6 address values. It requires the get_v6_addr_by_v4.py
    module to perform the IPv4 to IPv6 conversion.
"""

import yaml
import argparse
import sys
import re
import ipaddress
import os
from pathlib import Path
from get_v6_addr_by_v4 import convert_v4_addr_to_v6


def get_lab_location_from_filename(filename):
    """Determine lab location from filename."""
    if filename.startswith('str'):
        return 'str'
    elif filename.startswith('bjw3'):
        return 'bjw3'
    elif filename.startswith('bjw'):
        return 'bjw'
    elif filename.startswith('svc'):
        return 'svc'
    else:
        # Cannot determine lab location
        return None


def get_lab_location_from_inv_name(inv_name):
    """Determine lab location from inv_name field."""
    if not inv_name:
        return None
    
    # Handle various inv_name patterns
    if inv_name in ['str', 'str2', 'str3', 'str4', 'str5']:
        return 'str'
    elif inv_name in ['strtk5', 'strsvc', 'strsvc2']:
        return 'str'
    elif inv_name in ['bjw', 'bjw2']:
        return 'bjw'
    elif inv_name == 'bjw3':
        return 'bjw3'
    elif inv_name == 'svc':
        return 'svc'
    elif inv_name == 'ixia':
        # Special case for ixia, check other fields
        return None
    else:
        # Try to extract lab location from inv_name
        if inv_name.startswith('str'):
            return 'str'
        elif inv_name.startswith('bjw'):
            return 'bjw'
        elif inv_name.startswith('svc'):
            return 'svc'
        else:
            return None


def ipv4_to_ipv6(ipv4_addr, lab_location='str', entry_name='unknown'):
    """Convert IPv4 address to specific IPv6 format using the existing conversion logic."""
    # Remove subnet mask if present
    ipv4_clean = ipv4_addr.split('/')[0]

    try:
        # Use the existing conversion function
        ipv6_addr = convert_v4_addr_to_v6(lab_location, ipv4_clean)
        return ipv6_addr
    except SystemExit:
        # The original function uses sys.exit, catch it and return None
        print(f"Failed to convert IPv4 {ipv4_clean} to IPv6 for entry: {entry_name} (lab: {lab_location})", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error converting {ipv4_clean} for entry: {entry_name} - {str(e)}", file=sys.stderr)
        return None


def check_str_file(filepath, data, filename, lab_location, inplace=False):
    """Check and optionally fix IPv6 addresses in str* files."""
    issues = []
    modified = False
    modifications = {}  # Store line numbers and new values

    def check_hosts(hosts_data, parent_path=""):
        nonlocal modified
        if isinstance(hosts_data, dict):
            for host_name, host_data in hosts_data.items():
                if isinstance(host_data, dict):
                    if 'ansible_host' in host_data and 'ansible_hostv6' in host_data:
                        ipv4 = host_data['ansible_host']
                        ipv6_current = host_data['ansible_hostv6']
                        
                        # Skip if ipv6_current is None or empty
                        if not ipv6_current:
                            continue
                            
                        ipv6_expected = ipv4_to_ipv6(ipv4, lab_location, host_name)

                        if ipv6_expected and ipv6_current != ipv6_expected:
                            path = f"{parent_path}{host_name}"
                            if inplace:
                                # Find the line number in the original file
                                line_num = find_ipv6_line(filepath, host_name, ipv6_current)
                                if line_num:
                                    modifications[line_num] = (ipv6_current, ipv6_expected)
                                    modified = True
                                    print(f"Fixed: {path} - Changed {ipv6_current} to {ipv6_expected}")
                            else:
                                issues.append(f"{filename}: {path} - IPv6 mismatch: expected {ipv6_expected}, found {ipv6_current}")

    # Check all sections that might contain hosts
    if isinstance(data, dict):
        for section, section_data in data.items():
            if isinstance(section_data, dict):
                # Check direct hosts
                if 'hosts' in section_data:
                    check_hosts(section_data['hosts'], f"{section} -> hosts -> ")

                # Check children sections
                if 'children' in section_data and isinstance(section_data['children'], dict):
                    for child_name, child_data in section_data['children'].items():
                        if isinstance(child_data, dict) and 'hosts' in child_data:
                            check_hosts(child_data['hosts'], f"{section} -> children -> {child_name} -> hosts -> ")

    # Also check top-level hosts sections
    for key in data:
        if isinstance(data[key], dict) and 'hosts' in data[key]:
            check_hosts(data[key]['hosts'], f"{key} -> hosts -> ")

    # Apply modifications if any
    if modified and modifications:
        apply_modifications(filepath, modifications)

    return issues, modified


def check_testbed_file(filepath, data, filename, pattern=None, inplace=False):
    """Check and optionally fix IPv6 addresses in testbed.yaml file."""
    issues = []
    modified = False
    modifications = {}  # Store line numbers and new values
    skipped_count = 0

    # Compile pattern if provided
    pattern_re = None
    if pattern:
        try:
            pattern_re = re.compile(pattern)
        except re.error as e:
            print(f"Error: Invalid regex pattern '{pattern}': {e}", file=sys.stderr)
            return issues, modified

    if isinstance(data, list):
        for idx, entry in enumerate(data):
            if isinstance(entry, dict):
                conf_name = entry.get('conf-name', f'entry_{idx}')

                # Check if pattern matches (if pattern is provided)
                if pattern_re:
                    if not pattern_re.search(conf_name):
                        skipped_count += 1
                        continue

                # Skip entries without ptf_ipv6
                if 'ptf_ipv6' not in entry or not entry['ptf_ipv6']:
                    continue

                if 'ptf_ip' in entry:
                    ipv4 = entry['ptf_ip']
                    ipv6_current = entry['ptf_ipv6'].split('/')[0]  # Remove subnet mask

                    # Determine lab location from inv_name field
                    lab_location = None
                    if 'inv_name' in entry:
                        inv_name = entry['inv_name']
                        lab_location = get_lab_location_from_inv_name(inv_name)

                    if lab_location is None:
                        print(f"Warning: Cannot determine lab location for {conf_name} (inv_name: {entry.get('inv_name', 'None')}), skipping...", file=sys.stderr)
                        continue

                    ipv6_expected = ipv4_to_ipv6(ipv4, lab_location, conf_name)

                    if ipv6_expected and ipv6_current != ipv6_expected:
                        if inplace:
                            # Find the line with ptf_ipv6
                            line_num = find_ptf_ipv6_line(filepath, conf_name, entry['ptf_ipv6'])
                            if line_num:
                                # Preserve subnet mask if present
                                subnet = ""
                                if '/' in entry['ptf_ipv6']:
                                    subnet = '/' + entry['ptf_ipv6'].split('/')[1]
                                new_value = ipv6_expected + subnet
                                modifications[line_num] = (entry['ptf_ipv6'], new_value)
                                modified = True
                                print(f"Fixed: {conf_name} (lab: {lab_location}, inv_name: {inv_name}) - Changed {ipv6_current} to {ipv6_expected}")
                        else:
                            issues.append(f"{filename}: {conf_name} (line ~{idx*20}, lab: {lab_location}, inv_name: {entry.get('inv_name', 'None')}) - IPv6 mismatch: expected {ipv6_expected}, found {ipv6_current}")

    if pattern and skipped_count > 0:
        print(f"Info: Skipped {skipped_count} entries that didn't match pattern '{pattern}'")

    # Apply modifications if any
    if modified and modifications:
        apply_modifications(filepath, modifications)

    return issues, modified


def find_ipv6_line(filepath, host_name, ipv6_value):
    """Find the line number containing the IPv6 address for a specific host."""
    if not ipv6_value:
        return None
        
    with open(filepath, 'r') as f:
        lines = f.readlines()
        in_target_host = False
        host_indent = 0
        
        for i, line in enumerate(lines):
            # Check if we're entering the target host section
            if f'{host_name}:' in line:
                in_target_host = True
                host_indent = len(line) - len(line.lstrip())
                continue
                
            # If we're in the target host section
            if in_target_host:
                current_indent = len(line) - len(line.lstrip())
                
                # If we've exited this host's section (same or less indentation)
                if line.strip() and current_indent <= host_indent:
                    in_target_host = False
                    continue
                    
                # Check if this line contains the ansible_hostv6
                if 'ansible_hostv6:' in line and ipv6_value in line:
                    return i + 1  # Line numbers are 1-based
                    
    return None


def find_ptf_ipv6_line(filepath, conf_name, ptf_ipv6_value):
    """Find the line number containing the ptf_ipv6 address for a specific conf-name."""
    if not ptf_ipv6_value:
        return None
        
    with open(filepath, 'r') as f:
        lines = f.readlines()
        in_target_entry = False
        
        for i, line in enumerate(lines):
            # Check if line contains conf-name
            if 'conf-name:' in line and conf_name in line:
                in_target_entry = True
            elif 'conf-name:' in line and conf_name not in line:
                in_target_entry = False
            elif in_target_entry and 'ptf_ipv6:' in line and ptf_ipv6_value in line:
                return i + 1  # Line numbers are 1-based
                
    return None


def apply_modifications(filepath, modifications):
    """Apply modifications to the file while preserving formatting."""
    with open(filepath, 'r') as f:
        lines = f.readlines()

    for line_num, (old_value, new_value) in modifications.items():
        if 1 <= line_num <= len(lines):
            lines[line_num - 1] = lines[line_num - 1].replace(old_value, new_value)

    with open(filepath, 'w') as f:
        f.writelines(lines)


def main():
    parser = argparse.ArgumentParser(description='Check and optionally fix IPv6 addresses based on IPv4 addresses in YAML files.')
    parser.add_argument('files', nargs='+', help='YAML files to check')
    parser.add_argument('-i', '--inplace', action='store_true', help='Modify files in place')
    parser.add_argument('-l', '--lab-location', help='Lab location (str, bjw, svc). If not specified, will be determined from filename or DUT name')
    parser.add_argument('-p', '--pattern', help='Regex pattern to filter conf-name entries (only for testbed.yaml files)')

    args = parser.parse_args()

    all_issues = []

    for filepath in args.files:
        try:
            path = Path(filepath)
            filename = path.name

            # Read YAML file
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)

            # Determine file type and check
            if filename.startswith(('str', 'bjw', 'svc')) and not re.match(r'^(str|bjw|svc)-', filename):
                # For str* files, determine lab location
                if args.lab_location:
                    lab_location = args.lab_location
                else:
                    lab_location = get_lab_location_from_filename(filename)
                    if lab_location is None:
                        print(f"Warning: Cannot determine lab location for {filename}, skipping...", file=sys.stderr)
                        continue
                    print(f"Auto-detected lab location for {filename}: {lab_location}")

                issues, modified = check_str_file(filepath, data, filename, lab_location, args.inplace)
            elif 'testbed' in filename:
                # For testbed.yaml, lab location is determined per entry based on inv_name
                issues, modified = check_testbed_file(filepath, data, filename, args.pattern, args.inplace)
            else:
                print(f"Warning: Unknown file type for {filename}, skipping...")
                continue

            if args.inplace and modified:
                print(f"Updated {filename}")

            all_issues.extend(issues)

        except Exception as e:
            import traceback
            print(f"Error processing {filepath}: {str(e)}", file=sys.stderr)
            traceback.print_exc()

    # Print all issues if not in inplace mode
    if not args.inplace and all_issues:
        print("\nFound IPv6 address issues:")
        for issue in all_issues:
            print(f"  - {issue}")
        return 1
    elif not args.inplace and not all_issues:
        print("All IPv6 addresses are correct!")
        return 0

    return 0


if __name__ == '__main__':
    sys.exit(main())
