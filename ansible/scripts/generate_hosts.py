#!/usr/bin/env python3
"""
Generate hosts file from CSV device files

This script generates a hosts file by merging device information from CSV
files with an existing base hosts file. It preserves comments and empty lines
from the base file while adding new entries in a naturally sorted order.

Features:
- Merges multiple CSV device files into a single hosts file
- Preserves existing entries, comments, and formatting from base hosts file
- Detects and warns about duplicate hostname/IP mappings
- Supports interactive mode for handling conflicts
- Uses natural sorting for hostnames

CSV File Format:
The CSV files should contain at least these columns:
- ManagementIp: IP address with optional CIDR notation
- Hostname: Device hostname (e.g., "str4-7060x6")

Usage:
    # Basic usage - generate hosts file from CSV files
    ./generate_hosts.py -o /tmp/new_hosts

    # Use a specific base hosts file
    ./generate_hosts.py -b /etc/hosts -o /tmp/new_hosts

    # Use custom CSV file pattern
    ./generate_hosts.py -c "/path/to/device_*.csv" -o /tmp/new_hosts

    # Add hostnames to existing IPs without prompting
    ./generate_hosts.py -b /etc/hosts -o /tmp/new_hosts --override

Examples:
    1. Generate a new hosts file from all sonic device CSV files:
       $ ./generate_hosts.py -o ./hosts

    2. Update existing /etc/hosts with new devices:
       $ sudo ./generate_hosts.py -b /etc/hosts -o /etc/hosts.new
       $ sudo mv /etc/hosts.new /etc/hosts

    3. Process specific CSV files:
       $ ./generate_hosts.py \
           -c "../files/sonic_lab_devices.csv" -o ./lab_hosts

Arguments:
    -b, --base-hosts    Path to the base hosts file (default: /etc/hosts)
    -o, --output        Path to the output hosts file (required)
    -c, --csv-pattern   Glob pattern for CSV files
    --override          Add hostnames to existing IPs without prompting

Output Format:
    The generated hosts file will:
    - Preserve all content from the base hosts file
    - Add new entries in IP-hostname format, aligned for readability
    - Include warning comments for IPs with multiple hostnames
    - Sort new entries by hostname in natural order

Author: Ze Gan
Version: 1.0
"""

import argparse
import csv
import glob
import ipaddress
import os
import re
import shutil
import stat
import sys
import tempfile
from collections import defaultdict


HOSTNAME_LABEL_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
)


def parse_hosts_line(line):
    """Parse a hosts file line into an IP and all hostnames on that line."""
    stripped_line = line.split('#', 1)[0].strip()
    if not stripped_line:
        return None, []

    parts = stripped_line.split()
    if len(parts) < 2:
        return None, []

    ip = parts[0]
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        ip = parts[0]

    return ip, parts[1:]


def load_existing_hosts(file_path):
    """Load mappings and original lines from an existing hosts file."""
    hosts_map = defaultdict(list)
    original_lines = []

    if not file_path:
        return hosts_map, original_lines

    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"Base hosts file '{file_path}' does not exist."
        )

    if not stat.S_ISREG(os.stat(file_path).st_mode):
        raise ValueError(
            f"Base hosts file '{file_path}' is not a regular file."
        )

    with open(file_path, 'r') as f:
        for line in f:
            original_lines.append(line)
            ip, hostnames = parse_hosts_line(line)
            if ip:
                for hostname in hostnames:
                    hosts_map[ip].append(hostname)

    return hosts_map, original_lines


def normalize_hostname(hostname):
    """Return the case-insensitive form used to compare hostnames."""
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    return hostname.lower()


def is_valid_hostname(hostname):
    """Return whether hostname is a valid RFC 1123-style host name."""
    if not hostname or len(hostname) > 253:
        return False

    hostname = normalize_hostname(hostname)

    return bool(hostname) and all(
        HOSTNAME_LABEL_PATTERN.fullmatch(label)
        for label in hostname.split('.')
    )


def load_csv_devices(csv_pattern):
    """Load devices from all matching CSV files."""
    devices = {}
    device_ips = {}
    errors = []
    csv_files = sorted(glob.glob(csv_pattern))

    if not csv_files:
        raise ValueError(f"No CSV files matched pattern '{csv_pattern}'.")

    for csv_file in csv_files:
        try:
            with open(csv_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                missing_columns = (
                    {'ManagementIp', 'Hostname'}
                    - set(reader.fieldnames or [])
                )
                if missing_columns:
                    columns = ', '.join(sorted(missing_columns))
                    errors.append(
                        f"{csv_file}: missing required CSV column(s): "
                        f"{columns}."
                    )
                    continue

                for line_num, row in enumerate(reader, start=2):
                    management_ip = (row.get('ManagementIp') or '').strip()
                    hostname = (row.get('Hostname') or '').strip()
                    if not management_ip or not hostname:
                        errors.append(
                            f"{csv_file} line {line_num}: ManagementIp and "
                            "Hostname must not be empty."
                        )
                        continue

                    try:
                        ip = str(ipaddress.ip_interface(management_ip).ip)
                    except ValueError:
                        errors.append(
                            f"{csv_file} line {line_num}: invalid "
                            f"ManagementIp '{management_ip}'."
                        )
                        continue

                    if not is_valid_hostname(hostname):
                        errors.append(
                            f"{csv_file} line {line_num}: invalid Hostname "
                            f"'{hostname}'."
                        )
                        continue

                    hostname_key = normalize_hostname(hostname)
                    if hostname_key in device_ips and device_ips[hostname_key] != ip:
                        errors.append(
                            f"{csv_file} line {line_num}: Hostname "
                            f"{hostname} is mapped to multiple IPs: "
                            f"{device_ips[hostname_key]} and {ip}."
                        )
                        continue
                    if hostname_key not in device_ips:
                        devices[hostname] = ip
                        device_ips[hostname_key] = ip
        except csv.Error as error:
            errors.append(f"{csv_file}: invalid CSV data: {error}.")

    if errors:
        raise ValueError("Invalid CSV input:\n  " + "\n  ".join(errors))

    return devices


def natural_sort_key(s):
    """Sort key that orders embedded numbers numerically."""
    return [
        int(text) if text.isdigit() else text.lower()
        for text in re.split('([0-9]+)', s)
    ]


def write_hosts_file(file_path, hosts_map, original_lines):
    """Atomically write mappings while preserving the original file content."""
    # First, extract all existing IP-hostname pairs from original lines
    existing_pairs = set()
    for line in original_lines:
        ip, hostnames = parse_hosts_line(line)
        if ip:
            for hostname in hostnames:
                existing_pairs.add((ip, normalize_hostname(hostname)))

    # Sort by hostname (natural order)
    sorted_entries = sorted(
        [
            (ip, hostname)
            for ip, hostnames in hosts_map.items()
            for hostname in hostnames
        ],
        key=lambda x: natural_sort_key(x[1])
    )

    # Determine the maximum IP length for alignment
    max_ip_length = (
        max(len(ip) for ip, _ in sorted_entries) if sorted_entries else 0
    )

    new_lines = []
    warned_ips = set()
    for ip, hostname in sorted_entries:
        if (ip, normalize_hostname(hostname)) in existing_pairs:
            continue

        if len(hosts_map[ip]) > 1 and ip not in warned_ips:
            hostnames = ', '.join(hosts_map[ip])
            new_lines.append(
                f"# Warning: IP {ip} is mapped to multiple hostnames: "
                f"{hostnames}\n"
            )
            warned_ips.add(ip)
        new_lines.append(f"{ip.ljust(max_ip_length)} {hostname}\n")

    requested_output_path = os.path.abspath(file_path)
    if os.path.lexists(requested_output_path) and not os.path.exists(requested_output_path):
        raise ValueError(
            f"Output path '{file_path}' is a broken or cyclic symlink."
        )

    output_path = os.path.realpath(requested_output_path)
    output_dir = os.path.dirname(output_path)
    if os.path.exists(output_path):
        output_stat = os.stat(output_path)
        if not stat.S_ISREG(output_stat.st_mode):
            raise ValueError(
                f"Output path '{file_path}' is not a regular file."
            )
        output_mode = stat.S_IMODE(output_stat.st_mode)
    else:
        output_stat = None
        current_umask = os.umask(0)
        os.umask(current_umask)
        output_mode = 0o666 & ~current_umask

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w',
            dir=output_dir,
            prefix=f".{os.path.basename(output_path)}.",
            delete=False
        ) as f:
            temp_path = f.name
            f.writelines(original_lines)
            if new_lines and original_lines and not original_lines[-1].endswith('\n'):
                f.write('\n')
            f.writelines(new_lines)
            f.flush()
            os.fsync(f.fileno())

        if output_stat is not None:
            os.chown(temp_path, output_stat.st_uid, output_stat.st_gid)
            shutil.copystat(output_path, temp_path)
            os.utime(temp_path, None)
        else:
            os.chmod(temp_path, output_mode)
        os.replace(temp_path, output_path)
    except Exception:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
        raise


def main(base_hosts, output_file, csv_pattern, override):
    try:
        existing_hosts, original_lines = load_existing_hosts(base_hosts)
        devices = load_csv_devices(csv_pattern)
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    existing_hostnames = {}
    for ip, hostnames in existing_hosts.items():
        for hostname in hostnames:
            hostname_key = normalize_hostname(hostname)
            if hostname_key in existing_hostnames and existing_hostnames[hostname_key][1] != ip:
                existing_ip = existing_hostnames[hostname_key][1]
                print(
                    f"Error: Base hosts file maps {hostname} to both "
                    f"{existing_ip} and {ip}.",
                    file=sys.stderr
                )
                return 1
            existing_hostnames[hostname_key] = (hostname, ip)
    has_conflicts = False

    # Merge devices into existing hosts
    for hostname, ip in devices.items():
        hostname_key = normalize_hostname(hostname)
        if hostname_key in existing_hostnames:
            existing_hostname, existing_ip = existing_hostnames[hostname_key]
            if existing_ip == ip:
                continue
            print(
                f"Error: Hostname {existing_hostname} already exists with "
                f"IP {existing_ip}, cannot add new IP {ip}.",
                file=sys.stderr
            )
            has_conflicts = True
            continue

        if ip in existing_hosts:
            if override:
                print(
                    f"Adding hostname {hostname} to existing IP {ip}.",
                    file=sys.stderr
                )
                existing_hosts[ip].append(hostname)
                existing_hostnames[hostname_key] = (hostname, ip)
            else:
                if sys.stdin is None or not sys.stdin.isatty():
                    print(
                        f"Error: IP {ip} already exists with hostnames "
                        f"{existing_hosts[ip]}. Cannot prompt to add "
                        f"{hostname} in non-interactive mode. Use "
                        "--override to add it.",
                        file=sys.stderr
                    )
                    has_conflicts = True
                    continue

                print(
                    f"IP {ip} already exists with hostnames "
                    f"{existing_hosts[ip]}. Do you want to add hostname "
                    f"{hostname} to this IP? (y/n): ",
                    end='', file=sys.stderr, flush=True
                )
                try:
                    choice = input().strip().lower()
                except EOFError:
                    choice = ''
                if choice == 'y':
                    existing_hosts[ip].append(hostname)
                    existing_hostnames[hostname_key] = (hostname, ip)
                else:
                    print(
                        f"Error: Hostname {hostname} was not added to "
                        f"IP {ip}.",
                        file=sys.stderr
                    )
                    has_conflicts = True
        else:
            existing_hosts[ip].append(hostname)
            existing_hostnames[hostname_key] = (hostname, ip)

    if has_conflicts:
        print(
            "Error: Conflicts were found; no output file was written.",
            file=sys.stderr
        )
        return 1

    try:
        write_hosts_file(output_file, existing_hosts, original_lines)
    except (OSError, ValueError) as error:
        print(
            f"Error: Could not write {output_file}: {error}",
            file=sys.stderr
        )
        return 1

    print(f"Hosts file generated at {output_file}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a hosts file from CSV device files."
    )
    parser.add_argument(
        "-b", "--base-hosts",
        help="Path to the base hosts file. Can be empty if no base file.",
        default="/etc/hosts"
    )
    parser.add_argument(
        "-o", "--output", required=True,
        help="Path to the new hosts file."
    )
    parser.add_argument(
        "-c", "--csv-pattern",
        help="Glob pattern for CSV files.",
        default=os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "files/sonic_*_devices.csv"
        )
    )
    parser.add_argument(
        "--override", action="store_true",
        help="Force override without prompting."
    )
    args = parser.parse_args()

    sys.exit(
        main(args.base_hosts, args.output, args.csv_pattern, args.override)
    )
