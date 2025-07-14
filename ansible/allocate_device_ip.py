#!/usr/bin/env python

import csv
import ipaddress
import glob
import subprocess
import click
import yaml
import re
import os


def read_ips_from_csv(file_pattern: str):
    ips = []

    for file_path in glob.glob(file_pattern):
        with open(file_path, newline='') as file:
            reader = csv.reader(file)

            # Skip the header line
            next(reader)

            # The IPs in CSV file are CIDRs, hence we need to split the IP CIDR to get the IP part.
            ips.extend(row[1].split('/')[0] for row in reader if row)

    return ips


def extract_ips_from_value(value):
    """Extract IP addresses from a value, handling strings, lists, and complex formats."""
    ips = []

    if isinstance(value, str):
        # Remove CIDR notation and extract IP
        ip_str = value.split('/')[0]
        try:
            ipaddress.ip_address(ip_str)
            ips.append(ip_str)
        except ValueError:
            pass
    elif isinstance(value, list):
        for item in value:
            ips.extend(extract_ips_from_value(item))
    elif isinstance(value, dict):
        for v in value.values():
            ips.extend(extract_ips_from_value(v))

    return ips


def walk_yaml_structure(data, ips=None):
    """Recursively walk through YAML data structure to extract all IP addresses."""
    if ips is None:
        ips = []

    if isinstance(data, dict):
        for key, value in data.items():
            # Look for common IP address keys
            if key in ['ansible_host', 'ansible_hostv6'] or 'ip' in key.lower():
                ips.extend(extract_ips_from_value(value))
            else:
                walk_yaml_structure(value, ips)
    elif isinstance(data, list):
        for item in data:
            walk_yaml_structure(item, ips)
    else:
        # Try to extract IP from string values
        ips.extend(extract_ips_from_value(data))

    return ips


def read_ips_from_yaml_file(file_path):
    """Read IP addresses from YAML file."""
    ips = []

    try:
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)
            ips = walk_yaml_structure(data)
    except Exception as e:
        print(f"Warning: Failed to parse YAML file {file_path}: {e}")

    return ips


def read_ips_from_ini_inventory(file_path):
    """Read IP addresses from INI-style inventory file."""
    ips = []

    try:
        with open(file_path, 'r') as f:
            content = f.read()

        # Use regex to find ansible_host entries
        host_pattern = r'ansible_host=([^\s]+)'
        hostv6_pattern = r'ansible_hostv6=([^\s]+)'

        for match in re.finditer(host_pattern, content):
            ip_str = match.group(1).strip('\'"')
            ips.extend(extract_ips_from_value(ip_str))

        for match in re.finditer(hostv6_pattern, content):
            ip_str = match.group(1).strip('\'"')
            ips.extend(extract_ips_from_value(ip_str))

    except Exception as e:
        print(f"Warning: Failed to parse INI file {file_path}: {e}")

    return ips


def read_ips_from_testbed_files():
    """Read IP addresses from testbed YAML files."""
    ips = []
    ansible_dir = os.path.dirname(__file__)
    testbed_files = ['testbed.yaml', 'testbed.nut.yaml']

    for testbed_file in testbed_files:
        testbed_path = os.path.join(ansible_dir, testbed_file)

        if os.path.exists(testbed_path):
            try:
                ips.extend(read_ips_from_yaml_file(testbed_path))
            except Exception as e:
                print(f"Warning: Failed to process testbed file {testbed_path}: {e}")
        else:
            print(f"Warning: Testbed file {testbed_path} not found")

    return ips


def read_ips_from_inventory_files():
    """Read inventory file names from graph_groups.yml and extract IPs from those files."""
    ips = []
    ansible_dir = os.path.dirname(__file__)

    # Read graph_groups.yml to get inventory file names
    graph_groups_path = os.path.join(ansible_dir, 'files', 'graph_groups.yml')

    try:
        with open(graph_groups_path, 'r') as f:
            inventory_groups = yaml.safe_load(f)

        # Process inventory files from graph_groups.yml
        for group in inventory_groups:
            inventory_path = os.path.join(ansible_dir, group)

            if os.path.exists(inventory_path):
                # Try to determine file format and parse accordingly
                try:
                    with open(inventory_path, 'r') as f:
                        first_line = f.readline().strip()

                    if first_line.startswith('---') or first_line.startswith('all:'):
                        # YAML format
                        ips.extend(read_ips_from_yaml_file(inventory_path))
                    else:
                        # INI format
                        ips.extend(read_ips_from_ini_inventory(inventory_path))

                except Exception as e:
                    print(f"Warning: Failed to process inventory file {inventory_path}: {e}")
            else:
                print(f"Warning: Inventory file {inventory_path} not found")

    except Exception as e:
        print(f"Warning: Failed to read graph_groups.yml: {e}")

    return ips


def check_ip_available(ip: str, ping: bool) -> bool:
    if ip.endswith(".0") or ip.endswith(".255"):
        return False

    if not ping:
        return True

    print(f"Pinging IP: {ip}")
    try:
        response = subprocess.run(
            ['ping', '-c', '1', '-W', '0.3', ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True)

        return response.returncode != 0
    except Exception as e:
        print(f"Failed to ping {ip}: {str(e)}")
        return True


def find_unused_ips(all_used_ips, ip_range, ping, count):
    range_ips = ipaddress.ip_network(ip_range)
    used_ips = set(ipaddress.ip_address(ip) for ip in all_used_ips)

    unused_ips = []
    for ip in range_ips:
        if len(unused_ips) >= count:
            break

        if ip in used_ips:
            continue

        if not check_ip_available(str(ip), ping):
            continue

        unused_ips.append(str(ip))

    return unused_ips


@click.command()
@click.argument('file_pattern', default='files/*_devices.csv')
@click.option('-r', 'ip_range', required=True, help="IP range to check for unused IPs.")
@click.option('-n', 'count', default=1, help="Numbers of IPs to return.")
@click.option('-p', '--ping', is_flag=True, help="Ping each unused IP to check if it's reachable.")
def main(ping, file_pattern, ip_range, count):
    """
    Get available IPs by looking at the used IPs from the device CSV files.

    Examples:

    - Allocate a IP within 10.0.0.0/24 IP range.

      ./allocate_device_ip.py -r 10.0.0.0/24

    - Allocate 6 IPs within 10.0.1.0/24 range, also ping the IPs and only select the ones that is not reachable.

      ./allocate_device_ip.py -r 10.0.1.0/24 -n 6 -p
    """
    csv_ips = read_ips_from_csv(file_pattern)
    inventory_ips = read_ips_from_inventory_files()
    testbed_ips = read_ips_from_testbed_files()
    all_used_ips = csv_ips + inventory_ips + testbed_ips
    unused_ips = find_unused_ips(all_used_ips, ip_range, ping, count)

    print("Avaiable IPs:")
    for ip in unused_ips:
        print(ip)


if __name__ == '__main__':
    main()
