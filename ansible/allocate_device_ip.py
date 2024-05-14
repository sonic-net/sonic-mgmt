#!/usr/bin/env python

import csv
import ipaddress
import glob
import subprocess
import click


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


def find_unused_ips(csv_ips, ip_range, ping, count):
    range_ips = ipaddress.ip_network(ip_range)
    used_ips = set(ipaddress.ip_address(ip) for ip in csv_ips)

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
    unused_ips = find_unused_ips(csv_ips, ip_range, ping, count)

    print("Avaiable IPs:")
    for ip in unused_ips:
        print(ip)


if __name__ == '__main__':
    main()
