"""This script is to parse ansible inventory file and return the mgmt IP for given host server.
"""

import argparse
import sys

from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager


def main(args):
    server_name = args.server_name
    inv_file = args.inv_file
    ip_ver = args.ip_ver

    inv_mgr = InventoryManager(loader=DataLoader(), sources=inv_file)
    all_hosts = inv_mgr.get_hosts(pattern=server_name)

    if len(all_hosts) == 0:
        sys.stderr.write("No host matches {} in inventory file {}".format(server_name, inv_file))
        sys.exit(1)
    else:
        for host in all_hosts:
            if host.name.startswith('VM'):
                continue
            if ip_ver == 'ipv4':
                result = host.get_vars().get("ansible_host", "")
            else:
                result = host.get_vars().get("ansible_hostv6", "")
            sys.stdout.write(result)
            sys.exit(0)

        sys.stderr.write(
            "Unable to find IP address of host server {} in inventory file {}".format(server_name, inv_file)
        )
        sys.exit(2)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Gather mgmt IP for given host server (like server_17)')
    parser.add_argument(
        '--server-name',
        help='The name of vm_host server, like server_1'
    )
    parser.add_argument(
        '--inv-file',
        default='veos',
        help='The inventory file contains server information. Default is veos.'
    )
    parser.add_argument(
        '--ip-ver',
        default='ipv4',
        choices=['ipv4', 'ipv6'],
        help='The IP version to return. Default is ipv4.'
    )
    args = parser.parse_args()
    main(args)
