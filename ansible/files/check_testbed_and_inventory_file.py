"""Tool for checking testbed file and related inventory file.

When we may make some mistakes while adding or updating testbed configurations in testbed file and inventory files.
These mistakes are hard to find and can cause many troubles. This tool is to do some basic checks of testbed file
and the related inventory files. This tool only supports the yaml format testbed file.

Checked items:
* Check if the topologies defined in vm inventory file are valid.
* Check if there is duplicated testbed name in testbed file.
* For each test server, check if there is duplicated group name.
* Check if the the topo name of each testbed is valid.
* Check if the PTF host of each testbed is defined in inventory file. Also check if the PTF IP in testbed file matches
  the IP address defined in inventory file.
* Check if there is duplicated IP address in inventory files.

The tool will print out results of all the failed checks.

Example usage:
    $ python ansible/check_testbed_and_inventory_file.py -t vtestbed.yaml -m veos_vtb
"""
from __future__ import print_function, division

import argparse
import json
import os
import re
import sys
import yaml

from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager

MODULE_PATH = os.path.dirname(__file__)
TOPO_FILE_PATH = os.path.abspath(os.path.join(MODULE_PATH, '../vars'))
INV_FILE_PATH = os.path.abspath(os.path.join(MODULE_PATH, '..'))


def _find_dup_in_list(items):
    item_count = {}
    for x in items:
        if str(x) not in item_count:
            item_count[str(x)] = {'count': 1, 'value': x}
        else:
            item_count[str(x)]['count'] += 1

    return [v['value'] for _, v in item_count.items() if v['count'] > 1]


def _load_inventory(path):
    res = {}
    res['path'] = path
    with open(path) as f:
        res['content'] = yaml.safe_load(f)
    res['im'] = InventoryManager(loader=DataLoader(), sources=path)
    return res


def get_defined_topo_names():
    # Find out supported topo names
    topo_names = []
    for topo_file in os.listdir(TOPO_FILE_PATH):
        topo_names.extend(re.findall('^topo_(.*)\.y[a]?ml$', topo_file))
    return topo_names


def get_inventories(testbeds):
    inventories = {}
    for tb in testbeds:
        inv_name = tb.get('inv_name', '').strip()
        if not inv_name:
            continue
        if inv_name not in inventories:
            inv_path = os.path.join(INV_FILE_PATH, inv_name)
            inventories[inv_name] = _load_inventory(inv_path)
    return inventories


def get_vm_inventory(vmfile):
    return _load_inventory(os.path.abspath(vmfile))


def check_testbed_name(testbeds):
    result = {
        'check_item': 'uniqueness of testbed names',
        'valid': True,
    }
    tbnames = [tb['conf-name'] for tb in testbeds]

    dup_tbnames = _find_dup_in_list(tbnames)
    if len(dup_tbnames) > 0:
        result['valid'] = False
        result['msg'] = 'There are duplicated testbed names: ' + str(dup_tbnames)
    return result


def check_server_group_name(testbeds):
    result = {
        'check_item': 'uniqueness of group name per test server',
        'valid': True
    }
    server_groups = {}
    for tb in testbeds:
        if tb['server'] not in server_groups:
            server_groups[tb['server']] = [tb['group-name']]
        else:
            server_groups[tb['server']].append(tb['group-name'])

    dup_server_groups = {}
    for server, groups in server_groups.items():
        dup_groups = _find_dup_in_list(groups)
        if dup_groups:
            dup_server_groups[server] = dup_groups


    if dup_server_groups:
        result['valid'] = False
        result['msg'] = 'Group name belong to each test server must be unique, duplicated groups per server: {}'.format(dup_server_groups)
    return result


def check_topo_name(testbeds, vm_inventory):
    result = {
        'check_item': 'check if topo name is supported',
        'valid': True
    }
    failures = []

    # Find out supported topo names
    topo_names = get_defined_topo_names()
    vmfile_topologies = vm_inventory['im'].groups['servers'].vars['topologies']

    for tb in testbeds:
        topo = tb['topo']
        if topo not in topo_names:
            failures.append('Topology {} of testbed {} is invalid'.format(
                topo,
                tb['conf-name']
            ))
        if topo not in vmfile_topologies:
            failures.append('Topology {} of testbed {} is not defined in vm inventory file {}'.format(
                topo,
                tb['conf-name'],
                vm_inventory['path']
            ))

    if failures:
        result['valid'] = False
        result['failures'] = failures
    return result


def check_vmfile_topologies(vm_inventory):
    result = {
        'check_item': 'check defined topologies and topologies list in vm inventory file',
        'valid': True
    }
    defined_topologies = get_defined_topo_names()
    vmfile_topologies = vm_inventory['im'].groups['servers'].vars['topologies']

    dup_topologies_in_vmfile = _find_dup_in_list(vmfile_topologies)
    invalid_topo_in_vmfile = list(set(vmfile_topologies) - set(defined_topologies))

    failures = []
    if dup_topologies_in_vmfile:
        failures.append('Duplicated topologies in {}. '.format(vm_inventory['path']))

    if invalid_topo_in_vmfile:
        failures.append('Topologies {} in {} are invalid.'.format(str(list(invalid_topo_in_vmfile)), vm_inventory['path']))

    if failures:
        result['valid'] = False
        result['failures'] = failures
    return result


def check_ptf(testbeds, inventories):
    result = {
        'check_item': 'check ptf host and IP',
        'valid': True
    }

    failures = []

    for tb in testbeds:
        # Check if the ptf host is defined in inventory file
        ptf_name = tb['ptf']
        inv_name = tb.get('inv_name', '').strip()
        if not inv_name:
            continue

        inventory = inventories[inv_name]
        ptf_host = inventory['im'].get_host(ptf_name)
        if not ptf_host:
            failures.append('PTF {} of testbed {} is not defined in inventory {}'.format(
                ptf_name,
                tb['conf-name'],
                inventory['path']
            ))
            continue

        if 'ptf' not in [g.name for g in ptf_host.groups]:
            failures.append('PTF {} of testbed {} is not defined under group "ptf" in inventory {}'.format(
                ptf_name,
                tb['conf-name'],
                inventory['path']
            ))
        ptf_ip = tb['ptf_ip'].split('/')[0]
        ansible_host = ptf_host.vars.get('ansible_host', '')
        if ansible_host != ptf_ip:
            failures.append('Inconsistent PTF IP in testbed file and inventory file, testbed={}, ptf_ip={}, inv_ptf_ip={}'.format(
                tb['conf-name'],
                ptf_ip,
                ansible_host
            ))

    if failures:
        result['valid'] = False
        result['failures'] = failures
    return result


def check_duplicated_ip(inventory):
    result = {
        'check_item': 'check if IP is unique in inventory file {}'.format(inventory['path']),
        'valid': True
    }

    ips = []
    inv_im = inventory['im']
    for host in inv_im.get_hosts():
        ip = host.vars.get('ansible_host', None)
        if ip:
            ips.append(ip)

    dup_ips = _find_dup_in_list(ips)
    if dup_ips:
        result['valid'] = False
        result['msg'] ='Found duplicated IP in inventory {}: {}'.format(
            inventory['path'],
            dup_ips
        )
    return result


def check(args):
    results = []
    with open(args.tbfile) as f:
        testbeds = yaml.safe_load(f)
    inventories = get_inventories(testbeds)
    vm_inventory = get_vm_inventory(args.vmfile)

    results.append(check_vmfile_topologies(vm_inventory))
    results.append(check_testbed_name(testbeds))
    results.append(check_server_group_name(testbeds))
    results.append(check_topo_name(testbeds, vm_inventory))
    results.append(check_ptf(testbeds, inventories))
    results.append(check_duplicated_ip(vm_inventory))
    for inventory in inventories:
        results.append(check_duplicated_ip(inventories[inventory]))

    failed_checks = [result for result in results if not result['valid']]
    if len(failed_checks) > 0:
        print('Check failed, detailed results: {}'.format(json.dumps(failed_checks, indent=4)))
        sys.exit(1)
    else:
        print('Check passed')
        sys.exit(0)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='Check testbed and related inventory files')

    parser.add_argument('-t', '--testbed-file',
        type=str,
        dest='tbfile',
        required=True,
        help='Testbed file. Only yaml format testbed file is supported.')

    parser.add_argument('-m', '--vm-file',
        type=str,
        dest='vmfile',
        required=True,
        help='VM files, typically it is the `veos` file')

    args = parser.parse_args()
    check(args)
