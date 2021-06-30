#! /usr/bin/env python

import argparse
import csv
import re
import os
import yaml
import imp

from collections import defaultdict
from operator import itemgetter

'''
Testbed parser

Usage:
   python available_vmset_finder.py -t <topo_name>

Arguments:
   -t <topo_name>
   -i <inventory file hosting the DUT>

Optional args:
   -f <testbed file to parse>  default: testbed.csv
   -v <vm info file>            default: veos

Return:
   available base_vm and server where it resides
'''

TOPO_PATH = 'vars/'
ANSIBLE_DIR = os.path.abspath(os.path.dirname(__file__))
SONIC_MGMT_DIR = os.path.dirname(ANSIBLE_DIR)


def build_topo_vmcnt():
    topo_vm_cnt = dict()

    try:
        topo_files = [f for f in os.listdir(TOPO_PATH) if os.path.isfile('{}{}'.format(TOPO_PATH, f)) and f.startswith('topo_t') or f.startswith('topo_mgmt')]
        for tfile in topo_files:
            topo = re.findall('topo_(.*)\.yml', tfile)[0]
            with open(TOPO_PATH + tfile) as f:
                vmtopo = yaml.load(f, Loader=yaml.FullLoader)
                topo_vm_cnt[topo] = len(vmtopo['topology']['VMs'])
    except EnvironmentError as e:
        print 'Error while trying to open/read topo files: {}'.format(str(e))
        exit(1)

    return topo_vm_cnt

def parse_file(topo_vm_cnt, testbed_file, server_pool):
    server_info = defaultdict(list)
    testbed = imp.load_source('testbed', os.path.join(SONIC_MGMT_DIR, 'tests/common/testbed.py'))

    try:
        for tb in testbed.TestbedInfo(testbed_file).testbed_topo.values():
            if "ptf" in tb["topo"]["name"]:
                continue
            if tb["server"] in server_pool:
                server_info[tb["server"]].append((tb["vm_base"], topo_vm_cnt[tb["topo"]["name"]]))
    except EnvironmentError as e:
        print 'Error while trying to open/read testbed file: {}'.format(str(e))
        exit(1)

    for key in server_info:
        server_info[key] = sorted(server_info[key], key=itemgetter(0))
    return server_info

def parse_vm_file(vm_file, server_pool):
    vms = dict()
    try:
        with open(vm_file) as f:
            veos_info = yaml.load(f, Loader=yaml.FullLoader)
            vms_names = [key for key in veos_info if 'vms_' in key]
            for name in vms_names:
                server_name = 'server_{}'.format(name.split('_')[1])
                if server_name in server_pool:
                    vm_list = sorted(veos_info[name]['hosts'].keys())
                    vms[server_name] = {'start_vm': vm_list[0],
                                        'end_vm': vm_list[-1]
                                       }
    except EnvironmentError as e:
        print 'Error while trying to open/read vms file: {}'.format(str(e))
        exit(1)
    return vms

def define_parser(topo_vm_cnt):
    parser = argparse.ArgumentParser(description="Process testbed csv file")
    parser.add_argument('-f', "--testbed-file", help='testbed info file', nargs="?", default="testbed.csv")
    parser.add_argument('-v', "--vm-file", help='vms info file', nargs="?", default="veos")
    parser.add_argument('-t', "--topo-type", help='topo name for which VMs are needed (eg, t0, t1)`', required=True)
    parser.add_argument('-i', "--inventory", help='inventory file hosting the DUT`', required=True)
    args = parser.parse_args()
    if not os.path.isfile(args.testbed_file):
        print 'Cannot open testbed file: %s' % args.testbed_file
        exit(1)
    if not os.path.isfile(args.vm_file):
        print 'Cannot open VMs file: %s' % args.vm_file
        exit(1)
    if args.topo_type not in topo_vm_cnt:
        print 'Invalid topo type: {} \nValid types: {}'.format(args.topo_type, topo_vm_cnt.keys())
        exit(1)
    return args

def get_base_vm(server_info, vms, need_vm_cnt=4):
    for server in server_info:
        prev_vm = None
        for index, item in enumerate(server_info[server]):
            curr_vm = int(item[0][2:])
            curr_vm_cnt = item[1]

            # get free block in the beginning if it exists
            if index == 0:
                if server in vms and vms[server]['start_vm'] != item[0]:
                    server_start_vm = int(vms[server]['start_vm'][2:])
                    if server_start_vm + need_vm_cnt <= curr_vm:
                        return server, server_start_vm
            if prev_vm:
                # handle vm reuse case between diff topologies
                if prev_vm == curr_vm:
                    if prev_vm_cnt > curr_vm_cnt:
                        curr_vm_cnt = prev_vm_cnt

                # there might be a free block in between
                elif (block_start_vm < curr_vm) and (block_start_vm + need_vm_cnt <= curr_vm):
                   return server, block_start_vm

            prev_vm = curr_vm
            prev_vm_cnt = curr_vm_cnt
            block_start_vm = prev_vm + prev_vm_cnt

        # get free block at the end
        server_end_vm = int(vms[server]['end_vm'][2:])
        if block_start_vm + need_vm_cnt <= server_end_vm:
            return server, block_start_vm

    # pick up unused servers from vms file if any
    for server in vms:
        if server not in server_info:
            return server, int(vms[server]['start_vm'][2:])

    return None, 0

def parse_devices_file(inv):
    devices_file = os.path.join("files", "sonic_{}_devices.csv".format(inv))
    server_pool = set()
    try:
        with open(devices_file) as f:
             content = csv.DictReader(f)
             for line in content:
                 if 'Server' in line['Type']:
                     server_id = line['Hostname'].split('-')[-1]
                     server_pool.add("server_{}".format(server_id))
    except EnvironmentError as e:
        print 'Error while trying to open/read devices file: {}'.format(str(e))
        exit(1)

    return server_pool

def main():
    topo_vm_cnt = build_topo_vmcnt()
    args = define_parser(topo_vm_cnt)
    server_pool = parse_devices_file(args.inventory)
    server_info = parse_file(topo_vm_cnt, args.testbed_file, server_pool)
    vms = parse_vm_file(args.vm_file, server_pool)
    server, base_vm = get_base_vm(server_info, vms, need_vm_cnt=topo_vm_cnt[args.topo_type])
    if not server:
        print 'Need {} VMs for topo {}. No free VMs'.format(topo_vm_cnt[args.topo_type], args.topo_type)
    else:
        print 'Need {} VMs for topo {}. Available VM{:0>4} on server {}'.format(topo_vm_cnt[args.topo_type], args.topo_type, base_vm, server)

if __name__== "__main__":
    main()
