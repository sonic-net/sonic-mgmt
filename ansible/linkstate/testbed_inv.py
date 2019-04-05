#!/usr/bin/env python

import sys
import json
import yaml
import itertools
import ConfigParser
import os

from pprint import pprint

def read_config():
    config = ConfigParser.ConfigParser()
    with open('linkstate/testbed_inv.ini') as fp:
        config.readfp(fp)
    testbed_topologies = config.get("Global", "testbed_configuration")
    vm_inventory = config.get("Global", "vm_inventory")
    lab_inventory = config.get("Global", "lab_inventory")
    lab_links = config.get("Global", "lab_links")
    return {"topos": testbed_topologies,
            "inv": {"vm": vm_inventory,
                    "lab": lab_inventory},
            "links": lab_links}

def parse_testbed_configuration(filename, target):
    with open(filename) as fp:
        for line in fp:
            if line.startswith(target + ','):
                splitted_line = line.split(",")
                ptf_name = splitted_line[1]
                topo_name = splitted_line[2]
                ptf_addr = splitted_line[4]
                vm_start = splitted_line[6]
                dut = splitted_line[7]
    return ptf_name, topo_name, ptf_addr, vm_start, dut

def parse_topology(topology_name, vm_start):
    with open("vars/topo_%s.yml" % topology_name) as fp:
        topo = yaml.load(fp)
    vms = ["%s%04d" % (vm_start[0:2], int(vm_start[2:]) + v["vm_offset"]) for v in topo['topology']['VMs'].values()]
    ports = list(itertools.chain(*(val['vlans'] for val in topo['topology']['VMs'].values())))
    return vms, ports

def parse_links(links, dut, ports):
    with open(links) as fp:
        result = set(line.split(',')[2] for line in fp if line.startswith(dut + ','))
    return list(result)

def extract_hostvars(filename, host):
    with open(filename) as fp:
        for line in fp:
            if line.startswith(host):
                return {value.split('=')[0]:value.split('=')[1] for value in line.rstrip().split()[1:]}

def get_hosts(host):
    config = read_config()
    ptf_name, topo_name, ptf_addr, vm_start, dut = parse_testbed_configuration(config["topos"], host)
    vms, ports = parse_topology(topo_name, vm_start)
    fanouts = parse_links(config["links"], dut, ports)
    returned = {}
    returned['ptf_host'] = [ptf_name]
    returned['lab'] = fanouts
    returned['str'] = fanouts
    returned['eos'] = vms

    all_hosts = [ptf_name]
    all_hosts.extend(vms)
    all_hosts.extend(fanouts)
    returned['all'] = all_hosts

    hostvars = {}

    hostvars[ptf_name] = extract_hostvars(config['inv']['lab'], ptf_name)
    hostvars[ptf_name]['topo'] = topo_name
    hostvars[ptf_name]['vm_base'] = vm_start
    hostvars[ptf_name]['dut'] = dut

    for fanout in fanouts:
        hostvars[fanout] = extract_hostvars(config['inv']['lab'], fanout)
        hostvars[fanout]["ptf_host"] = ptf_addr.split('/')[0]

    for vm in vms:
        hostvars[vm] = extract_hostvars(config['inv']['vm'], vm)

    returned['_meta'] = {}
    returned['_meta']['hostvars'] = hostvars

    return returned

def get_hostname():
    ppid = os.getppid()
    with open('/proc/%d/cmdline' % ppid) as fp:
        cmdline = fp.read()
    for pair in cmdline.split('\0'):
        if '=' in pair and pair.split('=')[0] == 'target_host':
            return pair.split('=')[1]

    return None

if __name__ == '__main__':
    inventory = {}

    hostname = get_hostname()
    if hostname is not None:
        inventory = get_hosts(hostname)

#    with open('inventory_facts', 'w') as f:
#        json.dump(inventory, f, indent=2)

    sys.stdout.write(json.dumps(inventory, indent=2))
