#!/usr/bin/env python
import os
import traceback
import ipaddr as ipaddress
import csv
from operator import itemgetter
from itertools import groupby
import yaml
import json

DOCUMENTATION = '''
module: topo_facts.py
version_added:  2.0.0.2
short_description: get topology information
options:
    - topo:
      Description: the topology name
      Default: None
      required: True
'''

def get_vm_type(ngs_type):
    if ngs_type == "ToRRouter":
        return "tor"
    if ngs_type == "LeafRouter":
        return "leaf"
    if ngs_type == "SpineRouter":
        return "spine"

class ParseTestbedTopoinfo():
    '''
    Parse topology yml file
    '''
    def __init__(self):
        self.vm_topo_config = {}

    def parse_clet(self, lst, cfg, fpath):
        # Get the neighbors list
        for e in lst:
            if e.has_key('DEVICE_NEIGHBOR_METADATA'):
                for vm in e['DEVICE_NEIGHBOR_METADATA']:
                    cfg[vm] = dict()
                    cfg[vm]['intfs'] = []
                    cfg[vm]['properties'] = ["common"]
                    cfg[vm]['properties'].append(get_vm_type(e['DEVICE_NEIGHBOR_METADATA'][vm]["type"]))

        # fill data for each VM
        for e in lst:
            if e.has_key('DEVICE_NEIGHBOR'):
                for intf in e['DEVICE_NEIGHBOR']:
                    vm = e['DEVICE_NEIGHBOR'][intf]['name']
                    cfg[vm]['interface_indexes'] = [int(intf[-2:]), ]

            elif e.has_key('BGP_NEIGHBOR'):
                for b in e['BGP_NEIGHBOR']:
                    vm = e['BGP_NEIGHBOR'][b]['name']
                    cfg[vm]['bgp_asn'] = int(e['BGP_NEIGHBOR'][b]['asn'])
                    if b.find(".") != -1:
                        cfg[vm]['peer_ipv4'] = b
                        cfg[vm]['bgp_ipv4'] = e['BGP_NEIGHBOR'][b]['local_addr']

                    elif b.find(":") != -1:
                        cfg[vm]['peer_ipv6'] = b.upper()
                        cfg[vm]['bgp_ipv6'] = e['BGP_NEIGHBOR'][b]['local_addr'].upper()

                    else:
                        raise Exception("BGP_NEIGHBOR address {} neither v4 nor v6 {} file!".format(b, fpath))


        for e in lst:
            if e.has_key('PORTCHANNEL_INTERFACE'):
                for p in e['PORTCHANNEL_INTERFACE']:
                    found = False
                    (pc, ipm) = p.split('|')
                    (ip, mask) = ipm.split('/')
                    for v in cfg:
                        if cfg[v]['bgp_ipv4'] == ip:
                            cfg[v]['ipv4mask'] = mask
                            found = True

                        elif cfg[v]['bgp_ipv6'] == ip.upper():
                            cfg[v]['ipv6mask'] = mask
                            found = True

                        if found:
                            cfg[v]['ip_intf'] = "Port-Channel1"
                            break

            if e.has_key('DEVICE_NEIGHBOR'):
                for p in e['DEVICE_NEIGHBOR']:
                    vm = e['DEVICE_NEIGHBOR'][p]['name']
                    if cfg.has_key(vm):
                        cfg[vm]['intfs'].append(e['DEVICE_NEIGHBOR'][p]['port'])
                    else:
                        raise Exception("DEVICE_NEIGHBOR {} is missing {}".format(vm, fpath))



    def get_topo_config(self, topo_name):
        if 'ptf32' in topo_name:
            topo_name = 't1'
        if 'ptf64' in topo_name:
            topo_name = 't1-64'
        topo_filename = 'vars/topo_' + topo_name + '.yml'
        topo_cletname = 'vars/configlet/' + topo_name + '/clet-add.json'
        vm_topo_config = dict()

        ### read topology definition
        if not os.path.isfile(topo_filename):
            raise Exception("cannot find topology definition file under vars/topo_%s.yml file!" % topo_name)
        else:
            with open(topo_filename) as f:
                topo_definition = yaml.load(f)

        ### parse topo file specified in vars/ to reverse as dut config
        if 'VMs' in topo_definition['topology']:
            dut_asn = topo_definition['configuration_properties']['common']['dut_asn']
            vm_topo_config['dut_asn'] = dut_asn
            vm_topo_config['dut_type'] = topo_definition['configuration_properties']['common']['dut_type']
            vmconfig = dict()
            for vm in topo_definition['topology']['VMs']:
                vmconfig[vm] = dict()
                vmconfig[vm]['intfs'] = []
                vmconfig[vm]['properties']=topo_definition['configuration'][vm]['properties']
                vmconfig[vm]['interface_indexes'] = topo_definition['topology']['VMs'][vm]['vlans']
                vmconfig[vm]['bgp_asn'] = topo_definition['configuration'][vm]['bgp']['asn']
                for intf in topo_definition['configuration'][vm]['interfaces']:
                    if 'ipv4' in topo_definition['configuration'][vm]['interfaces'][intf] and ('loopback' not in intf.lower()):
                        (vmconfig[vm]['peer_ipv4'], vmconfig[vm]['ipv4mask']) = topo_definition['configuration'][vm]['interfaces'][intf]['ipv4'].split('/')
                        vmconfig[vm]['ip_intf'] = intf
                    if 'ipv6' in topo_definition['configuration'][vm]['interfaces'][intf] and ('loopback' not in intf.lower()):
                        (ipv6_addr, vmconfig[vm]['ipv6mask']) = topo_definition['configuration'][vm]['interfaces'][intf]['ipv6'].split('/')
                        vmconfig[vm]['ip_intf'] = intf
                        vmconfig[vm]['peer_ipv6'] = ipv6_addr.upper()
                    if 'Ethernet' in intf:
                        vmconfig[vm]['intfs'].append(intf)
                for ip in topo_definition['configuration'][vm]['bgp']['peers'][dut_asn]:
                    if ip[0:5].upper() in vmconfig[vm]['peer_ipv4'].upper():
                        vmconfig[vm]['bgp_ipv4'] = ip.upper()
                    if ip[0:5].upper() in vmconfig[vm]['peer_ipv6'].upper():
                        vmconfig[vm]['bgp_ipv6'] = ip.upper()

            if os.path.isfile(topo_cletname):
                with open(topo_cletname) as f:
                    clet_definition = json.load(f)
                    self.parse_clet(clet_definition, vmconfig, topo_cletname)

            vm_topo_config['vm'] = vmconfig

        if 'host_interfaces' in topo_definition['topology']:
            vm_topo_config['host_interfaces'] = topo_definition['topology']['host_interfaces']
        else:
            vm_topo_config['host_interfaces'] = []

        if 'disabled_host_interfaces' in topo_definition['topology']:
            vm_topo_config['disabled_host_interfaces'] = topo_definition['topology']['disabled_host_interfaces']
        else:
            vm_topo_config['disabled_host_interfaces'] = []

        self.vm_topo_config = vm_topo_config
        return vm_topo_config

def main():
    module = AnsibleModule(
        argument_spec=dict(
            topo=dict(required=True, default=None),
        ),
        supports_check_mode=True
    )
    m_args = module.params
    topo_name = m_args['topo']
    try:
        topoinfo = ParseTestbedTopoinfo()
        vm_topo_config = topoinfo.get_topo_config(topo_name)
        module.exit_json(ansible_facts={'vm_topo_config': vm_topo_config})
    except (IOError, OSError):
        module.fail_json(msg="Can not find topo file for %s" % topo_name)
    except Exception as e:
        module.fail_json(msg=traceback.format_exc())

from ansible.module_utils.basic import *
if __name__== "__main__":
    main()
