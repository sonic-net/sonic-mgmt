#!/usr/bin/env python
import os
import traceback
import ipaddr as ipaddress
import csv
from operator import itemgetter
from itertools import groupby
import yaml

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

class ParseTestbedTopoinfo():
    '''
    Parse topology yml file
    '''
    def __init__(self):
        self.vm_topo_config = {}

    def get_topo_config(self, topo_name):
        if 'ptf32' in topo_name:
            topo_name = 't1'
        if 'ptf64' in topo_name:
            topo_name = 't1-64'
        topo_filename = 'vars/topo_' + topo_name + '.yml'
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
            vm_topo_config['vm'] = vmconfig

        if 'host_interfaces' in topo_definition['topology']:
            vm_topo_config['host_interfaces'] = topo_definition['topology']['host_interfaces']
        else:
            vm_topo_config['host_interfaces'] = []

        if 'disabled_host_interfaces' in topo_definition['topology']:
            vm_topo_config['disabled_host_interfaces'] = topo_definition['topology']['disabled_host_interfaces']
        else:
            vm_topo_config['disabled_host_interfaces'] = []

        if 'DUT' in topo_definition['topology']:
            vm_topo_config['DUT'] = topo_definition['topology']['DUT']
        else:
            vm_topo_config['DUT'] = {}

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
