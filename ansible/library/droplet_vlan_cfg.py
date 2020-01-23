#!/usr/bin/env python

import re
import yaml
import os
import traceback
import subprocess
import ipaddr as ipaddress
from operator import itemgetter
from itertools import groupby
from collections import defaultdict

DOCUMENTATION = '''
module: droplet_vlan_cfg.py
Ansible_version_added:  2.0.0.2
short_description: Gather all vlan info related to droplet interfaces 
Description:
       When deploy testbed topology with droplet connected to TOR SONiC, gather interface aliases info for generating SONiC minigraph file
 arguments:
    vm_topo_config: Topology file; required: True
    port_alias: Port aliases of TOR SONiC; required: True
    vlan_file:  File containing host vlan configurationl required: False

Ansible_facts:
    'vlan_cfgs': all Vlans Configuration 

'''

EXAMPLES = '''
    - name: find all vlan configurations for T0 topology
      droplet_vlan_cfg: vm_topo_config={{ vm_topo_config }} port_alias={{ port_alias }} vlan_file={{ vlan_file|default(None) }}
'''

def get_vlan_info(vlan_file):
    with open(vlan_file) as f:
        vlan_info = yaml.load(f, Loader=yaml.SafeLoader)
    return vlan_info

def main():
    module = AnsibleModule(
        argument_spec=dict(
            vm_topo_config=dict(required=True),
            port_alias=dict(required=True),
            vlan_file=dict(required=False, type='str', default=None),
        ),
        supports_check_mode=True
    )
    m_args = module.params
    port_alias = m_args['port_alias']
    vlan_file = m_args['vlan_file']

    vlan_cfgs = {}
    try:
        if len(vlan_file) == 0:
            # Support for legacy vlan configuration
            vm_topo_config = m_args['vm_topo_config']
            host_interface = set(vm_topo_config['host_interfaces']) - set(vm_topo_config['disabled_host_interfaces'])
    
            vlan_cfgs = {'Vlan1000' : {}}
            vlan_cfgs['Vlan1000']['id'] = 1000
            vlan_cfgs['Vlan1000']['tag'] = 1000
            vlan_cfgs['Vlan1000']['subnets'] = '192.168.0.0/21'
            vlan_cfgs['Vlan1000']['intfs'] = [port_alias[i] for i in host_interface] 
        else:
            vlan_info = get_vlan_info(vlan_file)
            for vlan, vlan_cfg in vlan_info['Vlans'].items():
                vlan_cfgs.update({vlan : {}})
                vlan_cfgs[vlan]['id'] = vlan_cfg['id']
                vlan_cfgs[vlan]['tag'] = vlan_cfg['tag']
                vlan_cfgs[vlan]['subnets'] = vlan_cfg['subnets']
                vlan_cfgs[vlan]['intfs'] = [port_alias[i] for i in vlan_cfg['intfs']]
    except (IOError, OSError):
        module.fail_json(msg = "Can not find file " + vlan_file)
    except Exception as e:
        module.fail_json(msg = traceback.format_exc())
    else:
        module.exit_json(ansible_facts={'vlan_cfgs':vlan_cfgs})

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
