#!/usr/bin/env python

import yaml
import traceback

DOCUMENTATION = '''
module: droplet_vlan_cfg.py
Ansible_version_added:  2.0.0.2
short_description: Gather all vlan info related to droplet interfaces 
Description:
       When deploy testbed topology with droplet connected to TOR SONiC, 
       gather droplet vlan interfaces info for generating SONiC minigraph file
 arguments:
    vm_topo_config: Topology file; required: True
    port_alias: Port aliases of TOR SONiC; required: True
    vlan_cfg:  vlan config name to use; required: False

Ansible_facts:
    'vlan_cfgs': all Vlans Configuration 
'''

EXAMPLES = '''
    - name: find all vlan configurations for T0 topology
      droplet_vlan_cfg: 
        vm_topo_config: "{{ vm_topo_config }}"
        port_alias: "{{ port_alias }}"
        vlan_cfg: "{{ vlan_cfg|default(None) }}"
'''

def main():
    module = AnsibleModule(
        argument_spec=dict(
            vm_topo_config=dict(required=True),
            port_alias=dict(required=True),
            vlan_cfg=dict(required=False, type='str', default=None),
        ),
        supports_check_mode=True
    )
    m_args = module.params
    port_alias = m_args['port_alias']
    vlan_cfg = m_args['vlan_cfg']

    vlan_cfgs = {}
    try:
        if len(vlan_cfg) > 0:
            default_vlan = vlan_cfg
        else:
            default_vlan = m_args['vm_topo_config']['DUT']['vlan_cfgs']['default_vlan_cfg']

        vlan_info = m_args['vm_topo_config']['DUT']['vlan_cfgs'][default_vlan]
        for vlan, vlan_cfg in vlan_info.items():
            vlan_cfgs.update({vlan : {}})
            vlan_cfgs[vlan]['id'] = vlan_cfg['id']
            vlan_cfgs[vlan]['tag'] = vlan_cfg['tag']
            vlan_cfgs[vlan]['subnets'] = vlan_cfg['subnets']
            vlan_cfgs[vlan]['intfs'] = [port_alias[i] for i in vlan_cfg['intfs']]
    except Exception as e:
        module.fail_json(msg = traceback.format_exc())
    else:
        module.exit_json(ansible_facts={'vlan_cfgs':vlan_cfgs})

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
