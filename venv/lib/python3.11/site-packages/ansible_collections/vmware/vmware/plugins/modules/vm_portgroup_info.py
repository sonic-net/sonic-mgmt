#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r'''
---
module: vm_portgroup_info
version_added: '1.4.0'
short_description: Returns information about the portgroups of virtual machines
description:
    - Returns information about the standard or distributed portgroups of virtual machines.
author:
    - Ansible Cloud Team (@ansible-collections)
requirements:
    - vSphere Automation SDK
options:
    vm_names:
        description:
            - VM names for retrieving the information about portgroup
        required: true
        type: list
        elements: str
extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options
'''

EXAMPLES = r'''
- name: Gather list of portgroup by VMs
  vmware.vmware.portgroup_info:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    vm_names:
      - vm-test1
      - vm-test2
'''

RETURN = r'''
vm_portgroup_info:
    description:
        - Dictionary of the requested VMs with the portgroup information
    returned: On success
    type: dict
    sample: {
        "vm1": [
        {
            "name": "Network Name",
            "nic_mac_address": "00:00:00:00:00:00",
            "nic_mac_type": "ASSIGNED",
            "nic_type": "VMXNET3",
            "port_id": "network-port-id",
            "type": "STANDARD_PORTGROUP",
            "vlan_id": "0",
            "vswitch_name": "vSwitch0"
        }]
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import ModulePyvmomiBase
from ansible_collections.vmware.vmware.plugins.module_utils import _network as vmware_network
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import ModuleRestBase
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import rest_compatible_argument_spec


class PortgroupInfo(ModulePyvmomiBase):
    def __init__(self, module):
        super(PortgroupInfo, self).__init__(module)
        self.vmware_client = ModuleRestBase(module)
        self.vms = self.params['vm_names']

    def get_dvs_portgroup_detailed(self, pg_id):
        dvs_pg = self.get_dvs_portgroup_by_name_or_moid(pg_id)
        pg = {'portgroup_name': dvs_pg.name, 'vswitch_name': dvs_pg.config.distributedVirtualSwitch.name,
              'type': 'DISTRIBUTED_PORTGROUP', 'port_id': pg_id,
              'port_binding': vmware_network.get_dvs_port_allocation(dvs_pg.config.type),
              'port_allocation': vmware_network.get_dvs_auto_expand(dvs_pg.config.autoExpand),
              'network_policy': vmware_network.get_dvs_network_policy(dvs_pg.config.defaultPortConfig.macManagementPolicy),
              'mac_learning': vmware_network.get_dvs_mac_learning(dvs_pg.config.defaultPortConfig.macManagementPolicy.macLearningPolicy),
              'teaming_policy': vmware_network.get_teaming_policy(dvs_pg.config.defaultPortConfig.uplinkTeamingPolicy),
              'port_policy': vmware_network.get_port_policy(dvs_pg.config.policy),
              'vlan_info': vmware_network.get_vlan_info(dvs_pg.config.defaultPortConfig.vlan)
              }

        port_config = dvs_pg.config.defaultPortConfig
        if port_config.uplinkTeamingPolicy and \
                port_config.uplinkTeamingPolicy.uplinkPortOrder:
            pg['active_uplinks'] = port_config.uplinkTeamingPolicy.uplinkPortOrder.activeUplinkPort
            pg['standby_uplinks'] = port_config.uplinkTeamingPolicy.uplinkPortOrder.standbyUplinkPort

        return pg

    def get_standard_portgroup_detailed(self, pg_id):
        pg = self.get_standard_portgroup_by_name_or_moid(pg_id)
        pg_name = str(pg.summary.name)
        ret_pg = vmware_network.get_standard_portgroup_vlan_vswitch(pg, pg_name)
        ret_pg['port_id'] = pg_id
        ret_pg['type'] = 'STANDARD_PORTGROUP'
        return ret_pg

    def get_portgroup_of_vm(self):
        vms_nics = {}
        # Save a dictionary of portgroup details for reuse
        pg_map = {}
        for vm in self.vms:
            vm_detailed = self.get_vm_detailed(vm_name=vm)
            vm_nics = []
            for nic in vm_detailed.nics:
                nic_details = {
                    'nic_mac_address': vm_detailed.nics[nic].mac_address,
                    'nic_mac_type': str(vm_detailed.nics[nic].mac_type),
                    'nic_type': str(vm_detailed.nics[nic].type)
                }

                pg_type = str(vm_detailed.nics[nic].backing.type)
                pg_id = str(vm_detailed.nics[nic].backing.network)

                if pg_type not in ['DISTRIBUTED_PORTGROUP', 'STANDARD_PORTGROUP']:
                    continue
                if pg_id not in pg_map:
                    if pg_type == 'STANDARD_PORTGROUP':
                        pg_map[pg_id] = self.get_standard_portgroup_detailed(pg_id)
                    else:
                        pg_map[pg_id] = self.get_dvs_portgroup_detailed(pg_id)

                nic_details.update(pg_map[pg_id])
                vm_nics.append(nic_details)

            vms_nics[vm_detailed.name] = vm_nics

        return vms_nics

    def get_vm_detailed(self, vm_name):
        vm_id = self.vmware_client.get_vm_obj_by_name(vm_name)
        return self.vmware_client.api_client.vcenter.VM.get(vm=vm_id)


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(
        dict(
            vm_names=dict(type='list', elements='str', required=True)
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    portgroup_info = PortgroupInfo(module)
    portgroup_info_result = portgroup_info.get_portgroup_of_vm()
    module.exit_json(changed=False, vm_portgroup_info=portgroup_info_result)


if __name__ == '__main__':
    main()
