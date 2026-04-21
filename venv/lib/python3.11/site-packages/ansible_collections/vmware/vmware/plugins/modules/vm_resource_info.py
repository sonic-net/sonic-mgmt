#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vm_resource_info
short_description: Gather information about the resources of one or more VMs.
description:
    - This module gathers information about VM resources, like CPU and memory configuration.
    - It also returns identifying information about the ESXi host that the VM is on, as well as the
      resource pool that contains the VM.
author:
    - Ansible Cloud Team (@ansible-collections)

options:
    name:
        description:
            - The name of the vm to gather info for
            - Only one of name, moid, uuid is allowed
        type: str
        required: False
    uuid:
        description:
            - The UUID of the vm to gather info for
            - Only one of name, moid, uuid is allowed
        type: str
        required: False
    moid:
        description:
            - The MOID of the vm to gather info for
            - Only one of name, moid, uuid is allowed
        type: str
        required: False
    use_instance_uuid:
        description:
            - If true, search by instance UUID instead of BIOS UUID.
            - BIOS UUID may not be unique and may cause errors.
        type: bool
        required: False
        default: True
    name_match:
        description:
            - If using name and multiple VMs have the same name, specify which VM should be selected
        type: str
        required: False
        choices: ['first', 'last']
    gather_cpu_config:
        description:
            - If true, information is gathered about the VM(s) CPU configuration.
            - Setting to false can speed up module results.
        default: True
        type: bool
    gather_cpu_stats:
        description:
            - If true, information is gathered about the VM(s) CPU usage metrics.
            - Setting to false can speed up module results.
        default: True
        type: bool
    gather_memory_config:
        description:
            - If true, information is gathered about the VM(s) memory configuration.
            - Setting to false can speed up module results.
        default: True
        type: bool
    gather_memory_stats:
        description:
            - If true, information is gathered about the VM(s) memory usage metrics.
            - Setting to false can speed up module results.
        default: True
        type: bool

extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Gather VM Resource Info
  vmware.vmware.vm_resource_info:
    moid: "{{ vm_id }}"

- name: Gather VM Resource Info By Name
  vmware.vmware.vm_resource_info:
    name: "{{ vm_name }}"
    name_match: first

- name: Gather Just Resource Config Info
  vmware.vmware.vm_resource_info:
    moid: "{{ vm_id }}"
    gather_cpu_stats: false
    gather_memory_stats: false

- name: Gather Just The Host and Resource Pool IDs For All VMs
  vmware.vmware.vm_resource_info:
    moid: "{{ vm_id }}"
    gather_cpu_config: false
    gather_memory_config: false
    gather_cpu_stats: false
    gather_memory_stats: false
# Note: although all gather parameters are set to false in the previous example, the output keys will still be present in the results. For example:
# "vms": [
#     {
#         "cpu": {},
#         "esxi_host": {
#             "moid": "host-64",
#             "name": "10.10.10.129"
#         },
#         "memory": {},
#         "moid": "vm-75373",
#         "name": "ma1",
#         "resource_pool": {
#             "moid": "resgroup-35",
#             "name": "Resources"
#         },
#         "stats": {
#             "cpu": {},
#             "memory": {}
#         }
#     }
# ]
'''

RETURN = r'''
vms:
    description:
        - Information about CPU and memory for the selected VMs.
    returned: Always
    type: list
    sample: [
        {
            "cpu": {
                "cores_per_socket": 1,
                "hot_add_enabled": false,
                "hot_remove_enabled": false,
                "processor_count": 1
            },
            "esxi_host": {
                "moid": "host-64",
                "name": "10.10.10.129"
            },
            "memory": {
                "hot_add_enabled": false,
                "hot_add_increment": 0,
                "hot_add_max_limit": 4096,
                "size_mb": 4096
            },
            "moid": "vm-75373",
            "name": "ma1",
            "resource_pool": {
                "moid": "resgroup-35",
                "name": "Resources"
            },
            "stats": {
                "cpu": {
                    "demand_mhz": 68,
                    "distributed_entitlement_mhz": 68,
                    "readiness_mhz": 0,
                    "static_entitlement_mhz": 1989,
                    "usage_mhz": 68
                },
                "memory": {
                    "active_mb": 81,
                    "ballooned_mb": 0,
                    "consumed_overhead_mb": 38,
                    "distributed_entitlement_mb": 857,
                    "guest_usage_mb": 81,
                    "host_usage_mb": 1890,
                    "static_entitlement_mb": 4406,
                    "swapped_mb": 0
                }
            }
        }
    ]
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import ModulePyvmomiBase
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import base_argument_spec


class VmwareGuestInfo(ModulePyvmomiBase):
    def __init__(self, module):
        super(VmwareGuestInfo, self).__init__(module)

    def _format_cpu_output(self, vm):
        if not self.params['gather_cpu_config']:
            return {}
        return {
            'processor_count': vm.config.hardware.numCPU,
            'cores_per_socket': vm.config.hardware.numCoresPerSocket,
            'hot_add_enabled': vm.config.cpuHotAddEnabled,
            'hot_remove_enabled': vm.config.cpuHotRemoveEnabled,
        }

    def _format_cpu_stats_output(self, vm):
        if not self.params['gather_cpu_stats']:
            return {}
        return {
            'demand_mhz': vm.summary.quickStats.overallCpuDemand,
            'readiness_mhz': vm.summary.quickStats.overallCpuReadiness,
            'usage_mhz': vm.summary.quickStats.overallCpuUsage,
            'static_entitlement_mhz': vm.summary.quickStats.staticCpuEntitlement,
            'distributed_entitlement_mhz': vm.summary.quickStats.distributedCpuEntitlement,
        }

    def _format_memory_output(self, vm):
        if not self.params['gather_memory_config']:
            return {}
        return {
            'size_mb': vm.config.hardware.memoryMB,
            'hot_add_enabled': vm.config.memoryHotAddEnabled,
            'hot_add_max_limit': vm.config.hotPlugMemoryLimit,
            'hot_add_increment': vm.config.hotPlugMemoryIncrementSize
        }

    def _format_memory_stats_output(self, vm):
        if not self.params['gather_memory_stats']:
            return {}
        return {
            'active_mb': vm.summary.quickStats.activeMemory,
            'ballooned_mb': vm.summary.quickStats.balloonedMemory,
            'consumed_overhead_mb': vm.summary.quickStats.consumedOverheadMemory,
            'guest_usage_mb': vm.summary.quickStats.guestMemoryUsage,
            'host_usage_mb': vm.summary.quickStats.hostMemoryUsage,
            'swapped_mb': vm.summary.quickStats.swappedMemory,
            'distributed_entitlement_mb': vm.summary.quickStats.distributedMemoryEntitlement,
            'static_entitlement_mb': vm.summary.quickStats.staticMemoryEntitlement
        }

    def _format_esxi_output(self, vm):
        try:
            return {
                'name': vm.runtime.host.name,
                'moid': vm.runtime.host._GetMoId()
            }
        except AttributeError:
            return {}

    def _format_rp_output(self, vm):
        try:
            return {
                'name': vm.resourcePool.name,
                'moid': vm.resourcePool._GetMoId()
            }
        except AttributeError:
            return {}

    def gather_info_for_vms(self):
        all_vm_info = []
        for vm in self.get_vms():
            info = {
                'name': vm.name,
                'moid': vm._GetMoId(),
                'esxi_host': self._format_esxi_output(vm),
                'resource_pool': self._format_rp_output(vm),
                'cpu': self._format_cpu_output(vm),
                'memory': self._format_memory_output(vm),
                'stats': {
                    'cpu': self._format_cpu_stats_output(vm),
                    'memory': self._format_memory_stats_output(vm)
                }
            }
            all_vm_info.append(info)

        return all_vm_info

    def get_vms(self):
        """
        Uses the UUID, MOID, or name provided to find the source VM for the template. Returns an error if using the name,
        multiple matches are found, and the user did not provide a name_match strategy.
        """
        if self.params.get('name') or self.params.get('uuid') or self.params.get('moid'):
            vm = self.get_vms_using_params(fail_on_missing=False)
        else:
            vm = self.get_all_vms()

        return vm if vm else []


def main():
    argument_spec = base_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type='str'),
            name_match=dict(type='str', choices=['first', 'last'], default=None),
            uuid=dict(type='str'),
            use_instance_uuid=dict(type='bool', default=True),
            moid=dict(type='str'),
            gather_cpu_config=dict(type='bool', default=True),
            gather_memory_config=dict(type='bool', default=True),
            gather_cpu_stats=dict(type='bool', default=True),
            gather_memory_stats=dict(type='bool', default=True),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[['name', 'uuid', 'moid']]
    )

    vmware_hw_info = VmwareGuestInfo(module)
    gathered_info = vmware_hw_info.gather_info_for_vms()
    module.exit_json(changed=False, vms=gathered_info)


if __name__ == '__main__':
    main()
