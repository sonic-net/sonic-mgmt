#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: esxi_maintenance_mode
short_description: Manage an ESXi hosts maintenance mode setting in vCenter
description:
    - Manage an ESXi hosts maintenance mode setting in vCenter
author:
    - Ansible Cloud Team (@ansible-collections)

options:
    esxi_host_name:
        description:
            - Name of the host as defined in vCenter.
        required: true
        type: str
        aliases: ['name']
    enable_maintenance_mode:
        description:
            - If true, the ESXi host will be put into maintenance mode.
        required: false
        default: true
        type: bool
    vsan_compliance_mode:
        description:
            - Specify which VSAN compliant mode to enter.
        choices:
            - 'ensureObjectAccessibility'
            - 'evacuateAllData'
            - 'noAction'
        required: false
        type: str
    evacuate:
        description:
            - If set to V(true), evacuate all powered off VMs.
        default: false
        required: false
        type: bool
    timeout:
        description:
            - Specify a timeout for the operation.
        required: false
        default: 0
        type: int


extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Enable ESXi Maintenance Mode On A Host
  vmware.vmware.esxi_maintenance_mode:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    name: my_esxi_host
    enable_maintenance_mode: true
    evacuate: true
    timeout: 600

- name: Disable ESXi Maintenance Mode On A Host
  vmware.vmware.esxi_maintenance_mode:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    name: my_esxi_host
    enable_maintenance_mode: false

- name: Enable With A Specific VSAN Mode
  vmware.vmware.esxi_maintenance_mode:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    name: my_esxi_host
    enable_maintenance_mode: true
    vsan_compliance_mode: ensureObjectAccessibility
'''

RETURN = r'''
result:
    description:
        - Information about the maintenance mode update task, if something changed
        - If nothing changed, an empty dictionary is returned
    returned: On success
    type: dict
    sample: {
        "result": {
            "completion_time": "2024-07-29T15:27:37.041577+00:00",
            "entity_name": "test-5fb1_my_esxi_host",
            "error": null,
            "state": "success"
        }
    }
host:
    description:
        - Identifying information about the host
    returned: always
    type: dict
    sample: {
        "host": {
            "moid": "host-111111",
            "name": "10.10.10.10"
        },
    }
'''

try:
    from pyVmomi import vim, vmodl
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    base_argument_spec
)
from ansible_collections.vmware.vmware.plugins.module_utils._vsphere_tasks import (
    TaskError,
    RunningTaskMonitor
)


class EsxiMaintenanceModeModule(ModulePyvmomiBase):
    def __init__(self, module):
        super(EsxiMaintenanceModeModule, self).__init__(module)
        self.host = self.get_esxi_host_by_name_or_moid(identifier=self.params['esxi_host_name'], fail_on_missing=True)

    def current_state_matches_desired_state(self):
        """
        Checks the ESXi hosts current maintenance mode setting and compares it to the user's desired maintenance mode
        setting.
        Returns:
            bool, true if they match, otherwise false
        """
        if self.params['enable_maintenance_mode'] and self.host.runtime.inMaintenanceMode:
            return True
        if (not self.params['enable_maintenance_mode']) and (not self.host.runtime.inMaintenanceMode):
            return True

        return False

    def enable_maintenance_mode(self):
        """
        Creates a task in vCenter to transition the host into maintenance mode. Waits until the task is complete to
        continue.
        Returns:
            task object describing the maintenance mode transition task
        """
        spec = vim.host.MaintenanceSpec()
        if self.params['vsan_compliance_mode']:
            spec.vsanMode = vim.vsan.host.DecommissionMode()
            spec.vsanMode.objectAction = self.params['vsan_compliance_mode']

        try:
            task = self.host.EnterMaintenanceMode_Task(
                self.module.params['timeout'],
                self.module.params['evacuate'],
                spec
            )
            _, task_result = RunningTaskMonitor(task).wait_for_completion()   # pylint: disable=disallowed-name
        except (vmodl.RuntimeFault, vmodl.MethodFault)as vmodl_fault:
            self.module.fail_json(msg=to_native(vmodl_fault.msg))
        except TaskError as task_e:
            self.module.fail_json(msg=to_native(task_e))
        except Exception as generic_exc:
            self.module.fail_json(msg=(
                "Failed to exit maintenance mode on %s due to exception %s" %
                (self.params['esxi_host_name'], to_native(generic_exc))
            ))

        return task_result

    def disable_maintenance_mode(self):
        """
        Creates a task in vCenter to transition the host out of maintenance mode. Waits until the task is complete to
        continue.
        Returns:
            task object describing the maintenance mode transition task
        """
        try:
            task = self.host.ExitMaintenanceMode_Task(self.module.params['timeout'])
            _, task_result = RunningTaskMonitor(task).wait_for_completion()   # pylint: disable=disallowed-name
        except (vmodl.RuntimeFault, vmodl.MethodFault)as vmodl_fault:
            self.module.fail_json(msg=to_native(vmodl_fault.msg))
        except TaskError as task_e:
            self.module.fail_json(msg=to_native(task_e))
        except Exception as generic_exc:
            self.module.fail_json(msg=(
                "Failed to exit maintenance mode on %s due to exception %s" %
                (self.params['esxi_host_name'], to_native(generic_exc))
            ))

        return task_result


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(), **dict(
                esxi_host_name=dict(type='str', required=True, aliases=['name']),
                vsan_compliance_mode=dict(type='str', required=False, choices=['ensureObjectAccessibility', 'evacuateAllData', 'noAction']),
                enable_maintenance_mode=dict(type='bool', default=True),
                evacuate=dict(type='bool', default=False),
                timeout=dict(type='int', default=0),
            )
        },
        supports_check_mode=True,
    )

    result = dict(
        changed=False,
        result={},
        host=dict(name='', moid='')
    )

    esxi_maint_mode = EsxiMaintenanceModeModule(module)
    result['host']['name'] = module.params['esxi_host_name']
    result['host']['moid'] = esxi_maint_mode.host._GetMoId()
    if esxi_maint_mode.current_state_matches_desired_state():
        module.exit_json(**result)

    result['changed'] = True
    if module.check_mode:
        module.exit_json(**result)

    if module.params['enable_maintenance_mode']:
        result['result'] = esxi_maint_mode.enable_maintenance_mode()
    else:
        result['result'] = esxi_maint_mode.disable_maintenance_mode()

    # this field has the ESXi host object in it, which can't be output by ansible without manipulation.
    # but we dont need it in the output anyway, so just delete it
    del result['result']['result']

    module.exit_json(**result)


if __name__ == '__main__':
    main()
