#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: esxi_connection
short_description: Manage VMware ESXi host connection status in vCenter
description:
    - Manage VMware ESXi host connection status in vCenter. Disconnecting hosts temporarily
      disables monitoring for the host and its VMs. However they will still show up in vCenter.
    - This module does not manage the addition, removal, or placement of hosts in vCenter.
      That functionality is in vmware.vmware.esxi_host
    - The community.vmware.vmware_host module allows you to add a host in a disconnected state.
      The host must have been added in a connected state for you to reconnect it using this module.
      You can remove the host and add it back using the vmware.vmware.esxi_host to get it in the proper state.

author:
    - Ansible Cloud Team (@ansible-collections)

seealso:
    - module: vmware.vmware.esxi_host

options:
    datacenter:
        description:
            - The name of the datacenter.
        type: str
        required: true
        aliases: [datacenter_name]
    esxi_host_name:
        description:
            - ESXi hostname to manage.
        required: true
        type: str
        aliases: [name]
    state:
        description:
            - Sets the connection status of the host in vCenter
        default: connected
        choices: ['connected', 'disconnected']
        type: str

extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Connect Host
  vmware.vmware.esxi_connection:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    validate_certs: false
    datacenter: "{{ vcenter_datacenter }}"
    esxi_host_name: 10.10.10.10
    state: connected

- name: Disconnect Host
  vmware.vmware.esxi_connection:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    validate_certs: false
    datacenter: "{{ vcenter_datacenter }}"
    esxi_host_name: 10.10.10.10
    state: disconnected
'''

RETURN = r'''
host:
    description:
        - Identifying information about the managed host
    returned: Always
    type: dict
    sample: {
        "host": {
            "moid": "host-111111",
            "name": "10.10.10.10"
        },
    }
result:
    description:
        - Information about the vCenter task, if something changed
    returned: On change
    type: dict
    sample: {
        "result": {
            "completion_time": "2024-07-29T15:27:37.041577+00:00",
            "entity_name": "test-5fb1_my_esxi_host",
            "error": null,
            "state": "success"
        }
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


class VmwareHostConnection(ModulePyvmomiBase):
    def __init__(self, module):
        super().__init__(module)
        self.datacenter = self.get_datacenter_by_name_or_moid(self.params.get('datacenter'), fail_on_missing=True)
        self.host = self.get_esxi_host_by_name_or_moid(identifier=self.params['esxi_host_name'], fail_on_missing=True)

    def reconnect_host(self):
        reconnect_spec = vim.HostSystem.ReconnectSpec()
        reconnect_spec.syncState = True
        try:
            task = self.host.ReconnectHost_Task(reconnectSpec=reconnect_spec)
            _, task_result = RunningTaskMonitor(task).wait_for_completion()   # pylint: disable=disallowed-name
        except vim.fault.InvalidLogin:
            self.module.fail_json(msg=(
                'Failed to connect host due to invalid username or password. If these values are correct, you '
                'can try removing and adding the host in a connected state, using the vmware.vmware.esxi_host module.'
            ))
        except (vmodl.RuntimeFault, vmodl.MethodFault)as vmodl_fault:
            self.module.fail_json(msg=to_native(vmodl_fault.msg))
        except TaskError as task_e:
            self.module.fail_json(msg=to_native(task_e))
        except Exception as generic_exc:
            self.module.fail_json(msg=(
                "Failed to reconnect host %s due to exception %s" %
                (self.params['esxi_host_name'], to_native(generic_exc))
            ))

        return task_result

    def disconnect_host(self):
        try:
            task = self.host.DisconnectHost_Task()
            _, task_result = RunningTaskMonitor(task).wait_for_completion()   # pylint: disable=disallowed-name
        except (vmodl.RuntimeFault, vmodl.MethodFault)as vmodl_fault:
            self.module.fail_json(msg=to_native(vmodl_fault.msg))
        except TaskError as task_e:
            self.module.fail_json(msg=to_native(task_e))
        except Exception as generic_exc:
            self.module.fail_json(msg=(
                "Failed to disconnect host %s due to exception %s" %
                (self.params['esxi_host_name'], to_native(generic_exc))
            ))
        return task_result


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(), **dict(
                datacenter=dict(type='str', required=True, aliases=['datacenter_name']),
                state=dict(type='str', default='connected', choices=['connected', 'disconnected']),
                esxi_host_name=dict(type='str', required=True, aliases=['name']),
            )
        },
        supports_check_mode=True
    )

    vmware_host_connection = VmwareHostConnection(module)
    result = dict(changed=False, host=dict(
        name=vmware_host_connection.host.name,
        moid=vmware_host_connection.host._GetMoId()
    ))
    if module.params['state'] == vmware_host_connection.host.runtime.connectionState:
        module.exit_json(**result)

    result['changed'] = True
    if module.check_mode:
        module.exit_json(**result)

    if module.params['state'] == 'disconnected':
        vmware_host_connection.disconnect_host()
    else:
        vmware_host_connection.reconnect_host()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
