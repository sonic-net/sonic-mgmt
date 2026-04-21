#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Ansible Project
# Copyright: (c) 2019, Pavan Bidkar <pbidkar@vmware.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: deploy_content_library_template
short_description: Deploy a virtual machine from a template in a content library.
description:
    - Create a VM based on a template in a content library.
    - The module basis idempotentency on if the deployed VM exists or not, not the storage or power settings applied at deployment time.
author:
    - Ansible Cloud Team (@ansible-collections)

requirements:
    - vSphere Automation SDK

seealso:
    - module: vmware.vmware.deploy_content_library_ovf
    - module: vmware.vmware.deploy_folder_template

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options
    - vmware.vmware.module_deploy_vm_base_options

options:
    library_item_name:
        description:
            - The name of content library template to use when deploying the VM.
            - This option is mutually exclusive with O(library_item_id).
            - One of either O(library_item_name) or O(library_item_id) is required.
        type: str
        required: false
        aliases: [template_name]
    library_item_id:
        description:
            - The ID of content library template to use when deploying the VM.
            - This option is mutually exclusive with O(library_item_name).
            - One of either O(library_item_name) or O(library_item_id) is required.
        type: str
        required: false
        aliases: [template_id]
    library_name:
        description:
            - The name of the content library where the template exists.
            - >-
              This is an optional parameter, but may be required if you use O(template_name) and have
              multiple templates in different libraries with the same name.
            - This option is mutually exclusive with O(library_id).
        type: str
        required: false
    library_id:
        description:
            - The ID of the content library where the template exists.
            - >-
              This is an optional parameter, but may be required if you use O(template_name) and have
              multiple templates in different libraries with the same name.
            - This option is mutually exclusive with O(library_name).
        type: str
        required: false
    esxi_host:
        description:
            - The name of the ESXi host onto which the virtual machine should be deployed.
            - If O(esxi_host) and O(resource_pool) are both specified, O(resource_pool) must belong to O(esxi_host).
            - If O(esxi_host) and O(cluster) are both specified, O(esxi_host) must be a member of O(cluster).
            - Changing this option will not result in the VM being redeployed (it does not affect idempotency).
        type: str
        required: false
        aliases: [host]
    power_on_after_deploy:
        description:
            - Whether or not the VM should be powered on once it has been deployed.
            - This is only applied when the VM is deployed. If the VM already exists, the power state is not modified.
            - Changing this option will not result in the VM being redeployed (it does not affect idempotency).
        type: bool
        default: false
        required: false
'''

EXAMPLES = r'''
- name: Create Virtual Machine From Content Library Template
  vmware.vmware.deploy_content_library_template:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    library_item_name: mytemplate
    library_name: mylibrary
    vm_name: myvm
    datacenter: DC01
    datastore: DS01
    resource_pool: RP01
    esxi_host: Host01


- name: Create Virtual Machine Using Absolute Folder Destination
  vmware.vmware.deploy_content_library_template:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    library_item_name: mytemplate
    library_name: mylibrary
    vm_name: myvm
    datacenter: DC01
    datastore: DS01
    folder: /DC01/vm/my/deploys

- name: Create Virtual Machine Using Relative Folder Destination
  vmware.vmware.deploy_content_library_template:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    library_item_name: mytemplate
    library_name: mylibrary
    vm_name: myvm
    datacenter: DC01
    datastore: DS01
    folder: my/deploys
'''

RETURN = r'''
vm:
    description:
        - Identifying information about the vm
    returned: always
    type: dict
    sample: {
        "vm": {
            "moid": "vm-111111",
            "name": "my-vm"
        },
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import rest_compatible_argument_spec
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import ModuleRestBase
from ansible_collections.vmware.vmware.plugins.module_utils._module_deploy_vm_base import (
    ModuleVmDeployBase,
    vm_deploy_module_argument_spec
)
from ansible.module_utils.common.text.converters import to_native

try:
    from com.vmware.vcenter.vm_template_client import LibraryItems as TemplateLibraryItems
    from com.vmware.vapi.std.errors_client import Error
except ImportError:
    pass


class VmwareContentDeployTemplate(ModuleVmDeployBase):
    def __init__(self, module):
        """Constructor."""
        super(VmwareContentDeployTemplate, self).__init__(module)

        self.rest_base = ModuleRestBase(module)
        self.template_service = self.rest_base.api_client.vcenter.vm_template.LibraryItems
        self._library_item_id = self.params.get('library_item_id')

    def create_deploy_spec(self):
        deploy_spec_args = dict(
            name=self.params['vm_name'],
            powered_on=self.params['power_on_after_deploy']
        )

        placement_spec = TemplateLibraryItems.DeployPlacementSpec(folder=self.vm_folder._GetMoId())
        if self.params.get('esxi_host'):
            placement_spec.host = self.placement_service.get_esxi_host()._GetMoId()

        if self.resource_pool:
            placement_spec.resource_pool = self.resource_pool._GetMoId()

        deploy_spec_args['placement'] = placement_spec

        if self.datastore:
            deploy_spec_args['vm_home_storage'] = TemplateLibraryItems.DeploySpecVmHomeStorage(
                datastore=to_native(self.datastore._GetMoId())
            )
            deploy_spec_args['disk_storage'] = TemplateLibraryItems.DeploySpecDiskStorage(
                datastore=to_native(self.datastore._GetMoId())
            )

        return TemplateLibraryItems.DeploySpec(**deploy_spec_args)

    def deploy(self, deploy_spec):
        try:
            return self.template_service.deploy(
                self.library_item_id,
                deploy_spec
            )
        except Error as error:
            self.module.fail_json(msg=' ,'.join([err.default_message % err.args for err in error.messages]))
        except Exception as err:
            self._fail(msg="%s" % to_native(err))


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(vm_deploy_module_argument_spec())
    argument_spec.update(
        library_name=dict(type='str', required=False),
        library_id=dict(type='str', required=False),
        library_item_name=dict(type='str', required=False, aliases=['template_name']),
        library_item_id=dict(type='str', required=False, aliases=['template_id']),
        esxi_host=dict(type='str', required=False, aliases=['host']),
        power_on_after_deploy=dict(type='bool', default=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ('library_name', 'library_id'),
            ('library_item_name', 'library_item_id'),
            ('datastore', 'datastore_cluster'),
            ('cluster', 'resource_pool')
        ],
        required_one_of=[
            ('library_item_name', 'library_item_id'),
        ]
    )

    result = {'changed': False, 'vm': {'name': module.params['vm_name']}}
    vmware_template = VmwareContentDeployTemplate(module)
    vm = vmware_template.get_deployed_vm()
    if vm:
        result['vm']['moid'] = vm._GetMoId()
    else:
        result['changed'] = True
        spec = vmware_template.create_deploy_spec()
        if not module.check_mode:
            vm_id = vmware_template.deploy(spec)
            result['vm']['moid'] = vm_id

    module.exit_json(**result)


if __name__ == '__main__':
    main()
