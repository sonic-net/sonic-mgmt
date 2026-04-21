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
module: deploy_content_library_ovf
short_description: Deploy a virtual machine from an OVF in a content library.
description:
    - Create a VM based on an OVF in a content library.
    - The module basis idempotentency on if the deployed VM exists or not, not the storage or deployment spec applied at deployment time.
author:
    - Ansible Cloud Team (@ansible-collections)

requirements:
    - vSphere Automation SDK

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options
    - vmware.vmware.module_deploy_vm_base_options

seealso:
    - module: vmware.vmware.deploy_content_library_template
    - module: vmware.vmware.deploy_folder_template

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
    storage_provisioning:
        description:
            - Default storage provisioning type to use for all sections of type vmw:StorageSection in the OVF descriptor.
        type: str
        default: 'thin'
        choices: [ thin, thick, eagerZeroedThick ]

    # These are defined in the vmware.vmware.module_deploy_vm_base_options doc frag, so this section is just updating the
    # description of these options as needed
    resource_pool:
        description:
            - The name of a resource pool into which the virtual machine should be deployed.
            - Changing this option will not result in the VM being redeployed (it does not affect idempotency).
            - One and only one of O(resource_pool) or O(cluster) is required.
    cluster:
        description:
            - The name of the cluster where the VM should be deployed.
            - Changing this option will not result in the VM being redeployed (it does not affect idempotency).
            - One and only one of O(resource_pool) or O(cluster) is required.
'''

EXAMPLES = r'''
- name: Create Virtual Machine From OVF Template
  vmware.vmware.deploy_content_library_ovf:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    library_item_name: mytemplate
    library_name: mylibrary
    vm_name: myvm
    datacenter: DC01
    datastore: DS01
    resource_pool: RP01


- name: Create Virtual Machine Using Absolute Folder Destination
  vmware.vmware.deploy_content_library_ovf:
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
  vmware.vmware.deploy_content_library_ovf:
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
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import ModuleRestBase
from ansible_collections.vmware.vmware.plugins.module_utils._module_deploy_vm_base import (
    ModuleVmDeployBase,
    vm_deploy_module_argument_spec
)

try:
    from com.vmware.vcenter.ovf_client import LibraryItem as OvfLibraryItems
    from com.vmware.vapi.std.errors_client import Error
except ImportError:
    pass


class VmwareContentDeployOvf(ModuleVmDeployBase):
    def __init__(self, module):
        """Constructor."""
        super(VmwareContentDeployOvf, self).__init__(module)

        # Initialize member variables
        self.rest_base = ModuleRestBase(module)
        self.ovf_service = self.rest_base.api_client.vcenter.ovf.LibraryItem
        self._library_item_id = self.params.get('library_item_id')

    def create_deploy_spec(self):
        deployment_target = OvfLibraryItems.DeploymentTarget(
            resource_pool_id=self.resource_pool._GetMoId(),
            folder_id=self.vm_folder._GetMoId()
        )

        ovf_summary = self.ovf_service.filter(
            ovf_library_item_id=self.library_item_id,
            target=deployment_target
        )

        deploy_spec = OvfLibraryItems.ResourcePoolDeploymentSpec(
            name=self.params['vm_name'],
            annotation=ovf_summary.annotation,
            accept_all_eula=True,
            network_mappings=None,
            storage_mappings=None,
            storage_provisioning=self.params['storage_provisioning'],
            storage_profile_id=None,
            locale=None,
            flags=None,
            additional_parameters=None,
            default_datastore_id=(self.datastore._GetMoId() if self.datastore else None)
        )

        return deployment_target, deploy_spec

    def deploy(self, deployment_target, deploy_spec):
        try:
            response = self.ovf_service.deploy(
                self.library_item_id,
                deployment_target,
                deploy_spec
            )
        except Error as error:
            self.module.fail_json(msg=' ,'.join([err.default_message % err.args for err in error.messages]))
        except Exception as err:
            self._fail(msg="%s" % to_native(err))

        if not response.succeeded:
            self.module.fail_json(msg=(
                "Failed to deploy OVF %s to VM %s. Check vSphere event log for more details" %
                (self.library_item_id, self.params['vm_name'])
            ))

        return response.resource_id.id


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(vm_deploy_module_argument_spec())
    argument_spec.update(
        library_name=dict(type='str', required=False),
        library_id=dict(type='str', required=False),
        library_item_name=dict(type='str', required=False, aliases=['template_name']),
        library_item_id=dict(type='str', required=False, aliases=['template_id']),
        storage_provisioning=dict(type='str', default='thin', choices=['thin', 'thick', 'eagerZeroedThick']),
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
            ('cluster', 'resource_pool'),
        ]
    )

    result = {'changed': False, 'vm': {'name': module.params['vm_name']}}
    vmware_template = VmwareContentDeployOvf(module)
    vm = vmware_template.get_deployed_vm()
    if vm:
        result['vm']['moid'] = vm._GetMoId()
    else:
        result['changed'] = True
        deployment_target, deploy_spec = vmware_template.create_deploy_spec()
        if not module.check_mode:
            vm_id = vmware_template.deploy(deployment_target, deploy_spec)
            result['vm']['moid'] = vm_id

    module.exit_json(**result)


if __name__ == '__main__':
    main()
