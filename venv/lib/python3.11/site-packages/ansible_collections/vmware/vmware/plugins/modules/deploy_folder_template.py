#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: deploy_folder_template
short_description: Deploy a VM from a template located in a folder
description:
    - Create a VM from a template that is located in vCenter. The template must be found in a folder, as opposed to being in a content library.
    - This module manages the deployed VM, not the template. The template will be unchanged.
    - To further configure the VM, ensure it is deployed in the powered off state and then use other modules to configure it.
    - The module basis idempotentency on if the deployed VM exists or not, not the storage or power settings applied at deployment time.

author:
    - Ansible Cloud Team (@ansible-collections)

seealso:
    - module: vmware.vmware.folder_template_from_vm

options:
    template_name:
        description:
            - The name of the template to use when deploying.
            - You must also supply O(template_folder) if you use this parameter.
            - This parameter is not used if O(template_id) is supplied.
        type: str
        required: False
    template_folder:
        description:
            - The path to the folder where the template with O(template_name) exists.
            - This parameter is not used if O(template_id) is supplied.
            - This can be an absolute (/datacenter/vm/my/folder) or relative (my/folder) path.
            - This parameter is mutually exclusive with O(template_folder_id).
        type: str
        required: False
    template_folder_id:
        description:
            - The ID of the folder where the template with O(template_name) exists.
            - This parameter is not used if O(template_id) is supplied.
            - This parameter is mutually exclusive with O(template_folder).
        type: str
        required: False
    template_id:
        description:
            - The ID of the template to use when deploying.
            - This parameter takes precedence over O(template_name) and O(template_folder)
        type: str
        required: False
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

attributes:
    check_mode:
        description: The check_mode support.
        support: full

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.module_deploy_vm_base_options

'''

EXAMPLES = r'''
- name: Create A New VM From A Template
  vmware.vmware.deploy_folder_template:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    datacenter: "my-datacenter"
    vm_name: "my_vm"
    template_name: "my_template"

- name: Create A New Template Using Folders To Specify Which VM and Template
  vmware.vmware.deploy_folder_template:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    datacenter: "my-datacenter"
    vm_name: "my_vm"
    template_name: "my_template"
    vm_folder: foo/bar/my/vms
    template_folder: /my-datacenter/vm/foo/bar/my/templates
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

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_deploy_vm_base import (
    ModuleVmDeployBase,
    vm_deploy_module_argument_spec
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    base_argument_spec
)
from ansible_collections.vmware.vmware.plugins.module_utils._vsphere_tasks import RunningTaskMonitor, TaskError

PYVMOMI_IMP_ERR = None
try:
    from pyVmomi import vim
    HAS_PYVMOMI = True
except ImportError:
    PYVMOMI_IMP_ERR = traceback.format_exc()
    HAS_PYVMOMI = False


class VmwareFolderTemplate(ModuleVmDeployBase):
    def __init__(self, module):
        super().__init__(module)
        self.template = None

    def __lookup_template_folder(self):
        if self.params['template_folder_id']:
            folder = self.get_folders_by_name_or_moid(self.params['template_folder_id'], fail_on_missing=True)[0]
        else:
            folder = self.placement_service.get_folder(folder_param='template_folder')

        return folder

    def __lookup_template_from_name_and_folder(self):
        folder = self.__lookup_template_folder()
        templates = self.get_objs_by_name_or_moid(
            [vim.VirtualMachine], self.params['template_name'], return_all=True, search_root_folder=folder
        )

        template = None
        for possible_template in templates:
            if not possible_template.config.template:
                continue
            if template:
                self.module.fail_json(msg=(
                    "Found multiple templates with the name %s in folder %s" %
                    (self.params['template_name'], folder.name)
                ))

            template = possible_template
            # can't break here, need to check all the others in case there's more than one

        if not template:
            self.module.fail_json(msg=(
                "Unable to find template with name %s in folder %s" % (self.params['template_name'], folder.name)
            ))
        return template

    def resolve_template_object(self):
        """
            Lookup template object by ID or name/path combo. When looking up by name and path, fail if multiple
            templates are found, since its unclear which one to use. I think this situation might be impossible
            but I am not sure.
            If the object found isn't actually a template, fail.
            Returns:
                template object or None
        """
        if self.params['template_id']:
            templates = self.get_objs_by_name_or_moid([vim.VirtualMachine], self.params['template_id'])
            if not templates:
                self.module.fail_json(msg="Unable to find template with ID %s" % self.params['template_id'])
            template = templates[0]
        else:
            template = self.__lookup_template_from_name_and_folder()

        if not template.config.template:
            self.module.fail_json(msg="Object found matching template name or ID is not a template")

        self.template = template
        return template

    def deploy(self, deploy_spec):
        try:
            task = self.template.Clone(name=self.params['vm_name'], folder=self.vm_folder, spec=deploy_spec)
            _, task_result = RunningTaskMonitor(task).wait_for_completion()   # pylint: disable=disallowed-name
        except TaskError as e:
            self.module.fail_json(msg="Failed to complete VM clone from template task due to: %s" % e)
        except Exception as e:
            self.module.fail_json(msg="Failed to clone VM from template due to unexpected exception: %s" % e)

        return task_result['result']

    def create_deploy_spec(self):
        relo_spec = vim.vm.RelocateSpec()
        if self.datastore:
            relo_spec.datastore = self.datastore

        if self.resource_pool:
            relo_spec.pool = self.resource_pool

        if self.params['esxi_host']:
            relo_spec.host = self.placement_service.get_esxi_host()

        clone_spec = vim.vm.CloneSpec()
        clone_spec.location = relo_spec
        clone_spec.powerOn = self.params['power_on_after_deploy']
        return clone_spec


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(),
            **vm_deploy_module_argument_spec(),
            **dict(
                template_id=dict(type='str', required=False),
                template_name=dict(type='str', required=False),
                template_folder=dict(type='str', required=False),
                template_folder_id=dict(type='str', required=False),
                esxi_host=dict(type='str', required=False, aliases=['host']),
                power_on_after_deploy=dict(type='bool', default=False)
            )
        },
        mutually_exclusive=[
            ('template_id', 'template_name'),
            ('datastore', 'datastore_cluster'),
            ('cluster', 'resource_pool'),
            ('template_folder', 'template_folder_id')
        ],
        required_one_of=[
            ('template_id', 'template_name')
        ],
        supports_check_mode=True,
    )

    result = dict(
        changed=False,
        vm=dict(
            name=module.params['vm_name'],
            moid=None
        )
    )

    folder_template = VmwareFolderTemplate(module)
    vm = folder_template.get_deployed_vm()
    if vm:
        result['vm']['moid'] = vm._GetMoId()
    else:
        result['changed'] = True
        folder_template.resolve_template_object()
        deploy_spec = folder_template.create_deploy_spec()
        if not module.check_mode:
            vm = folder_template.deploy(deploy_spec)
            result['vm']['moid'] = vm._GetMoId()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
