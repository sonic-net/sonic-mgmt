#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: folder_template_from_vm
short_description: Create a template in a local VCenter folder from an existing VM
description:
    - >-
      This module creates a template in a local VCenter folder from an existing VM. The folder must already exist.
      The VM must be powered off, and is otherwise unchanged. If the template already exists and the desired state
      is 'present', nothing is done.
author:
    - Ansible Cloud Team (@ansible-collections)
requirements:
    - pyvmomi
options:
    vm_name:
        description:
            - The name of the vm to be used to create the template
            - One of vm_name, vm_moid, vm_uuid is required
            - This parameter is ignored when state is 'absent'
        type: str
        required: False
    vm_uuid:
        description:
            - The UUID of the vm to be used to create the template
            - One of vm_name, vm_moid, vm_uuid is required
            - This parameter is ignored when state is 'absent'
        type: str
        required: False
    vm_moid:
        description:
            - The MOID of the vm to be used to create the template
            - One of vm_name, vm_moid, vm_uuid is required
            - This parameter is ignored when state is 'absent'
        type: str
        required: False
    vm_use_instance_uuid:
        description:
            - If true, search by instance UUID instead of BIOS UUID.
            - BIOS UUID may not be unique and may cause errors.
        type: bool
        required: False
        default: True
    vm_name_match:
        description:
            - If using vm_name and multiple VMs have the same name, specify which VM should be selected
        type: str
        required: False
        choices: ['first', 'last']
    template_folder:
        description:
            - The name of the folder that the new template should be placed in
            - Should be the full folder path, with or without the 'datacenter/vm/' prefix
            - For example 'datacenter name/vm/path/to/folder' or 'path/to/folder'
        type: str
        required: True
    folder_paths_are_absolute:
        description:
            - If true, any folder path parameters are treated as absolute paths.
            - If false, modules will try to intelligently determine if the path is absolute
              or relative.
            - This option is useful when your environment has a complex folder structure. By default,
              modules will try to intelligently determine if the path is absolute or relative.
              They may mistakenly prepend the datacenter name or other folder names, and this option
              can be used to avoid this.
        type: bool
        required: false
        default: false
    template_name:
        description:
            - The name to give to the new template.
        type: str
        required: True
    state:
        description:
            - If the template should be present or absent
        type: str
        required: False
        default: present
        choices: ['present', 'absent']
    datacenter:
        description:
           - The name of datacenter in which to operate
        type: str
        aliases: ['datacenter_name']
        required: True
    datastore:
        description:
            - The name of datastore to use as storage for the template.
        type: str
    resource_pool:
        description:
           - The resource pool to place the template in.
        type: str
    wait_for_template:
        description:
            - If true, the module will wait until the template is created to exit.
        type: bool
        default: True
attributes:
    check_mode:
        description: The check_mode support.
        support: full
extends_documentation_fragment:
    - vmware.vmware.base_options

'''

EXAMPLES = r'''
- name: Create A New Template Using VM UUID
  vmware.vmware.folder_template:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    datacenter: "my-datacenter"
    vm_uuid: "11111111-11111111-11111111"
    template_folder: "my-datacenter/vm/netsted/folder/path/templates"
    template_name: "my_template"

- name: Create A New Template Using VM Name
  vmware.vmware.folder_template_from_vm:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    datacenter: "my-datacenter"
    vm_name: "my_vm"
    vm_name_match: "first"
    template_name: "my_template"
    template_folder: "nested/folder/path/templates"

- name: Destroy A Template In A Folder
  vmware.vmware.folder_template_from_vm:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    datacenter: "my-datacenter"
    vm_name: "foo"
    state: "absent"
    template_name: "my_template"
    template_folder: "nested/folder/path/templates"
'''

RETURN = r'''
'''

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    base_argument_spec
)
from ansible_collections.vmware.vmware.plugins.module_utils._folder_paths import format_folder_path_as_vm_fq_path
from ansible_collections.vmware.vmware.plugins.module_utils._vsphere_tasks import RunningTaskMonitor, TaskError

PYVMOMI_IMP_ERR = None
try:
    from pyVmomi import vim
    HAS_PYVMOMI = True
except ImportError:
    PYVMOMI_IMP_ERR = traceback.format_exc()
    HAS_PYVMOMI = False


class VmwareFolderTemplate(ModulePyvmomiBase):
    def __init__(self, module):
        super(VmwareFolderTemplate, self).__init__(module)
        if not self.is_vcenter():
            self.module.fail_json("Only VCenter clusters are supported for this module.")

        self.template_name = self.params.get("template_name")

        if self.params.get("folder_paths_are_absolute"):
            fq_folder_path = self.params.get("template_folder")
        else:
            fq_folder_path = format_folder_path_as_vm_fq_path(
                self.params.get("template_folder"),
                self.params.get("datacenter")
            )
        self.template_folder = self.get_folder_by_absolute_path(fq_folder_path, fail_on_missing=True)

    def check_if_template_exists(self):
        """
        Checks if a template with the given name and folder already exists
        """
        templates = self.get_vms_using_params(name_param='template_name', fail_on_missing=False)
        if not templates:
            return False

        for template in templates:
            if not template.parent == self.template_folder:
                continue

            if template.config.template:
                return template
            else:
                self.module.fail_json("A virtual machine already exists with desired template name, %s." % self.template_name)

        return False

    def __get_source_vm(self):
        """
        Uses the UUID, MOID, or name provided to find the source VM for the template. Returns an error if using the name,
        multiple matches are found, and the user did not provide a name_match strategy.
        """
        vms = self.get_vms_using_params(
            name_param='vm_name',
            moid_param='vm_moid',
            uuid_param='vm_uuid',
            name_match_param='vm_name_match',
            use_instance_uuid_param='vm_use_instance_uuid',
            fail_on_missing=True)

        if len(vms) != 1:
            self.module.fail_json("Multiple VMs found during search. Try using the vm_name_match or vm_uuid/vm_moid attributes.")

        vm = vms[0]
        if vm.runtime.powerState != 'poweredOff':
            self.module.fail_json(msg="VM must be in powered off state before creating a template from it.")

        return vm

    def create_template_in_folder(self):
        """
        Clones an existing VM into a new template instance.
        """
        vm = self.__get_source_vm()
        template_location_spec = self.__create_template_location_spec()
        template_spec = vim.vm.CloneSpec(powerOn=False, template=True, location=template_location_spec)
        if self.module.check_mode:
            return

        task = vm.Clone(
            name=self.template_name,
            folder=self.template_folder,
            spec=template_spec
        )

        if self.params.get("wait_for_template"):
            try:
                RunningTaskMonitor(task).wait_for_completion()
            except TaskError as e:
                self.module.fail_json(msg="Cloning task failed with exception: %s" % e)

    def __create_template_location_spec(self):
        template_location_spec = vim.vm.RelocateSpec()
        if self.params.get("datastore"):
            template_location_spec.datastore = self.get_datastore_by_name_or_moid(
                self.params.get("datastore"),
                fail_on_missing=True)

        if self.params.get("resource_pool"):
            template_location_spec.pool = self.get_resource_pool_by_name_or_moid(
                self.params.get("resource_pool"),
                fail_on_missing=True)

        return template_location_spec


def custom_validation(module):
    """
        This validation is too complex to be done with the provided ansible validation
    """
    if module.params.get('state') == 'present':
        if (not module.params.get('vm_name') and
                not module.params.get('vm_uuid') and
                not module.params.get('vm_moid')):
            module.fail_json("One of vm_name, vm_uuid, or vm_moid is required when state is 'present'")


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(), **dict(
                vm_name=dict(type='str', required=False, default=None),
                vm_name_match=dict(type='str', required=False, choices=['first', 'last']),
                vm_uuid=dict(type='str', required=False, default=None),
                vm_use_instance_uuid=dict(type='bool', required=False, default=True),
                vm_moid=dict(type='str', required=False, default=None),
                state=dict(type='str', required=False, default='present', choices=['present', 'absent']),
                template_name=dict(type='str', required=True),
                template_folder=dict(type='str', required=True),
                folder_paths_are_absolute=dict(type='bool', required=False, default=False),
                datacenter=dict(type='str', aliases=['datacenter_name'], required=True),
                datastore=dict(type='str', required=False),
                resource_pool=dict(type='str', required=False),
                wait_for_template=dict(type='bool', required=False, default=True),
            )
        },
        mutually_exclusive=[['vm_name', 'vm_uuid', 'vm_moid']],
        supports_check_mode=True,
    )

    result = dict(
        changed=False,
    )

    custom_validation(module)
    folder_template = VmwareFolderTemplate(module)
    if module.params.get('state') == 'present':
        if not folder_template.check_if_template_exists():
            folder_template.create_template_in_folder()
            result['changed'] = True
    else:
        template = folder_template.check_if_template_exists()
        if template:
            if not module.check_mode:
                template.Destroy_Task()
            result['changed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
