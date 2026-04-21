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
module: content_template
short_description: Manage template in content library from virtual machine.
description:
    - Module to manage template in content library from virtual machine.
    - Content Library feature is introduced in vSphere 6.0 version.
    - This module does not work with vSphere version older than 67U2.
author:
    - Ansible Cloud Team (@ansible-collections)
requirements:
    - vSphere Automation SDK
options:
    vm_name:
        description:
            - The name of the VM to be used to create template.
            - Virtual machine names in vCenter are not necessarily unique, which may be problematic, see O(vm_name_match).
            - This is required if O(vm_moid) or O(vm_uuid) is not supplied.
            - A VM identifier is required when O(state) is present.
        type: str
    vm_name_match:
        description:
            - If multiple virtual machines matching the name, use the first or last found.
        default: first
        choices: [ first, last ]
        type: str
    vm_uuid:
        description:
            - UUID of the instance to manage if known, this is VMware's unique identifier.
            - This is required if O(vm_moid) or O(vm_name) is not supplied.
            - A VM identifier is required when O(state) is present.
        type: str
    vm_moid:
        description:
            - Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance.
            - This is required if O(vm_name) or O(vm_uuid) is not supplied.
            - A VM identifier is required when O(state) is present.
        type: str
    use_instance_uuid:
        description:
            - Whether to use the VMware instance UUID rather than the BIOS UUID when searching for the VM.
        default: false
        type: bool
    vm_folder:
        description:
            - Destination folder, absolute or relative path to find an existing guest.
            - Should be the full folder path, with or without the 'datacenter/vm/' prefix
            - For example 'datacenter_name/vm/path/to/folder' or 'path/to/folder'
        type: str
        required: false
    template_folder:
        description:
        - Virtual machine folder into which the virtual machine template should be placed.
        - This attribute was added in vSphere API 6.8.
        - If not specified, the virtual machine template will be placed in the same
          folder as the source virtual machine.
        type: str
        aliases: [template_folder]
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
            - The name of template to manage.
        type: str
        required: true
        aliases: [template]
    library:
        description:
            - The name of the content library where the template will be created.
        type: str
        required: true
    host:
        description:
            - Host onto which the virtual machine template should be placed.
            - If O(host) and O(resource_pool) are both specified, O(resource_pool)
              must belong to O(host).
            - If O(host) and O(cluster) are both specified, O(host) must be a member of O(cluster).
            - This attribute was added in vSphere API 6.8.
        type: str
    resource_pool:
        description:
            - Resource pool into which the virtual machine template should be placed.
            - This attribute was added in vSphere API 6.8.
            - If not specified, the system will attempt to choose a suitable resource pool
              for the virtual machine template; if a resource pool cannot be
              chosen, the library item creation operation will fail.
            - If O(cluster) and O(resource_pool) are both specified, O(resource_pool) must belong
              to O(cluster).
            - If O(host) and O(resource_pool) are both specified, O(resource_pool)
              must belong to O(host).
        type: str
    cluster:
        description:
            - Cluster onto which the virtual machine template should be placed.
            - If O(cluster) and O(resource_pool) are both specified, O(resource_pool) must belong
              to O(cluster).
            - If O(cluster) and O(host) are both specified, O(host) must be a member of O(cluster).
            - This attribute was added in vSphere API 6.8.
        type: str
        aliases: [cluster_name]
    datacenter:
        description:
            - The name of the datacenter to use when searching for the source VM.
            - This parameter is optional, and only used if you use a relative O(vm_folder) path.
        type: str
        required: false
        aliases: [datacenter_name]
    state:
        description:
            - State of the template in content library.
            - If C(present), the template will be created in content library.
            - If C(absent), the template will be deleted from content library.
        type: str
        default: present
        choices:
            - present
            - absent
extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options
'''

EXAMPLES = r'''
- name: Create template in content library from Virtual Machine
  vmware.vmware.content_template:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    template: mytemplate
    library: mylibrary
    vm_name: myvm
    host: myhost
'''

RETURN = r'''
template_info:
  description: Template creation message and template_id
  returned: on success
  type: dict
  sample: {
        "msg": "Template 'mytemplate'.",
        "template_id": "template-1009"
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import ModuleRestBase
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import ModulePyvmomiBase
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import rest_compatible_argument_spec
from ansible.module_utils.common.text.converters import to_native

try:
    from com.vmware.vcenter.vm_template_client import LibraryItems
    from com.vmware.vapi.std.errors_client import Error
except ImportError:
    pass


class VmwareContentTemplate(ModuleRestBase):
    def __init__(self, module):
        """Constructor."""
        super(VmwareContentTemplate, self).__init__(module)

        # Initialize member variables
        self._template_service = self.api_client.vcenter.vm_template.LibraryItems
        self.result = {'changed': False, 'template_info': {}}

        # Get parameters
        self.template_name = self.params.get('template_name')
        self.host = self.params.get('host')
        self.cluster = self.params.get('cluster')
        self.resource_pool = self.params.get('resource_pool')
        self.library_id = self.get_content_library_ids(name=self.params.get('library'), fail_on_missing=True)[0]
        self.template_folder = self.params.get('template_folder')

        if self.params['state'] == 'present':
            pyvmomi = ModulePyvmomiBase(module)
            self.vm = pyvmomi.get_vms_using_params(
                name_param='vm_name', uuid_param='vm_uuid', moid_param='vm_moid',
                name_match_param='vm_name_match', folder_param='vm_folder', fail_on_missing=True
            )[0]

    def create_template_from_vm(self):
        _template = self.get_library_item_ids(name=self.template_name, library_id=self.library_id)
        if _template:
            self.result['template_info'] = dict(
                msg="Template '%s' already exists." % self.template_name,
                template_id=_template[0],
            )
            return

        # Create template placement specs
        placement_spec = LibraryItems.CreatePlacementSpec()
        if self.host:
            placement_spec.host = self.get_host_by_name(self.host)
        if self.resource_pool:
            placement_spec.resource_pool = self.get_resource_pool_by_name(self.resource_pool)
        if self.cluster:
            placement_spec.cluster = self.get_cluster_by_name(self.cluster)
        if self.template_folder:
            placement_spec.folder = self.get_folder_by_name(self.template_folder)
        create_spec = LibraryItems.CreateSpec(
            name=self.template_name,
            placement=placement_spec,
            library=self.library_id,
            source_vm=self.vm._GetMoId(),
        )
        template_id = ''
        try:
            template_id = self._template_service.create(create_spec)
        except Error as error:
            self.module.fail_json(msg=' ,'.join([err.default_message % err.args for err in error.messages]))
        except Exception as err:
            self.module.fail_json(msg="%s" % to_native(err))

        if not template_id:
            self.result['template_info'] = dict(
                msg="Template creation failed",
            )
            self.module.fail_json(**self.result)
        self.result['changed'] = True
        self.result['template_info'] = dict(
            msg="Template '%s'." % self.template_name,
            template_id=template_id,
        )

    def delete_template(self):
        _template = self.get_library_item_ids(name=self.template_name, library_id=self.library_id)
        if not _template:
            self.result['template_info'] = dict(
                msg="Template '%s' doesn't exists." % self.template_name,
            )
            return
        template_id = _template[0]

        try:
            self.api_client.content.library.Item.delete(template_id)
        except Exception as err:
            self.module.fail_json(msg="%s" % to_native(err))

        self.result['changed'] = True
        self.result['template_info'] = dict(
            msg="Template '%s' has been deleted." % self.template_name,
            template_id=template_id,
        )


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(
        template_name=dict(type='str', required=True, aliases=['template']),
        vm_name=dict(type='str'),
        vm_name_match=dict(type='str', choices=['first', 'last'], default='first'),
        vm_uuid=dict(type='str'),
        vm_moid=dict(type='str'),
        use_instance_uuid=dict(type='bool', default=False),
        vm_folder=dict(type='str', required=False),
        folder_paths_are_absolute=dict(type='bool', required=False, default=False),
        library=dict(type='str', required=True),
        host=dict(type='str'),
        cluster=dict(type='str', aliases=['cluster_name']),
        datacenter=dict(type='str', required=False, aliases=['datacenter_name']),
        resource_pool=dict(type='str'),
        template_folder=dict(type='str'),
        state=dict(type='str', default='present', choices=['present', 'absent']),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ('state', 'present', ["vm_name", "vm_uuid", "vm_moid"], True),
            ('state', 'present', ["host", "resource_pool", "cluster"], True)
        ],
        mutually_exclusive=[
            ("vm_name", "vm_uuid", "vm_moid")
        ]
    )

    result = {'failed': False, 'changed': False}
    vmware_contentlib = VmwareContentTemplate(module)
    if module.check_mode:
        result.update(
            vm_name=module.params.get('vm_name'),
            changed=True,
            desired_operation='{} template'.format(module.params.get('state')),
        )
        module.exit_json(**result)
    if module.params.get('state') == 'present':
        vmware_contentlib.create_template_from_vm()
    else:
        vmware_contentlib.delete_template()
    module.exit_json(**vmware_contentlib.result)


if __name__ == '__main__':
    main()
