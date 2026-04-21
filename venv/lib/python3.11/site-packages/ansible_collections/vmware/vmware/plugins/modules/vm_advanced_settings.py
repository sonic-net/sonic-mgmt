#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vm_advanced_settings
short_description: Manages the advanced settings for a VM
description:
    - Manages the advanced settings for a VM.
    - Changing advanced settings can cause instability for the VM. Be careful when removing or updating existing settings.
author:
    - Ansible Cloud Team (@ansible-collections)

options:
    datacenter:
        description:
            - The name of the datacenter to search for the VM.
            - This is only used if O(folder) is also used.
        type: str
        required: false
        aliases: [datacenter_name]
    state:
        description:
            - Set the state of the advanced settings on the VM.
            - If present, the specified advanced settings are added to the VM if they are missing or the value is incorrect.
            - If absent, the specified advanced settings are removed. If a setting is provided with an empty value,
              then the setting will be removed regardless of the current value on the VM.
        choices: [present, absent]
        default: present
        type: str
    name:
        description:
            - Name of the virtual machine to work with.
            - Virtual machine names in vCenter are not necessarily unique, which may be problematic, see O(name_match).
            - This is required if O(moid) or O(uuid) is not supplied.
        type: str
    name_match:
        description:
            - If multiple virtual machines matching the name, use the first or last found.
        default: first
        choices: [ first, last ]
        type: str
    uuid:
        description:
            - UUID of the instance to manage if known, this is VMware's unique identifier.
            - This is required if O(name) or O(moid) is not supplied.
        type: str
    moid:
        description:
            - Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance.
            - This is required if O(name) or O(uuid) is not supplied.
        type: str
    use_instance_uuid:
        description:
            - Whether to use the VMware instance UUID rather than the BIOS UUID.
        default: false
        type: bool
    folder:
        description:
            - Destination folder, absolute or relative path to find an existing guest.
            - Should be the full folder path, with or without the 'datacenter/vm/' prefix
            - For example 'datacenter_name/vm/path/to/folder' or 'path/to/folder'
        type: str
        required: false
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
    settings:
        description:
            - A dictionary that describes the advanced settings you want to manage.
            - All settings values are converted to strings. The case of the string is taken into consideration when checking for changes.
              For example 'True' != 'TRUE'.
            - When O(state) is present, settings must have a value and cannot be an empty string or None (you can use the string 'None').
        type: dict
        required: true

extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Make Sure The Following Advanced Settings Are Present
  vmware.vmware.vm_advanced_settings:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    validate_certs: false
    name: my-test-vm
    settings:
      one: 1
      two: 2
      three: 3
    state: present

- name: Remove The Following Advanced Settings
  vmware.vmware.vm_advanced_settings:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    validate_certs: false
    name: "{{ vm }}"
    settings:
      one: 1    # remove advanced setting if it has both key == 'one' and value == 1
      two: ""   # remove any advanced setting with the key 'two', regardless of value
    state: absent
'''

RETURN = r'''
vm:
    description:
        - Information about the target VM
    returned: On success
    type: dict
    sample: {
        "vm": {
            "moid": vm-79828,
            "name": test-d9c1-vm
        }
    }

updated_settings:
    description:
        - Information about any settings that were changed. Includes the old value and the new value
    returned: Always
    type: dict
    sample: {
        "updated_settings": {
            "my-setting": {
                "old": "old-value",
                "new": "new-value"
            }
        }
    }

result:
    description:
        - Information about the vCenter task, if something changed
    returned: On change
    type: dict
    sample: {
        "result": {
            "completion_time": "2024-07-29T15:27:37.041577+00:00",
            "entity_name": "test-4ad4-vm_advanced_settings",
            "result": null,
            "error": null,
            "state": "success"
        }
    }
'''

try:
    from pyVmomi import vim
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
from ansible_collections.vmware.vmware.plugins.module_utils._type_utils import (
    convert_vmodl_option_set_to_py_dict,
    convert_py_primitive_to_vmodl_type
)
from ansible_collections.vmware.vmware.plugins.module_utils._vsphere_tasks import (
    RunningTaskMonitor
)


class VmAdvancedSettingsModule(ModulePyvmomiBase):
    def __init__(self, module):
        super().__init__(module)
        self.vm = self.get_vms_using_params(fail_on_missing=True)[0]
        self.current_settings = convert_vmodl_option_set_to_py_dict(self.vm.config.extraConfig)
        self.new_settings = self.current_settings.copy()

    def convert_value_for_vim_option(self, value):
        try:
            return convert_py_primitive_to_vmodl_type(value, truthy_strings_as_bool=False)
        except TypeError:
            return value

    def __get_settings_to_remove(self):
        settings_to_update = {}
        for remove_k, remove_v in self.params['settings'].items():
            if remove_k not in self.current_settings:
                continue

            if str(remove_v) and self.current_settings[remove_k] != str(remove_v):
                continue

            settings_to_update[remove_k] = {'old': self.current_settings[remove_k], 'new': None}
            # empty string causes vmware to drop the setting altogether
            self.new_settings[remove_k] = ''

        return settings_to_update

    def __get_settings_to_add(self):
        settings_to_update = {}
        for add_k, add_v in self.params['settings'].items():
            if add_k in self.current_settings and self.current_settings[add_k] == str(add_v):
                continue

            settings_to_update[add_k] = {'old': self.current_settings.get(add_k, None), 'new': add_v}
            self.new_settings[add_k] = add_v

        return settings_to_update

    def get_settings_changes(self):
        if self.params['state'] == 'present':
            settings_to_update = self.__get_settings_to_add()
        else:
            settings_to_update = self.__get_settings_to_remove()

        return settings_to_update

    def apply_new_settings(self):
        config_spec = vim.vm.ConfigSpec()
        config_spec.extraConfig = []
        for k, v in self.new_settings.items():
            option = vim.option.OptionValue()
            option.key = k
            option.value = self.convert_value_for_vim_option(v)
            config_spec.extraConfig.append(option)

        try:
            task = self.vm.ReconfigVM_Task(config_spec)
            _, task_result = RunningTaskMonitor(task).wait_for_completion()   # pylint: disable=disallowed-name
        except Exception as generic_exc:
            self.module.fail_json(
                msg="Failed to update settings due to exception %s" % to_native(generic_exc),
                settings=self.new_settings
            )

        return task_result


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(), **dict(
                datacenter=dict(type='str', required=False, aliases=['datacenter_name']),
                state=dict(type='str', default='present', choices=['present', 'absent']),
                name=dict(type='str'),
                name_match=dict(type='str', choices=['first', 'last'], default='first'),
                uuid=dict(type='str'),
                moid=dict(type='str'),
                use_instance_uuid=dict(type='bool', default=False),
                folder=dict(type='str', required=False),
                folder_paths_are_absolute=dict(type='bool', required=False, default=False),
                settings=dict(type='dict', required=True),
            )
        },
        supports_check_mode=True,
        mutually_exclusive=[
            ['name', 'uuid', 'moid'],
        ],
        required_one_of=[
            ['name', 'uuid', 'moid']
        ],
    )

    vm_module = VmAdvancedSettingsModule(module)

    result = dict(
        vm=dict(name=vm_module.vm.name, moid=vm_module.vm._GetMoId()),
        changed=False,
        result=dict(),
        removed_settings=dict(),
        updated_settings=dict()
    )

    if module.params['state'] == 'present' and {v for v in module.params['settings'].values() if v == ''}:
        module.fail_json('Settings may not have empty strings as values when state is present.')

    settings_to_update = vm_module.get_settings_changes()
    if settings_to_update:
        result['changed'] = True
        result['updated_settings'] = settings_to_update
        if not module.check_mode:
            result['result'] = vm_module.apply_new_settings()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
