#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: guest_info
short_description: Gather guest information
description:
    - This module gathers vm guest information.
author:
    - Ansible Cloud Team (@ansible-collections)
requirements:
    - vSphere Automation SDK
options:
    datacenter:
        description:
            - The datacenter with the VM you would like to query.
            - This is only used if the O(folder) parameter is supplied as a relative path.
        aliases: [datacenter_name]
        type: str
        required: false
    guest_username:
        description:
            - The username to be used to connect to guest vm and fetch environment info.
        type: str
    guest_password:
        description:
            - The password of the user to be used to connect to guest vm and fetch environment info.
        type: str
    name:
        description:
            - The name of the vm to gather info for
            - Only one of name, moid, uuid is allowed
        type: str
        required: False
        aliases: [guest_name]
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
    folder:
        description:
          - Absolute or relative folder path to search for the virtual machine.
          - This parameter is only used if O(name) is supplied, and can help identify the machine you want to query.
          - For example 'datacenter name/vm/path/to/folder' or 'path/to/folder'
        type: str
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
    gather_tags:
        description:
            - If true, gather any tags attached to the vm(s)
        type: bool
        default: false
        required: false
    schema:
        description:
            - The type of info to gather from the vms
        choices: [summary, vsphere]
        default: summary
        type: str
    properties:
        description:
            - If the schema is 'vsphere', gather these specific properties only
        type: list
        elements: str

attributes:
    check_mode:
        description: The check_mode support.
        support: full
extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options
'''

EXAMPLES = r'''
- name: Gather guest vm info
  vmware.vmware.guest_info:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    validate_certs: false
    guest_name: "my_vm"
'''

RETURN = r'''
guests:
    description:
        - Information about guest.
    returned: On success
    type: list
    sample: [
        {
          "advanced_settings": {
              "govcsim": "TRUE"
          },
          "annotation": null,
          "current_snapshot": null,
          "customvalues": {},
          "env": {},
          "guest_consolidation_needed": false,
          "guest_question": null,
          "guest_tools_status": "guestToolsNotRunning",
          "guest_tools_version": "0",
          "hw_cluster": null,
          "hw_cores_per_socket": 1,
          "hw_datastores": [
              "LocalDS_0"
          ],
          "hw_esxi_host": "DC0_H0",
          "hw_eth0": {
              "addresstype": "generated",
              "ipaddresses": [],
              "label": "ethernet-0",
              "macaddress": "00:0c:29:36:63:62",
              "macaddress_dash": "00-0c-29-36-63-62",
              "portgroup_key": "dvportgroup-13",
              "portgroup_portkey": null,
              "summary": "DVSwitch: fea97929-4b2d-5972-b146-930c6d0b4014"
          },
          "hw_files": [
              "[LocalDS_0] DC0_H0_VM0/DC0_H0_VM0.vmx",
              "[LocalDS_0] DC0_H0_VM0/DC0_H0_VM0.nvram",
              "[LocalDS_0] DC0_H0_VM0/vmware.log",
              "[LocalDS_0] DC0_H0_VM0/disk1.vmdk"
          ],
          "hw_folder": "DC0/vm",
          "hw_guest_full_name": null,
          "hw_guest_ha_state": null,
          "hw_guest_id": "otherGuest",
          "hw_interfaces": [
              "eth0"
          ],
          "hw_is_template": false,
          "hw_memtotal_mb": 32,
          "hw_name": "DC0_H0_VM0",
          "hw_power_status": "poweredOn",
          "hw_processor_count": 1,
          "hw_product_uuid": "265104de-1472-547c-b873-6dc7883fb6cb",
          "hw_version": "vmx-13",
          "identity": {},
          "instance_uuid": "b4689bed-97f0-5bcd-8a4c-07477cc8f06f",
          "ipv4": null,
          "ipv6": null,
          "module_hw": true,
          "moid": "vm-63",
          "snapshots": [],
          "tags": [],
          "tpm_info": {
              "provider_id": null,
              "tpm_present": null
          },
          "vimref": "vim.VirtualMachine:vm-63",
          "vnc": {}
        }
      ]
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import ModulePyvmomiBase
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import ModuleRestBase
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import rest_compatible_argument_spec
from ansible_collections.vmware.vmware.plugins.module_utils._facts import (
    VmFacts,
    vmware_obj_to_json,
    extract_object_attributes_to_dict
)


class VmwareGuestInfo(ModuleRestBase):
    def __init__(self, module):
        super(VmwareGuestInfo, self).__init__(module)
        self.pyvmomi = ModulePyvmomiBase(module)
        self.vm_svc = self.api_client.vcenter.vm

    def _get_env(self, vm):
        """
        Gets the guest env facts from a vm and returns them as a dict.
        This requires the VM is running, has vmware tools installed, and the user
        provided a username and password to the VM via params
        """
        if not self.params.get('guest_username'):
            return {}

        try:
            return self.vm_svc.guest.Environment.list(
                vm=vm,
                credentials={
                    'type': 'USERNAME_PASSWORD',
                    'user_name': self.params.get('guest_username'),
                    'password': self.params.get('guest_password'),
                    'interactive_session': False
                },
                names=set()
            )
        except Exception:
            return {}

    def _get_identity(self, vm):
        """
        Gets the guest identity facts (guest os name, guest family, etc) about a VM
        """
        guest_svc = self.vm_svc.guest
        try:
            identity = guest_svc.Identity.get(vm=str(vm._GetMoId()))

        except Exception as e:
            return {}

        return extract_object_attributes_to_dict(identity)

    def gather_info_for_guests(self):
        all_guest_info = []
        for guest in self.get_guests():
            guest_info = {}
            if self.params['schema'] == 'summary':
                vm_facts = VmFacts(guest)
                guest_info = vm_facts.all_facts(self.pyvmomi.content)
            else:
                guest_info = vmware_obj_to_json(guest, self.params['properties'])

            guest_info['identity'] = self._get_identity(guest)
            # legacy output
            guest_info.update(guest_info['identity'])

            guest_info['tags'] = self._get_tags(guest)
            guest_info['env'] = self._get_env(guest)

            all_guest_info += [guest_info]

        return all_guest_info

    def get_guests(self):
        """
        Uses the UUID, MOID, or name provided to find the source VM for the template. Returns an error if using the name,
        multiple matches are found, and the user did not provide a name_match strategy.
        """
        if self.params.get('name') or self.params.get('uuid') or self.params.get('moid'):
            vm = self.pyvmomi.get_vms_using_params(fail_on_missing=False)
        else:
            vm = self.pyvmomi.get_all_vms()

        return vm if vm else []

    def _get_tags(self, vm):
        """
        Gets the tags on a VM. Tags are formatted as a list of dictionaries corresponding to each tag
        """
        output = []
        if not self.params.get('gather_tags'):
            return output

        tags = self.get_tags_by_vm_moid(vm._moId)
        for tag in tags:
            output.append(self.format_tag_identity_as_dict(tag))

        return output


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type='str', aliases=['guest_name']),
            name_match=dict(type='str', choices=['first', 'last'], default=None),
            uuid=dict(type='str'),
            use_instance_uuid=dict(type='bool', default=True),
            moid=dict(type='str'),
            datacenter=dict(type='str', required=False, aliases=['datacenter_name']),
            folder=dict(type='str', required=False),
            folder_paths_are_absolute=dict(type='bool', required=False, default=False),

            gather_tags=dict(type='bool', default=False),

            schema=dict(type='str', choices=['summary', 'vsphere'], default='summary'),
            properties=dict(type='list', elements='str'),

            guest_username=dict(type='str', required=False),
            guest_password=dict(type='str', no_log=True, required=False),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=[
            ('guest_username', 'guest_password'),
        ],
        mutually_exclusive=[['name', 'uuid', 'moid']]
    )

    if module.params['schema'] != 'vsphere' and module.params.get('properties'):
        module.fail_json(msg="The option 'properties' is only valid when the schema is 'vsphere'")

    vmware_appliance_mgr = VmwareGuestInfo(module)
    guests = vmware_appliance_mgr.gather_info_for_guests()
    module.exit_json(changed=False, guests=guests)


if __name__ == '__main__':
    main()
