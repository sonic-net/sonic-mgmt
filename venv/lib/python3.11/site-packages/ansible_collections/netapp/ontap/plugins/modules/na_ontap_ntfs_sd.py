#!/usr/bin/python

# (c) 2020-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'certified'
}

DOCUMENTATION = """

module: na_ontap_ntfs_sd
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
short_description: NetApp ONTAP create, delete or modify NTFS security descriptor
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '20.4.0'
description:
    - Create, modify or destroy NTFS security descriptor

options:
  state:
    description:
    - Whether the specified NTFS security descriptor should exist or not.
    choices: ['present', 'absent']
    default: present
    type: str

  vserver:
    description:
    - Specifies the vserver for the NTFS security descriptor.
    required: true
    type: str

  name:
    description:
    - Specifies the NTFS security descriptor name. Not modifiable.
    required: true
    type: str

  owner:
    description:
    - Specifies the owner's SID or domain account of the NTFS security descriptor.
    - Need to provide the full path of the owner.
    type: str

  group:
    description:
    - Specifies the group's SID or domain account of the NTFS security descriptor.
    - Need to provide the full path of the group.
    required: false
    type: str

  control_flags_raw:
    description:
    - Specifies the security descriptor control flags.
    - 1... .... .... .... = Self Relative
    - .0.. .... .... .... = RM Control Valid
    - ..0. .... .... .... = SACL Protected
    - ...0 .... .... .... = DACL Protected
    - .... 0... .... .... = SACL Inherited
    - .... .0.. .... .... = DACL Inherited
    - .... ..0. .... .... = SACL Inherit Required
    - .... ...0 .... .... = DACL Inherit Required
    - .... .... ..0. .... = SACL Defaulted
    - .... .... ...0 .... = SACL Present
    - .... .... .... 0... = DACL Defaulted
    - .... .... .... .1.. = DACL Present
    - .... .... .... ..0. = Group Defaulted
    - .... .... .... ...0 = Owner Defaulted
    - At present only the following flags are honored. Others are ignored.
    - ..0. .... .... .... = SACL Protected
    - ...0 .... .... .... = DACL Protected
    - .... .... ..0. .... = SACL Defaulted
    - .... .... .... 0... = DACL Defaulted
    - .... .... .... ..0. = Group Defaulted
    - .... .... .... ...0 = Owner Defaulted
    - Convert the 16 bit binary flags and convert to decimal for the input.
    type: int

"""

EXAMPLES = """
- name: Create NTFS Security Descriptor
  netapp.ontap.na_ontap_ntfs_sd:
    state: present
    vserver: SVM1
    name: ansible_sd
    owner: DOMAIN\\Account
    group: DOMAIN\\Group
    control_flags_raw: 0
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify NTFS Security Descriptor
  netapp.ontap.na_ontap_ntfs_sd:
    state: present
    vserver: SVM1
    name: ansible_sd
    owner: DOMAIN\\Account
    group: DOMAIN\\Group
    control_flags_raw: 0
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete NTFS Security Descriptor
  netapp.ontap.na_ontap_ntfs_sd:
    state: absent
    vserver: SVM1
    name: ansible_sd
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""


import traceback
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapNtfsSd(object):
    """
        Creates, Modifies and Destroys a NTFS security descriptor
    """

    def __init__(self):
        """
            Initialize the Ontap NTFS Security Descriptor class
        """
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            owner=dict(required=False, type='str'),
            group=dict(required=False, type='str'),
            control_flags_raw=dict(required=False, type='int'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        # set up variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        if HAS_NETAPP_LIB is False:
            self.module.fail_json(msg='The python NetApp-Lib module is required')
        else:
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_ntfs_sd(self):

        ntfs_sd_entry, result = None, None

        ntfs_sd_get_iter = netapp_utils.zapi.NaElement('file-directory-security-ntfs-get-iter')
        ntfs_sd_info = netapp_utils.zapi.NaElement('file-directory-security-ntfs')
        ntfs_sd_info.add_new_child('vserver', self.parameters['vserver'])
        ntfs_sd_info.add_new_child('ntfs-sd', self.parameters['name'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(ntfs_sd_info)
        ntfs_sd_get_iter.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(ntfs_sd_get_iter, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching NTFS security descriptor %s : %s'
                                      % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            attributes_list = result.get_child_by_name('attributes-list')
            ntfs_sd = attributes_list.get_child_by_name('file-directory-security-ntfs')
            ntfs_sd_entry = {
                'vserver': ntfs_sd.get_child_content('vserver'),
                'name': ntfs_sd.get_child_content('ntfs-sd'),
                'owner': ntfs_sd.get_child_content('owner'),
                'group': ntfs_sd.get_child_content('group'),
                'control_flags_raw': ntfs_sd.get_child_content('control-flags-raw'),
            }
            if ntfs_sd_entry.get('control_flags_raw'):
                ntfs_sd_entry['control_flags_raw'] = int(ntfs_sd_entry['control_flags_raw'])
            return ntfs_sd_entry
        return None

    def add_ntfs_sd(self):
        """
        Adds a new NTFS security descriptor
        """

        ntfs_sd_obj = netapp_utils.zapi.NaElement("file-directory-security-ntfs-create")
        ntfs_sd_obj.add_new_child("ntfs-sd", self.parameters['name'])

        if self.parameters.get('control_flags_raw') is not None:
            ntfs_sd_obj.add_new_child("control-flags-raw", str(self.parameters['control_flags_raw']))

        if self.parameters.get('owner'):
            ntfs_sd_obj.add_new_child("owner", self.parameters['owner'])

        if self.parameters.get('group'):
            ntfs_sd_obj.add_new_child("group", self.parameters['group'])

        try:
            self.server.invoke_successfully(ntfs_sd_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(
                msg='Error creating NTFS security descriptor %s: %s' % (self.parameters['name'], to_native(error)),
                exception=traceback.format_exc())

    def remove_ntfs_sd(self):
        """
        Deletes a NTFS security descriptor
        """
        ntfs_sd_obj = netapp_utils.zapi.NaElement("file-directory-security-ntfs-delete")
        ntfs_sd_obj.add_new_child("ntfs-sd", self.parameters['name'])
        try:
            self.server.invoke_successfully(ntfs_sd_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting NTFS security descriptor %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_ntfs_sd(self):
        """
        Modifies a NTFS security descriptor
        """

        ntfs_sd_obj = netapp_utils.zapi.NaElement("file-directory-security-ntfs-modify")
        ntfs_sd_obj.add_new_child("ntfs-sd", self.parameters['name'])

        if self.parameters.get('control_flags_raw') is not None:
            ntfs_sd_obj.add_new_child('control-flags-raw', str(self.parameters['control_flags_raw']))

        if self.parameters.get('owner'):
            ntfs_sd_obj.add_new_child('owner', self.parameters['owner'])

        if self.parameters.get('group'):
            ntfs_sd_obj.add_new_child('group', self.parameters['group'])

        try:
            self.server.invoke_successfully(ntfs_sd_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(
                msg='Error modifying NTFS security descriptor %s: %s' % (self.parameters['name'], to_native(error)),
                exception=traceback.format_exc())

    def apply(self):
        current, modify = self.get_ntfs_sd(), None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.add_ntfs_sd()
            elif cd_action == 'delete':
                self.remove_ntfs_sd()
            elif modify:
                self.modify_ntfs_sd()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Creates, deletes and modifies NTFS secudity descriptor
    """
    obj = NetAppOntapNtfsSd()
    obj.apply()


if __name__ == '__main__':
    main()
