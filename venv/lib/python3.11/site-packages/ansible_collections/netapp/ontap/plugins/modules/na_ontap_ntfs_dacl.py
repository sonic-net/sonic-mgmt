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
module: na_ontap_ntfs_dacl
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
short_description: NetApp Ontap create, delete or modify NTFS DACL (discretionary access control list)
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '20.4.0'
description:
- Create, modify, or destroy a NTFS DACL

options:
  state:
    description:
    - Whether the specified NTFS DACL should exist or not.
    choices: ['present', 'absent']
    default: present
    type: str

  vserver:
    description:
    - Specifies the vserver for the NTFS DACL.
    required: true
    type: str

  security_descriptor:
    description:
    - Specifies the NTFS security descriptor.
    required: true
    type: str

  access_type:
    description:
    - Specifies DACL ACE's access type. Possible values.
    choices: ['allow', 'deny']
    required: true
    type: str

  account:
    description:
    - Specifies DACL ACE's SID or domain account name of NTFS security descriptor.
    required: true
    type: str

  rights:
    description:
    - Specifies DACL ACE's access rights. Mutually exclusive with advanced_access_rights.
    choices: ['no_access', 'full_control', 'modify', 'read_and_execute', 'read', 'write']
    type: str

  apply_to:
    description:
    - Specifies apply DACL entry.
    choices: ['this_folder', 'sub_folders', 'files']
    type: list
    elements: str

  advanced_access_rights:
    description:
    - Specifies DACL ACE's Advanced access rights. Mutually exclusive with rights.
    choices: ['read_data', 'write_data', 'append_data', 'read_ea', 'write_ea', 'execute_file', 'delete_child',
    'read_attr', 'write_attr', 'delete', 'read_perm', 'write_perm', 'write_owner', 'full_control']
    type: list
    elements: str

"""

EXAMPLES = """
- name: Add NTFS DACL
  netapp.ontap.na_ontap_ntfs_dacl:
    state: present
    vserver: SVM1
    security_descriptor: ansible_sd
    access_type: allow
    account: DOMAIN\\Account
    rights: modify
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify NTFS DACL
  netapp.ontap.na_ontap_ntfs_dacl:
    state: present
    vserver: SVM1
    security_descriptor: ansible_sd
    access_type: full_control
    account: DOMAIN\\Account
    rights: modify
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Remove NTFS DACL
  netapp.ontap.na_ontap_ntfs_dacl:
    state: absent
    vserver: SVM1
    security_descriptor: ansible_sd
    account: DOMAIN\\Account
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapNtfsDacl(object):
    """
        Creates, Modifies and Destroys an NTFS DACL
    """

    def __init__(self):
        """
            Initialize the Ontap NTFS DACL class
        """

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            security_descriptor=dict(required=True, type='str'),
            access_type=dict(required=True, choices=['allow', 'deny'], type='str'),
            account=dict(required=True, type='str'),
            rights=dict(required=False,
                        choices=['no_access', 'full_control', 'modify', 'read_and_execute', 'read', 'write'],
                        type='str'),
            apply_to=dict(required=False, choices=['this_folder', 'sub_folders', 'files'], type='list', elements='str'),
            advanced_access_rights=dict(required=False,
                                        choices=['read_data', 'write_data', 'append_data', 'read_ea', 'write_ea',
                                                 'execute_file', 'delete_child', 'read_attr', 'write_attr', 'delete',
                                                 'read_perm', 'write_perm', 'write_owner', 'full_control'],
                                        type='list', elements='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
            mutually_exclusive=[('rights', 'advanced_access_rights')],
        )

        # set up variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        if HAS_NETAPP_LIB is False:
            self.module.fail_json(msg='The python NetApp-Lib module is required')
        else:
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_dacl(self):

        dacl_entry = None
        advanced_access_list = None

        dacl_get_iter = netapp_utils.zapi.NaElement('file-directory-security-ntfs-dacl-get-iter')
        dacl_info = netapp_utils.zapi.NaElement('file-directory-security-ntfs-dacl')
        dacl_info.add_new_child('vserver', self.parameters['vserver'])
        dacl_info.add_new_child('ntfs-sd', self.parameters['security_descriptor'])
        dacl_info.add_new_child('access-type', self.parameters['access_type'])
        dacl_info.add_new_child('account', self.parameters['account'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(dacl_info)
        dacl_get_iter.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(dacl_get_iter, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching %s DACL for account %s for security descriptor %s: %s' % (
                self.parameters['access_type'], self.parameters['account'], self.parameters['security_descriptor'],
                to_native(error)), exception=traceback.format_exc())

        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            attributes_list = result.get_child_by_name('attributes-list')

            if attributes_list is None:
                return None

            dacl = attributes_list.get_child_by_name('file-directory-security-ntfs-dacl')

            apply_to_list = []
            apply_to = dacl.get_child_by_name('apply-to')
            for apply_child in apply_to.get_children():
                inheritance_level = apply_child.get_content()

                apply_to_list.append(inheritance_level)

            if dacl.get_child_by_name('advanced-rights'):

                advanced_access_list = []
                advanced_access = dacl.get_child_by_name('advanced-rights')
                for right in advanced_access.get_children():
                    advanced_access_right = right.get_content()
                    advanced_right = {
                        'advanced_access_rights': advanced_access_right
                    }
                    advanced_access_list.append(advanced_right)

            dacl_entry = {
                'access_type': dacl.get_child_content('access-type'),
                'account': dacl.get_child_content('account'),
                'apply_to': apply_to_list,
                'security_descriptor': dacl.get_child_content('ntfs-sd'),
                'readable_access_rights': dacl.get_child_content('readable-access-rights'),
                'vserver': dacl.get_child_content('vserver'),
            }

            if advanced_access_list is not None:
                dacl_entry['advanced_rights'] = advanced_access_list
            else:
                dacl_entry['rights'] = dacl.get_child_content('rights')
        return dacl_entry

    def add_dacl(self):
        """
        Adds a new NTFS DACL to an existing NTFS security descriptor
        """

        dacl_obj = netapp_utils.zapi.NaElement("file-directory-security-ntfs-dacl-add")
        dacl_obj.add_new_child("access-type", self.parameters['access_type'])
        dacl_obj.add_new_child("account", self.parameters['account'])
        dacl_obj.add_new_child("ntfs-sd", self.parameters['security_descriptor'])

        if 'rights' not in self.parameters.keys() and 'advanced_access_rights' not in self.parameters.keys():
            self.module.fail_json(msg='Either rights or advanced_access_rights must be specified.')

        if self.parameters.get('apply_to'):
            apply_to_obj = netapp_utils.zapi.NaElement("apply-to")

            for apply_entry in self.parameters['apply_to']:
                apply_to_obj.add_new_child('inheritance-level', apply_entry)
            dacl_obj.add_child_elem(apply_to_obj)

        if self.parameters.get('advanced_access_rights'):
            access_rights_obj = netapp_utils.zapi.NaElement("advanced-rights")

            for right in self.parameters['advanced_access_rights']:
                access_rights_obj.add_new_child('advanced-access-rights', right)

            dacl_obj.add_child_elem(access_rights_obj)

        if self.parameters.get('rights'):
            dacl_obj.add_new_child("rights", self.parameters['rights'])

        try:
            self.server.invoke_successfully(dacl_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error adding %s DACL for account %s for security descriptor %s: %s' % (
                self.parameters['access_type'], self.parameters['account'], self.parameters['security_descriptor'], to_native(error)),
                exception=traceback.format_exc())

    def remove_dacl(self):
        """
        Deletes a NTFS DACL from an existing NTFS security descriptor
        """
        dacl_obj = netapp_utils.zapi.NaElement("file-directory-security-ntfs-dacl-remove")
        dacl_obj.add_new_child("access-type", self.parameters['access_type'])
        dacl_obj.add_new_child("account", self.parameters['account'])
        dacl_obj.add_new_child("ntfs-sd", self.parameters['security_descriptor'])

        try:
            self.server.invoke_successfully(dacl_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting %s DACL for account %s for security descriptor %s: %s' % (
                self.parameters['access_type'], self.parameters['account'], self.parameters['security_descriptor'], to_native(error)),
                exception=traceback.format_exc())

    def modify_dacl(self):
        """
        Modifies a NTFS DACL on an existing NTFS security descriptor
        """

        dacl_obj = netapp_utils.zapi.NaElement("file-directory-security-ntfs-dacl-modify")
        dacl_obj.add_new_child("access-type", self.parameters['access_type'])
        dacl_obj.add_new_child("account", self.parameters['account'])
        dacl_obj.add_new_child("ntfs-sd", self.parameters['security_descriptor'])

        if self.parameters.get('apply_to'):
            apply_to_obj = netapp_utils.zapi.NaElement("apply-to")

            for apply_entry in self.parameters['apply_to']:
                apply_to_obj.add_new_child('inheritance-level', apply_entry)
            dacl_obj.add_child_elem(apply_to_obj)

        if self.parameters.get('advanced_access_rights'):
            access_rights_obj = netapp_utils.zapi.NaElement("advanced-rights")

            for right in self.parameters['advanced_access_rights']:
                access_rights_obj.add_new_child('advanced-access-rights', right)

            dacl_obj.add_child_elem(access_rights_obj)

        if self.parameters.get('rights'):
            dacl_obj.add_new_child("rights", self.parameters['rights'])

        try:
            self.server.invoke_successfully(dacl_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying %s DACL for account %s for security descriptor %s: %s' % (
                self.parameters['access_type'], self.parameters['account'], self.parameters['security_descriptor'],
                to_native(error)), exception=traceback.format_exc())

    def apply(self):
        current, modify = self.get_dacl(), None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == 'create':
                    self.add_dacl()
                elif cd_action == 'delete':
                    self.remove_dacl()
                elif modify:
                    self.modify_dacl()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Creates the NetApp Ontap NTFS DACL object and runs the correct play task
    """
    obj = NetAppOntapNtfsDacl()
    obj.apply()


if __name__ == '__main__':
    main()
