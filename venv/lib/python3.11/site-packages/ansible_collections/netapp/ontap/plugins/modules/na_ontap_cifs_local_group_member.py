#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
module: na_ontap_cifs_local_group_member
short_description: NetApp Ontap - Add or remove CIFS local group member
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '21.2.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Add or remove CIFS local group member
options:
  state:
    description:
      - Whether the specified member should be part of the CIFS local group
    choices: ['present', 'absent']
    default: present
    type: str

  vserver:
    description:
      - Specifies the vserver that owns the CIFS local group
    required: true
    type: str

  group:
    description:
      - Specifies name of the CIFS local group
    required: true
    type: str

  member:
    description:
      - Specifies the name of the member
    required: true
    type: str

notes:
  - Supports check_mode.
  - Supported with ZAPI.
  - Supported with REST starting with ONTAP 9.10.1.
"""

EXAMPLES = """
- name: Add member to CIFS local group
  netapp.ontap.na_ontap_cifs_local_group_member:
    state: present
    vserver: svm1
    group: BUILTIN\\administrators
    member: DOMAIN\\Domain Admins
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    ontapi: "{{ ontap_facts.ontap_version }}"
    https: true
    validate_certs: false

- name: Remove member from CIFS local group
  netapp.ontap.na_ontap_cifs_local_group_member:
    state: absent
    vserver: svm1
    group: BUILTIN\\administrators
    member: DOMAIN\\Domain Admins
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    ontapi: "{{ ontap_facts.ontap_version }}"
    https: true
    validate_certs: false
"""

RETURN = """

"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapCifsLocalGroupMember:
    """
        Add or remove CIFS local group members
    """
    def __init__(self):
        """
            Initialize the Ontap CifsLocalGroupMember class
        """

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            group=dict(required=True, type='str'),
            member=dict(required=True, type='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        # set up variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if self.use_rest and not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 10, 1):
            msg = 'REST requires ONTAP 9.10.1 or later for cifs_local_group_member APIs.'
            self.use_rest = self.na_helper.fall_back_to_zapi(self.module, msg, self.parameters)
        self.svm_uuid = None
        self.sid = None

        if not self.use_rest:
            if netapp_utils.has_netapp_lib() is False:
                self.module.fail_json(msg="the python NetApp-Lib module is required")
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_cifs_local_group_rest(self):
        """
        Retrieves the local group of an SVM.
        """
        api = "protocols/cifs/local-groups"
        query = {
            'name': self.parameters['group'],
            'svm.name': self.parameters['vserver'],
            'fields': 'svm.uuid,sid'
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg="Error on fetching cifs local-group: %s" % error)
        if record:
            self.svm_uuid = self.na_helper.safe_get(record, ['svm', 'uuid'])
            self.sid = self.na_helper.safe_get(record, ['sid'])
        if record is None:
            self.module.fail_json(
                msg='CIFS local group %s does not exist on vserver %s' %
                (self.parameters['group'], self.parameters['vserver'])
            )

    def get_cifs_local_group_member(self):
        """
        Retrieves local users, Active Directory users and
        Active Directory groups which are members of the specified local group and SVM.
        """
        return_value = None

        if self.use_rest:
            self.get_cifs_local_group_rest()
            api = 'protocols/cifs/local-groups/%s/%s/members' % (self.svm_uuid, self.sid)
            query = {
                'name': self.parameters['member'],
                'svm.name': self.parameters['vserver'],
                'fields': 'name',
            }
            record, error = rest_generic.get_one_record(self.rest_api, api, query)
            if error:
                self.module.fail_json(
                    msg='Error getting CIFS local group members for group %s on vserver %s: %s' %
                    (self.parameters['group'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

            if record:
                return {
                    'member': self.na_helper.safe_get(record, ['name'])
                }
            return record

        else:
            group_members_get_iter = netapp_utils.zapi.NaElement('cifs-local-group-members-get-iter')
            group_members_info = netapp_utils.zapi.NaElement('cifs-local-group-members')
            group_members_info.add_new_child('group-name', self.parameters['group'])
            group_members_info.add_new_child('vserver', self.parameters['vserver'])
            group_members_info.add_new_child('member', self.parameters['member'])
            query = netapp_utils.zapi.NaElement('query')
            query.add_child_elem(group_members_info)
            group_members_get_iter.add_child_elem(query)

            try:
                result = self.server.invoke_successfully(group_members_get_iter, True)
                if result.get_child_by_name('attributes-list'):
                    group_member_policy_attributes = result['attributes-list']['cifs-local-group-members']

                    return_value = {
                        'group': group_member_policy_attributes['group-name'],
                        'member': group_member_policy_attributes['member'],
                        'vserver': group_member_policy_attributes['vserver']
                    }

            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error getting CIFS local group members for group %s on vserver %s: %s' %
                    (self.parameters['group'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

            return return_value

    def add_cifs_local_group_member(self):
        """
        Adds a member to a CIFS local group
        """
        if self.use_rest:
            api = 'protocols/cifs/local-groups/%s/%s/members' % (self.svm_uuid, self.sid)
            body = {'name': self.parameters['member']}
            dummy, error = rest_generic.post_async(self.rest_api, api, body)
            if error:
                self.module.fail_json(
                    msg='Error adding member %s to cifs local group %s on vserver %s: %s' %
                    (self.parameters['member'], self.parameters['group'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

        else:
            group_members_obj = netapp_utils.zapi.NaElement("cifs-local-group-members-add-members")
            group_members_obj.add_new_child("group-name", self.parameters['group'])
            member_names = netapp_utils.zapi.NaElement("member-names")
            member_names.add_new_child('cifs-name', self.parameters['member'])
            group_members_obj.add_child_elem(member_names)

            try:
                self.server.invoke_successfully(group_members_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error adding member %s to cifs local group %s on vserver %s: %s' %
                    (self.parameters['member'], self.parameters['group'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

    def remove_cifs_local_group_member(self):
        """
        Removes a member from a CIFS local group
        """
        if self.use_rest:
            api = 'protocols/cifs/local-groups/%s/%s/members' % (self.svm_uuid, self.sid)
            body = {'name': self.parameters['member']}
            dummy, error = rest_generic.delete_async(self.rest_api, api, None, body)
            if error:
                self.module.fail_json(
                    msg='Error removing member %s from cifs local group %s on vserver %s: %s' %
                    (self.parameters['member'], self.parameters['group'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

        else:
            group_members_obj = netapp_utils.zapi.NaElement("cifs-local-group-members-remove-members")
            group_members_obj.add_new_child("group-name", self.parameters['group'])
            member_names = netapp_utils.zapi.NaElement("member-names")
            member_names.add_new_child('cifs-name', self.parameters['member'])
            group_members_obj.add_child_elem(member_names)

            try:
                self.server.invoke_successfully(group_members_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error removing member %s from cifs local group %s on vserver %s: %s' %
                    (self.parameters['member'], self.parameters['group'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

    def apply(self):
        current = self.get_cifs_local_group_member()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)

        if self.na_helper.changed:
            if not self.module.check_mode:
                if cd_action == 'create':
                    self.add_cifs_local_group_member()
                elif cd_action == 'delete':
                    self.remove_cifs_local_group_member()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action)
        self.module.exit_json(**result)


def main():
    """
    Creates the NetApp Ontap Cifs Local Group Member object and runs the correct play task
    """
    obj = NetAppOntapCifsLocalGroupMember()
    obj.apply()


if __name__ == '__main__':
    main()
