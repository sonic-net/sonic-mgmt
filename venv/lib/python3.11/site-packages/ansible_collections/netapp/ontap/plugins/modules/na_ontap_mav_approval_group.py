#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_mav_approval_group
short_description: NetApp ONTAP multi-admin verification (MAV) approval group
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 23.0.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/modify/delete multi-admin verification (MAV) approval group.
options:
  state:
    description:
      - Specifies whether to create/modify or delete the specified approval group.
    choices: ['present', 'absent']
    type: str
    default: present

  name:
    description:
      - Specifies the name of an approval group.
    required: true
    type: str

  email:
    description:
      - Specifies the list of email addresses that are notified when a request is created, approved, vetoed, or executed.
    type: list
    elements: str

  approvers:
    description:
      - Specifies the list of ONTAP users that are part of the approval group.
    type: list
    elements: str

notes:
  - Only supported with REST and requires ONTAP 9.11.1 or later.
"""

EXAMPLES = """
- name: Create an approval group
  netapp.ontap.na_ontap_mav_approval_group:
    state: present
    name: group1
    email: ["group1@netapp.com"]
    approvers: ["admin1", "admin2"]
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Update an approval group
  netapp.ontap.na_ontap_mav_approval_group:
    state: present
    name: group1
    approvers: ["admin1", "admin3"]
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Delete an approval group
  netapp.ontap.na_ontap_mav_approval_group:
    state: absent
    name: group1
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always
"""

RETURN = """

"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapMAVApprovalGroup:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            email=dict(required=False, type='list', elements='str'),
            approvers=dict(required=False, type='list', elements='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ('state', 'present', ['approvers']),
            ],
            supports_check_mode=True
        )

        self.owner_uuid = None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_mav_approval_group:', 9, 11, 1)

    def get_approval_group(self):
        """ Retrieves multi-admin-verify approval group """
        api = 'security/multi-admin-verify/approval-groups'
        fields = 'name,email,approvers,owner.uuid'
        params = {
            'name': self.parameters['name'],
            'fields': fields
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg="Error fetching multi-admin-verify approval group named %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            self.owner_uuid = self.na_helper.safe_get(record, ['owner', 'uuid'])
            return {
                'name': record.get('name'),
                'email': record.get('email'),
                'approvers': record.get('approvers')
            }
        return None

    def create_approval_group(self):
        """ Create a multi-admin-verify approval group """
        api = 'security/multi-admin-verify/approval-groups'
        body = {
            'name': self.parameters['name'],
            'approvers': self.parameters['approvers']
        }
        if 'email' in self.parameters:
            body['email'] = self.parameters['email']
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg="Error creating multi-admin-verify approval group %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_approval_group(self, modify):
        """ Updates a multi-admin-verify approval group """
        api = 'security/multi-admin-verify/approval-groups'
        uuids = '%s/%s' % (self.owner_uuid, self.parameters['name'])
        dummy, error = rest_generic.patch_async(self.rest_api, api, uuids, modify)
        if error:
            self.module.fail_json(msg="Error modifying multi-admin-verify approval group %s: %s." % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_approval_group(self):
        """ Deletes a multi-admin-verify approval group """
        api = 'security/multi-admin-verify/approval-groups'
        uuids = '%s/%s' % (self.owner_uuid, self.parameters['name'])
        dummy, error = rest_generic.delete_async(self.rest_api, api, uuid=uuids)
        if error:
            self.module.fail_json(msg="Error deleting multi-admin-verify approval group %s: %s." % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        current = self.get_approval_group()
        modify = None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_approval_group()
            elif cd_action == 'delete':
                self.delete_approval_group()
            elif modify:
                self.modify_approval_group(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    approval_group = NetAppOntapMAVApprovalGroup()
    approval_group.apply()


if __name__ == '__main__':
    main()
