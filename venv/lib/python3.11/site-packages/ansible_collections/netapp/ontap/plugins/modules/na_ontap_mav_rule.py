#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_mav_rule
short_description: NetApp ONTAP multi-admin verification (MAV) rule
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 23.0.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/modify/delete multi-admin verification (MAV) rule.
options:
  state:
    description:
      - Specifies whether to create/modify or delete the specified rule.
    choices: ['present', 'absent']
    type: str
    default: present

  operation:
    description:
      - Specifies the command that requires one or more approvals.
    required: true
    type: str

  query:
    description:
      - Specifies the query information which is applied to the subset of objects of ONTAP operation of the rule.
    type: str

  required_approvers:
    description:
      - Specifies the number of required approvers, excluding the user that made the request.
      - The default and minimum number of required approvers is 1.
    type: int

  approval_groups:
    description:
      - Specifies the list of approval groups that are allowed to approve requests for rules that don't have approval groups.
    type: list
    elements: str

  approval_expiry:
    description:
      - Specifies the time, in ISO-8601 duration format, that the approvers have after a new execution request
        is submitted to approve or disapprove the request before the request expires.
      - The default value is one hour (PT1H), the minimum supported value is one second (PT1S),
        and the maximum supported value is 14 days (P14D).
    type: str

  execution_expiry:
    description:
      - Specifies the time, in ISO-8601 duration format, that the authorized users have after a request
        is approved to execute the requested operation before the request expires.
      - The default value is one hour (PT1H), the minimum supported value is one second (PT1S),
        and the maximum supported value is 14 days (P14D).
    type: str

  auto_request_create:
    description:
      - When true, ONTAP automatically creates a request for any failed operation where there is no matching pending request.
      - Defaults to True.
    type: bool

notes:
  - Only supported with REST and requires ONTAP 9.11.1 or later.
  - System rules cannot be deleted or have their query modified.
"""

EXAMPLES = """
- name: Create a rule
  netapp.ontap.na_ontap_mav_rule:
    state: present
    auto_request_create: true
    required_approvers: 1
    approval_groups: ["group1", "group2"]
    approval_expiry: "P14D"
    execution_expiry: "P14D"
    operation: "volume delete"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Update a rule
  netapp.ontap.na_ontap_mav_rule:
    state: present
    query: "-vserver svm1"
    operation: "volume delete"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Delete a rule
  netapp.ontap.na_ontap_mav_rule:
    state: absent
    operation: "volume delete"
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


class NetAppOntapMAVRule:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            operation=dict(required=True, type='str'),
            query=dict(required=False, type='str'),
            required_approvers=dict(required=False, type='int'),
            approval_groups=dict(required=False, type='list', elements='str'),
            approval_expiry=dict(required=False, type='str'),
            execution_expiry=dict(required=False, type='str'),
            auto_request_create=dict(required=False, type='bool')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.owner_uuid = None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_mav_rule:', 9, 11, 1)

    def get_mav_rule(self):
        """ Retrieves multi-admin-verify rule """
        api = 'security/multi-admin-verify/rules'
        params = {
            'operation': self.parameters['operation'],
            'fields': 'owner.uuid,'
                      'query,'
                      'required_approvers,'
                      'approval_groups,'
                      'approval_expiry,'
                      'execution_expiry,'
                      'auto_request_create,'
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg="Error fetching multi-admin-verify rule for %s: %s" % (self.parameters['operation'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            self.owner_uuid = self.na_helper.safe_get(record, ['owner', 'uuid'])
            approval_groups_list = [group['name'] for group in record.get('approval_groups', [])]
            return {
                'query': record.get('query'),
                'required_approvers': record.get('required_approvers'),
                'approval_groups': approval_groups_list,
                'approval_expiry': record.get('approval_expiry'),
                'execution_expiry': record.get('execution_expiry'),
                'auto_request_create': record.get('auto_request_create')
            }
        return None

    def create_mav_rule(self):
        """ Create a multi-admin-verify rule """
        api = 'security/multi-admin-verify/rules'
        body = {
            'operation': self.parameters['operation']
        }
        if 'query' in self.parameters:
            body['query'] = self.parameters['query']
        if 'required_approvers' in self.parameters:
            body['required_approvers'] = self.parameters['required_approvers']
        if 'approval_groups' in self.parameters:
            body['approval_groups'] = self.parameters['approval_groups']
        if 'approval_expiry' in self.parameters:
            body['approval_expiry'] = self.parameters['approval_expiry']
        if 'execution_expiry' in self.parameters:
            body['execution_expiry'] = self.parameters['execution_expiry']
        if 'auto_request_create' in self.parameters:
            body['auto_request_create'] = self.parameters['auto_request_create']
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg="Error creating multi-admin-verify rule for %s: %s" % (self.parameters['operation'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_mav_rule(self, modify):
        """ Updates a multi-admin-verify rule """
        api = 'security/multi-admin-verify/rules'
        query = {'operation': self.parameters['operation'], 'owner.uuid': self.owner_uuid}
        dummy, error = rest_generic.patch_async(self.rest_api, api, uuid_or_name=None, body=modify, query=query)
        if error:
            self.module.fail_json(msg="Error modifying multi-admin-verify rule for %s: %s." % (self.parameters['operation'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_mav_rule(self):
        """ Deletes a multi-admin-verify rule """
        api = 'security/multi-admin-verify/rules'
        query = {'operation': self.parameters['operation'], 'owner.uuid': self.owner_uuid}
        dummy, error = rest_generic.delete_async(self.rest_api, api, uuid=None, query=query)
        if error:
            self.module.fail_json(msg="Error deleting multi-admin-verify rule for %s: %s." % (self.parameters['operation'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        current = self.get_mav_rule()
        modify = None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_mav_rule()
            elif cd_action == 'delete':
                self.delete_mav_rule()
            elif modify:
                self.modify_mav_rule(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    mav_rule = NetAppOntapMAVRule()
    mav_rule.apply()


if __name__ == '__main__':
    main()
