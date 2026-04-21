#!/usr/bin/python

# (c) 2022-2025, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_s3_groups
short_description: NetApp ONTAP S3 groups
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 21.21.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create, delete, or modify S3 groups on NetApp ONTAP.

options:
  state:
    description:
    - Whether the specified S3 group should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'

  name:
    description:
    - The name of the S3 group.
    type: str
    required: true

  vserver:
    description:
    - Name of the vserver to use.
    type: str
    required: true

  comment:
    description:
    - comment about the group
    type: str

  users:
    description: List of users to to add the the group
    type: list
    elements: dict
    suboptions:
      name:
        description: username
        type: str

  policies:
    description: Policies to add the the group
    type: list
    elements: dict
    suboptions:
      name:
        description: policy name
        type: str
'''

EXAMPLES = """
- name: Create and modify a S3 Group
  netapp.ontap.na_ontap_s3_groups:
    state: present
    name: dev-group
    comment: group for devs
    vserver: ansibleSVM
    users:
      - name: carchi8py
      - name: carchi8py2
    policies:
      - name: allow_policy
      - name: deny_policy
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
    use_rest: always

- name: Delete a S3 Group
  netapp.ontap.na_ontap_s3_groups:
    state: absent
    name: dev-group
    vserver: ansibleSVM
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
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
from ansible_collections.netapp.ontap.plugins.module_utils import rest_vserver


class NetAppOntapS3Groups:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            comment=dict(required=False, type='str'),
            users=dict(required=False, type='list', elements='dict', options=dict(
                name=dict(required=False, type='str'))),
            policies=dict(required=False, type='list', elements='dict', options=dict(
                name=dict(required=False, type='str')))))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        self.svm_uuid = None
        self.group_id = None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_s3_groups', 9, 8)

    def get_s3_groups(self):
        self.get_svm_uuid()
        api = 'protocols/s3/services/%s/groups' % self.svm_uuid
        fields = ','.join(('name',
                          'comment',
                           'users.name',
                           'policies.name'))
        params = {'name': self.parameters['name'],
                  'fields': fields}
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg='Error fetching S3 groups %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            self.group_id = record.get('id')
            return self.form_current(record)
        return record

    @staticmethod
    def form_current(record):
        current = {
            'comment': record.get('comment'),
            'users': [],
            'policies': [],
        }
        # the APi Returning _link in each user and policy record which is causing modify to get called
        if record.get('users'):
            for user in record['users']:
                current['users'].append({'name': user['name']})
        if record.get('policies'):
            for policy in record['policies']:
                current['policies'].append({'name': policy['name']})
        return current

    def create_s3_groups(self):
        api = 'protocols/s3/services/%s/groups' % self.svm_uuid
        body = {'name': self.parameters['name'],
                'users': self.parameters['users'],
                'policies': self.parameters['policies']}
        if self.parameters.get('comment'):
            body['comment'] = self.parameters['comment']
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error creating S3 groups %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_s3_groups(self):
        api = 'protocols/s3/services/%s/groups' % self.svm_uuid
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.group_id)
        if error:
            self.module.fail_json(msg='Error deleting S3 group %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_s3_groups(self, modify):
        api = 'protocols/s3/services/%s/groups' % self.svm_uuid
        body = {}
        if modify.get('comment') is not None:
            body['comment'] = self.parameters['comment']
        if modify.get('users') is not None:
            body['users'] = self.parameters['users']
        if modify.get('policies') is not None:
            body['policies'] = self.parameters['policies']
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.group_id, body)
        if error:
            self.module.fail_json(msg='Error modifying S3 group %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def get_svm_uuid(self):
        record, error = rest_vserver.get_vserver_uuid(self.rest_api, self.parameters['vserver'], self.module, True)
        self.svm_uuid = record

    def apply(self):
        current = self.get_s3_groups()
        cd_action, modify = None, None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if cd_action == 'create' and (self.na_helper.safe_get(self.parameters, ['users']) is None
                                      or self.na_helper.safe_get(self.parameters, ['policies']) is None):
            self.module.fail_json(msg='policies and users are required for a creating a group.')
        if modify and (self.na_helper.safe_get(self.parameters, ['users']) is None
                       or self.na_helper.safe_get(self.parameters, ['policies']) is None):
            self.module.fail_json(msg='policies and users can not be empty when modifying a group.')
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_s3_groups()
            if cd_action == 'delete':
                self.delete_s3_groups()
            if modify:
                self.modify_s3_groups(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    obj = NetAppOntapS3Groups()
    obj.apply()


if __name__ == '__main__':
    main()
