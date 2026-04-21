#!/usr/bin/python

# (c) 2022-2025, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_s3_users
short_description: NetApp ONTAP S3 users
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 21.20.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create, delete, or modify S3 users on NetApp ONTAP.

options:
  state:
    description:
    - Whether the specified S3 user should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'

  name:
    description:
    - The name of the S3 user.
    type: str
    required: true

  vserver:
    description:
    - Name of the vserver to use.
    type: str
    required: true

  comment:
    description:
    - comment about the user
    type: str

  regenerate_keys:
    description:
    - Specifies whether or not to regenerate the user keys.
    type: bool
    version_added: 22.13.0

  delete_keys:
    description:
    - Specifies whether or not to delete the user keys.
    - Requires ONTAP 9.14 or later.
    type: bool
    version_added: 22.13.0

notes:
  - This module is not idempotent when using regenerate_keys.
'''

EXAMPLES = """
- name: Create or modify s3 user
  netapp.ontap.na_ontap_s3_users:
    state: present
    name: carchi8py
    vserver: ansibleSVM
    comment: not enabled
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
    use_rest: always

- name: Delete s3 user
  netapp.ontap.na_ontap_s3_users:
    state: absent
    name: carchi8py
    vserver: ansibleSVM
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
    use_rest: always
"""

RETURN = """
secret_key:
  description: secret_key generated for the user
  returned: on creation of user
  type: str
access_key:
  description: access_key generated for the user
  returned: on creation of user
  type: str
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic
from ansible_collections.netapp.ontap.plugins.module_utils import rest_vserver


class NetAppOntapS3Users:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            comment=dict(required=False, type='str'),
            regenerate_keys=dict(required=False, type='bool'),
            delete_keys=dict(required=False, type='bool')
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.svm_uuid = None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_s3_users', 9, 8)
        dummy, error = self.rest_api.is_rest(partially_supported_rest_properties=[['delete_keys', (9, 14, 1)]],
                                             parameters=self.parameters)
        if error:
            self.module.fail_json(msg=error)

    def get_s3_user(self):
        self.get_svm_uuid()
        api = 'protocols/s3/services/%s/users' % self.svm_uuid
        fields = ','.join(('name',
                           'comment',
                           'access_key'))
        params = {'name': self.parameters['name'],
                  'fields': fields}
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg='Error fetching S3 user %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        return record

    def get_svm_uuid(self):
        record, error = rest_vserver.get_vserver_uuid(self.rest_api, self.parameters['vserver'], self.module, True)
        self.svm_uuid = record

    def create_s3_user(self):
        api = 'protocols/s3/services/%s/users' % self.svm_uuid
        body = {'name': self.parameters['name']}
        if self.parameters.get('comment'):
            body['comment'] = self.parameters['comment']
        response, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error creating S3 user %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if response.get('num_records') == 1:
            return response.get('records')[0]
        self.module.fail_json(msg='Error creating S3 user %s' % self.parameters['name'], exception=traceback.format_exc())

    def delete_s3_user(self):
        api = 'protocols/s3/services/%s/users' % self.svm_uuid
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.parameters['name'])
        if error:
            self.module.fail_json(msg='Error deleting S3 user %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_s3_user(self, modify):
        api = 'protocols/s3/services/%s/users' % self.svm_uuid
        body = {}
        query = {}
        if modify is not None:
            if modify.get('comment'):
                body['comment'] = self.parameters['comment']
        if self.parameters.get('regenerate_keys'):
            query['regenerate_keys'] = self.parameters['regenerate_keys']
        if self.parameters.get('delete_keys'):
            query['delete_keys'] = self.parameters['delete_keys']
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.parameters['name'], body, query)
        if error:
            self.module.fail_json(msg='Error modifying S3 user %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if dummy.get('num_records') == 1:
            return dummy.get('records')[0]

    def parse_response(self, response):
        if response is not None:
            return response.get('secret_key'), response.get('access_key')
        return None, None

    def apply(self):
        current = self.get_s3_user()
        cd_action, modify, response = None, None, None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            if self.parameters.get('regenerate_keys') or self.parameters.get('delete_keys'):
                response = self.modify_s3_user(modify)

                if self.parameters.get('regenerate_keys'):
                    self.na_helper.changed = True
                elif self.parameters.get('delete_keys') and current.get('access_key') is not None:
                    self.na_helper.changed = True
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                response = self.create_s3_user()
            if cd_action == 'delete':
                self.delete_s3_user()
            if modify:
                self.modify_s3_user(modify)
        secret_key, access_key = self.parse_response(response)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify, extra_responses={'secret_key': secret_key,
                                                                                                          'access_key': access_key})
        self.module.exit_json(**result)


def main():
    '''Apply volume operations from playbook'''
    obj = NetAppOntapS3Users()
    obj.apply()


if __name__ == '__main__':
    main()
