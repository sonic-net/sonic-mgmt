#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_s3_services
short_description: NetApp ONTAP S3 services
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 21.20.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create, delete or modify S3 Service

options:
  state:
    description:
    - Whether the specified S3 bucket should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'

  name:
    description:
    - The name of the S3 service.
    type: str
    required: true

  vserver:
    description:
    - Name of the vserver to use.
    type: str
    required: true

  enabled:
    description:
    - enable or disable the service
    type: bool

  comment:
    description:
    - comment about the service
    type: str

  is_http_enabled:
    description:
    - Specifies whether HTTP is enabled on the S3 server being created or modified
    type: bool
    default: no
    version_added: 22.13.0

  is_https_enabled:
    description:
    - Specifies whether HTTPS is enabled on the S3 server being created or modified
    type: bool
    default: yes
    version_added: 22.13.0

  port:
    description:
    - Specifies the HTTP listener port for the S3 server
    type: int
    default: 80
    version_added: 22.13.0

  secure_port:
    description:
    - Specifies the HTTPS listener port for the S3 server
    type: int
    default: 443
    version_added: 22.13.0

  certificate_name:
    description:
    - name of https certificate to use for the service
    type: str
'''

EXAMPLES = """
- name: Create or modify s3 service
  netapp.ontap.na_ontap_s3_services:
    state: present
    name: carchi-test
    vserver: ansibleSVM
    comment: not enabled
    enabled: false
    certificate_name: ansibleSVM_16E1C1284D889609
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
    use_rest: always

- name: Create or modify s3 service with https
  netapp.ontap.na_ontap_s3_services:
    state: present
    name: carchi-test
    vserver: ansibleSVM
    comment: not enabled
    enabled: true
    is_https_enabled: true
    port: 80
    certificate_name: ansibleSVM_16E1C1284D889609
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
    use_rest: always

- name: Delete s3 service
  netapp.ontap.na_ontap_s3_services:
    state: absent
    name: carchi-test
    vserver: ansibleSVM
    certificate_name: ansibleSVM_16E1C1284D889609
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
    use_rest: always
"""

RETURN = """
s3_service_info:
    description: Returns S3 service response.
    returned: on creation or modification of S3 service
    type: dict
    sample: '{
        "s3_service_info": {
            "name": "Service1",
            "enabled": false,
            "certificate_name": "testSVM_177966509ABA4EC6",
            "users": [{"name": "root"}, {"name": "user1", "access_key": "IWE711019OW02ZB3WH6Q"}],
            "svm": {"name": "testSVM", "uuid": "39c2a5a0-35e2-11ee-b8da-005056b37403"}}
            }
        }'
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapS3Services:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            enabled=dict(required=False, type='bool'),
            vserver=dict(required=True, type='str'),
            comment=dict(required=False, type='str'),
            certificate_name=dict(required=False, type='str'),
            is_http_enabled=dict(type='bool', default=False),
            is_https_enabled=dict(type='bool', default=True),
            port=dict(type='int', default=80),
            secure_port=dict(type='int', default=443)
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
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_s3_services', 9, 8)

    def get_s3_service(self, extra_field=False):
        api = 'protocols/s3/services'
        fields = ','.join(('name',
                           'enabled',
                           'svm.uuid',
                           'comment',
                           'certificate.name',
                           'is_http_enabled',
                           'is_https_enabled',
                           'port',
                           'secure_port'))
        if extra_field:
            fields += ',users'

        params = {
            'svm.name': self.parameters['vserver'],
            'fields': fields
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg='Error fetching S3 service %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            if self.na_helper.safe_get(record, ['certificate', 'name']):
                record['certificate_name'] = self.na_helper.safe_get(record, ['certificate', 'name'])
            return self.set_uuids(record)
        return None

    def create_s3_service(self):
        api = 'protocols/s3/services'
        body = {'svm.name': self.parameters['vserver'], 'name': self.parameters['name']}
        if self.parameters.get('enabled') is not None:
            body['enabled'] = self.parameters['enabled']
        if self.parameters.get('comment'):
            body['comment'] = self.parameters['comment']
        if self.parameters.get('certificate_name'):
            body['certificate.name'] = self.parameters['certificate_name']
        if self.parameters.get('is_http_enabled') is not None:
            body['is_http_enabled'] = self.parameters['is_http_enabled']
        if self.parameters.get('is_https_enabled') is not None:
            body['is_https_enabled'] = self.parameters['is_https_enabled']
        if self.parameters.get('port'):
            body['port'] = self.parameters['port']
        if self.parameters.get('secured_port'):
            body['secured_port'] = self.parameters['secured_port']
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error creating S3 service %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_s3_service(self):
        api = 'protocols/s3/services'
        # The rest default is to delete all users, and empty bucket attached to a service.
        # This would not be idempotent, so switching this to False.
        # second issue, delete_all: True will say it deleted, but the ONTAP system will show it's still there until the job for the
        # delete buckets/users/groups is complete.
        body = {'delete_all': False}
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.svm_uuid, body=body)
        if error:
            self.module.fail_json(msg='Error deleting S3 service %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_s3_service(self, modify):
        # Once the service is created, bucket and user can not be modified by the service api, but only the user/group/bucket modules
        api = 'protocols/s3/services'
        body = {'name': self.parameters['name']}
        if modify.get('enabled') is not None:
            body['enabled'] = self.parameters['enabled']
        if modify.get('comment'):
            body['comment'] = self.parameters['comment']
        if modify.get('certificate_name'):
            body['certificate.name'] = self.parameters['certificate_name']
        if modify.get('is_http_enabled') is not None:
            body['is_http_enabled'] = self.parameters['is_http_enabled']
        if modify.get('is_https_enabled') is not None:
            body['is_https_enabled'] = self.parameters['is_https_enabled']
        if modify.get('port'):
            body['port'] = self.parameters['port']
        if modify.get('secured_port'):
            body['secured_port'] = self.parameters['secured_port']
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.svm_uuid, body)
        if error:
            self.module.fail_json(msg='Error modifying S3 service %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def set_uuids(self, record):
        self.svm_uuid = record['svm']['uuid']
        return record

    def parse_response(self, response):
        if response is not None:
            users_info = []
            options = ['name', 'access_key', 'secret_key']
            for user_info in response.get('users'):
                info = {}
                for option in options:
                    if user_info.get(option) is not None:
                        info[option] = user_info.get(option)
                users_info.append(info)
            return {
                'name': response.get('name'),
                'enabled': response.get('enabled'),
                'certificate_name': response.get('certificate_name'),
                'users': users_info,
                'svm': {'name': self.na_helper.safe_get(response, ['svm', 'name']),
                        'uuid': self.na_helper.safe_get(response, ['svm', 'uuid'])}
            }
        return None

    def apply(self):
        current = self.get_s3_service()
        cd_action, modify, response = None, None, None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_s3_service()
                response = self.get_s3_service(True)
            if cd_action == 'delete':
                self.delete_s3_service()
            if modify:
                self.modify_s3_service(modify)
                response = self.get_s3_service(True)
        message = self.parse_response(response)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify, extra_responses={'s3_service_info': message})
        self.module.exit_json(**result)


def main():
    '''Apply S3 service operations from playbook'''
    obj = NetAppOntapS3Services()
    obj.apply()


if __name__ == '__main__':
    main()
