#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''

module: na_ontap_unix_user

short_description: NetApp ONTAP UNIX users
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.8.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
- Create, delete or modify UNIX users local to ONTAP.

options:

  state:
    description:
    - Whether the specified user should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'

  name:
    description:
    - Specifies user's UNIX account name.
    - REST support requires ONTAP version 9.9.0 or later.
    - Non-modifiable.
    required: true
    type: str

  primary_gid:
    description:
    - Specifies the primary group identification number for the UNIX user.
    - REST support requires ONTAP version 9.9.0 or later.
    - Required for create, modifiable.
    aliases: ['group_id']
    type: int
    version_added: 21.21.0

  vserver:
    description:
    - Specifies the Vserver for the UNIX user.
    - REST support requires ONTAP version 9.9.0 or later.
    - Non-modifiable.
    required: true
    type: str

  id:
    description:
    - Specifies an identification number for the UNIX user.
    - REST support requires ONTAP version 9.9.0 or later.
    - Required for create, modifiable.
    type: int

  full_name:
    description:
    - Specifies the full name of the UNIX user
    - REST support requires ONTAP version 9.9.0 or later.
    - Optional for create, modifiable.
    type: str
'''

EXAMPLES = """
- name: Create UNIX User
  netapp.ontap.na_ontap_unix_user:
    state: present
    name: SampleUser
    vserver: ansibleVServer
    group_id: 1
    id: 2
    full_name: Test User
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete UNIX User
  netapp.ontap.na_ontap_unix_user:
    state: absent
    name: SampleUser
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapUnixUser:
    """
    Common operations to manage users and roles.
    """

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            primary_gid=dict(required=False, type='int', aliases=['group_id']),
            id=dict(required=False, type='int'),
            full_name=dict(required=False, type='str'),
            vserver=dict(required=True, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Set up Rest API
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if self.use_rest and not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9, 0):
            msg = 'REST requires ONTAP 9.9.0 or later for unix-users APIs.'
            self.use_rest = self.na_helper.fall_back_to_zapi(self.module, msg, self.parameters)

        if not self.use_rest:
            if netapp_utils.has_netapp_lib() is False:
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_unix_user(self):
        """
        Checks if the UNIX user exists.

        :return:
            dict() if user found
            None if user is not found
        """
        get_unix_user = netapp_utils.zapi.NaElement('name-mapping-unix-user-get-iter')
        attributes = {
            'query': {
                'unix-user-info': {
                    'user-name': self.parameters['name'],
                    'vserver': self.parameters['vserver'],
                }
            }
        }
        get_unix_user.translate_struct(attributes)
        try:
            result = self.server.invoke_successfully(get_unix_user, enable_tunneling=True)
            if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
                user_info = result['attributes-list']['unix-user-info']
                return {'primary_gid': int(user_info['group-id']),
                        'id': int(user_info['user-id']),
                        'full_name': user_info['full-name']}
            return None
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error getting UNIX user %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def create_unix_user(self):
        """
        Creates an UNIX user in the specified Vserver

        :return: None
        """
        if self.parameters.get('primary_gid') is None or self.parameters.get('id') is None:
            self.module.fail_json(msg='Error: Missing one or more required parameters for create: (primary_gid, id)')

        user_create = netapp_utils.zapi.NaElement.create_node_with_children(
            'name-mapping-unix-user-create', **{'user-name': self.parameters['name'],
                                                'group-id': str(self.parameters['primary_gid']),
                                                'user-id': str(self.parameters['id'])})
        if self.parameters.get('full_name') is not None:
            user_create.add_new_child('full-name', self.parameters['full_name'])

        try:
            self.server.invoke_successfully(user_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating UNIX user %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_unix_user(self):
        """
        Deletes an UNIX user from a vserver

        :return: None
        """
        user_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'name-mapping-unix-user-destroy', **{'user-name': self.parameters['name']})

        try:
            self.server.invoke_successfully(user_delete, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error removing UNIX user %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_unix_user(self, params):
        user_modify = netapp_utils.zapi.NaElement.create_node_with_children(
            'name-mapping-unix-user-modify', **{'user-name': self.parameters['name']})
        for key in params:
            if key == 'primary_gid':
                user_modify.add_new_child('group-id', str(params['primary_gid']))
            if key == 'id':
                user_modify.add_new_child('user-id', str(params['id']))
            if key == 'full_name':
                user_modify.add_new_child('full-name', params['full_name'])

        try:
            self.server.invoke_successfully(user_modify, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying UNIX user %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def get_unix_user_rest(self):
        """
        Retrieves UNIX user information for the specified user and SVM with rest API.
        """
        if not self.use_rest:
            return self.get_unix_user()
        query = {'svm.name': self.parameters.get('vserver'),
                 'name': self.parameters.get('name')}
        api = 'name-services/unix-users'
        fields = 'svm.uuid,id,primary_gid,name,full_name'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg="Error on getting unix-user info: %s" % error)
        if record:
            return {
                'svm': {'uuid': self.na_helper.safe_get(record, ['svm', 'uuid'])},
                'name': self.na_helper.safe_get(record, ['name']),
                'full_name': self.na_helper.safe_get(record, ['full_name']),
                'id': self.na_helper.safe_get(record, ['id']),
                'primary_gid': self.na_helper.safe_get(record, ['primary_gid']),
            }
        return None

    def create_unix_user_rest(self):
        """
        Creates the local UNIX user configuration for an SVM with rest API.
        """
        if not self.use_rest:
            return self.create_unix_user()

        body = {'svm.name': self.parameters.get('vserver')}
        for key in ('name', 'full_name', 'id', 'primary_gid'):
            if key in self.parameters:
                body[key] = self.parameters.get(key)
        api = 'name-services/unix-users'
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error is not None:
            self.module.fail_json(msg="Error on creating unix-user: %s" % error)

    def delete_unix_user_rest(self, current):
        """
        Deletes a UNIX user configuration for the specified SVM with rest API.
        """
        if not self.use_rest:
            return self.delete_unix_user()

        api = 'name-services/unix-users/%s' % current['svm']['uuid']
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.parameters['name'])
        if error is not None:
            self.module.fail_json(msg="Error on deleting unix-user: %s" % error)

    def modify_unix_user_rest(self, modify, current=None):
        """
        Updates UNIX user information for the specified user and SVM with rest API.
        """
        if not self.use_rest:
            return self.modify_unix_user(modify)

        query = {'svm.name': self.parameters.get('vserver')}
        body = {}
        for key in ('full_name', 'id', 'primary_gid'):
            if key in modify:
                body[key] = modify[key]
        api = 'name-services/unix-users/%s' % current['svm']['uuid']
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.parameters['name'], body, query)
        if error is not None:
            self.module.fail_json(msg="Error on modifying unix-user: %s" % error)

    def apply(self):
        """
        Invoke appropriate action based on playbook parameters

        :return: None
        """
        cd_action = None
        current = self.get_unix_user_rest()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.na_helper.get_modified_attributes(current, self.parameters) if cd_action is None else None
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_unix_user_rest()
            elif cd_action == 'delete':
                self.delete_unix_user_rest(current)
            else:
                self.modify_unix_user_rest(modify, current)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    obj = NetAppOntapUnixUser()
    obj.apply()


if __name__ == '__main__':
    main()
