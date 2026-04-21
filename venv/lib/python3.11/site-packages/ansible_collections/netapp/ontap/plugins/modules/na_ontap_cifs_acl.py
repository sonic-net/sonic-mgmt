#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - "Create or destroy or modify cifs-share-access-controls on ONTAP"
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
module: na_ontap_cifs_acl
options:
  permission:
    choices: ['no_access', 'read', 'change', 'full_control']
    type: str
    description:
      - The access rights that the user or group has on the defined CIFS share.
  share_name:
    description:
      - The name of the cifs-share-access-control to manage.
    required: true
    type: str
    aliases: ['share']
  state:
    choices: ['present', 'absent']
    description:
      - Whether the specified CIFS share acl should exist or not.
    default: present
    type: str
  vserver:
    description:
      - Name of the vserver to use.
    required: true
    type: str
  user_or_group:
    description:
      - The user or group name for which the permissions are listed.
    required: true
    type: str
  type:
    description:
      - The type (also known as user-group-type) of the user or group to add to the ACL.
      - Type is required for create, delete and modify unix-user or unix-group to/from the ACL in ZAPI.
    type: str
    choices: [windows, unix_user, unix_group]
    version_added: 21.17.0
short_description: NetApp ONTAP manage cifs-share-access-control

'''

EXAMPLES = """
- name: Create CIFS share ACL
  netapp.ontap.na_ontap_cifs_acl:
    state: present
    share_name: cifsShareName
    user_or_group: Everyone
    permission: read
    vserver: "{{ netapp_vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify CIFS share ACL permission
  netapp.ontap.na_ontap_cifs_acl:
    state: present
    share_name: cifsShareName
    user_or_group: Everyone
    permission: change
    vserver: "{{ netapp_vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete CIFS share ACL
  netapp.ontap.na_ontap_cifs_acl:
    state: absent
    share_name: cifsShareName
    user_or_group: localUser
    permission: read
    vserver: "{{ netapp_vserver }}"
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


class NetAppONTAPCifsAcl:
    """
    Methods to create/delete/modify CIFS share/user access-control
    """

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            share_name=dict(required=True, type='str', aliases=['share']),
            user_or_group=dict(required=True, type='str'),
            permission=dict(required=False, type='str', choices=['no_access', 'read', 'change', 'full_control']),
            type=dict(required=False, type='str', choices=['windows', 'unix_user', 'unix_group']),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ('state', 'present', ['permission'])
            ],
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Set up Rest API
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            if netapp_utils.has_netapp_lib() is False:
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_cifs_acl(self):
        """
        Return details about the cifs-share-access-control
        :param:
            name : Name of the cifs-share-access-control
        :return: Details about the cifs-share-access-control. None if not found.
        :rtype: dict
        """
        cifs_acl_iter = netapp_utils.zapi.NaElement('cifs-share-access-control-get-iter')
        cifs_acl_info = netapp_utils.zapi.NaElement('cifs-share-access-control')
        cifs_acl_info.add_new_child('share', self.parameters['share_name'])
        cifs_acl_info.add_new_child('user-or-group', self.parameters['user_or_group'])
        cifs_acl_info.add_new_child('vserver', self.parameters['vserver'])
        if self.parameters.get('type') is not None:
            cifs_acl_info.add_new_child('user-group-type', self.parameters['type'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(cifs_acl_info)
        cifs_acl_iter.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(cifs_acl_iter, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error getting cifs-share-access-control %s: %s'
                                  % (self.parameters['share_name'], to_native(error)))
        return_value = None
        # check if query returns the expected cifs-share-access-control
        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) == 1:

            cifs_acl = result.get_child_by_name('attributes-list').get_child_by_name('cifs-share-access-control')
            return_value = {
                'share': cifs_acl.get_child_content('share'),
                'user-or-group': cifs_acl.get_child_content('user-or-group'),
                'permission': cifs_acl.get_child_content('permission'),
                'type': cifs_acl.get_child_content('user-group-type'),
            }
        return return_value

    def create_cifs_acl(self):
        """
        Create access control for the given CIFS share/user-group
        """
        options = {
            'share': self.parameters['share_name'],
            'user-or-group': self.parameters['user_or_group'],
            'permission': self.parameters['permission']
        }
        # type is required for unix-user and unix-group
        if self.parameters.get('type') is not None:
            options['user-group-type'] = self.parameters['type']

        cifs_acl_create = netapp_utils.zapi.NaElement.create_node_with_children(
            'cifs-share-access-control-create', **options)
        try:
            self.server.invoke_successfully(cifs_acl_create,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating cifs-share-access-control %s: %s'
                                  % (self.parameters['share_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_cifs_acl(self):
        """
        Delete access control for the given CIFS share/user-group
        """
        options = {
            'share': self.parameters['share_name'],
            'user-or-group': self.parameters['user_or_group']
        }
        # type is required for unix-user and unix-group
        if self.parameters.get('type') is not None:
            options['user-group-type'] = self.parameters['type']
        cifs_acl_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'cifs-share-access-control-delete', **options)
        try:
            self.server.invoke_successfully(cifs_acl_delete,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting cifs-share-access-control %s: %s'
                                  % (self.parameters['share_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_cifs_acl_permission(self):
        """
        Change permission or type for the given CIFS share/user-group
        """
        options = {
            'share': self.parameters['share_name'],
            'user-or-group': self.parameters['user_or_group'],
            'permission': self.parameters['permission']
        }
        # type is required for unix-user and unix-group
        if self.parameters.get('type') is not None:
            options['user-group-type'] = self.parameters['type']

        cifs_acl_modify = netapp_utils.zapi.NaElement.create_node_with_children(
            'cifs-share-access-control-modify', **options)
        try:
            self.server.invoke_successfully(cifs_acl_modify,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying cifs-share-access-control permission %s: %s'
                                  % (self.parameters['share_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def get_modify(self, current):

        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if not modify or ('permission' in modify and len(modify) == 1):
            return modify
        if 'type' in modify:
            self.module.fail_json(msg='Error: changing the type is not supported by ONTAP - current: %s, desired: %s'
                                  % (current['type'], self.parameters['type']))
        self.module.fail_json(msg='Error: only permission can be changed - modify: %s' % modify)

    def get_cifs_share_rest(self):
        """
        get uuid of the svm which has CIFS share with rest API.
        """
        options = {'svm.name': self.parameters.get('vserver'),
                   'name': self.parameters.get('share_name')}
        api = 'protocols/cifs/shares'
        fields = 'svm.uuid,name'
        record, error = rest_generic.get_one_record(self.rest_api, api, options, fields)
        if error:
            self.module.fail_json(msg="Error on fetching cifs shares: %s" % error)
        if record:
            return {'uuid': record['svm']['uuid']}
        self.module.fail_json(msg="Error: the cifs share does not exist: %s" % self.parameters['share_name'])

    def get_cifs_acl_rest(self, svm_uuid):
        """
        get details of the CIFS share acl with rest API.
        """
        if not self.use_rest:
            return self.get_cifs_acl()
        query = {'user_or_group': self.parameters.get('user_or_group')}
        ug_type = self.parameters.get('type')
        if ug_type:
            query['type'] = ug_type
        api = 'protocols/cifs/shares/%s/%s/acls' % (svm_uuid['uuid'], self.parameters.get('share_name'))
        fields = 'svm.uuid,user_or_group,type,permission'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg="Error on fetching cifs shares acl: %s" % error)
        if record:
            return {
                'uuid': record['svm']['uuid'],
                'share': record['share'],
                'user_or_group': record['user_or_group'],
                'type': record['type'],
                'permission': record['permission']
            }
        return None

    def create_cifs_acl_rest(self, svm_uuid):
        """
        create CIFS share acl with rest API.
        """
        if not self.use_rest:
            return self.create_cifs_acl()
        body = {
            'user_or_group': self.parameters.get('user_or_group'),
            'permission': self.parameters.get('permission')
        }
        ug_type = self.parameters.get('type')
        if ug_type:
            body['type'] = ug_type
        api = 'protocols/cifs/shares/%s/%s/acls' % (svm_uuid['uuid'], self.parameters.get('share_name'))
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error is not None:
            self.module.fail_json(msg="Error on creating cifs share acl: %s" % error)

    def delete_cifs_acl_rest(self, current):
        """
        Delete access control for the given CIFS share/user-group with rest API.
        """
        if not self.use_rest:
            return self.delete_cifs_acl()
        body = {'svm.name': self.parameters.get('vserver')}
        api = 'protocols/cifs/shares/%s/%s/acls/%s/%s' % (
            current['uuid'], self.parameters.get('share_name'), self.parameters.get('user_or_group'), current.get('type'))
        dummy, error = rest_generic.delete_async(self.rest_api, api, None, body)
        if error is not None:
            self.module.fail_json(msg="Error on deleting cifs share acl: %s" % error)

    def modify_cifs_acl_permission_rest(self, current):
        """
        Change permission for the given CIFS share/user-group with rest API.
        """
        if not self.use_rest:
            return self.modify_cifs_acl_permission()
        body = {'permission': self.parameters.get('permission')}
        api = 'protocols/cifs/shares/%s/%s/acls/%s/%s' % (
            current['uuid'], self.parameters.get('share_name'), self.parameters.get('user_or_group'), current.get('type'))
        dummy, error = rest_generic.patch_async(self.rest_api, api, None, body)
        if error is not None:
            self.module.fail_json(msg="Error modifying cifs share ACL permission: %s" % error)

    def apply(self):
        """
        Apply action to cifs-share-access-control
        """
        svm_uuid = self.get_cifs_share_rest() if self.use_rest else None
        current = self.get_cifs_acl_rest(svm_uuid)
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.get_modify(current) if cd_action is None and self.parameters['state'] == 'present' else None
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_cifs_acl_rest(svm_uuid)
            if cd_action == 'delete':
                self.delete_cifs_acl_rest(current)
            if modify:
                self.modify_cifs_acl_permission_rest(current)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Execute action from playbook
    """
    cifs_acl = NetAppONTAPCifsAcl()
    cifs_acl.apply()


if __name__ == '__main__':
    main()
