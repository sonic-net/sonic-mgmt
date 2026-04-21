#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
module: na_ontap_ntp
short_description: NetApp ONTAP NTP server
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create or delete or modify NTP server in ONTAP
options:
  state:
    description:
      - Whether the specified NTP server should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'
  server_name:
    description:
      - The name of the NTP server to manage.
    required: True
    type: str
  version:
    description:
      - give version for NTP server
    choices: ['auto', '3', '4']
    default: 'auto'
    type: str
  key_id:
    description:
      - The symmetric authentication key ID being used for this time server.
    type: int
    version_added: 21.21.0
"""

EXAMPLES = """
- name: Create NTP server
  netapp.ontap.na_ontap_ntp:
    state: present
    version: auto
    key_id: 1
    server_name: "{{ server_name }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete NTP server
  netapp.ontap.na_ontap_ntp:
    state: absent
    server_name: "{{ server_name }}"
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


class NetAppOntapNTPServer:
    """ object initialize and class methods """
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            server_name=dict(required=True, type='str'),
            version=dict(required=False, type='str', default='auto',
                         choices=['auto', '3', '4']),
            key_id=dict(required=False, type='int'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        if self.use_rest and not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 7):
            msg = 'REST requires ONTAP 9.7 or later for na_ontap_ntp'
            self.use_rest = self.na_helper.fall_back_to_zapi(self.module, msg, self.parameters)
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg="the python NetApp-Lib module is required")
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def get_ntp_server(self):
        """
        Return details about the ntp server
        :param:
            name : Name of the server_name
        :return: Details about the ntp server. None if not found.
        :rtype: dict
        """
        if self.use_rest:
            return self.get_ntp_server_rest()
        ntp_iter = netapp_utils.zapi.NaElement('ntp-server-get-iter')
        ntp_info = netapp_utils.zapi.NaElement('ntp-server-info')
        ntp_info.add_new_child('server-name', self.parameters['server_name'])

        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(ntp_info)

        ntp_iter.add_child_elem(query)
        result = self.server.invoke_successfully(ntp_iter, True)
        return_value = None

        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) == 1:

            ntp_server_name = result.get_child_by_name('attributes-list').\
                get_child_by_name('ntp-server-info').\
                get_child_content('server-name')
            server_version = result.get_child_by_name('attributes-list').\
                get_child_by_name('ntp-server-info').\
                get_child_content('version')
            server_key_id = result.get_child_by_name('attributes-list').\
                get_child_by_name('ntp-server-info').\
                get_child_content('key-id')
            return_value = {
                'server-name': ntp_server_name,
                'version': server_version,
                'key_id': int(server_key_id) if server_key_id is not None else 0,
            }

        return return_value

    def get_ntp_server_rest(self):
        api = 'cluster/ntp/servers'
        options = {'server': self.parameters['server_name'],
                   'fields': 'server,version,key.id'}
        record, error = rest_generic.get_one_record(self.rest_api, api, options)
        if error:
            self.module.fail_json(msg=error)
        if record:
            return {
                'server': self.na_helper.safe_get(record, ['server']),
                'version': self.na_helper.safe_get(record, ['version']),
                'key_id': self.na_helper.safe_get(record, ['key', 'id']),
            }
        return None

    def create_ntp_server(self):
        """
        create ntp server.
        """
        if self.use_rest:
            return self.create_ntp_server_rest()
        ntp_server_create = netapp_utils.zapi.NaElement.create_node_with_children(
            'ntp-server-create', **{'server-name': self.parameters['server_name'],
                                    'version': self.parameters['version']
                                    })
        if self.parameters.get('key_id'):
            ntp_server_create.add_new_child("key-id", str(self.parameters['key_id']))

        try:
            self.server.invoke_successfully(ntp_server_create,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating ntp server %s: %s'
                                  % (self.parameters['server_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def create_ntp_server_rest(self):
        api = 'cluster/ntp/servers'
        params = {
            'server': self.parameters['server_name'],
            'version': self.parameters['version']
        }
        if self.parameters.get('key_id'):
            params['key'] = {'id': self.parameters['key_id']}
        dummy, error = rest_generic.post_async(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg=error)

    def delete_ntp_server(self):
        """
        delete ntp server.
        """
        if self.use_rest:
            return self.delete_ntp_server_rest()
        ntp_server_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'ntp-server-delete', **{'server-name': self.parameters['server_name']})

        try:
            self.server.invoke_successfully(ntp_server_delete,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting ntp server %s: %s'
                                  % (self.parameters['server_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_ntp_server_rest(self):
        dummy, error = rest_generic.delete_async(self.rest_api, 'cluster/ntp/servers', self.parameters['server_name'])
        if error:
            self.module.fail_json(msg=error)

    def modify_ntp_server(self, modify):
        """
        modify the ntp server
        """
        if self.use_rest:
            return self.modify_ntp_server_rest(modify)
        ntp_modify = netapp_utils.zapi.NaElement.create_node_with_children(
            'ntp-server-modify',
            **{'server-name': self.parameters['server_name'], 'version': self.parameters['version']})
        if modify.get('key_id'):
            ntp_modify.add_new_child("key-id", str(self.parameters['key_id']))
        try:
            self.server.invoke_successfully(ntp_modify,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying version for ntp server %s: %s'
                                  % (self.parameters['server_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_ntp_server_rest(self, modify):
        body = {}
        if modify.get('version'):
            body['version'] = modify['version']
        if modify.get('key_id'):
            body['key'] = {'id': modify['key_id']}
        if body:
            dummy, error = rest_generic.patch_async(self.rest_api, 'cluster/ntp/servers', self.parameters['server_name'], body)
            if error:
                self.module.fail_json(msg=error)

    def apply(self):
        """Apply action to ntp-server"""

        modify = None
        current = self.get_ntp_server()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_ntp_server()
            elif cd_action == 'delete':
                self.delete_ntp_server()
            elif modify:
                self.modify_ntp_server(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """ Create object and call apply """
    ntp_obj = NetAppOntapNTPServer()
    ntp_obj.apply()


if __name__ == '__main__':
    main()
