#!/usr/bin/python

# (c) 2021-2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: na_ontap_log_forward
short_description: NetApp ONTAP Log Forward Configuration
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '21.2.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create, delete or modify the log forward configuration
options:
  state:
    description:
    - Whether the log forward configuration should exist or not
    choices: ['present', 'absent']
    default: present
    type: str

  destination:
    description:
    - Destination address that the log messages will be forwarded to. Can be a hostname or IP address.
    required: true
    type: str

  port:
    description:
    - The destination port used to forward the message.
    required: true
    type: int

  facility:
    description:
    - Facility code used to indicate the type of software that generated the message.
    type: str
    choices: ['kern', 'user', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7']

  force:
    description:
    - Skip the Connectivity Test
    type: bool

  protocol:
    description:
    - Log Forwarding Protocol
    choices: ['udp_unencrypted', 'tcp_unencrypted', 'tcp_encrypted']
    type: str

  verify_server:
    description:
    - Verify Destination Server Identity
    type: bool
'''

EXAMPLES = """
- name: Create log forward configuration
  netapp.ontap.na_ontap_log_forward:
    state: present
    destination: 10.11.12.13
    port: 514
    protocol: udp_unencrypted
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Modify log forward configuration
  netapp.ontap.na_ontap_log_forward:
    state: present
    destination: 10.11.12.13
    port: 514
    protocol: tcp_unencrypted
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Delete log forward configuration
  netapp.ontap.na_ontap_log_forward:
    state: absent
    destination: 10.11.12.13
    port: 514
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
"""

RETURN = """
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapLogForward(object):

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(choices=['present', 'absent'], default='present'),
            destination=dict(required=True, type='str'),
            port=dict(required=True, type='int'),
            facility=dict(required=False, type='str', choices=['kern', 'user', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7']),
            force=dict(required=False, type='bool'),
            protocol=dict(required=False, type='str', choices=['udp_unencrypted', 'tcp_unencrypted', 'tcp_encrypted']),
            verify_server=dict(required=False, type='bool')
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            if HAS_NETAPP_LIB is False:
                self.module.fail_json(msg="the python NetApp-Lib module is required")
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def get_log_forward_config(self):
        """
        gets log forward configuration
        :return: dict of log forward properties if exist, None if not
        """

        if self.use_rest:
            log_forward_config = None
            api = "security/audit/destinations"
            query = {'fields': 'port,protocol,facility,address,verify_server',
                     'address': self.parameters['destination'],
                     'port': self.parameters['port']}

            message, error = self.rest_api.get(api, query)
            if error:
                self.module.fail_json(msg=error)
            if len(message.keys()) == 0:
                return None
            elif 'records' in message and len(message['records']) == 0:
                return None
            elif 'records' not in message:
                error = "Unexpected response in get_security_key_manager from %s: %s" % (api, repr(message))
                self.module.fail_json(msg=error)
            log_forward_config = {
                'destination': message['records'][0]['address'],
                'facility': message['records'][0]['facility'],
                'port': message['records'][0]['port'],
                'protocol': message['records'][0]['protocol'],
                'verify_server': message['records'][0]['verify_server']
            }

            return log_forward_config

        else:
            log_forward_config = None

            log_forward_get = netapp_utils.zapi.NaElement('cluster-log-forward-get')
            log_forward_get.add_new_child('destination', self.parameters['destination'])
            log_forward_get.add_new_child('port', self.na_helper.get_value_for_int(False, self.parameters['port']))

            try:
                result = self.server.invoke_successfully(log_forward_get, True)
            except netapp_utils.zapi.NaApiError as error:
                if to_native(error.code) == "15661":
                    # config doesnt exist
                    return None
                else:
                    self.module.fail_json(
                        msg='Error getting log forward configuration for destination %s on port %s: %s' %
                            (self.parameters['destination'], self.na_helper.get_value_for_int(False, self.parameters['port']), to_native(error)),
                            exception=traceback.format_exc()
                    )

            if result.get_child_by_name('attributes'):
                log_forward_attributes = result.get_child_by_name('attributes')
                cluster_log_forward_info = log_forward_attributes.get_child_by_name('cluster-log-forward-info')
                log_forward_config = {
                    'destination': cluster_log_forward_info.get_child_content('destination'),
                    'facility': cluster_log_forward_info.get_child_content('facility'),
                    'port': self.na_helper.get_value_for_int(True, cluster_log_forward_info.get_child_content('port')),
                    'protocol': cluster_log_forward_info.get_child_content('protocol'),
                    'verify_server': self.na_helper.get_value_for_bool(True, cluster_log_forward_info.get_child_content('verify-server'))
                }

            return log_forward_config

    def create_log_forward_config(self):
        """
        Creates a log forward config
        :return: nothing
        """

        if self.use_rest:
            api = "security/audit/destinations"
            body = dict()
            body['address'] = self.parameters['destination']
            body['port'] = self.parameters['port']

            for attr in ('protocol', 'facility', 'verify_server', 'force'):
                if attr in self.parameters:
                    body[attr] = self.parameters[attr]

            dummy, error = self.rest_api.post(api, body)
            if error:
                self.module.fail_json(msg=error)

        else:
            log_forward_config_obj = netapp_utils.zapi.NaElement('cluster-log-forward-create')
            log_forward_config_obj.add_new_child('destination', self.parameters['destination'])
            log_forward_config_obj.add_new_child('port', self.na_helper.get_value_for_int(False, self.parameters['port']))

            if 'facility' in self.parameters:
                log_forward_config_obj.add_new_child('facility', self.parameters['facility'])

            if 'force' in self.parameters:
                log_forward_config_obj.add_new_child('force', self.na_helper.get_value_for_bool(False, self.parameters['force']))

            if 'protocol' in self.parameters:
                log_forward_config_obj.add_new_child('protocol', self.parameters['protocol'])

            if 'verify_server' in self.parameters:
                log_forward_config_obj.add_new_child('verify-server', self.na_helper.get_value_for_bool(False, self.parameters['verify_server']))

            try:
                self.server.invoke_successfully(log_forward_config_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error creating log forward config with destination %s on port %s: %s' %
                                          (self.parameters['destination'], self.na_helper.get_value_for_int(False, self.parameters['port']), to_native(error)),
                                      exception=traceback.format_exc())

    def modify_log_forward_config(self):
        # need to recreate as protocol can't be changed
        self.destroy_log_forward_config()
        self.create_log_forward_config()

    def destroy_log_forward_config(self):
        """
        Delete a log forward configuration
        :return: nothing
        """
        if self.use_rest:

            api = "security/audit/destinations/%s/%s" % (self.parameters['destination'], self.parameters['port'])
            body = None
            query = {'return_timeout': 3}
            dummy, error = self.rest_api.delete(api, body, query)
            if error:
                self.module.fail_json(msg=error)

        else:
            log_forward_config_obj = netapp_utils.zapi.NaElement('cluster-log-forward-destroy')
            log_forward_config_obj.add_new_child('destination', self.parameters['destination'])
            log_forward_config_obj.add_new_child('port', self.na_helper.get_value_for_int(False, self.parameters['port']))

            try:
                self.server.invoke_successfully(log_forward_config_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error destroying log forward destination %s on port %s: %s' %
                                          (self.parameters['destination'], self.na_helper.get_value_for_int(False, self.parameters['port']), to_native(error)),
                                      exception=traceback.format_exc())

    def apply(self):
        current = self.get_log_forward_config()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = None

        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed:
            if not self.module.check_mode:
                if cd_action == 'create':
                    self.create_log_forward_config()
                elif cd_action == 'delete':
                    self.destroy_log_forward_config()
                elif modify:
                    self.modify_log_forward_config()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Execute action from playbook
    """
    command = NetAppOntapLogForward()
    command.apply()


if __name__ == '__main__':
    main()
