#!/usr/bin/python

# (c) 2019-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_rest_cli
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Run CLI commands on ONTAP through REST api/private/cli/.
  - This module can run as admin or vsdamin and requires HTTP application to be enabled.
  - Access permissions can be customized using ONTAP rest-role.
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap_rest
module: na_ontap_rest_cli
short_description: NetApp ONTAP run any CLI command using REST api/private/cli/
version_added: 2.9.0
options:
  command:
    description:
      - A CLI command.
    required: true
    type: str
  verb:
    description:
      - Define which action to perform with the provided command.
      - Values are mapped to show, create, modify, delete.
      - OPTIONS is useful to know which verbs are supported by the REST API
    choices: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS']
    required: true
    type: str
  params:
    description:
      - a dictionary of parameters to pass into the api call
    type: dict
  body:
    description:
      - a dictionary for info specification
    type: dict
'''

EXAMPLES = """
- name: Run ONTAP REST CLI command
  netapp.ontap.na_ontap_rest_cli:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    command: version
    verb: GET

# The fields key allows returning a subset of parameters for a given object
- name: Run volume show command with a filter to only return volumes matching the provided vserver and policy values.
  netapp.ontap.na_ontap_rest_cli:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    command: volume
    verb: GET
    params:
      vserver: vs0
      policy: default
      fields: vserver,volume,policy
  register: vs0_volumes

- name: Run security login motd modify command
  netapp.ontap.na_ontap_rest_cli:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    command: security/login/motd
    verb: PATCH
    params:
      vserver: ansibleSVM
    body:
      message: test

- name: Set option
  netapp.ontap.na_ontap_rest_cli:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    command: options
    verb: PATCH
    params:
      option_name: lldp.enable
    body:
      option_value: "on"

- name: Run security certificate delete command
  netapp.ontap.na_ontap_rest_cli:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    command: security/certificate
    verb: DELETE
    body:
      vserver: vs1
      common-name: cluster01
      ca: cluster01
      type: server
      serial: 17EBE9D26GGE91B9

- name: Run volume create command
  netapp.ontap.na_ontap_rest_cli:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    command: volume
    verb: POST
    body:
      vserver: vs1
      volume: my_test_volume
      size: 10g
      aggregate: aggr1_node1
      policy: default
      type: RW
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI


class NetAppONTAPCommandREST():
    ''' calls a CLI command '''

    def __init__(self):
        self.use_rest = False
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            command=dict(required=True, type='str'),
            verb=dict(required=True, type='str', choices=['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS']),
            params=dict(required=False, type='dict'),
            body=dict(required=False, type='dict')
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.rest_api = OntapRestAPI(self.module)
        parameters = self.module.params
        # set up state variables
        self.command = parameters['command']
        self.verb = parameters['verb']
        self.params = parameters['params']
        self.body = parameters['body']

        if self.rest_api.is_rest():
            self.use_rest = True
        else:
            msg = 'failed to connect to REST over %s: %s' % (parameters['hostname'], self.rest_api.errors)
            msg += '.  Use na_ontap_command for non-rest CLI.'
            self.module.fail_json(msg=msg)

    def run_command(self):
        api = "private/cli/" + self.command

        if self.verb == 'POST':
            message, error = self.rest_api.post(api, self.body, self.params)
        elif self.verb == 'GET':
            message, error = self.rest_api.get(api, self.params)
            if message is not None and isinstance(message, dict) and '_links' in message:
                self.get_all_records(message)
        elif self.verb == 'PATCH':
            message, error = self.rest_api.patch(api, self.body, self.params)
        elif self.verb == 'DELETE':
            message, error = self.rest_api.delete(api, self.body, self.params)
        elif self.verb == 'OPTIONS':
            message, error = self.rest_api.options(api, self.params)
        else:
            self.module.fail_json(msg='Error: unexpected verb %s' % self.verb,
                                  exception=traceback.format_exc())

        if error:
            self.module.fail_json(msg='Error: %s' % error)
        return message

    def get_next_records(self, api):
        """
            Gather next set of ONTAP information for the specified api
            Input for REST APIs call : (api, data)
            return gather_info
        """

        gather_info, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        return gather_info

    def get_all_records(self, message):
        """ Iteratively get all records """

        # If the response contains a next link, we need to gather all records
        while message.get('_links', {}).get('next'):
            next_api = message['_links']['next']['href']
            gathered_info = self.get_next_records(next_api.replace('/api', ''))

            # Update the message with the gathered info
            message['_links'] = gathered_info.get('_links', {})
            message['records'].extend(gathered_info['records'])

        # metrocluster doesn't have a records field, so we need to skip this
        if message.get('records') is not None:
            # Getting total number of records
            message['num_records'] = len(message['records'])

        return message

    def apply(self):
        ''' calls the command and returns raw output '''
        changed = False if self.verb in ['GET', 'OPTIONS'] else True
        if self.module.check_mode and self.verb in ['POST', 'PATCH', 'DELETE']:
            output = "Would run command: '%s'" % str(self.command)
        else:
            output = self.run_command()
        self.module.exit_json(changed=changed, msg=output)


def main():
    """
    Execute action from playbook
    """
    command = NetAppONTAPCommandREST()
    command.apply()


if __name__ == '__main__':
    main()
