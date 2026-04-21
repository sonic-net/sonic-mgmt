#!/usr/bin/python

# (c) 2020-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_autosupport_invoke
'''

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'certified'
}

DOCUMENTATION = '''

module: na_ontap_autosupport_invoke
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
short_description: NetApp ONTAP send AutoSupport message
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '20.4.0'
description:
    - Send an AutoSupport message from a node

options:

  name:
    description:
      - The name of the node to send the message to.
      - Not specifying this option invokes AutoSupport on all nodes in the cluster.
    type: str

  autosupport_message:
    description:
      - Text sent in the subject line of the AutoSupport message.
      - message is deprecated and will be removed to avoid a conflict with an Ansible internal variable.
    type: str
    aliases:
      - message
    version_added: 20.8.0

  type:
    description:
      - Type of AutoSupport Collection to Issue.
    choices: ['test', 'performance', 'all']
    default: 'all'
    type: str

  uri:
    description:
      - send the AutoSupport message to the destination you specify instead of the configured destination.
    type: str

'''

EXAMPLES = '''
- name: Send message
  netapp.ontap.na_ontap_autosupport_invoke:
    name: node1
    autosupport_message: invoked test autosupport rest
    uri: http://1.2.3.4/delivery_uri
    type: test
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
'''

RETURN = '''
'''

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppONTAPasupInvoke(object):
    ''' send ASUP message '''
    def __init__(self):
        self.use_rest = False
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            name=dict(required=False, type='str'),
            autosupport_message=dict(required=False, type='str', aliases=["message"]),
            type=dict(required=False, choices=[
                'test', 'performance', 'all'], default='all'),
            uri=dict(required=False, type='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        if 'message' in self.parameters:
            self.module.warn('Error: "message" option conflicts with Ansible internal variable - please use "autosupport_message".')

        # REST API should be used for ONTAP 9.6 or higher.
        self.rest_api = OntapRestAPI(self.module)
        if self.rest_api.is_rest():
            self.use_rest = True
        else:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def get_nodes(self):
        nodes = []
        node_obj = netapp_utils.zapi.NaElement('system-node-get-iter')
        desired_attributes = netapp_utils.zapi.NaElement('desired-attributes')
        node_details_info = netapp_utils.zapi.NaElement('node-details-info')
        node_details_info.add_new_child('node', '')
        desired_attributes.add_child_elem(node_details_info)
        node_obj.add_child_elem(desired_attributes)
        try:
            result = self.server.invoke_successfully(node_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg=to_native(error), exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) > 0:
            node_info = result.get_child_by_name('attributes-list')
            if node_info is not None:
                nodes = [node_details.get_child_content('node') for node_details in node_info.get_children()]
        return nodes

    def send_zapi_message(self, params, node_name):
        params['node-name'] = node_name
        send_message = netapp_utils.zapi.NaElement.create_node_with_children('autosupport-invoke', **params)
        try:
            self.server.invoke_successfully(send_message, enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error on sending autosupport message to node %s: %s."
                                  % (node_name, to_native(error)),
                                  exception=traceback.format_exc())

    def send_message(self):
        params = {}
        if self.parameters.get('autosupport_message'):
            params['message'] = self.parameters['autosupport_message']
        if self.parameters.get('type'):
            params['type'] = self.parameters['type']
        if self.parameters.get('uri'):
            params['uri'] = self.parameters['uri']

        if self.use_rest:
            if self.parameters.get('name'):
                params['node.name'] = self.parameters['name']
                node_name = params['node.name']
            else:
                node_name = '*'
            api = 'support/autosupport/messages'
            dummy, error = self.rest_api.post(api, params)
            if error is not None:
                self.module.fail_json(msg="Error on sending autosupport message to node %s: %s."
                                      % (node_name, error))
        else:
            if self.parameters.get('name'):
                node_names = [self.parameters['name']]
            else:
                # simulate REST behavior by sending to all nodes in the cluster
                node_names = self.get_nodes()
            for name in node_names:
                self.send_zapi_message(params, name)

    def apply(self):
        if not self.module.check_mode:
            self.send_message()
        self.module.exit_json(changed=True)


def main():
    message = NetAppONTAPasupInvoke()
    message.apply()


if __name__ == '__main__':
    main()
