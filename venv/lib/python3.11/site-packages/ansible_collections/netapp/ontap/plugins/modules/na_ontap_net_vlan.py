#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_net_vlan
'''

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_net_vlan
short_description: NetApp ONTAP network VLAN
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create/Modify/Delete network VLAN
- Modify VLAN are supported only with REST
- broadcast_domain, ipspace and enabled keys are supported with REST and is ignored with ZAPI
options:
  state:
    description:
    - Whether the specified network VLAN should exist or not
    choices: ['present', 'absent']
    type: str
    default: present
  parent_interface:
    description:
    - The interface that hosts the VLAN interface.
    required: true
    type: str
  vlanid:
    description:
    - The VLAN id. Ranges from 1 to 4094.
    required: true
    type: int
  node:
    description:
    - Node name of VLAN interface.
    required: true
    type: str
  broadcast_domain:
    description:
    - Specify the broadcast_domain name.
    - Only supported with REST and is ignored with ZAPI.
    - Required with 9.6 and 9.7, but optional with 9.8 or later.
    type: str
    version_added: 21.13.0
  ipspace:
    description:
    - Specify the ipspace for the broadcast domain.
    - Only supported with REST and is ignored with ZAPI.
    - Required with 9.6 and 9.7, but optional with 9.8 or later.
    type: str
    version_added: 21.13.0
  enabled:
    description:
    - Enable/Disable Net vlan.
    - Only supported with REST and is ignored with ZAPI.
    type: bool
    version_added: 21.13.0
notes:
  - The C(interface_name) option has been removed and should be deleted from playbooks
'''

EXAMPLES = """
- name: Create VLAN
  netapp.ontap.na_ontap_net_vlan:
    state: present
    vlanid: 13
    node: "{{ vlan_node }}"
    ipspace: "{{ ipspace_name }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Create and add vlan to broadcast domain - REST
  netapp.ontap.na_ontap_net_vlan:
    state: present
    vlanid: 14
    node: "{{ vlan_node }}"
    parent_interface: "{{ vlan_parent_interface_name }}"
    broadcast_domain: "{{ broadcast_domain_name }}"
    ipspace: "{{ ipspace_name }}"
    enabled: true
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Disable VLAN - REST
  netapp.ontap.na_ontap_net_vlan:
    state: present
    vlanid: 14
    node: "{{ vlan_node }}"
    parent_interface: "{{ vlan_parent_interface_name }}"
    enabled: false
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Delete VLAN
  netapp.ontap.na_ontap_net_vlan:
    state: absent
    vlanid: 14
    node: "{{ vlan_node }}"
    parent_interface: "{{ vlan_parent_interface_name }}"
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
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapVlan:
    """
    Created, and destorys Net Vlans's
    """
    def __init__(self):
        """
        Initializes the NetAppOntapVlan function
        """
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            parent_interface=dict(required=True, type='str'),
            vlanid=dict(required=True, type='int'),
            node=dict(required=True, type='str'),
            broadcast_domain=dict(required=False, type='str'),
            ipspace=dict(required=False, type='str'),
            enabled=dict(required=False, type='bool')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_together=[['broadcast_domain', 'ipspace']],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.parameters['interface_name'] = "%s-%s" % (self.parameters['parent_interface'], self.parameters['vlanid'])

        # Set up Rest API
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if self.use_rest and not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 8, 0):
            if 'broadcast_domain' not in self.parameters and 'ipspace' not in self.parameters and self.parameters['state'] == 'present':
                error_msg = 'broadcast_domain and ipspace are required fields with ONTAP 9.6 and 9.7'
                self.module.fail_json(msg=error_msg)

        if not self.use_rest and ('broadcast_domain' in self.parameters or 'enabled' in self.parameters):
            msg = 'Using ZAPI and ignoring keys - enabled, broadcast_domain and ipspace'
            self.module.warn(msg)
            self.parameters.pop('broadcast_domain', None)
            self.parameters.pop('ipspace', None)
            self.parameters.pop('enabled', None)

        if not self.use_rest:
            if HAS_NETAPP_LIB is False:
                self.module.fail_json(msg="the python NetApp-Lib module is required")
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def invoke_vlan(self, zapi):
        """
        Invoke zapi - add/delete take the same NaElement structure
        """
        vlan_obj = netapp_utils.zapi.NaElement(zapi)
        vlan_info = self.create_vlan_info()
        vlan_obj.add_child_elem(vlan_info)
        try:
            self.server.invoke_successfully(vlan_obj, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            if zapi == 'net-vlan-create':
                action = 'adding'
            elif zapi == 'net-vlan-delete':
                action = 'deleting'
            else:
                action = 'unexpected'
            self.module.fail_json(msg='Error %s Net Vlan %s: %s' % (action, self.parameters['interface_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def create_vlan(self):
        """
        Creates a new vlan
        """
        if self.use_rest:
            api = 'network/ethernet/ports'
            body = {
                'type': 'vlan',
                'node': {'name': self.parameters['node']},
                'vlan': {
                    'base_port': {
                        'name': self.parameters['parent_interface'],
                        'node': {'name': self.parameters['node']}
                    },
                    'tag': self.parameters['vlanid']
                }
            }
            if 'broadcast_domain' in self.parameters:
                body['broadcast_domain'] = {'name': self.parameters['broadcast_domain']}
                body['broadcast_domain']['ipspace'] = {'name': self.parameters['ipspace']}
            if 'enabled' in self.parameters:
                body['enabled'] = self.parameters['enabled']
            dummy, error = rest_generic.post_async(self.rest_api, api, body)
            if error:
                self.module.fail_json(msg=error)
        else:
            self.invoke_vlan('net-vlan-create')

    def delete_vlan(self, current=None):
        """
        Deletes a vland
        """
        if self.use_rest:
            uuid = current['uuid']
            api = 'network/ethernet/ports'
            dummy, error = rest_generic.delete_async(self.rest_api, api, uuid)
            if error:
                self.module.fail_json(msg=error)
        else:
            self.invoke_vlan('net-vlan-delete')

    def get_vlan(self):
        """
        Checks to see if a vlan already exists or not
        :return: Returns dictionary of attributes if the vlan exists, None if it dosn't
        """
        if self.use_rest:
            return self.get_vlan_rest()
        vlan_obj = netapp_utils.zapi.NaElement("net-vlan-get-iter")
        query = {
            'query': {
                'vlan-info': {
                    'interface-name': self.parameters['interface_name'],
                    'node': self.parameters['node']
                }
            }
        }
        vlan_obj.translate_struct(query)
        try:
            result = self.server.invoke_successfully(vlan_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg=to_native(error), exception=traceback.format_exc())
        # This checks desired vlan already exists and returns interface_name and node
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) == 1:
            vlan_info = result.get_child_by_name('attributes-list').get_child_by_name('vlan-info')
            current = {
                'interface_name': vlan_info.get_child_content('interface-name'),
                'node': vlan_info.get_child_content('node')
            }
            return current
        return None

    def get_vlan_rest(self):
        api = 'network/ethernet/ports'
        query = {
            'name': self.parameters['interface_name'],
            'node.name': self.parameters['node'],
        }
        fields = 'name,node,uuid,broadcast_domain,enabled'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg=error)
        if record:
            current = {
                'interface_name': record['name'],
                'node': record['node']['name'],
                'uuid': record['uuid'],
                'enabled': record['enabled']
            }
            if 'broadcast_domain' in record:
                current['broadcast_domain'] = record['broadcast_domain']['name']
                current['ipspace'] = record['broadcast_domain']['ipspace']['name']
            return current
        return None

    def modify_vlan(self, current, modify):
        """
        Modify broadcast domain, ipspace and enable/disable vlan
        """
        uuid = current['uuid']
        api = 'network/ethernet/ports'
        body = {}
        # Requires both broadcast_domain and ipspace in body
        # of PATCH call if any one of it present in modify
        if 'broadcast_domain' in modify or 'ipspace' in modify:
            broadcast_domain = modify['broadcast_domain'] if 'broadcast_domain' in modify else current['broadcast_domain']
            ipspace = modify['ipspace'] if 'ipspace' in modify else current['ipspace']
            body['broadcast_domain'] = {'name': broadcast_domain}
            body['broadcast_domain']['ipspace'] = {'name': ipspace}
        if 'enabled' in modify:
            body['enabled'] = modify['enabled']
        dummy, error = rest_generic.patch_async(self.rest_api, api, uuid, body)
        if error:
            self.module.fail_json(msg=error)

    def create_vlan_info(self):
        """
        Create a vlan_info object to be used in a create/delete
        :return:
        """
        vlan_info = netapp_utils.zapi.NaElement("vlan-info")

        #  set up the vlan_info object:
        vlan_info.add_new_child("parent-interface", self.parameters['parent_interface'])
        vlan_info.add_new_child("vlanid", str(self.parameters['vlanid']))
        vlan_info.add_new_child("node", self.parameters['node'])
        return vlan_info

    def apply(self):
        """
        check the option in the playbook to see what needs to be done
        :return:
        """
        modify = None
        current = self.get_vlan()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if self.use_rest and cd_action is None:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_vlan()
                # enabled key in POST call has no effect
                # applying PATCH if there is change in default value
                if self.use_rest:
                    current = self.get_vlan_rest()
                    modify = self.na_helper.get_modified_attributes(current, self.parameters)
            if cd_action == 'delete':
                self.delete_vlan(current)
            if modify:
                self.modify_vlan(current, modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Creates the NetApp Ontap vlan object, and runs the correct play task.
    """
    vlan_obj = NetAppOntapVlan()
    vlan_obj.apply()


if __name__ == '__main__':
    main()
