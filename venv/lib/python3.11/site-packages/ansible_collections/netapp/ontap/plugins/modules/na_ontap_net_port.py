#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

'''
na_ontap_net_port
'''

DOCUMENTATION = """
module: na_ontap_net_port
short_description: NetApp ONTAP network ports.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Modify a ONTAP network port.
options:
  state:
    description:
    - Whether the specified net port should exist or not.
    choices: ['present']
    type: str
    default: present
  node:
    description:
    - Specifies the name of node.
    required: true
    type: str
  ports:
    aliases:
    - port
    description:
    - Specifies the name of port(s).
    required: true
    type: list
    elements: str
  mtu:
    description:
    - Specifies the maximum transmission unit (MTU) reported by the port.
    - Not supported with REST.
    type: int
  autonegotiate_admin:
    description:
    - Enables or disables Ethernet auto-negotiation of speed,
      duplex and flow control.
    - Not supported with REST.
    type: bool
  duplex_admin:
    description:
    - Specifies the user preferred duplex setting of the port.
    - Valid values auto, half, full
    - Not supported with REST.
    type: str
  speed_admin:
    description:
    - Specifies the user preferred speed setting of the port.
    - Not supported with REST.
    type: str
  flowcontrol_admin:
    description:
    - Specifies the user preferred flow control setting of the port.
    - Supported with REST for 9.16.1 and later.
    choices: ['none', 'receive', 'send', 'full', 'pfc']
    type: str
  ipspace:
    description:
    - Specifies the port's associated IPspace name.
    - The 'Cluster' ipspace is reserved for cluster ports.
    - use netapp.ontap.na_ontap_ports to modify ipspace with REST.
    type: str
  up_admin:
    description:
    - Enables or disables the port.
    type: bool
    version_added: 21.8.0
"""

EXAMPLES = """
- name: Modify Net Port
  netapp.ontap.na_ontap_net_port:
    state: present
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    node: "{{ node_name }}"
    ports: e0d,e0c
    autonegotiate_admin: true
    up_admin: true
    mtu: 1500
    flowcontrol_admin: full
    ipspace: test_ipspace
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


class NetAppOntapNetPort:
    """
        Modify a Net port
    """

    def __init__(self):
        """
            Initialize the Ontap Net Port Class
        """
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present'], default='present'),
            node=dict(required=True, type="str"),
            ports=dict(required=True, type='list', elements='str', aliases=['port']),
            mtu=dict(required=False, type="int", default=None),
            autonegotiate_admin=dict(required=False, type="bool", default=None),
            up_admin=dict(required=False, type="bool", default=None),
            duplex_admin=dict(required=False, type="str", default=None),
            speed_admin=dict(required=False, type="str", default=None),
            flowcontrol_admin=dict(required=False, type="str", choices=['none', 'receive', 'send', 'full', 'pfc'], default=None),
            ipspace=dict(required=False, type="str", default=None)
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        # Set up Rest API
        self.rest_api = OntapRestAPI(self.module)
        unsupported_rest_properties = ['mtu', 'autonegotiate_admin', 'duplex_admin', 'speed_admin']
        partially_supported_rest_properties = [['flowcontrol_admin', (9, 16, 1)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties, partially_supported_rest_properties)
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg="the python NetApp-Lib module is required")
            else:
                self.set_playbook_zapi_key_map()
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def set_playbook_zapi_key_map(self):
        self.na_helper.zapi_string_keys = {
            'duplex_admin': 'administrative-duplex',
            'speed_admin': 'administrative-speed',
            'flowcontrol_admin': 'administrative-flowcontrol',
            'ipspace': 'ipspace'
        }
        self.na_helper.zapi_bool_keys = {
            'up_admin': 'is-administrative-up',
            'autonegotiate_admin': 'is-administrative-auto-negotiate',
        }
        self.na_helper.zapi_int_keys = {
            'mtu': 'mtu',
        }

    def get_net_port(self, port):
        """
        Return details about the net port
        :param: port: Name of the port
        :return: Dictionary with current state of the port. None if not found.
        :rtype: dict
        """
        if self.use_rest:
            return self.get_net_port_rest(port)
        net_port_get = netapp_utils.zapi.NaElement('net-port-get-iter')
        attributes = {
            'query': {
                'net-port-info': {
                    'node': self.parameters['node'],
                    'port': port
                }
            }
        }
        net_port_get.translate_struct(attributes)

        try:
            result = self.server.invoke_successfully(net_port_get, True)
            if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
                port_info = result['attributes-list']['net-port-info']
                port_details = dict()
            else:
                return None
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error getting net ports for %s: %s' % (self.parameters['node'], to_native(error)),
                                  exception=traceback.format_exc())

        for item_key, zapi_key in self.na_helper.zapi_bool_keys.items():
            port_details[item_key] = self.na_helper.get_value_for_bool(from_zapi=True, value=port_info.get_child_content(zapi_key))
        for item_key, zapi_key in self.na_helper.zapi_int_keys.items():
            port_details[item_key] = self.na_helper.get_value_for_int(from_zapi=True, value=port_info.get_child_content(zapi_key))
        for item_key, zapi_key in self.na_helper.zapi_string_keys.items():
            port_details[item_key] = port_info.get_child_content(zapi_key)
        return port_details

    def get_net_port_rest(self, port):
        api = 'network/ethernet/ports'
        query = {
            'name': port,
            'node.name': self.parameters['node'],
            'fields': 'name,node,uuid,enabled,broadcast_domain.ipspace.name,'
        }
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 16, 1):
            query['fields'] += 'flowcontrol_admin,'
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg=error)
        if record:
            current = {
                'node': self.na_helper.safe_get(record, ['node', 'name']),
                'uuid': self.na_helper.safe_get(record, ['uuid']),
                'up_admin': self.na_helper.safe_get(record, ['enabled']),
                'flowcontrol_admin': self.na_helper.safe_get(record, ['flowcontrol_admin']),
                'ipspace': self.na_helper.safe_get(record, ['broadcast_domain', 'ipspace', 'name']),
            }
            return current
        return None

    def modify_net_port(self, port, modify):
        """
        Modify a port

        :param port: Name of the port
        :param modify: dict with attributes to be modified
        :return: None
        """
        if self.use_rest:
            return self.modify_net_port_rest(port, modify)

        def get_zapi_key_and_value(key, value):
            zapi_key = self.na_helper.zapi_string_keys.get(key)
            if zapi_key is not None:
                return zapi_key, value
            zapi_key = self.na_helper.zapi_bool_keys.get(key)
            if zapi_key is not None:
                return zapi_key, self.na_helper.get_value_for_bool(from_zapi=False, value=value)
            zapi_key = self.na_helper.zapi_int_keys.get(key)
            if zapi_key is not None:
                return zapi_key, self.na_helper.get_value_for_int(from_zapi=False, value=value)
            raise KeyError(key)

        port_modify = netapp_utils.zapi.NaElement('net-port-modify')
        port_attributes = {'node': self.parameters['node'], 'port': port}
        for key, value in modify.items():
            zapi_key, value = get_zapi_key_and_value(key, value)
            port_attributes[zapi_key] = value
        port_modify.translate_struct(port_attributes)
        try:
            self.server.invoke_successfully(port_modify, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying net ports for %s: %s' % (self.parameters['node'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_net_port_rest(self, uuid, modify):
        """
        Modify broadcast domain, ipspace and enable/disable port
        """
        api = 'network/ethernet/ports'
        body = {}
        if 'up_admin' in modify:
            body['enabled'] = modify['up_admin']
        if 'flowcontrol_admin' in modify:
            body['flowcontrol_admin'] = modify['flowcontrol_admin']
        if 'ipspace' in modify:
            body['broadcast_domain.ipspace.name'] = modify['ipspace']
        dummy, error = rest_generic.patch_async(self.rest_api, api, uuid, body)
        if error:
            self.module.fail_json(msg=error)

    def apply(self):
        """
        Run Module based on play book
        """
        # Run the task for all ports in the list of 'ports'
        missing_ports = list()
        modified = dict()
        for port in self.parameters['ports']:
            current = self.get_net_port(port)
            if current is None:
                missing_ports.append(port)
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            modified[port] = modify
            if modify and not self.module.check_mode:
                port = current['uuid'] if self.use_rest else port
                self.modify_net_port(port, modify)
        if missing_ports:
            plural, suffix = '', '.'
            if len(missing_ports) == len(self.parameters['ports']):
                suffix = ' - check node name.'
            if len(missing_ports) > 1:
                plural = 's'
            self.module.fail_json(changed=self.na_helper.changed, modify=modified,
                                  msg='Error: port%s: %s not found on node: %s%s'
                                  % (plural, ', '.join(missing_ports), self.parameters['node'], suffix))
        result = netapp_utils.generate_result(self.na_helper.changed, modify=modified)
        self.module.exit_json(**result)


def main():
    """
    Create the NetApp Ontap Net Port Object and modify it
    """
    obj = NetAppOntapNetPort()
    obj.apply()


if __name__ == '__main__':
    main()
