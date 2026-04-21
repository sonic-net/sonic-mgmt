#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_firewall_policy
short_description: NetApp ONTAP Manage a firewall policy
version_added: 2.7.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Configure firewall on an ONTAP node and manage firewall policy for an ONTAP SVM
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap_zapi
requirements:
  - Python package ipaddress. Install using 'pip install ipaddress'
options:
  state:
    description:
      - Whether to set up a firewall policy or not
    choices: ['present', 'absent']
    type: str
    default: present
  allow_list:
    description:
      - A list of IPs and masks to use.
      - The host bits of the IP addresses used in this list must be set to 0.
    type: list
    elements: str
  policy:
    description:
      - A policy name for the firewall policy
    type: str
  service:
    description:
      - The service to apply the policy to
      - https and ssh are not supported starting with ONTAP 9.6
      - portmap is supported for ONTAP 9.4, 9.5 and 9.6
      - none is supported for ONTAP 9.8 onwards.
    choices: ['dns', 'http', 'https', 'ndmp', 'ndmps', 'ntp', 'portmap', 'rsh', 'snmp', 'ssh', 'telnet', 'none']
    type: str
  vserver:
    description:
      - The Vserver to apply the policy to.
    type: str
  enable:
    description:
      - enable firewall on a node
    choices: ['enable', 'disable']
    type: str
  logging:
    description:
      - enable logging for firewall on a node
    choices: ['enable', 'disable']
    type: str
  node:
    description:
      - The node to run the firewall configuration on
    type: str
'''

EXAMPLES = """
- name: Create firewall Policy
  netapp.ontap.na_ontap_firewall_policy:
    state: present
    allow_list: [1.2.3.0/24, 1.3.0.0/16]
    policy: pizza
    service: http
    vserver: ci_dev
    hostname: "{{ netapp hostname }}"
    username: "{{ netapp username }}"
    password: "{{ netapp password }}"

- name: Modify firewall Policy
  netapp.ontap.na_ontap_firewall_policy:
    state: present
    allow_list: [1.5.3.0/24]
    policy: pizza
    service: http
    vserver: ci_dev
    hostname: "{{ netapp hostname }}"
    username: "{{ netapp username }}"
    password: "{{ netapp password }}"

- name: Destory firewall Policy
  netapp.ontap.na_ontap_firewall_policy:
    state: absent
    policy: pizza
    service: http
    vserver: ci_dev
    hostname: "{{ netapp hostname }}"
    username: "{{ netapp username }}"
    password: "{{ netapp password }}"

- name: Enable firewall and logging on a node
  netapp.ontap.na_ontap_firewall_policy:
    node: test-vsim1
    enable: enable
    logging: enable
    hostname: "{{ netapp hostname }}"
    username: "{{ netapp username }}"
    password: "{{ netapp password }}"
"""

RETURN = """
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import netapp_ipaddress


class NetAppONTAPFirewallPolicy:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_zapi_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            allow_list=dict(required=False, type='list', elements='str'),
            policy=dict(required=False, type='str'),
            service=dict(required=False, type='str', choices=['dns', 'http', 'https', 'ndmp', 'ndmps',
                                                              'ntp', 'portmap', 'rsh', 'snmp', 'ssh', 'telnet', 'none']),
            vserver=dict(required=False, type="str"),
            enable=dict(required=False, type="str", choices=['enable', 'disable']),
            logging=dict(required=False, type="str", choices=['enable', 'disable']),
            node=dict(required=False, type="str")
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_together=(['policy', 'service', 'vserver'],
                               ['enable', 'node']
                               ),
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.module.warn('The module only supports ZAPI; refer to netapp.ontap.na_ontap_service_policy module for RESTful equivalent.')
        if not netapp_utils.has_netapp_lib():
            self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
        self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def validate_ip_addresses(self):
        '''
            Validate if the given IP address is a network address (i.e. it's host bits are set to 0)
            ONTAP doesn't validate if the host bits are set,
            and hence doesn't add a new address unless the IP is from a different network.
            So this validation allows the module to be idempotent.
            :return: None
        '''
        for ip in self.parameters['allow_list']:
            netapp_ipaddress.validate_ip_address_is_network_address(ip, self.module)

    def get_firewall_policy(self):
        """
        Get a firewall policy
        :return: returns a firewall policy object, or returns False if there are none
        """
        net_firewall_policy_obj = netapp_utils.zapi.NaElement("net-firewall-policy-get-iter")
        attributes = {
            'query': {
                'net-firewall-policy-info': self.firewall_policy_attributes()
            }
        }
        net_firewall_policy_obj.translate_struct(attributes)

        try:
            result = self.server.invoke_successfully(net_firewall_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error getting firewall policy %s:%s" % (self.parameters['policy'],
                                                                               to_native(error)),
                                  exception=traceback.format_exc())

        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            attributes_list = result.get_child_by_name('attributes-list')
            policy_info = attributes_list.get_child_by_name('net-firewall-policy-info')
            ips = self.na_helper.get_value_for_list(from_zapi=True,
                                                    zapi_parent=policy_info.get_child_by_name('allow-list'))
            return {
                'service': policy_info['service'],
                'allow_list': ips}
        return None

    def create_firewall_policy(self):
        """
        Create a firewall policy for given vserver
        :return: None
        """
        net_firewall_policy_obj = netapp_utils.zapi.NaElement("net-firewall-policy-create")
        net_firewall_policy_obj.translate_struct(self.firewall_policy_attributes())
        if self.parameters.get('allow_list'):
            self.validate_ip_addresses()
            net_firewall_policy_obj.add_child_elem(self.na_helper.get_value_for_list(from_zapi=False,
                                                                                     zapi_parent='allow-list',
                                                                                     zapi_child='ip-and-mask',
                                                                                     data=self.parameters['allow_list'])
                                                   )
        try:
            self.server.invoke_successfully(net_firewall_policy_obj, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error creating Firewall Policy: %s" % (to_native(error)), exception=traceback.format_exc())

    def destroy_firewall_policy(self):
        """
        Destroy a Firewall Policy from a vserver
        :return: None
        """
        net_firewall_policy_obj = netapp_utils.zapi.NaElement("net-firewall-policy-destroy")
        net_firewall_policy_obj.translate_struct(self.firewall_policy_attributes())
        try:
            self.server.invoke_successfully(net_firewall_policy_obj, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error destroying Firewall Policy: %s" % (to_native(error)), exception=traceback.format_exc())

    def modify_firewall_policy(self, modify):
        """
        Modify a firewall Policy on a vserver
        :return: none
        """
        self.validate_ip_addresses()
        net_firewall_policy_obj = netapp_utils.zapi.NaElement("net-firewall-policy-modify")
        net_firewall_policy_obj.translate_struct(self.firewall_policy_attributes())
        net_firewall_policy_obj.add_child_elem(self.na_helper.get_value_for_list(from_zapi=False,
                                                                                 zapi_parent='allow-list',
                                                                                 zapi_child='ip-and-mask',
                                                                                 data=modify['allow_list']))
        try:
            self.server.invoke_successfully(net_firewall_policy_obj, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error modifying Firewall Policy: %s" % (to_native(error)), exception=traceback.format_exc())

    def firewall_policy_attributes(self):
        return {
            'policy': self.parameters['policy'],
            'service': self.parameters['service'],
            'vserver': self.parameters['vserver'],
        }

    def get_firewall_config_for_node(self):
        """
        Get firewall configuration on the node
        :return: dict() with firewall config details
        """
        if self.parameters.get('logging') and self.parameters.get('node') is None:
            self.module.fail_json(msg='Error: Missing parameter \'node\' to modify firewall logging')
        net_firewall_config_obj = netapp_utils.zapi.NaElement("net-firewall-config-get")
        net_firewall_config_obj.add_new_child('node-name', self.parameters['node'])
        try:
            result = self.server.invoke_successfully(net_firewall_config_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error getting Firewall Configuration: %s" % (to_native(error)),
                                  exception=traceback.format_exc())
        if result.get_child_by_name('attributes'):
            firewall_info = result['attributes'].get_child_by_name('net-firewall-config-info')
            return {'enable': self.change_status_to_bool(firewall_info.get_child_content('is-enabled'), to_zapi=False),
                    'logging': self.change_status_to_bool(firewall_info.get_child_content('is-logging'), to_zapi=False)}
        return None

    def modify_firewall_config(self, modify):
        """
        Modify the configuration of a firewall on node
        :return: None
        """
        net_firewall_config_obj = netapp_utils.zapi.NaElement("net-firewall-config-modify")
        net_firewall_config_obj.add_new_child('node-name', self.parameters['node'])
        if modify.get('enable'):
            net_firewall_config_obj.add_new_child('is-enabled', self.change_status_to_bool(self.parameters['enable']))
        if modify.get('logging'):
            net_firewall_config_obj.add_new_child('is-logging', self.change_status_to_bool(self.parameters['logging']))
        try:
            self.server.invoke_successfully(net_firewall_config_obj, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error modifying Firewall Config: %s" % (to_native(error)),
                                  exception=traceback.format_exc())

    def change_status_to_bool(self, input, to_zapi=True):
        if to_zapi:
            return 'true' if input == 'enable' else 'false'
        else:
            return 'enable' if input == 'true' else 'disable'

    def apply(self):
        cd_action, modify, modify_config = None, None, None
        if self.parameters.get('policy'):
            current = self.get_firewall_policy()
            cd_action = self.na_helper.get_cd_action(current, self.parameters)
            if cd_action is None and self.parameters['state'] == 'present':
                modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.parameters.get('node'):
            current_config = self.get_firewall_config_for_node()
            # firewall config for a node is always present, we cannot create or delete a firewall on a node
            modify_config = self.na_helper.get_modified_attributes(current_config, self.parameters)

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_firewall_policy()
            elif cd_action == 'delete':
                self.destroy_firewall_policy()
            else:
                if modify:
                    self.modify_firewall_policy(modify)
                if modify_config:
                    self.modify_firewall_config(modify_config)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify, extra_responses={'modify_config': modify_config})
        self.module.exit_json(**result)


def main():
    """
    Execute action from playbook
    :return: nothing
    """
    cg_obj = NetAppONTAPFirewallPolicy()
    cg_obj.apply()


if __name__ == '__main__':
    main()
