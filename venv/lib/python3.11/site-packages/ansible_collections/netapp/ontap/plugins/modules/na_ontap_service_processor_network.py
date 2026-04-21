#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = '''
module: na_ontap_service_processor_network
short_description: NetApp ONTAP service processor network
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Modify a ONTAP service processor network
options:
  state:
    description:
      - Whether the specified service processor network should exist or not.
    choices: ['present']
    type: str
    default: present
  address_type:
    description:
      - Specify address class.
    required: true
    type: str
    choices: ['ipv4', 'ipv6']
  is_enabled:
    description:
      - Specify whether to enable or disable the service processor network.
      - Required with ZAPI.
      - Disable service processor network status not supported in REST.
      - Setting C(ip_address), C(netmask) or C(prefix_length), C(gateway_ip_address) will enable sp network in REST.
    type: bool
  node:
    description:
      - The node where the service processor network should be enabled
    required: true
    type: str
  dhcp:
    description:
      - Specify dhcp type.
      - Setting C(dhcp=none) requires all of C(ip_address), C(netmask), C(gateway_ip_address) and at least one of its value different from current.
    type: str
    choices: ['v4', 'none']
  gateway_ip_address:
    description:
      - Specify the gateway ip.
    type: str
  ip_address:
    description:
      - Specify the service processor ip address.
    type: str
  netmask:
    description:
      - Specify the service processor netmask.
    type: str
  prefix_length:
    description:
      - Specify the service processor prefix_length.
    type: int
  wait_for_completion:
    description:
      - Set this parameter to 'true' for synchronous execution (wait until SP status is successfully updated)
      - Set this parameter to 'false' for asynchronous execution
      - For asynchronous, execution exits as soon as the request is sent, without checking SP status
    type: bool
    default: false
    version_added: 2.8.0
'''

EXAMPLES = """
- name: Modify Service Processor Network, enable dhcp.
  netapp.ontap.na_ontap_service_processor_network:
    state: present
    address_type: ipv4
    is_enabled: true
    dhcp: v4
    node: "{{ netapp_node }}"
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
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic
import time


class NetAppOntapServiceProcessorNetwork:
    """
        Modify a Service Processor Network
    """

    def __init__(self):
        """
            Initialize the NetAppOntapServiceProcessorNetwork class
        """
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present'], default='present'),
            address_type=dict(required=True, type='str', choices=['ipv4', 'ipv6']),
            is_enabled=dict(required=False, type='bool'),
            node=dict(required=True, type='str'),
            dhcp=dict(required=False, type='str', choices=['v4', 'none']),
            gateway_ip_address=dict(required=False, type='str'),
            ip_address=dict(required=False, type='str'),
            netmask=dict(required=False, type='str'),
            prefix_length=dict(required=False, type='int'),
            wait_for_completion=dict(required=False, type='bool', default=False)
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
            mutually_exclusive=[('netmask', 'prefix_length')]
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Set up Rest API
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.uuid, self.ipv4_or_ipv6 = None, None
        dhcp_mutual_options = ['ip_address', 'gateway_ip_address', 'netmask']
        if self.parameters.get('dhcp') == 'v4':
            # error if dhcp is set to v4 and address_type is ipv6.
            if self.parameters['address_type'] == 'ipv6':
                self.module.fail_json(msg="Error: dhcp cannot be set for address_type: ipv6.")
            # error if dhcp is set to v4 and manual interface options are present.
            if any(x in self.parameters for x in dhcp_mutual_options):
                self.module.fail_json(msg="Error: set dhcp v4 or all of 'ip_address, gateway_ip_address, netmask'.")
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            if 'is_enabled' not in self.parameters:
                self.module.fail_json(msg='missing required arguments: is_enabled in ZAPI')
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=None)
            self.set_playbook_zapi_key_map()

    def set_playbook_zapi_key_map(self):
        self.na_helper.zapi_string_keys = {
            'address_type': 'address-type',
            'node': 'node',
            'dhcp': 'dhcp',
            'gateway_ip_address': 'gateway-ip-address',
            'ip_address': 'ip-address',
            'netmask': 'netmask'
        }
        self.na_helper.zapi_int_keys = {
            'prefix_length': 'prefix-length'
        }
        self.na_helper.zapi_bool_keys = {
            'is_enabled': 'is-enabled',
        }
        self.na_helper.zapi_required = {
            'address_type': 'address-type',
            'node': 'node',
            'is_enabled': 'is-enabled'
        }

    def get_sp_network_status(self):
        """
        Return status of service processor network
        :param:
            name : name of the node
        :return: Status of the service processor network
        :rtype: dict
        """
        spn_get_iter = netapp_utils.zapi.NaElement('service-processor-network-get-iter')
        query_info = {
            'query': {
                'service-processor-network-info': {
                    'node': self.parameters['node'],
                    'address-type': self.parameters['address_type']
                }
            }
        }
        spn_get_iter.translate_struct(query_info)
        try:
            result = self.server.invoke_successfully(spn_get_iter, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching service processor network status for %s: %s' %
                                  (self.parameters['node'], to_native(error)), exception=traceback.format_exc())
        if int(result['num-records']) >= 1:
            sp_attr_info = result['attributes-list']['service-processor-network-info']
            return sp_attr_info.get_child_content('setup-status')
        return None

    def get_service_processor_network(self):
        """
        Return details about service processor network
        :param:
            name : name of the node
        :return: Details about service processor network. None if not found.
        :rtype: dict
        """
        if self.use_rest:
            return self.get_service_processor_network_rest()
        spn_get_iter = netapp_utils.zapi.NaElement('service-processor-network-get-iter')
        query_info = {
            'query': {
                'service-processor-network-info': {
                    'node': self.parameters['node']
                }
            }
        }
        spn_get_iter.translate_struct(query_info)
        try:
            result = self.server.invoke_successfully(spn_get_iter, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching service processor network info for %s: %s' %
                                  (self.parameters['node'], to_native(error)), exception=traceback.format_exc())
        sp_details = None
        # check if job exists
        if int(result['num-records']) >= 1:
            sp_details = dict()
            sp_attr_info = result['attributes-list']['service-processor-network-info']
            for item_key, zapi_key in self.na_helper.zapi_string_keys.items():
                sp_details[item_key] = sp_attr_info.get_child_content(zapi_key)
                # set dhcp: 'none' if current dhcp set as None to avoid idempotent issue.
                if item_key == 'dhcp' and sp_details[item_key] is None:
                    sp_details[item_key] = 'none'
            for item_key, zapi_key in self.na_helper.zapi_bool_keys.items():
                sp_details[item_key] = self.na_helper.get_value_for_bool(from_zapi=True,
                                                                         value=sp_attr_info.get_child_content(zapi_key))
            for item_key, zapi_key in self.na_helper.zapi_int_keys.items():
                sp_details[item_key] = self.na_helper.get_value_for_int(from_zapi=True,
                                                                        value=sp_attr_info.get_child_content(zapi_key))
        return sp_details

    def modify_service_processor_network(self, params=None):
        """
        Modify a service processor network.
        :param params: A dict of modified options.
        When dhcp is not set to v4, ip_address, netmask, and gateway_ip_address must be specified even if remains the same.
        """
        if self.use_rest:
            return self.modify_service_processor_network_rest(params)

        sp_modify = netapp_utils.zapi.NaElement('service-processor-network-modify')
        sp_attributes = dict()
        for item_key in self.parameters:
            if item_key in self.na_helper.zapi_string_keys:
                zapi_key = self.na_helper.zapi_string_keys.get(item_key)
                sp_attributes[zapi_key] = self.parameters[item_key]
            elif item_key in self.na_helper.zapi_bool_keys:
                zapi_key = self.na_helper.zapi_bool_keys.get(item_key)
                sp_attributes[zapi_key] = self.na_helper.get_value_for_bool(from_zapi=False, value=self.parameters[item_key])
            elif item_key in self.na_helper.zapi_int_keys:
                zapi_key = self.na_helper.zapi_int_keys.get(item_key)
                sp_attributes[zapi_key] = self.na_helper.get_value_for_int(from_zapi=False, value=self.parameters[item_key])
        sp_modify.translate_struct(sp_attributes)
        try:
            self.server.invoke_successfully(sp_modify, enable_tunneling=True)
            if self.parameters.get('wait_for_completion'):
                retries = 25
                # when try to enable and set dhcp:v4 or manual ip, the status will be 'not_setup' before changes to complete.
                status_key = 'not_setup' if params.get('is_enabled') else 'in_progress'
                while self.get_sp_network_status() == status_key and retries > 0:
                    time.sleep(15)
                    retries -= 1
                # In ZAPI, once the status is 'succeeded', it takes few more seconds for ip details take effect..
                time.sleep(10)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying service processor network: %s' % (to_native(error)),
                                  exception=traceback.format_exc())

    def get_service_processor_network_rest(self):
        api = 'cluster/nodes'
        fields = 'uuid,service_processor,service_processor.dhcp_enabled'
        query = {'name': self.parameters['node']}
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg='Error fetching service processor network info for %s: %s' %
                                  (self.parameters['node'], error))
        current = None
        if record:
            self.uuid = record['uuid']
            # if the desired address_type already configured in current, interface details will be returned.
            # if the desired address_type not configured in current,  None will be set in network interface options
            # and setting either dhcp(for v4) or (ip_address, gateway_ip_address, netmask) will enable and configure the interface.
            self.ipv4_or_ipv6 = 'ipv4_interface' if self.parameters['address_type'] == 'ipv4' else 'ipv6_interface'
            netmask_or_prefix = 'netmask' if self.ipv4_or_ipv6 == 'ipv4_interface' else 'prefix_length'
            current = {
                'dhcp': 'v4' if self.na_helper.safe_get(record, ['service_processor', 'dhcp_enabled']) else 'none',
                'gateway_ip_address': self.na_helper.safe_get(record, ['service_processor', self.ipv4_or_ipv6, 'gateway']),
                'ip_address': self.na_helper.safe_get(record, ['service_processor', self.ipv4_or_ipv6, 'address']),
                'is_enabled': True if self.na_helper.safe_get(record, ['service_processor', self.ipv4_or_ipv6]) else False,
                netmask_or_prefix: self.na_helper.safe_get(record, ['service_processor', self.ipv4_or_ipv6, 'netmask'])
            }
        return current

    def modify_service_processor_network_rest(self, modify):
        api = 'cluster/nodes'
        body = {'service_processor': {}}
        ipv4_or_ipv6_body = {}
        if self.parameters.get('gateway_ip_address'):
            ipv4_or_ipv6_body['gateway'] = self.parameters['gateway_ip_address']
        if self.parameters.get('netmask'):
            ipv4_or_ipv6_body['netmask'] = self.parameters['netmask']
        if self.parameters.get('prefix_length'):
            ipv4_or_ipv6_body['netmask'] = self.parameters['prefix_length']
        if self.parameters.get('ip_address'):
            ipv4_or_ipv6_body['address'] = self.parameters['ip_address']
        if ipv4_or_ipv6_body:
            body['service_processor'][self.ipv4_or_ipv6] = ipv4_or_ipv6_body
        if 'dhcp' in self.parameters:
            body['service_processor']['dhcp_enabled'] = True if self.parameters['dhcp'] == 'v4' else False
        # if dhcp is enabled in REST, setting ip_address details manually requires dhcp: 'none' in params.
        # if dhcp: 'none' is not in params set it False to disable dhcp and assign manual ip address.
        elif ipv4_or_ipv6_body.get('gateway') and ipv4_or_ipv6_body.get('address') and ipv4_or_ipv6_body.get('netmask'):
            body['service_processor']['dhcp_enabled'] = False
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body)
        if error:
            self.module.fail_json(msg='Error modifying service processor network: %s' % error)
        if self.parameters.get('wait_for_completion'):
            retries = 25
            while self.is_sp_modified_rest(modify) is False and retries > 0:
                time.sleep(15)
                retries -= 1

    def is_sp_modified_rest(self, modify):
        current = self.get_service_processor_network_rest()
        if current is None:
            return False
        for sp_option in modify:
            if modify[sp_option] != current[sp_option]:
                return False
        return True

    def validate_rest(self, modify):
        # error if try to disable service processor network status in REST.
        if modify.get('is_enabled') is False:
            error = "Error: disable service processor network status not allowed in REST"
            self.module.fail_json(msg=error)
        # error if try to enable and modify not have either dhcp or (ip_address, netamsk, gateway)
        if modify.get('is_enabled') and len(modify) == 1:
            error = "Error: enable service processor network requires dhcp or ip_address,netmask,gateway details in REST."
            self.module.fail_json(msg=error)

    def validate_zapi(self, modify):
        if self.parameters['is_enabled'] is False:
            if len(modify) > 1 and 'is_enabled' in modify:
                self.module.fail_json(msg='Error: Cannot modify any other parameter for a service processor network if option "is_enabled" is set to false.')
            elif modify and 'is_enabled' not in modify:
                self.module.fail_json(msg='Error: Cannot modify a service processor network if it is disabled in ZAPI.')

    def apply(self):
        """
        Run Module based on play book
        """
        current = self.get_service_processor_network()
        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if not current:
            self.module.fail_json(msg='Error No Service Processor for node: %s' % self.parameters['node'])
        if modify:
            # disable dhcp requires configuring one of ip-address, netmask and gateway different from current.
            if modify.get('dhcp') == 'none' and not any(x in modify for x in ['ip_address', 'gateway_ip_address', 'netmask']):
                error = "Error: To disable dhcp, configure ip-address, netmask and gateway details manually."
                self.module.fail_json(msg=error)
            self.validate_rest(modify) if self.use_rest else self.validate_zapi(modify)
        if self.na_helper.changed and not self.module.check_mode:
            self.modify_service_processor_network(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, modify=modify)
        self.module.exit_json(**result)


def main():
    """
    Create the NetApp Ontap Service Processor Network Object and modify it
    """

    obj = NetAppOntapServiceProcessorNetwork()
    obj.apply()


if __name__ == '__main__':
    main()
