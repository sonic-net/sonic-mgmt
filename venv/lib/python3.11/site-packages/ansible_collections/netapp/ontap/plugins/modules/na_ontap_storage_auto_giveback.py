#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = """
module: na_ontap_storage_auto_giveback
short_description: Enables or disables NetApp ONTAP storage auto giveback for a specified node
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '21.3.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Enable or disable storage auto giveback
options:
  name:
    description:
    - Specifies the node name to enable or disable storage auto giveback on.
    required: true
    type: str

  auto_giveback_enabled:
    description:
    - specifies whether auto give back should be enabled or disabled
    required: true
    type: bool

  auto_giveback_after_panic_enabled:
    description:
    - specifies whether auto give back on panic should be enabled or disabled
    type: bool

"""

EXAMPLES = """
- name: Enable storage auto giveback
  netapp.ontap.na_ontap_storage_auto_giveback:
    name: node1
    auto_giveback_enabled: true
    auto_giveback_after_panic_enabled: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Disable storage auto giveback
  netapp.ontap.na_ontap_storage_auto_giveback:
    name: node1
    auto_giveback_enabled: false
    auto_giveback_after_panic_enabled: false
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
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh


class NetAppOntapStorageAutoGiveback(object):
    """
        Enable or disable storage failover for a specified node
    """
    def __init__(self):
        """
            Initialize the ONTAP Storage auto giveback class
        """

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            name=dict(required=True, type='str'),
            auto_giveback_enabled=dict(required=True, type='bool'),
            auto_giveback_after_panic_enabled=dict(required=False, type='bool')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        # set up variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg='The python NetApp-Lib module is required')
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def get_storage_auto_giveback(self):
        """
        get the storage failover giveback options for a given node
        :return: dict for options
        """
        return_value = None

        if self.use_rest:

            api = "private/cli/storage/failover"
            query = {
                'fields': 'node,auto_giveback,auto_giveback_after_panic',
                'node': self.parameters['name'],
            }
            message, error = self.rest_api.get(api, query)
            records, error = rrh.check_for_0_or_1_records(api, message, error)

            if error is None and records is not None:
                return_value = {
                    'name': message['records'][0]['node'],
                    'auto_giveback_enabled': message['records'][0].get('auto_giveback'),
                    'auto_giveback_after_panic_enabled': message['records'][0].get('auto_giveback_after_panic')
                }

            if error:
                self.module.fail_json(msg=error)

            if not records:
                error = "REST API did not return failover options for node %s" % (self.parameters['name'])
                self.module.fail_json(msg=error)

        else:

            storage_auto_giveback_get_iter = netapp_utils.zapi.NaElement('cf-get-iter')

            try:
                result = self.server.invoke_successfully(storage_auto_giveback_get_iter, True)

            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error getting auto giveback info for node %s: %s' % (self.parameters['name'], to_native(error)),
                                      exception=traceback.format_exc())

            if result.get_child_by_name('attributes-list'):
                attributes_list = result.get_child_by_name('attributes-list')
                for storage_failover_info_attributes in attributes_list.get_children():

                    sfo_node_info = storage_failover_info_attributes.get_child_by_name('sfo-node-info')
                    node_related_info = sfo_node_info.get_child_by_name('node-related-info')

                    if node_related_info.get_child_content('node') == self.parameters['name']:

                        sfo_options_info = storage_failover_info_attributes.get_child_by_name('sfo-options-info')
                        options_related_info = sfo_options_info.get_child_by_name('options-related-info')
                        sfo_giveback_options_info = options_related_info.get_child_by_name('sfo-giveback-options-info')
                        giveback_options = sfo_giveback_options_info.get_child_by_name('giveback-options')

                        return_value = {
                            'name': node_related_info.get_child_content('node'),
                            'auto_giveback_enabled': self.na_helper.get_value_for_bool(
                                True, options_related_info.get_child_content('auto-giveback-enabled')),
                            'auto_giveback_after_panic_enabled': self.na_helper.get_value_for_bool(
                                True, giveback_options.get_child_content('auto-giveback-after-panic-enabled')),
                        }
                        break

        return return_value

    def modify_storage_auto_giveback(self):
        """
        Modifies storage failover giveback options for a specified node
        """
        if self.use_rest:
            api = "private/cli/storage/failover"
            body = dict()
            query = {
                'node': self.parameters['name']
            }

            body['auto_giveback'] = self.parameters['auto_giveback_enabled']
            if 'auto_giveback_after_panic_enabled' in self.parameters:
                body['auto_giveback_after_panic'] = self.parameters['auto_giveback_after_panic_enabled']

            dummy, error = self.rest_api.patch(api, body, query)
            if error:
                self.module.fail_json(msg=error)

        else:

            storage_auto_giveback_enable = netapp_utils.zapi.NaElement('cf-modify-iter')
            attributes_info = netapp_utils.zapi.NaElement('options-related-info-modify')
            query_info = netapp_utils.zapi.NaElement('options-related-info-modify')

            attributes_info.add_new_child('node', self.parameters['name'])
            attributes_info.add_new_child('auto-giveback-enabled', self.na_helper.get_value_for_bool(
                from_zapi=False, value=self.parameters['auto_giveback_enabled']))

            if 'auto_giveback_after_panic_enabled' in self.parameters:
                sfo_give_back_options_info_modify = netapp_utils.zapi.NaElement('sfo-giveback-options-info-modify')
                give_back_options_modify = netapp_utils.zapi.NaElement('giveback-options-modify')
                give_back_options_modify.add_new_child('auto-giveback-after-panic-enabled', self.na_helper.get_value_for_bool(
                    from_zapi=False, value=self.parameters['auto_giveback_after_panic_enabled']))
                sfo_give_back_options_info_modify.add_child_elem(give_back_options_modify)
                attributes_info.add_child_elem(sfo_give_back_options_info_modify)

            query = netapp_utils.zapi.NaElement('query')
            attributes = netapp_utils.zapi.NaElement("attributes")
            query.add_child_elem(query_info)
            attributes.add_child_elem(attributes_info)

            storage_auto_giveback_enable.add_child_elem(query)
            storage_auto_giveback_enable.add_child_elem(attributes)

            try:
                self.server.invoke_successfully(storage_auto_giveback_enable, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error modifying auto giveback for node %s: %s' % (self.parameters['name'], to_native(error)),
                                      exception=traceback.format_exc())

    def apply(self):
        current = self.get_storage_auto_giveback()
        modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed:
            if not self.module.check_mode:
                self.modify_storage_auto_giveback()
        result = netapp_utils.generate_result(self.na_helper.changed, modify=modify)
        self.module.exit_json(**result)


def main():
    """
    Enables or disables NetApp ONTAP storage auto giveback for a specified node
    """
    obj = NetAppOntapStorageAutoGiveback()
    obj.apply()


if __name__ == '__main__':
    main()
