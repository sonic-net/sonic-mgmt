#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_fpolicy_event
short_description: NetApp ONTAP FPolicy policy event configuration
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '21.4.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create, delete or modify an FPolicy policy event.
options:
  state:
    description:
    - Whether the FPolicy policy event is present or not.
    choices: ['present', 'absent']
    default: present
    type: str

  vserver:
    description:
    - The name of the vserver to create the event on.
    required: true
    type: str

  name:
    description:
    - Name of the Event.
    required: true
    type: str

  file_operations:
    description:
    - Name of file operations to be applied to the event. By default no operations are monitored.
    type: list
    elements: 'str'
    choices: ['close', 'create', 'create_dir', 'delete', 'delete_dir', 'getattr', 'link', 'lookup',
    'open', 'read', 'write', 'rename', 'rename_dir', 'setattr', 'symlink']

  filters:
    description:
    - Name of filters to be applied to the event. It is notification filtering parameters. By default no filters are selected.
    type: list
    elements: 'str'
    choices: ['monitor_ads', 'close_with_modification', 'close_without_modification', 'first_read', 'first_write', 'offline_bit', 'open_with_delete_intent',
    'open_with_write_intent', 'write_with_size_change', 'close_with_read', 'setattr_with_owner_change', 'setattr_with_group_change',
    'setattr_with_sacl_change', 'setattr_with_dacl_change', 'setattr_with_modify_time_change', 'setattr_with_access_time_change',
    'setattr_with_creation_time_change', 'setattr_with_mode_change', 'setattr_with_size_change', 'setattr_with_allocation_size_change', 'exclude_directory']

  protocol:
    description:
    - Name of protocol for which event is created. By default no protocol is selected.
    choices: ['cifs', 'nfsv3', 'nfsv4']
    type: str

  volume_monitoring:
    description:
    - Indicator if the volume operation required for the event. If not specified the default Value is false.
    type: bool

notes:
- Support check_mode.
'''

EXAMPLES = """
- name: Create FPolicy Event
  netapp.ontap.na_ontap_fpolicy_event:
    state: present
    vserver: svm1
    name: fpolicy_event
    file_operations: ['create', 'create_dir', 'delete', 'delete_dir', 'read', 'close', 'rename', 'rename_dir']
    filters: ['first_read', 'close_with_modification']
    protocol: cifs
    volume_monitoring: false
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Modify FPolicy Event
  netapp.ontap.na_ontap_fpolicy_event:
    state: present
    vserver: svm1
    name: fpolicy_event
    volume_monitoring: true
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Delete FPolicy Event
  netapp.ontap.na_ontap_fpolicy_event:
    state: absent
    vserver: svm1
    name: fpolicy_event
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
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh


class NetAppOntapFpolicyEvent():

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(choices=['present', 'absent'], type='str', default='present'),
            vserver=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            file_operations=dict(
                required=False,
                type='list',
                elements='str',
                choices=['close', 'create', 'create_dir', 'delete', 'delete_dir', 'getattr', 'link',
                         'lookup', 'open', 'read', 'write', 'rename', 'rename_dir', 'setattr', 'symlink']),
            filters=dict(
                required=False,
                type='list',
                elements='str',
                choices=['monitor_ads', 'close_with_modification', 'close_without_modification', 'first_read',
                         'first_write', 'offline_bit', 'open_with_delete_intent', 'open_with_write_intent', 'write_with_size_change', 'close_with_read',
                         'setattr_with_owner_change', 'setattr_with_group_change', 'setattr_with_sacl_change', 'setattr_with_dacl_change',
                         'setattr_with_modify_time_change', 'setattr_with_access_time_change', 'setattr_with_creation_time_change', 'setattr_with_mode_change',
                         'setattr_with_size_change', 'setattr_with_allocation_size_change', 'exclude_directory']),
            protocol=dict(required=False, type='str', choices=['cifs', 'nfsv3', 'nfsv4']),
            volume_monitoring=dict(required=False, type='bool')
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
            required_together=[
                ('protocol', 'file_operations')]
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.vserver_uuid = None

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp)
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_vserver_uuid(self):
        """
        Get vserver uuid, used for API calls.
        """
        api = "/svm/svms"
        query = {
            'name': self.parameters['vserver']
        }
        message, error = self.rest_api.get(api, query)
        if error:
            self.module.fail_json(msg=error)
        #  if vserver does not exist we expect message to be a dict containing 'records': []
        if not message['records']:
            self.module.fail_json(msg="vserver does not exist")

        return message['records'][0]['uuid']

    def list_to_dict(self, params):
        """
        Converts a list of entries to a dictionary with the key as the parameter name and the value as True as expected by the REST API
        """
        return dict((param, True) for param in params)

    def get_fpolicy_event(self):
        """
        Get FPolicy event configuration if an event matching the parameters exists
        """
        return_value = None
        if self.use_rest:
            api = "/protocols/fpolicy/%s/events" % (self.vserver_uuid)
            query = {
                'fields': 'protocol,filters,file_operations,volume_monitoring'
            }
            message, error = self.rest_api.get(api, query)
            records, error = rrh.check_for_0_or_more_records(api, message, error)
            if error:
                self.module.fail_json(msg=error)
            if records is not None:
                for record in records:
                    if record['name'] == self.parameters['name']:
                        return_value = {}
                        for parameter in ('protocol', 'volume_monitoring'):
                            return_value[parameter] = []
                            if parameter in record:
                                return_value[parameter] = record[parameter]
                        #  file_operations and filters contains a dict all possible choices as the keys and True/False as the values.
                        #  Return a list of the choices that are True.
                        return_value['file_operations'] = []
                        if 'file_operations' in record:
                            file_operation_list = [file_operation for file_operation, enabled in record['file_operations'].items() if enabled]
                            return_value['file_operations'] = file_operation_list

                        return_value['filters'] = []
                        if 'filters' in record:
                            filters_list = [filter for filter, enabled in record['filters'].items() if enabled]
                            return_value['filters'] = filters_list

            return return_value

        else:
            fpolicy_event_obj = netapp_utils.zapi.NaElement('fpolicy-policy-event-get-iter')
            fpolicy_event_config = netapp_utils.zapi.NaElement('fpolicy-event-options-config')
            fpolicy_event_config.add_new_child('event-name', self.parameters['name'])
            fpolicy_event_config.add_new_child('vserver', self.parameters['vserver'])
            query = netapp_utils.zapi.NaElement('query')
            query.add_child_elem(fpolicy_event_config)
            fpolicy_event_obj.add_child_elem(query)

            try:
                result = self.server.invoke_successfully(fpolicy_event_obj, True)

            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error searching for FPolicy policy event %s on vserver %s: %s' % (
                    self.parameters['name'], self.parameters['vserver'], to_native(error)),
                    exception=traceback.format_exc()
                )

            if result.get_child_by_name('attributes-list'):
                fpolicy_event_attributes = result['attributes-list']['fpolicy-event-options-config']

                #  get file operations as list
                file_operations = []
                if fpolicy_event_attributes.get_child_by_name('file-operations'):
                    for file_operation in fpolicy_event_attributes.get_child_by_name('file-operations').get_children():
                        file_operations.append(file_operation.get_content())

                #  get filter string as list
                filters = []
                if fpolicy_event_attributes.get_child_by_name('filter-string'):
                    for filter in fpolicy_event_attributes.get_child_by_name('filter-string').get_children():
                        filters.append(filter.get_content())

                protocol = ""
                if fpolicy_event_attributes.get_child_by_name('protocol'):
                    protocol = fpolicy_event_attributes.get_child_content('protocol')

                return_value = {
                    'vserver': fpolicy_event_attributes.get_child_content('vserver'),
                    'name': fpolicy_event_attributes.get_child_content('event-name'),
                    'file_operations': file_operations,
                    'filters': filters,
                    'protocol': protocol,
                    'volume_monitoring': self.na_helper.get_value_for_bool(
                        from_zapi=True, value=fpolicy_event_attributes.get_child_content('volume-operation')
                    )
                }

            return return_value

    def create_fpolicy_event(self):
        """
        Create an FPolicy policy event
        :return: nothing
        """
        if self.use_rest:
            api = "/protocols/fpolicy/%s/events" % (self.vserver_uuid)
            body = {
                'name': self.parameters['name']
            }

            if 'protocol' in self.parameters:
                body['protocol'] = self.parameters['protocol']
            if 'volume_monitoring' in self.parameters:
                body['volume_monitoring'] = self.parameters['volume_monitoring']

            if 'filters' in self.parameters:
                body['filters'] = self.list_to_dict(self.parameters['filters'])
            if 'file_operations' in self.parameters:
                body['file_operations'] = self.list_to_dict(self.parameters['file_operations'])

            dummy, error = self.rest_api.post(api, body)

            if error:
                self.module.fail_json(msg=error)

        else:
            fpolicy_event_obj = netapp_utils.zapi.NaElement('fpolicy-policy-event-create')
            fpolicy_event_obj.add_new_child('event-name', self.parameters['name'])

            if 'file_operations' in self.parameters:

                file_operation_obj = netapp_utils.zapi.NaElement('file-operations')

                for file_operation in self.parameters['file_operations']:
                    file_operation_obj.add_new_child('fpolicy-operation', file_operation)
                fpolicy_event_obj.add_child_elem(file_operation_obj)

            if 'filters' in self.parameters:

                filter_string_obj = netapp_utils.zapi.NaElement('filter-string')

                for filter in self.parameters['filters']:
                    filter_string_obj.add_new_child('fpolicy-filter', filter)
                fpolicy_event_obj.add_child_elem(filter_string_obj)

            if 'protocol' in self.parameters:
                fpolicy_event_obj.add_new_child('protocol', self.parameters['protocol'])

            if 'volume_monitoring' in self.parameters:
                fpolicy_event_obj.add_new_child(
                    'volume-operation', self.na_helper.get_value_for_bool(from_zapi=False, value=self.parameters['volume_monitoring'])
                )

            try:
                self.server.invoke_successfully(fpolicy_event_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error creating fPolicy policy event %s on vserver %s: %s' % (
                    self.parameters['name'], self.parameters['vserver'], to_native(error)),
                    exception=traceback.format_exc())

    def modify_fpolicy_event(self, modify):
        """
        Modify an FPolicy policy event
        :return: nothing
        """
        if self.use_rest:
            api = "/private/cli/vserver/fpolicy/policy/event"
            query = {
                'vserver': self.parameters['vserver'],
                'event-name': self.parameters['name']
            }
            body = {}
            #  protocol and file_operations must be parsed into the API together
            #  if filters exists filters,protocol and file_operations must be parsed together.
            for parameter in 'protocol', 'filters', 'file_operations':
                if parameter in modify:
                    body[parameter] = modify[parameter]
                elif parameter in self.parameters:
                    body[parameter] = self.parameters[parameter]
            if 'volume_monitoring' in modify:
                body['volume-operation'] = modify['volume_monitoring']

            dummy, error = self.rest_api.patch(api, body, query)
            if error:
                self.module.fail_json(msg=error)

        else:
            fpolicy_event_obj = netapp_utils.zapi.NaElement('fpolicy-policy-event-modify')
            fpolicy_event_obj.add_new_child('event-name', self.parameters['name'])

            if 'file_operations' in self.parameters:
                file_operation_obj = netapp_utils.zapi.NaElement('file-operations')
                for file_operation in self.parameters['file_operations']:
                    file_operation_obj.add_new_child('fpolicy-operation', file_operation)
                fpolicy_event_obj.add_child_elem(file_operation_obj)

            if 'filters' in self.parameters:
                filter_string_obj = netapp_utils.zapi.NaElement('filter-string')
                for filter in self.parameters['filters']:
                    filter_string_obj.add_new_child('fpolicy-filter', filter)
                fpolicy_event_obj.add_child_elem(filter_string_obj)

            if 'protocol' in self.parameters:
                fpolicy_event_obj.add_new_child('protocol', self.parameters['protocol'])

            if 'volume_monitoring' in self.parameters:
                fpolicy_event_obj.add_new_child(
                    'volume-operation', self.na_helper.get_value_for_bool(from_zapi=False, value=self.parameters['volume_monitoring'])
                )

            try:
                self.server.invoke_successfully(fpolicy_event_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error modifying fPolicy policy event %s on vserver %s: %s' % (
                    self.parameters['name'], self.parameters['vserver'], to_native(error)),
                    exception=traceback.format_exc())

    def delete_fpolicy_event(self):
        """
        Delete an FPolicy policy event
        :return: nothing
        """
        if self.use_rest:
            api = "/protocols/fpolicy/%s/events/%s" % (self.vserver_uuid, self.parameters['name'])

            dummy, error = self.rest_api.delete(api)
            if error:
                self.module.fail_json(msg=error)
        else:
            fpolicy_event_obj = netapp_utils.zapi.NaElement('fpolicy-policy-event-delete')
            fpolicy_event_obj.add_new_child('event-name', self.parameters['name'])

            try:
                self.server.invoke_successfully(fpolicy_event_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error deleting fPolicy policy event %s on vserver %s: %s' % (
                    self.parameters['name'], self.parameters['vserver'],
                    to_native(error)), exception=traceback.format_exc()
                )

    def apply(self):
        if self.use_rest:
            self.vserver_uuid = self.get_vserver_uuid()

        current, modify = self.get_fpolicy_event(), None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)

        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed:
            if not self.module.check_mode:
                if cd_action == 'create':
                    self.create_fpolicy_event()
                elif cd_action == 'delete':
                    self.delete_fpolicy_event()
                elif modify:
                    self.modify_fpolicy_event(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Execute action from playbook
    """
    command = NetAppOntapFpolicyEvent()
    command.apply()


if __name__ == '__main__':
    main()
