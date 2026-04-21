#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_fpolicy_scope
short_description: NetApp ONTAP - Create, delete or modify an FPolicy policy scope configuration.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '21.4.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create, delete or modify an FPolicy policy scope.
options:
  state:
    description:
    - Whether the FPolicy policy scope is present or not
    choices: ['present', 'absent']
    default: present
    type: str

  vserver:
    description:
    - the name of the vserver to create the scope on
    required: true
    type: str

  name:
    description:
    - Name of the policy.  The FPolicy policy must exist for the scope to be created.
    required: true
    type: str

  check_extensions_on_directories:
    description:
    - Indicates whether directory names are also subjected to extensions check, similar to file names.
    - By default, the value is true if policy is configured with Native engine, false otherwise.
    type: bool

  export_policies_to_exclude:
    description:
    -  Export Policies to exclude for file access monitoring. By default no export policy is selected.
    type: list
    elements: str

  export_policies_to_include:
    description:
    - Export policies to include for file access monitoring. By default no export policy is selected.
    type: list
    elements: str

  file_extensions_to_exclude:
    description:
    - File extensions excluded for screening. By default no file extension is selected.
    type: list
    elements: str

  file_extensions_to_include:
    description:
    - File extensions included for screening. By default no file extension is selected.
    type: list
    elements: str

  is_monitoring_of_objects_with_no_extension_enabled:
    description:
    - Indicates whether monitoring of objects with no extension is required. By default, the value is false.
    type: bool

  shares_to_exclude:
    description:
    - Shares to exclude for file access monitoring. By default no share is selected.
    type: list
    elements: str

  shares_to_include:
    description:
    - Shares to include for file access monitoring. By default no share is selected.
    type: list
    elements: str

  volumes_to_exclude:
    description:
    - Volumes that are inactive for the file policy. The list can include items which are regular expressions, such as 'vol*' or 'user?'.
    - Note that if a policy has both an exclude list and an include list, the include list is ignored by the filer when processing user requests.
    - By default no volume is selected.
    type: list
    elements: str

  volumes_to_include:
    description:
    - Volumes that are active for the file policy. The list can include items which are regular expressions, such as 'vol*' or 'user?'.
    - By default no volume is selected.
    type: list
    elements: str

'''

EXAMPLES = """
- name: Create FPolicy scope
  netapp.ontap.na_ontap_fpolicy_scope:
    state: present
    vserver: GBSMNAS80LD
    name: policy1
    export_policies_to_include: export1
    shares_to_include: share1
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Modify FPolicy scope
  netapp.ontap.na_ontap_fpolicy_scope:
    state: present
    vserver: GBSMNAS80LD
    name: policy1
    export_policies_to_include: export1,export2
    shares_to_include: share1,share2
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Delete FPolicy scope
  netapp.ontap.na_ontap_fpolicy_scope:
    state: absent
    vserver: GBSMNAS80LD
    name: policy1
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


class NetAppOntapFpolicyScope():

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            check_extensions_on_directories=dict(required=False, type='bool'),
            export_policies_to_exclude=dict(required=False, type='list', elements='str'),
            export_policies_to_include=dict(required=False, type='list', elements='str'),
            file_extensions_to_exclude=dict(required=False, type='list', elements='str'),
            file_extensions_to_include=dict(required=False, type='list', elements='str'),
            is_monitoring_of_objects_with_no_extension_enabled=dict(required=False, type='bool'),
            shares_to_exclude=dict(required=False, type='list', elements='str'),
            shares_to_include=dict(required=False, type='list', elements='str'),
            volumes_to_exclude=dict(required=False, type='list', elements='str'),
            volumes_to_include=dict(required=False, type='list', elements='str')
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
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_fpolicy_scope(self):
        """
        Check to see if the fPolicy scope exists or not
        :return: dict of scope properties if exist, None if not
        """
        return_value = None

        if self.use_rest:
            api = "/private/cli/vserver/fpolicy/policy/scope"
            query = {
                'vserver': self.parameters['vserver'],
                'policy-name': self.parameters['name'],
                'fields': 'shares-to-include,shares-to-exclude,volumes-to-include,volumes-to-exclude,export-policies-to-include,\
export-policies-to-exclude,file-extensions-to-include,file-extensions-to-exclude,\
is-file-extension-check-on-directories-enabled,is-monitoring-of-objects-with-no-extension-enabled'
            }
            message, error = self.rest_api.get(api, query)
            records, error = rrh.check_for_0_or_more_records(api, message, error)
            if error:
                self.module.fail_json(msg=error)

            if records is not None:
                return_value = {
                    'name': records[0]['policy_name'],
                    'check_extensions_on_directories': records[0]['is_file_extension_check_on_directories_enabled'],
                    'is_monitoring_of_objects_with_no_extension_enabled': records[0]['is_monitoring_of_objects_with_no_extension_enabled']
                }

                for field in (
                    'export_policies_to_exclude', 'export_policies_to_include', 'export_policies_to_include', 'file_extensions_to_exclude',
                    'file_extensions_to_include', 'shares_to_exclude', 'shares_to_include', 'volumes_to_exclude', 'volumes_to_include'
                ):
                    return_value[field] = []
                    if field in records[0]:
                        return_value[field] = records[0][field]

            return return_value

        else:
            fpolicy_scope_obj = netapp_utils.zapi.NaElement('fpolicy-policy-scope-get-iter')
            fpolicy_scope_config = netapp_utils.zapi.NaElement('fpolicy-scope-config')
            fpolicy_scope_config.add_new_child('policy-name', self.parameters['name'])
            fpolicy_scope_config.add_new_child('vserver', self.parameters['vserver'])
            query = netapp_utils.zapi.NaElement('query')
            query.add_child_elem(fpolicy_scope_config)
            fpolicy_scope_obj.add_child_elem(query)

            try:
                result = self.server.invoke_successfully(fpolicy_scope_obj, True)

            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error searching for FPolicy policy scope %s on vserver %s: %s' % (
                        self.parameters['name'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

            if result.get_child_by_name('attributes-list'):
                fpolicy_scope_attributes = result['attributes-list']['fpolicy-scope-config']
                param_dict = {
                    'export_policies_to_exclude': [],
                    'export_policies_to_include': [],
                    'file_extensions_to_exclude': [],
                    'file_extensions_to_include': [],
                    'shares_to_exclude': [],
                    'shares_to_include': [],
                    'volumes_to_exclude': [],
                    'volumes_to_include': []
                }

                for param in param_dict.keys():
                    if fpolicy_scope_attributes.get_child_by_name(param.replace('_', '-')):
                        param_dict[param] = [
                            child_name.get_content() for child_name in fpolicy_scope_attributes.get_child_by_name((param.replace('_', '-'))).get_children()
                        ]

                return_value = {
                    'name': fpolicy_scope_attributes.get_child_content('policy-name'),
                    'check_extensions_on_directories': self.na_helper.get_value_for_bool(
                        from_zapi=True, value=fpolicy_scope_attributes.get_child_content('check-extensions-on-directories')),
                    'is_monitoring_of_objects_with_no_extension_enabled': self.na_helper.get_value_for_bool(
                        from_zapi=True, value=fpolicy_scope_attributes.get_child_content('is-monitoring-of-objects-with-no-extension-enabled')),
                }
                return_value.update(param_dict)
            return return_value

    def create_fpolicy_scope(self):
        """
        Create an FPolicy policy scope
        :return: nothing
        """
        if self.use_rest:
            api = "/private/cli/vserver/fpolicy/policy/scope"
            body = {
                'vserver': self.parameters['vserver'],
                'policy-name': self.parameters['name']
            }
            for parameter in (
                'export_policies_to_exclude', 'export_policies_to_include', 'export_policies_to_include', 'file_extensions_to_exclude',
                'file_extensions_to_include', 'shares_to_exclude', 'shares_to_include', 'volumes_to_exclude', 'volumes_to_include',
                'is-file-extension-check-on-directories-enabled', 'is-monitoring-of-objects-with-no-extension-enabled'
            ):
                if parameter in self.parameters:
                    body[parameter.replace('_', '-')] = self.parameters[parameter]

            dummy, error = self.rest_api.post(api, body)
            if error:
                self.module.fail_json(msg=error)
        else:
            fpolicy_scope_obj = netapp_utils.zapi.NaElement('fpolicy-policy-scope-create')
            fpolicy_scope_obj.add_new_child('policy-name', self.parameters['name'])

            if 'check_extensions_on_directories' in self.parameters:
                fpolicy_scope_obj.add_new_child(
                    'check-extensions-on-directories', self.na_helper.get_value_for_bool(
                        from_zapi=False, value=self.parameters['check_extensions_on_directories']
                    )
                )

            if 'is_monitoring_of_objects_with_no_extension_enabled' in self.parameters:
                fpolicy_scope_obj.add_new_child(
                    'is-monitoring-of-objects-with-no-extension-enabled', self.na_helper.get_value_for_bool(
                        from_zapi=False, value=self.parameters['is_monitoring_of_objects_with_no_extension_enabled']
                    )
                )

            if 'export_policies_to_exclude' in self.parameters:
                export_policies_to_exclude_obj = netapp_utils.zapi.NaElement('export-policies-to-exclude')
                for export_policies_to_exclude in self.parameters['export_policies_to_exclude']:
                    export_policies_to_exclude_obj.add_new_child('string', export_policies_to_exclude)
                fpolicy_scope_obj.add_child_elem(export_policies_to_exclude_obj)

            if 'export_policies_to_include' in self.parameters:
                export_policies_to_include_obj = netapp_utils.zapi.NaElement('export-policies-to-include')
                for export_policies_to_include in self.parameters['export_policies_to_include']:
                    export_policies_to_include_obj.add_new_child('string', export_policies_to_include)
                fpolicy_scope_obj.add_child_elem(export_policies_to_include_obj)

            if 'file_extensions_to_exclude' in self.parameters:
                file_extensions_to_exclude_obj = netapp_utils.zapi.NaElement('file-extensions-to-exclude')
                for file_extensions_to_exclude in self.parameters['file_extensions_to_exclude']:
                    file_extensions_to_exclude_obj.add_new_child('string', file_extensions_to_exclude)
                fpolicy_scope_obj.add_child_elem(file_extensions_to_exclude_obj)

            if 'file_extensions_to_include' in self.parameters:
                file_extensions_to_include_obj = netapp_utils.zapi.NaElement('file-extensions-to-include')
                for file_extensions_to_include in self.parameters['file_extensions_to_include']:
                    file_extensions_to_include_obj.add_new_child('string', file_extensions_to_include)
                fpolicy_scope_obj.add_child_elem(file_extensions_to_include_obj)

            if 'shares_to_exclude' in self.parameters:
                shares_to_exclude_obj = netapp_utils.zapi.NaElement('shares-to-exclude')
                for shares_to_exclude in self.parameters['shares_to_exclude']:
                    shares_to_exclude_obj.add_new_child('string', shares_to_exclude)
                fpolicy_scope_obj.add_child_elem(shares_to_exclude_obj)

            if 'volumes_to_exclude' in self.parameters:
                volumes_to_exclude_obj = netapp_utils.zapi.NaElement('volumes-to-exclude')
                for volumes_to_exclude in self.parameters['volumes_to_exclude']:
                    volumes_to_exclude_obj.add_new_child('string', volumes_to_exclude)
                fpolicy_scope_obj.add_child_elem(volumes_to_exclude_obj)

            if 'shares_to_include' in self.parameters:
                shares_to_include_obj = netapp_utils.zapi.NaElement('shares-to-include')
                for shares_to_include in self.parameters['shares_to_include']:
                    shares_to_include_obj.add_new_child('string', shares_to_include)
                fpolicy_scope_obj.add_child_elem(shares_to_include_obj)

            if 'volumes_to_include' in self.parameters:
                volumes_to_include_obj = netapp_utils.zapi.NaElement('volumes-to-include')
                for volumes_to_include in self.parameters['volumes_to_include']:
                    volumes_to_include_obj.add_new_child('string', volumes_to_include)
                fpolicy_scope_obj.add_child_elem(volumes_to_include_obj)

            try:
                self.server.invoke_successfully(fpolicy_scope_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error creating fPolicy policy scope %s on vserver %s: %s' % (
                        self.parameters['name'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

    def modify_fpolicy_scope(self, modify):
        """
        Modify an FPolicy policy scope
        :return: nothing
        """
        if self.use_rest:
            api = "/private/cli/vserver/fpolicy/policy/scope"
            query = {'vserver': self.parameters['vserver']}
            query['policy-name'] = self.parameters['name']
            dummy, error = self.rest_api.patch(api, modify, query)
            if error:
                self.module.fail_json(msg=error)

        else:
            fpolicy_scope_obj = netapp_utils.zapi.NaElement('fpolicy-policy-scope-modify')
            fpolicy_scope_obj.add_new_child('policy-name', self.parameters['name'])

            if 'check_extensions_on_directories' in self.parameters:
                fpolicy_scope_obj.add_new_child(
                    'check-extensions-on-directories', self.na_helper.get_value_for_bool(
                        from_zapi=False, value=self.parameters['check_extensions_on_directories']
                    )
                )

            if 'is_monitoring_of_objects_with_no_extension_enabled' in self.parameters:
                fpolicy_scope_obj.add_new_child(
                    'is-monitoring-of-objects-with-no-extension-enabled',
                    self.na_helper.get_value_for_bool(from_zapi=False, value=self.parameters['is_monitoring_of_objects_with_no_extension_enabled'])
                )

            if 'export_policies_to_exclude' in self.parameters:
                export_policies_to_exclude_obj = netapp_utils.zapi.NaElement('export-policies-to-exclude')
                for export_policies_to_exclude in self.parameters['export_policies_to_exclude']:
                    export_policies_to_exclude_obj.add_new_child('string', export_policies_to_exclude)
                fpolicy_scope_obj.add_child_elem(export_policies_to_exclude_obj)

            if 'export_policies_to_include' in self.parameters:
                export_policies_to_include_obj = netapp_utils.zapi.NaElement('export-policies-to-include')

                for export_policies_to_include in self.parameters['export_policies_to_include']:
                    export_policies_to_include_obj.add_new_child('string', export_policies_to_include)
                fpolicy_scope_obj.add_child_elem(export_policies_to_include_obj)

            if 'file_extensions_to_exclude' in self.parameters:
                file_extensions_to_exclude_obj = netapp_utils.zapi.NaElement('file-extensions-to-exclude')

                for file_extensions_to_exclude in self.parameters['file_extensions_to_exclude']:
                    file_extensions_to_exclude_obj.add_new_child('string', file_extensions_to_exclude)
                fpolicy_scope_obj.add_child_elem(file_extensions_to_exclude_obj)

            if 'file_extensions_to_include' in self.parameters:
                file_extensions_to_include_obj = netapp_utils.zapi.NaElement('file-extensions-to-include')

                for file_extensions_to_include in self.parameters['file_extensions_to_include']:
                    file_extensions_to_include_obj.add_new_child('string', file_extensions_to_include)
                fpolicy_scope_obj.add_child_elem(file_extensions_to_include_obj)

            if 'shares_to_exclude' in self.parameters:
                shares_to_exclude_obj = netapp_utils.zapi.NaElement('shares-to-exclude')

                for shares_to_exclude in self.parameters['shares_to_exclude']:
                    shares_to_exclude_obj.add_new_child('string', shares_to_exclude)
                fpolicy_scope_obj.add_child_elem(shares_to_exclude_obj)

            if 'volumes_to_exclude' in self.parameters:
                volumes_to_exclude_obj = netapp_utils.zapi.NaElement('volumes-to-exclude')

                for volumes_to_exclude in self.parameters['volumes_to_exclude']:
                    volumes_to_exclude_obj.add_new_child('string', volumes_to_exclude)
                fpolicy_scope_obj.add_child_elem(volumes_to_exclude_obj)

            if 'shares_to_include' in self.parameters:
                shares_to_include_obj = netapp_utils.zapi.NaElement('shares-to-include')

                for shares_to_include in self.parameters['shares_to_include']:
                    shares_to_include_obj.add_new_child('string', shares_to_include)
                fpolicy_scope_obj.add_child_elem(shares_to_include_obj)

            if 'volumes_to_include' in self.parameters:
                volumes_to_include_obj = netapp_utils.zapi.NaElement('volumes-to-include')

                for volumes_to_include in self.parameters['volumes_to_include']:
                    volumes_to_include_obj.add_new_child('string', volumes_to_include)
                fpolicy_scope_obj.add_child_elem(volumes_to_include_obj)

            try:
                self.server.invoke_successfully(fpolicy_scope_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error modifying fPolicy policy scope %s on vserver %s: %s' % (
                    self.parameters['name'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

    def delete_fpolicy_scope(self):
        """
        Delete an FPolicy policy scope
        :return: nothing
        """

        if self.use_rest:
            api = "/private/cli/vserver/fpolicy/policy/scope"
            body = {
                'vserver': self.parameters['vserver'],
                'policy-name': self.parameters['name']
            }
            dummy, error = self.rest_api.delete(api, body)
            if error:
                self.module.fail_json(msg=error)
        else:
            fpolicy_scope_obj = netapp_utils.zapi.NaElement('fpolicy-policy-scope-delete')
            fpolicy_scope_obj.add_new_child('policy-name', self.parameters['name'])

            try:
                self.server.invoke_successfully(fpolicy_scope_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error deleting fPolicy policy scope %s on vserver %s: %s' % (
                        self.parameters['name'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

    def apply(self):
        current, modify = self.get_fpolicy_scope(), None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)

        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_fpolicy_scope()
            elif cd_action == 'delete':
                self.delete_fpolicy_scope()
            elif modify:
                self.modify_fpolicy_scope(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Execute action from playbook
    """
    command = NetAppOntapFpolicyScope()
    command.apply()


if __name__ == '__main__':
    main()
