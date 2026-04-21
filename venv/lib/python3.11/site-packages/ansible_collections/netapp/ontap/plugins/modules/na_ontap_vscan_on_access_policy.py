#!/usr/bin/python

# (c) 2018-2025, NetApp Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = '''
module: na_ontap_vscan_on_access_policy
short_description: NetApp ONTAP Vscan on access policy configuration.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.8.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Configure on access policy for Vscan (virus scan)
options:
  state:
    description:
      - Whether a Vscan on Access policy is present or not
    choices: ['present', 'absent']
    type: str
    default: present

  vserver:
    description:
      - the name of the data vserver to use.
    required: true
    type: str

  policy_name:
    description:
      - The name of the policy
    required: true
    type: str

  file_ext_to_exclude:
    description:
      - File extensions for which On-Access scanning must not be performed.
    type: list
    elements: str

  file_ext_to_include:
    description:
      - File extensions for which On-Access scanning is considered. The default value is '*', which means that all files are considered for scanning except
      - those which are excluded from scanning.
    type: list
    elements: str

  filters:
    description:
      - A list of filters which can be used to define the scope of the On-Access policy more precisely. The filters can be added in any order. Possible values
      - scan_ro_volume  Enable scans for read-only volume,
      - scan_execute_access  Scan only files opened with execute-access (CIFS only).
      - deprecated with REST, use C(scan_readonly_volumes) or C(only_execute_access).
    type: list
    elements: str

  is_scan_mandatory:
    description:
      - Specifies whether access to a file is allowed if there are no external virus-scanning servers available for virus scanning.
      - If not specified, default value is False in ZAPI.
    type: bool

  max_file_size:
    description:
      - Max file-size (in bytes) allowed for scanning. The default value of 2147483648 (2GB) is taken if not provided at the time of creating a policy.
    type: int

  paths_to_exclude:
    description:
      - File paths for which On-Access scanning must not be performed.
    type: list
    elements: str

  scan_files_with_no_ext:
    description:
      - Specifies whether files without any extension are considered for scanning or not.
      - If not specified, default value is True in ZAPI.
    type: bool

  policy_status:
    description:
      - Status for the created policy
    type: bool
    version_added: 20.8.0

  scan_readonly_volumes:
    description:
      - Specifies whether or not read-only volume can be scanned.
      - If not specified, default value is False in creating policy.
    type: bool
    version_added: 21.20.0

  only_execute_access:
    description:
      - Scan only files opened with execute-access.
      - If not specified, default value is False in creating policy.
    type: bool
    version_added: 21.20.0
'''

EXAMPLES = """
- name: Create Vscan On Access Policy
  netapp.ontap.na_ontap_vscan_on_access_policy:
    state: present
    username: '{{ netapp_username }}'
    password: '{{ netapp_password }}'
    hostname: '{{ netapp_hostname }}'
    vserver: carchi-vsim2
    policy_name: carchi_policy
    file_ext_to_exclude: ['exe', 'yml']
- name: Create Vscan On Access Policy with Policy Status enabled
  netapp.ontap.na_ontap_vscan_on_access_policy:
    state: present
    username: '{{ netapp_username }}'
    password: '{{ netapp_password }}'
    hostname: '{{ netapp_hostname }}'
    vserver: carchi-vsim2
    policy_name: carchi_policy
    file_ext_to_exclude: ['exe', 'yml']
    policy_status: true
- name: Modify Vscan on Access Policy
  netapp.ontap.na_ontap_vscan_on_access_policy:
    state: present
    username: '{{ netapp_username }}'
    password: '{{ netapp_password }}'
    hostname: '{{ netapp_hostname }}'
    vserver: carchi-vsim2
    policy_name: carchi_policy
    file_ext_to_exclude: ['exe', 'yml', 'py']
- name: Delete On Access Policy
  netapp.ontap.na_ontap_vscan_on_access_policy:
    state: absent
    username: '{{ netapp_username }}'
    password: '{{ netapp_password }}'
    hostname: '{{ netapp_hostname }}'
    vserver: carchi-vsim2
    policy_name: carchi_policy
"""

RETURN = """

"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, rest_vserver


class NetAppOntapVscanOnAccessPolicy:
    """
    Create/Modify/Delete a Vscan OnAccess policy
    """
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            policy_name=dict(required=True, type='str'),
            file_ext_to_exclude=dict(required=False, type='list', elements='str'),
            file_ext_to_include=dict(required=False, type='list', elements='str'),
            filters=dict(required=False, type='list', elements='str'),
            is_scan_mandatory=dict(required=False, type='bool'),
            max_file_size=dict(required=False, type="int"),
            paths_to_exclude=dict(required=False, type='list', elements='str'),
            scan_files_with_no_ext=dict(required=False, type='bool'),
            policy_status=dict(required=False, type='bool'),
            scan_readonly_volumes=dict(required=False, type='bool'),
            only_execute_access=dict(required=False, type='bool')
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
            mutually_exclusive=[
                ['filters', 'scan_readonly_volumes'],
                ['filters', 'only_execute_access']
            ]
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        # Set up Rest API
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.svm_uuid = None

        # validate list options not contains '' in it in REST.
        if self.use_rest:
            self.validate_options()

        # file_ext_to_include cannot be empty in both ZAPI and REST.
        if 'file_ext_to_include' in self.parameters and len(self.parameters['file_ext_to_include']) < 1:
            self.module.fail_json(msg="Error: The value for file_ext_include cannot be empty")

        # map filters options to rest equivalent options.
        if self.use_rest and 'filters' in self.parameters:
            self.parameters['only_execute_access'], self.parameters['scan_readonly_volumes'] = False, False
            for filter in self.parameters['filters']:
                if filter.lower() not in ['scan_execute_access', 'scan_ro_volume']:
                    self.module.fail_json(msg="Error: Invalid value %s specified for filters %s" % filter)
                if filter.lower() == 'scan_execute_access':
                    self.parameters['only_execute_access'] = True
                if filter.lower() == 'scan_ro_volume':
                    self.parameters['scan_readonly_volumes'] = True

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])
            self.set_playbook_zapi_key_map()

            # set default value for is_scan_mandatory and scan_files_with_no_ext if not set.
            if self.parameters.get('is_scan_mandatory') is None:
                self.parameters['is_scan_mandatory'] = False
            if self.parameters.get('scan_files_with_no_ext') is None:
                self.parameters['scan_files_with_no_ext'] = True

            # form filters from REST options only_execute_access and scan_readonly_volumes.
            filters = []
            if self.parameters.get('only_execute_access'):
                filters.append('scan_execute_access')
            if self.parameters.get('scan_readonly_volumes'):
                filters.append('scan_ro_volume')
            if filters:
                self.parameters['filters'] = filters

    def validate_options(self):
        list_options = ['filters', 'file_ext_to_exclude', 'file_ext_to_include', 'paths_to_exclude']
        invalid_options = []
        for option in list_options:
            if option in self.parameters:
                for value in self.parameters[option]:
                    # '' is an invalid value.
                    if len(value.strip()) < 1:
                        invalid_options.append(option)
        if invalid_options:
            self.module.fail_json(msg="Error: Invalid value specified for option(s): %s" % ', '.join(invalid_options))

    def set_playbook_zapi_key_map(self):
        self.na_helper.zapi_int_keys = {
            'max_file_size': 'max-file-size'
        }
        self.na_helper.zapi_str_keys = {
            'vserver': 'vserver',
            'policy_name': 'policy-name'
        }
        self.na_helper.zapi_bool_keys = {
            'is_scan_mandatory': 'is-scan-mandatory',
            'policy_status': 'is-policy-enabled',
            'scan_files_with_no_ext': 'scan-files-with-no-ext'
        }
        self.na_helper.zapi_list_keys = {
            'file_ext_to_exclude': 'file-ext-to-exclude',
            'file_ext_to_include': 'file-ext-to-include',
            'paths_to_exclude': 'paths-to-exclude',
            'filters': 'filters'
        }

    def get_on_access_policy(self):
        """
        Return a Vscan on Access Policy
        :return: None if there is no access policy, return the policy if there is
        """
        if self.use_rest:
            return self.get_on_access_policy_rest()
        access_policy_obj = netapp_utils.zapi.NaElement('vscan-on-access-policy-get-iter')
        access_policy_info = netapp_utils.zapi.NaElement('vscan-on-access-policy-info')
        access_policy_info.add_new_child('policy-name', self.parameters['policy_name'])
        access_policy_info.add_new_child('vserver', self.parameters['vserver'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(access_policy_info)
        access_policy_obj.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(access_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error searching Vscan on Access Policy %s: %s' %
                                      (self.parameters['policy_name'], to_native(error)), exception=traceback.format_exc())
        return_value = {}
        if result.get_child_by_name('num-records'):
            if int(result.get_child_content('num-records')) == 1:
                attributes_list = result.get_child_by_name('attributes-list')
                vscan_info = attributes_list.get_child_by_name('vscan-on-access-policy-info')
                for option, zapi_key in self.na_helper.zapi_int_keys.items():
                    return_value[option] = self.na_helper.get_value_for_int(from_zapi=True, value=vscan_info.get_child_content(zapi_key))
                for option, zapi_key in self.na_helper.zapi_bool_keys.items():
                    return_value[option] = self.na_helper.get_value_for_bool(from_zapi=True, value=vscan_info.get_child_content(zapi_key))
                for option, zapi_key in self.na_helper.zapi_list_keys.items():
                    return_value[option] = self.na_helper.get_value_for_list(from_zapi=True, zapi_parent=vscan_info.get_child_by_name(zapi_key))
                for option, zapi_key in self.na_helper.zapi_str_keys.items():
                    return_value[option] = vscan_info.get_child_content(zapi_key)
                return return_value
            elif int(result.get_child_content('num-records')) > 1:
                self.module.fail_json(msg='Mutiple Vscan on Access Policy matching %s:' % self.parameters['policy_name'])
        return None

    def create_on_access_policy(self):
        """
        Create a Vscan on Access policy
        :return: none
        """
        if self.use_rest:
            return self.create_on_access_policy_rest()
        access_policy_obj = netapp_utils.zapi.NaElement('vscan-on-access-policy-create')
        access_policy_obj.add_new_child('policy-name', self.parameters['policy_name'])
        access_policy_obj.add_new_child('protocol', 'cifs')
        access_policy_obj = self._fill_in_access_policy(access_policy_obj)

        try:
            self.server.invoke_successfully(access_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating Vscan on Access Policy %s: %s' %
                                      (self.parameters['policy_name'], to_native(error)), exception=traceback.format_exc())

    def status_modify_on_access_policy(self):
        """
        Update the status of policy
        """
        if self.use_rest:
            return self.modify_on_access_policy_rest({'policy_status': False})
        access_policy_obj = netapp_utils.zapi.NaElement('vscan-on-access-policy-status-modify')
        access_policy_obj.add_new_child('policy-name', self.parameters['policy_name'])
        access_policy_obj.add_new_child('policy-status', str(self.parameters['policy_status']).lower())

        try:
            self.server.invoke_successfully(access_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying status Vscan on Access Policy %s: %s' %
                                      (self.parameters['policy_name'], to_native(error)), exception=traceback.format_exc())

    def delete_on_access_policy(self):
        """
        Delete a Vscan On Access Policy
        :return:
        """
        if self.use_rest:
            return self.delete_on_access_policy_rest()
        access_policy_obj = netapp_utils.zapi.NaElement('vscan-on-access-policy-delete')
        access_policy_obj.add_new_child('policy-name', self.parameters['policy_name'])
        try:
            self.server.invoke_successfully(access_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error Deleting Vscan on Access Policy %s: %s' %
                                      (self.parameters['policy_name'], to_native(error)), exception=traceback.format_exc())

    def modify_on_access_policy(self, modify=None):
        """
        Modify a Vscan On Access policy
        :return: nothing
        """
        if self.use_rest:
            return self.modify_on_access_policy_rest(modify)
        access_policy_obj = netapp_utils.zapi.NaElement('vscan-on-access-policy-modify')
        access_policy_obj.add_new_child('policy-name', self.parameters['policy_name'])
        access_policy_obj = self._fill_in_access_policy(access_policy_obj)
        try:
            self.server.invoke_successfully(access_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error Modifying Vscan on Access Policy %s: %s' %
                                      (self.parameters['policy_name'], to_native(error)), exception=traceback.format_exc())

    def _fill_in_access_policy(self, access_policy_obj):
        if self.parameters.get('is_scan_mandatory') is not None:
            access_policy_obj.add_new_child('is-scan-mandatory', str(self.parameters['is_scan_mandatory']).lower())
        if self.parameters.get('max_file_size'):
            access_policy_obj.add_new_child('max-file-size', str(self.parameters['max_file_size']))
        if self.parameters.get('scan_files_with_no_ext') is not None:
            access_policy_obj.add_new_child('scan-files-with-no-ext', str(self.parameters['scan_files_with_no_ext']))
        if 'file_ext_to_exclude' in self.parameters:
            ext_obj = netapp_utils.zapi.NaElement('file-ext-to-exclude')
            access_policy_obj.add_child_elem(ext_obj)
            if len(self.parameters['file_ext_to_exclude']) < 1:
                ext_obj.add_new_child('file-extension', "")
            else:
                for extension in self.parameters['file_ext_to_exclude']:
                    ext_obj.add_new_child('file-extension', extension)
        if 'file_ext_to_include' in self.parameters:
            ext_obj = netapp_utils.zapi.NaElement('file-ext-to-include')
            access_policy_obj.add_child_elem(ext_obj)
            for extension in self.parameters['file_ext_to_include']:
                ext_obj.add_new_child('file-extension', extension)
        if 'filters' in self.parameters:
            ui_filter_obj = netapp_utils.zapi.NaElement('filters')
            access_policy_obj.add_child_elem(ui_filter_obj)
            if len(self.parameters['filters']) < 1:
                ui_filter_obj.add_new_child('vscan-on-access-policy-ui-filter', "")
            else:
                for filter in self.parameters['filters']:
                    ui_filter_obj.add_new_child('vscan-on-access-policy-ui-filter', filter)
        if 'paths_to_exclude' in self.parameters:
            path_obj = netapp_utils.zapi.NaElement('paths-to-exclude')
            access_policy_obj.add_child_elem(path_obj)
            if len(self.parameters['paths_to_exclude']) < 1:
                path_obj.add_new_child('file-path', "")
            else:
                for path in self.parameters['paths_to_exclude']:
                    path_obj.add_new_child('file-path', path)
        return access_policy_obj

    def get_on_access_policy_rest(self):
        self.svm_uuid = self.get_svm_uuid()
        if self.svm_uuid is None:
            self.module.fail_json(msg="Error: vserver %s not found" % self.parameters['vserver'])
        api = "protocols/vscan/%s/on-access-policies" % self.svm_uuid
        query = {'name': self.parameters['policy_name']}
        fields = 'svm,name,mandatory,scope,enabled'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg='Error searching Vscan on Access Policy %s: %s' %
                                      (self.parameters['policy_name'], to_native(error)))
        if record:
            return {
                'max_file_size': self.na_helper.safe_get(record, ['scope', 'max_file_size']),
                'vserver': self.na_helper.safe_get(record, ['svm', 'name']),
                'policy_name': record['name'],
                'is_scan_mandatory': record['mandatory'],
                'policy_status': record['enabled'],
                'scan_files_with_no_ext': self.na_helper.safe_get(record, ['scope', 'scan_without_extension']),
                'file_ext_to_exclude': self.na_helper.safe_get(record, ['scope', 'exclude_extensions']),
                'file_ext_to_include': self.na_helper.safe_get(record, ['scope', 'include_extensions']),
                'paths_to_exclude': self.na_helper.safe_get(record, ['scope', 'exclude_paths']),
                'scan_readonly_volumes': self.na_helper.safe_get(record, ['scope', 'scan_readonly_volumes']),
                'only_execute_access': self.na_helper.safe_get(record, ['scope', 'only_execute_access'])
            }
        return None

    def get_svm_uuid(self):
        uuid, error = rest_vserver.get_vserver_uuid(self.rest_api, self.parameters['vserver'], self.module, True)
        return uuid

    def create_on_access_policy_rest(self):
        api = "protocols/vscan/%s/on-access-policies" % self.svm_uuid
        body = {'name': self.parameters['policy_name']}
        body.update(self.form_create_or_modify_body(self.parameters))
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error creating Vscan on Access Policy %s: %s' %
                                      (self.parameters['policy_name'], to_native(error)))

    def modify_on_access_policy_rest(self, modify):
        api = "protocols/vscan/%s/on-access-policies" % self.svm_uuid
        body = self.form_create_or_modify_body(modify)
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.parameters['policy_name'], body)
        if error:
            self.module.fail_json(msg='Error Modifying Vscan on Access Policy %s: %s' %
                                      (self.parameters['policy_name'], to_native(error)))

    def form_create_or_modify_body(self, params):
        body = {}
        if params.get('is_scan_mandatory') is not None:
            body['mandatory'] = params['is_scan_mandatory']
        if params.get('policy_status') is not None:
            body['enabled'] = params['policy_status']
        if params.get('max_file_size'):
            body['scope.max_file_size'] = params['max_file_size']
        if params.get('scan_files_with_no_ext') is not None:
            body['scope.scan_without_extension'] = params['scan_files_with_no_ext']
        if 'file_ext_to_exclude' in params:
            body['scope.exclude_extensions'] = params['file_ext_to_exclude']
        if 'file_ext_to_include' in params:
            body['scope.include_extensions'] = params['file_ext_to_include']
        if 'paths_to_exclude' in params:
            body['scope.exclude_paths'] = params['paths_to_exclude']
        if params.get('scan_readonly_volumes') is not None:
            body['scope.scan_readonly_volumes'] = params['scan_readonly_volumes']
        if params.get('only_execute_access') is not None:
            body['scope.only_execute_access'] = params['only_execute_access']
        return body

    def delete_on_access_policy_rest(self):
        api = "protocols/vscan/%s/on-access-policies" % self.svm_uuid
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.parameters['policy_name'])
        if error:
            self.module.fail_json(msg='Error Deleting Vscan on Access Policy %s: %s' %
                                      (self.parameters['policy_name'], to_native(error)))

    def apply(self):
        modify_policy_state, modify = None, None
        current = self.get_on_access_policy()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            # enable/disable policy handled in single modify api with REST.
            if not self.use_rest and modify.get('policy_status') is not None:
                modify_policy_state = True
        # policy cannot be deleted unless its disabled, so disable it before delete.
        if cd_action == 'delete' and current['policy_status'] is True and self.parameters.get('policy_status') is False:
            modify_policy_state = True
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_on_access_policy()
                # by default newly created policy will be in disabled state, enable if policy_status is set in ZAPI.
                # REST enable policy on create itself.
                if not self.use_rest and self.parameters.get('policy_status'):
                    modify_policy_state = True
            if modify_policy_state:
                self.status_modify_on_access_policy()
            if cd_action == 'delete':
                self.delete_on_access_policy()
            if modify:
                self.modify_on_access_policy(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify,
                                              extra_responses={'modify_policy_state': modify_policy_state})
        self.module.exit_json(**result)


def main():
    """
    Execute action from playbook
    """
    command = NetAppOntapVscanOnAccessPolicy()
    command.apply()


if __name__ == '__main__':
    main()
