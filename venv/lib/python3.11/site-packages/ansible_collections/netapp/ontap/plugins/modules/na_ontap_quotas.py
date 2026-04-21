#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

'''
na_ontap_quotas
'''


DOCUMENTATION = '''
module: na_ontap_quotas
short_description: NetApp ONTAP Quotas
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.8.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Set/Modify/Delete quota on ONTAP
options:
  state:
    description:
      - Whether the specified quota should exist or not.
    choices: ['present', 'absent']
    default: present
    type: str
  vserver:
    required: true
    description:
      - Name of the vserver to use.
    type: str
  volume:
    description:
      - The name of the volume that the quota resides on.
    required: true
    type: str
  quota_target:
    description:
      - The quota target of the type specified.
      - users and group takes quota_target value in REST.
      - For default user and group quota rules, the quota_target must be specified as "".
    type: str
  qtree:
    description:
      - Name of the qtree for the quota.
      - For user or group rules, it can be the qtree name or "" if no qtree.
      - For tree type rules, this field must be "".
    default: ""
    type: str
  type:
    description:
      - The type of quota rule.
    choices: ['user', 'group', 'tree']
    type: str
  policy:
    description:
      - Name of the quota policy from which the quota rule should be obtained.
      - Only supported with ZAPI.
      - Multiple alternative quota policies (active and backup) are not supported in REST.
      - REST manages the quota rules of the active policy.
    type: str
  set_quota_status:
    description:
      - Whether the specified volume should have quota status on or off.
    type: bool
  perform_user_mapping:
    description:
      - Whether quota management will perform user mapping for the user specified in quota-target.
      - User mapping can be specified only for a user quota rule.
    type: bool
    aliases: ['user_mapping']
    version_added: 20.12.0
  file_limit:
    description:
      - The number of files that the target can have.
      - use '-' to reset file limit.
    type: str
  disk_limit:
    description:
      - The amount of disk space that is reserved for the target.
      - Expects a number followed with B (for bytes), KB, MB, GB, TB.
      - If the unit is not present KB is used by default.
      - Examples - 10MB, 20GB, 1TB, 20B, 10.
      - In REST, if limit is less than 1024 bytes, the value is rounded up to 1024 bytes.
      - use '-' to reset disk limit.
    type: str
  soft_file_limit:
    description:
      - The number of files the target would have to exceed before a message is logged and an SNMP trap is generated.
      - use '-' to reset soft file limit.
    type: str
  soft_disk_limit:
    description:
      - The amount of disk space the target would have to exceed before a message is logged and an SNMP trap is generated.
      - See C(disk_limit) for format description.
      - In REST, if limit is less than 1024 bytes, the value is rounded up to 1024 bytes.
      - use '-' to reset soft disk limit.
    type: str
  threshold:
    description:
      - The amount of disk space the target would have to exceed before a message is logged.
      - See C(disk_limit) for format description.
      - Only supported with ZAPI.
    type: str
  activate_quota_on_change:
    description:
      - Method to use to activate quota on a change.
      - Default value is 'resize' in ZAPI.
      - With REST, Changes to quota rule limits C(file_limit), C(disk_limit), C(soft_file_limit), and C(soft_disk_limit) are applied automatically
        without requiring a quota resize operation.
    choices: ['resize', 'reinitialize', 'none']
    type: str
    version_added: 20.12.0

'''

EXAMPLES = """
- name: Create quota rule in ZAPI.
  netapp.ontap.na_ontap_quotas:
    state: present
    vserver: ansible
    volume: ansible
    quota_target: user1
    type: user
    policy: ansible
    file_limit: 2
    disk_limit: 3
    set_quota_status: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
- name: Resize quota
  netapp.ontap.na_ontap_quotas:
    state: present
    vserver: ansible
    volume: ansible
    quota_target: user1
    type: user
    policy: ansible
    file_limit: 2
    disk_limit: 3
    set_quota_status: true
    activate_quota_on_change: resize
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
- name: Reinitialize quota
  netapp.ontap.na_ontap_quotas:
    state: present
    vserver: ansible
    volume: ansible
    quota_target: user1
    type: user
    policy: ansible
    file_limit: 2
    disk_limit: 3
    set_quota_status: true
    activate_quota_on_change: reinitialize
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
- name: Modify quota
  netapp.ontap.na_ontap_quotas:
    state: present
    vserver: ansible
    volume: ansible
    quota_target: user1
    type: user
    policy: ansible
    file_limit: 2
    disk_limit: 3
    threshold: 3
    set_quota_status: false
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
- name: Delete quota
  netapp.ontap.na_ontap_quotas:
    state: absent
    vserver: ansible
    volume: ansible
    quota_target: /vol/ansible
    type: user
    policy: ansible
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
- name: Add/Set quota rule for type user in REST.
  netapp.ontap.na_ontap_quotas:
    state: present
    vserver: ansible
    volume: ansible
    quota_target: "user1,user2"
    qtree: qtree
    type: user
    file_limit: 2
    disk_limit: 3
    set_quota_status: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
- name: Modify quota reset file limit and modify disk limit.
  netapp.ontap.na_ontap_quotas:
    state: present
    vserver: ansible
    volume: ansible
    quota_target: "user1,user2"
    qtree: qtree
    type: user
    file_limit: "-"
    disk_limit: 100
    set_quota_status: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
- name: Add/Set quota rule for type group in REST.
  netapp.ontap.na_ontap_quotas:
    state: present
    vserver: ansible
    volume: ansible
    quota_target: group1
    qtree: qtree
    type: group
    file_limit: 2
    disk_limit: 3
    set_quota_status: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
- name: Add/Set quota rule for type qtree in REST.
  netapp.ontap.na_ontap_quotas:
    state: present
    vserver: ansible
    volume: ansible
    quota_target: qtree1
    type: tree
    file_limit: 2
    disk_limit: 3
    set_quota_status: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """

"""

import time
import traceback
import re
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh


class NetAppONTAPQuotas:
    '''Class with quotas methods'''

    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            volume=dict(required=True, type='str'),
            quota_target=dict(required=False, type='str'),
            qtree=dict(required=False, type='str', default=""),
            type=dict(required=False, type='str', choices=['user', 'group', 'tree']),
            policy=dict(required=False, type='str'),
            set_quota_status=dict(required=False, type='bool'),
            perform_user_mapping=dict(required=False, type='bool', aliases=['user_mapping']),
            file_limit=dict(required=False, type='str'),
            disk_limit=dict(required=False, type='str'),
            soft_file_limit=dict(required=False, type='str'),
            soft_disk_limit=dict(required=False, type='str'),
            threshold=dict(required=False, type='str'),
            activate_quota_on_change=dict(required=False, type='str', choices=['resize', 'reinitialize', 'none'])
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
            required_by={
                'policy': ['quota_target', 'type'],
                'perform_user_mapping': ['quota_target', 'type'],
                'file_limit': ['quota_target', 'type'],
                'disk_limit': ['quota_target', 'type'],
                'soft_file_limit': ['quota_target', 'type'],
                'soft_disk_limit': ['quota_target', 'type'],
                'threshold': ['quota_target', 'type'],
            },
            required_together=[('quota_target', 'type')]
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Set up Rest API
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        unsupported_rest_properties = ['policy', 'threshold']
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties)
        self.volume_uuid = None   # volume UUID after quota rule creation, used for on or off quota status
        self.quota_uuid = None
        self.warn_msg = None
        self.validate_parameters_ZAPI_REST()

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def validate_parameters_ZAPI_REST(self):
        if self.use_rest:
            if self.parameters.get('type') == 'tree':
                if self.parameters['qtree']:
                    self.module.fail_json(msg="Error: Qtree cannot be specified for a tree type rule, it should be ''.")
            # valid qtree name for ZAPI is /vol/vol_name/qtree_name and REST is qtree_name.
            if '/' in self.parameters.get('quota_target', ''):
                self.parameters['quota_target'] = self.parameters['quota_target'].split('/')[-1]
            for quota_limit in ['file_limit', 'disk_limit', 'soft_file_limit', 'soft_disk_limit']:
                if self.parameters.get(quota_limit) == '-1':
                    self.parameters[quota_limit] = '-'
        else:
            # converted blank parameter to * as shown in vsim
            if self.parameters.get('quota_target') == "":
                self.parameters['quota_target'] = '*'
            if not self.parameters.get('activate_quota_on_change'):
                self.parameters['activate_quota_on_change'] = 'resize'
        size_format_error_message = "input string is not a valid size format. A valid size format is constructed as" \
                                    "<integer><size unit>. For example, '10MB', '10KB'.  Only numeric input is also valid." \
                                    "The default unit size is KB."
        if self.parameters.get('disk_limit') and self.parameters['disk_limit'] != '-' and not self.convert_to_kb_or_bytes('disk_limit'):
            self.module.fail_json(msg='disk_limit %s' % size_format_error_message)
        if self.parameters.get('soft_disk_limit') and self.parameters['soft_disk_limit'] != '-' and not self.convert_to_kb_or_bytes('soft_disk_limit'):
            self.module.fail_json(msg='soft_disk_limit %s' % size_format_error_message)
        if self.parameters.get('threshold') and self.parameters['threshold'] != '-' and not self.convert_to_kb_or_bytes('threshold'):
            self.module.fail_json(msg='threshold %s' % size_format_error_message)

    def get_quota_status(self):
        """
        Return details about the quota status
        :param:
            name : volume name
        :return: status of the quota. None if not found.
        :rtype: dict
        """
        quota_status_get = netapp_utils.zapi.NaElement('quota-status')
        quota_status_get.translate_struct({
            'volume': self.parameters['volume']
        })
        try:
            result = self.server.invoke_successfully(quota_status_get, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching quotas status info: %s' % to_native(error),
                                  exception=traceback.format_exc())
        return result['status']

    def get_quotas_with_retry(self, get_request, policy):
        return_values = None
        if policy is not None:
            get_request['query']['quota-entry'].add_new_child('policy', policy)
        try:
            result = self.server.invoke_successfully(get_request, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            # Bypass a potential issue in ZAPI when policy is not set in the query
            # https://github.com/ansible-collections/netapp.ontap/issues/4
            # BURT1076601 Loop detected in next() for table quota_rules_zapi
            if policy is None and 'Reason - 13001:success' in to_native(error):
                result = None
                return_values = self.debug_quota_get_error(error)
            else:
                self.module.fail_json(msg='Error fetching quotas info for policy %s: %s'
                                      % (policy, to_native(error)),
                                      exception=traceback.format_exc())
        return result, return_values

    def get_quotas(self, policy=None):
        """
        Get quota details
        :return: name of volume if quota exists, None otherwise
        """
        if self.parameters.get('type') is None:
            return None
        if policy is None:
            policy = self.parameters.get('policy')
        quota_get = netapp_utils.zapi.NaElement('quota-list-entries-iter')
        query = {
            'query': {
                'quota-entry': {
                    'volume': self.parameters['volume'],
                    'quota-target': self.parameters['quota_target'],
                    'quota-type': self.parameters['type'],
                    'vserver': self.parameters['vserver'],
                    'qtree': self.parameters['qtree'] or '""'
                }
            }
        }
        quota_get.translate_struct(query)
        result, return_values = self.get_quotas_with_retry(quota_get, policy)
        if result is None:
            return return_values
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            # if quota-target is '*', the query treats it as a wildcard. But a blank entry is represented as '*'.
            # Hence the need to loop through all records to find a match.
            for quota_entry in result.get_child_by_name('attributes-list').get_children():
                quota_target = quota_entry.get_child_content('quota-target')
                if quota_target == self.parameters['quota_target']:
                    return_values = {'volume': quota_entry.get_child_content('volume'),
                                     'file_limit': quota_entry.get_child_content('file-limit'),
                                     'disk_limit': quota_entry.get_child_content('disk-limit'),
                                     'soft_file_limit': quota_entry.get_child_content('soft-file-limit'),
                                     'soft_disk_limit': quota_entry.get_child_content('soft-disk-limit'),
                                     'threshold': quota_entry.get_child_content('threshold')}
                    value = self.na_helper.safe_get(quota_entry, ['perform-user-mapping'])
                    if value is not None:
                        return_values['perform_user_mapping'] = self.na_helper.get_value_for_bool(True, value)
                    return return_values
        return None

    def get_quota_policies(self):
        """
        Get list of quota policies
        :return: list of quota policies (empty list if None found)
        """
        quota_policy_get = netapp_utils.zapi.NaElement('quota-policy-get-iter')
        query = {
            'query': {
                'quota-policy-info': {
                    'vserver': self.parameters['vserver']
                }
            }
        }
        quota_policy_get.translate_struct(query)
        try:
            result = self.server.invoke_successfully(quota_policy_get, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching quota policies: %s' % to_native(error),
                                  exception=traceback.format_exc())
        return ([policy['policy-name'] for policy in result['attributes-list'].get_children()]
                if result.get_child_by_name('attributes-list')
                else [])

    def debug_quota_get_error(self, error):
        policies = self.get_quota_policies()
        entries = {}
        for policy in policies:
            entries[policy] = self.get_quotas(policy)
        if len(policies) == 1:
            self.module.warn('retried with success using policy="%s" on "13001:success" ZAPI error.' % policy)
            return entries[policies[0]]
        self.module.fail_json(msg='Error fetching quotas info: %s - current vserver policies: %s, details: %s'
                              % (to_native(error), policies, entries))

    def quota_entry_set(self):
        """
        Adds a quota entry
        """
        options = {'volume': self.parameters['volume'],
                   'quota-target': self.parameters['quota_target'],
                   'quota-type': self.parameters['type'],
                   'qtree': self.parameters['qtree']}

        self.set_zapi_options(options)
        if self.parameters.get('policy'):
            options['policy'] = self.parameters['policy']
        set_entry = netapp_utils.zapi.NaElement.create_node_with_children(
            'quota-set-entry', **options)
        try:
            self.server.invoke_successfully(set_entry, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error adding/modifying quota entry %s: %s'
                                  % (self.parameters['volume'], to_native(error)),
                                  exception=traceback.format_exc())

    def quota_entry_delete(self):
        """
        Deletes a quota entry
        """
        options = {'volume': self.parameters['volume'],
                   'quota-target': self.parameters['quota_target'],
                   'quota-type': self.parameters['type'],
                   'qtree': self.parameters['qtree']}
        set_entry = netapp_utils.zapi.NaElement.create_node_with_children(
            'quota-delete-entry', **options)
        if self.parameters.get('policy'):
            set_entry.add_new_child('policy', self.parameters['policy'])
        try:
            self.server.invoke_successfully(set_entry, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting quota entry %s: %s'
                                  % (self.parameters['volume'], to_native(error)),
                                  exception=traceback.format_exc())

    def quota_entry_modify(self, modify_attrs):
        """
        Modifies a quota entry
        """
        for key in list(modify_attrs):
            modify_attrs[key.replace("_", "-")] = modify_attrs.pop(key)
        options = {'volume': self.parameters['volume'],
                   'quota-target': self.parameters['quota_target'],
                   'quota-type': self.parameters['type'],
                   'qtree': self.parameters['qtree']}
        options.update(modify_attrs)
        self.set_zapi_options(options)
        if self.parameters.get('policy'):
            options['policy'] = str(self.parameters['policy'])
        modify_entry = netapp_utils.zapi.NaElement.create_node_with_children(
            'quota-modify-entry', **options)
        try:
            self.server.invoke_successfully(modify_entry, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying quota entry %s: %s'
                                  % (self.parameters['volume'], to_native(error)),
                                  exception=traceback.format_exc())

    def set_zapi_options(self, options):
        if self.parameters.get('file_limit'):
            options['file-limit'] = self.parameters['file_limit']
        if self.parameters.get('disk_limit'):
            options['disk-limit'] = self.parameters['disk_limit']
        if self.parameters.get('perform_user_mapping') is not None:
            options['perform-user-mapping'] = str(self.parameters['perform_user_mapping'])
        if self.parameters.get('soft_file_limit'):
            options['soft-file-limit'] = self.parameters['soft_file_limit']
        if self.parameters.get('soft_disk_limit'):
            options['soft-disk-limit'] = self.parameters['soft_disk_limit']
        if self.parameters.get('threshold'):
            options['threshold'] = self.parameters['threshold']

    def on_or_off_quota(self, status, cd_action=None):
        """
        on or off quota
        """
        quota = netapp_utils.zapi.NaElement.create_node_with_children(
            status, **{'volume': self.parameters['volume']})
        try:
            self.server.invoke_successfully(quota,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            if cd_action == 'delete' and status == 'quota-on' and '14958:No valid quota rules found' in to_native(error):
                # ignore error on quota-on, as all rules have been deleted
                self.module.warn('Last rule deleted, quota is off.')
                return
            self.module.fail_json(msg='Error setting %s for %s: %s'
                                  % (status, self.parameters['volume'], to_native(error)),
                                  exception=traceback.format_exc())

    def resize_quota(self, cd_action=None):
        """
        resize quota
        """
        quota = netapp_utils.zapi.NaElement.create_node_with_children(
            'quota-resize', **{'volume': self.parameters['volume']})
        try:
            self.server.invoke_successfully(quota,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            if cd_action == 'delete' and '14958:No valid quota rules found' in to_native(error):
                # ignore error on quota-on, as all rules have been deleted
                self.module.warn('Last rule deleted, but quota is on as resize is not allowed.')
                return
            self.module.fail_json(msg='Error setting %s for %s: %s'
                                  % ('quota-resize', self.parameters['volume'], to_native(error)),
                                  exception=traceback.format_exc())

    def get_quotas_rest(self):
        """
        Retrieves quotas with rest API.
        If type is user then it returns all possible combinations of user name records.
        Report api is used to fetch file and disk limit info
        """
        if not self.use_rest:
            return self.get_quotas()
        query = {'svm.name': self.parameters.get('vserver'),
                 'volume.name': self.parameters.get('volume'),
                 'type': self.parameters.get('type'),
                 'fields': 'svm.uuid,'
                           'svm.name,'
                           'space.hard_limit,'
                           'files.hard_limit,'
                           'user_mapping,'
                           'qtree.name,'
                           'type,'
                           'space.soft_limit,'
                           'files.soft_limit,'
                           'volume.uuid,'
                           'users.name,'
                           'users.id,'
                           'group.name,'}

        # set qtree name in query for type user and group if not ''.
        if self.parameters['qtree']:
            query['qtree.name'] = self.parameters['qtree']
        users_names, users_ids = [], []
        if self.parameters.get('quota_target'):
            type = self.parameters['type']
            if type == 'user':
                users_names = [target for target in self.parameters['quota_target'].split(',') if not target.isdigit()]
                users_ids = [target for target in self.parameters['quota_target'].split(',') if target.isdigit()]
                if users_names:
                    query['users.name'] = ",".join(users_names)
                if users_ids:
                    query['users.id'] = ",".join(users_ids)
            else:
                field_name = 'group.name' if type == 'group' else 'qtree.name'
                query[field_name] = self.parameters['quota_target']

        api = 'storage/quota/rules'
        # If type: user, get quota rules api returns users which has name starts with input target user names.
        # Example of users list in a record:
        # users: [{'name': 'quota_user'}], users: [{'name': 'quota_user'}, {'name': 'quota'}]
        records, error = rest_generic.get_0_or_more_records(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg="Error on getting quota rule info: %s" % error)
        if records:
            record = None
            for item in records:
                # along with user/group, qtree should also match to get current quota.
                # for type user/group if qtree is not set in create, its not returned in GET, make desired qtree None if ''.
                desired_qtree = self.parameters['qtree'] if self.parameters.get('qtree') else None
                current_qtree = self.na_helper.safe_get(item, ['qtree', 'name'])
                type = self.parameters.get('type')
                if type in ['user', 'group']:
                    if desired_qtree != current_qtree:
                        continue
                    if type == 'user':
                        current_users = {}
                        current_users['names'] = [user['name'] for user in item['users'] if user.get('name')]
                        current_users['ids'] = [user['id'] for user in item['users'] if user.get('id')]
                        if set(current_users['names']) == set(users_names) and \
                                set(current_users['ids']) == set(users_ids):
                            record = item
                            break
                    elif item['group']['name'] == self.parameters['quota_target']:
                        record = item
                        break
                # for type tree, desired quota_target should match current tree.
                elif type == 'tree' and current_qtree == self.parameters['quota_target']:
                    record = item
                    break
            if record:
                self.volume_uuid = record['volume']['uuid']
                self.quota_uuid = record['uuid']
                current = {
                    'soft_file_limit': self.na_helper.safe_get(record, ['files', 'soft_limit']),
                    'disk_limit': self.na_helper.safe_get(record, ['space', 'hard_limit']),
                    'soft_disk_limit': self.na_helper.safe_get(record, ['space', 'soft_limit']),
                    'file_limit': self.na_helper.safe_get(record, ['files', 'hard_limit']),
                    'perform_user_mapping': self.na_helper.safe_get(record, ['user_mapping']),
                }
                # Rest allows reset quota limits using '-', convert None to '-' to avoid idempotent issue.
                current['soft_file_limit'] = '-' if current['soft_file_limit'] is None else str(current['soft_file_limit'])
                current['disk_limit'] = '-' if current['disk_limit'] is None else str(current['disk_limit'])
                current['soft_disk_limit'] = '-' if current['soft_disk_limit'] is None else str(current['soft_disk_limit'])
                current['file_limit'] = '-' if current['file_limit'] is None else str(current['file_limit'])
                return current
        return None

    def quota_entry_set_rest(self):
        """
        quota_entry_set with rest API.
        for type: 'user' and 'group', quota_target is used.
        value for user, group and qtree should be passed as ''
        """
        if not self.use_rest:
            return self.quota_entry_set()
        body = {'svm.name': self.parameters.get('vserver'),
                'volume.name': self.parameters.get('volume'),
                'type': self.parameters.get('type'),
                'qtree.name': self.parameters.get('qtree')}
        quota_target = self.parameters.get('quota_target')
        if self.parameters.get('type') == 'user':
            body['users.name'] = quota_target.split(',')
        elif self.parameters.get('type') == 'group':
            body['group.name'] = quota_target
        if self.parameters.get('type') == 'tree':
            body['qtree.name'] = quota_target
        if 'file_limit' in self.parameters:
            body['files.hard_limit'] = self.parameters.get('file_limit')
        if 'soft_file_limit' in self.parameters:
            body['files.soft_limit'] = self.parameters.get('soft_file_limit')
        if 'disk_limit' in self.parameters:
            body['space.hard_limit'] = self.parameters.get('disk_limit')
        if 'soft_disk_limit' in self.parameters:
            body['space.soft_limit'] = self.parameters.get('soft_disk_limit')
        if 'perform_user_mapping' in self.parameters:
            body['user_mapping'] = self.parameters.get('perform_user_mapping')
        query = {'return_records': 'true'}    # in order to capture UUID
        api = 'storage/quota/rules'
        response, error = rest_generic.post_async(self.rest_api, api, body, query)
        if error:
            if "job reported error:" in error and "entry doesn't exist" in error:
                # ignore RBAC issue with FSx - BURT1525998
                self.module.warn('Ignoring job status, assuming success.')
            elif '5308568' in error:
                # code: 5308568 requires quota to be disabled/enabled to take effect.
                # code: 5308571 - rule created, but to make it active reinitialize quota.
                # reinitialize will disable/enable quota.
                self.form_warn_msg_rest('create', '5308568')
            elif '5308571' in error:
                self.form_warn_msg_rest('create', '5308571')
            else:
                self.module.fail_json(msg="Error on creating quotas rule: %s" % error)
            # fetch volume uuid as response will be None if above code error occurs.
            self.volume_uuid = self.get_quota_status_or_volume_id_rest(get_volume=True)
        # skip fetching volume uuid from response if volume_uuid already populated.
        if not self.volume_uuid and response:
            record, error = rrh.check_for_0_or_1_records(api, response, error, query)
            if not error and record and not record['volume']['uuid']:
                error = 'volume uuid key not present in %s:' % record
            if error:
                self.module.fail_json(msg='Error on getting volume uuid: %s' % error)
            if record:
                self.volume_uuid = record['volume']['uuid']

    def quota_entry_delete_rest(self):
        """
        quota_entry_delete with rest API.
        """
        if not self.use_rest:
            return self.quota_entry_delete()
        api = 'storage/quota/rules'
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.quota_uuid)
        if error is not None:
            # delete operation succeeded, but reinitialize is required.
            # code: 5308569 requires quota to be disabled/enabled to take effect.
            # code: 5308572 error occurs when trying to delete last rule.
            if '5308569' in error:
                self.form_warn_msg_rest('delete', '5308569')
            elif '5308572' in error:
                self.form_warn_msg_rest('delete', '5308572')
            else:
                self.module.fail_json(msg="Error on deleting quotas rule: %s" % error)

    def quota_entry_modify_rest(self, modify_quota):
        """
        quota_entry_modify with rest API.
        User mapping cannot be turned on for multiuser quota rules.
        """
        if not self.use_rest:
            return self.quota_entry_modify(modify_quota)
        body = {}
        if 'disk_limit' in modify_quota:
            body['space.hard_limit'] = modify_quota['disk_limit']
        if 'file_limit' in modify_quota:
            body['files.hard_limit'] = modify_quota['file_limit']
        if 'soft_disk_limit' in modify_quota:
            body['space.soft_limit'] = modify_quota['soft_disk_limit']
        if 'soft_file_limit' in modify_quota:
            body['files.soft_limit'] = modify_quota['soft_file_limit']
        if 'perform_user_mapping' in modify_quota:
            body['user_mapping'] = modify_quota['perform_user_mapping']
        api = 'storage/quota/rules'
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.quota_uuid, body)
        if error is not None:
            # limits are modified but internal error, require reinitialize quota.
            if '5308567' in error:
                self.form_warn_msg_rest('modify', '5308567')
            else:
                self.module.fail_json(msg="Error on modifying quotas rule: %s" % error)

    def get_quota_status_or_volume_id_rest(self, get_volume=None):
        """
        Get the status info on or off
        """
        if not self.use_rest:
            return self.get_quota_status()
        api = 'storage/volumes'
        params = {'name': self.parameters['volume'],
                  'svm.name': self.parameters['vserver'],
                  'fields': 'quota.state,uuid'}
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            msg = "volume uuid" if get_volume else "quota status info"
            self.module.fail_json(msg="Error on getting %s: %s" % (msg, error))
        if record:
            return record['uuid'] if get_volume else record['quota']['state']
        self.module.fail_json(msg="Error: Volume %s in SVM %s does not exist" % (self.parameters['volume'], self.parameters['vserver']))

    def on_or_off_quota_rest(self, status, cd_action=None):
        """
        quota_entry_modify quota status with rest API.
        """
        if not self.use_rest:
            return self.on_or_off_quota(status, cd_action)
        body = {}
        body['quota.enabled'] = status == 'quota-on'
        api = 'storage/volumes'
        if not self.volume_uuid:
            self.volume_uuid = self.get_quota_status_or_volume_id_rest(get_volume=True)
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.volume_uuid, body)
        if error is not None:
            self.module.fail_json(msg='Error setting %s for %s: %s'
                                  % (status, self.parameters['volume'], to_native(error)))

    def form_warn_msg_rest(self, action, code):
        start_msg = "Quota policy rule %s opertation succeeded. " % action
        end_msg = "reinitialize(disable and enable again) the quota for volume %s " \
                  "in SVM %s." % (self.parameters['volume'], self.parameters['vserver'])
        msg = 'unexpected code: %s' % code
        if code == '5308572':
            msg = "However the rule is still being enforced. To stop enforcing, "
        if code in ['5308568', '5308569', '5308567']:
            msg = "However quota resize failed due to an internal error. To make quotas active, "
        if code == '5308571':
            msg = "but quota resize is skipped. To make quotas active, "
        self.warn_msg = start_msg + msg + end_msg

    def apply(self):
        """
        Apply action to quotas
        """
        cd_action = None
        modify_quota_status = None
        modify_quota = None
        current = self.get_quotas_rest()
        if self.parameters.get('type') is not None:
            cd_action = self.na_helper.get_cd_action(current, self.parameters)
            if cd_action is None:
                modify_quota = self.na_helper.get_modified_attributes(current, self.parameters)
        quota_status = self.get_quota_status_or_volume_id_rest()
        if 'set_quota_status' in self.parameters and quota_status is not None:
            # if 'set_quota_status' == True in create, sometimes there is delay in status update from 'initializing' -> 'on'.
            # if quota_status == 'on' and options(set_quota_status == True and activate_quota_on_change == 'resize'),
            # sometimes there is delay in status update from 'resizing' -> 'on'
            set_quota_status = True if quota_status in ('on', 'resizing', 'initializing') else False
            quota_status_action = self.na_helper.get_modified_attributes({'set_quota_status': set_quota_status}, self.parameters)
            if quota_status_action:
                modify_quota_status = 'quota-on' if quota_status_action['set_quota_status'] else 'quota-off'
        if (self.parameters.get('activate_quota_on_change') in ['resize', 'reinitialize']
                and (cd_action is not None or modify_quota is not None)
                and modify_quota_status is None
                and quota_status in ('on', None)):
            modify_quota_status = self.parameters['activate_quota_on_change']
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.quota_entry_set_rest()
            elif cd_action == 'delete':
                self.quota_entry_delete_rest()
            elif modify_quota:
                self.quota_entry_modify_rest(modify_quota)
            if modify_quota_status in ['quota-off', 'quota-on']:
                self.on_or_off_quota_rest(modify_quota_status)
            elif modify_quota_status == 'resize':
                if not self.use_rest:
                    self.resize_quota(cd_action)
            elif modify_quota_status == 'reinitialize':
                self.on_or_off_quota_rest('quota-off')
                time.sleep(10)  # status switch interval
                self.on_or_off_quota_rest('quota-on', cd_action)
            # if warn message and quota not reinitialize, throw warnings to reinitialize in REST.
            if self.warn_msg and modify_quota_status != 'reinitialize':
                self.module.warn(self.warn_msg)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify_quota, extra_responses={'modify_quota_status': modify_quota_status})
        self.module.exit_json(**result)

    def convert_to_kb_or_bytes(self, option):
        """
        convert input to kb, and set to self.parameters.
        :param option: disk_limit or soft_disk_limit.
        :return: boolean if it can be converted.
        """
        self.parameters[option].replace(' ', '')
        slices = re.findall(r"\d+|\D+", self.parameters[option])
        if len(slices) < 1 or len(slices) > 2:
            return False
        if not slices[0].isdigit():
            return False
        if len(slices) > 1 and slices[1].lower() not in ['b', 'kb', 'mb', 'gb', 'tb']:
            return False
        # force kb as the default unit for REST
        if len(slices) == 1 and self.use_rest:
            slices = (slices[0], 'kb')
        if len(slices) > 1:
            if not self.use_rest:
                # conversion to KB
                self.parameters[option] = str(int(slices[0]) * netapp_utils.POW2_BYTE_MAP[slices[1].lower()] // 1024)
            else:
                # conversion to Bytes
                self.parameters[option] = str(int(slices[0]) * netapp_utils.POW2_BYTE_MAP[slices[1].lower()])
        if self.use_rest:
            # Rounding off the converted bytes
            self.parameters[option] = str(((int(self.parameters[option]) + 1023) // 1024) * 1024)
        return True


def main():
    '''Execute action'''
    quota_obj = NetAppONTAPQuotas()
    quota_obj.apply()


if __name__ == '__main__':
    main()
