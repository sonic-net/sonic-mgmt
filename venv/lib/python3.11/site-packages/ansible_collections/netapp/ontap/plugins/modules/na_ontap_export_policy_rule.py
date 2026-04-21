#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_export_policy_rule
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''

module: na_ontap_export_policy_rule

short_description: NetApp ONTAP manage export policy rules
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
  - Create or delete or modify export rules in ONTAP

options:
  state:
    description:
      - Whether the specified export policy rule should exist or not.
    required: false
    choices: ['present', 'absent']
    type: str
    default: present

  name:
    description:
      - The name of the export policy this rule will be added to (or modified, or removed from).
    required: True
    type: str
    aliases:
      - policy_name

  client_match:
    description:
      - List of Client Match host names, IP Addresses, Netgroups, or Domains.
    type: list
    elements: str

  anonymous_user_id:
    description:
      - User name or ID to which anonymous users are mapped. Default value is '65534'.
    type: str

  ro_rule:
    description:
      - List of Read only access specifications for the rule
    choices: ['any','none','never','krb5','krb5i','krb5p','ntlm','sys']
    type: list
    elements: str

  rw_rule:
    description:
      - List of Read Write access specifications for the rule
    choices: ['any','none','never','krb5','krb5i','krb5p','ntlm','sys']
    type: list
    elements: str

  super_user_security:
    description:
      - List of Read Write access specifications for the rule
    choices: ['any','none','krb5','krb5i','krb5p','ntlm','sys']
    type: list
    elements: str

  allow_suid:
    description:
      - If 'true', NFS server will honor SetUID bits in SETATTR operation. Default value on creation is 'true'
    type: bool

  protocol:
    description:
      - List of Client access protocols.
      - Default value is set to 'any' during create.
    choices: [any,nfs,nfs3,nfs4,cifs,flexcache]
    type: list
    elements: str
    aliases:
      - protocols

  rule_index:
    description:
      - Index of the export policy rule.
      - When rule_index is not set, we try to find a rule with an exact match.
        If found, no action is taken with state set to present, and the rule is deleted with state set to absent.
        An error is reported if more than one rule is found.
      - When rule_index is set and state is present, if a rule cannot be found with this index,
        we try to find a rule with an exact match and assign the index to this rule if found.
        If no match is found, a new rule is created.
      - All attributes that are set are used for an exact match.  As a minimum, client_match, ro_rule, and rw_rule are required.
    type: int

  from_rule_index:
    description:
      - index of the export policy rule to be re-indexed
    type: int
    version_added: 21.20.0

  vserver:
    description:
      - Name of the vserver to use.
    required: true
    type: str

  ntfs_unix_security:
    description:
      - NTFS export UNIX security options.
      - With REST, supported from ONTAP 9.9.1 version.
    type: str
    choices: ['fail', 'ignore']
    version_added: 21.18.0

  force_delete_on_first_match:
    description:
      - when rule_index is not set, the default is to report an error on multiple matches.
      - when this option is set, one of the rules with an exact match is deleted when state is absent.
      - ignored when state is present.
    type: bool
    default: false
    version_added: 21.23.0

  chown_mode:
    description:
      - Specifies who is authorized to change the ownership mode of a file.
      - With REST, supported from ONTAP 9.9.1 version.
    type: str
    choices: ['restricted', 'unrestricted']
    version_added: 22.0.0

  allow_device_creation:
    description:
      - Specifies whether or not device creation is allowed.
      - default is true.
      - With REST, supported from ONTAP 9.9.1 version.
    type: bool
    version_added: 22.0.0
'''

EXAMPLES = """
- name: Create ExportPolicyRule
  netapp.ontap.na_ontap_export_policy_rule:
    state: present
    name: default123
    rule_index: 100
    vserver: ci_dev
    client_match: 0.0.0.0/0,1.1.1.0/24
    ro_rule: krb5,krb5i
    rw_rule: any
    protocol: nfs,nfs3
    super_user_security: any
    anonymous_user_id: 65534
    allow_suid: true
    ntfs_unix_security: ignore
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify ExportPolicyRule
  netapp.ontap.na_ontap_export_policy_rule:
    state: present
    name: default123
    rule_index: 100
    vserver: ci_dev
    client_match: 0.0.0.0/0
    anonymous_user_id: 65521
    ro_rule: ntlm
    rw_rule: any
    protocol: any
    allow_suid: false
    ntfs_unix_security: fail
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Rename ExportPolicyRule index
  netapp.ontap.na_ontap_export_policy_rule:
    state: present
    name: default123
    from_rule_index: 100
    rule_index: 99
    client_match: 0.0.0.0/0
    anonymous_user_id: 65521
    ro_rule: ntlm
    rw_rule: any
    protocol: any
    allow_suid: false
    ntfs_unix_security: fail
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete ExportPolicyRule
  netapp.ontap.na_ontap_export_policy_rule:
    state: absent
    name: default123
    rule_index: 99
    vserver: ci_dev
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
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule


class NetAppontapExportRule:
    ''' object initialize and class methods '''

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str', aliases=['policy_name']),
            protocol=dict(required=False,
                          type='list', elements='str', default=None,
                          choices=['any', 'nfs', 'nfs3', 'nfs4', 'cifs', 'flexcache'],
                          aliases=['protocols']),
            client_match=dict(required=False, type='list', elements='str'),
            ro_rule=dict(required=False,
                         type='list', elements='str', default=None,
                         choices=['any', 'none', 'never', 'krb5', 'krb5i', 'krb5p', 'ntlm', 'sys']),
            rw_rule=dict(required=False,
                         type='list', elements='str', default=None,
                         choices=['any', 'none', 'never', 'krb5', 'krb5i', 'krb5p', 'ntlm', 'sys']),
            super_user_security=dict(required=False,
                                     type='list', elements='str', default=None,
                                     choices=['any', 'none', 'krb5', 'krb5i', 'krb5p', 'ntlm', 'sys']),
            allow_suid=dict(required=False, type='bool'),
            from_rule_index=dict(required=False, type='int'),
            rule_index=dict(required=False, type='int'),
            anonymous_user_id=dict(required=False, type='str'),
            vserver=dict(required=True, type='str'),
            ntfs_unix_security=dict(required=False, type='str', choices=['fail', 'ignore']),
            force_delete_on_first_match=dict(required=False, type='bool', default=False),
            chown_mode=dict(required=False, type='str', choices=['restricted', 'unrestricted']),
            allow_device_creation=dict(required=False, type='bool'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.set_playbook_zapi_key_map()
        self.policy_id = None

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        partially_supported_rest_properties = [['ntfs_unix_security', (9, 9, 1)], ['allow_suid', (9, 9, 1)],
                                               ['allow_device_creation', (9, 9, 1)], ['chown_mode', (9, 9, 1)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, None, partially_supported_rest_properties)
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])
        if 'rule_index' not in self.parameters:
            self.fail_on_missing_required_params('matching (as rule_index is not specified) or creating')

    def fail_on_missing_required_params(self, action):
        missing_keys = [key for key in ('client_match', 'ro_rule', 'rw_rule') if self.parameters.get(key) is None]
        plural = 's' if len(missing_keys) > 1 else ''
        if missing_keys:
            self.module.fail_json(msg='Error: Missing required option%s for %s export policy rule: %s' % (plural, action, ', '.join(missing_keys)))

    def set_playbook_zapi_key_map(self):
        self.na_helper.zapi_string_keys = {
            'anonymous_user_id': 'anonymous-user-id',
            'client_match': 'client-match',
            'name': 'policy-name',
            'ntfs_unix_security': 'export-ntfs-unix-security-ops',
            'chown_mode': 'export-chown-mode'
        }
        self.na_helper.zapi_list_keys = {
            'protocol': ('protocol', 'access-protocol'),
            'ro_rule': ('ro-rule', 'security-flavor'),
            'rw_rule': ('rw-rule', 'security-flavor'),
            'super_user_security': ('super-user-security', 'security-flavor'),
        }
        self.na_helper.zapi_bool_keys = {
            'allow_suid': 'is-allow-set-uid-enabled',
            'allow_device_creation': 'is-allow-dev-is-enabled'
        }
        self.na_helper.zapi_int_keys = {
            'rule_index': 'rule-index'
        }

    @staticmethod
    def set_dict_when_not_none(query, key, value):
        if value is not None:
            query[key] = value

    @staticmethod
    def list_to_string(alist):
        return ','.join(alist).replace(' ', '') if alist else ''

    def set_query_parameters(self, rule_index):
        """
        Return dictionary of query parameters and
        :return:
        """
        query = {
            'policy-name': self.parameters['name'],
            'vserver': self.parameters['vserver']
        }
        if rule_index is not None:
            query['rule-index'] = rule_index
        else:
            for item_key, value in self.parameters.items():
                zapi_key = None
                if item_key in self.na_helper.zapi_string_keys and item_key != 'client_match':
                    # ignore client_match as ZAPI query is string based and preserves order
                    zapi_key = self.na_helper.zapi_string_keys[item_key]
                elif item_key in self.na_helper.zapi_bool_keys:
                    zapi_key = self.na_helper.zapi_bool_keys[item_key]
                    value = self.na_helper.get_value_for_bool(from_zapi=False, value=value)
                # skipping int keys to not include rule index in query as we're matching on attributes
                elif item_key in self.na_helper.zapi_list_keys:
                    zapi_key, child_key = self.na_helper.zapi_list_keys[item_key]
                    value = [{child_key: item} for item in value] if value else None
                if zapi_key:
                    self.set_dict_when_not_none(query, zapi_key, value)

        return {
            'query': {
                'export-rule-info': query
            }
        }

    def get_export_policy_rule(self, rule_index):
        """
        Return details about the export policy rule
        If rule_index is None, fetch policy based on attributes
        :param:
            name : Name of the export_policy
        :return: Details about the export_policy. None if not found.
        :rtype: dict
        """
        if self.use_rest:
            return self.get_export_policy_rule_rest(rule_index)
        result = None
        rule_iter = netapp_utils.zapi.NaElement('export-rule-get-iter')
        query = self.set_query_parameters(rule_index)
        rule_iter.translate_struct(query)
        try:
            result = self.server.invoke_successfully(rule_iter, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error getting export policy rule %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if result is not None and result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            if rule_index is None:
                return self.match_export_policy_rule_exactly(result.get_child_by_name('attributes-list').get_children(), query, is_rest=False)
            return self.zapi_export_rule_info_to_dict(result.get_child_by_name('attributes-list').get_child_by_name('export-rule-info'))
        return None

    def zapi_export_rule_info_to_dict(self, rule_info):
        current = {}
        for item_key, zapi_key in self.na_helper.zapi_string_keys.items():
            current[item_key] = rule_info.get_child_content(zapi_key)
            if item_key == 'client_match' and current[item_key]:
                current[item_key] = current[item_key].split(',')
        for item_key, zapi_key in self.na_helper.zapi_bool_keys.items():
            current[item_key] = self.na_helper.get_value_for_bool(from_zapi=True,
                                                                  value=rule_info[zapi_key])
        for item_key, zapi_key in self.na_helper.zapi_int_keys.items():
            current[item_key] = self.na_helper.get_value_for_int(from_zapi=True,
                                                                 value=rule_info[zapi_key])
        for item_key, zapi_key in self.na_helper.zapi_list_keys.items():
            parent, dummy = zapi_key
            current[item_key] = self.na_helper.get_value_for_list(from_zapi=True,
                                                                  zapi_parent=rule_info.get_child_by_name(parent))
        return current

    def set_export_policy_id(self):
        """
        Fetch export-policy id
        :param:
            name : Name of the export-policy

        :return: Set self.policy_id
        """
        if self.policy_id is not None:
            return
        if self.use_rest:
            return self.set_export_policy_id_rest()
        export_policy_iter = netapp_utils.zapi.NaElement('export-policy-get-iter')
        attributes = {
            'query': {
                'export-policy-info': {
                    'policy-name': self.parameters['name'],
                    'vserver': self.parameters['vserver']
                }
            }
        }

        export_policy_iter.translate_struct(attributes)
        try:
            result = self.server.invoke_successfully(export_policy_iter, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error getting export policy %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) == 1:
            self.policy_id = self.na_helper.safe_get(result, ['attributes-list', 'export-policy-info', 'policy-id'])
            if self.policy_id is None:
                self.module.fail_json(msg='Error getting export policy id for %s: got: %s.'
                                      % (self.parameters['name'], result.to_string()))

    def add_parameters_for_create_or_modify(self, na_element_object, params):
        """
            Add children node for create or modify NaElement object
            :param na_element_object: modify or create NaElement object
            :param values: dictionary of cron values to be added
            :return: None
        """
        for key, value in params.items():
            if key in self.na_helper.zapi_string_keys:
                zapi_key = self.na_helper.zapi_string_keys.get(key)
                # convert client_match list to comma-separated string
                if value and key == 'client_match':
                    value = self.list_to_string(value)
            elif key in self.na_helper.zapi_list_keys:
                parent_key, child_key = self.na_helper.zapi_list_keys.get(key)
                value = self.na_helper.get_value_for_list(from_zapi=False, zapi_parent=parent_key, zapi_child=child_key, data=value)
            elif key in self.na_helper.zapi_int_keys:
                zapi_key = self.na_helper.zapi_int_keys.get(key)
                value = self.na_helper.get_value_for_int(from_zapi=False, value=value)
            elif key in self.na_helper.zapi_bool_keys:
                zapi_key = self.na_helper.zapi_bool_keys.get(key)
                value = self.na_helper.get_value_for_bool(from_zapi=False, value=value)
            else:
                # ignore options that are not relevant
                value = None

            if value is not None:
                if key in self.na_helper.zapi_list_keys:
                    na_element_object.add_child_elem(value)
                else:
                    na_element_object[zapi_key] = value

    def create_export_policy_rule(self):
        """
        create rule for the export policy.
        """
        if self.use_rest:
            return self.create_export_policy_rule_rest()
        export_rule_create = netapp_utils.zapi.NaElement('export-rule-create')
        self.add_parameters_for_create_or_modify(export_rule_create, self.parameters)
        try:
            self.server.invoke_successfully(export_rule_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating export policy rule %s: %s'
                                  % (self.parameters['name'], to_native(error)), exception=traceback.format_exc())

    def create_export_policy(self):
        """
        Creates an export policy
        """
        if self.use_rest:
            return self.create_export_policy_rest()
        export_policy_create = netapp_utils.zapi.NaElement.create_node_with_children(
            'export-policy-create', **{'policy-name': self.parameters['name']})
        try:
            self.server.invoke_successfully(export_policy_create,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating export policy %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_export_policy_rule(self, rule_index):
        """
        delete rule for the export policy.
        """
        if self.use_rest:
            return self.delete_export_policy_rule_rest(rule_index)
        export_rule_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'export-rule-destroy', **{'policy-name': self.parameters['name'],
                                      'rule-index': str(rule_index)})

        try:
            self.server.invoke_successfully(export_rule_delete,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting export policy rule %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_export_policy_rule(self, params, rule_index=None, rename=False):
        '''
        Modify an existing export policy rule
        :param params: dict() of attributes with desired values
        :return: None
        '''
        if self.use_rest:
            return self.modify_export_policy_rule_rest(params, rule_index, rename)
        params.pop('rule_index', None)
        if params:
            export_rule_modify = netapp_utils.zapi.NaElement.create_node_with_children(
                'export-rule-modify', **{'policy-name': self.parameters['name'],
                                         'rule-index': str(rule_index)})
            self.add_parameters_for_create_or_modify(export_rule_modify, params)
            try:
                self.server.invoke_successfully(export_rule_modify, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error modifying export policy rule index %s: %s'
                                      % (rule_index, to_native(error)),
                                      exception=traceback.format_exc())
        if rename:
            export_rule_set_index = netapp_utils.zapi.NaElement.create_node_with_children(
                'export-rule-set-index', **{'policy-name': self.parameters['name'],
                                            'rule-index': str(self.parameters['from_rule_index']),
                                            'new-rule-index': str(self.parameters['rule_index'])})
            try:
                self.server.invoke_successfully(export_rule_set_index, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error reindexing export policy rule index %s: %s'
                                          % (self.parameters['from_rule_index'], to_native(error)),
                                      exception=traceback.format_exc())

    def set_export_policy_id_rest(self):
        if self.policy_id is not None:
            return
        options = {'fields': 'name,id',
                   'svm.name': self.parameters['vserver'],
                   'name': self.parameters['name']}
        api = 'protocols/nfs/export-policies'
        record, error = rest_generic.get_one_record(self.rest_api, api, options)
        if error:
            self.module.fail_json(msg="Error on fetching export policy: %s" % error)
        if record:
            self.policy_id = record['id']

    def get_export_policy_rule_exact_match(self, query):
        """ fetch rules based on attributes
            REST queries only allow for one value at a time in a list, so:
            1. get a short list of matches using a simple query
            2. then look for an exact match
        """
        api = 'protocols/nfs/export-policies/%s/rules' % self.policy_id
        query.update(self.create_query(self.parameters))
        records, error = rest_generic.get_0_or_more_records(self.rest_api, api, query)
        if error:
            # If no rule matches the query, return None
            if "entry doesn't exist" in error:
                return None
            self.module.fail_json(msg="Error on fetching export policy rules: %s" % error)
        return self.match_export_policy_rule_exactly(records, query, is_rest=True)

    def match_export_policy_rule_exactly(self, records, query, is_rest):
        if not records:
            return None
        founds = []
        for record in records:
            record = self.filter_get_results(record) if is_rest else self.zapi_export_rule_info_to_dict(record)
            modify = self.na_helper.get_modified_attributes(record, self.parameters)
            modify.pop('rule_index', None)
            if not modify:
                founds.append(record)
        if founds and len(founds) > 1 and not (self.parameters['state'] == 'absent' and self.parameters['force_delete_on_first_match']):
            self.module.fail_json(msg='Error multiple records exist for query: %s.  Specify index to modify or delete a rule.  Found: %s'
                                  % (query, founds))
        return founds[0] if founds else None

    def get_export_policy_rule_rest(self, rule_index):
        self.set_export_policy_id_rest()
        if not self.policy_id:
            return None
        query = {'fields': 'anonymous_user,clients,index,protocols,ro_rule,rw_rule,superuser'}
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9, 1):
            query['fields'] += ',ntfs_unix_security,allow_suid,chown_mode,allow_device_creation'
        if rule_index is None:
            return self.get_export_policy_rule_exact_match(query)
        api = 'protocols/nfs/export-policies/%s/rules/%s' % (self.policy_id, rule_index)
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            # If rule index passed in doesn't exist, return None
            if "entry doesn't exist" in error:
                return None
            self.module.fail_json(msg="Error on fetching export policy rule: %s" % error)
        return self.filter_get_results(record) if record else None

    def filter_get_results(self, record):
        record['rule_index'] = record.pop('index')
        record['anonymous_user_id'] = record.pop('anonymous_user')
        record['protocol'] = record.pop('protocols')
        record['super_user_security'] = record.pop('superuser')
        record['client_match'] = [each['match'] for each in record['clients']]
        record.pop('clients')
        return record

    def create_export_policy_rest(self):
        body = {'name': self.parameters['name'], 'svm.name': self.parameters['vserver']}
        api = 'protocols/nfs/export-policies'
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error is not None:
            self.module.fail_json(msg="Error on creating export policy: %s" % error)

    def create_export_policy_rule_rest(self):
        api = 'protocols/nfs/export-policies/%s/rules?return_records=true' % self.policy_id
        response, error = rest_generic.post_async(self.rest_api, api, self.create_body(self.parameters))
        if error:
            self.module.fail_json(msg="Error on creating export policy rule: %s" % error)
        # force a 'rename' to set the index
        rule_index = None
        if response and response.get('num_records') == 1:
            rule_index = self.na_helper.safe_get(response, ['records', 0, 'index'])
        if rule_index is None:
            self.module.fail_json(msg="Error on creating export policy rule, returned response is invalid: %s" % response)
        if self.parameters.get('rule_index'):
            self.modify_export_policy_rule_rest({}, rule_index, True)

    def client_match_format(self, client_match):
        return [{'match': each} for each in client_match]

    def delete_export_policy_rule_rest(self, rule_index):
        api = 'protocols/nfs/export-policies/%s/rules' % self.policy_id
        dummy, error = rest_generic. delete_async(self.rest_api, api, rule_index)
        if error:
            self.module.fail_json(msg="Error on deleting export policy Rule: %s" % error)

    def create_body(self, params):
        body = self.create_body_or_query_common(params)
        # lists
        if params.get('protocol'):
            body['protocols'] = self.parameters['protocol']
        if params.get('super_user_security'):
            body['superuser'] = self.parameters['super_user_security']
        if params.get('client_match'):
            body['clients'] = self.client_match_format(self.parameters['client_match'])
        if params.get('ro_rule'):
            body['ro_rule'] = self.parameters['ro_rule']
        if params.get('rw_rule'):
            body['rw_rule'] = self.parameters['rw_rule']
        return body

    def create_query(self, params):
        query = self.create_body_or_query_common(params)
        # for list, do an initial query based on first element
        if params.get('protocol'):
            query['protocols'] = self.parameters['protocol'][0]
        if params.get('super_user_security'):
            query['superuser'] = self.parameters['super_user_security'][0]
        if params.get('client_match'):
            query['clients.match'] = self.parameters['client_match'][0]
        if params.get('ro_rule'):
            query['ro_rule'] = self.parameters['ro_rule'][0]
        if params.get('rw_rule'):
            query['rw_rule'] = self.parameters['rw_rule'][0]
        return query

    def create_body_or_query_common(self, params):
        result = {}
        if params.get('anonymous_user_id') is not None:
            result['anonymous_user'] = self.parameters['anonymous_user_id']
        if params.get('ntfs_unix_security') is not None:
            result['ntfs_unix_security'] = self.parameters['ntfs_unix_security']
        if params.get('allow_suid') is not None:
            result['allow_suid'] = self.parameters['allow_suid']
        if params.get('chown_mode') is not None:
            result['chown_mode'] = self.parameters['chown_mode']
        if params.get('allow_device_creation') is not None:
            result['allow_device_creation'] = self.parameters['allow_device_creation']
        return result

    def modify_export_policy_rule_rest(self, params, rule_index, rename=False):
        api = 'protocols/nfs/export-policies/%s/rules' % self.policy_id
        query = {'new_index': self.parameters['rule_index']} if rename else None
        dummy, error = rest_generic.patch_async(self.rest_api, api, rule_index, self.create_body(params), query)

        if error:
            self.module.fail_json(msg="Error on modifying export policy Rule: %s" % error)

    def apply(self):
        ''' Apply required action from the play'''
        current = self.get_export_policy_rule(self.parameters.get('rule_index'))
        cd_action, rename, modify = None, None, None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        # if rule_index is not None, see if we need to re-index an existing rule
        # the existing rule may be indexed by from_rule_index or we can match the attributes
        if cd_action == 'create' and self.parameters.get('rule_index'):
            from_current = self.get_export_policy_rule(self.parameters.get('from_rule_index'))
            rename = self.na_helper.is_rename_action(from_current, current)
            if rename is None and self.parameters.get('from_rule_index') is not None:
                self.module.fail_json(
                    msg="Error reindexing: export policy rule %s does not exist." % self.parameters['from_rule_index'])
            if rename:
                current = from_current
                cd_action = None
                self.parameters['from_rule_index'] = current['rule_index']

        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed:
            self.set_export_policy_id()
            if cd_action == 'create':
                self.fail_on_missing_required_params('creating')

        if self.na_helper.changed and not self.module.check_mode:
            # create export policy (if policy doesn't exist) only when changed=True
            if rename:
                self.modify_export_policy_rule(modify, self.parameters['from_rule_index'], rename=True)
            elif cd_action == 'create':
                if not self.policy_id:
                    self.create_export_policy()
                    self.set_export_policy_id()
                self.create_export_policy_rule()
            elif cd_action == 'delete':
                self.delete_export_policy_rule(current['rule_index'])
            elif modify:
                self.modify_export_policy_rule(modify, current['rule_index'])

        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    ''' Create object and call apply '''
    rule_obj = NetAppontapExportRule()
    rule_obj.apply()


if __name__ == '__main__':
    main()
