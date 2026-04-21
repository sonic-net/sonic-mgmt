#!/usr/bin/python
"""
create Autosupport module to enable, disable or modify
"""

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_autosupport
short_description: NetApp ONTAP autosupport
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
version_added: 2.7.0
description:
  - Enable/Disable Autosupport
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
options:
  state:
    description:
      - Specifies whether the AutoSupport daemon is to be enabled or disabled.
      - When this setting is absent, delivery of all AutoSupport messages is turned off.
    choices: ['present', 'absent']
    type: str
    default: present
  node_name:
    description:
      - The name of the filer that owns the AutoSupport Configuration.
      - Supported only with ZAPI.
    type: str
  transport:
    description:
      - The name of the transport protocol used to deliver AutoSupport messages.
    choices: ['http', 'https', 'smtp']
    type: str
  noteto:
    description:
      - Specifies up to five recipients of short AutoSupport e-mail messages.
      - Supported only with ZAPI.
    type: list
    elements: str
  post_url:
    description:
      - The URL used to deliver AutoSupport messages via HTTP POST.
      - Supported only with ZAPI.
    type: str
  mail_hosts:
    description:
      - List of mail server(s) used to deliver AutoSupport messages via SMTP.
      - Both host names and IP addresses may be used as valid input.
    type: list
    elements: str
  support:
    description:
      - Specifies whether AutoSupport notification to technical support is enabled.
    type: bool
  from_address:
    description:
      - specify the e-mail address from which the node sends AutoSupport messages.
    version_added: 2.8.0
    type: str
  partner_addresses:
    description:
      - Specifies up to five partner vendor recipients of full AutoSupport e-mail messages.
    version_added: 2.8.0
    type: list
    elements: str
  to_addresses:
    description:
      - Specifies up to five recipients of full AutoSupport e-mail messages.
    version_added: 2.8.0
    type: list
    elements: str
  proxy_url:
    description:
      - specify an HTTP or HTTPS proxy if the 'transport' parameter is set to HTTP or HTTPS and your organization uses a proxy.
      - If authentication is required, use the format "username:password@host:port".
    version_added: 2.8.0
    type: str
  hostname_in_subject:
    description:
      - Specify whether the hostname of the node is included in the subject line of the AutoSupport message.
      - Supported only with ZAPI.
    type: bool
    version_added: 2.8.0
  nht_data_enabled:
    description:
      - Specify whether the disk health data is collected as part of the AutoSupport data.
      - Supported only with ZAPI.
    type: bool
    version_added: '21.5.0'
  perf_data_enabled:
    description:
      - Specify whether the performance data is collected as part of the AutoSupport data.
      - Supported only with ZAPI.
    type: bool
    version_added: '21.5.0'
  retry_count:
    description:
      - Specify the maximum number of delivery attempts for an AutoSupport message.
      - Supported only with ZAPI.
    type: int
    version_added: '21.5.0'
  reminder_enabled:
    description:
      - Specify whether AutoSupport reminders are enabled or disabled.
      - Supported only with ZAPI.
    type: bool
    version_added: '21.5.0'
  max_http_size:
    description:
      - Specify delivery size limit for the HTTP transport protocol (in bytes).
      - Supported only with ZAPI.
    type: int
    version_added: '21.5.0'
  max_smtp_size:
    description:
      - Specify delivery size limit for the SMTP transport protocol (in bytes).
      - Supported only with ZAPI.
    type: int
    version_added: '21.5.0'
  private_data_removed:
    description:
      - Specify the removal of customer-supplied data.
      - Supported only with ZAPI.
    type: bool
    version_added: '21.5.0'
  local_collection_enabled:
    description:
      - Specify whether collection of AutoSupport data when the AutoSupport daemon is disabled.
      - Supported only with ZAPI.
    type: bool
    version_added: '21.5.0'
  ondemand_enabled:
    description:
      - Specify whether the AutoSupport OnDemand Download feature is enabled.
    type: bool
    version_added: '21.5.0'
  validate_digital_certificate:
    description:
      - When set to true each node will validate the digital certificates that it receives.
      - Supported only with ZAPI.
    type: bool
    version_added: '21.5.0'
  is_minimal:
    description:
      - Specifies whether the system information is collected in compliant form, to remove private data or in complete form, to enhance diagnostics.
      - Supported only with REST.
    type: bool
    version_added: '23.2.0'
  smtp_encryption:
    description:
      - The encryption protocol used to deliver AutoSupport messages via SMTP to the configured mail_hosts.
      - Supported only with REST.
    choices: ['none', 'start_tls']
    type: str
    version_added: '23.2.0'
  force:
    description:
      - Set the force flag to true to modify some of the AutoSupport configurations that are otherwise blocked when the automatic update feature is enabled.
      - Without this flag set to true, an attempt to disable AutoSupport, modify the transport to SMTP,
        or disable the AutoSupport OnDemand feature fails if the automatic update feature is enabled.
    type: bool
    version_added: '23.2.0'
    """

EXAMPLES = """
- name: Enable autosupport - ZAPI
  netapp.ontap.na_ontap_autosupport:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    state: present
    node_name: test
    transport: https
    noteto: abc@def.com,def@ghi.com
    mail_hosts: 1.2.3.4,5.6.7.8
    support: false
    post_url: url/1.0/post

- name: Modify autosupport proxy_url with password - ZAPI
  netapp.ontap.na_ontap_autosupport:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    state: present
    node_name: test
    transport: https
    proxy_url: username:password@host.com:8000

- name: Modify autosupport proxy_url without password - ZAPI
  netapp.ontap.na_ontap_autosupport:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    state: present
    node_name: test
    transport: https
    proxy_url: username@host.com:8000

- name: Disable autosupport - ZAPI
  netapp.ontap.na_ontap_autosupport:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    state: absent
    node_name: test

- name: Enable autosupport - REST
  netapp.ontap.na_ontap_autosupport:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    transport: https
    mail_hosts: 1.2.3.4,5.6.7.8
    proxy_url: proxyhost.local.com
    to_addresses: rst@xyz.com
    from_address: testmail1@abc.com
    ondemand_enabled: true
    support: true
    state: present
    force: true
    is_minimal: true
    smtp_encryption: none
    partner_addresses: test2@xyz.com

- name: Modify autosupport - REST
  netapp.ontap.na_ontap_autosupport:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    transport: smtp
    mail_hosts: 1.2.3.4:25
    proxy_url: proxyhost.local.com
    to_addresses: rst@xyz.com,mymail@abc.com
    from_address: testmail@abc.com
    ondemand_enabled: false
    support: false
    state: present
    is_minimal: false
    smtp_encryption: start_tls
    partner_addresses: test1@xyz.com
    force: true

- name: Disable autosupport - REST
  netapp.ontap.na_ontap_autosupport:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    state: absent
"""

RETURN = """
"""
import re
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppONTAPasup:
    """Class with autosupport methods"""

    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            node_name=dict(required=False, type='str'),
            transport=dict(required=False, type='str', choices=['smtp', 'http', 'https']),
            noteto=dict(required=False, type='list', elements='str'),
            post_url=dict(required=False, type='str'),
            support=dict(required=False, type='bool'),
            mail_hosts=dict(required=False, type='list', elements='str'),
            from_address=dict(required=False, type='str'),
            partner_addresses=dict(required=False, type='list', elements='str'),
            to_addresses=dict(required=False, type='list', elements='str'),
            # proxy_url may contain a password: user:password@url
            proxy_url=dict(required=False, type='str', no_log=True),
            hostname_in_subject=dict(required=False, type='bool'),
            nht_data_enabled=dict(required=False, type='bool'),
            perf_data_enabled=dict(required=False, type='bool'),
            retry_count=dict(required=False, type='int'),
            reminder_enabled=dict(required=False, type='bool'),
            max_http_size=dict(required=False, type='int'),
            max_smtp_size=dict(required=False, type='int'),
            private_data_removed=dict(required=False, type='bool'),
            local_collection_enabled=dict(required=False, type='bool'),
            ondemand_enabled=dict(required=False, type='bool'),
            validate_digital_certificate=dict(required=False, type='bool'),
            is_minimal=dict(required=False, type='bool'),
            smtp_encryption=dict(required=False, type='str', choices=['none', 'start_tls']),
            force=dict(required=False, type='bool'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        if 'state' in self.parameters:
            if self.parameters.get('state') == 'present':
                self.parameters['enabled'] = True
            else:
                self.parameters['enabled'] = False
            # present or absent requires modifying state to enabled or disabled
            if 'enabled' in self.parameters:
                self.parameters['service_state'] = 'started' if self.parameters.get('enabled') is True else 'stopped'
        self.set_playbook_zapi_key_map()

        self.rest_api = OntapRestAPI(self.module)
        unsupported_rest_properties = ['node_name', 'retry_count', 'max_http_size', 'max_smtp_size',
                                       'noteto', 'hostname_in_subject', 'nht_data_enabled',
                                       'perf_data_enabled', 'reminder_enabled', 'private_data_removed',
                                       'local_collection_enabled', 'validate_digital_certificate']
        partially_supported_rest_properties = [['smtp_encryption', (9, 15, 1)], ['ondemand_enabled', (9, 16, 1)], ['force', (9, 16, 1)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties, partially_supported_rest_properties)
        unsupported_zapi_properties = ['smtp_encryption', 'is_minimal', 'force']

        if not self.use_rest:
            if netapp_utils.has_netapp_lib() is False:
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            if 'node_name' not in self.parameters:
                self.module.fail_json(msg="Error: The option 'node_name' is required when using ZAPI.")
            used_unsupported_zapi_properties = [option for option in unsupported_zapi_properties if option in self.parameters]
            if used_unsupported_zapi_properties:
                self.module.fail_json(msg="Error: %s options supported only with REST." % ", ".join(used_unsupported_zapi_properties))
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def set_playbook_zapi_key_map(self):
        self.na_helper.zapi_string_keys = {
            'node_name': 'node-name',
            'transport': 'transport',
            'post_url': 'post-url',
            'from_address': 'from',
            'proxy_url': 'proxy-url'
        }
        self.na_helper.zapi_int_keys = {
            'retry_count': 'retry-count',
            'max_http_size': 'max-http-size',
            'max_smtp_size': 'max-smtp-size'
        }
        self.na_helper.zapi_list_keys = {
            'noteto': ('noteto', 'mail-address'),
            'mail_hosts': ('mail-hosts', 'string'),
            'partner_addresses': ('partner-address', 'mail-address'),
            'to_addresses': ('to', 'mail-address')
        }
        self.na_helper.zapi_bool_keys = {
            'support': 'is-support-enabled',
            'hostname_in_subject': 'is-node-in-subject',
            'nht_data_enabled': 'is-nht-data-enabled',
            'perf_data_enabled': 'is-perf-data-enabled',
            'reminder_enabled': 'is-reminder-enabled',
            'private_data_removed': 'is-private-data-removed',
            'local_collection_enabled': 'is-local-collection-enabled',
            'ondemand_enabled': 'is-ondemand-enabled',
            'validate_digital_certificate': 'validate-digital-certificate'
        }

    def get_autosupport_config(self):
        """
        get current autosupport details
        :return: dict()
        """
        asup_info = {}
        if self.use_rest:
            api = "support/autosupport"
            query = {
                'fields': 'transport,mail_hosts,proxy_url,partner_addresses,to,is_minimal,from,contact_support,enabled,'
            }
            if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 15, 1):
                query['fields'] += 'smtp_encryption,'
            if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 16, 1):
                query['fields'] += 'ondemand_enabled,'
            record, error = rest_generic.get_one_record(self.rest_api, api, query)
            if error:
                self.module.fail_json(msg='Error fetching auto support configuration info: %s' % error)
            if record:
                return {
                    'transport': self.na_helper.safe_get(record, ['transport']),
                    'mail_hosts': self.na_helper.safe_get(record, ['mail_hosts']),
                    'smtp_encryption': self.na_helper.safe_get(record, ['smtp_encryption']),
                    'proxy_url': self.na_helper.safe_get(record, ['proxy_url']),
                    'partner_addresses': record['partner_addresses'] if 'partner_addresses' in record else list(),
                    'to_addresses': record['to'] if 'to' in record else list(),
                    'is_minimal': record['is_minimal'] in ['enable', True] if 'is_minimal' in record else False,
                    'from_address': record['from'] if 'from' in record else "",
                    'ondemand_enabled': record['ondemand_enabled'] in ['enable', True] if 'ondemand_enabled' in record else False,
                    'support': record['contact_support'] in ['enable', True] if 'contact_support' in record else False,
                    'enabled': record['enabled'] in ['enable', True] if 'enabled' in record else False,
                }
            return record
        else:
            asup_details = netapp_utils.zapi.NaElement('autosupport-config-get')
            asup_details.add_new_child('node-name', self.parameters['node_name'])
            try:
                result = self.server.invoke_successfully(asup_details, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error fetching info: %s' % to_native(error), exception=traceback.format_exc())
            # zapi invoke successful
            asup_attr_info = result.get_child_by_name('attributes').get_child_by_name('autosupport-config-info')
            asup_info['service_state'] = 'started' if asup_attr_info['is-enabled'] == 'true' else 'stopped'
            for item_key, zapi_key in self.na_helper.zapi_string_keys.items():
                value = asup_attr_info.get_child_content(zapi_key)
                asup_info[item_key] = value if value is not None else ""
            for item_key, zapi_key in self.na_helper.zapi_int_keys.items():
                value = asup_attr_info.get_child_content(zapi_key)
                if value is not None:
                    asup_info[item_key] = self.na_helper.get_value_for_int(from_zapi=True, value=value)
            for item_key, zapi_key in self.na_helper.zapi_bool_keys.items():
                value = asup_attr_info.get_child_content(zapi_key)
                if value is not None:
                    asup_info[item_key] = self.na_helper.get_value_for_bool(from_zapi=True, value=value)
            for item_key, zapi_key in self.na_helper.zapi_list_keys.items():
                parent, dummy = zapi_key
                asup_info[item_key] = self.na_helper.get_value_for_list(from_zapi=True, zapi_parent=asup_attr_info.get_child_by_name(parent))
        return asup_info

    def modify_autosupport_config(self, modify):
        """
        modify autosupport config
        @return: modfied attributes / FAILURE with an error_message
        """

        if self.use_rest:
            api = "support/autosupport"
            body = {}
            query = {}
            if 'transport' in modify:
                body['transport'] = modify['transport']
            if 'mail_hosts' in modify:
                body['mail_hosts'] = modify['mail_hosts']
            if 'smtp_encryption' in modify:
                body['smtp_encryption'] = modify['smtp_encryption']
            if 'proxy_url' in modify:
                body['proxy_url'] = modify['proxy_url']
            if 'partner_addresses' in modify:
                body['partner_addresses'] = modify['partner_addresses']
            if 'from_address' in modify:
                body['from'] = modify.pop('from_address')
            if 'to_addresses' in modify:
                body['to'] = modify.pop('to_addresses')
            if 'ondemand_enabled' in modify:
                body['ondemand_enabled'] = modify['ondemand_enabled']
            if 'is_minimal' in modify:
                body['is_minimal'] = modify['is_minimal']
            if 'support' in modify:
                body['contact_support'] = modify['support']
            if 'enabled' in modify:
                body['enabled'] = modify['enabled']
            if 'force' in self.parameters:
                query['force'] = self.parameters.get('force')
            dummy, error = rest_generic.patch_async(self.rest_api, api, None, body, query)

            if error:
                self.module.fail_json(msg='Error modifying auto support configuration: %s' % error)
        else:
            asup_details = {'node-name': self.parameters['node_name']}
            if modify.get('service_state'):
                asup_details['is-enabled'] = 'true' if modify.get('service_state') == 'started' else 'false'
            asup_config = netapp_utils.zapi.NaElement('autosupport-config-modify')
            for item_key in modify:
                if item_key in self.na_helper.zapi_string_keys:
                    zapi_key = self.na_helper.zapi_string_keys.get(item_key)
                    asup_details[zapi_key] = modify[item_key]
                elif item_key in self.na_helper.zapi_int_keys:
                    zapi_key = self.na_helper.zapi_int_keys.get(item_key)
                    asup_details[zapi_key] = modify[item_key]
                elif item_key in self.na_helper.zapi_bool_keys:
                    zapi_key = self.na_helper.zapi_bool_keys.get(item_key)
                    asup_details[zapi_key] = self.na_helper.get_value_for_bool(from_zapi=False, value=modify[item_key])
                elif item_key in self.na_helper.zapi_list_keys:
                    parent_key, child_key = self.na_helper.zapi_list_keys.get(item_key)
                    asup_config.add_child_elem(self.na_helper.get_value_for_list(
                        from_zapi=False, zapi_parent=parent_key, zapi_child=child_key, data=modify.get(item_key)))

            asup_config.translate_struct(asup_details)
            try:
                return self.server.invoke_successfully(asup_config, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error modifying asup: %s' % to_native(error), exception=traceback.format_exc())

    @staticmethod
    def strip_password(url):
        ''' if url matches user:password@address return user@address
            otherwise return None
        '''
        if url:
            needle = r'(.*):(.*)@(.*)'
            matched = re.match(needle, url)
            if matched:
                return matched.group(1, 3)
        return None, None

    def idempotency_check(self, current, modify):
        sanitized_modify = dict(modify)
        if 'proxy_url' in modify:
            user_url_m = self.strip_password(modify['proxy_url'])
            user_url_c = self.strip_password(current.get('proxy_url'))
            if user_url_m == user_url_c and user_url_m != (None, None):
                # change in password, it can be a false positive as password is replaced with ********* by ONTAP
                self.module.warn('na_ontap_autosupport is not idempotent because the password value in proxy_url cannot be compared.')
            if user_url_m != (None, None):
                # password was found in proxy_url, sanitize it, use something different than ZAPI *********
                sanitized_modify['proxy_url'] = "%s:XXXXXXXX@%s" % user_url_m
        return sanitized_modify

    def apply(self):
        """
        Apply action to autosupport
        """
        current = self.get_autosupport_config()
        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        sanitized_modify = self.idempotency_check(current, modify)
        if self.na_helper.changed and not self.module.check_mode:
            self.modify_autosupport_config(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, modify=sanitized_modify)
        self.module.exit_json(**result)


def main():
    """Execute action"""
    asup_obj = NetAppONTAPasup()
    asup_obj.apply()


if __name__ == '__main__':
    main()
