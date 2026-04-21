#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = '''
---
module: na_ontap_vserver_cifs_security
short_description: NetApp ONTAP vserver CIFS security modification
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_zapi
version_added: 2.9.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
    - modify vserver CIFS security.

options:

  vserver:
    description:
    - name of the vserver.
    required: true
    type: str

  kerberos_clock_skew:
    description:
    - The clock skew in minutes is the tolerance for accepting tickets with time stamps that do not exactly match the host's system clock.
    type: int

  kerberos_ticket_age:
    description:
    - Determine the maximum amount of time in hours that a user's ticket may be used for the purpose of Kerberos authentication.
    type: int

  kerberos_renew_age:
    description:
    - Determine the maximum amount of time in days for which a ticket can be renewed.
    type: int

  kerberos_kdc_timeout:
    description:
    - Determine the timeout value in seconds for KDC connections.
    type: int

  is_signing_required:
    description:
    - Determine whether signing is required for incoming CIFS traffic.
    type: bool

  is_password_complexity_required:
    description:
    - Determine whether password complexity is required for local users.
    type: bool

  is_aes_encryption_enabled:
    description:
    - Determine whether AES-128 and AES-256 encryption mechanisms are enabled for Kerberos-related CIFS communication.
    type: bool

  is_smb_encryption_required:
    description:
    - Determine whether SMB encryption is required for incoming CIFS traffic.
    type: bool

  lm_compatibility_level:
    description:
    - Determine the LM compatibility level.
    choices: ['lm_ntlm_ntlmv2_krb', 'ntlm_ntlmv2_krb', 'ntlmv2_krb', 'krb']
    type: str

  referral_enabled_for_ad_ldap:
    description:
    - Determine whether LDAP referral chasing is enabled or not for AD LDAP connections.
    type: bool

  session_security_for_ad_ldap:
    description:
    - Determine the level of security required for LDAP communications.
    choices: ['none', 'sign', 'seal']
    type: str

  smb1_enabled_for_dc_connections:
    description:
    - Determine if SMB version 1 is used for connections to domain controllers.
    choices: ['false', 'true', 'system_default']
    type: str

  smb2_enabled_for_dc_connections:
    description:
    - Determine if SMB version 2 is used for connections to domain controllers.
    choices: ['false', 'true', 'system_default']
    type: str

  use_start_tls_for_ad_ldap:
    description:
    - Determine whether to use start_tls for AD LDAP connections.
    type: bool

  encryption_required_for_dc_connections:
    description:
    - Specifies whether encryption is required for domain controller connections.
    type: bool
    version_added: 21.20.0

  use_ldaps_for_ad_ldap:
    description:
    - Determine whether to use LDAPS for secure Active Directory LDAP connections.
    type: bool
    version_added: 21.20.0

'''

EXAMPLES = '''
- name: Modify cifs security
  netapp.ontap.na_ontap_vserver_cifs_security:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    vserver: ansible
    is_aes_encryption_enabled: false
    lm_compatibility_level: lm_ntlm_ntlmv2_krb
    smb1_enabled_for_dc_connections: system_default
    smb2_enabled_for_dc_connections: system_default
    use_start_tls_for_ad_ldap: false
    referral_enabled_for_ad_ldap: false
    session_security_for_ad_ldap: none
    is_signing_required: false
    is_password_complexity_required: false
    encryption_required_for_dc_connections: false
    use_ldaps_for_ad_ldap: false

- name: modify cifs security is_smb_encryption_required
  netapp.ontap.na_ontap_vserver_cifs_security:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    vserver: ansible
    is_smb_encryption_required: false

- name: modify cifs security int options
  netapp.ontap.na_ontap_vserver_cifs_security:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    vserver: ansible
    kerberos_clock_skew: 10
    kerberos_ticket_age: 10
    kerberos_renew_age: 5
    kerberos_kdc_timeout: 3
'''

RETURN = '''
'''

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule


class NetAppONTAPCifsSecurity(object):
    '''
    modify vserver cifs security
    '''
    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_zapi_only_spec()
        self.argument_spec.update(dict(
            vserver=dict(required=True, type='str'),
            kerberos_clock_skew=dict(required=False, type='int'),
            kerberos_ticket_age=dict(required=False, type='int'),
            kerberos_renew_age=dict(required=False, type='int'),
            kerberos_kdc_timeout=dict(required=False, type='int'),
            is_signing_required=dict(required=False, type='bool'),
            is_password_complexity_required=dict(required=False, type='bool'),
            is_aes_encryption_enabled=dict(required=False, type='bool'),
            is_smb_encryption_required=dict(required=False, type='bool'),
            lm_compatibility_level=dict(required=False, choices=['lm_ntlm_ntlmv2_krb', 'ntlm_ntlmv2_krb', 'ntlmv2_krb', 'krb']),
            referral_enabled_for_ad_ldap=dict(required=False, type='bool'),
            session_security_for_ad_ldap=dict(required=False, choices=['none', 'sign', 'seal']),
            smb1_enabled_for_dc_connections=dict(required=False, choices=['false', 'true', 'system_default']),
            smb2_enabled_for_dc_connections=dict(required=False, choices=['false', 'true', 'system_default']),
            use_start_tls_for_ad_ldap=dict(required=False, type='bool'),
            encryption_required_for_dc_connections=dict(required=False, type='bool'),
            use_ldaps_for_ad_ldap=dict(required=False, type='bool')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
            mutually_exclusive=[('use_ldaps_for_ad_ldap', 'use_start_tls_for_ad_ldap')]
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.na_helper.module_replaces('na_ontap_cifs_server', self.module)
        msg = 'The module only supports ZAPI; refer to netapp.ontap.na_ontap_cifs_server module for RESTful equivalent.'
        self.na_helper.fall_back_to_zapi(self.module, msg, self.parameters)

        self.set_playbook_zapi_key_map()
        if not netapp_utils.has_netapp_lib():
            self.module.fail_json(msg="the python NetApp-Lib module is required")
        else:
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def set_playbook_zapi_key_map(self):

        self.na_helper.zapi_int_keys = {
            'kerberos_clock_skew': 'kerberos-clock-skew',
            'kerberos_ticket_age': 'kerberos-ticket-age',
            'kerberos_renew_age': 'kerberos-renew-age',
            'kerberos_kdc_timeout': 'kerberos-kdc-timeout'
        }
        self.na_helper.zapi_bool_keys = {
            'is_signing_required': 'is-signing-required',
            'is_password_complexity_required': 'is-password-complexity-required',
            'is_aes_encryption_enabled': 'is-aes-encryption-enabled',
            'is_smb_encryption_required': 'is-smb-encryption-required',
            'referral_enabled_for_ad_ldap': 'referral-enabled-for-ad-ldap',
            'use_start_tls_for_ad_ldap': 'use-start-tls-for-ad-ldap',
            'encryption_required_for_dc_connections': 'encryption-required-for-dc-connections',
            'use_ldaps_for_ad_ldap': 'use-ldaps-for-ad-ldap'
        }
        self.na_helper.zapi_str_keys = {
            'lm_compatibility_level': 'lm-compatibility-level',
            'session_security_for_ad_ldap': 'session-security-for-ad-ldap',
            'smb1_enabled_for_dc_connections': 'smb1-enabled-for-dc-connections',
            'smb2_enabled_for_dc_connections': 'smb2-enabled-for-dc-connections'
        }

    def cifs_security_get_iter(self):
        """
        get current vserver cifs security.
        :return: a dict of vserver cifs security
        """
        cifs_security_get = netapp_utils.zapi.NaElement('cifs-security-get-iter')
        query = netapp_utils.zapi.NaElement('query')
        cifs_security = netapp_utils.zapi.NaElement('cifs-security')
        cifs_security.add_new_child('vserver', self.parameters['vserver'])
        query.add_child_elem(cifs_security)
        cifs_security_get.add_child_elem(query)
        cifs_security_details = dict()
        try:
            result = self.server.invoke_successfully(cifs_security_get, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching cifs security from %s: %s'
                                      % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) > 0:
            cifs_security_info = result.get_child_by_name('attributes-list').get_child_by_name('cifs-security')
            for option, zapi_key in self.na_helper.zapi_int_keys.items():
                cifs_security_details[option] = self.na_helper.get_value_for_int(from_zapi=True, value=cifs_security_info.get_child_content(zapi_key))
            for option, zapi_key in self.na_helper.zapi_bool_keys.items():
                cifs_security_details[option] = self.na_helper.get_value_for_bool(from_zapi=True, value=cifs_security_info.get_child_content(zapi_key))
            for option, zapi_key in self.na_helper.zapi_str_keys.items():
                if cifs_security_info.get_child_content(zapi_key) is None:
                    cifs_security_details[option] = None
                else:
                    cifs_security_details[option] = cifs_security_info.get_child_content(zapi_key)
            return cifs_security_details
        return None

    def cifs_security_modify(self, modify):
        """
        :param modify: A list of attributes to modify
        :return: None
        """
        cifs_security_modify = netapp_utils.zapi.NaElement('cifs-security-modify')
        for attribute in modify:
            cifs_security_modify.add_new_child(self.attribute_to_name(attribute), str(self.parameters[attribute]))
        try:
            self.server.invoke_successfully(cifs_security_modify, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as e:
            self.module.fail_json(msg='Error modifying cifs security on %s: %s'
                                  % (self.parameters['vserver'], to_native(e)),
                                  exception=traceback.format_exc())

    @staticmethod
    def attribute_to_name(attribute):
        return str.replace(attribute, '_', '-')

    def apply(self):
        """Call modify operations."""
        current = self.cifs_security_get_iter()
        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if modify:
                    self.cifs_security_modify(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, modify=modify)
        self.module.exit_json(**result)


def main():
    obj = NetAppONTAPCifsSecurity()
    obj.apply()


if __name__ == '__main__':
    main()
