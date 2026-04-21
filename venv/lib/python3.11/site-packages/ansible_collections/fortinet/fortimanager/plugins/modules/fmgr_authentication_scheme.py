#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_authentication_scheme
short_description: Configure Authentication Schemes.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    authentication_scheme:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            domain_controller:
                aliases: ['domain-controller']
                type: str
                description: Domain controller setting.
            fsso_agent_for_ntlm:
                aliases: ['fsso-agent-for-ntlm']
                type: str
                description: FSSO agent to use for NTLM authentication.
            fsso_guest:
                aliases: ['fsso-guest']
                type: str
                description: Enable/disable user fsso-guest authentication
                choices:
                    - 'disable'
                    - 'enable'
            kerberos_keytab:
                aliases: ['kerberos-keytab']
                type: str
                description: Kerberos keytab setting.
            method:
                type: list
                elements: str
                description: Authentication methods
                choices:
                    - 'ntlm'
                    - 'basic'
                    - 'digest'
                    - 'form'
                    - 'negotiate'
                    - 'fsso'
                    - 'rsso'
                    - 'ssh-publickey'
                    - 'saml'
                    - 'cert'
                    - 'x-auth-user'
                    - 'saml-sp'
                    - 'entra-sso'
            name:
                type: str
                description: Authentication scheme name.
                required: true
            negotiate_ntlm:
                aliases: ['negotiate-ntlm']
                type: str
                description: Enable/disable negotiate authentication for NTLM
                choices:
                    - 'disable'
                    - 'enable'
            require_tfa:
                aliases: ['require-tfa']
                type: str
                description: Enable/disable two-factor authentication
                choices:
                    - 'disable'
                    - 'enable'
            ssh_ca:
                aliases: ['ssh-ca']
                type: str
                description: SSH CA name.
            user_database:
                aliases: ['user-database']
                type: raw
                description: (list or str) Authentication server to contain user information; local
            ems_device_owner:
                aliases: ['ems-device-owner']
                type: str
                description: Enable/disable SSH public-key authentication with device owner
                choices:
                    - 'disable'
                    - 'enable'
            saml_server:
                aliases: ['saml-server']
                type: str
                description: SAML configuration.
            saml_timeout:
                aliases: ['saml-timeout']
                type: int
                description: SAML authentication timeout in seconds.
            user_cert:
                aliases: ['user-cert']
                type: str
                description: Enable/disable authentication with user certificate
                choices:
                    - 'disable'
                    - 'enable'
            external_idp:
                aliases: ['external-idp']
                type: raw
                description: (list) External identity provider configuration.
            digest_algo:
                aliases: ['digest-algo']
                type: list
                elements: str
                description: Digest Authentication Algorithms.
                choices:
                    - 'md5'
                    - 'sha-256'
            group_attr_type:
                aliases: ['group-attr-type']
                type: str
                description: Group attribute type used to match SCIM groups
                choices:
                    - 'display-name'
                    - 'external-id'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure Authentication Schemes.
      fortinet.fortimanager.fmgr_authentication_scheme:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        authentication_scheme:
          name: "your value" # Required variable, string
          # domain_controller: <string>
          # fsso_agent_for_ntlm: <string>
          # fsso_guest: <value in [disable, enable]>
          # kerberos_keytab: <string>
          # method:
          #   - "ntlm"
          #   - "basic"
          #   - "digest"
          #   - "form"
          #   - "negotiate"
          #   - "fsso"
          #   - "rsso"
          #   - "ssh-publickey"
          #   - "saml"
          #   - "cert"
          #   - "x-auth-user"
          #   - "saml-sp"
          #   - "entra-sso"
          # negotiate_ntlm: <value in [disable, enable]>
          # require_tfa: <value in [disable, enable]>
          # ssh_ca: <string>
          # user_database: <list or string>
          # ems_device_owner: <value in [disable, enable]>
          # saml_server: <string>
          # saml_timeout: <integer>
          # user_cert: <value in [disable, enable]>
          # external_idp: <list or string>
          # digest_algo:
          #   - "md5"
          #   - "sha-256"
          # group_attr_type: <value in [display-name, external-id]>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/authentication/scheme',
        '/pm/config/global/obj/authentication/scheme'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'authentication_scheme': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'domain-controller': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'fsso-agent-for-ntlm': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'fsso-guest': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'kerberos-keytab': {'v_range': [['6.2.1', '']], 'no_log': True, 'type': 'str'},
                'method': {
                    'v_range': [['6.2.1', '']],
                    'type': 'list',
                    'choices': [
                        'ntlm', 'basic', 'digest', 'form', 'negotiate', 'fsso', 'rsso', 'ssh-publickey', 'saml', 'cert', 'x-auth-user', 'saml-sp',
                        'entra-sso'
                    ],
                    'elements': 'str'
                },
                'name': {'v_range': [['6.2.1', '']], 'required': True, 'type': 'str'},
                'negotiate-ntlm': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'require-tfa': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-ca': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'user-database': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'ems-device-owner': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'saml-server': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'saml-timeout': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'user-cert': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'external-idp': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                'digest-algo': {'v_range': [['7.6.3', '']], 'type': 'list', 'choices': ['md5', 'sha-256'], 'elements': 'str'},
                'group-attr-type': {'v_range': [['7.6.3', '']], 'choices': ['display-name', 'external-id'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'authentication_scheme'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
