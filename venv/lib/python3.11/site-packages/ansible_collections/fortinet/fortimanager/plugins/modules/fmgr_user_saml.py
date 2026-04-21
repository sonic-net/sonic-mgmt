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
module: fmgr_user_saml
short_description: SAML server entry configuration.
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
    user_saml:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cert:
                type: str
                description: Certificate to sign SAML messages.
            entity_id:
                aliases: ['entity-id']
                type: str
                description: SP entity ID.
            group_name:
                aliases: ['group-name']
                type: str
                description: Group name in assertion statement.
            idp_cert:
                aliases: ['idp-cert']
                type: str
                description: IDP Certificate name.
            idp_entity_id:
                aliases: ['idp-entity-id']
                type: str
                description: IDP entity ID.
            idp_single_logout_url:
                aliases: ['idp-single-logout-url']
                type: str
                description: IDP single logout url.
            idp_single_sign_on_url:
                aliases: ['idp-single-sign-on-url']
                type: str
                description: IDP single sign-on URL.
            name:
                type: str
                description: SAML server entry name.
                required: true
            single_logout_url:
                aliases: ['single-logout-url']
                type: str
                description: SP single logout URL.
            single_sign_on_url:
                aliases: ['single-sign-on-url']
                type: str
                description: SP single sign-on URL.
            user_name:
                aliases: ['user-name']
                type: str
                description: User name in assertion statement.
            adfs_claim:
                aliases: ['adfs-claim']
                type: str
                description: Enable/disable ADFS Claim for user/group attribute in assertion statement
                choices:
                    - 'disable'
                    - 'enable'
            digest_method:
                aliases: ['digest-method']
                type: str
                description: Digest Method Algorithm.
                choices:
                    - 'sha1'
                    - 'sha256'
            group_claim_type:
                aliases: ['group-claim-type']
                type: str
                description: Group claim in assertion statement.
                choices:
                    - 'email'
                    - 'given-name'
                    - 'name'
                    - 'upn'
                    - 'common-name'
                    - 'email-adfs-1x'
                    - 'group'
                    - 'upn-adfs-1x'
                    - 'role'
                    - 'sur-name'
                    - 'ppid'
                    - 'name-identifier'
                    - 'authentication-method'
                    - 'deny-only-group-sid'
                    - 'deny-only-primary-sid'
                    - 'deny-only-primary-group-sid'
                    - 'group-sid'
                    - 'primary-group-sid'
                    - 'primary-sid'
                    - 'windows-account-name'
            limit_relaystate:
                aliases: ['limit-relaystate']
                type: str
                description: Enable/disable limiting of relay-state parameter when it exceeds SAML 2.
                choices:
                    - 'disable'
                    - 'enable'
            user_claim_type:
                aliases: ['user-claim-type']
                type: str
                description: User name claim in assertion statement.
                choices:
                    - 'email'
                    - 'given-name'
                    - 'name'
                    - 'upn'
                    - 'common-name'
                    - 'email-adfs-1x'
                    - 'group'
                    - 'upn-adfs-1x'
                    - 'role'
                    - 'sur-name'
                    - 'ppid'
                    - 'name-identifier'
                    - 'authentication-method'
                    - 'deny-only-group-sid'
                    - 'deny-only-primary-sid'
                    - 'deny-only-primary-group-sid'
                    - 'group-sid'
                    - 'primary-group-sid'
                    - 'primary-sid'
                    - 'windows-account-name'
            clock_tolerance:
                aliases: ['clock-tolerance']
                type: int
                description: Clock skew tolerance in seconds
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    _scope:
                        type: list
                        elements: dict
                        description: Scope.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    adfs_claim:
                        aliases: ['adfs-claim']
                        type: str
                        description: Enable/disable ADFS Claim for user/group attribute in assertion statement
                        choices:
                            - 'disable'
                            - 'enable'
                    cert:
                        type: str
                        description: Certificate to sign SAML messages.
                    clock_tolerance:
                        aliases: ['clock-tolerance']
                        type: int
                        description: Clock skew tolerance in seconds
                    digest_method:
                        aliases: ['digest-method']
                        type: str
                        description: Digest method algorithm
                        choices:
                            - 'sha1'
                            - 'sha256'
                    entity_id:
                        aliases: ['entity-id']
                        type: str
                        description: SP entity ID.
                    group_claim_type:
                        aliases: ['group-claim-type']
                        type: str
                        description: Group claim in assertion statement.
                        choices:
                            - 'email'
                            - 'given-name'
                            - 'name'
                            - 'upn'
                            - 'common-name'
                            - 'email-adfs-1x'
                            - 'group'
                            - 'upn-adfs-1x'
                            - 'role'
                            - 'sur-name'
                            - 'ppid'
                            - 'name-identifier'
                            - 'authentication-method'
                            - 'deny-only-group-sid'
                            - 'deny-only-primary-sid'
                            - 'deny-only-primary-group-sid'
                            - 'group-sid'
                            - 'primary-group-sid'
                            - 'primary-sid'
                            - 'windows-account-name'
                    group_name:
                        aliases: ['group-name']
                        type: str
                        description: Group name in assertion statement.
                    idp_cert:
                        aliases: ['idp-cert']
                        type: str
                        description: IDP Certificate name.
                    idp_entity_id:
                        aliases: ['idp-entity-id']
                        type: str
                        description: IDP entity ID.
                    idp_single_logout_url:
                        aliases: ['idp-single-logout-url']
                        type: str
                        description: IDP single logout url.
                    idp_single_sign_on_url:
                        aliases: ['idp-single-sign-on-url']
                        type: str
                        description: IDP single sign-on URL.
                    limit_relaystate:
                        aliases: ['limit-relaystate']
                        type: str
                        description: Enable/disable limiting of relay-state parameter when it exceeds SAML 2.
                        choices:
                            - 'disable'
                            - 'enable'
                    single_logout_url:
                        aliases: ['single-logout-url']
                        type: str
                        description: SP single logout URL.
                    single_sign_on_url:
                        aliases: ['single-sign-on-url']
                        type: str
                        description: SP single sign-on URL.
                    user_claim_type:
                        aliases: ['user-claim-type']
                        type: str
                        description: User name claim in assertion statement.
                        choices:
                            - 'email'
                            - 'given-name'
                            - 'name'
                            - 'upn'
                            - 'common-name'
                            - 'email-adfs-1x'
                            - 'group'
                            - 'upn-adfs-1x'
                            - 'role'
                            - 'sur-name'
                            - 'ppid'
                            - 'name-identifier'
                            - 'authentication-method'
                            - 'deny-only-group-sid'
                            - 'deny-only-primary-sid'
                            - 'deny-only-primary-group-sid'
                            - 'group-sid'
                            - 'primary-group-sid'
                            - 'primary-sid'
                            - 'windows-account-name'
                    user_name:
                        aliases: ['user-name']
                        type: str
                        description: User name in assertion statement.
                    auth_url:
                        aliases: ['auth-url']
                        type: str
                        description: URL to verify authentication.
                    reauth:
                        type: str
                        description: Enable/disable signalling of IDP to force user re-authentication
                        choices:
                            - 'disable'
                            - 'enable'
                    scim_client:
                        aliases: ['scim-client']
                        type: raw
                        description: (list) SCIM client name.
                    scim_group_attr_type:
                        aliases: ['scim-group-attr-type']
                        type: str
                        description: Group attribute type used to match SCIM groups
                        choices:
                            - 'display-name'
                            - 'external-id'
            auth_url:
                aliases: ['auth-url']
                type: str
                description: URL to verify authentication.
            reauth:
                type: str
                description: Enable/disable signalling of IDP to force user re-authentication
                choices:
                    - 'disable'
                    - 'enable'
            scim_client:
                aliases: ['scim-client']
                type: raw
                description: (list) SCIM client name.
            scim_group_attr_type:
                aliases: ['scim-group-attr-type']
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
    - name: SAML server entry configuration.
      fortinet.fortimanager.fmgr_user_saml:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        user_saml:
          name: "your value" # Required variable, string
          # cert: <string>
          # entity_id: <string>
          # group_name: <string>
          # idp_cert: <string>
          # idp_entity_id: <string>
          # idp_single_logout_url: <string>
          # idp_single_sign_on_url: <string>
          # single_logout_url: <string>
          # single_sign_on_url: <string>
          # user_name: <string>
          # adfs_claim: <value in [disable, enable]>
          # digest_method: <value in [sha1, sha256]>
          # group_claim_type: <value in [email, given-name, name, ...]>
          # limit_relaystate: <value in [disable, enable]>
          # user_claim_type: <value in [email, given-name, name, ...]>
          # clock_tolerance: <integer>
          # dynamic_mapping:
          #   - _scope:
          #       - name: <string>
          #         vdom: <string>
          #     adfs_claim: <value in [disable, enable]>
          #     cert: <string>
          #     clock_tolerance: <integer>
          #     digest_method: <value in [sha1, sha256]>
          #     entity_id: <string>
          #     group_claim_type: <value in [email, given-name, name, ...]>
          #     group_name: <string>
          #     idp_cert: <string>
          #     idp_entity_id: <string>
          #     idp_single_logout_url: <string>
          #     idp_single_sign_on_url: <string>
          #     limit_relaystate: <value in [disable, enable]>
          #     single_logout_url: <string>
          #     single_sign_on_url: <string>
          #     user_claim_type: <value in [email, given-name, name, ...]>
          #     user_name: <string>
          #     auth_url: <string>
          #     reauth: <value in [disable, enable]>
          #     scim_client: <list or string>
          #     scim_group_attr_type: <value in [display-name, external-id]>
          # auth_url: <string>
          # reauth: <value in [disable, enable]>
          # scim_client: <list or string>
          # scim_group_attr_type: <value in [display-name, external-id]>
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
        '/pm/config/adom/{adom}/obj/user/saml',
        '/pm/config/global/obj/user/saml'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_saml': {
            'type': 'dict',
            'v_range': [['6.4.0', '']],
            'options': {
                'cert': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'entity-id': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'group-name': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'idp-cert': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'idp-entity-id': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'idp-single-logout-url': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'idp-single-sign-on-url': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'name': {'v_range': [['6.4.0', '']], 'required': True, 'type': 'str'},
                'single-logout-url': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'single-sign-on-url': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'user-name': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'adfs-claim': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'digest-method': {'v_range': [['7.0.0', '']], 'choices': ['sha1', 'sha256'], 'type': 'str'},
                'group-claim-type': {
                    'v_range': [['7.0.0', '']],
                    'choices': [
                        'email', 'given-name', 'name', 'upn', 'common-name', 'email-adfs-1x', 'group', 'upn-adfs-1x', 'role', 'sur-name', 'ppid',
                        'name-identifier', 'authentication-method', 'deny-only-group-sid', 'deny-only-primary-sid', 'deny-only-primary-group-sid',
                        'group-sid', 'primary-group-sid', 'primary-sid', 'windows-account-name'
                    ],
                    'type': 'str'
                },
                'limit-relaystate': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user-claim-type': {
                    'v_range': [['7.0.0', '']],
                    'choices': [
                        'email', 'given-name', 'name', 'upn', 'common-name', 'email-adfs-1x', 'group', 'upn-adfs-1x', 'role', 'sur-name', 'ppid',
                        'name-identifier', 'authentication-method', 'deny-only-group-sid', 'deny-only-primary-sid', 'deny-only-primary-group-sid',
                        'group-sid', 'primary-group-sid', 'primary-sid', 'windows-account-name'
                    ],
                    'type': 'str'
                },
                'clock-tolerance': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'dynamic_mapping': {
                    'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']],
                    'type': 'list',
                    'options': {
                        '_scope': {
                            'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                                'vdom': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'adfs-claim': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'cert': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                        'clock-tolerance': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'int'},
                        'digest-method': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'choices': ['sha1', 'sha256'], 'type': 'str'},
                        'entity-id': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                        'group-claim-type': {
                            'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']],
                            'choices': [
                                'email', 'given-name', 'name', 'upn', 'common-name', 'email-adfs-1x', 'group', 'upn-adfs-1x', 'role', 'sur-name', 'ppid',
                                'name-identifier', 'authentication-method', 'deny-only-group-sid', 'deny-only-primary-sid',
                                'deny-only-primary-group-sid', 'group-sid', 'primary-group-sid', 'primary-sid', 'windows-account-name'
                            ],
                            'type': 'str'
                        },
                        'group-name': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                        'idp-cert': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                        'idp-entity-id': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                        'idp-single-logout-url': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                        'idp-single-sign-on-url': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                        'limit-relaystate': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'single-logout-url': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                        'single-sign-on-url': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                        'user-claim-type': {
                            'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']],
                            'choices': [
                                'email', 'given-name', 'name', 'upn', 'common-name', 'email-adfs-1x', 'group', 'upn-adfs-1x', 'role', 'sur-name', 'ppid',
                                'name-identifier', 'authentication-method', 'deny-only-group-sid', 'deny-only-primary-sid',
                                'deny-only-primary-group-sid', 'group-sid', 'primary-group-sid', 'primary-sid', 'windows-account-name'
                            ],
                            'type': 'str'
                        },
                        'user-name': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                        'auth-url': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'reauth': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'scim-client': {'v_range': [['7.6.0', '']], 'type': 'raw'},
                        'scim-group-attr-type': {'v_range': [['7.6.3', '']], 'choices': ['display-name', 'external-id'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'auth-url': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'reauth': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'scim-client': {'v_range': [['7.6.0', '']], 'type': 'raw'},
                'scim-group-attr-type': {'v_range': [['7.6.3', '']], 'choices': ['display-name', 'external-id'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_saml'),
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
