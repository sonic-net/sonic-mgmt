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
module: fmgr_vpn_ssl_settings_authenticationrule
short_description: Authentication rule for SSL VPN.
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
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    vpn_ssl_settings_authenticationrule:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth:
                type: str
                description: SSL VPN authentication method restriction.
                choices:
                    - 'any'
                    - 'local'
                    - 'radius'
                    - 'ldap'
                    - 'tacacs+'
                    - 'peer'
            cipher:
                type: str
                description: SSL VPN cipher strength.
                choices:
                    - 'any'
                    - 'high'
                    - 'medium'
            client_cert:
                aliases: ['client-cert']
                type: str
                description: Enable/disable SSL VPN client certificate restrictive.
                choices:
                    - 'disable'
                    - 'enable'
            groups:
                type: raw
                description: (list or str) User groups.
            id:
                type: int
                description: ID
                required: true
            portal:
                type: str
                description: SSL VPN portal.
            realm:
                type: str
                description: SSL VPN realm.
            source_address:
                aliases: ['source-address']
                type: raw
                description: (list or str) Source address of incoming traffic.
            source_address_negate:
                aliases: ['source-address-negate']
                type: str
                description: Enable/disable negated source address match.
                choices:
                    - 'disable'
                    - 'enable'
            source_address6:
                aliases: ['source-address6']
                type: raw
                description: (list or str) IPv6 source address of incoming traffic.
            source_address6_negate:
                aliases: ['source-address6-negate']
                type: str
                description: Enable/disable negated source IPv6 address match.
                choices:
                    - 'disable'
                    - 'enable'
            source_interface:
                aliases: ['source-interface']
                type: raw
                description: (list or str) SSL VPN source interface of incoming traffic.
            user_peer:
                aliases: ['user-peer']
                type: str
                description: Name of user peer.
            users:
                type: raw
                description: (list or str) User name.
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
    - name: Authentication rule for SSL VPN.
      fortinet.fortimanager.fmgr_vpn_ssl_settings_authenticationrule:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        vpn_ssl_settings_authenticationrule:
          id: 0 # Required variable, integer
          # auth: <value in [any, local, radius, ...]>
          # cipher: <value in [any, high, medium]>
          # client_cert: <value in [disable, enable]>
          # groups: <list or string>
          # portal: <string>
          # realm: <string>
          # source_address: <list or string>
          # source_address_negate: <value in [disable, enable]>
          # source_address6: <list or string>
          # source_address6_negate: <value in [disable, enable]>
          # source_interface: <list or string>
          # user_peer: <string>
          # users: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings/authentication-rule'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'vpn_ssl_settings_authenticationrule': {
            'type': 'dict',
            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']],
            'options': {
                'auth': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'choices': ['any', 'local', 'radius', 'ldap', 'tacacs+', 'peer'], 'type': 'str'},
                'cipher': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'choices': ['any', 'high', 'medium'], 'type': 'str'},
                'client-cert': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'groups': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'raw'},
                'id': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'required': True, 'type': 'int'},
                'portal': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'str'},
                'realm': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'str'},
                'source-address': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'raw'},
                'source-address-negate': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'source-address6': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'raw'},
                'source-address6-negate': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'source-interface': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'raw'},
                'user-peer': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'str'},
                'users': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_ssl_settings_authenticationrule'),
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
