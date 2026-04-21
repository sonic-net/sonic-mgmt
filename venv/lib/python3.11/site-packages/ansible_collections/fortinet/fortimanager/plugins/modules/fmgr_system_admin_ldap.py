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
module: fmgr_system_admin_ldap
short_description: LDAP server entry configuration.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
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
    system_admin_ldap:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adom:
                type: list
                elements: dict
                description: Adom.
                suboptions:
                    adom_name:
                        aliases: ['adom-name']
                        type: str
                        description: Admin domain names.
            adom_attr:
                aliases: ['adom-attr']
                type: str
                description: Attribute used to retrieve adom
            attributes:
                type: str
                description: Attributes used for group searching.
            ca_cert:
                aliases: ['ca-cert']
                type: str
                description: CA certificate name.
            cnid:
                type: str
                description: Common Name Identifier
            connect_timeout:
                aliases: ['connect-timeout']
                type: int
                description: LDAP connection timeout
            dn:
                type: str
                description: Distinguished Name.
            filter:
                type: str
                description: Filter used for group searching.
            group:
                type: str
                description: Full base DN used for group searching.
            memberof_attr:
                aliases: ['memberof-attr']
                type: str
                description: Attribute used to retrieve memeberof.
            name:
                type: str
                description: LDAP server entry name.
                required: true
            password:
                type: raw
                description: (list) Password for initial binding.
            port:
                type: int
                description: Port number of LDAP server
            profile_attr:
                aliases: ['profile-attr']
                type: str
                description: Attribute used to retrieve admin profile.
            secondary_server:
                aliases: ['secondary-server']
                type: str
                description: No description
            secure:
                type: str
                description:
                    - SSL connection.
                    - disable - No SSL.
                    - starttls - Use StartTLS.
                    - ldaps - Use LDAPS.
                choices:
                    - 'disable'
                    - 'starttls'
                    - 'ldaps'
            server:
                type: str
                description: No description
            tertiary_server:
                aliases: ['tertiary-server']
                type: str
                description: No description
            type:
                type: str
                description:
                    - Type of LDAP binding.
                    - simple - Simple password authentication without search.
                    - anonymous - Bind using anonymous user search.
                    - regular - Bind using username/password and then search.
                choices:
                    - 'simple'
                    - 'anonymous'
                    - 'regular'
            username:
                type: str
                description: Username
            adom_access:
                aliases: ['adom-access']
                type: str
                description:
                    - set all or specify adom access type.
                    - all - All ADOMs access.
                    - specify - Specify ADOMs access.
                choices:
                    - 'all'
                    - 'specify'
            ssl_protocol:
                aliases: ['ssl-protocol']
                type: str
                description:
                    - set the lowest SSL protocol version for connection to ldap server.
                    - follow-global-ssl-protocol - Follow system.
                    - sslv3 - set SSLv3 as the lowest version.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                choices:
                    - 'follow-global-ssl-protocol'
                    - 'sslv3'
                    - 'tlsv1.0'
                    - 'tlsv1.1'
                    - 'tlsv1.2'
                    - 'tlsv1.3'
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: LDAP server entry configuration.
      fortinet.fortimanager.fmgr_system_admin_ldap:
        bypass_validation: false
        state: present
        system_admin_ldap:
          adom:
            - adom_name: ansible
          name: ansible-test-ldap
          password: Fortinet
          port: 390
          server: ansible
          type: regular # <value in [simple, anonymous, regular]>
          username: ansible-username

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the LDAP servers
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_admin_ldap"
          params:
            ldap: "your_value"
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
        '/cli/global/system/admin/ldap'
    ]
    url_params = []
    module_primary_key = 'name'
    module_arg_spec = {
        'system_admin_ldap': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'adom': {'type': 'list', 'options': {'adom-name': {'type': 'str'}}, 'elements': 'dict'},
                'adom-attr': {'type': 'str'},
                'attributes': {'type': 'str'},
                'ca-cert': {'type': 'str'},
                'cnid': {'type': 'str'},
                'connect-timeout': {'v_range': [['6.0.0', '7.2.9'], ['7.4.0', '7.4.2']], 'type': 'int'},
                'dn': {'type': 'str'},
                'filter': {'type': 'str'},
                'group': {'type': 'str'},
                'memberof-attr': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'password': {'no_log': True, 'type': 'raw'},
                'port': {'type': 'int'},
                'profile-attr': {'type': 'str'},
                'secondary-server': {'type': 'str'},
                'secure': {'choices': ['disable', 'starttls', 'ldaps'], 'type': 'str'},
                'server': {'type': 'str'},
                'tertiary-server': {'type': 'str'},
                'type': {'choices': ['simple', 'anonymous', 'regular'], 'type': 'str'},
                'username': {'type': 'str'},
                'adom-access': {'v_range': [['7.0.3', '']], 'choices': ['all', 'specify'], 'type': 'str'},
                'ssl-protocol': {
                    'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']],
                    'choices': ['follow-global-ssl-protocol', 'sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_admin_ldap'),
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
