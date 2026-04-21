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
module: fmgr_user_fsso
short_description: Configure Fortinet Single Sign On
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
    user_fsso:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _gui_meta:
                type: str
                description: Gui meta.
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    _gui_meta:
                        type: str
                        description: Gui meta.
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
                    ldap_server:
                        aliases: ['ldap-server']
                        type: str
                        description: Ldap server.
                    password:
                        type: raw
                        description: (list) Password.
                    password2:
                        type: raw
                        description: (list) Password2.
                    password3:
                        type: raw
                        description: (list) Password3.
                    password4:
                        type: raw
                        description: (list) Password4.
                    password5:
                        type: raw
                        description: (list) Password5.
                    port:
                        type: int
                        description: Port.
                    port2:
                        type: int
                        description: Port2.
                    port3:
                        type: int
                        description: Port3.
                    port4:
                        type: int
                        description: Port4.
                    port5:
                        type: int
                        description: Port5.
                    server:
                        type: str
                        description: Server.
                    server2:
                        type: str
                        description: Server2.
                    server3:
                        type: str
                        description: Server3.
                    server4:
                        type: str
                        description: Server4.
                    server5:
                        type: str
                        description: Server5.
                    source_ip:
                        aliases: ['source-ip']
                        type: str
                        description: Source ip.
                    source_ip6:
                        aliases: ['source-ip6']
                        type: str
                        description: Source ip6.
                    ssl:
                        type: str
                        description: Ssl.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_trusted_cert:
                        aliases: ['ssl-trusted-cert']
                        type: str
                        description: Ssl trusted cert.
                    type:
                        type: str
                        description: Type.
                        choices:
                            - 'default'
                            - 'fortiems'
                            - 'fortinac'
                            - 'fortiems-cloud'
                    user_info_server:
                        aliases: ['user-info-server']
                        type: raw
                        description: (list or str) User info server.
                    ldap_poll:
                        aliases: ['ldap-poll']
                        type: str
                        description: Ldap poll.
                        choices:
                            - 'disable'
                            - 'enable'
                    ldap_poll_filter:
                        aliases: ['ldap-poll-filter']
                        type: str
                        description: Ldap poll filter.
                    ldap_poll_interval:
                        aliases: ['ldap-poll-interval']
                        type: int
                        description: Ldap poll interval.
                    group_poll_interval:
                        aliases: ['group-poll-interval']
                        type: int
                        description: Group poll interval.
                    interface:
                        type: str
                        description: Interface.
                    interface_select_method:
                        aliases: ['interface-select-method']
                        type: str
                        description: Interface select method.
                        choices:
                            - 'auto'
                            - 'sdwan'
                            - 'specify'
                    logon_timeout:
                        aliases: ['logon-timeout']
                        type: int
                        description: Interval in minutes to keep logons after FSSO server down.
                    sni:
                        type: str
                        description: Server Name Indication.
                    ssl_server_host_ip_check:
                        aliases: ['ssl-server-host-ip-check']
                        type: str
                        description: Enable/disable server host/IP verification.
                        choices:
                            - 'disable'
                            - 'enable'
                    vrf_select:
                        aliases: ['vrf-select']
                        type: int
                        description: VRF ID used for connection to server.
            ldap_server:
                aliases: ['ldap-server']
                type: str
                description: LDAP server to get group information.
            name:
                type: str
                description: Name.
                required: true
            password:
                type: raw
                description: (list) Password of the first FSSO collector agent.
            password2:
                type: raw
                description: (list) Password of the second FSSO collector agent.
            password3:
                type: raw
                description: (list) Password of the third FSSO collector agent.
            password4:
                type: raw
                description: (list) Password of the fourth FSSO collector agent.
            password5:
                type: raw
                description: (list) Password of the fifth FSSO collector agent.
            port:
                type: int
                description: Port of the first FSSO collector agent.
            port2:
                type: int
                description: Port of the second FSSO collector agent.
            port3:
                type: int
                description: Port of the third FSSO collector agent.
            port4:
                type: int
                description: Port of the fourth FSSO collector agent.
            port5:
                type: int
                description: Port of the fifth FSSO collector agent.
            server:
                type: str
                description: Domain name or IP address of the first FSSO collector agent.
            server2:
                type: str
                description: Domain name or IP address of the second FSSO collector agent.
            server3:
                type: str
                description: Domain name or IP address of the third FSSO collector agent.
            server4:
                type: str
                description: Domain name or IP address of the fourth FSSO collector agent.
            server5:
                type: str
                description: Domain name or IP address of the fifth FSSO collector agent.
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source IP for communications to FSSO agent.
            source_ip6:
                aliases: ['source-ip6']
                type: str
                description: IPv6 source for communications to FSSO agent.
            ldap_poll:
                aliases: ['ldap-poll']
                type: str
                description: Enable/disable automatic fetching of groups from LDAP server.
                choices:
                    - 'disable'
                    - 'enable'
            ldap_poll_filter:
                aliases: ['ldap-poll-filter']
                type: str
                description: Filter used to fetch groups.
            ldap_poll_interval:
                aliases: ['ldap-poll-interval']
                type: int
                description: Interval in minutes within to fetch groups from LDAP server.
            ssl:
                type: str
                description: Enable/disable use of SSL.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_trusted_cert:
                aliases: ['ssl-trusted-cert']
                type: str
                description: Trusted server certificate or CA certificate.
            type:
                type: str
                description: Server type.
                choices:
                    - 'default'
                    - 'fortiems'
                    - 'fortinac'
                    - 'fortiems-cloud'
            user_info_server:
                aliases: ['user-info-server']
                type: str
                description: LDAP server to get user information.
            group_poll_interval:
                aliases: ['group-poll-interval']
                type: int
                description: Interval in minutes within to fetch groups from FSSO server, or unset to disable.
            interface:
                type: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            logon_timeout:
                aliases: ['logon-timeout']
                type: int
                description: Interval in minutes to keep logons after FSSO server down.
            sni:
                type: str
                description: Server Name Indication.
            ssl_server_host_ip_check:
                aliases: ['ssl-server-host-ip-check']
                type: str
                description: Enable/disable server host/IP verification.
                choices:
                    - 'disable'
                    - 'enable'
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
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
    - name: Configure Fortinet Single Sign On (FSSO) agents.
      fortinet.fortimanager.fmgr_user_fsso:
        bypass_validation: false
        adom: ansible
        state: present
        user_fsso:
          name: ansible-test-fsso
          password: fortinet
          port: 9000
          server: ansible

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the Fortinet Single Sign On (FSSO) agents
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "user_fsso"
          params:
            adom: "ansible"
            fsso: "your_value"
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
        '/pm/config/adom/{adom}/obj/user/fsso',
        '/pm/config/global/obj/user/fsso'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_fsso': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                '_gui_meta': {'type': 'str'},
                'dynamic_mapping': {
                    'type': 'list',
                    'options': {
                        '_gui_meta': {'type': 'str'},
                        '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                        'ldap-server': {'type': 'str'},
                        'password': {'no_log': True, 'type': 'raw'},
                        'password2': {'no_log': True, 'type': 'raw'},
                        'password3': {'no_log': True, 'type': 'raw'},
                        'password4': {'no_log': True, 'type': 'raw'},
                        'password5': {'no_log': True, 'type': 'raw'},
                        'port': {'type': 'int'},
                        'port2': {'type': 'int'},
                        'port3': {'type': 'int'},
                        'port4': {'type': 'int'},
                        'port5': {'type': 'int'},
                        'server': {'type': 'str'},
                        'server2': {'type': 'str'},
                        'server3': {'type': 'str'},
                        'server4': {'type': 'str'},
                        'server5': {'type': 'str'},
                        'source-ip': {'type': 'str'},
                        'source-ip6': {'type': 'str'},
                        'ssl': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-trusted-cert': {'type': 'str'},
                        'type': {'choices': ['default', 'fortiems', 'fortinac', 'fortiems-cloud'], 'type': 'str'},
                        'user-info-server': {'type': 'raw'},
                        'ldap-poll': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ldap-poll-filter': {'v_range': [['6.2.1', '']], 'type': 'str'},
                        'ldap-poll-interval': {'v_range': [['6.2.1', '']], 'type': 'int'},
                        'group-poll-interval': {'v_range': [['6.2.2', '']], 'type': 'int'},
                        'interface': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'str'},
                        'interface-select-method': {
                            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']],
                            'choices': ['auto', 'sdwan', 'specify'],
                            'type': 'str'
                        },
                        'logon-timeout': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'sni': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'ssl-server-host-ip-check': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'ldap-server': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'password': {'no_log': True, 'type': 'raw'},
                'password2': {'no_log': True, 'type': 'raw'},
                'password3': {'no_log': True, 'type': 'raw'},
                'password4': {'no_log': True, 'type': 'raw'},
                'password5': {'no_log': True, 'type': 'raw'},
                'port': {'type': 'int'},
                'port2': {'type': 'int'},
                'port3': {'type': 'int'},
                'port4': {'type': 'int'},
                'port5': {'type': 'int'},
                'server': {'type': 'str'},
                'server2': {'type': 'str'},
                'server3': {'type': 'str'},
                'server4': {'type': 'str'},
                'server5': {'type': 'str'},
                'source-ip': {'type': 'str'},
                'source-ip6': {'type': 'str'},
                'ldap-poll': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ldap-poll-filter': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'ldap-poll-interval': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'ssl': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-trusted-cert': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'type': {'v_range': [['6.2.0', '']], 'choices': ['default', 'fortiems', 'fortinac', 'fortiems-cloud'], 'type': 'str'},
                'user-info-server': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'group-poll-interval': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'interface': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'str'},
                'interface-select-method': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'logon-timeout': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'sni': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'ssl-server-host-ip-check': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_fsso'),
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
