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
module: fmgr_system_logfetch_clientprofile
short_description: Log-fetch client profile settings.
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
    system_logfetch_clientprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            client_adom:
                aliases: ['client-adom']
                type: str
                description: Log-fetch client sides adom name.
            data_range:
                aliases: ['data-range']
                type: str
                description:
                    - Data-range for fetched logs.
                    - custom - Specify some other date and time range.
                choices:
                    - 'custom'
            data_range_value:
                aliases: ['data-range-value']
                type: int
                description: Last n days or hours.
            device_filter:
                aliases: ['device-filter']
                type: list
                elements: dict
                description: Device filter.
                suboptions:
                    adom:
                        type: str
                        description: Adom name.
                    device:
                        type: str
                        description: Device name or Serial number.
                    id:
                        type: int
                        description: Add or edit a device filter.
                    vdom:
                        type: str
                        description: Vdom filters.
            end_time:
                aliases: ['end-time']
                type: raw
                description: (list) End date and time of the data-range
            id:
                type: int
                description: Log-fetch client profile ID.
                required: true
            index_fetch_logs:
                aliases: ['index-fetch-logs']
                type: str
                description:
                    - Enable/Disable indexing logs automatically after fetching logs.
                    - disable - Disable attribute function.
                    - enable - Enable attribute function.
                choices:
                    - 'disable'
                    - 'enable'
            log_filter:
                aliases: ['log-filter']
                type: list
                elements: dict
                description: Log filter.
                suboptions:
                    field:
                        type: str
                        description: Field name.
                    id:
                        type: int
                        description: Log filter ID.
                    oper:
                        type: str
                        description:
                            - Field filter operator.
                            - no description
                            - no description
                            - contain - Contain
                            - not-contain - Not contain
                            - match - Match
                        choices:
                            - '='
                            - '!='
                            - '<'
                            - '>'
                            - '<='
                            - '>='
                            - 'contain'
                            - 'not-contain'
                            - 'match'
                    value:
                        type: str
                        description: Field filter operand or free-text matching expression.
            log_filter_logic:
                aliases: ['log-filter-logic']
                type: str
                description:
                    - And/Or logic for log-filters.
                    - and - Logic And.
                    - or - Logic Or.
                choices:
                    - 'and'
                    - 'or'
            log_filter_status:
                aliases: ['log-filter-status']
                type: str
                description:
                    - Enable/Disable log-filter.
                    - disable - Disable attribute function.
                    - enable - Enable attribute function.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Name of log-fetch client profile.
            password:
                type: raw
                description: (list) Log-fetch server login password.
            secure_connection:
                aliases: ['secure-connection']
                type: str
                description:
                    - Enable/Disable protecting log-fetch connection with TLS/SSL.
                    - disable - Disable attribute function.
                    - enable - Enable attribute function.
                choices:
                    - 'disable'
                    - 'enable'
            server_adom:
                aliases: ['server-adom']
                type: str
                description: Log-fetch server sides adom name.
            server_ip:
                aliases: ['server-ip']
                type: str
                description: Log-fetch server IP address.
            start_time:
                aliases: ['start-time']
                type: raw
                description: (list) Start date and time of the data-range
            sync_adom_config:
                aliases: ['sync-adom-config']
                type: str
                description:
                    - Enable/Disable sync adom related config.
                    - disable - Disable attribute function.
                    - enable - Enable attribute function.
                choices:
                    - 'disable'
                    - 'enable'
            user:
                type: str
                description: Log-fetch server login username.
            peer_cert_cn:
                aliases: ['peer-cert-cn']
                type: str
                description: Certificate common name of log-fetch server.
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
    - name: Log-fetch client profile settings.
      fortinet.fortimanager.fmgr_system_logfetch_clientprofile:
        bypass_validation: false
        state: present
        system_logfetch_clientprofile:
          client_adom: ansible
          data_range: custom # <value in [custom]>
          id: 1
          index_fetch_logs: enable
          name: ansible-test-clientprofile
          password: fortinet
          server_ip: "222.222.22.25"
          user: ansible

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the Log-fetch client profile settings
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_logfetch_clientprofile"
          params:
            client_profile: "your_value"
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
        '/cli/global/system/log-fetch/client-profile'
    ]
    url_params = []
    module_primary_key = 'id'
    module_arg_spec = {
        'system_logfetch_clientprofile': {
            'type': 'dict',
            'v_range': [['6.0.0', '7.2.1']],
            'options': {
                'client-adom': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'data-range': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['custom'], 'type': 'str'},
                'data-range-value': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                'device-filter': {
                    'v_range': [['6.0.0', '7.2.1']],
                    'type': 'list',
                    'options': {
                        'adom': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                        'device': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                        'id': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                        'vdom': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'end-time': {'v_range': [['6.0.0', '7.2.1']], 'type': 'raw'},
                'id': {'v_range': [['6.0.0', '7.2.1']], 'required': True, 'type': 'int'},
                'index-fetch-logs': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-filter': {
                    'v_range': [['6.0.0', '7.2.1']],
                    'type': 'list',
                    'options': {
                        'field': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                        'id': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                        'oper': {
                            'v_range': [['6.0.0', '7.2.1']],
                            'choices': ['=', '!=', '<', '>', '<=', '>=', 'contain', 'not-contain', 'match'],
                            'type': 'str'
                        },
                        'value': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'log-filter-logic': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['and', 'or'], 'type': 'str'},
                'log-filter-status': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'password': {'v_range': [['6.0.0', '7.2.1']], 'no_log': True, 'type': 'raw'},
                'secure-connection': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'server-adom': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'server-ip': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'start-time': {'v_range': [['6.0.0', '7.2.1']], 'type': 'raw'},
                'sync-adom-config': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'peer-cert-cn': {'v_range': [['7.0.3', '7.2.1']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_logfetch_clientprofile'),
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
