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
module: fmgr_system_ntp
short_description: NTP settings.
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
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    system_ntp:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ntpserver:
                type: list
                elements: dict
                description: Ntpserver.
                suboptions:
                    authentication:
                        type: str
                        description:
                            - Enable/disable MD5 authentication.
                            - disable - Disable setting.
                            - enable - Enable setting.
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: Time server ID.
                    key:
                        type: raw
                        description: (list) Key for authentication.
                    key_id:
                        aliases: ['key-id']
                        type: int
                        description: Key ID for authentication.
                    ntpv3:
                        type: str
                        description:
                            - Enable/disable NTPv3.
                            - disable - Disable setting.
                            - enable - Enable setting.
                        choices:
                            - 'disable'
                            - 'enable'
                    server:
                        type: str
                        description: IP address/hostname of NTP Server.
                    maxpoll:
                        type: int
                        description: Maximum poll interval in seconds as power of 2
                    minpoll:
                        type: int
                        description: Minimum poll interval in seconds as power of 2
            status:
                type: str
                description:
                    - Enable/disable NTP.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            sync_interval:
                type: int
                description: NTP sync interval
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
    - name: NTP settings.
      fortinet.fortimanager.fmgr_system_ntp:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        system_ntp:
          # ntpserver:
          #   - authentication: <value in [disable, enable]>
          #     id: <integer>
          #     key: <list or string>
          #     key_id: <integer>
          #     ntpv3: <value in [disable, enable]>
          #     server: <string>
          #     maxpoll: <integer>
          #     minpoll: <integer>
          # status: <value in [disable, enable]>
          # sync_interval: <integer>
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
        '/cli/global/system/ntp'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'system_ntp': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'ntpserver': {
                    'type': 'list',
                    'options': {
                        'authentication': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'type': 'int'},
                        'key': {'no_log': True, 'type': 'raw'},
                        'key-id': {'no_log': True, 'type': 'int'},
                        'ntpv3': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'server': {'type': 'str'},
                        'maxpoll': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'},
                        'minpoll': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'sync_interval': {'v_range': [['6.0.0', '6.4.7'], ['7.0.0', '7.0.2']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_ntp'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
