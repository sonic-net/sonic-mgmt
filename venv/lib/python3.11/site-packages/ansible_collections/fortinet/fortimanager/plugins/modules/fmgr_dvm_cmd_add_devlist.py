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
module: fmgr_dvm_cmd_add_devlist
short_description: Add multiple devices to the Device Manager database.
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
    dvm_cmd_add_devlist:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            add_dev_list:
                aliases: ['add-dev-list']
                type: list
                elements: dict
                description: A list of device objects to be added.
                suboptions:
                    adm_pass:
                        type: raw
                        description: (list) Add real and promote device.
                    adm_usr:
                        type: str
                        description: Add real and promote device.
                    desc:
                        type: str
                        description: Available for all operations.
                    device_action:
                        aliases: ['device action']
                        type: str
                        description:
                            - Specify add device operations, or leave blank to add real device
                            - add_model - add a model device.
                            - promote_unreg - promote an unregistered device to be managed by FortiManager using information from database.
                    faz_quota:
                        aliases: ['faz.quota']
                        type: int
                        description: Available for all operations.
                    ip:
                        type: str
                        description: Add real device only.
                    meta_fields:
                        aliases: ['meta fields']
                        type: raw
                        description: (dict or str) Add real and model device.
                    mgmt_mode:
                        type: str
                        description: Add real and model device.
                        choices:
                            - 'unreg'
                            - 'fmg'
                            - 'faz'
                            - 'fmgfaz'
                    mr:
                        type: int
                        description: Add model device only.
                    name:
                        type: str
                        description: Required for all operations.
                    os_type:
                        type: str
                        description: Add model device only.
                        choices:
                            - 'unknown'
                            - 'fos'
                            - 'fsw'
                            - 'foc'
                            - 'fml'
                            - 'faz'
                            - 'fwb'
                            - 'fch'
                            - 'fct'
                            - 'log'
                            - 'fmg'
                            - 'fsa'
                            - 'fdd'
                            - 'fac'
                            - 'fpx'
                            - 'fna'
                    os_ver:
                        type: str
                        description: Add model device only.
                        choices:
                            - 'unknown'
                            - '0.0'
                            - '1.0'
                            - '2.0'
                            - '3.0'
                            - '4.0'
                            - '5.0'
                            - '6.0'
                            - '7.0'
                            - '8.0'
                    patch:
                        type: int
                        description: Add model device only.
                    platform_str:
                        type: str
                        description: Add model device only.
                    sn:
                        type: str
                        description: Add model device only.
                    device_blueprint:
                        aliases: ['device blueprint']
                        type: str
                        description: Add model device only.
                    authorization_template:
                        aliases: ['authorization template']
                        type: str
                        description: Add model device only.
            adom:
                type: str
                description: Name or ID of the ADOM where the command is to be executed on.
            flags:
                type: list
                elements: str
                description:
                    - create_task - Create a new task in task manager database.
                    - nonblocking - The API will return immediately in for non-blocking call.
                choices:
                    - 'none'
                    - 'create_task'
                    - 'nonblocking'
                    - 'log_dev'
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
    - name: Add multiple devices to the Device Manager database.
      fortinet.fortimanager.fmgr_dvm_cmd_add_devlist:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        dvm_cmd_add_devlist:
          # add_dev_list:
          #   - adm_pass: <list or string>
          #     adm_usr: <string>
          #     desc: <string>
          #     device_action: <string>
          #     faz_quota: <integer>
          #     ip: <string>
          #     meta_fields: <dict or string>
          #     mgmt_mode: <value in [unreg, fmg, faz, ...]>
          #     mr: <integer>
          #     name: <string>
          #     os_type: <value in [unknown, fos, fsw, ...]>
          #     os_ver: <value in [unknown, 0.0, 1.0, ...]>
          #     patch: <integer>
          #     platform_str: <string>
          #     sn: <string>
          #     device_blueprint: <string>
          #     authorization_template: <string>
          # adom: <string>
          # flags:
          #   - "none"
          #   - "create_task"
          #   - "nonblocking"
          #   - "log_dev"
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
        '/dvm/cmd/add/dev-list'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'dvm_cmd_add_devlist': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'add-dev-list': {
                    'type': 'list',
                    'options': {
                        'adm_pass': {'no_log': True, 'type': 'raw'},
                        'adm_usr': {'type': 'str'},
                        'desc': {'type': 'str'},
                        'device action': {'type': 'str'},
                        'faz.quota': {'type': 'int'},
                        'ip': {'type': 'str'},
                        'meta fields': {'type': 'raw'},
                        'mgmt_mode': {'choices': ['unreg', 'fmg', 'faz', 'fmgfaz'], 'type': 'str'},
                        'mr': {'type': 'int'},
                        'name': {'type': 'str'},
                        'os_type': {
                            'choices': [
                                'unknown', 'fos', 'fsw', 'foc', 'fml', 'faz', 'fwb', 'fch', 'fct', 'log', 'fmg', 'fsa', 'fdd', 'fac', 'fpx', 'fna'
                            ],
                            'type': 'str'
                        },
                        'os_ver': {'choices': ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0'], 'type': 'str'},
                        'patch': {'type': 'int'},
                        'platform_str': {'type': 'str'},
                        'sn': {'type': 'str'},
                        'device blueprint': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'authorization template': {'v_range': [['7.4.1', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'adom': {'type': 'str'},
                'flags': {'type': 'list', 'choices': ['none', 'create_task', 'nonblocking', 'log_dev'], 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvm_cmd_add_devlist'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('exec', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_exec()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
