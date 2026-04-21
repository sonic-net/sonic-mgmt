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
module: fmgr_system_docker
short_description: Docker host.
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
    system_docker:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            fortiportal:
                type: str
                description:
                    - Enable/disable container.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fortiwlm:
                type: str
                description:
                    - Enable/disable container.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            sdwancontroller:
                type: str
                description:
                    - Enable/disable container.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            status:
                type: str
                description:
                    - Enable and set registry.
                    - disable - Disable docker host service.
                    - enable - Enable production registry.
                    - qa - Enable QA test registry.
                    - dev - Enable QA test registry
                choices:
                    - 'disable'
                    - 'enable'
                    - 'qa'
                    - 'dev'
            cpu:
                type: int
                description: Cpu.
            default_address_pool_base:
                aliases: ['default-address-pool_base']
                type: str
                description: Set default-address-pool CIDR.
            default_address_pool_size:
                aliases: ['default-address-pool_size']
                type: int
                description: Set default-address-pool size.
            fortiauthenticator:
                type: str
                description:
                    - Enable/disable container.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fortisigconverter:
                type: str
                description:
                    - Enable/disable container.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            mem:
                type: int
                description: Max % RAM usage.
            docker_user_login_max:
                aliases: ['docker-user-login-max']
                type: int
                description: Max login session for docker users.
            fortisoar:
                type: str
                description:
                    - Enable/disable container.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fortiaiops:
                type: str
                description:
                    - Enable/disable container.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            policyanalyzer:
                type: str
                description:
                    - Enable/disable container.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            universalconnector:
                type: str
                description:
                    - Enable/disable container.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fsmcollector:
                type: str
                description:
                    - Enable/disable container.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Docker host.
      fortinet.fortimanager.fmgr_system_docker:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        system_docker:
          # fortiportal: <value in [disable, enable]>
          # fortiwlm: <value in [disable, enable]>
          # sdwancontroller: <value in [disable, enable]>
          # status: <value in [disable, enable, qa, ...]>
          # cpu: <integer>
          # default_address_pool_base: <string>
          # default_address_pool_size: <integer>
          # fortiauthenticator: <value in [disable, enable]>
          # fortisigconverter: <value in [disable, enable]>
          # mem: <integer>
          # docker_user_login_max: <integer>
          # fortisoar: <value in [disable, enable]>
          # fortiaiops: <value in [disable, enable]>
          # policyanalyzer: <value in [disable, enable]>
          # universalconnector: <value in [disable, enable]>
          # fsmcollector: <value in [disable, enable]>
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
        '/cli/global/system/docker'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'system_docker': {
            'type': 'dict',
            'v_range': [['6.4.0', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '']],
            'options': {
                'fortiportal': {'v_range': [['6.4.0', '7.0.13'], ['7.2.0', '7.2.4'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiwlm': {
                    'v_range': [['6.4.0', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '7.4.6'], ['7.6.0', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'sdwancontroller': {'v_range': [['6.4.0', '7.0.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {
                    'v_range': [['6.4.0', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '']],
                    'choices': ['disable', 'enable', 'qa', 'dev'],
                    'type': 'str'
                },
                'cpu': {'v_range': [['6.4.5', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '']], 'type': 'int'},
                'default-address-pool_base': {'v_range': [['6.4.3', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '']], 'type': 'str'},
                'default-address-pool_size': {'v_range': [['6.4.3', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '']], 'type': 'int'},
                'fortiauthenticator': {'v_range': [['6.4.3', '7.0.13'], ['7.2.0', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortisigconverter': {
                    'v_range': [['6.4.3', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'mem': {'v_range': [['6.4.5', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '']], 'type': 'int'},
                'docker-user-login-max': {'v_range': [['6.4.6', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '']], 'type': 'int'},
                'fortisoar': {
                    'v_range': [['7.0.0', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '7.4.6'], ['7.6.0', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'fortiaiops': {
                    'v_range': [['7.0.1', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '7.4.6'], ['7.6.0', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'policyanalyzer': {
                    'v_range': [['7.0.2', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '7.4.6'], ['7.6.0', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'universalconnector': {
                    'v_range': [['7.0.1', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'fsmcollector': {'v_range': [['7.0.1', '7.0.1']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_docker'),
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
