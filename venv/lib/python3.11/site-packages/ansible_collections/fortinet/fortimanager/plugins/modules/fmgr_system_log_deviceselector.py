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
module: fmgr_system_log_deviceselector
short_description: Accept/reject devices matching specified filter types.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10.0"
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
    system_log_deviceselector:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description:
                    - Include or exclude the matching devices.
                    - include - Include devices matching specified filter type.
                    - exclude - Exclude devices matching specified filter type.
                choices:
                    - 'include'
                    - 'exclude'
            comment:
                type: str
                description: Additional comment for the selector.
            devid:
                type: str
                description: Device ID.
            expire:
                type: str
                description: Expiration time of the selector.
            id:
                type: int
                description: ID of device selector entry.
                required: true
            srcip:
                type: str
                description: Source IP or IP range.
            srcip_mode:
                aliases: ['srcip-mode']
                type: str
                description:
                    - Apply the selector to UDP/514, TCP/514 or any mode.
                    - UDP514 - Clients logging through UDP port 514.
                    - TCP514 - Clients logging through TCP port 514.
                    - any - Clients logging through any mode.
                choices:
                    - 'UDP514'
                    - 'TCP514'
                    - 'any'
            type:
                type: str
                description:
                    - Type of the selector.
                    - unspecified - Filter type unspecified.
                    - devid - Filter devices by DeviceID.
                    - srcip - Filter devices by source IP.
                choices:
                    - 'unspecified'
                    - 'devid'
                    - 'srcip'
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
    - name: Accept/reject devices matching specified filter types.
      fortinet.fortimanager.fmgr_system_log_deviceselector:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        state: present # <value in [present, absent]>
        system_log_deviceselector:
          id: 0 # Required variable, integer
          # action: <value in [include, exclude]>
          # comment: <string>
          # devid: <string>
          # expire: <string>
          # srcip: <string>
          # srcip_mode: <value in [UDP514, TCP514, any]>
          # type: <value in [unspecified, devid, srcip]>
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
        '/cli/global/system/log/device-selector'
    ]
    url_params = []
    module_primary_key = 'id'
    module_arg_spec = {
        'system_log_deviceselector': {
            'type': 'dict',
            'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']],
            'options': {
                'action': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                'comment': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'str'},
                'devid': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'str'},
                'expire': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'str'},
                'id': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'required': True, 'type': 'int'},
                'srcip': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'str'},
                'srcip-mode': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['UDP514', 'TCP514', 'any'], 'type': 'str'},
                'type': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['unspecified', 'devid', 'srcip'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_log_deviceselector'),
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
