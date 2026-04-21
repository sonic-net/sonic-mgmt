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
module: fmgr_switchcontroller_qos_dot1pmap
short_description: Configure FortiSwitch QoS 802.
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
    switchcontroller_qos_dot1pmap:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            description:
                type: str
                description: Description of the 802.
            name:
                type: str
                description: Dot1p map name.
                required: true
            priority_0:
                aliases: ['priority-0']
                type: str
                description: COS queue mapped to dot1p priority number.
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_1:
                aliases: ['priority-1']
                type: str
                description: COS queue mapped to dot1p priority number.
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_2:
                aliases: ['priority-2']
                type: str
                description: COS queue mapped to dot1p priority number.
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_3:
                aliases: ['priority-3']
                type: str
                description: COS queue mapped to dot1p priority number.
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_4:
                aliases: ['priority-4']
                type: str
                description: COS queue mapped to dot1p priority number.
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_5:
                aliases: ['priority-5']
                type: str
                description: COS queue mapped to dot1p priority number.
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_6:
                aliases: ['priority-6']
                type: str
                description: COS queue mapped to dot1p priority number.
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            priority_7:
                aliases: ['priority-7']
                type: str
                description: COS queue mapped to dot1p priority number.
                choices:
                    - 'queue-0'
                    - 'queue-1'
                    - 'queue-2'
                    - 'queue-3'
                    - 'queue-4'
                    - 'queue-5'
                    - 'queue-6'
                    - 'queue-7'
            egress_pri_tagging:
                aliases: ['egress-pri-tagging']
                type: str
                description: Enable/disable egress priority-tag frame.
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
    - name: Configure FortiSwitch QoS 802.
      fortinet.fortimanager.fmgr_switchcontroller_qos_dot1pmap:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_qos_dot1pmap:
          name: "your value" # Required variable, string
          # description: <string>
          # priority_0: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_1: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_2: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_3: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_4: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_5: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_6: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_7: <value in [queue-0, queue-1, queue-2, ...]>
          # egress_pri_tagging: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/switch-controller/qos/dot1p-map',
        '/pm/config/global/obj/switch-controller/qos/dot1p-map'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_qos_dot1pmap': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'description': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'priority-0': {'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'], 'type': 'str'},
                'priority-1': {'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'], 'type': 'str'},
                'priority-2': {'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'], 'type': 'str'},
                'priority-3': {'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'], 'type': 'str'},
                'priority-4': {'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'], 'type': 'str'},
                'priority-5': {'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'], 'type': 'str'},
                'priority-6': {'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'], 'type': 'str'},
                'priority-7': {'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'], 'type': 'str'},
                'egress-pri-tagging': {'v_range': [['6.2.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_qos_dot1pmap'),
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
