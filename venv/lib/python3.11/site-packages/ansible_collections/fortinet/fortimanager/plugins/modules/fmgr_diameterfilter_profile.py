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
module: fmgr_diameterfilter_profile
short_description: Configure Diameter filter profiles.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.4.0"
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
    diameterfilter_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cmd_flags_reserve_set:
                aliases: ['cmd-flags-reserve-set']
                type: str
                description: Action to be taken for messages with cmd flag reserve bits set.
                choices:
                    - 'block'
                    - 'reset'
                    - 'monitor'
                    - 'allow'
            command_code_invalid:
                aliases: ['command-code-invalid']
                type: str
                description: Action to be taken for messages with invalid command code.
                choices:
                    - 'block'
                    - 'reset'
                    - 'monitor'
                    - 'allow'
            command_code_range:
                aliases: ['command-code-range']
                type: str
                description: Valid range for command codes
            comment:
                type: str
                description: Comment.
            log_packet:
                aliases: ['log-packet']
                type: str
                description: Enable/disable packet log for triggered diameter settings.
                choices:
                    - 'disable'
                    - 'enable'
            message_length_invalid:
                aliases: ['message-length-invalid']
                type: str
                description: Action to be taken for invalid message length.
                choices:
                    - 'block'
                    - 'reset'
                    - 'monitor'
                    - 'allow'
            missing_request_action:
                aliases: ['missing-request-action']
                type: str
                description: Action to be taken for answers without corresponding request.
                choices:
                    - 'block'
                    - 'reset'
                    - 'monitor'
                    - 'allow'
            monitor_all_messages:
                aliases: ['monitor-all-messages']
                type: str
                description: Enable/disable logging for all User Name and Result Code AVP messages.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Profile name.
                required: true
            protocol_version_invalid:
                aliases: ['protocol-version-invalid']
                type: str
                description: Action to be taken for invalid protocol version.
                choices:
                    - 'block'
                    - 'reset'
                    - 'monitor'
                    - 'allow'
            request_error_flag_set:
                aliases: ['request-error-flag-set']
                type: str
                description: Action to be taken for request messages with error flag set.
                choices:
                    - 'block'
                    - 'reset'
                    - 'monitor'
                    - 'allow'
            track_requests_answers:
                aliases: ['track-requests-answers']
                type: str
                description: Enable/disable validation that each answer has a corresponding request.
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
    - name: Configure Diameter filter profiles.
      fortinet.fortimanager.fmgr_diameterfilter_profile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        diameterfilter_profile:
          name: "your value" # Required variable, string
          # cmd_flags_reserve_set: <value in [block, reset, monitor, ...]>
          # command_code_invalid: <value in [block, reset, monitor, ...]>
          # command_code_range: <string>
          # comment: <string>
          # log_packet: <value in [disable, enable]>
          # message_length_invalid: <value in [block, reset, monitor, ...]>
          # missing_request_action: <value in [block, reset, monitor, ...]>
          # monitor_all_messages: <value in [disable, enable]>
          # protocol_version_invalid: <value in [block, reset, monitor, ...]>
          # request_error_flag_set: <value in [block, reset, monitor, ...]>
          # track_requests_answers: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/diameter-filter/profile',
        '/pm/config/global/obj/diameter-filter/profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'diameterfilter_profile': {
            'type': 'dict',
            'v_range': [['7.4.2', '']],
            'options': {
                'cmd-flags-reserve-set': {'v_range': [['7.4.2', '']], 'choices': ['block', 'reset', 'monitor', 'allow'], 'type': 'str'},
                'command-code-invalid': {'v_range': [['7.4.2', '']], 'choices': ['block', 'reset', 'monitor', 'allow'], 'type': 'str'},
                'command-code-range': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'comment': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'log-packet': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'message-length-invalid': {'v_range': [['7.4.2', '']], 'choices': ['block', 'reset', 'monitor', 'allow'], 'type': 'str'},
                'missing-request-action': {'v_range': [['7.4.2', '']], 'choices': ['block', 'reset', 'monitor', 'allow'], 'type': 'str'},
                'monitor-all-messages': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.2', '']], 'required': True, 'type': 'str'},
                'protocol-version-invalid': {'v_range': [['7.4.2', '']], 'choices': ['block', 'reset', 'monitor', 'allow'], 'type': 'str'},
                'request-error-flag-set': {'v_range': [['7.4.2', '']], 'choices': ['block', 'reset', 'monitor', 'allow'], 'type': 'str'},
                'track-requests-answers': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'diameterfilter_profile'),
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
