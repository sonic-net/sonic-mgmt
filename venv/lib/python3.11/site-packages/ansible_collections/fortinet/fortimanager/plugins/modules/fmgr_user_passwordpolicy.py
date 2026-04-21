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
module: fmgr_user_passwordpolicy
short_description: Configure user password policy.
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
    user_passwordpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            expire_days:
                aliases: ['expire-days']
                type: int
                description: Time in days before the users password expires.
            name:
                type: str
                description: Password policy name.
                required: true
            warn_days:
                aliases: ['warn-days']
                type: int
                description: Time in days before a password expiration warning message is displayed to the user upon login.
            expired_password_renewal:
                aliases: ['expired-password-renewal']
                type: str
                description: Enable/disable renewal of a password that already is expired.
                choices:
                    - 'disable'
                    - 'enable'
            expire_status:
                aliases: ['expire-status']
                type: str
                description: Enable/disable password expiration.
                choices:
                    - 'disable'
                    - 'enable'
            min_change_characters:
                aliases: ['min-change-characters']
                type: int
                description: Minimum number of unique characters in new password which do not exist in old password
            min_lower_case_letter:
                aliases: ['min-lower-case-letter']
                type: int
                description: Minimum number of lowercase characters in password
            min_non_alphanumeric:
                aliases: ['min-non-alphanumeric']
                type: int
                description: Minimum number of non-alphanumeric characters in password
            min_number:
                aliases: ['min-number']
                type: int
                description: Minimum number of numeric characters in password
            min_upper_case_letter:
                aliases: ['min-upper-case-letter']
                type: int
                description: Minimum number of uppercase characters in password
            minimum_length:
                aliases: ['minimum-length']
                type: int
                description: Minimum password length
            reuse_password:
                aliases: ['reuse-password']
                type: str
                description: Enable/disable reuse of password.
                choices:
                    - 'disable'
                    - 'enable'
            reuse_password_limit:
                aliases: ['reuse-password-limit']
                type: int
                description: Number of times passwords can be reused
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
    - name: Configure user password policy.
      fortinet.fortimanager.fmgr_user_passwordpolicy:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        user_passwordpolicy:
          name: "your value" # Required variable, string
          # expire_days: <integer>
          # warn_days: <integer>
          # expired_password_renewal: <value in [disable, enable]>
          # expire_status: <value in [disable, enable]>
          # min_change_characters: <integer>
          # min_lower_case_letter: <integer>
          # min_non_alphanumeric: <integer>
          # min_number: <integer>
          # min_upper_case_letter: <integer>
          # minimum_length: <integer>
          # reuse_password: <value in [disable, enable]>
          # reuse_password_limit: <integer>
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
        '/pm/config/adom/{adom}/obj/user/password-policy',
        '/pm/config/global/obj/user/password-policy'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_passwordpolicy': {
            'type': 'dict',
            'no_log': False,
            'v_range': [['6.0.0', '']],
            'options': {
                'expire-days': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'warn-days': {'type': 'int'},
                'expired-password-renewal': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'expire-status': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'min-change-characters': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'min-lower-case-letter': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'min-non-alphanumeric': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'min-number': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'min-upper-case-letter': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'minimum-length': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'reuse-password': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'reuse-password-limit': {'v_range': [['7.6.0', '']], 'no_log': True, 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_passwordpolicy'),
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
