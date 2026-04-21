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
module: fmgr_casb_profile_saasapplication
short_description: CASB profile SaaS application.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.3.0"
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    casb_profile_saasapplication:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            access_rule:
                aliases: ['access-rule']
                type: list
                elements: dict
                description: Access rule.
                suboptions:
                    action:
                        type: str
                        description: CASB access rule action.
                        choices:
                            - 'block'
                            - 'bypass'
                            - 'monitor'
                    bypass:
                        type: list
                        elements: str
                        description: CASB bypass options.
                        choices:
                            - 'av'
                            - 'dlp'
                            - 'web-filter'
                            - 'file-filter'
                            - 'video-filter'
                    name:
                        type: str
                        description: CASB access rule activity name.
                    attribute_filter:
                        aliases: ['attribute-filter']
                        type: list
                        elements: dict
                        description: Attribute filter.
                        suboptions:
                            action:
                                type: str
                                description: CASB access rule tenant control action.
                                choices:
                                    - 'block'
                                    - 'monitor'
                                    - 'bypass'
                            attribute_match:
                                aliases: ['attribute-match']
                                type: list
                                elements: str
                                description: CASB access rule tenant match.
                            id:
                                type: int
                                description: CASB tenant control ID.
            custom_control:
                aliases: ['custom-control']
                type: list
                elements: dict
                description: Custom control.
                suboptions:
                    name:
                        type: str
                        description: CASB custom control user activity name.
                    option:
                        type: list
                        elements: dict
                        description: Option.
                        suboptions:
                            name:
                                type: str
                                description: CASB custom control option name.
                            user_input:
                                aliases: ['user-input']
                                type: list
                                elements: str
                                description: CASB custom control user input.
                    attribute_filter:
                        aliases: ['attribute-filter']
                        type: list
                        elements: dict
                        description: Attribute filter.
                        suboptions:
                            action:
                                type: str
                                description: CASB access rule tenant control action.
                                choices:
                                    - 'block'
                                    - 'monitor'
                                    - 'bypass'
                            attribute_match:
                                aliases: ['attribute-match']
                                type: list
                                elements: str
                                description: CASB access rule tenant match.
                            id:
                                type: int
                                description: CASB tenant control ID.
            domain_control:
                aliases: ['domain-control']
                type: str
                description: Enable/disable domain control.
                choices:
                    - 'disable'
                    - 'enable'
            domain_control_domains:
                aliases: ['domain-control-domains']
                type: list
                elements: str
                description: CASB profile domain control domains.
            log:
                type: str
                description: Enable/disable log settings.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: CASB profile SaaS application name.
                required: true
            safe_search:
                aliases: ['safe-search']
                type: str
                description: Enable/disable safe search.
                choices:
                    - 'disable'
                    - 'enable'
            safe_search_control:
                aliases: ['safe-search-control']
                type: list
                elements: str
                description: CASB profile safe search control.
            tenant_control:
                aliases: ['tenant-control']
                type: str
                description: Enable/disable tenant control.
                choices:
                    - 'disable'
                    - 'enable'
            tenant_control_tenants:
                aliases: ['tenant-control-tenants']
                type: list
                elements: str
                description: CASB profile tenant control tenants.
            status:
                type: str
                description: Enable/disable setting.
                choices:
                    - 'disable'
                    - 'enable'
            advanced_tenant_control:
                aliases: ['advanced-tenant-control']
                type: list
                elements: dict
                description: Advanced tenant control.
                suboptions:
                    attribute:
                        type: list
                        elements: dict
                        description: Attribute.
                        suboptions:
                            input:
                                type: list
                                elements: str
                                description: CASB extend user input value.
                            name:
                                type: str
                                description: CASB extend user input name.
                    name:
                        type: list
                        elements: str
                        description: CASB advanced tenant control name.
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
    - name: CASB profile SaaS application.
      fortinet.fortimanager.fmgr_casb_profile_saasapplication:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        profile: <your own value>
        state: present # <value in [present, absent]>
        casb_profile_saasapplication:
          name: "your value" # Required variable, string
          # access_rule:
          #   - action: <value in [block, bypass, monitor]>
          #     bypass:
          #       - "av"
          #       - "dlp"
          #       - "web-filter"
          #       - "file-filter"
          #       - "video-filter"
          #     name: <string>
          #     attribute_filter:
          #       - action: <value in [block, monitor, bypass]>
          #         attribute_match: <list or string>
          #         id: <integer>
          # custom_control:
          #   - name: <string>
          #     option:
          #       - name: <string>
          #         user_input: <list or string>
          #     attribute_filter:
          #       - action: <value in [block, monitor, bypass]>
          #         attribute_match: <list or string>
          #         id: <integer>
          # domain_control: <value in [disable, enable]>
          # domain_control_domains: <list or string>
          # log: <value in [disable, enable]>
          # safe_search: <value in [disable, enable]>
          # safe_search_control: <list or string>
          # tenant_control: <value in [disable, enable]>
          # tenant_control_tenants: <list or string>
          # status: <value in [disable, enable]>
          # advanced_tenant_control:
          #   - attribute:
          #       - input: <list or string>
          #         name: <string>
          #     name: <list or string>
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
        '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application',
        '/pm/config/global/obj/casb/profile/{profile}/saas-application'
    ]
    url_params = ['adom', 'profile']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'casb_profile_saasapplication': {
            'type': 'dict',
            'v_range': [['7.4.1', '']],
            'options': {
                'access-rule': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.4.1', '']], 'choices': ['block', 'bypass', 'monitor'], 'type': 'str'},
                        'bypass': {
                            'v_range': [['7.4.1', '']],
                            'type': 'list',
                            'choices': ['av', 'dlp', 'web-filter', 'file-filter', 'video-filter'],
                            'elements': 'str'
                        },
                        'name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'attribute-filter': {
                            'v_range': [['7.6.2', '']],
                            'type': 'list',
                            'options': {
                                'action': {'v_range': [['7.6.2', '']], 'choices': ['block', 'monitor', 'bypass'], 'type': 'str'},
                                'attribute-match': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                                'id': {'v_range': [['7.6.2', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        }
                    },
                    'elements': 'dict'
                },
                'custom-control': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'option': {
                            'v_range': [['7.4.1', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                                'user-input': {'v_range': [['7.4.1', '']], 'type': 'list', 'elements': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'attribute-filter': {
                            'v_range': [['7.6.2', '']],
                            'type': 'list',
                            'options': {
                                'action': {'v_range': [['7.6.2', '']], 'choices': ['block', 'monitor', 'bypass'], 'type': 'str'},
                                'attribute-match': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                                'id': {'v_range': [['7.6.2', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        }
                    },
                    'elements': 'dict'
                },
                'domain-control': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'domain-control-domains': {'v_range': [['7.4.1', '']], 'type': 'list', 'elements': 'str'},
                'log': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.1', '']], 'required': True, 'type': 'str'},
                'safe-search': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'safe-search-control': {'v_range': [['7.4.1', '']], 'type': 'list', 'elements': 'str'},
                'tenant-control': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tenant-control-tenants': {'v_range': [['7.4.1', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'advanced-tenant-control': {
                    'v_range': [['7.6.2', '']],
                    'type': 'list',
                    'options': {
                        'attribute': {
                            'v_range': [['7.6.2', '']],
                            'type': 'list',
                            'options': {
                                'input': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                                'name': {'v_range': [['7.6.2', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'name': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'casb_profile_saasapplication'),
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
