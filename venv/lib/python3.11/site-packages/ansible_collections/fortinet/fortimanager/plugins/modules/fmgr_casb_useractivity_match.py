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
module: fmgr_casb_useractivity_match
short_description: CASB user activity match rules.
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
    user-activity:
        description: Deprecated, please use "user_activity"
        type: str
    user_activity:
        description: The parameter (user-activity) in requested url.
        type: str
    casb_useractivity_match:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            id:
                type: int
                description: CASB user activity match rules ID.
                required: true
            rules:
                type: list
                elements: dict
                description: Rules.
                suboptions:
                    case_sensitive:
                        aliases: ['case-sensitive']
                        type: str
                        description: CASB user activity match case sensitive.
                        choices:
                            - 'disable'
                            - 'enable'
                    domains:
                        type: list
                        elements: str
                        description: CASB user activity domain list.
                    header_name:
                        aliases: ['header-name']
                        type: str
                        description: CASB user activity rule header name.
                    id:
                        type: int
                        description: CASB user activity rule ID.
                    match_pattern:
                        aliases: ['match-pattern']
                        type: str
                        description: CASB user activity rule match pattern.
                        choices:
                            - 'simple'
                            - 'substr'
                            - 'regexp'
                    match_value:
                        aliases: ['match-value']
                        type: str
                        description: CASB user activity rule match value.
                    methods:
                        type: list
                        elements: str
                        description: CASB user activity method list.
                    negate:
                        type: str
                        description: Enable/disable what the matching strategy must not be.
                        choices:
                            - 'disable'
                            - 'enable'
                    type:
                        type: str
                        description: CASB user activity rule type.
                        choices:
                            - 'domains'
                            - 'host'
                            - 'path'
                            - 'header'
                            - 'header-value'
                            - 'method'
                            - 'body'
                    body_type:
                        aliases: ['body-type']
                        type: str
                        description: CASB user activity match rule body type.
                        choices:
                            - 'json'
                    jq:
                        type: str
                        description: CASB user activity rule match jq script.
            strategy:
                type: str
                description: CASB user activity rules strategy.
                choices:
                    - 'or'
                    - 'and'
            tenant_extraction:
                aliases: ['tenant-extraction']
                type: dict
                description: Tenant extraction.
                suboptions:
                    filters:
                        type: list
                        elements: dict
                        description: Filters.
                        suboptions:
                            body_type:
                                aliases: ['body-type']
                                type: str
                                description: CASB tenant extraction filter body type.
                                choices:
                                    - 'json'
                            direction:
                                type: str
                                description: CASB tenant extraction filter direction.
                                choices:
                                    - 'request'
                                    - 'response'
                            header_name:
                                aliases: ['header-name']
                                type: str
                                description: CASB tenant extraction filter header name.
                            id:
                                type: int
                                description: CASB tenant extraction filter ID.
                            place:
                                type: str
                                description: CASB tenant extraction filter place type.
                                choices:
                                    - 'path'
                                    - 'header'
                                    - 'body'
                    jq:
                        type: str
                        description: CASB user activity tenant extraction jq script.
                    status:
                        type: str
                        description: Enable/disable CASB tenant extraction.
                        choices:
                            - 'disable'
                            - 'enable'
                    type:
                        type: str
                        description: CASB user activity tenant extraction type.
                        choices:
                            - 'json-query'
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
    - name: CASB user activity match rules.
      fortinet.fortimanager.fmgr_casb_useractivity_match:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        user_activity: <your own value>
        state: present # <value in [present, absent]>
        casb_useractivity_match:
          id: 0 # Required variable, integer
          # rules:
          #   - case_sensitive: <value in [disable, enable]>
          #     domains: <list or string>
          #     header_name: <string>
          #     id: <integer>
          #     match_pattern: <value in [simple, substr, regexp]>
          #     match_value: <string>
          #     methods: <list or string>
          #     negate: <value in [disable, enable]>
          #     type: <value in [domains, host, path, ...]>
          #     body_type: <value in [json]>
          #     jq: <string>
          # strategy: <value in [or, and]>
          # tenant_extraction:
          #   filters:
          #     - body_type: <value in [json]>
          #       direction: <value in [request, response]>
          #       header_name: <string>
          #       id: <integer>
          #       place: <value in [path, header, body]>
          #   jq: <string>
          #   status: <value in [disable, enable]>
          #   type: <value in [json-query]>
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
        '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match',
        '/pm/config/global/obj/casb/user-activity/{user-activity}/match'
    ]
    url_params = ['adom', 'user-activity']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'user-activity': {'type': 'str', 'api_name': 'user_activity'},
        'user_activity': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'casb_useractivity_match': {
            'type': 'dict',
            'v_range': [['7.4.1', '']],
            'options': {
                'id': {'v_range': [['7.4.1', '']], 'required': True, 'type': 'int'},
                'rules': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'options': {
                        'case-sensitive': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'domains': {'v_range': [['7.4.1', '']], 'type': 'list', 'elements': 'str'},
                        'header-name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'id': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'match-pattern': {'v_range': [['7.4.1', '']], 'choices': ['simple', 'substr', 'regexp'], 'type': 'str'},
                        'match-value': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'methods': {'v_range': [['7.4.1', '']], 'type': 'list', 'elements': 'str'},
                        'negate': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'type': {
                            'v_range': [['7.4.1', '']],
                            'choices': ['domains', 'host', 'path', 'header', 'header-value', 'method', 'body'],
                            'type': 'str'
                        },
                        'body-type': {'v_range': [['7.6.2', '']], 'choices': ['json'], 'type': 'str'},
                        'jq': {'v_range': [['7.6.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'strategy': {'v_range': [['7.4.1', '']], 'choices': ['or', 'and'], 'type': 'str'},
                'tenant-extraction': {
                    'v_range': [['7.6.2', '']],
                    'type': 'dict',
                    'options': {
                        'filters': {
                            'v_range': [['7.6.2', '']],
                            'type': 'list',
                            'options': {
                                'body-type': {'v_range': [['7.6.2', '']], 'choices': ['json'], 'type': 'str'},
                                'direction': {'v_range': [['7.6.2', '']], 'choices': ['request', 'response'], 'type': 'str'},
                                'header-name': {'v_range': [['7.6.2', '']], 'type': 'str'},
                                'id': {'v_range': [['7.6.2', '']], 'type': 'int'},
                                'place': {'v_range': [['7.6.2', '']], 'choices': ['path', 'header', 'body'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'jq': {'v_range': [['7.6.2', '']], 'type': 'str'},
                        'status': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'type': {'v_range': [['7.6.2', '']], 'choices': ['json-query'], 'type': 'str'}
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'casb_useractivity_match'),
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
