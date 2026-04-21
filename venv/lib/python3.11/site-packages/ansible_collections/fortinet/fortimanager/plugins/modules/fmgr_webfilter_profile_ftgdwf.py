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
module: fmgr_webfilter_profile_ftgdwf
short_description: FortiGuard Web Filter settings.
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
    webfilter_profile_ftgdwf:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            exempt_quota:
                aliases: ['exempt-quota']
                type: raw
                description: (list or str) Do not stop quota for these categories.
            filters:
                type: list
                elements: dict
                description: Filters.
                suboptions:
                    action:
                        type: str
                        description: Action to take for matches.
                        choices:
                            - 'block'
                            - 'monitor'
                            - 'warning'
                            - 'authenticate'
                    auth_usr_grp:
                        aliases: ['auth-usr-grp']
                        type: raw
                        description: (list or str) Groups with permission to authenticate.
                    category:
                        type: str
                        description: Categories and groups the filter examines.
                    id:
                        type: int
                        description: ID number.
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    override_replacemsg:
                        aliases: ['override-replacemsg']
                        type: str
                        description: Override replacement message.
                    warn_duration:
                        aliases: ['warn-duration']
                        type: str
                        description: Duration of warnings.
                    warning_duration_type:
                        aliases: ['warning-duration-type']
                        type: str
                        description: Re-display warning after closing browser or after a timeout.
                        choices:
                            - 'session'
                            - 'timeout'
                    warning_prompt:
                        aliases: ['warning-prompt']
                        type: str
                        description: Warning prompts in each category or each domain.
                        choices:
                            - 'per-domain'
                            - 'per-category'
            max_quota_timeout:
                aliases: ['max-quota-timeout']
                type: int
                description: Maximum FortiGuard quota used by single page view in seconds
            options:
                type: list
                elements: str
                description: Options for FortiGuard Web Filter.
                choices:
                    - 'error-allow'
                    - 'http-err-detail'
                    - 'rate-image-urls'
                    - 'strict-blocking'
                    - 'rate-server-ip'
                    - 'redir-block'
                    - 'connect-request-bypass'
                    - 'log-all-url'
                    - 'ftgd-disable'
            ovrd:
                type: raw
                description: (list or str) Allow web filter profile overrides.
            quota:
                type: list
                elements: dict
                description: Quota.
                suboptions:
                    category:
                        type: raw
                        description: (list or str) FortiGuard categories to apply quota to
                    duration:
                        type: str
                        description: Duration of quota.
                    id:
                        type: int
                        description: ID number.
                    override_replacemsg:
                        aliases: ['override-replacemsg']
                        type: str
                        description: Override replacement message.
                    type:
                        type: str
                        description: Quota type.
                        choices:
                            - 'time'
                            - 'traffic'
                    unit:
                        type: str
                        description: Traffic quota unit of measurement.
                        choices:
                            - 'B'
                            - 'KB'
                            - 'MB'
                            - 'GB'
                    value:
                        type: int
                        description: Traffic quota value.
            rate_crl_urls:
                aliases: ['rate-crl-urls']
                type: str
                description: Enable/disable rating CRL by URL.
                choices:
                    - 'disable'
                    - 'enable'
            rate_css_urls:
                aliases: ['rate-css-urls']
                type: str
                description: Enable/disable rating CSS by URL.
                choices:
                    - 'disable'
                    - 'enable'
            rate_image_urls:
                aliases: ['rate-image-urls']
                type: str
                description: Enable/disable rating images by URL.
                choices:
                    - 'disable'
                    - 'enable'
            rate_javascript_urls:
                aliases: ['rate-javascript-urls']
                type: str
                description: Enable/disable rating JavaScript by URL.
                choices:
                    - 'disable'
                    - 'enable'
            category_override:
                aliases: ['category-override']
                type: str
                description: Local categories take precedence over FortiGuard categories.
            risk:
                type: list
                elements: dict
                description: Risk.
                suboptions:
                    action:
                        type: str
                        description: Action to take for matches.
                        choices:
                            - 'block'
                            - 'monitor'
                    id:
                        type: int
                        description: ID number.
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    risk_level:
                        aliases: ['risk-level']
                        type: raw
                        description: (list) Risk level to be examined.
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
    - name: FortiGuard Web Filter settings.
      fortinet.fortimanager.fmgr_webfilter_profile_ftgdwf:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        profile: <your own value>
        webfilter_profile_ftgdwf:
          # exempt_quota: <list or string>
          # filters:
          #   - action: <value in [block, monitor, warning, ...]>
          #     auth_usr_grp: <list or string>
          #     category: <string>
          #     id: <integer>
          #     log: <value in [disable, enable]>
          #     override_replacemsg: <string>
          #     warn_duration: <string>
          #     warning_duration_type: <value in [session, timeout]>
          #     warning_prompt: <value in [per-domain, per-category]>
          # max_quota_timeout: <integer>
          # options:
          #   - "error-allow"
          #   - "http-err-detail"
          #   - "rate-image-urls"
          #   - "strict-blocking"
          #   - "rate-server-ip"
          #   - "redir-block"
          #   - "connect-request-bypass"
          #   - "log-all-url"
          #   - "ftgd-disable"
          # ovrd: <list or string>
          # quota:
          #   - category: <list or string>
          #     duration: <string>
          #     id: <integer>
          #     override_replacemsg: <string>
          #     type: <value in [time, traffic]>
          #     unit: <value in [B, KB, MB, ...]>
          #     value: <integer>
          # rate_crl_urls: <value in [disable, enable]>
          # rate_css_urls: <value in [disable, enable]>
          # rate_image_urls: <value in [disable, enable]>
          # rate_javascript_urls: <value in [disable, enable]>
          # category_override: <string>
          # risk:
          #   - action: <value in [block, monitor]>
          #     id: <integer>
          #     log: <value in [disable, enable]>
          #     risk_level: <list or string>
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
        '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf',
        '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf'
    ]
    url_params = ['adom', 'profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'webfilter_profile_ftgdwf': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'exempt-quota': {'type': 'raw'},
                'filters': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['block', 'monitor', 'warning', 'authenticate'], 'type': 'str'},
                        'auth-usr-grp': {'type': 'raw'},
                        'category': {'type': 'str'},
                        'id': {'type': 'int'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-replacemsg': {'type': 'str'},
                        'warn-duration': {'type': 'str'},
                        'warning-duration-type': {'choices': ['session', 'timeout'], 'type': 'str'},
                        'warning-prompt': {'choices': ['per-domain', 'per-category'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'max-quota-timeout': {'type': 'int'},
                'options': {
                    'type': 'list',
                    'choices': [
                        'error-allow', 'http-err-detail', 'rate-image-urls', 'strict-blocking', 'rate-server-ip', 'redir-block',
                        'connect-request-bypass', 'log-all-url', 'ftgd-disable'
                    ],
                    'elements': 'str'
                },
                'ovrd': {'type': 'raw'},
                'quota': {
                    'type': 'list',
                    'options': {
                        'category': {'type': 'raw'},
                        'duration': {'type': 'str'},
                        'id': {'type': 'int'},
                        'override-replacemsg': {'type': 'str'},
                        'type': {'choices': ['time', 'traffic'], 'type': 'str'},
                        'unit': {'choices': ['B', 'KB', 'MB', 'GB'], 'type': 'str'},
                        'value': {'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'rate-crl-urls': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rate-css-urls': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rate-image-urls': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rate-javascript-urls': {'choices': ['disable', 'enable'], 'type': 'str'},
                'category-override': {'v_range': [['6.2.0', '6.4.15']], 'type': 'str'},
                'risk': {
                    'v_range': [['7.6.2', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.6.2', '']], 'choices': ['block', 'monitor'], 'type': 'str'},
                        'id': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'log': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'risk-level': {'v_range': [['7.6.2', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_profile_ftgdwf'),
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
