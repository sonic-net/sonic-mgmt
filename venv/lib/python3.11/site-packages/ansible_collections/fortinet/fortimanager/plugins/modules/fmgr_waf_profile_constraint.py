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
module: fmgr_waf_profile_constraint
short_description: WAF HTTP protocol restrictions.
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
    waf_profile_constraint:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            content_length:
                aliases: ['content-length']
                type: dict
                description: Content length.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'block'
                    length:
                        type: int
                        description: Length of HTTP content in bytes
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Enable/disable the constraint.
                        choices:
                            - 'disable'
                            - 'enable'
            exception:
                type: list
                elements: dict
                description: Exception.
                suboptions:
                    address:
                        type: str
                        description: Host address.
                    content_length:
                        aliases: ['content-length']
                        type: str
                        description: HTTP content length in request.
                        choices:
                            - 'disable'
                            - 'enable'
                    header_length:
                        aliases: ['header-length']
                        type: str
                        description: HTTP header length in request.
                        choices:
                            - 'disable'
                            - 'enable'
                    hostname:
                        type: str
                        description: Enable/disable hostname check.
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: Exception ID.
                    line_length:
                        aliases: ['line-length']
                        type: str
                        description: HTTP line length in request.
                        choices:
                            - 'disable'
                            - 'enable'
                    malformed:
                        type: str
                        description: Enable/disable malformed HTTP request check.
                        choices:
                            - 'disable'
                            - 'enable'
                    max_cookie:
                        aliases: ['max-cookie']
                        type: str
                        description: Maximum number of cookies in HTTP request.
                        choices:
                            - 'disable'
                            - 'enable'
                    max_header_line:
                        aliases: ['max-header-line']
                        type: str
                        description: Maximum number of HTTP header line.
                        choices:
                            - 'disable'
                            - 'enable'
                    max_range_segment:
                        aliases: ['max-range-segment']
                        type: str
                        description: Maximum number of range segments in HTTP range line.
                        choices:
                            - 'disable'
                            - 'enable'
                    max_url_param:
                        aliases: ['max-url-param']
                        type: str
                        description: Maximum number of parameters in URL.
                        choices:
                            - 'disable'
                            - 'enable'
                    method:
                        type: str
                        description: Enable/disable HTTP method check.
                        choices:
                            - 'disable'
                            - 'enable'
                    param_length:
                        aliases: ['param-length']
                        type: str
                        description: Maximum length of parameter in URL, HTTP POST request or HTTP body.
                        choices:
                            - 'disable'
                            - 'enable'
                    pattern:
                        type: str
                        description: URL pattern.
                    regex:
                        type: str
                        description: Enable/disable regular expression based pattern match.
                        choices:
                            - 'disable'
                            - 'enable'
                    url_param_length:
                        aliases: ['url-param-length']
                        type: str
                        description: Maximum length of parameter in URL.
                        choices:
                            - 'disable'
                            - 'enable'
                    version:
                        type: str
                        description: Enable/disable HTTP version check.
                        choices:
                            - 'disable'
                            - 'enable'
            header_length:
                aliases: ['header-length']
                type: dict
                description: Header length.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'block'
                    length:
                        type: int
                        description: Length of HTTP header in bytes
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Enable/disable the constraint.
                        choices:
                            - 'disable'
                            - 'enable'
            hostname:
                type: dict
                description: Hostname.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Enable/disable the constraint.
                        choices:
                            - 'disable'
                            - 'enable'
            line_length:
                aliases: ['line-length']
                type: dict
                description: Line length.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'block'
                    length:
                        type: int
                        description: Length of HTTP line in bytes
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Enable/disable the constraint.
                        choices:
                            - 'disable'
                            - 'enable'
            malformed:
                type: dict
                description: Malformed.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Enable/disable the constraint.
                        choices:
                            - 'disable'
                            - 'enable'
            max_cookie:
                aliases: ['max-cookie']
                type: dict
                description: Max cookie.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    max_cookie:
                        aliases: ['max-cookie']
                        type: int
                        description: Maximum number of cookies in HTTP request
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Enable/disable the constraint.
                        choices:
                            - 'disable'
                            - 'enable'
            max_header_line:
                aliases: ['max-header-line']
                type: dict
                description: Max header line.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    max_header_line:
                        aliases: ['max-header-line']
                        type: int
                        description: Maximum number HTTP header lines
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Enable/disable the constraint.
                        choices:
                            - 'disable'
                            - 'enable'
            max_range_segment:
                aliases: ['max-range-segment']
                type: dict
                description: Max range segment.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    max_range_segment:
                        aliases: ['max-range-segment']
                        type: int
                        description: Maximum number of range segments in HTTP range line
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Enable/disable the constraint.
                        choices:
                            - 'disable'
                            - 'enable'
            max_url_param:
                aliases: ['max-url-param']
                type: dict
                description: Max url param.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    max_url_param:
                        aliases: ['max-url-param']
                        type: int
                        description: Maximum number of parameters in URL
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Enable/disable the constraint.
                        choices:
                            - 'disable'
                            - 'enable'
            method:
                type: dict
                description: Method.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Enable/disable the constraint.
                        choices:
                            - 'disable'
                            - 'enable'
            param_length:
                aliases: ['param-length']
                type: dict
                description: Param length.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'block'
                    length:
                        type: int
                        description: Maximum length of parameter in URL, HTTP POST request or HTTP body in bytes
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Enable/disable the constraint.
                        choices:
                            - 'disable'
                            - 'enable'
            url_param_length:
                aliases: ['url-param-length']
                type: dict
                description: Url param length.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'block'
                    length:
                        type: int
                        description: Maximum length of URL parameter in bytes
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Enable/disable the constraint.
                        choices:
                            - 'disable'
                            - 'enable'
            version:
                type: dict
                description: Version.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'block'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Enable/disable the constraint.
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
    - name: WAF HTTP protocol restrictions.
      fortinet.fortimanager.fmgr_waf_profile_constraint:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        profile: <your own value>
        waf_profile_constraint:
          # content_length:
          #   action: <value in [allow, block]>
          #   length: <integer>
          #   log: <value in [disable, enable]>
          #   severity: <value in [low, medium, high]>
          #   status: <value in [disable, enable]>
          # exception:
          #   - address: <string>
          #     content_length: <value in [disable, enable]>
          #     header_length: <value in [disable, enable]>
          #     hostname: <value in [disable, enable]>
          #     id: <integer>
          #     line_length: <value in [disable, enable]>
          #     malformed: <value in [disable, enable]>
          #     max_cookie: <value in [disable, enable]>
          #     max_header_line: <value in [disable, enable]>
          #     max_range_segment: <value in [disable, enable]>
          #     max_url_param: <value in [disable, enable]>
          #     method: <value in [disable, enable]>
          #     param_length: <value in [disable, enable]>
          #     pattern: <string>
          #     regex: <value in [disable, enable]>
          #     url_param_length: <value in [disable, enable]>
          #     version: <value in [disable, enable]>
          # header_length:
          #   action: <value in [allow, block]>
          #   length: <integer>
          #   log: <value in [disable, enable]>
          #   severity: <value in [low, medium, high]>
          #   status: <value in [disable, enable]>
          # hostname:
          #   action: <value in [allow, block]>
          #   log: <value in [disable, enable]>
          #   severity: <value in [low, medium, high]>
          #   status: <value in [disable, enable]>
          # line_length:
          #   action: <value in [allow, block]>
          #   length: <integer>
          #   log: <value in [disable, enable]>
          #   severity: <value in [low, medium, high]>
          #   status: <value in [disable, enable]>
          # malformed:
          #   action: <value in [allow, block]>
          #   log: <value in [disable, enable]>
          #   severity: <value in [low, medium, high]>
          #   status: <value in [disable, enable]>
          # max_cookie:
          #   action: <value in [allow, block]>
          #   log: <value in [disable, enable]>
          #   max_cookie: <integer>
          #   severity: <value in [low, medium, high]>
          #   status: <value in [disable, enable]>
          # max_header_line:
          #   action: <value in [allow, block]>
          #   log: <value in [disable, enable]>
          #   max_header_line: <integer>
          #   severity: <value in [low, medium, high]>
          #   status: <value in [disable, enable]>
          # max_range_segment:
          #   action: <value in [allow, block]>
          #   log: <value in [disable, enable]>
          #   max_range_segment: <integer>
          #   severity: <value in [low, medium, high]>
          #   status: <value in [disable, enable]>
          # max_url_param:
          #   action: <value in [allow, block]>
          #   log: <value in [disable, enable]>
          #   max_url_param: <integer>
          #   severity: <value in [low, medium, high]>
          #   status: <value in [disable, enable]>
          # method:
          #   action: <value in [allow, block]>
          #   log: <value in [disable, enable]>
          #   severity: <value in [low, medium, high]>
          #   status: <value in [disable, enable]>
          # param_length:
          #   action: <value in [allow, block]>
          #   length: <integer>
          #   log: <value in [disable, enable]>
          #   severity: <value in [low, medium, high]>
          #   status: <value in [disable, enable]>
          # url_param_length:
          #   action: <value in [allow, block]>
          #   length: <integer>
          #   log: <value in [disable, enable]>
          #   severity: <value in [low, medium, high]>
          #   status: <value in [disable, enable]>
          # version:
          #   action: <value in [allow, block]>
          #   log: <value in [disable, enable]>
          #   severity: <value in [low, medium, high]>
          #   status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint',
        '/pm/config/global/obj/waf/profile/{profile}/constraint'
    ]
    url_params = ['adom', 'profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'waf_profile_constraint': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'content-length': {
                    'type': 'dict',
                    'options': {
                        'action': {'choices': ['allow', 'block'], 'type': 'str'},
                        'length': {'type': 'int'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'exception': {
                    'type': 'list',
                    'options': {
                        'address': {'type': 'str'},
                        'content-length': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'header-length': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'hostname': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'type': 'int'},
                        'line-length': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'malformed': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-cookie': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-header-line': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-range-segment': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-url-param': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'method': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'param-length': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'pattern': {'type': 'str'},
                        'regex': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'url-param-length': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'version': {'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'header-length': {
                    'type': 'dict',
                    'options': {
                        'action': {'choices': ['allow', 'block'], 'type': 'str'},
                        'length': {'type': 'int'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'hostname': {
                    'type': 'dict',
                    'options': {
                        'action': {'choices': ['allow', 'block'], 'type': 'str'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'line-length': {
                    'type': 'dict',
                    'options': {
                        'action': {'choices': ['allow', 'block'], 'type': 'str'},
                        'length': {'type': 'int'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'malformed': {
                    'type': 'dict',
                    'options': {
                        'action': {'choices': ['allow', 'block'], 'type': 'str'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'max-cookie': {
                    'type': 'dict',
                    'options': {
                        'action': {'choices': ['allow', 'block'], 'type': 'str'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-cookie': {'type': 'int'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'max-header-line': {
                    'type': 'dict',
                    'options': {
                        'action': {'choices': ['allow', 'block'], 'type': 'str'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-header-line': {'type': 'int'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'max-range-segment': {
                    'type': 'dict',
                    'options': {
                        'action': {'choices': ['allow', 'block'], 'type': 'str'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-range-segment': {'type': 'int'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'max-url-param': {
                    'type': 'dict',
                    'options': {
                        'action': {'choices': ['allow', 'block'], 'type': 'str'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-url-param': {'type': 'int'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'method': {
                    'type': 'dict',
                    'options': {
                        'action': {'choices': ['allow', 'block'], 'type': 'str'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'param-length': {
                    'type': 'dict',
                    'options': {
                        'action': {'choices': ['allow', 'block'], 'type': 'str'},
                        'length': {'type': 'int'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'url-param-length': {
                    'type': 'dict',
                    'options': {
                        'action': {'choices': ['allow', 'block'], 'type': 'str'},
                        'length': {'type': 'int'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'version': {
                    'type': 'dict',
                    'options': {
                        'action': {'choices': ['allow', 'block'], 'type': 'str'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'waf_profile_constraint'),
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
