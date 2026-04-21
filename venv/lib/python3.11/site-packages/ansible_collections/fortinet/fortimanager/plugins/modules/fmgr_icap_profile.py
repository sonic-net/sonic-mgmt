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
module: fmgr_icap_profile
short_description: Configure ICAP profiles.
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
    icap_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            methods:
                type: list
                elements: str
                description: The allowed HTTP methods that will be sent to ICAP server for further processing.
                choices:
                    - 'delete'
                    - 'get'
                    - 'head'
                    - 'options'
                    - 'post'
                    - 'put'
                    - 'trace'
                    - 'other'
                    - 'connect'
            name:
                type: str
                description: ICAP profile name.
                required: true
            replacemsg_group:
                aliases: ['replacemsg-group']
                type: str
                description: Replacement message group.
            request:
                type: str
                description: Enable/disable whether an HTTP request is passed to an ICAP server.
                choices:
                    - 'disable'
                    - 'enable'
            request_failure:
                aliases: ['request-failure']
                type: str
                description: Action to take if the ICAP server cannot be contacted when processing an HTTP request.
                choices:
                    - 'error'
                    - 'bypass'
            request_path:
                aliases: ['request-path']
                type: str
                description: Path component of the ICAP URI that identifies the HTTP request processing service.
            request_server:
                aliases: ['request-server']
                type: str
                description: ICAP server to use for an HTTP request.
            response:
                type: str
                description: Enable/disable whether an HTTP response is passed to an ICAP server.
                choices:
                    - 'disable'
                    - 'enable'
            response_failure:
                aliases: ['response-failure']
                type: str
                description: Action to take if the ICAP server cannot be contacted when processing an HTTP response.
                choices:
                    - 'error'
                    - 'bypass'
            response_path:
                aliases: ['response-path']
                type: str
                description: Path component of the ICAP URI that identifies the HTTP response processing service.
            response_server:
                aliases: ['response-server']
                type: str
                description: ICAP server to use for an HTTP response.
            streaming_content_bypass:
                aliases: ['streaming-content-bypass']
                type: str
                description: Enable/disable bypassing of ICAP server for streaming content.
                choices:
                    - 'disable'
                    - 'enable'
            icap_headers:
                aliases: ['icap-headers']
                type: list
                elements: dict
                description: Icap headers.
                suboptions:
                    base64_encoding:
                        aliases: ['base64-encoding']
                        type: str
                        description: Enable/disable use of base64 encoding of HTTP content.
                        choices:
                            - 'disable'
                            - 'enable'
                    content:
                        type: str
                        description: HTTP header content.
                    id:
                        type: int
                        description: HTTP forwarded header ID.
                    name:
                        type: str
                        description: HTTP forwarded header name.
            preview:
                type: str
                description: Enable/disable preview of data to ICAP server.
                choices:
                    - 'disable'
                    - 'enable'
            preview_data_length:
                aliases: ['preview-data-length']
                type: int
                description: Preview data length to be sent to ICAP server.
            response_req_hdr:
                aliases: ['response-req-hdr']
                type: str
                description: Enable/disable addition of req-hdr for ICAP response modification
                choices:
                    - 'disable'
                    - 'enable'
            respmod_default_action:
                aliases: ['respmod-default-action']
                type: str
                description: Default action to ICAP response modification
                choices:
                    - 'bypass'
                    - 'forward'
            respmod_forward_rules:
                aliases: ['respmod-forward-rules']
                type: list
                elements: dict
                description: Respmod forward rules.
                suboptions:
                    action:
                        type: str
                        description: Action to be taken for ICAP server.
                        choices:
                            - 'bypass'
                            - 'forward'
                    header_group:
                        aliases: ['header-group']
                        type: list
                        elements: dict
                        description: Header group.
                        suboptions:
                            case_sensitivity:
                                aliases: ['case-sensitivity']
                                type: str
                                description: Enable/disable case sensitivity when matching header.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            header:
                                type: str
                                description: HTTP header regular expression.
                            header_name:
                                aliases: ['header-name']
                                type: str
                                description: HTTP header.
                            id:
                                type: int
                                description: ID.
                    host:
                        type: str
                        description: Address object for the host.
                    http_resp_status_code:
                        aliases: ['http-resp-status-code']
                        type: raw
                        description: (list) HTTP response status code.
                    name:
                        type: str
                        description: Address name.
            204_response:
                aliases: ['204-response']
                type: str
                description: Enable/disable allowance of 204 response from ICAP server.
                choices:
                    - 'disable'
                    - 'enable'
            204_size_limit:
                aliases: ['204-size-limit']
                type: int
                description: 204 response size limit to be saved by ICAP client in megabytes
            chunk_encap:
                aliases: ['chunk-encap']
                type: str
                description: Enable/disable chunked encapsulation
                choices:
                    - 'disable'
                    - 'enable'
            extension_feature:
                aliases: ['extension-feature']
                type: list
                elements: str
                description: Enable/disable ICAP extension features.
                choices:
                    - 'scan-progress'
            file_transfer:
                aliases: ['file-transfer']
                type: list
                elements: str
                description: Configure the file transfer protocols to pass transferred files to an ICAP server as REQMOD.
                choices:
                    - 'ssh'
                    - 'ftp'
            file_transfer_failure:
                aliases: ['file-transfer-failure']
                type: str
                description: Action to take if the ICAP server cannot be contacted when processing a file transfer.
                choices:
                    - 'error'
                    - 'bypass'
            file_transfer_path:
                aliases: ['file-transfer-path']
                type: str
                description: Path component of the ICAP URI that identifies the file transfer processing service.
            file_transfer_server:
                aliases: ['file-transfer-server']
                type: str
                description: ICAP server to use for a file transfer.
            icap_block_log:
                aliases: ['icap-block-log']
                type: str
                description: Enable/disable UTM log when infection found
                choices:
                    - 'disable'
                    - 'enable'
            scan_progress_interval:
                aliases: ['scan-progress-interval']
                type: int
                description: Scan progress interval value.
            timeout:
                type: int
                description: Time
            comment:
                type: str
                description: Comment.
            ocr_only:
                aliases: ['ocr-only']
                type: str
                description: Enable/disable this FortiGate unit to submit only OCR interested content to the ICAP server.
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
    - name: Configure ICAP profiles.
      fortinet.fortimanager.fmgr_icap_profile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        icap_profile:
          name: "your value" # Required variable, string
          # methods:
          #   - "delete"
          #   - "get"
          #   - "head"
          #   - "options"
          #   - "post"
          #   - "put"
          #   - "trace"
          #   - "other"
          #   - "connect"
          # replacemsg_group: <string>
          # request: <value in [disable, enable]>
          # request_failure: <value in [error, bypass]>
          # request_path: <string>
          # request_server: <string>
          # response: <value in [disable, enable]>
          # response_failure: <value in [error, bypass]>
          # response_path: <string>
          # response_server: <string>
          # streaming_content_bypass: <value in [disable, enable]>
          # icap_headers:
          #   - base64_encoding: <value in [disable, enable]>
          #     content: <string>
          #     id: <integer>
          #     name: <string>
          # preview: <value in [disable, enable]>
          # preview_data_length: <integer>
          # response_req_hdr: <value in [disable, enable]>
          # respmod_default_action: <value in [bypass, forward]>
          # respmod_forward_rules:
          #   - action: <value in [bypass, forward]>
          #     header_group:
          #       - case_sensitivity: <value in [disable, enable]>
          #         header: <string>
          #         header_name: <string>
          #         id: <integer>
          #     host: <string>
          #     http_resp_status_code: <list or integer>
          #     name: <string>
          # 204_response: <value in [disable, enable]>
          # 204_size_limit: <integer>
          # chunk_encap: <value in [disable, enable]>
          # extension_feature:
          #   - "scan-progress"
          # file_transfer:
          #   - "ssh"
          #   - "ftp"
          # file_transfer_failure: <value in [error, bypass]>
          # file_transfer_path: <string>
          # file_transfer_server: <string>
          # icap_block_log: <value in [disable, enable]>
          # scan_progress_interval: <integer>
          # timeout: <integer>
          # comment: <string>
          # ocr_only: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/icap/profile',
        '/pm/config/global/obj/icap/profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'icap_profile': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'methods': {
                    'type': 'list',
                    'choices': ['delete', 'get', 'head', 'options', 'post', 'put', 'trace', 'other', 'connect'],
                    'elements': 'str'
                },
                'name': {'required': True, 'type': 'str'},
                'replacemsg-group': {'type': 'str'},
                'request': {'choices': ['disable', 'enable'], 'type': 'str'},
                'request-failure': {'choices': ['error', 'bypass'], 'type': 'str'},
                'request-path': {'type': 'str'},
                'request-server': {'type': 'str'},
                'response': {'choices': ['disable', 'enable'], 'type': 'str'},
                'response-failure': {'choices': ['error', 'bypass'], 'type': 'str'},
                'response-path': {'type': 'str'},
                'response-server': {'type': 'str'},
                'streaming-content-bypass': {'choices': ['disable', 'enable'], 'type': 'str'},
                'icap-headers': {
                    'v_range': [['6.2.0', '']],
                    'type': 'list',
                    'options': {
                        'base64-encoding': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'content': {'v_range': [['6.2.0', '']], 'type': 'str'},
                        'id': {'v_range': [['6.2.0', '']], 'type': 'int'},
                        'name': {'v_range': [['6.2.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'preview': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'preview-data-length': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'response-req-hdr': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'respmod-default-action': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'forward'], 'type': 'str'},
                'respmod-forward-rules': {
                    'v_range': [['6.4.0', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'forward'], 'type': 'str'},
                        'header-group': {
                            'v_range': [['6.4.0', '']],
                            'type': 'list',
                            'options': {
                                'case-sensitivity': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'header': {'v_range': [['6.4.0', '']], 'type': 'str'},
                                'header-name': {'v_range': [['6.4.0', '']], 'type': 'str'},
                                'id': {'v_range': [['6.4.0', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'host': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'http-resp-status-code': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                        'name': {'v_range': [['6.4.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                '204-response': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '204-size-limit': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'chunk-encap': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'extension-feature': {'v_range': [['7.0.2', '']], 'type': 'list', 'choices': ['scan-progress'], 'elements': 'str'},
                'file-transfer': {'v_range': [['7.2.0', '']], 'type': 'list', 'choices': ['ssh', 'ftp'], 'elements': 'str'},
                'file-transfer-failure': {'v_range': [['7.2.0', '']], 'choices': ['error', 'bypass'], 'type': 'str'},
                'file-transfer-path': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'file-transfer-server': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'icap-block-log': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'scan-progress-interval': {'v_range': [['7.0.2', '']], 'type': 'int'},
                'timeout': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'comment': {'v_range': [['7.2.2', '']], 'type': 'str'},
                'ocr-only': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'icap_profile'),
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
