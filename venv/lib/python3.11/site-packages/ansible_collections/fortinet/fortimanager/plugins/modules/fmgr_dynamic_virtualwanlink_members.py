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
module: fmgr_dynamic_virtualwanlink_members
short_description: FortiGate interfaces added to the virtual-wan-link.
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
    dynamic_virtualwanlink_members:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            cost:
                type: int
                description: Cost.
            detect_failtime:
                aliases: ['detect-failtime']
                type: int
                description: Detect failtime.
            detect_http_get:
                aliases: ['detect-http-get']
                type: str
                description: Detect http get.
            detect_http_match:
                aliases: ['detect-http-match']
                type: str
                description: Detect http match.
            detect_http_port:
                aliases: ['detect-http-port']
                type: int
                description: Detect http port.
            detect_interval:
                aliases: ['detect-interval']
                type: int
                description: Detect interval.
            detect_protocol:
                aliases: ['detect-protocol']
                type: str
                description: Detect protocol.
                choices:
                    - 'ping'
                    - 'tcp-echo'
                    - 'udp-echo'
                    - 'http'
            detect_recoverytime:
                aliases: ['detect-recoverytime']
                type: int
                description: Detect recoverytime.
            detect_server:
                aliases: ['detect-server']
                type: str
                description: Detect server.
            detect_timeout:
                aliases: ['detect-timeout']
                type: int
                description: Detect timeout.
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    _scope:
                        type: list
                        elements: dict
                        description: Scope.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    comment:
                        type: str
                        description: Comment.
                    cost:
                        type: int
                        description: Cost.
                    detect_failtime:
                        aliases: ['detect-failtime']
                        type: int
                        description: Detect failtime.
                    detect_http_get:
                        aliases: ['detect-http-get']
                        type: str
                        description: Detect http get.
                    detect_http_match:
                        aliases: ['detect-http-match']
                        type: str
                        description: Detect http match.
                    detect_http_port:
                        aliases: ['detect-http-port']
                        type: int
                        description: Detect http port.
                    detect_interval:
                        aliases: ['detect-interval']
                        type: int
                        description: Detect interval.
                    detect_protocol:
                        aliases: ['detect-protocol']
                        type: str
                        description: Detect protocol.
                        choices:
                            - 'ping'
                            - 'tcp-echo'
                            - 'udp-echo'
                            - 'http'
                    detect_recoverytime:
                        aliases: ['detect-recoverytime']
                        type: int
                        description: Detect recoverytime.
                    detect_server:
                        aliases: ['detect-server']
                        type: str
                        description: Detect server.
                    detect_timeout:
                        aliases: ['detect-timeout']
                        type: int
                        description: Detect timeout.
                    gateway:
                        type: str
                        description: Gateway.
                    gateway6:
                        type: str
                        description: Gateway6.
                    ingress_spillover_threshold:
                        aliases: ['ingress-spillover-threshold']
                        type: int
                        description: Ingress spillover threshold.
                    interface:
                        type: str
                        description: Interface.
                    priority:
                        type: int
                        description: Priority.
                    source:
                        type: str
                        description: Source.
                    source6:
                        type: str
                        description: Source6.
                    spillover_threshold:
                        aliases: ['spillover-threshold']
                        type: int
                        description: Spillover threshold.
                    status:
                        type: str
                        description: Status.
                        choices:
                            - 'disable'
                            - 'enable'
                    volume_ratio:
                        aliases: ['volume-ratio']
                        type: int
                        description: Volume ratio.
                    weight:
                        type: int
                        description: Weight.
            gateway:
                type: str
                description: Gateway.
            gateway6:
                type: str
                description: Gateway6.
            ingress_spillover_threshold:
                aliases: ['ingress-spillover-threshold']
                type: int
                description: Ingress spillover threshold.
            interface:
                type: str
                description: Interface.
            name:
                type: str
                description: Name.
                required: true
            priority:
                type: int
                description: Priority.
            source:
                type: str
                description: Source.
            source6:
                type: str
                description: Source6.
            spillover_threshold:
                aliases: ['spillover-threshold']
                type: int
                description: Spillover threshold.
            status:
                type: str
                description: Status.
                choices:
                    - 'disable'
                    - 'enable'
            volume_ratio:
                aliases: ['volume-ratio']
                type: int
                description: Volume ratio.
            weight:
                type: int
                description: Weight.
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
    - name: FortiGate interfaces added to the virtual-wan-link.
      fortinet.fortimanager.fmgr_dynamic_virtualwanlink_members:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        dynamic_virtualwanlink_members:
          name: "your value" # Required variable, string
          # comment: <string>
          # cost: <integer>
          # detect_failtime: <integer>
          # detect_http_get: <string>
          # detect_http_match: <string>
          # detect_http_port: <integer>
          # detect_interval: <integer>
          # detect_protocol: <value in [ping, tcp-echo, udp-echo, ...]>
          # detect_recoverytime: <integer>
          # detect_server: <string>
          # detect_timeout: <integer>
          # dynamic_mapping:
          #   - _scope:
          #       - name: <string>
          #         vdom: <string>
          #     comment: <string>
          #     cost: <integer>
          #     detect_failtime: <integer>
          #     detect_http_get: <string>
          #     detect_http_match: <string>
          #     detect_http_port: <integer>
          #     detect_interval: <integer>
          #     detect_protocol: <value in [ping, tcp-echo, udp-echo, ...]>
          #     detect_recoverytime: <integer>
          #     detect_server: <string>
          #     detect_timeout: <integer>
          #     gateway: <string>
          #     gateway6: <string>
          #     ingress_spillover_threshold: <integer>
          #     interface: <string>
          #     priority: <integer>
          #     source: <string>
          #     source6: <string>
          #     spillover_threshold: <integer>
          #     status: <value in [disable, enable]>
          #     volume_ratio: <integer>
          #     weight: <integer>
          # gateway: <string>
          # gateway6: <string>
          # ingress_spillover_threshold: <integer>
          # interface: <string>
          # priority: <integer>
          # source: <string>
          # source6: <string>
          # spillover_threshold: <integer>
          # status: <value in [disable, enable]>
          # volume_ratio: <integer>
          # weight: <integer>
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
        '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members',
        '/pm/config/global/obj/dynamic/virtual-wan-link/members'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dynamic_virtualwanlink_members': {
            'type': 'dict',
            'v_range': [['6.0.0', '6.4.15']],
            'options': {
                'comment': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'cost': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                'detect-failtime': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                'detect-http-get': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'detect-http-match': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'detect-http-port': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                'detect-interval': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                'detect-protocol': {'v_range': [['6.0.0', '6.4.15']], 'choices': ['ping', 'tcp-echo', 'udp-echo', 'http'], 'type': 'str'},
                'detect-recoverytime': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                'detect-server': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'detect-timeout': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                'dynamic_mapping': {
                    'v_range': [['6.0.0', '6.4.15']],
                    'type': 'list',
                    'options': {
                        '_scope': {
                            'v_range': [['6.0.0', '6.4.15']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                                'vdom': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'comment': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                        'cost': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                        'detect-failtime': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                        'detect-http-get': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                        'detect-http-match': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                        'detect-http-port': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                        'detect-interval': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                        'detect-protocol': {'v_range': [['6.0.0', '6.4.15']], 'choices': ['ping', 'tcp-echo', 'udp-echo', 'http'], 'type': 'str'},
                        'detect-recoverytime': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                        'detect-server': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                        'detect-timeout': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                        'gateway': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                        'gateway6': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                        'ingress-spillover-threshold': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                        'interface': {'v_range': [['6.0.0', '6.4.0']], 'type': 'str'},
                        'priority': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                        'source': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                        'source6': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                        'spillover-threshold': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                        'status': {'v_range': [['6.0.0', '6.4.15']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'volume-ratio': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                        'weight': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'gateway': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'gateway6': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'ingress-spillover-threshold': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                'interface': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'name': {'v_range': [['6.0.0', '6.4.15']], 'required': True, 'type': 'str'},
                'priority': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                'source': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'source6': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'spillover-threshold': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                'status': {'v_range': [['6.0.0', '6.4.15']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'volume-ratio': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'},
                'weight': {'v_range': [['6.0.0', '6.4.15']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dynamic_virtualwanlink_members'),
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
