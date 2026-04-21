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
module: fmgr_switchcontroller_qos_ipdscpmap_map
short_description: Maps between IP-DSCP value to COS queue.
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
    ip-dscp-map:
        description: Deprecated, please use "ip_dscp_map"
        type: str
    ip_dscp_map:
        description: The parameter (ip-dscp-map) in requested url.
        type: str
    switchcontroller_qos_ipdscpmap_map:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cos_queue:
                aliases: ['cos-queue']
                type: int
                description: COS queue number.
            diffserv:
                type: list
                elements: str
                description: Differentiated service.
                choices:
                    - 'CS0'
                    - 'CS1'
                    - 'AF11'
                    - 'AF12'
                    - 'AF13'
                    - 'CS2'
                    - 'AF21'
                    - 'AF22'
                    - 'AF23'
                    - 'CS3'
                    - 'AF31'
                    - 'AF32'
                    - 'AF33'
                    - 'CS4'
                    - 'AF41'
                    - 'AF42'
                    - 'AF43'
                    - 'CS5'
                    - 'EF'
                    - 'CS6'
                    - 'CS7'
            ip_precedence:
                aliases: ['ip-precedence']
                type: list
                elements: str
                description: IP Precedence.
                choices:
                    - 'network-control'
                    - 'internetwork-control'
                    - 'critic-ecp'
                    - 'flashoverride'
                    - 'flash'
                    - 'immediate'
                    - 'priority'
                    - 'routine'
            name:
                type: str
                description: Dscp mapping entry name.
                required: true
            value:
                type: str
                description: Raw values of DSCP
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
    - name: Maps between IP-DSCP value to COS queue.
      fortinet.fortimanager.fmgr_switchcontroller_qos_ipdscpmap_map:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        ip_dscp_map: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_qos_ipdscpmap_map:
          name: "your value" # Required variable, string
          # cos_queue: <integer>
          # diffserv:
          #   - "CS0"
          #   - "CS1"
          #   - "AF11"
          #   - "AF12"
          #   - "AF13"
          #   - "CS2"
          #   - "AF21"
          #   - "AF22"
          #   - "AF23"
          #   - "CS3"
          #   - "AF31"
          #   - "AF32"
          #   - "AF33"
          #   - "CS4"
          #   - "AF41"
          #   - "AF42"
          #   - "AF43"
          #   - "CS5"
          #   - "EF"
          #   - "CS6"
          #   - "CS7"
          # ip_precedence:
          #   - "network-control"
          #   - "internetwork-control"
          #   - "critic-ecp"
          #   - "flashoverride"
          #   - "flash"
          #   - "immediate"
          #   - "priority"
          #   - "routine"
          # value: <string>
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
        '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map',
        '/pm/config/global/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map'
    ]
    url_params = ['adom', 'ip-dscp-map']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'ip-dscp-map': {'type': 'str', 'api_name': 'ip_dscp_map'},
        'ip_dscp_map': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_qos_ipdscpmap_map': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'cos-queue': {'type': 'int'},
                'diffserv': {
                    'type': 'list',
                    'choices': [
                        'CS0', 'CS1', 'AF11', 'AF12', 'AF13', 'CS2', 'AF21', 'AF22', 'AF23', 'CS3', 'AF31', 'AF32', 'AF33', 'CS4', 'AF41', 'AF42',
                        'AF43', 'CS5', 'EF', 'CS6', 'CS7'
                    ],
                    'elements': 'str'
                },
                'ip-precedence': {
                    'type': 'list',
                    'choices': ['network-control', 'internetwork-control', 'critic-ecp', 'flashoverride', 'flash', 'immediate', 'priority', 'routine'],
                    'elements': 'str'
                },
                'name': {'required': True, 'type': 'str'},
                'value': {'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_qos_ipdscpmap_map'),
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
