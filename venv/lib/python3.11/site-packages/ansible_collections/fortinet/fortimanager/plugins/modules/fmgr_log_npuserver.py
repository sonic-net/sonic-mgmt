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
module: fmgr_log_npuserver
short_description: Configure all the log servers and create the server groups.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    log_npuserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            log_processing:
                aliases: ['log-processing']
                type: str
                description: Configure log processed by host to drop or no drop.
                choices:
                    - 'may-drop'
                    - 'no-drop'
            log_processor:
                aliases: ['log-processor']
                type: str
                description: Configure the log module.
                choices:
                    - 'hardware'
                    - 'host'
            netflow_ver:
                aliases: ['netflow-ver']
                type: str
                description: Configure the netfow verson.
                choices:
                    - 'v9'
                    - 'v10'
            server_group:
                aliases: ['server-group']
                type: list
                elements: dict
                description: Server group.
                suboptions:
                    group_name:
                        aliases: ['group-name']
                        type: str
                        description: Server group name.
                    log_format:
                        aliases: ['log-format']
                        type: str
                        description: Set the log format
                        choices:
                            - 'syslog'
                            - 'netflow'
                    log_mode:
                        aliases: ['log-mode']
                        type: str
                        description: Set the log mode
                        choices:
                            - 'per-session'
                            - 'per-nat-mapping'
                            - 'per-session-ending'
                    log_tx_mode:
                        aliases: ['log-tx-mode']
                        type: str
                        description: Configure log transmit mode.
                        choices:
                            - 'multicast'
                            - 'roundrobin'
                    server_number:
                        aliases: ['server-number']
                        type: int
                        description: Server number in this group.
                    server_start_id:
                        aliases: ['server-start-id']
                        type: int
                        description: The start id of the continuous server series in this group,[1,16].
                    sw_log_flags:
                        aliases: ['sw-log-flags']
                        type: raw
                        description: (int or str) Set flags for software logging via driver.
                    log_gen_event:
                        aliases: ['log-gen-event']
                        type: str
                        description: Enable/disbale generating event for Per-Mapping log
                        choices:
                            - 'disable'
                            - 'enable'
                    log_user_info:
                        aliases: ['log-user-info']
                        type: str
                        description: Enable/disbale logging user information.
                        choices:
                            - 'disable'
                            - 'enable'
            server_info:
                aliases: ['server-info']
                type: list
                elements: dict
                description: Server info.
                suboptions:
                    dest_port:
                        aliases: ['dest-port']
                        type: int
                        description: Set the dest port for the log packet
                    id:
                        type: int
                        description: Server id.
                    ip_family:
                        aliases: ['ip-family']
                        type: str
                        description: Set the version the IP address
                        choices:
                            - 'v4'
                            - 'v6'
                    ipv4_server:
                        aliases: ['ipv4-server']
                        type: str
                        description: Set the IPv4 address for the log server
                    ipv6_server:
                        aliases: ['ipv6-server']
                        type: str
                        description: Set the IPv6 address for the log server
                    source_port:
                        aliases: ['source-port']
                        type: int
                        description: Set the source port for the log packet
                    template_tx_timeout:
                        aliases: ['template-tx-timeout']
                        type: int
                        description: Set the template tx timeout
                    vdom:
                        type: str
                        description: Interface connected to the log server is in this virtual domain
                    log_transport:
                        aliases: ['log-transport']
                        type: str
                        description: Set transport protocol
                        choices:
                            - 'udp'
                            - 'tcp'
                    vdom_:
                        type: str
                        description: Vdom.
            fmgr_syslog_facility:
                aliases: ['syslog-facility']
                type: int
                description: Configure the syslog facility.
            syslog_severity:
                aliases: ['syslog-severity']
                type: int
                description: Configure the syslog severity.
            enforce_seq_order:
                aliases: ['enforce-seq-order']
                type: str
                description: Sw session netflow logs will be delivered in strict order if the option is enabled.
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
    - name: Configure all the log servers and create the server groups.
      fortinet.fortimanager.fmgr_log_npuserver:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        log_npuserver:
          # log_processing: <value in [may-drop, no-drop]>
          # log_processor: <value in [hardware, host]>
          # netflow_ver: <value in [v9, v10]>
          # server_group:
          #   - group_name: <string>
          #     log_format: <value in [syslog, netflow]>
          #     log_mode: <value in [per-session, per-nat-mapping, per-session-ending]>
          #     log_tx_mode: <value in [multicast, roundrobin]>
          #     server_number: <integer>
          #     server_start_id: <integer>
          #     sw_log_flags: <value in [tcp-udp-only, enable-all-log, disable-all-log]>
          #     log_gen_event: <value in [disable, enable]>
          #     log_user_info: <value in [disable, enable]>
          # server_info:
          #   - dest_port: <integer>
          #     id: <integer>
          #     ip_family: <value in [v4, v6]>
          #     ipv4_server: <string>
          #     ipv6_server: <string>
          #     source_port: <integer>
          #     template_tx_timeout: <integer>
          #     vdom: <string>
          #     log_transport: <value in [udp, tcp]>
          #     vdom_: <string>
          # fmgr_syslog_facility: <integer>
          # syslog_severity: <integer>
          # enforce_seq_order: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/log/npu-server',
        '/pm/config/global/obj/log/npu-server'
    ]
    url_params = ['adom']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'log_npuserver': {
            'type': 'dict',
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
            'options': {
                'log-processing': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'choices': ['may-drop', 'no-drop'], 'type': 'str'},
                'log-processor': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['hardware', 'host'], 'type': 'str'},
                'netflow-ver': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['v9', 'v10'], 'type': 'str'},
                'server-group': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'list',
                    'options': {
                        'group-name': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'log-format': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['syslog', 'netflow'], 'type': 'str'},
                        'log-mode': {
                            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                            'choices': ['per-session', 'per-nat-mapping', 'per-session-ending'],
                            'type': 'str'
                        },
                        'log-tx-mode': {'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']], 'choices': ['multicast', 'roundrobin'], 'type': 'str'},
                        'server-number': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'server-start-id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'sw-log-flags': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'raw'},
                        'log-gen-event': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-user-info': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'server-info': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'list',
                    'options': {
                        'dest-port': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'ip-family': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['v4', 'v6'], 'type': 'str'},
                        'ipv4-server': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'ipv6-server': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'source-port': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'template-tx-timeout': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'vdom': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.10'], ['7.4.0', '']], 'type': 'str'},
                        'log-transport': {'v_range': [['7.4.2', '']], 'choices': ['udp', 'tcp'], 'type': 'str'},
                        'vdom_': {'v_range': [['7.2.11', '7.2.11']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'syslog-facility': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'syslog-severity': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'enforce-seq-order': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_npuserver'),
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
