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
module: fmgr_telemetrycontroller_profile
short_description: Configure FortiTelemetry profiles.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10.0"
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
    telemetrycontroller_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            application:
                type: list
                elements: dict
                description: Application.
                suboptions:
                    app_name:
                        aliases: ['app-name']
                        type: list
                        elements: str
                        description: Application name.
                    app_throughput:
                        aliases: ['app-throughput']
                        type: int
                        description: Application throughput in megabytes
                    atdt_threshold:
                        aliases: ['atdt-threshold']
                        type: int
                        description: Threshold of application total downloading time in milliseconds
                    dns_time_threshold:
                        aliases: ['dns-time-threshold']
                        type: int
                        description: Threshold of DNS resolution time in milliseconds
                    experience_score_threshold:
                        aliases: ['experience-score-threshold']
                        type: int
                        description: Threshold of experience score
                    failure_rate_threshold:
                        aliases: ['failure-rate-threshold']
                        type: int
                        description: Threshold of failure rate
                    id:
                        type: int
                        description: ID.
                    interval:
                        type: int
                        description: Time in milliseconds to check the application
                    jitter_threshold:
                        aliases: ['jitter-threshold']
                        type: int
                        description: Threshold of jitter in milliseconds
                    latency_threshold:
                        aliases: ['latency-threshold']
                        type: int
                        description: Threshold of latency in milliseconds
                    monitor:
                        type: str
                        description: Enable/disable monitoring of the application.
                        choices:
                            - 'disable'
                            - 'enable'
                    packet_loss_threshold:
                        aliases: ['packet-loss-threshold']
                        type: int
                        description: Threshold of packet loss
                    sla:
                        type: dict
                        description: Sla.
                        suboptions:
                            app_throughput_threshold:
                                aliases: ['app-throughput-threshold']
                                type: int
                                description: Threshold of application throughput in megabytes
                            atdt_threshold:
                                aliases: ['atdt-threshold']
                                type: int
                                description: Threshold of application total downloading time in milliseconds
                            dns_time_threshold:
                                aliases: ['dns-time-threshold']
                                type: int
                                description: Threshold of 95th percentile of DNS resolution time in milliseconds
                            experience_score_threshold:
                                aliases: ['experience-score-threshold']
                                type: int
                                description: Threshold of experience score
                            failure_rate_threshold:
                                aliases: ['failure-rate-threshold']
                                type: int
                                description: Threshold of failure rate
                            jitter_threshold:
                                aliases: ['jitter-threshold']
                                type: int
                                description: Threshold of jitter in milliseconds
                            latency_threshold:
                                aliases: ['latency-threshold']
                                type: int
                                description: Threshold of latency in milliseconds
                            packet_loss_threshold:
                                aliases: ['packet-loss-threshold']
                                type: int
                                description: Threshold of packet loss
                            sla_factor:
                                aliases: ['sla-factor']
                                type: list
                                elements: str
                                description: Criteria on which metric to SLA threshold list.
                                choices:
                                    - 'latency'
                                    - 'jitter'
                                    - 'packet-loss'
                                    - 'experience-score'
                                    - 'failure-rate'
                                    - 'ttfb'
                                    - 'atdt'
                                    - 'tcp-rtt'
                                    - 'dns-time'
                                    - 'tls-time'
                                    - 'app-throughput'
                            tcp_rtt_threshold:
                                aliases: ['tcp-rtt-threshold']
                                type: int
                                description: Threshold of TCP round-trip time in milliseconds
                            tls_time_threshold:
                                aliases: ['tls-time-threshold']
                                type: int
                                description: Threshold of 95th percentile of TLS handshake time in milliseconds
                            ttfb_threshold:
                                aliases: ['ttfb-threshold']
                                type: int
                                description: Threshold of time to first byte in milliseconds
                    tcp_rtt_threshold:
                        aliases: ['tcp-rtt-threshold']
                        type: int
                        description: Threshold of TCP round-trip time in milliseconds
                    tls_time_threshold:
                        aliases: ['tls-time-threshold']
                        type: int
                        description: Threshold of TLS handshake time in milliseconds
                    ttfb_threshold:
                        aliases: ['ttfb-threshold']
                        type: int
                        description: Threshold of time to first byte in milliseconds
            comment:
                type: str
                description: Comment.
            name:
                type: str
                description: Name of the profile.
                required: true
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
    - name: Configure FortiTelemetry profiles.
      fortinet.fortimanager.fmgr_telemetrycontroller_profile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        telemetrycontroller_profile:
          name: "your value" # Required variable, string
          # application:
          #   - app_name: <list or string>
          #     app_throughput: <integer>
          #     atdt_threshold: <integer>
          #     dns_time_threshold: <integer>
          #     experience_score_threshold: <integer>
          #     failure_rate_threshold: <integer>
          #     id: <integer>
          #     interval: <integer>
          #     jitter_threshold: <integer>
          #     latency_threshold: <integer>
          #     monitor: <value in [disable, enable]>
          #     packet_loss_threshold: <integer>
          #     sla:
          #       app_throughput_threshold: <integer>
          #       atdt_threshold: <integer>
          #       dns_time_threshold: <integer>
          #       experience_score_threshold: <integer>
          #       failure_rate_threshold: <integer>
          #       jitter_threshold: <integer>
          #       latency_threshold: <integer>
          #       packet_loss_threshold: <integer>
          #       sla_factor:
          #         - "latency"
          #         - "jitter"
          #         - "packet-loss"
          #         - "experience-score"
          #         - "failure-rate"
          #         - "ttfb"
          #         - "atdt"
          #         - "tcp-rtt"
          #         - "dns-time"
          #         - "tls-time"
          #         - "app-throughput"
          #       tcp_rtt_threshold: <integer>
          #       tls_time_threshold: <integer>
          #       ttfb_threshold: <integer>
          #     tcp_rtt_threshold: <integer>
          #     tls_time_threshold: <integer>
          #     ttfb_threshold: <integer>
          # comment: <string>
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
        '/pm/config/adom/{adom}/obj/telemetry-controller/profile',
        '/pm/config/global/obj/telemetry-controller/profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'telemetrycontroller_profile': {
            'type': 'dict',
            'v_range': [['7.6.3', '']],
            'options': {
                'application': {
                    'v_range': [['7.6.3', '']],
                    'type': 'list',
                    'options': {
                        'app-name': {'v_range': [['7.6.3', '']], 'type': 'list', 'elements': 'str'},
                        'app-throughput': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'atdt-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'dns-time-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'experience-score-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'failure-rate-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'id': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'interval': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'jitter-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'latency-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'monitor': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'packet-loss-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'sla': {
                            'v_range': [['7.6.3', '']],
                            'type': 'dict',
                            'options': {
                                'app-throughput-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                                'atdt-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                                'dns-time-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                                'experience-score-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                                'failure-rate-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                                'jitter-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                                'latency-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                                'packet-loss-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                                'sla-factor': {
                                    'v_range': [['7.6.3', '']],
                                    'type': 'list',
                                    'choices': [
                                        'latency', 'jitter', 'packet-loss', 'experience-score', 'failure-rate', 'ttfb', 'atdt', 'tcp-rtt', 'dns-time',
                                        'tls-time', 'app-throughput'
                                    ],
                                    'elements': 'str'
                                },
                                'tcp-rtt-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                                'tls-time-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                                'ttfb-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'}
                            }
                        },
                        'tcp-rtt-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'tls-time-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'ttfb-threshold': {'v_range': [['7.6.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'comment': {'v_range': [['7.6.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.6.3', '']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'telemetrycontroller_profile'),
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
