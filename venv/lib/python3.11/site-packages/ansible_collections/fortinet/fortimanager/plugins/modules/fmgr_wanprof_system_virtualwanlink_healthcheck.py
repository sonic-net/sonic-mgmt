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
module: fmgr_wanprof_system_virtualwanlink_healthcheck
short_description: SD-WAN status checking or health checking.
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
    wanprof:
        description: The parameter (wanprof) in requested url.
        type: str
        required: true
    wanprof_system_virtualwanlink_healthcheck:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _dynamic_server:
                aliases: ['_dynamic-server']
                type: str
                description: Dynamic server.
            addr_mode:
                aliases: ['addr-mode']
                type: str
                description: Address mode
                choices:
                    - 'ipv4'
                    - 'ipv6'
            failtime:
                type: int
                description: Number of failures before server is considered lost
            http_agent:
                aliases: ['http-agent']
                type: str
                description: String in the http-agent field in the HTTP header.
            http_get:
                aliases: ['http-get']
                type: str
                description: URL used to communicate with the server if the protocol if the protocol is HTTP.
            http_match:
                aliases: ['http-match']
                type: str
                description: Response string expected from the server if the protocol is HTTP.
            interval:
                type: int
                description: Status check interval, or the time between attempting to connect to the server
            members:
                type: raw
                description: (list or str) Member sequence number list.
            name:
                type: str
                description: Status check or health check name.
                required: true
            packet_size:
                aliases: ['packet-size']
                type: int
                description: Packet size of a twamp test session,
            password:
                type: raw
                description: (list) Twamp controller password in authentication mode
            port:
                type: int
                description: Port number used to communicate with the server over the selected protocol.
            protocol:
                type: str
                description: Protocol used to determine if the FortiGate can communicate with the server.
                choices:
                    - 'ping'
                    - 'tcp-echo'
                    - 'udp-echo'
                    - 'http'
                    - 'twamp'
                    - 'ping6'
                    - 'dns'
            recoverytime:
                type: int
                description: Number of successful responses received before server is considered recovered
            security_mode:
                aliases: ['security-mode']
                type: str
                description: Twamp controller security mode.
                choices:
                    - 'none'
                    - 'authentication'
            server:
                type: raw
                description: (list) IP address or FQDN name of the server.
            sla:
                type: list
                elements: dict
                description: Sla.
                suboptions:
                    id:
                        type: int
                        description: SLA ID.
                    jitter_threshold:
                        aliases: ['jitter-threshold']
                        type: int
                        description: Jitter for SLA to make decision in milliseconds.
                    latency_threshold:
                        aliases: ['latency-threshold']
                        type: int
                        description: Latency for SLA to make decision in milliseconds.
                    link_cost_factor:
                        aliases: ['link-cost-factor']
                        type: list
                        elements: str
                        description: Criteria on which to base link selection.
                        choices:
                            - 'latency'
                            - 'jitter'
                            - 'packet-loss'
                    packetloss_threshold:
                        aliases: ['packetloss-threshold']
                        type: int
                        description: Packet loss for SLA to make decision in percentage.
            threshold_alert_jitter:
                aliases: ['threshold-alert-jitter']
                type: int
                description: Alert threshold for jitter
            threshold_alert_latency:
                aliases: ['threshold-alert-latency']
                type: int
                description: Alert threshold for latency
            threshold_alert_packetloss:
                aliases: ['threshold-alert-packetloss']
                type: int
                description: Alert threshold for packet loss
            threshold_warning_jitter:
                aliases: ['threshold-warning-jitter']
                type: int
                description: Warning threshold for jitter
            threshold_warning_latency:
                aliases: ['threshold-warning-latency']
                type: int
                description: Warning threshold for latency
            threshold_warning_packetloss:
                aliases: ['threshold-warning-packetloss']
                type: int
                description: Warning threshold for packet loss
            update_cascade_interface:
                aliases: ['update-cascade-interface']
                type: str
                description: Enable/disable update cascade interface.
                choices:
                    - 'disable'
                    - 'enable'
            update_static_route:
                aliases: ['update-static-route']
                type: str
                description: Enable/disable updating the static route.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_id:
                aliases: ['internet-service-id']
                type: str
                description: Internet service ID.
            probe_packets:
                aliases: ['probe-packets']
                type: str
                description: Enable/disable transmission of probe packets.
                choices:
                    - 'disable'
                    - 'enable'
            sla_fail_log_period:
                aliases: ['sla-fail-log-period']
                type: int
                description: Time interval in seconds that SLA fail log messages will be generated
            sla_pass_log_period:
                aliases: ['sla-pass-log-period']
                type: int
                description: Time interval in seconds that SLA pass log messages will be generated
            timeout:
                type: int
                description: How long to wait before not receiving a reply from the server to consider the connetion attempt a failure
            ha_priority:
                aliases: ['ha-priority']
                type: int
                description: HA election priority
            diffservcode:
                type: str
                description: Differentiated services code point
            probe_timeout:
                aliases: ['probe-timeout']
                type: int
                description: Time to wait before a probe packet is considered lost
            dns_request_domain:
                aliases: ['dns-request-domain']
                type: str
                description: Fully qualified domain name to resolve for the DNS probe.
            probe_count:
                aliases: ['probe-count']
                type: int
                description: Number of most recent probes that should be used to calculate latency and jitter
            system_dns:
                aliases: ['system-dns']
                type: str
                description: Enable/disable system DNS as the probe server.
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
    - name: SD-WAN status checking or health checking.
      fortinet.fortimanager.fmgr_wanprof_system_virtualwanlink_healthcheck:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        wanprof: <your own value>
        state: present # <value in [present, absent]>
        wanprof_system_virtualwanlink_healthcheck:
          name: "your value" # Required variable, string
          # _dynamic_server: <string>
          # addr_mode: <value in [ipv4, ipv6]>
          # failtime: <integer>
          # http_agent: <string>
          # http_get: <string>
          # http_match: <string>
          # interval: <integer>
          # members: <list or string>
          # packet_size: <integer>
          # password: <list or string>
          # port: <integer>
          # protocol: <value in [ping, tcp-echo, udp-echo, ...]>
          # recoverytime: <integer>
          # security_mode: <value in [none, authentication]>
          # server: <list or string>
          # sla:
          #   - id: <integer>
          #     jitter_threshold: <integer>
          #     latency_threshold: <integer>
          #     link_cost_factor:
          #       - "latency"
          #       - "jitter"
          #       - "packet-loss"
          #     packetloss_threshold: <integer>
          # threshold_alert_jitter: <integer>
          # threshold_alert_latency: <integer>
          # threshold_alert_packetloss: <integer>
          # threshold_warning_jitter: <integer>
          # threshold_warning_latency: <integer>
          # threshold_warning_packetloss: <integer>
          # update_cascade_interface: <value in [disable, enable]>
          # update_static_route: <value in [disable, enable]>
          # internet_service_id: <string>
          # probe_packets: <value in [disable, enable]>
          # sla_fail_log_period: <integer>
          # sla_pass_log_period: <integer>
          # timeout: <integer>
          # ha_priority: <integer>
          # diffservcode: <string>
          # probe_timeout: <integer>
          # dns_request_domain: <string>
          # probe_count: <integer>
          # system_dns: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check'
    ]
    url_params = ['adom', 'wanprof']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'wanprof': {'required': True, 'type': 'str'},
        'wanprof_system_virtualwanlink_healthcheck': {
            'type': 'dict',
            'v_range': [['6.0.0', '7.6.2']],
            'options': {
                '_dynamic-server': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'addr-mode': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'failtime': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'http-agent': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'http-get': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'http-match': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'interval': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'members': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'name': {'v_range': [['6.0.0', '7.6.2']], 'required': True, 'type': 'str'},
                'packet-size': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'password': {'v_range': [['6.0.0', '7.6.2']], 'no_log': True, 'type': 'raw'},
                'port': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'protocol': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['ping', 'tcp-echo', 'udp-echo', 'http', 'twamp', 'ping6', 'dns'], 'type': 'str'},
                'recoverytime': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'security-mode': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'authentication'], 'type': 'str'},
                'server': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'sla': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'jitter-threshold': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'latency-threshold': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'link-cost-factor': {
                            'v_range': [['6.0.0', '7.6.2']],
                            'type': 'list',
                            'choices': ['latency', 'jitter', 'packet-loss'],
                            'elements': 'str'
                        },
                        'packetloss-threshold': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'threshold-alert-jitter': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'threshold-alert-latency': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'threshold-alert-packetloss': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'threshold-warning-jitter': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'threshold-warning-latency': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'threshold-warning-packetloss': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'update-cascade-interface': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-static-route': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-id': {'v_range': [['6.2.0', '7.2.0']], 'type': 'str'},
                'probe-packets': {'v_range': [['6.2.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sla-fail-log-period': {'v_range': [['6.2.0', '7.6.2']], 'type': 'int'},
                'sla-pass-log-period': {'v_range': [['6.2.0', '7.6.2']], 'no_log': True, 'type': 'int'},
                'timeout': {'v_range': [['6.2.0', '6.4.15']], 'type': 'int'},
                'ha-priority': {'v_range': [['6.2.2', '7.6.2']], 'type': 'int'},
                'diffservcode': {'v_range': [['6.2.5', '7.6.2']], 'type': 'str'},
                'probe-timeout': {'v_range': [['6.2.5', '7.6.2']], 'type': 'int'},
                'dns-request-domain': {'v_range': [['6.4.0', '6.4.0']], 'type': 'str'},
                'probe-count': {'v_range': [['6.4.0', '6.4.0']], 'type': 'int'},
                'system-dns': {'v_range': [['6.4.0', '6.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanprof_system_virtualwanlink_healthcheck'),
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
