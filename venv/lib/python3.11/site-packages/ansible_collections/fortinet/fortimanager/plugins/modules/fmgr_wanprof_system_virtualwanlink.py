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
module: fmgr_wanprof_system_virtualwanlink
short_description: Configure redundant internet connections using SD-WAN
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
    wanprof_system_virtualwanlink:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            fail_detect:
                aliases: ['fail-detect']
                type: str
                description: Enable/disable SD-WAN Internet connection status checking
                choices:
                    - 'disable'
                    - 'enable'
            health_check:
                aliases: ['health-check']
                type: list
                elements: dict
                description: Health check.
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
            load_balance_mode:
                aliases: ['load-balance-mode']
                type: str
                description: Algorithm or mode to use for load balancing Internet traffic to SD-WAN members.
                choices:
                    - 'source-ip-based'
                    - 'weight-based'
                    - 'usage-based'
                    - 'source-dest-ip-based'
                    - 'measured-volume-based'
            members:
                type: list
                elements: dict
                description: Members.
                suboptions:
                    _dynamic_member:
                        aliases: ['_dynamic-member']
                        type: str
                        description: Dynamic member.
                    comment:
                        type: str
                        description: Comments.
                    gateway:
                        type: str
                        description: The default gateway for this interface.
                    gateway6:
                        type: str
                        description: IPv6 gateway.
                    ingress_spillover_threshold:
                        aliases: ['ingress-spillover-threshold']
                        type: int
                        description: Ingress spillover threshold for this interface
                    interface:
                        type: str
                        description: Interface name.
                    priority:
                        type: int
                        description: Priority of the interface
                    seq_num:
                        aliases: ['seq-num']
                        type: int
                        description: Sequence number
                    source:
                        type: str
                        description: Source IP address used in the health-check packet to the server.
                    source6:
                        type: str
                        description: Source IPv6 address used in the health-check packet to the server.
                    spillover_threshold:
                        aliases: ['spillover-threshold']
                        type: int
                        description: Egress spillover threshold for this interface
                    status:
                        type: str
                        description: Enable/disable this interface in the SD-WAN.
                        choices:
                            - 'disable'
                            - 'enable'
                    volume_ratio:
                        aliases: ['volume-ratio']
                        type: int
                        description: Measured volume ratio
                    weight:
                        type: int
                        description: Weight of this interface for weighted load balancing.
                    cost:
                        type: int
                        description: Cost of this interface for services in SLA mode
            service:
                type: list
                elements: dict
                description: Service.
                suboptions:
                    addr_mode:
                        aliases: ['addr-mode']
                        type: str
                        description: Address mode
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                    bandwidth_weight:
                        aliases: ['bandwidth-weight']
                        type: int
                        description: Coefficient of reciprocal of available bidirectional bandwidth in the formula of custom-profile-1.
                    default:
                        type: str
                        description: Enable/disable use of SD-WAN as default service.
                        choices:
                            - 'disable'
                            - 'enable'
                    dscp_forward:
                        aliases: ['dscp-forward']
                        type: str
                        description: Enable/disable forward traffic DSCP tag.
                        choices:
                            - 'disable'
                            - 'enable'
                    dscp_forward_tag:
                        aliases: ['dscp-forward-tag']
                        type: str
                        description: Forward traffic DSCP tag.
                    dscp_reverse:
                        aliases: ['dscp-reverse']
                        type: str
                        description: Enable/disable reverse traffic DSCP tag.
                        choices:
                            - 'disable'
                            - 'enable'
                    dscp_reverse_tag:
                        aliases: ['dscp-reverse-tag']
                        type: str
                        description: Reverse traffic DSCP tag.
                    dst:
                        type: raw
                        description: (list or str) Destination address name.
                    dst_negate:
                        aliases: ['dst-negate']
                        type: str
                        description: Enable/disable negation of destination address match.
                        choices:
                            - 'disable'
                            - 'enable'
                    dst6:
                        type: raw
                        description: (list or str) Destination address6 name.
                    end_port:
                        aliases: ['end-port']
                        type: int
                        description: End destination port number.
                    gateway:
                        type: str
                        description: Enable/disable SD-WAN service gateway.
                        choices:
                            - 'disable'
                            - 'enable'
                    groups:
                        type: raw
                        description: (list or str) User groups.
                    health_check:
                        aliases: ['health-check']
                        type: str
                        description: Health check.
                    hold_down_time:
                        aliases: ['hold-down-time']
                        type: int
                        description: Waiting period in seconds when switching from the back-up member to the primary member
                    id:
                        type: int
                        description: Priority rule ID
                    internet_service:
                        aliases: ['internet-service']
                        type: str
                        description: Enable/disable use of Internet service for application-based load balancing.
                        choices:
                            - 'disable'
                            - 'enable'
                    internet_service_ctrl:
                        aliases: ['internet-service-ctrl']
                        type: raw
                        description: (list) Control-based Internet Service ID list.
                    internet_service_ctrl_group:
                        aliases: ['internet-service-ctrl-group']
                        type: raw
                        description: (list or str) Control-based Internet Service group list.
                    internet_service_custom:
                        aliases: ['internet-service-custom']
                        type: raw
                        description: (list or str) Custom Internet service name list.
                    internet_service_custom_group:
                        aliases: ['internet-service-custom-group']
                        type: raw
                        description: (list or str) Custom Internet Service group list.
                    internet_service_group:
                        aliases: ['internet-service-group']
                        type: raw
                        description: (list or str) Internet Service group list.
                    internet_service_id:
                        aliases: ['internet-service-id']
                        type: raw
                        description: (list or str) Internet service ID list.
                    jitter_weight:
                        aliases: ['jitter-weight']
                        type: int
                        description: Coefficient of jitter in the formula of custom-profile-1.
                    latency_weight:
                        aliases: ['latency-weight']
                        type: int
                        description: Coefficient of latency in the formula of custom-profile-1.
                    link_cost_factor:
                        aliases: ['link-cost-factor']
                        type: str
                        description: Link cost factor.
                        choices:
                            - 'latency'
                            - 'jitter'
                            - 'packet-loss'
                            - 'inbandwidth'
                            - 'outbandwidth'
                            - 'bibandwidth'
                            - 'custom-profile-1'
                    link_cost_threshold:
                        aliases: ['link-cost-threshold']
                        type: int
                        description: Percentage threshold change of link cost values that will result in policy route regeneration
                    member:
                        type: str
                        description: Member sequence number.
                    mode:
                        type: str
                        description: Control how the priority rule sets the priority of interfaces in the SD-WAN.
                        choices:
                            - 'auto'
                            - 'manual'
                            - 'priority'
                            - 'sla'
                            - 'load-balance'
                    name:
                        type: str
                        description: Priority rule name.
                    packet_loss_weight:
                        aliases: ['packet-loss-weight']
                        type: int
                        description: Coefficient of packet-loss in the formula of custom-profile-1.
                    priority_members:
                        aliases: ['priority-members']
                        type: raw
                        description: (list or str) Member sequence number list.
                    protocol:
                        type: int
                        description: Protocol number.
                    quality_link:
                        aliases: ['quality-link']
                        type: int
                        description: Quality grade.
                    route_tag:
                        aliases: ['route-tag']
                        type: int
                        description: IPv4 route map route-tag.
                    sla:
                        type: list
                        elements: dict
                        description: Sla.
                        suboptions:
                            health_check:
                                aliases: ['health-check']
                                type: str
                                description: Virtual WAN Link health-check.
                            id:
                                type: int
                                description: SLA ID.
                    src:
                        type: raw
                        description: (list or str) Source address name.
                    src_negate:
                        aliases: ['src-negate']
                        type: str
                        description: Enable/disable negation of source address match.
                        choices:
                            - 'disable'
                            - 'enable'
                    src6:
                        type: raw
                        description: (list or str) Source address6 name.
                    start_port:
                        aliases: ['start-port']
                        type: int
                        description: Start destination port number.
                    status:
                        type: str
                        description: Enable/disable SD-WAN service.
                        choices:
                            - 'disable'
                            - 'enable'
                    tos:
                        type: str
                        description: Type of service bit pattern.
                    tos_mask:
                        aliases: ['tos-mask']
                        type: str
                        description: Type of service evaluated bits.
                    users:
                        type: raw
                        description: (list or str) User name.
                    internet_service_app_ctrl:
                        aliases: ['internet-service-app-ctrl']
                        type: raw
                        description: (list) Application control based Internet Service ID list.
                    internet_service_app_ctrl_group:
                        aliases: ['internet-service-app-ctrl-group']
                        type: raw
                        description: (list or str) Application control based Internet Service group list.
                    role:
                        type: str
                        description: Service role to work with neighbor.
                        choices:
                            - 'primary'
                            - 'secondary'
                            - 'standalone'
                    sla_compare_method:
                        aliases: ['sla-compare-method']
                        type: str
                        description: Method to compare SLA value for sla and load balance mode.
                        choices:
                            - 'order'
                            - 'number'
                    standalone_action:
                        aliases: ['standalone-action']
                        type: str
                        description: Enable/disable service when selected neighbor role is standalone while service role is not standalone.
                        choices:
                            - 'disable'
                            - 'enable'
                    input_device:
                        aliases: ['input-device']
                        type: raw
                        description: (list or str) Source interface name.
                    internet_service_name:
                        aliases: ['internet-service-name']
                        type: str
                        description: Internet service name list.
                    input_device_negate:
                        aliases: ['input-device-negate']
                        type: str
                        description: Enable/disable negation of input device match.
                        choices:
                            - 'disable'
                            - 'enable'
            status:
                type: str
                description: Enable/disable SD-WAN.
                choices:
                    - 'disable'
                    - 'enable'
            neighbor:
                type: list
                elements: dict
                description: Neighbor.
                suboptions:
                    health_check:
                        aliases: ['health-check']
                        type: str
                        description: SD-WAN health-check name.
                    ip:
                        type: str
                        description: IP address of neighbor.
                    member:
                        type: str
                        description: Member sequence number.
                    role:
                        type: str
                        description: Role of neighbor.
                        choices:
                            - 'primary'
                            - 'secondary'
                            - 'standalone'
                    sla_id:
                        aliases: ['sla-id']
                        type: int
                        description: SLA ID.
            neighbor_hold_boot_time:
                aliases: ['neighbor-hold-boot-time']
                type: int
                description: Waiting period in seconds when switching from the primary neighbor to the secondary neighbor from the neighbor start.
            neighbor_hold_down:
                aliases: ['neighbor-hold-down']
                type: str
                description: Enable/disable hold switching from the secondary neighbor to the primary neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            neighbor_hold_down_time:
                aliases: ['neighbor-hold-down-time']
                type: int
                description: Waiting period in seconds when switching from the secondary neighbor to the primary neighbor when hold-down is disabled.
            fail_alert_interfaces:
                aliases: ['fail-alert-interfaces']
                type: raw
                description: (list) Physical interfaces that will be alerted.
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
    - name: Configure redundant internet connections using SD-WAN
      fortinet.fortimanager.fmgr_wanprof_system_virtualwanlink:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        wanprof: <your own value>
        wanprof_system_virtualwanlink:
          # fail_detect: <value in [disable, enable]>
          # health_check:
          #   - _dynamic_server: <string>
          #     addr_mode: <value in [ipv4, ipv6]>
          #     failtime: <integer>
          #     http_agent: <string>
          #     http_get: <string>
          #     http_match: <string>
          #     interval: <integer>
          #     members: <list or string>
          #     name: <string>
          #     packet_size: <integer>
          #     password: <list or string>
          #     port: <integer>
          #     protocol: <value in [ping, tcp-echo, udp-echo, ...]>
          #     recoverytime: <integer>
          #     security_mode: <value in [none, authentication]>
          #     server: <list or string>
          #     sla:
          #       - id: <integer>
          #         jitter_threshold: <integer>
          #         latency_threshold: <integer>
          #         link_cost_factor:
          #           - "latency"
          #           - "jitter"
          #           - "packet-loss"
          #         packetloss_threshold: <integer>
          #     threshold_alert_jitter: <integer>
          #     threshold_alert_latency: <integer>
          #     threshold_alert_packetloss: <integer>
          #     threshold_warning_jitter: <integer>
          #     threshold_warning_latency: <integer>
          #     threshold_warning_packetloss: <integer>
          #     update_cascade_interface: <value in [disable, enable]>
          #     update_static_route: <value in [disable, enable]>
          #     internet_service_id: <string>
          #     probe_packets: <value in [disable, enable]>
          #     sla_fail_log_period: <integer>
          #     sla_pass_log_period: <integer>
          #     timeout: <integer>
          #     ha_priority: <integer>
          #     diffservcode: <string>
          #     probe_timeout: <integer>
          #     dns_request_domain: <string>
          #     probe_count: <integer>
          #     system_dns: <value in [disable, enable]>
          # load_balance_mode: <value in [source-ip-based, weight-based, usage-based, ...]>
          # members:
          #   - _dynamic_member: <string>
          #     comment: <string>
          #     gateway: <string>
          #     gateway6: <string>
          #     ingress_spillover_threshold: <integer>
          #     interface: <string>
          #     priority: <integer>
          #     seq_num: <integer>
          #     source: <string>
          #     source6: <string>
          #     spillover_threshold: <integer>
          #     status: <value in [disable, enable]>
          #     volume_ratio: <integer>
          #     weight: <integer>
          #     cost: <integer>
          # service:
          #   - addr_mode: <value in [ipv4, ipv6]>
          #     bandwidth_weight: <integer>
          #     default: <value in [disable, enable]>
          #     dscp_forward: <value in [disable, enable]>
          #     dscp_forward_tag: <string>
          #     dscp_reverse: <value in [disable, enable]>
          #     dscp_reverse_tag: <string>
          #     dst: <list or string>
          #     dst_negate: <value in [disable, enable]>
          #     dst6: <list or string>
          #     end_port: <integer>
          #     gateway: <value in [disable, enable]>
          #     groups: <list or string>
          #     health_check: <string>
          #     hold_down_time: <integer>
          #     id: <integer>
          #     internet_service: <value in [disable, enable]>
          #     internet_service_ctrl: <list or integer>
          #     internet_service_ctrl_group: <list or string>
          #     internet_service_custom: <list or string>
          #     internet_service_custom_group: <list or string>
          #     internet_service_group: <list or string>
          #     internet_service_id: <list or string>
          #     jitter_weight: <integer>
          #     latency_weight: <integer>
          #     link_cost_factor: <value in [latency, jitter, packet-loss, ...]>
          #     link_cost_threshold: <integer>
          #     member: <string>
          #     mode: <value in [auto, manual, priority, ...]>
          #     name: <string>
          #     packet_loss_weight: <integer>
          #     priority_members: <list or string>
          #     protocol: <integer>
          #     quality_link: <integer>
          #     route_tag: <integer>
          #     sla:
          #       - health_check: <string>
          #         id: <integer>
          #     src: <list or string>
          #     src_negate: <value in [disable, enable]>
          #     src6: <list or string>
          #     start_port: <integer>
          #     status: <value in [disable, enable]>
          #     tos: <string>
          #     tos_mask: <string>
          #     users: <list or string>
          #     internet_service_app_ctrl: <list or integer>
          #     internet_service_app_ctrl_group: <list or string>
          #     role: <value in [primary, secondary, standalone]>
          #     sla_compare_method: <value in [order, number]>
          #     standalone_action: <value in [disable, enable]>
          #     input_device: <list or string>
          #     internet_service_name: <string>
          #     input_device_negate: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # neighbor:
          #   - health_check: <string>
          #     ip: <string>
          #     member: <string>
          #     role: <value in [primary, secondary, standalone]>
          #     sla_id: <integer>
          # neighbor_hold_boot_time: <integer>
          # neighbor_hold_down: <value in [disable, enable]>
          # neighbor_hold_down_time: <integer>
          # fail_alert_interfaces: <list or string>
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
        '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link'
    ]
    url_params = ['adom', 'wanprof']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'wanprof': {'required': True, 'type': 'str'},
        'wanprof_system_virtualwanlink': {
            'type': 'dict',
            'v_range': [['6.0.0', '7.6.2']],
            'options': {
                'fail-detect': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'health-check': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'options': {
                        '_dynamic-server': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                        'addr-mode': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'failtime': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'http-agent': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'http-get': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'http-match': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'interval': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'members': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                        'name': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'packet-size': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'password': {'v_range': [['6.0.0', '7.6.2']], 'no_log': True, 'type': 'raw'},
                        'port': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'protocol': {
                            'v_range': [['6.0.0', '7.6.2']],
                            'choices': ['ping', 'tcp-echo', 'udp-echo', 'http', 'twamp', 'ping6', 'dns'],
                            'type': 'str'
                        },
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
                    },
                    'elements': 'dict'
                },
                'load-balance-mode': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'choices': ['source-ip-based', 'weight-based', 'usage-based', 'source-dest-ip-based', 'measured-volume-based'],
                    'type': 'str'
                },
                'members': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'options': {
                        '_dynamic-member': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                        'comment': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'gateway': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'gateway6': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'ingress-spillover-threshold': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'interface': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'priority': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'seq-num': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'source': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'source6': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'spillover-threshold': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'volume-ratio': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'weight': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'cost': {'v_range': [['6.2.0', '7.6.2']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'service': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'options': {
                        'addr-mode': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'bandwidth-weight': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'default': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dscp-forward': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dscp-forward-tag': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'dscp-reverse': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dscp-reverse-tag': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'dst': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                        'dst-negate': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dst6': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                        'end-port': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'gateway': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'groups': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                        'health-check': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'hold-down-time': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'id': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'internet-service': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'internet-service-ctrl': {'v_range': [['6.0.0', '7.2.1']], 'type': 'raw'},
                        'internet-service-ctrl-group': {'v_range': [['6.0.0', '7.2.1']], 'type': 'raw'},
                        'internet-service-custom': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                        'internet-service-custom-group': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                        'internet-service-group': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                        'internet-service-id': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                        'jitter-weight': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'latency-weight': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'link-cost-factor': {
                            'v_range': [['6.0.0', '7.6.2']],
                            'choices': ['latency', 'jitter', 'packet-loss', 'inbandwidth', 'outbandwidth', 'bibandwidth', 'custom-profile-1'],
                            'type': 'str'
                        },
                        'link-cost-threshold': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'member': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                        'mode': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['auto', 'manual', 'priority', 'sla', 'load-balance'], 'type': 'str'},
                        'name': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'packet-loss-weight': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'priority-members': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                        'protocol': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'quality-link': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'route-tag': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'sla': {
                            'v_range': [['6.0.0', '7.6.2']],
                            'type': 'list',
                            'options': {
                                'health-check': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                                'id': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'src': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                        'src-negate': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'src6': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                        'start-port': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                        'status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tos': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'tos-mask': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'users': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                        'internet-service-app-ctrl': {'v_range': [['6.2.0', '7.6.2']], 'type': 'raw'},
                        'internet-service-app-ctrl-group': {'v_range': [['6.2.0', '7.6.2']], 'type': 'raw'},
                        'role': {'v_range': [['6.2.1', '7.6.2']], 'choices': ['primary', 'secondary', 'standalone'], 'type': 'str'},
                        'sla-compare-method': {'v_range': [['6.2.1', '7.6.2']], 'choices': ['order', 'number'], 'type': 'str'},
                        'standalone-action': {'v_range': [['6.2.1', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'input-device': {'v_range': [['6.2.2', '7.6.2']], 'type': 'raw'},
                        'internet-service-name': {'v_range': [['6.4.0', '6.4.0']], 'type': 'str'},
                        'input-device-negate': {'v_range': [['6.4.1', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'neighbor': {
                    'v_range': [['6.2.1', '7.6.2']],
                    'type': 'list',
                    'options': {
                        'health-check': {'v_range': [['6.2.1', '7.6.2']], 'type': 'str'},
                        'ip': {'v_range': [['6.2.1', '7.6.2']], 'type': 'str'},
                        'member': {'v_range': [['6.2.1', '7.6.2']], 'type': 'str'},
                        'role': {'v_range': [['6.2.1', '7.6.2']], 'choices': ['primary', 'secondary', 'standalone'], 'type': 'str'},
                        'sla-id': {'v_range': [['6.2.1', '7.6.2']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'neighbor-hold-boot-time': {'v_range': [['6.2.1', '7.6.2']], 'type': 'int'},
                'neighbor-hold-down': {'v_range': [['6.2.1', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'neighbor-hold-down-time': {'v_range': [['6.2.1', '7.6.2']], 'type': 'int'},
                'fail-alert-interfaces': {'v_range': [['7.2.3', '7.6.2']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanprof_system_virtualwanlink'),
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
