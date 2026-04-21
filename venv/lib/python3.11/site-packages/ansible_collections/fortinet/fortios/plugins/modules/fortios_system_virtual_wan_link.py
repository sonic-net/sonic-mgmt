#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_system_virtual_wan_link
short_description: Configure redundant internet connections using SD-WAN (formerly virtual WAN link) in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and virtual_wan_link category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

    - The module supports check_mode.

requirements:
    - ansible>=2.15
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    system_virtual_wan_link:
        description:
            - Configure redundant internet connections using SD-WAN (formerly virtual WAN link).
        default: null
        type: dict
        suboptions:
            fail_alert_interfaces:
                description:
                    - Physical interfaces that will be alerted.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Physical interface name. Source system.interface.name.
                        required: true
                        type: str
            fail_detect:
                description:
                    - Enable/disable SD-WAN Internet connection status checking (failure detection).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            health_check:
                description:
                    - SD-WAN status checking or health checking. Identify a server on the Internet and determine how SD-WAN verifies that the FortiGate can
                       communicate with it.
                type: list
                elements: dict
                suboptions:
                    addr_mode:
                        description:
                            - Address mode (IPv4 or IPv6).
                        type: str
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                    diffservcode:
                        description:
                            - Differentiated services code point (DSCP) in the IP header of the probe packet.
                        type: str
                    failtime:
                        description:
                            - Number of failures before server is considered lost (1 - 3600).
                        type: int
                    ha_priority:
                        description:
                            - HA election priority (1 - 50).
                        type: int
                    http_agent:
                        description:
                            - String in the http-agent field in the HTTP header.
                        type: str
                    http_get:
                        description:
                            - URL used to communicate with the server if the protocol if the protocol is HTTP.
                        type: str
                    http_match:
                        description:
                            - Response string expected from the server if the protocol is HTTP.
                        type: str
                    interval:
                        description:
                            - Status check interval in milliseconds, or the time between attempting to connect to the server (500 - 3600*1000 msec).
                        type: int
                    members:
                        description:
                            - Member sequence number list.
                        type: list
                        elements: dict
                        suboptions:
                            seq_num:
                                description:
                                    - Member sequence number. see <a href='#notes'>Notes</a>. Source system.virtual-wan-link.members.seq-num.
                                required: true
                                type: int
                    name:
                        description:
                            - Status check or health check name.
                        required: true
                        type: str
                    packet_size:
                        description:
                            - Packet size of a twamp test session,
                        type: int
                    password:
                        description:
                            - Twamp controller password in authentication mode
                        type: str
                    port:
                        description:
                            - Port number used to communicate with the server over the selected protocol.
                        type: int
                    probe_packets:
                        description:
                            - Enable/disable transmission of probe packets.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    probe_timeout:
                        description:
                            - Time to wait before a probe packet is considered lost (500 - 5000 msec).
                        type: int
                    protocol:
                        description:
                            - Protocol used to determine if the FortiGate can communicate with the server.
                        type: str
                        choices:
                            - 'ping'
                            - 'tcp-echo'
                            - 'udp-echo'
                            - 'http'
                            - 'twamp'
                            - 'ping6'
                    recoverytime:
                        description:
                            - Number of successful responses received before server is considered recovered (1 - 3600).
                        type: int
                    security_mode:
                        description:
                            - Twamp controller security mode.
                        type: str
                        choices:
                            - 'none'
                            - 'authentication'
                    server:
                        description:
                            - IP address or FQDN name of the server.
                        type: str
                    sla:
                        description:
                            - Service level agreement (SLA).
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - SLA ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            jitter_threshold:
                                description:
                                    - Jitter for SLA to make decision in milliseconds. (0 - 10000000).
                                type: int
                            latency_threshold:
                                description:
                                    - Latency for SLA to make decision in milliseconds. (0 - 10000000).
                                type: int
                            link_cost_factor:
                                description:
                                    - Criteria on which to base link selection.
                                type: list
                                elements: str
                                choices:
                                    - 'latency'
                                    - 'jitter'
                                    - 'packet-loss'
                            packetloss_threshold:
                                description:
                                    - Packet loss for SLA to make decision in percentage. (0 - 100).
                                type: int
                    sla_fail_log_period:
                        description:
                            - Time interval in seconds that SLA fail log messages will be generated (0 - 3600).
                        type: int
                    sla_pass_log_period:
                        description:
                            - Time interval in seconds that SLA pass log messages will be generated (0 - 3600).
                        type: int
                    threshold_alert_jitter:
                        description:
                            - Alert threshold for jitter (ms).
                        type: int
                    threshold_alert_latency:
                        description:
                            - Alert threshold for latency (ms).
                        type: int
                    threshold_alert_packetloss:
                        description:
                            - Alert threshold for packet loss (percentage).
                        type: int
                    threshold_warning_jitter:
                        description:
                            - Warning threshold for jitter (ms).
                        type: int
                    threshold_warning_latency:
                        description:
                            - Warning threshold for latency (ms).
                        type: int
                    threshold_warning_packetloss:
                        description:
                            - Warning threshold for packet loss (percentage).
                        type: int
                    update_cascade_interface:
                        description:
                            - Enable/disable update cascade interface.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    update_static_route:
                        description:
                            - Enable/disable updating the static route.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            load_balance_mode:
                description:
                    - Algorithm or mode to use for load balancing Internet traffic to SD-WAN members.
                type: str
                choices:
                    - 'source-ip-based'
                    - 'weight-based'
                    - 'usage-based'
                    - 'source-dest-ip-based'
                    - 'measured-volume-based'
            members:
                description:
                    - FortiGate interfaces added to the virtual-wan-link.
                type: list
                elements: dict
                suboptions:
                    comment:
                        description:
                            - Comments.
                        type: str
                    cost:
                        description:
                            - Cost of this interface for services in SLA mode (0 - 4294967295).
                        type: int
                    gateway:
                        description:
                            - The default gateway for this interface. Usually the default gateway of the Internet service provider that this interface is
                               connected to.
                        type: str
                    gateway6:
                        description:
                            - IPv6 gateway.
                        type: str
                    ingress_spillover_threshold:
                        description:
                            - Ingress spillover threshold for this interface (0 - 16776000 kbit/s). When this traffic volume threshold is reached, new
                               sessions spill over to other interfaces in the SD-WAN.
                        type: int
                    interface:
                        description:
                            - Interface name. Source system.interface.name.
                        type: str
                    priority:
                        description:
                            - Priority of the interface (0 - 4294967295). Used for SD-WAN rules or priority rules.
                        type: int
                    seq_num:
                        description:
                            - Sequence number(1-255). see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    source:
                        description:
                            - Source IP address used in the health-check packet to the server.
                        type: str
                    source6:
                        description:
                            - Source IPv6 address used in the health-check packet to the server.
                        type: str
                    spillover_threshold:
                        description:
                            - Egress spillover threshold for this interface (0 - 16776000 kbit/s). When this traffic volume threshold is reached, new sessions
                               spill over to other interfaces in the SD-WAN.
                        type: int
                    status:
                        description:
                            - Enable/disable this interface in the SD-WAN.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    volume_ratio:
                        description:
                            - Measured volume ratio (this value / sum of all values = percentage of link volume, 1 - 255).
                        type: int
                    weight:
                        description:
                            - Weight of this interface for weighted load balancing. (1 - 255) More traffic is directed to interfaces with higher weights.
                        type: int
            neighbor:
                description:
                    - Create SD-WAN neighbor from BGP neighbor table to control route advertisements according to SLA status.
                type: list
                elements: dict
                suboptions:
                    health_check:
                        description:
                            - SD-WAN health-check name. Source system.virtual-wan-link.health-check.name.
                        type: str
                    ip:
                        description:
                            - IP address of neighbor. Source router.bgp.neighbor.ip.
                        required: true
                        type: str
                    member:
                        description:
                            - Member sequence number. Source system.virtual-wan-link.members.seq-num.
                        type: int
                    role:
                        description:
                            - Role of neighbor.
                        type: str
                        choices:
                            - 'standalone'
                            - 'primary'
                            - 'secondary'
                    sla_id:
                        description:
                            - SLA ID.
                        type: int
            neighbor_hold_boot_time:
                description:
                    - Waiting period in seconds when switching from the primary neighbor to the secondary neighbor from the neighbor start. (0 - 10000000).
                type: int
            neighbor_hold_down:
                description:
                    - Enable/disable hold switching from the secondary neighbor to the primary neighbor.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            neighbor_hold_down_time:
                description:
                    - Waiting period in seconds when switching from the secondary neighbor to the primary neighbor when hold-down is disabled. (0 - 10000000).
                type: int
            service:
                description:
                    - Create SD-WAN rules (also called services) to control how sessions are distributed to interfaces in the SD-WAN.
                type: list
                elements: dict
                suboptions:
                    addr_mode:
                        description:
                            - Address mode (IPv4 or IPv6).
                        type: str
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                    bandwidth_weight:
                        description:
                            - Coefficient of reciprocal of available bidirectional bandwidth in the formula of custom-profile-1.
                        type: int
                    default:
                        description:
                            - Enable/disable use of SD-WAN as default service.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    dscp_forward:
                        description:
                            - Enable/disable forward traffic DSCP tag.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    dscp_forward_tag:
                        description:
                            - Forward traffic DSCP tag.
                        type: str
                    dscp_reverse:
                        description:
                            - Enable/disable reverse traffic DSCP tag.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    dscp_reverse_tag:
                        description:
                            - Reverse traffic DSCP tag.
                        type: str
                    dst:
                        description:
                            - Destination address name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address or address group name. Source firewall.address.name firewall.addrgrp.name.
                                required: true
                                type: str
                    dst_negate:
                        description:
                            - Enable/disable negation of destination address match.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    dst6:
                        description:
                            - Destination address6 name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address6 or address6 group name. Source firewall.address6.name firewall.addrgrp6.name.
                                required: true
                                type: str
                    end_port:
                        description:
                            - End destination port number.
                        type: int
                    gateway:
                        description:
                            - Enable/disable SD-WAN service gateway.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    groups:
                        description:
                            - User groups.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Group name. Source user.group.name.
                                required: true
                                type: str
                    health_check:
                        description:
                            - Health check. Source system.virtual-wan-link.health-check.name.
                        type: str
                    hold_down_time:
                        description:
                            - Waiting period in seconds when switching from the back-up member to the primary member (0 - 10000000).
                        type: int
                    id:
                        description:
                            - Priority rule ID (1 - 4000). see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    input_device:
                        description:
                            - Source interface name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Interface name. Source system.interface.name.
                                required: true
                                type: str
                    input_device_negate:
                        description:
                            - Enable/disable negation of input device match.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    internet_service:
                        description:
                            - Enable/disable use of Internet service for application-based load balancing.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    internet_service_app_ctrl:
                        description:
                            - Application control based Internet Service ID list.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Application control based Internet Service ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                    internet_service_app_ctrl_group:
                        description:
                            - Application control based Internet Service group list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Application control based Internet Service group name. Source application.group.name.
                                required: true
                                type: str
                    internet_service_ctrl:
                        description:
                            - Control-based Internet Service ID list.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Control-based Internet Service ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                    internet_service_ctrl_group:
                        description:
                            - Control-based Internet Service group list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Control-based Internet Service group name. Source application.group.name.
                                required: true
                                type: str
                    internet_service_custom:
                        description:
                            - Custom Internet service name list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Custom Internet service name. Source firewall.internet-service-custom.name.
                                required: true
                                type: str
                    internet_service_custom_group:
                        description:
                            - Custom Internet Service group list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Custom Internet Service group name. Source firewall.internet-service-custom-group.name.
                                required: true
                                type: str
                    internet_service_group:
                        description:
                            - Internet Service group list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Internet Service group name. Source firewall.internet-service-group.name.
                                required: true
                                type: str
                    internet_service_id:
                        description:
                            - Internet service ID list.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Internet service ID. see <a href='#notes'>Notes</a>. Source firewall.internet-service.id.
                                required: true
                                type: int
                    jitter_weight:
                        description:
                            - Coefficient of jitter in the formula of custom-profile-1.
                        type: int
                    latency_weight:
                        description:
                            - Coefficient of latency in the formula of custom-profile-1.
                        type: int
                    link_cost_factor:
                        description:
                            - Link cost factor.
                        type: str
                        choices:
                            - 'latency'
                            - 'jitter'
                            - 'packet-loss'
                            - 'inbandwidth'
                            - 'outbandwidth'
                            - 'bibandwidth'
                            - 'custom-profile-1'
                    link_cost_threshold:
                        description:
                            - Percentage threshold change of link cost values that will result in policy route regeneration (0 - 10000000).
                        type: int
                    member:
                        description:
                            - Member sequence number. Source system.virtual-wan-link.members.seq-num.
                        type: int
                    mode:
                        description:
                            - Control how the priority rule sets the priority of interfaces in the SD-WAN.
                        type: str
                        choices:
                            - 'auto'
                            - 'manual'
                            - 'priority'
                            - 'sla'
                            - 'load-balance'
                    name:
                        description:
                            - Priority rule name.
                        type: str
                    packet_loss_weight:
                        description:
                            - Coefficient of packet-loss in the formula of custom-profile-1.
                        type: int
                    priority_members:
                        description:
                            - Member sequence number list.
                        type: list
                        elements: dict
                        suboptions:
                            seq_num:
                                description:
                                    - Member sequence number. see <a href='#notes'>Notes</a>. Source system.virtual-wan-link.members.seq-num.
                                required: true
                                type: int
                    protocol:
                        description:
                            - Protocol number.
                        type: int
                    quality_link:
                        description:
                            - Quality grade.
                        type: int
                    role:
                        description:
                            - Service role to work with neighbor.
                        type: str
                        choices:
                            - 'standalone'
                            - 'primary'
                            - 'secondary'
                    route_tag:
                        description:
                            - IPv4 route map route-tag.
                        type: int
                    sla:
                        description:
                            - Service level agreement (SLA).
                        type: list
                        elements: dict
                        suboptions:
                            health_check:
                                description:
                                    - Virtual WAN Link health-check. Source system.virtual-wan-link.health-check.name.
                                required: true
                                type: str
                            id:
                                description:
                                    - SLA ID.
                                type: int
                    sla_compare_method:
                        description:
                            - Method to compare SLA value for sla and load balance mode.
                        type: str
                        choices:
                            - 'order'
                            - 'number'
                    src:
                        description:
                            - Source address name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address or address group name. Source firewall.address.name firewall.addrgrp.name.
                                required: true
                                type: str
                    src_negate:
                        description:
                            - Enable/disable negation of source address match.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    src6:
                        description:
                            - Source address6 name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address6 or address6 group name. Source firewall.address6.name firewall.addrgrp6.name.
                                required: true
                                type: str
                    standalone_action:
                        description:
                            - Enable/disable service when selected neighbor role is standalone while service role is not standalone.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    start_port:
                        description:
                            - Start destination port number.
                        type: int
                    status:
                        description:
                            - Enable/disable SD-WAN service.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tos:
                        description:
                            - Type of service bit pattern.
                        type: str
                    tos_mask:
                        description:
                            - Type of service evaluated bits.
                        type: str
                    users:
                        description:
                            - User name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - User name. Source user.local.name.
                                required: true
                                type: str
            status:
                description:
                    - Enable/disable SD-WAN.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            zone:
                description:
                    - Configure SD-WAN zones.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Zone name.
                        required: true
                        type: str
"""

EXAMPLES = """
- name: Configure redundant internet connections using SD-WAN (formerly virtual WAN link).
  fortinet.fortios.fortios_system_virtual_wan_link:
      vdom: "{{ vdom }}"
      system_virtual_wan_link:
          fail_alert_interfaces:
              -
                  name: "default_name_4 (source system.interface.name)"
          fail_detect: "enable"
          health_check:
              -
                  addr_mode: "ipv4"
                  diffservcode: "<your_own_value>"
                  failtime: "1800"
                  ha_priority: "25"
                  http_agent: "<your_own_value>"
                  http_get: "<your_own_value>"
                  http_match: "<your_own_value>"
                  interval: "1800000"
                  members:
                      -
                          seq_num: "<you_own_value>"
                  name: "default_name_17"
                  packet_size: "512"
                  password: "<your_own_value>"
                  port: "32767"
                  probe_packets: "disable"
                  probe_timeout: "2500"
                  protocol: "ping"
                  recoverytime: "1800"
                  security_mode: "none"
                  server: "192.168.100.40"
                  sla:
                      -
                          id: "28"
                          jitter_threshold: "5000000"
                          latency_threshold: "5000000"
                          link_cost_factor: "latency"
                          packetloss_threshold: "50"
                  sla_fail_log_period: "1800"
                  sla_pass_log_period: "1800"
                  threshold_alert_jitter: "2147483647"
                  threshold_alert_latency: "2147483647"
                  threshold_alert_packetloss: "50"
                  threshold_warning_jitter: "2147483647"
                  threshold_warning_latency: "2147483647"
                  threshold_warning_packetloss: "50"
                  update_cascade_interface: "enable"
                  update_static_route: "enable"
          load_balance_mode: "source-ip-based"
          members:
              -
                  comment: "Comments."
                  cost: "2147483647"
                  gateway: "<your_own_value>"
                  gateway6: "<your_own_value>"
                  ingress_spillover_threshold: "8388000"
                  interface: "<your_own_value> (source system.interface.name)"
                  priority: "2147483647"
                  seq_num: "<you_own_value>"
                  source: "<your_own_value>"
                  source6: "<your_own_value>"
                  spillover_threshold: "8388000"
                  status: "disable"
                  volume_ratio: "127"
                  weight: "127"
          neighbor:
              -
                  health_check: "<your_own_value> (source system.virtual-wan-link.health-check.name)"
                  ip: "<your_own_value> (source router.bgp.neighbor.ip)"
                  member: "2147483647"
                  role: "standalone"
                  sla_id: "2147483647"
          neighbor_hold_boot_time: "5000000"
          neighbor_hold_down: "enable"
          neighbor_hold_down_time: "5000000"
          service:
              -
                  addr_mode: "ipv4"
                  bandwidth_weight: "5000000"
                  default: "enable"
                  dscp_forward: "enable"
                  dscp_forward_tag: "<your_own_value>"
                  dscp_reverse: "enable"
                  dscp_reverse_tag: "<your_own_value>"
                  dst:
                      -
                          name: "default_name_77 (source firewall.address.name firewall.addrgrp.name)"
                  dst_negate: "enable"
                  dst6:
                      -
                          name: "default_name_80 (source firewall.address6.name firewall.addrgrp6.name)"
                  end_port: "32767"
                  gateway: "enable"
                  groups:
                      -
                          name: "default_name_84 (source user.group.name)"
                  health_check: "<your_own_value> (source system.virtual-wan-link.health-check.name)"
                  hold_down_time: "5000000"
                  id: "87"
                  input_device:
                      -
                          name: "default_name_89 (source system.interface.name)"
                  input_device_negate: "enable"
                  internet_service: "enable"
                  internet_service_app_ctrl:
                      -
                          id: "93"
                  internet_service_app_ctrl_group:
                      -
                          name: "default_name_95 (source application.group.name)"
                  internet_service_ctrl:
                      -
                          id: "97"
                  internet_service_ctrl_group:
                      -
                          name: "default_name_99 (source application.group.name)"
                  internet_service_custom:
                      -
                          name: "default_name_101 (source firewall.internet-service-custom.name)"
                  internet_service_custom_group:
                      -
                          name: "default_name_103 (source firewall.internet-service-custom-group.name)"
                  internet_service_group:
                      -
                          name: "default_name_105 (source firewall.internet-service-group.name)"
                  internet_service_id:
                      -
                          id: "107 (source firewall.internet-service.id)"
                  jitter_weight: "5000000"
                  latency_weight: "5000000"
                  link_cost_factor: "latency"
                  link_cost_threshold: "5000000"
                  member: "2147483647"
                  mode: "auto"
                  name: "default_name_114"
                  packet_loss_weight: "5000000"
                  priority_members:
                      -
                          seq_num: "<you_own_value>"
                  protocol: "127"
                  quality_link: "127"
                  role: "standalone"
                  route_tag: "2147483647"
                  sla:
                      -
                          health_check: "<your_own_value> (source system.virtual-wan-link.health-check.name)"
                          id: "124"
                  sla_compare_method: "order"
                  src:
                      -
                          name: "default_name_127 (source firewall.address.name firewall.addrgrp.name)"
                  src_negate: "enable"
                  src6:
                      -
                          name: "default_name_130 (source firewall.address6.name firewall.addrgrp6.name)"
                  standalone_action: "enable"
                  start_port: "32767"
                  status: "enable"
                  tos: "<your_own_value>"
                  tos_mask: "<your_own_value>"
                  users:
                      -
                          name: "default_name_137 (source user.local.name)"
          status: "disable"
          zone:
              -
                  name: "default_name_140"
"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    find_current_values,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    unify_data_format,
)


def filter_system_virtual_wan_link_data(json):
    option_list = [
        "fail_alert_interfaces",
        "fail_detect",
        "health_check",
        "load_balance_mode",
        "members",
        "neighbor",
        "neighbor_hold_boot_time",
        "neighbor_hold_down",
        "neighbor_hold_down_time",
        "service",
        "status",
        "zone",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or (not data[path[index]] and not isinstance(data[path[index]], list))
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
        if len(data[path[index]]) == 0:
            data[path[index]] = None
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["health_check", "sla", "link_cost_factor"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def system_virtual_wan_link(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_virtual_wan_link_data = data["system_virtual_wan_link"]

    filtered_data = filter_system_virtual_wan_link_data(system_virtual_wan_link_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "virtual-wan-link", filtered_data, vdom=vdom)
        current_data = fos.get("system", "virtual-wan-link", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and (
                mkeyname
                and isinstance(current_data.get("results"), list)
                and len(current_data["results"]) > 0
                or not mkeyname
                and current_data["results"]  # global object response
            )
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)
            unified_filtered_data = unify_data_format(copied_filtered_data)

            current_data_results = current_data.get("results", {})
            current_config = (
                current_data_results[0]
                if mkeyname
                and isinstance(current_data_results, list)
                and len(current_data_results) > 0
                else current_data_results
            )
            if is_existed:
                unified_current_values = find_current_values(
                    unified_filtered_data,
                    unify_data_format(current_config),
                )

                is_same = is_same_comparison(
                    serialize(unified_current_values), serialize(unified_filtered_data)
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": unified_current_values, "after": unified_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}
    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["system_virtual_wan_link"] = filtered_data
    fos.do_member_operation(
        "system",
        "virtual-wan-link",
        data_copy,
    )

    return fos.set("system", "virtual-wan-link", data=converted_data, vdom=vdom)


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_system(data, fos, check_mode):

    if data["system_virtual_wan_link"]:
        resp = system_virtual_wan_link(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_virtual_wan_link"))
    if isinstance(resp, tuple) and len(resp) == 4:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "v_range": [["v6.0.0", "v6.2.7"]],
    "type": "dict",
    "children": {
        "status": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "load_balance_mode": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [
                {"value": "source-ip-based"},
                {"value": "weight-based"},
                {"value": "usage-based"},
                {"value": "source-dest-ip-based"},
                {"value": "measured-volume-based"},
            ],
        },
        "neighbor_hold_down": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "neighbor_hold_down_time": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "integer",
        },
        "neighbor_hold_boot_time": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "integer",
        },
        "fail_detect": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fail_alert_interfaces": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "zone": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.2.7"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.2.7"]],
        },
        "members": {
            "type": "list",
            "elements": "dict",
            "children": {
                "seq_num": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                    "required": True,
                },
                "interface": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "gateway": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "source": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "gateway6": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "source6": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "cost": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "integer"},
                "weight": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "priority": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "spillover_threshold": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "ingress_spillover_threshold": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "volume_ratio": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "status": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "comment": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "health_check": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "required": True,
                },
                "probe_packets": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "addr_mode": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "ipv4"}, {"value": "ipv6"}],
                },
                "server": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "protocol": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "ping"},
                        {"value": "tcp-echo"},
                        {"value": "udp-echo"},
                        {"value": "http"},
                        {"value": "twamp"},
                        {"value": "ping6"},
                    ],
                },
                "port": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "security_mode": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "none"}, {"value": "authentication"}],
                },
                "password": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "packet_size": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "ha_priority": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "integer"},
                "http_get": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "http_agent": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "http_match": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "interval": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "probe_timeout": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.2.7"]],
                    "type": "integer",
                },
                "failtime": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "recoverytime": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "diffservcode": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.2.7"]],
                    "type": "string",
                },
                "update_cascade_interface": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "update_static_route": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "sla_fail_log_period": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "integer",
                },
                "sla_pass_log_period": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "integer",
                },
                "threshold_warning_packetloss": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "threshold_alert_packetloss": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "threshold_warning_latency": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "threshold_alert_latency": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "threshold_warning_jitter": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "threshold_alert_jitter": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "members": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "seq_num": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "sla": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "integer",
                            "required": True,
                        },
                        "link_cost_factor": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "list",
                            "options": [
                                {"value": "latency"},
                                {"value": "jitter"},
                                {"value": "packet-loss"},
                            ],
                            "multiple_values": True,
                            "elements": "str",
                        },
                        "latency_threshold": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "integer",
                        },
                        "jitter_threshold": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "integer",
                        },
                        "packetloss_threshold": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "integer",
                        },
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "neighbor": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ip": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "required": True,
                },
                "member": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "integer"},
                "role": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "standalone"},
                        {"value": "primary"},
                        {"value": "secondary"},
                    ],
                },
                "health_check": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
                "sla_id": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "integer"},
            },
            "v_range": [["v6.2.0", "v6.2.7"]],
        },
        "service": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                    "required": True,
                },
                "name": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "addr_mode": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "ipv4"}, {"value": "ipv6"}],
                },
                "input_device": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "input_device_negate": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "mode": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "auto"},
                        {"value": "manual"},
                        {"value": "priority"},
                        {"value": "sla"},
                        {"value": "load-balance", "v_range": [["v6.2.0", "v6.2.7"]]},
                    ],
                },
                "role": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "standalone"},
                        {"value": "primary"},
                        {"value": "secondary"},
                    ],
                },
                "standalone_action": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "quality_link": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "tos": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "tos_mask": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "protocol": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "start_port": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "end_port": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "route_tag": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "dst": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "dst_negate": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "src": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "dst6": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "src6": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "src_negate": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "users": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "groups": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "internet_service": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "internet_service_custom": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "internet_service_custom_group": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "internet_service_id": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "internet_service_group": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "internet_service_app_ctrl": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.2.0", "v6.2.7"]],
                },
                "internet_service_app_ctrl_group": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.2.0", "v6.2.7"]],
                },
                "health_check": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "link_cost_factor": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "latency"},
                        {"value": "jitter"},
                        {"value": "packet-loss"},
                        {"value": "inbandwidth"},
                        {"value": "outbandwidth"},
                        {"value": "bibandwidth"},
                        {"value": "custom-profile-1"},
                    ],
                },
                "packet_loss_weight": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "latency_weight": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "jitter_weight": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "bandwidth_weight": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "link_cost_threshold": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "hold_down_time": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "dscp_forward": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "dscp_reverse": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "dscp_forward_tag": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                },
                "dscp_reverse_tag": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                },
                "sla": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "health_check": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        },
                        "id": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "priority_members": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "seq_num": {
                            "v_range": [["v6.0.0", "v6.2.7"]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.2.7"]],
                },
                "status": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "gateway": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "default": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "sla_compare_method": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "order"}, {"value": "number"}],
                },
                "member": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "integer",
                },
                "internet_service_ctrl": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", "v6.0.11"]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.0.11"]],
                },
                "internet_service_ctrl_group": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", "v6.0.11"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.0.11"]],
                },
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
    },
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "system_virtual_wan_link": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_virtual_wan_link"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_virtual_wan_link"]["options"][attribute_name][
                "required"
            ] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "system_virtual_wan_link"
        )

        is_error, has_changed, result, diff = fortios_system(
            module.params, fos, module.check_mode
        )

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
