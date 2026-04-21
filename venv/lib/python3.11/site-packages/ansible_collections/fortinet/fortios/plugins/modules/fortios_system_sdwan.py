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
module: fortios_system_sdwan
short_description: Configure redundant Internet connections with multiple outbound links and health-check profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and sdwan category.
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

    system_sdwan:
        description:
            - Configure redundant Internet connections with multiple outbound links and health-check profiles.
        default: null
        type: dict
        suboptions:
            app_perf_log_period:
                description:
                    - Time interval in seconds that application performance logs are generated (0 - 3600).
                type: int
            duplication:
                description:
                    - Create SD-WAN duplication rule.
                type: list
                elements: dict
                suboptions:
                    dstaddr:
                        description:
                            - Destination address or address group names.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address or address group name. Source firewall.address.name firewall.addrgrp.name.
                                required: true
                                type: str
                    dstaddr6:
                        description:
                            - Destination address6 or address6 group names.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address6 or address6 group name. Source firewall.address6.name firewall.addrgrp6.name.
                                required: true
                                type: str
                    dstintf:
                        description:
                            - Outgoing (egress) interfaces or zones.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Interface, zone or SDWAN zone name. Source system.interface.name system.zone.name system.sdwan.zone.name.
                                required: true
                                type: str
                    id:
                        description:
                            - Duplication rule ID (1 - 255). see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    packet_de_duplication:
                        description:
                            - Enable/disable discarding of packets that have been duplicated.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    packet_duplication:
                        description:
                            - Configure packet duplication method.
                        type: str
                        choices:
                            - 'disable'
                            - 'force'
                            - 'on-demand'
                    service:
                        description:
                            - Service and service group name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Service and service group name. Source firewall.service.custom.name firewall.service.group.name.
                                required: true
                                type: str
                    service_id:
                        description:
                            - SD-WAN service rule ID list.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - SD-WAN service rule ID. see <a href='#notes'>Notes</a>. Source system.sdwan.service.id.
                                required: true
                                type: int
                    sla_match_service:
                        description:
                            - Enable/disable packet duplication matching health-check SLAs in service rule.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    srcaddr:
                        description:
                            - Source address or address group names.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address or address group name. Source firewall.address.name firewall.addrgrp.name.
                                required: true
                                type: str
                    srcaddr6:
                        description:
                            - Source address6 or address6 group names.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address6 or address6 group name. Source firewall.address6.name firewall.addrgrp6.name.
                                required: true
                                type: str
                    srcintf:
                        description:
                            - Incoming (ingress) interfaces or zones.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Interface, zone or SDWAN zone name. Source system.interface.name system.zone.name system.sdwan.zone.name.
                                required: true
                                type: str
            duplication_max_discrepancy:
                description:
                    - Maximum discrepancy between two packets for deduplication in milliseconds (250 - 1000).
                type: int
            duplication_max_num:
                description:
                    - Maximum number of interface members a packet is duplicated in the SD-WAN zone (2 - 4).
                type: int
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
                    agent_probe_timeout:
                        description:
                            - Time to wait before a probe packet is considered lost when detect-mode is agent (5000 - 3600*1000 msec).
                        type: int
                    bandwidth_weight:
                        description:
                            - Coefficient of reciprocal of available bidirectional bandwidth in the formula of custom-profile-1.
                        type: int
                    class_id:
                        description:
                            - Traffic class ID. Source firewall.traffic-class.class-id.
                        type: int
                    detect_mode:
                        description:
                            - The mode determining how to detect the server.
                        type: str
                        choices:
                            - 'active'
                            - 'passive'
                            - 'prefer-passive'
                            - 'remote'
                            - 'agent-based'
                    diffservcode:
                        description:
                            - Differentiated services code point (DSCP) in the IP header of the probe packet.
                        type: str
                    dns_match_ip:
                        description:
                            - Response IP expected from DNS server if the protocol is DNS.
                        type: str
                    dns_request_domain:
                        description:
                            - Fully qualified domain name to resolve for the DNS probe.
                        type: str
                    embed_measured_health:
                        description:
                            - Enable/disable embedding measured health information.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    failtime:
                        description:
                            - Number of failures before server is considered lost (1 - 3600).
                        type: int
                    fortiguard:
                        description:
                            - Enable/disable use of FortiGuard predefined server.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    fortiguard_name:
                        description:
                            - Predefined health-check target name. Source system.health-check-fortiguard.name.
                        type: str
                    ftp_file:
                        description:
                            - Full path and file name on the FTP server to download for FTP health-check to probe.
                        type: str
                    ftp_mode:
                        description:
                            - FTP mode.
                        type: str
                        choices:
                            - 'passive'
                            - 'port'
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
                            - Status check interval in milliseconds, or the time between attempting to connect to the server (20 - 3600*1000 msec).
                        type: int
                    jitter_weight:
                        description:
                            - Coefficient of jitter in the formula of custom-profile-1.
                        type: int
                    latency_weight:
                        description:
                            - Coefficient of latency in the formula of custom-profile-1.
                        type: int
                    members:
                        description:
                            - Member sequence number list.
                        type: list
                        elements: dict
                        suboptions:
                            seq_num:
                                description:
                                    - Member sequence number. see <a href='#notes'>Notes</a>. Source system.sdwan.members.seq-num.
                                required: true
                                type: int
                    mos_codec:
                        description:
                            - Codec to use for MOS calculation .
                        type: str
                        choices:
                            - 'g711'
                            - 'g722'
                            - 'g729'
                    name:
                        description:
                            - Status check or health check name.
                        required: true
                        type: str
                    packet_loss_weight:
                        description:
                            - Coefficient of packet-loss in the formula of custom-profile-1.
                        type: int
                    packet_size:
                        description:
                            - Packet size of a TWAMP test session. (124/158 - 1024)
                        type: int
                    password:
                        description:
                            - TWAMP controller password in authentication mode.
                        type: str
                    port:
                        description:
                            - 'Port number used to communicate with the server over the selected protocol (0 - 65535).'
                        type: int
                    probe_count:
                        description:
                            - Number of most recent probes that should be used to calculate latency and jitter (5 - 30).
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
                            - Time to wait before a probe packet is considered lost (20 - 3600*1000 msec).
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
                            - 'https'
                            - 'twamp'
                            - 'dns'
                            - 'tcp-connect'
                            - 'ftp'
                            - 'ping6'
                    quality_measured_method:
                        description:
                            - Method to measure the quality of tcp-connect.
                        type: str
                        choices:
                            - 'half-open'
                            - 'half-close'
                    recoverytime:
                        description:
                            - Number of successful responses received before server is considered recovered (1 - 3600).
                        type: int
                    remote_probe_timeout:
                        description:
                            - Time to wait before a probe packet is considered lost when detect-mode is remote (20 - 3600*1000 msec).
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
                        type: list
                        elements: str
                    sla:
                        description:
                            - Service level agreement (SLA).
                        type: list
                        elements: dict
                        suboptions:
                            custom_profile_threshold:
                                description:
                                    - Custom profile threshold for SLA to be marked as pass(0 - 10000000).
                                type: int
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
                                    - 'custom-profile-1'
                                    - 'mos'
                                    - 'remote'
                            mos_threshold:
                                description:
                                    - Minimum mean opinion score for SLA to be marked as pass(1.0 - 5.0).
                                type: str
                            packetloss_threshold:
                                description:
                                    - Packet loss for SLA to make decision in percentage. (0 - 100).
                                type: int
                            priority_in_sla:
                                description:
                                    - Value to be distributed into routing table when in-sla (0 - 65535).
                                type: int
                            priority_out_sla:
                                description:
                                    - Value to be distributed into routing table when out-sla (0 - 65535).
                                type: int
                    sla_fail_log_period:
                        description:
                            - Time interval in seconds that SLA fail log messages will be generated (0 - 3600).
                        type: int
                    sla_id_redistribute:
                        description:
                            - Select the ID from the SLA sub-table. The selected SLA"s priority value will be distributed into the routing table (0 - 32).
                        type: int
                    sla_pass_log_period:
                        description:
                            - Time interval in seconds that SLA pass log messages will be generated (0 - 3600).
                        type: int
                    source:
                        description:
                            - Source IP address used in the health-check packet to the server.
                        type: str
                    source6:
                        description:
                            - Source IPv6 address used in the health-check packet to server.
                        type: str
                    system_dns:
                        description:
                            - Enable/disable system DNS as the probe server.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
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
                    user:
                        description:
                            - The user name to access probe server.
                        type: str
                    vrf:
                        description:
                            - Virtual Routing Forwarding ID.
                        type: int
            health_check_fortiguard:
                description:
                    - SD-WAN status checking or health checking. Identify a server predefine by FortiGuard and determine how SD-WAN verifies that FGT can
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
                    class_id:
                        description:
                            - Traffic class ID. Source firewall.traffic-class.class-id.
                        type: int
                    detect_mode:
                        description:
                            - The mode determining how to detect the server.
                        type: str
                        choices:
                            - 'active'
                            - 'passive'
                            - 'prefer-passive'
                            - 'remote'
                            - 'agent-based'
                    diffservcode:
                        description:
                            - Differentiated services code point (DSCP) in the IP header of the probe packet.
                        type: str
                    dns_match_ip:
                        description:
                            - Response IP expected from DNS server if the protocol is DNS.
                        type: str
                    dns_request_domain:
                        description:
                            - Fully qualified domain name to resolve for the DNS probe.
                        type: str
                    embed_measured_health:
                        description:
                            - Enable/disable embedding measured health information.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    failtime:
                        description:
                            - Number of failures before server is considered lost (1 - 3600).
                        type: int
                    ftp_file:
                        description:
                            - Full path and file name on the FTP server to download for FTP health-check to probe.
                        type: str
                    ftp_mode:
                        description:
                            - FTP mode.
                        type: str
                        choices:
                            - 'passive'
                            - 'port'
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
                            - Status check interval in milliseconds, or the time between attempting to connect to the server (20 - 3600*1000 msec).
                        type: int
                    members:
                        description:
                            - Member sequence number list.
                        type: list
                        elements: dict
                        suboptions:
                            seq_num:
                                description:
                                    - Member sequence number. see <a href='#notes'>Notes</a>. Source system.sdwan.members.seq-num.
                                required: true
                                type: int
                    mos_codec:
                        description:
                            - Codec to use for MOS calculation .
                        type: str
                        choices:
                            - 'g711'
                            - 'g722'
                            - 'g729'
                    packet_size:
                        description:
                            - Packet size of a TWAMP test session. (124/158 - 1024)
                        type: int
                    password:
                        description:
                            - TWAMP controller password in authentication mode.
                        type: str
                    port:
                        description:
                            - 'Port number used to communicate with the server over the selected protocol (0 - 65535).'
                        type: int
                    probe_count:
                        description:
                            - Number of most recent probes that should be used to calculate latency and jitter (5 - 30).
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
                            - Time to wait before a probe packet is considered lost (20 - 3600*1000 msec).
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
                            - 'https'
                            - 'twamp'
                            - 'dns'
                            - 'tcp-connect'
                            - 'ftp'
                    quality_measured_method:
                        description:
                            - Method to measure the quality of tcp-connect.
                        type: str
                        choices:
                            - 'half-open'
                            - 'half-close'
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
                            - Predefined IP address or FQDN name from FortiGuard.
                        type: list
                        elements: str
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
                                    - 'mos'
                                    - 'remote'
                            mos_threshold:
                                description:
                                    - Minimum Mean Opinion Score for SLA to be marked as pass. (1.0 - 5.0).
                                type: str
                            packetloss_threshold:
                                description:
                                    - Packet loss for SLA to make decision in percentage. (0 - 100).
                                type: int
                            priority_in_sla:
                                description:
                                    - Value to be distributed into routing table when in-sla (0 - 65535).
                                type: int
                            priority_out_sla:
                                description:
                                    - Value to be distributed into routing table when out-sla (0 - 65535).
                                type: int
                    sla_fail_log_period:
                        description:
                            - Time interval in seconds that SLA fail log messages will be generated (0 - 3600).
                        type: int
                    sla_id_redistribute:
                        description:
                            - Select the ID from the SLA sub-table. The selected SLA"s priority value will be distributed into the routing table (0 - 32).
                        type: int
                    sla_pass_log_period:
                        description:
                            - Time interval in seconds that SLA pass log messages will be generated (0 - 3600).
                        type: int
                    source:
                        description:
                            - Source IP address used in the health-check packet to the server.
                        type: str
                    source6:
                        description:
                            - Source IPv6 address used in the health-check packet to server.
                        type: str
                    system_dns:
                        description:
                            - Enable/disable system DNS as the probe server.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    target_name:
                        description:
                            - Status check or predefined health-check targets name.
                        required: true
                        type: str
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
                    user:
                        description:
                            - The user name to access probe server.
                        type: str
                    vrf:
                        description:
                            - Virtual Routing Forwarding ID.
                        type: int
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
                    - FortiGate interfaces added to the SD-WAN.
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
                    preferred_source:
                        description:
                            - Preferred source of route for this member.
                        type: str
                    priority:
                        description:
                            - Priority of the interface for IPv4 (1 - 65535). Used for SD-WAN rules or priority rules.
                        type: int
                    priority_in_sla:
                        description:
                            - Preferred priority of routes to this member when this member is in-sla (0 - 65535).
                        type: int
                    priority_out_sla:
                        description:
                            - Preferred priority of routes to this member when this member is out-of-sla (0 - 65535).
                        type: int
                    priority6:
                        description:
                            - Priority of the interface for IPv6 (1 - 65535). Used for SD-WAN rules or priority rules.
                        type: int
                    seq_num:
                        description:
                            - Sequence number(1-512). see <a href='#notes'>Notes</a>.
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
                    transport_group:
                        description:
                            - Measured transport group (0 - 255).
                        type: int
                    volume_ratio:
                        description:
                            - Measured volume ratio (this value / sum of all values = percentage of link volume, 1 - 255).
                        type: int
                    weight:
                        description:
                            - Weight of this interface for weighted load balancing. (1 - 255) More traffic is directed to interfaces with higher weights.
                        type: int
                    zone:
                        description:
                            - Zone name. Source system.sdwan.zone.name.
                        type: str
            neighbor:
                description:
                    - Create SD-WAN neighbor from BGP neighbor table to control route advertisements according to SLA status.
                type: list
                elements: dict
                suboptions:
                    health_check:
                        description:
                            - SD-WAN health-check name. Source system.sdwan.health-check.name.
                        type: str
                    ip:
                        description:
                            - IP/IPv6 address of neighbor or neighbor-group name. Source router.bgp.neighbor-group.name router.bgp.neighbor.ip.
                        required: true
                        type: str
                    member:
                        description:
                            - Member sequence number list. Source system.sdwan.members.seq-num.
                        type: list
                        elements: dict
                        suboptions:
                            seq_num:
                                description:
                                    - Member sequence number. see <a href='#notes'>Notes</a>. Source system.sdwan.members.seq-num.
                                required: true
                                type: int
                    minimum_sla_meet_members:
                        description:
                            - Minimum number of members which meet SLA when the neighbor is preferred.
                        type: int
                    mode:
                        description:
                            - What metric to select the neighbor.
                        type: str
                        choices:
                            - 'sla'
                            - 'speedtest'
                    role:
                        description:
                            - Role of neighbor.
                        type: str
                        choices:
                            - 'standalone'
                            - 'primary'
                            - 'secondary'
                    route_metric:
                        description:
                            - Route-metric of neighbor.
                        type: str
                        choices:
                            - 'preferable'
                            - 'priority'
                    service_id:
                        description:
                            - SD-WAN service ID to work with the neighbor. Source system.sdwan.service.id.
                        type: int
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
                    agent_exclusive:
                        description:
                            - Set/unset the service as agent use exclusively.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bandwidth_weight:
                        description:
                            - Coefficient of reciprocal of available bidirectional bandwidth in the formula of custom-profile-1.
                        type: int
                    comment:
                        description:
                            - Comments.
                        type: str
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
                    end_src_port:
                        description:
                            - End source port number.
                        type: int
                    fib_best_match_force:
                        description:
                            - Enable/disable force using fib-best-match oif as outgoing interface.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
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
                    hash_mode:
                        description:
                            - Hash algorithm for selected priority members for load balance mode.
                        type: str
                        choices:
                            - 'round-robin'
                            - 'source-ip-based'
                            - 'source-dest-ip-based'
                            - 'inbandwidth'
                            - 'outbandwidth'
                            - 'bibandwidth'
                    health_check:
                        description:
                            - Health check list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Health check name. Source system.sdwan.health-check.name.
                                required: true
                                type: str
                    hold_down_time:
                        description:
                            - Waiting period in seconds when switching from the back-up member to the primary member (0 - 10000000).
                        type: int
                    id:
                        description:
                            - SD-WAN rule ID (1 - 4000). see <a href='#notes'>Notes</a>.
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
                    input_zone:
                        description:
                            - Source input-zone name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Zone. Source system.sdwan.zone.name.
                                required: true
                                type: str
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
                    internet_service_app_ctrl_category:
                        description:
                            - IDs of one or more application control categories.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Application control category ID. see <a href='#notes'>Notes</a>.
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
                    internet_service_fortiguard:
                        description:
                            - FortiGuard Internet service name list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - FortiGuard Internet service name. Source firewall.internet-service-fortiguard.name.
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
                    internet_service_name:
                        description:
                            - Internet service name list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Internet service name. Source firewall.internet-service-name.name.
                                required: true
                                type: str
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
                    load_balance:
                        description:
                            - Enable/disable load-balance.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    minimum_sla_meet_members:
                        description:
                            - Minimum number of members which meet SLA.
                        type: int
                    mode:
                        description:
                            - Control how the SD-WAN rule sets the priority of interfaces in the SD-WAN.
                        type: str
                        choices:
                            - 'auto'
                            - 'manual'
                            - 'priority'
                            - 'sla'
                            - 'load-balance'
                    name:
                        description:
                            - SD-WAN rule name.
                        type: str
                    packet_loss_weight:
                        description:
                            - Coefficient of packet-loss in the formula of custom-profile-1.
                        type: int
                    passive_measurement:
                        description:
                            - Enable/disable passive measurement based on the service criteria.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    priority_members:
                        description:
                            - Member sequence number list.
                        type: list
                        elements: dict
                        suboptions:
                            seq_num:
                                description:
                                    - Member sequence number. see <a href='#notes'>Notes</a>. Source system.sdwan.members.seq-num.
                                required: true
                                type: int
                    priority_zone:
                        description:
                            - Priority zone name list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Priority zone name. Source system.sdwan.zone.name.
                                required: true
                                type: str
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
                    shortcut:
                        description:
                            - Enable/disable shortcut for this service.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    shortcut_priority:
                        description:
                            - High priority of ADVPN shortcut for this service.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                            - 'auto'
                    shortcut_stickiness:
                        description:
                            - Enable/disable shortcut-stickiness of ADVPN.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    sla:
                        description:
                            - Service level agreement (SLA).
                        type: list
                        elements: dict
                        suboptions:
                            health_check:
                                description:
                                    - SD-WAN health-check. Source system.sdwan.health-check.name.
                                required: true
                                type: str
                            id:
                                description:
                                    - SLA ID.
                                type: int
                    sla_compare_method:
                        description:
                            - Method to compare SLA value for SLA mode.
                        type: str
                        choices:
                            - 'order'
                            - 'number'
                    sla_stickiness:
                        description:
                            - Enable/disable SLA stickiness .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
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
                    start_src_port:
                        description:
                            - Start source port number.
                        type: int
                    status:
                        description:
                            - Enable/disable SD-WAN service.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tie_break:
                        description:
                            - Method of selecting member if more than one meets the SLA.
                        type: str
                        choices:
                            - 'zone'
                            - 'cfg-order'
                            - 'fib-best-match'
                            - 'priority'
                            - 'input-device'
                    tos:
                        description:
                            - Type of service bit pattern.
                        type: str
                    tos_mask:
                        description:
                            - Type of service evaluated bits.
                        type: str
                    use_shortcut_sla:
                        description:
                            - Enable/disable use of ADVPN shortcut for quality comparison.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
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
                    zone_mode:
                        description:
                            - Enable/disable zone mode.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            speedtest_bypass_routing:
                description:
                    - Enable/disable bypass routing when speedtest on a SD-WAN member.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
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
                    advpn_health_check:
                        description:
                            - Health check for ADVPN local overlay link quality. Source system.sdwan.health-check.name.
                        type: str
                    advpn_select:
                        description:
                            - Enable/disable selection of ADVPN based on SDWAN information.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    minimum_sla_meet_members:
                        description:
                            - Minimum number of members which meet SLA when the neighbor is preferred.
                        type: int
                    name:
                        description:
                            - Zone name.
                        required: true
                        type: str
                    service_sla_tie_break:
                        description:
                            - Method of selecting member if more than one meets the SLA.
                        type: str
                        choices:
                            - 'cfg-order'
                            - 'fib-best-match'
                            - 'priority'
                            - 'input-device'
"""

EXAMPLES = """
- name: Configure redundant Internet connections with multiple outbound links and health-check profiles.
  fortinet.fortios.fortios_system_sdwan:
      vdom: "{{ vdom }}"
      system_sdwan:
          app_perf_log_period: "0"
          duplication:
              -
                  dstaddr:
                      -
                          name: "default_name_6 (source firewall.address.name firewall.addrgrp.name)"
                  dstaddr6:
                      -
                          name: "default_name_8 (source firewall.address6.name firewall.addrgrp6.name)"
                  dstintf:
                      -
                          name: "default_name_10 (source system.interface.name system.zone.name system.sdwan.zone.name)"
                  id: "11"
                  packet_de_duplication: "enable"
                  packet_duplication: "disable"
                  service:
                      -
                          name: "default_name_15 (source firewall.service.custom.name firewall.service.group.name)"
                  service_id:
                      -
                          id: "17 (source system.sdwan.service.id)"
                  sla_match_service: "enable"
                  srcaddr:
                      -
                          name: "default_name_20 (source firewall.address.name firewall.addrgrp.name)"
                  srcaddr6:
                      -
                          name: "default_name_22 (source firewall.address6.name firewall.addrgrp6.name)"
                  srcintf:
                      -
                          name: "default_name_24 (source system.interface.name system.zone.name system.sdwan.zone.name)"
          duplication_max_discrepancy: "250"
          duplication_max_num: "2"
          fail_alert_interfaces:
              -
                  name: "default_name_28 (source system.interface.name)"
          fail_detect: "enable"
          health_check:
              -
                  addr_mode: "ipv4"
                  agent_probe_timeout: "60000"
                  bandwidth_weight: "0"
                  class_id: "0"
                  detect_mode: "active"
                  diffservcode: "<your_own_value>"
                  dns_match_ip: "<your_own_value>"
                  dns_request_domain: "<your_own_value>"
                  embed_measured_health: "enable"
                  failtime: "5"
                  fortiguard: "disable"
                  fortiguard_name: "<your_own_value> (source system.health-check-fortiguard.name)"
                  ftp_file: "<your_own_value>"
                  ftp_mode: "passive"
                  ha_priority: "1"
                  http_agent: "<your_own_value>"
                  http_get: "<your_own_value>"
                  http_match: "<your_own_value>"
                  interval: "500"
                  jitter_weight: "0"
                  latency_weight: "0"
                  members:
                      -
                          seq_num: "<you_own_value>"
                  mos_codec: "g711"
                  name: "default_name_55"
                  packet_loss_weight: "0"
                  packet_size: "124"
                  password: "<your_own_value>"
                  port: "0"
                  probe_count: "30"
                  probe_packets: "disable"
                  probe_timeout: "500"
                  protocol: "ping"
                  quality_measured_method: "half-open"
                  recoverytime: "5"
                  remote_probe_timeout: "5000"
                  security_mode: "none"
                  server: "192.168.100.40"
                  sla:
                      -
                          custom_profile_threshold: "0"
                          id: "71"
                          jitter_threshold: "5"
                          latency_threshold: "5"
                          link_cost_factor: "latency"
                          mos_threshold: "<your_own_value>"
                          packetloss_threshold: "0"
                          priority_in_sla: "0"
                          priority_out_sla: "0"
                  sla_fail_log_period: "0"
                  sla_id_redistribute: "0"
                  sla_pass_log_period: "0"
                  source: "<your_own_value>"
                  source6: "<your_own_value>"
                  system_dns: "disable"
                  threshold_alert_jitter: "0"
                  threshold_alert_latency: "0"
                  threshold_alert_packetloss: "0"
                  threshold_warning_jitter: "0"
                  threshold_warning_latency: "0"
                  threshold_warning_packetloss: "0"
                  update_cascade_interface: "enable"
                  update_static_route: "enable"
                  user: "<your_own_value>"
                  vrf: "0"
          health_check_fortiguard:
              -
                  addr_mode: "ipv4"
                  class_id: "0"
                  detect_mode: "active"
                  diffservcode: "<your_own_value>"
                  dns_match_ip: "<your_own_value>"
                  dns_request_domain: "<your_own_value>"
                  embed_measured_health: "enable"
                  failtime: "5"
                  ftp_file: "<your_own_value>"
                  ftp_mode: "passive"
                  ha_priority: "1"
                  http_agent: "<your_own_value>"
                  http_get: "<your_own_value>"
                  http_match: "<your_own_value>"
                  interval: "500"
                  members:
                      -
                          seq_num: "<you_own_value>"
                  mos_codec: "g711"
                  packet_size: "124"
                  password: "<your_own_value>"
                  port: "0"
                  probe_count: "30"
                  probe_packets: "disable"
                  probe_timeout: "500"
                  protocol: "ping"
                  quality_measured_method: "half-open"
                  recoverytime: "5"
                  security_mode: "none"
                  server: "192.168.100.40"
                  sla:
                      -
                          id: "126"
                          jitter_threshold: "5"
                          latency_threshold: "5"
                          link_cost_factor: "latency"
                          mos_threshold: "<your_own_value>"
                          packetloss_threshold: "0"
                          priority_in_sla: "0"
                          priority_out_sla: "0"
                  sla_fail_log_period: "0"
                  sla_id_redistribute: "0"
                  sla_pass_log_period: "0"
                  source: "<your_own_value>"
                  source6: "<your_own_value>"
                  system_dns: "disable"
                  target_name: "<your_own_value>"
                  threshold_alert_jitter: "0"
                  threshold_alert_latency: "0"
                  threshold_alert_packetloss: "0"
                  threshold_warning_jitter: "0"
                  threshold_warning_latency: "0"
                  threshold_warning_packetloss: "0"
                  update_cascade_interface: "enable"
                  update_static_route: "enable"
                  user: "<your_own_value>"
                  vrf: "0"
          load_balance_mode: "source-ip-based"
          members:
              -
                  comment: "Comments."
                  cost: "0"
                  gateway: "<your_own_value>"
                  gateway6: "<your_own_value>"
                  ingress_spillover_threshold: "0"
                  interface: "<your_own_value> (source system.interface.name)"
                  preferred_source: "<your_own_value>"
                  priority: "1"
                  priority_in_sla: "0"
                  priority_out_sla: "0"
                  priority6: "1024"
                  seq_num: "<you_own_value>"
                  source: "<your_own_value>"
                  source6: "<your_own_value>"
                  spillover_threshold: "0"
                  status: "disable"
                  transport_group: "0"
                  volume_ratio: "1"
                  weight: "1"
                  zone: "<your_own_value> (source system.sdwan.zone.name)"
          neighbor:
              -
                  health_check: "<your_own_value> (source system.sdwan.health-check.name)"
                  ip: "<your_own_value> (source router.bgp.neighbor-group.name router.bgp.neighbor.ip)"
                  member:
                      -
                          seq_num: "<you_own_value>"
                  minimum_sla_meet_members: "1"
                  mode: "sla"
                  role: "standalone"
                  route_metric: "preferable"
                  service_id: "0"
                  sla_id: "0"
          neighbor_hold_boot_time: "0"
          neighbor_hold_down: "enable"
          neighbor_hold_down_time: "0"
          service:
              -
                  addr_mode: "ipv4"
                  agent_exclusive: "enable"
                  bandwidth_weight: "0"
                  comment: "Comments."
                  default: "enable"
                  dscp_forward: "enable"
                  dscp_forward_tag: "<your_own_value>"
                  dscp_reverse: "enable"
                  dscp_reverse_tag: "<your_own_value>"
                  dst:
                      -
                          name: "default_name_198 (source firewall.address.name firewall.addrgrp.name)"
                  dst_negate: "enable"
                  dst6:
                      -
                          name: "default_name_201 (source firewall.address6.name firewall.addrgrp6.name)"
                  end_port: "65535"
                  end_src_port: "65535"
                  fib_best_match_force: "disable"
                  gateway: "enable"
                  groups:
                      -
                          name: "default_name_207 (source user.group.name)"
                  hash_mode: "round-robin"
                  health_check:
                      -
                          name: "default_name_210 (source system.sdwan.health-check.name)"
                  hold_down_time: "0"
                  id: "212"
                  input_device:
                      -
                          name: "default_name_214 (source system.interface.name)"
                  input_device_negate: "enable"
                  input_zone:
                      -
                          name: "default_name_217 (source system.sdwan.zone.name)"
                  internet_service: "enable"
                  internet_service_app_ctrl:
                      -
                          id: "220"
                  internet_service_app_ctrl_category:
                      -
                          id: "222"
                  internet_service_app_ctrl_group:
                      -
                          name: "default_name_224 (source application.group.name)"
                  internet_service_custom:
                      -
                          name: "default_name_226 (source firewall.internet-service-custom.name)"
                  internet_service_custom_group:
                      -
                          name: "default_name_228 (source firewall.internet-service-custom-group.name)"
                  internet_service_fortiguard:
                      -
                          name: "default_name_230 (source firewall.internet-service-fortiguard.name)"
                  internet_service_group:
                      -
                          name: "default_name_232 (source firewall.internet-service-group.name)"
                  internet_service_name:
                      -
                          name: "default_name_234 (source firewall.internet-service-name.name)"
                  jitter_weight: "0"
                  latency_weight: "0"
                  link_cost_factor: "latency"
                  link_cost_threshold: "10"
                  load_balance: "enable"
                  minimum_sla_meet_members: "0"
                  mode: "auto"
                  name: "default_name_242"
                  packet_loss_weight: "0"
                  passive_measurement: "enable"
                  priority_members:
                      -
                          seq_num: "<you_own_value>"
                  priority_zone:
                      -
                          name: "default_name_248 (source system.sdwan.zone.name)"
                  protocol: "0"
                  quality_link: "0"
                  role: "standalone"
                  route_tag: "0"
                  shortcut: "enable"
                  shortcut_priority: "enable"
                  shortcut_stickiness: "enable"
                  sla:
                      -
                          health_check: "<your_own_value> (source system.sdwan.health-check.name)"
                          id: "258"
                  sla_compare_method: "order"
                  sla_stickiness: "enable"
                  src:
                      -
                          name: "default_name_262 (source firewall.address.name firewall.addrgrp.name)"
                  src_negate: "enable"
                  src6:
                      -
                          name: "default_name_265 (source firewall.address6.name firewall.addrgrp6.name)"
                  standalone_action: "enable"
                  start_port: "1"
                  start_src_port: "1"
                  status: "enable"
                  tie_break: "zone"
                  tos: "<your_own_value>"
                  tos_mask: "<your_own_value>"
                  use_shortcut_sla: "enable"
                  users:
                      -
                          name: "default_name_275 (source user.local.name)"
                  zone_mode: "enable"
          speedtest_bypass_routing: "disable"
          status: "disable"
          zone:
              -
                  advpn_health_check: "<your_own_value> (source system.sdwan.health-check.name)"
                  advpn_select: "enable"
                  minimum_sla_meet_members: "1"
                  name: "default_name_283"
                  service_sla_tie_break: "cfg-order"
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


def filter_system_sdwan_data(json):
    option_list = [
        "app_perf_log_period",
        "duplication",
        "duplication_max_discrepancy",
        "duplication_max_num",
        "fail_alert_interfaces",
        "fail_detect",
        "health_check",
        "health_check_fortiguard",
        "load_balance_mode",
        "members",
        "neighbor",
        "neighbor_hold_boot_time",
        "neighbor_hold_down",
        "neighbor_hold_down_time",
        "service",
        "speedtest_bypass_routing",
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
        ["health_check", "server"],
        ["health_check", "sla", "link_cost_factor"],
        ["health_check_fortiguard", "server"],
        ["health_check_fortiguard", "sla", "link_cost_factor"],
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


def system_sdwan(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_sdwan_data = data["system_sdwan"]

    filtered_data = filter_system_sdwan_data(system_sdwan_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "sdwan", filtered_data, vdom=vdom)
        current_data = fos.get("system", "sdwan", vdom=vdom, mkey=mkey)
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
    data_copy["system_sdwan"] = filtered_data
    fos.do_member_operation(
        "system",
        "sdwan",
        data_copy,
    )

    return fos.set("system", "sdwan", data=converted_data, vdom=vdom)


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

    if data["system_sdwan"]:
        resp = system_sdwan(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_sdwan"))
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
    "v_range": [["v6.4.0", ""]],
    "type": "dict",
    "children": {
        "status": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "load_balance_mode": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [
                {"value": "source-ip-based"},
                {"value": "weight-based"},
                {"value": "usage-based"},
                {"value": "source-dest-ip-based"},
                {"value": "measured-volume-based"},
            ],
        },
        "speedtest_bypass_routing": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "duplication_max_num": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "duplication_max_discrepancy": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "neighbor_hold_down": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "neighbor_hold_down_time": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "app_perf_log_period": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "neighbor_hold_boot_time": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "fail_detect": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fail_alert_interfaces": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.4.0", ""]],
        },
        "zone": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "advpn_select": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "advpn_health_check": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "service_sla_tie_break": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "cfg-order"},
                        {"value": "fib-best-match"},
                        {"value": "priority", "v_range": [["v7.6.4", ""]]},
                        {"value": "input-device", "v_range": [["v7.2.0", ""]]},
                    ],
                },
                "minimum_sla_meet_members": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "integer",
                },
            },
            "v_range": [["v6.4.0", ""]],
        },
        "members": {
            "type": "list",
            "elements": "dict",
            "children": {
                "seq_num": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "interface": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "zone": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "gateway": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "preferred_source": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "source": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "gateway6": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "source6": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "cost": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "weight": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "priority": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "priority6": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "priority_in_sla": {"v_range": [["v7.6.0", ""]], "type": "integer"},
                "priority_out_sla": {"v_range": [["v7.6.0", ""]], "type": "integer"},
                "spillover_threshold": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "ingress_spillover_threshold": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "integer",
                },
                "volume_ratio": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "status": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "transport_group": {"v_range": [["v7.4.2", ""]], "type": "integer"},
                "comment": {"v_range": [["v6.4.0", ""]], "type": "string"},
            },
            "v_range": [["v6.4.0", ""]],
        },
        "health_check": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "fortiguard": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "fortiguard_name": {"v_range": [["v7.6.1", ""]], "type": "string"},
                "probe_packets": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "addr_mode": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "ipv4"}, {"value": "ipv6"}],
                },
                "system_dns": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "server": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "detect_mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "active"},
                        {"value": "passive"},
                        {"value": "prefer-passive"},
                        {"value": "remote", "v_range": [["v7.2.1", ""]]},
                        {"value": "agent-based", "v_range": [["v7.2.4", ""]]},
                    ],
                },
                "protocol": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ping"},
                        {"value": "tcp-echo"},
                        {"value": "udp-echo"},
                        {"value": "http"},
                        {"value": "https", "v_range": [["v7.4.1", ""]]},
                        {"value": "twamp"},
                        {"value": "dns"},
                        {
                            "value": "tcp-connect",
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                        },
                        {
                            "value": "ftp",
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                        },
                        {"value": "ping6", "v_range": [["v6.4.1", "v6.4.1"]]},
                    ],
                },
                "port": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "quality_measured_method": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "half-open"}, {"value": "half-close"}],
                },
                "security_mode": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "none"}, {"value": "authentication"}],
                },
                "user": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                },
                "password": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "packet_size": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "ha_priority": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "ftp_mode": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "passive"}, {"value": "port"}],
                },
                "ftp_file": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                },
                "http_get": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "http_agent": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "http_match": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "dns_request_domain": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "dns_match_ip": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                },
                "interval": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "probe_timeout": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "agent_probe_timeout": {"v_range": [["v7.6.3", ""]], "type": "integer"},
                "remote_probe_timeout": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "integer",
                },
                "failtime": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "recoverytime": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "probe_count": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "diffservcode": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "update_cascade_interface": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "update_static_route": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "embed_measured_health": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "sla_id_redistribute": {"v_range": [["v7.2.1", ""]], "type": "integer"},
                "sla_fail_log_period": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "sla_pass_log_period": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "threshold_warning_packetloss": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "integer",
                },
                "threshold_alert_packetloss": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "integer",
                },
                "threshold_warning_latency": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "integer",
                },
                "threshold_alert_latency": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "integer",
                },
                "threshold_warning_jitter": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "integer",
                },
                "threshold_alert_jitter": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "integer",
                },
                "vrf": {"v_range": [["v7.2.0", ""]], "type": "integer"},
                "source": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "source6": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "members": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "seq_num": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "mos_codec": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "g711"},
                        {"value": "g722"},
                        {"value": "g729"},
                    ],
                },
                "class_id": {"v_range": [["v7.4.0", ""]], "type": "integer"},
                "packet_loss_weight": {"v_range": [["v7.6.4", ""]], "type": "integer"},
                "latency_weight": {"v_range": [["v7.6.4", ""]], "type": "integer"},
                "jitter_weight": {"v_range": [["v7.6.4", ""]], "type": "integer"},
                "bandwidth_weight": {"v_range": [["v7.6.4", ""]], "type": "integer"},
                "sla": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "link_cost_factor": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "list",
                            "options": [
                                {"value": "latency"},
                                {"value": "jitter"},
                                {"value": "packet-loss"},
                                {
                                    "value": "custom-profile-1",
                                    "v_range": [["v7.6.4", ""]],
                                },
                                {"value": "mos", "v_range": [["v7.2.0", ""]]},
                                {"value": "remote", "v_range": [["v7.6.0", ""]]},
                            ],
                            "multiple_values": True,
                            "elements": "str",
                        },
                        "latency_threshold": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "integer",
                        },
                        "jitter_threshold": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "integer",
                        },
                        "packetloss_threshold": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "integer",
                        },
                        "mos_threshold": {
                            "v_range": [["v7.2.0", ""]],
                            "type": "string",
                        },
                        "custom_profile_threshold": {
                            "v_range": [["v7.6.4", ""]],
                            "type": "integer",
                        },
                        "priority_in_sla": {
                            "v_range": [["v7.2.1", ""]],
                            "type": "integer",
                        },
                        "priority_out_sla": {
                            "v_range": [["v7.2.1", ""]],
                            "type": "integer",
                        },
                    },
                    "v_range": [["v6.4.0", ""]],
                },
            },
            "v_range": [["v6.4.0", ""]],
        },
        "service": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "name": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "addr_mode": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "ipv4"}, {"value": "ipv6"}],
                },
                "load_balance": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "input_device": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "input_device_negate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "input_zone": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.2.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.0", ""]],
                },
                "mode": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "auto"},
                        {"value": "manual"},
                        {"value": "priority"},
                        {"value": "sla"},
                        {"value": "load-balance", "v_range": [["v6.4.0", "v7.4.0"]]},
                    ],
                },
                "zone_mode": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "minimum_sla_meet_members": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "integer",
                },
                "hash_mode": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "round-robin"},
                        {"value": "source-ip-based"},
                        {"value": "source-dest-ip-based"},
                        {"value": "inbandwidth"},
                        {"value": "outbandwidth"},
                        {"value": "bibandwidth"},
                    ],
                },
                "shortcut_priority": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "disable"},
                        {"value": "auto"},
                    ],
                },
                "role": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standalone"},
                        {"value": "primary"},
                        {"value": "secondary"},
                    ],
                },
                "standalone_action": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "quality_link": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "tos": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "tos_mask": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "protocol": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "start_port": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "end_port": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "start_src_port": {"v_range": [["v7.4.1", ""]], "type": "integer"},
                "end_src_port": {"v_range": [["v7.4.1", ""]], "type": "integer"},
                "dst": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "dst_negate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "src": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "dst6": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "src6": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "src_negate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "users": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "groups": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "internet_service": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "internet_service_custom": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "internet_service_custom_group": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "internet_service_fortiguard": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.6.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.6.4", ""]],
                },
                "internet_service_name": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "internet_service_group": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "internet_service_app_ctrl": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "internet_service_app_ctrl_group": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "internet_service_app_ctrl_category": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.2.0", ""]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.0", ""]],
                },
                "health_check": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "link_cost_factor": {
                    "v_range": [["v6.4.0", ""]],
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
                "packet_loss_weight": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "latency_weight": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "jitter_weight": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "bandwidth_weight": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "link_cost_threshold": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "hold_down_time": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "sla_stickiness": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "dscp_forward": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "dscp_reverse": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "dscp_forward_tag": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "dscp_reverse_tag": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "sla": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "health_check": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "id": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "priority_members": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "seq_num": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "priority_zone": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.0.1", ""]],
                },
                "status": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "gateway": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "default": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "sla_compare_method": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "order"}, {"value": "number"}],
                },
                "fib_best_match_force": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "tie_break": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "zone"},
                        {"value": "cfg-order"},
                        {"value": "fib-best-match"},
                        {"value": "priority", "v_range": [["v7.6.4", ""]]},
                        {"value": "input-device", "v_range": [["v7.2.0", ""]]},
                    ],
                },
                "use_shortcut_sla": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "passive_measurement": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "agent_exclusive": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "shortcut": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "comment": {"v_range": [["v7.6.0", ""]], "type": "string"},
                "shortcut_stickiness": {
                    "v_range": [["v7.4.0", "v7.4.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_tag": {"v_range": [["v6.4.0", "v7.2.4"]], "type": "integer"},
            },
            "v_range": [["v6.4.0", ""]],
        },
        "neighbor": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ip": {"v_range": [["v6.4.0", ""]], "type": "string", "required": True},
                "member": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "seq_num": {
                            "v_range": [["v7.2.0", ""]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "service_id": {"v_range": [["v7.4.1", ""]], "type": "integer"},
                "minimum_sla_meet_members": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "integer",
                },
                "mode": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "sla"}, {"value": "speedtest"}],
                },
                "role": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standalone"},
                        {"value": "primary"},
                        {"value": "secondary"},
                    ],
                },
                "route_metric": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "preferable"}, {"value": "priority"}],
                },
                "health_check": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "sla_id": {"v_range": [["v6.4.0", ""]], "type": "integer"},
            },
            "v_range": [["v6.4.0", ""]],
        },
        "duplication": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "integer",
                    "required": True,
                },
                "service_id": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.4.4", ""]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.4", ""]],
                },
                "srcaddr": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                },
                "dstaddr": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                },
                "srcaddr6": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                },
                "dstaddr6": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                },
                "srcintf": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                },
                "dstintf": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                },
                "service": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                },
                "packet_duplication": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "force"},
                        {"value": "on-demand"},
                    ],
                },
                "sla_match_service": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "packet_de_duplication": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
        },
        "health_check_fortiguard": {
            "type": "list",
            "elements": "dict",
            "children": {
                "target_name": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "required": True,
                },
                "probe_packets": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "addr_mode": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [{"value": "ipv4"}, {"value": "ipv6"}],
                },
                "system_dns": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "server": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "detect_mode": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [
                        {"value": "active"},
                        {"value": "passive"},
                        {"value": "prefer-passive"},
                        {"value": "remote"},
                        {"value": "agent-based"},
                    ],
                },
                "protocol": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [
                        {"value": "ping"},
                        {"value": "tcp-echo"},
                        {"value": "udp-echo"},
                        {"value": "http"},
                        {"value": "https"},
                        {"value": "twamp"},
                        {"value": "dns"},
                        {"value": "tcp-connect"},
                        {"value": "ftp"},
                    ],
                },
                "port": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
                "quality_measured_method": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [{"value": "half-open"}, {"value": "half-close"}],
                },
                "security_mode": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [{"value": "none"}, {"value": "authentication"}],
                },
                "user": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
                "password": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
                "packet_size": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
                "ha_priority": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
                "ftp_mode": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [{"value": "passive"}, {"value": "port"}],
                },
                "ftp_file": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
                "http_get": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
                "http_agent": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
                "http_match": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
                "dns_request_domain": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                },
                "dns_match_ip": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
                "interval": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
                "probe_timeout": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
                "failtime": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
                "recoverytime": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
                "probe_count": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
                "diffservcode": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
                "update_cascade_interface": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "update_static_route": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "embed_measured_health": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "sla_id_redistribute": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "sla_fail_log_period": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "sla_pass_log_period": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "threshold_warning_packetloss": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "threshold_alert_packetloss": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "threshold_warning_latency": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "threshold_alert_latency": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "threshold_warning_jitter": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "threshold_alert_jitter": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "vrf": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
                "source": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
                "source6": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
                "members": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "seq_num": {
                            "v_range": [["v7.6.0", "v7.6.0"]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.6.0", "v7.6.0"]],
                },
                "mos_codec": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [
                        {"value": "g711"},
                        {"value": "g722"},
                        {"value": "g729"},
                    ],
                },
                "class_id": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
                "sla": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.6.0", "v7.6.0"]],
                            "type": "integer",
                            "required": True,
                        },
                        "link_cost_factor": {
                            "v_range": [["v7.6.0", "v7.6.0"]],
                            "type": "list",
                            "options": [
                                {"value": "latency"},
                                {"value": "jitter"},
                                {"value": "packet-loss"},
                                {"value": "mos"},
                                {"value": "remote"},
                            ],
                            "multiple_values": True,
                            "elements": "str",
                        },
                        "latency_threshold": {
                            "v_range": [["v7.6.0", "v7.6.0"]],
                            "type": "integer",
                        },
                        "jitter_threshold": {
                            "v_range": [["v7.6.0", "v7.6.0"]],
                            "type": "integer",
                        },
                        "packetloss_threshold": {
                            "v_range": [["v7.6.0", "v7.6.0"]],
                            "type": "integer",
                        },
                        "mos_threshold": {
                            "v_range": [["v7.6.0", "v7.6.0"]],
                            "type": "string",
                        },
                        "priority_in_sla": {
                            "v_range": [["v7.6.0", "v7.6.0"]],
                            "type": "integer",
                        },
                        "priority_out_sla": {
                            "v_range": [["v7.6.0", "v7.6.0"]],
                            "type": "integer",
                        },
                    },
                    "v_range": [["v7.6.0", "v7.6.0"]],
                },
            },
            "v_range": [["v7.6.0", "v7.6.0"]],
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
        "system_sdwan": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_sdwan"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_sdwan"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_sdwan"
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
