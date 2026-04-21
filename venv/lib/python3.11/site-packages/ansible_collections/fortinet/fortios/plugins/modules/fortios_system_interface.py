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
module: fortios_system_interface
short_description: Configure interfaces in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and interface category.
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

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    system_interface:
        description:
            - Configure interfaces.
        default: null
        type: dict
        suboptions:
            ac_name:
                description:
                    - PPPoE server name.
                type: str
            aggregate:
                description:
                    - Aggregate interface.
                type: str
            aggregate_type:
                description:
                    - Type of aggregation.
                type: str
                choices:
                    - 'physical'
                    - 'vxlan'
            algorithm:
                description:
                    - Frame distribution algorithm.
                type: str
                choices:
                    - 'L2'
                    - 'L3'
                    - 'L4'
                    - 'NPU-GRE'
                    - 'Source-MAC'
            alias:
                description:
                    - Alias will be displayed with the interface name to make it easier to distinguish.
                type: str
            allowaccess:
                description:
                    - Permitted types of management access to this interface.
                type: list
                elements: str
                choices:
                    - 'ping'
                    - 'https'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
                    - 'fgfm'
                    - 'radius-acct'
                    - 'probe-response'
                    - 'fabric'
                    - 'ftm'
                    - 'speed-test'
                    - 'scim'
                    - 'capwap'
            ap_discover:
                description:
                    - Enable/disable automatic registration of unknown FortiAP devices.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            arpforward:
                description:
                    - Enable/disable ARP forwarding.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_cert:
                description:
                    - HTTPS server certificate. Source vpn.certificate.local.name.
                type: str
            auth_portal_addr:
                description:
                    - Address of captive portal.
                type: str
            auth_type:
                description:
                    - PPP authentication type to use.
                type: str
                choices:
                    - 'auto'
                    - 'pap'
                    - 'chap'
                    - 'mschapv1'
                    - 'mschapv2'
            auto_auth_extension_device:
                description:
                    - Enable/disable automatic authorization of dedicated Fortinet extension device on this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bandwidth_measure_time:
                description:
                    - Bandwidth measure time.
                type: int
            bfd:
                description:
                    - Bidirectional Forwarding Detection (BFD) settings.
                type: str
                choices:
                    - 'global'
                    - 'enable'
                    - 'disable'
            bfd_desired_min_tx:
                description:
                    - BFD desired minimal transmit interval.
                type: int
            bfd_detect_mult:
                description:
                    - BFD detection multiplier.
                type: int
            bfd_required_min_rx:
                description:
                    - BFD required minimal receive interval.
                type: int
            broadcast_forticlient_discovery:
                description:
                    - Enable/disable broadcasting FortiClient discovery messages.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            broadcast_forward:
                description:
                    - Enable/disable broadcast forwarding.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            captive_portal:
                description:
                    - Enable/disable captive portal.
                type: int
            cli_conn_status:
                description:
                    - CLI connection status.
                type: int
            client_options:
                description:
                    - DHCP client options.
                type: list
                elements: dict
                suboptions:
                    code:
                        description:
                            - DHCP client option code.
                        type: int
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ip:
                        description:
                            - DHCP option IPs.
                        type: list
                        elements: str
                    type:
                        description:
                            - DHCP client option type.
                        type: str
                        choices:
                            - 'hex'
                            - 'string'
                            - 'ip'
                            - 'fqdn'
                    value:
                        description:
                            - DHCP client option value.
                        type: str
            color:
                description:
                    - Color of icon on the GUI.
                type: int
            dedicated_to:
                description:
                    - Configure interface for single purpose.
                type: str
                choices:
                    - 'none'
                    - 'management'
            default_purdue_level:
                description:
                    - default purdue level of device detected on this interface.
                type: str
                choices:
                    - '1'
                    - '1.5'
                    - '2'
                    - '2.5'
                    - '3'
                    - '3.5'
                    - '4'
                    - '5'
                    - '5.5'
            defaultgw:
                description:
                    - Enable to get the gateway IP from the DHCP or PPPoE server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            description:
                description:
                    - Description.
                type: str
            detected_peer_mtu:
                description:
                    - MTU of detected peer (0 - 4294967295).
                type: int
            detectprotocol:
                description:
                    - Protocols used to detect the server.
                type: list
                elements: str
                choices:
                    - 'ping'
                    - 'tcp-echo'
                    - 'udp-echo'
            detectserver:
                description:
                    - Gateway"s ping server for this IP.
                type: str
            device_access_list:
                description:
                    - Device access list.
                type: str
            device_identification:
                description:
                    - Enable/disable passively gathering of device identity information about the devices on the network connected to this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            device_identification_active_scan:
                description:
                    - Enable/disable active gathering of device identity information about the devices on the network connected to this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            device_netscan:
                description:
                    - Enable/disable inclusion of devices detected on this interface in network vulnerability scans.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            device_user_identification:
                description:
                    - Enable/disable passive gathering of user identity information about users on this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            devindex:
                description:
                    - Device Index.
                type: int
            dhcp_broadcast_flag:
                description:
                    - Enable/disable setting of the broadcast flag in messages sent by the DHCP client .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_classless_route_addition:
                description:
                    - Enable/disable addition of classless static routes retrieved from DHCP server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dhcp_client_identifier:
                description:
                    - DHCP client identifier.
                type: str
            dhcp_relay_agent_option:
                description:
                    - Enable/disable DHCP relay agent option.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dhcp_relay_allow_no_end_option:
                description:
                    - Enable/disable relaying DHCP messages with no end option.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_relay_circuit_id:
                description:
                    - DHCP relay circuit ID.
                type: str
            dhcp_relay_interface:
                description:
                    - Specify outgoing interface to reach server. Source system.interface.name.
                type: str
            dhcp_relay_interface_select_method:
                description:
                    - Specify how to select outgoing interface to reach server.
                type: str
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            dhcp_relay_ip:
                description:
                    - DHCP relay IP address.
                type: list
                elements: str
            dhcp_relay_link_selection:
                description:
                    - DHCP relay link selection.
                type: str
            dhcp_relay_request_all_server:
                description:
                    - Enable/disable sending of DHCP requests to all servers.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_relay_service:
                description:
                    - Enable/disable allowing this interface to act as a DHCP relay.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_relay_source_ip:
                description:
                    - IP address used by the DHCP relay as its source IP.
                type: str
            dhcp_relay_type:
                description:
                    - DHCP relay type (regular or IPsec).
                type: str
                choices:
                    - 'regular'
                    - 'ipsec'
            dhcp_relay_vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
            dhcp_renew_time:
                description:
                    - DHCP renew time in seconds (300-604800), 0 means use the renew time provided by the server.
                type: int
            dhcp_smart_relay:
                description:
                    - Enable/disable DHCP smart relay.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_snooping_server_list:
                description:
                    - Configure DHCP server access list.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - DHCP server name.
                        required: true
                        type: str
                    server_ip:
                        description:
                            - IP address for DHCP server.
                        type: str
            disc_retry_timeout:
                description:
                    - Time in seconds to wait before retrying to start a PPPoE discovery, 0 means no timeout.
                type: int
            disconnect_threshold:
                description:
                    - Time in milliseconds to wait before sending a notification that this interface is down or disconnected.
                type: int
            distance:
                description:
                    - Distance for routes learned through PPPoE or DHCP, lower distance indicates preferred route.
                type: int
            dns_server_override:
                description:
                    - Enable/disable use DNS acquired by DHCP or PPPoE.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dns_server_protocol:
                description:
                    - DNS transport protocols.
                type: list
                elements: str
                choices:
                    - 'cleartext'
                    - 'dot'
                    - 'doh'
            drop_fragment:
                description:
                    - Enable/disable drop fragment packets.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            drop_overlapped_fragment:
                description:
                    - Enable/disable drop overlapped fragment packets.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eap_ca_cert:
                description:
                    - EAP CA certificate name. Source certificate.ca.name.
                type: str
            eap_identity:
                description:
                    - EAP identity.
                type: str
            eap_method:
                description:
                    - EAP method.
                type: str
                choices:
                    - 'tls'
                    - 'peap'
            eap_password:
                description:
                    - EAP password.
                type: str
            eap_supplicant:
                description:
                    - Enable/disable EAP-Supplicant.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eap_user_cert:
                description:
                    - EAP user certificate name. Source certificate.local.name.
                type: str
            egress_cos:
                description:
                    - Override outgoing CoS in user VLAN tag.
                type: str
                choices:
                    - 'disable'
                    - 'cos0'
                    - 'cos1'
                    - 'cos2'
                    - 'cos3'
                    - 'cos4'
                    - 'cos5'
                    - 'cos6'
                    - 'cos7'
            egress_queues:
                description:
                    - Configure queues of NP port on egress path.
                type: dict
                suboptions:
                    cos0:
                        description:
                            - CoS profile name for CoS 0. Source system.isf-queue-profile.name.
                        type: str
                    cos1:
                        description:
                            - CoS profile name for CoS 1. Source system.isf-queue-profile.name.
                        type: str
                    cos2:
                        description:
                            - CoS profile name for CoS 2. Source system.isf-queue-profile.name.
                        type: str
                    cos3:
                        description:
                            - CoS profile name for CoS 3. Source system.isf-queue-profile.name.
                        type: str
                    cos4:
                        description:
                            - CoS profile name for CoS 4. Source system.isf-queue-profile.name.
                        type: str
                    cos5:
                        description:
                            - CoS profile name for CoS 5. Source system.isf-queue-profile.name.
                        type: str
                    cos6:
                        description:
                            - CoS profile name for CoS 6. Source system.isf-queue-profile.name.
                        type: str
                    cos7:
                        description:
                            - CoS profile name for CoS 7. Source system.isf-queue-profile.name.
                        type: str
            egress_shaping_profile:
                description:
                    - Outgoing traffic shaping profile. Source firewall.shaping-profile.profile-name.
                type: str
            endpoint_compliance:
                description:
                    - Enable/disable endpoint compliance enforcement.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            estimated_downstream_bandwidth:
                description:
                    - Estimated maximum downstream bandwidth (kbps). Used to estimate link utilization.
                type: int
            estimated_upstream_bandwidth:
                description:
                    - Estimated maximum upstream bandwidth (kbps). Used to estimate link utilization.
                type: int
            exclude_signatures:
                description:
                    - Exclude IOT or OT application signatures.
                type: list
                elements: str
                choices:
                    - 'iot'
                    - 'ot'
            explicit_ftp_proxy:
                description:
                    - Enable/disable the explicit FTP proxy on this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            explicit_web_proxy:
                description:
                    - Enable/disable the explicit web proxy on this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            external:
                description:
                    - Enable/disable identifying the interface as an external interface (which usually means it"s connected to the Internet).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fail_action_on_extender:
                description:
                    - Action on FortiExtender when interface fail.
                type: str
                choices:
                    - 'soft-restart'
                    - 'hard-restart'
                    - 'reboot'
            fail_alert_interfaces:
                description:
                    - Names of the FortiGate interfaces to which the link failure alert is sent.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Names of the non-virtual interface. Source system.interface.name.
                        required: true
                        type: str
            fail_alert_method:
                description:
                    - Select link-failed-signal or link-down method to alert about a failed link.
                type: str
                choices:
                    - 'link-failed-signal'
                    - 'link-down'
            fail_detect:
                description:
                    - Enable/disable fail detection features for this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fail_detect_option:
                description:
                    - Options for detecting that this interface has failed.
                type: list
                elements: str
                choices:
                    - 'detectserver'
                    - 'link-down'
            fortiheartbeat:
                description:
                    - Enable/disable FortiHeartBeat (FortiTelemetry on GUI).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortilink:
                description:
                    - Enable FortiLink to dedicate this interface to manage other Fortinet devices.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortilink_backup_link:
                description:
                    - FortiLink split interface backup link.
                type: int
            fortilink_neighbor_detect:
                description:
                    - Protocol for FortiGate neighbor discovery.
                type: str
                choices:
                    - 'lldp'
                    - 'fortilink'
            fortilink_split_interface:
                description:
                    - Enable/disable FortiLink split interface to connect member link to different FortiSwitch in stack for uplink redundancy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortilink_stacking:
                description:
                    - Enable/disable FortiLink switch-stacking on this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forward_domain:
                description:
                    - Transparent mode forward domain.
                type: int
            forward_error_correction:
                description:
                    - Configure forward error correction (FEC).
                type: str
                choices:
                    - 'none'
                    - 'disable'
                    - 'cl91-rs-fec'
                    - 'cl74-fc-fec'
                    - 'auto'
            gi_gk:
                description:
                    - Enable/disable Gi Gatekeeper.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gwdetect:
                description:
                    - Enable/disable detect gateway alive for first.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ha_priority:
                description:
                    - HA election priority for the PING server.
                type: int
            icmp_accept_redirect:
                description:
                    - Enable/disable ICMP accept redirect.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            icmp_send_redirect:
                description:
                    - Enable/disable sending of ICMP redirects.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ident_accept:
                description:
                    - Enable/disable authentication for this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            idle_timeout:
                description:
                    - PPPoE auto disconnect after idle timeout seconds, 0 means no timeout.
                type: int
            ike_saml_server:
                description:
                    - Configure IKE authentication SAML server. Source user.saml.name.
                type: str
            inbandwidth:
                description:
                    - Bandwidth limit for incoming traffic (0 - 80000000 kbps), 0 means unlimited.
                type: int
            ingress_cos:
                description:
                    - Override incoming CoS in user VLAN tag on VLAN interface or assign a priority VLAN tag on physical interface.
                type: str
                choices:
                    - 'disable'
                    - 'cos0'
                    - 'cos1'
                    - 'cos2'
                    - 'cos3'
                    - 'cos4'
                    - 'cos5'
                    - 'cos6'
                    - 'cos7'
            ingress_shaping_profile:
                description:
                    - Incoming traffic shaping profile. Source firewall.shaping-profile.profile-name.
                type: str
            ingress_spillover_threshold:
                description:
                    - Ingress Spillover threshold (0 - 16776000 kbps), 0 means unlimited.
                type: int
            interconnect_profile:
                description:
                    - Set interconnect profile.
                type: str
                choices:
                    - 'default'
                    - 'profile1'
                    - 'profile2'
            interface:
                description:
                    - Interface name. Source system.interface.name.
                type: str
            internal:
                description:
                    - Implicitly created.
                type: int
            ip:
                description:
                    - 'Interface IPv4 address and subnet mask, syntax: X.X.X.X/24.'
                type: str
            ip_managed_by_fortiipam:
                description:
                    - Enable/disable automatic IP address assignment of this interface by FortiIPAM.
                type: str
                choices:
                    - 'inherit-global'
                    - 'enable'
                    - 'disable'
            ipmac:
                description:
                    - Enable/disable IP/MAC binding.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ips_sniffer_mode:
                description:
                    - Enable/disable the use of this interface as a one-armed sniffer.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipunnumbered:
                description:
                    - Unnumbered IP used for PPPoE interfaces for which no unique local address is provided.
                type: str
            ipv6:
                description:
                    - IPv6 of interface.
                type: dict
                suboptions:
                    autoconf:
                        description:
                            - Enable/disable address auto config.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    cli_conn6_status:
                        description:
                            - CLI IPv6 connection status.
                        type: int
                    client_options:
                        description:
                            - DHCP6 client options.
                        type: list
                        elements: dict
                        suboptions:
                            code:
                                description:
                                    - DHCPv6 option code.
                                type: int
                            id:
                                description:
                                    - ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            ip6:
                                description:
                                    - DHCP option IP6s.
                                type: list
                                elements: str
                            type:
                                description:
                                    - DHCPv6 option type.
                                type: str
                                choices:
                                    - 'hex'
                                    - 'string'
                                    - 'ip6'
                                    - 'fqdn'
                            value:
                                description:
                                    - DHCPv6 option value (hexadecimal value must be even).
                                type: str
                    dhcp6_client_options:
                        description:
                            - DHCPv6 client options.
                        type: list
                        elements: str
                        choices:
                            - 'rapid'
                            - 'iapd'
                            - 'iana'
                    dhcp6_iapd_list:
                        description:
                            - DHCPv6 IA-PD list.
                        type: list
                        elements: dict
                        suboptions:
                            iaid:
                                description:
                                    - Identity association identifier. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            prefix_hint:
                                description:
                                    - DHCPv6 prefix that will be used as a hint to the upstream DHCPv6 server.
                                type: str
                            prefix_hint_plt:
                                description:
                                    - DHCPv6 prefix hint preferred life time (sec), 0 means unlimited lease time.
                                type: int
                            prefix_hint_vlt:
                                description:
                                    - DHCPv6 prefix hint valid life time (sec).
                                type: int
                    dhcp6_information_request:
                        description:
                            - Enable/disable DHCPv6 information request.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    dhcp6_prefix_delegation:
                        description:
                            - Enable/disable DHCPv6 prefix delegation.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    dhcp6_prefix_hint:
                        description:
                            - DHCPv6 prefix that will be used as a hint to the upstream DHCPv6 server.
                        type: str
                    dhcp6_prefix_hint_plt:
                        description:
                            - DHCPv6 prefix hint preferred life time (sec), 0 means unlimited lease time.
                        type: int
                    dhcp6_prefix_hint_vlt:
                        description:
                            - DHCPv6 prefix hint valid life time (sec).
                        type: int
                    dhcp6_relay_interface_id:
                        description:
                            - DHCP6 relay interface ID.
                        type: str
                    dhcp6_relay_ip:
                        description:
                            - DHCPv6 relay IP address.
                        type: list
                        elements: str
                    dhcp6_relay_service:
                        description:
                            - Enable/disable DHCPv6 relay.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp6_relay_source_interface:
                        description:
                            - Enable/disable use of address on this interface as the source address of the relay message.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp6_relay_source_ip:
                        description:
                            - IPv6 address used by the DHCP6 relay as its source IP.
                        type: str
                    dhcp6_relay_type:
                        description:
                            - DHCPv6 relay type.
                        type: str
                        choices:
                            - 'regular'
                    icmp6_send_redirect:
                        description:
                            - Enable/disable sending of ICMPv6 redirects.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    interface_identifier:
                        description:
                            - IPv6 interface identifier.
                        type: str
                    ip6_address:
                        description:
                            - 'Primary IPv6 address prefix. Syntax: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xxx.'
                        type: str
                    ip6_adv_rio:
                        description:
                            - Enable/disable sending advertisements with route information option.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ip6_allowaccess:
                        description:
                            - Allow management access to the interface.
                        type: list
                        elements: str
                        choices:
                            - 'ping'
                            - 'https'
                            - 'ssh'
                            - 'snmp'
                            - 'http'
                            - 'telnet'
                            - 'fgfm'
                            - 'fabric'
                            - 'scim'
                            - 'capwap'
                    ip6_default_life:
                        description:
                            - Default life (sec).
                        type: int
                    ip6_delegated_prefix_iaid:
                        description:
                            - IAID of obtained delegated-prefix from the upstream interface.
                        type: int
                    ip6_delegated_prefix_list:
                        description:
                            - Advertised IPv6 delegated prefix list.
                        type: list
                        elements: dict
                        suboptions:
                            autonomous_flag:
                                description:
                                    - Enable/disable the autonomous flag.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            delegated_prefix_iaid:
                                description:
                                    - IAID of obtained delegated-prefix from the upstream interface.
                                type: int
                            onlink_flag:
                                description:
                                    - Enable/disable the onlink flag.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            prefix_id:
                                description:
                                    - Prefix ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            rdnss:
                                description:
                                    - Recursive DNS server option.
                                type: list
                                elements: str
                            rdnss_service:
                                description:
                                    - Recursive DNS service option.
                                type: str
                                choices:
                                    - 'delegated'
                                    - 'default'
                                    - 'specify'
                            subnet:
                                description:
                                    - Add subnet ID to routing prefix.
                                type: str
                            upstream_interface:
                                description:
                                    - Name of the interface that provides delegated information. Source system.interface.name.
                                type: str
                    ip6_dns_server_override:
                        description:
                            - Enable/disable using the DNS server acquired by DHCP.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ip6_dnssl_list:
                        description:
                            - Advertised IPv6 DNSS list.
                        type: list
                        elements: dict
                        suboptions:
                            dnssl_life_time:
                                description:
                                    - DNS search list time in seconds (0 - 4294967295).
                                type: int
                            domain:
                                description:
                                    - Domain name.
                                required: true
                                type: str
                    ip6_extra_addr:
                        description:
                            - Extra IPv6 address prefixes of interface.
                        type: list
                        elements: dict
                        suboptions:
                            prefix:
                                description:
                                    - IPv6 address prefix.
                                required: true
                                type: str
                    ip6_hop_limit:
                        description:
                            - Hop limit (0 means unspecified).
                        type: int
                    ip6_link_mtu:
                        description:
                            - IPv6 link MTU.
                        type: int
                    ip6_manage_flag:
                        description:
                            - Enable/disable the managed flag.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ip6_max_interval:
                        description:
                            - IPv6 maximum interval (4 to 1800 sec).
                        type: int
                    ip6_min_interval:
                        description:
                            - IPv6 minimum interval (3 to 1350 sec).
                        type: int
                    ip6_mode:
                        description:
                            - Addressing mode (static, DHCP, delegated).
                        type: str
                        choices:
                            - 'static'
                            - 'dhcp'
                            - 'pppoe'
                            - 'delegated'
                    ip6_other_flag:
                        description:
                            - Enable/disable the other IPv6 flag.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ip6_prefix_list:
                        description:
                            - Advertised prefix list.
                        type: list
                        elements: dict
                        suboptions:
                            autonomous_flag:
                                description:
                                    - Enable/disable the autonomous flag.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            dnssl:
                                description:
                                    - DNS search list option.
                                type: list
                                elements: dict
                                suboptions:
                                    domain:
                                        description:
                                            - Domain name.
                                        required: true
                                        type: str
                            onlink_flag:
                                description:
                                    - Enable/disable the onlink flag.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            preferred_life_time:
                                description:
                                    - Preferred life time (sec).
                                type: int
                            prefix:
                                description:
                                    - IPv6 prefix.
                                required: true
                                type: str
                            rdnss:
                                description:
                                    - Recursive DNS server option.
                                type: list
                                elements: str
                            valid_life_time:
                                description:
                                    - Valid life time (sec).
                                type: int
                    ip6_prefix_mode:
                        description:
                            - Assigning a prefix from DHCP or RA.
                        type: str
                        choices:
                            - 'dhcp6'
                            - 'ra'
                    ip6_rdnss_list:
                        description:
                            - Advertised IPv6 RDNSS list.
                        type: list
                        elements: dict
                        suboptions:
                            rdnss:
                                description:
                                    - Recursive DNS server option.
                                required: true
                                type: str
                            rdnss_life_time:
                                description:
                                    - Recursive DNS server life time in seconds (0 - 4294967295).
                                type: int
                    ip6_reachable_time:
                        description:
                            - IPv6 reachable time (milliseconds; 0 means unspecified).
                        type: int
                    ip6_retrans_time:
                        description:
                            - IPv6 retransmit time (milliseconds; 0 means unspecified).
                        type: int
                    ip6_route_list:
                        description:
                            - Advertised route list.
                        type: list
                        elements: dict
                        suboptions:
                            route:
                                description:
                                    - IPv6 route.
                                required: true
                                type: str
                            route_life_time:
                                description:
                                    - Route life time in seconds (0 - 65535).
                                type: int
                            route_pref:
                                description:
                                    - Set route preference to the interface .
                                type: str
                                choices:
                                    - 'medium'
                                    - 'high'
                                    - 'low'
                    ip6_route_pref:
                        description:
                            - Set route preference to the interface .
                        type: str
                        choices:
                            - 'medium'
                            - 'high'
                            - 'low'
                    ip6_send_adv:
                        description:
                            - Enable/disable sending advertisements about the interface.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ip6_subnet:
                        description:
                            - 'Subnet to routing prefix. Syntax: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xxx.'
                        type: str
                    ip6_upstream_interface:
                        description:
                            - Interface name providing delegated information. Source system.interface.name.
                        type: str
                    nd_cert:
                        description:
                            - Neighbor discovery certificate. Source certificate.local.name.
                        type: str
                    nd_cga_modifier:
                        description:
                            - Neighbor discovery CGA modifier.
                        type: str
                    nd_mode:
                        description:
                            - Neighbor discovery mode.
                        type: str
                        choices:
                            - 'basic'
                            - 'SEND-compatible'
                    nd_security_level:
                        description:
                            - Neighbor discovery security level (0 - 7; 0 = least secure).
                        type: int
                    nd_timestamp_delta:
                        description:
                            - Neighbor discovery timestamp delta value (1 - 3600 sec; ).
                        type: int
                    nd_timestamp_fuzz:
                        description:
                            - Neighbor discovery timestamp fuzz factor (1 - 60 sec; ).
                        type: int
                    ra_send_mtu:
                        description:
                            - Enable/disable sending link MTU in RA packet.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    unique_autoconf_addr:
                        description:
                            - Enable/disable unique auto config address.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    vrip6_link_local:
                        description:
                            - Link-local IPv6 address of virtual router.
                        type: str
                    vrrp_virtual_mac6:
                        description:
                            - Enable/disable virtual MAC for VRRP.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    vrrp6:
                        description:
                            - IPv6 VRRP configuration.
                        type: list
                        elements: dict
                        suboptions:
                            accept_mode:
                                description:
                                    - Enable/disable accept mode.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            adv_interval:
                                description:
                                    - Advertisement interval (250 - 255000 milliseconds).
                                type: int
                            ignore_default_route:
                                description:
                                    - Enable/disable ignoring of default route when checking destination.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            preempt:
                                description:
                                    - Enable/disable preempt mode.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            priority:
                                description:
                                    - Priority of the virtual router (1 - 255).
                                type: int
                            start_time:
                                description:
                                    - Startup time (1 - 255 seconds).
                                type: int
                            status:
                                description:
                                    - Enable/disable VRRP.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            vrdst_priority:
                                description:
                                    - Priority of the virtual router when the virtual router destination becomes unreachable (0 - 254).
                                type: int
                            vrdst6:
                                description:
                                    - Monitor the route to this destination.
                                type: list
                                elements: str
                            vrgrp:
                                description:
                                    - VRRP group ID (1 - 65535).
                                type: int
                            vrid:
                                description:
                                    - Virtual router identifier (1 - 255). see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            vrip6:
                                description:
                                    - IPv6 address of the virtual router.
                                type: str
            l2forward:
                description:
                    - Enable/disable l2 forwarding.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            lacp_ha_secondary:
                description:
                    - LACP HA secondary member.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            lacp_ha_slave:
                description:
                    - LACP HA slave.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            lacp_mode:
                description:
                    - LACP mode.
                type: str
                choices:
                    - 'static'
                    - 'passive'
                    - 'active'
            lacp_speed:
                description:
                    - How often the interface sends LACP messages.
                type: str
                choices:
                    - 'slow'
                    - 'fast'
            lcp_echo_interval:
                description:
                    - Time in seconds between PPPoE Link Control Protocol (LCP) echo requests.
                type: int
            lcp_max_echo_fails:
                description:
                    - Maximum missed LCP echo messages before disconnect.
                type: int
            link_up_delay:
                description:
                    - Number of milliseconds to wait before considering a link is up.
                type: int
            lldp_network_policy:
                description:
                    - LLDP-MED network policy profile. Source system.lldp.network-policy.name.
                type: str
            lldp_reception:
                description:
                    - Enable/disable Link Layer Discovery Protocol (LLDP) reception.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
                    - 'vdom'
            lldp_transmission:
                description:
                    - Enable/disable Link Layer Discovery Protocol (LLDP) transmission.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
                    - 'vdom'
            macaddr:
                description:
                    - Change the interface"s MAC address.
                type: str
            managed_device:
                description:
                    - Available when FortiLink is enabled, used for managed devices through FortiLink interface.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Managed dev identifier.
                        required: true
                        type: str
            managed_subnetwork_size:
                description:
                    - Number of IP addresses to be allocated by FortiIPAM and used by this FortiGate unit"s DHCP server settings.
                type: str
                choices:
                    - '4'
                    - '8'
                    - '16'
                    - '32'
                    - '64'
                    - '128'
                    - '256'
                    - '512'
                    - '1024'
                    - '2048'
                    - '4096'
                    - '8192'
                    - '16384'
                    - '32768'
                    - '65536'
                    - '131072'
                    - '262144'
                    - '524288'
                    - '1048576'
                    - '2097152'
                    - '4194304'
                    - '8388608'
                    - '16777216'
            management_ip:
                description:
                    - High Availability in-band management IP address of this interface.
                type: str
            measured_downstream_bandwidth:
                description:
                    - Measured downstream bandwidth (kbps).
                type: int
            measured_upstream_bandwidth:
                description:
                    - Measured upstream bandwidth (kbps).
                type: int
            mediatype:
                description:
                    - Select SFP media interface type
                type: str
                choices:
                    - 'none'
                    - 'gmii'
                    - 'sgmii'
                    - 'sr'
                    - 'lr'
                    - 'cr'
                    - 'sr2'
                    - 'lr2'
                    - 'cr2'
                    - 'sr4'
                    - 'lr4'
                    - 'cr4'
                    - 'sr8'
                    - 'lr8'
                    - 'cr8'
                    - 'cfp2-sr10'
                    - 'cfp2-lr4'
            member:
                description:
                    - Physical interfaces that belong to the aggregate or redundant interface.
                type: list
                elements: dict
                suboptions:
                    interface_name:
                        description:
                            - Physical interface name. Source system.interface.name.
                        required: true
                        type: str
            min_links:
                description:
                    - Minimum number of aggregated ports that must be up.
                type: int
            min_links_down:
                description:
                    - Action to take when less than the configured minimum number of links are active.
                type: str
                choices:
                    - 'operational'
                    - 'administrative'
            mirroring_direction:
                description:
                    - Port mirroring direction.
                type: str
                choices:
                    - 'rx'
                    - 'tx'
                    - 'both'
            mirroring_filter:
                description:
                    - Mirroring filter.
                type: dict
                suboptions:
                    filter_dport:
                        description:
                            - Destinatin port of mirroring filter.
                        type: int
                    filter_dstip:
                        description:
                            - Destinatin IP and mask of mirroring filter.
                        type: str
                    filter_protocol:
                        description:
                            - Protocol of mirroring filter.
                        type: int
                    filter_sport:
                        description:
                            - Source port of mirroring filter.
                        type: int
                    filter_srcip:
                        description:
                            - Source IP and mask of mirroring filter.
                        type: str
            mirroring_port:
                description:
                    - Mirroring port. Source system.interface.name.
                type: str
            mode:
                description:
                    - Addressing mode (static, DHCP, PPPoE).
                type: str
                choices:
                    - 'static'
                    - 'dhcp'
                    - 'pppoe'
            monitor_bandwidth:
                description:
                    - Enable monitoring bandwidth on this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mtu:
                description:
                    - MTU value for this interface.
                type: int
            mtu_override:
                description:
                    - Enable to set a custom MTU for this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Name.
                required: true
                type: str
            ndiscforward:
                description:
                    - Enable/disable NDISC forwarding.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            netbios_forward:
                description:
                    - Enable/disable NETBIOS forwarding.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            netflow_sample_rate:
                description:
                    - NetFlow sample rate.  Sample one packet every configured number of packets(1 - 65535).
                type: int
            netflow_sampler:
                description:
                    - Enable/disable NetFlow on this interface and set the data that NetFlow collects (rx, tx, or both).
                type: str
                choices:
                    - 'disable'
                    - 'tx'
                    - 'rx'
                    - 'both'
            netflow_sampler_id:
                description:
                    - Netflow sampler ID.
                type: int
            np_qos_profile:
                description:
                    - NP QoS profile ID.
                type: int
            outbandwidth:
                description:
                    - Bandwidth limit for outgoing traffic (0 - 80000000 kbps).
                type: int
            padt_retry_timeout:
                description:
                    - PPPoE Active Discovery Terminate (PADT) used to terminate sessions after an idle time.
                type: int
            password:
                description:
                    - PPPoE account"s password.
                type: str
            ping_serv_status:
                description:
                    - PING server status.
                type: int
            polling_interval:
                description:
                    - sFlow polling interval in seconds (1 - 255).
                type: int
            port_mirroring:
                description:
                    - Enable/disable NP port mirroring.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            pppoe_egress_cos:
                description:
                    - CoS in VLAN tag for outgoing PPPoE/PPP packets.
                type: str
                choices:
                    - 'cos0'
                    - 'cos1'
                    - 'cos2'
                    - 'cos3'
                    - 'cos4'
                    - 'cos5'
                    - 'cos6'
                    - 'cos7'
            pppoe_unnumbered_negotiate:
                description:
                    - Enable/disable PPPoE unnumbered negotiation.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pptp_auth_type:
                description:
                    - PPTP authentication type.
                type: str
                choices:
                    - 'auto'
                    - 'pap'
                    - 'chap'
                    - 'mschapv1'
                    - 'mschapv2'
            pptp_client:
                description:
                    - Enable/disable PPTP client.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pptp_password:
                description:
                    - PPTP password.
                type: str
            pptp_server_ip:
                description:
                    - PPTP server IP address.
                type: str
            pptp_timeout:
                description:
                    - Idle timer in minutes (0 for disabled).
                type: int
            pptp_user:
                description:
                    - PPTP user name.
                type: str
            preserve_session_route:
                description:
                    - Enable/disable preservation of session route when dirty.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            priority:
                description:
                    - Priority of learned routes.
                type: int
            priority_override:
                description:
                    - Enable/disable fail back to higher priority port once recovered.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            proxy_captive_portal:
                description:
                    - Enable/disable proxy captive portal on this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            reachable_time:
                description:
                    - IPv4 reachable time in milliseconds (30000 - 3600000).
                type: int
            redundant_interface:
                description:
                    - Redundant interface.
                type: str
            remote_ip:
                description:
                    - Remote IP address of tunnel.
                type: str
            replacemsg_override_group:
                description:
                    - Replacement message override group.
                type: str
            ring_rx:
                description:
                    - RX ring size.
                type: int
            ring_tx:
                description:
                    - TX ring size.
                type: int
            role:
                description:
                    - Interface role.
                type: str
                choices:
                    - 'lan'
                    - 'wan'
                    - 'dmz'
                    - 'undefined'
            sample_direction:
                description:
                    - Data that NetFlow collects (rx, tx, or both).
                type: str
                choices:
                    - 'tx'
                    - 'rx'
                    - 'both'
            sample_rate:
                description:
                    - sFlow sample rate (10 - 99999).
                type: int
            scan_botnet_connections:
                description:
                    - Enable monitoring or blocking connections to Botnet servers through this interface.
                type: str
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            secondary_IP:
                description:
                    - Enable/disable adding a secondary IP to this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            secondaryip:
                description:
                    - Second IP address of interface.
                type: list
                elements: dict
                suboptions:
                    allowaccess:
                        description:
                            - Management access settings for the secondary IP address.
                        type: list
                        elements: str
                        choices:
                            - 'ping'
                            - 'https'
                            - 'ssh'
                            - 'snmp'
                            - 'http'
                            - 'telnet'
                            - 'fgfm'
                            - 'radius-acct'
                            - 'probe-response'
                            - 'fabric'
                            - 'ftm'
                            - 'speed-test'
                            - 'scim'
                            - 'capwap'
                    detectprotocol:
                        description:
                            - Protocols used to detect the server.
                        type: list
                        elements: str
                        choices:
                            - 'ping'
                            - 'tcp-echo'
                            - 'udp-echo'
                    detectserver:
                        description:
                            - Gateway"s ping server for this IP.
                        type: str
                    gwdetect:
                        description:
                            - Enable/disable detect gateway alive for first.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ha_priority:
                        description:
                            - HA election priority for the PING server.
                        type: int
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ip:
                        description:
                            - Secondary IP address of the interface.
                        type: str
                    ping_serv_status:
                        description:
                            - PING server status.
                        type: int
                    secip_relay_ip:
                        description:
                            - DHCP relay IP address.
                        type: list
                        elements: str
            security_8021x_dynamic_vlan_id:
                description:
                    - VLAN ID for virtual switch.
                type: int
            security_8021x_master:
                description:
                    - 802.1X master virtual-switch.
                type: str
            security_8021x_member_mode:
                description:
                    - 802.1X member mode.
                type: str
                choices:
                    - 'switch'
                    - 'disable'
            security_8021x_mode:
                description:
                    - 802.1X mode.
                type: str
                choices:
                    - 'default'
                    - 'dynamic-vlan'
                    - 'fallback'
                    - 'slave'
            security_exempt_list:
                description:
                    - Name of security-exempt-list.
                type: str
            security_external_logout:
                description:
                    - URL of external authentication logout server.
                type: str
            security_external_web:
                description:
                    - URL of external authentication web server.
                type: str
            security_groups:
                description:
                    - User groups that can authenticate with the captive portal.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Names of user groups that can authenticate with the captive portal. Source user.group.name.
                        required: true
                        type: str
            security_ip_auth_bypass:
                description:
                    - Enable/disable IP authentication bypass.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            security_mac_auth_bypass:
                description:
                    - Enable/disable MAC authentication bypass.
                type: str
                choices:
                    - 'mac-auth-only'
                    - 'enable'
                    - 'disable'
            security_mode:
                description:
                    - Turn on captive portal authentication for this interface.
                type: str
                choices:
                    - 'none'
                    - 'captive-portal'
                    - '802.1X'
            security_redirect_url:
                description:
                    - URL redirection after disclaimer/authentication.
                type: str
            service_name:
                description:
                    - PPPoE service name.
                type: str
            sflow_sampler:
                description:
                    - Enable/disable sFlow on this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            snmp_index:
                description:
                    - Permanent SNMP Index of the interface.
                type: int
            speed:
                description:
                    - Interface speed. The default setting and the options available depend on the interface hardware.
                type: str
                choices:
                    - 'auto'
                    - '10full'
                    - '10half'
                    - '100full'
                    - '100half'
                    - '100auto'
                    - '1000full'
                    - '1000auto'
                    - '10000full'
                    - '10000auto'
                    - '40000full'
                    - '40000auto'
                    - '2500auto'
                    - '5000auto'
                    - '25000full'
                    - '25000auto'
                    - '50000full'
                    - '50000auto'
                    - '100Gfull'
                    - '100Gauto'
                    - '200Gfull'
                    - '200Gauto'
                    - '400Gfull'
                    - '400Gauto'
                    - '1000half'
            spillover_threshold:
                description:
                    - Egress Spillover threshold (0 - 16776000 kbps), 0 means unlimited.
                type: int
            src_check:
                description:
                    - Enable/disable source IP check.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            status:
                description:
                    - Bring the interface up or shut the interface down.
                type: str
                choices:
                    - 'up'
                    - 'down'
            stp:
                description:
                    - Enable/disable STP.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            stp_edge:
                description:
                    - Enable/disable as STP edge port.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            stp_ha_secondary:
                description:
                    - Control STP behavior on HA secondary.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
                    - 'priority-adjust'
            stp_ha_slave:
                description:
                    - Control STP behaviour on HA slave.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
                    - 'priority-adjust'
            stpforward:
                description:
                    - Enable/disable STP forwarding.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            stpforward_mode:
                description:
                    - Configure STP forwarding mode.
                type: str
                choices:
                    - 'rpl-all-ext-id'
                    - 'rpl-bridge-ext-id'
                    - 'rpl-nothing'
            subst:
                description:
                    - Enable to always send packets from this interface to a destination MAC address.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            substitute_dst_mac:
                description:
                    - Destination MAC address that all packets are sent to from this interface.
                type: str
            sw_algorithm:
                description:
                    - Frame distribution algorithm for switch.
                type: str
                choices:
                    - 'l2'
                    - 'l3'
                    - 'eh'
            swc_first_create:
                description:
                    - Initial create for switch-controller VLANs.
                type: int
            swc_vlan:
                description:
                    - Creation status for switch-controller VLANs.
                type: int
            switch:
                description:
                    - Contained in switch.
                type: str
            switch_controller_access_vlan:
                description:
                    - Block FortiSwitch port-to-port traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_controller_arp_inspection:
                description:
                    - Enable/disable/Monitor FortiSwitch ARP inspection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
                    - 'monitor'
            switch_controller_dhcp_snooping:
                description:
                    - Switch controller DHCP snooping.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_controller_dhcp_snooping_option82:
                description:
                    - Switch controller DHCP snooping option82.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_controller_dhcp_snooping_verify_mac:
                description:
                    - Switch controller DHCP snooping verify MAC.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_controller_dynamic:
                description:
                    - Integrated FortiLink settings for managed FortiSwitch. Source switch-controller.fortilink-settings.name.
                type: str
            switch_controller_feature:
                description:
                    - Interface"s purpose when assigning traffic (read only).
                type: str
                choices:
                    - 'none'
                    - 'default-vlan'
                    - 'quarantine'
                    - 'rspan'
                    - 'voice'
                    - 'video'
                    - 'nac'
                    - 'nac-segment'
            switch_controller_igmp_snooping:
                description:
                    - Switch controller IGMP snooping.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_controller_igmp_snooping_fast_leave:
                description:
                    - Switch controller IGMP snooping fast-leave.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_controller_igmp_snooping_proxy:
                description:
                    - Switch controller IGMP snooping proxy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_controller_iot_scanning:
                description:
                    - Enable/disable managed FortiSwitch IoT scanning.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_controller_learning_limit:
                description:
                    - Limit the number of dynamic MAC addresses on this VLAN (1 - 128, 0 = no limit, default).
                type: int
            switch_controller_mgmt_vlan:
                description:
                    - VLAN to use for FortiLink management purposes.
                type: int
            switch_controller_nac:
                description:
                    - Integrated FortiLink settings for managed FortiSwitch. Source switch-controller.fortilink-settings.name.
                type: str
            switch_controller_netflow_collect:
                description:
                    - NetFlow collection and processing.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            switch_controller_offload:
                description:
                    - Enable/disable managed FortiSwitch routing offload.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_controller_offload_gw:
                description:
                    - Enable/disable managed FortiSwitch routing offload gateway.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_controller_offload_ip:
                description:
                    - IP for routing offload on FortiSwitch.
                type: str
            switch_controller_rspan_mode:
                description:
                    - Stop Layer2 MAC learning and interception of BPDUs and other packets on this interface.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            switch_controller_source_ip:
                description:
                    - Source IP address used in FortiLink over L3 connections.
                type: str
                choices:
                    - 'outbound'
                    - 'fixed'
            switch_controller_traffic_policy:
                description:
                    - Switch controller traffic policy for the VLAN. Source switch-controller.traffic-policy.name.
                type: str
            system_id:
                description:
                    - Define a system ID for the aggregate interface.
                type: str
            system_id_type:
                description:
                    - Method in which system ID is generated.
                type: str
                choices:
                    - 'auto'
                    - 'user'
            tagging:
                description:
                    - Config object tagging.
                type: list
                elements: dict
                suboptions:
                    category:
                        description:
                            - Tag category. Source system.object-tagging.category.
                        type: str
                    name:
                        description:
                            - Tagging entry name.
                        required: true
                        type: str
                    tags:
                        description:
                            - Tags.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Tag name. Source system.object-tagging.tags.name.
                                required: true
                                type: str
            tcp_mss:
                description:
                    - TCP maximum segment size. 0 means do not change segment size.
                type: int
            telemetry_discover:
                description:
                    - Enable/disable automatic registration of unknown FortiTelemetry agents.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            trunk:
                description:
                    - Enable/disable VLAN trunk.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            trust_ip_1:
                description:
                    - Trusted host for dedicated management traffic (0.0.0.0/24 for all hosts).
                type: str
            trust_ip_2:
                description:
                    - Trusted host for dedicated management traffic (0.0.0.0/24 for all hosts).
                type: str
            trust_ip_3:
                description:
                    - Trusted host for dedicated management traffic (0.0.0.0/24 for all hosts).
                type: str
            trust_ip6_1:
                description:
                    - 'Trusted IPv6 host for dedicated management traffic (::/0 for all hosts).'
                type: str
            trust_ip6_2:
                description:
                    - 'Trusted IPv6 host for dedicated management traffic (::/0 for all hosts).'
                type: str
            trust_ip6_3:
                description:
                    - 'Trusted IPv6 host for dedicated management traffic (::/0 for all hosts).'
                type: str
            type:
                description:
                    - Interface type.
                type: str
                choices:
                    - 'physical'
                    - 'vlan'
                    - 'aggregate'
                    - 'redundant'
                    - 'tunnel'
                    - 'vdom-link'
                    - 'loopback'
                    - 'switch'
                    - 'vap-switch'
                    - 'wl-mesh'
                    - 'fext-wan'
                    - 'vxlan'
                    - 'geneve'
                    - 'switch-vlan'
                    - 'emac-vlan'
                    - 'lan-extension'
                    - 'hdlc'
                    - 'ssl'
                    - 'hard-switch'
            username:
                description:
                    - Username of the PPPoE account, provided by your ISP.
                type: str
            vdom:
                description:
                    - Interface is in this virtual domain (VDOM). Source system.vdom.name.
                type: str
            vindex:
                description:
                    - Switch control interface VLAN ID.
                type: int
            virtual_mac:
                description:
                    - Change the interface"s virtual MAC address.
                type: str
            vlan_protocol:
                description:
                    - Ethernet protocol of VLAN.
                type: str
                choices:
                    - '8021q'
                    - '8021ad'
            vlanforward:
                description:
                    - Enable/disable traffic forwarding between VLANs on this interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vlanid:
                description:
                    - VLAN ID (1 - 4094).
                type: int
            vrf:
                description:
                    - Virtual Routing Forwarding ID.
                type: int
            vrrp:
                description:
                    - VRRP configuration.
                type: list
                elements: dict
                suboptions:
                    accept_mode:
                        description:
                            - Enable/disable accept mode.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    adv_interval:
                        description:
                            - Advertisement interval (250 - 255000 milliseconds).
                        type: int
                    ignore_default_route:
                        description:
                            - Enable/disable ignoring of default route when checking destination.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    preempt:
                        description:
                            - Enable/disable preempt mode.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    priority:
                        description:
                            - Priority of the virtual router (1 - 255).
                        type: int
                    proxy_arp:
                        description:
                            - VRRP Proxy ARP configuration.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            ip:
                                description:
                                    - Set IP addresses of proxy ARP.
                                type: str
                    start_time:
                        description:
                            - Startup time (1 - 255 seconds).
                        type: int
                    status:
                        description:
                            - Enable/disable this VRRP configuration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    version:
                        description:
                            - VRRP version.
                        type: str
                        choices:
                            - '2'
                            - '3'
                    vrdst:
                        description:
                            - Monitor the route to this destination.
                        type: list
                        elements: str
                    vrdst_priority:
                        description:
                            - Priority of the virtual router when the virtual router destination becomes unreachable (0 - 254).
                        type: int
                    vrgrp:
                        description:
                            - VRRP group ID (1 - 65535).
                        type: int
                    vrid:
                        description:
                            - Virtual router identifier (1 - 255). see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    vrip:
                        description:
                            - IP address of the virtual router.
                        type: str
            vrrp_virtual_mac:
                description:
                    - Enable/disable use of virtual MAC for VRRP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wccp:
                description:
                    - Enable/disable WCCP on this interface. Used for encapsulated WCCP communication between WCCP clients and servers.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            weight:
                description:
                    - Default weight for static routes (if route has no weight configured).
                type: int
            wins_ip:
                description:
                    - WINS server IP.
                type: str
"""

EXAMPLES = """
- name: Configure interfaces.
  fortinet.fortios.fortios_system_interface:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_interface:
          ac_name: "<your_own_value>"
          aggregate: "<your_own_value>"
          aggregate_type: "physical"
          algorithm: "L2"
          alias: "<your_own_value>"
          allowaccess: "ping"
          ap_discover: "enable"
          arpforward: "enable"
          auth_cert: "<your_own_value> (source vpn.certificate.local.name)"
          auth_portal_addr: "<your_own_value>"
          auth_type: "auto"
          auto_auth_extension_device: "enable"
          bandwidth_measure_time: "0"
          bfd: "global"
          bfd_desired_min_tx: "250"
          bfd_detect_mult: "3"
          bfd_required_min_rx: "250"
          broadcast_forticlient_discovery: "enable"
          broadcast_forward: "enable"
          captive_portal: "2147483647"
          cli_conn_status: "0"
          client_options:
              -
                  code: "0"
                  id: "26"
                  ip: "<your_own_value>"
                  type: "hex"
                  value: "<your_own_value>"
          color: "0"
          dedicated_to: "none"
          default_purdue_level: "1"
          defaultgw: "enable"
          description: "<your_own_value>"
          detected_peer_mtu: "0"
          detectprotocol: "ping"
          detectserver: "<your_own_value>"
          device_access_list: "<your_own_value>"
          device_identification: "enable"
          device_identification_active_scan: "enable"
          device_netscan: "disable"
          device_user_identification: "enable"
          devindex: "0"
          dhcp_broadcast_flag: "disable"
          dhcp_classless_route_addition: "enable"
          dhcp_client_identifier: "myId_46"
          dhcp_relay_agent_option: "enable"
          dhcp_relay_allow_no_end_option: "disable"
          dhcp_relay_circuit_id: "<your_own_value>"
          dhcp_relay_interface: "<your_own_value> (source system.interface.name)"
          dhcp_relay_interface_select_method: "auto"
          dhcp_relay_ip: "<your_own_value>"
          dhcp_relay_link_selection: "<your_own_value>"
          dhcp_relay_request_all_server: "disable"
          dhcp_relay_service: "disable"
          dhcp_relay_source_ip: "<your_own_value>"
          dhcp_relay_type: "regular"
          dhcp_relay_vrf_select: "-1"
          dhcp_renew_time: "0"
          dhcp_smart_relay: "disable"
          dhcp_snooping_server_list:
              -
                  name: "default_name_62"
                  server_ip: "<your_own_value>"
          disc_retry_timeout: "1"
          disconnect_threshold: "0"
          distance: "5"
          dns_server_override: "enable"
          dns_server_protocol: "cleartext"
          drop_fragment: "enable"
          drop_overlapped_fragment: "enable"
          eap_ca_cert: "<your_own_value> (source certificate.ca.name)"
          eap_identity: "<your_own_value>"
          eap_method: "tls"
          eap_password: "<your_own_value>"
          eap_supplicant: "enable"
          eap_user_cert: "<your_own_value> (source certificate.local.name)"
          egress_cos: "disable"
          egress_queues:
              cos0: "<your_own_value> (source system.isf-queue-profile.name)"
              cos1: "<your_own_value> (source system.isf-queue-profile.name)"
              cos2: "<your_own_value> (source system.isf-queue-profile.name)"
              cos3: "<your_own_value> (source system.isf-queue-profile.name)"
              cos4: "<your_own_value> (source system.isf-queue-profile.name)"
              cos5: "<your_own_value> (source system.isf-queue-profile.name)"
              cos6: "<your_own_value> (source system.isf-queue-profile.name)"
              cos7: "<your_own_value> (source system.isf-queue-profile.name)"
          egress_shaping_profile: "<your_own_value> (source firewall.shaping-profile.profile-name)"
          endpoint_compliance: "enable"
          estimated_downstream_bandwidth: "0"
          estimated_upstream_bandwidth: "0"
          exclude_signatures: "iot"
          explicit_ftp_proxy: "enable"
          explicit_web_proxy: "enable"
          external: "enable"
          fail_action_on_extender: "soft-restart"
          fail_alert_interfaces:
              -
                  name: "default_name_97 (source system.interface.name)"
          fail_alert_method: "link-failed-signal"
          fail_detect: "enable"
          fail_detect_option: "detectserver"
          fortiheartbeat: "enable"
          fortilink: "enable"
          fortilink_backup_link: "0"
          fortilink_neighbor_detect: "lldp"
          fortilink_split_interface: "enable"
          fortilink_stacking: "enable"
          forward_domain: "0"
          forward_error_correction: "none"
          gi_gk: "enable"
          gwdetect: "enable"
          ha_priority: "1"
          icmp_accept_redirect: "enable"
          icmp_send_redirect: "enable"
          ident_accept: "enable"
          idle_timeout: "0"
          ike_saml_server: "<your_own_value> (source user.saml.name)"
          inbandwidth: "0"
          ingress_cos: "disable"
          ingress_shaping_profile: "<your_own_value> (source firewall.shaping-profile.profile-name)"
          ingress_spillover_threshold: "0"
          interconnect_profile: "default"
          interface: "<your_own_value> (source system.interface.name)"
          internal: "0"
          ip: "<your_own_value>"
          ip_managed_by_fortiipam: "inherit-global"
          ipmac: "enable"
          ips_sniffer_mode: "enable"
          ipunnumbered: "<your_own_value>"
          ipv6:
              autoconf: "enable"
              cli_conn6_status: "0"
              client_options:
                  -
                      code: "0"
                      id: "134"
                      ip6: "<your_own_value>"
                      type: "hex"
                      value: "<your_own_value>"
              dhcp6_client_options: "rapid"
              dhcp6_iapd_list:
                  -
                      iaid: "<you_own_value>"
                      prefix_hint: "<your_own_value>"
                      prefix_hint_plt: "604800"
                      prefix_hint_vlt: "2592000"
              dhcp6_information_request: "enable"
              dhcp6_prefix_delegation: "enable"
              dhcp6_prefix_hint: "<your_own_value>"
              dhcp6_prefix_hint_plt: "604800"
              dhcp6_prefix_hint_vlt: "2592000"
              dhcp6_relay_interface_id: "<your_own_value>"
              dhcp6_relay_ip: "<your_own_value>"
              dhcp6_relay_service: "disable"
              dhcp6_relay_source_interface: "disable"
              dhcp6_relay_source_ip: "<your_own_value>"
              dhcp6_relay_type: "regular"
              icmp6_send_redirect: "enable"
              interface_identifier: "myId_156"
              ip6_address: "<your_own_value>"
              ip6_adv_rio: "enable"
              ip6_allowaccess: "ping"
              ip6_default_life: "1800"
              ip6_delegated_prefix_iaid: "0"
              ip6_delegated_prefix_list:
                  -
                      autonomous_flag: "enable"
                      delegated_prefix_iaid: "0"
                      onlink_flag: "enable"
                      prefix_id: "<you_own_value>"
                      rdnss: "<your_own_value>"
                      rdnss_service: "delegated"
                      subnet: "<your_own_value>"
                      upstream_interface: "<your_own_value> (source system.interface.name)"
              ip6_dns_server_override: "enable"
              ip6_dnssl_list:
                  -
                      dnssl_life_time: "1800"
                      domain: "<your_own_value>"
              ip6_extra_addr:
                  -
                      prefix: "<your_own_value>"
              ip6_hop_limit: "0"
              ip6_link_mtu: "0"
              ip6_manage_flag: "enable"
              ip6_max_interval: "600"
              ip6_min_interval: "198"
              ip6_mode: "static"
              ip6_other_flag: "enable"
              ip6_prefix_list:
                  -
                      autonomous_flag: "enable"
                      dnssl:
                          -
                              domain: "<your_own_value>"
                      onlink_flag: "enable"
                      preferred_life_time: "604800"
                      prefix: "<your_own_value>"
                      rdnss: "<your_own_value>"
                      valid_life_time: "2592000"
              ip6_prefix_mode: "dhcp6"
              ip6_rdnss_list:
                  -
                      rdnss: "<your_own_value>"
                      rdnss_life_time: "1800"
              ip6_reachable_time: "0"
              ip6_retrans_time: "0"
              ip6_route_list:
                  -
                      route: "<your_own_value>"
                      route_life_time: "1800"
                      route_pref: "medium"
              ip6_route_pref: "medium"
              ip6_send_adv: "enable"
              ip6_subnet: "<your_own_value>"
              ip6_upstream_interface: "<your_own_value> (source system.interface.name)"
              nd_cert: "<your_own_value> (source certificate.local.name)"
              nd_cga_modifier: "<your_own_value>"
              nd_mode: "basic"
              nd_security_level: "0"
              nd_timestamp_delta: "300"
              nd_timestamp_fuzz: "1"
              ra_send_mtu: "enable"
              unique_autoconf_addr: "enable"
              vrip6_link_local: "<your_own_value>"
              vrrp_virtual_mac6: "enable"
              vrrp6:
                  -
                      accept_mode: "enable"
                      adv_interval: "1000"
                      ignore_default_route: "enable"
                      preempt: "enable"
                      priority: "100"
                      start_time: "3"
                      status: "enable"
                      vrdst_priority: "0"
                      vrdst6: "<your_own_value>"
                      vrgrp: "0"
                      vrid: "<you_own_value>"
                      vrip6: "<your_own_value>"
          l2forward: "enable"
          lacp_ha_secondary: "enable"
          lacp_ha_slave: "enable"
          lacp_mode: "static"
          lacp_speed: "slow"
          lcp_echo_interval: "5"
          lcp_max_echo_fails: "3"
          link_up_delay: "50"
          lldp_network_policy: "<your_own_value> (source system.lldp.network-policy.name)"
          lldp_reception: "enable"
          lldp_transmission: "enable"
          macaddr: "<your_own_value>"
          managed_device:
              -
                  name: "default_name_243"
          managed_subnetwork_size: "4"
          management_ip: "<your_own_value>"
          measured_downstream_bandwidth: "0"
          measured_upstream_bandwidth: "0"
          mediatype: "none"
          member:
              -
                  interface_name: "<your_own_value> (source system.interface.name)"
          min_links: "1"
          min_links_down: "operational"
          mirroring_direction: "rx"
          mirroring_filter:
              filter_dport: "0"
              filter_dstip: "<your_own_value>"
              filter_protocol: "0"
              filter_sport: "0"
              filter_srcip: "<your_own_value>"
          mirroring_port: "<your_own_value> (source system.interface.name)"
          mode: "static"
          monitor_bandwidth: "enable"
          mtu: "1500"
          mtu_override: "enable"
          name: "default_name_265"
          ndiscforward: "enable"
          netbios_forward: "disable"
          netflow_sample_rate: "1"
          netflow_sampler: "disable"
          netflow_sampler_id: "0"
          np_qos_profile: "0"
          outbandwidth: "0"
          padt_retry_timeout: "1"
          password: "<your_own_value>"
          ping_serv_status: "0"
          polling_interval: "20"
          port_mirroring: "disable"
          pppoe_egress_cos: "cos0"
          pppoe_unnumbered_negotiate: "enable"
          pptp_auth_type: "auto"
          pptp_client: "enable"
          pptp_password: "<your_own_value>"
          pptp_server_ip: "<your_own_value>"
          pptp_timeout: "0"
          pptp_user: "<your_own_value>"
          preserve_session_route: "enable"
          priority: "1"
          priority_override: "enable"
          proxy_captive_portal: "enable"
          reachable_time: "30000"
          redundant_interface: "<your_own_value>"
          remote_ip: "<your_own_value>"
          replacemsg_override_group: "<your_own_value>"
          ring_rx: "0"
          ring_tx: "0"
          role: "lan"
          sample_direction: "tx"
          sample_rate: "2000"
          scan_botnet_connections: "disable"
          secondary_IP: "enable"
          secondaryip:
              -
                  allowaccess: "ping"
                  detectprotocol: "ping"
                  detectserver: "<your_own_value>"
                  gwdetect: "enable"
                  ha_priority: "1"
                  id: "307"
                  ip: "<your_own_value>"
                  ping_serv_status: "0"
                  secip_relay_ip: "<your_own_value>"
          security_8021x_dynamic_vlan_id: "0"
          security_8021x_master: "<your_own_value>"
          security_8021x_member_mode: "switch"
          security_8021x_mode: "default"
          security_exempt_list: "<your_own_value>"
          security_external_logout: "<your_own_value>"
          security_external_web: "<your_own_value>"
          security_groups:
              -
                  name: "default_name_319 (source user.group.name)"
          security_ip_auth_bypass: "enable"
          security_mac_auth_bypass: "mac-auth-only"
          security_mode: "none"
          security_redirect_url: "<your_own_value>"
          service_name: "<your_own_value>"
          sflow_sampler: "enable"
          snmp_index: "0"
          speed: "auto"
          spillover_threshold: "0"
          src_check: "enable"
          status: "up"
          stp: "disable"
          stp_edge: "disable"
          stp_ha_secondary: "disable"
          stp_ha_slave: "disable"
          stpforward: "enable"
          stpforward_mode: "rpl-all-ext-id"
          subst: "enable"
          substitute_dst_mac: "<your_own_value>"
          sw_algorithm: "l2"
          swc_first_create: "0"
          swc_vlan: "0"
          switch: "<your_own_value>"
          switch_controller_access_vlan: "enable"
          switch_controller_arp_inspection: "enable"
          switch_controller_dhcp_snooping: "enable"
          switch_controller_dhcp_snooping_option82: "enable"
          switch_controller_dhcp_snooping_verify_mac: "enable"
          switch_controller_dynamic: "<your_own_value> (source switch-controller.fortilink-settings.name)"
          switch_controller_feature: "none"
          switch_controller_igmp_snooping: "enable"
          switch_controller_igmp_snooping_fast_leave: "enable"
          switch_controller_igmp_snooping_proxy: "enable"
          switch_controller_iot_scanning: "enable"
          switch_controller_learning_limit: "0"
          switch_controller_mgmt_vlan: "4094"
          switch_controller_nac: "<your_own_value> (source switch-controller.fortilink-settings.name)"
          switch_controller_netflow_collect: "disable"
          switch_controller_offload: "enable"
          switch_controller_offload_gw: "enable"
          switch_controller_offload_ip: "<your_own_value>"
          switch_controller_rspan_mode: "disable"
          switch_controller_source_ip: "outbound"
          switch_controller_traffic_policy: "<your_own_value> (source switch-controller.traffic-policy.name)"
          system_id: "<your_own_value>"
          system_id_type: "auto"
          tagging:
              -
                  category: "<your_own_value> (source system.object-tagging.category)"
                  name: "default_name_368"
                  tags:
                      -
                          name: "default_name_370 (source system.object-tagging.tags.name)"
          tcp_mss: "0"
          telemetry_discover: "enable"
          trunk: "enable"
          trust_ip_1: "<your_own_value>"
          trust_ip_2: "<your_own_value>"
          trust_ip_3: "<your_own_value>"
          trust_ip6_1: "<your_own_value>"
          trust_ip6_2: "<your_own_value>"
          trust_ip6_3: "<your_own_value>"
          type: "physical"
          username: "<your_own_value>"
          vdom: "<your_own_value> (source system.vdom.name)"
          vindex: "0"
          virtual_mac: "<your_own_value>"
          vlan_protocol: "8021q"
          vlanforward: "enable"
          vlanid: "0"
          vrf: "0"
          vrrp:
              -
                  accept_mode: "enable"
                  adv_interval: "1000"
                  ignore_default_route: "enable"
                  preempt: "enable"
                  priority: "100"
                  proxy_arp:
                      -
                          id: "396"
                          ip: "<your_own_value>"
                  start_time: "3"
                  status: "enable"
                  version: "2"
                  vrdst: "<your_own_value>"
                  vrdst_priority: "0"
                  vrgrp: "0"
                  vrid: "<you_own_value>"
                  vrip: "<your_own_value>"
          vrrp_virtual_mac: "enable"
          wccp: "enable"
          weight: "0"
          wins_ip: "<your_own_value>"
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


def filter_system_interface_data(json):
    option_list = [
        "ac_name",
        "aggregate",
        "aggregate_type",
        "algorithm",
        "alias",
        "allowaccess",
        "ap_discover",
        "arpforward",
        "auth_cert",
        "auth_portal_addr",
        "auth_type",
        "auto_auth_extension_device",
        "bandwidth_measure_time",
        "bfd",
        "bfd_desired_min_tx",
        "bfd_detect_mult",
        "bfd_required_min_rx",
        "broadcast_forticlient_discovery",
        "broadcast_forward",
        "captive_portal",
        "cli_conn_status",
        "client_options",
        "color",
        "dedicated_to",
        "default_purdue_level",
        "defaultgw",
        "description",
        "detected_peer_mtu",
        "detectprotocol",
        "detectserver",
        "device_access_list",
        "device_identification",
        "device_identification_active_scan",
        "device_netscan",
        "device_user_identification",
        "devindex",
        "dhcp_broadcast_flag",
        "dhcp_classless_route_addition",
        "dhcp_client_identifier",
        "dhcp_relay_agent_option",
        "dhcp_relay_allow_no_end_option",
        "dhcp_relay_circuit_id",
        "dhcp_relay_interface",
        "dhcp_relay_interface_select_method",
        "dhcp_relay_ip",
        "dhcp_relay_link_selection",
        "dhcp_relay_request_all_server",
        "dhcp_relay_service",
        "dhcp_relay_source_ip",
        "dhcp_relay_type",
        "dhcp_relay_vrf_select",
        "dhcp_renew_time",
        "dhcp_smart_relay",
        "dhcp_snooping_server_list",
        "disc_retry_timeout",
        "disconnect_threshold",
        "distance",
        "dns_server_override",
        "dns_server_protocol",
        "drop_fragment",
        "drop_overlapped_fragment",
        "eap_ca_cert",
        "eap_identity",
        "eap_method",
        "eap_password",
        "eap_supplicant",
        "eap_user_cert",
        "egress_cos",
        "egress_queues",
        "egress_shaping_profile",
        "endpoint_compliance",
        "estimated_downstream_bandwidth",
        "estimated_upstream_bandwidth",
        "exclude_signatures",
        "explicit_ftp_proxy",
        "explicit_web_proxy",
        "external",
        "fail_action_on_extender",
        "fail_alert_interfaces",
        "fail_alert_method",
        "fail_detect",
        "fail_detect_option",
        "fortiheartbeat",
        "fortilink",
        "fortilink_backup_link",
        "fortilink_neighbor_detect",
        "fortilink_split_interface",
        "fortilink_stacking",
        "forward_domain",
        "forward_error_correction",
        "gi_gk",
        "gwdetect",
        "ha_priority",
        "icmp_accept_redirect",
        "icmp_send_redirect",
        "ident_accept",
        "idle_timeout",
        "ike_saml_server",
        "inbandwidth",
        "ingress_cos",
        "ingress_shaping_profile",
        "ingress_spillover_threshold",
        "interconnect_profile",
        "interface",
        "internal",
        "ip",
        "ip_managed_by_fortiipam",
        "ipmac",
        "ips_sniffer_mode",
        "ipunnumbered",
        "ipv6",
        "l2forward",
        "lacp_ha_secondary",
        "lacp_ha_slave",
        "lacp_mode",
        "lacp_speed",
        "lcp_echo_interval",
        "lcp_max_echo_fails",
        "link_up_delay",
        "lldp_network_policy",
        "lldp_reception",
        "lldp_transmission",
        "macaddr",
        "managed_device",
        "managed_subnetwork_size",
        "management_ip",
        "measured_downstream_bandwidth",
        "measured_upstream_bandwidth",
        "mediatype",
        "member",
        "min_links",
        "min_links_down",
        "mirroring_direction",
        "mirroring_filter",
        "mirroring_port",
        "mode",
        "monitor_bandwidth",
        "mtu",
        "mtu_override",
        "name",
        "ndiscforward",
        "netbios_forward",
        "netflow_sample_rate",
        "netflow_sampler",
        "netflow_sampler_id",
        "np_qos_profile",
        "outbandwidth",
        "padt_retry_timeout",
        "password",
        "ping_serv_status",
        "polling_interval",
        "port_mirroring",
        "pppoe_egress_cos",
        "pppoe_unnumbered_negotiate",
        "pptp_auth_type",
        "pptp_client",
        "pptp_password",
        "pptp_server_ip",
        "pptp_timeout",
        "pptp_user",
        "preserve_session_route",
        "priority",
        "priority_override",
        "proxy_captive_portal",
        "reachable_time",
        "redundant_interface",
        "remote_ip",
        "replacemsg_override_group",
        "ring_rx",
        "ring_tx",
        "role",
        "sample_direction",
        "sample_rate",
        "scan_botnet_connections",
        "secondary_IP",
        "secondaryip",
        "security_8021x_dynamic_vlan_id",
        "security_8021x_master",
        "security_8021x_member_mode",
        "security_8021x_mode",
        "security_exempt_list",
        "security_external_logout",
        "security_external_web",
        "security_groups",
        "security_ip_auth_bypass",
        "security_mac_auth_bypass",
        "security_mode",
        "security_redirect_url",
        "service_name",
        "sflow_sampler",
        "snmp_index",
        "speed",
        "spillover_threshold",
        "src_check",
        "status",
        "stp",
        "stp_edge",
        "stp_ha_secondary",
        "stp_ha_slave",
        "stpforward",
        "stpforward_mode",
        "subst",
        "substitute_dst_mac",
        "sw_algorithm",
        "swc_first_create",
        "swc_vlan",
        "switch",
        "switch_controller_access_vlan",
        "switch_controller_arp_inspection",
        "switch_controller_dhcp_snooping",
        "switch_controller_dhcp_snooping_option82",
        "switch_controller_dhcp_snooping_verify_mac",
        "switch_controller_dynamic",
        "switch_controller_feature",
        "switch_controller_igmp_snooping",
        "switch_controller_igmp_snooping_fast_leave",
        "switch_controller_igmp_snooping_proxy",
        "switch_controller_iot_scanning",
        "switch_controller_learning_limit",
        "switch_controller_mgmt_vlan",
        "switch_controller_nac",
        "switch_controller_netflow_collect",
        "switch_controller_offload",
        "switch_controller_offload_gw",
        "switch_controller_offload_ip",
        "switch_controller_rspan_mode",
        "switch_controller_source_ip",
        "switch_controller_traffic_policy",
        "system_id",
        "system_id_type",
        "tagging",
        "tcp_mss",
        "telemetry_discover",
        "trunk",
        "trust_ip_1",
        "trust_ip_2",
        "trust_ip_3",
        "trust_ip6_1",
        "trust_ip6_2",
        "trust_ip6_3",
        "type",
        "username",
        "vdom",
        "vindex",
        "virtual_mac",
        "vlan_protocol",
        "vlanforward",
        "vlanid",
        "vrf",
        "vrrp",
        "vrrp_virtual_mac",
        "wccp",
        "weight",
        "wins_ip",
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
        ["client_options", "ip"],
        ["dhcp_relay_ip"],
        ["allowaccess"],
        ["detectprotocol"],
        ["fail_detect_option"],
        ["dns_server_protocol"],
        ["exclude_signatures"],
        ["vrrp", "vrdst"],
        ["secondaryip", "secip_relay_ip"],
        ["secondaryip", "allowaccess"],
        ["secondaryip", "detectprotocol"],
        ["ipv6", "client_options", "ip6"],
        ["ipv6", "ip6_allowaccess"],
        ["ipv6", "ip6_prefix_list", "rdnss"],
        ["ipv6", "ip6_delegated_prefix_list", "rdnss"],
        ["ipv6", "dhcp6_relay_ip"],
        ["ipv6", "vrrp6", "vrdst6"],
        ["ipv6", "dhcp6_client_options"],
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


def system_interface(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_interface_data = data["system_interface"]

    filtered_data = filter_system_interface_data(system_interface_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "interface", filtered_data, vdom=vdom)
        current_data = fos.get("system", "interface", vdom=vdom, mkey=mkey)
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
    data_copy["system_interface"] = filtered_data
    fos.do_member_operation(
        "system",
        "interface",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "interface", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("system", "interface", mkey=converted_data["name"], vdom=vdom)
    else:
        fos._module.fail_json(msg="state must be present or absent!")


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

    if data["system_interface"]:
        resp = system_interface(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_interface"))
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
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "vdom": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "vrf": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "fortilink": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "switch_controller_source_ip": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "outbound"}, {"value": "fixed"}],
        },
        "mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "static"}, {"value": "dhcp"}, {"value": "pppoe"}],
        },
        "client_options": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "code": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "type": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "hex"},
                        {"value": "string"},
                        {"value": "ip"},
                        {"value": "fqdn"},
                    ],
                },
                "value": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "ip": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
            },
            "v_range": [["v6.4.0", ""]],
        },
        "distance": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dhcp_relay_interface_select_method": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "dhcp_relay_interface": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "dhcp_relay_vrf_select": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "dhcp_broadcast_flag": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "dhcp_relay_service": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "dhcp_relay_ip": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "dhcp_relay_source_ip": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "dhcp_relay_circuit_id": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "dhcp_relay_link_selection": {"v_range": [["v7.0.4", ""]], "type": "string"},
        "dhcp_relay_request_all_server": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "dhcp_relay_allow_no_end_option": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "dhcp_relay_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "regular"}, {"value": "ipsec"}],
        },
        "dhcp_smart_relay": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "dhcp_relay_agent_option": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dhcp_classless_route_addition": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "management_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "allowaccess": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "ping"},
                {"value": "https"},
                {"value": "ssh"},
                {"value": "snmp"},
                {"value": "http"},
                {"value": "telnet"},
                {"value": "fgfm"},
                {"value": "radius-acct"},
                {"value": "probe-response"},
                {"value": "fabric", "v_range": [["v6.2.0", ""]]},
                {"value": "ftm"},
                {"value": "speed-test", "v_range": [["v7.0.1", ""]]},
                {"value": "scim", "v_range": [["v7.6.0", ""]]},
                {"value": "capwap", "v_range": [["v6.0.0", "v6.0.11"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "gwdetect": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "detectserver": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "detectprotocol": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "ping"},
                {"value": "tcp-echo"},
                {"value": "udp-echo"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ha_priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "fail_detect": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fail_detect_option": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [{"value": "detectserver"}, {"value": "link-down"}],
            "multiple_values": True,
            "elements": "str",
        },
        "fail_alert_method": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "link-failed-signal"}, {"value": "link-down"}],
        },
        "fail_action_on_extender": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "soft-restart"},
                {"value": "hard-restart"},
                {"value": "reboot"},
            ],
        },
        "fail_alert_interfaces": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "dhcp_client_identifier": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dhcp_renew_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ipunnumbered": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "username": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "pppoe_egress_cos": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [
                {"value": "cos0"},
                {"value": "cos1"},
                {"value": "cos2"},
                {"value": "cos3"},
                {"value": "cos4"},
                {"value": "cos5"},
                {"value": "cos6"},
                {"value": "cos7"},
            ],
        },
        "pppoe_unnumbered_negotiate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "idle_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "disc_retry_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "padt_retry_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "service_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ac_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "lcp_echo_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "lcp_max_echo_fails": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "defaultgw": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dns_server_override": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dns_server_protocol": {
            "v_range": [["v7.0.4", ""]],
            "type": "list",
            "options": [{"value": "cleartext"}, {"value": "dot"}, {"value": "doh"}],
            "multiple_values": True,
            "elements": "str",
        },
        "auth_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "auto"},
                {"value": "pap"},
                {"value": "chap"},
                {"value": "mschapv1"},
                {"value": "mschapv2"},
            ],
        },
        "pptp_client": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pptp_user": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "pptp_password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "pptp_server_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "pptp_auth_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "auto"},
                {"value": "pap"},
                {"value": "chap"},
                {"value": "mschapv1"},
                {"value": "mschapv2"},
            ],
        },
        "pptp_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "arpforward": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ndiscforward": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "broadcast_forward": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "bfd": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "global"}, {"value": "enable"}, {"value": "disable"}],
        },
        "bfd_desired_min_tx": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "bfd_detect_mult": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "bfd_required_min_rx": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "l2forward": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "icmp_send_redirect": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "icmp_accept_redirect": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "reachable_time": {"v_range": [["v7.0.4", ""]], "type": "integer"},
        "vlanforward": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "stpforward": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "stpforward_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "rpl-all-ext-id"},
                {"value": "rpl-bridge-ext-id"},
                {"value": "rpl-nothing"},
            ],
        },
        "ips_sniffer_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ident_accept": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipmac": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "subst": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "macaddr": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "virtual_mac": {"v_range": [["v7.6.0", ""]], "type": "string"},
        "substitute_dst_mac": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "speed": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "auto"},
                {"value": "10full"},
                {"value": "10half"},
                {"value": "100full"},
                {"value": "100half"},
                {"value": "100auto", "v_range": [["v7.4.2", "v7.4.2"], ["v7.6.4", ""]]},
                {"value": "1000full"},
                {"value": "1000auto"},
                {"value": "10000full"},
                {"value": "10000auto"},
                {"value": "40000full"},
                {"value": "40000auto", "v_range": [["v7.4.0", ""]]},
                {"value": "2500auto", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "5000auto", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "25000full", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "25000auto", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "50000full", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "50000auto", "v_range": [["v7.4.2", "v7.4.2"]]},
                {
                    "value": "100Gfull",
                    "v_range": [
                        ["v6.0.0", "v6.2.7"],
                        ["v6.4.1", "v7.0.12"],
                        ["v7.2.1", "v7.2.4"],
                        ["v7.4.2", "v7.4.2"],
                    ],
                },
                {"value": "100Gauto", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "200Gfull", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "200Gauto", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "400Gfull", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "400Gauto", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "1000half", "v_range": [["v6.0.0", "v7.0.3"]]},
            ],
        },
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "up"}, {"value": "down"}],
        },
        "netbios_forward": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "wins_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "physical"},
                {"value": "vlan"},
                {"value": "aggregate"},
                {"value": "redundant"},
                {"value": "tunnel"},
                {"value": "vdom-link"},
                {"value": "loopback"},
                {"value": "switch"},
                {"value": "vap-switch"},
                {"value": "wl-mesh"},
                {"value": "fext-wan"},
                {"value": "vxlan"},
                {"value": "geneve", "v_range": [["v6.2.0", ""]]},
                {"value": "switch-vlan"},
                {"value": "emac-vlan"},
                {"value": "lan-extension", "v_range": [["v7.0.2", ""]]},
                {"value": "hdlc", "v_range": [["v6.0.0", "v7.6.3"]]},
                {"value": "ssl", "v_range": [["v7.0.0", "v7.6.3"]]},
                {
                    "value": "hard-switch",
                    "v_range": [
                        ["v6.0.0", "v6.2.7"],
                        ["v6.4.1", "v7.0.12"],
                        ["v7.2.1", "v7.2.4"],
                        ["v7.4.2", "v7.4.2"],
                    ],
                },
            ],
        },
        "dedicated_to": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "management"}],
        },
        "trust_ip_1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trust_ip_2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trust_ip_3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trust_ip6_1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trust_ip6_2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trust_ip6_3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "wccp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "netflow_sampler": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "tx"},
                {"value": "rx"},
                {"value": "both"},
            ],
        },
        "netflow_sample_rate": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "netflow_sampler_id": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "sflow_sampler": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "drop_fragment": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "src_check": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sample_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "polling_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "sample_direction": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "tx"}, {"value": "rx"}, {"value": "both"}],
        },
        "explicit_web_proxy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "explicit_ftp_proxy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "proxy_captive_portal": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tcp_mss": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "inbandwidth": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "outbandwidth": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "egress_shaping_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ingress_shaping_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "spillover_threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ingress_spillover_threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "weight": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "external": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mtu_override": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mtu": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "vlan_protocol": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "8021q"}, {"value": "8021ad"}],
        },
        "vlanid": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "gi_gk": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forward_domain": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "remote_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "member": {
            "type": "list",
            "elements": "dict",
            "children": {
                "interface_name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "lacp_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "static"}, {"value": "passive"}, {"value": "active"}],
        },
        "lacp_ha_secondary": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "system_id_type": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "user"}],
        },
        "system_id": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "lacp_speed": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "slow"}, {"value": "fast"}],
        },
        "min_links": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "min_links_down": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "operational"}, {"value": "administrative"}],
        },
        "algorithm": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "L2"},
                {"value": "L3"},
                {"value": "L4"},
                {"value": "NPU-GRE", "v_range": [["v7.6.4", ""]]},
                {"value": "Source-MAC", "v_range": [["v7.2.1", ""]]},
            ],
        },
        "link_up_delay": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "aggregate_type": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "physical"}, {"value": "vxlan"}],
        },
        "priority_override": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sw_algorithm": {
            "v_range": [["v7.2.0", "v7.2.0"], ["v7.4.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "l2"}, {"value": "l3"}, {"value": "eh"}],
        },
        "description": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "alias": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "security_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "captive-portal"},
                {"value": "802.1X"},
            ],
        },
        "security_mac_auth_bypass": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "mac-auth-only", "v_range": [["v6.2.0", ""]]},
                {"value": "enable"},
                {"value": "disable"},
            ],
        },
        "security_ip_auth_bypass": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "security_external_web": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "security_external_logout": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "replacemsg_override_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "security_redirect_url": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "auth_cert": {"v_range": [["v7.0.4", ""]], "type": "string"},
        "auth_portal_addr": {"v_range": [["v7.0.4", ""]], "type": "string"},
        "security_exempt_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "security_groups": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ike_saml_server": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "device_identification": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "exclude_signatures": {
            "v_range": [["v7.6.1", ""]],
            "type": "list",
            "options": [{"value": "iot"}, {"value": "ot"}],
            "multiple_values": True,
            "elements": "str",
        },
        "device_user_identification": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "lldp_reception": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}, {"value": "vdom"}],
        },
        "lldp_transmission": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}, {"value": "vdom"}],
        },
        "lldp_network_policy": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "estimated_upstream_bandwidth": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "estimated_downstream_bandwidth": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "measured_upstream_bandwidth": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "measured_downstream_bandwidth": {
            "v_range": [["v6.4.0", ""]],
            "type": "integer",
        },
        "bandwidth_measure_time": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "monitor_bandwidth": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vrrp_virtual_mac": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vrrp": {
            "type": "list",
            "elements": "dict",
            "children": {
                "vrid": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "version": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "2"}, {"value": "3"}],
                },
                "vrgrp": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "vrip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "adv_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "start_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "preempt": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "accept_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "vrdst": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "vrdst_priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ignore_default_route": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "proxy_arp": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "role": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "lan"},
                {"value": "wan"},
                {"value": "dmz"},
                {"value": "undefined"},
            ],
        },
        "snmp_index": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "secondary_IP": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "secondaryip": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "secip_relay_ip": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "allowaccess": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "ping"},
                        {"value": "https"},
                        {"value": "ssh"},
                        {"value": "snmp"},
                        {"value": "http"},
                        {"value": "telnet"},
                        {"value": "fgfm"},
                        {"value": "radius-acct"},
                        {"value": "probe-response"},
                        {"value": "fabric", "v_range": [["v6.2.0", ""]]},
                        {"value": "ftm"},
                        {"value": "speed-test", "v_range": [["v7.0.1", ""]]},
                        {"value": "scim", "v_range": [["v7.6.0", ""]]},
                        {"value": "capwap", "v_range": [["v6.0.0", "v6.0.11"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "gwdetect": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "detectserver": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "detectprotocol": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "ping"},
                        {"value": "tcp-echo"},
                        {"value": "udp-echo"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "ha_priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ping_serv_status": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "preserve_session_route": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auto_auth_extension_device": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ap_discover": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "telemetry_discover": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fortilink_neighbor_detect": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "lldp"}, {"value": "fortilink"}],
        },
        "ip_managed_by_fortiipam": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [
                {"value": "inherit-global", "v_range": [["v7.4.0", ""]]},
                {"value": "enable"},
                {"value": "disable"},
            ],
        },
        "managed_subnetwork_size": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [
                {"value": "4", "v_range": [["v7.6.3", ""]]},
                {"value": "8", "v_range": [["v7.6.3", ""]]},
                {"value": "16", "v_range": [["v7.6.3", ""]]},
                {"value": "32", "v_range": [["v7.0.2", ""]]},
                {"value": "64", "v_range": [["v7.0.2", ""]]},
                {"value": "128", "v_range": [["v7.0.2", ""]]},
                {"value": "256"},
                {"value": "512"},
                {"value": "1024"},
                {"value": "2048"},
                {"value": "4096"},
                {"value": "8192"},
                {"value": "16384"},
                {"value": "32768"},
                {"value": "65536"},
                {"value": "131072", "v_range": [["v7.6.3", ""]]},
                {"value": "262144", "v_range": [["v7.6.3", ""]]},
                {"value": "524288", "v_range": [["v7.6.3", ""]]},
                {"value": "1048576", "v_range": [["v7.6.3", ""]]},
                {"value": "2097152", "v_range": [["v7.6.3", ""]]},
                {"value": "4194304", "v_range": [["v7.6.3", ""]]},
                {"value": "8388608", "v_range": [["v7.6.3", ""]]},
                {"value": "16777216", "v_range": [["v7.6.3", ""]]},
            ],
        },
        "fortilink_split_interface": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internal": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "switch_controller_access_vlan": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "switch_controller_traffic_policy": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
        },
        "switch_controller_rspan_mode": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "switch_controller_netflow_collect": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "switch_controller_mgmt_vlan": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "switch_controller_igmp_snooping": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "switch_controller_igmp_snooping_proxy": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "switch_controller_igmp_snooping_fast_leave": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "switch_controller_dhcp_snooping": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "switch_controller_dhcp_snooping_verify_mac": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "switch_controller_dhcp_snooping_option82": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dhcp_snooping_server_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "required": True,
                },
                "server_ip": {"v_range": [["v7.0.1", ""]], "type": "string"},
            },
            "v_range": [["v7.0.1", ""]],
        },
        "switch_controller_arp_inspection": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "enable"},
                {"value": "disable"},
                {"value": "monitor", "v_range": [["v7.4.4", ""]]},
            ],
        },
        "switch_controller_learning_limit": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "switch_controller_nac": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "switch_controller_dynamic": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "switch_controller_feature": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "default-vlan"},
                {"value": "quarantine"},
                {"value": "rspan"},
                {"value": "voice"},
                {"value": "video"},
                {"value": "nac"},
                {"value": "nac-segment", "v_range": [["v7.0.1", ""]]},
            ],
        },
        "switch_controller_iot_scanning": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "switch_controller_offload": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "switch_controller_offload_ip": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "switch_controller_offload_gw": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "color": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "tagging": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "category": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "tags": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "egress_queues": {
            "v_range": [
                ["v6.4.0", "v6.4.0"],
                ["v7.2.0", "v7.2.0"],
                ["v7.4.0", "v7.4.1"],
                ["v7.4.3", ""],
            ],
            "type": "dict",
            "children": {
                "cos0": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos1": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos2": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos3": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos4": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos5": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos6": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos7": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
            },
        },
        "ingress_cos": {
            "v_range": [
                ["v6.4.0", "v6.4.0"],
                ["v7.2.0", "v7.2.0"],
                ["v7.4.0", "v7.4.1"],
                ["v7.4.3", ""],
            ],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "cos0"},
                {"value": "cos1"},
                {"value": "cos2"},
                {"value": "cos3"},
                {"value": "cos4"},
                {"value": "cos5"},
                {"value": "cos6"},
                {"value": "cos7"},
            ],
        },
        "egress_cos": {
            "v_range": [
                ["v6.4.0", "v6.4.0"],
                ["v7.2.0", "v7.2.0"],
                ["v7.4.0", "v7.4.1"],
                ["v7.4.3", ""],
            ],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "cos0"},
                {"value": "cos1"},
                {"value": "cos2"},
                {"value": "cos3"},
                {"value": "cos4"},
                {"value": "cos5"},
                {"value": "cos6"},
                {"value": "cos7"},
            ],
        },
        "eap_supplicant": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "eap_method": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "tls"}, {"value": "peap"}],
        },
        "eap_identity": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "eap_password": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "eap_ca_cert": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "eap_user_cert": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "default_purdue_level": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [
                {"value": "1"},
                {"value": "1.5"},
                {"value": "2"},
                {"value": "2.5"},
                {"value": "3"},
                {"value": "3.5"},
                {"value": "4"},
                {"value": "5"},
                {"value": "5.5"},
            ],
        },
        "ipv6": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ip6_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "static"},
                        {"value": "dhcp"},
                        {"value": "pppoe"},
                        {"value": "delegated"},
                    ],
                },
                "client_options": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.6.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "code": {"v_range": [["v7.6.0", ""]], "type": "integer"},
                        "type": {
                            "v_range": [["v7.6.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "hex"},
                                {"value": "string"},
                                {"value": "ip6"},
                                {"value": "fqdn"},
                            ],
                        },
                        "value": {"v_range": [["v7.6.0", ""]], "type": "string"},
                        "ip6": {
                            "v_range": [["v7.6.0", ""]],
                            "type": "list",
                            "multiple_values": True,
                            "elements": "str",
                        },
                    },
                    "v_range": [["v7.6.0", ""]],
                },
                "nd_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "basic"}, {"value": "SEND-compatible"}],
                },
                "nd_cert": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "nd_security_level": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "nd_timestamp_delta": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "nd_timestamp_fuzz": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "nd_cga_modifier": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ip6_dns_server_override": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ip6_address": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ip6_extra_addr": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "prefix": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "ip6_allowaccess": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "ping"},
                        {"value": "https"},
                        {"value": "ssh"},
                        {"value": "snmp"},
                        {"value": "http"},
                        {"value": "telnet"},
                        {"value": "fgfm"},
                        {"value": "fabric", "v_range": [["v6.2.0", ""]]},
                        {"value": "scim", "v_range": [["v7.6.4", ""]]},
                        {"value": "capwap", "v_range": [["v6.0.0", "v6.0.11"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "ip6_send_adv": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "icmp6_send_redirect": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ip6_manage_flag": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ip6_other_flag": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ip6_max_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ip6_min_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ip6_link_mtu": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ra_send_mtu": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ip6_reachable_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ip6_retrans_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ip6_default_life": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ip6_hop_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ip6_adv_rio": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ip6_route_pref": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "low"},
                    ],
                },
                "ip6_route_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "route": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "route_pref": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "medium"},
                                {"value": "high"},
                                {"value": "low"},
                            ],
                        },
                        "route_life_time": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "integer",
                        },
                    },
                    "v_range": [["v7.6.1", ""]],
                },
                "autoconf": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "unique_autoconf_addr": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "interface_identifier": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "ip6_prefix_mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "dhcp6"}, {"value": "ra"}],
                },
                "ip6_delegated_prefix_iaid": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "integer",
                },
                "ip6_upstream_interface": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                },
                "ip6_subnet": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ip6_prefix_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "prefix": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "autonomous_flag": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "onlink_flag": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "valid_life_time": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "preferred_life_time": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "rdnss": {
                            "v_range": [["v6.0.0", "v7.6.0"]],
                            "type": "list",
                            "multiple_values": True,
                            "elements": "str",
                        },
                        "dnssl": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "domain": {
                                    "v_range": [["v6.0.0", "v7.6.0"]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v6.0.0", "v7.6.0"]],
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "ip6_rdnss_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "rdnss": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "rdnss_life_time": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "integer",
                        },
                    },
                    "v_range": [["v7.6.1", ""]],
                },
                "ip6_dnssl_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "domain": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "dnssl_life_time": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "integer",
                        },
                    },
                    "v_range": [["v7.6.1", ""]],
                },
                "ip6_delegated_prefix_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "prefix_id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "upstream_interface": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                        },
                        "delegated_prefix_iaid": {
                            "v_range": [["v7.0.2", ""]],
                            "type": "integer",
                        },
                        "autonomous_flag": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "onlink_flag": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "subnet": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "rdnss_service": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "delegated"},
                                {"value": "default"},
                                {"value": "specify"},
                            ],
                        },
                        "rdnss": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "list",
                            "multiple_values": True,
                            "elements": "str",
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "dhcp6_relay_service": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "dhcp6_relay_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "regular"}],
                },
                "dhcp6_relay_source_interface": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "dhcp6_relay_ip": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "dhcp6_relay_source_ip": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                },
                "dhcp6_relay_interface_id": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                },
                "dhcp6_prefix_delegation": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "dhcp6_information_request": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "dhcp6_iapd_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "iaid": {
                            "v_range": [["v7.0.2", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "prefix_hint": {"v_range": [["v7.0.2", ""]], "type": "string"},
                        "prefix_hint_plt": {
                            "v_range": [["v7.0.2", ""]],
                            "type": "integer",
                        },
                        "prefix_hint_vlt": {
                            "v_range": [["v7.0.2", ""]],
                            "type": "integer",
                        },
                    },
                    "v_range": [["v7.0.2", ""]],
                },
                "vrrp_virtual_mac6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "vrip6_link_local": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "vrrp6": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vrid": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "vrgrp": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "vrip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "adv_interval": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "start_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "preempt": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "accept_mode": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "vrdst6": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "list",
                            "multiple_values": True,
                            "elements": "str",
                        },
                        "vrdst_priority": {
                            "v_range": [["v7.6.0", ""]],
                            "type": "integer",
                        },
                        "ignore_default_route": {
                            "v_range": [["v7.4.2", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "status": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "dhcp6_client_options": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "list",
                    "options": [
                        {"value": "rapid"},
                        {"value": "iapd"},
                        {"value": "iana"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "cli_conn6_status": {
                    "v_range": [["v7.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "dhcp6_prefix_hint": {
                    "v_range": [["v6.0.0", "v7.0.1"]],
                    "type": "string",
                },
                "dhcp6_prefix_hint_plt": {
                    "v_range": [["v6.0.0", "v7.0.1"]],
                    "type": "integer",
                },
                "dhcp6_prefix_hint_vlt": {
                    "v_range": [["v6.0.0", "v7.0.1"]],
                    "type": "integer",
                },
            },
        },
        "drop_overlapped_fragment": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ring_rx": {"v_range": [], "type": "integer"},
        "ring_tx": {"v_range": [], "type": "integer"},
        "swc_first_create": {"v_range": [["v6.4.4", "v7.6.0"]], "type": "integer"},
        "mediatype": {
            "v_range": [
                ["v6.0.0", "v6.2.7"],
                ["v6.4.1", "v7.0.12"],
                ["v7.2.1", "v7.2.4"],
                ["v7.4.2", "v7.4.2"],
            ],
            "type": "string",
            "options": [
                {"value": "none", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "gmii", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "sgmii", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "sr", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "lr", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "cr", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "sr2", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "lr2", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "cr2", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "sr4", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "lr4", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "cr4", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "sr8", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "lr8", "v_range": [["v7.4.2", "v7.4.2"]]},
                {"value": "cr8", "v_range": [["v7.4.2", "v7.4.2"]]},
                {
                    "value": "cfp2-sr10",
                    "v_range": [
                        ["v6.0.0", "v6.2.7"],
                        ["v6.4.1", "v7.0.12"],
                        ["v7.2.1", "v7.2.4"],
                    ],
                },
                {
                    "value": "cfp2-lr4",
                    "v_range": [
                        ["v6.0.0", "v6.2.7"],
                        ["v6.4.1", "v7.0.12"],
                        ["v7.2.1", "v7.2.4"],
                    ],
                },
            ],
        },
        "trunk": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "security_8021x_mode": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [
                {"value": "default"},
                {"value": "dynamic-vlan"},
                {"value": "fallback"},
                {"value": "slave"},
            ],
        },
        "security_8021x_master": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "string"},
        "security_8021x_dynamic_vlan_id": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "integer",
        },
        "security_8021x_member_mode": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "switch"}, {"value": "disable"}],
        },
        "stp": {
            "v_range": [
                ["v6.0.0", "v6.2.7"],
                ["v6.4.1", "v7.0.12"],
                ["v7.2.1", "v7.2.4"],
                ["v7.4.2", "v7.4.2"],
            ],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "stp_ha_secondary": {
            "v_range": [
                ["v7.0.0", "v7.0.12"],
                ["v7.2.1", "v7.2.4"],
                ["v7.4.2", "v7.4.2"],
            ],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "enable"},
                {"value": "priority-adjust"},
            ],
        },
        "stp_edge": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "forward_error_correction": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "disable"},
                {"value": "cl91-rs-fec"},
                {"value": "cl74-fc-fec"},
                {"value": "auto"},
            ],
        },
        "interconnect_profile": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [
                {"value": "default"},
                {"value": "profile1"},
                {"value": "profile2"},
            ],
        },
        "np_qos_profile": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
        "port_mirroring": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "mirroring_direction": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "rx"}, {"value": "tx"}, {"value": "both"}],
        },
        "mirroring_port": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "string"},
        "mirroring_filter": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "dict",
            "children": {
                "filter_srcip": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "string"},
                "filter_dstip": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "string"},
                "filter_sport": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "filter_dport": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "filter_protocol": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "integer",
                },
            },
        },
        "disconnect_threshold": {"v_range": [["v6.0.0", "v7.4.0"]], "type": "integer"},
        "cli_conn_status": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "ping_serv_status": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "detected_peer_mtu": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "lacp_ha_slave": {
            "v_range": [["v6.0.0", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "aggregate": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "redundant_interface": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "devindex": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "vindex": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "switch": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "fortilink_backup_link": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "swc_vlan": {
            "v_range": [["v6.4.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "stp_ha_slave": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.4"]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "enable"},
                {"value": "priority-adjust"},
            ],
        },
        "fortilink_stacking": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "broadcast_forticlient_discovery": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "captive_portal": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "integer",
        },
        "device_identification_active_scan": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "device_access_list": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "scan_botnet_connections": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "block"}, {"value": "monitor"}],
        },
        "managed_device": {
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
        "device_netscan": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "fortiheartbeat": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "endpoint_compliance": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
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
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "system_interface": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_interface"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_interface"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_interface"
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
