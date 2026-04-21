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
module: fortios_system_settings
short_description: Configure VDOM settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and settings category.
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

    system_settings:
        description:
            - Configure VDOM settings.
        default: null
        type: dict
        suboptions:
            allow_linkdown_path:
                description:
                    - Enable/disable link down path.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            allow_subnet_overlap:
                description:
                    - Enable/disable allowing interface subnets to use overlapping IP addresses.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            application_bandwidth_tracking:
                description:
                    - Enable/disable application bandwidth tracking.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            asymroute:
                description:
                    - Enable/disable IPv4 asymmetric routing.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            asymroute_icmp:
                description:
                    - Enable/disable ICMP asymmetric routing.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            asymroute6:
                description:
                    - Enable/disable asymmetric IPv6 routing.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            asymroute6_icmp:
                description:
                    - Enable/disable asymmetric ICMPv6 routing.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auxiliary_session:
                description:
                    - Enable/disable auxiliary session.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bfd:
                description:
                    - Enable/disable Bi-directional Forwarding Detection (BFD) on all interfaces.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bfd_desired_min_tx:
                description:
                    - BFD desired minimal transmit interval (1 - 100000 ms).
                type: int
            bfd_detect_mult:
                description:
                    - BFD detection multiplier (1 - 50).
                type: int
            bfd_dont_enforce_src_port:
                description:
                    - Enable to not enforce verifying the source port of BFD Packets.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bfd_required_min_rx:
                description:
                    - BFD required minimal receive interval (1 - 100000 ms).
                type: int
            block_land_attack:
                description:
                    - Enable/disable blocking of land attacks.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            central_nat:
                description:
                    - Enable/disable central NAT.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            comments:
                description:
                    - VDOM comments.
                type: str
            compliance_check:
                description:
                    - Enable/disable PCI DSS compliance checking.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            consolidated_firewall_mode:
                description:
                    - Consolidated firewall mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            default_app_port_as_service:
                description:
                    - Enable/disable policy service enforcement based on application default ports.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            default_policy_expiry_days:
                description:
                    - Default policy expiry in days (0 - 365 days).
                type: int
            default_voip_alg_mode:
                description:
                    - Configure how the FortiGate handles VoIP traffic when a policy that accepts the traffic doesn"t include a VoIP profile.
                type: str
                choices:
                    - 'proxy-based'
                    - 'kernel-helper-based'
            deny_tcp_with_icmp:
                description:
                    - Enable/disable denying TCP by sending an ICMP communication prohibited packet.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            detect_unknown_esp:
                description:
                    - Enable/disable detection of unknown ESP packets .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            device:
                description:
                    - Interface to use for management access for NAT mode. Source system.interface.name.
                type: str
            dhcp_proxy:
                description:
                    - Enable/disable the DHCP Proxy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dhcp_proxy_interface:
                description:
                    - Specify outgoing interface to reach server. Source system.interface.name.
                type: str
            dhcp_proxy_interface_select_method:
                description:
                    - Specify how to select outgoing interface to reach server.
                type: str
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            dhcp_proxy_vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
            dhcp_server_ip:
                description:
                    - DHCP Server IPv4 address.
                type: list
                elements: str
            dhcp6_server_ip:
                description:
                    - DHCPv6 server IPv6 address.
                type: list
                elements: str
            discovered_device_timeout:
                description:
                    - Timeout for discovered devices (1 - 365 days).
                type: int
            dyn_addr_session_check:
                description:
                    - Enable/disable dirty session check caused by dynamic address updates.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ecmp_max_paths:
                description:
                    - Maximum number of Equal Cost Multi-Path (ECMP) next-hops. Set to 1 to disable ECMP routing (1 - 255).
                type: int
            email_portal_check_dns:
                description:
                    - Enable/disable using DNS to validate email addresses collected by a captive portal.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ext_resource_session_check:
                description:
                    - Enable/disable dirty session check caused by external resource updates.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            firewall_session_dirty:
                description:
                    - Select how to manage sessions affected by firewall policy configuration changes.
                type: str
                choices:
                    - 'check-all'
                    - 'check-new'
                    - 'check-policy-option'
            fqdn_session_check:
                description:
                    - Enable/disable dirty session check caused by FQDN updates.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fw_session_hairpin:
                description:
                    - Enable/disable checking for a matching policy each time hairpin traffic goes through the FortiGate.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gateway:
                description:
                    - Transparent mode IPv4 default gateway IP address.
                type: str
            gateway6:
                description:
                    - Transparent mode IPv6 default gateway IP address.
                type: str
            gtp_asym_fgsp:
                description:
                    - Enable/disable GTP asymmetric traffic handling on FGSP.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            gtp_monitor_mode:
                description:
                    - Enable/disable GTP monitor mode (VDOM level).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_advanced_policy:
                description:
                    - Enable/disable advanced policy configuration on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_advanced_wireless_features:
                description:
                    - Enable/disable advanced wireless features in GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_allow_unnamed_policy:
                description:
                    - Enable/disable the requirement for policy naming on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_antivirus:
                description:
                    - Enable/disable AntiVirus on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_ap_profile:
                description:
                    - Enable/disable FortiAP profiles on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_application_control:
                description:
                    - Enable/disable application control on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_casb:
                description:
                    - Enable/disable Inline-CASB on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_default_policy_columns:
                description:
                    - Default columns to display for policy lists on GUI.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Select column name.
                        required: true
                        type: str
            gui_dhcp_advanced:
                description:
                    - Enable/disable advanced DHCP options on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_dlp:
                description:
                    - Enable/disable DLP on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_dlp_advanced:
                description:
                    - Enable/disable Show advanced DLP expressions on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_dlp_profile:
                description:
                    - Enable/disable Data Loss Prevention on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_dns_database:
                description:
                    - Enable/disable DNS database settings on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_dnsfilter:
                description:
                    - Enable/disable DNS Filtering on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_domain_ip_reputation:
                description:
                    - Enable/disable Domain and IP Reputation on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_dos_policy:
                description:
                    - Enable/disable DoS policies on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_dynamic_device_os_id:
                description:
                    - Enable/disable Create dynamic addresses to manage known devices.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_dynamic_profile_display:
                description:
                    - Enable/disable RADIUS Single Sign On (RSSO) on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_dynamic_routing:
                description:
                    - Enable/disable dynamic routing on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_email_collection:
                description:
                    - Enable/disable email collection on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_endpoint_control:
                description:
                    - Enable/disable endpoint control on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_endpoint_control_advanced:
                description:
                    - Enable/disable advanced endpoint control options on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_enforce_change_summary:
                description:
                    - Enforce change summaries for select tables in the GUI.
                type: str
                choices:
                    - 'disable'
                    - 'require'
                    - 'optional'
            gui_explicit_proxy:
                description:
                    - Enable/disable the explicit proxy on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_file_filter:
                description:
                    - Enable/disable File-filter on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_fortiap_split_tunneling:
                description:
                    - Enable/disable FortiAP split tunneling on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_fortiextender_controller:
                description:
                    - Enable/disable FortiExtender on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_fortitelemetry:
                description:
                    - Enable/disable FortiTelemetry on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_gtp:
                description:
                    - Enable/disable Manage general radio packet service (GPRS) protocols on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_icap:
                description:
                    - Enable/disable ICAP on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_implicit_policy:
                description:
                    - Enable/disable implicit firewall policies on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_ips:
                description:
                    - Enable/disable IPS on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_load_balance:
                description:
                    - Enable/disable server load balancing on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_local_in_policy:
                description:
                    - Enable/disable Local-In policies on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_local_reports:
                description:
                    - Enable/disable local reports on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_multicast_policy:
                description:
                    - Enable/disable multicast firewall policies on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_multiple_interface_policy:
                description:
                    - Enable/disable adding multiple interfaces to a policy on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_multiple_utm_profiles:
                description:
                    - Enable/disable multiple UTM profiles on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_nat46_64:
                description:
                    - Enable/disable NAT46 and NAT64 settings on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_object_colors:
                description:
                    - Enable/disable object colors on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_ot:
                description:
                    - Enable/disable Operational technology features on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_per_policy_disclaimer:
                description:
                    - Enable/disable policy disclaimer on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_policy_based_ipsec:
                description:
                    - Enable/disable policy-based IPsec VPN on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_policy_disclaimer:
                description:
                    - Enable/disable policy disclaimer on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_policy_learning:
                description:
                    - Enable/disable firewall policy learning mode on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_proxy_inspection:
                description:
                    - Enable/disable the proxy features on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_replacement_message_groups:
                description:
                    - Enable/disable replacement message groups on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_route_tag_address_creation:
                description:
                    - Enable/disable route-tag addresses on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_security_profile_group:
                description:
                    - Enable/disable Security Profile Groups on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_spamfilter:
                description:
                    - Enable/disable Antispam on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_sslvpn:
                description:
                    - Enable/disable SSL-VPN settings pages on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_sslvpn_personal_bookmarks:
                description:
                    - Enable/disable SSL-VPN personal bookmark management on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_sslvpn_realms:
                description:
                    - Enable/disable SSL-VPN realms on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_switch_controller:
                description:
                    - Enable/disable the switch controller on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_threat_weight:
                description:
                    - Enable/disable threat weight on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_traffic_shaping:
                description:
                    - Enable/disable traffic shaping on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_videofilter:
                description:
                    - Enable/disable Video filtering on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_virtual_patch_profile:
                description:
                    - Enable/disable Virtual Patching on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_voip_profile:
                description:
                    - Enable/disable VoIP profiles on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_vpn:
                description:
                    - Enable/disable IPsec VPN settings pages on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_waf_profile:
                description:
                    - Enable/disable Web Application Firewall on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_wan_load_balancing:
                description:
                    - Enable/disable SD-WAN on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_wanopt_cache:
                description:
                    - Enable/disable WAN Optimization and Web Caching on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_webfilter:
                description:
                    - Enable/disable Web filtering on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_webfilter_advanced:
                description:
                    - Enable/disable advanced web filtering on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_wireless_controller:
                description:
                    - Enable/disable the wireless controller on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_ztna:
                description:
                    - Enable/disable Zero Trust Network Access features on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            h323_direct_model:
                description:
                    - Enable/disable H323 direct model.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            http_external_dest:
                description:
                    - Offload HTTP traffic to FortiWeb or FortiCache.
                type: str
                choices:
                    - 'fortiweb'
                    - 'forticache'
            ike_detailed_event_logs:
                description:
                    - Enable/disable detail log for IKE events.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ike_dn_format:
                description:
                    - Configure IKE ASN.1 Distinguished Name format conventions.
                type: str
                choices:
                    - 'with-space'
                    - 'no-space'
            ike_policy_route:
                description:
                    - Enable/disable IKE Policy Based Routing (PBR).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ike_port:
                description:
                    - UDP port for IKE/IPsec traffic .
                type: int
            ike_quick_crash_detect:
                description:
                    - Enable/disable IKE quick crash detection (RFC 6290).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ike_session_resume:
                description:
                    - Enable/disable IKEv2 session resumption (RFC 5723).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ike_tcp_port:
                description:
                    - TCP port for IKE/IPsec traffic .
                type: int
            implicit_allow_dns:
                description:
                    - Enable/disable implicitly allowing DNS traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            inspection_mode:
                description:
                    - Inspection mode (proxy-based or flow-based).
                type: str
                choices:
                    - 'proxy'
                    - 'flow'
            internet_service_app_ctrl_size:
                description:
                    - Maximum number of tuple entries (protocol, port, IP address, application ID) stored by the FortiGate unit (0 - 4294967295). A smaller
                       value limits the FortiGate unit from learning about internet applications.
                type: int
            internet_service_database_cache:
                description:
                    - Enable/disable Internet Service database caching.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            intree_ses_best_route:
                description:
                    - Force the intree session to always use the best route.
                type: str
                choices:
                    - 'force'
                    - 'disable'
            ip:
                description:
                    - IP address and netmask.
                type: str
            ip6:
                description:
                    - IPv6 address prefix for NAT mode.
                type: str
            lan_extension_controller_addr:
                description:
                    - Controller IP address or FQDN to connect.
                type: str
            link_down_access:
                description:
                    - Enable/disable link down access traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            lldp_reception:
                description:
                    - Enable/disable Link Layer Discovery Protocol (LLDP) reception for this VDOM or apply global settings to this VDOM.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
                    - 'global'
            lldp_transmission:
                description:
                    - Enable/disable Link Layer Discovery Protocol (LLDP) transmission for this VDOM or apply global settings to this VDOM.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
                    - 'global'
            location_id:
                description:
                    - Local location ID in the form of an IPv4 address.
                type: str
            mac_ttl:
                description:
                    - Duration of MAC addresses in Transparent mode (300 - 8640000 sec).
                type: int
            manageip:
                description:
                    - Transparent mode IPv4 management IP address and netmask.
                type: str
            manageip6:
                description:
                    - Transparent mode IPv6 management IP address and netmask.
                type: str
            multicast_forward:
                description:
                    - Enable/disable multicast forwarding.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            multicast_skip_policy:
                description:
                    - Enable/disable allowing multicast traffic through the FortiGate without a policy check.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            multicast_ttl_notchange:
                description:
                    - Enable/disable preventing the FortiGate from changing the TTL for forwarded multicast packets.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            nat46_force_ipv4_packet_forwarding:
                description:
                    - Enable/disable mandatory IPv4 packet forwarding in NAT46.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            nat46_generate_ipv6_fragment_header:
                description:
                    - Enable/disable NAT46 IPv6 fragment header generation.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            nat64_force_ipv6_packet_forwarding:
                description:
                    - Enable/disable mandatory IPv6 packet forwarding in NAT64.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ngfw_mode:
                description:
                    - Next Generation Firewall (NGFW) mode.
                type: str
                choices:
                    - 'profile-based'
                    - 'policy-based'
            opmode:
                description:
                    - Firewall operation mode (NAT or Transparent).
                type: str
                choices:
                    - 'nat'
                    - 'transparent'
            pfcp_monitor_mode:
                description:
                    - Enable/disable PFCP monitor mode (VDOM level).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            policy_offload_level:
                description:
                    - Configure firewall policy offload level.
                type: str
                choices:
                    - 'disable'
                    - 'dos-offload'
            prp_trailer_action:
                description:
                    - Enable/disable action to take on PRP trailer.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sccp_port:
                description:
                    - TCP port the SCCP proxy monitors for SCCP traffic (0 - 65535).
                type: int
            sctp_session_without_init:
                description:
                    - Enable/disable SCTP session creation without SCTP INIT.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ses_denied_multicast_traffic:
                description:
                    - Enable/disable including denied multicast session in the session table.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ses_denied_traffic:
                description:
                    - Enable/disable including denied session in the session table.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sip_expectation:
                description:
                    - Enable/disable the SIP kernel session helper to create an expectation for port 5060.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sip_helper:
                description:
                    - Enable/disable the SIP session helper to process SIP sessions unless SIP sessions are accepted by the SIP application layer gateway
                       (ALG).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sip_nat_trace:
                description:
                    - Enable/disable recording the original SIP source IP address when NAT is used.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sip_ssl_port:
                description:
                    - TCP port the SIP proxy monitors for SIP SSL/TLS traffic (0 - 65535).
                type: int
            sip_tcp_port:
                description:
                    - TCP port the SIP proxy monitors for SIP traffic (0 - 65535).
                type: list
                elements: int
            sip_udp_port:
                description:
                    - UDP port the SIP proxy monitors for SIP traffic (0 - 65535).
                type: list
                elements: int
            snat_hairpin_traffic:
                description:
                    - Enable/disable source NAT (SNAT) for VIP hairpin traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_ssh_profile:
                description:
                    - Profile for SSL/SSH inspection. Source firewall.ssl-ssh-profile.name.
                type: str
            status:
                description:
                    - Enable/disable this VDOM.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            strict_src_check:
                description:
                    - Enable/disable strict source verification.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tcp_session_without_syn:
                description:
                    - Enable/disable allowing TCP session without SYN flags.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            utf8_spam_tagging:
                description:
                    - Enable/disable converting antispam tags to UTF-8 for better non-ASCII character support.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            v4_ecmp_mode:
                description:
                    - IPv4 Equal-cost multi-path (ECMP) routing and load balancing mode.
                type: str
                choices:
                    - 'source-ip-based'
                    - 'weight-based'
                    - 'usage-based'
                    - 'source-dest-ip-based'
            vdom_type:
                description:
                    - Vdom type (traffic, lan-extension or admin).
                type: str
                choices:
                    - 'traffic'
                    - 'lan-extension'
                    - 'admin'
            vpn_stats_log:
                description:
                    - Enable/disable periodic VPN log statistics for one or more types of VPN. Separate names with a space.
                type: list
                elements: str
                choices:
                    - 'ipsec'
                    - 'pptp'
                    - 'l2tp'
                    - 'ssl'
            vpn_stats_period:
                description:
                    - Period to send VPN log statistics (0 or 60 - 86400 sec).
                type: int
            wccp_cache_engine:
                description:
                    - Enable/disable WCCP cache engine.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure VDOM settings.
  fortinet.fortios.fortios_system_settings:
      vdom: "{{ vdom }}"
      system_settings:
          allow_linkdown_path: "enable"
          allow_subnet_overlap: "enable"
          application_bandwidth_tracking: "disable"
          asymroute: "enable"
          asymroute_icmp: "enable"
          asymroute6: "enable"
          asymroute6_icmp: "enable"
          auxiliary_session: "enable"
          bfd: "enable"
          bfd_desired_min_tx: "250"
          bfd_detect_mult: "3"
          bfd_dont_enforce_src_port: "enable"
          bfd_required_min_rx: "250"
          block_land_attack: "disable"
          central_nat: "enable"
          comments: "<your_own_value>"
          compliance_check: "enable"
          consolidated_firewall_mode: "enable"
          default_app_port_as_service: "enable"
          default_policy_expiry_days: "30"
          default_voip_alg_mode: "proxy-based"
          deny_tcp_with_icmp: "enable"
          detect_unknown_esp: "enable"
          device: "<your_own_value> (source system.interface.name)"
          dhcp_proxy: "enable"
          dhcp_proxy_interface: "<your_own_value> (source system.interface.name)"
          dhcp_proxy_interface_select_method: "auto"
          dhcp_proxy_vrf_select: "0"
          dhcp_server_ip: "<your_own_value>"
          dhcp6_server_ip: "<your_own_value>"
          discovered_device_timeout: "28"
          dyn_addr_session_check: "enable"
          ecmp_max_paths: "255"
          email_portal_check_dns: "disable"
          ext_resource_session_check: "enable"
          firewall_session_dirty: "check-all"
          fqdn_session_check: "enable"
          fw_session_hairpin: "enable"
          gateway: "<your_own_value>"
          gateway6: "<your_own_value>"
          gtp_asym_fgsp: "disable"
          gtp_monitor_mode: "enable"
          gui_advanced_policy: "enable"
          gui_advanced_wireless_features: "enable"
          gui_allow_unnamed_policy: "enable"
          gui_antivirus: "enable"
          gui_ap_profile: "enable"
          gui_application_control: "enable"
          gui_casb: "enable"
          gui_default_policy_columns:
              -
                  name: "default_name_53"
          gui_dhcp_advanced: "enable"
          gui_dlp: "enable"
          gui_dlp_advanced: "enable"
          gui_dlp_profile: "enable"
          gui_dns_database: "enable"
          gui_dnsfilter: "enable"
          gui_domain_ip_reputation: "enable"
          gui_dos_policy: "enable"
          gui_dynamic_device_os_id: "enable"
          gui_dynamic_profile_display: "enable"
          gui_dynamic_routing: "enable"
          gui_email_collection: "enable"
          gui_endpoint_control: "enable"
          gui_endpoint_control_advanced: "enable"
          gui_enforce_change_summary: "disable"
          gui_explicit_proxy: "enable"
          gui_file_filter: "enable"
          gui_fortiap_split_tunneling: "enable"
          gui_fortiextender_controller: "enable"
          gui_fortitelemetry: "enable"
          gui_gtp: "enable"
          gui_icap: "enable"
          gui_implicit_policy: "enable"
          gui_ips: "enable"
          gui_load_balance: "enable"
          gui_local_in_policy: "enable"
          gui_local_reports: "enable"
          gui_multicast_policy: "enable"
          gui_multiple_interface_policy: "enable"
          gui_multiple_utm_profiles: "enable"
          gui_nat46_64: "enable"
          gui_object_colors: "enable"
          gui_ot: "enable"
          gui_per_policy_disclaimer: "enable"
          gui_policy_based_ipsec: "enable"
          gui_policy_disclaimer: "enable"
          gui_policy_learning: "enable"
          gui_proxy_inspection: "enable"
          gui_replacement_message_groups: "enable"
          gui_route_tag_address_creation: "enable"
          gui_security_profile_group: "enable"
          gui_spamfilter: "enable"
          gui_sslvpn: "enable"
          gui_sslvpn_personal_bookmarks: "enable"
          gui_sslvpn_realms: "enable"
          gui_switch_controller: "enable"
          gui_threat_weight: "enable"
          gui_traffic_shaping: "enable"
          gui_videofilter: "enable"
          gui_virtual_patch_profile: "enable"
          gui_voip_profile: "enable"
          gui_vpn: "enable"
          gui_waf_profile: "enable"
          gui_wan_load_balancing: "enable"
          gui_wanopt_cache: "enable"
          gui_webfilter: "enable"
          gui_webfilter_advanced: "enable"
          gui_wireless_controller: "enable"
          gui_ztna: "enable"
          h323_direct_model: "disable"
          http_external_dest: "fortiweb"
          ike_detailed_event_logs: "disable"
          ike_dn_format: "with-space"
          ike_policy_route: "enable"
          ike_port: "500"
          ike_quick_crash_detect: "enable"
          ike_session_resume: "enable"
          ike_tcp_port: "443"
          implicit_allow_dns: "enable"
          inspection_mode: "proxy"
          internet_service_app_ctrl_size: "32768"
          internet_service_database_cache: "disable"
          intree_ses_best_route: "force"
          ip: "<your_own_value>"
          ip6: "<your_own_value>"
          lan_extension_controller_addr: "<your_own_value>"
          link_down_access: "enable"
          lldp_reception: "enable"
          lldp_transmission: "enable"
          location_id: "<your_own_value>"
          mac_ttl: "300"
          manageip: "<your_own_value>"
          manageip6: "<your_own_value>"
          multicast_forward: "enable"
          multicast_skip_policy: "enable"
          multicast_ttl_notchange: "enable"
          nat46_force_ipv4_packet_forwarding: "enable"
          nat46_generate_ipv6_fragment_header: "enable"
          nat64_force_ipv6_packet_forwarding: "enable"
          ngfw_mode: "profile-based"
          opmode: "nat"
          pfcp_monitor_mode: "enable"
          policy_offload_level: "disable"
          prp_trailer_action: "enable"
          sccp_port: "2000"
          sctp_session_without_init: "enable"
          ses_denied_multicast_traffic: "enable"
          ses_denied_traffic: "enable"
          sip_expectation: "enable"
          sip_helper: "enable"
          sip_nat_trace: "enable"
          sip_ssl_port: "5061"
          sip_tcp_port: "<your_own_value>"
          sip_udp_port: "<your_own_value>"
          snat_hairpin_traffic: "enable"
          ssl_ssh_profile: "<your_own_value> (source firewall.ssl-ssh-profile.name)"
          status: "enable"
          strict_src_check: "enable"
          tcp_session_without_syn: "enable"
          utf8_spam_tagging: "enable"
          v4_ecmp_mode: "source-ip-based"
          vdom_type: "traffic"
          vpn_stats_log: "ipsec"
          vpn_stats_period: "600"
          wccp_cache_engine: "enable"
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


def filter_system_settings_data(json):
    option_list = [
        "allow_linkdown_path",
        "allow_subnet_overlap",
        "application_bandwidth_tracking",
        "asymroute",
        "asymroute_icmp",
        "asymroute6",
        "asymroute6_icmp",
        "auxiliary_session",
        "bfd",
        "bfd_desired_min_tx",
        "bfd_detect_mult",
        "bfd_dont_enforce_src_port",
        "bfd_required_min_rx",
        "block_land_attack",
        "central_nat",
        "comments",
        "compliance_check",
        "consolidated_firewall_mode",
        "default_app_port_as_service",
        "default_policy_expiry_days",
        "default_voip_alg_mode",
        "deny_tcp_with_icmp",
        "detect_unknown_esp",
        "device",
        "dhcp_proxy",
        "dhcp_proxy_interface",
        "dhcp_proxy_interface_select_method",
        "dhcp_proxy_vrf_select",
        "dhcp_server_ip",
        "dhcp6_server_ip",
        "discovered_device_timeout",
        "dyn_addr_session_check",
        "ecmp_max_paths",
        "email_portal_check_dns",
        "ext_resource_session_check",
        "firewall_session_dirty",
        "fqdn_session_check",
        "fw_session_hairpin",
        "gateway",
        "gateway6",
        "gtp_asym_fgsp",
        "gtp_monitor_mode",
        "gui_advanced_policy",
        "gui_advanced_wireless_features",
        "gui_allow_unnamed_policy",
        "gui_antivirus",
        "gui_ap_profile",
        "gui_application_control",
        "gui_casb",
        "gui_default_policy_columns",
        "gui_dhcp_advanced",
        "gui_dlp",
        "gui_dlp_advanced",
        "gui_dlp_profile",
        "gui_dns_database",
        "gui_dnsfilter",
        "gui_domain_ip_reputation",
        "gui_dos_policy",
        "gui_dynamic_device_os_id",
        "gui_dynamic_profile_display",
        "gui_dynamic_routing",
        "gui_email_collection",
        "gui_endpoint_control",
        "gui_endpoint_control_advanced",
        "gui_enforce_change_summary",
        "gui_explicit_proxy",
        "gui_file_filter",
        "gui_fortiap_split_tunneling",
        "gui_fortiextender_controller",
        "gui_fortitelemetry",
        "gui_gtp",
        "gui_icap",
        "gui_implicit_policy",
        "gui_ips",
        "gui_load_balance",
        "gui_local_in_policy",
        "gui_local_reports",
        "gui_multicast_policy",
        "gui_multiple_interface_policy",
        "gui_multiple_utm_profiles",
        "gui_nat46_64",
        "gui_object_colors",
        "gui_ot",
        "gui_per_policy_disclaimer",
        "gui_policy_based_ipsec",
        "gui_policy_disclaimer",
        "gui_policy_learning",
        "gui_proxy_inspection",
        "gui_replacement_message_groups",
        "gui_route_tag_address_creation",
        "gui_security_profile_group",
        "gui_spamfilter",
        "gui_sslvpn",
        "gui_sslvpn_personal_bookmarks",
        "gui_sslvpn_realms",
        "gui_switch_controller",
        "gui_threat_weight",
        "gui_traffic_shaping",
        "gui_videofilter",
        "gui_virtual_patch_profile",
        "gui_voip_profile",
        "gui_vpn",
        "gui_waf_profile",
        "gui_wan_load_balancing",
        "gui_wanopt_cache",
        "gui_webfilter",
        "gui_webfilter_advanced",
        "gui_wireless_controller",
        "gui_ztna",
        "h323_direct_model",
        "http_external_dest",
        "ike_detailed_event_logs",
        "ike_dn_format",
        "ike_policy_route",
        "ike_port",
        "ike_quick_crash_detect",
        "ike_session_resume",
        "ike_tcp_port",
        "implicit_allow_dns",
        "inspection_mode",
        "internet_service_app_ctrl_size",
        "internet_service_database_cache",
        "intree_ses_best_route",
        "ip",
        "ip6",
        "lan_extension_controller_addr",
        "link_down_access",
        "lldp_reception",
        "lldp_transmission",
        "location_id",
        "mac_ttl",
        "manageip",
        "manageip6",
        "multicast_forward",
        "multicast_skip_policy",
        "multicast_ttl_notchange",
        "nat46_force_ipv4_packet_forwarding",
        "nat46_generate_ipv6_fragment_header",
        "nat64_force_ipv6_packet_forwarding",
        "ngfw_mode",
        "opmode",
        "pfcp_monitor_mode",
        "policy_offload_level",
        "prp_trailer_action",
        "sccp_port",
        "sctp_session_without_init",
        "ses_denied_multicast_traffic",
        "ses_denied_traffic",
        "sip_expectation",
        "sip_helper",
        "sip_nat_trace",
        "sip_ssl_port",
        "sip_tcp_port",
        "sip_udp_port",
        "snat_hairpin_traffic",
        "ssl_ssh_profile",
        "status",
        "strict_src_check",
        "tcp_session_without_syn",
        "utf8_spam_tagging",
        "v4_ecmp_mode",
        "vdom_type",
        "vpn_stats_log",
        "vpn_stats_period",
        "wccp_cache_engine",
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
        ["vpn_stats_log"],
        ["dhcp_server_ip"],
        ["dhcp6_server_ip"],
        ["sip_tcp_port"],
        ["sip_udp_port"],
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


def system_settings(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_settings_data = data["system_settings"]

    filtered_data = filter_system_settings_data(system_settings_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "settings", filtered_data, vdom=vdom)
        current_data = fos.get("system", "settings", vdom=vdom, mkey=mkey)
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
    data_copy["system_settings"] = filtered_data
    fos.do_member_operation(
        "system",
        "settings",
        data_copy,
    )

    return fos.set("system", "settings", data=converted_data, vdom=vdom)


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

    if data["system_settings"]:
        resp = system_settings(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_settings"))
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
    "v_range": [["v6.0.0", ""]],
    "type": "dict",
    "children": {
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "vdom_type": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "traffic"},
                {"value": "lan-extension", "v_range": [["v7.2.1", ""]]},
                {"value": "admin"},
            ],
        },
        "lan_extension_controller_addr": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
        },
        "opmode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "nat"}, {"value": "transparent"}],
        },
        "ngfw_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "profile-based"}, {"value": "policy-based"}],
        },
        "http_external_dest": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "fortiweb"}, {"value": "forticache"}],
        },
        "firewall_session_dirty": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "check-all"},
                {"value": "check-new"},
                {"value": "check-policy-option"},
            ],
        },
        "manageip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "gateway": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "manageip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "gateway6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "device": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "bfd": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "bfd_desired_min_tx": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "bfd_required_min_rx": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "bfd_detect_mult": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "bfd_dont_enforce_src_port": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "utf8_spam_tagging": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wccp_cache_engine": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vpn_stats_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "ipsec"},
                {"value": "pptp"},
                {"value": "l2tp"},
                {"value": "ssl"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "vpn_stats_period": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "v4_ecmp_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "source-ip-based"},
                {"value": "weight-based"},
                {"value": "usage-based"},
                {"value": "source-dest-ip-based"},
            ],
        },
        "mac_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "fw_session_hairpin": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "prp_trailer_action": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "snat_hairpin_traffic": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dhcp_proxy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dhcp_proxy_interface_select_method": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "dhcp_proxy_interface": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "dhcp_proxy_vrf_select": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "dhcp_server_ip": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "dhcp6_server_ip": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "central_nat": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_default_policy_columns": {
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
        "lldp_reception": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}, {"value": "global"}],
        },
        "lldp_transmission": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}, {"value": "global"}],
        },
        "link_down_access": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nat46_generate_ipv6_fragment_header": {
            "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nat46_force_ipv4_packet_forwarding": {
            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nat64_force_ipv6_packet_forwarding": {
            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "detect_unknown_esp": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "intree_ses_best_route": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "force"}, {"value": "disable"}],
        },
        "auxiliary_session": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "asymroute": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "asymroute_icmp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tcp_session_without_syn": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ses_denied_traffic": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ses_denied_multicast_traffic": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "strict_src_check": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "allow_linkdown_path": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "asymroute6": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "asymroute6_icmp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sctp_session_without_init": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sip_expectation": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sip_nat_trace": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "h323_direct_model": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sip_tcp_port": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "int",
        },
        "sip_udp_port": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "int",
        },
        "sip_ssl_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "sccp_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "multicast_forward": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "multicast_ttl_notchange": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "multicast_skip_policy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "allow_subnet_overlap": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "deny_tcp_with_icmp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ecmp_max_paths": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "discovered_device_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "email_portal_check_dns": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "default_voip_alg_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "proxy-based"}, {"value": "kernel-helper-based"}],
        },
        "gui_icap": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_implicit_policy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_dns_database": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_load_balance": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_multicast_policy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_dos_policy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_object_colors": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_route_tag_address_creation": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_voip_profile": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_ap_profile": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_security_profile_group": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_local_in_policy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_wanopt_cache": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "enable", "v_range": [["v6.0.0", ""]]},
                {"value": "disable", "v_range": [["v6.0.0", ""]]},
            ],
        },
        "gui_explicit_proxy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_dynamic_routing": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_sslvpn_personal_bookmarks": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_sslvpn_realms": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_policy_based_ipsec": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_threat_weight": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_spamfilter": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_file_filter": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_application_control": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_ips": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_dhcp_advanced": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_vpn": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_sslvpn": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_wireless_controller": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_advanced_wireless_features": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_switch_controller": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_fortiap_split_tunneling": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_webfilter_advanced": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_traffic_shaping": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_wan_load_balancing": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_antivirus": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_webfilter": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_fortitelemetry": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_videofilter": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_dnsfilter": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_waf_profile": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_dlp_profile": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_dlp_advanced": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_virtual_patch_profile": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_casb": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_fortiextender_controller": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_advanced_policy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_allow_unnamed_policy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_email_collection": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_multiple_interface_policy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_policy_disclaimer": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_ztna": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_ot": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_dynamic_device_os_id": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_gtp": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "location_id": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "ike_session_resume": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ike_quick_crash_detect": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ike_dn_format": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "with-space"}, {"value": "no-space"}],
        },
        "ike_port": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "ike_tcp_port": {"v_range": [["v7.4.2", ""]], "type": "integer"},
        "ike_policy_route": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ike_detailed_event_logs": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "block_land_attack": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "default_app_port_as_service": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gtp_asym_fgsp": {
            "v_range": [["v6.2.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "gtp_monitor_mode": {
            "v_range": [["v6.2.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pfcp_monitor_mode": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fqdn_session_check": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ext_resource_session_check": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dyn_addr_session_check": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "default_policy_expiry_days": {"v_range": [["v7.2.0", ""]], "type": "integer"},
        "gui_enforce_change_summary": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "require"},
                {"value": "optional"},
            ],
        },
        "internet_service_database_cache": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "internet_service_app_ctrl_size": {
            "v_range": [["v7.4.4", ""]],
            "type": "integer",
        },
        "application_bandwidth_tracking": {
            "v_range": [["v7.0.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "gui_proxy_inspection": {
            "v_range": [["v7.2.4", "v7.4.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "policy_offload_level": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "dos-offload"}],
        },
        "gui_endpoint_control": {
            "v_range": [["v6.0.0", "v7.2.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_endpoint_control_advanced": {
            "v_range": [["v6.0.0", "v7.2.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_local_reports": {
            "v_range": [["v6.0.0", "v7.2.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_nat46_64": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_replacement_message_groups": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_dynamic_profile_display": {
            "v_range": [["v6.0.0", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_multiple_utm_profiles": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_domain_ip_reputation": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "implicit_allow_dns": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "consolidated_firewall_mode": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_per_policy_disclaimer": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "inspection_mode": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "proxy"}, {"value": "flow"}],
        },
        "ssl_ssh_profile": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
        "sip_helper": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_dlp": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_policy_learning": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "compliance_check": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "system_settings": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_settings"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_settings"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_settings"
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
