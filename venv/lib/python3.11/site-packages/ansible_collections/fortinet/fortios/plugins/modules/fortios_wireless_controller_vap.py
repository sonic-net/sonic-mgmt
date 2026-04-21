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
module: fortios_wireless_controller_vap
short_description: Configure Virtual Access Points (VAPs) in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and vap category.
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
    wireless_controller_vap:
        description:
            - Configure Virtual Access Points (VAPs).
        default: null
        type: dict
        suboptions:
            access_control_list:
                description:
                    - Profile name for access-control-list. Source wireless-controller.access-control-list.name.
                type: str
            acct_interim_interval:
                description:
                    - WiFi RADIUS accounting interim interval (60 - 86400 sec).
                type: int
            additional_akms:
                description:
                    - Additional AKMs.
                type: list
                elements: str
                choices:
                    - 'akm6'
                    - 'akm24'
            address_group:
                description:
                    - Firewall Address Group Name. Source firewall.addrgrp.name.
                type: str
            address_group_policy:
                description:
                    - Configure MAC address filtering policy for MAC addresses that are in the address-group.
                type: str
                choices:
                    - 'disable'
                    - 'allow'
                    - 'deny'
            akm24_only:
                description:
                    - WPA3 SAE using group-dependent hash only .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            alias:
                description:
                    - Alias.
                type: str
            antivirus_profile:
                description:
                    - AntiVirus profile name. Source antivirus.profile.name.
                type: str
            application_detection_engine:
                description:
                    - Enable/disable application detection engine .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            application_dscp_marking:
                description:
                    - Enable/disable application attribute based DSCP marking .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            application_list:
                description:
                    - Application control list name. Source application.list.name.
                type: str
            application_report_intv:
                description:
                    - Application report interval (30 - 864000 sec).
                type: int
            atf_weight:
                description:
                    - Airtime weight in percentage .
                type: int
            auth:
                description:
                    - Authentication protocol.
                type: str
                choices:
                    - 'radius'
                    - 'usergroup'
                    - 'psk'
            auth_cert:
                description:
                    - HTTPS server certificate. Source vpn.certificate.local.name.
                type: str
            auth_portal_addr:
                description:
                    - Address of captive portal.
                type: str
            beacon_advertising:
                description:
                    - Fortinet beacon advertising IE data   .
                type: list
                elements: str
                choices:
                    - 'name'
                    - 'model'
                    - 'serial-number'
            beacon_protection:
                description:
                    - Enable/disable beacon protection support .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            broadcast_ssid:
                description:
                    - Enable/disable broadcasting the SSID .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            broadcast_suppression:
                description:
                    - Optional suppression of broadcast messages. For example, you can keep DHCP messages, ARP broadcasts, and so on off of the wireless
                       network.
                type: list
                elements: str
                choices:
                    - 'dhcp-up'
                    - 'dhcp-down'
                    - 'dhcp-starvation'
                    - 'dhcp-ucast'
                    - 'arp-known'
                    - 'arp-unknown'
                    - 'arp-reply'
                    - 'arp-poison'
                    - 'arp-proxy'
                    - 'netbios-ns'
                    - 'netbios-ds'
                    - 'ipv6'
                    - 'all-other-mc'
                    - 'all-other-bc'
            bss_color_partial:
                description:
                    - Enable/disable 802.11ax partial BSS color .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bstm_disassociation_imminent:
                description:
                    - Enable/disable forcing of disassociation after the BSTM request timer has been reached .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bstm_load_balancing_disassoc_timer:
                description:
                    - Time interval for client to voluntarily leave AP before forcing a disassociation due to AP load-balancing (0 to 30).
                type: int
            bstm_rssi_disassoc_timer:
                description:
                    - Time interval for client to voluntarily leave AP before forcing a disassociation due to low RSSI (0 to 2000).
                type: int
            called_station_id_type:
                description:
                    - The format type of RADIUS attribute Called-Station-Id .
                type: str
                choices:
                    - 'mac'
                    - 'ip'
                    - 'apname'
            captive_network_assistant_bypass:
                description:
                    - Enable/disable Captive Network Assistant bypass.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            captive_portal:
                description:
                    - Enable/disable captive portal.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            captive_portal_ac_name:
                description:
                    - Local-bridging captive portal ac-name.
                type: str
            captive_portal_auth_timeout:
                description:
                    - Hard timeout - AP will always clear the session after timeout regardless of traffic (0 - 864000 sec).
                type: int
            captive_portal_fw_accounting:
                description:
                    - Enable/disable RADIUS accounting for captive portal firewall authentication session.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            captive_portal_macauth_radius_secret:
                description:
                    - Secret key to access the macauth RADIUS server.
                type: str
            captive_portal_macauth_radius_server:
                description:
                    - Captive portal external RADIUS server domain name or IP address.
                type: str
            captive_portal_radius_secret:
                description:
                    - Secret key to access the RADIUS server.
                type: str
            captive_portal_radius_server:
                description:
                    - Captive portal RADIUS server domain name or IP address.
                type: str
            captive_portal_session_timeout_interval:
                description:
                    - Session timeout interval (0 - 864000 sec).
                type: int
            dhcp_address_enforcement:
                description:
                    - Enable/disable DHCP address enforcement .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dhcp_lease_time:
                description:
                    - DHCP lease time in seconds for NAT IP address.
                type: int
            dhcp_option43_insertion:
                description:
                    - Enable/disable insertion of DHCP option 43 .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dhcp_option82_circuit_id_insertion:
                description:
                    - Enable/disable DHCP option 82 circuit-id insert .
                type: str
                choices:
                    - 'style-1'
                    - 'style-2'
                    - 'style-3'
                    - 'disable'
            dhcp_option82_insertion:
                description:
                    - Enable/disable DHCP option 82 insert .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dhcp_option82_remote_id_insertion:
                description:
                    - Enable/disable DHCP option 82 remote-id insert .
                type: str
                choices:
                    - 'style-1'
                    - 'disable'
            domain_name_stripping:
                description:
                    - Enable/disable stripping domain name from identity .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            dynamic_vlan:
                description:
                    - Enable/disable dynamic VLAN assignment.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eap_reauth:
                description:
                    - Enable/disable EAP re-authentication for WPA-Enterprise security.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eap_reauth_intv:
                description:
                    - EAP re-authentication interval (1800 - 864000 sec).
                type: int
            eapol_key_retries:
                description:
                    - Enable/disable retransmission of EAPOL-Key frames (message 3/4 and group message 1/2) .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            encrypt:
                description:
                    - Encryption protocol to use (only available when security is set to a WPA type).
                type: str
                choices:
                    - 'TKIP'
                    - 'AES'
                    - 'TKIP-AES'
            external_fast_roaming:
                description:
                    - Enable/disable fast roaming or pre-authentication with external APs not managed by the FortiGate .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            external_logout:
                description:
                    - URL of external authentication logout server.
                type: str
            external_pre_auth:
                description:
                    - Enable/disable pre-authentication with external APs not managed by the FortiGate .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            external_web:
                description:
                    - URL of external authentication web server.
                type: str
            external_web_format:
                description:
                    - URL query parameter detection .
                type: str
                choices:
                    - 'auto-detect'
                    - 'no-query-string'
                    - 'partial-query-string'
            fast_bss_transition:
                description:
                    - Enable/disable 802.11r Fast BSS Transition (FT) .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            fast_roaming:
                description:
                    - Enable/disable fast-roaming, or pre-authentication, where supported by clients .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ft_mobility_domain:
                description:
                    - Mobility domain identifier in FT (1 - 65535).
                type: int
            ft_over_ds:
                description:
                    - Enable/disable FT over the Distribution System (DS).
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ft_r0_key_lifetime:
                description:
                    - Lifetime of the PMK-R0 key in FT, 1-65535 minutes.
                type: int
            gas_comeback_delay:
                description:
                    - GAS comeback delay (0 or 100 - 10000 milliseconds).
                type: int
            gas_fragmentation_limit:
                description:
                    - GAS fragmentation limit (512 - 4096).
                type: int
            gtk_rekey:
                description:
                    - Enable/disable GTK rekey for WPA security.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gtk_rekey_intv:
                description:
                    - GTK rekey interval (600 - 864000 sec).
                type: int
            high_efficiency:
                description:
                    - Enable/disable 802.11ax high efficiency .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            hotspot20_profile:
                description:
                    - Hotspot 2.0 profile name. Source wireless-controller.hotspot20.hs-profile.name.
                type: str
            igmp_snooping:
                description:
                    - Enable/disable IGMP snooping.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            intra_vap_privacy:
                description:
                    - Enable/disable blocking communication between clients on the same SSID (called intra-SSID privacy) .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ip:
                description:
                    - IP address and subnet mask for the local standalone NAT subnet.
                type: str
            ips_sensor:
                description:
                    - IPS sensor name. Source ips.sensor.name.
                type: str
            ipv6_rules:
                description:
                    - Optional rules of IPv6 packets. For example, you can keep RA, RS and so on off of the wireless network.
                type: list
                elements: str
                choices:
                    - 'drop-icmp6ra'
                    - 'drop-icmp6rs'
                    - 'drop-llmnr6'
                    - 'drop-icmp6mld2'
                    - 'drop-dhcp6s'
                    - 'drop-dhcp6c'
                    - 'ndp-proxy'
                    - 'drop-ns-dad'
                    - 'drop-ns-nondad'
            key:
                description:
                    - WEP Key.
                type: str
            keyindex:
                description:
                    - WEP key index (1 - 4).
                type: int
            l3_roaming:
                description:
                    - Enable/disable layer 3 roaming .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            l3_roaming_mode:
                description:
                    - Select the way that layer 3 roaming traffic is passed .
                type: str
                choices:
                    - 'direct'
                    - 'indirect'
            ldpc:
                description:
                    - VAP low-density parity-check (LDPC) coding configuration.
                type: str
                choices:
                    - 'disable'
                    - 'rx'
                    - 'tx'
                    - 'rxtx'
            local_authentication:
                description:
                    - Enable/disable AP local authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_bridging:
                description:
                    - Enable/disable bridging of wireless and Ethernet interfaces on the FortiAP .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_lan:
                description:
                    - Allow/deny traffic destined for a Class A, B, or C private IP address .
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            local_lan_partition:
                description:
                    - Enable/disable segregating client traffic to local LAN side .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_standalone:
                description:
                    - Enable/disable AP local standalone .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_standalone_dns:
                description:
                    - Enable/disable AP local standalone DNS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_standalone_dns_ip:
                description:
                    - IPv4 addresses for the local standalone DNS.
                type: list
                elements: str
            local_standalone_nat:
                description:
                    - Enable/disable AP local standalone NAT mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mac_auth_bypass:
                description:
                    - Enable/disable MAC authentication bypass.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mac_called_station_delimiter:
                description:
                    - MAC called station delimiter .
                type: str
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac_calling_station_delimiter:
                description:
                    - MAC calling station delimiter .
                type: str
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac_case:
                description:
                    - MAC case .
                type: str
                choices:
                    - 'uppercase'
                    - 'lowercase'
            mac_filter:
                description:
                    - Enable/disable MAC filtering to block wireless clients by mac address.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mac_filter_list:
                description:
                    - Create a list of MAC addresses for MAC address filtering.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    mac:
                        description:
                            - MAC address.
                        type: str
                    mac_filter_policy:
                        description:
                            - Deny or allow the client with this MAC address.
                        type: str
                        choices:
                            - 'allow'
                            - 'deny'
            mac_filter_policy_other:
                description:
                    - Allow or block clients with MAC addresses that are not in the filter list.
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            mac_password_delimiter:
                description:
                    - MAC authentication password delimiter .
                type: str
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac_username_delimiter:
                description:
                    - MAC authentication username delimiter .
                type: str
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            max_clients:
                description:
                    - Maximum number of clients that can connect simultaneously to the VAP .
                type: int
            max_clients_ap:
                description:
                    - Maximum number of clients that can connect simultaneously to the VAP per AP radio .
                type: int
            mbo:
                description:
                    - Enable/disable Multiband Operation .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            mbo_cell_data_conn_pref:
                description:
                    - MBO cell data connection preference (0, 1, or 255).
                type: str
                choices:
                    - 'excluded'
                    - 'prefer-not'
                    - 'prefer-use'
            me_disable_thresh:
                description:
                    - Disable multicast enhancement when this many clients are receiving multicast traffic.
                type: int
            mesh_backhaul:
                description:
                    - Enable/disable using this VAP as a WiFi mesh backhaul . This entry is only available when security is set to a WPA type or open.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mpsk:
                description:
                    - Enable/disable multiple PSK authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mpsk_concurrent_clients:
                description:
                    - Maximum number of concurrent clients that connect using the same passphrase in multiple PSK authentication (0 - 65535).
                type: int
            mpsk_key:
                description:
                    - List of multiple PSK entries.
                type: list
                elements: dict
                suboptions:
                    comment:
                        description:
                            - Comment.
                        type: str
                    concurrent_clients:
                        description:
                            - Number of clients that can connect using this pre-shared key.
                        type: str
                    key_name:
                        description:
                            - Pre-shared key name.
                        required: true
                        type: str
                    mpsk_schedules:
                        description:
                            - Firewall schedule for MPSK passphrase. The passphrase will be effective only when at least one schedule is valid.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Schedule name. Source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime.name.
                                required: true
                                type: str
                    passphrase:
                        description:
                            - WPA Pre-shared key.
                        type: str
            mpsk_profile:
                description:
                    - MPSK profile name. Source wireless-controller.mpsk-profile.name.
                type: str
            mu_mimo:
                description:
                    - Enable/disable Multi-user MIMO .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            multicast_enhance:
                description:
                    - Enable/disable converting multicast to unicast to improve performance .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            multicast_rate:
                description:
                    - Multicast rate (0, 6000, 12000, or 24000 kbps).
                type: str
                choices:
                    - '0'
                    - '6000'
                    - '12000'
                    - '24000'
            nac:
                description:
                    - Enable/disable network access control.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            nac_profile:
                description:
                    - NAC profile name. Source wireless-controller.nac-profile.name.
                type: str
            name:
                description:
                    - Virtual AP name.
                required: true
                type: str
            nas_filter_rule:
                description:
                    - Enable/disable NAS filter rule support .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            neighbor_report_dual_band:
                description:
                    - Enable/disable dual-band neighbor report .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            okc:
                description:
                    - Enable/disable Opportunistic Key Caching (OKC) .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            osen:
                description:
                    - Enable/disable OSEN as part of key management .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            owe_groups:
                description:
                    - OWE-Groups.
                type: list
                elements: str
                choices:
                    - '19'
                    - '20'
                    - '21'
            owe_transition:
                description:
                    - Enable/disable OWE transition mode support.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            owe_transition_ssid:
                description:
                    - OWE transition mode peer SSID.
                type: str
            passphrase:
                description:
                    - WPA pre-shared key (PSK) to be used to authenticate WiFi users.
                type: str
            pmf:
                description:
                    - Protected Management Frames (PMF) support .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
                    - 'optional'
            pmf_assoc_comeback_timeout:
                description:
                    - Protected Management Frames (PMF) comeback maximum timeout (1-20 sec).
                type: int
            pmf_sa_query_retry_timeout:
                description:
                    - Protected Management Frames (PMF) SA query retry timeout interval (1 - 5 100s of msec).
                type: int
            port_macauth:
                description:
                    - Enable/disable LAN port MAC authentication .
                type: str
                choices:
                    - 'disable'
                    - 'radius'
                    - 'address-group'
            port_macauth_reauth_timeout:
                description:
                    - LAN port MAC authentication re-authentication timeout value .
                type: int
            port_macauth_timeout:
                description:
                    - LAN port MAC authentication idle timeout value .
                type: int
            portal_message_override_group:
                description:
                    - Replacement message group for this VAP (only available when security is set to a captive portal type). Source system.replacemsg-group
                      .name.
                type: str
            portal_message_overrides:
                description:
                    - Individual message overrides.
                type: dict
                suboptions:
                    auth_disclaimer_page:
                        description:
                            - Override auth-disclaimer-page message with message from portal-message-overrides group.
                        type: str
                    auth_login_failed_page:
                        description:
                            - Override auth-login-failed-page message with message from portal-message-overrides group.
                        type: str
                    auth_login_page:
                        description:
                            - Override auth-login-page message with message from portal-message-overrides group.
                        type: str
                    auth_reject_page:
                        description:
                            - Override auth-reject-page message with message from portal-message-overrides group.
                        type: str
            portal_type:
                description:
                    - Captive portal functionality. Configure how the captive portal authenticates users and whether it includes a disclaimer.
                type: str
                choices:
                    - 'auth'
                    - 'auth+disclaimer'
                    - 'disclaimer'
                    - 'email-collect'
                    - 'cmcc'
                    - 'cmcc-macauth'
                    - 'auth-mac'
                    - 'external-auth'
                    - 'external-macauth'
            pre_auth:
                description:
                    - Enable/disable pre-authentication, where supported by clients .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            primary_wag_profile:
                description:
                    - Primary wireless access gateway profile name. Source wireless-controller.wag-profile.name.
                type: str
            probe_resp_suppression:
                description:
                    - Enable/disable probe response suppression (to ignore weak signals) .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            probe_resp_threshold:
                description:
                    - Minimum signal level/threshold in dBm required for the AP response to probe requests (-95 to -20).
                type: str
            ptk_rekey:
                description:
                    - Enable/disable PTK rekey for WPA-Enterprise security.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ptk_rekey_intv:
                description:
                    - PTK rekey interval (600 - 864000 sec).
                type: int
            qos_profile:
                description:
                    - Quality of service profile name. Source wireless-controller.qos-profile.name.
                type: str
            quarantine:
                description:
                    - Enable/disable station quarantine .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            radio_2g_threshold:
                description:
                    - Minimum signal level/threshold in dBm required for the AP response to receive a packet in 2.4G band (-95 to -20).
                type: str
            radio_5g_threshold:
                description:
                    - Minimum signal level/threshold in dBm required for the AP response to receive a packet in 5G band(-95 to -20).
                type: str
            radio_sensitivity:
                description:
                    - Enable/disable software radio sensitivity (to ignore weak signals) .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            radius_mac_auth:
                description:
                    - Enable/disable RADIUS-based MAC authentication of clients .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            radius_mac_auth_block_interval:
                description:
                    - Don"t send RADIUS MAC auth request again if the client has been rejected within specific interval (0 or 30 - 864000 seconds).
                type: int
            radius_mac_auth_server:
                description:
                    - RADIUS-based MAC authentication server. Source user.radius.name.
                type: str
            radius_mac_auth_usergroups:
                description:
                    - Selective user groups that are permitted for RADIUS mac authentication.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - User group name. Source user.group.name.
                        required: true
                        type: str
            radius_mac_mpsk_auth:
                description:
                    - Enable/disable RADIUS-based MAC authentication of clients for MPSK authentication .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            radius_mac_mpsk_timeout:
                description:
                    - RADIUS MAC MPSK cache timeout interval (0 or 300 - 864000).
                type: int
            radius_server:
                description:
                    - RADIUS server to be used to authenticate WiFi users. Source user.radius.name.
                type: str
            rates_11a:
                description:
                    - Allowed data rates for 802.11a.
                type: list
                elements: str
                choices:
                    - '6'
                    - '6-basic'
                    - '9'
                    - '9-basic'
                    - '12'
                    - '12-basic'
                    - '18'
                    - '18-basic'
                    - '24'
                    - '24-basic'
                    - '36'
                    - '36-basic'
                    - '48'
                    - '48-basic'
                    - '54'
                    - '54-basic'
                    - '1'
                    - '1-basic'
                    - '2'
                    - '2-basic'
                    - '5.5'
                    - '5.5-basic'
                    - '11'
                    - '11-basic'
            rates_11ac_mcs_map:
                description:
                    - Comma separated list of max supported VHT MCS for spatial streams 1 through 8.
                type: str
            rates_11ac_ss12:
                description:
                    - Allowed data rates for 802.11ac with 1 or 2 spatial streams.
                type: list
                elements: str
                choices:
                    - 'mcs0/1'
                    - 'mcs1/1'
                    - 'mcs2/1'
                    - 'mcs3/1'
                    - 'mcs4/1'
                    - 'mcs5/1'
                    - 'mcs6/1'
                    - 'mcs7/1'
                    - 'mcs8/1'
                    - 'mcs9/1'
                    - 'mcs10/1'
                    - 'mcs11/1'
                    - 'mcs0/2'
                    - 'mcs1/2'
                    - 'mcs2/2'
                    - 'mcs3/2'
                    - 'mcs4/2'
                    - 'mcs5/2'
                    - 'mcs6/2'
                    - 'mcs7/2'
                    - 'mcs8/2'
                    - 'mcs9/2'
                    - 'mcs10/2'
                    - 'mcs11/2'
            rates_11ac_ss34:
                description:
                    - Allowed data rates for 802.11ac with 3 or 4 spatial streams.
                type: list
                elements: str
                choices:
                    - 'mcs0/3'
                    - 'mcs1/3'
                    - 'mcs2/3'
                    - 'mcs3/3'
                    - 'mcs4/3'
                    - 'mcs5/3'
                    - 'mcs6/3'
                    - 'mcs7/3'
                    - 'mcs8/3'
                    - 'mcs9/3'
                    - 'mcs10/3'
                    - 'mcs11/3'
                    - 'mcs0/4'
                    - 'mcs1/4'
                    - 'mcs2/4'
                    - 'mcs3/4'
                    - 'mcs4/4'
                    - 'mcs5/4'
                    - 'mcs6/4'
                    - 'mcs7/4'
                    - 'mcs8/4'
                    - 'mcs9/4'
                    - 'mcs10/4'
                    - 'mcs11/4'
            rates_11ax_mcs_map:
                description:
                    - Comma separated list of max supported HE MCS for spatial streams 1 through 8.
                type: str
            rates_11ax_ss12:
                description:
                    - Allowed data rates for 802.11ax with 1 or 2 spatial streams.
                type: list
                elements: str
                choices:
                    - 'mcs0/1'
                    - 'mcs1/1'
                    - 'mcs2/1'
                    - 'mcs3/1'
                    - 'mcs4/1'
                    - 'mcs5/1'
                    - 'mcs6/1'
                    - 'mcs7/1'
                    - 'mcs8/1'
                    - 'mcs9/1'
                    - 'mcs10/1'
                    - 'mcs11/1'
                    - 'mcs0/2'
                    - 'mcs1/2'
                    - 'mcs2/2'
                    - 'mcs3/2'
                    - 'mcs4/2'
                    - 'mcs5/2'
                    - 'mcs6/2'
                    - 'mcs7/2'
                    - 'mcs8/2'
                    - 'mcs9/2'
                    - 'mcs10/2'
                    - 'mcs11/2'
            rates_11ax_ss34:
                description:
                    - Allowed data rates for 802.11ax with 3 or 4 spatial streams.
                type: list
                elements: str
                choices:
                    - 'mcs0/3'
                    - 'mcs1/3'
                    - 'mcs2/3'
                    - 'mcs3/3'
                    - 'mcs4/3'
                    - 'mcs5/3'
                    - 'mcs6/3'
                    - 'mcs7/3'
                    - 'mcs8/3'
                    - 'mcs9/3'
                    - 'mcs10/3'
                    - 'mcs11/3'
                    - 'mcs0/4'
                    - 'mcs1/4'
                    - 'mcs2/4'
                    - 'mcs3/4'
                    - 'mcs4/4'
                    - 'mcs5/4'
                    - 'mcs6/4'
                    - 'mcs7/4'
                    - 'mcs8/4'
                    - 'mcs9/4'
                    - 'mcs10/4'
                    - 'mcs11/4'
            rates_11be_mcs_map:
                description:
                    - Comma separated list of max nss that supports EHT-MCS 0-9, 10-11, 12-13 for 20MHz/40MHz/80MHz bandwidth.
                type: str
            rates_11be_mcs_map_160:
                description:
                    - Comma separated list of max nss that supports EHT-MCS 0-9, 10-11, 12-13 for 160MHz bandwidth.
                type: str
            rates_11be_mcs_map_320:
                description:
                    - Comma separated list of max nss that supports EHT-MCS 0-9, 10-11, 12-13 for 320MHz bandwidth.
                type: str
            rates_11bg:
                description:
                    - Allowed data rates for 802.11b/g.
                type: list
                elements: str
                choices:
                    - '1'
                    - '1-basic'
                    - '2'
                    - '2-basic'
                    - '5.5'
                    - '5.5-basic'
                    - '11'
                    - '11-basic'
                    - '6'
                    - '6-basic'
                    - '9'
                    - '9-basic'
                    - '12'
                    - '12-basic'
                    - '18'
                    - '18-basic'
                    - '24'
                    - '24-basic'
                    - '36'
                    - '36-basic'
                    - '48'
                    - '48-basic'
                    - '54'
                    - '54-basic'
            rates_11n_ss12:
                description:
                    - Allowed data rates for 802.11n with 1 or 2 spatial streams.
                type: list
                elements: str
                choices:
                    - 'mcs0/1'
                    - 'mcs1/1'
                    - 'mcs2/1'
                    - 'mcs3/1'
                    - 'mcs4/1'
                    - 'mcs5/1'
                    - 'mcs6/1'
                    - 'mcs7/1'
                    - 'mcs8/2'
                    - 'mcs9/2'
                    - 'mcs10/2'
                    - 'mcs11/2'
                    - 'mcs12/2'
                    - 'mcs13/2'
                    - 'mcs14/2'
                    - 'mcs15/2'
            rates_11n_ss34:
                description:
                    - Allowed data rates for 802.11n with 3 or 4 spatial streams.
                type: list
                elements: str
                choices:
                    - 'mcs16/3'
                    - 'mcs17/3'
                    - 'mcs18/3'
                    - 'mcs19/3'
                    - 'mcs20/3'
                    - 'mcs21/3'
                    - 'mcs22/3'
                    - 'mcs23/3'
                    - 'mcs24/4'
                    - 'mcs25/4'
                    - 'mcs26/4'
                    - 'mcs27/4'
                    - 'mcs28/4'
                    - 'mcs29/4'
                    - 'mcs30/4'
                    - 'mcs31/4'
            roaming_acct_interim_update:
                description:
                    - Enable/disable using accounting interim update instead of accounting start/stop on roaming for WPA-Enterprise security.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sae_groups:
                description:
                    - SAE-Groups.
                type: list
                elements: str
                choices:
                    - '19'
                    - '20'
                    - '21'
                    - '1'
                    - '2'
                    - '5'
                    - '14'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '27'
                    - '28'
                    - '29'
                    - '30'
                    - '31'
            sae_h2e_only:
                description:
                    - Use hash-to-element-only mechanism for PWE derivation .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sae_hnp_only:
                description:
                    - Use hunting-and-pecking-only mechanism for PWE derivation .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sae_password:
                description:
                    - WPA3 SAE password to be used to authenticate WiFi users.
                type: str
            sae_pk:
                description:
                    - Enable/disable WPA3 SAE-PK .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sae_private_key:
                description:
                    - Private key used for WPA3 SAE-PK authentication.
                type: str
            scan_botnet_connections:
                description:
                    - Block or monitor connections to Botnet servers or disable Botnet scanning.
                type: str
                choices:
                    - 'disable'
                    - 'monitor'
                    - 'block'
            schedule:
                description:
                    - Firewall schedules for enabling this VAP on the FortiAP. This VAP will be enabled when at least one of the schedules is valid. Separate
                       multiple schedule names with a space.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Schedule name. Source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime.name.
                        required: true
                        type: str
            secondary_wag_profile:
                description:
                    - Secondary wireless access gateway profile name. Source wireless-controller.wag-profile.name.
                type: str
            security:
                description:
                    - Security mode for the wireless interface .
                type: str
                choices:
                    - 'open'
                    - 'wep64'
                    - 'wep128'
                    - 'wpa-personal'
                    - 'wpa-enterprise'
                    - 'wpa-only-personal'
                    - 'wpa-only-enterprise'
                    - 'wpa2-only-personal'
                    - 'wpa2-only-enterprise'
                    - 'wpa3-enterprise'
                    - 'wpa3-only-enterprise'
                    - 'wpa3-enterprise-transition'
                    - 'wpa3-sae'
                    - 'wpa3-sae-transition'
                    - 'owe'
                    - 'osen'
                    - 'captive-portal'
                    - 'wpa-personal+captive-portal'
                    - 'wpa-only-personal+captive-portal'
                    - 'wpa2-only-personal+captive-portal'
            security_exempt_list:
                description:
                    - Optional security exempt list for captive portal authentication. Source user.security-exempt-list.name.
                type: str
            security_obsolete_option:
                description:
                    - Enable/disable obsolete security options.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            security_redirect_url:
                description:
                    - Optional URL for redirecting users after they pass captive portal authentication.
                type: str
            selected_usergroups:
                description:
                    - Selective user groups that are permitted to authenticate.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - User group name. Source user.group.name.
                        required: true
                        type: str
            set_80211k:
                description:
                    - Enable/disable 802.11k assisted roaming .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            set_80211v:
                description:
                    - Enable/disable 802.11v assisted roaming .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            split_tunneling:
                description:
                    - Enable/disable split tunneling .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssid:
                description:
                    - IEEE 802.11 service set identifier (SSID) for the wireless interface. Users who wish to use the wireless network must configure their
                       computers to access this SSID name.
                type: str
            sticky_client_remove:
                description:
                    - Enable/disable sticky client remove to maintain good signal level clients in SSID .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sticky_client_threshold_2g:
                description:
                    - Minimum signal level/threshold in dBm required for the 2G client to be serviced by the AP (-95 to -20).
                type: str
            sticky_client_threshold_5g:
                description:
                    - Minimum signal level/threshold in dBm required for the 5G client to be serviced by the AP (-95 to -20).
                type: str
            sticky_client_threshold_6g:
                description:
                    - Minimum signal level/threshold in dBm required for the 6G client to be serviced by the AP (-95 to -20).
                type: str
            target_wake_time:
                description:
                    - Enable/disable 802.11ax target wake time .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tkip_counter_measure:
                description:
                    - Enable/disable TKIP counter measure.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tunnel_echo_interval:
                description:
                    - The time interval to send echo to both primary and secondary tunnel peers (1 - 65535 sec).
                type: int
            tunnel_fallback_interval:
                description:
                    - The time interval for secondary tunnel to fall back to primary tunnel (0 - 65535 sec).
                type: int
            usergroup:
                description:
                    - Firewall user group to be used to authenticate WiFi users.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - User group name. Source user.group.name.
                        required: true
                        type: str
            utm_log:
                description:
                    - Enable/disable UTM logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            utm_profile:
                description:
                    - UTM profile name. Source wireless-controller.utm-profile.name.
                type: str
            utm_status:
                description:
                    - Enable to add one or more security profiles (AV, IPS, etc.) to the VAP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vdom:
                description:
                    - Name of the VDOM that the Virtual AP has been added to. Source system.vdom.name.
                type: str
            vlan_auto:
                description:
                    - Enable/disable automatic management of SSID VLAN interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vlan_name:
                description:
                    - Table for mapping VLAN name to VLAN ID.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - VLAN name.
                        required: true
                        type: str
                    vlan_id:
                        description:
                            - VLAN IDs (maximum 8 VLAN IDs).
                        type: list
                        elements: int
            vlan_pool:
                description:
                    - VLAN pool.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    wtp_group:
                        description:
                            - WTP group name. Source wireless-controller.wtp-group.name.
                        type: str
            vlan_pooling:
                description:
                    - Enable/disable VLAN pooling, to allow grouping of multiple wireless controller VLANs into VLAN pools . When set to wtp-group, VLAN
                       pooling occurs with VLAN assignment by wtp-group.
                type: str
                choices:
                    - 'wtp-group'
                    - 'round-robin'
                    - 'hash'
                    - 'disable'
            vlanid:
                description:
                    - Optional VLAN ID.
                type: int
            voice_enterprise:
                description:
                    - Enable/disable 802.11k and 802.11v assisted Voice-Enterprise roaming .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            webfilter_profile:
                description:
                    - WebFilter profile name. Source webfilter.profile.name.
                type: str
"""

EXAMPLES = """
- name: Configure Virtual Access Points (VAPs).
  fortinet.fortios.fortios_wireless_controller_vap:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wireless_controller_vap:
          access_control_list: "<your_own_value> (source wireless-controller.access-control-list.name)"
          acct_interim_interval: "43200"
          additional_akms: "akm6"
          address_group: "<your_own_value> (source firewall.addrgrp.name)"
          address_group_policy: "disable"
          akm24_only: "disable"
          alias: "<your_own_value>"
          antivirus_profile: "<your_own_value> (source antivirus.profile.name)"
          application_detection_engine: "enable"
          application_dscp_marking: "enable"
          application_list: "<your_own_value> (source application.list.name)"
          application_report_intv: "120"
          atf_weight: "20"
          auth: "radius"
          auth_cert: "<your_own_value> (source vpn.certificate.local.name)"
          auth_portal_addr: "<your_own_value>"
          beacon_advertising: "name"
          beacon_protection: "disable"
          broadcast_ssid: "enable"
          broadcast_suppression: "dhcp-up"
          bss_color_partial: "enable"
          bstm_disassociation_imminent: "enable"
          bstm_load_balancing_disassoc_timer: "10"
          bstm_rssi_disassoc_timer: "200"
          called_station_id_type: "mac"
          captive_network_assistant_bypass: "enable"
          captive_portal: "enable"
          captive_portal_ac_name: "<your_own_value>"
          captive_portal_auth_timeout: "0"
          captive_portal_fw_accounting: "enable"
          captive_portal_macauth_radius_secret: "<your_own_value>"
          captive_portal_macauth_radius_server: "<your_own_value>"
          captive_portal_radius_secret: "<your_own_value>"
          captive_portal_radius_server: "<your_own_value>"
          captive_portal_session_timeout_interval: "432000"
          dhcp_address_enforcement: "enable"
          dhcp_lease_time: "2400"
          dhcp_option43_insertion: "enable"
          dhcp_option82_circuit_id_insertion: "style-1"
          dhcp_option82_insertion: "enable"
          dhcp_option82_remote_id_insertion: "style-1"
          domain_name_stripping: "disable"
          dynamic_vlan: "enable"
          eap_reauth: "enable"
          eap_reauth_intv: "86400"
          eapol_key_retries: "disable"
          encrypt: "TKIP"
          external_fast_roaming: "enable"
          external_logout: "<your_own_value>"
          external_pre_auth: "enable"
          external_web: "<your_own_value>"
          external_web_format: "auto-detect"
          fast_bss_transition: "disable"
          fast_roaming: "enable"
          ft_mobility_domain: "1000"
          ft_over_ds: "disable"
          ft_r0_key_lifetime: "480"
          gas_comeback_delay: "500"
          gas_fragmentation_limit: "1024"
          gtk_rekey: "enable"
          gtk_rekey_intv: "86400"
          high_efficiency: "enable"
          hotspot20_profile: "<your_own_value> (source wireless-controller.hotspot20.hs-profile.name)"
          igmp_snooping: "enable"
          intra_vap_privacy: "enable"
          ip: "<your_own_value>"
          ips_sensor: "<your_own_value> (source ips.sensor.name)"
          ipv6_rules: "drop-icmp6ra"
          key: "<your_own_value>"
          keyindex: "1"
          l3_roaming: "enable"
          l3_roaming_mode: "direct"
          ldpc: "disable"
          local_authentication: "enable"
          local_bridging: "enable"
          local_lan: "allow"
          local_lan_partition: "enable"
          local_standalone: "enable"
          local_standalone_dns: "enable"
          local_standalone_dns_ip: "<your_own_value>"
          local_standalone_nat: "enable"
          mac_auth_bypass: "enable"
          mac_called_station_delimiter: "hyphen"
          mac_calling_station_delimiter: "hyphen"
          mac_case: "uppercase"
          mac_filter: "enable"
          mac_filter_list:
              -
                  id: "90"
                  mac: "<your_own_value>"
                  mac_filter_policy: "allow"
          mac_filter_policy_other: "allow"
          mac_password_delimiter: "hyphen"
          mac_username_delimiter: "hyphen"
          max_clients: "0"
          max_clients_ap: "0"
          mbo: "disable"
          mbo_cell_data_conn_pref: "excluded"
          me_disable_thresh: "32"
          mesh_backhaul: "enable"
          mpsk: "enable"
          mpsk_concurrent_clients: "32767"
          mpsk_key:
              -
                  comment: "Comment."
                  concurrent_clients: "<your_own_value>"
                  key_name: "<your_own_value>"
                  mpsk_schedules:
                      -
                          name: "default_name_109 (source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime.name)"
                  passphrase: "<your_own_value>"
          mpsk_profile: "<your_own_value> (source wireless-controller.mpsk-profile.name)"
          mu_mimo: "enable"
          multicast_enhance: "enable"
          multicast_rate: "0"
          nac: "enable"
          nac_profile: "<your_own_value> (source wireless-controller.nac-profile.name)"
          name: "default_name_117"
          nas_filter_rule: "enable"
          neighbor_report_dual_band: "disable"
          okc: "disable"
          osen: "enable"
          owe_groups: "19"
          owe_transition: "disable"
          owe_transition_ssid: "<your_own_value>"
          passphrase: "<your_own_value>"
          pmf: "disable"
          pmf_assoc_comeback_timeout: "1"
          pmf_sa_query_retry_timeout: "2"
          port_macauth: "disable"
          port_macauth_reauth_timeout: "7200"
          port_macauth_timeout: "600"
          portal_message_override_group: "<your_own_value> (source system.replacemsg-group.name)"
          portal_message_overrides:
              auth_disclaimer_page: "<your_own_value>"
              auth_login_failed_page: "<your_own_value>"
              auth_login_page: "<your_own_value>"
              auth_reject_page: "<your_own_value>"
          portal_type: "auth"
          pre_auth: "enable"
          primary_wag_profile: "<your_own_value> (source wireless-controller.wag-profile.name)"
          probe_resp_suppression: "enable"
          probe_resp_threshold: "<your_own_value>"
          ptk_rekey: "enable"
          ptk_rekey_intv: "86400"
          qos_profile: "<your_own_value> (source wireless-controller.qos-profile.name)"
          quarantine: "enable"
          radio_2g_threshold: "<your_own_value>"
          radio_5g_threshold: "<your_own_value>"
          radio_sensitivity: "enable"
          radius_mac_auth: "enable"
          radius_mac_auth_block_interval: "0"
          radius_mac_auth_server: "<your_own_value> (source user.radius.name)"
          radius_mac_auth_usergroups:
              -
                  name: "default_name_154 (source user.group.name)"
          radius_mac_mpsk_auth: "enable"
          radius_mac_mpsk_timeout: "86400"
          radius_server: "<your_own_value> (source user.radius.name)"
          rates_11a: "6"
          rates_11ac_mcs_map: "<your_own_value>"
          rates_11ac_ss12: "mcs0/1"
          rates_11ac_ss34: "mcs0/3"
          rates_11ax_mcs_map: "<your_own_value>"
          rates_11ax_ss12: "mcs0/1"
          rates_11ax_ss34: "mcs0/3"
          rates_11be_mcs_map: "<your_own_value>"
          rates_11be_mcs_map_160: "<your_own_value>"
          rates_11be_mcs_map_320: "<your_own_value>"
          rates_11bg: "1"
          rates_11n_ss12: "mcs0/1"
          rates_11n_ss34: "mcs16/3"
          roaming_acct_interim_update: "enable"
          sae_groups: "19"
          sae_h2e_only: "enable"
          sae_hnp_only: "enable"
          sae_password: "<your_own_value>"
          sae_pk: "enable"
          sae_private_key: "<your_own_value>"
          scan_botnet_connections: "disable"
          schedule:
              -
                  name: "default_name_180 (source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime.name)"
          secondary_wag_profile: "<your_own_value> (source wireless-controller.wag-profile.name)"
          security: "open"
          security_exempt_list: "<your_own_value> (source user.security-exempt-list.name)"
          security_obsolete_option: "enable"
          security_redirect_url: "<your_own_value>"
          selected_usergroups:
              -
                  name: "default_name_187 (source user.group.name)"
          set_80211k: "disable"
          set_80211v: "disable"
          split_tunneling: "enable"
          ssid: "<your_own_value>"
          sticky_client_remove: "enable"
          sticky_client_threshold_2g: "<your_own_value>"
          sticky_client_threshold_5g: "<your_own_value>"
          sticky_client_threshold_6g: "<your_own_value>"
          target_wake_time: "enable"
          tkip_counter_measure: "enable"
          tunnel_echo_interval: "300"
          tunnel_fallback_interval: "7200"
          usergroup:
              -
                  name: "default_name_201 (source user.group.name)"
          utm_log: "enable"
          utm_profile: "<your_own_value> (source wireless-controller.utm-profile.name)"
          utm_status: "enable"
          vdom: "<your_own_value> (source system.vdom.name)"
          vlan_auto: "enable"
          vlan_name:
              -
                  name: "default_name_208"
                  vlan_id: "<your_own_value>"
          vlan_pool:
              -
                  id: "211"
                  wtp_group: "<your_own_value> (source wireless-controller.wtp-group.name)"
          vlan_pooling: "wtp-group"
          vlanid: "0"
          voice_enterprise: "disable"
          webfilter_profile: "<your_own_value> (source webfilter.profile.name)"
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


def filter_wireless_controller_vap_data(json):
    option_list = [
        "access_control_list",
        "acct_interim_interval",
        "additional_akms",
        "address_group",
        "address_group_policy",
        "akm24_only",
        "alias",
        "antivirus_profile",
        "application_detection_engine",
        "application_dscp_marking",
        "application_list",
        "application_report_intv",
        "atf_weight",
        "auth",
        "auth_cert",
        "auth_portal_addr",
        "beacon_advertising",
        "beacon_protection",
        "broadcast_ssid",
        "broadcast_suppression",
        "bss_color_partial",
        "bstm_disassociation_imminent",
        "bstm_load_balancing_disassoc_timer",
        "bstm_rssi_disassoc_timer",
        "called_station_id_type",
        "captive_network_assistant_bypass",
        "captive_portal",
        "captive_portal_ac_name",
        "captive_portal_auth_timeout",
        "captive_portal_fw_accounting",
        "captive_portal_macauth_radius_secret",
        "captive_portal_macauth_radius_server",
        "captive_portal_radius_secret",
        "captive_portal_radius_server",
        "captive_portal_session_timeout_interval",
        "dhcp_address_enforcement",
        "dhcp_lease_time",
        "dhcp_option43_insertion",
        "dhcp_option82_circuit_id_insertion",
        "dhcp_option82_insertion",
        "dhcp_option82_remote_id_insertion",
        "domain_name_stripping",
        "dynamic_vlan",
        "eap_reauth",
        "eap_reauth_intv",
        "eapol_key_retries",
        "encrypt",
        "external_fast_roaming",
        "external_logout",
        "external_pre_auth",
        "external_web",
        "external_web_format",
        "fast_bss_transition",
        "fast_roaming",
        "ft_mobility_domain",
        "ft_over_ds",
        "ft_r0_key_lifetime",
        "gas_comeback_delay",
        "gas_fragmentation_limit",
        "gtk_rekey",
        "gtk_rekey_intv",
        "high_efficiency",
        "hotspot20_profile",
        "igmp_snooping",
        "intra_vap_privacy",
        "ip",
        "ips_sensor",
        "ipv6_rules",
        "key",
        "keyindex",
        "l3_roaming",
        "l3_roaming_mode",
        "ldpc",
        "local_authentication",
        "local_bridging",
        "local_lan",
        "local_lan_partition",
        "local_standalone",
        "local_standalone_dns",
        "local_standalone_dns_ip",
        "local_standalone_nat",
        "mac_auth_bypass",
        "mac_called_station_delimiter",
        "mac_calling_station_delimiter",
        "mac_case",
        "mac_filter",
        "mac_filter_list",
        "mac_filter_policy_other",
        "mac_password_delimiter",
        "mac_username_delimiter",
        "max_clients",
        "max_clients_ap",
        "mbo",
        "mbo_cell_data_conn_pref",
        "me_disable_thresh",
        "mesh_backhaul",
        "mpsk",
        "mpsk_concurrent_clients",
        "mpsk_key",
        "mpsk_profile",
        "mu_mimo",
        "multicast_enhance",
        "multicast_rate",
        "nac",
        "nac_profile",
        "name",
        "nas_filter_rule",
        "neighbor_report_dual_band",
        "okc",
        "osen",
        "owe_groups",
        "owe_transition",
        "owe_transition_ssid",
        "passphrase",
        "pmf",
        "pmf_assoc_comeback_timeout",
        "pmf_sa_query_retry_timeout",
        "port_macauth",
        "port_macauth_reauth_timeout",
        "port_macauth_timeout",
        "portal_message_override_group",
        "portal_message_overrides",
        "portal_type",
        "pre_auth",
        "primary_wag_profile",
        "probe_resp_suppression",
        "probe_resp_threshold",
        "ptk_rekey",
        "ptk_rekey_intv",
        "qos_profile",
        "quarantine",
        "radio_2g_threshold",
        "radio_5g_threshold",
        "radio_sensitivity",
        "radius_mac_auth",
        "radius_mac_auth_block_interval",
        "radius_mac_auth_server",
        "radius_mac_auth_usergroups",
        "radius_mac_mpsk_auth",
        "radius_mac_mpsk_timeout",
        "radius_server",
        "rates_11a",
        "rates_11ac_mcs_map",
        "rates_11ac_ss12",
        "rates_11ac_ss34",
        "rates_11ax_mcs_map",
        "rates_11ax_ss12",
        "rates_11ax_ss34",
        "rates_11be_mcs_map",
        "rates_11be_mcs_map_160",
        "rates_11be_mcs_map_320",
        "rates_11bg",
        "rates_11n_ss12",
        "rates_11n_ss34",
        "roaming_acct_interim_update",
        "sae_groups",
        "sae_h2e_only",
        "sae_hnp_only",
        "sae_password",
        "sae_pk",
        "sae_private_key",
        "scan_botnet_connections",
        "schedule",
        "secondary_wag_profile",
        "security",
        "security_exempt_list",
        "security_obsolete_option",
        "security_redirect_url",
        "selected_usergroups",
        "set_80211k",
        "set_80211v",
        "split_tunneling",
        "ssid",
        "sticky_client_remove",
        "sticky_client_threshold_2g",
        "sticky_client_threshold_5g",
        "sticky_client_threshold_6g",
        "target_wake_time",
        "tkip_counter_measure",
        "tunnel_echo_interval",
        "tunnel_fallback_interval",
        "usergroup",
        "utm_log",
        "utm_profile",
        "utm_status",
        "vdom",
        "vlan_auto",
        "vlan_name",
        "vlan_pool",
        "vlan_pooling",
        "vlanid",
        "voice_enterprise",
        "webfilter_profile",
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
        ["sae_groups"],
        ["owe_groups"],
        ["additional_akms"],
        ["local_standalone_dns_ip"],
        ["broadcast_suppression"],
        ["ipv6_rules"],
        ["vlan_name", "vlan_id"],
        ["rates_11a"],
        ["rates_11bg"],
        ["rates_11n_ss12"],
        ["rates_11n_ss34"],
        ["beacon_advertising"],
        ["rates_11ac_ss12"],
        ["rates_11ac_ss34"],
        ["rates_11ax_ss12"],
        ["rates_11ax_ss34"],
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


def valid_attr_to_invalid_attr(data):
    speciallist = {"80211k": "set_80211k", "80211v": "set_80211v"}

    for k, v in speciallist.items():
        if v == data:
            return k

    return data


def valid_attr_to_invalid_attrs(data):
    if isinstance(data, list):
        new_data = []
        for elem in data:
            elem = valid_attr_to_invalid_attrs(elem)
            new_data.append(elem)
        data = new_data
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[valid_attr_to_invalid_attr(k)] = valid_attr_to_invalid_attrs(v)
        data = new_data

    return valid_attr_to_invalid_attr(data)


def wireless_controller_vap(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    wireless_controller_vap_data = data["wireless_controller_vap"]

    filtered_data = filter_wireless_controller_vap_data(wireless_controller_vap_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("wireless-controller", "vap", filtered_data, vdom=vdom)
        current_data = fos.get("wireless-controller", "vap", vdom=vdom, mkey=mkey)
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
    data_copy["wireless_controller_vap"] = filtered_data
    fos.do_member_operation(
        "wireless-controller",
        "vap",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("wireless-controller", "vap", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "wireless-controller", "vap", mkey=converted_data["name"], vdom=vdom
        )
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


def fortios_wireless_controller(data, fos, check_mode):

    if data["wireless_controller_vap"]:
        resp = wireless_controller_vap(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("wireless_controller_vap"))
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
        "pre_auth": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "external_pre_auth": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mesh_backhaul": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "atf_weight": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "max_clients": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "max_clients_ap": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ssid": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "broadcast_ssid": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "security": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "open"},
                {"value": "wep64"},
                {"value": "wep128"},
                {"value": "wpa-personal"},
                {"value": "wpa-enterprise"},
                {"value": "wpa-only-personal"},
                {"value": "wpa-only-enterprise"},
                {"value": "wpa2-only-personal"},
                {"value": "wpa2-only-enterprise"},
                {"value": "wpa3-enterprise", "v_range": [["v6.2.0", ""]]},
                {"value": "wpa3-only-enterprise", "v_range": [["v7.0.0", ""]]},
                {"value": "wpa3-enterprise-transition", "v_range": [["v7.0.0", ""]]},
                {"value": "wpa3-sae", "v_range": [["v6.2.0", ""]]},
                {"value": "wpa3-sae-transition", "v_range": [["v6.2.0", ""]]},
                {"value": "owe", "v_range": [["v6.2.0", ""]]},
                {"value": "osen"},
                {"value": "captive-portal", "v_range": [["v6.0.0", "v7.4.3"]]},
                {
                    "value": "wpa-personal+captive-portal",
                    "v_range": [["v6.0.0", "v7.4.3"]],
                },
                {
                    "value": "wpa-only-personal+captive-portal",
                    "v_range": [["v6.0.0", "v7.4.3"]],
                },
                {
                    "value": "wpa2-only-personal+captive-portal",
                    "v_range": [["v6.0.0", "v7.4.3"]],
                },
            ],
        },
        "pmf": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "enable"},
                {"value": "optional"},
            ],
        },
        "pmf_assoc_comeback_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "pmf_sa_query_retry_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "beacon_protection": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "okc": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "mbo": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "gas_comeback_delay": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "gas_fragmentation_limit": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "mbo_cell_data_conn_pref": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "excluded"},
                {"value": "prefer-not"},
                {"value": "prefer-use"},
            ],
        },
        "neighbor_report_dual_band": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "fast_bss_transition": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ft_mobility_domain": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ft_r0_key_lifetime": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ft_over_ds": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "sae_groups": {
            "v_range": [["v6.2.0", ""]],
            "type": "list",
            "options": [
                {"value": "19"},
                {"value": "20"},
                {"value": "21"},
                {"value": "1", "v_range": [["v6.2.3", "v6.2.3"]]},
                {"value": "2", "v_range": [["v6.2.3", "v6.2.3"]]},
                {"value": "5", "v_range": [["v6.2.3", "v6.2.3"]]},
                {"value": "14", "v_range": [["v6.2.3", "v6.2.3"]]},
                {"value": "15", "v_range": [["v6.2.3", "v6.2.3"]]},
                {"value": "16", "v_range": [["v6.2.3", "v6.2.3"]]},
                {"value": "17", "v_range": [["v6.2.3", "v6.2.3"]]},
                {"value": "18", "v_range": [["v6.2.3", "v6.2.3"]]},
                {"value": "27", "v_range": [["v6.2.3", "v6.2.3"]]},
                {"value": "28", "v_range": [["v6.2.3", "v6.2.3"]]},
                {"value": "29", "v_range": [["v6.2.3", "v6.2.3"]]},
                {"value": "30", "v_range": [["v6.2.3", "v6.2.3"]]},
                {"value": "31", "v_range": [["v6.2.3", "v6.2.3"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "owe_groups": {
            "v_range": [["v6.2.0", ""]],
            "type": "list",
            "options": [{"value": "19"}, {"value": "20"}, {"value": "21"}],
            "multiple_values": True,
            "elements": "str",
        },
        "owe_transition": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "owe_transition_ssid": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "additional_akms": {
            "v_range": [["v7.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "akm6"},
                {"value": "akm24", "v_range": [["v7.4.4", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "eapol_key_retries": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "tkip_counter_measure": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "external_web": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "external_web_format": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "auto-detect"},
                {"value": "no-query-string"},
                {"value": "partial-query-string"},
            ],
        },
        "external_logout": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "mac_username_delimiter": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "hyphen"},
                {"value": "single-hyphen"},
                {"value": "colon"},
                {"value": "none"},
            ],
        },
        "mac_password_delimiter": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "hyphen"},
                {"value": "single-hyphen"},
                {"value": "colon"},
                {"value": "none"},
            ],
        },
        "mac_calling_station_delimiter": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "hyphen"},
                {"value": "single-hyphen"},
                {"value": "colon"},
                {"value": "none"},
            ],
        },
        "mac_called_station_delimiter": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "hyphen"},
                {"value": "single-hyphen"},
                {"value": "colon"},
                {"value": "none"},
            ],
        },
        "mac_case": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "uppercase"}, {"value": "lowercase"}],
        },
        "called_station_id_type": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "mac"}, {"value": "ip"}, {"value": "apname"}],
        },
        "mac_auth_bypass": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "radius_mac_auth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "radius_mac_auth_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "radius_mac_auth_block_interval": {
            "v_range": [["v7.2.4", ""]],
            "type": "integer",
        },
        "radius_mac_mpsk_auth": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "radius_mac_mpsk_timeout": {"v_range": [["v7.0.2", ""]], "type": "integer"},
        "radius_mac_auth_usergroups": {
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
        "auth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "radius"},
                {"value": "usergroup"},
                {"value": "psk", "v_range": [["v6.0.0", "v7.4.0"]]},
            ],
        },
        "encrypt": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "TKIP"}, {"value": "AES"}, {"value": "TKIP-AES"}],
        },
        "keyindex": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "key": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "passphrase": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sae_password": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "sae_h2e_only": {
            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sae_hnp_only": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sae_pk": {
            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sae_private_key": {
            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
        },
        "akm24_only": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "radius_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "nas_filter_rule": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "domain_name_stripping": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "local_standalone": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "local_standalone_nat": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dhcp_lease_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "local_standalone_dns": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "local_standalone_dns_ip": {
            "v_range": [["v7.0.1", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "local_lan_partition": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "local_bridging": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "local_lan": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "local_authentication": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "usergroup": {
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
        "captive_portal": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "captive_network_assistant_bypass": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "portal_message_override_group": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
        },
        "portal_message_overrides": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "auth_disclaimer_page": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "auth_reject_page": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "auth_login_page": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "auth_login_failed_page": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                },
            },
        },
        "portal_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "auth"},
                {"value": "auth+disclaimer"},
                {"value": "disclaimer"},
                {"value": "email-collect"},
                {"value": "cmcc"},
                {"value": "cmcc-macauth"},
                {"value": "auth-mac"},
                {"value": "external-auth", "v_range": [["v6.2.0", ""]]},
                {"value": "external-macauth", "v_range": [["v7.0.0", ""]]},
            ],
        },
        "selected_usergroups": {
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
        "security_exempt_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "security_redirect_url": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "auth_cert": {"v_range": [["v7.0.4", ""]], "type": "string"},
        "auth_portal_addr": {"v_range": [["v7.0.4", ""]], "type": "string"},
        "intra_vap_privacy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "schedule": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ldpc": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "rx"},
                {"value": "tx"},
                {"value": "rxtx"},
            ],
        },
        "high_efficiency": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "target_wake_time": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "port_macauth": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "radius"},
                {"value": "address-group"},
            ],
        },
        "port_macauth_timeout": {"v_range": [["v6.4.4", ""]], "type": "integer"},
        "port_macauth_reauth_timeout": {"v_range": [["v6.4.4", ""]], "type": "integer"},
        "bss_color_partial": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mpsk_profile": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "split_tunneling": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nac": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nac_profile": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "vlanid": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "vlan_auto": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dynamic_vlan": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "captive_portal_fw_accounting": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "captive_portal_ac_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "captive_portal_auth_timeout": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "multicast_rate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "0"},
                {"value": "6000"},
                {"value": "12000"},
                {"value": "24000"},
            ],
        },
        "multicast_enhance": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "igmp_snooping": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dhcp_address_enforcement": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "broadcast_suppression": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "dhcp-up"},
                {"value": "dhcp-down"},
                {"value": "dhcp-starvation"},
                {"value": "dhcp-ucast", "v_range": [["v6.2.0", ""]]},
                {"value": "arp-known"},
                {"value": "arp-unknown"},
                {"value": "arp-reply"},
                {"value": "arp-poison"},
                {"value": "arp-proxy"},
                {"value": "netbios-ns"},
                {"value": "netbios-ds"},
                {"value": "ipv6"},
                {"value": "all-other-mc"},
                {"value": "all-other-bc"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ipv6_rules": {
            "v_range": [["v6.4.0", ""]],
            "type": "list",
            "options": [
                {"value": "drop-icmp6ra"},
                {"value": "drop-icmp6rs"},
                {"value": "drop-llmnr6"},
                {"value": "drop-icmp6mld2"},
                {"value": "drop-dhcp6s"},
                {"value": "drop-dhcp6c"},
                {"value": "ndp-proxy"},
                {"value": "drop-ns-dad"},
                {"value": "drop-ns-nondad"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "me_disable_thresh": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "mu_mimo": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "probe_resp_suppression": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "probe_resp_threshold": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "radio_sensitivity": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "quarantine": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "radio_5g_threshold": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "radio_2g_threshold": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "vlan_name": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.4", ""]],
                    "type": "string",
                    "required": True,
                },
                "vlan_id": {
                    "v_range": [["v7.0.4", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
            },
            "v_range": [["v7.0.4", ""]],
        },
        "vlan_pooling": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "wtp-group"},
                {"value": "round-robin"},
                {"value": "hash"},
                {"value": "disable"},
            ],
        },
        "vlan_pool": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "wtp_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "dhcp_option43_insertion": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dhcp_option82_insertion": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dhcp_option82_circuit_id_insertion": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "style-1"},
                {"value": "style-2"},
                {"value": "style-3", "v_range": [["v6.4.0", ""]]},
                {"value": "disable"},
            ],
        },
        "dhcp_option82_remote_id_insertion": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "style-1"}, {"value": "disable"}],
        },
        "ptk_rekey": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ptk_rekey_intv": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "gtk_rekey": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gtk_rekey_intv": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "eap_reauth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "eap_reauth_intv": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "roaming_acct_interim_update": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "qos_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "hotspot20_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "access_control_list": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "primary_wag_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "secondary_wag_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "tunnel_echo_interval": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "tunnel_fallback_interval": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "rates_11a": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "6"},
                {"value": "6-basic"},
                {"value": "9"},
                {"value": "9-basic"},
                {"value": "12"},
                {"value": "12-basic"},
                {"value": "18"},
                {"value": "18-basic"},
                {"value": "24"},
                {"value": "24-basic"},
                {"value": "36"},
                {"value": "36-basic"},
                {"value": "48"},
                {"value": "48-basic"},
                {"value": "54"},
                {"value": "54-basic"},
                {"value": "1", "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", "v7.4.4"]]},
                {
                    "value": "1-basic",
                    "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", "v7.4.4"]],
                },
                {"value": "2", "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", "v7.4.4"]]},
                {
                    "value": "2-basic",
                    "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", "v7.4.4"]],
                },
                {
                    "value": "5.5",
                    "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", "v7.4.4"]],
                },
                {
                    "value": "5.5-basic",
                    "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", "v7.4.4"]],
                },
                {
                    "value": "11",
                    "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", "v7.4.4"]],
                },
                {
                    "value": "11-basic",
                    "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", "v7.4.4"]],
                },
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "rates_11bg": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "1", "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", ""]]},
                {"value": "1-basic", "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", ""]]},
                {"value": "2", "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", ""]]},
                {"value": "2-basic", "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", ""]]},
                {"value": "5.5", "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", ""]]},
                {
                    "value": "5.5-basic",
                    "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", ""]],
                },
                {"value": "11", "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", ""]]},
                {
                    "value": "11-basic",
                    "v_range": [["v6.0.0", "v7.4.0"], ["v7.4.2", ""]],
                },
                {"value": "6"},
                {"value": "6-basic"},
                {"value": "9"},
                {"value": "9-basic"},
                {"value": "12"},
                {"value": "12-basic"},
                {"value": "18"},
                {"value": "18-basic"},
                {"value": "24"},
                {"value": "24-basic"},
                {"value": "36"},
                {"value": "36-basic"},
                {"value": "48"},
                {"value": "48-basic"},
                {"value": "54"},
                {"value": "54-basic"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "rates_11n_ss12": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "mcs0/1"},
                {"value": "mcs1/1"},
                {"value": "mcs2/1"},
                {"value": "mcs3/1"},
                {"value": "mcs4/1"},
                {"value": "mcs5/1"},
                {"value": "mcs6/1"},
                {"value": "mcs7/1"},
                {"value": "mcs8/2"},
                {"value": "mcs9/2"},
                {"value": "mcs10/2"},
                {"value": "mcs11/2"},
                {"value": "mcs12/2"},
                {"value": "mcs13/2"},
                {"value": "mcs14/2"},
                {"value": "mcs15/2"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "rates_11n_ss34": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "mcs16/3"},
                {"value": "mcs17/3"},
                {"value": "mcs18/3"},
                {"value": "mcs19/3"},
                {"value": "mcs20/3"},
                {"value": "mcs21/3"},
                {"value": "mcs22/3"},
                {"value": "mcs23/3"},
                {"value": "mcs24/4"},
                {"value": "mcs25/4"},
                {"value": "mcs26/4"},
                {"value": "mcs27/4"},
                {"value": "mcs28/4"},
                {"value": "mcs29/4"},
                {"value": "mcs30/4"},
                {"value": "mcs31/4"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "rates_11ac_mcs_map": {"v_range": [["v7.2.1", ""]], "type": "string"},
        "rates_11ax_mcs_map": {"v_range": [["v7.2.1", ""]], "type": "string"},
        "rates_11be_mcs_map": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "rates_11be_mcs_map_160": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "rates_11be_mcs_map_320": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "utm_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "utm_status": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "utm_log": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ips_sensor": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "application_list": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "antivirus_profile": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "webfilter_profile": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "scan_botnet_connections": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "monitor"}, {"value": "block"}],
        },
        "address_group": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "address_group_policy": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "allow"}, {"value": "deny"}],
        },
        "sticky_client_remove": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sticky_client_threshold_5g": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "sticky_client_threshold_2g": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "sticky_client_threshold_6g": {
            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
        },
        "bstm_rssi_disassoc_timer": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "bstm_load_balancing_disassoc_timer": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
        },
        "bstm_disassociation_imminent": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "beacon_advertising": {
            "v_range": [["v7.0.2", ""]],
            "type": "list",
            "options": [
                {"value": "name"},
                {"value": "model"},
                {"value": "serial-number"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "osen": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "application_detection_engine": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "application_dscp_marking": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "application_report_intv": {"v_range": [["v7.2.0", ""]], "type": "integer"},
        "l3_roaming": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "l3_roaming_mode": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "direct"}, {"value": "indirect"}],
        },
        "fast_roaming": {
            "v_range": [["v6.0.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "external_fast_roaming": {
            "v_range": [["v6.0.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "voice_enterprise": {
            "v_range": [["v6.0.0", "v7.4.1"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "mac_filter": {
            "v_range": [["v6.0.0", "v7.4.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mac_filter_policy_other": {
            "v_range": [["v6.0.0", "v7.4.0"]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "mac_filter_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v7.4.0"]],
                    "type": "integer",
                    "required": True,
                },
                "mac": {"v_range": [["v6.0.0", "v7.4.0"]], "type": "string"},
                "mac_filter_policy": {
                    "v_range": [["v6.0.0", "v7.4.0"]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "deny"}],
                },
            },
            "v_range": [["v6.0.0", "v7.4.0"]],
        },
        "rates_11ac_ss12": {
            "v_range": [["v6.0.0", "v7.2.0"]],
            "type": "list",
            "options": [
                {"value": "mcs0/1"},
                {"value": "mcs1/1"},
                {"value": "mcs2/1"},
                {"value": "mcs3/1"},
                {"value": "mcs4/1"},
                {"value": "mcs5/1"},
                {"value": "mcs6/1"},
                {"value": "mcs7/1"},
                {"value": "mcs8/1"},
                {"value": "mcs9/1"},
                {"value": "mcs10/1"},
                {"value": "mcs11/1"},
                {"value": "mcs0/2"},
                {"value": "mcs1/2"},
                {"value": "mcs2/2"},
                {"value": "mcs3/2"},
                {"value": "mcs4/2"},
                {"value": "mcs5/2"},
                {"value": "mcs6/2"},
                {"value": "mcs7/2"},
                {"value": "mcs8/2"},
                {"value": "mcs9/2"},
                {"value": "mcs10/2"},
                {"value": "mcs11/2"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "rates_11ac_ss34": {
            "v_range": [["v6.0.0", "v7.2.0"]],
            "type": "list",
            "options": [
                {"value": "mcs0/3"},
                {"value": "mcs1/3"},
                {"value": "mcs2/3"},
                {"value": "mcs3/3"},
                {"value": "mcs4/3"},
                {"value": "mcs5/3"},
                {"value": "mcs6/3"},
                {"value": "mcs7/3"},
                {"value": "mcs8/3"},
                {"value": "mcs9/3"},
                {"value": "mcs10/3"},
                {"value": "mcs11/3"},
                {"value": "mcs0/4"},
                {"value": "mcs1/4"},
                {"value": "mcs2/4"},
                {"value": "mcs3/4"},
                {"value": "mcs4/4"},
                {"value": "mcs5/4"},
                {"value": "mcs6/4"},
                {"value": "mcs7/4"},
                {"value": "mcs8/4"},
                {"value": "mcs9/4"},
                {"value": "mcs10/4"},
                {"value": "mcs11/4"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "rates_11ax_ss12": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "list",
            "options": [
                {"value": "mcs0/1"},
                {"value": "mcs1/1"},
                {"value": "mcs2/1"},
                {"value": "mcs3/1"},
                {"value": "mcs4/1"},
                {"value": "mcs5/1"},
                {"value": "mcs6/1"},
                {"value": "mcs7/1"},
                {"value": "mcs8/1"},
                {"value": "mcs9/1"},
                {"value": "mcs10/1"},
                {"value": "mcs11/1"},
                {"value": "mcs0/2"},
                {"value": "mcs1/2"},
                {"value": "mcs2/2"},
                {"value": "mcs3/2"},
                {"value": "mcs4/2"},
                {"value": "mcs5/2"},
                {"value": "mcs6/2"},
                {"value": "mcs7/2"},
                {"value": "mcs8/2"},
                {"value": "mcs9/2"},
                {"value": "mcs10/2"},
                {"value": "mcs11/2"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "rates_11ax_ss34": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "list",
            "options": [
                {"value": "mcs0/3"},
                {"value": "mcs1/3"},
                {"value": "mcs2/3"},
                {"value": "mcs3/3"},
                {"value": "mcs4/3"},
                {"value": "mcs5/3"},
                {"value": "mcs6/3"},
                {"value": "mcs7/3"},
                {"value": "mcs8/3"},
                {"value": "mcs9/3"},
                {"value": "mcs10/3"},
                {"value": "mcs11/3"},
                {"value": "mcs0/4"},
                {"value": "mcs1/4"},
                {"value": "mcs2/4"},
                {"value": "mcs3/4"},
                {"value": "mcs4/4"},
                {"value": "mcs5/4"},
                {"value": "mcs6/4"},
                {"value": "mcs7/4"},
                {"value": "mcs8/4"},
                {"value": "mcs9/4"},
                {"value": "mcs10/4"},
                {"value": "mcs11/4"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "mpsk": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mpsk_concurrent_clients": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "integer",
        },
        "mpsk_key": {
            "type": "list",
            "elements": "dict",
            "children": {
                "key_name": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "required": True,
                },
                "passphrase": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                },
                "concurrent_clients": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                },
                "comment": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                },
                "mpsk_schedules": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                },
            },
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
        },
        "acct_interim_interval": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "captive_portal_radius_server": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
        },
        "captive_portal_radius_secret": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
        },
        "captive_portal_macauth_radius_server": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
        },
        "captive_portal_macauth_radius_secret": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
        },
        "captive_portal_session_timeout_interval": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "integer",
        },
        "security_obsolete_option": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "alias": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "vdom": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
        "set_80211k": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "set_80211v": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
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
        "wireless_controller_vap": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_vap"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_vap"]["options"][attribute_name][
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
            fos, versioned_schema, "wireless_controller_vap"
        )

        is_error, has_changed, result, diff = fortios_wireless_controller(
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
