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
module: fortios_wireless_controller_wtp_profile
short_description: Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and wtp_profile category.
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
    wireless_controller_wtp_profile:
        description:
            - Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms.
        default: null
        type: dict
        suboptions:
            admin_auth_tacacs_plus:
                description:
                    - Remote authentication server for admin user. Source user.tacacs+.name.
                type: str
            admin_restrict_local:
                description:
                    - Enable/disable local admin authentication restriction when remote authenticator is up and running .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            allowaccess:
                description:
                    - Control management access to the managed WTP, FortiAP, or AP. Separate entries with a space.
                type: list
                elements: str
                choices:
                    - 'https'
                    - 'ssh'
                    - 'snmp'
                    - 'telnet'
                    - 'http'
            ap_country:
                description:
                    - Country in which this WTP, FortiAP, or AP will operate .
                type: str
                choices:
                    - '--'
                    - 'AF'
                    - 'AL'
                    - 'DZ'
                    - 'AS'
                    - 'AO'
                    - 'AR'
                    - 'AM'
                    - 'AU'
                    - 'AT'
                    - 'AZ'
                    - 'BS'
                    - 'BH'
                    - 'BD'
                    - 'BB'
                    - 'BY'
                    - 'BE'
                    - 'BZ'
                    - 'BJ'
                    - 'BM'
                    - 'BT'
                    - 'BO'
                    - 'BA'
                    - 'BW'
                    - 'BR'
                    - 'BN'
                    - 'BG'
                    - 'BF'
                    - 'KH'
                    - 'CM'
                    - 'KY'
                    - 'CF'
                    - 'TD'
                    - 'CL'
                    - 'CN'
                    - 'CX'
                    - 'CO'
                    - 'CG'
                    - 'CD'
                    - 'CR'
                    - 'HR'
                    - 'CY'
                    - 'CZ'
                    - 'DK'
                    - 'DJ'
                    - 'DM'
                    - 'DO'
                    - 'EC'
                    - 'EG'
                    - 'SV'
                    - 'ET'
                    - 'EE'
                    - 'GF'
                    - 'PF'
                    - 'FO'
                    - 'FJ'
                    - 'FI'
                    - 'FR'
                    - 'GA'
                    - 'GE'
                    - 'GM'
                    - 'DE'
                    - 'GH'
                    - 'GI'
                    - 'GR'
                    - 'GL'
                    - 'GD'
                    - 'GP'
                    - 'GU'
                    - 'GT'
                    - 'GY'
                    - 'HT'
                    - 'HN'
                    - 'HK'
                    - 'HU'
                    - 'IS'
                    - 'IN'
                    - 'ID'
                    - 'IQ'
                    - 'IE'
                    - 'IM'
                    - 'IL'
                    - 'IT'
                    - 'CI'
                    - 'JM'
                    - 'JO'
                    - 'KZ'
                    - 'KE'
                    - 'KR'
                    - 'KW'
                    - 'LA'
                    - 'LV'
                    - 'LB'
                    - 'LS'
                    - 'LR'
                    - 'LY'
                    - 'LI'
                    - 'LT'
                    - 'LU'
                    - 'MO'
                    - 'MK'
                    - 'MG'
                    - 'MW'
                    - 'MY'
                    - 'MV'
                    - 'ML'
                    - 'MT'
                    - 'MH'
                    - 'MQ'
                    - 'MR'
                    - 'MU'
                    - 'YT'
                    - 'MX'
                    - 'FM'
                    - 'MD'
                    - 'MC'
                    - 'MN'
                    - 'MA'
                    - 'MZ'
                    - 'MM'
                    - 'NA'
                    - 'NP'
                    - 'NL'
                    - 'AN'
                    - 'AW'
                    - 'NZ'
                    - 'NI'
                    - 'NE'
                    - 'NG'
                    - 'NO'
                    - 'MP'
                    - 'OM'
                    - 'PK'
                    - 'PW'
                    - 'PA'
                    - 'PG'
                    - 'PY'
                    - 'PE'
                    - 'PH'
                    - 'PL'
                    - 'PT'
                    - 'PR'
                    - 'QA'
                    - 'RE'
                    - 'RO'
                    - 'RU'
                    - 'RW'
                    - 'BL'
                    - 'KN'
                    - 'LC'
                    - 'MF'
                    - 'PM'
                    - 'VC'
                    - 'SA'
                    - 'SN'
                    - 'RS'
                    - 'ME'
                    - 'SL'
                    - 'SG'
                    - 'SK'
                    - 'SI'
                    - 'SO'
                    - 'ZA'
                    - 'ES'
                    - 'LK'
                    - 'SR'
                    - 'SZ'
                    - 'SE'
                    - 'CH'
                    - 'TW'
                    - 'TZ'
                    - 'TH'
                    - 'TL'
                    - 'TG'
                    - 'TT'
                    - 'TN'
                    - 'TR'
                    - 'TM'
                    - 'AE'
                    - 'TC'
                    - 'UG'
                    - 'UA'
                    - 'GB'
                    - 'US'
                    - 'PS'
                    - 'UY'
                    - 'UZ'
                    - 'VU'
                    - 'VE'
                    - 'VN'
                    - 'VI'
                    - 'WF'
                    - 'YE'
                    - 'ZM'
                    - 'ZW'
                    - 'JP'
                    - 'CA'
                    - 'IR'
                    - 'KP'
                    - 'SD'
                    - 'SY'
                    - 'ZB'
            ap_handoff:
                description:
                    - Enable/disable AP handoff of clients to other APs .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            apcfg_mesh:
                description:
                    - Enable/disable AP local mesh configuration .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            apcfg_mesh_ap_type:
                description:
                    - Mesh AP Type .
                type: str
                choices:
                    - 'ethernet'
                    - 'mesh'
                    - 'auto'
            apcfg_mesh_eth_bridge:
                description:
                    - Enable/disable mesh ethernet bridge .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            apcfg_mesh_ssid:
                description:
                    -  Mesh SSID . Source wireless-controller.vap.name.
                type: str
            apcfg_profile:
                description:
                    - AP local configuration profile name. Source wireless-controller.apcfg-profile.name.
                type: str
            ble_profile:
                description:
                    - Bluetooth Low Energy profile name. Source wireless-controller.ble-profile.name.
                type: str
            bonjour_profile:
                description:
                    - Bonjour profile name. Source wireless-controller.bonjour-profile.name.
                type: str
            comment:
                description:
                    - Comment.
                type: str
            console_login:
                description:
                    - Enable/disable FortiAP console login access .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            control_message_offload:
                description:
                    - Enable/disable CAPWAP control message data channel offload.
                type: list
                elements: str
                choices:
                    - 'ebp-frame'
                    - 'aeroscout-tag'
                    - 'ap-list'
                    - 'sta-list'
                    - 'sta-cap-list'
                    - 'stats'
                    - 'aeroscout-mu'
                    - 'sta-health'
                    - 'spectral-analysis'
            default_mesh_root:
                description:
                    - Configure default mesh root SSID when it is not included by radio"s SSID configuration.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            deny_mac_list:
                description:
                    - List of MAC addresses that are denied access to this WTP, FortiAP, or AP.
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
                            - A WiFi device with this MAC address is denied access to this WTP, FortiAP or AP.
                        type: str
            dtls_in_kernel:
                description:
                    - Enable/disable data channel DTLS in kernel.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dtls_policy:
                description:
                    - WTP data channel DTLS policy .
                type: list
                elements: str
                choices:
                    - 'clear-text'
                    - 'dtls-enabled'
                    - 'ipsec-vpn'
                    - 'ipsec-sn-vpn'
            energy_efficient_ethernet:
                description:
                    - Enable/disable use of energy efficient Ethernet on WTP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            esl_ses_dongle:
                description:
                    - ESL SES-imagotag dongle configuration.
                type: dict
                suboptions:
                    apc_addr_type:
                        description:
                            - ESL SES-imagotag APC address type .
                        type: str
                        choices:
                            - 'fqdn'
                            - 'ip'
                    apc_fqdn:
                        description:
                            - FQDN of ESL SES-imagotag Access Point Controller (APC).
                        type: str
                    apc_ip:
                        description:
                            - IP address of ESL SES-imagotag Access Point Controller (APC).
                        type: str
                    apc_port:
                        description:
                            - Port of ESL SES-imagotag Access Point Controller (APC).
                        type: int
                    coex_level:
                        description:
                            - ESL SES-imagotag dongle coexistence level .
                        type: str
                        choices:
                            - 'none'
                    compliance_level:
                        description:
                            - Compliance levels for the ESL solution integration .
                        type: str
                        choices:
                            - 'compliance-level-2'
                    esl_channel:
                        description:
                            - ESL SES-imagotag dongle channel .
                        type: str
                        choices:
                            - '-1'
                            - '0'
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                            - '6'
                            - '7'
                            - '8'
                            - '9'
                            - '10'
                            - '127'
                    output_power:
                        description:
                            - ESL SES-imagotag dongle output power .
                        type: str
                        choices:
                            - 'a'
                            - 'b'
                            - 'c'
                            - 'd'
                            - 'e'
                            - 'f'
                            - 'g'
                            - 'h'
                    scd_enable:
                        description:
                            - Enable/disable ESL SES-imagotag Serial Communication Daemon (SCD) .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tls_cert_verification:
                        description:
                            - Enable/disable TLS certificate verification .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tls_fqdn_verification:
                        description:
                            - Enable/disable TLS FQDN verification .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            ext_info_enable:
                description:
                    - Enable/disable station/VAP/radio extension information.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            frequency_handoff:
                description:
                    - Enable/disable frequency handoff of clients to other channels .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            handoff_roaming:
                description:
                    - Enable/disable client load balancing during roaming to avoid roaming delay .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            handoff_rssi:
                description:
                    - Minimum received signal strength indicator (RSSI) value for handoff (20 - 30).
                type: int
            handoff_sta_thresh:
                description:
                    - Threshold value for AP handoff.
                type: int
            indoor_outdoor_deployment:
                description:
                    - Set to allow indoor/outdoor-only channels under regulatory rules .
                type: str
                choices:
                    - 'platform-determined'
                    - 'outdoor'
                    - 'indoor'
            ip_fragment_preventing:
                description:
                    - Method(s) by which IP fragmentation is prevented for control and data packets through CAPWAP tunnel .
                type: list
                elements: str
                choices:
                    - 'tcp-mss-adjust'
                    - 'icmp-unreachable'
            lan:
                description:
                    - WTP LAN port mapping.
                type: dict
                suboptions:
                    port_esl_mode:
                        description:
                            - ESL port mode.
                        type: str
                        choices:
                            - 'offline'
                            - 'nat-to-wan'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                    port_esl_ssid:
                        description:
                            - Bridge ESL port to SSID. Source system.interface.name.
                        type: str
                    port_mode:
                        description:
                            - LAN port mode.
                        type: str
                        choices:
                            - 'offline'
                            - 'nat-to-wan'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                    port_ssid:
                        description:
                            - Bridge LAN port to SSID. Source system.interface.name.
                        type: str
                    port1_mode:
                        description:
                            - LAN port 1 mode.
                        type: str
                        choices:
                            - 'offline'
                            - 'nat-to-wan'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                    port1_ssid:
                        description:
                            - Bridge LAN port 1 to SSID. Source system.interface.name.
                        type: str
                    port2_mode:
                        description:
                            - LAN port 2 mode.
                        type: str
                        choices:
                            - 'offline'
                            - 'nat-to-wan'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                    port2_ssid:
                        description:
                            - Bridge LAN port 2 to SSID. Source system.interface.name.
                        type: str
                    port3_mode:
                        description:
                            - LAN port 3 mode.
                        type: str
                        choices:
                            - 'offline'
                            - 'nat-to-wan'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                    port3_ssid:
                        description:
                            - Bridge LAN port 3 to SSID. Source system.interface.name.
                        type: str
                    port4_mode:
                        description:
                            - LAN port 4 mode.
                        type: str
                        choices:
                            - 'offline'
                            - 'nat-to-wan'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                    port4_ssid:
                        description:
                            - Bridge LAN port 4 to SSID. Source system.interface.name.
                        type: str
                    port5_mode:
                        description:
                            - LAN port 5 mode.
                        type: str
                        choices:
                            - 'offline'
                            - 'nat-to-wan'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                    port5_ssid:
                        description:
                            - Bridge LAN port 5 to SSID. Source system.interface.name.
                        type: str
                    port6_mode:
                        description:
                            - LAN port 6 mode.
                        type: str
                        choices:
                            - 'offline'
                            - 'nat-to-wan'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                    port6_ssid:
                        description:
                            - Bridge LAN port 6 to SSID. Source system.interface.name.
                        type: str
                    port7_mode:
                        description:
                            - LAN port 7 mode.
                        type: str
                        choices:
                            - 'offline'
                            - 'nat-to-wan'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                    port7_ssid:
                        description:
                            - Bridge LAN port 7 to SSID. Source system.interface.name.
                        type: str
                    port8_mode:
                        description:
                            - LAN port 8 mode.
                        type: str
                        choices:
                            - 'offline'
                            - 'nat-to-wan'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                    port8_ssid:
                        description:
                            - Bridge LAN port 8 to SSID. Source system.interface.name.
                        type: str
            lbs:
                description:
                    - Set various location based service (LBS) options.
                type: dict
                suboptions:
                    aeroscout:
                        description:
                            - Enable/disable AeroScout Real Time Location Service (RTLS) support .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    aeroscout_ap_mac:
                        description:
                            - Use BSSID or board MAC address as AP MAC address in AeroScout AP messages .
                        type: str
                        choices:
                            - 'bssid'
                            - 'board-mac'
                    aeroscout_mmu_report:
                        description:
                            - Enable/disable compounded AeroScout tag and MU report .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    aeroscout_mu:
                        description:
                            - Enable/disable AeroScout Mobile Unit (MU) support .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    aeroscout_mu_factor:
                        description:
                            - AeroScout MU mode dilution factor .
                        type: int
                    aeroscout_mu_timeout:
                        description:
                            - AeroScout MU mode timeout (0 - 65535 sec).
                        type: int
                    aeroscout_server_ip:
                        description:
                            - IP address of AeroScout server.
                        type: str
                    aeroscout_server_port:
                        description:
                            - AeroScout server UDP listening port.
                        type: int
                    ble_rtls:
                        description:
                            - Set BLE Real Time Location Service (RTLS) support .
                        type: str
                        choices:
                            - 'none'
                            - 'polestar'
                            - 'evresys'
                    ble_rtls_accumulation_interval:
                        description:
                            - Time that measurements should be accumulated in seconds .
                        type: int
                    ble_rtls_asset_addrgrp_list:
                        description:
                            - Tags and asset addrgrp list to be reported. Source firewall.addrgrp.name.
                        type: str
                    ble_rtls_asset_uuid_list1:
                        description:
                            - Tags and asset UUID list 1 to be reported (string in the format of "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX").
                        type: str
                    ble_rtls_asset_uuid_list2:
                        description:
                            - Tags and asset UUID list 2 to be reported (string in the format of "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX").
                        type: str
                    ble_rtls_asset_uuid_list3:
                        description:
                            - Tags and asset UUID list 3 to be reported (string in the format of "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX").
                        type: str
                    ble_rtls_asset_uuid_list4:
                        description:
                            - Tags and asset UUID list 4 to be reported (string in the format of "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX").
                        type: str
                    ble_rtls_protocol:
                        description:
                            - Select the protocol to report Measurements, Advertising Data, or Location Data to Cloud Server .
                        type: str
                        choices:
                            - 'WSS'
                    ble_rtls_reporting_interval:
                        description:
                            - Time between reporting accumulated measurements in seconds .
                        type: int
                    ble_rtls_server_fqdn:
                        description:
                            - FQDN of BLE Real Time Location Service (RTLS) Server.
                        type: str
                    ble_rtls_server_path:
                        description:
                            - Path of BLE Real Time Location Service (RTLS) Server.
                        type: str
                    ble_rtls_server_port:
                        description:
                            - Port of BLE Real Time Location Service (RTLS) Server .
                        type: int
                    ble_rtls_server_token:
                        description:
                            - Access Token of BLE Real Time Location Service (RTLS) Server.
                        type: str
                    ekahau_blink_mode:
                        description:
                            - Enable/disable Ekahau blink mode (now known as AiRISTA Flow) to track and locate WiFi tags .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ekahau_tag:
                        description:
                            - WiFi frame MAC address or WiFi Tag.
                        type: str
                    erc_server_ip:
                        description:
                            - IP address of Ekahau RTLS Controller (ERC).
                        type: str
                    erc_server_port:
                        description:
                            - Ekahau RTLS Controller (ERC) UDP listening port.
                        type: int
                    fortipresence:
                        description:
                            - Enable/disable FortiPresence to monitor the location and activity of WiFi clients even if they don"t connect to this WiFi
                               network .
                        type: str
                        choices:
                            - 'foreign'
                            - 'both'
                            - 'disable'
                    fortipresence_ble:
                        description:
                            - Enable/disable FortiPresence finding and reporting BLE devices.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    fortipresence_frequency:
                        description:
                            - FortiPresence report transmit frequency (5 - 65535 sec).
                        type: int
                    fortipresence_port:
                        description:
                            - UDP listening port of FortiPresence server .
                        type: int
                    fortipresence_project:
                        description:
                            - FortiPresence project name (max. 16 characters).
                        type: str
                    fortipresence_rogue:
                        description:
                            - Enable/disable FortiPresence finding and reporting rogue APs.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    fortipresence_secret:
                        description:
                            - FortiPresence secret password (max. 16 characters).
                        type: str
                    fortipresence_server:
                        description:
                            - IP address of FortiPresence server.
                        type: str
                    fortipresence_server_addr_type:
                        description:
                            - FortiPresence server address type .
                        type: str
                        choices:
                            - 'ipv4'
                            - 'fqdn'
                    fortipresence_server_fqdn:
                        description:
                            - FQDN of FortiPresence server.
                        type: str
                    fortipresence_unassoc:
                        description:
                            - Enable/disable FortiPresence finding and reporting unassociated stations.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    polestar:
                        description:
                            - Enable/disable PoleStar BLE NAO Track Real Time Location Service (RTLS) support .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    polestar_accumulation_interval:
                        description:
                            - Time that measurements should be accumulated in seconds .
                        type: int
                    polestar_asset_addrgrp_list:
                        description:
                            - Tags and asset addrgrp list to be reported. Source firewall.addrgrp.name.
                        type: str
                    polestar_asset_uuid_list1:
                        description:
                            - Tags and asset UUID list 1 to be reported (string in the format of "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX").
                        type: str
                    polestar_asset_uuid_list2:
                        description:
                            - Tags and asset UUID list 2 to be reported (string in the format of "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX").
                        type: str
                    polestar_asset_uuid_list3:
                        description:
                            - Tags and asset UUID list 3 to be reported (string in the format of "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX").
                        type: str
                    polestar_asset_uuid_list4:
                        description:
                            - Tags and asset UUID list 4 to be reported (string in the format of "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX").
                        type: str
                    polestar_protocol:
                        description:
                            - Select the protocol to report Measurements, Advertising Data, or Location Data to NAO Cloud. .
                        type: str
                        choices:
                            - 'WSS'
                    polestar_reporting_interval:
                        description:
                            - Time between reporting accumulated measurements in seconds .
                        type: int
                    polestar_server_fqdn:
                        description:
                            - FQDN of PoleStar Nao Track Server .
                        type: str
                    polestar_server_path:
                        description:
                            - Path of PoleStar Nao Track Server .
                        type: str
                    polestar_server_port:
                        description:
                            - Port of PoleStar Nao Track Server .
                        type: int
                    polestar_server_token:
                        description:
                            - Access Token of PoleStar Nao Track Server.
                        type: str
                    station_locate:
                        description:
                            - Enable/disable client station locating services for all clients, whether associated or not .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            led_schedules:
                description:
                    - Recurring firewall schedules for illuminating LEDs on the FortiAP. If led-state is enabled, LEDs will be visible when at least one of
                       the schedules is valid. Separate multiple schedule names with a space.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Schedule name. Source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime.name.
                        required: true
                        type: str
            led_state:
                description:
                    - Enable/disable use of LEDs on WTP .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            lldp:
                description:
                    - Enable/disable Link Layer Discovery Protocol (LLDP) for the WTP, FortiAP, or AP .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            login_passwd:
                description:
                    - Set the managed WTP, FortiAP, or AP"s administrator password.
                type: str
            login_passwd_change:
                description:
                    - Change or reset the administrator password of a managed WTP, FortiAP or AP (yes, default, or no).
                type: str
                choices:
                    - 'yes'
                    - 'default'
                    - 'no'
            max_clients:
                description:
                    - Maximum number of stations (STAs) supported by the WTP .
                type: int
            name:
                description:
                    - WTP (or FortiAP or AP) profile name.
                required: true
                type: str
            platform:
                description:
                    - WTP, FortiAP, or AP platform.
                type: dict
                suboptions:
                    ddscan:
                        description:
                            - Enable/disable use of one radio for dedicated full-band scanning to detect RF characterization and wireless threat management.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    mode:
                        description:
                            - Configure operation mode of 5G radios .
                        type: str
                        choices:
                            - 'single-5G'
                            - 'dual-5G'
                    type:
                        description:
                            - WTP, FortiAP or AP platform type. There are built-in WTP profiles for all supported FortiAP models. You can select a built-in
                               profile and customize it or create a new profile.
                        type: str
                        choices:
                            - 'AP-11N'
                            - 'C24JE'
                            - '421E'
                            - '423E'
                            - '221E'
                            - '222E'
                            - '223E'
                            - '224E'
                            - '231E'
                            - '321E'
                            - '431F'
                            - '431FL'
                            - '432F'
                            - '432FR'
                            - '433F'
                            - '433FL'
                            - '231F'
                            - '231FL'
                            - '234F'
                            - '23JF'
                            - '831F'
                            - '231G'
                            - '233G'
                            - '234G'
                            - '431G'
                            - '432G'
                            - '433G'
                            - '231K'
                            - '23JK'
                            - '222KL'
                            - '241K'
                            - '243K'
                            - '244K'
                            - '441K'
                            - '443K'
                            - 'U421E'
                            - 'U422EV'
                            - 'U423E'
                            - 'U221EV'
                            - 'U223EV'
                            - 'U24JEV'
                            - 'U321EV'
                            - 'U323EV'
                            - 'U431F'
                            - 'U433F'
                            - 'U231F'
                            - 'U234F'
                            - 'U432F'
                            - 'U231G'
                            - '220B'
                            - '210B'
                            - '222B'
                            - '112B'
                            - '320B'
                            - '11C'
                            - '14C'
                            - '223B'
                            - '28C'
                            - '320C'
                            - '221C'
                            - '25D'
                            - '222C'
                            - '224D'
                            - '214B'
                            - '21D'
                            - '24D'
                            - '112D'
                            - '223C'
                            - '321C'
                            - 'C220C'
                            - 'C225C'
                            - 'C23JD'
                            - 'S321C'
                            - 'S322C'
                            - 'S323C'
                            - 'S311C'
                            - 'S313C'
                            - 'S321CR'
                            - 'S322CR'
                            - 'S323CR'
                            - 'S421E'
                            - 'S422E'
                            - 'S423E'
                            - 'S221E'
                            - 'S223E'
                            - 'U441G'
            poe_mode:
                description:
                    - Set the WTP, FortiAP, or AP"s PoE mode.
                type: str
                choices:
                    - 'auto'
                    - '8023af'
                    - '8023at'
                    - 'power-adapter'
                    - 'full'
                    - 'high'
                    - 'low'
            radio_1:
                description:
                    - Configuration options for radio 1.
                type: dict
                suboptions:
                    airtime_fairness:
                        description:
                            - Enable/disable airtime fairness .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    amsdu:
                        description:
                            - Enable/disable 802.11n AMSDU support. AMSDU can improve performance if supported by your WiFi clients .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_handoff:
                        description:
                            - Enable/disable AP handoff of clients to other APs .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_addr:
                        description:
                            - MAC address to monitor.
                        type: str
                    ap_sniffer_bufsize:
                        description:
                            - Sniffer buffer size (1 - 32 MB).
                        type: int
                    ap_sniffer_chan:
                        description:
                            - Channel on which to operate the sniffer .
                        type: int
                    ap_sniffer_chan_width:
                        description:
                            - Channel bandwidth for sniffer.
                        type: str
                        choices:
                            - '320MHz'
                            - '240MHz'
                            - '160MHz'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
                    ap_sniffer_ctl:
                        description:
                            - Enable/disable sniffer on WiFi control frame .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_data:
                        description:
                            - Enable/disable sniffer on WiFi data frame .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_mgmt_beacon:
                        description:
                            - Enable/disable sniffer on WiFi management Beacon frames .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_mgmt_other:
                        description:
                            - Enable/disable sniffer on WiFi management other frames  .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_mgmt_probe:
                        description:
                            - Enable/disable sniffer on WiFi management probe frames .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    arrp_profile:
                        description:
                            - Distributed Automatic Radio Resource Provisioning (DARRP) profile name to assign to the radio. Source wireless-controller
                              .arrp-profile.name.
                        type: str
                    auto_power_high:
                        description:
                            - The upper bound of automatic transmit power adjustment in dBm (the actual range of transmit power depends on the AP platform
                               type).
                        type: int
                    auto_power_level:
                        description:
                            - Enable/disable automatic power-level adjustment to prevent co-channel interference .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    auto_power_low:
                        description:
                            - The lower bound of automatic transmit power adjustment in dBm (the actual range of transmit power depends on the AP platform
                               type).
                        type: int
                    auto_power_target:
                        description:
                            - Target of automatic transmit power adjustment in dBm (-95 to -20).
                        type: str
                    band:
                        description:
                            - WiFi band that Radio 1 operates on.
                        type: list
                        elements: str
                        choices:
                            - '802.11a'
                            - '802.11b'
                            - '802.11g'
                            - '802.11n-2G'
                            - '802.11n-5G'
                            - '802.11ac-2G'
                            - '802.11ac-5G'
                            - '802.11ax-2G'
                            - '802.11ax-5G'
                            - '802.11ax-6G'
                            - '802.11be-2G'
                            - '802.11be-5G'
                            - '802.11be-6G'
                            - '802.11n'
                            - '802.11ac'
                            - '802.11ax'
                            - '802.11n,g-only'
                            - '802.11g-only'
                            - '802.11n-only'
                            - '802.11n-5G-only'
                            - '802.11ac,n-only'
                            - '802.11ac-only'
                            - '802.11ax,ac-only'
                            - '802.11ax,ac,n-only'
                            - '802.11ax-5G-only'
                            - '802.11ax,n-only'
                            - '802.11ax,n,g-only'
                            - '802.11ax-only'
                    band_5g_type:
                        description:
                            - WiFi 5G band type.
                        type: str
                        choices:
                            - '5g-full'
                            - '5g-high'
                            - '5g-low'
                    bandwidth_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) bandwidth admission control to optimize WiFi bandwidth use. A request to join the wireless
                               network is only allowed if the access point has enough bandwidth to support it.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bandwidth_capacity:
                        description:
                            - Maximum bandwidth capacity allowed (1 - 600000 Kbps).
                        type: int
                    beacon_interval:
                        description:
                            - Beacon interval. The time between beacon frames in milliseconds. Actual range of beacon interval depends on the AP platform type
                               .
                        type: int
                    bss_color:
                        description:
                            - BSS color value for this 11ax radio (0 - 63, disable = 0).
                        type: int
                    bss_color_mode:
                        description:
                            - BSS color mode for this 11ax radio .
                        type: str
                        choices:
                            - 'auto'
                            - 'static'
                    call_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) call admission control to optimize WiFi bandwidth use for VoIP calls. New VoIP calls are
                               only accepted if there is enough bandwidth available to support them.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    call_capacity:
                        description:
                            - Maximum number of Voice over WLAN (VoWLAN) phones supported by the radio (0 - 60).
                        type: int
                    channel:
                        description:
                            - Selected list of wireless radio channels.
                        type: list
                        elements: dict
                        suboptions:
                            chan:
                                description:
                                    - Channel number.
                                required: true
                                type: str
                    channel_bonding:
                        description:
                            - 'Channel bandwidth: 320, 240, 160, 80, 40, or 20MHz. Channels may use both 20 and 40 by enabling coexistence.'
                        type: str
                        choices:
                            - '320MHz'
                            - '240MHz'
                            - '160MHz'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
                    channel_bonding_ext:
                        description:
                            - 'Channel bandwidth extension: 320 MHz-1 and 320 MHz-2 .'
                        type: str
                        choices:
                            - '320MHz-1'
                            - '320MHz-2'
                    channel_utilization:
                        description:
                            - Enable/disable measuring channel utilization.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    coexistence:
                        description:
                            - Enable/disable allowing both HT20 and HT40 on the same radio .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    darrp:
                        description:
                            - Enable/disable Distributed Automatic Radio Resource Provisioning (DARRP) to make sure the radio is always using the most optimal
                               channel .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    drma:
                        description:
                            - Enable/disable dynamic radio mode assignment (DRMA) .
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    drma_sensitivity:
                        description:
                            - Network Coverage Factor (NCF) percentage required to consider a radio as redundant .
                        type: str
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    dtim:
                        description:
                            - Delivery Traffic Indication Map (DTIM) period (1 - 255). Set higher to save battery life of WiFi client in power-save mode.
                        type: int
                    frag_threshold:
                        description:
                            - Maximum packet size that can be sent without fragmentation (800 - 2346 bytes).
                        type: int
                    frequency_handoff:
                        description:
                            - Enable/disable frequency handoff of clients to other channels .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    iperf_protocol:
                        description:
                            - Iperf test protocol .
                        type: str
                        choices:
                            - 'udp'
                            - 'tcp'
                    iperf_server_port:
                        description:
                            - Iperf service port number.
                        type: int
                    max_clients:
                        description:
                            - Maximum number of stations (STAs) or WiFi clients supported by the radio. Range depends on the hardware.
                        type: int
                    max_distance:
                        description:
                            - Maximum expected distance between the AP and clients (0 - 54000 m).
                        type: int
                    mimo_mode:
                        description:
                            - Configure radio MIMO mode .
                        type: str
                        choices:
                            - 'default'
                            - '1x1'
                            - '2x2'
                            - '3x3'
                            - '4x4'
                            - '8x8'
                    mode:
                        description:
                            - Mode of radio 1. Radio 1 can be disabled, configured as an access point, a rogue AP monitor, a sniffer, or a station.
                        type: str
                        choices:
                            - 'disabled'
                            - 'ap'
                            - 'monitor'
                            - 'sniffer'
                            - 'sam'
                    optional_antenna:
                        description:
                            - Optional antenna used on FAP .
                        type: str
                        choices:
                            - 'none'
                            - 'custom'
                            - 'FANT-04ABGN-0606-O-N'
                            - 'FANT-04ABGN-1414-P-N'
                            - 'FANT-04ABGN-8065-P-N'
                            - 'FANT-04ABGN-0606-O-R'
                            - 'FANT-04ABGN-0606-P-R'
                            - 'FANT-10ACAX-1213-D-N'
                            - 'FANT-08ABGN-1213-D-R'
                            - 'FANT-04BEAX-0606-P-R'
                    optional_antenna_gain:
                        description:
                            - Optional antenna gain in dBi (0 to 20).
                        type: str
                    power_level:
                        description:
                            - Radio EIRP power level as a percentage of the maximum EIRP power (0 - 100).
                        type: int
                    power_mode:
                        description:
                            - Set radio effective isotropic radiated power (EIRP) in dBm or by a percentage of the maximum EIRP . This power takes into
                               account both radio transmit power and antenna gain. Higher power level settings may be constrained by local regulatory
                                  requirements and AP capabilities.
                        type: str
                        choices:
                            - 'dBm'
                            - 'percentage'
                    power_value:
                        description:
                            - Radio EIRP power in dBm (1 - 33).
                        type: int
                    powersave_optimize:
                        description:
                            - Enable client power-saving features such as TIM, AC VO, and OBSS etc.
                        type: list
                        elements: str
                        choices:
                            - 'tim'
                            - 'ac-vo'
                            - 'no-obss-scan'
                            - 'no-11b-rate'
                            - 'client-rate-follow'
                    protection_mode:
                        description:
                            - Enable/disable 802.11g protection modes to support backwards compatibility with older clients (rtscts, ctsonly, disable).
                        type: str
                        choices:
                            - 'rtscts'
                            - 'ctsonly'
                            - 'disable'
                    radio_id:
                        description:
                            - radio-id
                        type: int
                    rts_threshold:
                        description:
                            - Maximum packet size for RTS transmissions, specifying the maximum size of a data packet before RTS/CTS (256 - 2346 bytes).
                        type: int
                    sam_bssid:
                        description:
                            - BSSID for WiFi network.
                        type: str
                    sam_ca_certificate:
                        description:
                            - CA certificate for WPA2/WPA3-ENTERPRISE. Source vpn.certificate.ca.name.
                        type: str
                    sam_captive_portal:
                        description:
                            - Enable/disable Captive Portal Authentication .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    sam_client_certificate:
                        description:
                            - Client certificate for WPA2/WPA3-ENTERPRISE. Source vpn.certificate.local.name.
                        type: str
                    sam_cwp_failure_string:
                        description:
                            - Failure identification on the page after an incorrect login.
                        type: str
                    sam_cwp_match_string:
                        description:
                            - Identification string from the captive portal login form.
                        type: str
                    sam_cwp_password:
                        description:
                            - Password for captive portal authentication.
                        type: str
                    sam_cwp_success_string:
                        description:
                            - Success identification on the page after a successful login.
                        type: str
                    sam_cwp_test_url:
                        description:
                            - Website the client is trying to access.
                        type: str
                    sam_cwp_username:
                        description:
                            - Username for captive portal authentication.
                        type: str
                    sam_eap_method:
                        description:
                            - Select WPA2/WPA3-ENTERPRISE EAP Method .
                        type: str
                        choices:
                            - 'both'
                            - 'tls'
                            - 'peap'
                    sam_password:
                        description:
                            - Passphrase for WiFi network connection.
                        type: str
                    sam_private_key:
                        description:
                            - Private key for WPA2/WPA3-ENTERPRISE. Source vpn.certificate.local.name.
                        type: str
                    sam_private_key_password:
                        description:
                            - Password for private key file for WPA2/WPA3-ENTERPRISE.
                        type: str
                    sam_report_intv:
                        description:
                            - SAM report interval (sec), 0 for a one-time report.
                        type: int
                    sam_security_type:
                        description:
                            - Select WiFi network security type .
                        type: str
                        choices:
                            - 'open'
                            - 'wpa-personal'
                            - 'wpa-enterprise'
                            - 'wpa3-sae'
                            - 'owe'
                    sam_server:
                        description:
                            - SAM test server IP address or domain name.
                        type: str
                    sam_server_fqdn:
                        description:
                            - SAM test server domain name.
                        type: str
                    sam_server_ip:
                        description:
                            - SAM test server IP address.
                        type: str
                    sam_server_type:
                        description:
                            - Select SAM server type .
                        type: str
                        choices:
                            - 'ip'
                            - 'fqdn'
                    sam_ssid:
                        description:
                            - SSID for WiFi network.
                        type: str
                    sam_test:
                        description:
                            - Select SAM test type .
                        type: str
                        choices:
                            - 'ping'
                            - 'iperf'
                    sam_username:
                        description:
                            - Username for WiFi network connection.
                        type: str
                    set_80211d:
                        description:
                            - Enable/disable 802.11d countryie.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    set_80211mc:
                        description:
                            - Enable/disable 802.11mc responder mode .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    short_guard_interval:
                        description:
                            - Use either the short guard interval (Short GI) of 400 ns or the long guard interval (Long GI) of 800 ns.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    spectrum_analysis:
                        description:
                            - Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        type: str
                        choices:
                            - 'enable'
                            - 'scan-only'
                            - 'disable'
                    transmit_optimize:
                        description:
                            - Packet transmission optimization options including power saving, aggregation limiting, retry limiting, etc. All are enabled by
                               default.
                        type: list
                        elements: str
                        choices:
                            - 'disable'
                            - 'power-save'
                            - 'aggr-limit'
                            - 'retry-limit'
                            - 'send-bar'
                    vap_all:
                        description:
                            - Configure method for assigning SSIDs to this FortiAP .
                        type: str
                        choices:
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
                            - 'enable'
                            - 'disable'
                    vaps:
                        description:
                            - Manually selected list of Virtual Access Points (VAPs).
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Virtual Access Point (VAP) name. Source wireless-controller.vap-group.name system.interface.name.
                                required: true
                                type: str
                    wids_profile:
                        description:
                            - Wireless Intrusion Detection System (WIDS) profile name to assign to the radio. Source wireless-controller.wids-profile.name.
                        type: str
                    zero_wait_dfs:
                        description:
                            - Enable/disable zero wait DFS on radio .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            radio_2:
                description:
                    - Configuration options for radio 2.
                type: dict
                suboptions:
                    airtime_fairness:
                        description:
                            - Enable/disable airtime fairness .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    amsdu:
                        description:
                            - Enable/disable 802.11n AMSDU support. AMSDU can improve performance if supported by your WiFi clients .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_handoff:
                        description:
                            - Enable/disable AP handoff of clients to other APs .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_addr:
                        description:
                            - MAC address to monitor.
                        type: str
                    ap_sniffer_bufsize:
                        description:
                            - Sniffer buffer size (1 - 32 MB).
                        type: int
                    ap_sniffer_chan:
                        description:
                            - Channel on which to operate the sniffer .
                        type: int
                    ap_sniffer_chan_width:
                        description:
                            - Channel bandwidth for sniffer.
                        type: str
                        choices:
                            - '320MHz'
                            - '240MHz'
                            - '160MHz'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
                    ap_sniffer_ctl:
                        description:
                            - Enable/disable sniffer on WiFi control frame .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_data:
                        description:
                            - Enable/disable sniffer on WiFi data frame .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_mgmt_beacon:
                        description:
                            - Enable/disable sniffer on WiFi management Beacon frames .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_mgmt_other:
                        description:
                            - Enable/disable sniffer on WiFi management other frames  .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_mgmt_probe:
                        description:
                            - Enable/disable sniffer on WiFi management probe frames .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    arrp_profile:
                        description:
                            - Distributed Automatic Radio Resource Provisioning (DARRP) profile name to assign to the radio. Source wireless-controller
                              .arrp-profile.name.
                        type: str
                    auto_power_high:
                        description:
                            - The upper bound of automatic transmit power adjustment in dBm (the actual range of transmit power depends on the AP platform
                               type).
                        type: int
                    auto_power_level:
                        description:
                            - Enable/disable automatic power-level adjustment to prevent co-channel interference .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    auto_power_low:
                        description:
                            - The lower bound of automatic transmit power adjustment in dBm (the actual range of transmit power depends on the AP platform
                               type).
                        type: int
                    auto_power_target:
                        description:
                            - Target of automatic transmit power adjustment in dBm (-95 to -20).
                        type: str
                    band:
                        description:
                            - WiFi band that Radio 2 operates on.
                        type: list
                        elements: str
                        choices:
                            - '802.11a'
                            - '802.11b'
                            - '802.11g'
                            - '802.11n-2G'
                            - '802.11n-5G'
                            - '802.11ac-2G'
                            - '802.11ac-5G'
                            - '802.11ax-2G'
                            - '802.11ax-5G'
                            - '802.11ax-6G'
                            - '802.11be-2G'
                            - '802.11be-5G'
                            - '802.11be-6G'
                            - '802.11n'
                            - '802.11ac'
                            - '802.11ax'
                            - '802.11n,g-only'
                            - '802.11g-only'
                            - '802.11n-only'
                            - '802.11n-5G-only'
                            - '802.11ac,n-only'
                            - '802.11ac-only'
                            - '802.11ax,ac-only'
                            - '802.11ax,ac,n-only'
                            - '802.11ax-5G-only'
                            - '802.11ax,n-only'
                            - '802.11ax,n,g-only'
                            - '802.11ax-only'
                    band_5g_type:
                        description:
                            - WiFi 5G band type.
                        type: str
                        choices:
                            - '5g-full'
                            - '5g-high'
                            - '5g-low'
                    bandwidth_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) bandwidth admission control to optimize WiFi bandwidth use. A request to join the wireless
                               network is only allowed if the access point has enough bandwidth to support it.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bandwidth_capacity:
                        description:
                            - Maximum bandwidth capacity allowed (1 - 600000 Kbps).
                        type: int
                    beacon_interval:
                        description:
                            - Beacon interval. The time between beacon frames in milliseconds. Actual range of beacon interval depends on the AP platform type
                               .
                        type: int
                    bss_color:
                        description:
                            - BSS color value for this 11ax radio (0 - 63, disable = 0).
                        type: int
                    bss_color_mode:
                        description:
                            - BSS color mode for this 11ax radio .
                        type: str
                        choices:
                            - 'auto'
                            - 'static'
                    call_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) call admission control to optimize WiFi bandwidth use for VoIP calls. New VoIP calls are
                               only accepted if there is enough bandwidth available to support them.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    call_capacity:
                        description:
                            - Maximum number of Voice over WLAN (VoWLAN) phones supported by the radio (0 - 60).
                        type: int
                    channel:
                        description:
                            - Selected list of wireless radio channels.
                        type: list
                        elements: dict
                        suboptions:
                            chan:
                                description:
                                    - Channel number.
                                required: true
                                type: str
                    channel_bonding:
                        description:
                            - 'Channel bandwidth: 320, 240, 160, 80, 40, or 20MHz. Channels may use both 20 and 40 by enabling coexistence.'
                        type: str
                        choices:
                            - '320MHz'
                            - '240MHz'
                            - '160MHz'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
                    channel_bonding_ext:
                        description:
                            - 'Channel bandwidth extension: 320 MHz-1 and 320 MHz-2 .'
                        type: str
                        choices:
                            - '320MHz-1'
                            - '320MHz-2'
                    channel_utilization:
                        description:
                            - Enable/disable measuring channel utilization.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    coexistence:
                        description:
                            - Enable/disable allowing both HT20 and HT40 on the same radio .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    darrp:
                        description:
                            - Enable/disable Distributed Automatic Radio Resource Provisioning (DARRP) to make sure the radio is always using the most optimal
                               channel .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    drma:
                        description:
                            - Enable/disable dynamic radio mode assignment (DRMA) .
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    drma_sensitivity:
                        description:
                            - Network Coverage Factor (NCF) percentage required to consider a radio as redundant .
                        type: str
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    dtim:
                        description:
                            - Delivery Traffic Indication Map (DTIM) period (1 - 255). Set higher to save battery life of WiFi client in power-save mode.
                        type: int
                    frag_threshold:
                        description:
                            - Maximum packet size that can be sent without fragmentation (800 - 2346 bytes).
                        type: int
                    frequency_handoff:
                        description:
                            - Enable/disable frequency handoff of clients to other channels .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    iperf_protocol:
                        description:
                            - Iperf test protocol .
                        type: str
                        choices:
                            - 'udp'
                            - 'tcp'
                    iperf_server_port:
                        description:
                            - Iperf service port number.
                        type: int
                    max_clients:
                        description:
                            - Maximum number of stations (STAs) or WiFi clients supported by the radio. Range depends on the hardware.
                        type: int
                    max_distance:
                        description:
                            - Maximum expected distance between the AP and clients (0 - 54000 m).
                        type: int
                    mimo_mode:
                        description:
                            - Configure radio MIMO mode .
                        type: str
                        choices:
                            - 'default'
                            - '1x1'
                            - '2x2'
                            - '3x3'
                            - '4x4'
                            - '8x8'
                    mode:
                        description:
                            - Mode of radio 2. Radio 2 can be disabled, configured as an access point, a rogue AP monitor, a sniffer, or a station.
                        type: str
                        choices:
                            - 'disabled'
                            - 'ap'
                            - 'monitor'
                            - 'sniffer'
                            - 'sam'
                    optional_antenna:
                        description:
                            - Optional antenna used on FAP .
                        type: str
                        choices:
                            - 'none'
                            - 'custom'
                            - 'FANT-04ABGN-0606-O-N'
                            - 'FANT-04ABGN-1414-P-N'
                            - 'FANT-04ABGN-8065-P-N'
                            - 'FANT-04ABGN-0606-O-R'
                            - 'FANT-04ABGN-0606-P-R'
                            - 'FANT-10ACAX-1213-D-N'
                            - 'FANT-08ABGN-1213-D-R'
                            - 'FANT-04BEAX-0606-P-R'
                    optional_antenna_gain:
                        description:
                            - Optional antenna gain in dBi (0 to 20).
                        type: str
                    power_level:
                        description:
                            - Radio EIRP power level as a percentage of the maximum EIRP power (0 - 100).
                        type: int
                    power_mode:
                        description:
                            - Set radio effective isotropic radiated power (EIRP) in dBm or by a percentage of the maximum EIRP . This power takes into
                               account both radio transmit power and antenna gain. Higher power level settings may be constrained by local regulatory
                                  requirements and AP capabilities.
                        type: str
                        choices:
                            - 'dBm'
                            - 'percentage'
                    power_value:
                        description:
                            - Radio EIRP power in dBm (1 - 33).
                        type: int
                    powersave_optimize:
                        description:
                            - Enable client power-saving features such as TIM, AC VO, and OBSS etc.
                        type: list
                        elements: str
                        choices:
                            - 'tim'
                            - 'ac-vo'
                            - 'no-obss-scan'
                            - 'no-11b-rate'
                            - 'client-rate-follow'
                    protection_mode:
                        description:
                            - Enable/disable 802.11g protection modes to support backwards compatibility with older clients (rtscts, ctsonly, disable).
                        type: str
                        choices:
                            - 'rtscts'
                            - 'ctsonly'
                            - 'disable'
                    radio_id:
                        description:
                            - radio-id
                        type: int
                    rts_threshold:
                        description:
                            - Maximum packet size for RTS transmissions, specifying the maximum size of a data packet before RTS/CTS (256 - 2346 bytes).
                        type: int
                    sam_bssid:
                        description:
                            - BSSID for WiFi network.
                        type: str
                    sam_ca_certificate:
                        description:
                            - CA certificate for WPA2/WPA3-ENTERPRISE. Source vpn.certificate.ca.name.
                        type: str
                    sam_captive_portal:
                        description:
                            - Enable/disable Captive Portal Authentication .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    sam_client_certificate:
                        description:
                            - Client certificate for WPA2/WPA3-ENTERPRISE. Source vpn.certificate.local.name.
                        type: str
                    sam_cwp_failure_string:
                        description:
                            - Failure identification on the page after an incorrect login.
                        type: str
                    sam_cwp_match_string:
                        description:
                            - Identification string from the captive portal login form.
                        type: str
                    sam_cwp_password:
                        description:
                            - Password for captive portal authentication.
                        type: str
                    sam_cwp_success_string:
                        description:
                            - Success identification on the page after a successful login.
                        type: str
                    sam_cwp_test_url:
                        description:
                            - Website the client is trying to access.
                        type: str
                    sam_cwp_username:
                        description:
                            - Username for captive portal authentication.
                        type: str
                    sam_eap_method:
                        description:
                            - Select WPA2/WPA3-ENTERPRISE EAP Method .
                        type: str
                        choices:
                            - 'both'
                            - 'tls'
                            - 'peap'
                    sam_password:
                        description:
                            - Passphrase for WiFi network connection.
                        type: str
                    sam_private_key:
                        description:
                            - Private key for WPA2/WPA3-ENTERPRISE. Source vpn.certificate.local.name.
                        type: str
                    sam_private_key_password:
                        description:
                            - Password for private key file for WPA2/WPA3-ENTERPRISE.
                        type: str
                    sam_report_intv:
                        description:
                            - SAM report interval (sec), 0 for a one-time report.
                        type: int
                    sam_security_type:
                        description:
                            - Select WiFi network security type .
                        type: str
                        choices:
                            - 'open'
                            - 'wpa-personal'
                            - 'wpa-enterprise'
                            - 'wpa3-sae'
                            - 'owe'
                    sam_server:
                        description:
                            - SAM test server IP address or domain name.
                        type: str
                    sam_server_fqdn:
                        description:
                            - SAM test server domain name.
                        type: str
                    sam_server_ip:
                        description:
                            - SAM test server IP address.
                        type: str
                    sam_server_type:
                        description:
                            - Select SAM server type .
                        type: str
                        choices:
                            - 'ip'
                            - 'fqdn'
                    sam_ssid:
                        description:
                            - SSID for WiFi network.
                        type: str
                    sam_test:
                        description:
                            - Select SAM test type .
                        type: str
                        choices:
                            - 'ping'
                            - 'iperf'
                    sam_username:
                        description:
                            - Username for WiFi network connection.
                        type: str
                    set_80211d:
                        description:
                            - Enable/disable 802.11d countryie.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    set_80211mc:
                        description:
                            - Enable/disable 802.11mc responder mode .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    short_guard_interval:
                        description:
                            - Use either the short guard interval (Short GI) of 400 ns or the long guard interval (Long GI) of 800 ns.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    spectrum_analysis:
                        description:
                            - Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        type: str
                        choices:
                            - 'enable'
                            - 'scan-only'
                            - 'disable'
                    transmit_optimize:
                        description:
                            - Packet transmission optimization options including power saving, aggregation limiting, retry limiting, etc. All are enabled by
                               default.
                        type: list
                        elements: str
                        choices:
                            - 'disable'
                            - 'power-save'
                            - 'aggr-limit'
                            - 'retry-limit'
                            - 'send-bar'
                    vap_all:
                        description:
                            - Configure method for assigning SSIDs to this FortiAP .
                        type: str
                        choices:
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
                            - 'enable'
                            - 'disable'
                    vaps:
                        description:
                            - Manually selected list of Virtual Access Points (VAPs).
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Virtual Access Point (VAP) name. Source wireless-controller.vap-group.name system.interface.name.
                                required: true
                                type: str
                    wids_profile:
                        description:
                            - Wireless Intrusion Detection System (WIDS) profile name to assign to the radio. Source wireless-controller.wids-profile.name.
                        type: str
                    zero_wait_dfs:
                        description:
                            - Enable/disable zero wait DFS on radio .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            radio_3:
                description:
                    - Configuration options for radio 3.
                type: dict
                suboptions:
                    airtime_fairness:
                        description:
                            - Enable/disable airtime fairness .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    amsdu:
                        description:
                            - Enable/disable 802.11n AMSDU support. AMSDU can improve performance if supported by your WiFi clients .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_handoff:
                        description:
                            - Enable/disable AP handoff of clients to other APs .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_addr:
                        description:
                            - MAC address to monitor.
                        type: str
                    ap_sniffer_bufsize:
                        description:
                            - Sniffer buffer size (1 - 32 MB).
                        type: int
                    ap_sniffer_chan:
                        description:
                            - Channel on which to operate the sniffer .
                        type: int
                    ap_sniffer_chan_width:
                        description:
                            - Channel bandwidth for sniffer.
                        type: str
                        choices:
                            - '320MHz'
                            - '240MHz'
                            - '160MHz'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
                    ap_sniffer_ctl:
                        description:
                            - Enable/disable sniffer on WiFi control frame .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_data:
                        description:
                            - Enable/disable sniffer on WiFi data frame .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_mgmt_beacon:
                        description:
                            - Enable/disable sniffer on WiFi management Beacon frames .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_mgmt_other:
                        description:
                            - Enable/disable sniffer on WiFi management other frames  .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_mgmt_probe:
                        description:
                            - Enable/disable sniffer on WiFi management probe frames .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    arrp_profile:
                        description:
                            - Distributed Automatic Radio Resource Provisioning (DARRP) profile name to assign to the radio. Source wireless-controller
                              .arrp-profile.name.
                        type: str
                    auto_power_high:
                        description:
                            - The upper bound of automatic transmit power adjustment in dBm (the actual range of transmit power depends on the AP platform
                               type).
                        type: int
                    auto_power_level:
                        description:
                            - Enable/disable automatic power-level adjustment to prevent co-channel interference .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    auto_power_low:
                        description:
                            - The lower bound of automatic transmit power adjustment in dBm (the actual range of transmit power depends on the AP platform
                               type).
                        type: int
                    auto_power_target:
                        description:
                            - Target of automatic transmit power adjustment in dBm (-95 to -20).
                        type: str
                    band:
                        description:
                            - WiFi band that Radio 3 operates on.
                        type: list
                        elements: str
                        choices:
                            - '802.11a'
                            - '802.11b'
                            - '802.11g'
                            - '802.11n-2G'
                            - '802.11n-5G'
                            - '802.11ac-2G'
                            - '802.11ac-5G'
                            - '802.11ax-2G'
                            - '802.11ax-5G'
                            - '802.11ax-6G'
                            - '802.11be-2G'
                            - '802.11be-5G'
                            - '802.11be-6G'
                            - '802.11n'
                            - '802.11ac'
                            - '802.11ax'
                            - '802.11n,g-only'
                            - '802.11g-only'
                            - '802.11n-only'
                            - '802.11n-5G-only'
                            - '802.11ac,n-only'
                            - '802.11ac-only'
                            - '802.11ax,ac-only'
                            - '802.11ax,ac,n-only'
                            - '802.11ax-5G-only'
                            - '802.11ax,n-only'
                            - '802.11ax,n,g-only'
                            - '802.11ax-only'
                    band_5g_type:
                        description:
                            - WiFi 5G band type.
                        type: str
                        choices:
                            - '5g-full'
                            - '5g-high'
                            - '5g-low'
                    bandwidth_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) bandwidth admission control to optimize WiFi bandwidth use. A request to join the wireless
                               network is only allowed if the access point has enough bandwidth to support it.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bandwidth_capacity:
                        description:
                            - Maximum bandwidth capacity allowed (1 - 600000 Kbps).
                        type: int
                    beacon_interval:
                        description:
                            - Beacon interval. The time between beacon frames in milliseconds. Actual range of beacon interval depends on the AP platform type
                               .
                        type: int
                    bss_color:
                        description:
                            - BSS color value for this 11ax radio (0 - 63, disable = 0).
                        type: int
                    bss_color_mode:
                        description:
                            - BSS color mode for this 11ax radio .
                        type: str
                        choices:
                            - 'auto'
                            - 'static'
                    call_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) call admission control to optimize WiFi bandwidth use for VoIP calls. New VoIP calls are
                               only accepted if there is enough bandwidth available to support them.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    call_capacity:
                        description:
                            - Maximum number of Voice over WLAN (VoWLAN) phones supported by the radio (0 - 60).
                        type: int
                    channel:
                        description:
                            - Selected list of wireless radio channels.
                        type: list
                        elements: dict
                        suboptions:
                            chan:
                                description:
                                    - Channel number.
                                required: true
                                type: str
                    channel_bonding:
                        description:
                            - 'Channel bandwidth: 320, 240, 160, 80, 40, or 20MHz. Channels may use both 20 and 40 by enabling coexistence.'
                        type: str
                        choices:
                            - '320MHz'
                            - '240MHz'
                            - '160MHz'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
                    channel_bonding_ext:
                        description:
                            - 'Channel bandwidth extension: 320 MHz-1 and 320 MHz-2 .'
                        type: str
                        choices:
                            - '320MHz-1'
                            - '320MHz-2'
                    channel_utilization:
                        description:
                            - Enable/disable measuring channel utilization.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    coexistence:
                        description:
                            - Enable/disable allowing both HT20 and HT40 on the same radio .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    darrp:
                        description:
                            - Enable/disable Distributed Automatic Radio Resource Provisioning (DARRP) to make sure the radio is always using the most optimal
                               channel .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    drma:
                        description:
                            - Enable/disable dynamic radio mode assignment (DRMA) .
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    drma_sensitivity:
                        description:
                            - Network Coverage Factor (NCF) percentage required to consider a radio as redundant .
                        type: str
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    dtim:
                        description:
                            - Delivery Traffic Indication Map (DTIM) period (1 - 255). Set higher to save battery life of WiFi client in power-save mode.
                        type: int
                    frag_threshold:
                        description:
                            - Maximum packet size that can be sent without fragmentation (800 - 2346 bytes).
                        type: int
                    frequency_handoff:
                        description:
                            - Enable/disable frequency handoff of clients to other channels .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    iperf_protocol:
                        description:
                            - Iperf test protocol .
                        type: str
                        choices:
                            - 'udp'
                            - 'tcp'
                    iperf_server_port:
                        description:
                            - Iperf service port number.
                        type: int
                    max_clients:
                        description:
                            - Maximum number of stations (STAs) or WiFi clients supported by the radio. Range depends on the hardware.
                        type: int
                    max_distance:
                        description:
                            - Maximum expected distance between the AP and clients (0 - 54000 m).
                        type: int
                    mimo_mode:
                        description:
                            - Configure radio MIMO mode .
                        type: str
                        choices:
                            - 'default'
                            - '1x1'
                            - '2x2'
                            - '3x3'
                            - '4x4'
                            - '8x8'
                    mode:
                        description:
                            - Mode of radio 3. Radio 3 can be disabled, configured as an access point, a rogue AP monitor, a sniffer, or a station.
                        type: str
                        choices:
                            - 'disabled'
                            - 'ap'
                            - 'monitor'
                            - 'sniffer'
                            - 'sam'
                    optional_antenna:
                        description:
                            - Optional antenna used on FAP .
                        type: str
                        choices:
                            - 'none'
                            - 'custom'
                            - 'FANT-04ABGN-0606-O-N'
                            - 'FANT-04ABGN-1414-P-N'
                            - 'FANT-04ABGN-8065-P-N'
                            - 'FANT-04ABGN-0606-O-R'
                            - 'FANT-04ABGN-0606-P-R'
                            - 'FANT-10ACAX-1213-D-N'
                            - 'FANT-08ABGN-1213-D-R'
                            - 'FANT-04BEAX-0606-P-R'
                    optional_antenna_gain:
                        description:
                            - Optional antenna gain in dBi (0 to 20).
                        type: str
                    power_level:
                        description:
                            - Radio EIRP power level as a percentage of the maximum EIRP power (0 - 100).
                        type: int
                    power_mode:
                        description:
                            - Set radio effective isotropic radiated power (EIRP) in dBm or by a percentage of the maximum EIRP . This power takes into
                               account both radio transmit power and antenna gain. Higher power level settings may be constrained by local regulatory
                                  requirements and AP capabilities.
                        type: str
                        choices:
                            - 'dBm'
                            - 'percentage'
                    power_value:
                        description:
                            - Radio EIRP power in dBm (1 - 33).
                        type: int
                    powersave_optimize:
                        description:
                            - Enable client power-saving features such as TIM, AC VO, and OBSS etc.
                        type: list
                        elements: str
                        choices:
                            - 'tim'
                            - 'ac-vo'
                            - 'no-obss-scan'
                            - 'no-11b-rate'
                            - 'client-rate-follow'
                    protection_mode:
                        description:
                            - Enable/disable 802.11g protection modes to support backwards compatibility with older clients (rtscts, ctsonly, disable).
                        type: str
                        choices:
                            - 'rtscts'
                            - 'ctsonly'
                            - 'disable'
                    radio_id:
                        description:
                            - radio-id
                        type: int
                    rts_threshold:
                        description:
                            - Maximum packet size for RTS transmissions, specifying the maximum size of a data packet before RTS/CTS (256 - 2346 bytes).
                        type: int
                    sam_bssid:
                        description:
                            - BSSID for WiFi network.
                        type: str
                    sam_ca_certificate:
                        description:
                            - CA certificate for WPA2/WPA3-ENTERPRISE. Source vpn.certificate.ca.name.
                        type: str
                    sam_captive_portal:
                        description:
                            - Enable/disable Captive Portal Authentication .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    sam_client_certificate:
                        description:
                            - Client certificate for WPA2/WPA3-ENTERPRISE. Source vpn.certificate.local.name.
                        type: str
                    sam_cwp_failure_string:
                        description:
                            - Failure identification on the page after an incorrect login.
                        type: str
                    sam_cwp_match_string:
                        description:
                            - Identification string from the captive portal login form.
                        type: str
                    sam_cwp_password:
                        description:
                            - Password for captive portal authentication.
                        type: str
                    sam_cwp_success_string:
                        description:
                            - Success identification on the page after a successful login.
                        type: str
                    sam_cwp_test_url:
                        description:
                            - Website the client is trying to access.
                        type: str
                    sam_cwp_username:
                        description:
                            - Username for captive portal authentication.
                        type: str
                    sam_eap_method:
                        description:
                            - Select WPA2/WPA3-ENTERPRISE EAP Method .
                        type: str
                        choices:
                            - 'both'
                            - 'tls'
                            - 'peap'
                    sam_password:
                        description:
                            - Passphrase for WiFi network connection.
                        type: str
                    sam_private_key:
                        description:
                            - Private key for WPA2/WPA3-ENTERPRISE. Source vpn.certificate.local.name.
                        type: str
                    sam_private_key_password:
                        description:
                            - Password for private key file for WPA2/WPA3-ENTERPRISE.
                        type: str
                    sam_report_intv:
                        description:
                            - SAM report interval (sec), 0 for a one-time report.
                        type: int
                    sam_security_type:
                        description:
                            - Select WiFi network security type .
                        type: str
                        choices:
                            - 'open'
                            - 'wpa-personal'
                            - 'wpa-enterprise'
                            - 'wpa3-sae'
                            - 'owe'
                    sam_server:
                        description:
                            - SAM test server IP address or domain name.
                        type: str
                    sam_server_fqdn:
                        description:
                            - SAM test server domain name.
                        type: str
                    sam_server_ip:
                        description:
                            - SAM test server IP address.
                        type: str
                    sam_server_type:
                        description:
                            - Select SAM server type .
                        type: str
                        choices:
                            - 'ip'
                            - 'fqdn'
                    sam_ssid:
                        description:
                            - SSID for WiFi network.
                        type: str
                    sam_test:
                        description:
                            - Select SAM test type .
                        type: str
                        choices:
                            - 'ping'
                            - 'iperf'
                    sam_username:
                        description:
                            - Username for WiFi network connection.
                        type: str
                    set_80211d:
                        description:
                            - Enable/disable 802.11d countryie.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    set_80211mc:
                        description:
                            - Enable/disable 802.11mc responder mode .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    short_guard_interval:
                        description:
                            - Use either the short guard interval (Short GI) of 400 ns or the long guard interval (Long GI) of 800 ns.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    spectrum_analysis:
                        description:
                            - Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        type: str
                        choices:
                            - 'enable'
                            - 'scan-only'
                            - 'disable'
                    transmit_optimize:
                        description:
                            - Packet transmission optimization options including power saving, aggregation limiting, retry limiting, etc. All are enabled by
                               default.
                        type: list
                        elements: str
                        choices:
                            - 'disable'
                            - 'power-save'
                            - 'aggr-limit'
                            - 'retry-limit'
                            - 'send-bar'
                    vap_all:
                        description:
                            - Configure method for assigning SSIDs to this FortiAP .
                        type: str
                        choices:
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
                            - 'enable'
                            - 'disable'
                    vaps:
                        description:
                            - Manually selected list of Virtual Access Points (VAPs).
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Virtual Access Point (VAP) name. Source wireless-controller.vap-group.name system.interface.name.
                                required: true
                                type: str
                    wids_profile:
                        description:
                            - Wireless Intrusion Detection System (WIDS) profile name to assign to the radio. Source wireless-controller.wids-profile.name.
                        type: str
                    zero_wait_dfs:
                        description:
                            - Enable/disable zero wait DFS on radio .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            radio_4:
                description:
                    - Configuration options for radio 4.
                type: dict
                suboptions:
                    airtime_fairness:
                        description:
                            - Enable/disable airtime fairness .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    amsdu:
                        description:
                            - Enable/disable 802.11n AMSDU support. AMSDU can improve performance if supported by your WiFi clients .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_handoff:
                        description:
                            - Enable/disable AP handoff of clients to other APs .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_addr:
                        description:
                            - MAC address to monitor.
                        type: str
                    ap_sniffer_bufsize:
                        description:
                            - Sniffer buffer size (1 - 32 MB).
                        type: int
                    ap_sniffer_chan:
                        description:
                            - Channel on which to operate the sniffer .
                        type: int
                    ap_sniffer_chan_width:
                        description:
                            - Channel bandwidth for sniffer.
                        type: str
                        choices:
                            - '320MHz'
                            - '240MHz'
                            - '160MHz'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
                    ap_sniffer_ctl:
                        description:
                            - Enable/disable sniffer on WiFi control frame .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_data:
                        description:
                            - Enable/disable sniffer on WiFi data frame .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_mgmt_beacon:
                        description:
                            - Enable/disable sniffer on WiFi management Beacon frames .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_mgmt_other:
                        description:
                            - Enable/disable sniffer on WiFi management other frames  .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ap_sniffer_mgmt_probe:
                        description:
                            - Enable/disable sniffer on WiFi management probe frames .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    arrp_profile:
                        description:
                            - Distributed Automatic Radio Resource Provisioning (DARRP) profile name to assign to the radio. Source wireless-controller
                              .arrp-profile.name.
                        type: str
                    auto_power_high:
                        description:
                            - The upper bound of automatic transmit power adjustment in dBm (the actual range of transmit power depends on the AP platform
                               type).
                        type: int
                    auto_power_level:
                        description:
                            - Enable/disable automatic power-level adjustment to prevent co-channel interference .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    auto_power_low:
                        description:
                            - The lower bound of automatic transmit power adjustment in dBm (the actual range of transmit power depends on the AP platform
                               type).
                        type: int
                    auto_power_target:
                        description:
                            - Target of automatic transmit power adjustment in dBm (-95 to -20).
                        type: str
                    band:
                        description:
                            - WiFi band that Radio 4 operates on.
                        type: list
                        elements: str
                        choices:
                            - '802.11a'
                            - '802.11b'
                            - '802.11g'
                            - '802.11n-2G'
                            - '802.11n-5G'
                            - '802.11ac-2G'
                            - '802.11ac-5G'
                            - '802.11ax-2G'
                            - '802.11ax-5G'
                            - '802.11ax-6G'
                            - '802.11be-2G'
                            - '802.11be-5G'
                            - '802.11be-6G'
                            - '802.11n'
                            - '802.11ac'
                            - '802.11ax'
                            - '802.11n,g-only'
                            - '802.11g-only'
                            - '802.11n-only'
                            - '802.11n-5G-only'
                            - '802.11ac,n-only'
                            - '802.11ac-only'
                            - '802.11ax,ac-only'
                            - '802.11ax,ac,n-only'
                            - '802.11ax-5G-only'
                            - '802.11ax,n-only'
                            - '802.11ax,n,g-only'
                            - '802.11ax-only'
                    band_5g_type:
                        description:
                            - WiFi 5G band type.
                        type: str
                        choices:
                            - '5g-full'
                            - '5g-high'
                            - '5g-low'
                    bandwidth_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) bandwidth admission control to optimize WiFi bandwidth use. A request to join the wireless
                               network is only allowed if the access point has enough bandwidth to support it.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bandwidth_capacity:
                        description:
                            - Maximum bandwidth capacity allowed (1 - 600000 Kbps).
                        type: int
                    beacon_interval:
                        description:
                            - Beacon interval. The time between beacon frames in milliseconds. Actual range of beacon interval depends on the AP platform type
                               .
                        type: int
                    bss_color:
                        description:
                            - BSS color value for this 11ax radio (0 - 63, disable = 0).
                        type: int
                    bss_color_mode:
                        description:
                            - BSS color mode for this 11ax radio .
                        type: str
                        choices:
                            - 'auto'
                            - 'static'
                    call_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) call admission control to optimize WiFi bandwidth use for VoIP calls. New VoIP calls are
                               only accepted if there is enough bandwidth available to support them.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    call_capacity:
                        description:
                            - Maximum number of Voice over WLAN (VoWLAN) phones supported by the radio (0 - 60).
                        type: int
                    channel:
                        description:
                            - Selected list of wireless radio channels.
                        type: list
                        elements: dict
                        suboptions:
                            chan:
                                description:
                                    - Channel number.
                                required: true
                                type: str
                    channel_bonding:
                        description:
                            - 'Channel bandwidth: 320, 240, 160, 80, 40, or 20MHz. Channels may use both 20 and 40 by enabling coexistence.'
                        type: str
                        choices:
                            - '320MHz'
                            - '240MHz'
                            - '160MHz'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
                    channel_bonding_ext:
                        description:
                            - 'Channel bandwidth extension: 320 MHz-1 and 320 MHz-2 .'
                        type: str
                        choices:
                            - '320MHz-1'
                            - '320MHz-2'
                    channel_utilization:
                        description:
                            - Enable/disable measuring channel utilization.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    coexistence:
                        description:
                            - Enable/disable allowing both HT20 and HT40 on the same radio .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    darrp:
                        description:
                            - Enable/disable Distributed Automatic Radio Resource Provisioning (DARRP) to make sure the radio is always using the most optimal
                               channel .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    drma:
                        description:
                            - Enable/disable dynamic radio mode assignment (DRMA) .
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    drma_sensitivity:
                        description:
                            - Network Coverage Factor (NCF) percentage required to consider a radio as redundant .
                        type: str
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    dtim:
                        description:
                            - Delivery Traffic Indication Map (DTIM) period (1 - 255). Set higher to save battery life of WiFi client in power-save mode.
                        type: int
                    frag_threshold:
                        description:
                            - Maximum packet size that can be sent without fragmentation (800 - 2346 bytes).
                        type: int
                    frequency_handoff:
                        description:
                            - Enable/disable frequency handoff of clients to other channels .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    iperf_protocol:
                        description:
                            - Iperf test protocol .
                        type: str
                        choices:
                            - 'udp'
                            - 'tcp'
                    iperf_server_port:
                        description:
                            - Iperf service port number.
                        type: int
                    max_clients:
                        description:
                            - Maximum number of stations (STAs) or WiFi clients supported by the radio. Range depends on the hardware.
                        type: int
                    max_distance:
                        description:
                            - Maximum expected distance between the AP and clients (0 - 54000 m).
                        type: int
                    mimo_mode:
                        description:
                            - Configure radio MIMO mode .
                        type: str
                        choices:
                            - 'default'
                            - '1x1'
                            - '2x2'
                            - '3x3'
                            - '4x4'
                            - '8x8'
                    mode:
                        description:
                            - Mode of radio 4. Radio 4 can be disabled, configured as an access point, a rogue AP monitor, a sniffer, or a station.
                        type: str
                        choices:
                            - 'disabled'
                            - 'ap'
                            - 'monitor'
                            - 'sniffer'
                            - 'sam'
                    optional_antenna:
                        description:
                            - Optional antenna used on FAP .
                        type: str
                        choices:
                            - 'none'
                            - 'custom'
                            - 'FANT-04ABGN-0606-O-N'
                            - 'FANT-04ABGN-1414-P-N'
                            - 'FANT-04ABGN-8065-P-N'
                            - 'FANT-04ABGN-0606-O-R'
                            - 'FANT-04ABGN-0606-P-R'
                            - 'FANT-10ACAX-1213-D-N'
                            - 'FANT-08ABGN-1213-D-R'
                            - 'FANT-04BEAX-0606-P-R'
                    optional_antenna_gain:
                        description:
                            - Optional antenna gain in dBi (0 to 20).
                        type: str
                    power_level:
                        description:
                            - Radio EIRP power level as a percentage of the maximum EIRP power (0 - 100).
                        type: int
                    power_mode:
                        description:
                            - Set radio effective isotropic radiated power (EIRP) in dBm or by a percentage of the maximum EIRP . This power takes into
                               account both radio transmit power and antenna gain. Higher power level settings may be constrained by local regulatory
                                  requirements and AP capabilities.
                        type: str
                        choices:
                            - 'dBm'
                            - 'percentage'
                    power_value:
                        description:
                            - Radio EIRP power in dBm (1 - 33).
                        type: int
                    powersave_optimize:
                        description:
                            - Enable client power-saving features such as TIM, AC VO, and OBSS etc.
                        type: list
                        elements: str
                        choices:
                            - 'tim'
                            - 'ac-vo'
                            - 'no-obss-scan'
                            - 'no-11b-rate'
                            - 'client-rate-follow'
                    protection_mode:
                        description:
                            - Enable/disable 802.11g protection modes to support backwards compatibility with older clients (rtscts, ctsonly, disable).
                        type: str
                        choices:
                            - 'rtscts'
                            - 'ctsonly'
                            - 'disable'
                    rts_threshold:
                        description:
                            - Maximum packet size for RTS transmissions, specifying the maximum size of a data packet before RTS/CTS (256 - 2346 bytes).
                        type: int
                    sam_bssid:
                        description:
                            - BSSID for WiFi network.
                        type: str
                    sam_ca_certificate:
                        description:
                            - CA certificate for WPA2/WPA3-ENTERPRISE. Source vpn.certificate.ca.name.
                        type: str
                    sam_captive_portal:
                        description:
                            - Enable/disable Captive Portal Authentication .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    sam_client_certificate:
                        description:
                            - Client certificate for WPA2/WPA3-ENTERPRISE. Source vpn.certificate.local.name.
                        type: str
                    sam_cwp_failure_string:
                        description:
                            - Failure identification on the page after an incorrect login.
                        type: str
                    sam_cwp_match_string:
                        description:
                            - Identification string from the captive portal login form.
                        type: str
                    sam_cwp_password:
                        description:
                            - Password for captive portal authentication.
                        type: str
                    sam_cwp_success_string:
                        description:
                            - Success identification on the page after a successful login.
                        type: str
                    sam_cwp_test_url:
                        description:
                            - Website the client is trying to access.
                        type: str
                    sam_cwp_username:
                        description:
                            - Username for captive portal authentication.
                        type: str
                    sam_eap_method:
                        description:
                            - Select WPA2/WPA3-ENTERPRISE EAP Method .
                        type: str
                        choices:
                            - 'both'
                            - 'tls'
                            - 'peap'
                    sam_password:
                        description:
                            - Passphrase for WiFi network connection.
                        type: str
                    sam_private_key:
                        description:
                            - Private key for WPA2/WPA3-ENTERPRISE. Source vpn.certificate.local.name.
                        type: str
                    sam_private_key_password:
                        description:
                            - Password for private key file for WPA2/WPA3-ENTERPRISE.
                        type: str
                    sam_report_intv:
                        description:
                            - SAM report interval (sec), 0 for a one-time report.
                        type: int
                    sam_security_type:
                        description:
                            - Select WiFi network security type .
                        type: str
                        choices:
                            - 'open'
                            - 'wpa-personal'
                            - 'wpa-enterprise'
                            - 'wpa3-sae'
                            - 'owe'
                    sam_server:
                        description:
                            - SAM test server IP address or domain name.
                        type: str
                    sam_server_fqdn:
                        description:
                            - SAM test server domain name.
                        type: str
                    sam_server_ip:
                        description:
                            - SAM test server IP address.
                        type: str
                    sam_server_type:
                        description:
                            - Select SAM server type .
                        type: str
                        choices:
                            - 'ip'
                            - 'fqdn'
                    sam_ssid:
                        description:
                            - SSID for WiFi network.
                        type: str
                    sam_test:
                        description:
                            - Select SAM test type .
                        type: str
                        choices:
                            - 'ping'
                            - 'iperf'
                    sam_username:
                        description:
                            - Username for WiFi network connection.
                        type: str
                    set_80211d:
                        description:
                            - Enable/disable 802.11d countryie.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    set_80211mc:
                        description:
                            - Enable/disable 802.11mc responder mode .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    short_guard_interval:
                        description:
                            - Use either the short guard interval (Short GI) of 400 ns or the long guard interval (Long GI) of 800 ns.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    spectrum_analysis:
                        description:
                            - Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        type: str
                        choices:
                            - 'enable'
                            - 'scan-only'
                            - 'disable'
                    transmit_optimize:
                        description:
                            - Packet transmission optimization options including power saving, aggregation limiting, retry limiting, etc. All are enabled by
                               default.
                        type: list
                        elements: str
                        choices:
                            - 'disable'
                            - 'power-save'
                            - 'aggr-limit'
                            - 'retry-limit'
                            - 'send-bar'
                    vap_all:
                        description:
                            - Configure method for assigning SSIDs to this FortiAP .
                        type: str
                        choices:
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
                            - 'enable'
                            - 'disable'
                    vaps:
                        description:
                            - Manually selected list of Virtual Access Points (VAPs).
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Virtual Access Point (VAP) name. Source wireless-controller.vap-group.name system.interface.name.
                                required: true
                                type: str
                    wids_profile:
                        description:
                            - Wireless Intrusion Detection System (WIDS) profile name to assign to the radio. Source wireless-controller.wids-profile.name.
                        type: str
                    zero_wait_dfs:
                        description:
                            - Enable/disable zero wait DFS on radio .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            split_tunneling_acl:
                description:
                    - Split tunneling ACL filter list.
                type: list
                elements: dict
                suboptions:
                    dest_ip:
                        description:
                            - Destination IP and mask for the split-tunneling subnet.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            split_tunneling_acl_local_ap_subnet:
                description:
                    - Enable/disable automatically adding local subnetwork of FortiAP to split-tunneling ACL .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            split_tunneling_acl_path:
                description:
                    - Split tunneling ACL path is local/tunnel.
                type: str
                choices:
                    - 'tunnel'
                    - 'local'
            syslog_profile:
                description:
                    - System log server configuration profile name. Source wireless-controller.syslog-profile.name.
                type: str
            tun_mtu_downlink:
                description:
                    - The MTU of downlink CAPWAP tunnel (576 - 1500 bytes or 0; 0 means the local MTU of FortiAP; ).
                type: int
            tun_mtu_uplink:
                description:
                    - The maximum transmission unit (MTU) of uplink CAPWAP tunnel (576 - 1500 bytes or 0; 0 means the local MTU of FortiAP; ).
                type: int
            unii_4_5ghz_band:
                description:
                    - Enable/disable UNII-4 5Ghz band channels .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            usb_port:
                description:
                    - Enable/disable USB port of the WTP .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wan_port_auth:
                description:
                    - Set WAN port authentication mode .
                type: str
                choices:
                    - 'none'
                    - '802.1x'
            wan_port_auth_macsec:
                description:
                    - Enable/disable WAN port 802.1x supplicant MACsec policy .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wan_port_auth_methods:
                description:
                    - WAN port 802.1x supplicant EAP methods .
                type: str
                choices:
                    - 'all'
                    - 'EAP-FAST'
                    - 'EAP-TLS'
                    - 'EAP-PEAP'
            wan_port_auth_password:
                description:
                    - Set WAN port 802.1x supplicant password.
                type: str
            wan_port_auth_usrname:
                description:
                    - Set WAN port 802.1x supplicant user name.
                type: str
            wan_port_mode:
                description:
                    - Enable/disable using a WAN port as a LAN port.
                type: str
                choices:
                    - 'wan-lan'
                    - 'wan-only'
"""

EXAMPLES = """
- name: Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms.
  fortinet.fortios.fortios_wireless_controller_wtp_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wireless_controller_wtp_profile:
          admin_auth_tacacs_plus: "<your_own_value> (source user.tacacs+.name)"
          admin_restrict_local: "enable"
          allowaccess: "https"
          ap_country: "--"
          ap_handoff: "enable"
          apcfg_mesh: "enable"
          apcfg_mesh_ap_type: "ethernet"
          apcfg_mesh_eth_bridge: "enable"
          apcfg_mesh_ssid: "<your_own_value> (source wireless-controller.vap.name)"
          apcfg_profile: "<your_own_value> (source wireless-controller.apcfg-profile.name)"
          ble_profile: "<your_own_value> (source wireless-controller.ble-profile.name)"
          bonjour_profile: "<your_own_value> (source wireless-controller.bonjour-profile.name)"
          comment: "Comment."
          console_login: "enable"
          control_message_offload: "ebp-frame"
          default_mesh_root: "enable"
          deny_mac_list:
              -
                  id: "20"
                  mac: "<your_own_value>"
          dtls_in_kernel: "enable"
          dtls_policy: "clear-text"
          energy_efficient_ethernet: "enable"
          esl_ses_dongle:
              apc_addr_type: "fqdn"
              apc_fqdn: "<your_own_value>"
              apc_ip: "<your_own_value>"
              apc_port: "0"
              coex_level: "none"
              compliance_level: "compliance-level-2"
              esl_channel: "-1"
              output_power: "a"
              scd_enable: "enable"
              tls_cert_verification: "enable"
              tls_fqdn_verification: "enable"
          ext_info_enable: "enable"
          frequency_handoff: "enable"
          handoff_roaming: "enable"
          handoff_rssi: "25"
          handoff_sta_thresh: "0"
          indoor_outdoor_deployment: "platform-determined"
          ip_fragment_preventing: "tcp-mss-adjust"
          lan:
              port_esl_mode: "offline"
              port_esl_ssid: "<your_own_value> (source system.interface.name)"
              port_mode: "offline"
              port_ssid: "<your_own_value> (source system.interface.name)"
              port1_mode: "offline"
              port1_ssid: "<your_own_value> (source system.interface.name)"
              port2_mode: "offline"
              port2_ssid: "<your_own_value> (source system.interface.name)"
              port3_mode: "offline"
              port3_ssid: "<your_own_value> (source system.interface.name)"
              port4_mode: "offline"
              port4_ssid: "<your_own_value> (source system.interface.name)"
              port5_mode: "offline"
              port5_ssid: "<your_own_value> (source system.interface.name)"
              port6_mode: "offline"
              port6_ssid: "<your_own_value> (source system.interface.name)"
              port7_mode: "offline"
              port7_ssid: "<your_own_value> (source system.interface.name)"
              port8_mode: "offline"
              port8_ssid: "<your_own_value> (source system.interface.name)"
          lbs:
              aeroscout: "enable"
              aeroscout_ap_mac: "bssid"
              aeroscout_mmu_report: "enable"
              aeroscout_mu: "enable"
              aeroscout_mu_factor: "20"
              aeroscout_mu_timeout: "5"
              aeroscout_server_ip: "<your_own_value>"
              aeroscout_server_port: "0"
              ble_rtls: "none"
              ble_rtls_accumulation_interval: "2"
              ble_rtls_asset_addrgrp_list: "<your_own_value> (source firewall.addrgrp.name)"
              ble_rtls_asset_uuid_list1: "<your_own_value>"
              ble_rtls_asset_uuid_list2: "<your_own_value>"
              ble_rtls_asset_uuid_list3: "<your_own_value>"
              ble_rtls_asset_uuid_list4: "<your_own_value>"
              ble_rtls_protocol: "WSS"
              ble_rtls_reporting_interval: "2"
              ble_rtls_server_fqdn: "<your_own_value>"
              ble_rtls_server_path: "<your_own_value>"
              ble_rtls_server_port: "443"
              ble_rtls_server_token: "<your_own_value>"
              ekahau_blink_mode: "enable"
              ekahau_tag: "<your_own_value>"
              erc_server_ip: "<your_own_value>"
              erc_server_port: "8569"
              fortipresence: "foreign"
              fortipresence_ble: "enable"
              fortipresence_frequency: "30"
              fortipresence_port: "3000"
              fortipresence_project: "<your_own_value>"
              fortipresence_rogue: "enable"
              fortipresence_secret: "<your_own_value>"
              fortipresence_server: "<your_own_value>"
              fortipresence_server_addr_type: "ipv4"
              fortipresence_server_fqdn: "<your_own_value>"
              fortipresence_unassoc: "enable"
              polestar: "enable"
              polestar_accumulation_interval: "2"
              polestar_asset_addrgrp_list: "<your_own_value> (source firewall.addrgrp.name)"
              polestar_asset_uuid_list1: "<your_own_value>"
              polestar_asset_uuid_list2: "<your_own_value>"
              polestar_asset_uuid_list3: "<your_own_value>"
              polestar_asset_uuid_list4: "<your_own_value>"
              polestar_protocol: "WSS"
              polestar_reporting_interval: "2"
              polestar_server_fqdn: "<your_own_value>"
              polestar_server_path: "<your_own_value>"
              polestar_server_port: "443"
              polestar_server_token: "<your_own_value>"
              station_locate: "enable"
          led_schedules:
              -
                  name: "default_name_117 (source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime.name)"
          led_state: "enable"
          lldp: "enable"
          login_passwd: "<your_own_value>"
          login_passwd_change: "yes"
          max_clients: "0"
          name: "default_name_123"
          platform:
              ddscan: "enable"
              mode: "single-5G"
              type: "AP-11N"
          poe_mode: "auto"
          radio_1:
              airtime_fairness: "enable"
              amsdu: "enable"
              ap_handoff: "enable"
              ap_sniffer_addr: "<your_own_value>"
              ap_sniffer_bufsize: "16"
              ap_sniffer_chan: "36"
              ap_sniffer_chan_width: "320MHz"
              ap_sniffer_ctl: "enable"
              ap_sniffer_data: "enable"
              ap_sniffer_mgmt_beacon: "enable"
              ap_sniffer_mgmt_other: "enable"
              ap_sniffer_mgmt_probe: "enable"
              arrp_profile: "<your_own_value> (source wireless-controller.arrp-profile.name)"
              auto_power_high: "17"
              auto_power_level: "enable"
              auto_power_low: "10"
              auto_power_target: "<your_own_value>"
              band: "802.11a"
              band_5g_type: "5g-full"
              bandwidth_admission_control: "enable"
              bandwidth_capacity: "2000"
              beacon_interval: "100"
              bss_color: "0"
              bss_color_mode: "auto"
              call_admission_control: "enable"
              call_capacity: "10"
              channel:
                  -
                      chan: "<your_own_value>"
              channel_bonding: "320MHz"
              channel_bonding_ext: "320MHz-1"
              channel_utilization: "enable"
              coexistence: "enable"
              darrp: "enable"
              drma: "disable"
              drma_sensitivity: "low"
              dtim: "1"
              frag_threshold: "2346"
              frequency_handoff: "enable"
              iperf_protocol: "udp"
              iperf_server_port: "5001"
              max_clients: "0"
              max_distance: "0"
              mimo_mode: "default"
              mode: "disabled"
              optional_antenna: "none"
              optional_antenna_gain: "<your_own_value>"
              power_level: "100"
              power_mode: "dBm"
              power_value: "27"
              powersave_optimize: "tim"
              protection_mode: "rtscts"
              radio_id: "2"
              rts_threshold: "2346"
              sam_bssid: "<your_own_value>"
              sam_ca_certificate: "<your_own_value> (source vpn.certificate.ca.name)"
              sam_captive_portal: "enable"
              sam_client_certificate: "<your_own_value> (source vpn.certificate.local.name)"
              sam_cwp_failure_string: "<your_own_value>"
              sam_cwp_match_string: "<your_own_value>"
              sam_cwp_password: "<your_own_value>"
              sam_cwp_success_string: "<your_own_value>"
              sam_cwp_test_url: "<your_own_value>"
              sam_cwp_username: "<your_own_value>"
              sam_eap_method: "both"
              sam_password: "<your_own_value>"
              sam_private_key: "<your_own_value> (source vpn.certificate.local.name)"
              sam_private_key_password: "<your_own_value>"
              sam_report_intv: "0"
              sam_security_type: "open"
              sam_server: "<your_own_value>"
              sam_server_fqdn: "<your_own_value>"
              sam_server_ip: "<your_own_value>"
              sam_server_type: "ip"
              sam_ssid: "<your_own_value>"
              sam_test: "ping"
              sam_username: "<your_own_value>"
              set_80211d: "enable"
              set_80211mc: "enable"
              short_guard_interval: "enable"
              spectrum_analysis: "enable"
              transmit_optimize: "disable"
              vap_all: "tunnel"
              vaps:
                  -
                      name: "default_name_213 (source wireless-controller.vap-group.name system.interface.name)"
              wids_profile: "<your_own_value> (source wireless-controller.wids-profile.name)"
              zero_wait_dfs: "enable"
          radio_2:
              airtime_fairness: "enable"
              amsdu: "enable"
              ap_handoff: "enable"
              ap_sniffer_addr: "<your_own_value>"
              ap_sniffer_bufsize: "16"
              ap_sniffer_chan: "6"
              ap_sniffer_chan_width: "320MHz"
              ap_sniffer_ctl: "enable"
              ap_sniffer_data: "enable"
              ap_sniffer_mgmt_beacon: "enable"
              ap_sniffer_mgmt_other: "enable"
              ap_sniffer_mgmt_probe: "enable"
              arrp_profile: "<your_own_value> (source wireless-controller.arrp-profile.name)"
              auto_power_high: "17"
              auto_power_level: "enable"
              auto_power_low: "10"
              auto_power_target: "<your_own_value>"
              band: "802.11a"
              band_5g_type: "5g-full"
              bandwidth_admission_control: "enable"
              bandwidth_capacity: "2000"
              beacon_interval: "100"
              bss_color: "0"
              bss_color_mode: "auto"
              call_admission_control: "enable"
              call_capacity: "10"
              channel:
                  -
                      chan: "<your_own_value>"
              channel_bonding: "320MHz"
              channel_bonding_ext: "320MHz-1"
              channel_utilization: "enable"
              coexistence: "enable"
              darrp: "enable"
              drma: "disable"
              drma_sensitivity: "low"
              dtim: "1"
              frag_threshold: "2346"
              frequency_handoff: "enable"
              iperf_protocol: "udp"
              iperf_server_port: "5001"
              max_clients: "0"
              max_distance: "0"
              mimo_mode: "default"
              mode: "disabled"
              optional_antenna: "none"
              optional_antenna_gain: "<your_own_value>"
              power_level: "100"
              power_mode: "dBm"
              power_value: "27"
              powersave_optimize: "tim"
              protection_mode: "rtscts"
              radio_id: "2"
              rts_threshold: "2346"
              sam_bssid: "<your_own_value>"
              sam_ca_certificate: "<your_own_value> (source vpn.certificate.ca.name)"
              sam_captive_portal: "enable"
              sam_client_certificate: "<your_own_value> (source vpn.certificate.local.name)"
              sam_cwp_failure_string: "<your_own_value>"
              sam_cwp_match_string: "<your_own_value>"
              sam_cwp_password: "<your_own_value>"
              sam_cwp_success_string: "<your_own_value>"
              sam_cwp_test_url: "<your_own_value>"
              sam_cwp_username: "<your_own_value>"
              sam_eap_method: "both"
              sam_password: "<your_own_value>"
              sam_private_key: "<your_own_value> (source vpn.certificate.local.name)"
              sam_private_key_password: "<your_own_value>"
              sam_report_intv: "0"
              sam_security_type: "open"
              sam_server: "<your_own_value>"
              sam_server_fqdn: "<your_own_value>"
              sam_server_ip: "<your_own_value>"
              sam_server_type: "ip"
              sam_ssid: "<your_own_value>"
              sam_test: "ping"
              sam_username: "<your_own_value>"
              set_80211d: "enable"
              set_80211mc: "enable"
              short_guard_interval: "enable"
              spectrum_analysis: "enable"
              transmit_optimize: "disable"
              vap_all: "tunnel"
              vaps:
                  -
                      name: "default_name_300 (source wireless-controller.vap-group.name system.interface.name)"
              wids_profile: "<your_own_value> (source wireless-controller.wids-profile.name)"
              zero_wait_dfs: "enable"
          radio_3:
              airtime_fairness: "enable"
              amsdu: "enable"
              ap_handoff: "enable"
              ap_sniffer_addr: "<your_own_value>"
              ap_sniffer_bufsize: "16"
              ap_sniffer_chan: "37"
              ap_sniffer_chan_width: "320MHz"
              ap_sniffer_ctl: "enable"
              ap_sniffer_data: "enable"
              ap_sniffer_mgmt_beacon: "enable"
              ap_sniffer_mgmt_other: "enable"
              ap_sniffer_mgmt_probe: "enable"
              arrp_profile: "<your_own_value> (source wireless-controller.arrp-profile.name)"
              auto_power_high: "17"
              auto_power_level: "enable"
              auto_power_low: "10"
              auto_power_target: "<your_own_value>"
              band: "802.11a"
              band_5g_type: "5g-full"
              bandwidth_admission_control: "enable"
              bandwidth_capacity: "2000"
              beacon_interval: "100"
              bss_color: "0"
              bss_color_mode: "auto"
              call_admission_control: "enable"
              call_capacity: "10"
              channel:
                  -
                      chan: "<your_own_value>"
              channel_bonding: "320MHz"
              channel_bonding_ext: "320MHz-1"
              channel_utilization: "enable"
              coexistence: "enable"
              darrp: "enable"
              drma: "disable"
              drma_sensitivity: "low"
              dtim: "1"
              frag_threshold: "2346"
              frequency_handoff: "enable"
              iperf_protocol: "udp"
              iperf_server_port: "5001"
              max_clients: "0"
              max_distance: "0"
              mimo_mode: "default"
              mode: "disabled"
              optional_antenna: "none"
              optional_antenna_gain: "<your_own_value>"
              power_level: "100"
              power_mode: "dBm"
              power_value: "27"
              powersave_optimize: "tim"
              protection_mode: "rtscts"
              radio_id: "2"
              rts_threshold: "2346"
              sam_bssid: "<your_own_value>"
              sam_ca_certificate: "<your_own_value> (source vpn.certificate.ca.name)"
              sam_captive_portal: "enable"
              sam_client_certificate: "<your_own_value> (source vpn.certificate.local.name)"
              sam_cwp_failure_string: "<your_own_value>"
              sam_cwp_match_string: "<your_own_value>"
              sam_cwp_password: "<your_own_value>"
              sam_cwp_success_string: "<your_own_value>"
              sam_cwp_test_url: "<your_own_value>"
              sam_cwp_username: "<your_own_value>"
              sam_eap_method: "both"
              sam_password: "<your_own_value>"
              sam_private_key: "<your_own_value> (source vpn.certificate.local.name)"
              sam_private_key_password: "<your_own_value>"
              sam_report_intv: "0"
              sam_security_type: "open"
              sam_server: "<your_own_value>"
              sam_server_fqdn: "<your_own_value>"
              sam_server_ip: "<your_own_value>"
              sam_server_type: "ip"
              sam_ssid: "<your_own_value>"
              sam_test: "ping"
              sam_username: "<your_own_value>"
              set_80211d: "enable"
              set_80211mc: "enable"
              short_guard_interval: "enable"
              spectrum_analysis: "enable"
              transmit_optimize: "disable"
              vap_all: "tunnel"
              vaps:
                  -
                      name: "default_name_387 (source wireless-controller.vap-group.name system.interface.name)"
              wids_profile: "<your_own_value> (source wireless-controller.wids-profile.name)"
              zero_wait_dfs: "enable"
          radio_4:
              airtime_fairness: "enable"
              amsdu: "enable"
              ap_handoff: "enable"
              ap_sniffer_addr: "<your_own_value>"
              ap_sniffer_bufsize: "16"
              ap_sniffer_chan: "6"
              ap_sniffer_chan_width: "320MHz"
              ap_sniffer_ctl: "enable"
              ap_sniffer_data: "enable"
              ap_sniffer_mgmt_beacon: "enable"
              ap_sniffer_mgmt_other: "enable"
              ap_sniffer_mgmt_probe: "enable"
              arrp_profile: "<your_own_value> (source wireless-controller.arrp-profile.name)"
              auto_power_high: "17"
              auto_power_level: "enable"
              auto_power_low: "10"
              auto_power_target: "<your_own_value>"
              band: "802.11a"
              band_5g_type: "5g-full"
              bandwidth_admission_control: "enable"
              bandwidth_capacity: "2000"
              beacon_interval: "100"
              bss_color: "0"
              bss_color_mode: "auto"
              call_admission_control: "enable"
              call_capacity: "10"
              channel:
                  -
                      chan: "<your_own_value>"
              channel_bonding: "320MHz"
              channel_bonding_ext: "320MHz-1"
              channel_utilization: "enable"
              coexistence: "enable"
              darrp: "enable"
              drma: "disable"
              drma_sensitivity: "low"
              dtim: "1"
              frag_threshold: "2346"
              frequency_handoff: "enable"
              iperf_protocol: "udp"
              iperf_server_port: "5001"
              max_clients: "0"
              max_distance: "0"
              mimo_mode: "default"
              mode: "disabled"
              optional_antenna: "none"
              optional_antenna_gain: "<your_own_value>"
              power_level: "100"
              power_mode: "dBm"
              power_value: "27"
              powersave_optimize: "tim"
              protection_mode: "rtscts"
              rts_threshold: "2346"
              sam_bssid: "<your_own_value>"
              sam_ca_certificate: "<your_own_value> (source vpn.certificate.ca.name)"
              sam_captive_portal: "enable"
              sam_client_certificate: "<your_own_value> (source vpn.certificate.local.name)"
              sam_cwp_failure_string: "<your_own_value>"
              sam_cwp_match_string: "<your_own_value>"
              sam_cwp_password: "<your_own_value>"
              sam_cwp_success_string: "<your_own_value>"
              sam_cwp_test_url: "<your_own_value>"
              sam_cwp_username: "<your_own_value>"
              sam_eap_method: "both"
              sam_password: "<your_own_value>"
              sam_private_key: "<your_own_value> (source vpn.certificate.local.name)"
              sam_private_key_password: "<your_own_value>"
              sam_report_intv: "0"
              sam_security_type: "open"
              sam_server: "<your_own_value>"
              sam_server_fqdn: "<your_own_value>"
              sam_server_ip: "<your_own_value>"
              sam_server_type: "ip"
              sam_ssid: "<your_own_value>"
              sam_test: "ping"
              sam_username: "<your_own_value>"
              set_80211d: "enable"
              set_80211mc: "enable"
              short_guard_interval: "enable"
              spectrum_analysis: "enable"
              transmit_optimize: "disable"
              vap_all: "tunnel"
              vaps:
                  -
                      name: "default_name_473 (source wireless-controller.vap-group.name system.interface.name)"
              wids_profile: "<your_own_value> (source wireless-controller.wids-profile.name)"
              zero_wait_dfs: "enable"
          split_tunneling_acl:
              -
                  dest_ip: "<your_own_value>"
                  id: "478"
          split_tunneling_acl_local_ap_subnet: "enable"
          split_tunneling_acl_path: "tunnel"
          syslog_profile: "<your_own_value> (source wireless-controller.syslog-profile.name)"
          tun_mtu_downlink: "0"
          tun_mtu_uplink: "0"
          unii_4_5ghz_band: "enable"
          usb_port: "enable"
          wan_port_auth: "none"
          wan_port_auth_macsec: "enable"
          wan_port_auth_methods: "all"
          wan_port_auth_password: "<your_own_value>"
          wan_port_auth_usrname: "<your_own_value>"
          wan_port_mode: "wan-lan"
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


def filter_wireless_controller_wtp_profile_data(json):
    option_list = [
        "admin_auth_tacacs_plus",
        "admin_restrict_local",
        "allowaccess",
        "ap_country",
        "ap_handoff",
        "apcfg_mesh",
        "apcfg_mesh_ap_type",
        "apcfg_mesh_eth_bridge",
        "apcfg_mesh_ssid",
        "apcfg_profile",
        "ble_profile",
        "bonjour_profile",
        "comment",
        "console_login",
        "control_message_offload",
        "default_mesh_root",
        "deny_mac_list",
        "dtls_in_kernel",
        "dtls_policy",
        "energy_efficient_ethernet",
        "esl_ses_dongle",
        "ext_info_enable",
        "frequency_handoff",
        "handoff_roaming",
        "handoff_rssi",
        "handoff_sta_thresh",
        "indoor_outdoor_deployment",
        "ip_fragment_preventing",
        "lan",
        "lbs",
        "led_schedules",
        "led_state",
        "lldp",
        "login_passwd",
        "login_passwd_change",
        "max_clients",
        "name",
        "platform",
        "poe_mode",
        "radio_1",
        "radio_2",
        "radio_3",
        "radio_4",
        "split_tunneling_acl",
        "split_tunneling_acl_local_ap_subnet",
        "split_tunneling_acl_path",
        "syslog_profile",
        "tun_mtu_downlink",
        "tun_mtu_uplink",
        "unii_4_5ghz_band",
        "usb_port",
        "wan_port_auth",
        "wan_port_auth_macsec",
        "wan_port_auth_methods",
        "wan_port_auth_password",
        "wan_port_auth_usrname",
        "wan_port_mode",
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
        ["control_message_offload"],
        ["dtls_policy"],
        ["ip_fragment_preventing"],
        ["allowaccess"],
        ["radio_1", "band"],
        ["radio_1", "powersave_optimize"],
        ["radio_1", "transmit_optimize"],
        ["radio_2", "band"],
        ["radio_2", "powersave_optimize"],
        ["radio_2", "transmit_optimize"],
        ["radio_3", "band"],
        ["radio_3", "powersave_optimize"],
        ["radio_3", "transmit_optimize"],
        ["radio_4", "band"],
        ["radio_4", "powersave_optimize"],
        ["radio_4", "transmit_optimize"],
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
    speciallist = {
        "80211d": "set_80211d",
        "80211mc": "set_80211mc",
        "admin_auth_tacacs+": "admin_auth_tacacs_plus",
    }

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


def wireless_controller_wtp_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    wireless_controller_wtp_profile_data = data["wireless_controller_wtp_profile"]

    filtered_data = filter_wireless_controller_wtp_profile_data(
        wireless_controller_wtp_profile_data
    )
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey(
            "wireless-controller", "wtp-profile", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "wireless-controller", "wtp-profile", vdom=vdom, mkey=mkey
        )
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
    data_copy["wireless_controller_wtp_profile"] = filtered_data
    fos.do_member_operation(
        "wireless-controller",
        "wtp-profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "wireless-controller", "wtp-profile", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "wireless-controller", "wtp-profile", mkey=converted_data["name"], vdom=vdom
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

    if data["wireless_controller_wtp_profile"]:
        resp = wireless_controller_wtp_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("wireless_controller_wtp_profile")
        )
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
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "platform": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "AP-11N"},
                        {"value": "C24JE"},
                        {"value": "421E"},
                        {"value": "423E"},
                        {"value": "221E"},
                        {"value": "222E"},
                        {"value": "223E"},
                        {"value": "224E"},
                        {
                            "value": "231E",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                        },
                        {"value": "321E", "v_range": [["v6.2.0", ""]]},
                        {
                            "value": "431F",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                        },
                        {
                            "value": "431FL",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                        },
                        {
                            "value": "432F",
                            "v_range": [
                                ["v6.2.0", "v6.2.0"],
                                ["v6.2.5", "v6.4.0"],
                                ["v6.4.4", ""],
                            ],
                        },
                        {
                            "value": "432FR",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                        },
                        {
                            "value": "433F",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                        },
                        {
                            "value": "433FL",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                        },
                        {
                            "value": "231F",
                            "v_range": [
                                ["v6.2.0", "v6.2.0"],
                                ["v6.2.5", "v6.4.0"],
                                ["v6.4.4", ""],
                            ],
                        },
                        {
                            "value": "231FL",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                        },
                        {
                            "value": "234F",
                            "v_range": [
                                ["v6.2.0", "v6.2.0"],
                                ["v6.2.5", "v6.4.0"],
                                ["v6.4.4", ""],
                            ],
                        },
                        {
                            "value": "23JF",
                            "v_range": [
                                ["v6.2.0", "v6.2.0"],
                                ["v6.2.5", "v6.4.0"],
                                ["v6.4.4", ""],
                            ],
                        },
                        {"value": "831F", "v_range": [["v6.4.4", ""]]},
                        {
                            "value": "231G",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                        },
                        {
                            "value": "233G",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                        },
                        {"value": "234G", "v_range": [["v7.4.0", ""]]},
                        {
                            "value": "431G",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                        },
                        {"value": "432G", "v_range": [["v7.4.2", ""]]},
                        {
                            "value": "433G",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                        },
                        {"value": "231K", "v_range": [["v7.6.1", ""]]},
                        {"value": "23JK", "v_range": [["v7.6.1", ""]]},
                        {"value": "222KL", "v_range": [["v7.6.4", ""]]},
                        {"value": "241K", "v_range": [["v7.4.2", ""]]},
                        {"value": "243K", "v_range": [["v7.4.2", ""]]},
                        {"value": "244K", "v_range": [["v7.6.4", ""]]},
                        {"value": "441K", "v_range": [["v7.4.2", ""]]},
                        {"value": "443K", "v_range": [["v7.4.2", ""]]},
                        {"value": "U421E"},
                        {"value": "U422EV"},
                        {"value": "U423E"},
                        {"value": "U221EV"},
                        {"value": "U223EV"},
                        {"value": "U24JEV"},
                        {"value": "U321EV"},
                        {"value": "U323EV"},
                        {"value": "U431F", "v_range": [["v6.2.0", ""]]},
                        {"value": "U433F", "v_range": [["v6.2.0", ""]]},
                        {"value": "U231F", "v_range": [["v6.4.4", ""]]},
                        {"value": "U234F", "v_range": [["v6.4.4", ""]]},
                        {"value": "U432F", "v_range": [["v6.4.4", ""]]},
                        {
                            "value": "U231G",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
                        },
                        {"value": "220B", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "210B", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "222B", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "112B", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "320B", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "11C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "14C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "223B", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "28C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "320C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "221C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "25D", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "222C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "224D", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "214B", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "21D", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "24D", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "112D", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "223C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "321C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "C220C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "C225C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "C23JD", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "S321C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "S322C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "S323C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "S311C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "S313C", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "S321CR", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "S322CR", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "S323CR", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "S421E", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "S422E", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "S423E", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "S221E", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {"value": "S223E", "v_range": [["v6.0.0", "v7.2.4"]]},
                        {
                            "value": "U441G",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", "v7.2.4"]],
                        },
                    ],
                },
                "mode": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "single-5G"}, {"value": "dual-5G"}],
                },
                "ddscan": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "control_message_offload": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "ebp-frame"},
                {"value": "aeroscout-tag"},
                {"value": "ap-list"},
                {"value": "sta-list"},
                {"value": "sta-cap-list"},
                {"value": "stats"},
                {"value": "aeroscout-mu"},
                {"value": "sta-health", "v_range": [["v6.2.0", ""]]},
                {"value": "spectral-analysis", "v_range": [["v6.4.0", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "bonjour_profile": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "apcfg_profile": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "apcfg_mesh": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "apcfg_mesh_ap_type": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [{"value": "ethernet"}, {"value": "mesh"}, {"value": "auto"}],
        },
        "apcfg_mesh_ssid": {"v_range": [["v7.6.4", ""]], "type": "string"},
        "apcfg_mesh_eth_bridge": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ble_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "syslog_profile": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "wan_port_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "wan-lan"}, {"value": "wan-only"}],
        },
        "lan": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "port_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "offline"},
                        {"value": "nat-to-wan"},
                        {"value": "bridge-to-wan"},
                        {"value": "bridge-to-ssid"},
                    ],
                },
                "port_ssid": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "port1_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "offline"},
                        {"value": "nat-to-wan"},
                        {"value": "bridge-to-wan"},
                        {"value": "bridge-to-ssid"},
                    ],
                },
                "port1_ssid": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "port2_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "offline"},
                        {"value": "nat-to-wan"},
                        {"value": "bridge-to-wan"},
                        {"value": "bridge-to-ssid"},
                    ],
                },
                "port2_ssid": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "port3_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "offline"},
                        {"value": "nat-to-wan"},
                        {"value": "bridge-to-wan"},
                        {"value": "bridge-to-ssid"},
                    ],
                },
                "port3_ssid": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "port4_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "offline"},
                        {"value": "nat-to-wan"},
                        {"value": "bridge-to-wan"},
                        {"value": "bridge-to-ssid"},
                    ],
                },
                "port4_ssid": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "port5_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "offline"},
                        {"value": "nat-to-wan"},
                        {"value": "bridge-to-wan"},
                        {"value": "bridge-to-ssid"},
                    ],
                },
                "port5_ssid": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "port6_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "offline"},
                        {"value": "nat-to-wan"},
                        {"value": "bridge-to-wan"},
                        {"value": "bridge-to-ssid"},
                    ],
                },
                "port6_ssid": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "port7_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "offline"},
                        {"value": "nat-to-wan"},
                        {"value": "bridge-to-wan"},
                        {"value": "bridge-to-ssid"},
                    ],
                },
                "port7_ssid": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "port8_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "offline"},
                        {"value": "nat-to-wan"},
                        {"value": "bridge-to-wan"},
                        {"value": "bridge-to-ssid"},
                    ],
                },
                "port8_ssid": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "port_esl_mode": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "offline"},
                        {"value": "nat-to-wan"},
                        {"value": "bridge-to-wan"},
                        {"value": "bridge-to-ssid"},
                    ],
                },
                "port_esl_ssid": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                },
            },
        },
        "energy_efficient_ethernet": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "led_state": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "led_schedules": {
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
        "dtls_policy": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "clear-text"},
                {"value": "dtls-enabled"},
                {"value": "ipsec-vpn"},
                {"value": "ipsec-sn-vpn", "v_range": [["v7.4.0", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "dtls_in_kernel": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "max_clients": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "handoff_rssi": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "handoff_sta_thresh": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "handoff_roaming": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "deny_mac_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "mac": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ap_country": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "--", "v_range": [["v7.0.1", ""]]},
                {"value": "AF", "v_range": [["v7.0.0", ""]]},
                {"value": "AL"},
                {"value": "DZ"},
                {"value": "AS", "v_range": [["v7.0.0", ""]]},
                {"value": "AO"},
                {"value": "AR"},
                {"value": "AM"},
                {"value": "AU"},
                {"value": "AT"},
                {"value": "AZ"},
                {"value": "BS", "v_range": [["v6.4.0", ""]]},
                {"value": "BH"},
                {"value": "BD"},
                {"value": "BB"},
                {"value": "BY"},
                {"value": "BE"},
                {"value": "BZ"},
                {"value": "BJ", "v_range": [["v7.0.0", ""]]},
                {"value": "BM", "v_range": [["v7.0.0", ""]]},
                {"value": "BT", "v_range": [["v7.0.0", ""]]},
                {"value": "BO"},
                {"value": "BA"},
                {"value": "BW", "v_range": [["v7.0.0", ""]]},
                {"value": "BR"},
                {"value": "BN"},
                {"value": "BG"},
                {"value": "BF", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "KH"},
                {"value": "CM", "v_range": [["v7.0.0", ""]]},
                {"value": "KY", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "CF", "v_range": [["v6.2.0", ""]]},
                {"value": "TD", "v_range": [["v7.0.0", ""]]},
                {"value": "CL"},
                {"value": "CN"},
                {"value": "CX", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "CO"},
                {"value": "CG", "v_range": [["v7.0.0", ""]]},
                {"value": "CD", "v_range": [["v7.0.0", ""]]},
                {"value": "CR"},
                {"value": "HR"},
                {"value": "CY"},
                {"value": "CZ"},
                {"value": "DK"},
                {"value": "DJ", "v_range": [["v7.4.1", ""]]},
                {"value": "DM", "v_range": [["v7.0.0", ""]]},
                {"value": "DO"},
                {"value": "EC"},
                {"value": "EG"},
                {"value": "SV"},
                {"value": "ET", "v_range": [["v7.0.0", ""]]},
                {"value": "EE"},
                {"value": "GF", "v_range": [["v7.0.0", ""]]},
                {"value": "PF", "v_range": [["v7.0.0", ""]]},
                {"value": "FO", "v_range": [["v7.0.0", ""]]},
                {"value": "FJ", "v_range": [["v7.0.0", ""]]},
                {"value": "FI"},
                {"value": "FR"},
                {"value": "GA", "v_range": [["v7.4.1", ""]]},
                {"value": "GE"},
                {"value": "GM", "v_range": [["v7.4.1", ""]]},
                {"value": "DE"},
                {"value": "GH", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "GI", "v_range": [["v7.0.0", ""]]},
                {"value": "GR"},
                {"value": "GL"},
                {"value": "GD"},
                {"value": "GP", "v_range": [["v7.0.0", ""]]},
                {"value": "GU"},
                {"value": "GT"},
                {"value": "GY", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "HT"},
                {"value": "HN"},
                {"value": "HK"},
                {"value": "HU"},
                {"value": "IS"},
                {"value": "IN"},
                {"value": "ID"},
                {"value": "IQ", "v_range": [["v7.0.0", ""]]},
                {"value": "IE"},
                {"value": "IM", "v_range": [["v7.0.0", ""]]},
                {"value": "IL"},
                {"value": "IT"},
                {"value": "CI", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "JM"},
                {"value": "JO"},
                {"value": "KZ"},
                {"value": "KE"},
                {"value": "KR"},
                {"value": "KW"},
                {"value": "LA", "v_range": [["v7.0.0", ""]]},
                {"value": "LV"},
                {"value": "LB"},
                {"value": "LS", "v_range": [["v7.0.0", ""]]},
                {"value": "LR", "v_range": [["v7.4.1", ""]]},
                {"value": "LY", "v_range": [["v7.0.0", ""]]},
                {"value": "LI"},
                {"value": "LT"},
                {"value": "LU"},
                {"value": "MO"},
                {"value": "MK"},
                {"value": "MG", "v_range": [["v7.0.0", ""]]},
                {"value": "MW", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "MY"},
                {"value": "MV", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "ML", "v_range": [["v7.0.0", ""]]},
                {"value": "MT"},
                {"value": "MH", "v_range": [["v7.0.0", ""]]},
                {"value": "MQ", "v_range": [["v7.0.0", ""]]},
                {"value": "MR", "v_range": [["v7.0.0", ""]]},
                {"value": "MU", "v_range": [["v7.0.0", ""]]},
                {"value": "YT", "v_range": [["v7.0.0", ""]]},
                {"value": "MX"},
                {"value": "FM", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "MD", "v_range": [["v7.0.0", ""]]},
                {"value": "MC"},
                {"value": "MN", "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]]},
                {"value": "MA"},
                {"value": "MZ"},
                {"value": "MM"},
                {"value": "NA"},
                {"value": "NP"},
                {"value": "NL"},
                {"value": "AN"},
                {"value": "AW"},
                {"value": "NZ"},
                {"value": "NI", "v_range": [["v7.0.0", ""]]},
                {"value": "NE", "v_range": [["v7.0.0", ""]]},
                {"value": "NG", "v_range": [["v7.4.1", ""]]},
                {"value": "NO"},
                {"value": "MP", "v_range": [["v7.0.0", ""]]},
                {"value": "OM"},
                {"value": "PK"},
                {"value": "PW", "v_range": [["v7.0.0", ""]]},
                {"value": "PA"},
                {"value": "PG"},
                {"value": "PY"},
                {"value": "PE"},
                {"value": "PH"},
                {"value": "PL"},
                {"value": "PT"},
                {"value": "PR"},
                {"value": "QA"},
                {"value": "RE", "v_range": [["v7.0.0", ""]]},
                {"value": "RO"},
                {"value": "RU"},
                {"value": "RW"},
                {"value": "BL", "v_range": [["v7.0.0", ""]]},
                {"value": "KN", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "LC", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "MF", "v_range": [["v7.0.0", ""]]},
                {"value": "PM", "v_range": [["v7.0.0", ""]]},
                {"value": "VC", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "SA"},
                {"value": "SN", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "RS"},
                {"value": "ME"},
                {"value": "SL", "v_range": [["v7.0.0", ""]]},
                {"value": "SG"},
                {"value": "SK"},
                {"value": "SI"},
                {"value": "SO", "v_range": [["v7.4.1", ""]]},
                {"value": "ZA"},
                {"value": "ES"},
                {"value": "LK"},
                {"value": "SR", "v_range": [["v7.0.0", ""]]},
                {"value": "SZ", "v_range": [["v7.4.1", ""]]},
                {"value": "SE"},
                {"value": "CH"},
                {"value": "TW"},
                {"value": "TZ"},
                {"value": "TH"},
                {"value": "TL", "v_range": [["v7.6.3", ""]]},
                {"value": "TG", "v_range": [["v7.0.0", ""]]},
                {"value": "TT"},
                {"value": "TN"},
                {"value": "TR"},
                {"value": "TM", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "AE"},
                {"value": "TC", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "UG", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "UA"},
                {"value": "GB"},
                {"value": "US"},
                {"value": "PS"},
                {"value": "UY"},
                {"value": "UZ"},
                {"value": "VU", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "VE"},
                {"value": "VN"},
                {"value": "VI", "v_range": [["v7.0.0", ""]]},
                {"value": "WF", "v_range": [["v7.0.0", ""]]},
                {"value": "YE"},
                {"value": "ZM", "v_range": [["v7.0.0", ""]]},
                {"value": "ZW"},
                {"value": "JP"},
                {"value": "CA"},
                {"value": "IR", "v_range": [["v6.0.0", "v6.4.4"]]},
                {"value": "KP", "v_range": [["v6.0.0", "v6.4.4"]]},
                {"value": "SD", "v_range": [["v6.0.0", "v6.4.4"]]},
                {"value": "SY", "v_range": [["v6.0.0", "v6.4.4"]]},
                {"value": "ZB", "v_range": [["v6.0.0", "v6.4.4"]]},
            ],
        },
        "ip_fragment_preventing": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [{"value": "tcp-mss-adjust"}, {"value": "icmp-unreachable"}],
            "multiple_values": True,
            "elements": "str",
        },
        "tun_mtu_uplink": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "tun_mtu_downlink": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "split_tunneling_acl_path": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "tunnel"}, {"value": "local"}],
        },
        "split_tunneling_acl_local_ap_subnet": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "split_tunneling_acl": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "dest_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "allowaccess": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "https"},
                {"value": "ssh"},
                {"value": "snmp", "v_range": [["v6.2.0", ""]]},
                {"value": "telnet", "v_range": [["v6.0.0", "v6.0.11"]]},
                {"value": "http", "v_range": [["v6.0.0", "v6.0.11"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "login_passwd_change": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "yes"}, {"value": "default"}, {"value": "no"}],
        },
        "login_passwd": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "lldp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "poe_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "auto"},
                {"value": "8023af"},
                {"value": "8023at"},
                {"value": "power-adapter"},
                {"value": "full", "v_range": [["v6.4.4", ""]]},
                {"value": "high", "v_range": [["v6.4.4", ""]]},
                {"value": "low", "v_range": [["v6.4.4", ""]]},
            ],
        },
        "usb_port": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "frequency_handoff": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ap_handoff": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "default_mesh_root": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "radio_1": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disabled"},
                        {"value": "ap"},
                        {"value": "monitor"},
                        {"value": "sniffer"},
                        {"value": "sam", "v_range": [["v7.0.0", ""]]},
                    ],
                },
                "band": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "802.11a"},
                        {"value": "802.11b"},
                        {"value": "802.11g"},
                        {"value": "802.11n-2G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11n-5G"},
                        {"value": "802.11ac-2G", "v_range": [["v6.4.0", ""]]},
                        {"value": "802.11ac-5G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11ax-2G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11ax-5G", "v_range": [["v6.2.0", ""]]},
                        {
                            "value": "802.11ax-6G",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                        },
                        {"value": "802.11be-2G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11be-5G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11be-6G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11n", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11ac", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11ax", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {"value": "802.11n,g-only", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11g-only", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11n-only", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11n-5G-only", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11ac,n-only", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11ac-only", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {
                            "value": "802.11ax,ac-only",
                            "v_range": [["v6.2.0", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ax,ac,n-only",
                            "v_range": [["v6.2.0", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ax-5G-only",
                            "v_range": [["v6.2.0", "v7.4.3"]],
                        },
                        {"value": "802.11ax,n-only", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {
                            "value": "802.11ax,n,g-only",
                            "v_range": [["v6.2.0", "v7.4.3"]],
                        },
                        {"value": "802.11ax-only", "v_range": [["v6.2.0", "v7.4.3"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "band_5g_type": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [
                        {"value": "5g-full"},
                        {"value": "5g-high"},
                        {"value": "5g-low"},
                    ],
                },
                "drma": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "drma_sensitivity": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                    ],
                },
                "airtime_fairness": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "protection_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "rtscts"},
                        {"value": "ctsonly"},
                        {"value": "disable"},
                    ],
                },
                "powersave_optimize": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "tim"},
                        {"value": "ac-vo"},
                        {"value": "no-obss-scan"},
                        {"value": "no-11b-rate"},
                        {"value": "client-rate-follow"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "transmit_optimize": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "disable"},
                        {"value": "power-save"},
                        {"value": "aggr-limit"},
                        {"value": "retry-limit"},
                        {"value": "send-bar"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "amsdu": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "coexistence": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "zero_wait_dfs": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bss_color": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "integer",
                },
                "bss_color_mode": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                    "options": [{"value": "auto"}, {"value": "static"}],
                },
                "short_guard_interval": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "mimo_mode": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "default"},
                        {"value": "1x1"},
                        {"value": "2x2"},
                        {"value": "3x3"},
                        {"value": "4x4"},
                        {"value": "8x8"},
                    ],
                },
                "channel_bonding": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "320MHz", "v_range": [["v7.4.4", ""]]},
                        {"value": "240MHz", "v_range": [["v7.4.4", ""]]},
                        {"value": "160MHz", "v_range": [["v6.2.0", ""]]},
                        {"value": "80MHz"},
                        {"value": "40MHz"},
                        {"value": "20MHz"},
                    ],
                },
                "channel_bonding_ext": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "320MHz-1"}, {"value": "320MHz-2"}],
                },
                "optional_antenna": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "custom", "v_range": [["v7.4.2", ""]]},
                        {"value": "FANT-04ABGN-0606-O-N"},
                        {"value": "FANT-04ABGN-1414-P-N"},
                        {"value": "FANT-04ABGN-8065-P-N"},
                        {"value": "FANT-04ABGN-0606-O-R"},
                        {"value": "FANT-04ABGN-0606-P-R"},
                        {"value": "FANT-10ACAX-1213-D-N"},
                        {"value": "FANT-08ABGN-1213-D-R"},
                        {"value": "FANT-04BEAX-0606-P-R", "v_range": [["v7.6.4", ""]]},
                    ],
                },
                "optional_antenna_gain": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "auto_power_level": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "auto_power_high": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "auto_power_low": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "auto_power_target": {"v_range": [["v6.4.4", ""]], "type": "string"},
                "power_mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "dBm"}, {"value": "percentage"}],
                },
                "power_level": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "power_value": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "dtim": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "beacon_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "rts_threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "frag_threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ap_sniffer_bufsize": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ap_sniffer_chan": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ap_sniffer_chan_width": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "320MHz"},
                        {"value": "240MHz"},
                        {"value": "160MHz"},
                        {"value": "80MHz"},
                        {"value": "40MHz"},
                        {"value": "20MHz"},
                    ],
                },
                "ap_sniffer_addr": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ap_sniffer_mgmt_beacon": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_mgmt_probe": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_mgmt_other": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_ctl": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_data": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "sam_ssid": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_bssid": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_security_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "open"},
                        {"value": "wpa-personal"},
                        {"value": "wpa-enterprise"},
                        {"value": "wpa3-sae", "v_range": [["v7.4.2", ""]]},
                        {"value": "owe", "v_range": [["v7.4.2", ""]]},
                    ],
                },
                "sam_captive_portal": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "sam_cwp_username": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_password": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_test_url": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_match_string": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_success_string": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                },
                "sam_cwp_failure_string": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                },
                "sam_eap_method": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "both"}, {"value": "tls"}, {"value": "peap"}],
                },
                "sam_client_certificate": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "sam_private_key": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "sam_private_key_password": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "sam_ca_certificate": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "sam_username": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_password": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_test": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "ping"}, {"value": "iperf"}],
                },
                "sam_server_type": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "ip"}, {"value": "fqdn"}],
                },
                "sam_server_ip": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_server_fqdn": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "iperf_server_port": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "iperf_protocol": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "udp"}, {"value": "tcp"}],
                },
                "sam_report_intv": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "channel_utilization": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "wids_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "darrp": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "arrp_profile": {"v_range": [["v7.0.4", ""]], "type": "string"},
                "max_clients": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "max_distance": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "vap_all": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "tunnel", "v_range": [["v6.4.0", ""]]},
                        {"value": "bridge", "v_range": [["v6.4.0", ""]]},
                        {"value": "manual", "v_range": [["v6.4.0", ""]]},
                        {"value": "enable", "v_range": [["v6.0.0", "v6.2.7"]]},
                        {"value": "disable", "v_range": [["v6.0.0", "v6.2.7"]]},
                    ],
                },
                "vaps": {
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
                "channel": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "chan": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "call_admission_control": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "call_capacity": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "bandwidth_admission_control": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bandwidth_capacity": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "sam_server": {"v_range": [["v7.0.0", "v7.0.0"]], "type": "string"},
                "spectrum_analysis": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "scan-only", "v_range": [["v6.4.1", "v6.4.1"]]},
                        {"value": "disable"},
                    ],
                },
                "frequency_handoff": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_handoff": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "radio_id": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "integer",
                },
                "set_80211d": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "set_80211mc": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "radio_2": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disabled"},
                        {"value": "ap"},
                        {"value": "monitor"},
                        {"value": "sniffer"},
                        {"value": "sam", "v_range": [["v7.0.0", ""]]},
                    ],
                },
                "band": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "802.11a"},
                        {"value": "802.11b"},
                        {"value": "802.11g"},
                        {"value": "802.11n-2G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11n-5G"},
                        {"value": "802.11ac-2G", "v_range": [["v6.4.0", ""]]},
                        {"value": "802.11ac-5G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11ax-2G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11ax-5G", "v_range": [["v6.2.0", ""]]},
                        {
                            "value": "802.11ax-6G",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                        },
                        {"value": "802.11be-2G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11be-5G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11be-6G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11n", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11ac", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11ax", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {"value": "802.11n,g-only", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11g-only", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11n-only", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11n-5G-only", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11ac,n-only", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {"value": "802.11ac-only", "v_range": [["v6.0.0", "v7.4.3"]]},
                        {
                            "value": "802.11ax,ac-only",
                            "v_range": [["v6.2.0", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ax,ac,n-only",
                            "v_range": [["v6.2.0", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ax-5G-only",
                            "v_range": [["v6.2.0", "v7.4.3"]],
                        },
                        {"value": "802.11ax,n-only", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {
                            "value": "802.11ax,n,g-only",
                            "v_range": [["v6.2.0", "v7.4.3"]],
                        },
                        {"value": "802.11ax-only", "v_range": [["v6.2.0", "v7.4.3"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "band_5g_type": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [
                        {"value": "5g-full"},
                        {"value": "5g-high"},
                        {"value": "5g-low"},
                    ],
                },
                "drma": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "drma_sensitivity": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                    ],
                },
                "airtime_fairness": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "protection_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "rtscts"},
                        {"value": "ctsonly"},
                        {"value": "disable"},
                    ],
                },
                "powersave_optimize": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "tim"},
                        {"value": "ac-vo"},
                        {"value": "no-obss-scan"},
                        {"value": "no-11b-rate"},
                        {"value": "client-rate-follow"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "transmit_optimize": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "disable"},
                        {"value": "power-save"},
                        {"value": "aggr-limit"},
                        {"value": "retry-limit"},
                        {"value": "send-bar"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "amsdu": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "coexistence": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "zero_wait_dfs": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bss_color": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "integer",
                },
                "bss_color_mode": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                    "options": [{"value": "auto"}, {"value": "static"}],
                },
                "short_guard_interval": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "mimo_mode": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "default"},
                        {"value": "1x1"},
                        {"value": "2x2"},
                        {"value": "3x3"},
                        {"value": "4x4"},
                        {"value": "8x8"},
                    ],
                },
                "channel_bonding": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "320MHz", "v_range": [["v7.4.4", ""]]},
                        {"value": "240MHz", "v_range": [["v7.4.4", ""]]},
                        {"value": "160MHz", "v_range": [["v6.2.0", ""]]},
                        {"value": "80MHz"},
                        {"value": "40MHz"},
                        {"value": "20MHz"},
                    ],
                },
                "channel_bonding_ext": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "320MHz-1"}, {"value": "320MHz-2"}],
                },
                "optional_antenna": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "custom", "v_range": [["v7.4.2", ""]]},
                        {"value": "FANT-04ABGN-0606-O-N"},
                        {"value": "FANT-04ABGN-1414-P-N"},
                        {"value": "FANT-04ABGN-8065-P-N"},
                        {"value": "FANT-04ABGN-0606-O-R"},
                        {"value": "FANT-04ABGN-0606-P-R"},
                        {"value": "FANT-10ACAX-1213-D-N"},
                        {"value": "FANT-08ABGN-1213-D-R"},
                        {"value": "FANT-04BEAX-0606-P-R", "v_range": [["v7.6.4", ""]]},
                    ],
                },
                "optional_antenna_gain": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "auto_power_level": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "auto_power_high": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "auto_power_low": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "auto_power_target": {"v_range": [["v6.4.4", ""]], "type": "string"},
                "power_mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "dBm"}, {"value": "percentage"}],
                },
                "power_level": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "power_value": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "dtim": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "beacon_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "rts_threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "frag_threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ap_sniffer_bufsize": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ap_sniffer_chan": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ap_sniffer_chan_width": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "320MHz"},
                        {"value": "240MHz"},
                        {"value": "160MHz"},
                        {"value": "80MHz"},
                        {"value": "40MHz"},
                        {"value": "20MHz"},
                    ],
                },
                "ap_sniffer_addr": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ap_sniffer_mgmt_beacon": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_mgmt_probe": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_mgmt_other": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_ctl": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_data": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "sam_ssid": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_bssid": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_security_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "open"},
                        {"value": "wpa-personal"},
                        {"value": "wpa-enterprise"},
                        {"value": "wpa3-sae", "v_range": [["v7.4.2", ""]]},
                        {"value": "owe", "v_range": [["v7.4.2", ""]]},
                    ],
                },
                "sam_captive_portal": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "sam_cwp_username": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_password": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_test_url": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_match_string": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_success_string": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                },
                "sam_cwp_failure_string": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                },
                "sam_eap_method": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "both"}, {"value": "tls"}, {"value": "peap"}],
                },
                "sam_client_certificate": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "sam_private_key": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "sam_private_key_password": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "sam_ca_certificate": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "sam_username": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_password": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_test": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "ping"}, {"value": "iperf"}],
                },
                "sam_server_type": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "ip"}, {"value": "fqdn"}],
                },
                "sam_server_ip": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_server_fqdn": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "iperf_server_port": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "iperf_protocol": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "udp"}, {"value": "tcp"}],
                },
                "sam_report_intv": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "channel_utilization": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "wids_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "darrp": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "arrp_profile": {"v_range": [["v7.0.4", ""]], "type": "string"},
                "max_clients": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "max_distance": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "vap_all": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "tunnel", "v_range": [["v6.4.0", ""]]},
                        {"value": "bridge", "v_range": [["v6.4.0", ""]]},
                        {"value": "manual", "v_range": [["v6.4.0", ""]]},
                        {"value": "enable", "v_range": [["v6.0.0", "v6.2.7"]]},
                        {"value": "disable", "v_range": [["v6.0.0", "v6.2.7"]]},
                    ],
                },
                "vaps": {
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
                "channel": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "chan": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "call_admission_control": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "call_capacity": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "bandwidth_admission_control": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bandwidth_capacity": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "sam_server": {"v_range": [["v7.0.0", "v7.0.0"]], "type": "string"},
                "spectrum_analysis": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "scan-only", "v_range": [["v6.4.1", "v6.4.1"]]},
                        {"value": "disable"},
                    ],
                },
                "frequency_handoff": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_handoff": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "radio_id": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "integer",
                },
                "set_80211d": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "set_80211mc": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "radio_3": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disabled"},
                        {"value": "ap"},
                        {"value": "monitor"},
                        {"value": "sniffer"},
                        {"value": "sam", "v_range": [["v7.0.0", ""]]},
                    ],
                },
                "band": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "802.11a"},
                        {"value": "802.11b"},
                        {"value": "802.11g"},
                        {"value": "802.11n-2G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11n-5G"},
                        {"value": "802.11ac-2G", "v_range": [["v6.4.0", ""]]},
                        {"value": "802.11ac-5G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11ax-2G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11ax-5G"},
                        {
                            "value": "802.11ax-6G",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                        },
                        {"value": "802.11be-2G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11be-5G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11be-6G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11n", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {"value": "802.11ac", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {"value": "802.11ax", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {"value": "802.11n,g-only", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {"value": "802.11g-only", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {"value": "802.11n-only", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {"value": "802.11n-5G-only", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {"value": "802.11ac,n-only", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {"value": "802.11ac-only", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {
                            "value": "802.11ax,ac-only",
                            "v_range": [["v6.2.0", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ax,ac,n-only",
                            "v_range": [["v6.2.0", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ax-5G-only",
                            "v_range": [["v6.2.0", "v7.4.3"]],
                        },
                        {"value": "802.11ax,n-only", "v_range": [["v6.2.0", "v7.4.3"]]},
                        {
                            "value": "802.11ax,n,g-only",
                            "v_range": [["v6.2.0", "v7.4.3"]],
                        },
                        {"value": "802.11ax-only", "v_range": [["v6.2.0", "v7.4.3"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "band_5g_type": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [
                        {"value": "5g-full"},
                        {"value": "5g-high"},
                        {"value": "5g-low"},
                    ],
                },
                "drma": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "drma_sensitivity": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                    ],
                },
                "airtime_fairness": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "protection_mode": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "rtscts"},
                        {"value": "ctsonly"},
                        {"value": "disable"},
                    ],
                },
                "powersave_optimize": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "tim"},
                        {"value": "ac-vo"},
                        {"value": "no-obss-scan"},
                        {"value": "no-11b-rate"},
                        {"value": "client-rate-follow"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "transmit_optimize": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "disable"},
                        {"value": "power-save"},
                        {"value": "aggr-limit"},
                        {"value": "retry-limit"},
                        {"value": "send-bar"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "amsdu": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "coexistence": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "zero_wait_dfs": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bss_color": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "integer",
                },
                "bss_color_mode": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                    "options": [{"value": "auto"}, {"value": "static"}],
                },
                "short_guard_interval": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "mimo_mode": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "default"},
                        {"value": "1x1"},
                        {"value": "2x2"},
                        {"value": "3x3"},
                        {"value": "4x4"},
                        {"value": "8x8"},
                    ],
                },
                "channel_bonding": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "320MHz", "v_range": [["v7.4.4", ""]]},
                        {"value": "240MHz", "v_range": [["v7.4.4", ""]]},
                        {"value": "160MHz"},
                        {"value": "80MHz"},
                        {"value": "40MHz"},
                        {"value": "20MHz"},
                    ],
                },
                "channel_bonding_ext": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "320MHz-1"}, {"value": "320MHz-2"}],
                },
                "optional_antenna": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "custom", "v_range": [["v7.4.2", ""]]},
                        {"value": "FANT-04ABGN-0606-O-N"},
                        {"value": "FANT-04ABGN-1414-P-N"},
                        {"value": "FANT-04ABGN-8065-P-N"},
                        {"value": "FANT-04ABGN-0606-O-R"},
                        {"value": "FANT-04ABGN-0606-P-R"},
                        {"value": "FANT-10ACAX-1213-D-N"},
                        {"value": "FANT-08ABGN-1213-D-R"},
                        {"value": "FANT-04BEAX-0606-P-R", "v_range": [["v7.6.4", ""]]},
                    ],
                },
                "optional_antenna_gain": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "auto_power_level": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "auto_power_high": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "auto_power_low": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "auto_power_target": {"v_range": [["v6.4.4", ""]], "type": "string"},
                "power_mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "dBm"}, {"value": "percentage"}],
                },
                "power_level": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "power_value": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "dtim": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "beacon_interval": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "rts_threshold": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "frag_threshold": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "ap_sniffer_bufsize": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "ap_sniffer_chan": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "ap_sniffer_chan_width": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "320MHz"},
                        {"value": "240MHz"},
                        {"value": "160MHz"},
                        {"value": "80MHz"},
                        {"value": "40MHz"},
                        {"value": "20MHz"},
                    ],
                },
                "ap_sniffer_addr": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "ap_sniffer_mgmt_beacon": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_mgmt_probe": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_mgmt_other": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_ctl": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_data": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "sam_ssid": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_bssid": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_security_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "open"},
                        {"value": "wpa-personal"},
                        {"value": "wpa-enterprise"},
                        {"value": "wpa3-sae", "v_range": [["v7.4.2", ""]]},
                        {"value": "owe", "v_range": [["v7.4.2", ""]]},
                    ],
                },
                "sam_captive_portal": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "sam_cwp_username": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_password": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_test_url": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_match_string": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_success_string": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                },
                "sam_cwp_failure_string": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                },
                "sam_eap_method": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "both"}, {"value": "tls"}, {"value": "peap"}],
                },
                "sam_client_certificate": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "sam_private_key": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "sam_private_key_password": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "sam_ca_certificate": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "sam_username": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_password": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_test": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "ping"}, {"value": "iperf"}],
                },
                "sam_server_type": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "ip"}, {"value": "fqdn"}],
                },
                "sam_server_ip": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_server_fqdn": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "iperf_server_port": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "iperf_protocol": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "udp"}, {"value": "tcp"}],
                },
                "sam_report_intv": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "channel_utilization": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "wids_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "darrp": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "arrp_profile": {"v_range": [["v7.0.4", ""]], "type": "string"},
                "max_clients": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "max_distance": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "vap_all": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "tunnel", "v_range": [["v6.4.0", ""]]},
                        {"value": "bridge", "v_range": [["v6.4.0", ""]]},
                        {"value": "manual", "v_range": [["v6.4.0", ""]]},
                        {"value": "enable", "v_range": [["v6.2.0", "v6.2.7"]]},
                        {"value": "disable", "v_range": [["v6.2.0", "v6.2.7"]]},
                    ],
                },
                "vaps": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.2.0", ""]],
                },
                "channel": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "chan": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.2.0", ""]],
                },
                "call_admission_control": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "call_capacity": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "bandwidth_admission_control": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bandwidth_capacity": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "sam_server": {"v_range": [["v7.0.0", "v7.0.0"]], "type": "string"},
                "spectrum_analysis": {
                    "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "scan-only", "v_range": [["v6.4.1", "v6.4.1"]]},
                        {"value": "disable"},
                    ],
                },
                "frequency_handoff": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_handoff": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "radio_id": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "integer"},
                "set_80211d": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "set_80211mc": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "radio_4": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disabled"},
                        {"value": "ap"},
                        {"value": "monitor"},
                        {"value": "sniffer"},
                        {"value": "sam", "v_range": [["v7.0.0", ""]]},
                    ],
                },
                "band": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "list",
                    "options": [
                        {"value": "802.11a"},
                        {"value": "802.11b"},
                        {"value": "802.11g"},
                        {"value": "802.11n-2G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11n-5G"},
                        {"value": "802.11ac-2G", "v_range": [["v6.4.0", ""]]},
                        {"value": "802.11ac-5G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11ax-2G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11ax-5G"},
                        {
                            "value": "802.11ax-6G",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                        },
                        {"value": "802.11be-2G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11be-5G", "v_range": [["v7.4.4", ""]]},
                        {"value": "802.11be-6G", "v_range": [["v7.4.4", ""]]},
                        {
                            "value": "802.11n",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ac",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ax",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11n,g-only",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11g-only",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11n-only",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11n-5G-only",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ac,n-only",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ac-only",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ax,ac-only",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ax,ac,n-only",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ax-5G-only",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ax,n-only",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ax,n,g-only",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                        {
                            "value": "802.11ax-only",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.4.3"]],
                        },
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "band_5g_type": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [
                        {"value": "5g-full"},
                        {"value": "5g-high"},
                        {"value": "5g-low"},
                    ],
                },
                "drma": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "drma_sensitivity": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                    ],
                },
                "airtime_fairness": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "protection_mode": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [
                        {"value": "rtscts"},
                        {"value": "ctsonly"},
                        {"value": "disable"},
                    ],
                },
                "powersave_optimize": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "list",
                    "options": [
                        {"value": "tim"},
                        {"value": "ac-vo"},
                        {"value": "no-obss-scan"},
                        {"value": "no-11b-rate"},
                        {"value": "client-rate-follow"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "transmit_optimize": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "list",
                    "options": [
                        {"value": "disable"},
                        {"value": "power-save"},
                        {"value": "aggr-limit"},
                        {"value": "retry-limit"},
                        {"value": "send-bar"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "amsdu": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "coexistence": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "zero_wait_dfs": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bss_color": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "integer",
                },
                "bss_color_mode": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                    "options": [{"value": "auto"}, {"value": "static"}],
                },
                "short_guard_interval": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "mimo_mode": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "default"},
                        {"value": "1x1"},
                        {"value": "2x2"},
                        {"value": "3x3"},
                        {"value": "4x4"},
                        {"value": "8x8"},
                    ],
                },
                "channel_bonding": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [
                        {"value": "320MHz", "v_range": [["v7.4.4", ""]]},
                        {"value": "240MHz", "v_range": [["v7.4.4", ""]]},
                        {"value": "160MHz"},
                        {"value": "80MHz"},
                        {"value": "40MHz"},
                        {"value": "20MHz"},
                    ],
                },
                "channel_bonding_ext": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "320MHz-1"}, {"value": "320MHz-2"}],
                },
                "optional_antenna": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "custom", "v_range": [["v7.4.2", ""]]},
                        {"value": "FANT-04ABGN-0606-O-N"},
                        {"value": "FANT-04ABGN-1414-P-N"},
                        {"value": "FANT-04ABGN-8065-P-N"},
                        {"value": "FANT-04ABGN-0606-O-R"},
                        {"value": "FANT-04ABGN-0606-P-R"},
                        {"value": "FANT-10ACAX-1213-D-N"},
                        {"value": "FANT-08ABGN-1213-D-R"},
                        {"value": "FANT-04BEAX-0606-P-R", "v_range": [["v7.6.4", ""]]},
                    ],
                },
                "optional_antenna_gain": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "auto_power_level": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "auto_power_high": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "integer",
                },
                "auto_power_low": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "integer",
                },
                "auto_power_target": {"v_range": [["v6.4.4", ""]], "type": "string"},
                "power_mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "dBm"}, {"value": "percentage"}],
                },
                "power_level": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "integer",
                },
                "power_value": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "dtim": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "integer",
                },
                "beacon_interval": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "integer",
                },
                "rts_threshold": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "integer",
                },
                "frag_threshold": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "integer",
                },
                "ap_sniffer_bufsize": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "integer",
                },
                "ap_sniffer_chan": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "integer",
                },
                "ap_sniffer_chan_width": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "320MHz"},
                        {"value": "240MHz"},
                        {"value": "160MHz"},
                        {"value": "80MHz"},
                        {"value": "40MHz"},
                        {"value": "20MHz"},
                    ],
                },
                "ap_sniffer_addr": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                },
                "ap_sniffer_mgmt_beacon": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_mgmt_probe": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_mgmt_other": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_ctl": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_sniffer_data": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "sam_ssid": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_bssid": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_security_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "open"},
                        {"value": "wpa-personal"},
                        {"value": "wpa-enterprise"},
                        {"value": "wpa3-sae", "v_range": [["v7.4.2", ""]]},
                        {"value": "owe", "v_range": [["v7.4.2", ""]]},
                    ],
                },
                "sam_captive_portal": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "sam_cwp_username": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_password": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_test_url": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_match_string": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_cwp_success_string": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                },
                "sam_cwp_failure_string": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                },
                "sam_eap_method": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "both"}, {"value": "tls"}, {"value": "peap"}],
                },
                "sam_client_certificate": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "sam_private_key": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "sam_private_key_password": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "sam_ca_certificate": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "sam_username": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_password": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "sam_test": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "ping"}, {"value": "iperf"}],
                },
                "sam_server_type": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "ip"}, {"value": "fqdn"}],
                },
                "sam_server_ip": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "sam_server_fqdn": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "iperf_server_port": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "iperf_protocol": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "udp"}, {"value": "tcp"}],
                },
                "sam_report_intv": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "channel_utilization": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "wids_profile": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                },
                "darrp": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "arrp_profile": {"v_range": [["v7.0.4", ""]], "type": "string"},
                "max_clients": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "integer",
                },
                "max_distance": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "integer",
                },
                "vap_all": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [
                        {"value": "tunnel", "v_range": [["v6.4.0", ""]]},
                        {"value": "bridge", "v_range": [["v6.4.0", ""]]},
                        {"value": "manual", "v_range": [["v6.4.0", ""]]},
                        {
                            "value": "enable",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.2.7"]],
                        },
                        {
                            "value": "disable",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.2.7"]],
                        },
                    ],
                },
                "vaps": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                },
                "channel": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "chan": {
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                },
                "call_admission_control": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "call_capacity": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "integer",
                },
                "bandwidth_admission_control": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bandwidth_capacity": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "integer",
                },
                "sam_server": {"v_range": [["v7.0.0", "v7.0.0"]], "type": "string"},
                "spectrum_analysis": {
                    "v_range": [
                        ["v6.2.0", "v6.2.0"],
                        ["v6.2.5", "v6.2.7"],
                        ["v6.4.1", "v6.4.1"],
                    ],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "scan-only", "v_range": [["v6.4.1", "v6.4.1"]]},
                        {"value": "disable"},
                    ],
                },
                "frequency_handoff": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ap_handoff": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "set_80211d": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "set_80211mc": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "lbs": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ekahau_blink_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ekahau_tag": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "erc_server_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "erc_server_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "aeroscout": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "aeroscout_server_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "aeroscout_server_port": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "aeroscout_mu": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "aeroscout_ap_mac": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "bssid"}, {"value": "board-mac"}],
                },
                "aeroscout_mmu_report": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "aeroscout_mu_factor": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "aeroscout_mu_timeout": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "fortipresence": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "foreign"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "fortipresence_server_addr_type": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                    "options": [{"value": "ipv4"}, {"value": "fqdn"}],
                },
                "fortipresence_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "fortipresence_server_fqdn": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                },
                "fortipresence_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "fortipresence_secret": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "fortipresence_project": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                },
                "fortipresence_frequency": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "fortipresence_rogue": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "fortipresence_unassoc": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "fortipresence_ble": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "station_locate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ble_rtls": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "polestar"},
                        {"value": "evresys"},
                    ],
                },
                "ble_rtls_protocol": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "WSS"}],
                },
                "ble_rtls_server_fqdn": {"v_range": [["v7.6.1", ""]], "type": "string"},
                "ble_rtls_server_path": {"v_range": [["v7.6.1", ""]], "type": "string"},
                "ble_rtls_server_token": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                },
                "ble_rtls_server_port": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "integer",
                },
                "ble_rtls_accumulation_interval": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "integer",
                },
                "ble_rtls_reporting_interval": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "integer",
                },
                "ble_rtls_asset_uuid_list1": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                },
                "ble_rtls_asset_uuid_list2": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                },
                "ble_rtls_asset_uuid_list3": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                },
                "ble_rtls_asset_uuid_list4": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                },
                "ble_rtls_asset_addrgrp_list": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                },
                "polestar": {
                    "v_range": [["v7.4.1", "v7.6.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "polestar_protocol": {
                    "v_range": [["v7.4.1", "v7.6.0"]],
                    "type": "string",
                    "options": [{"value": "WSS"}],
                },
                "polestar_server_fqdn": {
                    "v_range": [["v7.4.1", "v7.6.0"]],
                    "type": "string",
                },
                "polestar_server_path": {
                    "v_range": [["v7.4.1", "v7.6.0"]],
                    "type": "string",
                },
                "polestar_server_token": {
                    "v_range": [["v7.4.1", "v7.6.0"]],
                    "type": "string",
                },
                "polestar_server_port": {
                    "v_range": [["v7.4.1", "v7.6.0"]],
                    "type": "integer",
                },
                "polestar_accumulation_interval": {
                    "v_range": [["v7.4.1", "v7.6.0"]],
                    "type": "integer",
                },
                "polestar_reporting_interval": {
                    "v_range": [["v7.4.1", "v7.6.0"]],
                    "type": "integer",
                },
                "polestar_asset_uuid_list1": {
                    "v_range": [["v7.4.1", "v7.6.0"]],
                    "type": "string",
                },
                "polestar_asset_uuid_list2": {
                    "v_range": [["v7.4.1", "v7.6.0"]],
                    "type": "string",
                },
                "polestar_asset_uuid_list3": {
                    "v_range": [["v7.4.1", "v7.6.0"]],
                    "type": "string",
                },
                "polestar_asset_uuid_list4": {
                    "v_range": [["v7.4.1", "v7.6.0"]],
                    "type": "string",
                },
                "polestar_asset_addrgrp_list": {
                    "v_range": [["v7.4.1", "v7.6.0"]],
                    "type": "string",
                },
            },
        },
        "ext_info_enable": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "indoor_outdoor_deployment": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [
                {"value": "platform-determined"},
                {"value": "outdoor"},
                {"value": "indoor"},
            ],
        },
        "esl_ses_dongle": {
            "v_range": [["v7.0.1", ""]],
            "type": "dict",
            "children": {
                "compliance_level": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "compliance-level-2"}],
                },
                "scd_enable": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "esl_channel": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "-1"},
                        {"value": "0"},
                        {"value": "1"},
                        {"value": "2"},
                        {"value": "3"},
                        {"value": "4"},
                        {"value": "5"},
                        {"value": "6"},
                        {"value": "7"},
                        {"value": "8"},
                        {"value": "9"},
                        {"value": "10"},
                        {"value": "127"},
                    ],
                },
                "output_power": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "a"},
                        {"value": "b"},
                        {"value": "c"},
                        {"value": "d"},
                        {"value": "e"},
                        {"value": "f"},
                        {"value": "g"},
                        {"value": "h"},
                    ],
                },
                "apc_addr_type": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "fqdn"}, {"value": "ip"}],
                },
                "apc_fqdn": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "apc_ip": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "apc_port": {"v_range": [["v7.0.1", ""]], "type": "integer"},
                "coex_level": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "none"}],
                },
                "tls_cert_verification": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "tls_fqdn_verification": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "console_login": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wan_port_auth": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "802.1x"}],
        },
        "wan_port_auth_usrname": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "wan_port_auth_password": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "wan_port_auth_methods": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [
                {"value": "all"},
                {"value": "EAP-FAST"},
                {"value": "EAP-TLS"},
                {"value": "EAP-PEAP"},
            ],
        },
        "wan_port_auth_macsec": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "unii_4_5ghz_band": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "admin_restrict_local": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "admin_auth_tacacs_plus": {"v_range": [["v7.6.1", ""]], "type": "string"},
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
        "wireless_controller_wtp_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_wtp_profile"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_wtp_profile"]["options"][attribute_name][
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
            fos, versioned_schema, "wireless_controller_wtp_profile"
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
