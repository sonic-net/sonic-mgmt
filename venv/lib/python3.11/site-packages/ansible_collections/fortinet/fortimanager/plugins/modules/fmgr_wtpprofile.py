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
module: fmgr_wtpprofile
short_description: Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms.
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
    wtpprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            allowaccess:
                type: list
                elements: str
                description: Control management access to the managed WTP, FortiAP, or AP.
                choices:
                    - 'https'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
            ap_country:
                aliases: ['ap-country']
                type: str
                description: Country in which this WTP, FortiAP or AP will operate
                choices:
                    - 'AL'
                    - 'DZ'
                    - 'AR'
                    - 'AM'
                    - 'AU'
                    - 'AT'
                    - 'AZ'
                    - 'BH'
                    - 'BD'
                    - 'BY'
                    - 'BE'
                    - 'BZ'
                    - 'BO'
                    - 'BA'
                    - 'BR'
                    - 'BN'
                    - 'BG'
                    - 'CA'
                    - 'CL'
                    - 'CN'
                    - 'CO'
                    - 'CR'
                    - 'HR'
                    - 'CY'
                    - 'CZ'
                    - 'DK'
                    - 'DO'
                    - 'EC'
                    - 'EG'
                    - 'SV'
                    - 'EE'
                    - 'FI'
                    - 'FR'
                    - 'GE'
                    - 'DE'
                    - 'GR'
                    - 'GT'
                    - 'HN'
                    - 'HK'
                    - 'HU'
                    - 'IS'
                    - 'IN'
                    - 'ID'
                    - 'IR'
                    - 'IE'
                    - 'IL'
                    - 'IT'
                    - 'JM'
                    - 'JP'
                    - 'JO'
                    - 'KZ'
                    - 'KE'
                    - 'KP'
                    - 'KR'
                    - 'KW'
                    - 'LV'
                    - 'LB'
                    - 'LI'
                    - 'LT'
                    - 'LU'
                    - 'MO'
                    - 'MK'
                    - 'MY'
                    - 'MT'
                    - 'MX'
                    - 'MC'
                    - 'MA'
                    - 'NP'
                    - 'NL'
                    - 'AN'
                    - 'NZ'
                    - 'NO'
                    - 'OM'
                    - 'PK'
                    - 'PA'
                    - 'PG'
                    - 'PE'
                    - 'PH'
                    - 'PL'
                    - 'PT'
                    - 'PR'
                    - 'QA'
                    - 'RO'
                    - 'RU'
                    - 'SA'
                    - 'SG'
                    - 'SK'
                    - 'SI'
                    - 'ZA'
                    - 'ES'
                    - 'LK'
                    - 'SE'
                    - 'CH'
                    - 'SY'
                    - 'TW'
                    - 'TH'
                    - 'TT'
                    - 'TN'
                    - 'TR'
                    - 'AE'
                    - 'UA'
                    - 'GB'
                    - 'US'
                    - 'PS'
                    - 'UY'
                    - 'UZ'
                    - 'VE'
                    - 'VN'
                    - 'YE'
                    - 'ZW'
                    - 'NA'
                    - 'KH'
                    - 'TZ'
                    - 'SD'
                    - 'AO'
                    - 'RW'
                    - 'MZ'
                    - 'RS'
                    - 'ME'
                    - 'BB'
                    - 'GD'
                    - 'GL'
                    - 'GU'
                    - 'PY'
                    - 'HT'
                    - 'AW'
                    - 'MM'
                    - 'ZB'
                    - 'CF'
                    - 'BS'
                    - 'VC'
                    - 'MV'
                    - 'SN'
                    - 'CI'
                    - 'GH'
                    - 'MW'
                    - 'UG'
                    - 'BF'
                    - 'KY'
                    - 'TC'
                    - 'TM'
                    - 'VU'
                    - 'FM'
                    - 'GY'
                    - 'KN'
                    - 'LC'
                    - 'CX'
                    - 'AF'
                    - 'CM'
                    - 'ML'
                    - 'BJ'
                    - 'MG'
                    - 'TD'
                    - 'BW'
                    - 'LY'
                    - 'LS'
                    - 'MU'
                    - 'SL'
                    - 'NE'
                    - 'TG'
                    - 'RE'
                    - 'MD'
                    - 'BM'
                    - 'VI'
                    - 'PM'
                    - 'MF'
                    - 'IM'
                    - 'FO'
                    - 'GI'
                    - 'LA'
                    - 'WF'
                    - 'MH'
                    - 'BT'
                    - 'PF'
                    - 'NI'
                    - 'GF'
                    - 'AS'
                    - 'MP'
                    - 'PW'
                    - 'GP'
                    - 'ET'
                    - 'SR'
                    - 'DM'
                    - 'MQ'
                    - 'YT'
                    - 'BL'
                    - 'ZM'
                    - 'CG'
                    - 'CD'
                    - 'MR'
                    - 'IQ'
                    - 'FJ'
                    - '--'
                    - 'MN'
                    - 'NG'
                    - 'GA'
                    - 'GM'
                    - 'SO'
                    - 'SZ'
                    - 'LR'
                    - 'DJ'
                    - 'TL'
            ble_profile:
                aliases: ['ble-profile']
                type: str
                description: Bluetooth Low Energy profile name.
            comment:
                type: str
                description: Comment.
            control_message_offload:
                aliases: ['control-message-offload']
                type: list
                elements: str
                description: Enable/disable CAPWAP control message data channel offload.
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
            deny_mac_list:
                aliases: ['deny-mac-list']
                type: list
                elements: dict
                description: Deny mac list.
                suboptions:
                    id:
                        type: int
                        description: ID.
                    mac:
                        type: str
                        description: A WiFi device with this MAC address is denied access to this WTP, FortiAP or AP.
            dtls_in_kernel:
                aliases: ['dtls-in-kernel']
                type: str
                description: Enable/disable data channel DTLS in kernel.
                choices:
                    - 'disable'
                    - 'enable'
            dtls_policy:
                aliases: ['dtls-policy']
                type: list
                elements: str
                description: WTP data channel DTLS policy
                choices:
                    - 'clear-text'
                    - 'dtls-enabled'
                    - 'ipsec-vpn'
                    - 'ipsec-sn-vpn'
            energy_efficient_ethernet:
                aliases: ['energy-efficient-ethernet']
                type: str
                description: Enable/disable use of energy efficient Ethernet on WTP.
                choices:
                    - 'disable'
                    - 'enable'
            ext_info_enable:
                aliases: ['ext-info-enable']
                type: str
                description: Enable/disable station/VAP/radio extension information.
                choices:
                    - 'disable'
                    - 'enable'
            handoff_roaming:
                aliases: ['handoff-roaming']
                type: str
                description: Enable/disable client load balancing during roaming to avoid roaming delay
                choices:
                    - 'disable'
                    - 'enable'
            handoff_rssi:
                aliases: ['handoff-rssi']
                type: int
                description: Minimum received signal strength indicator
            handoff_sta_thresh:
                aliases: ['handoff-sta-thresh']
                type: int
                description: Threshold value for AP handoff.
            ip_fragment_preventing:
                aliases: ['ip-fragment-preventing']
                type: list
                elements: str
                description: Select how to prevent IP fragmentation for CAPWAP tunneled control and data packets
                choices:
                    - 'tcp-mss-adjust'
                    - 'icmp-unreachable'
            led_schedules:
                aliases: ['led-schedules']
                type: raw
                description: (list or str) Recurring firewall schedules for illuminating LEDs on the FortiAP.
            led_state:
                aliases: ['led-state']
                type: str
                description: Enable/disable use of LEDs on WTP
                choices:
                    - 'disable'
                    - 'enable'
            lldp:
                type: str
                description: Enable/disable Link Layer Discovery Protocol
                choices:
                    - 'disable'
                    - 'enable'
            login_passwd:
                aliases: ['login-passwd']
                type: raw
                description: (list) Set the managed WTP, FortiAP, or APs administrator password.
            login_passwd_change:
                aliases: ['login-passwd-change']
                type: str
                description: Change or reset the administrator password of a managed WTP, FortiAP or AP
                choices:
                    - 'no'
                    - 'yes'
                    - 'default'
            max_clients:
                aliases: ['max-clients']
                type: int
                description: Maximum number of stations
            name:
                type: str
                description: WTP
                required: true
            poe_mode:
                aliases: ['poe-mode']
                type: str
                description: Set the WTP, FortiAP, or APs PoE mode.
                choices:
                    - 'auto'
                    - '8023af'
                    - '8023at'
                    - 'power-adapter'
                    - 'full'
                    - 'high'
                    - 'low'
            split_tunneling_acl:
                aliases: ['split-tunneling-acl']
                type: list
                elements: dict
                description: Split tunneling acl.
                suboptions:
                    dest_ip:
                        aliases: ['dest-ip']
                        type: str
                        description: Destination IP and mask for the split-tunneling subnet.
                    id:
                        type: int
                        description: ID.
            split_tunneling_acl_local_ap_subnet:
                aliases: ['split-tunneling-acl-local-ap-subnet']
                type: str
                description: Enable/disable automatically adding local subnetwork of FortiAP to split-tunneling ACL
                choices:
                    - 'disable'
                    - 'enable'
            split_tunneling_acl_path:
                aliases: ['split-tunneling-acl-path']
                type: str
                description: Split tunneling ACL path is local/tunnel.
                choices:
                    - 'tunnel'
                    - 'local'
            tun_mtu_downlink:
                aliases: ['tun-mtu-downlink']
                type: int
                description: Downlink CAPWAP tunnel MTU
            tun_mtu_uplink:
                aliases: ['tun-mtu-uplink']
                type: int
                description: Uplink CAPWAP tunnel MTU
            wan_port_mode:
                aliases: ['wan-port-mode']
                type: str
                description: Enable/disable using a WAN port as a LAN port.
                choices:
                    - 'wan-lan'
                    - 'wan-only'
            snmp:
                type: str
                description: Enable/disable SNMP for the WTP, FortiAP, or AP
                choices:
                    - 'disable'
                    - 'enable'
            ap_handoff:
                aliases: ['ap-handoff']
                type: str
                description: Enable/disable AP handoff of clients to other APs
                choices:
                    - 'disable'
                    - 'enable'
            apcfg_profile:
                aliases: ['apcfg-profile']
                type: str
                description: AP local configuration profile name.
            frequency_handoff:
                aliases: ['frequency-handoff']
                type: str
                description: Enable/disable frequency handoff of clients to other channels
                choices:
                    - 'disable'
                    - 'enable'
            lan:
                type: dict
                description: Lan.
                suboptions:
                    port_esl_mode:
                        aliases: ['port-esl-mode']
                        type: str
                        description: ESL port mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port_esl_ssid:
                        aliases: ['port-esl-ssid']
                        type: str
                        description: Bridge ESL port to SSID.
                    port_mode:
                        aliases: ['port-mode']
                        type: str
                        description: LAN port mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port_ssid:
                        aliases: ['port-ssid']
                        type: str
                        description: Bridge LAN port to SSID.
                    port1_mode:
                        aliases: ['port1-mode']
                        type: str
                        description: LAN port 1 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port1_ssid:
                        aliases: ['port1-ssid']
                        type: str
                        description: Bridge LAN port 1 to SSID.
                    port2_mode:
                        aliases: ['port2-mode']
                        type: str
                        description: LAN port 2 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port2_ssid:
                        aliases: ['port2-ssid']
                        type: str
                        description: Bridge LAN port 2 to SSID.
                    port3_mode:
                        aliases: ['port3-mode']
                        type: str
                        description: LAN port 3 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port3_ssid:
                        aliases: ['port3-ssid']
                        type: str
                        description: Bridge LAN port 3 to SSID.
                    port4_mode:
                        aliases: ['port4-mode']
                        type: str
                        description: LAN port 4 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port4_ssid:
                        aliases: ['port4-ssid']
                        type: str
                        description: Bridge LAN port 4 to SSID.
                    port5_mode:
                        aliases: ['port5-mode']
                        type: str
                        description: LAN port 5 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port5_ssid:
                        aliases: ['port5-ssid']
                        type: str
                        description: Bridge LAN port 5 to SSID.
                    port6_mode:
                        aliases: ['port6-mode']
                        type: str
                        description: LAN port 6 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port6_ssid:
                        aliases: ['port6-ssid']
                        type: str
                        description: Bridge LAN port 6 to SSID.
                    port7_mode:
                        aliases: ['port7-mode']
                        type: str
                        description: LAN port 7 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port7_ssid:
                        aliases: ['port7-ssid']
                        type: str
                        description: Bridge LAN port 7 to SSID.
                    port8_mode:
                        aliases: ['port8-mode']
                        type: str
                        description: LAN port 8 mode.
                        choices:
                            - 'offline'
                            - 'bridge-to-wan'
                            - 'bridge-to-ssid'
                            - 'nat-to-wan'
                    port8_ssid:
                        aliases: ['port8-ssid']
                        type: str
                        description: Bridge LAN port 8 to SSID.
            lbs:
                type: dict
                description: Lbs.
                suboptions:
                    aeroscout:
                        type: str
                        description: Enable/disable AeroScout Real Time Location Service
                        choices:
                            - 'disable'
                            - 'enable'
                    aeroscout_ap_mac:
                        aliases: ['aeroscout-ap-mac']
                        type: str
                        description: Use BSSID or board MAC address as AP MAC address in AeroScout AP messages
                        choices:
                            - 'bssid'
                            - 'board-mac'
                    aeroscout_mmu_report:
                        aliases: ['aeroscout-mmu-report']
                        type: str
                        description: Enable/disable compounded AeroScout tag and MU report
                        choices:
                            - 'disable'
                            - 'enable'
                    aeroscout_mu:
                        aliases: ['aeroscout-mu']
                        type: str
                        description: Enable/disable AeroScout Mobile Unit
                        choices:
                            - 'disable'
                            - 'enable'
                    aeroscout_mu_factor:
                        aliases: ['aeroscout-mu-factor']
                        type: int
                        description: AeroScout MU mode dilution factor
                    aeroscout_mu_timeout:
                        aliases: ['aeroscout-mu-timeout']
                        type: int
                        description: AeroScout MU mode timeout
                    aeroscout_server_ip:
                        aliases: ['aeroscout-server-ip']
                        type: str
                        description: IP address of AeroScout server.
                    aeroscout_server_port:
                        aliases: ['aeroscout-server-port']
                        type: int
                        description: AeroScout server UDP listening port.
                    ekahau_blink_mode:
                        aliases: ['ekahau-blink-mode']
                        type: str
                        description: Enable/disable Ekahau blink mode
                        choices:
                            - 'disable'
                            - 'enable'
                    ekahau_tag:
                        aliases: ['ekahau-tag']
                        type: str
                        description: WiFi frame MAC address or WiFi Tag.
                    erc_server_ip:
                        aliases: ['erc-server-ip']
                        type: str
                        description: IP address of Ekahau RTLS Controller
                    erc_server_port:
                        aliases: ['erc-server-port']
                        type: int
                        description: Ekahau RTLS Controller
                    fortipresence:
                        type: str
                        description: Enable/disable FortiPresence to monitor the location and activity of WiFi clients even if they dont connect to thi...
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'enable2'
                            - 'foreign'
                            - 'both'
                    fortipresence_ble:
                        aliases: ['fortipresence-ble']
                        type: str
                        description: Enable/disable FortiPresence finding and reporting BLE devices.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortipresence_frequency:
                        aliases: ['fortipresence-frequency']
                        type: int
                        description: FortiPresence report transmit frequency
                    fortipresence_port:
                        aliases: ['fortipresence-port']
                        type: int
                        description: FortiPresence server UDP listening port
                    fortipresence_project:
                        aliases: ['fortipresence-project']
                        type: str
                        description: FortiPresence project name
                    fortipresence_rogue:
                        aliases: ['fortipresence-rogue']
                        type: str
                        description: Enable/disable FortiPresence finding and reporting rogue APs.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortipresence_secret:
                        aliases: ['fortipresence-secret']
                        type: raw
                        description: (list) FortiPresence secret password
                    fortipresence_server:
                        aliases: ['fortipresence-server']
                        type: str
                        description: FortiPresence server IP address.
                    fortipresence_unassoc:
                        aliases: ['fortipresence-unassoc']
                        type: str
                        description: Enable/disable FortiPresence finding and reporting unassociated stations.
                        choices:
                            - 'disable'
                            - 'enable'
                    station_locate:
                        aliases: ['station-locate']
                        type: str
                        description: Enable/disable client station locating services for all clients, whether associated or not
                        choices:
                            - 'disable'
                            - 'enable'
                    fortipresence_server_addr_type:
                        aliases: ['fortipresence-server-addr-type']
                        type: str
                        description: FortiPresence server address type
                        choices:
                            - 'fqdn'
                            - 'ipv4'
                    fortipresence_server_fqdn:
                        aliases: ['fortipresence-server-fqdn']
                        type: str
                        description: FQDN of FortiPresence server.
                    polestar:
                        type: str
                        description: Enable/disable PoleStar BLE NAO Track Real Time Location Service
                        choices:
                            - 'disable'
                            - 'enable'
                    polestar_accumulation_interval:
                        aliases: ['polestar-accumulation-interval']
                        type: int
                        description: Time that measurements should be accumulated in seconds
                    polestar_asset_addrgrp_list:
                        aliases: ['polestar-asset-addrgrp-list']
                        type: str
                        description: Tags and asset addrgrp list to be reported.
                    polestar_asset_uuid_list1:
                        aliases: ['polestar-asset-uuid-list1']
                        type: str
                        description: Tags and asset UUID list 1 to be reported
                    polestar_asset_uuid_list2:
                        aliases: ['polestar-asset-uuid-list2']
                        type: str
                        description: Tags and asset UUID list 2 to be reported
                    polestar_asset_uuid_list3:
                        aliases: ['polestar-asset-uuid-list3']
                        type: str
                        description: Tags and asset UUID list 3 to be reported
                    polestar_asset_uuid_list4:
                        aliases: ['polestar-asset-uuid-list4']
                        type: str
                        description: Tags and asset UUID list 4 to be reported
                    polestar_protocol:
                        aliases: ['polestar-protocol']
                        type: str
                        description: Select the protocol to report Measurements, Advertising Data, or Location Data to NAO Cloud.
                        choices:
                            - 'WSS'
                    polestar_reporting_interval:
                        aliases: ['polestar-reporting-interval']
                        type: int
                        description: Time between reporting accumulated measurements in seconds
                    polestar_server_fqdn:
                        aliases: ['polestar-server-fqdn']
                        type: str
                        description: FQDN of PoleStar Nao Track Server
                    polestar_server_path:
                        aliases: ['polestar-server-path']
                        type: str
                        description: Path of PoleStar Nao Track Server
                    polestar_server_port:
                        aliases: ['polestar-server-port']
                        type: int
                        description: Port of PoleStar Nao Track Server
                    polestar_server_token:
                        aliases: ['polestar-server-token']
                        type: str
                        description: Access Token of PoleStar Nao Track Server.
                    ble_rtls:
                        aliases: ['ble-rtls']
                        type: str
                        description: Set BLE Real Time Location Service
                        choices:
                            - 'none'
                            - 'polestar'
                            - 'evresys'
                    ble_rtls_accumulation_interval:
                        aliases: ['ble-rtls-accumulation-interval']
                        type: int
                        description: Time that measurements should be accumulated in seconds
                    ble_rtls_asset_addrgrp_list:
                        aliases: ['ble-rtls-asset-addrgrp-list']
                        type: raw
                        description: (list) Tags and asset addrgrp list to be reported.
                    ble_rtls_asset_uuid_list1:
                        aliases: ['ble-rtls-asset-uuid-list1']
                        type: str
                        description: Tags and asset UUID list 1 to be reported
                    ble_rtls_asset_uuid_list2:
                        aliases: ['ble-rtls-asset-uuid-list2']
                        type: str
                        description: Tags and asset UUID list 2 to be reported
                    ble_rtls_asset_uuid_list3:
                        aliases: ['ble-rtls-asset-uuid-list3']
                        type: str
                        description: Tags and asset UUID list 3 to be reported
                    ble_rtls_asset_uuid_list4:
                        aliases: ['ble-rtls-asset-uuid-list4']
                        type: str
                        description: Tags and asset UUID list 4 to be reported
                    ble_rtls_protocol:
                        aliases: ['ble-rtls-protocol']
                        type: str
                        description: Select the protocol to report Measurements, Advertising Data, or Location Data to Cloud Server.
                        choices:
                            - 'WSS'
                    ble_rtls_reporting_interval:
                        aliases: ['ble-rtls-reporting-interval']
                        type: int
                        description: Time between reporting accumulated measurements in seconds
                    ble_rtls_server_fqdn:
                        aliases: ['ble-rtls-server-fqdn']
                        type: str
                        description: FQDN of BLE Real Time Location Service
                    ble_rtls_server_path:
                        aliases: ['ble-rtls-server-path']
                        type: str
                        description: Path of BLE Real Time Location Service
                    ble_rtls_server_port:
                        aliases: ['ble-rtls-server-port']
                        type: int
                        description: Port of BLE Real Time Location Service
                    ble_rtls_server_token:
                        aliases: ['ble-rtls-server-token']
                        type: str
                        description: Access Token of BLE Real Time Location Service
            platform:
                type: dict
                description: Platform.
                suboptions:
                    ddscan:
                        type: str
                        description: Enable/disable use of one radio for dedicated dual-band scanning to detect RF characterization and wireless threat...
                        choices:
                            - 'disable'
                            - 'enable'
                    mode:
                        type: str
                        description: Configure operation mode of 5G radios
                        choices:
                            - 'dual-5G'
                            - 'single-5G'
                    type:
                        type: str
                        description: WTP, FortiAP or AP platform type.
                        choices:
                            - '30B-50B'
                            - '60B'
                            - '80CM-81CM'
                            - '220A'
                            - '220B'
                            - '210B'
                            - '60C'
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
                            - 'S321C'
                            - 'S323C'
                            - 'FWF'
                            - 'S311C'
                            - 'S313C'
                            - 'AP-11N'
                            - 'S322C'
                            - 'S321CR'
                            - 'S322CR'
                            - 'S323CR'
                            - 'S421E'
                            - 'S422E'
                            - 'S423E'
                            - '421E'
                            - '423E'
                            - 'C221E'
                            - 'C226E'
                            - 'C23JD'
                            - 'C24JE'
                            - 'C21D'
                            - 'U421E'
                            - 'U423E'
                            - '221E'
                            - '222E'
                            - '223E'
                            - 'S221E'
                            - 'S223E'
                            - 'U221EV'
                            - 'U223EV'
                            - 'U321EV'
                            - 'U323EV'
                            - '224E'
                            - 'U422EV'
                            - 'U24JEV'
                            - '321E'
                            - 'U431F'
                            - 'U433F'
                            - '231E'
                            - '431F'
                            - '433F'
                            - '231F'
                            - '432F'
                            - '234F'
                            - '23JF'
                            - 'U231F'
                            - '831F'
                            - 'U234F'
                            - 'U432F'
                            - '431FL'
                            - '432FR'
                            - '433FL'
                            - '231FL'
                            - '231G'
                            - '233G'
                            - '431G'
                            - '433G'
                            - 'U231G'
                            - 'U441G'
                            - '234G'
                            - '432G'
                            - '441K'
                            - '443K'
                            - '241K'
                            - '243K'
                            - '231K'
                            - '23JK'
                    _local_platform_str:
                        type: str
                        description: Local platform str.
            radio_1:
                aliases: ['radio-1']
                type: dict
                description: Radio 1.
                suboptions:
                    airtime_fairness:
                        aliases: ['airtime-fairness']
                        type: str
                        description: Enable/disable airtime fairness
                        choices:
                            - 'disable'
                            - 'enable'
                    amsdu:
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_addr:
                        aliases: ['ap-sniffer-addr']
                        type: str
                        description: MAC address to monitor.
                    ap_sniffer_bufsize:
                        aliases: ['ap-sniffer-bufsize']
                        type: int
                        description: Sniffer buffer size
                    ap_sniffer_chan:
                        aliases: ['ap-sniffer-chan']
                        type: int
                        description: Channel on which to operate the sniffer
                    ap_sniffer_ctl:
                        aliases: ['ap-sniffer-ctl']
                        type: str
                        description: Enable/disable sniffer on WiFi control frame
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_data:
                        aliases: ['ap-sniffer-data']
                        type: str
                        description: Enable/disable sniffer on WiFi data frame
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_mgmt_beacon:
                        aliases: ['ap-sniffer-mgmt-beacon']
                        type: str
                        description: Enable/disable sniffer on WiFi management Beacon frames
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_mgmt_other:
                        aliases: ['ap-sniffer-mgmt-other']
                        type: str
                        description: Enable/disable sniffer on WiFi management other frames
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_mgmt_probe:
                        aliases: ['ap-sniffer-mgmt-probe']
                        type: str
                        description: Enable/disable sniffer on WiFi management probe frames
                        choices:
                            - 'disable'
                            - 'enable'
                    auto_power_high:
                        aliases: ['auto-power-high']
                        type: int
                        description: The upper bound of automatic transmit power adjustment in dBm
                    auto_power_level:
                        aliases: ['auto-power-level']
                        type: str
                        description: Enable/disable automatic power-level adjustment to prevent co-channel interference
                        choices:
                            - 'disable'
                            - 'enable'
                    auto_power_low:
                        aliases: ['auto-power-low']
                        type: int
                        description: The lower bound of automatic transmit power adjustment in dBm
                    auto_power_target:
                        aliases: ['auto-power-target']
                        type: str
                        description: The target of automatic transmit power adjustment in dBm.
                    band:
                        type: str
                        description: WiFi band that Radio 1 operates on.
                        choices:
                            - '802.11b'
                            - '802.11a'
                            - '802.11g'
                            - '802.11n'
                            - '802.11ac'
                            - '802.11n-5G'
                            - '802.11ax-5G'
                            - '802.11ax'
                            - '802.11ac-2G'
                            - '802.11g-only'
                            - '802.11n-only'
                            - '802.11n,g-only'
                            - '802.11ac-only'
                            - '802.11ac,n-only'
                            - '802.11n-5G-only'
                            - '802.11ax-5G-only'
                            - '802.11ax,ac-only'
                            - '802.11ax,ac,n-only'
                            - '802.11ax-only'
                            - '802.11ax,n-only'
                            - '802.11ax,n,g-only'
                            - '802.11ax-6G'
                            - '802.11n-2G'
                            - '802.11ac-5G'
                            - '802.11ax-2G'
                            - '802.11be-2G'
                            - '802.11be-5G'
                            - '802.11be-6G'
                    band_5g_type:
                        aliases: ['band-5g-type']
                        type: str
                        description: WiFi 5G band type.
                        choices:
                            - '5g-full'
                            - '5g-high'
                            - '5g-low'
                    bandwidth_admission_control:
                        aliases: ['bandwidth-admission-control']
                        type: str
                        description: Enable/disable WiFi multimedia
                        choices:
                            - 'disable'
                            - 'enable'
                    bandwidth_capacity:
                        aliases: ['bandwidth-capacity']
                        type: int
                        description: Maximum bandwidth capacity allowed
                    beacon_interval:
                        aliases: ['beacon-interval']
                        type: int
                        description: Beacon interval.
                    bss_color:
                        aliases: ['bss-color']
                        type: int
                        description: BSS color value for this 11ax radio
                    call_admission_control:
                        aliases: ['call-admission-control']
                        type: str
                        description: Enable/disable WiFi multimedia
                        choices:
                            - 'disable'
                            - 'enable'
                    call_capacity:
                        aliases: ['call-capacity']
                        type: int
                        description: Maximum number of Voice over WLAN
                    channel:
                        type: raw
                        description: (list) Selected list of wireless radio channels.
                    channel_bonding:
                        aliases: ['channel-bonding']
                        type: str
                        description: Channel bandwidth
                        choices:
                            - 'disable'
                            - 'enable'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
                            - '160MHz'
                            - '320MHz'
                            - '240MHz'
                    channel_utilization:
                        aliases: ['channel-utilization']
                        type: str
                        description: Enable/disable measuring channel utilization.
                        choices:
                            - 'disable'
                            - 'enable'
                    coexistence:
                        type: str
                        description: Enable/disable allowing both HT20 and HT40 on the same radio
                        choices:
                            - 'disable'
                            - 'enable'
                    darrp:
                        type: str
                        description: Enable/disable Distributed Automatic Radio Resource Provisioning
                        choices:
                            - 'disable'
                            - 'enable'
                    drma:
                        type: str
                        description: Enable/disable dynamic radio mode assignment
                        choices:
                            - 'disable'
                            - 'enable'
                    drma_sensitivity:
                        aliases: ['drma-sensitivity']
                        type: str
                        description: Network Coverage Factor
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    dtim:
                        type: int
                        description: Delivery Traffic Indication Map
                    frag_threshold:
                        aliases: ['frag-threshold']
                        type: int
                        description: Maximum packet size that can be sent without fragmentation
                    max_clients:
                        aliases: ['max-clients']
                        type: int
                        description: Maximum number of stations
                    max_distance:
                        aliases: ['max-distance']
                        type: int
                        description: Maximum expected distance between the AP and clients
                    mode:
                        type: str
                        description: Mode of radio 1.
                        choices:
                            - 'disabled'
                            - 'ap'
                            - 'monitor'
                            - 'sniffer'
                            - 'sam'
                    power_level:
                        aliases: ['power-level']
                        type: int
                        description: Radio power level as a percentage of the maximum transmit power
                    powersave_optimize:
                        aliases: ['powersave-optimize']
                        type: list
                        elements: str
                        description: Enable client power-saving features such as TIM, AC VO, and OBSS etc.
                        choices:
                            - 'tim'
                            - 'ac-vo'
                            - 'no-obss-scan'
                            - 'no-11b-rate'
                            - 'client-rate-follow'
                    protection_mode:
                        aliases: ['protection-mode']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'rtscts'
                            - 'ctsonly'
                            - 'disable'
                    radio_id:
                        aliases: ['radio-id']
                        type: int
                        description: Radio id.
                    rts_threshold:
                        aliases: ['rts-threshold']
                        type: int
                        description: Maximum packet size for RTS transmissions, specifying the maximum size of a data packet before RTS/CTS
                    short_guard_interval:
                        aliases: ['short-guard-interval']
                        type: str
                        description: Use either the short guard interval
                        choices:
                            - 'disable'
                            - 'enable'
                    spectrum_analysis:
                        aliases: ['spectrum-analysis']
                        type: str
                        description: Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'scan-only'
                    transmit_optimize:
                        aliases: ['transmit-optimize']
                        type: list
                        elements: str
                        description: Packet transmission optimization options including power saving, aggregation limiting, retry limiting, etc.
                        choices:
                            - 'disable'
                            - 'power-save'
                            - 'aggr-limit'
                            - 'retry-limit'
                            - 'send-bar'
                    vap_all:
                        aliases: ['vap-all']
                        type: str
                        description: Configure method for assigning SSIDs to this FortiAP
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
                    vap1:
                        type: str
                        description: Virtual Access Point
                    vap2:
                        type: str
                        description: Virtual Access Point
                    vap3:
                        type: str
                        description: Virtual Access Point
                    vap4:
                        type: str
                        description: Virtual Access Point
                    vap5:
                        type: str
                        description: Virtual Access Point
                    vap6:
                        type: str
                        description: Virtual Access Point
                    vap7:
                        type: str
                        description: Virtual Access Point
                    vap8:
                        type: str
                        description: Virtual Access Point
                    vaps:
                        type: raw
                        description: (list or str) Manually selected list of Virtual Access Points
                    wids_profile:
                        aliases: ['wids-profile']
                        type: str
                        description: Wireless Intrusion Detection System
                    zero_wait_dfs:
                        aliases: ['zero-wait-dfs']
                        type: str
                        description: Enable/disable zero wait DFS on radio
                        choices:
                            - 'disable'
                            - 'enable'
                    frequency_handoff:
                        aliases: ['frequency-handoff']
                        type: str
                        description: Enable/disable frequency handoff of clients to other channels
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_handoff:
                        aliases: ['ap-handoff']
                        type: str
                        description: Enable/disable AP handoff of clients to other APs
                        choices:
                            - 'disable'
                            - 'enable'
                    iperf_protocol:
                        aliases: ['iperf-protocol']
                        type: str
                        description: Iperf test protocol
                        choices:
                            - 'udp'
                            - 'tcp'
                    iperf_server_port:
                        aliases: ['iperf-server-port']
                        type: int
                        description: Iperf service port number.
                    power_mode:
                        aliases: ['power-mode']
                        type: str
                        description: Set radio effective isotropic radiated power
                        choices:
                            - 'dBm'
                            - 'percentage'
                    power_value:
                        aliases: ['power-value']
                        type: int
                        description: Radio EIRP power in dBm
                    sam_bssid:
                        aliases: ['sam-bssid']
                        type: str
                        description: BSSID for WiFi network.
                    sam_captive_portal:
                        aliases: ['sam-captive-portal']
                        type: str
                        description: Enable/disable Captive Portal Authentication
                        choices:
                            - 'disable'
                            - 'enable'
                    sam_password:
                        aliases: ['sam-password']
                        type: raw
                        description: (list) Passphrase for WiFi network connection.
                    sam_report_intv:
                        aliases: ['sam-report-intv']
                        type: int
                        description: SAM report interval
                    sam_security_type:
                        aliases: ['sam-security-type']
                        type: str
                        description: Select WiFi network security type
                        choices:
                            - 'open'
                            - 'wpa-personal'
                            - 'wpa-enterprise'
                            - 'owe'
                            - 'wpa3-sae'
                    sam_server:
                        aliases: ['sam-server']
                        type: str
                        description: SAM test server IP address or domain name.
                    sam_ssid:
                        aliases: ['sam-ssid']
                        type: str
                        description: SSID for WiFi network.
                    sam_test:
                        aliases: ['sam-test']
                        type: str
                        description: Select SAM test type
                        choices:
                            - 'ping'
                            - 'iperf'
                    sam_username:
                        aliases: ['sam-username']
                        type: str
                        description: Username for WiFi network connection.
                    arrp_profile:
                        aliases: ['arrp-profile']
                        type: str
                        description: Distributed Automatic Radio Resource Provisioning
                    bss_color_mode:
                        aliases: ['bss-color-mode']
                        type: str
                        description: BSS color mode for this 11ax radio
                        choices:
                            - 'auto'
                            - 'static'
                    sam_cwp_failure_string:
                        aliases: ['sam-cwp-failure-string']
                        type: str
                        description: Failure identification on the page after an incorrect login.
                    sam_cwp_match_string:
                        aliases: ['sam-cwp-match-string']
                        type: str
                        description: Identification string from the captive portal login form.
                    sam_cwp_password:
                        aliases: ['sam-cwp-password']
                        type: raw
                        description: (list) Password for captive portal authentication.
                    sam_cwp_success_string:
                        aliases: ['sam-cwp-success-string']
                        type: str
                        description: Success identification on the page after a successful login.
                    sam_cwp_test_url:
                        aliases: ['sam-cwp-test-url']
                        type: str
                        description: Website the client is trying to access.
                    sam_cwp_username:
                        aliases: ['sam-cwp-username']
                        type: str
                        description: Username for captive portal authentication.
                    sam_server_fqdn:
                        aliases: ['sam-server-fqdn']
                        type: str
                        description: SAM test server domain name.
                    sam_server_ip:
                        aliases: ['sam-server-ip']
                        type: str
                        description: SAM test server IP address.
                    sam_server_type:
                        aliases: ['sam-server-type']
                        type: str
                        description: Select SAM server type
                        choices:
                            - 'ip'
                            - 'fqdn'
                    d80211d:
                        aliases: ['80211d']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    optional_antenna:
                        aliases: ['optional-antenna']
                        type: str
                        description: Optional antenna used on FAP
                        choices:
                            - 'none'
                            - 'FANT-04ABGN-0606-O-N'
                            - 'FANT-04ABGN-1414-P-N'
                            - 'FANT-04ABGN-8065-P-N'
                            - 'FANT-04ABGN-0606-O-R'
                            - 'FANT-04ABGN-0606-P-R'
                            - 'FANT-10ACAX-1213-D-N'
                            - 'FANT-08ABGN-1213-D-R'
                            - 'custom'
                    mimo_mode:
                        aliases: ['mimo-mode']
                        type: str
                        description: Configure radio MIMO mode
                        choices:
                            - 'default'
                            - '1x1'
                            - '2x2'
                            - '3x3'
                            - '4x4'
                            - '8x8'
                    optional_antenna_gain:
                        aliases: ['optional-antenna-gain']
                        type: str
                        description: Optional antenna gain in dBi
                    sam_ca_certificate:
                        aliases: ['sam-ca-certificate']
                        type: str
                        description: CA certificate for WPA2/WPA3-ENTERPRISE.
                    sam_client_certificate:
                        aliases: ['sam-client-certificate']
                        type: str
                        description: Client certificate for WPA2/WPA3-ENTERPRISE.
                    sam_eap_method:
                        aliases: ['sam-eap-method']
                        type: str
                        description: Select WPA2/WPA3-ENTERPRISE EAP Method
                        choices:
                            - 'tls'
                            - 'peap'
                            - 'both'
                    sam_private_key:
                        aliases: ['sam-private-key']
                        type: str
                        description: Private key for WPA2/WPA3-ENTERPRISE.
                    sam_private_key_password:
                        aliases: ['sam-private-key-password']
                        type: raw
                        description: (list) Password for private key file for WPA2/WPA3-ENTERPRISE.
                    channel_bonding_ext:
                        aliases: ['channel-bonding-ext']
                        type: str
                        description: Channel bandwidth extension
                        choices:
                            - '320MHz-1'
                            - '320MHz-2'
                    d80211mc:
                        aliases: ['80211mc']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_chan_width:
                        aliases: ['ap-sniffer-chan-width']
                        type: str
                        description: Channel bandwidth for sniffer.
                        choices:
                            - '320MHz'
                            - '240MHz'
                            - '160MHz'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
            radio_2:
                aliases: ['radio-2']
                type: dict
                description: Radio 2.
                suboptions:
                    airtime_fairness:
                        aliases: ['airtime-fairness']
                        type: str
                        description: Enable/disable airtime fairness
                        choices:
                            - 'disable'
                            - 'enable'
                    amsdu:
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_addr:
                        aliases: ['ap-sniffer-addr']
                        type: str
                        description: MAC address to monitor.
                    ap_sniffer_bufsize:
                        aliases: ['ap-sniffer-bufsize']
                        type: int
                        description: Sniffer buffer size
                    ap_sniffer_chan:
                        aliases: ['ap-sniffer-chan']
                        type: int
                        description: Channel on which to operate the sniffer
                    ap_sniffer_ctl:
                        aliases: ['ap-sniffer-ctl']
                        type: str
                        description: Enable/disable sniffer on WiFi control frame
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_data:
                        aliases: ['ap-sniffer-data']
                        type: str
                        description: Enable/disable sniffer on WiFi data frame
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_mgmt_beacon:
                        aliases: ['ap-sniffer-mgmt-beacon']
                        type: str
                        description: Enable/disable sniffer on WiFi management Beacon frames
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_mgmt_other:
                        aliases: ['ap-sniffer-mgmt-other']
                        type: str
                        description: Enable/disable sniffer on WiFi management other frames
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_mgmt_probe:
                        aliases: ['ap-sniffer-mgmt-probe']
                        type: str
                        description: Enable/disable sniffer on WiFi management probe frames
                        choices:
                            - 'disable'
                            - 'enable'
                    auto_power_high:
                        aliases: ['auto-power-high']
                        type: int
                        description: The upper bound of automatic transmit power adjustment in dBm
                    auto_power_level:
                        aliases: ['auto-power-level']
                        type: str
                        description: Enable/disable automatic power-level adjustment to prevent co-channel interference
                        choices:
                            - 'disable'
                            - 'enable'
                    auto_power_low:
                        aliases: ['auto-power-low']
                        type: int
                        description: The lower bound of automatic transmit power adjustment in dBm
                    auto_power_target:
                        aliases: ['auto-power-target']
                        type: str
                        description: The target of automatic transmit power adjustment in dBm.
                    band:
                        type: str
                        description: WiFi band that Radio 2 operates on.
                        choices:
                            - '802.11b'
                            - '802.11a'
                            - '802.11g'
                            - '802.11n'
                            - '802.11ac'
                            - '802.11n-5G'
                            - '802.11ax-5G'
                            - '802.11ax'
                            - '802.11ac-2G'
                            - '802.11g-only'
                            - '802.11n-only'
                            - '802.11n,g-only'
                            - '802.11ac-only'
                            - '802.11ac,n-only'
                            - '802.11n-5G-only'
                            - '802.11ax-5G-only'
                            - '802.11ax,ac-only'
                            - '802.11ax,ac,n-only'
                            - '802.11ax-only'
                            - '802.11ax,n-only'
                            - '802.11ax,n,g-only'
                            - '802.11ax-6G'
                            - '802.11n-2G'
                            - '802.11ac-5G'
                            - '802.11ax-2G'
                            - '802.11be-2G'
                            - '802.11be-5G'
                            - '802.11be-6G'
                    band_5g_type:
                        aliases: ['band-5g-type']
                        type: str
                        description: WiFi 5G band type.
                        choices:
                            - '5g-full'
                            - '5g-high'
                            - '5g-low'
                    bandwidth_admission_control:
                        aliases: ['bandwidth-admission-control']
                        type: str
                        description: Enable/disable WiFi multimedia
                        choices:
                            - 'disable'
                            - 'enable'
                    bandwidth_capacity:
                        aliases: ['bandwidth-capacity']
                        type: int
                        description: Maximum bandwidth capacity allowed
                    beacon_interval:
                        aliases: ['beacon-interval']
                        type: int
                        description: Beacon interval.
                    bss_color:
                        aliases: ['bss-color']
                        type: int
                        description: BSS color value for this 11ax radio
                    call_admission_control:
                        aliases: ['call-admission-control']
                        type: str
                        description: Enable/disable WiFi multimedia
                        choices:
                            - 'disable'
                            - 'enable'
                    call_capacity:
                        aliases: ['call-capacity']
                        type: int
                        description: Maximum number of Voice over WLAN
                    channel:
                        type: raw
                        description: (list) Selected list of wireless radio channels.
                    channel_bonding:
                        aliases: ['channel-bonding']
                        type: str
                        description: Channel bandwidth
                        choices:
                            - 'disable'
                            - 'enable'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
                            - '160MHz'
                            - '320MHz'
                            - '240MHz'
                    channel_utilization:
                        aliases: ['channel-utilization']
                        type: str
                        description: Enable/disable measuring channel utilization.
                        choices:
                            - 'disable'
                            - 'enable'
                    coexistence:
                        type: str
                        description: Enable/disable allowing both HT20 and HT40 on the same radio
                        choices:
                            - 'disable'
                            - 'enable'
                    darrp:
                        type: str
                        description: Enable/disable Distributed Automatic Radio Resource Provisioning
                        choices:
                            - 'disable'
                            - 'enable'
                    drma:
                        type: str
                        description: Enable/disable dynamic radio mode assignment
                        choices:
                            - 'disable'
                            - 'enable'
                    drma_sensitivity:
                        aliases: ['drma-sensitivity']
                        type: str
                        description: Network Coverage Factor
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    dtim:
                        type: int
                        description: Delivery Traffic Indication Map
                    frag_threshold:
                        aliases: ['frag-threshold']
                        type: int
                        description: Maximum packet size that can be sent without fragmentation
                    max_clients:
                        aliases: ['max-clients']
                        type: int
                        description: Maximum number of stations
                    max_distance:
                        aliases: ['max-distance']
                        type: int
                        description: Maximum expected distance between the AP and clients
                    mode:
                        type: str
                        description: Mode of radio 2.
                        choices:
                            - 'disabled'
                            - 'ap'
                            - 'monitor'
                            - 'sniffer'
                            - 'sam'
                    power_level:
                        aliases: ['power-level']
                        type: int
                        description: Radio power level as a percentage of the maximum transmit power
                    powersave_optimize:
                        aliases: ['powersave-optimize']
                        type: list
                        elements: str
                        description: Enable client power-saving features such as TIM, AC VO, and OBSS etc.
                        choices:
                            - 'tim'
                            - 'ac-vo'
                            - 'no-obss-scan'
                            - 'no-11b-rate'
                            - 'client-rate-follow'
                    protection_mode:
                        aliases: ['protection-mode']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'rtscts'
                            - 'ctsonly'
                            - 'disable'
                    radio_id:
                        aliases: ['radio-id']
                        type: int
                        description: Radio id.
                    rts_threshold:
                        aliases: ['rts-threshold']
                        type: int
                        description: Maximum packet size for RTS transmissions, specifying the maximum size of a data packet before RTS/CTS
                    short_guard_interval:
                        aliases: ['short-guard-interval']
                        type: str
                        description: Use either the short guard interval
                        choices:
                            - 'disable'
                            - 'enable'
                    spectrum_analysis:
                        aliases: ['spectrum-analysis']
                        type: str
                        description: Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'scan-only'
                    transmit_optimize:
                        aliases: ['transmit-optimize']
                        type: list
                        elements: str
                        description: Packet transmission optimization options including power saving, aggregation limiting, retry limiting, etc.
                        choices:
                            - 'disable'
                            - 'power-save'
                            - 'aggr-limit'
                            - 'retry-limit'
                            - 'send-bar'
                    vap_all:
                        aliases: ['vap-all']
                        type: str
                        description: Configure method for assigning SSIDs to this FortiAP
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
                    vap1:
                        type: str
                        description: Virtual Access Point
                    vap2:
                        type: str
                        description: Virtual Access Point
                    vap3:
                        type: str
                        description: Virtual Access Point
                    vap4:
                        type: str
                        description: Virtual Access Point
                    vap5:
                        type: str
                        description: Virtual Access Point
                    vap6:
                        type: str
                        description: Virtual Access Point
                    vap7:
                        type: str
                        description: Virtual Access Point
                    vap8:
                        type: str
                        description: Virtual Access Point
                    vaps:
                        type: raw
                        description: (list or str) Manually selected list of Virtual Access Points
                    wids_profile:
                        aliases: ['wids-profile']
                        type: str
                        description: Wireless Intrusion Detection System
                    zero_wait_dfs:
                        aliases: ['zero-wait-dfs']
                        type: str
                        description: Enable/disable zero wait DFS on radio
                        choices:
                            - 'disable'
                            - 'enable'
                    frequency_handoff:
                        aliases: ['frequency-handoff']
                        type: str
                        description: Enable/disable frequency handoff of clients to other channels
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_handoff:
                        aliases: ['ap-handoff']
                        type: str
                        description: Enable/disable AP handoff of clients to other APs
                        choices:
                            - 'disable'
                            - 'enable'
                    iperf_protocol:
                        aliases: ['iperf-protocol']
                        type: str
                        description: Iperf test protocol
                        choices:
                            - 'udp'
                            - 'tcp'
                    iperf_server_port:
                        aliases: ['iperf-server-port']
                        type: int
                        description: Iperf service port number.
                    power_mode:
                        aliases: ['power-mode']
                        type: str
                        description: Set radio effective isotropic radiated power
                        choices:
                            - 'dBm'
                            - 'percentage'
                    power_value:
                        aliases: ['power-value']
                        type: int
                        description: Radio EIRP power in dBm
                    sam_bssid:
                        aliases: ['sam-bssid']
                        type: str
                        description: BSSID for WiFi network.
                    sam_captive_portal:
                        aliases: ['sam-captive-portal']
                        type: str
                        description: Enable/disable Captive Portal Authentication
                        choices:
                            - 'disable'
                            - 'enable'
                    sam_password:
                        aliases: ['sam-password']
                        type: raw
                        description: (list) Passphrase for WiFi network connection.
                    sam_report_intv:
                        aliases: ['sam-report-intv']
                        type: int
                        description: SAM report interval
                    sam_security_type:
                        aliases: ['sam-security-type']
                        type: str
                        description: Select WiFi network security type
                        choices:
                            - 'open'
                            - 'wpa-personal'
                            - 'wpa-enterprise'
                            - 'owe'
                            - 'wpa3-sae'
                    sam_server:
                        aliases: ['sam-server']
                        type: str
                        description: SAM test server IP address or domain name.
                    sam_ssid:
                        aliases: ['sam-ssid']
                        type: str
                        description: SSID for WiFi network.
                    sam_test:
                        aliases: ['sam-test']
                        type: str
                        description: Select SAM test type
                        choices:
                            - 'ping'
                            - 'iperf'
                    sam_username:
                        aliases: ['sam-username']
                        type: str
                        description: Username for WiFi network connection.
                    arrp_profile:
                        aliases: ['arrp-profile']
                        type: str
                        description: Distributed Automatic Radio Resource Provisioning
                    bss_color_mode:
                        aliases: ['bss-color-mode']
                        type: str
                        description: BSS color mode for this 11ax radio
                        choices:
                            - 'auto'
                            - 'static'
                    sam_cwp_failure_string:
                        aliases: ['sam-cwp-failure-string']
                        type: str
                        description: Failure identification on the page after an incorrect login.
                    sam_cwp_match_string:
                        aliases: ['sam-cwp-match-string']
                        type: str
                        description: Identification string from the captive portal login form.
                    sam_cwp_password:
                        aliases: ['sam-cwp-password']
                        type: raw
                        description: (list) Password for captive portal authentication.
                    sam_cwp_success_string:
                        aliases: ['sam-cwp-success-string']
                        type: str
                        description: Success identification on the page after a successful login.
                    sam_cwp_test_url:
                        aliases: ['sam-cwp-test-url']
                        type: str
                        description: Website the client is trying to access.
                    sam_cwp_username:
                        aliases: ['sam-cwp-username']
                        type: str
                        description: Username for captive portal authentication.
                    sam_server_fqdn:
                        aliases: ['sam-server-fqdn']
                        type: str
                        description: SAM test server domain name.
                    sam_server_ip:
                        aliases: ['sam-server-ip']
                        type: str
                        description: SAM test server IP address.
                    sam_server_type:
                        aliases: ['sam-server-type']
                        type: str
                        description: Select SAM server type
                        choices:
                            - 'ip'
                            - 'fqdn'
                    d80211d:
                        aliases: ['80211d']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    optional_antenna:
                        aliases: ['optional-antenna']
                        type: str
                        description: Optional antenna used on FAP
                        choices:
                            - 'none'
                            - 'FANT-04ABGN-0606-O-N'
                            - 'FANT-04ABGN-1414-P-N'
                            - 'FANT-04ABGN-8065-P-N'
                            - 'FANT-04ABGN-0606-O-R'
                            - 'FANT-04ABGN-0606-P-R'
                            - 'FANT-10ACAX-1213-D-N'
                            - 'FANT-08ABGN-1213-D-R'
                            - 'custom'
                    mimo_mode:
                        aliases: ['mimo-mode']
                        type: str
                        description: Configure radio MIMO mode
                        choices:
                            - 'default'
                            - '1x1'
                            - '2x2'
                            - '3x3'
                            - '4x4'
                            - '8x8'
                    optional_antenna_gain:
                        aliases: ['optional-antenna-gain']
                        type: str
                        description: Optional antenna gain in dBi
                    sam_ca_certificate:
                        aliases: ['sam-ca-certificate']
                        type: str
                        description: CA certificate for WPA2/WPA3-ENTERPRISE.
                    sam_client_certificate:
                        aliases: ['sam-client-certificate']
                        type: str
                        description: Client certificate for WPA2/WPA3-ENTERPRISE.
                    sam_eap_method:
                        aliases: ['sam-eap-method']
                        type: str
                        description: Select WPA2/WPA3-ENTERPRISE EAP Method
                        choices:
                            - 'tls'
                            - 'peap'
                            - 'both'
                    sam_private_key:
                        aliases: ['sam-private-key']
                        type: str
                        description: Private key for WPA2/WPA3-ENTERPRISE.
                    sam_private_key_password:
                        aliases: ['sam-private-key-password']
                        type: raw
                        description: (list) Password for private key file for WPA2/WPA3-ENTERPRISE.
                    channel_bonding_ext:
                        aliases: ['channel-bonding-ext']
                        type: str
                        description: Channel bandwidth extension
                        choices:
                            - '320MHz-1'
                            - '320MHz-2'
                    d80211mc:
                        aliases: ['80211mc']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_chan_width:
                        aliases: ['ap-sniffer-chan-width']
                        type: str
                        description: Channel bandwidth for sniffer.
                        choices:
                            - '320MHz'
                            - '240MHz'
                            - '160MHz'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
            radio_3:
                aliases: ['radio-3']
                type: dict
                description: Radio 3.
                suboptions:
                    airtime_fairness:
                        aliases: ['airtime-fairness']
                        type: str
                        description: Enable/disable airtime fairness
                        choices:
                            - 'disable'
                            - 'enable'
                    amsdu:
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_addr:
                        aliases: ['ap-sniffer-addr']
                        type: str
                        description: MAC address to monitor.
                    ap_sniffer_bufsize:
                        aliases: ['ap-sniffer-bufsize']
                        type: int
                        description: Sniffer buffer size
                    ap_sniffer_chan:
                        aliases: ['ap-sniffer-chan']
                        type: int
                        description: Channel on which to operate the sniffer
                    ap_sniffer_ctl:
                        aliases: ['ap-sniffer-ctl']
                        type: str
                        description: Enable/disable sniffer on WiFi control frame
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_data:
                        aliases: ['ap-sniffer-data']
                        type: str
                        description: Enable/disable sniffer on WiFi data frame
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_mgmt_beacon:
                        aliases: ['ap-sniffer-mgmt-beacon']
                        type: str
                        description: Enable/disable sniffer on WiFi management Beacon frames
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_mgmt_other:
                        aliases: ['ap-sniffer-mgmt-other']
                        type: str
                        description: Enable/disable sniffer on WiFi management other frames
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_mgmt_probe:
                        aliases: ['ap-sniffer-mgmt-probe']
                        type: str
                        description: Enable/disable sniffer on WiFi management probe frames
                        choices:
                            - 'disable'
                            - 'enable'
                    auto_power_high:
                        aliases: ['auto-power-high']
                        type: int
                        description: The upper bound of automatic transmit power adjustment in dBm
                    auto_power_level:
                        aliases: ['auto-power-level']
                        type: str
                        description: Enable/disable automatic power-level adjustment to prevent co-channel interference
                        choices:
                            - 'disable'
                            - 'enable'
                    auto_power_low:
                        aliases: ['auto-power-low']
                        type: int
                        description: The lower bound of automatic transmit power adjustment in dBm
                    auto_power_target:
                        aliases: ['auto-power-target']
                        type: str
                        description: The target of automatic transmit power adjustment in dBm.
                    band:
                        type: str
                        description: WiFi band that Radio 3 operates on.
                        choices:
                            - '802.11b'
                            - '802.11a'
                            - '802.11g'
                            - '802.11n'
                            - '802.11ac'
                            - '802.11n-5G'
                            - '802.11ax-5G'
                            - '802.11ax'
                            - '802.11ac-2G'
                            - '802.11g-only'
                            - '802.11n-only'
                            - '802.11n,g-only'
                            - '802.11ac-only'
                            - '802.11ac,n-only'
                            - '802.11n-5G-only'
                            - '802.11ax-5G-only'
                            - '802.11ax,ac-only'
                            - '802.11ax,ac,n-only'
                            - '802.11ax-only'
                            - '802.11ax,n-only'
                            - '802.11ax,n,g-only'
                            - '802.11ax-6G'
                            - '802.11n-2G'
                            - '802.11ac-5G'
                            - '802.11ax-2G'
                            - '802.11be-2G'
                            - '802.11be-5G'
                            - '802.11be-6G'
                    band_5g_type:
                        aliases: ['band-5g-type']
                        type: str
                        description: WiFi 5G band type.
                        choices:
                            - '5g-full'
                            - '5g-high'
                            - '5g-low'
                    bandwidth_admission_control:
                        aliases: ['bandwidth-admission-control']
                        type: str
                        description: Enable/disable WiFi multimedia
                        choices:
                            - 'disable'
                            - 'enable'
                    bandwidth_capacity:
                        aliases: ['bandwidth-capacity']
                        type: int
                        description: Maximum bandwidth capacity allowed
                    beacon_interval:
                        aliases: ['beacon-interval']
                        type: int
                        description: Beacon interval.
                    bss_color:
                        aliases: ['bss-color']
                        type: int
                        description: BSS color value for this 11ax radio
                    call_admission_control:
                        aliases: ['call-admission-control']
                        type: str
                        description: Enable/disable WiFi multimedia
                        choices:
                            - 'disable'
                            - 'enable'
                    call_capacity:
                        aliases: ['call-capacity']
                        type: int
                        description: Maximum number of Voice over WLAN
                    channel:
                        type: raw
                        description: (list) Selected list of wireless radio channels.
                    channel_bonding:
                        aliases: ['channel-bonding']
                        type: str
                        description: Channel bandwidth
                        choices:
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
                            - '160MHz'
                            - '320MHz'
                            - '240MHz'
                    channel_utilization:
                        aliases: ['channel-utilization']
                        type: str
                        description: Enable/disable measuring channel utilization.
                        choices:
                            - 'disable'
                            - 'enable'
                    coexistence:
                        type: str
                        description: Enable/disable allowing both HT20 and HT40 on the same radio
                        choices:
                            - 'disable'
                            - 'enable'
                    darrp:
                        type: str
                        description: Enable/disable Distributed Automatic Radio Resource Provisioning
                        choices:
                            - 'disable'
                            - 'enable'
                    drma:
                        type: str
                        description: Enable/disable dynamic radio mode assignment
                        choices:
                            - 'disable'
                            - 'enable'
                    drma_sensitivity:
                        aliases: ['drma-sensitivity']
                        type: str
                        description: Network Coverage Factor
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    dtim:
                        type: int
                        description: Delivery Traffic Indication Map
                    frag_threshold:
                        aliases: ['frag-threshold']
                        type: int
                        description: Maximum packet size that can be sent without fragmentation
                    max_clients:
                        aliases: ['max-clients']
                        type: int
                        description: Maximum number of stations
                    max_distance:
                        aliases: ['max-distance']
                        type: int
                        description: Maximum expected distance between the AP and clients
                    mode:
                        type: str
                        description: Mode of radio 3.
                        choices:
                            - 'disabled'
                            - 'ap'
                            - 'monitor'
                            - 'sniffer'
                            - 'sam'
                    power_level:
                        aliases: ['power-level']
                        type: int
                        description: Radio power level as a percentage of the maximum transmit power
                    powersave_optimize:
                        aliases: ['powersave-optimize']
                        type: list
                        elements: str
                        description: Enable client power-saving features such as TIM, AC VO, and OBSS etc.
                        choices:
                            - 'tim'
                            - 'ac-vo'
                            - 'no-obss-scan'
                            - 'no-11b-rate'
                            - 'client-rate-follow'
                    protection_mode:
                        aliases: ['protection-mode']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'rtscts'
                            - 'ctsonly'
                            - 'disable'
                    radio_id:
                        aliases: ['radio-id']
                        type: int
                        description: Radio id.
                    rts_threshold:
                        aliases: ['rts-threshold']
                        type: int
                        description: Maximum packet size for RTS transmissions, specifying the maximum size of a data packet before RTS/CTS
                    short_guard_interval:
                        aliases: ['short-guard-interval']
                        type: str
                        description: Use either the short guard interval
                        choices:
                            - 'disable'
                            - 'enable'
                    spectrum_analysis:
                        aliases: ['spectrum-analysis']
                        type: str
                        description: Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'scan-only'
                    transmit_optimize:
                        aliases: ['transmit-optimize']
                        type: list
                        elements: str
                        description: Packet transmission optimization options including power saving, aggregation limiting, retry limiting, etc.
                        choices:
                            - 'disable'
                            - 'power-save'
                            - 'aggr-limit'
                            - 'retry-limit'
                            - 'send-bar'
                    vap_all:
                        aliases: ['vap-all']
                        type: str
                        description: Configure method for assigning SSIDs to this FortiAP
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
                    vap1:
                        type: str
                        description: Virtual Access Point
                    vap2:
                        type: str
                        description: Virtual Access Point
                    vap3:
                        type: str
                        description: Virtual Access Point
                    vap4:
                        type: str
                        description: Virtual Access Point
                    vap5:
                        type: str
                        description: Virtual Access Point
                    vap6:
                        type: str
                        description: Virtual Access Point
                    vap7:
                        type: str
                        description: Virtual Access Point
                    vap8:
                        type: str
                        description: Virtual Access Point
                    vaps:
                        type: raw
                        description: (list or str) Manually selected list of Virtual Access Points
                    wids_profile:
                        aliases: ['wids-profile']
                        type: str
                        description: Wireless Intrusion Detection System
                    zero_wait_dfs:
                        aliases: ['zero-wait-dfs']
                        type: str
                        description: Enable/disable zero wait DFS on radio
                        choices:
                            - 'disable'
                            - 'enable'
                    frequency_handoff:
                        aliases: ['frequency-handoff']
                        type: str
                        description: Enable/disable frequency handoff of clients to other channels
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_handoff:
                        aliases: ['ap-handoff']
                        type: str
                        description: Enable/disable AP handoff of clients to other APs
                        choices:
                            - 'disable'
                            - 'enable'
                    iperf_protocol:
                        aliases: ['iperf-protocol']
                        type: str
                        description: Iperf test protocol
                        choices:
                            - 'udp'
                            - 'tcp'
                    iperf_server_port:
                        aliases: ['iperf-server-port']
                        type: int
                        description: Iperf service port number.
                    power_mode:
                        aliases: ['power-mode']
                        type: str
                        description: Set radio effective isotropic radiated power
                        choices:
                            - 'dBm'
                            - 'percentage'
                    power_value:
                        aliases: ['power-value']
                        type: int
                        description: Radio EIRP power in dBm
                    sam_bssid:
                        aliases: ['sam-bssid']
                        type: str
                        description: BSSID for WiFi network.
                    sam_captive_portal:
                        aliases: ['sam-captive-portal']
                        type: str
                        description: Enable/disable Captive Portal Authentication
                        choices:
                            - 'disable'
                            - 'enable'
                    sam_password:
                        aliases: ['sam-password']
                        type: raw
                        description: (list) Passphrase for WiFi network connection.
                    sam_report_intv:
                        aliases: ['sam-report-intv']
                        type: int
                        description: SAM report interval
                    sam_security_type:
                        aliases: ['sam-security-type']
                        type: str
                        description: Select WiFi network security type
                        choices:
                            - 'open'
                            - 'wpa-personal'
                            - 'wpa-enterprise'
                            - 'owe'
                            - 'wpa3-sae'
                    sam_server:
                        aliases: ['sam-server']
                        type: str
                        description: SAM test server IP address or domain name.
                    sam_ssid:
                        aliases: ['sam-ssid']
                        type: str
                        description: SSID for WiFi network.
                    sam_test:
                        aliases: ['sam-test']
                        type: str
                        description: Select SAM test type
                        choices:
                            - 'ping'
                            - 'iperf'
                    sam_username:
                        aliases: ['sam-username']
                        type: str
                        description: Username for WiFi network connection.
                    arrp_profile:
                        aliases: ['arrp-profile']
                        type: str
                        description: Distributed Automatic Radio Resource Provisioning
                    bss_color_mode:
                        aliases: ['bss-color-mode']
                        type: str
                        description: BSS color mode for this 11ax radio
                        choices:
                            - 'auto'
                            - 'static'
                    sam_cwp_failure_string:
                        aliases: ['sam-cwp-failure-string']
                        type: str
                        description: Failure identification on the page after an incorrect login.
                    sam_cwp_match_string:
                        aliases: ['sam-cwp-match-string']
                        type: str
                        description: Identification string from the captive portal login form.
                    sam_cwp_password:
                        aliases: ['sam-cwp-password']
                        type: raw
                        description: (list) Password for captive portal authentication.
                    sam_cwp_success_string:
                        aliases: ['sam-cwp-success-string']
                        type: str
                        description: Success identification on the page after a successful login.
                    sam_cwp_test_url:
                        aliases: ['sam-cwp-test-url']
                        type: str
                        description: Website the client is trying to access.
                    sam_cwp_username:
                        aliases: ['sam-cwp-username']
                        type: str
                        description: Username for captive portal authentication.
                    sam_server_fqdn:
                        aliases: ['sam-server-fqdn']
                        type: str
                        description: SAM test server domain name.
                    sam_server_ip:
                        aliases: ['sam-server-ip']
                        type: str
                        description: SAM test server IP address.
                    sam_server_type:
                        aliases: ['sam-server-type']
                        type: str
                        description: Select SAM server type
                        choices:
                            - 'ip'
                            - 'fqdn'
                    d80211d:
                        aliases: ['80211d']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    optional_antenna:
                        aliases: ['optional-antenna']
                        type: str
                        description: Optional antenna used on FAP
                        choices:
                            - 'none'
                            - 'FANT-04ABGN-0606-O-N'
                            - 'FANT-04ABGN-1414-P-N'
                            - 'FANT-04ABGN-8065-P-N'
                            - 'FANT-04ABGN-0606-O-R'
                            - 'FANT-04ABGN-0606-P-R'
                            - 'FANT-10ACAX-1213-D-N'
                            - 'FANT-08ABGN-1213-D-R'
                            - 'custom'
                    mimo_mode:
                        aliases: ['mimo-mode']
                        type: str
                        description: Configure radio MIMO mode
                        choices:
                            - 'default'
                            - '1x1'
                            - '2x2'
                            - '3x3'
                            - '4x4'
                            - '8x8'
                    optional_antenna_gain:
                        aliases: ['optional-antenna-gain']
                        type: str
                        description: Optional antenna gain in dBi
                    sam_ca_certificate:
                        aliases: ['sam-ca-certificate']
                        type: str
                        description: CA certificate for WPA2/WPA3-ENTERPRISE.
                    sam_client_certificate:
                        aliases: ['sam-client-certificate']
                        type: str
                        description: Client certificate for WPA2/WPA3-ENTERPRISE.
                    sam_eap_method:
                        aliases: ['sam-eap-method']
                        type: str
                        description: Select WPA2/WPA3-ENTERPRISE EAP Method
                        choices:
                            - 'tls'
                            - 'peap'
                            - 'both'
                    sam_private_key:
                        aliases: ['sam-private-key']
                        type: str
                        description: Private key for WPA2/WPA3-ENTERPRISE.
                    sam_private_key_password:
                        aliases: ['sam-private-key-password']
                        type: raw
                        description: (list) Password for private key file for WPA2/WPA3-ENTERPRISE.
                    channel_bonding_ext:
                        aliases: ['channel-bonding-ext']
                        type: str
                        description: Channel bandwidth extension
                        choices:
                            - '320MHz-1'
                            - '320MHz-2'
                    d80211mc:
                        aliases: ['80211mc']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_chan_width:
                        aliases: ['ap-sniffer-chan-width']
                        type: str
                        description: Channel bandwidth for sniffer.
                        choices:
                            - '320MHz'
                            - '240MHz'
                            - '160MHz'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
            radio_4:
                aliases: ['radio-4']
                type: dict
                description: Radio 4.
                suboptions:
                    airtime_fairness:
                        aliases: ['airtime-fairness']
                        type: str
                        description: Enable/disable airtime fairness
                        choices:
                            - 'disable'
                            - 'enable'
                    amsdu:
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_addr:
                        aliases: ['ap-sniffer-addr']
                        type: str
                        description: MAC address to monitor.
                    ap_sniffer_bufsize:
                        aliases: ['ap-sniffer-bufsize']
                        type: int
                        description: Sniffer buffer size
                    ap_sniffer_chan:
                        aliases: ['ap-sniffer-chan']
                        type: int
                        description: Channel on which to operate the sniffer
                    ap_sniffer_ctl:
                        aliases: ['ap-sniffer-ctl']
                        type: str
                        description: Enable/disable sniffer on WiFi control frame
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_data:
                        aliases: ['ap-sniffer-data']
                        type: str
                        description: Enable/disable sniffer on WiFi data frame
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_mgmt_beacon:
                        aliases: ['ap-sniffer-mgmt-beacon']
                        type: str
                        description: Enable/disable sniffer on WiFi management Beacon frames
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_mgmt_other:
                        aliases: ['ap-sniffer-mgmt-other']
                        type: str
                        description: Enable/disable sniffer on WiFi management other frames
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_mgmt_probe:
                        aliases: ['ap-sniffer-mgmt-probe']
                        type: str
                        description: Enable/disable sniffer on WiFi management probe frames
                        choices:
                            - 'disable'
                            - 'enable'
                    auto_power_high:
                        aliases: ['auto-power-high']
                        type: int
                        description: The upper bound of automatic transmit power adjustment in dBm
                    auto_power_level:
                        aliases: ['auto-power-level']
                        type: str
                        description: Enable/disable automatic power-level adjustment to prevent co-channel interference
                        choices:
                            - 'disable'
                            - 'enable'
                    auto_power_low:
                        aliases: ['auto-power-low']
                        type: int
                        description: The lower bound of automatic transmit power adjustment in dBm
                    auto_power_target:
                        aliases: ['auto-power-target']
                        type: str
                        description: The target of automatic transmit power adjustment in dBm.
                    band:
                        type: str
                        description: WiFi band that Radio 3 operates on.
                        choices:
                            - '802.11b'
                            - '802.11a'
                            - '802.11g'
                            - '802.11n'
                            - '802.11ac'
                            - '802.11n-5G'
                            - '802.11ax-5G'
                            - '802.11ax'
                            - '802.11ac-2G'
                            - '802.11g-only'
                            - '802.11n-only'
                            - '802.11n,g-only'
                            - '802.11ac-only'
                            - '802.11ac,n-only'
                            - '802.11n-5G-only'
                            - '802.11ax-5G-only'
                            - '802.11ax,ac-only'
                            - '802.11ax,ac,n-only'
                            - '802.11ax-only'
                            - '802.11ax,n-only'
                            - '802.11ax,n,g-only'
                            - '802.11ax-6G'
                            - '802.11n-2G'
                            - '802.11ac-5G'
                            - '802.11ax-2G'
                            - '802.11be-2G'
                            - '802.11be-5G'
                            - '802.11be-6G'
                    band_5g_type:
                        aliases: ['band-5g-type']
                        type: str
                        description: WiFi 5G band type.
                        choices:
                            - '5g-full'
                            - '5g-high'
                            - '5g-low'
                    bandwidth_admission_control:
                        aliases: ['bandwidth-admission-control']
                        type: str
                        description: Enable/disable WiFi multimedia
                        choices:
                            - 'disable'
                            - 'enable'
                    bandwidth_capacity:
                        aliases: ['bandwidth-capacity']
                        type: int
                        description: Maximum bandwidth capacity allowed
                    beacon_interval:
                        aliases: ['beacon-interval']
                        type: int
                        description: Beacon interval.
                    bss_color:
                        aliases: ['bss-color']
                        type: int
                        description: BSS color value for this 11ax radio
                    call_admission_control:
                        aliases: ['call-admission-control']
                        type: str
                        description: Enable/disable WiFi multimedia
                        choices:
                            - 'disable'
                            - 'enable'
                    call_capacity:
                        aliases: ['call-capacity']
                        type: int
                        description: Maximum number of Voice over WLAN
                    channel:
                        type: raw
                        description: (list) Selected list of wireless radio channels.
                    channel_bonding:
                        aliases: ['channel-bonding']
                        type: str
                        description: Channel bandwidth
                        choices:
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
                            - '160MHz'
                            - '320MHz'
                            - '240MHz'
                    channel_utilization:
                        aliases: ['channel-utilization']
                        type: str
                        description: Enable/disable measuring channel utilization.
                        choices:
                            - 'disable'
                            - 'enable'
                    coexistence:
                        type: str
                        description: Enable/disable allowing both HT20 and HT40 on the same radio
                        choices:
                            - 'disable'
                            - 'enable'
                    darrp:
                        type: str
                        description: Enable/disable Distributed Automatic Radio Resource Provisioning
                        choices:
                            - 'disable'
                            - 'enable'
                    drma:
                        type: str
                        description: Enable/disable dynamic radio mode assignment
                        choices:
                            - 'disable'
                            - 'enable'
                    drma_sensitivity:
                        aliases: ['drma-sensitivity']
                        type: str
                        description: Network Coverage Factor
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    dtim:
                        type: int
                        description: Delivery Traffic Indication Map
                    frag_threshold:
                        aliases: ['frag-threshold']
                        type: int
                        description: Maximum packet size that can be sent without fragmentation
                    max_clients:
                        aliases: ['max-clients']
                        type: int
                        description: Maximum number of stations
                    max_distance:
                        aliases: ['max-distance']
                        type: int
                        description: Maximum expected distance between the AP and clients
                    mode:
                        type: str
                        description: Mode of radio 3.
                        choices:
                            - 'ap'
                            - 'monitor'
                            - 'sniffer'
                            - 'disabled'
                            - 'sam'
                    power_level:
                        aliases: ['power-level']
                        type: int
                        description: Radio power level as a percentage of the maximum transmit power
                    powersave_optimize:
                        aliases: ['powersave-optimize']
                        type: list
                        elements: str
                        description: Enable client power-saving features such as TIM, AC VO, and OBSS etc.
                        choices:
                            - 'tim'
                            - 'ac-vo'
                            - 'no-obss-scan'
                            - 'no-11b-rate'
                            - 'client-rate-follow'
                    protection_mode:
                        aliases: ['protection-mode']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'rtscts'
                            - 'ctsonly'
                            - 'disable'
                    radio_id:
                        aliases: ['radio-id']
                        type: int
                        description: Radio id.
                    rts_threshold:
                        aliases: ['rts-threshold']
                        type: int
                        description: Maximum packet size for RTS transmissions, specifying the maximum size of a data packet before RTS/CTS
                    short_guard_interval:
                        aliases: ['short-guard-interval']
                        type: str
                        description: Use either the short guard interval
                        choices:
                            - 'disable'
                            - 'enable'
                    spectrum_analysis:
                        aliases: ['spectrum-analysis']
                        type: str
                        description: Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'scan-only'
                    transmit_optimize:
                        aliases: ['transmit-optimize']
                        type: list
                        elements: str
                        description: Packet transmission optimization options including power saving, aggregation limiting, retry limiting, etc.
                        choices:
                            - 'disable'
                            - 'power-save'
                            - 'aggr-limit'
                            - 'retry-limit'
                            - 'send-bar'
                    vap_all:
                        aliases: ['vap-all']
                        type: str
                        description: Configure method for assigning SSIDs to this FortiAP
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'tunnel'
                            - 'bridge'
                            - 'manual'
                    vap1:
                        type: str
                        description: Virtual Access Point
                    vap2:
                        type: str
                        description: Virtual Access Point
                    vap3:
                        type: str
                        description: Virtual Access Point
                    vap4:
                        type: str
                        description: Virtual Access Point
                    vap5:
                        type: str
                        description: Virtual Access Point
                    vap6:
                        type: str
                        description: Virtual Access Point
                    vap7:
                        type: str
                        description: Virtual Access Point
                    vap8:
                        type: str
                        description: Virtual Access Point
                    vaps:
                        type: raw
                        description: (list or str) Manually selected list of Virtual Access Points
                    wids_profile:
                        aliases: ['wids-profile']
                        type: str
                        description: Wireless Intrusion Detection System
                    zero_wait_dfs:
                        aliases: ['zero-wait-dfs']
                        type: str
                        description: Enable/disable zero wait DFS on radio
                        choices:
                            - 'disable'
                            - 'enable'
                    frequency_handoff:
                        aliases: ['frequency-handoff']
                        type: str
                        description: Enable/disable frequency handoff of clients to other channels
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_handoff:
                        aliases: ['ap-handoff']
                        type: str
                        description: Enable/disable AP handoff of clients to other APs
                        choices:
                            - 'disable'
                            - 'enable'
                    iperf_protocol:
                        aliases: ['iperf-protocol']
                        type: str
                        description: Iperf test protocol
                        choices:
                            - 'udp'
                            - 'tcp'
                    iperf_server_port:
                        aliases: ['iperf-server-port']
                        type: int
                        description: Iperf service port number.
                    power_mode:
                        aliases: ['power-mode']
                        type: str
                        description: Set radio effective isotropic radiated power
                        choices:
                            - 'dBm'
                            - 'percentage'
                    power_value:
                        aliases: ['power-value']
                        type: int
                        description: Radio EIRP power in dBm
                    sam_bssid:
                        aliases: ['sam-bssid']
                        type: str
                        description: BSSID for WiFi network.
                    sam_captive_portal:
                        aliases: ['sam-captive-portal']
                        type: str
                        description: Enable/disable Captive Portal Authentication
                        choices:
                            - 'disable'
                            - 'enable'
                    sam_password:
                        aliases: ['sam-password']
                        type: raw
                        description: (list) Passphrase for WiFi network connection.
                    sam_report_intv:
                        aliases: ['sam-report-intv']
                        type: int
                        description: SAM report interval
                    sam_security_type:
                        aliases: ['sam-security-type']
                        type: str
                        description: Select WiFi network security type
                        choices:
                            - 'open'
                            - 'wpa-personal'
                            - 'wpa-enterprise'
                            - 'owe'
                            - 'wpa3-sae'
                    sam_server:
                        aliases: ['sam-server']
                        type: str
                        description: SAM test server IP address or domain name.
                    sam_ssid:
                        aliases: ['sam-ssid']
                        type: str
                        description: SSID for WiFi network.
                    sam_test:
                        aliases: ['sam-test']
                        type: str
                        description: Select SAM test type
                        choices:
                            - 'ping'
                            - 'iperf'
                    sam_username:
                        aliases: ['sam-username']
                        type: str
                        description: Username for WiFi network connection.
                    arrp_profile:
                        aliases: ['arrp-profile']
                        type: str
                        description: Distributed Automatic Radio Resource Provisioning
                    bss_color_mode:
                        aliases: ['bss-color-mode']
                        type: str
                        description: BSS color mode for this 11ax radio
                        choices:
                            - 'auto'
                            - 'static'
                    sam_cwp_failure_string:
                        aliases: ['sam-cwp-failure-string']
                        type: str
                        description: Failure identification on the page after an incorrect login.
                    sam_cwp_match_string:
                        aliases: ['sam-cwp-match-string']
                        type: str
                        description: Identification string from the captive portal login form.
                    sam_cwp_password:
                        aliases: ['sam-cwp-password']
                        type: raw
                        description: (list) Password for captive portal authentication.
                    sam_cwp_success_string:
                        aliases: ['sam-cwp-success-string']
                        type: str
                        description: Success identification on the page after a successful login.
                    sam_cwp_test_url:
                        aliases: ['sam-cwp-test-url']
                        type: str
                        description: Website the client is trying to access.
                    sam_cwp_username:
                        aliases: ['sam-cwp-username']
                        type: str
                        description: Username for captive portal authentication.
                    sam_server_fqdn:
                        aliases: ['sam-server-fqdn']
                        type: str
                        description: SAM test server domain name.
                    sam_server_ip:
                        aliases: ['sam-server-ip']
                        type: str
                        description: SAM test server IP address.
                    sam_server_type:
                        aliases: ['sam-server-type']
                        type: str
                        description: Select SAM server type
                        choices:
                            - 'ip'
                            - 'fqdn'
                    d80211d:
                        aliases: ['80211d']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    optional_antenna:
                        aliases: ['optional-antenna']
                        type: str
                        description: Optional antenna used on FAP
                        choices:
                            - 'none'
                            - 'FANT-04ABGN-0606-O-N'
                            - 'FANT-04ABGN-1414-P-N'
                            - 'FANT-04ABGN-8065-P-N'
                            - 'FANT-04ABGN-0606-O-R'
                            - 'FANT-04ABGN-0606-P-R'
                            - 'FANT-10ACAX-1213-D-N'
                            - 'FANT-08ABGN-1213-D-R'
                            - 'custom'
                    mimo_mode:
                        aliases: ['mimo-mode']
                        type: str
                        description: Configure radio MIMO mode
                        choices:
                            - 'default'
                            - '1x1'
                            - '2x2'
                            - '3x3'
                            - '4x4'
                            - '8x8'
                    optional_antenna_gain:
                        aliases: ['optional-antenna-gain']
                        type: str
                        description: Optional antenna gain in dBi
                    sam_ca_certificate:
                        aliases: ['sam-ca-certificate']
                        type: str
                        description: CA certificate for WPA2/WPA3-ENTERPRISE.
                    sam_client_certificate:
                        aliases: ['sam-client-certificate']
                        type: str
                        description: Client certificate for WPA2/WPA3-ENTERPRISE.
                    sam_eap_method:
                        aliases: ['sam-eap-method']
                        type: str
                        description: Select WPA2/WPA3-ENTERPRISE EAP Method
                        choices:
                            - 'tls'
                            - 'peap'
                            - 'both'
                    sam_private_key:
                        aliases: ['sam-private-key']
                        type: str
                        description: Private key for WPA2/WPA3-ENTERPRISE.
                    sam_private_key_password:
                        aliases: ['sam-private-key-password']
                        type: raw
                        description: (list) Password for private key file for WPA2/WPA3-ENTERPRISE.
                    channel_bonding_ext:
                        aliases: ['channel-bonding-ext']
                        type: str
                        description: Channel bandwidth extension
                        choices:
                            - '320MHz-1'
                            - '320MHz-2'
                    d80211mc:
                        aliases: ['80211mc']
                        type: str
                        description: Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    ap_sniffer_chan_width:
                        aliases: ['ap-sniffer-chan-width']
                        type: str
                        description: Channel bandwidth for sniffer.
                        choices:
                            - '320MHz'
                            - '240MHz'
                            - '160MHz'
                            - '80MHz'
                            - '40MHz'
                            - '20MHz'
            console_login:
                aliases: ['console-login']
                type: str
                description: Enable/disable FortiAP console login access
                choices:
                    - 'disable'
                    - 'enable'
            esl_ses_dongle:
                aliases: ['esl-ses-dongle']
                type: dict
                description: Esl ses dongle.
                suboptions:
                    apc_addr_type:
                        aliases: ['apc-addr-type']
                        type: str
                        description: ESL SES-imagotag APC address type
                        choices:
                            - 'fqdn'
                            - 'ip'
                    apc_fqdn:
                        aliases: ['apc-fqdn']
                        type: str
                        description: FQDN of ESL SES-imagotag Access Point Controller
                    apc_ip:
                        aliases: ['apc-ip']
                        type: str
                        description: IP address of ESL SES-imagotag Access Point Controller
                    apc_port:
                        aliases: ['apc-port']
                        type: int
                        description: Port of ESL SES-imagotag Access Point Controller
                    coex_level:
                        aliases: ['coex-level']
                        type: str
                        description: ESL SES-imagotag dongle coexistence level
                        choices:
                            - 'none'
                    compliance_level:
                        aliases: ['compliance-level']
                        type: str
                        description: Compliance levels for the ESL solution integration
                        choices:
                            - 'compliance-level-2'
                    esl_channel:
                        aliases: ['esl-channel']
                        type: str
                        description: ESL SES-imagotag dongle channel
                        choices:
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
                            - '-1'
                    output_power:
                        aliases: ['output-power']
                        type: str
                        description: ESL SES-imagotag dongle output power
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
                        aliases: ['scd-enable']
                        type: str
                        description: Enable/disable ESL SES-imagotag Serial Communication Daemon
                        choices:
                            - 'disable'
                            - 'enable'
                    tls_cert_verification:
                        aliases: ['tls-cert-verification']
                        type: str
                        description: Enable/disable TLS certificate verification
                        choices:
                            - 'disable'
                            - 'enable'
                    tls_fqdn_verification:
                        aliases: ['tls-fqdn-verification']
                        type: str
                        description: Enable/disable TLS certificate verification
                        choices:
                            - 'disable'
                            - 'enable'
            indoor_outdoor_deployment:
                aliases: ['indoor-outdoor-deployment']
                type: str
                description: Set to allow indoor/outdoor-only channels under regulatory rules
                choices:
                    - 'platform-determined'
                    - 'outdoor'
                    - 'indoor'
            syslog_profile:
                aliases: ['syslog-profile']
                type: str
                description: System log server configuration profile name.
            wan_port_auth:
                aliases: ['wan-port-auth']
                type: str
                description: Set WAN port authentication mode
                choices:
                    - 'none'
                    - '802.1x'
            wan_port_auth_methods:
                aliases: ['wan-port-auth-methods']
                type: str
                description: WAN port 802.
                choices:
                    - 'all'
                    - 'EAP-FAST'
                    - 'EAP-TLS'
                    - 'EAP-PEAP'
            wan_port_auth_password:
                aliases: ['wan-port-auth-password']
                type: raw
                description: (list) Set WAN port 802.
            wan_port_auth_usrname:
                aliases: ['wan-port-auth-usrname']
                type: str
                description: Set WAN port 802.
            _is_factory_setting:
                type: str
                description: Is factory setting.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'ext'
            unii_4_5ghz_band:
                aliases: ['unii-4-5ghz-band']
                type: str
                description: Enable/disable UNII-4 5Ghz band channels
                choices:
                    - 'disable'
                    - 'enable'
            bonjour_profile:
                aliases: ['bonjour-profile']
                type: str
                description: Bonjour profile name.
            wan_port_auth_macsec:
                aliases: ['wan-port-auth-macsec']
                type: str
                description: Enable/disable WAN port 802.
                choices:
                    - 'disable'
                    - 'enable'
            usb_port:
                aliases: ['usb-port']
                type: str
                description: Enable/disable USB port of the WTP
                choices:
                    - 'disable'
                    - 'enable'
            admin_auth_tacacs_:
                aliases: ['admin-auth-tacacs+']
                type: raw
                description: (list) Remote authentication server for admin user.
            admin_restrict_local:
                aliases: ['admin-restrict-local']
                type: str
                description: Enable/disable local admin authentication restriction when remote authenticator is up and running
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
    - name: Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms.
      fortinet.fortimanager.fmgr_wtpprofile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        wtpprofile:
          name: "your value" # Required variable, string
          # allowaccess:
          #   - "https"
          #   - "ssh"
          #   - "snmp"
          #   - "http"
          #   - "telnet"
          # ap_country: <value in [AL, DZ, AR, ...]>
          # ble_profile: <string>
          # comment: <string>
          # control_message_offload:
          #   - "ebp-frame"
          #   - "aeroscout-tag"
          #   - "ap-list"
          #   - "sta-list"
          #   - "sta-cap-list"
          #   - "stats"
          #   - "aeroscout-mu"
          #   - "sta-health"
          #   - "spectral-analysis"
          # deny_mac_list:
          #   - id: <integer>
          #     mac: <string>
          # dtls_in_kernel: <value in [disable, enable]>
          # dtls_policy:
          #   - "clear-text"
          #   - "dtls-enabled"
          #   - "ipsec-vpn"
          #   - "ipsec-sn-vpn"
          # energy_efficient_ethernet: <value in [disable, enable]>
          # ext_info_enable: <value in [disable, enable]>
          # handoff_roaming: <value in [disable, enable]>
          # handoff_rssi: <integer>
          # handoff_sta_thresh: <integer>
          # ip_fragment_preventing:
          #   - "tcp-mss-adjust"
          #   - "icmp-unreachable"
          # led_schedules: <list or string>
          # led_state: <value in [disable, enable]>
          # lldp: <value in [disable, enable]>
          # login_passwd: <list or string>
          # login_passwd_change: <value in [no, yes, default]>
          # max_clients: <integer>
          # poe_mode: <value in [auto, 8023af, 8023at, ...]>
          # split_tunneling_acl:
          #   - dest_ip: <string>
          #     id: <integer>
          # split_tunneling_acl_local_ap_subnet: <value in [disable, enable]>
          # split_tunneling_acl_path: <value in [tunnel, local]>
          # tun_mtu_downlink: <integer>
          # tun_mtu_uplink: <integer>
          # wan_port_mode: <value in [wan-lan, wan-only]>
          # snmp: <value in [disable, enable]>
          # ap_handoff: <value in [disable, enable]>
          # apcfg_profile: <string>
          # frequency_handoff: <value in [disable, enable]>
          # lan:
          #   port_esl_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port_esl_ssid: <string>
          #   port_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port_ssid: <string>
          #   port1_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port1_ssid: <string>
          #   port2_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port2_ssid: <string>
          #   port3_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port3_ssid: <string>
          #   port4_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port4_ssid: <string>
          #   port5_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port5_ssid: <string>
          #   port6_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port6_ssid: <string>
          #   port7_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port7_ssid: <string>
          #   port8_mode: <value in [offline, bridge-to-wan, bridge-to-ssid, ...]>
          #   port8_ssid: <string>
          # lbs:
          #   aeroscout: <value in [disable, enable]>
          #   aeroscout_ap_mac: <value in [bssid, board-mac]>
          #   aeroscout_mmu_report: <value in [disable, enable]>
          #   aeroscout_mu: <value in [disable, enable]>
          #   aeroscout_mu_factor: <integer>
          #   aeroscout_mu_timeout: <integer>
          #   aeroscout_server_ip: <string>
          #   aeroscout_server_port: <integer>
          #   ekahau_blink_mode: <value in [disable, enable]>
          #   ekahau_tag: <string>
          #   erc_server_ip: <string>
          #   erc_server_port: <integer>
          #   fortipresence: <value in [disable, enable, enable2, ...]>
          #   fortipresence_ble: <value in [disable, enable]>
          #   fortipresence_frequency: <integer>
          #   fortipresence_port: <integer>
          #   fortipresence_project: <string>
          #   fortipresence_rogue: <value in [disable, enable]>
          #   fortipresence_secret: <list or string>
          #   fortipresence_server: <string>
          #   fortipresence_unassoc: <value in [disable, enable]>
          #   station_locate: <value in [disable, enable]>
          #   fortipresence_server_addr_type: <value in [fqdn, ipv4]>
          #   fortipresence_server_fqdn: <string>
          #   polestar: <value in [disable, enable]>
          #   polestar_accumulation_interval: <integer>
          #   polestar_asset_addrgrp_list: <string>
          #   polestar_asset_uuid_list1: <string>
          #   polestar_asset_uuid_list2: <string>
          #   polestar_asset_uuid_list3: <string>
          #   polestar_asset_uuid_list4: <string>
          #   polestar_protocol: <value in [WSS]>
          #   polestar_reporting_interval: <integer>
          #   polestar_server_fqdn: <string>
          #   polestar_server_path: <string>
          #   polestar_server_port: <integer>
          #   polestar_server_token: <string>
          #   ble_rtls: <value in [none, polestar, evresys]>
          #   ble_rtls_accumulation_interval: <integer>
          #   ble_rtls_asset_addrgrp_list: <list or string>
          #   ble_rtls_asset_uuid_list1: <string>
          #   ble_rtls_asset_uuid_list2: <string>
          #   ble_rtls_asset_uuid_list3: <string>
          #   ble_rtls_asset_uuid_list4: <string>
          #   ble_rtls_protocol: <value in [WSS]>
          #   ble_rtls_reporting_interval: <integer>
          #   ble_rtls_server_fqdn: <string>
          #   ble_rtls_server_path: <string>
          #   ble_rtls_server_port: <integer>
          #   ble_rtls_server_token: <string>
          # platform:
          #   ddscan: <value in [disable, enable]>
          #   mode: <value in [dual-5G, single-5G]>
          #   type: <value in [30B-50B, 60B, 80CM-81CM, ...]>
          #   _local_platform_str: <string>
          # radio_1:
          #   airtime_fairness: <value in [disable, enable]>
          #   amsdu: <value in [disable, enable]>
          #   ap_sniffer_addr: <string>
          #   ap_sniffer_bufsize: <integer>
          #   ap_sniffer_chan: <integer>
          #   ap_sniffer_ctl: <value in [disable, enable]>
          #   ap_sniffer_data: <value in [disable, enable]>
          #   ap_sniffer_mgmt_beacon: <value in [disable, enable]>
          #   ap_sniffer_mgmt_other: <value in [disable, enable]>
          #   ap_sniffer_mgmt_probe: <value in [disable, enable]>
          #   auto_power_high: <integer>
          #   auto_power_level: <value in [disable, enable]>
          #   auto_power_low: <integer>
          #   auto_power_target: <string>
          #   band: <value in [802.11b, 802.11a, 802.11g, ...]>
          #   band_5g_type: <value in [5g-full, 5g-high, 5g-low]>
          #   bandwidth_admission_control: <value in [disable, enable]>
          #   bandwidth_capacity: <integer>
          #   beacon_interval: <integer>
          #   bss_color: <integer>
          #   call_admission_control: <value in [disable, enable]>
          #   call_capacity: <integer>
          #   channel: <list or string>
          #   channel_bonding: <value in [disable, enable, 80MHz, ...]>
          #   channel_utilization: <value in [disable, enable]>
          #   coexistence: <value in [disable, enable]>
          #   darrp: <value in [disable, enable]>
          #   drma: <value in [disable, enable]>
          #   drma_sensitivity: <value in [low, medium, high]>
          #   dtim: <integer>
          #   frag_threshold: <integer>
          #   max_clients: <integer>
          #   max_distance: <integer>
          #   mode: <value in [disabled, ap, monitor, ...]>
          #   power_level: <integer>
          #   powersave_optimize:
          #     - "tim"
          #     - "ac-vo"
          #     - "no-obss-scan"
          #     - "no-11b-rate"
          #     - "client-rate-follow"
          #   protection_mode: <value in [rtscts, ctsonly, disable]>
          #   radio_id: <integer>
          #   rts_threshold: <integer>
          #   short_guard_interval: <value in [disable, enable]>
          #   spectrum_analysis: <value in [disable, enable, scan-only]>
          #   transmit_optimize:
          #     - "disable"
          #     - "power-save"
          #     - "aggr-limit"
          #     - "retry-limit"
          #     - "send-bar"
          #   vap_all: <value in [disable, enable, tunnel, ...]>
          #   vap1: <string>
          #   vap2: <string>
          #   vap3: <string>
          #   vap4: <string>
          #   vap5: <string>
          #   vap6: <string>
          #   vap7: <string>
          #   vap8: <string>
          #   vaps: <list or string>
          #   wids_profile: <string>
          #   zero_wait_dfs: <value in [disable, enable]>
          #   frequency_handoff: <value in [disable, enable]>
          #   ap_handoff: <value in [disable, enable]>
          #   iperf_protocol: <value in [udp, tcp]>
          #   iperf_server_port: <integer>
          #   power_mode: <value in [dBm, percentage]>
          #   power_value: <integer>
          #   sam_bssid: <string>
          #   sam_captive_portal: <value in [disable, enable]>
          #   sam_password: <list or string>
          #   sam_report_intv: <integer>
          #   sam_security_type: <value in [open, wpa-personal, wpa-enterprise, ...]>
          #   sam_server: <string>
          #   sam_ssid: <string>
          #   sam_test: <value in [ping, iperf]>
          #   sam_username: <string>
          #   arrp_profile: <string>
          #   bss_color_mode: <value in [auto, static]>
          #   sam_cwp_failure_string: <string>
          #   sam_cwp_match_string: <string>
          #   sam_cwp_password: <list or string>
          #   sam_cwp_success_string: <string>
          #   sam_cwp_test_url: <string>
          #   sam_cwp_username: <string>
          #   sam_server_fqdn: <string>
          #   sam_server_ip: <string>
          #   sam_server_type: <value in [ip, fqdn]>
          #   d80211d: <value in [disable, enable]>
          #   optional_antenna: <value in [none, FANT-04ABGN-0606-O-N, FANT-04ABGN-1414-P-N, ...]>
          #   mimo_mode: <value in [default, 1x1, 2x2, ...]>
          #   optional_antenna_gain: <string>
          #   sam_ca_certificate: <string>
          #   sam_client_certificate: <string>
          #   sam_eap_method: <value in [tls, peap, both]>
          #   sam_private_key: <string>
          #   sam_private_key_password: <list or string>
          #   channel_bonding_ext: <value in [320MHz-1, 320MHz-2]>
          #   d80211mc: <value in [disable, enable]>
          #   ap_sniffer_chan_width: <value in [320MHz, 240MHz, 160MHz, ...]>
          # radio_2:
          #   airtime_fairness: <value in [disable, enable]>
          #   amsdu: <value in [disable, enable]>
          #   ap_sniffer_addr: <string>
          #   ap_sniffer_bufsize: <integer>
          #   ap_sniffer_chan: <integer>
          #   ap_sniffer_ctl: <value in [disable, enable]>
          #   ap_sniffer_data: <value in [disable, enable]>
          #   ap_sniffer_mgmt_beacon: <value in [disable, enable]>
          #   ap_sniffer_mgmt_other: <value in [disable, enable]>
          #   ap_sniffer_mgmt_probe: <value in [disable, enable]>
          #   auto_power_high: <integer>
          #   auto_power_level: <value in [disable, enable]>
          #   auto_power_low: <integer>
          #   auto_power_target: <string>
          #   band: <value in [802.11b, 802.11a, 802.11g, ...]>
          #   band_5g_type: <value in [5g-full, 5g-high, 5g-low]>
          #   bandwidth_admission_control: <value in [disable, enable]>
          #   bandwidth_capacity: <integer>
          #   beacon_interval: <integer>
          #   bss_color: <integer>
          #   call_admission_control: <value in [disable, enable]>
          #   call_capacity: <integer>
          #   channel: <list or string>
          #   channel_bonding: <value in [disable, enable, 80MHz, ...]>
          #   channel_utilization: <value in [disable, enable]>
          #   coexistence: <value in [disable, enable]>
          #   darrp: <value in [disable, enable]>
          #   drma: <value in [disable, enable]>
          #   drma_sensitivity: <value in [low, medium, high]>
          #   dtim: <integer>
          #   frag_threshold: <integer>
          #   max_clients: <integer>
          #   max_distance: <integer>
          #   mode: <value in [disabled, ap, monitor, ...]>
          #   power_level: <integer>
          #   powersave_optimize:
          #     - "tim"
          #     - "ac-vo"
          #     - "no-obss-scan"
          #     - "no-11b-rate"
          #     - "client-rate-follow"
          #   protection_mode: <value in [rtscts, ctsonly, disable]>
          #   radio_id: <integer>
          #   rts_threshold: <integer>
          #   short_guard_interval: <value in [disable, enable]>
          #   spectrum_analysis: <value in [disable, enable, scan-only]>
          #   transmit_optimize:
          #     - "disable"
          #     - "power-save"
          #     - "aggr-limit"
          #     - "retry-limit"
          #     - "send-bar"
          #   vap_all: <value in [disable, enable, tunnel, ...]>
          #   vap1: <string>
          #   vap2: <string>
          #   vap3: <string>
          #   vap4: <string>
          #   vap5: <string>
          #   vap6: <string>
          #   vap7: <string>
          #   vap8: <string>
          #   vaps: <list or string>
          #   wids_profile: <string>
          #   zero_wait_dfs: <value in [disable, enable]>
          #   frequency_handoff: <value in [disable, enable]>
          #   ap_handoff: <value in [disable, enable]>
          #   iperf_protocol: <value in [udp, tcp]>
          #   iperf_server_port: <integer>
          #   power_mode: <value in [dBm, percentage]>
          #   power_value: <integer>
          #   sam_bssid: <string>
          #   sam_captive_portal: <value in [disable, enable]>
          #   sam_password: <list or string>
          #   sam_report_intv: <integer>
          #   sam_security_type: <value in [open, wpa-personal, wpa-enterprise, ...]>
          #   sam_server: <string>
          #   sam_ssid: <string>
          #   sam_test: <value in [ping, iperf]>
          #   sam_username: <string>
          #   arrp_profile: <string>
          #   bss_color_mode: <value in [auto, static]>
          #   sam_cwp_failure_string: <string>
          #   sam_cwp_match_string: <string>
          #   sam_cwp_password: <list or string>
          #   sam_cwp_success_string: <string>
          #   sam_cwp_test_url: <string>
          #   sam_cwp_username: <string>
          #   sam_server_fqdn: <string>
          #   sam_server_ip: <string>
          #   sam_server_type: <value in [ip, fqdn]>
          #   d80211d: <value in [disable, enable]>
          #   optional_antenna: <value in [none, FANT-04ABGN-0606-O-N, FANT-04ABGN-1414-P-N, ...]>
          #   mimo_mode: <value in [default, 1x1, 2x2, ...]>
          #   optional_antenna_gain: <string>
          #   sam_ca_certificate: <string>
          #   sam_client_certificate: <string>
          #   sam_eap_method: <value in [tls, peap, both]>
          #   sam_private_key: <string>
          #   sam_private_key_password: <list or string>
          #   channel_bonding_ext: <value in [320MHz-1, 320MHz-2]>
          #   d80211mc: <value in [disable, enable]>
          #   ap_sniffer_chan_width: <value in [320MHz, 240MHz, 160MHz, ...]>
          # radio_3:
          #   airtime_fairness: <value in [disable, enable]>
          #   amsdu: <value in [disable, enable]>
          #   ap_sniffer_addr: <string>
          #   ap_sniffer_bufsize: <integer>
          #   ap_sniffer_chan: <integer>
          #   ap_sniffer_ctl: <value in [disable, enable]>
          #   ap_sniffer_data: <value in [disable, enable]>
          #   ap_sniffer_mgmt_beacon: <value in [disable, enable]>
          #   ap_sniffer_mgmt_other: <value in [disable, enable]>
          #   ap_sniffer_mgmt_probe: <value in [disable, enable]>
          #   auto_power_high: <integer>
          #   auto_power_level: <value in [disable, enable]>
          #   auto_power_low: <integer>
          #   auto_power_target: <string>
          #   band: <value in [802.11b, 802.11a, 802.11g, ...]>
          #   band_5g_type: <value in [5g-full, 5g-high, 5g-low]>
          #   bandwidth_admission_control: <value in [disable, enable]>
          #   bandwidth_capacity: <integer>
          #   beacon_interval: <integer>
          #   bss_color: <integer>
          #   call_admission_control: <value in [disable, enable]>
          #   call_capacity: <integer>
          #   channel: <list or string>
          #   channel_bonding: <value in [80MHz, 40MHz, 20MHz, ...]>
          #   channel_utilization: <value in [disable, enable]>
          #   coexistence: <value in [disable, enable]>
          #   darrp: <value in [disable, enable]>
          #   drma: <value in [disable, enable]>
          #   drma_sensitivity: <value in [low, medium, high]>
          #   dtim: <integer>
          #   frag_threshold: <integer>
          #   max_clients: <integer>
          #   max_distance: <integer>
          #   mode: <value in [disabled, ap, monitor, ...]>
          #   power_level: <integer>
          #   powersave_optimize:
          #     - "tim"
          #     - "ac-vo"
          #     - "no-obss-scan"
          #     - "no-11b-rate"
          #     - "client-rate-follow"
          #   protection_mode: <value in [rtscts, ctsonly, disable]>
          #   radio_id: <integer>
          #   rts_threshold: <integer>
          #   short_guard_interval: <value in [disable, enable]>
          #   spectrum_analysis: <value in [disable, enable, scan-only]>
          #   transmit_optimize:
          #     - "disable"
          #     - "power-save"
          #     - "aggr-limit"
          #     - "retry-limit"
          #     - "send-bar"
          #   vap_all: <value in [disable, enable, tunnel, ...]>
          #   vap1: <string>
          #   vap2: <string>
          #   vap3: <string>
          #   vap4: <string>
          #   vap5: <string>
          #   vap6: <string>
          #   vap7: <string>
          #   vap8: <string>
          #   vaps: <list or string>
          #   wids_profile: <string>
          #   zero_wait_dfs: <value in [disable, enable]>
          #   frequency_handoff: <value in [disable, enable]>
          #   ap_handoff: <value in [disable, enable]>
          #   iperf_protocol: <value in [udp, tcp]>
          #   iperf_server_port: <integer>
          #   power_mode: <value in [dBm, percentage]>
          #   power_value: <integer>
          #   sam_bssid: <string>
          #   sam_captive_portal: <value in [disable, enable]>
          #   sam_password: <list or string>
          #   sam_report_intv: <integer>
          #   sam_security_type: <value in [open, wpa-personal, wpa-enterprise, ...]>
          #   sam_server: <string>
          #   sam_ssid: <string>
          #   sam_test: <value in [ping, iperf]>
          #   sam_username: <string>
          #   arrp_profile: <string>
          #   bss_color_mode: <value in [auto, static]>
          #   sam_cwp_failure_string: <string>
          #   sam_cwp_match_string: <string>
          #   sam_cwp_password: <list or string>
          #   sam_cwp_success_string: <string>
          #   sam_cwp_test_url: <string>
          #   sam_cwp_username: <string>
          #   sam_server_fqdn: <string>
          #   sam_server_ip: <string>
          #   sam_server_type: <value in [ip, fqdn]>
          #   d80211d: <value in [disable, enable]>
          #   optional_antenna: <value in [none, FANT-04ABGN-0606-O-N, FANT-04ABGN-1414-P-N, ...]>
          #   mimo_mode: <value in [default, 1x1, 2x2, ...]>
          #   optional_antenna_gain: <string>
          #   sam_ca_certificate: <string>
          #   sam_client_certificate: <string>
          #   sam_eap_method: <value in [tls, peap, both]>
          #   sam_private_key: <string>
          #   sam_private_key_password: <list or string>
          #   channel_bonding_ext: <value in [320MHz-1, 320MHz-2]>
          #   d80211mc: <value in [disable, enable]>
          #   ap_sniffer_chan_width: <value in [320MHz, 240MHz, 160MHz, ...]>
          # radio_4:
          #   airtime_fairness: <value in [disable, enable]>
          #   amsdu: <value in [disable, enable]>
          #   ap_sniffer_addr: <string>
          #   ap_sniffer_bufsize: <integer>
          #   ap_sniffer_chan: <integer>
          #   ap_sniffer_ctl: <value in [disable, enable]>
          #   ap_sniffer_data: <value in [disable, enable]>
          #   ap_sniffer_mgmt_beacon: <value in [disable, enable]>
          #   ap_sniffer_mgmt_other: <value in [disable, enable]>
          #   ap_sniffer_mgmt_probe: <value in [disable, enable]>
          #   auto_power_high: <integer>
          #   auto_power_level: <value in [disable, enable]>
          #   auto_power_low: <integer>
          #   auto_power_target: <string>
          #   band: <value in [802.11b, 802.11a, 802.11g, ...]>
          #   band_5g_type: <value in [5g-full, 5g-high, 5g-low]>
          #   bandwidth_admission_control: <value in [disable, enable]>
          #   bandwidth_capacity: <integer>
          #   beacon_interval: <integer>
          #   bss_color: <integer>
          #   call_admission_control: <value in [disable, enable]>
          #   call_capacity: <integer>
          #   channel: <list or string>
          #   channel_bonding: <value in [80MHz, 40MHz, 20MHz, ...]>
          #   channel_utilization: <value in [disable, enable]>
          #   coexistence: <value in [disable, enable]>
          #   darrp: <value in [disable, enable]>
          #   drma: <value in [disable, enable]>
          #   drma_sensitivity: <value in [low, medium, high]>
          #   dtim: <integer>
          #   frag_threshold: <integer>
          #   max_clients: <integer>
          #   max_distance: <integer>
          #   mode: <value in [ap, monitor, sniffer, ...]>
          #   power_level: <integer>
          #   powersave_optimize:
          #     - "tim"
          #     - "ac-vo"
          #     - "no-obss-scan"
          #     - "no-11b-rate"
          #     - "client-rate-follow"
          #   protection_mode: <value in [rtscts, ctsonly, disable]>
          #   radio_id: <integer>
          #   rts_threshold: <integer>
          #   short_guard_interval: <value in [disable, enable]>
          #   spectrum_analysis: <value in [disable, enable, scan-only]>
          #   transmit_optimize:
          #     - "disable"
          #     - "power-save"
          #     - "aggr-limit"
          #     - "retry-limit"
          #     - "send-bar"
          #   vap_all: <value in [disable, enable, tunnel, ...]>
          #   vap1: <string>
          #   vap2: <string>
          #   vap3: <string>
          #   vap4: <string>
          #   vap5: <string>
          #   vap6: <string>
          #   vap7: <string>
          #   vap8: <string>
          #   vaps: <list or string>
          #   wids_profile: <string>
          #   zero_wait_dfs: <value in [disable, enable]>
          #   frequency_handoff: <value in [disable, enable]>
          #   ap_handoff: <value in [disable, enable]>
          #   iperf_protocol: <value in [udp, tcp]>
          #   iperf_server_port: <integer>
          #   power_mode: <value in [dBm, percentage]>
          #   power_value: <integer>
          #   sam_bssid: <string>
          #   sam_captive_portal: <value in [disable, enable]>
          #   sam_password: <list or string>
          #   sam_report_intv: <integer>
          #   sam_security_type: <value in [open, wpa-personal, wpa-enterprise, ...]>
          #   sam_server: <string>
          #   sam_ssid: <string>
          #   sam_test: <value in [ping, iperf]>
          #   sam_username: <string>
          #   arrp_profile: <string>
          #   bss_color_mode: <value in [auto, static]>
          #   sam_cwp_failure_string: <string>
          #   sam_cwp_match_string: <string>
          #   sam_cwp_password: <list or string>
          #   sam_cwp_success_string: <string>
          #   sam_cwp_test_url: <string>
          #   sam_cwp_username: <string>
          #   sam_server_fqdn: <string>
          #   sam_server_ip: <string>
          #   sam_server_type: <value in [ip, fqdn]>
          #   d80211d: <value in [disable, enable]>
          #   optional_antenna: <value in [none, FANT-04ABGN-0606-O-N, FANT-04ABGN-1414-P-N, ...]>
          #   mimo_mode: <value in [default, 1x1, 2x2, ...]>
          #   optional_antenna_gain: <string>
          #   sam_ca_certificate: <string>
          #   sam_client_certificate: <string>
          #   sam_eap_method: <value in [tls, peap, both]>
          #   sam_private_key: <string>
          #   sam_private_key_password: <list or string>
          #   channel_bonding_ext: <value in [320MHz-1, 320MHz-2]>
          #   d80211mc: <value in [disable, enable]>
          #   ap_sniffer_chan_width: <value in [320MHz, 240MHz, 160MHz, ...]>
          # console_login: <value in [disable, enable]>
          # esl_ses_dongle:
          #   apc_addr_type: <value in [fqdn, ip]>
          #   apc_fqdn: <string>
          #   apc_ip: <string>
          #   apc_port: <integer>
          #   coex_level: <value in [none]>
          #   compliance_level: <value in [compliance-level-2]>
          #   esl_channel: <value in [0, 1, 2, ...]>
          #   output_power: <value in [a, b, c, ...]>
          #   scd_enable: <value in [disable, enable]>
          #   tls_cert_verification: <value in [disable, enable]>
          #   tls_fqdn_verification: <value in [disable, enable]>
          # indoor_outdoor_deployment: <value in [platform-determined, outdoor, indoor]>
          # syslog_profile: <string>
          # wan_port_auth: <value in [none, 802.1x]>
          # wan_port_auth_methods: <value in [all, EAP-FAST, EAP-TLS, ...]>
          # wan_port_auth_password: <list or string>
          # wan_port_auth_usrname: <string>
          # _is_factory_setting: <value in [disable, enable, ext]>
          # unii_4_5ghz_band: <value in [disable, enable]>
          # bonjour_profile: <string>
          # wan_port_auth_macsec: <value in [disable, enable]>
          # usb_port: <value in [disable, enable]>
          # admin_auth_tacacs_: <list or string>
          # admin_restrict_local: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile',
        '/pm/config/global/obj/wireless-controller/wtp-profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'wtpprofile': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'allowaccess': {'type': 'list', 'choices': ['https', 'ssh', 'snmp', 'http', 'telnet'], 'elements': 'str'},
                'ap-country': {
                    'choices': [
                        'AL', 'DZ', 'AR', 'AM', 'AU', 'AT', 'AZ', 'BH', 'BD', 'BY', 'BE', 'BZ', 'BO', 'BA', 'BR', 'BN', 'BG', 'CA', 'CL', 'CN', 'CO',
                        'CR', 'HR', 'CY', 'CZ', 'DK', 'DO', 'EC', 'EG', 'SV', 'EE', 'FI', 'FR', 'GE', 'DE', 'GR', 'GT', 'HN', 'HK', 'HU', 'IS', 'IN',
                        'ID', 'IR', 'IE', 'IL', 'IT', 'JM', 'JP', 'JO', 'KZ', 'KE', 'KP', 'KR', 'KW', 'LV', 'LB', 'LI', 'LT', 'LU', 'MO', 'MK', 'MY',
                        'MT', 'MX', 'MC', 'MA', 'NP', 'NL', 'AN', 'NZ', 'NO', 'OM', 'PK', 'PA', 'PG', 'PE', 'PH', 'PL', 'PT', 'PR', 'QA', 'RO', 'RU',
                        'SA', 'SG', 'SK', 'SI', 'ZA', 'ES', 'LK', 'SE', 'CH', 'SY', 'TW', 'TH', 'TT', 'TN', 'TR', 'AE', 'UA', 'GB', 'US', 'PS', 'UY',
                        'UZ', 'VE', 'VN', 'YE', 'ZW', 'NA', 'KH', 'TZ', 'SD', 'AO', 'RW', 'MZ', 'RS', 'ME', 'BB', 'GD', 'GL', 'GU', 'PY', 'HT', 'AW',
                        'MM', 'ZB', 'CF', 'BS', 'VC', 'MV', 'SN', 'CI', 'GH', 'MW', 'UG', 'BF', 'KY', 'TC', 'TM', 'VU', 'FM', 'GY', 'KN', 'LC', 'CX',
                        'AF', 'CM', 'ML', 'BJ', 'MG', 'TD', 'BW', 'LY', 'LS', 'MU', 'SL', 'NE', 'TG', 'RE', 'MD', 'BM', 'VI', 'PM', 'MF', 'IM', 'FO',
                        'GI', 'LA', 'WF', 'MH', 'BT', 'PF', 'NI', 'GF', 'AS', 'MP', 'PW', 'GP', 'ET', 'SR', 'DM', 'MQ', 'YT', 'BL', 'ZM', 'CG', 'CD',
                        'MR', 'IQ', 'FJ', '--', 'MN', 'NG', 'GA', 'GM', 'SO', 'SZ', 'LR', 'DJ', 'TL'
                    ],
                    'type': 'str'
                },
                'ble-profile': {'type': 'str'},
                'comment': {'type': 'str'},
                'control-message-offload': {
                    'type': 'list',
                    'choices': [
                        'ebp-frame', 'aeroscout-tag', 'ap-list', 'sta-list', 'sta-cap-list', 'stats', 'aeroscout-mu', 'sta-health', 'spectral-analysis'
                    ],
                    'elements': 'str'
                },
                'deny-mac-list': {'type': 'list', 'options': {'id': {'type': 'int'}, 'mac': {'type': 'str'}}, 'elements': 'dict'},
                'dtls-in-kernel': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dtls-policy': {'type': 'list', 'choices': ['clear-text', 'dtls-enabled', 'ipsec-vpn', 'ipsec-sn-vpn'], 'elements': 'str'},
                'energy-efficient-ethernet': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ext-info-enable': {'choices': ['disable', 'enable'], 'type': 'str'},
                'handoff-roaming': {'choices': ['disable', 'enable'], 'type': 'str'},
                'handoff-rssi': {'type': 'int'},
                'handoff-sta-thresh': {'type': 'int'},
                'ip-fragment-preventing': {'type': 'list', 'choices': ['tcp-mss-adjust', 'icmp-unreachable'], 'elements': 'str'},
                'led-schedules': {'type': 'raw'},
                'led-state': {'choices': ['disable', 'enable'], 'type': 'str'},
                'lldp': {'choices': ['disable', 'enable'], 'type': 'str'},
                'login-passwd': {'no_log': True, 'type': 'raw'},
                'login-passwd-change': {'choices': ['no', 'yes', 'default'], 'type': 'str'},
                'max-clients': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'poe-mode': {'choices': ['auto', '8023af', '8023at', 'power-adapter', 'full', 'high', 'low'], 'type': 'str'},
                'split-tunneling-acl': {'type': 'list', 'options': {'dest-ip': {'type': 'str'}, 'id': {'type': 'int'}}, 'elements': 'dict'},
                'split-tunneling-acl-local-ap-subnet': {'choices': ['disable', 'enable'], 'type': 'str'},
                'split-tunneling-acl-path': {'choices': ['tunnel', 'local'], 'type': 'str'},
                'tun-mtu-downlink': {'type': 'int'},
                'tun-mtu-uplink': {'type': 'int'},
                'wan-port-mode': {'choices': ['wan-lan', 'wan-only'], 'type': 'str'},
                'snmp': {'v_range': [['6.2.0', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ap-handoff': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'apcfg-profile': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'frequency-handoff': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'lan': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'port-esl-mode': {
                            'v_range': [['6.4.5', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port-esl-ssid': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'port-mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port-ssid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'port1-mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port1-ssid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'port2-mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port2-ssid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'port3-mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port3-ssid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'port4-mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port4-ssid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'port5-mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port5-ssid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'port6-mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port6-ssid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'port7-mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port7-ssid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'port8-mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['offline', 'bridge-to-wan', 'bridge-to-ssid', 'nat-to-wan'],
                            'type': 'str'
                        },
                        'port8-ssid': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'}
                    }
                },
                'lbs': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'aeroscout': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'aeroscout-ap-mac': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['bssid', 'board-mac'], 'type': 'str'},
                        'aeroscout-mmu-report': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'aeroscout-mu': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'aeroscout-mu-factor': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'aeroscout-mu-timeout': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'aeroscout-server-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'aeroscout-server-port': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ekahau-blink-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ekahau-tag': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'erc-server-ip': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'erc-server-port': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'fortipresence': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'enable2', 'foreign', 'both'],
                            'type': 'str'
                        },
                        'fortipresence-ble': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortipresence-frequency': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'fortipresence-port': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'fortipresence-project': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'fortipresence-rogue': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortipresence-secret': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'no_log': True, 'type': 'raw'},
                        'fortipresence-server': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'fortipresence-unassoc': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'station-locate': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortipresence-server-addr-type': {'v_range': [['7.0.2', '']], 'choices': ['fqdn', 'ipv4'], 'type': 'str'},
                        'fortipresence-server-fqdn': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'polestar': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'polestar-accumulation-interval': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'polestar-asset-addrgrp-list': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'polestar-asset-uuid-list1': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'polestar-asset-uuid-list2': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'polestar-asset-uuid-list3': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'polestar-asset-uuid-list4': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'polestar-protocol': {'v_range': [['7.4.1', '']], 'choices': ['WSS'], 'type': 'str'},
                        'polestar-reporting-interval': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'polestar-server-fqdn': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'polestar-server-path': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'polestar-server-port': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'polestar-server-token': {'v_range': [['7.4.1', '']], 'no_log': True, 'type': 'str'},
                        'ble-rtls': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'choices': ['none', 'polestar', 'evresys'], 'type': 'str'},
                        'ble-rtls-accumulation-interval': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'int'},
                        'ble-rtls-asset-addrgrp-list': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'raw'},
                        'ble-rtls-asset-uuid-list1': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'str'},
                        'ble-rtls-asset-uuid-list2': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'str'},
                        'ble-rtls-asset-uuid-list3': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'str'},
                        'ble-rtls-asset-uuid-list4': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'str'},
                        'ble-rtls-protocol': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'choices': ['WSS'], 'type': 'str'},
                        'ble-rtls-reporting-interval': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'int'},
                        'ble-rtls-server-fqdn': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'str'},
                        'ble-rtls-server-path': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'str'},
                        'ble-rtls-server-port': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'int'},
                        'ble-rtls-server-token': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'no_log': True, 'type': 'str'}
                    }
                },
                'platform': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'ddscan': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['dual-5G', 'single-5G'], 'type': 'str'},
                        'type': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                '30B-50B', '60B', '80CM-81CM', '220A', '220B', '210B', '60C', '222B', '112B', '320B', '11C', '14C', '223B', '28C',
                                '320C', '221C', '25D', '222C', '224D', '214B', '21D', '24D', '112D', '223C', '321C', 'C220C', 'C225C', 'S321C', 'S323C',
                                'FWF', 'S311C', 'S313C', 'AP-11N', 'S322C', 'S321CR', 'S322CR', 'S323CR', 'S421E', 'S422E', 'S423E', '421E', '423E',
                                'C221E', 'C226E', 'C23JD', 'C24JE', 'C21D', 'U421E', 'U423E', '221E', '222E', '223E', 'S221E', 'S223E', 'U221EV',
                                'U223EV', 'U321EV', 'U323EV', '224E', 'U422EV', 'U24JEV', '321E', 'U431F', 'U433F', '231E', '431F', '433F', '231F',
                                '432F', '234F', '23JF', 'U231F', '831F', 'U234F', 'U432F', '431FL', '432FR', '433FL', '231FL', '231G', '233G', '431G',
                                '433G', 'U231G', 'U441G', '234G', '432G', '441K', '443K', '241K', '243K', '231K', '23JK'
                            ],
                            'type': 'str'
                        },
                        '_local_platform_str': {'v_range': [['6.2.8', '6.2.13'], ['6.4.6', '']], 'type': 'str'}
                    }
                },
                'radio-1': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'airtime-fairness': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'amsdu': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-addr': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ap-sniffer-bufsize': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ap-sniffer-chan': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ap-sniffer-ctl': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-data': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-mgmt-beacon': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-mgmt-other': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-mgmt-probe': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auto-power-high': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'auto-power-level': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auto-power-low': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'auto-power-target': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'band': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                '802.11b', '802.11a', '802.11g', '802.11n', '802.11ac', '802.11n-5G', '802.11ax-5G', '802.11ax', '802.11ac-2G',
                                '802.11g-only', '802.11n-only', '802.11n,g-only', '802.11ac-only', '802.11ac,n-only', '802.11n-5G-only',
                                '802.11ax-5G-only', '802.11ax,ac-only', '802.11ax,ac,n-only', '802.11ax-only', '802.11ax,n-only', '802.11ax,n,g-only',
                                '802.11ax-6G', '802.11n-2G', '802.11ac-5G', '802.11ax-2G', '802.11be-2G', '802.11be-5G', '802.11be-6G'
                            ],
                            'type': 'str'
                        },
                        'band-5g-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['5g-full', '5g-high', '5g-low'], 'type': 'str'},
                        'bandwidth-admission-control': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bandwidth-capacity': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'beacon-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'bss-color': {'v_range': [['6.4.5', '']], 'type': 'int'},
                        'call-admission-control': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'call-capacity': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'channel': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'channel-bonding': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', '80MHz', '40MHz', '20MHz', '160MHz', '320MHz', '240MHz'],
                            'type': 'str'
                        },
                        'channel-utilization': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'coexistence': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'darrp': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'drma': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'drma-sensitivity': {'v_range': [['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'dtim': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'frag-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'max-clients': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'max-distance': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disabled', 'ap', 'monitor', 'sniffer', 'sam'],
                            'type': 'str'
                        },
                        'power-level': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'powersave-optimize': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['tim', 'ac-vo', 'no-obss-scan', 'no-11b-rate', 'client-rate-follow'],
                            'elements': 'str'
                        },
                        'protection-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['rtscts', 'ctsonly', 'disable'], 'type': 'str'},
                        'radio-id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'rts-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'short-guard-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'spectrum-analysis': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'scan-only'],
                            'type': 'str'
                        },
                        'transmit-optimize': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['disable', 'power-save', 'aggr-limit', 'retry-limit', 'send-bar'],
                            'elements': 'str'
                        },
                        'vap-all': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'tunnel', 'bridge', 'manual'],
                            'type': 'str'
                        },
                        'vap1': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap2': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap3': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap4': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap5': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap6': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap7': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap8': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vaps': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'wids-profile': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'zero-wait-dfs': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'frequency-handoff': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-handoff': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'iperf-protocol': {'v_range': [['7.0.0', '']], 'choices': ['udp', 'tcp'], 'type': 'str'},
                        'iperf-server-port': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'power-mode': {'v_range': [['7.0.0', '']], 'choices': ['dBm', 'percentage'], 'type': 'str'},
                        'power-value': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'sam-bssid': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'sam-captive-portal': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sam-password': {'v_range': [['7.0.0', '']], 'no_log': True, 'type': 'raw'},
                        'sam-report-intv': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'sam-security-type': {
                            'v_range': [['7.0.0', '']],
                            'choices': ['open', 'wpa-personal', 'wpa-enterprise', 'owe', 'wpa3-sae'],
                            'type': 'str'
                        },
                        'sam-server': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'sam-ssid': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'sam-test': {'v_range': [['7.0.0', '']], 'choices': ['ping', 'iperf'], 'type': 'str'},
                        'sam-username': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'arrp-profile': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'bss-color-mode': {'v_range': [['7.0.2', '']], 'choices': ['auto', 'static'], 'type': 'str'},
                        'sam-cwp-failure-string': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-match-string': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-password': {'v_range': [['7.0.1', '']], 'no_log': True, 'type': 'raw'},
                        'sam-cwp-success-string': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-test-url': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-username': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-server-fqdn': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-server-ip': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-server-type': {'v_range': [['7.0.1', '']], 'choices': ['ip', 'fqdn'], 'type': 'str'},
                        '80211d': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'optional-antenna': {
                            'v_range': [['7.2.3', '']],
                            'choices': [
                                'none', 'FANT-04ABGN-0606-O-N', 'FANT-04ABGN-1414-P-N', 'FANT-04ABGN-8065-P-N', 'FANT-04ABGN-0606-O-R',
                                'FANT-04ABGN-0606-P-R', 'FANT-10ACAX-1213-D-N', 'FANT-08ABGN-1213-D-R', 'custom'
                            ],
                            'type': 'str'
                        },
                        'mimo-mode': {'v_range': [['7.4.1', '']], 'choices': ['default', '1x1', '2x2', '3x3', '4x4', '8x8'], 'type': 'str'},
                        'optional-antenna-gain': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'sam-ca-certificate': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'sam-client-certificate': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'sam-eap-method': {'v_range': [['7.4.2', '']], 'choices': ['tls', 'peap', 'both'], 'type': 'str'},
                        'sam-private-key': {'v_range': [['7.4.2', '']], 'no_log': True, 'type': 'str'},
                        'sam-private-key-password': {'v_range': [['7.4.2', '']], 'no_log': True, 'type': 'raw'},
                        'channel-bonding-ext': {'v_range': [['7.4.3', '']], 'choices': ['320MHz-1', '320MHz-2'], 'type': 'str'},
                        '80211mc': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-chan-width': {
                            'v_range': [['7.4.4', '']],
                            'choices': ['320MHz', '240MHz', '160MHz', '80MHz', '40MHz', '20MHz'],
                            'type': 'str'
                        }
                    }
                },
                'radio-2': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'airtime-fairness': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'amsdu': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-addr': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ap-sniffer-bufsize': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ap-sniffer-chan': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ap-sniffer-ctl': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-data': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-mgmt-beacon': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-mgmt-other': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-mgmt-probe': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auto-power-high': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'auto-power-level': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auto-power-low': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'auto-power-target': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'band': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                '802.11b', '802.11a', '802.11g', '802.11n', '802.11ac', '802.11n-5G', '802.11ax-5G', '802.11ax', '802.11ac-2G',
                                '802.11g-only', '802.11n-only', '802.11n,g-only', '802.11ac-only', '802.11ac,n-only', '802.11n-5G-only',
                                '802.11ax-5G-only', '802.11ax,ac-only', '802.11ax,ac,n-only', '802.11ax-only', '802.11ax,n-only', '802.11ax,n,g-only',
                                '802.11ax-6G', '802.11n-2G', '802.11ac-5G', '802.11ax-2G', '802.11be-2G', '802.11be-5G', '802.11be-6G'
                            ],
                            'type': 'str'
                        },
                        'band-5g-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['5g-full', '5g-high', '5g-low'], 'type': 'str'},
                        'bandwidth-admission-control': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bandwidth-capacity': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'beacon-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'bss-color': {'v_range': [['6.4.5', '']], 'type': 'int'},
                        'call-admission-control': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'call-capacity': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'channel': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'channel-bonding': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', '80MHz', '40MHz', '20MHz', '160MHz', '320MHz', '240MHz'],
                            'type': 'str'
                        },
                        'channel-utilization': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'coexistence': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'darrp': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'drma': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'drma-sensitivity': {'v_range': [['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'dtim': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'frag-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'max-clients': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'max-distance': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disabled', 'ap', 'monitor', 'sniffer', 'sam'],
                            'type': 'str'
                        },
                        'power-level': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'powersave-optimize': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['tim', 'ac-vo', 'no-obss-scan', 'no-11b-rate', 'client-rate-follow'],
                            'elements': 'str'
                        },
                        'protection-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['rtscts', 'ctsonly', 'disable'], 'type': 'str'},
                        'radio-id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'rts-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'short-guard-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'spectrum-analysis': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'scan-only'],
                            'type': 'str'
                        },
                        'transmit-optimize': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['disable', 'power-save', 'aggr-limit', 'retry-limit', 'send-bar'],
                            'elements': 'str'
                        },
                        'vap-all': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'tunnel', 'bridge', 'manual'],
                            'type': 'str'
                        },
                        'vap1': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap2': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap3': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap4': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap5': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap6': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap7': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap8': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vaps': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'wids-profile': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'zero-wait-dfs': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'frequency-handoff': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-handoff': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'iperf-protocol': {'v_range': [['7.0.0', '']], 'choices': ['udp', 'tcp'], 'type': 'str'},
                        'iperf-server-port': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'power-mode': {'v_range': [['7.0.0', '']], 'choices': ['dBm', 'percentage'], 'type': 'str'},
                        'power-value': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'sam-bssid': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'sam-captive-portal': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sam-password': {'v_range': [['7.0.0', '']], 'no_log': True, 'type': 'raw'},
                        'sam-report-intv': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'sam-security-type': {
                            'v_range': [['7.0.0', '']],
                            'choices': ['open', 'wpa-personal', 'wpa-enterprise', 'owe', 'wpa3-sae'],
                            'type': 'str'
                        },
                        'sam-server': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'sam-ssid': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'sam-test': {'v_range': [['7.0.0', '']], 'choices': ['ping', 'iperf'], 'type': 'str'},
                        'sam-username': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'arrp-profile': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'bss-color-mode': {'v_range': [['7.0.2', '']], 'choices': ['auto', 'static'], 'type': 'str'},
                        'sam-cwp-failure-string': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-match-string': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-password': {'v_range': [['7.0.1', '']], 'no_log': True, 'type': 'raw'},
                        'sam-cwp-success-string': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-test-url': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-username': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-server-fqdn': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-server-ip': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-server-type': {'v_range': [['7.0.1', '']], 'choices': ['ip', 'fqdn'], 'type': 'str'},
                        '80211d': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'optional-antenna': {
                            'v_range': [['7.2.3', '']],
                            'choices': [
                                'none', 'FANT-04ABGN-0606-O-N', 'FANT-04ABGN-1414-P-N', 'FANT-04ABGN-8065-P-N', 'FANT-04ABGN-0606-O-R',
                                'FANT-04ABGN-0606-P-R', 'FANT-10ACAX-1213-D-N', 'FANT-08ABGN-1213-D-R', 'custom'
                            ],
                            'type': 'str'
                        },
                        'mimo-mode': {'v_range': [['7.4.1', '']], 'choices': ['default', '1x1', '2x2', '3x3', '4x4', '8x8'], 'type': 'str'},
                        'optional-antenna-gain': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'sam-ca-certificate': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'sam-client-certificate': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'sam-eap-method': {'v_range': [['7.4.2', '']], 'choices': ['tls', 'peap', 'both'], 'type': 'str'},
                        'sam-private-key': {'v_range': [['7.4.2', '']], 'no_log': True, 'type': 'str'},
                        'sam-private-key-password': {'v_range': [['7.4.2', '']], 'no_log': True, 'type': 'raw'},
                        'channel-bonding-ext': {'v_range': [['7.4.3', '']], 'choices': ['320MHz-1', '320MHz-2'], 'type': 'str'},
                        '80211mc': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-chan-width': {
                            'v_range': [['7.4.4', '']],
                            'choices': ['320MHz', '240MHz', '160MHz', '80MHz', '40MHz', '20MHz'],
                            'type': 'str'
                        }
                    }
                },
                'radio-3': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'airtime-fairness': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'amsdu': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-addr': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ap-sniffer-bufsize': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ap-sniffer-chan': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ap-sniffer-ctl': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-data': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-mgmt-beacon': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-mgmt-other': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-mgmt-probe': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auto-power-high': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'auto-power-level': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auto-power-low': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'auto-power-target': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'band': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                '802.11b', '802.11a', '802.11g', '802.11n', '802.11ac', '802.11n-5G', '802.11ax-5G', '802.11ax', '802.11ac-2G',
                                '802.11g-only', '802.11n-only', '802.11n,g-only', '802.11ac-only', '802.11ac,n-only', '802.11n-5G-only',
                                '802.11ax-5G-only', '802.11ax,ac-only', '802.11ax,ac,n-only', '802.11ax-only', '802.11ax,n-only', '802.11ax,n,g-only',
                                '802.11ax-6G', '802.11n-2G', '802.11ac-5G', '802.11ax-2G', '802.11be-2G', '802.11be-5G', '802.11be-6G'
                            ],
                            'type': 'str'
                        },
                        'band-5g-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['5g-full', '5g-high', '5g-low'], 'type': 'str'},
                        'bandwidth-admission-control': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bandwidth-capacity': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'beacon-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'bss-color': {'v_range': [['6.4.5', '']], 'type': 'int'},
                        'call-admission-control': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'call-capacity': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'channel': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'channel-bonding': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['80MHz', '40MHz', '20MHz', '160MHz', '320MHz', '240MHz'],
                            'type': 'str'
                        },
                        'channel-utilization': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'coexistence': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'darrp': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'drma': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'drma-sensitivity': {'v_range': [['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'dtim': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'frag-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'max-clients': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'max-distance': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disabled', 'ap', 'monitor', 'sniffer', 'sam'],
                            'type': 'str'
                        },
                        'power-level': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'powersave-optimize': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['tim', 'ac-vo', 'no-obss-scan', 'no-11b-rate', 'client-rate-follow'],
                            'elements': 'str'
                        },
                        'protection-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['rtscts', 'ctsonly', 'disable'], 'type': 'str'},
                        'radio-id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'rts-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'short-guard-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'spectrum-analysis': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'scan-only'],
                            'type': 'str'
                        },
                        'transmit-optimize': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['disable', 'power-save', 'aggr-limit', 'retry-limit', 'send-bar'],
                            'elements': 'str'
                        },
                        'vap-all': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'tunnel', 'bridge', 'manual'],
                            'type': 'str'
                        },
                        'vap1': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap2': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap3': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap4': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap5': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap6': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap7': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap8': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vaps': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'wids-profile': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'zero-wait-dfs': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'frequency-handoff': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-handoff': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'iperf-protocol': {'v_range': [['7.0.0', '']], 'choices': ['udp', 'tcp'], 'type': 'str'},
                        'iperf-server-port': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'power-mode': {'v_range': [['7.0.0', '']], 'choices': ['dBm', 'percentage'], 'type': 'str'},
                        'power-value': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'sam-bssid': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'sam-captive-portal': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sam-password': {'v_range': [['7.0.0', '']], 'no_log': True, 'type': 'raw'},
                        'sam-report-intv': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'sam-security-type': {
                            'v_range': [['7.0.0', '']],
                            'choices': ['open', 'wpa-personal', 'wpa-enterprise', 'owe', 'wpa3-sae'],
                            'type': 'str'
                        },
                        'sam-server': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'sam-ssid': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'sam-test': {'v_range': [['7.0.0', '']], 'choices': ['ping', 'iperf'], 'type': 'str'},
                        'sam-username': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'arrp-profile': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'bss-color-mode': {'v_range': [['7.0.2', '']], 'choices': ['auto', 'static'], 'type': 'str'},
                        'sam-cwp-failure-string': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-match-string': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-password': {'v_range': [['7.0.1', '']], 'no_log': True, 'type': 'raw'},
                        'sam-cwp-success-string': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-test-url': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-username': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-server-fqdn': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-server-ip': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-server-type': {'v_range': [['7.0.1', '']], 'choices': ['ip', 'fqdn'], 'type': 'str'},
                        '80211d': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'optional-antenna': {
                            'v_range': [['7.2.3', '']],
                            'choices': [
                                'none', 'FANT-04ABGN-0606-O-N', 'FANT-04ABGN-1414-P-N', 'FANT-04ABGN-8065-P-N', 'FANT-04ABGN-0606-O-R',
                                'FANT-04ABGN-0606-P-R', 'FANT-10ACAX-1213-D-N', 'FANT-08ABGN-1213-D-R', 'custom'
                            ],
                            'type': 'str'
                        },
                        'mimo-mode': {'v_range': [['7.4.1', '']], 'choices': ['default', '1x1', '2x2', '3x3', '4x4', '8x8'], 'type': 'str'},
                        'optional-antenna-gain': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'sam-ca-certificate': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'sam-client-certificate': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'sam-eap-method': {'v_range': [['7.4.2', '']], 'choices': ['tls', 'peap', 'both'], 'type': 'str'},
                        'sam-private-key': {'v_range': [['7.4.2', '']], 'no_log': True, 'type': 'str'},
                        'sam-private-key-password': {'v_range': [['7.4.2', '']], 'no_log': True, 'type': 'raw'},
                        'channel-bonding-ext': {'v_range': [['7.4.3', '']], 'choices': ['320MHz-1', '320MHz-2'], 'type': 'str'},
                        '80211mc': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-chan-width': {
                            'v_range': [['7.4.4', '']],
                            'choices': ['320MHz', '240MHz', '160MHz', '80MHz', '40MHz', '20MHz'],
                            'type': 'str'
                        }
                    }
                },
                'radio-4': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'airtime-fairness': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'amsdu': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-addr': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'ap-sniffer-bufsize': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ap-sniffer-chan': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ap-sniffer-ctl': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-data': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-mgmt-beacon': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-mgmt-other': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-mgmt-probe': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auto-power-high': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'auto-power-level': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auto-power-low': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'auto-power-target': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'band': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': [
                                '802.11b', '802.11a', '802.11g', '802.11n', '802.11ac', '802.11n-5G', '802.11ax-5G', '802.11ax', '802.11ac-2G',
                                '802.11g-only', '802.11n-only', '802.11n,g-only', '802.11ac-only', '802.11ac,n-only', '802.11n-5G-only',
                                '802.11ax-5G-only', '802.11ax,ac-only', '802.11ax,ac,n-only', '802.11ax-only', '802.11ax,n-only', '802.11ax,n,g-only',
                                '802.11ax-6G', '802.11n-2G', '802.11ac-5G', '802.11ax-2G', '802.11be-2G', '802.11be-5G', '802.11be-6G'
                            ],
                            'type': 'str'
                        },
                        'band-5g-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['5g-full', '5g-high', '5g-low'], 'type': 'str'},
                        'bandwidth-admission-control': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bandwidth-capacity': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'beacon-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'bss-color': {'v_range': [['6.4.5', '']], 'type': 'int'},
                        'call-admission-control': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'call-capacity': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'channel': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'channel-bonding': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['80MHz', '40MHz', '20MHz', '160MHz', '320MHz', '240MHz'],
                            'type': 'str'
                        },
                        'channel-utilization': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'coexistence': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'darrp': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'drma': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'drma-sensitivity': {'v_range': [['6.4.5', '']], 'choices': ['low', 'medium', 'high'], 'type': 'str'},
                        'dtim': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'frag-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'max-clients': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'max-distance': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mode': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['ap', 'monitor', 'sniffer', 'disabled', 'sam'],
                            'type': 'str'
                        },
                        'power-level': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'powersave-optimize': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['tim', 'ac-vo', 'no-obss-scan', 'no-11b-rate', 'client-rate-follow'],
                            'elements': 'str'
                        },
                        'protection-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['rtscts', 'ctsonly', 'disable'], 'type': 'str'},
                        'radio-id': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'rts-threshold': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'short-guard-interval': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'spectrum-analysis': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'scan-only'],
                            'type': 'str'
                        },
                        'transmit-optimize': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['disable', 'power-save', 'aggr-limit', 'retry-limit', 'send-bar'],
                            'elements': 'str'
                        },
                        'vap-all': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'tunnel', 'bridge', 'manual'],
                            'type': 'str'
                        },
                        'vap1': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap2': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap3': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap4': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap5': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap6': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap7': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vap8': {'v_range': [['6.4.5', '']], 'type': 'str'},
                        'vaps': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'wids-profile': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'zero-wait-dfs': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'frequency-handoff': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-handoff': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'iperf-protocol': {'v_range': [['7.0.0', '']], 'choices': ['udp', 'tcp'], 'type': 'str'},
                        'iperf-server-port': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'power-mode': {'v_range': [['7.0.0', '']], 'choices': ['dBm', 'percentage'], 'type': 'str'},
                        'power-value': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'sam-bssid': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'sam-captive-portal': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sam-password': {'v_range': [['7.0.0', '']], 'no_log': True, 'type': 'raw'},
                        'sam-report-intv': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'sam-security-type': {
                            'v_range': [['7.0.0', '']],
                            'choices': ['open', 'wpa-personal', 'wpa-enterprise', 'owe', 'wpa3-sae'],
                            'type': 'str'
                        },
                        'sam-server': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'sam-ssid': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'sam-test': {'v_range': [['7.0.0', '']], 'choices': ['ping', 'iperf'], 'type': 'str'},
                        'sam-username': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'arrp-profile': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'bss-color-mode': {'v_range': [['7.0.2', '']], 'choices': ['auto', 'static'], 'type': 'str'},
                        'sam-cwp-failure-string': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-match-string': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-password': {'v_range': [['7.0.1', '']], 'no_log': True, 'type': 'raw'},
                        'sam-cwp-success-string': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-test-url': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-cwp-username': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-server-fqdn': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-server-ip': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sam-server-type': {'v_range': [['7.0.1', '']], 'choices': ['ip', 'fqdn'], 'type': 'str'},
                        '80211d': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'optional-antenna': {
                            'v_range': [['7.2.3', '']],
                            'choices': [
                                'none', 'FANT-04ABGN-0606-O-N', 'FANT-04ABGN-1414-P-N', 'FANT-04ABGN-8065-P-N', 'FANT-04ABGN-0606-O-R',
                                'FANT-04ABGN-0606-P-R', 'FANT-10ACAX-1213-D-N', 'FANT-08ABGN-1213-D-R', 'custom'
                            ],
                            'type': 'str'
                        },
                        'mimo-mode': {'v_range': [['7.4.1', '']], 'choices': ['default', '1x1', '2x2', '3x3', '4x4', '8x8'], 'type': 'str'},
                        'optional-antenna-gain': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'sam-ca-certificate': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'sam-client-certificate': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'sam-eap-method': {'v_range': [['7.4.2', '']], 'choices': ['tls', 'peap', 'both'], 'type': 'str'},
                        'sam-private-key': {'v_range': [['7.4.2', '']], 'no_log': True, 'type': 'str'},
                        'sam-private-key-password': {'v_range': [['7.4.2', '']], 'no_log': True, 'type': 'raw'},
                        'channel-bonding-ext': {'v_range': [['7.4.3', '']], 'choices': ['320MHz-1', '320MHz-2'], 'type': 'str'},
                        '80211mc': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ap-sniffer-chan-width': {
                            'v_range': [['7.4.4', '']],
                            'choices': ['320MHz', '240MHz', '160MHz', '80MHz', '40MHz', '20MHz'],
                            'type': 'str'
                        }
                    }
                },
                'console-login': {'v_range': [['6.2.9', '6.2.13'], ['6.4.8', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'esl-ses-dongle': {
                    'v_range': [['7.0.1', '']],
                    'type': 'dict',
                    'options': {
                        'apc-addr-type': {'v_range': [['7.0.1', '']], 'choices': ['fqdn', 'ip'], 'type': 'str'},
                        'apc-fqdn': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'apc-ip': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'apc-port': {'v_range': [['7.0.1', '']], 'type': 'int'},
                        'coex-level': {'v_range': [['7.0.1', '']], 'choices': ['none'], 'type': 'str'},
                        'compliance-level': {'v_range': [['7.0.1', '']], 'choices': ['compliance-level-2'], 'type': 'str'},
                        'esl-channel': {
                            'v_range': [['7.0.1', '']],
                            'choices': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '127', '-1'],
                            'type': 'str'
                        },
                        'output-power': {'v_range': [['7.0.1', '']], 'choices': ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'], 'type': 'str'},
                        'scd-enable': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tls-cert-verification': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tls-fqdn-verification': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'indoor-outdoor-deployment': {'v_range': [['7.0.1', '']], 'choices': ['platform-determined', 'outdoor', 'indoor'], 'type': 'str'},
                'syslog-profile': {'v_range': [['7.0.2', '']], 'type': 'str'},
                'wan-port-auth': {'v_range': [['7.0.2', '']], 'choices': ['none', '802.1x'], 'type': 'str'},
                'wan-port-auth-methods': {'v_range': [['7.0.2', '']], 'choices': ['all', 'EAP-FAST', 'EAP-TLS', 'EAP-PEAP'], 'type': 'str'},
                'wan-port-auth-password': {'v_range': [['7.0.2', '']], 'no_log': True, 'type': 'raw'},
                'wan-port-auth-usrname': {'v_range': [['7.0.2', '']], 'type': 'str'},
                '_is_factory_setting': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable', 'ext'], 'type': 'str'},
                'unii-4-5ghz-band': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bonjour-profile': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'wan-port-auth-macsec': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'usb-port': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-auth-tacacs+': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                'admin-restrict-local': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wtpprofile'),
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
