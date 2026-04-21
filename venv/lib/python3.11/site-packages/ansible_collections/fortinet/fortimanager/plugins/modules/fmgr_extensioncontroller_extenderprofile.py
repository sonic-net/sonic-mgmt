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
module: fmgr_extensioncontroller_extenderprofile
short_description: FortiExtender extender profile configuration.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    extensioncontroller_extenderprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            allowaccess:
                type: list
                elements: str
                description: Control management access to the managed extender.
                choices:
                    - 'https'
                    - 'ping'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
            bandwidth_limit:
                aliases: ['bandwidth-limit']
                type: int
                description: FortiExtender LAN extension bandwidth limit
            cellular:
                type: dict
                description: Cellular.
                suboptions:
                    controller_report:
                        aliases: ['controller-report']
                        type: dict
                        description: Controller report.
                        suboptions:
                            interval:
                                type: int
                                description: Controller report interval.
                            signal_threshold:
                                aliases: ['signal-threshold']
                                type: int
                                description: Controller report signal threshold.
                            status:
                                type: str
                                description: FortiExtender controller report status.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    dataplan:
                        type: raw
                        description: (list) Dataplan names.
                    modem1:
                        type: dict
                        description: Modem1.
                        suboptions:
                            auto_switch:
                                aliases: ['auto-switch']
                                type: dict
                                description: Auto switch.
                                suboptions:
                                    dataplan:
                                        type: str
                                        description: Automatically switch based on data usage.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect:
                                        type: str
                                        description: Auto switch by disconnect.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect_period:
                                        aliases: ['disconnect-period']
                                        type: int
                                        description: Automatically switch based on disconnect period.
                                    disconnect_threshold:
                                        aliases: ['disconnect-threshold']
                                        type: int
                                        description: Automatically switch based on disconnect threshold.
                                    signal:
                                        type: str
                                        description: Automatically switch based on signal strength.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    switch_back:
                                        aliases: ['switch-back']
                                        type: list
                                        elements: str
                                        description: Auto switch with switch back multi-options.
                                        choices:
                                            - 'time'
                                            - 'timer'
                                    switch_back_time:
                                        aliases: ['switch-back-time']
                                        type: str
                                        description: Automatically switch over to preferred SIM/carrier at a specified time in UTC
                                    switch_back_timer:
                                        aliases: ['switch-back-timer']
                                        type: int
                                        description: Automatically switch over to preferred SIM/carrier after the given time
                            conn_status:
                                aliases: ['conn-status']
                                type: int
                                description: Conn status.
                            default_sim:
                                aliases: ['default-sim']
                                type: str
                                description: Default SIM selection.
                                choices:
                                    - 'sim1'
                                    - 'sim2'
                                    - 'carrier'
                                    - 'cost'
                            gps:
                                type: str
                                description: FortiExtender GPS enable/disable.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            modem_id:
                                aliases: ['modem-id']
                                type: int
                                description: Modem ID.
                            preferred_carrier:
                                aliases: ['preferred-carrier']
                                type: str
                                description: Preferred carrier.
                            redundant_intf:
                                aliases: ['redundant-intf']
                                type: str
                                description: Redundant interface.
                            redundant_mode:
                                aliases: ['redundant-mode']
                                type: str
                                description: FortiExtender mode.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1_pin:
                                aliases: ['sim1-pin']
                                type: str
                                description: SIM #1 PIN status.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1_pin_code:
                                aliases: ['sim1-pin-code']
                                type: raw
                                description: (list) SIM #1 PIN password.
                            sim2_pin:
                                aliases: ['sim2-pin']
                                type: str
                                description: SIM #2 PIN status.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim2_pin_code:
                                aliases: ['sim2-pin-code']
                                type: raw
                                description: (list) SIM #2 PIN password.
                            multiple_PDN:
                                aliases: ['multiple-PDN']
                                type: str
                                description: Multiple-PDN enable/disable.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            pdn1_dataplan:
                                aliases: ['pdn1-dataplan']
                                type: raw
                                description: (list) PDN1-dataplan.
                            pdn2_dataplan:
                                aliases: ['pdn2-dataplan']
                                type: raw
                                description: (list) PDN2-dataplan.
                            pdn3_dataplan:
                                aliases: ['pdn3-dataplan']
                                type: raw
                                description: (list) PDN3-dataplan.
                            pdn4_dataplan:
                                aliases: ['pdn4-dataplan']
                                type: raw
                                description: (list) PDN4-dataplan.
                    modem2:
                        type: dict
                        description: Modem2.
                        suboptions:
                            auto_switch:
                                aliases: ['auto-switch']
                                type: dict
                                description: Auto switch.
                                suboptions:
                                    dataplan:
                                        type: str
                                        description: Automatically switch based on data usage.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect:
                                        type: str
                                        description: Auto switch by disconnect.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect_period:
                                        aliases: ['disconnect-period']
                                        type: int
                                        description: Automatically switch based on disconnect period.
                                    disconnect_threshold:
                                        aliases: ['disconnect-threshold']
                                        type: int
                                        description: Automatically switch based on disconnect threshold.
                                    signal:
                                        type: str
                                        description: Automatically switch based on signal strength.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    switch_back:
                                        aliases: ['switch-back']
                                        type: list
                                        elements: str
                                        description: Auto switch with switch back multi-options.
                                        choices:
                                            - 'time'
                                            - 'timer'
                                    switch_back_time:
                                        aliases: ['switch-back-time']
                                        type: str
                                        description: Automatically switch over to preferred SIM/carrier at a specified time in UTC
                                    switch_back_timer:
                                        aliases: ['switch-back-timer']
                                        type: int
                                        description: Automatically switch over to preferred SIM/carrier after the given time
                            conn_status:
                                aliases: ['conn-status']
                                type: int
                                description: Conn status.
                            default_sim:
                                aliases: ['default-sim']
                                type: str
                                description: Default SIM selection.
                                choices:
                                    - 'sim1'
                                    - 'sim2'
                                    - 'carrier'
                                    - 'cost'
                            gps:
                                type: str
                                description: FortiExtender GPS enable/disable.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            modem_id:
                                aliases: ['modem-id']
                                type: int
                                description: Modem ID.
                            preferred_carrier:
                                aliases: ['preferred-carrier']
                                type: str
                                description: Preferred carrier.
                            redundant_intf:
                                aliases: ['redundant-intf']
                                type: str
                                description: Redundant interface.
                            redundant_mode:
                                aliases: ['redundant-mode']
                                type: str
                                description: FortiExtender mode.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1_pin:
                                aliases: ['sim1-pin']
                                type: str
                                description: SIM #1 PIN status.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1_pin_code:
                                aliases: ['sim1-pin-code']
                                type: raw
                                description: (list) SIM #1 PIN password.
                            sim2_pin:
                                aliases: ['sim2-pin']
                                type: str
                                description: SIM #2 PIN status.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim2_pin_code:
                                aliases: ['sim2-pin-code']
                                type: raw
                                description: (list) SIM #2 PIN password.
                            multiple_PDN:
                                aliases: ['multiple-PDN']
                                type: str
                                description: Multiple-PDN enable/disable.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            pdn1_dataplan:
                                aliases: ['pdn1-dataplan']
                                type: raw
                                description: (list) PDN1-dataplan.
                            pdn2_dataplan:
                                aliases: ['pdn2-dataplan']
                                type: raw
                                description: (list) PDN2-dataplan.
                            pdn3_dataplan:
                                aliases: ['pdn3-dataplan']
                                type: raw
                                description: (list) PDN3-dataplan.
                            pdn4_dataplan:
                                aliases: ['pdn4-dataplan']
                                type: raw
                                description: (list) PDN4-dataplan.
                    sms_notification:
                        aliases: ['sms-notification']
                        type: dict
                        description: Sms notification.
                        suboptions:
                            alert:
                                type: dict
                                description: Alert.
                                suboptions:
                                    data_exhausted:
                                        aliases: ['data-exhausted']
                                        type: str
                                        description: Display string when data exhausted.
                                    fgt_backup_mode_switch:
                                        aliases: ['fgt-backup-mode-switch']
                                        type: str
                                        description: Display string when FortiGate backup mode switched.
                                    low_signal_strength:
                                        aliases: ['low-signal-strength']
                                        type: str
                                        description: Display string when signal strength is low.
                                    mode_switch:
                                        aliases: ['mode-switch']
                                        type: str
                                        description: Display string when mode is switched.
                                    os_image_fallback:
                                        aliases: ['os-image-fallback']
                                        type: str
                                        description: Display string when falling back to a previous OS image.
                                    session_disconnect:
                                        aliases: ['session-disconnect']
                                        type: str
                                        description: Display string when session disconnected.
                                    system_reboot:
                                        aliases: ['system-reboot']
                                        type: str
                                        description: Display string when system rebooted.
                            receiver:
                                type: list
                                elements: dict
                                description: Receiver.
                                suboptions:
                                    alert:
                                        type: list
                                        elements: str
                                        description: Alert multi-options.
                                        choices:
                                            - 'system-reboot'
                                            - 'data-exhausted'
                                            - 'session-disconnect'
                                            - 'low-signal-strength'
                                            - 'mode-switch'
                                            - 'os-image-fallback'
                                            - 'fgt-backup-mode-switch'
                                    name:
                                        type: str
                                        description: FortiExtender SMS notification receiver name.
                                    phone_number:
                                        aliases: ['phone-number']
                                        type: str
                                        description: Receiver phone number.
                                    status:
                                        type: str
                                        description: SMS notification receiver status.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                            status:
                                type: str
                                description: FortiExtender SMS notification status.
                                choices:
                                    - 'disable'
                                    - 'enable'
            enforce_bandwidth:
                aliases: ['enforce-bandwidth']
                type: str
                description: Enable/disable enforcement of bandwidth on LAN extension interface.
                choices:
                    - 'disable'
                    - 'enable'
            extension:
                type: str
                description: Extension option.
                choices:
                    - 'wan-extension'
                    - 'lan-extension'
            id:
                type: int
                description: ID.
                required: true
            lan_extension:
                aliases: ['lan-extension']
                type: dict
                description: Lan extension.
                suboptions:
                    backhaul:
                        type: list
                        elements: dict
                        description: Backhaul.
                        suboptions:
                            name:
                                type: str
                                description: FortiExtender LAN extension backhaul name.
                            port:
                                type: str
                                description: FortiExtender uplink port.
                                choices:
                                    - 'wan'
                                    - 'lte1'
                                    - 'lte2'
                                    - 'port1'
                                    - 'port2'
                                    - 'port3'
                                    - 'port4'
                                    - 'port5'
                                    - 'sfp'
                            role:
                                type: str
                                description: FortiExtender uplink port.
                                choices:
                                    - 'primary'
                                    - 'secondary'
                            weight:
                                type: int
                                description: WRR weight parameter.
                    backhaul_interface:
                        aliases: ['backhaul-interface']
                        type: str
                        description: IPsec phase1 interface.
                    backhaul_ip:
                        aliases: ['backhaul-ip']
                        type: str
                        description: IPsec phase1 IPv4/FQDN.
                    ipsec_tunnel:
                        aliases: ['ipsec-tunnel']
                        type: str
                        description: IPsec tunnel name.
                    link_loadbalance:
                        aliases: ['link-loadbalance']
                        type: str
                        description: LAN extension link load balance strategy.
                        choices:
                            - 'activebackup'
                            - 'loadbalance'
                    downlinks:
                        type: list
                        elements: dict
                        description: Downlinks.
                        suboptions:
                            name:
                                type: str
                                description: FortiExtender LAN extension downlink config entry name.
                            port:
                                type: str
                                description: FortiExtender LAN extension downlink port.
                                choices:
                                    - 'port1'
                                    - 'port2'
                                    - 'port3'
                                    - 'port4'
                                    - 'port5'
                                    - 'lan1'
                                    - 'lan2'
                            pvid:
                                type: int
                                description: FortiExtender LAN extension downlink PVID.
                            type:
                                type: str
                                description: FortiExtender LAN extension downlink type [port/vap].
                                choices:
                                    - 'port'
                                    - 'vap'
                            vap:
                                type: raw
                                description: (list) FortiExtender LAN extension downlink vap.
                    traffic_split_services:
                        aliases: ['traffic-split-services']
                        type: list
                        elements: dict
                        description: Traffic split services.
                        suboptions:
                            address:
                                type: raw
                                description: (list) Address selection.
                            name:
                                type: str
                                description: FortiExtender LAN extension tunnel split entry name.
                            service:
                                type: raw
                                description: (list) Service selection.
                            vsdb:
                                type: str
                                description: Select vsdb [enable/disable].
                                choices:
                                    - 'disable'
                                    - 'enable'
            login_password:
                aliases: ['login-password']
                type: raw
                description: (list) Set the managed extenders administrator password.
            login_password_change:
                aliases: ['login-password-change']
                type: str
                description: Change or reset the administrator password of a managed extender
                choices:
                    - 'no'
                    - 'yes'
                    - 'default'
            model:
                type: str
                description: Model.
                choices:
                    - 'FX201E'
                    - 'FX211E'
                    - 'FX200F'
                    - 'FXA11F'
                    - 'FXE11F'
                    - 'FXA21F'
                    - 'FXE21F'
                    - 'FXA22F'
                    - 'FXE22F'
                    - 'FX212F'
                    - 'FX311F'
                    - 'FX312F'
                    - 'FX511F'
                    - 'FVG21F'
                    - 'FVA21F'
                    - 'FVG22F'
                    - 'FVA22F'
                    - 'FX04DA'
                    - 'FX04DN'
                    - 'FX04DI'
                    - 'FXR51G'
                    - 'FG'
                    - 'BS10FW'
                    - 'BS20GW'
                    - 'BS20GN'
                    - 'FXN51G'
                    - 'FXW51G'
                    - 'FVG51G'
                    - 'FXE11G'
            name:
                type: str
                description: FortiExtender profile name.
            _is_factory_setting:
                type: str
                description: Is factory setting.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'ext'
            wifi:
                type: dict
                description: Wifi.
                suboptions:
                    DFS:
                        type: str
                        description: Wi-Fi 5G Radio DFS channel enable/disable.
                        choices:
                            - 'disable'
                            - 'enable'
                    country:
                        type: str
                        description: Country in which this FEX will operate
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
                            - 'IE'
                            - 'IL'
                            - 'IT'
                            - 'JM'
                            - 'JP'
                            - 'JO'
                            - 'KZ'
                            - 'KE'
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
                            - 'BS'
                            - 'VC'
                            - 'KH'
                            - 'MV'
                            - 'AF'
                            - 'NG'
                            - 'TZ'
                            - 'ZM'
                            - 'SN'
                            - 'CI'
                            - 'GH'
                            - 'CM'
                            - 'MW'
                            - 'AO'
                            - 'GA'
                            - 'ML'
                            - 'BJ'
                            - 'MG'
                            - 'TD'
                            - 'BW'
                            - 'LY'
                            - 'RW'
                            - 'MZ'
                            - 'GM'
                            - 'LS'
                            - 'MU'
                            - 'CG'
                            - 'UG'
                            - 'BF'
                            - 'SL'
                            - 'SO'
                            - 'CD'
                            - 'NE'
                            - 'CF'
                            - 'SZ'
                            - 'TG'
                            - 'LR'
                            - 'MR'
                            - 'DJ'
                            - 'RE'
                            - 'RS'
                            - 'ME'
                            - 'IQ'
                            - 'MD'
                            - 'KY'
                            - 'BB'
                            - 'BM'
                            - 'TC'
                            - 'VI'
                            - 'PM'
                            - 'MF'
                            - 'GD'
                            - 'IM'
                            - 'FO'
                            - 'GI'
                            - 'GL'
                            - 'TM'
                            - 'MN'
                            - 'VU'
                            - 'FJ'
                            - 'LA'
                            - 'GU'
                            - 'WF'
                            - 'MH'
                            - 'BT'
                            - 'FM'
                            - 'PF'
                            - 'NI'
                            - 'PY'
                            - 'HT'
                            - 'GY'
                            - 'AW'
                            - 'KN'
                            - 'GF'
                            - 'AS'
                            - 'MP'
                            - 'PW'
                            - 'MM'
                            - 'LC'
                            - 'GP'
                            - 'ET'
                            - 'SR'
                            - 'CX'
                            - 'DM'
                            - 'MQ'
                            - 'YT'
                            - 'BL'
                            - '--'
                            - 'TL'
                    radio_1:
                        aliases: ['radio-1']
                        type: dict
                        description: Radio 1.
                        suboptions:
                            d80211d:
                                aliases: ['80211d']
                                type: str
                                description: Enable/disable Wi-Fi 802.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            band:
                                type: str
                                description: Wi-Fi band selection 2.
                                choices:
                                    - '2.4GHz'
                            bandwidth:
                                type: str
                                description: Wi-Fi channel bandwidth.
                                choices:
                                    - 'auto'
                                    - '20MHz'
                                    - '40MHz'
                                    - '80MHz'
                            beacon_interval:
                                aliases: ['beacon-interval']
                                type: int
                                description: Wi-Fi beacon interval in miliseconds
                            bss_color:
                                aliases: ['bss-color']
                                type: int
                                description: Wi-Fi 802.
                            bss_color_mode:
                                aliases: ['bss-color-mode']
                                type: str
                                description: Wi-Fi 802.
                                choices:
                                    - 'auto'
                                    - 'static'
                            channel:
                                type: list
                                elements: str
                                description: Wi-Fi channels.
                                choices:
                                    - 'CH1'
                                    - 'CH2'
                                    - 'CH3'
                                    - 'CH4'
                                    - 'CH5'
                                    - 'CH6'
                                    - 'CH7'
                                    - 'CH8'
                                    - 'CH9'
                                    - 'CH10'
                                    - 'CH11'
                            extension_channel:
                                aliases: ['extension-channel']
                                type: str
                                description: Wi-Fi extension channel.
                                choices:
                                    - 'auto'
                                    - 'higher'
                                    - 'lower'
                            guard_interval:
                                aliases: ['guard-interval']
                                type: str
                                description: Wi-Fi guard interval.
                                choices:
                                    - 'auto'
                                    - '400ns'
                                    - '800ns'
                            lan_ext_vap:
                                aliases: ['lan-ext-vap']
                                type: raw
                                description: (list) Wi-Fi LAN-Extention VAP.
                            local_vaps:
                                aliases: ['local-vaps']
                                type: raw
                                description: (list) Wi-Fi local VAP.
                            max_clients:
                                aliases: ['max-clients']
                                type: int
                                description: Maximum number of Wi-Fi radio clients
                            mode:
                                type: str
                                description: Wi-Fi radio mode AP
                                choices:
                                    - 'AP'
                                    - 'Client'
                            operating_standard:
                                aliases: ['operating-standard']
                                type: str
                                description: Wi-Fi operating standard.
                                choices:
                                    - 'auto'
                                    - '11A-N-AC-AX'
                                    - '11A-N-AC'
                                    - '11A-N'
                                    - '11A'
                                    - '11N-AC-AX'
                                    - '11AC-AX'
                                    - '11AC'
                                    - '11N-AC'
                                    - '11B-G-N-AX'
                                    - '11B-G-N'
                                    - '11B-G'
                                    - '11B'
                                    - '11G-N-AX'
                                    - '11N-AX'
                                    - '11AX'
                                    - '11G-N'
                                    - '11N'
                                    - '11G'
                            power_level:
                                aliases: ['power-level']
                                type: int
                                description: Wi-Fi power level in percent
                            radio_id:
                                aliases: ['radio-id']
                                type: int
                                description: Radio ID.
                            status:
                                type: str
                                description: Enable/disable Wi-Fi radio.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    radio_2:
                        aliases: ['radio-2']
                        type: dict
                        description: Radio 2.
                        suboptions:
                            d80211d:
                                aliases: ['80211d']
                                type: str
                                description: Enable/disable Wi-Fi 802.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            band:
                                type: str
                                description: Wi-Fi band selection 2.
                                choices:
                                    - '5GHz'
                            bandwidth:
                                type: str
                                description: Wi-Fi channel bandwidth.
                                choices:
                                    - 'auto'
                                    - '20MHz'
                                    - '40MHz'
                                    - '80MHz'
                            beacon_interval:
                                aliases: ['beacon-interval']
                                type: int
                                description: Wi-Fi beacon interval in miliseconds
                            bss_color:
                                aliases: ['bss-color']
                                type: int
                                description: Wi-Fi 802.
                            bss_color_mode:
                                aliases: ['bss-color-mode']
                                type: str
                                description: Wi-Fi 802.
                                choices:
                                    - 'auto'
                                    - 'static'
                            channel:
                                type: list
                                elements: str
                                description: Wi-Fi channels.
                                choices:
                                    - 'CH36'
                                    - 'CH40'
                                    - 'CH44'
                                    - 'CH48'
                                    - 'CH52'
                                    - 'CH56'
                                    - 'CH60'
                                    - 'CH64'
                                    - 'CH100'
                                    - 'CH104'
                                    - 'CH108'
                                    - 'CH112'
                                    - 'CH116'
                                    - 'CH120'
                                    - 'CH124'
                                    - 'CH128'
                                    - 'CH132'
                                    - 'CH136'
                                    - 'CH140'
                                    - 'CH144'
                                    - 'CH149'
                                    - 'CH153'
                                    - 'CH157'
                                    - 'CH161'
                                    - 'CH165'
                            extension_channel:
                                aliases: ['extension-channel']
                                type: str
                                description: Wi-Fi extension channel.
                                choices:
                                    - 'auto'
                                    - 'higher'
                                    - 'lower'
                            guard_interval:
                                aliases: ['guard-interval']
                                type: str
                                description: Wi-Fi guard interval.
                                choices:
                                    - 'auto'
                                    - '400ns'
                                    - '800ns'
                            lan_ext_vap:
                                aliases: ['lan-ext-vap']
                                type: raw
                                description: (list) Wi-Fi LAN-Extention VAP.
                            local_vaps:
                                aliases: ['local-vaps']
                                type: raw
                                description: (list) Wi-Fi local VAP.
                            max_clients:
                                aliases: ['max-clients']
                                type: int
                                description: Maximum number of Wi-Fi radio clients
                            mode:
                                type: str
                                description: Wi-Fi radio mode AP
                                choices:
                                    - 'AP'
                                    - 'Client'
                            operating_standard:
                                aliases: ['operating-standard']
                                type: str
                                description: Wi-Fi operating standard.
                                choices:
                                    - 'auto'
                                    - '11A-N-AC-AX'
                                    - '11A-N-AC'
                                    - '11A-N'
                                    - '11A'
                                    - '11N-AC-AX'
                                    - '11AC-AX'
                                    - '11AC'
                                    - '11N-AC'
                                    - '11B-G-N-AX'
                                    - '11B-G-N'
                                    - '11B-G'
                                    - '11B'
                                    - '11G-N-AX'
                                    - '11N-AX'
                                    - '11AX'
                                    - '11G-N'
                                    - '11N'
                                    - '11G'
                            power_level:
                                aliases: ['power-level']
                                type: int
                                description: Wi-Fi power level in percent
                            radio_id:
                                aliases: ['radio-id']
                                type: int
                                description: Radio ID.
                            status:
                                type: str
                                description: Enable/disable Wi-Fi radio.
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
    - name: FortiExtender extender profile configuration.
      fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        extensioncontroller_extenderprofile:
          id: 0 # Required variable, integer
          # allowaccess:
          #   - "https"
          #   - "ping"
          #   - "ssh"
          #   - "snmp"
          #   - "http"
          #   - "telnet"
          # bandwidth_limit: <integer>
          # cellular:
          #   controller_report:
          #     interval: <integer>
          #     signal_threshold: <integer>
          #     status: <value in [disable, enable]>
          #   dataplan: <list or string>
          #   modem1:
          #     auto_switch:
          #       dataplan: <value in [disable, enable]>
          #       disconnect: <value in [disable, enable]>
          #       disconnect_period: <integer>
          #       disconnect_threshold: <integer>
          #       signal: <value in [disable, enable]>
          #       switch_back:
          #         - "time"
          #         - "timer"
          #       switch_back_time: <string>
          #       switch_back_timer: <integer>
          #     conn_status: <integer>
          #     default_sim: <value in [sim1, sim2, carrier, ...]>
          #     gps: <value in [disable, enable]>
          #     modem_id: <integer>
          #     preferred_carrier: <string>
          #     redundant_intf: <string>
          #     redundant_mode: <value in [disable, enable]>
          #     sim1_pin: <value in [disable, enable]>
          #     sim1_pin_code: <list or string>
          #     sim2_pin: <value in [disable, enable]>
          #     sim2_pin_code: <list or string>
          #     multiple_PDN: <value in [disable, enable]>
          #     pdn1_dataplan: <list or string>
          #     pdn2_dataplan: <list or string>
          #     pdn3_dataplan: <list or string>
          #     pdn4_dataplan: <list or string>
          #   modem2:
          #     auto_switch:
          #       dataplan: <value in [disable, enable]>
          #       disconnect: <value in [disable, enable]>
          #       disconnect_period: <integer>
          #       disconnect_threshold: <integer>
          #       signal: <value in [disable, enable]>
          #       switch_back:
          #         - "time"
          #         - "timer"
          #       switch_back_time: <string>
          #       switch_back_timer: <integer>
          #     conn_status: <integer>
          #     default_sim: <value in [sim1, sim2, carrier, ...]>
          #     gps: <value in [disable, enable]>
          #     modem_id: <integer>
          #     preferred_carrier: <string>
          #     redundant_intf: <string>
          #     redundant_mode: <value in [disable, enable]>
          #     sim1_pin: <value in [disable, enable]>
          #     sim1_pin_code: <list or string>
          #     sim2_pin: <value in [disable, enable]>
          #     sim2_pin_code: <list or string>
          #     multiple_PDN: <value in [disable, enable]>
          #     pdn1_dataplan: <list or string>
          #     pdn2_dataplan: <list or string>
          #     pdn3_dataplan: <list or string>
          #     pdn4_dataplan: <list or string>
          #   sms_notification:
          #     alert:
          #       data_exhausted: <string>
          #       fgt_backup_mode_switch: <string>
          #       low_signal_strength: <string>
          #       mode_switch: <string>
          #       os_image_fallback: <string>
          #       session_disconnect: <string>
          #       system_reboot: <string>
          #     receiver:
          #       - alert:
          #           - "system-reboot"
          #           - "data-exhausted"
          #           - "session-disconnect"
          #           - "low-signal-strength"
          #           - "mode-switch"
          #           - "os-image-fallback"
          #           - "fgt-backup-mode-switch"
          #         name: <string>
          #         phone_number: <string>
          #         status: <value in [disable, enable]>
          #     status: <value in [disable, enable]>
          # enforce_bandwidth: <value in [disable, enable]>
          # extension: <value in [wan-extension, lan-extension]>
          # lan_extension:
          #   backhaul:
          #     - name: <string>
          #       port: <value in [wan, lte1, lte2, ...]>
          #       role: <value in [primary, secondary]>
          #       weight: <integer>
          #   backhaul_interface: <string>
          #   backhaul_ip: <string>
          #   ipsec_tunnel: <string>
          #   link_loadbalance: <value in [activebackup, loadbalance]>
          #   downlinks:
          #     - name: <string>
          #       port: <value in [port1, port2, port3, ...]>
          #       pvid: <integer>
          #       type: <value in [port, vap]>
          #       vap: <list or string>
          #   traffic_split_services:
          #     - address: <list or string>
          #       name: <string>
          #       service: <list or string>
          #       vsdb: <value in [disable, enable]>
          # login_password: <list or string>
          # login_password_change: <value in [no, yes, default]>
          # model: <value in [FX201E, FX211E, FX200F, ...]>
          # name: <string>
          # _is_factory_setting: <value in [disable, enable, ext]>
          # wifi:
          #   DFS: <value in [disable, enable]>
          #   country: <value in [AL, DZ, AR, ...]>
          #   radio_1:
          #     d80211d: <value in [disable, enable]>
          #     band: <value in [2.4GHz]>
          #     bandwidth: <value in [auto, 20MHz, 40MHz, ...]>
          #     beacon_interval: <integer>
          #     bss_color: <integer>
          #     bss_color_mode: <value in [auto, static]>
          #     channel:
          #       - "CH1"
          #       - "CH2"
          #       - "CH3"
          #       - "CH4"
          #       - "CH5"
          #       - "CH6"
          #       - "CH7"
          #       - "CH8"
          #       - "CH9"
          #       - "CH10"
          #       - "CH11"
          #     extension_channel: <value in [auto, higher, lower]>
          #     guard_interval: <value in [auto, 400ns, 800ns]>
          #     lan_ext_vap: <list or string>
          #     local_vaps: <list or string>
          #     max_clients: <integer>
          #     mode: <value in [AP, Client]>
          #     operating_standard: <value in [auto, 11A-N-AC-AX, 11A-N-AC, ...]>
          #     power_level: <integer>
          #     radio_id: <integer>
          #     status: <value in [disable, enable]>
          #   radio_2:
          #     d80211d: <value in [disable, enable]>
          #     band: <value in [5GHz]>
          #     bandwidth: <value in [auto, 20MHz, 40MHz, ...]>
          #     beacon_interval: <integer>
          #     bss_color: <integer>
          #     bss_color_mode: <value in [auto, static]>
          #     channel:
          #       - "CH36"
          #       - "CH40"
          #       - "CH44"
          #       - "CH48"
          #       - "CH52"
          #       - "CH56"
          #       - "CH60"
          #       - "CH64"
          #       - "CH100"
          #       - "CH104"
          #       - "CH108"
          #       - "CH112"
          #       - "CH116"
          #       - "CH120"
          #       - "CH124"
          #       - "CH128"
          #       - "CH132"
          #       - "CH136"
          #       - "CH140"
          #       - "CH144"
          #       - "CH149"
          #       - "CH153"
          #       - "CH157"
          #       - "CH161"
          #       - "CH165"
          #     extension_channel: <value in [auto, higher, lower]>
          #     guard_interval: <value in [auto, 400ns, 800ns]>
          #     lan_ext_vap: <list or string>
          #     local_vaps: <list or string>
          #     max_clients: <integer>
          #     mode: <value in [AP, Client]>
          #     operating_standard: <value in [auto, 11A-N-AC-AX, 11A-N-AC, ...]>
          #     power_level: <integer>
          #     radio_id: <integer>
          #     status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/extension-controller/extender-profile',
        '/pm/config/global/obj/extension-controller/extender-profile'
    ]
    url_params = ['adom']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'extensioncontroller_extenderprofile': {
            'type': 'dict',
            'v_range': [['7.2.1', '']],
            'options': {
                'allowaccess': {
                    'v_range': [['7.2.1', '']],
                    'type': 'list',
                    'choices': ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet'],
                    'elements': 'str'
                },
                'bandwidth-limit': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'cellular': {
                    'v_range': [['7.2.1', '']],
                    'type': 'dict',
                    'options': {
                        'controller-report': {
                            'v_range': [['7.2.1', '']],
                            'type': 'dict',
                            'options': {
                                'interval': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'signal-threshold': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'status': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'dataplan': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                        'modem1': {
                            'v_range': [['7.2.1', '']],
                            'type': 'dict',
                            'options': {
                                'auto-switch': {
                                    'v_range': [['7.2.1', '']],
                                    'type': 'dict',
                                    'options': {
                                        'dataplan': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'disconnect': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'disconnect-period': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                        'disconnect-threshold': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                        'signal': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'switch-back': {'v_range': [['7.2.1', '']], 'type': 'list', 'choices': ['time', 'timer'], 'elements': 'str'},
                                        'switch-back-time': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                        'switch-back-timer': {'v_range': [['7.2.1', '']], 'type': 'int'}
                                    }
                                },
                                'conn-status': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'default-sim': {'v_range': [['7.2.1', '']], 'choices': ['sim1', 'sim2', 'carrier', 'cost'], 'type': 'str'},
                                'gps': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'modem-id': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'preferred-carrier': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'redundant-intf': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'redundant-mode': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'sim1-pin': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'sim1-pin-code': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                                'sim2-pin': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'sim2-pin-code': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                                'multiple-PDN': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'pdn1-dataplan': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                                'pdn2-dataplan': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                                'pdn3-dataplan': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                                'pdn4-dataplan': {'v_range': [['7.6.2', '']], 'type': 'raw'}
                            }
                        },
                        'modem2': {
                            'v_range': [['7.2.1', '']],
                            'type': 'dict',
                            'options': {
                                'auto-switch': {
                                    'v_range': [['7.2.1', '']],
                                    'type': 'dict',
                                    'options': {
                                        'dataplan': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'disconnect': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'disconnect-period': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                        'disconnect-threshold': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                        'signal': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                        'switch-back': {'v_range': [['7.2.1', '']], 'type': 'list', 'choices': ['time', 'timer'], 'elements': 'str'},
                                        'switch-back-time': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                        'switch-back-timer': {'v_range': [['7.2.1', '']], 'type': 'int'}
                                    }
                                },
                                'conn-status': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'default-sim': {'v_range': [['7.2.1', '']], 'choices': ['sim1', 'sim2', 'carrier', 'cost'], 'type': 'str'},
                                'gps': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'modem-id': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'preferred-carrier': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'redundant-intf': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'redundant-mode': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'sim1-pin': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'sim1-pin-code': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                                'sim2-pin': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'sim2-pin-code': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                                'multiple-PDN': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'pdn1-dataplan': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                                'pdn2-dataplan': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                                'pdn3-dataplan': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                                'pdn4-dataplan': {'v_range': [['7.6.2', '']], 'type': 'raw'}
                            }
                        },
                        'sms-notification': {
                            'v_range': [['7.2.1', '']],
                            'type': 'dict',
                            'options': {
                                'alert': {
                                    'v_range': [['7.2.1', '']],
                                    'type': 'dict',
                                    'options': {
                                        'data-exhausted': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                        'fgt-backup-mode-switch': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                        'low-signal-strength': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                        'mode-switch': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                        'os-image-fallback': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                        'session-disconnect': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                        'system-reboot': {'v_range': [['7.2.1', '']], 'type': 'str'}
                                    }
                                },
                                'receiver': {
                                    'v_range': [['7.2.1', '']],
                                    'type': 'list',
                                    'options': {
                                        'alert': {
                                            'v_range': [['7.2.1', '']],
                                            'type': 'list',
                                            'choices': [
                                                'system-reboot', 'data-exhausted', 'session-disconnect', 'low-signal-strength', 'mode-switch',
                                                'os-image-fallback', 'fgt-backup-mode-switch'
                                            ],
                                            'elements': 'str'
                                        },
                                        'name': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                        'phone-number': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                        'status': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                                    },
                                    'elements': 'dict'
                                },
                                'status': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        }
                    }
                },
                'enforce-bandwidth': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'extension': {'v_range': [['7.2.1', '']], 'choices': ['wan-extension', 'lan-extension'], 'type': 'str'},
                'id': {'v_range': [['7.2.1', '']], 'required': True, 'type': 'int'},
                'lan-extension': {
                    'v_range': [['7.2.1', '']],
                    'type': 'dict',
                    'options': {
                        'backhaul': {
                            'v_range': [['7.2.1', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'port': {
                                    'v_range': [['7.2.1', '']],
                                    'choices': ['wan', 'lte1', 'lte2', 'port1', 'port2', 'port3', 'port4', 'port5', 'sfp'],
                                    'type': 'str'
                                },
                                'role': {'v_range': [['7.2.1', '']], 'choices': ['primary', 'secondary'], 'type': 'str'},
                                'weight': {'v_range': [['7.2.1', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'backhaul-interface': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'backhaul-ip': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'ipsec-tunnel': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'link-loadbalance': {'v_range': [['7.2.1', '']], 'choices': ['activebackup', 'loadbalance'], 'type': 'str'},
                        'downlinks': {
                            'v_range': [['7.6.0', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.6.0', '']], 'type': 'str'},
                                'port': {
                                    'v_range': [['7.6.0', '']],
                                    'choices': ['port1', 'port2', 'port3', 'port4', 'port5', 'lan1', 'lan2'],
                                    'type': 'str'
                                },
                                'pvid': {'v_range': [['7.6.0', '']], 'type': 'int'},
                                'type': {'v_range': [['7.6.0', '']], 'choices': ['port', 'vap'], 'type': 'str'},
                                'vap': {'v_range': [['7.6.0', '']], 'type': 'raw'}
                            },
                            'elements': 'dict'
                        },
                        'traffic-split-services': {
                            'v_range': [['7.6.2', '']],
                            'type': 'list',
                            'options': {
                                'address': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                                'name': {'v_range': [['7.6.2', '']], 'type': 'str'},
                                'service': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                                'vsdb': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        }
                    }
                },
                'login-password': {'v_range': [['7.2.1', '']], 'no_log': True, 'type': 'raw'},
                'login-password-change': {'v_range': [['7.2.1', '']], 'choices': ['no', 'yes', 'default'], 'type': 'str'},
                'model': {
                    'v_range': [['7.2.1', '']],
                    'choices': [
                        'FX201E', 'FX211E', 'FX200F', 'FXA11F', 'FXE11F', 'FXA21F', 'FXE21F', 'FXA22F', 'FXE22F', 'FX212F', 'FX311F', 'FX312F', 'FX511F',
                        'FVG21F', 'FVA21F', 'FVG22F', 'FVA22F', 'FX04DA', 'FX04DN', 'FX04DI', 'FXR51G', 'FG', 'BS10FW', 'BS20GW', 'BS20GN', 'FXN51G',
                        'FXW51G', 'FVG51G', 'FXE11G'
                    ],
                    'type': 'str'
                },
                'name': {'v_range': [['7.2.1', '']], 'type': 'str'},
                '_is_factory_setting': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable', 'ext'], 'type': 'str'},
                'wifi': {
                    'v_range': [['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'DFS': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'country': {
                            'v_range': [['7.4.3', '']],
                            'choices': [
                                'AL', 'DZ', 'AR', 'AM', 'AU', 'AT', 'AZ', 'BH', 'BD', 'BY', 'BE', 'BZ', 'BO', 'BA', 'BR', 'BN', 'BG', 'CA', 'CL', 'CN',
                                'CO', 'CR', 'HR', 'CY', 'CZ', 'DK', 'DO', 'EC', 'EG', 'SV', 'EE', 'FI', 'FR', 'GE', 'DE', 'GR', 'GT', 'HN', 'HK', 'HU',
                                'IS', 'IN', 'ID', 'IE', 'IL', 'IT', 'JM', 'JP', 'JO', 'KZ', 'KE', 'KR', 'KW', 'LV', 'LB', 'LI', 'LT', 'LU', 'MO', 'MK',
                                'MY', 'MT', 'MX', 'MC', 'MA', 'NP', 'NL', 'AN', 'NZ', 'NO', 'OM', 'PK', 'PA', 'PG', 'PE', 'PH', 'PL', 'PT', 'PR', 'QA',
                                'RO', 'RU', 'SA', 'SG', 'SK', 'SI', 'ZA', 'ES', 'LK', 'SE', 'CH', 'TW', 'TH', 'TT', 'TN', 'TR', 'AE', 'UA', 'GB', 'US',
                                'PS', 'UY', 'UZ', 'VE', 'VN', 'YE', 'ZW', 'NA', 'BS', 'VC', 'KH', 'MV', 'AF', 'NG', 'TZ', 'ZM', 'SN', 'CI', 'GH', 'CM',
                                'MW', 'AO', 'GA', 'ML', 'BJ', 'MG', 'TD', 'BW', 'LY', 'RW', 'MZ', 'GM', 'LS', 'MU', 'CG', 'UG', 'BF', 'SL', 'SO', 'CD',
                                'NE', 'CF', 'SZ', 'TG', 'LR', 'MR', 'DJ', 'RE', 'RS', 'ME', 'IQ', 'MD', 'KY', 'BB', 'BM', 'TC', 'VI', 'PM', 'MF', 'GD',
                                'IM', 'FO', 'GI', 'GL', 'TM', 'MN', 'VU', 'FJ', 'LA', 'GU', 'WF', 'MH', 'BT', 'FM', 'PF', 'NI', 'PY', 'HT', 'GY', 'AW',
                                'KN', 'GF', 'AS', 'MP', 'PW', 'MM', 'LC', 'GP', 'ET', 'SR', 'CX', 'DM', 'MQ', 'YT', 'BL', '--', 'TL'
                            ],
                            'type': 'str'
                        },
                        'radio-1': {
                            'v_range': [['7.4.3', '']],
                            'type': 'dict',
                            'options': {
                                '80211d': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'band': {'v_range': [['7.4.3', '']], 'choices': ['2.4GHz'], 'type': 'str'},
                                'bandwidth': {'v_range': [['7.4.3', '']], 'choices': ['auto', '20MHz', '40MHz', '80MHz'], 'type': 'str'},
                                'beacon-interval': {'v_range': [['7.4.3', '']], 'type': 'int'},
                                'bss-color': {'v_range': [['7.4.3', '']], 'type': 'int'},
                                'bss-color-mode': {'v_range': [['7.4.3', '']], 'choices': ['auto', 'static'], 'type': 'str'},
                                'channel': {
                                    'v_range': [['7.4.3', '']],
                                    'type': 'list',
                                    'choices': ['CH1', 'CH2', 'CH3', 'CH4', 'CH5', 'CH6', 'CH7', 'CH8', 'CH9', 'CH10', 'CH11'],
                                    'elements': 'str'
                                },
                                'extension-channel': {'v_range': [['7.4.3', '']], 'choices': ['auto', 'higher', 'lower'], 'type': 'str'},
                                'guard-interval': {'v_range': [['7.4.3', '']], 'choices': ['auto', '400ns', '800ns'], 'type': 'str'},
                                'lan-ext-vap': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                                'local-vaps': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                                'max-clients': {'v_range': [['7.4.3', '']], 'type': 'int'},
                                'mode': {'v_range': [['7.4.3', '']], 'choices': ['AP', 'Client'], 'type': 'str'},
                                'operating-standard': {
                                    'v_range': [['7.4.3', '']],
                                    'choices': [
                                        'auto', '11A-N-AC-AX', '11A-N-AC', '11A-N', '11A', '11N-AC-AX', '11AC-AX', '11AC', '11N-AC', '11B-G-N-AX',
                                        '11B-G-N', '11B-G', '11B', '11G-N-AX', '11N-AX', '11AX', '11G-N', '11N', '11G'
                                    ],
                                    'type': 'str'
                                },
                                'power-level': {'v_range': [['7.4.3', '']], 'type': 'int'},
                                'radio-id': {'v_range': [['7.4.3', '']], 'type': 'int'},
                                'status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        },
                        'radio-2': {
                            'v_range': [['7.4.3', '']],
                            'type': 'dict',
                            'options': {
                                '80211d': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'band': {'v_range': [['7.4.3', '']], 'choices': ['5GHz'], 'type': 'str'},
                                'bandwidth': {'v_range': [['7.4.3', '']], 'choices': ['auto', '20MHz', '40MHz', '80MHz'], 'type': 'str'},
                                'beacon-interval': {'v_range': [['7.4.3', '']], 'type': 'int'},
                                'bss-color': {'v_range': [['7.4.3', '']], 'type': 'int'},
                                'bss-color-mode': {'v_range': [['7.4.3', '']], 'choices': ['auto', 'static'], 'type': 'str'},
                                'channel': {
                                    'v_range': [['7.4.3', '']],
                                    'type': 'list',
                                    'choices': [
                                        'CH36', 'CH40', 'CH44', 'CH48', 'CH52', 'CH56', 'CH60', 'CH64', 'CH100', 'CH104', 'CH108', 'CH112', 'CH116',
                                        'CH120', 'CH124', 'CH128', 'CH132', 'CH136', 'CH140', 'CH144', 'CH149', 'CH153', 'CH157', 'CH161', 'CH165'
                                    ],
                                    'elements': 'str'
                                },
                                'extension-channel': {'v_range': [['7.4.3', '']], 'choices': ['auto', 'higher', 'lower'], 'type': 'str'},
                                'guard-interval': {'v_range': [['7.4.3', '']], 'choices': ['auto', '400ns', '800ns'], 'type': 'str'},
                                'lan-ext-vap': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                                'local-vaps': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                                'max-clients': {'v_range': [['7.4.3', '']], 'type': 'int'},
                                'mode': {'v_range': [['7.4.3', '']], 'choices': ['AP', 'Client'], 'type': 'str'},
                                'operating-standard': {
                                    'v_range': [['7.4.3', '']],
                                    'choices': [
                                        'auto', '11A-N-AC-AX', '11A-N-AC', '11A-N', '11A', '11N-AC-AX', '11AC-AX', '11AC', '11N-AC', '11B-G-N-AX',
                                        '11B-G-N', '11B-G', '11B', '11G-N-AX', '11N-AX', '11AX', '11G-N', '11N', '11G'
                                    ],
                                    'type': 'str'
                                },
                                'power-level': {'v_range': [['7.4.3', '']], 'type': 'int'},
                                'radio-id': {'v_range': [['7.4.3', '']], 'type': 'int'},
                                'status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        }
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extensioncontroller_extenderprofile'),
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
