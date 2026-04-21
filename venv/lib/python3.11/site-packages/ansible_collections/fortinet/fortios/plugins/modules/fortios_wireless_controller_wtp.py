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
module: fortios_wireless_controller_wtp
short_description: Configure Wireless Termination Points (WTPs), that is, FortiAPs or APs to be managed by FortiGate in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and wtp category.
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
    wireless_controller_wtp:
        description:
            - Configure Wireless Termination Points (WTPs), that is, FortiAPs or APs to be managed by FortiGate.
        default: null
        type: dict
        suboptions:
            admin:
                description:
                    - Configure how the FortiGate operating as a wireless controller discovers and manages this WTP, AP or FortiAP.
                type: str
                choices:
                    - 'discovered'
                    - 'disable'
                    - 'enable'
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
            apcfg_profile:
                description:
                    - AP local configuration profile name. Source wireless-controller.apcfg-profile.name.
                type: str
            ble_major_id:
                description:
                    - Override BLE Major ID.
                type: int
            ble_minor_id:
                description:
                    - Override BLE Minor ID.
                type: int
            bonjour_profile:
                description:
                    - Bonjour profile name. Source wireless-controller.bonjour-profile.name.
                type: str
            comment:
                description:
                    - Comment.
                type: str
            coordinate_enable:
                description:
                    - Enable/disable WTP coordinates (X,Y axis).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            coordinate_latitude:
                description:
                    - WTP latitude coordinate.
                type: str
            coordinate_longitude:
                description:
                    - WTP longitude coordinate.
                type: str
            coordinate_x:
                description:
                    - X axis coordinate.
                type: str
            coordinate_y:
                description:
                    - Y axis coordinate.
                type: str
            default_mesh_root:
                description:
                    - Configure default mesh root SSID when it is not included by radio"s SSID configuration.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            firmware_provision:
                description:
                    - Firmware version to provision to this FortiAP on bootup (major.minor.build, i.e. 6.2.1234).
                type: str
            firmware_provision_latest:
                description:
                    - Enable/disable one-time automatic provisioning of the latest firmware version.
                type: str
                choices:
                    - 'disable'
                    - 'once'
            image_download:
                description:
                    - Enable/disable WTP image download.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            index:
                description:
                    - Index (0 - 4294967295).
                type: int
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
            led_state:
                description:
                    - Enable to allow the FortiAPs LEDs to light. Disable to keep the LEDs off. You may want to keep the LEDs off so they are not distracting
                       in low light areas etc.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            location:
                description:
                    - Field for describing the physical location of the WTP, AP or FortiAP.
                type: str
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
            mesh_bridge_enable:
                description:
                    - Enable/disable mesh Ethernet bridge when WTP is configured as a mesh branch/leaf AP.
                type: str
                choices:
                    - 'default'
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - WTP, AP or FortiAP configuration name.
                type: str
            override_allowaccess:
                description:
                    - Enable to override the WTP profile management access configuration.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            override_default_mesh_root:
                description:
                    - Enable to override the WTP profile default mesh root SSID setting.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            override_ip_fragment:
                description:
                    - Enable/disable overriding the WTP profile IP fragment prevention setting.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            override_lan:
                description:
                    - Enable to override the WTP profile LAN port setting.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            override_led_state:
                description:
                    - Enable to override the profile LED state setting for this FortiAP. You must enable this option to use the led-state command to turn off
                       the FortiAP"s LEDs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            override_login_passwd_change:
                description:
                    - Enable to override the WTP profile login-password (administrator password) setting.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            override_split_tunnel:
                description:
                    - Enable/disable overriding the WTP profile split tunneling setting.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            override_wan_port_mode:
                description:
                    - Enable/disable overriding the wan-port-mode in the WTP profile.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            purdue_level:
                description:
                    - Purdue Level of this WTP.
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
            radio_1:
                description:
                    - Configuration options for radio 1.
                type: dict
                suboptions:
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
                    drma_manual_mode:
                        description:
                            - Radio mode to be used for DRMA manual mode .
                        type: str
                        choices:
                            - 'ap'
                            - 'monitor'
                            - 'ncf'
                            - 'ncf-peek'
                    override_analysis:
                        description:
                            - Enable to override the WTP profile spectrum analysis configuration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_band:
                        description:
                            - Enable to override the WTP profile band setting.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_channel:
                        description:
                            - Enable to override WTP profile channel settings.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_txpower:
                        description:
                            - Enable to override the WTP profile power level configuration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_vaps:
                        description:
                            - Enable to override WTP profile Virtual Access Point (VAP) settings.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
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
                    radio_id:
                        description:
                            - radio-id
                        type: int
                    spectrum_analysis:
                        description:
                            - Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        type: str
                        choices:
                            - 'enable'
                            - 'scan-only'
                            - 'disable'
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
            radio_2:
                description:
                    - Configuration options for radio 2.
                type: dict
                suboptions:
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
                    drma_manual_mode:
                        description:
                            - Radio mode to be used for DRMA manual mode .
                        type: str
                        choices:
                            - 'ap'
                            - 'monitor'
                            - 'ncf'
                            - 'ncf-peek'
                    override_analysis:
                        description:
                            - Enable to override the WTP profile spectrum analysis configuration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_band:
                        description:
                            - Enable to override the WTP profile band setting.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_channel:
                        description:
                            - Enable to override WTP profile channel settings.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_txpower:
                        description:
                            - Enable to override the WTP profile power level configuration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_vaps:
                        description:
                            - Enable to override WTP profile Virtual Access Point (VAP) settings.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
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
                    radio_id:
                        description:
                            - radio-id
                        type: int
                    spectrum_analysis:
                        description:
                            - Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        type: str
                        choices:
                            - 'enable'
                            - 'scan-only'
                            - 'disable'
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
            radio_3:
                description:
                    - Configuration options for radio 3.
                type: dict
                suboptions:
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
                    drma_manual_mode:
                        description:
                            - Radio mode to be used for DRMA manual mode .
                        type: str
                        choices:
                            - 'ap'
                            - 'monitor'
                            - 'ncf'
                            - 'ncf-peek'
                    override_analysis:
                        description:
                            - Enable to override the WTP profile spectrum analysis configuration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_band:
                        description:
                            - Enable to override the WTP profile band setting.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_channel:
                        description:
                            - Enable to override WTP profile channel settings.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_txpower:
                        description:
                            - Enable to override the WTP profile power level configuration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_vaps:
                        description:
                            - Enable to override WTP profile Virtual Access Point (VAP) settings.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
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
                    radio_id:
                        description:
                            - radio-id
                        type: int
                    spectrum_analysis:
                        description:
                            - Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        type: str
                        choices:
                            - 'enable'
                            - 'scan-only'
                            - 'disable'
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
            radio_4:
                description:
                    - Configuration options for radio 4.
                type: dict
                suboptions:
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
                    drma_manual_mode:
                        description:
                            - Radio mode to be used for DRMA manual mode .
                        type: str
                        choices:
                            - 'ap'
                            - 'monitor'
                            - 'ncf'
                            - 'ncf-peek'
                    override_analysis:
                        description:
                            - Enable to override the WTP profile spectrum analysis configuration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_band:
                        description:
                            - Enable to override the WTP profile band setting.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_channel:
                        description:
                            - Enable to override WTP profile channel settings.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_txpower:
                        description:
                            - Enable to override the WTP profile power level configuration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_vaps:
                        description:
                            - Enable to override WTP profile Virtual Access Point (VAP) settings.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
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
                    spectrum_analysis:
                        description:
                            - Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        type: str
                        choices:
                            - 'enable'
                            - 'scan-only'
                            - 'disable'
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
            region:
                description:
                    - Region name WTP is associated with. Source wireless-controller.region.name.
                type: str
            region_x:
                description:
                    - Relative horizontal region coordinate (between 0 and 1).
                type: str
            region_y:
                description:
                    - Relative vertical region coordinate (between 0 and 1).
                type: str
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
            tun_mtu_downlink:
                description:
                    - The MTU of downlink CAPWAP tunnel (576 - 1500 bytes or 0; 0 means the local MTU of FortiAP; ).
                type: int
            tun_mtu_uplink:
                description:
                    - The maximum transmission unit (MTU) of uplink CAPWAP tunnel (576 - 1500 bytes or 0; 0 means the local MTU of FortiAP; ).
                type: int
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            wan_port_mode:
                description:
                    - Enable/disable using the FortiAP WAN port as a LAN port.
                type: str
                choices:
                    - 'wan-lan'
                    - 'wan-only'
            wtp_id:
                description:
                    - WTP ID.
                required: true
                type: str
            wtp_mode:
                description:
                    - WTP, AP, or FortiAP operating mode; normal (by default) or remote. A tunnel mode SSID can be assigned to an AP in normal mode but not
                       remote mode, while a local-bridge mode SSID can be assigned to an AP in either normal mode or remote mode.
                type: str
                choices:
                    - 'normal'
                    - 'remote'
            wtp_profile:
                description:
                    - WTP profile name to apply to this WTP, AP or FortiAP. Source wireless-controller.wtp-profile.name.
                type: str
"""

EXAMPLES = """
- name: Configure Wireless Termination Points (WTPs), that is, FortiAPs or APs to be managed by FortiGate.
  fortinet.fortios.fortios_wireless_controller_wtp:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wireless_controller_wtp:
          admin: "discovered"
          allowaccess: "https"
          apcfg_profile: "<your_own_value> (source wireless-controller.apcfg-profile.name)"
          ble_major_id: "0"
          ble_minor_id: "0"
          bonjour_profile: "<your_own_value> (source wireless-controller.bonjour-profile.name)"
          comment: "Comment."
          coordinate_enable: "enable"
          coordinate_latitude: "<your_own_value>"
          coordinate_longitude: "<your_own_value>"
          coordinate_x: "<your_own_value>"
          coordinate_y: "<your_own_value>"
          default_mesh_root: "enable"
          firmware_provision: "<your_own_value>"
          firmware_provision_latest: "disable"
          image_download: "enable"
          index: "0"
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
          led_state: "enable"
          location: "<your_own_value>"
          login_passwd: "<your_own_value>"
          login_passwd_change: "yes"
          mesh_bridge_enable: "default"
          name: "default_name_47"
          override_allowaccess: "enable"
          override_default_mesh_root: "enable"
          override_ip_fragment: "enable"
          override_lan: "enable"
          override_led_state: "enable"
          override_login_passwd_change: "enable"
          override_split_tunnel: "enable"
          override_wan_port_mode: "enable"
          purdue_level: "1"
          radio_1:
              auto_power_high: "17"
              auto_power_level: "enable"
              auto_power_low: "10"
              auto_power_target: "<your_own_value>"
              band: "802.11a"
              channel:
                  -
                      chan: "<your_own_value>"
              drma_manual_mode: "ap"
              override_analysis: "enable"
              override_band: "enable"
              override_channel: "enable"
              override_txpower: "enable"
              override_vaps: "enable"
              power_level: "100"
              power_mode: "dBm"
              power_value: "27"
              radio_id: "2"
              spectrum_analysis: "enable"
              vap_all: "tunnel"
              vaps:
                  -
                      name: "default_name_78 (source wireless-controller.vap-group.name system.interface.name)"
          radio_2:
              auto_power_high: "17"
              auto_power_level: "enable"
              auto_power_low: "10"
              auto_power_target: "<your_own_value>"
              band: "802.11a"
              channel:
                  -
                      chan: "<your_own_value>"
              drma_manual_mode: "ap"
              override_analysis: "enable"
              override_band: "enable"
              override_channel: "enable"
              override_txpower: "enable"
              override_vaps: "enable"
              power_level: "100"
              power_mode: "dBm"
              power_value: "27"
              radio_id: "2"
              spectrum_analysis: "enable"
              vap_all: "tunnel"
              vaps:
                  -
                      name: "default_name_100 (source wireless-controller.vap-group.name system.interface.name)"
          radio_3:
              auto_power_high: "17"
              auto_power_level: "enable"
              auto_power_low: "10"
              auto_power_target: "<your_own_value>"
              band: "802.11a"
              channel:
                  -
                      chan: "<your_own_value>"
              drma_manual_mode: "ap"
              override_analysis: "enable"
              override_band: "enable"
              override_channel: "enable"
              override_txpower: "enable"
              override_vaps: "enable"
              power_level: "100"
              power_mode: "dBm"
              power_value: "27"
              radio_id: "2"
              spectrum_analysis: "enable"
              vap_all: "tunnel"
              vaps:
                  -
                      name: "default_name_122 (source wireless-controller.vap-group.name system.interface.name)"
          radio_4:
              auto_power_high: "17"
              auto_power_level: "enable"
              auto_power_low: "10"
              auto_power_target: "<your_own_value>"
              band: "802.11a"
              channel:
                  -
                      chan: "<your_own_value>"
              drma_manual_mode: "ap"
              override_analysis: "enable"
              override_band: "enable"
              override_channel: "enable"
              override_txpower: "enable"
              override_vaps: "enable"
              power_level: "100"
              power_mode: "dBm"
              power_value: "27"
              spectrum_analysis: "enable"
              vap_all: "tunnel"
              vaps:
                  -
                      name: "default_name_143 (source wireless-controller.vap-group.name system.interface.name)"
          region: "<your_own_value> (source wireless-controller.region.name)"
          region_x: "<your_own_value>"
          region_y: "<your_own_value>"
          split_tunneling_acl:
              -
                  dest_ip: "<your_own_value>"
                  id: "149"
          split_tunneling_acl_local_ap_subnet: "enable"
          split_tunneling_acl_path: "tunnel"
          tun_mtu_downlink: "0"
          tun_mtu_uplink: "0"
          uuid: "<your_own_value>"
          wan_port_mode: "wan-lan"
          wtp_id: "<your_own_value>"
          wtp_mode: "normal"
          wtp_profile: "<your_own_value> (source wireless-controller.wtp-profile.name)"
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


def filter_wireless_controller_wtp_data(json):
    option_list = [
        "admin",
        "allowaccess",
        "apcfg_profile",
        "ble_major_id",
        "ble_minor_id",
        "bonjour_profile",
        "comment",
        "coordinate_enable",
        "coordinate_latitude",
        "coordinate_longitude",
        "coordinate_x",
        "coordinate_y",
        "default_mesh_root",
        "firmware_provision",
        "firmware_provision_latest",
        "image_download",
        "index",
        "ip_fragment_preventing",
        "lan",
        "led_state",
        "location",
        "login_passwd",
        "login_passwd_change",
        "mesh_bridge_enable",
        "name",
        "override_allowaccess",
        "override_default_mesh_root",
        "override_ip_fragment",
        "override_lan",
        "override_led_state",
        "override_login_passwd_change",
        "override_split_tunnel",
        "override_wan_port_mode",
        "purdue_level",
        "radio_1",
        "radio_2",
        "radio_3",
        "radio_4",
        "region",
        "region_x",
        "region_y",
        "split_tunneling_acl",
        "split_tunneling_acl_local_ap_subnet",
        "split_tunneling_acl_path",
        "tun_mtu_downlink",
        "tun_mtu_uplink",
        "uuid",
        "wan_port_mode",
        "wtp_id",
        "wtp_mode",
        "wtp_profile",
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
        ["ip_fragment_preventing"],
        ["allowaccess"],
        ["radio_1", "band"],
        ["radio_2", "band"],
        ["radio_3", "band"],
        ["radio_4", "band"],
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


def wireless_controller_wtp(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    wireless_controller_wtp_data = data["wireless_controller_wtp"]

    filtered_data = filter_wireless_controller_wtp_data(wireless_controller_wtp_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("wireless-controller", "wtp", filtered_data, vdom=vdom)
        current_data = fos.get("wireless-controller", "wtp", vdom=vdom, mkey=mkey)
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
    data_copy["wireless_controller_wtp"] = filtered_data
    fos.do_member_operation(
        "wireless-controller",
        "wtp",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("wireless-controller", "wtp", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "wireless-controller", "wtp", mkey=converted_data["wtp-id"], vdom=vdom
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

    if data["wireless_controller_wtp"]:
        resp = wireless_controller_wtp(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("wireless_controller_wtp"))
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
        "wtp_id": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "uuid": {"v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]], "type": "string"},
        "admin": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "discovered"},
                {"value": "disable"},
                {"value": "enable"},
            ],
        },
        "name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "location": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "comment": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "region": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "region_x": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "region_y": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "firmware_provision": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "firmware_provision_latest": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "once"}],
        },
        "wtp_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "apcfg_profile": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "bonjour_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ble_major_id": {"v_range": [["v7.4.1", ""]], "type": "integer"},
        "ble_minor_id": {"v_range": [["v7.4.1", ""]], "type": "integer"},
        "override_led_state": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "led_state": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "override_wan_port_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wan_port_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "wan-lan"}, {"value": "wan-only"}],
        },
        "override_ip_fragment": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "override_split_tunnel": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
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
        "override_lan": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "override_allowaccess": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "override_login_passwd_change": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "login_passwd_change": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "yes"}, {"value": "default"}, {"value": "no"}],
        },
        "login_passwd": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "override_default_mesh_root": {
            "v_range": [["v7.6.4", ""]],
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
                "override_band": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
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
                        {
                            "value": "802.11ac-2G",
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                        },
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
                "override_txpower": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
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
                "override_vaps": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
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
                "override_channel": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
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
                "drma_manual_mode": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ap"},
                        {"value": "monitor"},
                        {"value": "ncf"},
                        {"value": "ncf-peek"},
                    ],
                },
                "override_analysis": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "spectrum_analysis": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "scan-only", "v_range": [["v6.4.1", "v6.4.1"]]},
                        {"value": "disable"},
                    ],
                },
                "radio_id": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "integer",
                },
            },
        },
        "radio_2": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "override_band": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
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
                        {
                            "value": "802.11ac-2G",
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                        },
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
                "override_txpower": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
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
                "override_vaps": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
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
                "override_channel": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
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
                "drma_manual_mode": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ap"},
                        {"value": "monitor"},
                        {"value": "ncf"},
                        {"value": "ncf-peek"},
                    ],
                },
                "override_analysis": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "spectrum_analysis": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "scan-only", "v_range": [["v6.4.1", "v6.4.1"]]},
                        {"value": "disable"},
                    ],
                },
                "radio_id": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "integer",
                },
            },
        },
        "radio_3": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "override_band": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
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
                        {
                            "value": "802.11ac-2G",
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                        },
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
                "override_txpower": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
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
                "override_vaps": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
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
                "override_channel": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
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
                "drma_manual_mode": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ap"},
                        {"value": "monitor"},
                        {"value": "ncf"},
                        {"value": "ncf-peek"},
                    ],
                },
                "override_analysis": {
                    "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "spectrum_analysis": {
                    "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "scan-only", "v_range": [["v6.4.1", "v6.4.1"]]},
                        {"value": "disable"},
                    ],
                },
                "radio_id": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "integer"},
            },
        },
        "radio_4": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "dict",
            "children": {
                "override_band": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
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
                        {
                            "value": "802.11ac-2G",
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                        },
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
                "override_txpower": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
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
                "override_vaps": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
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
                "override_channel": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
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
                "drma_manual_mode": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ap"},
                        {"value": "monitor"},
                        {"value": "ncf"},
                        {"value": "ncf-peek"},
                    ],
                },
                "override_analysis": {
                    "v_range": [
                        ["v6.2.0", "v6.2.0"],
                        ["v6.2.5", "v6.2.7"],
                        ["v6.4.1", "v6.4.1"],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
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
            },
        },
        "image_download": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mesh_bridge_enable": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "default"},
                {"value": "enable"},
                {"value": "disable"},
            ],
        },
        "purdue_level": {
            "v_range": [["v7.4.2", ""]],
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
        "coordinate_latitude": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "coordinate_longitude": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "index": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "wtp_mode": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "normal"}, {"value": "remote"}],
        },
        "coordinate_enable": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "coordinate_x": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
        "coordinate_y": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "wtp_id"
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
        "wireless_controller_wtp": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_wtp"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_wtp"]["options"][attribute_name][
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
            fos, versioned_schema, "wireless_controller_wtp"
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
