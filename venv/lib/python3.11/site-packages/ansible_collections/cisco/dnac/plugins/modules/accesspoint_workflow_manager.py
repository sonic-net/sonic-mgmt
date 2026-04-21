#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type
__author__ = ("A Mohamed Rafeek, Megha Kandari, Sonali Deepthi Kesali, Natarajan, Madhan Sankaranarayanan, Abhishek Maheshwari")
DOCUMENTATION = r"""
---
module: accesspoint_workflow_manager
short_description: Manage Cisco Catalyst Center access points
description:
  - Manage access point configurations in Cisco Catalyst Center.
  - Configure individual AP settings including radio interfaces, controller assignments, and location parameters.
  - Perform bulk configuration updates across multiple access points of the same series.
  - Execute lifecycle operations including AP reboot and factory reset for up to 100 devices.
  - Provision access points to sites and assign RF profiles (HIGH, LOW, TYPICAL, or custom).
  - Support advanced radio configurations for 2.4GHz, 5GHz, 6GHz, XOR, and TRI radio interfaces.
  - Compare current configurations with desired state to apply only necessary changes.
  - Identify access points using MAC address, hostname, or management IP address.
version_added: "6.17.0"
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - A Mohamed Rafeek (@mabdulk2)
  - Sonali Deepthi Kesali (@skesali)
  - Megha Kandari (@mekandar)
  - Natarajan (@natarajan)
  - Madhan Sankaranarayanan (@madhansansel)
  - Abhishek Maheshwari (@abmahesh)
options:
  config_verify:
    description: >
      Indicates whether configuration verification is enabled.
      This flag is always set to false. As a result, some field changes
      may not exhibit idempotent behavior due to Access Point reboots.
    type: bool
    default: false
  state:
    description: The desired state of the device replacement workflow.
    type: str
    choices: ["merged", "deleted"]
    default: merged
  dnac_api_task_timeout:
    description: The number of times to retry resynchronization.
    type: int
    default: 1200
  dnac_task_poll_interval:
    description: The interval, in seconds, for polling Cisco Catalyst Center.
    type: int
    default: 2
  next_task_after_interval:
    description: Time in seconds between Provision and AP updated execution
    type: int
    default: 5
  config:
    description: List of details of AP being managed.
    type: list
    elements: dict
    required: true
    suboptions:
      mac_address:
        description: |
          The MAC address used to identify the device. If provided, it cannot be modified.
          To identify the specific access point, at least one of the following parameters is required.
          - mac_address
          - hostname
          - management_ip_address
        type: str
        required: true
      hostname:
        description: |
          The Host Name used to identify the device. If provided, it cannot be modified.
          To identify the specific access point, at least one of the following parameters is required.
          - mac_address
          - hostname
          - management_ip_address
        type: str
        required: true
      management_ip_address:
        description: |
          The Management IP Address used to identify the device. If provided, it cannot be modified.
          To identify the specific access point, at least one of the following parameters is required.
          - mac_address
          - hostname
          - management_ip_address
        type: str
        required: true
      rf_profile:
        description: |
          Specifies the Radio Frequency (RF) profile name for the Access Point. It can be one of the standard profiles
          "HIGH", "LOW", "TYPICAL", or a custom profile that has been created. For example, "HIGH".
        type: str
        required: false
      site:
        description: Current site details where the Access Point is located.
        type: dict
        suboptions:
          floor:
            description: Floor details of the current site.
            type: dict
            required: false
            suboptions:
              name:
                description: Name of the floor. For example, "FLOOR1".
                type: str
                required: false
              parent_name:
                description: Parent name of the floor in the site hierarchy. For example,
                  "Global/USA/New York/BLDNYC".
                type: str
                required: false
      ap_name:
        description: Current AP name that needs to be changed along with the new AP
          name. For example, "Test2".
        type: str
        required: false
      admin_status:
        description: Status of the AP configuration. Accepts "Enabled" or "Disabled".
          For example, "Enabled".
        type: str
        required: false
      led_status:
        description: >
          Specifies led status for the access point accepts "Enabled" or "Disabled".
          When a led brightness level is provided, the led status defaults to "Enabled".
          For example, "Enabled".
        type: str
        required: false
      led_brightness_level:
        description: Brightness level of the AP's LED. Accepts values from 1 to 8.
          For example, 3.
        type: int
        required: false
      ap_mode:
        description: |
          Defines the operational mode of the Access Point (AP), which determines its primary function.
          - C(Local): The default mode where the AP serves wireless clients by tunneling
          all client traffic to the controller. Radio parameters (For example, C(2.4ghz_radio),
          C(5ghz_radio)) can only be modified when the AP is in this mode.
          - C(Monitor): The AP does not serve clients but actively monitors the RF environment
          for rogue devices, interference, and supports features like Radio Resource Management (RRM)
          and Intrusion Detection System (IDS).
          - C(Sniffer): The AP is dedicated to capturing all 802.11 packets on a specific channel
          and forwarding them to a remote machine for analysis with tools like Wireshark.
          - C(Bridge): The AP acts as a dedicated point-to-point or point-to-multipoint bridge to
          connect different network segments wirelessly. Clients cannot connect to the AP in this mode.
          Note: Changing the AP mode may cause the AP to reboot. Not all AP models support all modes.
        type: str
        required: false
      location:
        description: Location name of the AP. Provide this data if a change is required.
          For example, "Bangalore".
        type: str
        required: false
      is_assigned_site_as_location:
        description: |
          - Determines whether the access point's location is automatically set to its assigned site.
          - When set to C(Enabled), the assigned site is used as the location and no manual location configuration is needed.
          - When set to C(Disabled), the location must be specified manually.
          - Accepted values are C(Enabled) and C(Disabled).
          - Note: Idempotent behavior is not supported for this field; repeated runs may not guarantee consistent results.
        type: str
        choices: ["Enabled", "Disabled"]
        required: false
      failover_priority:
        description: Priority order for failover in AP configuration. Accepts "Low",
          "Medium", "High", or "Critical".
        type: str
        required: false
      clean_air_si_2.4ghz:
        description: |
          Clean Air Spectrum Intelligence (SI) feature status for the 2.4GHz band.
          Indicates whether Clean Air Spectrum Intelligence is enabled or disabled.
          For example, "Enabled".
        type: str
        required: false
      clean_air_si_5ghz:
        description: |
          Clean Air Spectrum Intelligence (SI) feature status for the 5GHz band.
          Indicates whether Clean Air Spectrum Intelligence is enabled or disabled.
          For example, "Enabled".
        type: str
        required: false
      clean_air_si_6ghz:
        description: |
          Clean Air Spectrum Intelligence (SI) feature status for the 6GHz band.
          Indicates whether Clean Air Spectrum Intelligence is enabled or disabled.
          For example, "Enabled".
        type: str
        required: false
      primary_controller_name:
        description: |
          Name or identifier of the primary wireless LAN controller (WLC) managing the Access Point (AP).
          For example, "SJ-EWLC-1".
        type: str
        required: false
      primary_ip_address:
        description: IP address of the primary wireless LAN controller (WLC) managing
          the Access Point (AP).
        type: dict
        required: false
        suboptions:
          address:
            description: IP address of the primary wireless LAN controller. For example,
              "10.0.0.3".
            type: str
            required: true
      secondary_controller_name:
        description: |
          Name or identifier of the secondary wireless LAN controller (WLC) managing the Access Point (AP).
          To modify only the primary controller, set the secondary and tertiary controller names
          to "Inherit from site / Clear".
        type: str
        required: false
      secondary_ip_address:
        description: IP address of the secondary wireless LAN controller (WLC) managing
          the Access Point (AP).
        type: dict
        required: false
        suboptions:
          address:
            description: IP address of the primary wireless LAN controller. For example,
              "10.0.0.3".
            type: str
            required: true
      tertiary_controller_name:
        description: |
          Name or identifier of the tertiary wireless LAN controller (WLC) managing the Access Point (AP).
          To modify only the primary controller, set the secondary and tertiary controller names
          to "Inherit from site / Clear".
        type: str
        required: false
      tertiary_ip_address:
        description: IP address of the tertiary wireless LAN controller (WLC) managing
          the Access Point (AP).
        type: dict
        required: false
        suboptions:
          address:
            description: IP address of the primary wireless LAN controller. For example,
              "10.0.0.2".
            type: str
            required: true
      2.4ghz_radio:
        description: |
          Configuration options for the 2.4GHz radio interface.
          Note: Updating access point radio configuration varies based on each model.
          Refer to the respective access point documentation before updating the radio configuration.
        type: dict
        required: false
        suboptions:
          admin_status:
            description: Administrative status for the 2.4GHz radio interface. For
              example, "Enabled".
            type: str
            required: false
          antenna_name:
            description: Name or type of antenna used for the 2.4GHz radio interface.
              For example, "other".
            type: str
            required: false
          antenna_gain:
            description: |
              Specifies the antenna gain value in decibels (dB) for the 2.4GHz radio interface,
              and antenna gain must be greater than cable loss.
              Valid values range from 0 to 20. For example, 10.
            type: int
            required: false
          radio_role_assignment:
            description: |
              Defines the operational role for the 2.4GHz radio interface.
              - C(Auto): The controller automatically manages the radio's role. This is the default behavior.
              - C(Client-serving): The radio is dedicated to serving wireless clients.
              - C(Monitor): The radio is dedicated to monitoring the RF environment and does not serve clients.
              Note: This parameter, along with all other radio settings, can only be modified when
              the access point's C(ap_mode) is set to C(Local).
            type: str
            required: false
          cable_loss:
            description: |
              Cable loss in dB for the 2.4GHz radio interface. Valid values are from 0 to 20.
              This value must be less than the antenna gain. For example, 2.
            type: int
            required: false
          antenna_cable_name:
            description: Name or type of antenna cable used for the 2.4GHz radio interface.
              For example, "other".
            type: str
            required: false
          channel_assignment_mode:
            description: >
              Specifies the channel assignment for the 2.4GHz radio interface.
              If the channel assignment is set to "Global", the channel_number is not required.
              When a channel_number is provided, the channel assignment defaults to "Custom".
              Accepts "Global" or "Custom". For example: "Global".
            type: str
            required: false
          channel_number:
            description: >
              Defines the custom channel number for the 2.4GHz radio interface.
              When a channel number is provided, the channel assignment defaults to "Custom".
              Valid values range from 1 to 14. For example: 3.
            type: int
            required: false
          power_assignment_mode:
            description: >
              Specifies the power assignment mode for the 2.4GHz radio interface.
              If the power assignment mode is set to "Global", the power level is not required.
              When a power level is provided, the power assignment mode automatically defaults to "Custom".
              Accepts "Global" or "Custom". For example: "Global".
            type: str
            required: false
          power_level:
            description: >
              Defines the custom power level for the 2.4GHz radio interface.
              When a power level is provided, the power assignment mode automatically defaults to "Custom".
              Valid values range from 1 to 8. For example: 3.
            type: int
            required: false
      5ghz_radio:
        description: >
          Configuration options for the 5GHz radio interface.
          Note: Updating access point radio configuration varies based on each model.
          Refer to the respective access point documentation before updating the radio configuration.
        type: dict
        required: false
        suboptions:
          admin_status:
            description: Administrative status for the 5GHz radio interface. For example,
              "Enabled".
            type: str
            required: false
          antenna_name:
            description: Name or type of antenna used for the 5GHz radio interface.
              For example, "other".
            type: str
            required: false
          antenna_gain:
            description: |
              Antenna gain value in decibels (dB) for the 5GHz radio interface,
              and antenna gain must be greater than cable loss.
              Valid values range from 0 to 20. For example, 5.
            type: int
            required: false
          radio_role_assignment:
            description: |
              Defines the operational role for the 5GHz radio interface.
              - C(Auto): The controller automatically manages the radio's role. This is the default behavior.
              - C(Client-serving): The radio is dedicated to serving wireless clients.
              - C(Monitor): The radio is dedicated to monitoring the RF environment and does not serve clients.
              Note: This parameter, along with all other radio settings, can only be modified when
              the access point's C(ap_mode) is set to C(Local).
            type: str
            required: false
          cable_loss:
            description: |
              Cable loss in dB for the 5GHz radio interface. Valid values are from 0 to 20.
              This value must be less than the antenna gain. For example, 3.
            type: int
            required: false
          antenna_cable_name:
            description: Name or type of antenna cable used for the 5GHz radio interface.
              For example, "other".
            type: str
            required: false
          channel_assignment_mode:
            description: >
              Specifies the channel assignment for the 5GHz radio interface.
              If the channel assignment is set to "Global", the channel_number is not required.
              When a channel_number is provided, the channel assignment defaults to "Custom".
              Accepts "Global" or "Custom". For example: "Global".
            type: str
            required: false
          channel_number:
            description: >
              Defines the custom channel number for the 5GHz radio interface.
              When a channel number is provided, the channel assignment defaults to "Custom".
              Valid values range from 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
              124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173.
              For example: 36.
            type: int
            required: false
          channel_width:
            description: |
              Width of the channel configured for the 5GHz radio interface. Accepts values
              "20 MHz", "40 MHz", "80 MHz" or "160 MHz". For example, 20 MHz.
            type: str
            required: false
          power_assignment_mode:
            description: >
              Specifies the power assignment mode for the 5 GHz radio interface.
              If the power assignment mode is set to "Global", the power level is not required.
              When a power level is provided, the power assignment mode automatically defaults to "Custom".
              Accepts "Global" or "Custom". For example: "Global".
            type: str
            required: false
          power_level:
            description: >
              Defines the custom power level for the 5 GHz radio interface.
              When a power level is provided, the power assignment mode automatically defaults to "Custom".
              Valid values range from 1 to 8. For example: 3.
            type: int
            required: false
      6ghz_radio:
        description: |
          Configuration options for the 6GHz radio interface.
          Note: Updating access point radio configuration varies based on each model.
          Refer to the respective access point documentation before updating the radio configuration.
        type: dict
        required: false
        suboptions:
          admin_status:
            description: Administrative status for the 6GHz radio interface. For example,
              "Enabled".
            type: str
            required: false
          antenna_name:
            description: Name or type of antenna used for the 6GHz radio interface.
              For example, "other".
            type: str
            required: false
          antenna_gain:
            description: |
              Antenna gain value in decibels (dB) for the 6GHz radio interface,
              and antenna gain must be greater than cable loss. Valid values range
              from 0 to 40. For example, 10.
            type: int
            required: false
          radio_role_assignment:
            description: |
              Defines the operational role for the 6GHz radio interface.
              - C(Auto): The controller automatically manages the radio's role. This is the default behavior.
              - C(Client-serving): The radio is dedicated to serving wireless clients.
              - C(Monitor): The radio is dedicated to monitoring the RF environment and does not serve clients.
              Note: This parameter, along with all other radio settings, can only be modified when
              the access point's C(ap_mode) is set to C(Local).
            type: str
            required: false
          cable_loss:
            description: |
              Cable loss in dB for the 6GHz radio interface. Valid values are from 0 to 40.
              This value must be less than the antenna gain. For example, 10.
            type: int
            required: false
          antenna_cable_name:
            description: Name or type of antenna cable used for the 6GHz radio interface.
              For example, "other".
            type: str
            required: false
          channel_assignment_mode:
            description: >
              Specifies the channel assignment for the 6GHz radio interface.
              If the channel assignment is set to "Global", the channel_number is not required.
              When a channel_number is provided, the channel assignment defaults to "Custom".
              Accepts "Global" or "Custom". For example: "Global".
            type: str
            required: false
          channel_number:
            description: >
              Defines the custom channel number for the 6GHz radio interface.
              When a channel number is provided, the channel assignment defaults to "Custom".
              Valid values range from 1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53,
              57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121,
              125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181,
              185, 189, 193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233.
              For example: 53.
            type: int
            required: false
          channel_width:
            description: |
              Width of the channel configured for the 6GHz radio interface. Accepts values
              "20 MHz", "40 MHz", "80 MHz", "160 MHz" or "320 MHz". For example, 20 MHz.
            type: str
            required: false
          power_assignment_mode:
            description: >
              Specifies the power assignment mode for the 6GHz radio interface.
              If the power assignment mode is set to "Global", the power level is not required.
              When a power level is provided, the power assignment mode automatically defaults to "Custom".
              Accepts "Global" or "Custom". For example: "Global".
            type: str
            required: false
          power_level:
            description: >
              Defines the custom power level for the 6GHz radio interface.
              When a power level is provided, the power assignment mode automatically defaults to "Custom".
              Valid values range from 1 to 8. For example: 3.
            type: int
            required: false
      xor_radio:
        description: |
          Configuration options for the XOR radio interface.
          Note: Updating access point radio configuration varies based on each model.
          Refer to the respective access point documentation before updating the radio configuration.
        type: dict
        required: false
        suboptions:
          admin_status:
            description: Administrative status for the XOR radio interface. For example,
              "Enabled".
            type: str
            required: false
          antenna_name:
            description: Name or type of antenna used for the XOR radio interface.
              For example, "other".
            type: str
            required: false
          antenna_gain:
            description: |
              Antenna gain value in decibels (dB) for the XOR radio interface,
              and antenna gain must be greater than cable loss. Valid values range
              from 0 to 40. For example, 14.
            type: int
            required: false
          radio_role_assignment:
            description: |
              Defines the operational role for the xor radio interface.
              - C(Auto): The controller automatically manages the radio's role. This is the default behavior.
              - C(Client-serving): The radio is dedicated to serving wireless clients.
              - C(Monitor): The radio is dedicated to monitoring the RF environment and does not serve clients.
              Note: This parameter, along with all other radio settings, can only be modified when
              the access point's C(ap_mode) is set to C(Local).
              If "radio_role_assignment" is set to "Client-serving" only the power level and channel number can be changed.
              Additionally, if the 5 GHz band is selected in the radio band, the power level cannot be modified.
              For example, "Auto".
            type: str
            required: false
          radio_band:
            description: |
              Radio band should be enabled if the radio role assignment is set to "Client-serving" mode.
              Accepts "2.4 GHz" or "5 GHz" or "6 GHz".
            type: str
            required: false
          cable_loss:
            description: |
              Cable loss in dB for the XOR radio interface. Valid values are from 0 to 40.
              This value must be less than the antenna gain. For example, 5.
            type: int
            required: false
          antenna_cable_name:
            description: Name or type of antenna cable used for the XOR radio interface.
              For example, "other".
            type: str
            required: false
          channel_assignment_mode:
            description: |
              If the channel assignment mode is set to "Global", the channel number is not required.
              When a channel number is provided, the channel assignment mode defaults to "Custom".
              Accepts "Global" or "Custom". For example: "Global".
              - For "Custom" mode and a radio band of "2.4 GHz", valid values are from 1 to 14.
              - For "Custom" mode and a radio band of "5 GHz", valid values are
                36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108,
                112, 116, 120, 124, 128, 132, 136, 140, 144,
                149, 153, 157, 161, 165, 169, 173.
              - For "Custom" mode and a radio band of "6 GHz", valid values are
                1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49,
                53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97,
                101, 105, 109, 113, 117, 121, 125, 129, 133, 137,
                141, 145, 149, 153, 157, 161, 165, 169, 173, 177,
                181, 185, 189, 193, 197, 201, 205, 209, 213, 217,
                221, 225, 229, 233.
              For example, "Custom".
            type: str
            required: false
          channel_number:
            description: Custom channel number configured for the XOR radio interface.
              - For "Custom" mode and a radio band of "2.4 GHz", valid values are from 1 to 14.
              - For "Custom" mode and a radio band of "5 GHz", valid values are
                36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108,
                112, 116, 120, 124, 128, 132, 136, 140, 144,
                149, 153, 157, 161, 165, 169, 173.
              - For "Custom" mode and a radio band of "6 GHz", valid values are
                1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49,
                53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97,
                101, 105, 109, 113, 117, 121, 125, 129, 133, 137,
                141, 145, 149, 153, 157, 161, 165, 169, 173, 177,
                181, 185, 189, 193, 197, 201, 205, 209, 213, 217,
                221, 225, 229, 233.
              For example, 6.
            type: int
            required: false
          channel_width:
            description: |
              Width of the channel configured for the XOR radio interface. Accepts values
              "20 MHz", "40 MHz", "80 MHz", "160 MHz" or "320 MHz". For example, 20 MHz.
            type: str
            required: false
          power_assignment_mode:
            description: >
              Specifies the power assignment mode for the XOR radio interface.
              If the power assignment mode is set to "Global", the power level is not required.
              When a power level is provided, the power assignment mode automatically defaults to "Custom".
              Accepts "Global" or "Custom". For example: "Global".
            type: str
            required: false
          power_level:
            description: >
              Defines the custom power level for the XOR radio interface.
              When a power level is provided, the power assignment mode automatically defaults to "Custom".
              Valid values range from 1 to 8. For example: 3.
            type: int
            required: false
      tri_radio:
        description: |
          Configuration options for the TRI radio interface.
          Note: Updating access point radio configuration varies based on each model.
          Refer to the respective access point documentation before updating the radio configuration.
        type: dict
        required: false
        suboptions:
          admin_status:
            description: Administrative status for the TRI radio interface. For example,
              "Enabled".
            type: str
            required: false
          antenna_name:
            description: Name or type of antenna used for the TRI radio interface.
              For example, "other".
            type: str
            required: false
          antenna_gain:
            description: |
              Antenna gain value in decibels (dB) for the TRI radio interface,
              and antenna gain must be greater than cable loss. Valid values range
              from 0 to 40. For example, 16.
            type: int
            required: false
          radio_role_assignment:
            description: |
              Defines the operational role for the TRI radio interface.
              - C(Auto): The controller automatically manages the radio's role. This is the default behavior.
              - C(Client-serving): The radio is dedicated to serving wireless clients.
              - C(Monitor): The radio is dedicated to monitoring the RF environment and does not serve clients.
              Note: This parameter, along with all other radio settings, can only be modified when
              the access point's C(ap_mode) is set to C(Local).
            type: str
            required: false
          cable_loss:
            description: |
              Cable loss in dB for the TRI radio interface. Valid values are from 0 to 40.
              This value must be less than the antenna gain. For example, 6.
            type: int
            required: false
          antenna_cable_name:
            description: Name or type of antenna cable used for the TRI radio interface.
              For example, "other".
            type: str
            required: false
          channel_assignment_mode:
            description: |
              Specifies the channel assignment mode for the TRI radio interface.
              If the channel assignment mode is set to "Global", the channel number is not required.
              When a channel number is provided, the channel assignment mode automatically defaults to "Custom".
              Accepts "Global" or "Custom". For example: "Global".
              For Custom, it accepts values like 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
              132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173. (eg. Custom)
            type: str
            required: false
          channel_number:
            description: Custom channel number configured for the TRI radio interface.
              For Custom, it accepts values like 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
              132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173. (eg. Custom)
              For example, 36.
            type: int
            required: false
          channel_width:
            description: |
              Width of the channel configured for the TRI radio interface. Accepts values
              "20 MHz", "40 MHz", "80 MHz", "160 MHz", or "320 MHz". For example, 20 MHz.
            type: str
            required: false
          power_assignment_mode:
            description: >
              Specifies the power assignment mode for the TRI radio interface.
              If the power assignment mode is set to "Global", the power level is not required.
              When a power level is provided, the power assignment mode automatically defaults to "Custom".
              Accepts "Global" or "Custom". For example: "Global".
            type: str
            required: false
          power_level:
            description: >
              Defines the custom power level for the TRI radio interface.
              When a power level is provided, the power assignment mode automatically defaults to "Custom".
              Valid values range from 1 to 8. For example: 3.
            type: int
            required: false
          dual_radio_mode:
            description: |
              Mode of operation configured for the TRI radio interface. Specifies how the
              access point (AP) manages its dual radio functionality. For example, Auto.
            type: str
            required: false
      ap_selected_fields:
        description: When enabling the verify flag "config_verify" to see only the filter
          field of the AP details in the output. (eg.
          "id,hostname,family,type,mac_address,management_ip_address,ap_ethernet_mac_address")
        type: str
        required: false
      ap_config_selected_fields:
        description: |
          When enabling the verify flag "config_verify" to see only the filter field of the AP configuration in the output.
          (eg. "mac_address,eth_mac,ap_name,led_brightness_level,led_status,location,radioDTOs")
        type: str
        required: false
      reboot_aps:
        description: |
          Reboot one or more access points (APs) identified by their MAC addresses, hostnames, or management IP addresses.
          At least one of the following parameters is required:
          - mac_addresses
          - hostnames
          - management_ip_addresses
        type: dict
        required: false
        suboptions:
          mac_addresses:
            description: A list of MAC addresses used to identify the access points
              for rebooting.
            type: list
            elements: str
            required: false
          hostnames:
            description: |
              A list of hostnames used to identify the access points for rebooting.
            type: list
            elements: str
            required: false
          management_ip_addresses:
            description: |
              A list of management IP addresses used to identify the access points for rebooting.
            type: list
            elements: str
            required: false
      factory_reset_aps:
        description: |
          Factory reset one or more access points (APs) identified by their MAC addresses, hostnames, or management IP addresses.
          At least one of the following parameters is required:
          - mac_addresses
          - hostnames
          - management_ip_addresses
        type: dict
        required: false
        suboptions:
          mac_addresses:
            description: A list of MAC addresses used to identify the access points
              for factory reset.
            type: list
            elements: str
            required: false
          hostnames:
            description: |
              A list of hostnames used to identify the access points for factory reset.
            type: list
            elements: str
            required: false
          management_ip_addresses:
            description: |
              A list of management IP addresses used to identify the access points for factory reset.
            type: list
            elements: str
            required: false
      bulk_update_aps:
        description: |
          Perform a bulk update on multiple access points (APs) of the same series,
          identified by one or more of the following parameters:
          - mac_address
          - hostname
          - management_ip_address
          At least one of these parameters must be specified to identify the APs for updating.
        type: dict
        required: false
        suboptions:
          ap_identifier:
            description: |
              AP identifier is a list of dict which contains MAC address, hostname, or management IP address
              which is used to identify the access points for bulk updated with AP Name to update the access point.
            type: list
            elements: str
            required: true
            suboptions:
              mac_address:
                description: |
                  The MAC address used to identify the device. If provided, it cannot be modified.
                  To identify the specific access point, at least one of the following parameters is required.
                  - mac_address
                  - hostname
                  - management_ip_address
                type: str
                required: true
              hostname:
                description: |
                  The Host Name used to identify the device. If provided, it cannot be modified.
                  To identify the specific access point, at least one of the following parameters is required.
                  - mac_address
                  - hostname
                  - management_ip_address
                type: str
                required: true
              management_ip_address:
                description: |
                  The Management IP Address used to identify the device. If provided, it cannot be modified.
                  To identify the specific access point, at least one of the following parameters is required.
                  - mac_address
                  - hostname
                  - management_ip_address
                type: str
                required: true
              ap_name:
                description: Current AP name that needs to be changed along with the
                  new AP name. For example, "Test2".
                type: str
                required: false
          common_fields_to_change:
            description: |
              Common fields to change AP is a dict which contains below data which is needed to update all listed access points.
            type: dict
            required: true
            suboptions:
              admin_status:
                description: Status of the AP configuration. Accepts "Enabled" or
                  "Disabled". For example, "Enabled".
                type: str
                required: false
              led_status:
                description: >
                  Specifies led status for the access point accepts "Enabled" or "Disabled".
                  When a led brightness level is provided, the led status defaults to "Enabled".
                  For example, "Enabled".
                type: str
                required: false
              led_brightness_level:
                description: Brightness level of the AP's LED. Accepts values from
                  1 to 8. For example, 3.
                type: int
                required: false
              ap_mode:
                description: |
                  Defines the mode of operation for the Access Point (AP). Possible values include "Local",
                  "Monitor", "Sniffer", or "Bridge". For example, "Local".
                type: str
                required: false
              location:
                description: Location name of the AP. Provide this data if a change
                  is required. For example, "Bangalore".
                type: str
                required: false
              is_assigned_site_as_location:
                description: |
                  Configures whether the access point location is automatically set to the site assigned to the access point.
                  Accepts "Enabled" or "Disabled". If set to "Enabled", no additional location configuration is required.
                type: str
                required: false
              failover_priority:
                description: Priority order for failover in AP configuration. Accepts
                  "Low", "Medium", "High", or "Critical".
                type: str
                required: false
              clean_air_si_2.4ghz:
                description: |
                  Clean Air Spectrum Intelligence (SI) feature status for the 2.4GHz band.
                  Indicates whether Clean Air Spectrum Intelligence is enabled or disabled.
                  For example, "Enabled".
                type: str
                required: false
              clean_air_si_5ghz:
                description: |
                  Clean Air Spectrum Intelligence (SI) feature status for the 5GHz band.
                  Indicates whether Clean Air Spectrum Intelligence is enabled or disabled.
                  For example, "Enabled".
                type: str
                required: false
              clean_air_si_6ghz:
                description: |
                  Clean Air Spectrum Intelligence (SI) feature status for the 6GHz band.
                  Indicates whether Clean Air Spectrum Intelligence is enabled or disabled.
                  For example, "Enabled".
                type: str
                required: false
              primary_controller_name:
                description: |
                  Name or identifier of the primary wireless LAN controller (WLC) managing the Access Point (AP).
                  For example, "SJ-EWLC-1".
                type: str
                required: false
              primary_ip_address:
                description: IP address of the primary wireless LAN controller (WLC)
                  managing the Access Point (AP).
                type: dict
                required: false
                suboptions:
                  address:
                    description: IP address of the primary wireless LAN controller.
                      For example, "10.0.0.3".
                    type: str
                    required: false
              secondary_controller_name:
                description: |
                  Name or identifier of the secondary wireless LAN controller (WLC) managing the Access Point (AP).
                  To modify only the primary controller, set the secondary and tertiary controller names
                  to "Inherit from site / Clear".
                type: str
                required: false
              secondary_ip_address:
                description: IP address of the secondary wireless LAN controller (WLC)
                  managing the Access Point (AP).
                type: dict
                required: false
                suboptions:
                  address:
                    description: IP address of the primary wireless LAN controller.
                      For example, "10.0.0.3".
                    type: str
                    required: false
              tertiary_controller_name:
                description: |
                  Name or identifier of the tertiary wireless LAN controller (WLC) managing the Access Point (AP).
                  To modify only the primary controller, set the secondary and tertiary controller names
                  to "Inherit from site / Clear".
                type: str
                required: false
              tertiary_ip_address:
                description: IP address of the tertiary wireless LAN controller (WLC)
                  managing the Access Point (AP).
                type: dict
                required: false
                suboptions:
                  address:
                    description: IP address of the primary wireless LAN controller.
                      For example, "10.0.0.2".
                    type: str
                    required: false
              2.4ghz_radio:
                description: |
                  Configuration options for the 2.4GHz radio interface.
                  Note: Updating access point radio configuration varies based on each model.
                  Refer to the respective access point documentation before updating the radio configuration.
                type: dict
                required: false
                suboptions:
                  admin_status:
                    description: Administrative status for the 2.4GHz radio interface.
                      For example, "Enabled".
                    type: str
                    required: false
                  antenna_name:
                    description: Name or type of antenna used for the 2.4GHz radio
                      interface. For example, "other".
                    type: str
                    required: false
                  antenna_gain:
                    description: |
                      Specifies the antenna gain value in decibels (dB) for the 2.4GHz radio interface,
                      and antenna gain must be greater than cable loss. Valid values range
                      from 0 to 20. For example, 10.
                    type: int
                    required: false
                  radio_role_assignment:
                    description: |
                      Defines the operational role for the 2.4GHz radio interface.
                      - C(Auto): The controller automatically manages the radio's role. This is the default behavior.
                      - C(Client-serving): The radio is dedicated to serving wireless clients.
                      - C(Monitor): The radio is dedicated to monitoring the RF environment and does not serve clients.
                      Note: This parameter, along with all other radio settings, can only be modified when
                      the access point's C(ap_mode) is set to C(Local).
                    type: str
                    required: false
                  cable_loss:
                    description: |
                      Cable loss in dB for the 2.4GHz radio interface. Valid values are from 0 to 20.
                      This value must be less than the antenna gain. For example, 2.
                    type: int
                    required: false
                  antenna_cable_name:
                    description: Name or type of antenna cable used for the 2.4GHz
                      radio interface. For example, "other".
                    type: str
                    required: false
                  channel_assignment_mode:
                    description: >
                      Specifies the channel assignment for the 2.4GHz radio interface.
                      If the channel assignment is set to "Global", the channel_number is not required.
                      When a channel_number is provided, the channel assignment defaults to "Custom".
                      Accepts "Global" or "Custom". For example: "Global".
                    type: str
                    required: false
                  channel_number:
                    description: >
                      Defines the custom channel number for the 2.4GHz radio interface.
                      When a channel number is provided, the channel assignment defaults to "Custom".
                      Valid values range from 1 to 14. For example: 3.
                    type: int
                    required: false
                  power_assignment_mode:
                    description: >
                      Specifies the power assignment mode for the 2.4GHz radio interface.
                      If the power assignment mode is set to "Global", the power level is not required.
                      When a power level is provided, the power assignment mode automatically defaults to "Custom".
                      Accepts "Global" or "Custom". For example: "Global".
                    type: str
                    required: false
                  power_level:
                    description: >
                      Defines the custom power level for the 2.4GHz radio interface.
                      When a power level is provided, the power assignment mode automatically defaults to "Custom".
                      Valid values range from 1 to 8. For example: 3.
                    type: int
                    required: false
              5ghz_radio:
                description: |
                  Configuration options for the 5GHz radio interface.
                  Note: Updating access point radio configuration varies based on each model.
                  Refer to the respective access point documentation before updating the radio configuration.
                type: dict
                required: false
                suboptions:
                  admin_status:
                    description: Administrative status for the 5GHz radio interface.
                      For example, "Enabled".
                    type: str
                    required: false
                  antenna_name:
                    description: Name or type of antenna used for the 5GHz radio interface.
                      For example, "other".
                    type: str
                    required: false
                  antenna_gain:
                    description: |
                      Antenna gain value in decibels (dB) for the 5GHz radio interface,
                      and antenna gain must be greater than cable loss. Valid values range
                      from 0 to 20. For example, 5.
                    type: int
                    required: false
                  radio_role_assignment:
                    description: |
                      Defines the operational role for the 5GHz radio interface.
                      - C(Auto): The controller automatically manages the radio's role. This is the default behavior.
                      - C(Client-serving): The radio is dedicated to serving wireless clients.
                      - C(Monitor): The radio is dedicated to monitoring the RF environment and does not serve clients.
                      Note: This parameter, along with all other radio settings, can only be modified when
                      the access point's C(ap_mode) is set to C(Local).
                      This field is not required for xor series access point slot 1.
                    type: str
                    required: false
                  cable_loss:
                    description: |
                      Cable loss in dB for the 5GHz radio interface. Valid values are from 0 to 20.
                      This value must be less than the antenna gain. For example, 3.
                    type: int
                    required: false
                  antenna_cable_name:
                    description: Name or type of antenna cable used for the 5GHz radio
                      interface. For example, "other".
                    type: str
                    required: false
                  channel_assignment_mode:
                    description: >
                      Specifies the channel assignment for the 5GHz radio interface.
                      If the channel assignment is set to "Global", the channel_number is not required.
                      When a channel_number is provided, the channel assignment defaults to "Custom".
                      Accepts "Global" or "Custom". For example: "Global".
                    type: str
                    required: false
                  channel_number:
                    description: >
                      Defines the custom channel number for the 5GHz radio interface.
                      When a channel number is provided, the channel assignment defaults to "Custom".
                      Valid values range from 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
                      124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173.
                      For example: 36.
                    type: int
                    required: false
                  power_assignment_mode:
                    description: >
                      Specifies the power assignment mode for the 5GHz radio interface.
                      If the power assignment mode is set to "Global", the power level is not required.
                      When a power level is provided, the power assignment mode automatically defaults to "Custom".
                      Accepts "Global" or "Custom". For example: "Global".
                    type: str
                    required: false
                  power_level:
                    description: >
                      Defines the custom power level for the 5GHz radio interface.
                      When a power level is provided, the power assignment mode automatically defaults to "Custom".
                      Valid values range from 1 to 8. For example: 3.
                    type: int
                    required: false
              6ghz_radio:
                description: |
                  Configuration options for the 6GHz radio interface.
                  Note: Updating access point radio configuration varies based on each model.
                  Refer to the respective access point documentation before updating the radio configuration.
                type: dict
                required: false
                suboptions:
                  admin_status:
                    description: Administrative status for the 6GHz radio interface.
                      For example, "Enabled".
                    type: str
                    required: false
                  antenna_name:
                    description: Name or type of antenna used for the 6GHz radio interface.
                      For example, "other".
                    type: str
                    required: false
                  antenna_gain:
                    description: |
                      Antenna gain value in decibels (dB) for the 6GHz radio interface,
                      and antenna gain must be greater than cable loss. Valid values range
                      from 0 to 40. For example, 10.
                    type: int
                    required: false
                  radio_role_assignment:
                    description: |
                      Defines the operational role for the 6GHz radio interface.
                      - C(Auto): The controller automatically manages the radio's role. This is the default behavior.
                      - C(Client-serving): The radio is dedicated to serving wireless clients.
                      - C(Monitor): The radio is dedicated to monitoring the RF environment and does not serve clients.
                      Note: This parameter, along with all other radio settings, can only be modified when
                      the access point's C(ap_mode) is set to C(Local).
                    type: str
                    required: false
                  cable_loss:
                    description: |
                      Cable loss in dB for the 6GHz radio interface. Valid values are from 0 to 40.
                      This value must be less than the antenna gain. For example, 10.
                    type: int
                    required: false
                  antenna_cable_name:
                    description: Name or type of antenna cable used for the 6GHz radio
                      interface. For example, "other".
                    type: str
                    required: false
                  channel_assignment_mode:
                    description: >
                      Specifies the channel assignment for the 6GHz radio interface.
                      If the channel assignment is set to "Global", the channel_number is not required.
                      When a channel_number is provided, the channel assignment defaults to "Custom".
                      Accepts "Global" or "Custom". For example: "Global".
                    type: str
                    required: false
                  channel_number:
                    description: >
                      Defines the custom channel number for the 6GHz radio interface.
                      When a channel number is provided, the channel assignment defaults to "Custom".
                      Valid values range from 1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53,
                      57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121,
                      125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181,
                      185, 189, 193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233.
                      For example: 53.
                    type: int
                    required: false
                  power_assignment_mode:
                    description: >
                      Specifies the power assignment mode for the 6GHz radio interface.
                      If the power assignment mode is set to "Global", the power level is not required.
                      When a power level is provided, the power assignment mode automatically defaults to "Custom".
                      Accepts "Global" or "Custom". For example: "Global".
                    type: str
                    required: false
                  power_level:
                    description: >
                      Defines the custom power level for the 6GHz radio interface.
                      When a power level is provided, the power assignment mode automatically defaults to "Custom".
                      Valid values range from 1 to 8. For example: 3.
                    type: int
                    required: false
              xor_radio:
                description: |
                  Configuration options for the XOR radio interface.
                  Note: Updating access point radio configuration varies based on each model.
                  Refer to the respective access point documentation before updating the radio configuration.
                type: dict
                required: false
                suboptions:
                  admin_status:
                    description: Administrative status for the XOR radio interface.
                      For example, "Enabled".
                    type: str
                    required: false
                  antenna_name:
                    description: Name or type of antenna used for the XOR radio interface.
                      For example, "other".
                    type: str
                    required: false
                  antenna_gain:
                    description: |
                      Antenna gain value in decibels (dB) for the XOR radio interface,
                      and antenna gain must be greater than cable loss. Valid values range
                      from 0 to 40. For example, 14.
                    type: int
                    required: false
                  radio_role_assignment:
                    description: |
                      Defines the operational role for the xor radio interface.
                      - C(Auto): The controller automatically manages the radio's role. This is the default behavior.
                      - C(Client-serving): The radio is dedicated to serving wireless clients.
                      - C(Monitor): The radio is dedicated to monitoring the RF environment and does not serve clients.
                      Note: This parameter, along with all other radio settings, can only be modified when
                      the access point's C(ap_mode) is set to C(Local).
                      If "radio_role_assignment" is set to "Client-serving" only the power level and channel number can be changed.
                      Additionally, if the 5 GHz band is selected in the radio band, the power level cannot be modified.
                      For example, "Auto".
                    type: str
                    required: false
                  radio_band:
                    description: |
                      Radio band should be enabled if the radio role assignment is set to "Client-serving" mode.
                      Accepts "2.4 GHz" or "5 GHz" or "6 GHz".
                    type: str
                    required: false
                  cable_loss:
                    description: |
                      Cable loss in dB for the XOR radio interface. Valid values are from 0 to 40.
                      This value must be less than the antenna gain. For example, 5.
                    type: int
                    required: false
                  antenna_cable_name:
                    description: Name or type of antenna cable used for the XOR radio
                      interface. For example, "other".
                    type: str
                    required: false
                  channel_assignment_mode:
                    description: |
                      If the channel assignment mode is set to "Global", the channel number is not required.
                      When a channel number is provided, the channel assignment mode defaults to "Custom".
                      Accepts "Global" or "Custom". For example: "Global".
                      - For "Custom" mode and a radio band of "2.4 GHz", valid values are from 1 to 14.
                      - For "Custom" mode and a radio band of "5 GHz", valid values are
                        36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108,
                        112, 116, 120, 124, 128, 132, 136, 140, 144,
                        149, 153, 157, 161, 165, 169, 173.
                      - For "Custom" mode and a radio band of "6 GHz", valid values are
                        1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49,
                        53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97,
                        101, 105, 109, 113, 117, 121, 125, 129, 133, 137,
                        141, 145, 149, 153, 157, 161, 165, 169, 173, 177,
                        181, 185, 189, 193, 197, 201, 205, 209, 213, 217,
                        221, 225, 229, 233.
                      For example, "Custom".
                    type: str
                    required: false
                  channel_number:
                    description: Custom channel number configured for the XOR radio interface.
                      - For "Custom" mode and a radio band of "2.4 GHz", valid values are from 1 to 14.
                      - For "Custom" mode and a radio band of "5 GHz", valid values are
                        36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108,
                        112, 116, 120, 124, 128, 132, 136, 140, 144,
                        149, 153, 157, 161, 165, 169, 173.
                      - For "Custom" mode and a radio band of "6 GHz", valid values are
                        1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49,
                        53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97,
                        101, 105, 109, 113, 117, 121, 125, 129, 133, 137,
                        141, 145, 149, 153, 157, 161, 165, 169, 173, 177,
                        181, 185, 189, 193, 197, 201, 205, 209, 213, 217,
                        221, 225, 229, 233.
                      For example, 6.
                    type: int
                    required: false
                  channel_width:
                    description: |
                      Width of the channel configured for the XOR radio interface. Accepts values
                      "20 MHz", "40 MHz", "80 MHz", "160 MHz" or "320 MHz". For example, 20 MHz.
                    type: str
                    required: false
                  power_assignment_mode:
                    description: >
                      Specifies the power assignment mode for the XOR radio interface.
                      If the power assignment mode is set to "Global", the power level is not required.
                      When a power level is provided, the power assignment mode automatically defaults to "Custom".
                      Accepts "Global" or "Custom". For example: "Global".
                    type: str
                    required: false
                  power_level:
                    description: >
                      Defines the custom power level for the XOR radio interface.
                      When a power level is provided, the power assignment mode automatically defaults to "Custom".
                      Valid values range from 1 to 8. For example: 3.
                    type: int
                    required: false
              tri_radio:
                description: |
                  Configuration options for the TRI radio interface.
                  Note: Updating access point radio configuration varies based on each model.
                  Refer to the respective access point documentation before updating the radio configuration.
                type: dict
                required: false
                suboptions:
                  admin_status:
                    description: Administrative status for the TRI radio interface.
                      For example, "Enabled".
                    type: str
                    required: false
                  antenna_name:
                    description: Name or type of antenna used for the TRI radio interface.
                      For example, "other".
                    type: str
                    required: false
                  antenna_gain:
                    description: |
                      Antenna gain value in decibels (dB) for the TRI radio interface,
                      and antenna gain must be greater than cable loss. Valid values range
                      from 0 to 40. For example, 16.
                    type: int
                    required: false
                  radio_role_assignment:
                    description: |
                      Defines the operational role for the TRI radio interface.
                      - C(Auto): The controller automatically manages the radio's role. This is the default behavior.
                      - C(Client-serving): The radio is dedicated to serving wireless clients.
                      - C(Monitor): The radio is dedicated to monitoring the RF environment and does not serve clients.
                      Note: This parameter, along with all other radio settings, can only be modified when
                      the access point's C(ap_mode) is set to C(Local).
                    type: str
                    required: false
                  cable_loss:
                    description: |
                      Cable loss in dB for the TRI radio interface. Valid values are from 0 to 40.
                      This value must be less than the antenna gain. For example, 6.
                    type: int
                    required: false
                  antenna_cable_name:
                    description: Name or type of antenna cable used for the TRI radio
                      interface. For example, "other".
                    type: str
                    required: false
                  channel_assignment_mode:
                    description: |
                      Specifies the channel assignment mode for the TRI radio interface.
                      If the channel assignment mode is set to "Global", the channel number is not required.
                      When a channel number is provided, the channel assignment mode automatically defaults to "Custom".
                      Accepts "Global" or "Custom". For example: "Global".
                      For Custom, it accepts values like 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
                      132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173. (eg. Custom)
                    type: str
                    required: false
                  channel_number:
                    description: Custom channel number configured for the TRI radio interface.
                      For Custom, it accepts values like 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
                      132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173. (eg. Custom)
                      For example, 36.
                    type: int
                    required: false
                  channel_width:
                    description: |
                      Width of the channel configured for the TRI radio interface. Accepts values
                      "20 MHz", "40 MHz", "80 MHz", "160 MHz", or "320 MHz". For example, 20 MHz.
                    type: str
                    required: false
                  power_assignment_mode:
                    description: >
                      Specifies the power assignment mode for the TRI radio interface.
                      If the power assignment mode is set to "Global", the power level is not required.
                      When a power level is provided, the power assignment mode automatically defaults to "Custom".
                      Accepts "Global" or "Custom". For example: "Global".
                    type: str
                    required: false
                  power_level:
                    description: >
                      Defines the custom power level for the TRI radio interface.
                      When a power level is provided, the power assignment mode automatically defaults to "Custom".
                      Valid values range from 1 to 8. For example: 3.
                    type: int
                    required: false
                  dual_radio_mode:
                    description: |
                      Mode of operation configured for the TRI radio interface. Specifies how the
                      access point (AP) manages its dual radio functionality. For example, Auto.
                    type: str
                    required: false
requirements:
  - dnacentersdk >= 2.7.2
  - python >= 3.8
seealso:
  - name: Cisco DNAC Ansible Collection Documentation
    description: Complete guide to using the Cisco DNAC Ansible collection.
    link: https://docs.ansible.com/ansible/latest/collections/cisco/dnac/index.html
  - name: Cisco DNAC API Documentation
    description: Official API documentation for Cisco DNAC.
    link: https://developer.cisco.com/docs/dna-center/
notes:
  - Make sure to install the required Python dependencies by executing pip install
    dnacentersdk.
  - SDK Method used are
  - devices.get_device_list
  - wireless.get_access_point_configuration
  - sites.get_site
  - sda.get_device_info
  - sites.assign_devices_to_site
  - wireless.ap_provision
  - wireless.configure_access_points
  - sites.get_membership
  - Paths used are
  - GET  /dna/intent/api/v1/network-device
  - GET  /dna/intent/api/v1/site
  - GET  /dna/intent/api/v1/business/sda/device
  - POST /dna/intent/api/v1/wireless/ap-provision
  - GET  /dna/intent/api/v1/membership/{siteId}
  - GET  /dna/intent/api/v1/wireless/accesspoint-configuration/details/{task_id}
  - POST /dna/intent/api/v2/wireless/accesspoint-configuration
  - POST /dna/intent/api/v1/assign-device-to-site/{siteId}/device
"""
EXAMPLES = r"""
- name: Provision/Move/Update Wireless Access Point Configuration
  hosts: dnac_servers
  connection: local
  gather_facts: false  # This space must be "no." It was set to false due to formatting errors.
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: false
        state: merged
        config:
          - mac_address: 90:e9:5e:03:f3:40
            2.4ghz_radio:
              admin_status: "Enabled"
              antenna_name: "AIR-ANT2513P4M-N-2.4GHz"
              radio_role_assignment: "Client-Serving"
              power_level: 5
              channel_number: 7
      register: output_list
    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: false
        state: merged
        config:
          - mac_address: 90:e9:5e:03:f3:40
            2.4ghz_radio:
              admin_status: "Enabled"
              power_assignment_mode: "Global"
      register: output_list
    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: false
        state: merged
        config:
          - mac_address: 90:e9:5e:03:f3:40
            2.4ghz_radio:
              admin_status: "Enabled"
              channel_assignment_mode: "Global"
      register: output_list
    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: false
        state: merged
        config:
          - mac_address: 90:e9:5e:03:f3:40
            5ghz_radio:
              admin_status: "Enabled"
              antenna_name: "AIR-ANT2513P4M-N-5GHz"
      register: output_list
    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: false
        state: merged
        config:
          - mac_address: 90:e9:5e:03:f3:40
            5ghz_radio:
              admin_status: "Enabled"
              antenna_name: "AIR-ANT2513P4M-N-5GHz"
              radio_role_assignment: "Client-Serving"
              channel_number: 44
      register: output_list
    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: false
        state: merged
        config:
          - mac_address: 90:e9:5e:03:f3:40
            5ghz_radio:
              admin_status: "Enabled"
              antenna_name: "C-ANT9104-Single-D0-5GHz"
              channel_number: 52
              power_level: 5
              channel_width: "40 MHz"
      register: output_list
    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: false
        state: merged
        config:
          - mac_address: 90:e9:5e:03:f3:40
            2.4ghz_radio:
              admin_status: "Enabled"
              antenna_name: "C-ANT9103-2.4GHz"
              channel_number: 9
              power_level: 4
            5ghz_radio:
              admin_status: "Enabled"
              antenna_name: "C-ANT9103-5GHz"
              channel_number: 40
              power_level: 3
              channel_width: "20 MHz"
      register: output_list
    - name: Provisioning and Re-provisiong Access Point Site details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        state: merged
        config:
          - mac_address: 90:e9:5e:03:f3:40
            rf_profile: "HIGH"
            site:
              floor:
                name: "FLOOR1"
                parent_name: "Global/USA/New York/BLDNYC"
      register: output_list
    - name: Updating Access Point Update / Controller Name
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        state: merged
        config:
          - mac_address: a4:88:73:d4:d6:60
            ap_name: "Cisco_Test_AP_T003"
            admin_status: "Enabled"
            led_status: "Enabled"
            led_brightness_level: 1
            ap_mode: "Local"
            is_assigned_site_as_location: "Enabled"
            failover_priority: "Low"
            primary_controller_name: "NY-EWLC-1"
            primary_ip_address:
              address: "204.192.6.200"
            secondary_controller_name: "NY-EWLC-20"
            secondary_ip_address:
              address: "fe80::202:b3ff:fe1e:8324"
            tertiary_controller_name: "SJ-EWLC-20"
            tertiary_ip_address:
              address: "fe80::202:b3ff:fe1e:8325"
      register: output_list
    - name: Updating Access Point Update / remove tertiary_controller_name
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        state: merged
        config:
          - mac_address: a4:88:73:d4:d6:60
            ap_name: "Cisco_Test_AP_T003"
            admin_status: "Enabled"
            led_status: "Enabled"
            led_brightness_level: 1
            ap_mode: "Local"
            is_assigned_site_as_location: "Enabled"
            failover_priority: "Low"
            primary_controller_name: "NY-EWLC-10"
            primary_ip_address:
              address: "fe80::202:b3ff:fe1e:8329"
            secondary_controller_name: "NY-EWLC-20"
            secondary_ip_address:
              address: "fe80::202:b3ff:fe1e:8324"
            tertiary_controller_name: "Inherit from site / Clear"
      register: output_list
    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: false
        state: merged
        config:
          - mac_address: 90:e9:5e:03:f3:40
            rf_profile: "HIGH"
            site:
              floor:
                name: "FLOOR1"
                parent_name: "Global/USA/New York/BLDNYC"
            ap_name: "LTTS-test2"
            admin_status: "Enabled"
            led_status: "Enabled"
            led_brightness_level: 5
            ap_mode: "Local"
            is_assigned_site_as_location: "Enabled"
            failover_priority: "Low"
            2.4ghz_radio:
              admin_status: "Enabled"
              antenna_name: "C-ANT9104-2.4GHz"
              radio_role_assignment: "Client-Serving"
              channel_number: 5
              power_level: 2
            5ghz_radio:
              admin_status: "Enabled"
              antenna_name: "AIR-ANT2513P4M-N-5GHz"
              radio_role_assignment: "Client-Serving"
              channel_number: 36
              power_level: 2
              channel_width: "40 MHz"
      register: output_list
    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        state: merged
        config:
          - mac_address: 6c:d6:e3:75:5a:e0
            ap_name: "LTTS_Test_9120_T2"
            admin_status: "Enabled"
            led_status: "Enabled"
            led_brightness_level: 2
            ap_mode: "Local"
            is_assigned_site_as_location: "Enabled"
            failover_priority: "Low"
            primary_controller_name: "NY-IAC-EWLC.cisco.local"
            primary_ip_address:
              address: "204.192.6.200"
            secondary_controller_name: "Inherit from site / Clear"
            tertiary_controller_name: "Inherit from site / Clear"
            xor_radio:
              admin_status: "Enabled"
              radio_role_assignment: "Client-Serving"
              channel_number: 4
              radio_band: "2.4 GHz"
              channel_width: "40 MHz"
            5ghz_radio:
              admin_status: "Enabled"
              antenna_name: "AIR-ANT2513P4M-N-5GHz"
              radio_role_assignment: "Client-Serving"
              channel_number: 40
              power_level: 2
              channel_width: "80 MHz"
      register: output_list
    - name: Updating Access Point Configuration
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        state: merged
        config:
          - mac_address: e4:38:7e:42:bc:00
            ap_name: "LTTS_Test_9166_T3"
            admin_status: "Enabled"
            led_status: "Enabled"
            led_brightness_level: 3
            ap_mode: "Local"
            is_assigned_site_as_location: "Enabled"
            failover_priority: "Low"
            primary_controller_name: "NY-IAC-EWLC"
            primary_ip_address:
              address: "204.192.6.200"
            secondary_controller_name: "Inherit from site / Clear"
            tertiary_controller_name: "Inherit from site / Clear"
            2.4ghz_radio:
              admin_status: "Enabled"
              radio_role_assignment: "Client-Serving"
              channel_number: 3
              power_level: 3
            5ghz_radio:
              admin_status: "Enabled"
              radio_role_assignment: "Client-Serving"
              channel_number: 44
              power_level: 3
              channel_width: "20 MHz"
            xor_radio:
              admin_status: "Enabled"
              radio_role_assignment: "Client-Serving"
              channel_number: 1
              power_level: 3
              radio_band: "6 GHz"
              channel_width: "40 MHz"
      register: output_list
    - name: Reboot single or multiple access point
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        state: merged
        config:
          - reboot_aps:
              mac_addresses:
                - "6c:d6:e3:75:5a:e0"
                - "e4:38:7e:42:bc:00"
      register: output_list
    - name: Reboot single or multiple access point by hostname
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        state: merged
        config:
          - reboot_aps:
              hostnames:
                - "cisco_Test_9166_T3"
                - "cisco_Test_9120_T1"
      register: output_list
    - name: Factory reset single or multiple access point
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        state: merged
        config:
          - factory_reset_aps:
              mac_addresses:
                - "6c:d6:e3:75:5a:e0"
                - "e4:38:7e:42:bc:00"
      register: output_list
    - name: Bulk update Access Point Configurations
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        state: merged
        config:
          - bulk_update_aps:
              ap_identifier:
                - mac_address: e4:38:7e:42:bc:40
                  ap_name: "Cisco_9166_T2"
                - mac_address: a4:88:73:d0:53:60
                  ap_name: "Cisco_9120_T2"
              common_fields_to_change:
                admin_status: "Disabled"
                led_status: "Enabled"
                led_brightness_level: 1
                ap_mode: "Local"
                is_assigned_site_as_location: "Enabled"
                failover_priority: "Low"
                clean_air_si_2.4ghz: "Enabled"
                clean_air_si_5ghz: "Enabled"
                clean_air_si_6ghz: "Disabled"
                primary_controller_name: "SJ-EWLC-1"
                primary_ip_address:
                  address: "204.192.4.200"
                secondary_controller_name: "Inherit from site / Clear"
                tertiary_controller_name: "Inherit from site / Clear"
"""
RETURN = r"""
#Case 1: Updating Access Point Configuration Details
response_1:
  description: >
    A list of dictionaries containing details about the AP updates and verification
    results, as returned by the Catalyst Center Python SDK
  returned: always
  type: dict
  sample: |
    {
        "response": [{
                "changed": true,
                "response": {
                    "ap_config_update_status": "The update for AP Config Cisco_Test_9120_T1 has been successfully verified."
                }
        }]
    }
#Case-2: Provisioning and Re-Provisioning of Accesspoint
response_2:
  description: >
    A dictionary with provision status returned by the Catalyst Center Python SDK
  returned: always
  type: dict
  sample: |
    {
        "response": [
        {
            "changed": true,
            "response": {
                "ap_provision_update_status": "AP provision for the site 'Global/Chennai/LTTS/FLOOR1' has been successfully verified."
            }
        }]
    }
#Case-3: Reboot single or multiple Accesspoint task
response_3:
  description: >
    A dictionary with reboot status of AP returned by the Catalyst Center Python SDK
  returned: always
  type: dict
  sample: |
    {
        "response": {
            "accesspoints_updates": {
                "ap_reboot_status": "AP ['6c:d6:e3:69:49:b4', '68:49:92:75:0f:d0'] Rebooted Successfully",
                "ap_reboot_task_details": {
                    "reboot_api_response": {
                        "apList": [
                            {
                                "apName": "LTTS_Test_9120_T2",
                                "failureReason": null,
                                "rebootStatus": "Success"
                            },
                            {
                                "apName": "LTTS_Test_9166_T3",
                                "failureReason": null,
                                "rebootStatus": "Success"
                            }
                        ],
                        "wlcIP": "204.192.6.200"
                    }
                }
            }
        }
    }
#Case-4: Bulk update for single or multiple Accesspoint
response_4:
  description: >
    A dictionary with bulk update status of AP returned by the Catalyst Center Python SDK
  returned: always
  type: dict
  sample: |
    {
      "response": {
        "accesspoints_updates": {
            "ap_config_update_status": ""List of AP Configuration ['Cisco_9120_T2', 'Cisco_9166_T2'] updated Successfully"",
            "ap_update_config_task_details": {
                "data": "workflow_id=76da6b66-ebf8-4697-bf78-5bd1b45b6367;cfs_id=2fca9272-0209-4fd8-9c54-4e1e690b39ff,a6595513-d395-4a99-bd53-a42b722e9aee;
                        rollback_status=not_supported;rollback_taskid=0;failure_task=NA;processcfs_complete=true",
                "progress": "TASK_INTENT"
            }
        }
      }
    }
#Case-5: Factory reset for single or multiple Accesspoint
response_5:
  description: >
    A dictionary with factory reset status of AP returned by the Catalyst Center Python SDK
  returned: always
  type: dict
  sample: |
    {
      "response": {
          "accesspoints_updates": {
              "ap_reset_status": "APs ['a4:88:73:ce:0a:6c'] reset successfully",
              "ap_reset_task_details": {
                  "reset_api_response": [
                      {
                          "apFactoryResetStatus": "Success",
                          "apName": "Cisco_9120_T1",
                          "ethernetMacAddress": "a4:88:73:ce:0a:6c",
                          "failureReason": null,
                          "radioMacAddress": "a4:88:73:d0:53:60"
                      }
                  ]
              }
          }
      }
    }
"""


import time
import re
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    validate_str,
    get_dict_result,
)
from ansible.module_utils.basic import AnsibleModule


class Accesspoint(DnacBase):
    """Class containing member attributes for DNAC Access Point Automation module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged"]
        self.payload = module.params
        self.payload["consolidated_result"] = []
        self.keymap = {
            "mac_addresses": "mac_address",
            "hostnames": "hostname",
            "management_ip_addresses": "management_ip_address"
        }
        self.radio_interface = ["6ghz_radio", "xor_radio", "tri_radio"]
        self.allowed_series = {
            "6ghz_radio": ["9136I", "9162I", "9163E", "9164I", "IW9167IH", "9178I", "9176I",
                           "9176D1", "9172I", "9172H", "9179F"],
            "xor_radio": ["280", "380", "480", "9120", "9166", "IW9167EH", "IW9165E", "IW9165DH",
                          "9176", "CW9174I", "CW9174E"],
            "tri_radio": ["9124AXE", "9130AXI", "9130AXE", "9178I", "9179F"]
        }
        self.allowed_channel_no = {
            "2.4ghz_radio": list(range(1, 15)),
            "5ghz_radio": (36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
                           124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173),
            "6ghz_radio": list(range(1, 234, 4))
        }

    def validate_input_yml(self):
        """
        Validate fields provided in a YAML file against predefined specifications.
        Checks playbook configuration to ensure it matches expected structure and data types.

        Parameters:
        - self (object): Instance of a class for Cisco Catalyst Center interaction.

        Returns:
        - Updates instance attributes:
            - self.msg: Validation result message.
            - self.status: Validation status ("success" or "failed").
            - self.validated_config: Validated "config" parameter if successful.

        Description:
        Example:
        Instantiate the class and call "validate_input_yml".
        - "self.status" is "success" on successful validation; "self.validated_config" holds
            validated data.
        - "self.status" is "failed" on validation failure; "self.msg" describes issues.
        """

        self.log("Validating the Playbook Yaml File..", "INFO")
        if not self.config:
            self.status = "success"
            self.msg = "Configuration is not available in the playbook for validation"
            self.log(self.msg, "ERROR")
            return self

        accesspoint_spec = {
            "mac_address": {"required": False, "type": "str"},
            "management_ip_address": {"required": False, "type": "str"},
            "hostname": {"required": False, "type": "str"},
            "rf_profile": {"required": False, "type": "str"},
            "site": {"required": False, "type": "dict"},
            "type": {"required": False, "type": "str"},
            "ap_name": {"required": False, "type": "str"},
            "admin_status": {"required": False, "type": "str"},
            "led_status": {"required": False, "type": "str"},
            "led_brightness_level": {"required": False, "type": "int", "range_min": 1, "range_max": 8},
            "ap_mode": {"required": False, "type": "str"},
            "location": {"required": False, "type": "str"},
            "is_assigned_site_as_location": {"required": False, "type": "str"},
            "failover_priority": {"required": False, "type": "str"},
            "primary_controller_name": {"required": False, "type": "str"},
            "primary_ip_address": {"required": False, "type": "dict"},
            "secondary_controller_name": {"required": False, "type": "str"},
            "secondary_ip_address": {"required": False, "type": "dict"},
            "tertiary_controller_name": {"required": False, "type": "str"},
            "tertiary_ip_address": {"required": False, "type": "dict"},
            "clean_air_si_2.4ghz": {"required": False, "type": "str"},
            "clean_air_si_5ghz": {"required": False, "type": "str"},
            "clean_air_si_6ghz": {"required": False, "type": "str"},
            "2.4ghz_radio": {"required": False, "type": "dict"},
            "5ghz_radio": {"required": False, "type": "dict"},
            "6ghz_radio": {"required": False, "type": "dict"},
            "xor_radio": {"required": False, "type": "dict"},
            "tri_radio": {"required": False, "type": "dict"},
            "reboot_aps": {"required": False, "type": "dict"},
            "factory_reset_aps": {"required": False, "type": "dict"},
            "bulk_update_aps": {"required": False, "type": "dict"},
            "ap_selected_fields": {"required": False, "type": "str"},
            "ap_config_selected_fields": {"required": False, "type": "str"}
        }
        radio_config_spec = {
            "admin_status": {"required": False, "type": "str"},
            "dual_radio_mode": {"required": False, "type": "str"},
            "antenna_name": {"required": False, "type": "str"},
            "antenna_gain": {"required": False, "type": "int"},
            "radio_role_assignment": {"required": False, "type": "str"},
            "cable_loss": {"required": False, "type": "int"},
            "antenna_cable_name": {"required": False, "type": "str"},
            "channel_assignment_mode": {"required": False, "type": "str"},
            "channel_number": {"required": False, "type": "int"},
            "power_assignment_mode": {"required": False, "type": "str"},
            "power_level": {"required": False, "type": "int", "range_min": 1, "range_max": 8},
            "channel_width": {"required": False, "type": "str"},
            "radio_band": {"required": False, "type": "str"}
        }
        ap_list = self.update_site_type_key(self.camel_to_snake_case(self.payload.get("config")))

        invalid_list_radio = []
        for each_ap in ap_list:
            for each_radio in ("2.4ghz_radio", "5ghz_radio", "6ghz_radio", "xor_radio", "tri_radio"):
                radio_config = each_ap.get(each_radio)
                if radio_config:
                    valid_param_radio, invalid_params_radio = \
                        validate_list_of_dicts([radio_config], radio_config_spec)
                    if len(invalid_params_radio) > 0:
                        invalid_list_radio.append(each_radio + str(invalid_params_radio))

        valid_param, invalid_params = validate_list_of_dicts(ap_list, accesspoint_spec)

        if invalid_params or invalid_list_radio:
            self.msg = "Invalid parameters in playbook: {0} ".format(
                "\n".join(invalid_params) + "\n".join(invalid_list_radio)
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.validated_config = valid_param
        msg = "Successfully validated playbook config params:{0}".format(self.pprint(valid_param))
        self.log(msg, "INFO")
        self.status = "success"
        return self

    def get_want(self, ap_config):
        """
        Retrieve Access Point configuration and site-related details from the playbook
        needed for AP configuration, provisioning, and re-provisioning.
        Parameters:
            self (object): An instance of a class for Cisco Catalyst Center interaction.
            ap_config (dict): Dictionary containing Access Point configuration information.

        Returns:
            self (object): Updated instance with extracted Access Point configuration
            stored in "want".

        Description:
            Extracts all Access Point configuration details from "ap_config", excluding
            fields such as "ap_selected_fields" and "ap_config_selected_fields".
            The extracted information is stored in the "want" attribute of the
            instance for use in subsequent workflow steps.
        """
        want = {}

        for key, value in ap_config.items():
            if key not in ("ap_selected_fields", "ap_config_selected_fields"):
                if ap_config.get(key) is not None:
                    want[key] = value

        self.want = want
        self.log("Desired State (want): {0}".format(self.pprint(self.want)), "INFO")
        return self

    def get_have(self, input_config):
        """
        Retrieve current Access Point configuration and site releated details from
        Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class for Cisco Catalyst Center interaction.
            input_config (dict): Dictionary containing configuration details.

        Returns:
            self (object): Updated instance with retrieved Access Point configuration stored \
                in "have".

        Description:
            Checks if the specified Access Point configuration and site exists in the system.
            If found, retrieves details such as MAC address, IP address, hostname,
            associated WLC IP, AP type and site information if available, these details
            are stored in the "have" attribute of the instance.
        """
        ap_exists = False
        current_ap_config = None
        (ap_exists, current_ap_config) = self.get_current_config(input_config)

        self.log("Current AP config details (have): {0}".format(self.pprint(
            current_ap_config)), "DEBUG")
        have = {}

        if ap_exists:
            have["mac_address"] = current_ap_config.get("mac_address")
            have["ap_exists"] = ap_exists
            have["current_ap_config"] = current_ap_config
            have["ip_address"] = self.payload["access_point_details"]["management_ip_address"]
            have["device_id"] = self.payload["access_point_details"]["id"]
            have["wlc_provision_status"] = self.payload.get("wlc_provision_status")
            have["ap_provision_status"] = self.payload.get("ap_provision_status")
            have["associated_wlc_ip"] = self.payload["access_point_details"]["associated_wlc_ip"]
            have["hostname"] = self.payload["access_point_details"]["hostname"]
            have["ap_type"] = self.payload["access_point_details"]["family"]

        if self.payload.get("site_exists"):
            have["site_name_hierarchy"] = self.want["site_name"]
            have["site_exists"] = self.payload["current_site"]
            have["site_required_changes"] = False if self.payload["site_changes"] else True
            have["site_id"] = self.payload["current_site"]["site_id"]

        self.have = have
        self.log("Current State (have): {0}".format(self.pprint(self.have)), "INFO")
        return self

    def get_diff_merged(self, ap_config):
        """
        Provision, re-provision, update, or create wireless access point configurations in
        Cisco Catalyst Center using playbook-provided fields.
        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            ap_config (dict): Dictionary containing configuration information.

        Returns:
            self (object): Updated instance with operation results stored in "result".

        Description:
            Determines whether to Provision, re-provision, update or create the Access Point
            configuration in Cisco Catalyst Center based on provided information.
            If the Access Point and site exists, it compares current configuration
            with input data. If changes are required, it updates the configuration using the
            "configure_access_points" function from the Cisco Catalyst Center API.
            If no updates are needed, it logs that the configuration is up to date.
            Handles provisioning and site assignment if specified by playbook data.
        """
        task_response = None
        self.validate_ap_config_parameters(ap_config).check_return_status()
        responses = {}
        responses["accesspoints_updates"] = {}

        if not self.have.get("ap_exists"):
            self.status = "failed"
            self.msg = "Access Point does not exist."
            self.log(self.msg, "ERROR")
            return self

        self.log("Access Point exists. Proceeding with configuration update.", "INFO")

        site_required_changes = self.have.get("site_required_changes")
        site = self.want.get("site")

        if site:
            if site_required_changes:
                if self.have.get("wlc_provision_status") != "success":
                    self.msg = "Wireless Controller {0} not provisioned at the site {1}.".format(
                        self.have.get("associated_wlc_ip"), self.have.get("site_name_hierarchy"))
                    self.log(self.msg, "INFO")
                    self.result["changed"] = False
                    responses["accesspoints_updates"].update({"provision_message": self.msg})
                else:
                    provision_status, provision_details = self.provision_device()
                    if provision_status == "SUCCESS":
                        self.result["changed"] = True
                        self.msg = "AP {0} provisioned successfully.".format(self.have["hostname"])
                        self.log(self.msg, "INFO")
                        responses["accesspoints_updates"].update({
                            "provision_message": self.msg
                        })
                    else:
                        self.msg = "Unable to provision the AP {0} for the site {1}.".format(
                            self.have.get("hostname"), self.have.get("site_name_hierarchy"))
                        self.log(self.msg, "INFO")
                        self.result["changed"] = False
                        responses["accesspoints_updates"].update({"provision_message": self.msg})
            else:
                self.msg = "AP {0} already provisioned at site {1}.".format(
                    self.have["hostname"], self.have.get("site_name_hierarchy"))
                self.log(self.msg, "INFO")
                self.result["changed"] = False
                responses["accesspoints_updates"].update({"provision_message": self.msg})

        if not self.ap_update_required:
            return self

        time.sleep(self.payload.get("next_task_after_interval"))

        self.log("Comparing current AP configuration with input data.", "INFO")
        consolidated_data = self.config_diff(self.have["current_ap_config"])
        if not consolidated_data:
            self.msg += "AP - {0} does not need any update".format(
                self.have.get("current_ap_config").get("ap_name"))
            self.log(self.msg, "INFO")
            del self.payload["access_point_details"]
            responses["accesspoints_updates"].update({
                "ap_config_message": self.msg
            })
            self.result["changed"] = True if self.result["changed"] else False
            self.result["response"] = responses
            self.set_operation_result(
                "success", False, self.msg, "INFO", responses).check_return_status()
            return self

        self.log("Final AP Configuration data to update {0}".format(self.pprint(
            consolidated_data)), "INFO")
        task_response = self.update_ap_configuration(consolidated_data)
        self.log("Access Point update response: {0} .".format(task_response), "INFO")

        if task_response and isinstance(task_response, dict):
            resync_retry_count = self.payload.get("dnac_api_task_timeout")
            resync_retry_interval = self.payload.get("dnac_task_poll_interval")
            while resync_retry_count:
                task_details_response = self.get_tasks_by_id(
                    task_response["response"]["taskId"])
                self.log("Status of the task: {0} .".format(self.status), "INFO")

                if task_details_response.get("endTime") is not None:
                    if task_details_response.get("status") == "FAILURE":
                        self.result["changed"] = True if self.result["changed"] is True else False
                        self.msg = "Unable to get success response, hence AP config not updated"
                        self.log(self.msg, "ERROR")
                        self.log("Task Details: {0} .".format(self.pprint(
                            task_details_response)), "ERROR")
                        failure_details = self.get_task_details_by_id(task_response["response"]["taskId"])
                        self.log("Failure Details: {0} .".format(self.pprint(failure_details)), "ERROR")
                        self.set_operation_result("failed", self.result["changed"],
                                                  self.msg, "ERROR", failure_details).check_return_status()
                    else:
                        self.result["changed"] = True
                        self.result["ap_update_status"] = True
                        self.log("Task Details: {0} .".format(self.pprint(
                            task_details_response)), "INFO")
                        self.msg = "AP Configuration - {0} updated Successfully".format(
                            self.have["current_ap_config"].get("ap_name"))
                        self.log(self.msg, "INFO")
                        responses["accesspoints_updates"] = {
                            "ap_update_config_task_details": self.get_task_details_by_id(task_details_response["id"]),
                            "ap_config_update_status": self.msg
                        }
                        self.result["ap_update_msg"] = self.msg
                    break

                time.sleep(resync_retry_interval)
                resync_retry_count = resync_retry_count - 1

        self.result["response"] = responses
        return self

    def ap_update_required(self):
        """
        Check if the necessary keys are present in the configuration for AP updates.

        Returns:
            bool: True if any of the required keys for AP update are present, False otherwise.
        """
        required_keys_for_updates = [
            "ap_name", "admin_status",
            "led_status", "led_brightness_level", "ap_mode", "location",
            "failover_priority", "clean_air_si_2.4ghz", "clean_air_si_5ghz", "clean_air_si_6ghz",
            "primary_controller_name", "primary_ip_address", "secondary_controller_name", "address",
            "secondary_ip_address", "tertiary_controller_name", "tertiary_ip_address", "2.4ghz_radio",
            "antenna_name", "radio_role_assignment", "cable_loss", "antenna_cable_name",
            "channel_assignment_mode", "channel_number", "power_assignment_mode", "power_level",
            "antenna_gain", "channel_width", "5ghz_radio", "6ghz_radio",
            "xor_radio", "radio_band", "tri_radio", "dual_radio_mode"
        ]
        want_key_list = self.want.keys()
        has_required_keys = bool(set(want_key_list).intersection(required_keys_for_updates))
        return has_required_keys

    def verify_diff_merged(self, config):
        """
        Verify if configuration changes for an Access Point (AP) have been successfully applied
        in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            config (dict): The configuration details to be verified.

        Returns:
            self (object): Updated instance reflecting verification results.

        Description:
            Checks the current and desired states of the AP configuration in Cisco Catalyst Center.
            Logs the current and desired configuration states and verifies if the AP exists and
            whether updates are required. If the configuration matches the desired state,
            it logs a success message. Otherwise, it indicates a potential issue with the
            merge operation.
        """

        self.get_have(config)
        self.log("Current AP Config (have): {0}".format(self.pprint(self.have)), "INFO")
        self.log("Desired AP Config (want): {0}".format(self.pprint(self.want)), "INFO")

        ap_exists = self.have.get("ap_exists")
        ap_name = self.have.get("current_ap_config").get("ap_name")
        responses = {}

        if not ap_exists:
            self.status = "failed"
            self.msg = "AP Config '{0}' does not exist in the system.".format(ap_name)
            self.log(self.msg, "ERROR")
            return self

        self.status = "success"
        self.msg = """The requested AP Config '{0}' is present in the Cisco Catalyst Center
                    and its updation has been verified.""".format(ap_name)
        self.log(self.msg, "INFO")

        unmatch_count = 0
        require_update = self.config_diff(self.have["current_ap_config"])
        self.log(self.pprint(require_update), "INFO")
        if require_update:
            radio_list = require_update.get(self.keymap["radio_configurations"], [])
            if len(radio_list) > 0:
                for each_radio in radio_list:
                    radio_key_list = list(each_radio.keys())
                    for each_key in radio_key_list:
                        if each_key not in ("antenna_name", self.keymap["radio_type"], "unmatch", "cable_loss",
                                            self.keymap["radio_role_assignment"], self.keymap["radio_band"],
                                            self.keymap["admin_status"]):
                            unmatch_count += 1

            other_keys = list(require_update.keys())
            self.log(other_keys, "INFO")
            for each_key in other_keys:
                if each_key not in (self.keymap["mac_address"], self.keymap["radio_configurations"],
                                    self.keymap["is_assigned_site_as_location"], "macAddress",
                                    self.keymap["primary_controller_name"], self.keymap["secondary_controller_name"],
                                    self.keymap["tertiary_controller_name"], self.keymap["primary_ip_address"],
                                    self.keymap["secondary_ip_address"], self.keymap["tertiary_ip_address"],
                                    self.keymap["clean_air_si_2.4ghz"], self.keymap["clean_air_si_5ghz"],
                                    self.keymap["clean_air_si_6ghz"]):
                    unmatch_count += 1

        self.log("Unmatch count for the radio configuration : {0}".format(str(unmatch_count)), "INFO")
        self.log(str(require_update), "INFO")
        responses["accesspoints_verify"] = {}

        if self.have.get("site_required_changes") is False:
            msg = "AP provision for the site '{0}' has been successfully verified."\
                .format(self.want.get("site_name"))
            responses["accesspoints_verify"]["ap_provision_update_status"] = msg
            self.result["changed"] = True

        self.log("Unmatch count for the radio configuration : {0}".format(str(unmatch_count)), "INFO")
        if self.result.get("ap_update_status") is True:
            if unmatch_count < 1:
                msg = "The update for AP Config '{0}' has been successfully verified.".format(ap_name)
                self.log(msg, "INFO")
                self.status = "success"
                self.result["changed"] = True

                ap_selected_fields = self.payload.get("config")[0].get("ap_selected_fields")
                if ap_selected_fields is None or ap_selected_fields == "" or ap_selected_fields == "all":
                    self.payload["access_point_details"] = self.payload["access_point_details"]
                else:
                    self.payload["access_point_details"] = self.data_frame(
                        ap_selected_fields, [self.payload["access_point_details"]])

                ap_config_selected_fields =\
                    self.payload.get("config")[0].get("ap_config_selected_fields")
                if ap_config_selected_fields is None or ap_config_selected_fields == "" \
                   or ap_config_selected_fields == "all":
                    self.payload["access_point_config"] = self.payload["access_point_config"]
                else:
                    self.payload["access_point_config"] = self.data_frame(
                        ap_config_selected_fields, [self.payload["access_point_config"]])
                self.have["current_ap_config"] = self.payload["access_point_config"]

                responses["accesspoints_verify"]["ap_config_update_status"] = msg
            else:
                self.msg = "Configuration for AP '{0}' does not match the desired state."\
                    .format(ap_name)
                self.log(self.msg, "DEBUG")
                self.status = "failed"

        self.result["response"] = responses
        return self

    def validate_radio_series(self, ap_config):
        """
        Additional validation to check if the provided input radio configuration data series
        can be updated to the Access Point radio configuration in Cisco Catalyst Center.

        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            ap_config (dict): Dictionary containing the input configuration details.

        Returns:
            list: List of invalid radio interfaces with details.

        Description:
            Iterates through available radio interfaces and checks if the Access Point
            series supports the specified radio type. If not supported, adds details
            to the "invalid_series" list. Returns the list of invalid radio interfaces
            for further action or validation.
        """
        invalid_series = []
        self.log("Starting validation of radio series with configuration: {0}".format(str(ap_config)), "INFO")
        for radio_type in self.radio_interface:
            ap_series = ap_config.get(radio_type)
            self.log("Validating radio type: {0}".format(radio_type), "INFO")

            if ap_series is not None:
                for series in self.allowed_series[radio_type]:
                    compiled_pattern = re.compile(r'\b{0}\w+|\b{0}\b'.format(re.escape(series)))
                    is_valid = compiled_pattern.search(self.payload["access_point_details"]["series"])
                    if is_valid:
                        invalid_series = []
                        break

                    invalid_entry = "Access Point series '{0}' not supported for the radio type {1} allowed series {2}".format(
                        self.payload["access_point_details"]["series"],
                        radio_type,
                        str(series)
                    )
                    self.log("Invalid series detected: {}".format(invalid_entry), "DEBUG")
                    invalid_series.append(invalid_entry)

        self.log("Completed validation. Invalid series: {}".format(invalid_series), "INFO")
        return invalid_series

    def validate_ap_config_parameters(self, ap_config):
        """
        Additional validation for the update API AP configuration, AP provisioning,
        and re-provisioning payload.

        Parameters:
        - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        - ap_config (dict): A dictionary containing the input configuration details.

        Returns:
        An instance of the class with updated attributes:
            - self.msg (str): A message describing the validation result.
            - self.status (str): The status of the validation ("success" or "failed").

        Description:
        This method validates various parameters in the AP configuration, AP provisioning, and
        re-provisioning provided by the playbook. It checks and logs errors for fields such as
        MAC address validity, IP address formats, string lengths, and specific values for
        fields like LED status and radio settings.

        Example:
        To use this method, create an instance of the class and call "validate_ap_config_parameters"
        on it. If validation succeeds, "self.status" will be "success". If it fails, "self.status"
        will be "failed", and "self.msg" will describe the validation issues.
        """
        errormsg = []
        for reboot_reset in ("reboot_aps", "factory_reset_aps"):
            reboot_reset_aps = ap_config.get(reboot_reset)
            if reboot_reset_aps is not None:
                ap_identity_type = list(reboot_reset_aps.keys())[0]  # Retrieve the type (mac, hostname, or IP)
                if ap_identity_type and ap_identity_type in self.keymap and len(reboot_reset_aps.get(ap_identity_type)) > 0:
                    for ap_identifier in reboot_reset_aps[ap_identity_type]:
                        if ap_identity_type == "mac_addresses":
                            mac_regex = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
                            if not mac_regex.match(ap_identifier):
                                errormsg.append("mac_addresses: Invalid MAC Address '{0}' in playbook.".format(
                                    str(ap_identifier)))
                                self.log("Invalid MAC address for {0}: {1}".format(reboot_reset, ap_identifier), "ERROR")
                        elif ap_identity_type == "management_ip_addresses":
                            if not (self.is_valid_ipv4(ap_identifier) or self.is_valid_ipv6(ap_identifier)):
                                errormsg.append("management_ip_addresses: Invalid Management IP Address '{0}' in playbook."
                                                .format(ap_identifier))
                                self.log("Invalid Management IP address for {0}: {1}".format(reboot_reset, ap_identifier), "ERROR")
                        elif ap_identity_type == "hostnames":
                            param_spec = dict(type="str", length_max=32)
                            validate_str(ap_identifier, param_spec, "hostnames", errormsg)
                            self.log("Hostname validation for '{0}' in {1} completed.".format(ap_identifier, reboot_reset), "DEBUG")

        ap_identifier = ap_config.get("ap_identifier")
        common_fields_to_change = ap_config.get("common_fields_to_change")
        self.log("Processing AP configuration. ap_identifier: {0}, common_fields_to_change: {1}".
                 format(ap_identifier, common_fields_to_change), "DEBUG")
        if ap_identifier is not None:
            for each_ap in ap_identifier:
                self.log("Validating AP entry: {0}".format(each_ap), "DEBUG")
                mac_address = each_ap.get("mac_address")
                if mac_address:
                    self.validate_mac_address(mac_address, errormsg)

                management_ip_address = each_ap.get("management_ip_address")
                if management_ip_address:
                    self.validate_ip_address(management_ip_address, "management_ip_address",
                                             errormsg)

                hostname = each_ap.get("hostname")
                if hostname:
                    self.log("Validating Hostname: {0}".format(hostname), "DEBUG")
                    param_spec = dict(type="str", length_max=32)
                    validate_str(hostname, param_spec, "hostname", errormsg)
                    self.log("Hostname validation for '{0}' completed.".format(hostname), "INFO")

                ap_name = each_ap.get("ap_name")
                if ap_name:
                    self.log("Validating AP Name: {0}".format(ap_name), "DEBUG")
                    param_spec = dict(type="str", length_max=32)
                    validate_str(ap_name, param_spec, "ap_name", errormsg)
                    if re.search(r'[ ?<]', ap_name):
                        errormsg.append("ap_name: Invalid '{0}' in playbook. Space, '?', '<' and XSS characters are not allowed".
                                        format(ap_name))
                    else:
                        self.log("AP Name '{0}' is valid.".format(ap_name), "INFO")
        if common_fields_to_change is not None:
            ap_config = common_fields_to_change
            self.log("Updated ap_config with common_fields_to_change: {0}".format(common_fields_to_change), "DEBUG")

        invalid_series = self.validate_radio_series(ap_config)
        if invalid_series:
            errormsg.append(invalid_series)
        else:
            self.log("Radio series validation completed with no errors.", "INFO")

        mac_address = ap_config.get("mac_address")
        if mac_address:
            mac_regex = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
            if not mac_regex.match(mac_address):
                errormsg.append("mac_address: Invalid MAC Address '{0}' in playbook.".format(
                    mac_address))

        management_ip_address = ap_config.get("management_ip_address")
        if management_ip_address and (not self.is_valid_ipv4(management_ip_address) and
                                      not self.is_valid_ipv6(management_ip_address)):
            errormsg.append("management_ip_address: Invalid Management IP Address '{0}'\
                            in playbook.".format(management_ip_address))

        rf_profile = ap_config.get("rf_profile")
        if rf_profile:
            self.log("Validating RF profile: {0}".format(rf_profile), "DEBUG")
            param_spec = dict(type="str", length_max=32)
            validate_str(rf_profile, param_spec, "rf_profile", errormsg)
            self.log("RF profile '{0}' validation completed.".format(rf_profile), "DEBUG")

        site = ap_config.get("site")
        if site:
            floor = site.get("floor")
            if floor:
                floor_name = floor.get("name")
                if floor_name and (not isinstance(floor_name, str) or len(floor_name) > 32):
                    errormsg.append("name: Invalid type or length > 32 characters in playbook.")

                parent_name = floor.get("parent_name")
                if parent_name and (not isinstance(parent_name, str) or len(parent_name) > 64):
                    errormsg.append("parent_name: Invalid type or length > 64 characters in playbook.")

        ap_name = ap_config.get("ap_name")
        if ap_name:
            param_spec = dict(type="str", length_max=32)
            validate_str(ap_name, param_spec, "ap_name", errormsg)
            if re.search(r'[ ?<]', ap_name):
                errormsg.append("ap_name: Invalid '{0}' in playbook. Space, '?', '<' and XSS characters are not allowed".format(ap_name))

        admin_status = ap_config.get("admin_status")
        if admin_status and admin_status not in ("Enabled", "Disabled"):
            errormsg.append("admin_status: Invalid value '{0}' for admin_status in playbook. Must be either 'Enabled' or 'Disabled'."
                            .format(admin_status))

        led_brightness_level = ap_config.get("led_brightness_level")
        if led_brightness_level and led_brightness_level not in range(1, 9):
            errormsg.append("led_brightness_level: Invalid LED Brightness level '{0}' in playbook."
                            .format(led_brightness_level))

        led_status = ap_config.get("led_status")
        if led_status and led_status not in ("Disabled", "Enabled"):
            errormsg.append("led_status: Invalid LED Status '{0}' in playbook.".format(led_status))

        location = ap_config.get("location")
        if location:
            param_spec = dict(type="str", length_max=255)
            validate_str(location, param_spec, "location", errormsg)

        is_assigned_site_as_location = ap_config.get("is_assigned_site_as_location")
        if is_assigned_site_as_location and is_assigned_site_as_location not in ("Disabled", "Enabled"):
            errormsg.append("is_assigned_site_as_location: Invalid value '{0}' for is_assigned_site_as_location in playbook.\
                            Must be either 'Disabled' or 'Enabled'.".format(is_assigned_site_as_location))

        ap_mode = ap_config.get("ap_mode")
        if ap_mode and ap_mode not in ("Local", "Monitor", "Sniffer", "Bridge"):
            errormsg.append("ap_mode: Invalid value '{0}' for ap_mode in playbook. Must be one of: Local, Monitor, Sniffer or Bridge."
                            .format(ap_mode))

        failover_priority = ap_config.get("failover_priority")
        if failover_priority and failover_priority not in ("Low", "Medium", "High", "Critical"):
            errormsg.append("failover_priority: Invalid value '{0}' for failover_priority in playbook. Must be one of: Low, Medium, High or Critical."
                            .format(failover_priority))

        for freq_band in ["clean_air_si_2.4ghz", "clean_air_si_5ghz", "clean_air_si_6ghz"]:
            ap_config_freq_band = ap_config.get(freq_band)
            if ap_config_freq_band and ap_config_freq_band not in ("Enabled", "Disabled"):
                errormsg.append("{0}: Invalid value '{1}' in playbook. Must be either 'Enabled' or 'Disabled'."
                                .format(freq_band, ap_config_freq_band))

        # Validate Controller Names
        check_duplicate_controller = []
        for ctrl_name in ["primary_controller_name", "secondary_controller_name", "tertiary_controller_name"]:
            controller = ap_config.get(ctrl_name)
            if controller is not None:
                if controller == "":
                    errormsg.append("{0}: Invalid {1} in playbook. Please select one of: Inherit from site / Clear or Controller name."
                                    .format(ctrl_name, controller))
                elif controller != "Inherit from site / Clear" and controller in check_duplicate_controller:
                    errormsg.append("{0}: Duplicate {1} in playbook.".format(ctrl_name, controller))
                check_duplicate_controller.append(controller)

        # Validate controller IP Addresses
        check_duplicate_ip = []
        for ip_address in ["primary_ip_address", "secondary_ip_address", "tertiary_ip_address"]:
            ap_config_ip_address = ap_config.get(ip_address)
            address = ap_config_ip_address.get("address") if ap_config_ip_address else None
            if address:
                if not self.is_valid_ipv4(address) and not self.is_valid_ipv6(address):
                    errormsg.append("{0}: Invalid IP address '{1}' in playbook".format(ip_address, address))
                elif address != "0.0.0.0" and address in check_duplicate_ip:
                    errormsg.append("{0}: Duplicate IP address '{1}' in playbook".format(ip_address, address))
                check_duplicate_ip.append(address)

        # Validate Dual Radio Mode
        dual_radio_mode = ap_config.get("dual_radio_mode")
        if dual_radio_mode and dual_radio_mode not in ["Auto", "Enable", "Disable"]:
            errormsg.append("dual_radio_mode: Invalid value '{0}' for Dual Radio Mode in playbook. Must be one of: Auto, Enable, Disable."
                            .format(dual_radio_mode))

        for radio_series in ["2.4ghz_radio", "5ghz_radio", "6ghz_radio", "xor_radio", "tri_radio"]:
            radio_config = ap_config.get(radio_series)
            if radio_config:
                if ap_config.get("ap_mode") not in ("Local/FlexConnect", "Local"):
                    errormsg.append("Radio Params cannot be changed when AP mode is in {0}."
                                    .format(ap_config.get("ap_mode")))
                self.validate_radio_parameters(radio_config, radio_series, errormsg)

        if len(errormsg) > 0:
            self.msg = "Invalid parameters in playbook config: '{0}' ".format(str(errormsg))
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        msg = "Successfully validated config params: {0}".format(str(ap_config))
        self.log(msg, "INFO")
        self.status = "success"
        return self

    def validate_mac_address(self, mac_address, errormsg):
        """
        Validates the provided MAC address.

        Parameters:
        - self (object): An instance of the class containing the method.
        - mac_address (str): The MAC address string to validate in the input configuration.
        - errormsg (list): List contain error message of the mac address error.

        Returns:
            An error message if validation fails; otherwise, returns Nothing

        Description:
        This helper function validates the MAC address provided with the specified field name.
        If the MAC address is invalid, it returns an error message containing with field name.
        """
        self.log("Validating MAC address: {0}".format(mac_address), "INFO")
        mac_regex = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

        if mac_address and not mac_regex.match(mac_address):
            errormsg.append("mac_address: Invalid MAC Address '{0}' in playbook.".format(mac_address))
        else:
            self.log("MAC address '{0}' is valid.".format(mac_address), "INFO")

    def validate_ip_address(self, ip_address, ip_type, errormsg):
        """
        Validates the provided IP Address.

        Parameters:
        - self (object): An instance of the class containing the method.
        - ip_address (str): The IP address string to validate in the input configuration.
        - ip_type (str): String contain field name needs to display in the error message
        - errormsg (list): List contain error message of the mac address error.

        Returns:
            An error message if validation fails; otherwise, returns Nothing
        """
        self.log("Validating {0}: {1}".format(ip_type, ip_address), "DEBUG")

        if ip_address and not (self.is_valid_ipv4(ip_address) or self.is_valid_ipv6(ip_address)):
            errormsg.append("{0}: Invalid {0} '{1}' in playbook.".format(ip_type, ip_address))
        else:
            self.log("{0}: '{1}' is valid.".format(ip_type, ip_address), "INFO")

    def validate_radio_parameters(self, radio_config, radio_series, errormsg):
        """
        Validate the Radio configuration each parameter.

        Parameters:
        - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        - radio_config (dict): Each radio config from input "2.4ghz_radio", "5ghz_radio",
                                "6ghz_radio", "xor_radio" or "tri_radio".
        - radio_series (str): Radio series name as "2.4ghz_radio", "5ghz_radio",
                                "6ghz_radio", "xor_radio" or "tri_radio"
        - errormsg (list): Track and append the error message with existing message.
        """
        admin_status = radio_config.get("admin_status")
        if admin_status and admin_status not in ("Enabled", "Disabled"):
            errormsg.append("admin_status: Invalid value '{0}' for admin_status in playbook. Must be either 'Enabled' or 'Disabled'."
                            .format(admin_status))

        radio_type_map = {"2.4ghz_radio": 1, "5ghz_radio": 2, "6ghz_radio": 6,
                          "xor_radio": 3, "tri_radio": 2}
        radio_config["radio_type"] = radio_type_map[radio_series]
        self.want[radio_series]["radio_type"] = radio_config["radio_type"]
        self.keymap["radio_type"] = "radioType"
        self.keymap["power_level"] = "powerlevel"
        radio_band = radio_config.get("radio_band")

        antenna_name = radio_config.get("antenna_name")
        if antenna_name:
            param_spec = dict(type="str", length_max=32)
            validate_str(antenna_name, param_spec, "antenna_name", errormsg)

        antenna_gain = radio_config.get("antenna_gain")
        if antenna_gain:
            if antenna_gain and radio_series in ["6ghz_radio"]:
                errormsg.append("antenna_gain: '{0}' Not supported for 6 GHz Radio in playbook."
                                .format(antenna_gain))
            elif antenna_gain not in range(0, 21) and radio_series in ["2.4ghz_radio", "5ghz_radio"]:
                errormsg.append("antenna_gain: Invalid '{0}' in playbook, allowed range of min: 0 and max: 20"
                                .format(antenna_gain))
            elif antenna_gain not in range(0, 41) and radio_series in ["xor_radio", "tri_radio"]:
                errormsg.append("antenna_gain: Invalid '{0}' in playbook, allowed range of min: 0 and max: 40"
                                .format(antenna_gain))

        cable_loss = radio_config.get("cable_loss")
        if cable_loss:
            if cable_loss and radio_series in ["6ghz_radio"]:
                errormsg.append("cable_loss: '{0}' Not supported for 6 GHz Radio in playbook."
                                .format(cable_loss))
            elif radio_series in ["2.4ghz_radio", "5ghz_radio"] and not 0 <= cable_loss <= 20:
                errormsg.append("cable_loss: Invalid '{0}' in playbook. Must be between 0 and 20.".format(cable_loss))
            elif radio_series in ["xor_radio", "tri_radio"] and not 0 <= cable_loss <= 40:
                errormsg.append("cable_loss: Invalid '{0}' in playbook. Must be between 0 and 40.".format(cable_loss))
            elif antenna_gain and cable_loss >= antenna_gain:
                errormsg.append("cable_loss: Invalid '{0}' in playbook. Must be less than antenna_gain: {1}."
                                .format(cable_loss, antenna_gain))

        channel_assignment_mode = radio_config.get("channel_assignment_mode")
        if channel_assignment_mode and channel_assignment_mode not in ("Global", "Custom"):
            errormsg.append("channel_assignment_mode: Invalid value '{0}' for Channel Assignment Mode in playbook. Must be either 'Global' or 'Custom'."
                            .format(channel_assignment_mode))

        channel_number = radio_config.get("channel_number")
        if channel_number:
            if radio_series == "xor_radio" and self.want.get(radio_series).get("radio_role_assignment") == "Client-Serving"\
               and radio_band in ["2.4 GHz", "5 GHz", "6 GHz"]:
                if radio_band == "2.4 GHz" and channel_number not in self.allowed_channel_no.get("2.4ghz_radio"):
                    errormsg.append(
                        "channel_number: Invalid value '{0}' for Channel Number in playbook. Must be one of: {1}."
                        .format(channel_number, str(self.allowed_channel_no["2.4ghz_radio"])))
                elif radio_band == "5 GHz" and channel_number not in self.allowed_channel_no.get("5ghz_radio"):
                    errormsg.append(
                        "channel_number: Invalid value '{0}' for Channel Number in playbook. Must be one of: {1}."
                        .format(channel_number, str(self.allowed_channel_no["5ghz_radio"])))
                elif radio_band == "6 GHz" and channel_number not in self.allowed_channel_no.get("6ghz_radio"):
                    errormsg.append(
                        "channel_number: Invalid value '{0}' for Channel Number in playbook. Must be one of: {1}."
                        .format(channel_number, str(self.allowed_channel_no["6ghz_radio"])))
            elif self.allowed_channel_no.get(radio_series) is not None and channel_number not in self.allowed_channel_no.get(radio_series):
                errormsg.append(
                    "channel_number: Invalid value '{0}' for Channel Number in playbook. Must be one of: {1}."
                    .format(channel_number, str(self.allowed_channel_no[radio_series]))
                )
            else:
                current_radio_role = self.check_current_radio_role_assignment(
                    radio_series, self.have["current_ap_config"].get("radio_dtos" , []), radio_band)
                if (self.want.get(radio_series).get("radio_role_assignment") != "Client-Serving" and
                   radio_series not in ("5ghz_radio", "6ghz_radio")):
                    errormsg.append(
                        "channel_number: This configuration is only supported with Client-Serving Radio Role Assignment {0} "
                        .format(current_radio_role)
                    )

        channel_width = radio_config.get("channel_width")
        valid_channel_widths = ["20 MHz", "40 MHz", "80 MHz", "160 MHz"]
        if channel_width:
            if radio_series == "2.4ghz_radio":
                errormsg.append("channel_width is not applicable for the 2.4GHz radio")
            elif radio_series != "6ghz_radio" and channel_width not in valid_channel_widths:
                errormsg.append(
                    "channel_width: Invalid value '{0}' for Channel width in playbook. "
                    "Must be one of: {1}.".format(channel_width, ", ".join(valid_channel_widths)))
            else:
                valid_channel_widths.append("320 MHz")
                if radio_series == "6ghz_radio" and channel_width not in valid_channel_widths:
                    errormsg.append(
                        "channel_width: Invalid value '{0}' for Channel width in playbook. "
                        "Must be one of: {1}.".format(channel_width, ", ".join(valid_channel_widths)))

        power_assignment_mode = radio_config.get("power_assignment_mode")
        if power_assignment_mode and power_assignment_mode not in ("Global", "Custom"):
            errormsg.append("power_assignment_mode: Invalid value '{0}' for Power assignment mode in playbook. Must be either 'Global' or 'Custom'."
                            .format(power_assignment_mode))

        power_level = radio_config.get("power_level")
        if power_level:
            if power_level not in range(1, 9):
                errormsg.append(
                    "power_level: Invalid Power level '{0}' in playbook. Must be between 1 to 8."
                    .format(power_level)
                )
            else:
                current_radio_role = self.check_current_radio_role_assignment(
                    radio_series, self.have["current_ap_config"].get("radio_dtos", []), radio_band)
                if (self.want.get(radio_series).get("radio_role_assignment") != "Client-Serving" and
                   radio_series not in ("5ghz_radio", "6ghz_radio")):
                    errormsg.append(
                        "power_level: This configuration is only supported with Client-Serving Radio Role Assignment {0} "
                        .format(current_radio_role)
                    )

        radio_role_assignment = radio_config.get("radio_role_assignment")
        if radio_role_assignment == "Client-Serving" and radio_band and radio_band not in ("2.4 GHz", "5 GHz", "6 GHz")\
           and radio_series == "xor_radio":
            errormsg.append("radio_band: Invalid value '{0}' in playbook. Must be either '2.4 GHz' or '5 GHz' or '6 GHz'."
                            .format(radio_band))

        if radio_role_assignment:
            if radio_role_assignment not in ("Auto", "Client-Serving", "Monitor"):
                errormsg.append(
                    "radio_role_assignment: Invalid value '{0}' for radio role assignment in playbook. "
                    "Must be one of: 'Auto', 'Monitor' or 'Client-Serving'."
                    .format(radio_role_assignment)
                )
            else:
                if self.want.get("ap_mode") not in ("Local/FlexConnect", "Local"):
                    errormsg.append(
                        "radio_role_assignment: Invalid value '{0}'. Hence, AP mode is not Local. "
                        "Kindly change the AP mode to Local then change the radio_role_assignment to Auto."
                        .format(radio_role_assignment)
                    )

        if radio_series == "xor_radio" and radio_role_assignment == "Client-Serving" and radio_band is None:
            errormsg.append("radio_band: Missing in '{0}' in playbook. Must be either '2.4 GHz' or '5 GHz' or '6 GHz'."
                            .format(radio_series))
        elif radio_series == "xor_radio" and radio_role_assignment in ("Auto", "Monitor") and radio_band is not None:
            errormsg.append("radio_band: Should be empty for '{0}' when radio_role_assignment in 'Auto' or 'Monitor' mode."
                            .format(radio_series))

    def check_current_radio_role_assignment(self, radio_type, radio_dtos, radio_band=any):
        """
        Check the current radio role assignment based on radio type and DTOs.

        Parameters:
        - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        - radio_type (str): Type of radio ("2.4ghz_radio", "5ghz_radio", or "6ghz_radio").
        - radio_dtos (list): List of radio data transfer objects containing slot IDs and
            role assignments.

        Returns:
        - str: Current radio role assignment corresponding to the specified radio type.

        Description:
        This method iterates through the provided list of radio DTOS to find and return
        the radio role assignment based on the specified radio type (2.4 GHz, 5 GHz, or 6 GHz).

        Example:
        To check the current radio role assignment for the 5 GHz radio, call this method with
        "5ghz_radio" as "radio_type" and the list of radio DTOS.
        """
        role_assignment = None
        for each_dto in radio_dtos:
            if_type = each_dto["if_type_value"]
            role_assignment = each_dto.get("radio_role_assignment")
            if (radio_type == "2.4ghz_radio" and if_type == "2.4 GHz") or \
               (radio_type == "5ghz_radio" and if_type == "5 GHz") or \
               (radio_type == "6ghz_radio" and if_type == "6 GHz") or \
               (radio_type == "xor_radio" and if_type == "Dual Radio") or \
               (radio_type == "tri_radio" and if_type == "Tri Radio"):
                break

        self.log("Completed checking radio role assignments. Role assignment: {0}, radio type: {1}, radio band: {2}"
                 .format(role_assignment, radio_type, radio_band), "INFO")
        return role_assignment

    def get_accesspoint_details(self, input_config):
        """
        Retrieves the current details of an device in Cisco Catalyst Center.

        Parameters:
        - self (object): An instance of the class containing the method.
        - input_config (dict): A dictionary containing the input configuration details.

        Returns:
        A tuple containing a boolean indicating if the device exists and a
        dictionary of the current inventory details based on the input given from
        playbook either mac_address or management_ip_address or hostname
        (
            True,
            {
                "ap_name": "NFW-AP1-9130AXE",
                "eth_mac": "34:5d:a8:0e:20:b4",
                "led_brightnessLevel": 3,
                "led_status": "Enabled",
                "location": "LTTS",
                "mac_address": "90:e9:5e:03:f3:40"
            }
        )

        Description:
        Retrieve device details from Cisco Catalyst Center using provided MAC address, management IP, or hostname.
        If found, return current device details; otherwise, log errors and fail the function.
        """
        accesspoint_exists = False
        current_configuration = {}
        ap_response = None
        input_param = {}
        self.keymap = self.map_config_key_to_api_param(self.keymap, input_config)
        self.keymap.update({
            "mac_address": "macAddress",
            "management_ip_address": "managementIpAddress",
            "hostname": "hostname",
            "radio_configurations": "radioConfigurations",
            "radio_type": "radioType",
            "is_assigned_site_as_location": "isAssignedSiteAsLocation",
            "clean_air_si_2.4ghz": "cleanAirSI24",
            "clean_air_si_5ghz": "cleanAirSI5",
            "clean_air_si_6ghz": "cleanAirSI6"
        })

        for key in ["mac_address", "management_ip_address", "hostname"]:
            if input_config.get(key):
                input_param[self.keymap[key]] = input_config[key]
                break

        ap_identifier = input_config.get("ap_identifier")

        if ap_identifier:
            ap_list = []
            selected_key = None
            self.log("Starting to process AP identifiers from input configuration.", "DEBUG")

            for each_ap in ap_identifier:
                for key in ["mac_address", "management_ip_address", "hostname"]:
                    if each_ap.get(key):
                        ap_list.append(each_ap[key])
                        selected_key = key
                        self.log("Selected key '{0}' with value '{1}' for AP identifier.".
                                 format(key, each_ap[key]), "DEBUG")
                        break
            input_param[self.keymap[selected_key]] = ap_list
            self.log("At AP details {0}".format(self.pprint(input_param)))
            self.log("Completed AP identifier processing. Mapped {0} to input_param with values: {1}".
                     format(self.keymap[selected_key], ap_list), "DEBUG")
            self.log("Final AP details structure: {0}".format(self.pprint(input_param)), "DEBUG")

        if not input_param:
            msg = "Required param of mac_address,ip_address or hostname is not in playbook config"
            self.log(msg, "WARNING")
            self.set_operation_result("failed", False, msg, "ERROR").check_return_status()

        try:
            ap_response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                op_modifies=True,
                params=input_param,
            )

            ap_response_data = ap_response.get("response") if ap_response else None
            ap_identifier_present = input_config.get("ap_identifier")

            if ap_response_data:
                ap_response = self.camel_to_snake_case(ap_response_data)
                accesspoint_exists = True

                if not ap_identifier_present:
                    current_configuration = ap_response[0]
                    self.log("AP response found without 'ap_identifier'; current configuration set.", "DEBUG")
                else:
                    self.log("AP response found with 'ap_identifier'; processed AP response data.", "DEBUG")

        except Exception as e:
            self.msg = "The provided device '{0}' is either invalid or not present in the \
                     Cisco Catalyst Center.".format(str(input_param))
            self.log(self.msg + str(e), "WARNING")

        if not accesspoint_exists:
            self.msg = "The provided device '{0}' is either invalid or not present in the \
                     Cisco Catalyst Center.".format(str(input_param))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
        else:
            ap_identifier_present = input_config.get("ap_identifier")
            is_unified_ap = current_configuration.get("family") == "Unified AP"

            if ap_identifier_present:
                filter_response = []
                for each_response in ap_response:
                    if each_response["family"] != "Unified AP":
                        self.msg = "Provided device {0} is not Access Point.".format(each_response["mac_address"])
                        self.log(self.msg, "WARNING")
                    else:
                        filter_response.append(each_response)
                self.log("Filtered Access points List: {0} ".format(self.pprint(filter_response)), "INFO")
                return accesspoint_exists, filter_response

            if not is_unified_ap:
                self.msg = "Provided device is not Access Point."
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        return accesspoint_exists, current_configuration

    def get_current_config(self, input_config):
        """
        Retrieves the current configuration of an access point and site releated details
        from Cisco Catalyst Center.

        Parameters:
          - self (object): An instance of the class containing the method.
          - input_config (dict): A dictionary containing the input configuration details.
        Returns:
            A tuple containing a boolean indicating if the access point and site exists and a
            dictionary of the current configuration based on the input given from
            playbook either mac_address or management_ip_address or hostname
            (
                True
                {
                    "ap_name": "NFW-AP1-9130AXE",
                    "eth_mac": "34:5d:a8:0e:20:b4",
                    "led_brightnessLevel": 3,
                    "led_status": "Enabled",
                    "location": "LTTS",
                    "mac_address": "90:e9:5e:03:f3:40"
                }
            )
        Description:
            Queries the Cisco Catalyst Center for the existence of an Access Point
            using the provided input configuration details such as MAC address,
            management IP address, or hostname. If found, it retrieves the current
            Access Point configuration and returns it.
        """
        self.log("Starting to retrieve current configuration with input: {0}".format(str(input_config)), "INFO")
        accesspoint_exists, current_configuration = self.get_accesspoint_details(
            input_config)
        self.log("Access point exists: {0}, Current configuration: {1}"
                 .format(accesspoint_exists, current_configuration), "INFO")

        current_eth_configuration = {}
        if accesspoint_exists:
            self.payload["access_point_details"] = current_configuration
            ap_ethernet_mac_address = current_configuration["ap_ethernet_mac_address"]
            ap_config_exists, current_eth_configuration = self.get_accesspoint_config(
                ap_ethernet_mac_address)
            self.log("Access point configuration exists: {0}, Current configuration: {1}"
                     .format(ap_config_exists, str(current_eth_configuration)), "INFO")

            if ap_config_exists:
                self.payload["access_point_config"] = current_eth_configuration
                self.log("Updated payload with access point configuration: {0}".format(str(self.payload)), "INFO")

        if input_config.get("site"):
            site_exists, current_site = self.site_exists(input_config)
            self.log("Site exists: {0}, Current site: {1}".format(site_exists, current_site), "INFO")

            if site_exists:
                self.payload.update({
                    "site_exists": site_exists,
                    "current_site": current_site,
                    "site_changes": self.get_site_device(current_site["site_id"],
                                                         current_configuration["mac_address"],
                                                         site_exists, current_site, current_configuration)
                })
                provision_status, wlc_details = self.verify_wlc_provision(
                    current_configuration["associated_wlc_ip"])
                self.payload["wlc_provision_status"] = provision_status
                self.log("WLC provision status: {0}".format(provision_status), "INFO")

                if self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") >= 0:
                    if current_eth_configuration.get("provisioning_status"):
                        self.payload["ap_provision_status"] = "Provisioned"
                    else:
                        self.payload["ap_provision_status"] = None
                    self.log("AP provision status: {0}".format(self.payload["ap_provision_status"]), "INFO")

        self.log("Completed retrieving current configuration. Access point exists: {0}, Current configuration: {1}"
                 .format(accesspoint_exists, current_eth_configuration), "INFO")
        return (accesspoint_exists, current_eth_configuration)

    def get_accesspoint_config(self, ap_ethernet_mac_address):
        """
        Retrieves the access point configuration data from Cisco Catalyst Center.

        Parameters:
        - self (object): An instance of the class containing the method.
        - ap_ethernet_mac_address (str): The Ethernet MAC address of the access point.
        - tuple: A tuple containing a boolean indicating if the access point exists and
            a dictionary of the current configuration.
        Returns:
            (
                True,
                {
                    "ap_name": "NFW-AP1-9130AXE",
                    "eth_mac": "34:5d:a8:0e:20:b4",
                    "led_brightnessLevel": 3,
                    "led_status": "Enabled",
                    "location": "LTTS",
                    "mac_address": "90:e9:5e:03:f3:40"
                }
            )
        Description:
            Requests the current configuration of an access point from the Cisco Catalyst Center
            using the Ethernet MAC address. The response is then processed and returned
            as a dictionary.
        """
        input_param = {}
        input_param["key"] = ap_ethernet_mac_address
        current_configuration = {}
        accesspoint_config_exists = False

        try:
            ap_config_response = self.dnac._exec(
                family="wireless",
                function="get_access_point_configuration",
                params=input_param,
            )

            if ap_config_response:
                self.keymap = self.map_config_key_to_api_param(self.keymap, ap_config_response)
                current_configuration = self.camel_to_snake_case(ap_config_response)
                self.log("Received API response from get_access_point_configuration: {0}".format(self.pprint(current_configuration)), "INFO")
                accesspoint_config_exists = True

        except Exception as e:
            self.log("Unable to get the Accesspoint configuration for '{0}'.".format(str(input_param) + str(e)), "WARNING")

        return (accesspoint_config_exists, current_configuration)

    def site_exists(self, input_config):
        """
        Checks if the site exists in Cisco Catalyst Center and retrieves current site details
        if they exist.

        Parameters:
        - self (object): An instance of the class containing the method.
        - input_config (dict): A dictionary containing the input configuration details.

        Returns:
        A tuple containing a boolean indicating if the site exists and a dictionary of the
        current site details.

        Description:
        Checks the existence of a site in Cisco Catalyst Center using the provided site details
        from the input configuration. If the site is found, returns current site details;
        otherwise, logs errors and fails the function.
        """
        site_exists = False
        floor_name = None
        parent_name = None
        floor = input_config.get("site").get("floor")
        if floor:
            floor_name = floor.get("name")
            parent_name = floor.get("parent_name")

        current_site = {}
        if floor_name and parent_name:
            site_name = parent_name + "/" + floor_name
            self.want["site_name"] = site_name
            try:
                response = self.get_site(site_name)
                if response.get("response"):
                    site = response["response"][0]
                    self.log("Site response: {0}".format(self.pprint(site)), "INFO")

                    if self.dnac_version <= self.dnac_versions["2.3.5.3"]:
                        location = get_dict_result(site.get("additionalInfo"), 'nameSpace', "Location")
                        type_info = location.get("attributes", {}).get("type")
                        parent_name = site.get("siteNameHierarchy").split("/" + site.get("name"))[0]
                    else:
                        type_info = site.get("type")
                        parent_name = site.get("nameHierarchy").split("/" + site.get("name"))[0]

                    if type_info == "floor":
                        site_info = {
                            "floor": {
                                "name": site.get("name"),
                                "parentName": parent_name
                            }
                        }

                    current_site = {
                        "type": type_info,
                        "site": site_info,
                        "site_id": site.get("id"),
                        "site_name": site_info["floor"]["parentName"] + "/" + site_info["floor"]["name"]
                    }
                    self.log("Current site details: {0}".format(str(current_site)), "INFO")
                    self.log("Site {0} exists in Cisco Catalyst Center".format(site.get("name")), "INFO")
                    site_exists = True
                else:
                    msg = "The provided site name '{0}' is either invalid or not present in the \
                        Cisco Catalyst Center.".format(self.want.get("site_name"))
                    self.log(msg, "WARNING")
                    self.set_operation_result("failed", False, msg, "ERROR").check_return_status()

            except Exception as e:
                msg = "The provided site name '{0}' is either invalid or not present in the \
                        Cisco Catalyst Center.".format(self.want.get("site_name"))
                self.log(msg + str(e), "WARNING")
                self.set_operation_result("failed", False, msg, "ERROR").check_return_status()

        return site_exists, current_site

    def get_site_device(self, site_id, ap_mac_address, site_exist=None, current_site=None, current_config=None):
        """
        Fetches device information associated with a specific site and checks if a given AP
        MAC address is present.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_id (str): The identifier for the site whose devices are to be fetched.
            ap_mac_address (str): The MAC address of the Access Point (AP) device to check.

        Returns:
            bool: True if the AP MAC address is found in the site's devices, otherwise False.

        Description:
            This method utilizes the "get_membership" API to retrieve details about devices
            associated with the specified "site_id". It verifies if the AP device identified by
            "ap_mac_address" is among the devices retrieved for the site. If found, it logs a
            success message indicating presence; otherwise, it logs a failure message.

            If the AP MAC address is found in the site, the method returns True. If the device is
            not found or if an error occurs during the API call, it returns False.
        """
        try:
            site_name = self.have.get("site_name_hierarchy", self.want.get("site_name"))
            api_response, device_list = self.get_device_ids_from_site(site_name, site_id)
            if current_config.get("id") is not None and current_config.get("id") in device_list:
                self.log("Device with MAC address: {0} found in site: {1} Proceeding with ap_site updation."
                         .format(ap_mac_address, site_id), "INFO")
                return True
            else:
                self.log("Given device not found on the site: {sId},".format(sId=site_id), "INFO")
                return False

        except Exception as e:
            self.log("Failed to execute the get_device_ids_from_site function '{0}'\
                      Error: {1}".format(site_id, str(e)), "ERROR")
            return False

    def verify_wlc_provision(self, wlc_ip_address):
        """
        Verifies if the WLC (device) is provisioned.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            wlc_ip_address (str): The management IP address of the Wireless LAN Controller (WLC).

        Returns:
            tuple: A tuple containing the provisioning status ("success" or "failed") and
            the provisioning details or error message.

        Description:
            Checks if the WLC specified by the management IP address is provisioned.
            Returns "success" and details if provisioned, otherwise logs an error
            and returns "failed" with error details.
        """

        provision_status = "failed"
        provision_details = None
        device_management_ip_address = wlc_ip_address

        try:
            response = self.dnac._exec(
                family="sda",
                function="get_device_info",
                op_modifies=True,
                params={"device_management_ip_address": device_management_ip_address}
            )
            if response and response.get("status") == "success":
                self.log("Response from get_device_info: {0}".format(self.pprint(response)),
                         "INFO")
                self.log("WLC already provisioned.", "INFO")
                provision_status = "success"
                provision_details = self.pprint(response)

        except Exception as e:
            msg = "Wireles controller is not provisioned:"
            self.log(msg + str(e), "ERROR")
            provision_details = str(e)
            self.status = "failed"
            self.set_operation_result("failed", False, msg, "ERROR",
                                      provision_details).check_return_status()

        return provision_status, provision_details

    def access_point_provision_old(self, rf_profile, hostname, type_name, site_name_hierarchy):
        """
        Provisions a device (AP) to a specific site. support Cisco Catalyst Center version
        less than 2.3.7.6

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            rf_profile (str): Radio profile name either custom or default like "HIGH", "LOW"
            hostname (str): Accesspoint host name
            type_name (str): Site type should be "floor" or "building"
            site_name_hierarchy (str): Complete path of the the site location.

        Returns:
            resoponse (dict): A dict containing the execution id and url.

        Description:
            Provisions an Access Point (AP) to a specified site using the provided
            site name hierarchy, RF profile, hostname, and AP type. Logs details
            and handles
        """
        if not site_name_hierarchy or not rf_profile or not hostname:
            error_msg = ("Cannot provision device: Missing parameters - "
                         "site_name_hierarchy: {0}, rf_profile: {1}, host_name: {2}"
                         .format(site_name_hierarchy, rf_profile, hostname))
            self.log(error_msg, "ERROR")
            self.set_operation_result("failed", False, error_msg, "ERROR").check_return_status()

        provision_params = [{
            "rfProfile": rf_profile,
            "deviceName": hostname,
            "type": type_name,
            "siteNameHierarchy": site_name_hierarchy
        }]
        self.log('Before AP provision: {0}'.format(self.pprint(provision_params)), "INFO")

        response = self.dnac._exec(
            family="wireless",
            function='ap_provision',
            op_modifies=True,
            params={"payload": provision_params},
        )

        self.log('Response from ap_provision: {0}'.format(str(response.get("response"))), "INFO")
        if response and isinstance(response, dict):
            return response
        return None

    def access_point_provision_new(self, rf_profile, device_id, site_id):
        """
        Provisions a device (AP) to a specific site. support Cisco Catalyst Center version
        2.3.7.6 and greater

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            rf_profile (str): Radio profile name either custom or default like "HIGH", "LOW"
            device_id (str): Accesspoint id collected from device details
            site_id (str): Site id of the site location

        Returns:
            resoponse (dict): A dict containing the Task id and url.

        Description:
            Provisions an Access Point (AP) to a specified site using the provided
            device id, RF profile and site id Logs details and handles
        """
        if not rf_profile or not device_id or not site_id:
            error_msg = ("Cannot provision device: Missing parameters - "
                         "device_id: {0}, rf_profile: {1}, site_id: {2}"
                         .format(device_id, rf_profile, site_id))
            self.log(error_msg, "ERROR")
            self.set_operation_result("failed", False, error_msg, "ERROR").check_return_status()

        provision_params = {
            "rfProfileName": rf_profile,
            "networkDevices": [{"deviceId": device_id}],
            "siteId": site_id
        }

        try:
            site_assign_status = self.assign_device_to_site([self.have.get("device_id")],
                                                            self.have.get("site_name_hierarchy"),
                                                            self.have.get("site_id"))
            if site_assign_status:
                self.log('Current device details: {0}'.format(self.pprint(provision_params)), "INFO")
                response = self.dnac._exec(
                    family="wireless",
                    function='ap_provision',
                    op_modifies=True,
                    params={"payload": provision_params},
                )
                self.log('Response from ap_provision: {0}'.format(str(response.get("response"))), "INFO")

                if response and isinstance(response, dict):
                    return response

                return None

        except Exception as e:
            error_msg = 'An error occurred during device provisioning: {0}'.format(str(e))
            self.log(error_msg, "ERROR")
            self.set_operation_result("failed", False, error_msg, "ERROR").check_return_status()

    def provision_device(self):
        """
        Provisions a device (AP) to a specific site.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Returns:
            tuple: A tuple containing the provisioning status ("SUCCESS" or "failed") and
            the provisioning details or error message.

        Description:
            Provisions an Access Point (AP) to a specified site using the provided
            site name hierarchy, RF profile, hostname, and AP type. Logs details
            and handles
        """
        provision_status = "failed"
        provision_details = None
        rf_profile = self.want.get("rf_profile")
        site_name_hierarchy = self.have.get("site_name_hierarchy")
        hostname = self.have.get("hostname")
        type_name = self.have.get("ap_type")
        device_id = self.have.get("device_id")
        site_id = self.have.get("site_id")

        try:
            if self.dnac_version <= self.dnac_versions["2.3.5.3"]:
                response = self.access_point_provision_old(rf_profile, hostname,
                                                           type_name, site_name_hierarchy)
                if response and isinstance(response, dict):
                    executionid = response.get("executionId")
                    resync_retry_count = int(self.payload.get("dnac_api_task_timeout", 100))
                    resync_retry_interval = int(self.payload.get("dnac_task_poll_interval", 5))

                    while resync_retry_count:
                        execution_details = self.get_execution_details(executionid)
                        if execution_details.get("status") == "SUCCESS":
                            self.result['changed'] = True
                            self.result['response'] = execution_details
                            provision_status = "SUCCESS"
                            provision_details = execution_details
                            break
                        if execution_details.get("bapiError"):
                            msg = execution_details.get("bapiError")
                            self.set_operation_result("failed", False, msg, "ERROR",
                                                      execution_details).check_return_status()
                            break

                        time.sleep(resync_retry_interval)
                        resync_retry_count = resync_retry_count - 1
            else:
                response = self.access_point_provision_new(rf_profile, device_id, site_id)
                if response and isinstance(response, dict):
                    task_id = response.get("response", {}).get("taskId")
                    resync_retry_count = int(self.payload.get("dnac_api_task_timeout"))
                    resync_retry_interval = int(self.payload.get("dnac_task_poll_interval"))

                    while resync_retry_count:
                        task_details_response = self.get_tasks_by_id(task_id)
                        self.log("Status of the task: {0} .".format(self.status), "INFO")
                        responses = {}
                        if task_details_response.get("endTime") is not None:
                            if task_details_response.get("status") == "SUCCESS":
                                self.log("Task Details: {0} .".format(self.pprint(
                                    task_details_response)), "INFO")
                                self.msg = "AP {0} provisioned Successfully".format(
                                    self.have["current_ap_config"].get("ap_name"))
                                self.log(self.msg, "INFO")
                                self.result['changed'] = True
                                self.result['response'] = self.msg
                                provision_status = "SUCCESS"
                                provision_details = self.get_task_details_by_id(task_id)
                                break
                            else:
                                self.result['changed'] = True if self.result['changed'] is True else False
                                self.msg = "Unable to get success response, hence not provisioned"
                                self.log(self.msg, "ERROR")
                                self.log("Task Details: {0} .".format(self.pprint(
                                    task_details_response)), "ERROR")
                                provision_details = self.get_task_details_by_id(task_id)
                                self.log("Provision error details: {0} .".format(self.pprint(
                                    provision_details)), "ERROR")
                                self.set_operation_result("failed", self.result['changed'],
                                                          self.msg, "ERROR", provision_details).check_return_status()
                        time.sleep(resync_retry_interval)
                        resync_retry_count = resync_retry_count - 1

            self.log("Provisioned device with host '{0}' to site '{1}' successfully.".format(
                hostname, site_name_hierarchy), "INFO")
        except Exception as e:
            error_msg = 'An error occurred during device provisioning: {0}'.format(str(e))
            self.log(error_msg, "ERROR")
            self.msg = error_msg
            self.status = "failed"

        return provision_status, provision_details

    def compare_radio_config(self, current_radio, want_radio):
        """
        Compares the current radio configuration with the desired radio configuration and
        returns a dictionary of unmatched values.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            current_radio (dict): A dictionary containing the current radio configuration.
            want_radio (dict): A dictionary containing the desired radio configuration.

        Returns:
            dict: A dictionary of unmatched configuration values.

        Description:
            This function checks the current radio configuration against the desired
            configuration for specific keys based on the radio slot ID. If discrepancies
            are found, they are collected and returned in a dictionary.
        """
        self.log("Starting radio configuration comparison.", "INFO")
        self.log("Current radio configuration: {0}".format(self.pprint(current_radio)), "INFO")
        self.log("Desired radio configuration: {0}".format(self.pprint(want_radio)), "INFO")
        available_key = {
            "_1": ("admin_status", "antenna_gain", "antenna_name", "radio_role_assignment",
                   "power_assignment_mode", "power_level", "channel_assignment_mode",
                   "channel_number", "cable_loss", "antenna_cable_name", "radio_type",
                   "radio_band"),
            "_2": ("admin_status", "antenna_gain", "antenna_name", "radio_role_assignment",
                   "power_assignment_mode", "power_level", "channel_assignment_mode",
                   "channel_number", "cable_loss", "antenna_cable_name", "channel_width",
                   "radio_type", "radio_band", "dual_radio_mode"),
            "_6": ("admin_status", "radio_role_assignment", "radio_type",
                   "power_assignment_mode", "power_level", "channel_assignment_mode",
                   "channel_number", "channel_width", "dual_radio_mode", "radio_band"),
            "_3": ("admin_status", "antenna_gain", "antenna_name", "radio_role_assignment",
                   "power_assignment_mode", "power_level", "channel_assignment_mode",
                   "channel_number", "cable_loss", "antenna_cable_name", "radio_band",
                   "channel_width", "radio_type"),
            "_5": ("admin_status", "antenna_gain", "antenna_name", "radio_role_assignment",
                   "power_assignment_mode", "power_level", "channel_assignment_mode",
                   "channel_number", "cable_loss", "antenna_cable_name", "dual_radio_mode",
                   "channel_width", "radio_type")
        }

        temp_dtos = {}
        unmatch_count = 0
        self.keymap["power_level"] = "powerlevel"
        dtos_keys = list(want_radio.keys())
        if_type_key = "_" + str(current_radio["if_type"])
        self.log("Comparing keys for if_type: {}".format(current_radio["if_type"]), "INFO")

        for dto_key in dtos_keys:
            if dto_key in available_key[if_type_key]:
                if dto_key == "antenna_name":
                    temp_dtos[dto_key] = want_radio[dto_key]
                    unmatch_count = unmatch_count + 1
                    self.log("Antenna name unmatched: {0}".format(want_radio[dto_key]), "INFO")
                elif dto_key == "admin_status" and want_radio.get(dto_key) == "Enabled":
                    temp_dtos[self.keymap[dto_key]] = want_radio.get(dto_key)
                elif dto_key == "cable_loss":
                    cable_loss = int(want_radio[dto_key])
                    antenna_gain = int(want_radio.get("antenna_gain", 0))
                    actual_gain = antenna_gain - cable_loss
                    if current_radio.get(self.keymap["antenna_gain"]) != actual_gain:
                        temp_dtos[dto_key] = cable_loss
                    self.log("Cable loss set to: {0}".format(want_radio[dto_key]), "INFO")
                elif dto_key == "antenna_cable_name":
                    temp_dtos[dto_key] = want_radio[dto_key]
                    self.log("Antenna cable name set to: {0}".format(want_radio[dto_key]), "INFO")
                elif dto_key == "radio_type":
                    temp_dtos[self.keymap[dto_key]] = want_radio[dto_key]
                    self.log("Radio type set to: {0}".format(want_radio[dto_key]), "INFO")
                elif dto_key == "radio_role_assignment":
                    temp_dtos[self.keymap[dto_key]] = want_radio[dto_key]
                    self.log("Radio Role Assignment set to: {0}".format(want_radio[dto_key]), "INFO")
                    unmatch_count = unmatch_count + 1
                elif dto_key == "radio_band":
                    temp_dtos[self.keymap[dto_key]] = want_radio[dto_key]
                    self.log("Radio band set to: {0}".format(want_radio[dto_key]), "INFO")
                elif dto_key == "power_level":
                    if want_radio[dto_key] != current_radio[self.keymap[dto_key]]:
                        temp_dtos[self.keymap[dto_key]] = want_radio[dto_key]
                        self.log("Unmatched key {0}: current value {1}, desired value {2}"
                                 .format(dto_key, current_radio[self.keymap[dto_key]],
                                         want_radio[dto_key]), "INFO")
                        unmatch_count = unmatch_count + 1
                else:
                    if want_radio[dto_key] != current_radio[dto_key]:
                        temp_dtos[self.keymap[dto_key]] = want_radio[dto_key]
                        unmatch_count = unmatch_count + 1
                        self.log("Unmatched key {0}: current value {1}, desired value {2}"
                                 .format(dto_key, current_radio[dto_key], want_radio[dto_key]), "INFO")

        temp_dtos["unmatch"] = unmatch_count
        self.log("Total unmatched keys: {0}".format(unmatch_count), "INFO")
        self.log("Completed radio configuration comparison. Result: {0}".format(temp_dtos), "INFO")
        return temp_dtos

    def config_diff(self, current_ap_config):
        """
        Compares the desired AP configuration with the current configuration and identifies
        changes.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            current_ap_config (dict): A dictionary containing the current AP configuration.

        Returns:
            dict: A dictionary with configuration updates needed to match the desired AP configuration.

        Example:
            functions = Accesspoint(module)
            final_input_data = functions.config_diff(current_ap_config)
        """
        update_config = {}

        if self.want and current_ap_config:
            if self.want.get("mac_address") == current_ap_config["mac_address"] or \
                    self.want.get("hostname") == current_ap_config["ap_name"] or \
                    self.want.get("management_ip_address") == self.have["ip_address"]:
                configurable_keys = list(self.want.keys())

                excluded_keys = ("mac_address", "hostname", "management_ip_address",
                                 "rf_profile", "site", "site_name")
                for value in excluded_keys:
                    if value in configurable_keys:
                        configurable_keys.remove(value)

                temp_dtos_list = []
                for each_key in configurable_keys :
                    if each_key == "ap_name":
                        if self.want["ap_name"] != current_ap_config.get("ap_name"):
                            update_config["apNameNew"] = self.want["ap_name"]
                            update_config["apName"] = current_ap_config.get("ap_name")
                    elif each_key == "is_assigned_site_as_location":
                        update_config["isAssignedSiteAsLocation"] = self.want["is_assigned_site_as_location"]
                    elif each_key in ("2.4ghz_radio", "5ghz_radio", "6ghz_radio",
                                      "xor_radio", "tri_radio"):
                        current_radio_dtos = current_ap_config.get("radio_dtos")
                        radio_data = {}
                        for each_radio in current_radio_dtos:
                            if each_key == "2.4ghz_radio" and each_radio["if_type_value"] == "2.4 GHz":
                                radio_data = self.compare_radio_config(each_radio,
                                                                       self.want[each_key])
                            elif each_key == "5ghz_radio" and each_radio["if_type_value"] == "5 GHz":
                                radio_data = self.compare_radio_config(each_radio,
                                                                       self.want[each_key])
                            elif each_key == "6ghz_radio" and each_radio["if_type_value"] == "6 GHz":
                                radio_data = self.compare_radio_config(each_radio,
                                                                       self.want[each_key])
                            elif each_key == "xor_radio" and each_radio["if_type_value"] == "Dual Radio":
                                radio_data = self.compare_radio_config(each_radio,
                                                                       self.want[each_key])
                            elif each_key == "tri_radio" and each_radio["if_type_value"] == "Tri Radio":
                                radio_data = self.compare_radio_config(each_radio,
                                                                       self.want[each_key])
                        if radio_data.get("unmatch") != 0:
                            temp_dtos_list.append(radio_data)
                    elif each_key in ("clean_air_si_2.4ghz", "clean_air_si_5ghz",
                                      "clean_air_si_6ghz"):
                        current_radio_dtos = current_ap_config.get("radio_dtos")
                        for each_dtos in current_radio_dtos:
                            if each_key == "clean_air_si_2.4ghz" and each_dtos["if_type_value"] == "2.4 GHz" \
                                    and each_dtos["clean_air_si"] != self.want.get(each_key):
                                update_config["cleanAirSI24"] = self.want[each_key]
                                break
                            elif each_key == "clean_air_si_5ghz" and each_dtos["if_type_value"] == "5 GHz" \
                                    and each_dtos["clean_air_si"] != self.want.get(each_key):
                                update_config["cleanAirSI5"] = self.want[each_key]
                                break
                            elif each_key == "clean_air_si_6ghz" and each_dtos["if_type_value"] == "6 GHz" \
                                    and each_dtos["clean_air_si"] != self.want.get(each_key):
                                update_config["cleanAirSI6"] = self.want[each_key]
                                break
                    else:
                        if self.want[each_key] != current_ap_config.get(each_key):
                            update_config[self.keymap[each_key]] = self.want[each_key]

                if temp_dtos_list:
                    update_config["radioConfigurations"] = temp_dtos_list
                if update_config.get("apName") is not None and \
                        update_config.get("apNameNew") is None:
                    del update_config["apName"]

                for ctrl_name in ["primary_controller_name", "secondary_controller_name", "tertiary_controller_name"]:
                    if ctrl_name == "primary_controller_name" and self.want.get(ctrl_name):
                        if self.want.get(ctrl_name) == "Inherit from site / Clear":
                            update_config["primaryControllerName"] = self.want.get(ctrl_name)
                            update_config[self.keymap["primary_ip_address"]] = {}
                            update_config[self.keymap["primary_ip_address"]]["address"] = "0.0.0.0"
                            update_config["secondaryControllerName"] = self.want.get(ctrl_name)
                            update_config[self.keymap["secondary_ip_address"]] = {}
                            update_config[self.keymap["secondary_ip_address"]]["address"] = "0.0.0.0"
                            update_config["tertiaryControllerName"] = self.want.get(ctrl_name)
                            update_config[self.keymap["tertiary_ip_address"]] = {}
                            update_config[self.keymap["tertiary_ip_address"]]["address"] = "0.0.0.0"
                        else:
                            update_config["primaryControllerName"] = self.want[ctrl_name]
                            update_config[self.keymap["primary_ip_address"]] = {}
                            if self.want.get("primary_ip_address", {}).get("address"):
                                update_config[self.keymap["primary_ip_address"]]["address"] = \
                                    self.want["primary_ip_address"]["address"]
                            else:
                                update_config[self.keymap["primary_ip_address"]]["address"] = "0.0.0.0"
                    elif ctrl_name == "secondary_controller_name" and self.want.get(ctrl_name):
                        if self.want.get(ctrl_name) == "Inherit from site / Clear":
                            update_config["secondaryControllerName"] = self.want.get(ctrl_name)
                            update_config[self.keymap["secondary_ip_address"]] = {}
                            update_config[self.keymap["secondary_ip_address"]]["address"] = "0.0.0.0"
                            update_config["tertiaryControllerName"] = self.want.get(ctrl_name)
                            update_config[self.keymap["tertiary_ip_address"]] = {}
                            update_config[self.keymap["tertiary_ip_address"]]["address"] = "0.0.0.0"
                        else:
                            update_config["secondaryControllerName"] = self.want[ctrl_name]
                            update_config[self.keymap["secondary_ip_address"]] = {}
                            if self.want.get("secondary_ip_address", {}).get("address"):
                                update_config[self.keymap["secondary_ip_address"]]["address"] = \
                                    self.want["secondary_ip_address"]["address"]
                            else:
                                update_config[self.keymap["secondary_ip_address"]]["address"] = "0.0.0.0"
                    elif ctrl_name == "tertiary_controller_name" and self.want.get(ctrl_name):
                        if self.want.get(ctrl_name) == "Inherit from site / Clear":
                            update_config["tertiaryControllerName"] = self.want.get(ctrl_name)
                            update_config[self.keymap["tertiary_ip_address"]] = {}
                            update_config[self.keymap["tertiary_ip_address"]]["address"] = "0.0.0.0"
                        else:
                            update_config["tertiaryControllerName"] = self.want[ctrl_name]
                            update_config[self.keymap["tertiary_ip_address"]] = {}
                            if self.want.get("tertiary_ip_address", {}).get("address"):
                                update_config[self.keymap["tertiary_ip_address"]]["address"] = \
                                    self.want["tertiary_ip_address"]["address"]
                            else:
                                update_config[self.keymap["tertiary_ip_address"]]["address"] = "0.0.0.0"

                    # remove the controller name if the key is in snake case.
                    if update_config.get(ctrl_name) is not None:
                        del update_config[ctrl_name]

                if update_config:
                    update_config["macAddress"] = current_ap_config["eth_mac"]

            if update_config:
                self.log("Consolidated config to update AP configuration: {0}"
                         .format(self.pprint(update_config)), "INFO")
                return update_config

            self.log("Playbook AP configuration remain same in current AP configration", "INFO")
            return None

    def update_ap_configuration(self, ap_config):
        """
        Updates the Access Point (AP) configuration based on the provided device data.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            ap_config (dict): Final input config data response from config_diff.

        Returns:
            dict: A dictionary containing the task ID and URL from the update response.

        Example:
            functions = Accesspoint(module)
            final_input_data = functions.update_ap_configuration(ap_config)
        """

        self.log("Updating access point configuration information: {0}"
                 .format(ap_config["macAddress"]), "INFO")

        ap_config["apList"] = []
        temp_dict = {}

        if ap_config.get("adminStatus") is not None:
            ap_config["configureAdminStatus"] = True
            ap_config["adminStatus"] = True \
                if ap_config["adminStatus"] == "Enabled" else False

        if not ap_config.get("bulk_update"):
            ap_name = ap_config.get(self.keymap["ap_name"])
            mac_address = ap_config.get(self.keymap["mac_address"])
            if ap_name is not None:
                temp_dict[self.keymap["ap_name"]] = ap_name
                temp_dict["apNameNew"] = ap_config["apNameNew"]
                temp_dict[self.keymap["mac_address"]] = mac_address
                self.log("Populated temp_dict with AP name: {0}, MAC address: {1}".format(ap_name,
                                                                                          mac_address), "DEBUG")
                del ap_config[self.keymap["ap_name"]]
                del ap_config["apNameNew"]
            elif mac_address is not None:
                temp_dict[self.keymap["mac_address"]] = mac_address
                self.log("Populated temp_dict with MAC address: {0}".format(mac_address), "DEBUG")
            else:
                self.log("No AP name or MAC address found in ap_config.", "WARNING")
            ap_config["apList"].append(temp_dict)
            self.log("Added temp_dict to apList. Current apList: {0}".
                     format(self.pprint(ap_config["apList"])), "INFO")
        else:
            ap_config["apList"] = ap_config.get("ap_list")
            self.log("Bulk update detected. Setting apList from ap_list. Current apList: {0}".
                     format(self.pprint(ap_config["apList"])), "INFO")
            del ap_config["ap_list"]
            self.log("Removed ap_list from ap_config.", "DEBUG")
            if ap_config.get(self.keymap["ap_name"]) and ap_config.get("apNameNew"):
                del ap_config[self.keymap["ap_name"]]
                del ap_config["apNameNew"]
                self.log("Removed old AP name and new AP name from ap_config.", "DEBUG")
            else:
                self.log("No AP name or new AP name to remove from ap_config.", "DEBUG")

        if ap_config.get(self.keymap["location"]) is not None:
            ap_config["configureLocation"] = True

        if ap_config.get("isAssignedSiteAsLocation") is not None:
            ap_config["configureLocation"] = True
            ap_config["isAssignedSiteAsLocation"] = True \
                if ap_config["isAssignedSiteAsLocation"] == "Enabled" else False

        if ap_config.get(self.keymap["led_brightness_level"]) is not None:
            ap_config["configureLedBrightnessLevel"] = True

        if ap_config.get(self.keymap["led_status"]) is not None:
            ap_config["configureLedStatus"] = True
            ap_config[self.keymap["led_status"]] = True \
                if ap_config[self.keymap["led_status"]] == "Enabled" else False

        if ap_config.get(self.keymap["ap_mode"]) is not None:
            if ap_config.get(self.keymap["ap_mode"]) == "Local":
                ap_config[self.keymap["ap_mode"]] = 0
            elif ap_config.get(self.keymap["ap_mode"]) == "Monitor":
                ap_config[self.keymap["ap_mode"]] = 1
            elif ap_config.get(self.keymap["ap_mode"]) == "Sniffer":
                ap_config[self.keymap["ap_mode"]] = 4
            else:
                ap_config[self.keymap["ap_mode"]] = 5
            ap_config["configureApMode"] = True

        if ap_config.get(self.keymap["primary_controller_name"]) is not None or \
                ap_config.get(self.keymap["secondary_controller_name"]) is not None or \
                ap_config.get(self.keymap["tertiary_controller_name"]) is not None or \
                ap_config.get(self.keymap["primary_ip_address"]) is not None or \
                ap_config.get(self.keymap["secondary_ip_address"]) is not None or \
                ap_config.get(self.keymap["tertiary_ip_address"]) is not None :
            ap_config["configureHAController"] = True

        if ap_config.get(self.keymap["failover_priority"]) is not None:
            if ap_config.get(self.keymap["failover_priority"]) == "Low":
                ap_config[self.keymap["failover_priority"]] = 1
            elif ap_config.get(self.keymap["failover_priority"]) == "Medium":
                ap_config[self.keymap["failover_priority"]] = 2
            elif ap_config.get(self.keymap["failover_priority"]) == "High":
                ap_config[self.keymap["failover_priority"]] = 3
            else:
                ap_config[self.keymap["failover_priority"]] = 4
            ap_config["configureFailoverPriority"] = True

        if ap_config.get("cleanAirSI24") is not None:
            ap_config["configureCleanAirSI24Ghz"] = True
            ap_config["cleanAirSI24"] = True \
                if ap_config["cleanAirSI24"] == "Enabled" else False

        if ap_config.get("cleanAirSI5") is not None:
            ap_config["configureCleanAirSI5Ghz"] = True
            ap_config["cleanAirSI5"] = True \
                if ap_config["cleanAirSI5"] == "Enabled" else False

        if ap_config.get("cleanAirSI6") is not None:
            ap_config["configureCleanAirSI6Ghz"] = True
            ap_config["cleanAirSI6"] = True \
                if ap_config["cleanAirSI6"] == "Enabled" else False

        if ap_config.get("radioConfigurations") is not None:
            radio_config_list = ap_config.get("radioConfigurations")
            temp_radio_dtos_list = []
            for each_radio in radio_config_list:
                radio_dtos = {}

                if each_radio.get(self.keymap["admin_status"]) is not None:
                    radio_dtos["configureAdminStatus"] = True
                    radio_dtos[self.keymap["admin_status"]] = True \
                        if each_radio[self.keymap["admin_status"]] == "Enabled" else False

                if each_radio.get(self.keymap["channel_assignment_mode"]) is not None:
                    radio_dtos[self.keymap["channel_assignment_mode"]] = 1 \
                        if each_radio[self.keymap["channel_assignment_mode"]] == "Global" else 2
                    radio_dtos["configureChannel"] = True

                if each_radio.get(self.keymap["channel_number"]) is not None:
                    radio_dtos["channelNumber"] = \
                        each_radio.get(self.keymap["channel_number"])
                    radio_dtos["configureChannel"] = True
                    radio_dtos[self.keymap["channel_assignment_mode"]] = 2

                if each_radio.get(self.keymap["channel_width"]) is not None:
                    if each_radio.get(self.keymap["channel_width"]) == "20 MHz":
                        radio_dtos[self.keymap["channel_width"]] = 3
                    elif each_radio.get(self.keymap["channel_width"]) == "40 MHz":
                        radio_dtos[self.keymap["channel_width"]] = 4
                    elif each_radio.get(self.keymap["channel_width"]) == "80 MHz":
                        radio_dtos[self.keymap["channel_width"]] = 5
                    elif each_radio.get(self.keymap["channel_width"]) == "160 MHz":
                        radio_dtos[self.keymap["channel_width"]] = 6
                    else:
                        radio_dtos[self.keymap["channel_width"]] = 7
                    radio_dtos["configureChannelWidth"] = True

                if each_radio.get(self.keymap["power_assignment_mode"]) is not None:
                    if each_radio[self.keymap["power_assignment_mode"]] == "Global":
                        radio_dtos[self.keymap["power_assignment_mode"]] = 1
                    else:
                        radio_dtos[self.keymap["power_assignment_mode"]] = 2
                    radio_dtos["configurePower"] = True
                self.log(self.pprint(each_radio), "INFO")
                if each_radio.get(self.keymap["power_level"]) is not None:
                    radio_dtos["powerlevel"] = \
                        each_radio.get(self.keymap["power_level"])
                    radio_dtos[self.keymap["power_assignment_mode"]] = 2
                    radio_dtos["configurePower"] = True

                if each_radio.get("antenna_cable_name") is not None:
                    radio_dtos["antennaCableName"] = \
                        each_radio.get("antenna_cable_name")
                    radio_dtos["configureAntennaCable"] = True

                if each_radio.get("antenna_name") is not None:
                    radio_dtos["antennaPatternName"] = each_radio.get("antenna_name")
                    radio_dtos["configureAntennaPatternName"] = True

                if each_radio.get(self.keymap["radio_band"]) is not None:
                    if each_radio[self.keymap["radio_band"]] == "2.4 GHz":
                        radio_dtos[self.keymap["radio_band"]] = "RADIO24"
                    elif each_radio[self.keymap["radio_band"]] == "5 GHz":
                        radio_dtos[self.keymap["radio_band"]] = "RADIO5"
                    else:
                        radio_dtos[self.keymap["radio_band"]] = "RADIO6"

                if each_radio.get(self.keymap["radio_role_assignment"]) is not None:
                    if each_radio.get(self.keymap["radio_role_assignment"]) == "Auto":
                        radio_dtos[self.keymap["radio_role_assignment"]] = "AUTO"
                    elif each_radio.get(self.keymap["radio_role_assignment"]) == "Client-Serving":
                        radio_dtos[self.keymap["radio_role_assignment"]] = "SERVING"
                    else:
                        radio_dtos[self.keymap["radio_role_assignment"]] = "MONITOR"
                    radio_dtos["configureRadioRoleAssignment"] = True

                if each_radio.get(self.keymap["radio_type"]) is not None:
                    radio_dtos[self.keymap["radio_type"]] = \
                        each_radio.get(self.keymap["radio_type"])

                if each_radio.get("cable_loss") is not None:
                    radio_dtos["cableLoss"] = each_radio.get("cable_loss")
                    radio_dtos["antennaCableName"] = "other"
                    radio_dtos["configureAntennaCable"] = True

                if each_radio.get(self.keymap["antenna_gain"]) is not None:
                    if each_radio.get(self.keymap["antenna_gain"]) is not None and \
                            each_radio.get(self.keymap["antenna_gain"]) >= 0:
                        radio_dtos[self.keymap["antenna_gain"]] = \
                            each_radio.get(self.keymap["antenna_gain"])
                        radio_dtos["antennaPatternName"] = "other"
                        radio_dtos["configureAntennaPatternName"] = True

                temp_radio_dtos_list.append(radio_dtos)
            ap_config["radioConfigurations"] = temp_radio_dtos_list

        for key_to_remove in ("mac_address", "hostname", "management_ip_address", "macAddress"):
            if ap_config.get(key_to_remove):
                del ap_config[key_to_remove]

        self.log("Update access point before update: {0}".format(self.pprint(ap_config)), "INFO")
        try:
            response = self.dnac._exec(
                family="wireless",
                function="configure_access_points_v2",
                op_modifies=True,
                params={"payload": ap_config}
            )

            if response:
                response = response.get("response")
                self.log("Response of Access Point Configuration: {0}".format(
                    self.pprint(response)), "INFO")
                if not ap_config.get("bulk_update"):
                    return dict(mac_address=self.have["mac_address"], response=response)
                else:
                    return dict(response=response)

        except Exception as e:
            self.log("AP config update Error: {0} {1}".format(self.pprint(ap_config), str(e)),
                     "ERROR")
            return None

    def data_frame(self, fields_to_include=None, records=list):
        """
        Filters the input data to include only the specified fields.

        Parameters:
            fields_to_include (str): Comma-separated string of keys to display.
            records (list of dict): A list of dictionaries with only the specified fields.

        Returns:
            list: A list of dictionaries containing filtered records.

        Example:
            functions = Accesspoint(module)
            final_input_data = functions.data_frame(ap_selected_fields, device_records)
        """
        try:
            if records is None:
                return []

            records = self.camel_to_snake_case(records)

            if not fields_to_include or fields_to_include.strip() == "":
                return records

            field_names = [field.strip() for field in fields_to_include.split(",")]
            filtered_data = []

            for record in records:
                filtered_record = {}

                for field in field_names:
                    filtered_record[field] = record.get(field)

                filtered_data.append(filtered_record)

            return filtered_data

        except Exception as e:
            self.log("Unable to filter fields: {0}".format(str(e)) , "ERROR")
            return None

    def consolidate_output(self):
        """
        Bulk access point changes collect each output update in the response.

        Parameters:
            self (dict): A dictionary used to collect the execution results.

        Returns:
            dict: A dictionary containing the result of the access point update response.
        """
        each_result = {
            "changed": self.result["changed"],
            "response": self.result["response"].get("accesspoints_verify"),
        }
        self.payload["consolidated_result"].append(each_result)
        self.log("Each execution Result {0}".format(self.pprint(self.result)))
        self.result["changed"] = False

        for each_cosolidated in self.payload["consolidated_result"]:
            if each_cosolidated["changed"]:
                self.result["changed"] = True
                break

        if self.result["changed"]:
            self.status = "success"

        self.msg = self.pprint(self.payload["consolidated_result"])
        self.result["response"] = self.payload["consolidated_result"]
        self.log("Consolidated Result: {0}".format(self.pprint(self.result)))

        return self

    def reboot_access_point(self, ap_list):
        """
        Reboots access points, handling single or bulk APs.

        Parameters:
            self (dict): A dictionary used to collect the execution results.
            ap_list (dict): A list containing the list of Access point Mac Address.

        Returns:
            dict: A dictionary containing the result of the access point reboot response.
        """
        try:
            self.log('Rebooting the list of APs: {0}'.format(self.pprint(ap_list)), "INFO")
            response = self.dnac._exec(
                family="wireless",
                function='reboot_access_points',
                op_modifies=True,
                params={"apMacAddresses": ap_list},
            )
            self.log("Response from reboot_access_points: {0}".format(str(response.get("response"))), "INFO")

            if response and isinstance(response, dict):
                task_id = response.get("response", {}).get("taskId")
                resync_retry_count = int(self.payload.get("dnac_api_task_timeout"))
                resync_retry_interval = int(self.payload.get("dnac_task_poll_interval"))

                while resync_retry_count:
                    task_details_response = self.get_tasks_by_id(task_id)
                    self.log("Status of the reboot task: {0} .".format(self.status), "INFO")
                    responses = {}
                    if task_details_response.get("endTime") is not None:
                        if task_details_response.get("status") == "SUCCESS":
                            self.log("Reboot Task Details: {0} .".format(self.pprint(
                                task_details_response)), "INFO")
                            self.msg = "APs {0} rebooted successfully".format(str(ap_list))
                            reboot_status = self.access_point_reboot_status(task_id)
                            responses = {
                                "accesspoints_updates": {
                                    "ap_reboot_task_details": {"reboot_api_response": reboot_status["apList"]},
                                    "ap_reboot_status": self.msg
                                }
                            }
                            self.result['changed'] = True
                            self.result['response'] = responses
                            self.log("Given APs '{0}' rebooted successfully with task: '{1}'."
                                     .format(ap_list, self.pprint(task_details_response)), "INFO")
                            return self

                        self.result['changed'] = False
                        self.msg = "Unable to get success response, hence APs are not rebooted"
                        self.log(self.msg, "ERROR")
                        self.log("Reboot Task Details: {0} .".format(self.pprint(
                            task_details_response)), "ERROR")
                        reboot_status = self.access_point_reboot_status(task_id)
                        responses["accesspoints_updates"] = {
                            "ap_reboot_task_details": {
                                "status": task_details_response.get("status"),
                                "reboot_api_response": reboot_status["apList"]
                            },
                            "ap_reboot_status": self.msg}
                        self.set_operation_result("failed", self.result['changed'],
                                                  self.msg, "ERROR", responses).check_return_status()
                    time.sleep(resync_retry_interval)
                    resync_retry_count = resync_retry_count - 1
            else:
                self.msg = "Failed to receive a valid response from AP reboot API."
                self.log(self.msg, "ERROR")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        except Exception as e:
            error_msg = 'An error occurred during access point reboot: {0}'.format(str(e))
            self.log(error_msg, "ERROR")
            self.set_operation_result("failed", False, error_msg, "ERROR").check_return_status()

    def access_point_reboot_status(self, task_id):
        """
        Get the reboot status of the accesspoint using by the task id.

        Parameters:
            self (dict): A dictionary used to collect the execution results.
            task_id (string): A sting containing the task id generated from reboot task.

        Returns:
            dict: A dictionary containing the result of the access point reboot status.
        """
        try:
            response = self.dnac._exec(
                family="wireless",
                function='get_access_point_reboot_task_result',
                op_modifies=True,
                params={"parentTaskId": task_id},
            )
            self.log("Response from ap reboot status: {0}".format(self.pprint(response)), "INFO")
            if response and isinstance(response[0], dict):
                return response[0]
            error_msg = "Invalid response format or missing data in AP reboot status."
            self.log(error_msg, "ERROR")
            self.set_operation_result("failed", False, error_msg, "ERROR").check_return_status()
        except Exception as e:
            error_msg = 'An error occurred during access point reboot status: {0}'.format(str(e))
            self.log(error_msg, "ERROR")
            self.set_operation_result("failed", False, error_msg, "ERROR").check_return_status()

    def reset_access_point(self, ap_list):
        """
        Factory reset access points, handling single or bulk APs.

        Parameters:
            self (dict): A dictionary used to collect the execution results.
            ap_list (dict): A list containing the list of Access point Mac Address.

        Returns:
            dict: A dictionary containing the result of the access point factory reset response.
        """
        try:
            self.log('Resetting the list of APs: {0}'.format(self.pprint(ap_list)), "INFO")
            response = self.dnac._exec(
                family="wireless",
                function='factory_reset_access_points',
                op_modifies=True,
                params={"apMacAddresses": ap_list, "keepStaticIPConfig": False},
            )
            self.log("Response from factory_reset_access_points: {0}".format(str(response.get("response"))), "INFO")

            if not (response or isinstance(response, dict)):
                self.msg = "Failed to receive a valid response from 'factory_reset_access_points' API."
                self.log(self.msg, "ERROR")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            task_id = response.get("response", {}).get("taskId")
            if not task_id:
                self.msg = "Failed to retrieve task id from 'factory_reset_access_points' API response."
                self.log(self.msg, "ERROR")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            resync_retry_count = int(self.payload.get("dnac_api_task_timeout"))
            resync_retry_interval = int(self.payload.get("dnac_task_poll_interval"))

            while resync_retry_count:
                task_details_response = self.get_tasks_by_id(task_id)
                self.log("Status of the reset task: {0} .".format(self.status), "INFO")
                responses = {}

                if task_details_response.get("endTime") is not None:
                    if task_details_response.get("status") == "SUCCESS":
                        self.log("Reset Task Details: {0} .".format(self.pprint(
                            task_details_response)), "INFO")
                        self.msg = "APs {0} reset successfully".format(str(ap_list))
                        reset_status = self.access_point_reset_status(task_id)
                        responses = {
                            "accesspoints_updates": {
                                "ap_reset_task_details": {"reset_api_response": reset_status.get("apResponseInfoList")},
                                "ap_reset_status": self.msg
                            }
                        }
                        self.result['changed'] = True
                        self.result['response'] = responses
                        self.log(
                            "Factory reset of APs '{0}' completed successfully with task: '{1}'.".format(
                                ap_list, self.pprint(task_details_response)
                            ),
                            "INFO"
                        )
                        return self

                    self.msg = (
                        "Failed to receive a successful response from the reset task; "
                        "therefore, the APs were not reset."
                    )
                    self.log(self.msg, "ERROR")
                    self.log("Reset Task Details: {0} .".format(self.pprint(
                        task_details_response)), "ERROR")
                    reset_status = self.access_point_reset_status(task_id)
                    self.log("Reset Error Details: {0} .".format(self.pprint(reset_status)), "ERROR")
                    responses["accesspoints_updates"] = {
                        "ap_reset_task_details": {
                            "status": task_details_response.get("status"),
                            "reset_api_response": reset_status.get("apResponseInfoList")
                        },
                        "ap_reset_status": self.msg}
                    self.set_operation_result("failed", False, self.msg, "ERROR", responses).check_return_status()

                time.sleep(resync_retry_interval)
                resync_retry_count = resync_retry_count - 1

        except Exception as e:
            error_msg = 'An error occurred during access point reset: {0}'.format(str(e))
            self.log(error_msg, "ERROR")
            self.set_operation_result("failed", False, error_msg, "ERROR").check_return_status()

    def access_point_reset_status(self, task_id):
        """
        Get the reset status of the accesspoint using by the task id.

        Parameters:
            self (dict): A dictionary used to collect the execution results.
            task_id (string): A sting containing the task id generated from factory reset task.

        Returns:
            dict: A dictionary containing the result of the access point reset status.
        """
        try:
            response = self.dnac._exec(
                family="wireless",
                function='get_access_points_factory_reset_status',
                params={"task_id": task_id},
            )
            self.log("Response from ap reset status: {0}".format(self.pprint(response)), "INFO")
            if response and isinstance(response.get("response")[0], dict):
                return response.get("response", {})[0]

            error_msg = "Invalid response format or missing data in AP reset status."
            self.log(error_msg, "ERROR")
            self.set_operation_result("failed", False, error_msg, "ERROR").check_return_status()

        except Exception as e:
            error_msg = 'An error occurred during access point reset status: {0}'.format(str(e))
            self.log(error_msg, "ERROR")
            self.set_operation_result("failed", False, error_msg, "ERROR").check_return_status()

    def reboot_factory_reset_function(self, ap_list, reboot_or_reset):
        """
        Process reboot and factory reset function from the main by accepting AP list and reset or reboot mode.

        Parameters:
            self (dict): A dictionary used to collect the execution results.
            ap_list (list): A list containing the APs mac address which need to reset or reboot.
            reboot_or_reset (str): A string containing reset or reboot mode.

        Returns:
            dict: A dictionary containing the result of the access point reset/reboot status.
        """
        ap_indentity = list(ap_list.keys())[0]
        if ap_indentity and len(ap_list.get(ap_indentity)) > 100:
            error_msg = "Maximum allowed AP list 100 but passed {0}".format(str(len(ap_list.get(ap_indentity))))
            self.log(error_msg, "ERROR")
            self.set_operation_result("failed", False, error_msg, "ERROR").check_return_status()

        if ap_indentity and ap_indentity in self.keymap and len(ap_list.get(ap_indentity)) > 0:
            eth_mac_list = []
            for each_ap in ap_list[ap_indentity]:
                ap_indentity_param = {self.keymap[ap_indentity]: each_ap}
                self.log("{0}: {1}".format(reboot_or_reset, str(ap_indentity_param)), "INFO")
                ap_exist, ap_details = self.get_accesspoint_details(ap_indentity_param)
                eth_mac_list.append(ap_details.get("ap_ethernet_mac_address"))

            if eth_mac_list:
                self.log("Ethernet MAC addresses to {0}: {1}".format(reboot_or_reset, eth_mac_list), "INFO")
                if reboot_or_reset == "reboot_aps":
                    self.reboot_access_point(eth_mac_list)
                else:
                    self.reset_access_point(eth_mac_list)
            else:
                self.log("No valid Ethernet MAC addresses found for {0}.".format(reboot_or_reset), "WARNING")

            return self

    def bulk_ap_update(self, bulk_config):
        """
        Access Point bulk update common field to update to all mentioned AP list.

        Parameters:
            self (dict): A dictionary used to collect the execution results.
            bulk_config (dict): A dict containing the APs mac address and cofig details which need to update APs.

        Returns:
            dict: A dictionary containing the result of the buld access point update status.
        """
        ap_exist, ap_details = self.get_accesspoint_details(bulk_config)
        self.payload["access_point_details"] = ap_details
        ap_update_list = []
        common_config = {}
        ap_output_list = []

        if ap_exist and len(ap_details) > 0:
            self.log("Access points exist. Total count: {0}".format(str(len(ap_details))), "INFO")

            for each_ap in ap_details:
                ap_config_exists, ap_configuration = self.get_accesspoint_config(each_ap["ap_ethernet_mac_address"])
                self.log("Access point configuration exists: {0}, Current configuration: {1}"
                         .format(ap_config_exists, self.pprint(ap_configuration)), "INFO")
                self.want = bulk_config.get("common_fields_to_change")
                self.want["mac_address"] = each_ap["mac_address"]
                ap_name = [ap.get('ap_name') for ap in bulk_config.get("ap_identifier")
                           if (each_ap["mac_address"] == ap.get('mac_address') or
                               each_ap["hostname"] == ap.get('hostname') or
                               each_ap["management_ip_address"] == ap.get('management_ip_address'))]
                if ap_name:
                    self.want["ap_name"] = ap_name[0]
                    ap_output_list.append(ap_name[0])
                    self.log("Identified AP name: {0}".format(ap_name[0]), "INFO")
                else:
                    self.log("No matching AP name found for MAC: {0}".format(each_ap["mac_address"]), "WARNING")

                self.log("Access point WANT configuration exists: {0}, Current configuration: {1}"
                         .format(ap_config_exists, self.pprint(self.want)), "INFO")
                consolidated_config = self.config_diff(ap_configuration)
                self.log("Consolidated configuration for AP {0}: {1}".format(each_ap["mac_address"],
                                                                             self.pprint(consolidated_config)), "DEBUG")

                temp_dict = {}
                if consolidated_config.get(self.keymap["ap_name"]) is not None:
                    temp_dict[self.keymap["ap_name"]] = consolidated_config.get(self.keymap["ap_name"])
                    temp_dict["apNameNew"] = consolidated_config["apNameNew"]
                    temp_dict[self.keymap["mac_address"]] = consolidated_config[self.keymap["mac_address"]]
                elif consolidated_config.get(self.keymap["mac_address"]) is not None:
                    temp_dict[self.keymap["mac_address"]] = consolidated_config.get(self.keymap["mac_address"])
                ap_update_list.append(temp_dict)
                self.log("Temp dict for AP {0}: {1}".format(each_ap["mac_address"], self.pprint(temp_dict)), "DEBUG")
                common_config.update(consolidated_config)

            common_config["bulk_update"] = True
            common_config["ap_list"] = ap_update_list
            self.log("Common configuration for bulk update: {0}".format(self.pprint(common_config)), "INFO")

            task_response = self.update_ap_configuration(common_config)
            self.log("Access Point update response: {0} .".format(task_response), "INFO")
            responses = {}
            if task_response and isinstance(task_response, dict):
                resync_retry_count = self.payload.get("dnac_api_task_timeout")
                resync_retry_interval = self.payload.get("dnac_task_poll_interval")
                self.log("Starting task polling with timeout: {0} and interval: {1}".
                         format(str(resync_retry_count), str(resync_retry_interval)), "INFO")
                while resync_retry_count:
                    task_details_response = self.get_tasks_by_id(
                        task_response["response"]["taskId"])
                    self.log("Status of the task: {0} .".format(self.status), "INFO")

                    if task_details_response.get("endTime") is not None:
                        if task_details_response.get("status") == "FAILURE":
                            self.result["changed"] = True if self.result["changed"] is True else False
                            self.msg = "Unable to get success response, hence AP config not updated"
                            self.log(self.msg, "ERROR")
                            self.log("Task Details: {0} .".format(self.pprint(task_details_response)), "ERROR")
                            failure_response = self.get_task_details_by_id(task_response["response"]["taskId"])
                            self.log("Failure Details: {0} .".format(self.pprint(failure_response)), "ERROR")
                            self.set_operation_result("failed", self.result["changed"],
                                                      self.msg, "ERROR", failure_response).check_return_status()
                        else:
                            self.result["changed"] = True
                            self.result["ap_update_status"] = True
                            self.log("Task Details: {0} .".format(self.pprint(
                                task_details_response)), "INFO")
                            self.msg = "List of AP Configuration {0} updated Successfully".format(str(ap_output_list))
                            self.log(self.msg, "INFO")
                            responses["accesspoints_updates"] = {
                                "ap_update_config_task_details": self.get_task_details_by_id(task_details_response["id"]),
                                "ap_config_update_status": self.msg
                            }
                            self.result["ap_update_msg"] = self.msg
                        break

                    self.log("Polling task status, waiting for {0} seconds before the next check...".
                             format(str(resync_retry_interval)), "DEBUG")
                    time.sleep(resync_retry_interval)
                    resync_retry_count = resync_retry_count - 1

            self.result["response"] = responses
            return self


def main():
    """ main entry point for module execution
    """
    accepoint_spec = {
        "dnac_host": {"required": True, "type": "str"},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": "True"},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "config_verify": {"type": "bool", "default": False},
        "dnac_log_append": {"type": "bool", "default": True},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "next_task_after_interval": {"type": "int", "default": 5},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "validate_response_schema": {"type": "bool", "default": True},
        "state": {"default": "merged", "choices": ["merged", "deleted"]}
    }
    module = AnsibleModule(
        argument_spec=accepoint_spec,
        supports_check_mode=True
    )

    ccc_network = Accesspoint(module)
    state = ccc_network.params.get("state")

    if state not in ccc_network.supported_states:
        ccc_network.status = "invalid"
        ccc_network.msg = "State {0} is invalid".format(state)
        ccc_network.check_return_status()

    if ccc_network.compare_dnac_versions(ccc_network.get_ccc_version(), "2.3.5.3") < 0:
        ccc_network.status = "failed"
        ccc_network.msg = (
            "The specified version '{0}' does not support the access point workflow feature."
            "Supported version(s) start from '2.3.5.3' onwards.".format(ccc_network.get_ccc_version())
        )
        ccc_network.log(ccc_network.msg, "ERROR")
        ccc_network.check_return_status()

    ccc_network.validate_input_yml().check_return_status()
    config_verify = ccc_network.params.get("config_verify")

    # Below set of line related to the Access Point reboot / factory reset function.
    for reboot_reset in ("reboot_aps", "factory_reset_aps"):
        ap_list = ccc_network.validated_config[0].get(reboot_reset)
        if ap_list is not None:
            ccc_network.validate_ap_config_parameters(ccc_network.validated_config[0]).check_return_status()
            ccc_network.reboot_factory_reset_function(ap_list, reboot_reset)
            module.exit_json(**ccc_network.result)

    bulk_updates = ccc_network.validated_config[0].get("bulk_update_aps")
    if bulk_updates is not None:
        ccc_network.log("Bulk List: {0}".format(ccc_network.pprint(bulk_updates)), "INFO")
        ccc_network.reset_values()
        ccc_network.validate_ap_config_parameters(bulk_updates).check_return_status()
        ccc_network.bulk_ap_update(bulk_updates)
        module.exit_json(**ccc_network.result)

    for config in ccc_network.validated_config:
        ccc_network.reset_values()
        ccc_network.get_want(config).check_return_status()
        ccc_network.get_have(config).check_return_status()
        ccc_network.get_diff_state_apply[state](config).check_return_status()

        if config_verify:
            waiting_time_to_verify = 10
            ccc_network.log("Starting verify AP details after {0} seconds".format(
                str(waiting_time_to_verify)), "INFO")
            time.sleep(waiting_time_to_verify)
            ccc_network.verify_diff_state_apply[state](config).check_return_status()
            ccc_network.consolidate_output()

    module.exit_json(**ccc_network.result)


if __name__ == "__main__":
    main()
