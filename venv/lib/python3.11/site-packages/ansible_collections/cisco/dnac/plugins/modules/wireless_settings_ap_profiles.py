#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_settings_ap_profiles
short_description: Resource module for Wireless Settings
  Ap Profiles
description:
  - Manage operation create of the resource Wireless
    Settings Ap Profiles.
  - This API allows the user to create a custom AP Profile.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  apPowerProfileName:
    description: Name of the existing AP power profile.
    type: str
  apProfileName:
    description: Name of the Access Point profile. Max
      length is 32 characters.
    type: str
  awipsEnabled:
    description: Indicates if AWIPS is enabled on the
      AP.
    type: bool
  awipsForensicEnabled:
    description: Indicates if AWIPS forensic is enabled
      on the AP. Forensic Capture is supported from
      IOS-XE version 17.4 and above. Forensic Capture
      can be activated only if aWIPS is enabled.
    type: bool
  calendarPowerProfiles:
    description: Wireless Settings Ap Profiles's calendarPowerProfiles.
    suboptions:
      duration:
        description: Wireless Settings Ap Profiles's
          duration.
        suboptions:
          schedulerDate:
            description: Start and End date of the duration
              setting, applicable for MONTHLY schedulers.
              Values must be between 1 and 31.
            elements: str
            type: list
          schedulerDay:
            description: Applies every week on the selected
              days. Ex "sunday","saturday","tuesday","wednesday","thu...
            elements: str
            type: list
          schedulerEndTime:
            description: End time of the duration setting.
            type: str
          schedulerStartTime:
            description: Start time of the duration
              setting.
            type: str
        type: dict
      powerProfileName:
        description: Name of the existing AP power profile
          to be mapped to the calendar power profile.
          API-/intent/api/v1/wirelessSettings/powerProfiles.
        type: str
      schedulerType:
        description: Type of the scheduler.
        type: str
    type: dict
  clientLimit:
    description: Number of clients. Value should be
      between 0-1200.
    type: int
  countryCode:
    description: Country Code.
    type: str
  description:
    description: Description of the AP profile. Max
      length is 241 characters.
    type: str
  managementSetting:
    description: Wireless Settings Ap Profiles's managementSetting.
    suboptions:
      authType:
        description: Authentication type used in the
          AP profile. These setting are applicable during
          PnP claim and for day-N authentication of
          AP. Changing these settings will be service
          impacting for the PnP onboarded APs and will
          need a factory-reset for those APs.
        type: str
      cdpState:
        description: Indicates if CDP is enabled on
          the AP. Enable CDP in order to make Cisco
          Access Points known to its neighboring devices
          and vice-versa.
        type: bool
      dot1xPassword:
        description: Password for 802.1X authentication.
          Length must be 8-120 characters.
        type: str
      dot1xUsername:
        description: Username for 802.1X authentication.
          Dot1xUsername must have a minimum of 1 character
          and a maximum of 32 characters.
        type: str
      managementEnablePassword:
        description: Enable password for managing the
          AP. Length must be 8-120 characters.
        type: str
      managementPassword:
        description: Management password for the AP.
          Length must be 8-120 characters.
        type: str
      managementUserName:
        description: Management username must have a
          minimum of 1 character and a maximum of 32
          characters.
        type: str
      sshEnabled:
        description: Indicates if SSH is enabled on
          the AP. Enable SSH add credentials for device
          management.
        type: bool
      telnetEnabled:
        description: Indicates if Telnet is enabled
          on the AP. Enable Telnet to add credentials
          for device management.
        type: bool
    type: dict
  meshEnabled:
    description: This indicates whether mesh networking
      is enabled on the AP. For IOS-XE devices, when
      mesh networking is enabled, a custom mesh profile
      with the configured parameters will be created
      and mapped to the AP join profile on the device.
      When mesh networking is disabled, any existing
      custom mesh profile will be deleted from the device,
      and the AP join profile will be mapped to the
      default mesh profile on the device.
    type: bool
  meshSetting:
    description: Wireless Settings Ap Profiles's meshSetting.
    suboptions:
      backhaulClientAccess:
        description: Indicates if backhaul client access
          is enabled on the AP.
        type: bool
      bridgeGroupName:
        description: Name of the bridge group for mesh
          settings. If not configured, 'Default' Bridge
          group name will be used in mesh profile.
        type: str
      ghz24BackhaulDataRates:
        description: 2.4GHz backhaul data rates.
        type: str
      ghz5BackhaulDataRates:
        description: 5GHz backhaul data rates.
        type: str
      range:
        description: Range of the mesh network. Value
          should be between 150-132000.
        type: int
      rapDownlinkBackhaul:
        description: Type of downlink backhaul used.
        type: str
    type: dict
  pmfDenialEnabled:
    description: Indicates if PMF denial is active on
      the AP. PMF Denial is supported from IOS-XE version
      17.12 and above.
    type: bool
  remoteWorkerEnabled:
    description: Indicates if remote worker mode is
      enabled on the AP. Remote teleworker enabled profile
      cannot support security features like aWIPS,Forensic
      Capture Enablement, Rogue Detection and Rogue
      Containment.
    type: bool
  rogueDetectionSetting:
    description: Wireless Settings Ap Profiles's rogueDetectionSetting.
    suboptions:
      rogueDetection:
        description: Indicates if rogue detection is
          enabled on the AP. Detect Access Points that
          have been installed on a secure network without
          explicit authorization from a system administrator
          and configure rogue general configuration
          parameters.
        type: bool
      rogueDetectionMinRssi:
        description: Minimum RSSI for rogue detection.
          Value should be in range -128 decibel milliwatts
          and -70 decibel milliwatts.
        type: int
      rogueDetectionReportInterval:
        description: Report interval for rogue detection.
          Value should be in range 10 and 300.
        type: int
      rogueDetectionTransientInterval:
        description: Transient interval for rogue detection.
          Value should be 0 or from 120 to 1800.
        type: int
    type: dict
  timeZone:
    description: In the Time Zone area, choose one of
      the following options. Not Configured - APs operate
      in the UTC time zone. Controller - APs operate
      in the Cisco Wireless Controller time zone. Delta
      from Controller - APs operate in the offset time
      from the wireless controller time zone.
    type: str
  timeZoneOffsetHour:
    description: Enter the hour value (HH). The valid
      range is from -12 through 14.
    type: int
  timeZoneOffsetMinutes:
    description: Enter the minute value (MM). The valid
      range is from 0 through 59.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      CreateAPProfile
    description: Complete reference of the CreateAPProfile
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-ap-profile
notes:
  - SDK Method used are
    wireless.Wireless.create_ap_profile,
  - Paths used are
    post /dna/intent/api/v1/wirelessSettings/apProfiles,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wireless_settings_ap_profiles:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    apPowerProfileName: string
    apProfileName: string
    awipsEnabled: true
    awipsForensicEnabled: true
    calendarPowerProfiles:
      duration:
        schedulerDate:
          - string
        schedulerDay:
          - string
        schedulerEndTime: string
        schedulerStartTime: string
      powerProfileName: string
      schedulerType: string
    clientLimit: 0
    countryCode: string
    description: string
    managementSetting:
      authType: string
      cdpState: true
      dot1xPassword: string
      dot1xUsername: string
      managementEnablePassword: string
      managementPassword: string
      managementUserName: string
      sshEnabled: true
      telnetEnabled: true
    meshEnabled: true
    meshSetting:
      backhaulClientAccess: true
      bridgeGroupName: string
      ghz24BackhaulDataRates: string
      ghz5BackhaulDataRates: string
      range: 0
      rapDownlinkBackhaul: string
    pmfDenialEnabled: true
    remoteWorkerEnabled: true
    rogueDetectionSetting:
      rogueDetection: true
      rogueDetectionMinRssi: 0
      rogueDetectionReportInterval: 0
      rogueDetectionTransientInterval: 0
    timeZone: string
    timeZoneOffsetHour: 0
    timeZoneOffsetMinutes: 0
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
