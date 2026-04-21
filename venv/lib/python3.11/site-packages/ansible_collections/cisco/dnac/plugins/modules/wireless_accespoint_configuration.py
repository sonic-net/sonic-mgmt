#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_accespoint_configuration
short_description: Resource module for Wireless Accespoint
  Configuration
description:
  - Manage operation create of the resource Wireless
    Accespoint Configuration. - > User can configure
    multiple access points with required options using
    this intent API. This API does not support configuration
    of CleanAir or SI for IOS-XE devices with version
    greater than or equal to 17.9.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  adminStatus:
    description: Configure the access point's admin
      status. Set this parameter's value to "true" to
      enable it and "false" to disable it.
    type: bool
  apList:
    description: Wireless Accespoint Configuration's
      apList.
    elements: dict
    suboptions:
      apName:
        description: The current host name of the access
          point.
        type: str
      apNameNew:
        description: The modified hostname of the access
          point.
        type: str
      macAddress:
        description: The ethernet MAC address of the
          access point.
        type: str
    type: list
  apMode:
    description: Configure the access point's mode for
      local/flexconnect mode, set "0"; for monitor mode,
      set "1"; for sniffer mode, set "4"; and for bridge/flex+bridge
      mode, set "5".
    type: int
  configureAdminStatus:
    description: To change the access point's admin
      status, set this parameter's value to "true".
    type: bool
  configureApMode:
    description: To change the access point's mode,
      set this parameter's value to "true".
    type: bool
  configureFailoverPriority:
    description: To change the access point's failover
      priority, set this parameter's value to "true".
    type: bool
  configureHAController:
    description: To change the access point's HA controller,
      set this parameter's value to "true".
    type: bool
  configureLedBrightnessLevel:
    description: To change the access point's LED brightness
      level, set this parameter's value to "true".
    type: bool
  configureLedStatus:
    description: To change the access point's LED status,
      set this parameter's value to "true".
    type: bool
  configureLocation:
    description: To change the access point's location,
      set this parameter's value to "true".
    type: bool
  failoverPriority:
    description: Configure the acess point's failover
      priority for low, set "1"; for medium, set "2";
      for high, set "3"; and for critical, set "4".
    type: int
  isAssignedSiteAsLocation:
    description: If AP is assigned to a site, then to
      assign AP location as the site name, set this
      parameter's value to "true".
    type: bool
  ledBrightnessLevel:
    description: Configure the access point's LED brightness
      level by setting a value between 1 and 8.
    type: int
  ledStatus:
    description: Configure the access point's LED status.
      Set "true" to enable its status and "false" to
      disable it.
    type: bool
  location:
    description: Configure the access point's location.
    type: str
  primaryControllerName:
    description: Configure the hostname for an access
      point's primary controller.
    type: str
  primaryIpAddress:
    description: Wireless Accespoint Configuration's
      primaryIpAddress.
    suboptions:
      address:
        description: Configure the IP address for an
          access point's primary controller.
        type: str
    type: dict
  radioConfigurations:
    description: Wireless Accespoint Configuration's
      radioConfigurations.
    elements: dict
    suboptions:
      adminStatus:
        description: Configure the admin status on the
          specified radio for an access point. Set this
          parameter's value to "true" to enable it and
          "false" to disable it.
        type: bool
      antennaCableName:
        description: Configure the antenna cable name
          on the specified radio for an access point.
          If cable loss needs to be configured, set
          this parameter's value to "other".
        type: str
      antennaGain:
        description: Configure the antenna gain on the
          specified radio for an access point by setting
          a decimal value (in dBi). To configure "antennaGain",
          set "antennaPatternName" value to "other".
          The External Antenna Gain value will be applied
          in 0.5 dBi increments on the controller. Therefore,
          the value entered will be multiplied by 2
          to configure the absolute gain value. AntennaGain
          should be in range of 0-20.
        type: int
      antennaPatternName:
        description: Specify the antenna name on the
          specified radio for an access point. The antenna
          name is used to calculate the gain on the
          radio slot.
        type: str
      cableLoss:
        description: Configure the cable loss on the
          specified radio for an access point by setting
          a decimal value (in dBi).
        type: float
      channelAssignmentMode:
        description: Configure the channel assignment
          mode on the specified radio for an access
          point for global mode, set "1"; and for custom
          mode, set "2".
        type: int
      channelNumber:
        description: Configure the channel number on
          the specified radio for an access point.
        type: int
      channelWidth:
        description: Configure the channel width on
          the specified radio for an access point for
          20 MHz, set "3"; for 40 MHz, set "4"; for
          80 MHz, set "5"; for 160 MHz, set "6", and
          for 320 MHz, set "7".
        type: int
      cleanAirSI:
        description: Configure CleanAir or Spectrum
          Intelligence on the specified radio for an
          access point. Set this parameter's value to
          "0" to disable the feature or "1" to enable
          it.
        type: int
      configureAdminStatus:
        description: To change the admin status on the
          specified radio for an access point, set this
          parameter's value to "true".
        type: bool
      configureAntennaCable:
        description: To change the antenna cable name
          on the specified radio for an access point,
          set this parameter's value to "true".
        type: bool
      configureAntennaPatternName:
        description: To change the antenna gain on the
          specified radio for an access point, set the
          value for this parameter to "true".
        type: bool
      configureChannel:
        description: To change the channel on the specified
          radio for an access point, set this parameter's
          value to "true".
        type: bool
      configureChannelWidth:
        description: To change the channel width on
          the specified radio for an access point, set
          this parameter's value to "true".
        type: bool
      configureCleanAirSI:
        description: To enable or disable either CleanAir
          or Spectrum Intelligence on the specified
          radio for an access point, set this parameter's
          value to "true".
        type: bool
      configurePower:
        description: To change the power assignment
          mode on the specified radio for an access
          point, set this parameter's value to "true".
        type: bool
      configureRadioRoleAssignment:
        description: To change the radio role on the
          specified radio for an access point, set this
          parameter's value to "true".
        type: bool
      powerAssignmentMode:
        description: Configure the power assignment
          mode on the specified radio for an access
          point for global mode, set "1"; and for custom
          mode, set "2".
        type: int
      powerlevel:
        description: Configure the power level on the
          specified radio for an access point by setting
          a value between 1 and 8.
        type: int
      radioBand:
        description: Configure the band on the specified
          radio for an access point for 2.4 GHz, set
          "RADIO24"; for 5 GHz, set "RADIO5"; for 6
          GHz, set "RADIO6". Any other string is invalid,
          including empty string.
        type: str
      radioRoleAssignment:
        description: Configure only one of the following
          roles on the specified radio for an access
          point as "AUTO", "SERVING", or "MONITOR".
          Any other string is invalid, including empty
          string.
        type: str
      radioType:
        description: Configure an access point's radio
          band for 2.4 GHz, set "1"; for 5 GHz, set
          "2"; for XOR, set "3"; and for 6 GHz, set
          "6".
        type: int
    type: list
  secondaryControllerName:
    description: Configure the hostname for an access
      point's secondary controller.
    type: str
  secondaryIpAddress:
    description: Wireless Accespoint Configuration's
      secondaryIpAddress.
    suboptions:
      address:
        description: Configure the IP address for an
          access point's secondary controller.
        type: str
    type: dict
  tertiaryControllerName:
    description: Configure the hostname for an access
      point's tertiary controller.
    type: str
  tertiaryIpAddress:
    description: Wireless Accespoint Configuration's
      tertiaryIpAddress.
    suboptions:
      address:
        description: Configure the IP address for an
          access point's tertiary controller.
        type: str
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      ConfigureAccessPoints
    description: Complete reference of the ConfigureAccessPoints
      API.
    link: https://developer.cisco.com/docs/dna-center/#!configure-access-points
notes:
  - SDK Method used are
    wireless.Wireless.configure_access_points,
  - Paths used are
    post /dna/intent/api/v1/wireless/accesspoint-configuration,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wireless_accespoint_configuration:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    adminStatus: true
    apList:
      - apName: string
        apNameNew: string
        macAddress: string
    apMode: 0
    configureAdminStatus: true
    configureApMode: true
    configureFailoverPriority: true
    configureHAController: true
    configureLedBrightnessLevel: true
    configureLedStatus: true
    configureLocation: true
    failoverPriority: 0
    isAssignedSiteAsLocation: true
    ledBrightnessLevel: 0
    ledStatus: true
    location: string
    primaryControllerName: string
    primaryIpAddress:
      address: string
    radioConfigurations:
      - adminStatus: true
        antennaCableName: string
        antennaGain: 0
        antennaPatternName: string
        cableLoss: 0
        channelAssignmentMode: 0
        channelNumber: 0
        channelWidth: 0
        cleanAirSI: 0
        configureAdminStatus: true
        configureAntennaCable: true
        configureAntennaPatternName: true
        configureChannel: true
        configureChannelWidth: true
        configureCleanAirSI: true
        configurePower: true
        configureRadioRoleAssignment: true
        powerAssignmentMode: 0
        powerlevel: 0
        radioBand: string
        radioRoleAssignment: string
        radioType: 0
    secondaryControllerName: string
    secondaryIpAddress:
      address: string
    tertiaryControllerName: string
    tertiaryIpAddress:
      address: string
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
