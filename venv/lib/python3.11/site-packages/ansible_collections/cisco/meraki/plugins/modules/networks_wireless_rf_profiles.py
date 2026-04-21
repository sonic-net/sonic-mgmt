#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_rf_profiles
short_description: Resource module for networks _wireless _rf _profiles
description:
  - Manage operations create, update and delete of the resource networks _wireless _rf _profiles.
  - Creates new RF profile for this network.
  - Delete a RF Profile. - > Updates specified RF profile for this network. Note built-in RF profiles can only be assigned as a default, and its
    attributes are immutable.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  apBandSettings:
    description: Settings that will be enabled if selectionType is set to 'ap'.
    suboptions:
      bandOperationMode:
        description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'. Defaults to dual.
        type: str
      bandSteeringEnabled:
        description: Steers client to most open band. Can be either true or false. Defaults to true.
        type: bool
      bands:
        description: Settings related to all bands.
        suboptions:
          enabled:
            description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
            elements: str
            type: list
        type: dict
    type: dict
  bandSelectionType:
    description: Band selection can be set to either 'ssid' or 'ap'. This param is required on creation.
    type: str
  clientBalancingEnabled:
    description: Steers client to best available access point. Can be either true or false. Defaults to true.
    type: bool
  fiveGhzSettings:
    description: Settings related to 5Ghz band.
    suboptions:
      channelWidth:
        description: Sets channel width (MHz) for 5Ghz band. Can be one of 'auto', '20', '40' or '80'. Defaults to auto.
        type: str
      maxPower:
        description: Sets max power (dBm) of 5Ghz band. Can be integer between 2 and 30. Defaults to 30.
        type: int
      minBitrate:
        description: Sets min bitrate (Mbps) of 5Ghz band. Can be one of '6', '9', '12', '18', '24', '36', '48' or '54'. Defaults to 12.
        type: int
      minPower:
        description: Sets min power (dBm) of 5Ghz band. Can be integer between 2 and 30. Defaults to 8.
        type: int
      rxsop:
        description: The RX-SOP level controls the sensitivity of the radio. It is strongly recommended to use RX-SOP only after consulting a
          wireless expert. RX-SOP can be configured in the range of -65 to -95 (dBm). A value of null will reset this to the default.
        type: int
      validAutoChannels:
        description: Sets valid auto channels for 5Ghz band. Can be one of '36', '40', '44', '48', '52', '56', '60', '64', '100', '104', '108',
          '112', '116', '120', '124', '128', '132', '136', '140', '144', '149', '153', '157', '161' or '165'.Defaults to 36, 40, 44, 48, 52, 56,
          60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165.
        elements: int
        type: list
    type: dict
  flexRadios:
    description: Flex radio settings.
    suboptions:
      byModel:
        description: Flex radios by model.
        elements: dict
        suboptions:
          bands:
            description: Band to use for each flex radio. For example, '6' will set the AP's first flex radio to 6 GHz.
            elements: str
            type: list
          model:
            description: Model of the AP.
            type: str
        type: list
    type: dict
  isIndoorDefault:
    description: Set this profile as the default indoor rf profile. If the profile ID is one of 'indoor' or 'outdoor', then a new profile will
      be created from the respective ID and set as the default.
    type: bool
  isOutdoorDefault:
    description: Set this profile as the default outdoor rf profile. If the profile ID is one of 'indoor' or 'outdoor', then a new profile will
      be created from the respective ID and set as the default.
    type: bool
  minBitrateType:
    description: Minimum bitrate can be set to either 'band' or 'ssid'. Defaults to band.
    type: str
  name:
    description: The name of the new profile. Must be unique. This param is required on creation.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  perSsidSettings:
    description: Per-SSID radio settings by number.
    suboptions:
      '0':
        description: Settings for SSID 0.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '1':
        description: Settings for SSID 1.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '10':
        description: Settings for SSID 10.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '11':
        description: Settings for SSID 11.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '12':
        description: Settings for SSID 12.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '13':
        description: Settings for SSID 13.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '14':
        description: Settings for SSID 14.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '2':
        description: Settings for SSID 2.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '3':
        description: Settings for SSID 3.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '4':
        description: Settings for SSID 4.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '5':
        description: Settings for SSID 5.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '6':
        description: Settings for SSID 6.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '7':
        description: Settings for SSID 7.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '8':
        description: Settings for SSID 8.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
      '9':
        description: Settings for SSID 9.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
          bands:
            description: Settings related to all bands.
            suboptions:
              enabled:
                description: List of enabled bands. Can include "2.4", "5", "6", "disabled".
                elements: str
                type: list
            type: dict
          minBitrate:
            description: Sets min bitrate (Mbps) of this SSID. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or
              '54'.
            type: float
        type: dict
    type: dict
  rfProfileId:
    description: RfProfileId path parameter. Rf profile ID.
    type: str
  sixGhzSettings:
    description: Settings related to 6Ghz band. Only applicable to networks with 6Ghz capable APs.
    suboptions:
      channelWidth:
        description: Sets channel width (MHz) for 6Ghz band. Can be one of '0', '20', '40', '80' or '160'. Defaults to 0.
        type: str
      maxPower:
        description: Sets max power (dBm) of 6Ghz band. Can be integer between 2 and 30. Defaults to 30.
        type: int
      minBitrate:
        description: Sets min bitrate (Mbps) of 6Ghz band. Can be one of '6', '9', '12', '18', '24', '36', '48' or '54'. Defaults to 12.
        type: int
      minPower:
        description: Sets min power (dBm) of 6Ghz band. Can be integer between 2 and 30. Defaults to 8.
        type: int
      rxsop:
        description: The RX-SOP level controls the sensitivity of the radio. It is strongly recommended to use RX-SOP only after consulting a
          wireless expert. RX-SOP can be configured in the range of -65 to -95 (dBm). A value of null will reset this to the default.
        type: int
      validAutoChannels:
        description: Sets valid auto channels for 6Ghz band. Can be one of '1', '5', '9', '13', '17', '21', '25', '29', '33', '37', '41', '45',
          '49', '53', '57', '61', '65', '69', '73', '77', '81', '85', '89', '93', '97', '101', '105', '109', '113', '117', '121', '125', '129',
          '133', '137', '141', '145', '149', '153', '157', '161', '165', '169', '173', '177', '181', '185', '189', '193', '197', '201', '205',
          '209', '213', '217', '221', '225', '229' or '233'.Defaults to 1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73,
          77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185,
          189, 193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233.
        elements: int
        type: list
    type: dict
  transmission:
    description: Settings related to radio transmission.
    suboptions:
      enabled:
        description: Toggle for radio transmission. When false, radios will not transmit at all.
        type: bool
    type: dict
  twoFourGhzSettings:
    description: Settings related to 2.4Ghz band.
    suboptions:
      axEnabled:
        description: Determines whether ax radio on 2.4Ghz band is on or off. Can be either true or false. If false, we highly recommend disabling
          band steering. Defaults to true.
        type: bool
      maxPower:
        description: Sets max power (dBm) of 2.4Ghz band. Can be integer between 2 and 30. Defaults to 30.
        type: int
      minBitrate:
        description: Sets min bitrate (Mbps) of 2.4Ghz band. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or '54'.
          Defaults to 11.
        type: float
      minPower:
        description: Sets min power (dBm) of 2.4Ghz band. Can be integer between 2 and 30. Defaults to 5.
        type: int
      rxsop:
        description: The RX-SOP level controls the sensitivity of the radio. It is strongly recommended to use RX-SOP only after consulting a
          wireless expert. RX-SOP can be configured in the range of -65 to -95 (dBm). A value of null will reset this to the default.
        type: int
      validAutoChannels:
        description: Sets valid auto channels for 2.4Ghz band. Can be one of '1', '6' or '11'. Defaults to 1, 6, 11.
        elements: int
        type: list
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless createNetworkWirelessRfProfile
    description: Complete reference of the createNetworkWirelessRfProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-wireless-rf-profile
  - name: Cisco Meraki documentation for wireless deleteNetworkWirelessRfProfile
    description: Complete reference of the deleteNetworkWirelessRfProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-wireless-rf-profile
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessRfProfile
    description: Complete reference of the updateNetworkWirelessRfProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-rf-profile
notes:
  - SDK Method used are
    wireless.Wireless.create_network_wireless_rf_profile,
    wireless.Wireless.delete_network_wireless_rf_profile,
    wireless.Wireless.update_network_wireless_rf_profile,
  - Paths used are
    post /networks/{networkId}/wireless/rfProfiles,
    delete /networks/{networkId}/wireless/rfProfiles/{rfProfileId},
    put /networks/{networkId}/wireless/rfProfiles/{rfProfileId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_wireless_rf_profiles:
    meraki_api_key: "{{ meraki_api_key }}"
    meraki_base_url: "{{ meraki_base_url }}"
    meraki_single_request_timeout: "{{ meraki_single_request_timeout }}"
    meraki_certificate_path: "{{ meraki_certificate_path }}"
    meraki_requests_proxy: "{{ meraki_requests_proxy }}"
    meraki_wait_on_rate_limit: "{{ meraki_wait_on_rate_limit }}"
    meraki_nginx_429_retry_wait_time: "{{ meraki_nginx_429_retry_wait_time }}"
    meraki_action_batch_retry_wait_time: "{{ meraki_action_batch_retry_wait_time }}"
    meraki_retry_4xx_error: "{{ meraki_retry_4xx_error }}"
    meraki_retry_4xx_error_wait_time: "{{ meraki_retry_4xx_error_wait_time }}"
    meraki_maximum_retries: "{{ meraki_maximum_retries }}"
    meraki_output_log: "{{ meraki_output_log }}"
    meraki_log_file_prefix: "{{ meraki_log_file_prefix }}"
    meraki_log_path: "{{ meraki_log_path }}"
    meraki_print_console: "{{ meraki_print_console }}"
    meraki_suppress_logging: "{{ meraki_suppress_logging }}"
    meraki_simulate: "{{ meraki_simulate }}"
    meraki_be_geo_id: "{{ meraki_be_geo_id }}"
    meraki_caller: "{{ meraki_caller }}"
    meraki_use_iterator_for_get_pages: "{{ meraki_use_iterator_for_get_pages }}"
    meraki_inherit_logging_config: "{{ meraki_inherit_logging_config }}"
    state: present
    apBandSettings:
      bandOperationMode: dual
      bandSteeringEnabled: true
      bands:
        enabled:
          - '2.4'
          - '5'
    bandSelectionType: ap
    clientBalancingEnabled: true
    fiveGhzSettings:
      channelWidth: auto
      maxPower: 30
      minBitrate: 12
      minPower: 8
      rxsop: -95
      validAutoChannels:
        - 36
        - 40
        - 44
        - 48
        - 52
        - 56
        - 60
        - 64
        - 100
        - 104
        - 108
        - 112
        - 116
        - 120
        - 124
        - 128
        - 132
        - 136
        - 140
        - 144
        - 149
        - 153
        - 157
        - 161
        - 165
    flexRadios:
      byModel:
        - bands:
            - '5'
          model: MR34
    minBitrateType: band
    name: Main Office
    networkId: string
    perSsidSettings:
      '0':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '1':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '10':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '11':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '12':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '13':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '14':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '2':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '3':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '4':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '5':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '6':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '7':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '8':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '9':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
    sixGhzSettings:
      channelWidth: auto
      maxPower: 30
      minBitrate: 12
      minPower: 8
      rxsop: -95
      validAutoChannels:
        - 1
        - 5
        - 9
        - 13
        - 17
        - 21
        - 25
        - 29
        - 33
        - 37
        - 41
        - 45
        - 49
        - 53
        - 57
        - 61
        - 65
        - 69
        - 73
        - 77
        - 81
        - 85
        - 89
        - 93
        - 97
        - 101
        - 105
        - 109
        - 113
        - 117
        - 121
        - 125
        - 129
        - 133
        - 137
        - 141
        - 145
        - 149
        - 153
        - 157
        - 161
        - 165
        - 169
        - 173
        - 177
        - 181
        - 185
        - 189
        - 193
        - 197
        - 201
        - 205
        - 209
        - 213
        - 217
        - 221
        - 225
        - 229
        - 233
    transmission:
      enabled: true
    twoFourGhzSettings:
      axEnabled: true
      maxPower: 30
      minBitrate: 11.0
      minPower: 5
      rxsop: -95
      validAutoChannels:
        - 1
        - 6
        - 11
- name: Delete by id
  cisco.meraki.networks_wireless_rf_profiles:
    meraki_api_key: "{{ meraki_api_key }}"
    meraki_base_url: "{{ meraki_base_url }}"
    meraki_single_request_timeout: "{{ meraki_single_request_timeout }}"
    meraki_certificate_path: "{{ meraki_certificate_path }}"
    meraki_requests_proxy: "{{ meraki_requests_proxy }}"
    meraki_wait_on_rate_limit: "{{ meraki_wait_on_rate_limit }}"
    meraki_nginx_429_retry_wait_time: "{{ meraki_nginx_429_retry_wait_time }}"
    meraki_action_batch_retry_wait_time: "{{ meraki_action_batch_retry_wait_time }}"
    meraki_retry_4xx_error: "{{ meraki_retry_4xx_error }}"
    meraki_retry_4xx_error_wait_time: "{{ meraki_retry_4xx_error_wait_time }}"
    meraki_maximum_retries: "{{ meraki_maximum_retries }}"
    meraki_output_log: "{{ meraki_output_log }}"
    meraki_log_file_prefix: "{{ meraki_log_file_prefix }}"
    meraki_log_path: "{{ meraki_log_path }}"
    meraki_print_console: "{{ meraki_print_console }}"
    meraki_suppress_logging: "{{ meraki_suppress_logging }}"
    meraki_simulate: "{{ meraki_simulate }}"
    meraki_be_geo_id: "{{ meraki_be_geo_id }}"
    meraki_caller: "{{ meraki_caller }}"
    meraki_use_iterator_for_get_pages: "{{ meraki_use_iterator_for_get_pages }}"
    meraki_inherit_logging_config: "{{ meraki_inherit_logging_config }}"
    state: absent
    networkId: string
    rfProfileId: string
- name: Update by id
  cisco.meraki.networks_wireless_rf_profiles:
    meraki_api_key: "{{ meraki_api_key }}"
    meraki_base_url: "{{ meraki_base_url }}"
    meraki_single_request_timeout: "{{ meraki_single_request_timeout }}"
    meraki_certificate_path: "{{ meraki_certificate_path }}"
    meraki_requests_proxy: "{{ meraki_requests_proxy }}"
    meraki_wait_on_rate_limit: "{{ meraki_wait_on_rate_limit }}"
    meraki_nginx_429_retry_wait_time: "{{ meraki_nginx_429_retry_wait_time }}"
    meraki_action_batch_retry_wait_time: "{{ meraki_action_batch_retry_wait_time }}"
    meraki_retry_4xx_error: "{{ meraki_retry_4xx_error }}"
    meraki_retry_4xx_error_wait_time: "{{ meraki_retry_4xx_error_wait_time }}"
    meraki_maximum_retries: "{{ meraki_maximum_retries }}"
    meraki_output_log: "{{ meraki_output_log }}"
    meraki_log_file_prefix: "{{ meraki_log_file_prefix }}"
    meraki_log_path: "{{ meraki_log_path }}"
    meraki_print_console: "{{ meraki_print_console }}"
    meraki_suppress_logging: "{{ meraki_suppress_logging }}"
    meraki_simulate: "{{ meraki_simulate }}"
    meraki_be_geo_id: "{{ meraki_be_geo_id }}"
    meraki_caller: "{{ meraki_caller }}"
    meraki_use_iterator_for_get_pages: "{{ meraki_use_iterator_for_get_pages }}"
    meraki_inherit_logging_config: "{{ meraki_inherit_logging_config }}"
    state: present
    apBandSettings:
      bandOperationMode: dual
      bandSteeringEnabled: true
      bands:
        enabled:
          - '2.4'
          - '5'
    bandSelectionType: ap
    clientBalancingEnabled: true
    fiveGhzSettings:
      channelWidth: auto
      maxPower: 30
      minBitrate: 12
      minPower: 8
      rxsop: -95
      validAutoChannels:
        - 36
        - 40
        - 44
        - 48
        - 52
        - 56
        - 60
        - 64
        - 100
        - 104
        - 108
        - 112
        - 116
        - 120
        - 124
        - 128
        - 132
        - 136
        - 140
        - 144
        - 149
        - 153
        - 157
        - 161
        - 165
    flexRadios:
      byModel:
        - bands:
            - '5'
          model: MR34
    isIndoorDefault: true
    isOutdoorDefault: true
    minBitrateType: band
    name: '1234'
    networkId: string
    perSsidSettings:
      '0':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '1':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '10':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '11':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '12':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '13':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '14':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '2':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '3':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '4':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '5':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '6':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '7':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '8':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
      '9':
        bandOperationMode: dual
        bandSteeringEnabled: true
        bands:
          enabled:
            - '2.4'
            - '5'
        minBitrate: 11.0
    rfProfileId: string
    sixGhzSettings:
      channelWidth: auto
      maxPower: 30
      minBitrate: 12
      minPower: 8
      rxsop: -95
      validAutoChannels:
        - 1
        - 5
        - 9
        - 13
        - 17
        - 21
        - 25
        - 29
        - 33
        - 37
        - 41
        - 45
        - 49
        - 53
        - 57
        - 61
        - 65
        - 69
        - 73
        - 77
        - 81
        - 85
        - 89
        - 93
        - 97
        - 101
        - 105
        - 109
        - 113
        - 117
        - 121
        - 125
        - 129
        - 133
        - 137
        - 141
        - 145
        - 149
        - 153
        - 157
        - 161
        - 165
        - 169
        - 173
        - 177
        - 181
        - 185
        - 189
        - 193
        - 197
        - 201
        - 205
        - 209
        - 213
        - 217
        - 221
        - 225
        - 229
        - 233
    transmission:
      enabled: true
    twoFourGhzSettings:
      axEnabled: true
      maxPower: 30
      minBitrate: 11.0
      minPower: 5
      rxsop: -95
      validAutoChannels:
        - 1
        - 6
        - 11
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "apBandSettings": {
        "bandOperationMode": "string",
        "bandSteeringEnabled": true,
        "bands": {
          "enabled": [
            "string"
          ]
        }
      },
      "bandSelectionType": "string",
      "clientBalancingEnabled": true,
      "fiveGhzSettings": {
        "channelWidth": "string",
        "maxPower": 0,
        "minBitrate": 0,
        "minPower": 0,
        "rxsop": 0,
        "validAutoChannels": [
          0
        ]
      },
      "id": "string",
      "isIndoorDefault": true,
      "isOutdoorDefault": true,
      "minBitrateType": "string",
      "name": "string",
      "networkId": "string",
      "perSsidSettings": {
        "0": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "1": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "10": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "11": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "12": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "13": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "14": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "2": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "3": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "4": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "5": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "6": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "7": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "8": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        },
        "9": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true,
          "bands": {
            "enabled": [
              "string"
            ]
          },
          "minBitrate": 0,
          "name": "string"
        }
      },
      "sixGhzSettings": {
        "channelWidth": "string",
        "maxPower": 0,
        "minBitrate": 0,
        "minPower": 0,
        "rxsop": 0,
        "validAutoChannels": [
          0
        ]
      },
      "transmission": {
        "enabled": true
      },
      "twoFourGhzSettings": {
        "axEnabled": true,
        "maxPower": 0,
        "minBitrate": 0,
        "minPower": 0,
        "rxsop": 0,
        "validAutoChannels": [
          0
        ]
      }
    }
"""
