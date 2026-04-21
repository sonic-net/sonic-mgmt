#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_rf_profiles
short_description: Resource module for networks _appliance _rf _profiles
description:
  - Manage operations create, update and delete of the resource networks _appliance _rf _profiles.
  - Creates new RF profile for this network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  fiveGhzSettings:
    description: Settings related to 5Ghz band.
    suboptions:
      axEnabled:
        description: Determines whether ax radio on 5Ghz band is on or off. Can be either true or false. If false, we highly recommend disabling
          band steering. Defaults to true.
        type: bool
      minBitrate:
        description: Sets min bitrate (Mbps) of 5Ghz band. Can be one of '6', '9', '12', '18', '24', '36', '48' or '54'. Defaults to 12.
        type: int
    type: dict
  name:
    description: The name of the new profile. Must be unique. This param is required on creation.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  perSsidSettings:
    description: Per-SSID radio settings by number.
    suboptions:
      '1':
        description: Settings for SSID 1.
        suboptions:
          bandOperationMode:
            description: Choice between 'dual', '2.4ghz', '5ghz', '6ghz' or 'multi'.
            type: str
          bandSteeringEnabled:
            description: Steers client to most open band between 2.4 GHz and 5 GHz. Can be either true or false.
            type: bool
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
        type: dict
    type: dict
  twoFourGhzSettings:
    description: Settings related to 2.4Ghz band.
    suboptions:
      axEnabled:
        description: Determines whether ax radio on 2.4Ghz band is on or off. Can be either true or false. If false, we highly recommend disabling
          band steering. Defaults to true.
        type: bool
      minBitrate:
        description: Sets min bitrate (Mbps) of 2.4Ghz band. Can be one of '1', '2', '5.5', '6', '9', '11', '12', '18', '24', '36', '48' or '54'.
          Defaults to 11.
        type: float
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance createNetworkApplianceRfProfile
    description: Complete reference of the createNetworkApplianceRfProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-appliance-rf-profile
notes:
  - SDK Method used are
    appliance.Appliance.create_network_appliance_rf_profile,
  - Paths used are
    post /networks/{networkId}/appliance/rfProfiles,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_appliance_rf_profiles:
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
    fiveGhzSettings:
      axEnabled: true
      minBitrate: 48
    name: MX RF Profile
    networkId: string
    perSsidSettings:
      '1':
        bandOperationMode: dual
        bandSteeringEnabled: true
      '2':
        bandOperationMode: dual
        bandSteeringEnabled: true
      '3':
        bandOperationMode: dual
        bandSteeringEnabled: true
      '4':
        bandOperationMode: dual
        bandSteeringEnabled: true
    twoFourGhzSettings:
      axEnabled: true
      minBitrate: 12.0
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "fiveGhzSettings": {
        "axEnabled": true,
        "minBitrate": 0
      },
      "id": "string",
      "name": "string",
      "networkId": "string",
      "perSsidSettings": {
        "1": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true
        },
        "2": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true
        },
        "3": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true
        },
        "4": {
          "bandOperationMode": "string",
          "bandSteeringEnabled": true
        }
      },
      "twoFourGhzSettings": {
        "axEnabled": true,
        "minBitrate": 0
      }
    }
"""
