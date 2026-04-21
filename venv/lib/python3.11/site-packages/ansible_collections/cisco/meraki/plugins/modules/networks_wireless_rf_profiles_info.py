#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_rf_profiles_info
short_description: Information module for networks _wireless _rf _profiles
description:
  - Get all networks _wireless _rf _profiles.
  - Get networks _wireless _rf _profiles by id.
  - List RF profiles for this network.
  - Return a RF profile.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  networkId:
    description:
      - NetworkId path parameter. Network ID.
    type: str
  includeTemplateProfiles:
    description:
      - >
        IncludeTemplateProfiles query parameter. If the network is bound to a template, this parameter controls whether or not the non-basic RF
        profiles defined on the template should be included in the response alongside the non-basic profiles defined on the bound network. Defaults
        to false.
    type: bool
  rfProfileId:
    description:
      - RfProfileId path parameter. Rf profile ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless getNetworkWirelessRfProfile
    description: Complete reference of the getNetworkWirelessRfProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-wireless-rf-profile
  - name: Cisco Meraki documentation for wireless getNetworkWirelessRfProfiles
    description: Complete reference of the getNetworkWirelessRfProfiles API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-wireless-rf-profiles
notes:
  - SDK Method used are
    wireless.Wireless.get_network_wireless_rf_profile,
    wireless.Wireless.get_network_wireless_rf_profiles,
  - Paths used are
    get /networks/{networkId}/wireless/rfProfiles,
    get /networks/{networkId}/wireless/rfProfiles/{rfProfileId},
"""

EXAMPLES = r"""
- name: Get all networks _wireless _rf _profiles
  cisco.meraki.networks_wireless_rf_profiles_info:
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
    includeTemplateProfiles: true
    networkId: string
  register: result
- name: Get networks _wireless _rf _profiles by id
  cisco.meraki.networks_wireless_rf_profiles_info:
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
    networkId: string
    rfProfileId: string
  register: result
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
