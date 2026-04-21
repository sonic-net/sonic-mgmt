#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_sensor_alerts_profiles_info
short_description: Information module for networks _sensor _alerts _profiles
description:
  - Get all networks _sensor _alerts _profiles.
  - Get networks _sensor _alerts _profiles by id.
  - Lists all sensor alert profiles for a network.
  - Show details of a sensor alert profile for a network.
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
  id:
    description:
      - Id path parameter.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for sensor getNetworkSensorAlertsProfile
    description: Complete reference of the getNetworkSensorAlertsProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-sensor-alerts-profile
  - name: Cisco Meraki documentation for sensor getNetworkSensorAlertsProfiles
    description: Complete reference of the getNetworkSensorAlertsProfiles API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-sensor-alerts-profiles
notes:
  - SDK Method used are
    sensor.Sensor.get_network_sensor_alerts_profile,
    sensor.Sensor.get_network_sensor_alerts_profiles,
  - Paths used are
    get /networks/{networkId}/sensor/alerts/profiles,
    get /networks/{networkId}/sensor/alerts/profiles/{id},
"""

EXAMPLES = r"""
- name: Get all networks _sensor _alerts _profiles
  cisco.meraki.networks_sensor_alerts_profiles_info:
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
  register: result
- name: Get networks _sensor _alerts _profiles by id
  cisco.meraki.networks_sensor_alerts_profiles_info:
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
    id: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "conditions": [
        {
          "direction": "string",
          "duration": 0,
          "metric": "string",
          "threshold": {
            "apparentPower": {
              "draw": 0
            },
            "co2": {
              "concentration": 0,
              "quality": "string"
            },
            "current": {
              "draw": 0
            },
            "door": {
              "open": true
            },
            "frequency": {
              "level": 0
            },
            "humidity": {
              "quality": "string",
              "relativePercentage": 0
            },
            "indoorAirQuality": {
              "quality": "string",
              "score": 0
            },
            "noise": {
              "ambient": {
                "level": 0,
                "quality": "string"
              }
            },
            "pm25": {
              "concentration": 0,
              "quality": "string"
            },
            "powerFactor": {
              "percentage": 0
            },
            "realPower": {
              "draw": 0
            },
            "temperature": {
              "celsius": 0,
              "fahrenheit": 0,
              "quality": "string"
            },
            "tvoc": {
              "concentration": 0,
              "quality": "string"
            },
            "upstreamPower": {
              "outageDetected": true
            },
            "voltage": {
              "level": 0
            },
            "water": {
              "present": true
            }
          }
        }
      ],
      "includeSensorUrl": true,
      "message": "string",
      "name": "string",
      "profileId": "string",
      "recipients": {
        "emails": [
          "string"
        ],
        "httpServerIds": [
          "string"
        ],
        "smsNumbers": [
          "string"
        ]
      },
      "schedule": {
        "id": "string",
        "name": "string"
      },
      "serials": [
        "string"
      ]
    }
"""
