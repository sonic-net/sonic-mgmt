#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_floor_plans_info
short_description: Information module for networks _floor _plans
description:
  - Get all networks _floor _plans.
  - Get networks _floor _plans by id.
  - Find a floor plan by ID.
  - List the floor plans that belong to your network.
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
  floorPlanId:
    description:
      - FloorPlanId path parameter. Floor plan ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks getNetworkFloorPlan
    description: Complete reference of the getNetworkFloorPlan API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-floor-plan
  - name: Cisco Meraki documentation for networks getNetworkFloorPlans
    description: Complete reference of the getNetworkFloorPlans API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-floor-plans
notes:
  - SDK Method used are
    networks.Networks.get_network_floor_plan,
    networks.Networks.get_network_floor_plans,
  - Paths used are
    get /networks/{networkId}/floorPlans,
    get /networks/{networkId}/floorPlans/{floorPlanId},
"""

EXAMPLES = r"""
- name: Get all networks _floor _plans
  cisco.meraki.networks_floor_plans_info:
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
- name: Get networks _floor _plans by id
  cisco.meraki.networks_floor_plans_info:
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
    floorPlanId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "bottomLeftCorner": {
        "lat": 0,
        "lng": 0
      },
      "bottomRightCorner": {
        "lat": 0,
        "lng": 0
      },
      "center": {
        "lat": 0,
        "lng": 0
      },
      "devices": [
        {
          "address": "string",
          "details": [
            {
              "name": "string",
              "value": "string"
            }
          ],
          "firmware": "string",
          "imei": "string",
          "lanIp": "string",
          "lat": 0,
          "lng": 0,
          "mac": "string",
          "model": "string",
          "name": "string",
          "networkId": "string",
          "notes": "string",
          "productType": "string",
          "serial": "string",
          "tags": [
            "string"
          ]
        }
      ],
      "floorNumber": 0,
      "floorPlanId": "string",
      "height": 0,
      "imageExtension": "string",
      "imageMd5": "string",
      "imageUrl": "string",
      "imageUrlExpiresAt": "string",
      "name": "string",
      "topLeftCorner": {
        "lat": 0,
        "lng": 0
      },
      "topRightCorner": {
        "lat": 0,
        "lng": 0
      },
      "width": 0
    }
"""
