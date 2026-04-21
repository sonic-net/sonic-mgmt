#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_floor_plans
short_description: Resource module for networks _floor _plans
description:
  - Manage operations create, update and delete of the resource networks _floor _plans.
  - Upload a floor plan.
  - Destroy a floor plan.
  - Update a floor plan's geolocation and other meta data.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  bottomLeftCorner:
    description: The longitude and latitude of the bottom left corner of your floor plan.
    suboptions:
      lat:
        description: Latitude.
        type: float
      lng:
        description: Longitude.
        type: float
    type: dict
  bottomRightCorner:
    description: The longitude and latitude of the bottom right corner of your floor plan.
    suboptions:
      lat:
        description: Latitude.
        type: float
      lng:
        description: Longitude.
        type: float
    type: dict
  center:
    description: The longitude and latitude of the center of your floor plan. The 'center' or two adjacent corners (e.g. 'topLeftCorner' and 'bottomLeftCorner')
      must be specified. If 'center' is specified, the floor plan is placed over that point with no rotation. If two adjacent corners are specified,
      the floor plan is rotated to line up with the two specified points. The aspect ratio of the floor plan's image is preserved regardless of
      which corners/center are specified. (This means if that more than two corners are specified, only two corners may be used to preserve the
      floor plan's aspect ratio.). No two points can have the same latitude, longitude pair.
    suboptions:
      lat:
        description: Latitude.
        type: float
      lng:
        description: Longitude.
        type: float
    type: dict
  floorNumber:
    description: The floor number of the floors within the building.
    type: float
  floorPlanId:
    description: FloorPlanId path parameter. Floor plan ID.
    type: str
  imageContents:
    description: The file contents (a base 64 encoded string) of your image. Supported formats are PNG, GIF, and JPG. Note that all images are
      saved as PNG files, regardless of the format they are uploaded in.
    type: str
  name:
    description: The name of your floor plan.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  topLeftCorner:
    description: The longitude and latitude of the top left corner of your floor plan.
    suboptions:
      lat:
        description: Latitude.
        type: float
      lng:
        description: Longitude.
        type: float
    type: dict
  topRightCorner:
    description: The longitude and latitude of the top right corner of your floor plan.
    suboptions:
      lat:
        description: Latitude.
        type: float
      lng:
        description: Longitude.
        type: float
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks createNetworkFloorPlan
    description: Complete reference of the createNetworkFloorPlan API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-floor-plan
  - name: Cisco Meraki documentation for networks deleteNetworkFloorPlan
    description: Complete reference of the deleteNetworkFloorPlan API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-floor-plan
  - name: Cisco Meraki documentation for networks updateNetworkFloorPlan
    description: Complete reference of the updateNetworkFloorPlan API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-floor-plan
notes:
  - SDK Method used are
    networks.Networks.create_network_floor_plan,
    networks.Networks.delete_network_floor_plan,
    networks.Networks.update_network_floor_plan,
  - Paths used are
    post /networks/{networkId}/floorPlans,
    delete /networks/{networkId}/floorPlans/{floorPlanId},
    put /networks/{networkId}/floorPlans/{floorPlanId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_floor_plans:
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
    bottomLeftCorner:
      lat: 37.770040510499996
      lng: -122.38714009525
    bottomRightCorner:
      lat: 37.770040510499996
      lng: -122.38714009525
    center:
      lat: 37.770040510499996
      lng: -122.38714009525
    floorNumber: 5.0
    imageContents: 2a9edd3f4ffd80130c647d13eacb59f3
    name: HQ Floor Plan
    networkId: string
    topLeftCorner:
      lat: 37.770040510499996
      lng: -122.38714009525
    topRightCorner:
      lat: 37.770040510499996
      lng: -122.38714009525
- name: Delete by id
  cisco.meraki.networks_floor_plans:
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
    floorPlanId: string
    networkId: string
- name: Update by id
  cisco.meraki.networks_floor_plans:
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
    bottomLeftCorner:
      lat: 37.770040510499996
      lng: -122.38714009525
    bottomRightCorner:
      lat: 37.770040510499996
      lng: -122.38714009525
    center:
      lat: 37.770040510499996
      lng: -122.38714009525
    floorNumber: 5.0
    floorPlanId: string
    imageContents: 2a9edd3f4ffd80130c647d13eacb59f3
    name: HQ Floor Plan
    networkId: string
    topLeftCorner:
      lat: 37.770040510499996
      lng: -122.38714009525
    topRightCorner:
      lat: 37.770040510499996
      lng: -122.38714009525
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
