#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_sensor_relationships
short_description: Resource module for devices _sensor _relationships
description:
  - Manage operation update of the resource devices _sensor _relationships.
  - Assign one or more sensor roles to a given sensor or camera device.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  livestream:
    description: A role defined between an MT sensor and an MV camera that adds the camera's livestream to the sensor's details page. Snapshots
      from the camera will also appear in alert notifications that the sensor triggers.
    suboptions:
      relatedDevices:
        description: An array of the related devices for the role.
        elements: dict
        suboptions:
          serial:
            description: The serial of the related device.
            type: str
        type: list
    type: dict
  serial:
    description: Serial path parameter.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for sensor updateDeviceSensorRelationships
    description: Complete reference of the updateDeviceSensorRelationships API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-sensor-relationships
notes:
  - SDK Method used are
    sensor.Sensor.update_device_sensor_relationships,
  - Paths used are
    put /devices/{serial}/sensor/relationships,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.devices_sensor_relationships:
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
    livestream:
      relatedDevices:
        - serial: string
    serial: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "relatedDevices": [
        {
          "productType": "string",
          "serial": "string"
        }
      ]
    }
"""
