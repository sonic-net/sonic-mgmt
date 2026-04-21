#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices
short_description: Resource module for devices
description:
  - Manage operation update of the resource devices.
  - Update the attributes of a device.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  address:
    description: The address of a device.
    type: str
  floorPlanId:
    description: The floor plan to associate to this device. Null disassociates the device from the floorplan.
    type: str
  lat:
    description: The latitude of a device.
    type: float
  lng:
    description: The longitude of a device.
    type: float
  moveMapMarker:
    description: Whether or not to set the latitude and longitude of a device based on the new address. Only applies when lat and lng are not
      specified.
    type: bool
  name:
    description: The name of a device.
    type: str
  notes:
    description: The notes for the device. String. Limited to 255 characters.
    type: str
  serial:
    description: Serial path parameter.
    type: str
  switchProfileId:
    description: The ID of a switch template to bind to the device (for available switch templates, see the 'Switch Templates' endpoint). Use
      null to unbind the switch device from the current profile. For a device to be bindable to a switch template, it must (1) be a switch, and
      (2) belong to a network that is bound to a configuration template.
    type: str
  tags:
    description: The list of tags of a device.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for devices updateDevice
    description: Complete reference of the updateDevice API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device
notes:
  - SDK Method used are
    devices.Devices.update_device,
  - Paths used are
    put /devices/{serial},
"""

EXAMPLES = r"""
- name: Update by id
  cisco.meraki.devices:
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
    address: 1600 Pennsylvania Ave
    floorPlanId: g_2176982374
    lat: 37.4180951010362
    lng: -122.098531723022
    moveMapMarker: true
    name: My AP
    notes: My AP's note
    serial: string
    switchProfileId: '1234'
    tags:
      - ' recently-added '
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "address": "string",
      "beaconIdParams": {
        "major": 0,
        "minor": 0,
        "uuid": "string"
      },
      "details": [
        {
          "name": "string",
          "value": "string"
        }
      ],
      "firmware": "string",
      "floorPlanId": "string",
      "lanIp": "string",
      "lat": 0,
      "lng": 0,
      "mac": "string",
      "model": "string",
      "name": "string",
      "networkId": "string",
      "notes": "string",
      "serial": "string",
      "tags": [
        "string"
      ]
    }
"""
