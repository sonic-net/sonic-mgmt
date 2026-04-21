#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_floor_plans_devices_batch_update
short_description: Resource module for networks _floor _plans _devices _batch _update
description:
  - Manage operation create of the resource networks _floor _plans _devices _batch _update.
  - Update floorplan assignments for a batch of devices.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  assignments:
    description: List of floorplan assignments to update. Up to 100 floor plan assignments can be provided in a request.
    elements: dict
    suboptions:
      floorPlan:
        description: Floorplan to be assigned or unassigned.
        suboptions:
          id:
            description: The ID of the floor plan to assign the device to, or null to unassign the device from its floor plan.
            type: str
        type: dict
      serial:
        description: Serial of the device to change the floor plan assignment for.
        type: str
    type: list
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks batchNetworkFloorPlansDevicesUpdate
    description: Complete reference of the batchNetworkFloorPlansDevicesUpdate API.
    link: https://developer.cisco.com/meraki/api-v1/#!batch-network-floor-plans-devices-update
notes:
  - SDK Method used are
    networks.Networks.batch_network_floor_plans_devices_update,
  - Paths used are
    post /networks/{networkId}/floorPlans/devices/batchUpdate,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_floor_plans_devices_batch_update:
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
    assignments:
      - floorPlan:
          id: g_2176982374
        serial: Q234-ABCD-5678
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "success": true
    }
"""
