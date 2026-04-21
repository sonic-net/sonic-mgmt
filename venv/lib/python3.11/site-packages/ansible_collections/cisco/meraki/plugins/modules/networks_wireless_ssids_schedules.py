#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_ssids_schedules
short_description: Resource module for networks _wireless _ssids _schedules
description:
  - Manage operation update of the resource networks _wireless _ssids _schedules.
  - Update the outage schedule for the SSID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  enabled:
    description: If true, the SSID outage schedule is enabled.
    type: bool
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  number:
    description: Number path parameter.
    type: str
  ranges:
    description: List of outage ranges. Has a start date and time, and end date and time. If this parameter is passed in along with rangesInSeconds
      parameter, this will take precedence.
    elements: dict
    suboptions:
      endDay:
        description: Day of when the outage ends. Can be either full day name, or three letter abbreviation.
        type: str
      endTime:
        description: 24 hour time when the outage ends.
        type: str
      startDay:
        description: Day of when the outage starts. Can be either full day name, or three letter abbreviation.
        type: str
      startTime:
        description: 24 hour time when the outage starts.
        type: str
    type: list
  rangesInSeconds:
    description: List of outage ranges in seconds since Sunday at Midnight. Has a start and end. If this parameter is passed in along with the
      ranges parameter, ranges will take precedence.
    elements: dict
    suboptions:
      end:
        description: Seconds since Sunday at midnight when that outage range ends.
        type: int
      start:
        description: Seconds since Sunday at midnight when the outage range starts.
        type: int
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessSsidSchedules
    description: Complete reference of the updateNetworkWirelessSsidSchedules API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-ssid-schedules
notes:
  - SDK Method used are
    wireless.Wireless.update_network_wireless_ssid_schedules,
  - Paths used are
    put /networks/{networkId}/wireless/ssids/{number}/schedules,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_wireless_ssids_schedules:
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
    enabled: true
    networkId: string
    number: string
    ranges:
      - endDay: Tuesday
        endTime: 05:00
        startDay: Tuesday
        startTime: 01:00
    rangesInSeconds:
      - end: 0
        start: 604800
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "enabled": true,
      "ranges": [
        {
          "endDay": "string",
          "endTime": "string",
          "startDay": "string",
          "startTime": "string"
        }
      ],
      "rangesInSeconds": [
        {
          "end": 0,
          "start": 0
        }
      ]
    }
"""
