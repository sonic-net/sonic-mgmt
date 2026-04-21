#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_sensor_readings_history_info
short_description: Information module for organizations _sensor _readings _history
description:
  - Get all organizations _sensor _readings _history.
  - Return all reported readings from sensors in a given timespan, sorted by timestamp.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
  - cisco.meraki.module_info_pagination
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  organizationId:
    description:
      - OrganizationId path parameter. Organization ID.
    type: str
  perPage:
    description:
      - PerPage query parameter. The number of entries per page returned. Acceptable range is 3 - 1000. Default is 1000.
    type: int
  startingAfter:
    description:
      - >
        StartingAfter query parameter. A token used by the server to indicate the start of the page. Often this is a timestamp or an ID but it
        is not limited to those. This parameter should not be defined by client applications. The link for the first, last, prev, or next page
        in the HTTP Link header should define it.
    type: str
  endingBefore:
    description:
      - >
        EndingBefore query parameter. A token used by the server to indicate the end of the page. Often this is a timestamp or an ID but it is
        not limited to those. This parameter should not be defined by client applications. The link for the first, last, prev, or next page in
        the HTTP Link header should define it.
    type: str
  t0:
    description:
      - >
        T0 query parameter. The beginning of the timespan for the data. The maximum lookback period is 365 days and 6 hours from today.
    type: str
  t1:
    description:
      - T1 query parameter. The end of the timespan for the data. T1 can be a maximum of 7 days after t0.
    type: str
  timespan:
    description:
      - >
        Timespan query parameter. The timespan for which the information will be fetched. If specifying timespan, do not specify parameters t0
        and t1. The value must be in seconds and be less than or equal to 7 days. The default is 2 hours.
    type: float
  networkIds:
    description:
      - NetworkIds query parameter. Optional parameter to filter readings by network.
    elements: str
    type: list
  serials:
    description:
      - Serials query parameter. Optional parameter to filter readings by sensor.
    elements: str
    type: list
  metrics:
    description:
      - >
        Metrics query parameter. Types of sensor readings to retrieve. If no metrics are supplied, all available types of readings will be retrieved.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for sensor getOrganizationSensorReadingsHistory
    description: Complete reference of the getOrganizationSensorReadingsHistory API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-sensor-readings-history
notes:
  - SDK Method used are
    sensor.Sensor.get_organization_sensor_readings_history,
  - Paths used are
    get /organizations/{organizationId}/sensor/readings/history,
"""

EXAMPLES = r"""
- name: Get all organizations _sensor _readings _history
  cisco.meraki.organizations_sensor_readings_history_info:
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
    perPage: 0
    startingAfter: string
    endingBefore: string
    t0: string
    t1: string
    timespan: 0
    networkIds: []
    serials: []
    metrics: []
    organizationId: string
    total_pages: -1
    direction: next
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "apparentPower": {
          "draw": 0
        },
        "battery": {
          "percentage": 0
        },
        "button": {
          "pressType": "string"
        },
        "co2": {
          "concentration": 0
        },
        "current": {
          "draw": 0
        },
        "door": {
          "open": true
        },
        "downstreamPower": {
          "enabled": true
        },
        "frequency": {
          "level": 0
        },
        "humidity": {
          "relativePercentage": 0
        },
        "indoorAirQuality": {
          "score": 0
        },
        "metric": "string",
        "network": {
          "id": "string",
          "name": "string"
        },
        "noise": {
          "ambient": {
            "level": 0
          }
        },
        "pm25": {
          "concentration": 0
        },
        "powerFactor": {
          "percentage": 0
        },
        "realPower": {
          "draw": 0
        },
        "remoteLockoutSwitch": {
          "locked": true
        },
        "serial": "string",
        "temperature": {
          "celsius": 0,
          "fahrenheit": 0
        },
        "ts": "string",
        "tvoc": {
          "concentration": 0
        },
        "voltage": {
          "level": 0
        },
        "water": {
          "present": true
        }
      }
    ]
"""
