#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_insight_applications_health_by_time_info
short_description: Information module for networks _insight _applications _health _by _time
description:
  - Get all networks _insight _applications _health _by _time.
  - Get application health by time.
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
  applicationId:
    description:
      - ApplicationId path parameter. Application ID.
    type: str
  t0:
    description:
      - T0 query parameter. The beginning of the timespan for the data. The maximum lookback period is 7 days from today.
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
  resolution:
    description:
      - >
        Resolution query parameter. The time resolution in seconds for returned data. The valid resolutions are 60, 300, 3600, 86400. The default
        is 300.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for insight getNetworkInsightApplicationHealthByTime
    description: Complete reference of the getNetworkInsightApplicationHealthByTime API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-insight-application-health-by-time
notes:
  - SDK Method used are
    insight.Insight.get_network_insight_application_health_by_time,
  - Paths used are
    get /networks/{networkId}/insight/applications/{applicationId}/healthByTime,
"""

EXAMPLES = r"""
- name: Get all networks _insight _applications _health _by _time
  cisco.meraki.networks_insight_applications_health_by_time_info:
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
    t0: string
    t1: string
    timespan: 0
    resolution: 0
    networkId: string
    applicationId: string
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
        "endTs": "string",
        "lanGoodput": 0,
        "lanLatencyMs": 0,
        "lanLossPercent": 0,
        "numClients": 0,
        "recv": 0,
        "responseDuration": 0,
        "sent": 0,
        "startTs": "string",
        "wanGoodput": 0,
        "wanLatencyMs": 0,
        "wanLossPercent": 0
      }
    ]
"""
