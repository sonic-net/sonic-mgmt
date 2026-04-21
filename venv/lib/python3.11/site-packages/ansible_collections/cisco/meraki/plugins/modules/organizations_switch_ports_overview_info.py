#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_switch_ports_overview_info
short_description: Information module for organizations _switch _ports _overview
description:
  - Get all organizations _switch _ports _overview. - > Returns the counts of all active ports for the requested timespan, grouped by speed. An
    active port is a port that at any point during the timeframe is observed to be connected to a responsive device and isn't configured to be
    disabled. For a port that is observed at multiple speeds during the timeframe, it will be counted at the highest speed observed. The number
    of inactive ports, and the total number of ports are also provided. Only ports on switches online during the timeframe will be represented
    and a port is only guaranteed to be present if its switch was online for at least 6 hours of the timeframe.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  organizationId:
    description:
      - OrganizationId path parameter. Organization ID.
    type: str
  t0:
    description:
      - T0 query parameter. The beginning of the timespan for the data.
    type: str
  t1:
    description:
      - T1 query parameter. The end of the timespan for the data. T1 can be a maximum of 186 days after t0.
    type: str
  timespan:
    description:
      - >
        Timespan query parameter. The timespan for which the information will be fetched. If specifying timespan, do not specify parameters t0
        and t1. The value must be in seconds and be greater than or equal to 12 hours and be less than or equal to 186 days. The default is 1
        day.
    type: float
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch getOrganizationSwitchPortsOverview
    description: Complete reference of the getOrganizationSwitchPortsOverview API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-switch-ports-overview
notes:
  - SDK Method used are
    switch.Switch.get_organization_switch_ports_overview,
  - Paths used are
    get /organizations/{organizationId}/switch/ports/overview,
"""

EXAMPLES = r"""
- name: Get all organizations _switch _ports _overview
  cisco.meraki.organizations_switch_ports_overview_info:
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
    organizationId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "byStatus": {
        "active": {
          "byMediaAndLinkSpeed": {
            "rj45": {
              "10": 0,
              "100": 0,
              "1000": 0,
              "10000": 0,
              "2500": 0,
              "5000": 0,
              "total": 0
            },
            "sfp": {
              "100": 0,
              "1000": 0,
              "10000": 0,
              "100000": 0,
              "20000": 0,
              "25000": 0,
              "40000": 0,
              "50000": 0,
              "total": 0
            }
          },
          "total": 0
        },
        "inactive": {
          "byMedia": {
            "rj45": {
              "total": 0
            },
            "sfp": {
              "total": 0
            }
          },
          "total": 0
        }
      },
      "total": 0
    }
"""
