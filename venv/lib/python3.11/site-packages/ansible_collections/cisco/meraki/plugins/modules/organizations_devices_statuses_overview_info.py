#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_devices_statuses_overview_info
short_description: Information module for organizations _devices _statuses _overview
description:
  - Get all organizations _devices _statuses _overview.
  - Return an overview of current device statuses.
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
  productTypes:
    description:
      - >
        ProductTypes query parameter. An optional parameter to filter device statuses by product type. Valid types are wireless, appliance, switch,
        systemsManager, camera, cellularGateway, sensor, wirelessController, and secureConnect.
    elements: str
    type: list
  networkIds:
    description:
      - NetworkIds query parameter. An optional parameter to filter device statuses by network.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations getOrganizationDevicesStatusesOverview
    description: Complete reference of the getOrganizationDevicesStatusesOverview API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-devices-statuses-overview
notes:
  - SDK Method used are
    organizations.Organizations.get_organization_devices_statuses_overview,
  - Paths used are
    get /organizations/{organizationId}/devices/statuses/overview,
"""

EXAMPLES = r"""
- name: Get all organizations _devices _statuses _overview
  cisco.meraki.organizations_devices_statuses_overview_info:
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
    productTypes: []
    networkIds: []
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
        "alerting": 0,
        "dormant": 0,
        "offline": 0,
        "online": 0
      }
    }
"""
