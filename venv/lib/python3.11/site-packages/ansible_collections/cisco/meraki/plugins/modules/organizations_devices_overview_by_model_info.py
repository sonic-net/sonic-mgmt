#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_devices_overview_by_model_info
short_description: Information module for organizations _devices _overview _by _model
description:
  - Get all organizations _devices _overview _by _model.
  - Lists the count for each device model.
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
  models:
    description:
      - >
        Models query parameter. Optional parameter to filter devices by one or more models. All returned devices will have a model that is an
        exact match.
    elements: str
    type: list
  networkIds:
    description:
      - NetworkIds query parameter. Optional parameter to filter devices by networkId.
    elements: str
    type: list
  productTypes:
    description:
      - >
        ProductTypes query parameter. Optional parameter to filter device by device product types. This filter uses multiple exact matches.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations getOrganizationDevicesOverviewByModel
    description: Complete reference of the getOrganizationDevicesOverviewByModel API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-devices-overview-by-model
notes:
  - SDK Method used are
    organizations.Organizations.get_organization_devices_overview_by_model,
  - Paths used are
    get /organizations/{organizationId}/devices/overview/byModel,
"""

EXAMPLES = r"""
- name: Get all organizations _devices _overview _by _model
  cisco.meraki.organizations_devices_overview_by_model_info:
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
    models: []
    networkIds: []
    productTypes: []
    organizationId: string
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
        "model": "string",
        "total": 0
      }
    ]
"""
