#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_api_requests_info
short_description: Information module for organizations _api _requests
description:
  - Get all organizations _api _requests.
  - List the API requests made by an organization.
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
  t0:
    description:
      - T0 query parameter. The beginning of the timespan for the data. The maximum lookback period is 31 days from today.
    type: str
  t1:
    description:
      - T1 query parameter. The end of the timespan for the data. T1 can be a maximum of 31 days after t0.
    type: str
  timespan:
    description:
      - >
        Timespan query parameter. The timespan for which the information will be fetched. If specifying timespan, do not specify parameters t0
        and t1. The value must be in seconds and be less than or equal to 31 days. The default is 31 days.
    type: float
  perPage:
    description:
      - PerPage query parameter. The number of entries per page returned. Acceptable range is 3 - 1000. Default is 50.
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
  adminId:
    description:
      - AdminId query parameter. Filter the results by the ID of the admin who made the API requests.
    type: str
  path:
    description:
      - Path query parameter. Filter the results by the path of the API requests.
    type: str
  method:
    description:
      - >
        Method query parameter. Filter the results by the method of the API requests (must be 'GET', 'PUT', 'POST' or 'DELETE').
    type: str
  responseCode:
    description:
      - ResponseCode query parameter. Filter the results by the response code of the API requests.
    type: int
  sourceIp:
    description:
      - SourceIp query parameter. Filter the results by the IP address of the originating API request.
    type: str
  userAgent:
    description:
      - UserAgent query parameter. Filter the results by the user agent string of the API request.
    type: str
  version:
    description:
      - Version query parameter. Filter the results by the API version of the API request.
    type: int
  operationIds:
    description:
      - OperationIds query parameter. Filter the results by one or more operation IDs for the API request.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations getOrganizationApiRequests
    description: Complete reference of the getOrganizationApiRequests API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-api-requests
notes:
  - SDK Method used are
    organizations.Organizations.get_organization_api_requests,
  - Paths used are
    get /organizations/{organizationId}/apiRequests,
"""

EXAMPLES = r"""
- name: Get all organizations _api _requests
  cisco.meraki.organizations_api_requests_info:
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
    perPage: 0
    startingAfter: string
    endingBefore: string
    adminId: string
    path: string
    method: string
    responseCode: 0
    sourceIp: string
    userAgent: string
    version: 0
    operationIds: []
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
        "adminId": "string",
        "client": {
          "id": "string",
          "type": "string"
        },
        "host": "string",
        "method": "string",
        "operationId": "string",
        "path": "string",
        "queryString": "string",
        "responseCode": 0,
        "sourceIp": "string",
        "ts": "string",
        "userAgent": "string",
        "version": 0
      }
    ]
"""
