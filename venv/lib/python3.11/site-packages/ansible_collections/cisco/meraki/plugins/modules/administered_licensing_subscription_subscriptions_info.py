#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: administered_licensing_subscription_subscriptions_info
short_description: Information module for administered _licensing _subscription _subscriptions
description:
  - Get all administered _licensing _subscription _subscriptions.
  - List available subscriptions.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
  - cisco.meraki.module_info_pagination
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
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
  subscriptionIds:
    description:
      - SubscriptionIds query parameter. List of subscription ids to fetch.
    elements: str
    type: list
  organizationIds:
    description:
      - OrganizationIds query parameter. Organizations to get associated subscriptions for.
    elements: str
    type: list
  statuses:
    description:
      - Statuses query parameter. List of statuses that returned subscriptions can have.
    elements: str
    type: list
  productTypes:
    description:
      - ProductTypes query parameter. List of product types that returned subscriptions need to have entitlements for.
    elements: str
    type: list
  name:
    description:
      - Name query parameter. Search for subscription name.
    type: str
  startDate:
    description:
      - >
        StartDate query parameter. Filter subscriptions by start date, ISO 8601 format. To filter with a range of dates, use 'startDate<option>=?'
        in the request. Accepted options include lt, gt, lte, gte.
    type: str
  endDate:
    description:
      - >
        EndDate query parameter. Filter subscriptions by end date, ISO 8601 format. To filter with a range of dates, use 'endDate<option>=?' in
        the request. Accepted options include lt, gt, lte, gte.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for licensing getAdministeredLicensingSubscriptionSubscriptions
    description: Complete reference of the getAdministeredLicensingSubscriptionSubscriptions API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-administered-licensing-subscription-subscriptions
notes:
  - SDK Method used are
    licensing.Licensing.get_administered_licensing_subscription_subscriptions,
  - Paths used are
    get /administered/licensing/subscription/subscriptions,
"""

EXAMPLES = r"""
- name: Get all administered _licensing _subscription _subscriptions
  cisco.meraki.administered_licensing_subscription_subscriptions_info:
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
    subscriptionIds: []
    organizationIds: []
    statuses: []
    productTypes: []
    name: string
    startDate: str
    endDate: str
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
        "counts": {
          "networks": 0,
          "organizations": 0,
          "seats": {
            "assigned": 0,
            "available": 0,
            "limit": 0
          }
        },
        "description": "string",
        "endDate": "string",
        "enterpriseAgreement": {
          "suites": [
            "string"
          ]
        },
        "entitlements": [
          {
            "seats": {
              "assigned": 0,
              "available": 0,
              "limit": 0
            },
            "sku": "string",
            "webOrderLineId": "string"
          }
        ],
        "lastUpdatedAt": "string",
        "name": "string",
        "productTypes": [
          "string"
        ],
        "renewalRequested": true,
        "smartAccount": {
          "account": {
            "domain": "string",
            "id": "string",
            "name": "string"
          },
          "status": "string"
        },
        "startDate": "string",
        "status": "string",
        "subscriptionId": "string",
        "type": "string",
        "webOrderId": "string"
      }
    ]
"""
