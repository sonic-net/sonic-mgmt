#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: administered_licensing_subscription_subscriptions_claim
short_description: Resource module for administered _licensing _subscription _subscriptions _claim
description:
  - Manage operation create of the resource administered _licensing _subscription _subscriptions _claim.
  - Claim a subscription into an organization.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  claimKey:
    description: The subscription's claim key.
    type: str
  description:
    description: Extra details or notes about the subscription.
    type: str
  name:
    description: Friendly name to identify the subscription.
    type: str
  organizationId:
    description: The id of the organization claiming the subscription.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for licensing claimAdministeredLicensingSubscriptionSubscriptions
    description: Complete reference of the claimAdministeredLicensingSubscriptionSubscriptions API.
    link: https://developer.cisco.com/meraki/api-v1/#!claim-administered-licensing-subscription-subscriptions
notes:
  - SDK Method used are
    licensing.Licensing.claim_administered_licensing_subscription_subscriptions,
  - Paths used are
    post /administered/licensing/subscription/subscriptions/claim,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.administered_licensing_subscription_subscriptions_claim:
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
    claimKey: S2345-6789A-BCDEF-GHJKM
    description: Subscription for all main offices
    name: Corporate subscription
    organizationId: '12345678910'
    validate: true
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
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
"""
