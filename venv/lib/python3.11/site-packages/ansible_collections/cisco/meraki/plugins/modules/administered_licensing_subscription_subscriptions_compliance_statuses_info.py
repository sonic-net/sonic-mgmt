#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: administered_licensing_subscription_subscriptions_compliance_statuses_info
short_description: Information module for administered _licensing _subscription _subscriptions _compliance _statuses
description:
  - Get all administered _licensing _subscription _subscriptions _compliance _statuses.
  - Get compliance status for requested subscriptions.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  organizationIds:
    description:
      - OrganizationIds query parameter. Organizations to get subscription compliance information for.
    elements: str
    type: list
  subscriptionIds:
    description:
      - SubscriptionIds query parameter. Subscription ids.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for licensing getAdministeredLicensingSubscriptionSubscriptionsComplianceStatuses
    description: Complete reference of the getAdministeredLicensingSubscriptionSubscriptionsComplianceStatuses API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-administered-licensing-subscription-subscriptions-compliance-statuses
notes:
  - SDK Method used are
    licensing.Licensing.get_administered_licensing_subscription_subscriptions_compliance_statuses,
  - Paths used are
    get /administered/licensing/subscription/subscriptions/compliance/statuses,
"""

EXAMPLES = r"""
- name: Get all administered _licensing _subscription _subscriptions _compliance _statuses
  cisco.meraki.administered_licensing_subscription_subscriptions_compliance_statuses_info:
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
    organizationIds: []
    subscriptionIds: []
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
        "subscription": {
          "id": "string",
          "name": "string",
          "status": "string"
        },
        "violations": {
          "byProductClass": [
            {
              "gracePeriodEndsAt": "string",
              "missing": {
                "entitlements": [
                  {
                    "quantity": 0,
                    "sku": "string"
                  }
                ]
              },
              "productClass": "string"
            }
          ]
        }
      }
    ]
"""
