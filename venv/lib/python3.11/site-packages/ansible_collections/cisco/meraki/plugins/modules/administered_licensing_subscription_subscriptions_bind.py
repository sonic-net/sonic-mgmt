#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: administered_licensing_subscription_subscriptions_bind
short_description: Resource module for administered _licensing _subscription _subscriptions _bind
description:
  - Manage operation create of the resource administered _licensing _subscription _subscriptions _bind.
  - Bind networks to a subscription.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  networkIds:
    description: List of network ids to bind to the subscription.
    elements: str
    type: list
  subscriptionId:
    description: SubscriptionId path parameter. Subscription ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for licensing bindAdministeredLicensingSubscriptionSubscription
    description: Complete reference of the bindAdministeredLicensingSubscriptionSubscription API.
    link: https://developer.cisco.com/meraki/api-v1/#!bind-administered-licensing-subscription-subscription
notes:
  - SDK Method used are
    licensing.Licensing.bind_administered_licensing_subscription_subscription,
  - Paths used are
    post /administered/licensing/subscription/subscriptions/{subscriptionId}/bind,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.administered_licensing_subscription_subscriptions_bind:
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
    networkIds:
      - L_1234
      - N_5678
    subscriptionId: string
    validate: true
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "errors": [
        "string"
      ],
      "insufficientEntitlements": [
        {
          "quantity": 0,
          "sku": "string"
        }
      ],
      "networks": [
        {
          "id": "string",
          "name": "string"
        }
      ],
      "subscriptionId": "string"
    }
"""
