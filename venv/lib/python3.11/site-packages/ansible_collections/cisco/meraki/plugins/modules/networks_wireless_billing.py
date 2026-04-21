#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_billing
short_description: Resource module for networks _wireless _billing
description:
  - Manage operation update of the resource networks _wireless _billing.
  - Update the billing settings.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  currency:
    description: The currency code of this node group's billing plans.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  plans:
    description: Array of billing plans in the node group. (Can configure a maximum of 5).
    elements: dict
    suboptions:
      bandwidthLimits:
        description: The uplink bandwidth settings for the pricing plan.
        suboptions:
          limitDown:
            description: The maximum download limit (integer, in Kbps). Null indicates no limit.
            type: int
          limitUp:
            description: The maximum upload limit (integer, in Kbps). Null indicates no limit.
            type: int
        type: dict
      id:
        description: The id of the pricing plan to update.
        type: str
      price:
        description: The price of the billing plan.
        type: float
      timeLimit:
        description: The time limit of the pricing plan in minutes. Can be '1 hour', '1 day', '1 week', or '30 days'.
        type: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessBilling
    description: Complete reference of the updateNetworkWirelessBilling API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-billing
notes:
  - SDK Method used are
    wireless.Wireless.update_network_wireless_billing,
  - Paths used are
    put /networks/{networkId}/wireless/billing,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_wireless_billing:
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
    state: present
    currency: USD
    networkId: string
    plans:
      - bandwidthLimits:
          limitDown: 1000000
          limitUp: 1000000
        id: '1'
        price: 5.0
        timeLimit: 1 hour
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "currency": "string",
      "plans": [
        {
          "bandwidthLimits": {
            "limitDown": 0,
            "limitUp": 0
          },
          "id": "string",
          "price": 0,
          "timeLimit": "string"
        }
      ]
    }
"""
