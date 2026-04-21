#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_ssids_eap_override
short_description: Resource module for networks _wireless _ssids _eap _override
description:
  - Manage operation update of the resource networks _wireless _ssids _eap _override.
  - Update the EAP overridden parameters for an SSID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  eapolKey:
    description: EAPOL Key settings.
    suboptions:
      retries:
        description: Maximum number of EAPOL key retries.
        type: int
      timeoutInMs:
        description: EAPOL Key timeout in milliseconds.
        type: int
    type: dict
  identity:
    description: EAP settings for identity requests.
    suboptions:
      retries:
        description: Maximum number of EAP retries.
        type: int
      timeout:
        description: EAP timeout in seconds.
        type: int
    type: dict
  maxRetries:
    description: Maximum number of general EAP retries.
    type: int
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  number:
    description: Number path parameter.
    type: str
  timeout:
    description: General EAP timeout in seconds.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessSsidEapOverride
    description: Complete reference of the updateNetworkWirelessSsidEapOverride API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-ssid-eap-override
notes:
  - SDK Method used are
    wireless.Wireless.update_network_wireless_ssid_eap_override,
  - Paths used are
    put /networks/{networkId}/wireless/ssids/{number}/eapOverride,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_wireless_ssids_eap_override:
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
    eapolKey:
      retries: 5
      timeoutInMs: 5000
    identity:
      retries: 5
      timeout: 5
    maxRetries: 5
    networkId: string
    number: string
    timeout: 5
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "eapolKey": {
        "retries": 0,
        "timeoutInMs": 0
      },
      "identity": {
        "retries": 0,
        "timeout": 0
      },
      "maxRetries": 0,
      "timeout": 0
    }
"""
