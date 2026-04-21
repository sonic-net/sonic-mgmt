#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_settings
short_description: Resource module for networks _appliance _settings
description:
  - Manage operation update of the resource networks _appliance _settings.
  - Update the appliance settings for a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  clientTrackingMethod:
    description: Client tracking method of a network.
    type: str
  deploymentMode:
    description: Deployment mode of a network.
    type: str
  dynamicDns:
    description: Dynamic DNS settings for a network.
    suboptions:
      enabled:
        description: Dynamic DNS enabled.
        type: bool
      prefix:
        description: Dynamic DNS url prefix. DDNS must be enabled to update.
        type: str
    type: dict
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceSettings
    description: Complete reference of the updateNetworkApplianceSettings API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-settings
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_settings,
  - Paths used are
    put /networks/{networkId}/appliance/settings,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_appliance_settings:
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
    clientTrackingMethod: MAC address
    deploymentMode: routed
    dynamicDns:
      enabled: true
      prefix: test
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "clientTrackingMethod": "string",
      "deploymentMode": "string",
      "dynamicDns": {
        "enabled": true,
        "prefix": "string",
        "url": "string"
      }
    }
"""
