#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_dhcp_server_policy
short_description: Resource module for networks _switch _dhcp _server _policy
description:
  - Manage operation update of the resource networks _switch _dhcp _server _policy. - > Update the DHCP server settings. Blocked/allowed servers
    are only applied when default policy is allow/block, respectively.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  alerts:
    description: Alert settings for DHCP servers.
    suboptions:
      email:
        description: Email alert settings for DHCP servers.
        suboptions:
          enabled:
            description: When enabled, send an email if a new DHCP server is seen. Default value is false.
            type: bool
        type: dict
    type: dict
  allowedServers:
    description: List the MAC addresses of DHCP servers to permit on the network when defaultPolicy is set to block. An empty array will clear
      the entries.
    elements: str
    type: list
  arpInspection:
    description: Dynamic ARP Inspection settings.
    suboptions:
      enabled:
        description: Enable or disable Dynamic ARP Inspection on the network. Default value is false.
        type: bool
    type: dict
  blockedServers:
    description: List the MAC addresses of DHCP servers to block on the network when defaultPolicy is set to allow. An empty array will clear
      the entries.
    elements: str
    type: list
  defaultPolicy:
    description: '''allow'' or ''block'' new DHCP servers. Default value is ''allow''.'
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch updateNetworkSwitchDhcpServerPolicy
    description: Complete reference of the updateNetworkSwitchDhcpServerPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-dhcp-server-policy
notes:
  - SDK Method used are
    switch.Switch.update_network_switch_dhcp_server_policy,
  - Paths used are
    put /networks/{networkId}/switch/dhcpServerPolicy,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_switch_dhcp_server_policy:
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
    alerts:
      email:
        enabled: true
    allowedServers:
      - 00:50:56:00:00:01
      - 00:50:56:00:00:02
    arpInspection:
      enabled: true
    blockedServers:
      - 00:50:56:00:00:03
      - 00:50:56:00:00:04
    defaultPolicy: block
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "alerts": {
        "email": {
          "enabled": true
        }
      },
      "allowedServers": [
        "string"
      ],
      "arpInspection": {
        "enabled": true,
        "unsupportedModels": [
          "string"
        ]
      },
      "blockedServers": [
        "string"
      ],
      "defaultPolicy": "string"
    }
"""
