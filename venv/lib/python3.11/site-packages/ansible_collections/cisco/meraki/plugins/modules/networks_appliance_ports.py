#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_ports
short_description: Resource module for networks _appliance _ports
description:
  - Manage operation update of the resource networks _appliance _ports.
  - Update the per-port VLAN settings for a single MX port.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  accessPolicy:
    description: The name of the policy. Only applicable to Access ports. Valid values are 'open', '8021x-radius', 'mac-radius', 'hybris-radius'
      for MX64 or Z3 or any MX supporting the per port authentication feature. Otherwise, 'open' is the only valid value and 'open' is the default
      value if the field is missing.
    type: str
  allowedVlans:
    description: Comma-delimited list of the VLAN ID's allowed on the port, or 'all' to permit all VLAN's on the port.
    type: str
  dropUntaggedTraffic:
    description: Trunk port can Drop all Untagged traffic. When true, no VLAN is required. Access ports cannot have dropUntaggedTraffic set to
      true.
    type: bool
  enabled:
    description: The status of the port.
    type: bool
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  portId:
    description: PortId path parameter. Port ID.
    type: str
  type:
    description: The type of the port 'access' or 'trunk'.
    type: str
  vlan:
    description: Native VLAN when the port is in Trunk mode. Access VLAN when the port is in Access mode.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateNetworkAppliancePort
    description: Complete reference of the updateNetworkAppliancePort API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-port
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_port,
  - Paths used are
    put /networks/{networkId}/appliance/ports/{portId},
"""

EXAMPLES = r"""
- name: Update by id
  cisco.meraki.networks_appliance_ports:
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
    accessPolicy: open
    allowedVlans: all
    dropUntaggedTraffic: false
    enabled: true
    networkId: string
    portId: string
    type: access
    vlan: 3
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "accessPolicy": "string",
      "allowedVlans": "string",
      "dropUntaggedTraffic": true,
      "enabled": true,
      "number": 0,
      "type": "string",
      "vlan": 0
    }
"""
