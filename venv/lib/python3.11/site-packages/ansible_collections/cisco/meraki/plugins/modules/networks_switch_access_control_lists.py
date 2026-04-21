#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_access_control_lists
short_description: Resource module for networks _switch _access _control _lists
description:
  - Manage operation update of the resource networks _switch _access _control _lists.
  - Update the access control lists for a MS network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  rules:
    description: An ordered array of the access control list rules (not including the default rule). An empty array will clear the rules.
    elements: dict
    suboptions:
      comment:
        description: Description of the rule (optional).
        type: str
      dstCidr:
        description: Destination IP address (in IP or CIDR notation) or 'any'.
        type: str
      dstPort:
        description: Destination port. Must be in the range of 1-65535 or 'any'. Default is 'any'.
        type: str
      ipVersion:
        description: IP address version (must be 'any', 'ipv4' or 'ipv6'). Applicable only if network supports IPv6. Default value is 'ipv4'.
        type: str
      policy:
        description: '''allow'' or ''deny'' traffic specified by this rule.'
        type: str
      protocol:
        description: The type of protocol (must be 'tcp', 'udp', or 'any').
        type: str
      srcCidr:
        description: Source IP address (in IP or CIDR notation) or 'any'.
        type: str
      srcPort:
        description: Source port. Must be in the range of 1-65535 or 'any'. Default is 'any'.
        type: str
      vlan:
        description: Incoming traffic VLAN. Must be in the range of 1-4095 or 'any'. Default is 'any'.
        type: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch updateNetworkSwitchAccessControlLists
    description: Complete reference of the updateNetworkSwitchAccessControlLists API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-access-control-lists
notes:
  - SDK Method used are
    switch.Switch.update_network_switch_access_control_lists,
  - Paths used are
    put /networks/{networkId}/switch/accessControlLists,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_switch_access_control_lists:
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
    networkId: string
    rules:
      - comment: Deny SSH
        dstCidr: 172.16.30/24
        dstPort: '22'
        ipVersion: ipv4
        policy: deny
        protocol: tcp
        srcCidr: 10.1.10.0/24
        srcPort: any
        vlan: '10'
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    [
      {
        "comment": "string",
        "dstCidr": "string",
        "dstPort": "string",
        "ipVersion": "string",
        "policy": "string",
        "protocol": "string",
        "srcCidr": "string",
        "srcPort": "string",
        "vlan": "string"
      }
    ]
"""
