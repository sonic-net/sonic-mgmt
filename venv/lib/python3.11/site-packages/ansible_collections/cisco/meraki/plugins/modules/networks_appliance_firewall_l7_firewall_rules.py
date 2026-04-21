#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_firewall_l7_firewall_rules
short_description: Resource module for networks _appliance _firewall l7 _firewall _rules
description:
  - Manage operation update of the resource networks _appliance _firewall l7 _firewall _rules.
  - Update the MX L7 firewall rules for an MX network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  rules:
    description: An ordered array of the MX L7 firewall rules.
    elements: dict
    suboptions:
      policy:
        description: '''Deny'' traffic specified by this rule.'
        type: str
      type:
        description: Type of the L7 rule. One of 'application', 'applicationCategory', 'host', 'port', 'ipRange'.
        type: str
      value:
        description: The 'value' of what you want to block. Format of 'value' varies depending on type of the rule. The application categories
          and application ids can be retrieved from the the 'MX L7 application categories' endpoint. The countries follow the two-letter ISO 3166-1
          alpha-2 format.
        type: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceFirewallL7FirewallRules
    description: Complete reference of the updateNetworkApplianceFirewallL7FirewallRules API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-firewall-l7-firewall-rules
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_firewall_l7_firewall_rules,
  - Paths used are
    put /networks/{networkId}/appliance/firewall/l7FirewallRules,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_appliance_firewall_l7_firewall_rules:
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
      - policy: deny
        type: host
        value: google.com
      - policy: deny
        type: port
        value: '23'
      - policy: deny
        type: ipRange
        value: 10.11.12.00/24
      - policy: deny
        type: ipRange
        value: 10.11.12.00/24:5555
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
