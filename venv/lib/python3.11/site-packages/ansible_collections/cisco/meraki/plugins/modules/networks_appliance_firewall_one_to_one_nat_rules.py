#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_firewall_one_to_one_nat_rules
short_description: Resource module for networks _appliance _firewall _one _to _one _nat _rules
description:
  - Manage operation update of the resource networks _appliance _firewall _one _to _one _nat _rules.
  - Set the 1 1 NAT mapping rules for an MX network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  rules:
    description: An array of 1 1 nat rules.
    elements: dict
    suboptions:
      allowedInbound:
        description: The ports this mapping will provide access on, and the remote IPs that will be allowed access to the resource.
        elements: dict
        suboptions:
          allowedIps:
            description: An array of ranges of WAN IP addresses that are allowed to make inbound connections on the specified ports or port ranges,
              or 'any'.
            elements: str
            type: list
          destinationPorts:
            description: An array of ports or port ranges that will be forwarded to the host on the LAN.
            elements: str
            type: list
          protocol:
            description: Either of the following 'tcp', 'udp', 'icmp-ping' or 'any'.
            type: str
        type: list
      lanIp:
        description: The IP address of the server or device that hosts the internal resource that you wish to make available on the WAN.
        type: str
      name:
        description: A descriptive name for the rule.
        type: str
      publicIp:
        description: The IP address that will be used to access the internal resource from the WAN.
        type: str
      uplink:
        description: The physical WAN interface on which the traffic will arrive, formatted as 'internetN' where N is an integer representing
          a valid uplink for the network's appliance.
        type: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceFirewallOneToOneNatRules
    description: Complete reference of the updateNetworkApplianceFirewallOneToOneNatRules API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-firewall-one-to-one-nat-rules
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_firewall_one_to_one_nat_rules,
  - Paths used are
    put /networks/{networkId}/appliance/firewall/oneToOneNatRules,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_appliance_firewall_one_to_one_nat_rules:
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
      - allowedInbound:
          - allowedIps:
              - 10.82.112.0/24
              - 10.82.0.0/16
            destinationPorts:
              - '80'
            protocol: tcp
          - allowedIps:
              - 10.81.110.5
              - 10.81.0.0/16
            destinationPorts:
              - '8080'
            protocol: udp
        lanIp: 192.168.128.22
        name: Service behind NAT
        publicIp: 146.12.3.33
        uplink: internet1
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
