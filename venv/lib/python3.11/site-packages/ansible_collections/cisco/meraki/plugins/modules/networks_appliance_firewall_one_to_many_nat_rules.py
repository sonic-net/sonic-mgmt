#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_firewall_one_to_many_nat_rules
short_description: Resource module for networks _appliance _firewall _one _to _many _nat _rules
description:
  - Manage operation update of the resource networks _appliance _firewall _one _to _many _nat _rules.
  - Set the 1 Many NAT mapping rules for an MX network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  rules:
    description: An array of 1 Many nat rules.
    elements: dict
    suboptions:
      portRules:
        description: An array of associated forwarding rules.
        elements: dict
        suboptions:
          allowedIps:
            description: Remote IP addresses or ranges that are permitted to access the internal resource via this port forwarding rule, or 'any'.
            elements: str
            type: list
          localIp:
            description: Local IP address to which traffic will be forwarded.
            type: str
          localPort:
            description: Destination port of the forwarded traffic that will be sent from the MX to the specified host on the LAN. If you simply
              wish to forward the traffic without translating the port, this should be the same as the Public port.
            type: str
          name:
            description: A description of the rule.
            type: str
          protocol:
            description: '''tcp'' or ''udp''.'
            type: str
          publicPort:
            description: Destination port of the traffic that is arriving on the WAN.
            type: str
        type: list
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
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceFirewallOneToManyNatRules
    description: Complete reference of the updateNetworkApplianceFirewallOneToManyNatRules API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-firewall-one-to-many-nat-rules
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_firewall_one_to_many_nat_rules,
  - Paths used are
    put /networks/{networkId}/appliance/firewall/oneToManyNatRules,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_appliance_firewall_one_to_many_nat_rules:
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
      - portRules:
          - allowedIps:
              - any
            localIp: 192.168.128.1
            localPort: '443'
            name: Rule 1
            protocol: tcp
            publicPort: '9443'
          - allowedIps:
              - 10.82.110.0/24
              - 10.82.111.0/24
            localIp: 192.168.128.1
            localPort: '80'
            name: Rule 2
            protocol: tcp
            publicPort: '8080'
        publicIp: 146.11.11.13
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
