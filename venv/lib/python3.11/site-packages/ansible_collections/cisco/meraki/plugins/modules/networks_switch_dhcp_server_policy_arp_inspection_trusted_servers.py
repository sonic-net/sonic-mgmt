#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_dhcp_server_policy_arp_inspection_trusted_servers
short_description: Resource module for networks _switch _dhcp _server _policy _arp _inspection _trusted _servers
description:
  - Manage operations create, update and delete of the resource networks _switch _dhcp _server _policy _arp _inspection _trusted _servers.
  - Add a server to be trusted by Dynamic ARP Inspection on this network.
  - Remove a server from being trusted by Dynamic ARP Inspection on this network.
  - Update a server that is trusted by Dynamic ARP Inspection on this network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  ipv4:
    description: The IPv4 attributes of the trusted server being added.
    suboptions:
      address:
        description: The IPv4 address of the trusted server being added.
        type: str
    type: dict
  mac:
    description: The mac address of the trusted server being added.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  trustedServerId:
    description: TrustedServerId path parameter. Trusted server ID.
    type: str
  vlan:
    description: The VLAN of the trusted server being added. It must be between 1 and 4094.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch createNetworkSwitchDhcpServerPolicyArpInspectionTrustedServer
    description: Complete reference of the createNetworkSwitchDhcpServerPolicyArpInspectionTrustedServer API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-switch-dhcp-server-policy-arp-inspection-trusted-server
  - name: Cisco Meraki documentation for switch deleteNetworkSwitchDhcpServerPolicyArpInspectionTrustedServer
    description: Complete reference of the deleteNetworkSwitchDhcpServerPolicyArpInspectionTrustedServer API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-switch-dhcp-server-policy-arp-inspection-trusted-server
  - name: Cisco Meraki documentation for switch updateNetworkSwitchDhcpServerPolicyArpInspectionTrustedServer
    description: Complete reference of the updateNetworkSwitchDhcpServerPolicyArpInspectionTrustedServer API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-dhcp-server-policy-arp-inspection-trusted-server
notes:
  - SDK Method used are
    switch.Switch.create_network_switch_dhcp_server_policy_arp_inspection_trusted_server,
    switch.Switch.delete_network_switch_dhcp_server_policy_arp_inspection_trusted_server,
    switch.Switch.update_network_switch_dhcp_server_policy_arp_inspection_trusted_server,
  - Paths used are
    post /networks/{networkId}/switch/dhcpServerPolicy/arpInspection/trustedServers,
    delete /networks/{networkId}/switch/dhcpServerPolicy/arpInspection/trustedServers/{trustedServerId},
    put /networks/{networkId}/switch/dhcpServerPolicy/arpInspection/trustedServers/{trustedServerId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_switch_dhcp_server_policy_arp_inspection_trusted_servers:
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
    ipv4:
      address: 1.2.3.4
    mac: 00:11:22:33:44:55
    networkId: string
    vlan: 100
- name: Delete by id
  cisco.meraki.networks_switch_dhcp_server_policy_arp_inspection_trusted_servers:
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
    state: absent
    networkId: string
    trustedServerId: string
- name: Update by id
  cisco.meraki.networks_switch_dhcp_server_policy_arp_inspection_trusted_servers:
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
    ipv4:
      address: 1.2.3.4
    mac: 00:11:22:33:44:55
    networkId: string
    trustedServerId: string
    vlan: 100
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "ipv4": {
        "address": "string"
      },
      "mac": "string",
      "trustedServerId": "string",
      "vlan": 0
    }
"""
