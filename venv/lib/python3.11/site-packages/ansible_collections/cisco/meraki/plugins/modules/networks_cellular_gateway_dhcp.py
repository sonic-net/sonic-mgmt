#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_cellular_gateway_dhcp
short_description: Resource module for networks _cellular _gateway _dhcp
description:
  - Manage operation update of the resource networks _cellular _gateway _dhcp.
  - Update common DHCP settings of MGs.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  dhcpLeaseTime:
    description: DHCP Lease time for all MG of the network. Possible values are '30 minutes', '1 hour', '4 hours', '12 hours', '1 day' or '1 week'.
    type: str
  dnsCustomNameservers:
    description: List of fixed IPs representing the the DNS Name servers when the mode is 'custom'.
    elements: str
    type: list
  dnsNameservers:
    description: DNS name servers mode for all MG of the network. Possible values are 'upstream_dns', 'google_dns', 'opendns', 'custom'.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for cellularGateway updateNetworkCellularGatewayDhcp
    description: Complete reference of the updateNetworkCellularGatewayDhcp API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-cellular-gateway-dhcp
notes:
  - SDK Method used are
    cellular_gateway.CellularGateway.update_network_cellular_gateway_dhcp,
  - Paths used are
    put /networks/{networkId}/cellularGateway/dhcp,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_cellular_gateway_dhcp:
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
    dhcpLeaseTime: 1 hour
    dnsCustomNameservers:
      - 172.16.2.111
      - 172.16.2.30
    dnsNameservers: custom
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "dhcpLeaseTime": "string",
      "dnsCustomNameservers": [
        "string"
      ],
      "dnsNameservers": "string"
    }
"""
