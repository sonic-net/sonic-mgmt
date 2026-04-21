#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_traffic_shaping_vpn_exclusions
short_description: Resource module for networks _appliance _traffic _shaping _vpn _exclusions
description:
  - Manage operation update of the resource networks _appliance _traffic _shaping _vpn _exclusions.
  - Update VPN exclusion rules for an MX network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  custom:
    description: Custom VPN exclusion rules. Pass an empty array to clear existing rules.
    elements: dict
    suboptions:
      destination:
        description: Destination address; hostname required for DNS, IPv4 otherwise.
        type: str
      port:
        description: Destination port.
        type: str
      protocol:
        description: Protocol.
        type: str
    type: list
  majorApplications:
    description: Major Application based VPN exclusion rules. Pass an empty array to clear existing rules.
    elements: dict
    suboptions:
      id:
        description: Application's Meraki ID.
        type: str
      name:
        description: Application's name.
        type: str
    type: list
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceTrafficShapingVpnExclusions
    description: Complete reference of the updateNetworkApplianceTrafficShapingVpnExclusions API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-traffic-shaping-vpn-exclusions
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_traffic_shaping_vpn_exclusions,
  - Paths used are
    put /networks/{networkId}/appliance/trafficShaping/vpnExclusions,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_appliance_traffic_shaping_vpn_exclusions:
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
    custom:
      - destination: 192.168.3.0/24
        port: '8000'
        protocol: tcp
    majorApplications:
      - id: meraki:vpnExclusion/application/2
        name: Office 365 Sharepoint
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "custom": [
        {
          "destination": "string",
          "port": "string",
          "protocol": "string"
        }
      ],
      "majorApplications": [
        {
          "id": "string",
          "name": "string"
        }
      ],
      "networkId": "string",
      "networkName": "string"
    }
"""
