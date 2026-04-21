#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_single_lan
short_description: Resource module for networks _appliance _single _lan
description:
  - Manage operation update of the resource networks _appliance _single _lan.
  - Update single LAN configuration.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  applianceIp:
    description: The appliance IP address of the single LAN.
    type: str
  ipv6:
    description: IPv6 configuration on the VLAN.
    suboptions:
      enabled:
        description: Enable IPv6 on VLAN.
        type: bool
      prefixAssignments:
        description: Prefix assignments on the VLAN.
        elements: dict
        suboptions:
          autonomous:
            description: Auto assign a /64 prefix from the origin to the VLAN.
            type: bool
          origin:
            description: The origin of the prefix.
            suboptions:
              interfaces:
                description: Interfaces associated with the prefix.
                elements: str
                type: list
              type:
                description: Type of the origin.
                type: str
            type: dict
          staticApplianceIp6:
            description: Manual configuration of the IPv6 Appliance IP.
            type: str
          staticPrefix:
            description: Manual configuration of a /64 prefix on the VLAN.
            type: str
        type: list
    type: dict
  mandatoryDhcp:
    description: Mandatory DHCP will enforce that clients connecting to this LAN must use the IP address assigned by the DHCP server. Clients
      who use a static IP address won't be able to associate. Only available on firmware versions 17.0 and above.
    suboptions:
      enabled:
        description: Enable Mandatory DHCP on LAN.
        type: bool
    type: dict
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  subnet:
    description: The subnet of the single LAN configuration.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceSingleLan
    description: Complete reference of the updateNetworkApplianceSingleLan API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-single-lan
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_single_lan,
  - Paths used are
    put /networks/{networkId}/appliance/singleLan,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_appliance_single_lan:
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
    applianceIp: string
    ipv6:
      enabled: true
      prefixAssignments:
        - autonomous: true
          origin:
            interfaces:
              - string
            type: string
          staticApplianceIp6: string
          staticPrefix: string
    mandatoryDhcp:
      enabled: true
    networkId: string
    subnet: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "applianceIp": "string",
      "ipv6": {
        "enabled": true,
        "prefixAssignments": [
          {
            "autonomous": true,
            "origin": {
              "interfaces": [
                "string"
              ],
              "type": "string"
            },
            "staticApplianceIp6": "string",
            "staticPrefix": "string"
          }
        ]
      },
      "mandatoryDhcp": {
        "enabled": true
      },
      "subnet": "string"
    }
"""
