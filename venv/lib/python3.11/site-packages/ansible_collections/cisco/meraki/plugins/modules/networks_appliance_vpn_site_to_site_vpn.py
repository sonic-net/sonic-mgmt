#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_vpn_site_to_site_vpn
short_description: Resource module for networks _appliance _vpn _site _to _site _vpn
description:
  - Manage operation update of the resource networks _appliance _vpn _site _to _site _vpn.
  - Update the site-to-site VPN settings of a network. Only valid for MX networks in NAT mode.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  hubs:
    description: The list of VPN hubs, in order of preference. In spoke mode, at least 1 hub is required.
    elements: dict
    suboptions:
      hubId:
        description: The network ID of the hub.
        type: str
      useDefaultRoute:
        description: Only valid in 'spoke' mode. Indicates whether default route traffic should be sent to this hub.
        type: bool
    type: list
  mode:
    description: The site-to-site VPN mode. Can be one of 'none', 'spoke' or 'hub'.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  subnet:
    description: Configuration of subnet features.
    suboptions:
      nat:
        description: Configuration of NAT for subnets.
        suboptions:
          isAllowed:
            description: If enabled, VPN subnet translation can be used to translate any local subnets that are allowed to use the VPN into a
              new subnet with the same number of addresses.
            type: bool
        type: dict
    type: dict
  subnets:
    description: The list of subnets and their VPN presence.
    elements: dict
    suboptions:
      localSubnet:
        description: The CIDR notation subnet used within the VPN.
        type: str
      nat:
        description: Configuration of NAT for the subnet.
        suboptions:
          enabled:
            description: Whether or not VPN subnet translation is enabled for the subnet.
            type: bool
          remoteSubnet:
            description: The translated subnet to be used in the VPN.
            type: str
        type: dict
      useVpn:
        description: Indicates the presence of the subnet in the VPN.
        type: bool
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceVpnSiteToSiteVpn
    description: Complete reference of the updateNetworkApplianceVpnSiteToSiteVpn API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-vpn-site-to-site-vpn
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_vpn_site_to_site_vpn,
  - Paths used are
    put /networks/{networkId}/appliance/vpn/siteToSiteVpn,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_appliance_vpn_site_to_site_vpn:
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
    hubs:
      - hubId: N_4901849
        useDefaultRoute: true
    mode: spoke
    networkId: string
    subnet:
      nat:
        isAllowed: true
    subnets:
      - localSubnet: 192.168.1.0/24
        nat:
          enabled: true
          remoteSubnet: 192.168.2.0/24
        useVpn: true
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "hubs": [
        {
          "hubId": "string",
          "useDefaultRoute": true
        }
      ],
      "mode": "string",
      "subnet": {
        "nat": {
          "isAllowed": true
        }
      },
      "subnets": [
        {
          "localSubnet": "string",
          "nat": {
            "enabled": true,
            "remoteSubnet": "string"
          },
          "useVpn": true
        }
      ]
    }
"""
