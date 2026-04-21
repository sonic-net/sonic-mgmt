#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_settings
short_description: Resource module for networks _wireless _settings
description:
  - Manage operation update of the resource networks _wireless _settings.
  - Update the wireless settings for a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  ipv6BridgeEnabled:
    description: Toggle for enabling or disabling IPv6 bridging in a network (Note if enabled, SSIDs must also be configured to use bridge mode).
    type: bool
  ledLightsOn:
    description: Toggle for enabling or disabling LED lights on all APs in the network (making them run dark).
    type: bool
  locationAnalyticsEnabled:
    description: Toggle for enabling or disabling location analytics for your network.
    type: bool
  meshingEnabled:
    description: Toggle for enabling or disabling meshing in a network.
    type: bool
  namedVlans:
    description: Named VLAN settings for wireless networks.
    suboptions:
      poolDhcpMonitoring:
        description: Named VLAN Pool DHCP Monitoring settings.
        suboptions:
          duration:
            description: The duration in minutes that devices will refrain from using dirty VLANs before adding them back to the pool.
            type: int
          enabled:
            description: Whether or not devices using named VLAN pools should remove dirty VLANs from the pool, thereby preventing clients from
              being assigned to VLANs where they would be unable to obtain an IP address via DHCP.
            type: bool
        type: dict
    type: dict
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  upgradeStrategy:
    description: The default strategy that network devices will use to perform an upgrade. Requires firmware version MR 26.8 or higher.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessSettings
    description: Complete reference of the updateNetworkWirelessSettings API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-settings
notes:
  - SDK Method used are
    wireless.Wireless.update_network_wireless_settings,
  - Paths used are
    put /networks/{networkId}/wireless/settings,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_wireless_settings:
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
    ipv6BridgeEnabled: false
    ledLightsOn: false
    locationAnalyticsEnabled: false
    meshingEnabled: true
    namedVlans:
      poolDhcpMonitoring:
        duration: 5
        enabled: true
    networkId: string
    upgradeStrategy: minimizeUpgradeTime
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "ipv6BridgeEnabled": true,
      "ledLightsOn": true,
      "locationAnalyticsEnabled": true,
      "meshingEnabled": true,
      "namedVlans": {
        "poolDhcpMonitoring": {
          "duration": 0,
          "enabled": true
        }
      },
      "regulatoryDomain": {
        "countryCode": "string",
        "name": "string",
        "permits6e": true
      },
      "upgradeStrategy": "string"
    }
"""
