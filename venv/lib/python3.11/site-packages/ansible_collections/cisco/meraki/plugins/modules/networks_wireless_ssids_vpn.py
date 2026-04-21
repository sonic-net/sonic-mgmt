#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_ssids_vpn
short_description: Resource module for networks _wireless _ssids _vpn
description:
  - Manage operation update of the resource networks _wireless _ssids _vpn.
  - Update the VPN settings for the SSID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  concentrator:
    description: The VPN concentrator settings for this SSID.
    suboptions:
      networkId:
        description: The NAT ID of the concentrator that should be set.
        type: str
      vlanId:
        description: The VLAN that should be tagged for the concentrator.
        type: int
    type: dict
  failover:
    description: Secondary VPN concentrator settings. This is only used when two VPN concentrators are configured on the SSID.
    suboptions:
      heartbeatInterval:
        description: Idle timer interval in seconds.
        type: int
      idleTimeout:
        description: Idle timer timeout in seconds.
        type: int
      requestIp:
        description: IP addressed reserved on DHCP server where SSID will terminate.
        type: str
    type: dict
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  number:
    description: Number path parameter.
    type: str
  splitTunnel:
    description: The VPN split tunnel settings for this SSID.
    suboptions:
      enabled:
        description: If true, VPN split tunnel is enabled.
        type: bool
      rules:
        description: List of VPN split tunnel rules.
        elements: dict
        suboptions:
          comment:
            description: Description for this split tunnel rule (optional).
            type: str
          destCidr:
            description: Destination for this split tunnel rule. IP address, fully-qualified domain names (FQDN) or 'any'.
            type: str
          destPort:
            description: Destination port for this split tunnel rule, (integer in the range 1-65535), or 'any'.
            type: str
          policy:
            description: Traffic policy specified for this split tunnel rule, 'allow' or 'deny'.
            type: str
          protocol:
            description: Protocol for this split tunnel rule.
            type: str
        type: list
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessSsidVpn
    description: Complete reference of the updateNetworkWirelessSsidVpn API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-ssid-vpn
notes:
  - SDK Method used are
    wireless.Wireless.update_network_wireless_ssid_vpn,
  - Paths used are
    put /networks/{networkId}/wireless/ssids/{number}/vpn,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_wireless_ssids_vpn:
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
    concentrator:
      name: some concentrator name
      networkId: N_123
      vlanId: 44
    failover:
      heartbeatInterval: 10
      idleTimeout: 30
      requestIp: 1.1.1.1
    networkId: string
    number: string
    splitTunnel:
      enabled: true
      rules:
        - comment: split tunnel rule 1
          destCidr: 1.1.1.1/32
          destPort: any
          policy: allow
          protocol: Any
        - comment: split tunnel rule 2
          destCidr: foo.com
          destPort: any
          policy: deny
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
