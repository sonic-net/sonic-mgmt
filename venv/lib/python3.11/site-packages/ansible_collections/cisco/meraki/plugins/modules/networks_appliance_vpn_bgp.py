#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_vpn_bgp
short_description: Resource module for networks _appliance _vpn _bgp
description:
  - Manage operation update of the resource networks _appliance _vpn _bgp.
  - Update a Hub BGP Configuration.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  asNumber:
    description: An Autonomous System Number (ASN) is required if you are to run BGP and peer with another BGP Speaker outside of the Auto VPN
      domain. This ASN will be applied to the entire Auto VPN domain. The entire 4-byte ASN range is supported. So, the ASN must be an integer
      between 1 and 4294967295. When absent, this field is not updated. If no value exists then it defaults to 64512.
    type: int
  enabled:
    description: Boolean value to enable or disable the BGP configuration. When BGP is enabled, the asNumber (ASN) will be autopopulated with
      the preconfigured ASN at other Hubs or a default value if there is no ASN configured.
    type: bool
  ibgpHoldTimer:
    description: The iBGP holdtimer in seconds. The iBGP holdtimer must be an integer between 12 and 240. When absent, this field is not updated.
      If no value exists then it defaults to 240.
    type: int
  neighbors:
    description: List of BGP neighbors. This list replaces the existing set of neighbors. When absent, this field is not updated.
    elements: dict
    suboptions:
      allowTransit:
        description: When this feature is on, the Meraki device will advertise routes learned from other Autonomous Systems, thereby allowing
          traffic between Autonomous Systems to transit this AS. When absent, it defaults to false.
        type: bool
      authentication:
        description: Authentication settings between BGP peers.
        suboptions:
          password:
            description: Password to configure MD5 authentication between BGP peers.
            type: str
        type: dict
      ebgpHoldTimer:
        description: The eBGP hold timer in seconds for each neighbor. The eBGP hold timer must be an integer between 12 and 240.
        type: int
      ebgpMultihop:
        description: Configure this if the neighbor is not adjacent. The eBGP multi-hop must be an integer between 1 and 255.
        type: int
      ip:
        description: The IPv4 address of the neighbor.
        type: str
      ipv6:
        description: Information regarding IPv6 address of the neighbor, Required if `ip` is not present.
        suboptions:
          address:
            description: The IPv6 address of the neighbor.
            type: str
        type: dict
      nextHopIp:
        description: The IPv4 address of the remote BGP peer that will establish a TCP session with the local MX.
        type: str
      receiveLimit:
        description: The receive limit is the maximum number of routes that can be received from any BGP peer. The receive limit must be an integer
          between 0 and 2147483647. When absent, it defaults to 0.
        type: int
      remoteAsNumber:
        description: Remote ASN of the neighbor. The remote ASN must be an integer between 1 and 4294967295.
        type: int
      sourceInterface:
        description: The output interface for peering with the remote BGP peer. Valid values are 'wan{NUMBER}' (e.g. 'wan3') or 'vlan{VLAN ID}'
          (e.g. 'vlan123').
        type: str
      ttlSecurity:
        description: Settings for BGP TTL security to protect BGP peering sessions from forged IP attacks.
        suboptions:
          enabled:
            description: Boolean value to enable or disable BGP TTL security.
            type: bool
        type: dict
    type: list
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceVpnBgp
    description: Complete reference of the updateNetworkApplianceVpnBgp API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-vpn-bgp
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_vpn_bgp,
  - Paths used are
    put /networks/{networkId}/appliance/vpn/bgp,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_appliance_vpn_bgp:
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
    asNumber: 64515
    enabled: true
    ibgpHoldTimer: 120
    neighbors:
      - allowTransit: true
        authentication:
          password: abc123
        ebgpHoldTimer: 180
        ebgpMultihop: 2
        ip: 10.10.10.22
        ipv6:
          address: 2002::1234:abcd:ffff:c0a8:101
        nextHopIp: 1.2.3.4
        receiveLimit: 120
        remoteAsNumber: 64343
        sourceInterface: wan1
        ttlSecurity:
          enabled: false
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "asNumber": 0,
      "enabled": true,
      "ibgpHoldTimer": 0,
      "neighbors": [
        {
          "allowTransit": true,
          "authentication": {
            "password": "string"
          },
          "ebgpHoldTimer": 0,
          "ebgpMultihop": 0,
          "ip": "string",
          "ipv6": {
            "address": "string"
          },
          "nextHopIp": "string",
          "receiveLimit": 0,
          "remoteAsNumber": 0,
          "sourceInterface": "string",
          "ttlSecurity": {
            "enabled": true
          }
        }
      ]
    }
"""
