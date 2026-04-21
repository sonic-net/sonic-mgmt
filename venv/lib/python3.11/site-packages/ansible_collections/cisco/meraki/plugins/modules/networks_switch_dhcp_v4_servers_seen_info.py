#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_dhcp_v4_servers_seen_info
short_description: Information module for networks _switch _dhcp v4 _servers _seen
description:
  - Get all networks _switch _dhcp v4 _servers _seen.
  - Return the network's DHCPv4 servers seen within the selected timeframe default 1 day .
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
  - cisco.meraki.module_info_pagination
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  networkId:
    description:
      - NetworkId path parameter. Network ID.
    type: str
  t0:
    description:
      - T0 query parameter. The beginning of the timespan for the data. The maximum lookback period is 31 days from today.
    type: str
  timespan:
    description:
      - >
        Timespan query parameter. The timespan for which the information will be fetched. If specifying timespan, do not specify parameter t0.
        The value must be in seconds and be less than or equal to 31 days. The default is 1 day.
    type: float
  perPage:
    description:
      - PerPage query parameter. The number of entries per page returned. Acceptable range is 3 - 1000. Default is 1000.
    type: int
  startingAfter:
    description:
      - >
        StartingAfter query parameter. A token used by the server to indicate the start of the page. Often this is a timestamp or an ID but it
        is not limited to those. This parameter should not be defined by client applications. The link for the first, last, prev, or next page
        in the HTTP Link header should define it.
    type: str
  endingBefore:
    description:
      - >
        EndingBefore query parameter. A token used by the server to indicate the end of the page. Often this is a timestamp or an ID but it is
        not limited to those. This parameter should not be defined by client applications. The link for the first, last, prev, or next page in
        the HTTP Link header should define it.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch getNetworkSwitchDhcpV4ServersSeen
    description: Complete reference of the getNetworkSwitchDhcpV4ServersSeen API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-switch-dhcp-v4-servers-seen
notes:
  - SDK Method used are
    switch.Switch.get_network_switch_dhcp_v4_servers_seen,
  - Paths used are
    get /networks/{networkId}/switch/dhcp/v4/servers/seen,
"""

EXAMPLES = r"""
- name: Get all networks _switch _dhcp v4 _servers _seen
  cisco.meraki.networks_switch_dhcp_v4_servers_seen_info:
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
    t0: string
    timespan: 0
    perPage: 0
    startingAfter: string
    endingBefore: string
    networkId: string
    total_pages: -1
    direction: next
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "clientId": "string",
        "device": {
          "interface": {
            "name": "string",
            "url": "string"
          },
          "name": "string",
          "serial": "string",
          "url": "string"
        },
        "ipv4": {
          "address": "string",
          "gateway": "string",
          "subnet": "string"
        },
        "isAllowed": true,
        "isConfigured": true,
        "lastAck": {
          "ipv4": {
            "address": "string"
          },
          "ts": "string"
        },
        "lastPacket": {
          "destination": {
            "ipv4": {
              "address": "string"
            },
            "mac": "string",
            "port": 0
          },
          "ethernet": {
            "type": "string"
          },
          "fields": {
            "chaddr": "string",
            "ciaddr": "string",
            "flags": "string",
            "giaddr": "string",
            "hlen": 0,
            "hops": 0,
            "htype": 0,
            "magicCookie": "string",
            "op": 0,
            "options": [
              {
                "name": "string",
                "value": "string"
              }
            ],
            "secs": 0,
            "siaddr": "string",
            "sname": "string",
            "xid": "string",
            "yiaddr": "string"
          },
          "ip": {
            "dscp": {
              "ecn": 0,
              "tag": 0
            },
            "headerLength": 0,
            "id": "string",
            "length": 0,
            "protocol": 0,
            "ttl": 0,
            "version": 0
          },
          "source": {
            "ipv4": {
              "address": "string"
            },
            "mac": "string",
            "port": 0
          },
          "type": "string",
          "udp": {
            "checksum": "string",
            "length": 0
          }
        },
        "lastSeenAt": "string",
        "mac": "string",
        "seenBy": [
          {
            "name": "string",
            "serial": "string",
            "url": "string"
          }
        ],
        "type": "string",
        "vlan": 0
      }
    ]
"""
