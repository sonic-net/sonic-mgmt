#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_routing_ospf
short_description: Resource module for networks _switch _routing _ospf
description:
  - Manage operation update of the resource networks _switch _routing _ospf.
  - Update layer 3 OSPF routing configuration.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  areas:
    description: OSPF areas.
    elements: dict
    suboptions:
      areaId:
        description: OSPF area ID.
        type: str
      areaName:
        description: Name of the OSPF area.
        type: str
      areaType:
        description: Area types in OSPF. Must be one of "normal", "stub", "nssa".
        type: str
    type: list
  deadTimerInSeconds:
    description: Time interval to determine when the peer will be declared inactive/dead. Value must be between 1 and 65535.
    type: int
  enabled:
    description: Boolean value to enable or disable OSPF routing. OSPF routing is disabled by default.
    type: bool
  helloTimerInSeconds:
    description: Time interval in seconds at which hello packet will be sent to OSPF neighbors to maintain connectivity. Value must be between
      1 and 255. Default is 10 seconds.
    type: int
  md5AuthenticationEnabled:
    description: Boolean value to enable or disable MD5 authentication. MD5 authentication is disabled by default.
    type: bool
  md5AuthenticationKey:
    description: MD5 authentication credentials. This param is only relevant if md5AuthenticationEnabled is true.
    suboptions:
      id:
        description: MD5 authentication key index. Key index must be between 1 to 255.
        type: int
      passphrase:
        description: MD5 authentication passphrase.
        type: str
    type: dict
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  v3:
    description: OSPF v3 configuration.
    suboptions:
      areas:
        description: OSPF v3 areas.
        elements: dict
        suboptions:
          areaId:
            description: OSPF area ID.
            type: str
          areaName:
            description: Name of the OSPF area.
            type: str
          areaType:
            description: Area types in OSPF. Must be one of "normal", "stub", "nssa".
            type: str
        type: list
      deadTimerInSeconds:
        description: Time interval to determine when the peer will be declared inactive/dead. Value must be between 1 and 65535.
        type: int
      enabled:
        description: Boolean value to enable or disable V3 OSPF routing. OSPF V3 routing is disabled by default.
        type: bool
      helloTimerInSeconds:
        description: Time interval in seconds at which hello packet will be sent to OSPF neighbors to maintain connectivity. Value must be between
          1 and 255. Default is 10 seconds.
        type: int
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch updateNetworkSwitchRoutingOspf
    description: Complete reference of the updateNetworkSwitchRoutingOspf API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-routing-ospf
notes:
  - SDK Method used are
    switch.Switch.update_network_switch_routing_ospf,
  - Paths used are
    put /networks/{networkId}/switch/routing/ospf,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_switch_routing_ospf:
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
    areas:
      - areaId: '1284392014819'
        areaName: Backbone
        areaType: normal
    deadTimerInSeconds: 40
    enabled: true
    helloTimerInSeconds: 10
    md5AuthenticationEnabled: true
    md5AuthenticationKey:
      id: 1234
      passphrase: abc1234
    networkId: string
    v3:
      areas:
        - areaId: '1284392014819'
          areaName: V3 Backbone
          areaType: normal
      deadTimerInSeconds: 40
      enabled: true
      helloTimerInSeconds: 10
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "areas": [
        {
          "areaId": "string",
          "areaName": "string",
          "areaType": "string"
        }
      ],
      "deadTimerInSeconds": 0,
      "enabled": true,
      "helloTimerInSeconds": 0,
      "md5AuthenticationEnabled": true,
      "md5AuthenticationKey": {
        "id": 0,
        "passphrase": "string"
      },
      "v3": {
        "areas": [
          {
            "areaId": "string",
            "areaName": "string",
            "areaType": "string"
          }
        ],
        "deadTimerInSeconds": 0,
        "enabled": true,
        "helloTimerInSeconds": 0
      }
    }
"""
