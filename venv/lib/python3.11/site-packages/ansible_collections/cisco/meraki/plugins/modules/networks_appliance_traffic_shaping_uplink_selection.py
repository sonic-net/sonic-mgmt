#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_traffic_shaping_uplink_selection
short_description: Resource module for networks _appliance _traffic _shaping _uplink _selection
description:
  - Manage operation update of the resource networks _appliance _traffic _shaping _uplink _selection.
  - Update uplink selection settings for an MX network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  activeActiveAutoVpnEnabled:
    description: Toggle for enabling or disabling active-active AutoVPN.
    type: bool
  defaultUplink:
    description: The default uplink. Must be one of 'wan1' or 'wan2'.
    type: str
  failoverAndFailback:
    description: WAN failover and failback behavior.
    suboptions:
      immediate:
        description: Immediate WAN transition terminates all flows (new and existing) on current WAN when it is deemed unreliable.
        suboptions:
          enabled:
            description: Toggle for enabling or disabling immediate WAN failover and failback.
            type: bool
        type: dict
    type: dict
  loadBalancingEnabled:
    description: Toggle for enabling or disabling load balancing.
    type: bool
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  vpnTrafficUplinkPreferences:
    description: Array of uplink preference rules for VPN traffic.
    elements: dict
    suboptions:
      failOverCriterion:
        description: Fail over criterion for this uplink preference rule. Must be one of 'poorPerformance' or 'uplinkDown'.
        type: str
      performanceClass:
        description: Performance class setting for this uplink preference rule.
        suboptions:
          builtinPerformanceClassName:
            description: Name of builtin performance class, must be present when performanceClass type is 'builtin', and value must be one of
              'VoIP'.
            type: str
          customPerformanceClassId:
            description: ID of created custom performance class, must be present when performanceClass type is 'custom'.
            type: str
          type:
            description: Type of this performance class. Must be one of 'builtin' or 'custom'.
            type: str
        type: dict
      preferredUplink:
        description: Preferred uplink for this uplink preference rule. Must be one of 'wan1', 'wan2', 'bestForVoIP', 'loadBalancing' or 'defaultUplink'.
        type: str
      trafficFilters:
        description: Array of traffic filters for this uplink preference rule.
        elements: dict
        suboptions:
          type:
            description: Type of this traffic filter. Must be one of 'applicationCategory', 'application' or 'custom'.
            type: str
          value:
            description: Value object of this traffic filter.
            suboptions:
              destination:
                description: Destination of this custom type traffic filter.
                suboptions:
                  cidr:
                    description: CIDR format address, or "any". E.g. "192.168.10.0/24", "192.168.10.1" (same as "192.168.10.1/32"), "0.0.0.0/0"
                      (same as "any").
                    type: str
                  fqdn:
                    description: FQDN format address. Currently only availabe in 'destination' of 'vpnTrafficUplinkPreference' object. E.g. 'www.google.com'.
                    type: str
                  host:
                    description: Host ID in the VLAN, should be used along with 'vlan', and not exceed the vlan subnet capacity. Currently only
                      available under a template network.
                    type: int
                  network:
                    description: Meraki network ID. Currently only available under a template network, and the value should be ID of either same
                      template network, or another template network currently. E.g. "L_12345678".
                    type: str
                  port:
                    description: E.g. "any", "0" (also means "any"), "8080", "1-1024".
                    type: str
                  vlan:
                    description: VLAN ID of the configured VLAN in the Meraki network. Currently only available under a template network.
                    type: int
                type: dict
              id:
                description: ID of this applicationCategory or application type traffic filter. E.g. "meraki layer7/category/1", "meraki layer7/application/4".
                type: str
              protocol:
                description: Protocol of this custom type traffic filter. Must be one of 'tcp', 'udp', 'icmp', 'icmp6' or 'any'.
                type: str
              source:
                description: Source of this custom type traffic filter.
                suboptions:
                  cidr:
                    description: CIDR format address, or "any". E.g. "192.168.10.0/24", "192.168.10.1" (same as "192.168.10.1/32"), "0.0.0.0/0"
                      (same as "any").
                    type: str
                  host:
                    description: Host ID in the VLAN, should be used along with 'vlan', and not exceed the vlan subnet capacity. Currently only
                      available under a template network.
                    type: int
                  network:
                    description: Meraki network ID. Currently only available under a template network, and the value should be ID of either same
                      template network, or another template network currently. E.g. "L_12345678".
                    type: str
                  port:
                    description: E.g. "any", "0" (also means "any"), "8080", "1-1024".
                    type: str
                  vlan:
                    description: VLAN ID of the configured VLAN in the Meraki network. Currently only available under a template network.
                    type: int
                type: dict
            type: dict
        type: list
    type: list
  wanTrafficUplinkPreferences:
    description: Array of uplink preference rules for WAN traffic.
    elements: dict
    suboptions:
      preferredUplink:
        description: Preferred uplink for this uplink preference rule. Must be one of 'wan1' or 'wan2'.
        type: str
      trafficFilters:
        description: Array of traffic filters for this uplink preference rule.
        elements: dict
        suboptions:
          type:
            description: Type of this traffic filter. Must be one of 'custom'.
            type: str
          value:
            description: Value object of this traffic filter.
            suboptions:
              destination:
                description: Destination of this custom type traffic filter.
                suboptions:
                  cidr:
                    description: CIDR format address, or "any". E.g. "192.168.10.0/24", "192.168.10.1" (same as "192.168.10.1/32"), "0.0.0.0/0"
                      (same as "any").
                    type: str
                  port:
                    description: E.g. "any", "0" (also means "any"), "8080", "1-1024".
                    type: str
                type: dict
              protocol:
                description: Protocol of this custom type traffic filter. Must be one of 'tcp', 'udp', 'icmp6' or 'any'.
                type: str
              source:
                description: Source of this custom type traffic filter.
                suboptions:
                  cidr:
                    description: CIDR format address, or "any". E.g. "192.168.10.0/24", "192.168.10.1" (same as "192.168.10.1/32"), "0.0.0.0/0"
                      (same as "any").
                    type: str
                  host:
                    description: Host ID in the VLAN, should be used along with 'vlan', and not exceed the vlan subnet capacity. Currently only
                      available under a template network.
                    type: int
                  port:
                    description: E.g. "any", "0" (also means "any"), "8080", "1-1024".
                    type: str
                  vlan:
                    description: VLAN ID of the configured VLAN in the Meraki network. Currently only available under a template network.
                    type: int
                type: dict
            type: dict
        type: list
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceTrafficShapingUplinkSelection
    description: Complete reference of the updateNetworkApplianceTrafficShapingUplinkSelection API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-traffic-shaping-uplink-selection
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_traffic_shaping_uplink_selection,
  - Paths used are
    put /networks/{networkId}/appliance/trafficShaping/uplinkSelection,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_appliance_traffic_shaping_uplink_selection:
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
    activeActiveAutoVpnEnabled: true
    defaultUplink: wan1
    failoverAndFailback:
      immediate:
        enabled: true
    loadBalancingEnabled: true
    networkId: string
    vpnTrafficUplinkPreferences:
      - failOverCriterion: poorPerformance
        performanceClass:
          builtinPerformanceClassName: VoIP
          customPerformanceClassId: '123456'
          type: custom
        preferredUplink: bestForVoIP
        trafficFilters:
          - type: applicationCategory
            value:
              destination:
                cidr: any
                fqdn: www.google.com
                host: 254
                network: L_12345678
                port: 1-1024
                vlan: 10
              id: meraki:layer7/category/1
              protocol: tcp
              source:
                cidr: 192.168.1.0/24
                host: 200
                network: L_23456789
                port: any
                vlan: 20
    wanTrafficUplinkPreferences:
      - preferredUplink: wan1
        trafficFilters:
          - type: custom
            value:
              destination:
                cidr: any
                port: any
              protocol: tcp
              source:
                cidr: 192.168.1.0/24
                host: 254
                port: 1-1024
                vlan: 10
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "activeActiveAutoVpnEnabled": true,
      "defaultUplink": "string",
      "failoverAndFailback": {
        "immediate": {
          "enabled": true
        }
      },
      "loadBalancingEnabled": true,
      "vpnTrafficUplinkPreferences": [
        {
          "failOverCriterion": "string",
          "performanceClass": {
            "builtinPerformanceClassName": "string",
            "customPerformanceClassId": "string",
            "type": "string"
          },
          "preferredUplink": "string",
          "trafficFilters": [
            {
              "type": "string",
              "value": {
                "destination": {
                  "cidr": "string",
                  "fqdn": "string",
                  "host": 0,
                  "network": "string",
                  "port": "string",
                  "vlan": 0
                },
                "id": "string",
                "protocol": "string",
                "source": {
                  "cidr": "string",
                  "host": 0,
                  "network": "string",
                  "port": "string",
                  "vlan": 0
                }
              }
            }
          ]
        }
      ],
      "wanTrafficUplinkPreferences": [
        {
          "preferredUplink": "string",
          "trafficFilters": [
            {
              "type": "string",
              "value": {
                "destination": {
                  "applications": [
                    {
                      "id": "string",
                      "name": "string",
                      "type": "string"
                    }
                  ],
                  "cidr": "string",
                  "port": "string"
                },
                "protocol": "string",
                "source": {
                  "cidr": "string",
                  "host": 0,
                  "port": "string",
                  "vlan": 0
                }
              }
            }
          ]
        }
      ]
    }
"""
