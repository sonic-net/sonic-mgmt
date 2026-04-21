#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_sdwan_internet_policies
short_description: Resource module for networks _appliance _sdwan _internet _policies
description:
  - Manage operation update of the resource networks _appliance _sdwan _internet _policies.
  - Update SDWAN internet traffic preferences for an MX network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  wanTrafficUplinkPreferences:
    description: Policies with respective traffic filters for an MX network.
    elements: dict
    suboptions:
      failOverCriterion:
        description: WAN failover and failback behavior.
        type: str
      performanceClass:
        description: Performance class setting for uplink preference rule.
        suboptions:
          builtinPerformanceClassName:
            description: Name of builtin performance class. Must be present when performanceClass type is 'builtin' and value must be one of 'VoIP'.
            type: str
          customPerformanceClassId:
            description: ID of created custom performance class, must be present when performanceClass type is "custom".
            type: str
          type:
            description: Type of this performance class. Must be one of 'builtin' or 'custom'.
            type: str
        type: dict
      preferredUplink:
        description: Preferred uplink for uplink preference rule. Must be one of 'wan1', 'wan2', 'bestForVoIP', 'loadBalancing' or 'defaultUplink'.
        type: str
      trafficFilters:
        description: Traffic filters.
        elements: dict
        suboptions:
          type:
            description: Traffic filter type. Must be 'custom', 'major_application', 'application (NBAR)', if type is 'application', you can pass
              either an NBAR App Category or Application.
            type: str
          value:
            description: Value of traffic filter.
            suboptions:
              destination:
                description: Destination of 'custom' type traffic filter.
                suboptions:
                  applications:
                    description: List of application objects (either majorApplication or nbar).
                    elements: dict
                    suboptions:
                      id:
                        description: Id of the major application, or a list of NBAR Application Category or Application selections.
                        type: str
                      name:
                        description: Name of the major application or application category selected.
                        type: str
                      type:
                        description: App type (major or nbar).
                        type: str
                    type: list
                  cidr:
                    description: CIDR format address (e.g."192.168.10.1", which is the same as "192.168.10.1/32"), or "any".
                    type: str
                  port:
                    description: E.g. "any", "0" (also means "any"), "8080", "1-1024".
                    type: str
                type: dict
              protocol:
                description: Protocol of the traffic filter. Must be one of 'tcp', 'udp', 'icmp6' or 'any'.
                type: str
              source:
                description: Source of traffic filter.
                suboptions:
                  cidr:
                    description: CIDR format address (e.g."192.168.10.1", which is the same as "192.168.10.1/32"), or "any". Cannot be used in
                      combination with the "vlan" property.
                    type: str
                  host:
                    description: Host ID in the VLAN. Should not exceed the VLAN subnet capacity. Must be used along with the "vlan" property
                      and is currently only available under a template network.
                    type: int
                  port:
                    description: E.g. "any", "0" (also means "any"), "8080", "1-1024".
                    type: str
                  vlan:
                    description: VLAN ID of the configured VLAN in the Meraki network. Cannot be used in combination with the "cidr" property
                      and is currently only available under a template network.
                    type: int
                type: dict
            type: dict
        type: list
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceSdwanInternetPolicies
    description: Complete reference of the updateNetworkApplianceSdwanInternetPolicies API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-sdwan-internet-policies
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_sdwan_internet_policies,
  - Paths used are
    put /networks/{networkId}/appliance/sdwan/internetPolicies,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_appliance_sdwan_internet_policies:
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
    networkId: string
    wanTrafficUplinkPreferences:
      - failOverCriterion: poorPerformance
        performanceClass:
          builtinPerformanceClassName: VoIP
          customPerformanceClassId: '123456'
          type: custom
        preferredUplink: wan1
        trafficFilters:
          - type: custom
            value:
              destination:
                applications:
                  - id: meraki:layer7/application/3
                    name: DNS
                    type: major
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
      "wanTrafficUplinkPreferences": [
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
