#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_traffic_shaping_rules
short_description: Resource module for networks _appliance _traffic _shaping _rules
description:
  - Manage operation update of the resource networks _appliance _traffic _shaping _rules.
  - Update the traffic shaping settings rules for an MX network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  defaultRulesEnabled:
    description: Whether default traffic shaping rules are enabled (true) or disabled (false). There are 4 default rules, which can be seen on
      your network's traffic shaping page. Note that default rules count against the rule limit of 8.
    type: bool
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  rules:
    description: An array of traffic shaping rules. Rules are applied in the order that they are specified in. An empty list (or null) means no
      rules. Note that you are allowed a maximum of 8 rules.
    elements: dict
    suboptions:
      definitions:
        description: A list of objects describing the definitions of your traffic shaping rule. At least one definition is required.
        elements: dict
        suboptions:
          type:
            description: The type of definition. Can be one of 'application', 'applicationCategory', 'host', 'port', 'ipRange' or 'localNet'.
            type: str
          value:
            description: If "type" is 'host', 'port', 'ipRange' or 'localNet', then "value" must be a string, matching either a hostname (e.g.
              "somesite.com"), a port (e.g. 8080), or an IP range ("192.1.0.0", "192.1.0.0/16", or "10.1.0.0/16 80"). 'localNet' also supports
              CIDR notation, excluding custom ports. If "type" is 'application' or 'applicationCategory', then "value" must be an object with
              the structure { "id" "meraki layer7/..." }, where "id" is the application category or application ID (for a list of IDs for your
              network, use the trafficShaping/applicationCategories endpoint).
            type: str
        type: list
      dscpTagValue:
        description: The DSCP tag applied by your rule. Null means 'Do not change DSCP tag'. For a list of possible tag values, use the
          trafficShaping/dscpTaggingOptions endpoint.
        type: int
      perClientBandwidthLimits:
        description: An object describing the bandwidth settings for your rule.
        suboptions:
          bandwidthLimits:
            description: The bandwidth limits object, specifying the upload ('limitUp') and download ('limitDown') speed in Kbps. These are only
              enforced if 'settings' is set to 'custom'.
            suboptions:
              limitDown:
                description: The maximum download limit (integer, in Kbps).
                type: int
              limitUp:
                description: The maximum upload limit (integer, in Kbps).
                type: int
            type: dict
          settings:
            description: How bandwidth limits are applied by your rule. Can be one of 'network default', 'ignore' or 'custom'.
            type: str
        type: dict
      priority:
        description: A string, indicating the priority level for packets bound to your rule. Can be 'low', 'normal' or 'high'.
        type: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceTrafficShapingRules
    description: Complete reference of the updateNetworkApplianceTrafficShapingRules API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-traffic-shaping-rules
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_traffic_shaping_rules,
  - Paths used are
    put /networks/{networkId}/appliance/trafficShaping/rules,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_appliance_traffic_shaping_rules:
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
    defaultRulesEnabled: true
    networkId: string
    rules:
      - definitions:
          - type: host
            value: google.com
          - type: port
            value: '9090'
          - type: ipRange
            value: 192.1.0.0
          - type: ipRange
            value: 192.1.0.0/16
          - type: ipRange
            value: 10.1.0.0/16:80
          - type: localNet
            value: 192.168.0.0/16
        dscpTagValue: 0
        perClientBandwidthLimits:
          bandwidthLimits:
            limitDown: 1000000
            limitUp: 1000000
          settings: custom
        priority: normal
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
