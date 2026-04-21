#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_group_policies
short_description: Resource module for networks _group _policies
description:
  - Manage operations create, update and delete of the resource networks _group _policies.
  - Create a group policy.
  - Delete a group policy.
  - Update a group policy.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  bandwidth:
    description: The bandwidth settings for clients bound to your group policy.
    suboptions:
      bandwidthLimits:
        description: The bandwidth limits object, specifying upload and download speed for clients bound to the group policy. These are only enforced
          if 'settings' is set to 'custom'.
        suboptions:
          limitDown:
            description: The maximum download limit (integer, in Kbps). Null indicates no limit.
            type: int
          limitUp:
            description: The maximum upload limit (integer, in Kbps). Null indicates no limit.
            type: int
        type: dict
      settings:
        description: How bandwidth limits are enforced. Can be 'network default', 'ignore' or 'custom'.
        type: str
    type: dict
  bonjourForwarding:
    description: The Bonjour settings for your group policy. Only valid if your network has a wireless configuration.
    suboptions:
      rules:
        description: A list of the Bonjour forwarding rules for your group policy. If 'settings' is set to 'custom', at least one rule must be
          specified.
        elements: dict
        suboptions:
          description:
            description: A description for your Bonjour forwarding rule. Optional.
            type: str
          services:
            description: A list of Bonjour services. At least one service must be specified. Available services are 'All Services', 'AFP', 'AirPlay',
              'Apple screen share', 'BitTorrent', 'Chromecast', 'FTP', 'iChat', 'iTunes', 'Printers', 'Samba', 'Scanners', 'Spotify' and 'SSH'.
            elements: str
            type: list
          vlanId:
            description: The ID of the service VLAN. Required.
            type: str
        type: list
      settings:
        description: How Bonjour rules are applied. Can be 'network default', 'ignore' or 'custom'.
        type: str
    type: dict
  contentFiltering:
    description: The content filtering settings for your group policy.
    suboptions:
      allowedUrlPatterns:
        description: Settings for allowed URL patterns.
        suboptions:
          patterns:
            description: A list of URL patterns that are allowed.
            elements: str
            type: list
          settings:
            description: How URL patterns are applied. Can be 'network default', 'append' or 'override'.
            type: str
        type: dict
      blockedUrlCategories:
        description: Settings for blocked URL categories.
        suboptions:
          categories:
            description: A list of URL categories to block.
            elements: str
            type: list
          settings:
            description: How URL categories are applied. Can be 'network default', 'append' or 'override'.
            type: str
        type: dict
      blockedUrlPatterns:
        description: Settings for blocked URL patterns.
        suboptions:
          patterns:
            description: A list of URL patterns that are blocked.
            elements: str
            type: list
          settings:
            description: How URL patterns are applied. Can be 'network default', 'append' or 'override'.
            type: str
        type: dict
    type: dict
  firewallAndTrafficShaping:
    description: The firewall and traffic shaping rules and settings for your policy.
    suboptions:
      l3FirewallRules:
        description: An ordered array of the L3 firewall rules.
        elements: dict
        suboptions:
          comment:
            description: Description of the rule (optional).
            type: str
          destCidr:
            description: Destination IP address (in IP or CIDR notation), a fully-qualified domain name (FQDN, if your network supports it) or
              'any'.
            type: str
          destPort:
            description: Destination port (integer in the range 1-65535), a port range (e.g. 8080-9090), or 'any'.
            type: str
          policy:
            description: '''allow'' or ''deny'' traffic specified by this rule.'
            type: str
          protocol:
            description: The type of protocol (must be 'tcp', 'udp', 'icmp', 'icmp6' or 'any').
            type: str
        type: list
      l7FirewallRules:
        description: An ordered array of L7 firewall rules.
        elements: dict
        suboptions:
          policy:
            description: The policy applied to matching traffic. Must be 'deny'.
            type: str
          type:
            description: Type of the L7 Rule. Must be 'application', 'applicationCategory', 'host', 'port' or 'ipRange'.
            type: str
          value:
            description: The 'value' of what you want to block. If 'type' is 'host', 'port' or 'ipRange', 'value' must be a string matching either
              a hostname (e.g. Somewhere.com), a port (e.g. 8080), or an IP range (e.g. 192.1.0.0/16). If 'type' is 'application' or 'applicationCategory',
              then 'value' must be an object with an ID for the application.
            type: str
        type: list
      settings:
        description: How firewall and traffic shaping rules are enforced. Can be 'network default', 'ignore' or 'custom'.
        type: str
      trafficShapingRules:
        description: An array of traffic shaping rules. Rules are applied in the order that they are specified in. An empty list (or null) means
          no rules. Note that you are allowed a maximum of 8 rules.
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
                  the structure { "id" "meraki layer7/..." }, where "id" is the application category or application ID (for a list of IDs for
                  your network, use the trafficShaping/applicationCategories endpoint).
                type: str
            type: list
          dscpTagValue:
            description: The DSCP tag applied by your rule. Null means 'Do not change DSCP tag'. For a list of possible tag values, use the
              trafficShaping/dscpTaggingOptions endpoint.
            type: int
          pcpTagValue:
            description: The PCP tag applied by your rule. Can be 0 (lowest priority) through 7 (highest priority). Null means 'Do not set PCP
              tag'.
            type: int
          perClientBandwidthLimits:
            description: An object describing the bandwidth settings for your rule.
            suboptions:
              bandwidthLimits:
                description: The bandwidth limits object, specifying the upload ('limitUp') and download ('limitDown') speed in Kbps. These are
                  only enforced if 'settings' is set to 'custom'.
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
    type: dict
  force:
    description: Force query parameter. If true, the system deletes the GP even if there are active clients using the GP. After deletion, active
      clients that were assigned to that Group Policy will be left without any policy applied. Default is false.
    type: bool
  groupPolicyId:
    description: GroupPolicyId path parameter. Group policy ID.
    type: str
  name:
    description: The name for your group policy. Required.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  scheduling:
    description: The schedule for the group policy. Schedules are applied to days of the week.
    suboptions:
      enabled:
        description: Whether scheduling is enabled (true) or disabled (false). Defaults to false. If true, the schedule objects for each day of
          the week (monday - sunday) are parsed.
        type: bool
      friday:
        description: The schedule object for Friday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
      monday:
        description: The schedule object for Monday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
      saturday:
        description: The schedule object for Saturday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
      sunday:
        description: The schedule object for Sunday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
      thursday:
        description: The schedule object for Thursday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
      tuesday:
        description: The schedule object for Tuesday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
      wednesday:
        description: The schedule object for Wednesday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
    type: dict
  splashAuthSettings:
    description: Whether clients bound to your policy will bypass splash authorization or behave according to the network's rules. Can be one
      of 'network default' or 'bypass'. Only available if your network has a wireless configuration.
    type: str
  vlanTagging:
    description: The VLAN tagging settings for your group policy. Only available if your network has a wireless configuration.
    suboptions:
      settings:
        description: How VLAN tagging is applied. Can be 'network default', 'ignore' or 'custom'.
        type: str
      vlanId:
        description: The ID of the vlan you want to tag. This only applies if 'settings' is set to 'custom'.
        type: str
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks createNetworkGroupPolicy
    description: Complete reference of the createNetworkGroupPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-group-policy
  - name: Cisco Meraki documentation for networks deleteNetworkGroupPolicy
    description: Complete reference of the deleteNetworkGroupPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-group-policy
  - name: Cisco Meraki documentation for networks updateNetworkGroupPolicy
    description: Complete reference of the updateNetworkGroupPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-group-policy
notes:
  - SDK Method used are
    networks.Networks.create_network_group_policy,
    networks.Networks.delete_network_group_policy,
    networks.Networks.update_network_group_policy,
  - Paths used are
    post /networks/{networkId}/groupPolicies,
    delete /networks/{networkId}/groupPolicies/{groupPolicyId},
    put /networks/{networkId}/groupPolicies/{groupPolicyId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_group_policies:
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
    bandwidth:
      bandwidthLimits:
        limitDown: 1000000
        limitUp: 1000000
      settings: custom
    bonjourForwarding:
      rules:
        - description: A simple bonjour rule
          services:
            - All Services
          vlanId: '1'
      settings: custom
    contentFiltering:
      allowedUrlPatterns:
        patterns: []
        settings: network default
      blockedUrlCategories:
        categories:
          - meraki:contentFiltering/category/1
          - meraki:contentFiltering/category/7
        settings: override
      blockedUrlPatterns:
        patterns:
          - http://www.example.com
          - http://www.betting.com
        settings: append
    firewallAndTrafficShaping:
      l3FirewallRules:
        - comment: Allow TCP traffic to subnet with HTTP servers.
          destCidr: 192.168.1.0/24
          destPort: '443'
          policy: allow
          protocol: tcp
      l7FirewallRules:
        - policy: deny
          type: host
          value: google.com
      settings: custom
      trafficShapingRules:
        - definitions:
            - type: host
              value: google.com
          dscpTagValue: 0
          pcpTagValue: 0
          perClientBandwidthLimits:
            bandwidthLimits:
              limitDown: 1000000
              limitUp: 1000000
            settings: custom
          priority: normal
    name: No video streaming
    networkId: string
    scheduling:
      enabled: true
      friday:
        active: true
        from: '9:00'
        to: '17:00'
      monday:
        active: true
        from: '9:00'
        to: '17:00'
      saturday:
        active: true
        from: '9:00'
        to: '17:00'
      sunday:
        active: true
        from: '9:00'
        to: '17:00'
      thursday:
        active: true
        from: '9:00'
        to: '17:00'
      tuesday:
        active: true
        from: '9:00'
        to: '17:00'
      wednesday:
        active: true
        from: '9:00'
        to: '17:00'
    splashAuthSettings: bypass
    vlanTagging:
      settings: custom
      vlanId: '1'
- name: Delete by id
  cisco.meraki.networks_group_policies:
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
    state: absent
    force: true
    groupPolicyId: string
    networkId: string
- name: Update by id
  cisco.meraki.networks_group_policies:
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
    bandwidth:
      bandwidthLimits:
        limitDown: 1000000
        limitUp: 1000000
      settings: custom
    bonjourForwarding:
      rules:
        - description: A simple bonjour rule
          services:
            - All Services
          vlanId: '1'
      settings: custom
    contentFiltering:
      allowedUrlPatterns:
        patterns: []
        settings: network default
      blockedUrlCategories:
        categories:
          - meraki:contentFiltering/category/1
          - meraki:contentFiltering/category/7
        settings: override
      blockedUrlPatterns:
        patterns:
          - http://www.example.com
          - http://www.betting.com
        settings: append
    firewallAndTrafficShaping:
      l3FirewallRules:
        - comment: Allow TCP traffic to subnet with HTTP servers.
          destCidr: 192.168.1.0/24
          destPort: '443'
          policy: allow
          protocol: tcp
      l7FirewallRules:
        - policy: deny
          type: host
          value: google.com
      settings: custom
      trafficShapingRules:
        - definitions:
            - type: host
              value: google.com
          dscpTagValue: 0
          pcpTagValue: 0
          perClientBandwidthLimits:
            bandwidthLimits:
              limitDown: 1000000
              limitUp: 1000000
            settings: custom
          priority: normal
    groupPolicyId: string
    name: No video streaming
    networkId: string
    scheduling:
      enabled: true
      friday:
        active: true
        from: '9:00'
        to: '17:00'
      monday:
        active: true
        from: '9:00'
        to: '17:00'
      saturday:
        active: true
        from: '9:00'
        to: '17:00'
      sunday:
        active: true
        from: '9:00'
        to: '17:00'
      thursday:
        active: true
        from: '9:00'
        to: '17:00'
      tuesday:
        active: true
        from: '9:00'
        to: '17:00'
      wednesday:
        active: true
        from: '9:00'
        to: '17:00'
    splashAuthSettings: bypass
    vlanTagging:
      settings: custom
      vlanId: '1'
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "bandwidth": {
        "bandwidthLimits": {
          "limitDown": 0,
          "limitUp": 0
        },
        "settings": "string"
      },
      "bonjourForwarding": {
        "rules": [
          {
            "description": "string",
            "services": [
              "string"
            ],
            "vlanId": "string"
          }
        ],
        "settings": "string"
      },
      "contentFiltering": {
        "allowedUrlPatterns": {
          "patterns": [
            "string"
          ],
          "settings": "string"
        },
        "blockedUrlCategories": {
          "categories": [
            "string"
          ],
          "settings": "string"
        },
        "blockedUrlPatterns": {
          "patterns": [
            "string"
          ],
          "settings": "string"
        }
      },
      "firewallAndTrafficShaping": {
        "l3FirewallRules": [
          {
            "comment": "string",
            "destCidr": "string",
            "destPort": "string",
            "policy": "string",
            "protocol": "string"
          }
        ],
        "l7FirewallRules": [
          {
            "policy": "string",
            "type": "string",
            "value": "string"
          }
        ],
        "settings": "string",
        "trafficShapingRules": [
          {
            "definitions": [
              {
                "type": "string",
                "value": "string"
              }
            ],
            "dscpTagValue": 0,
            "pcpTagValue": 0,
            "perClientBandwidthLimits": {
              "bandwidthLimits": {
                "limitDown": 0,
                "limitUp": 0
              },
              "settings": "string"
            },
            "priority": "string"
          }
        ]
      },
      "groupPolicyId": "string",
      "scheduling": {
        "enabled": true,
        "friday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "monday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "saturday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "sunday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "thursday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "tuesday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "wednesday": {
          "active": true,
          "from": "string",
          "to": "string"
        }
      },
      "splashAuthSettings": "string",
      "vlanTagging": {
        "settings": "string",
        "vlanId": "string"
      }
    }
"""
