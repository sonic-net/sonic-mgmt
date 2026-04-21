#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_access_policies
short_description: Resource module for networks _switch _access _policies
description:
  - Manage operations create, update and delete of the resource networks _switch _access _policies. - > Create an access policy for a switch network.
    If you would like to enable Meraki Authentication, set radiusServers to empty array.
  - Delete an access policy for a switch network. - > Update an access policy for a switch network. If you would like to enable Meraki Authentication,
    set radiusServers to empty array.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  accessPolicyNumber:
    description: AccessPolicyNumber path parameter. Access policy number.
    type: str
  accessPolicyType:
    description: Access Type of the policy. Automatically 'Hybrid authentication' when hostMode is 'Multi-Domain'.
    type: str
  dot1x:
    description: 802.1x Settings.
    suboptions:
      controlDirection:
        description: Supports either 'both' or 'inbound'. Set to 'inbound' to allow unauthorized egress on the switchport. Set to 'both' to control
          both traffic directions with authorization. Defaults to 'both'.
        type: str
    type: dict
  guestPortBouncing:
    description: If enabled, Meraki devices will periodically send access-request messages to these RADIUS servers.
    type: bool
  guestVlanId:
    description: ID for the guest VLAN allow unauthorized devices access to limited network resources.
    type: int
  hostMode:
    description: Choose the Host Mode for the access policy.
    type: str
  increaseAccessSpeed:
    description: Enabling this option will make switches execute 802.1X and MAC-bypass authentication simultaneously so that clients authenticate
      faster. Only required when accessPolicyType is 'Hybrid Authentication.
    type: bool
  name:
    description: Name of the access policy.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  radius:
    description: Object for RADIUS Settings.
    suboptions:
      cache:
        description: Object for RADIUS Cache Settings.
        suboptions:
          enabled:
            description: Enable to cache authorization and authentication responses on the RADIUS server.
            type: bool
          timeout:
            description: If RADIUS caching is enabled, this value dictates how long the cache will remain in the RADIUS server, in hours, to allow
              network access without authentication.
            type: int
        type: dict
      criticalAuth:
        description: Critical auth settings for when authentication is rejected by the RADIUS server.
        suboptions:
          dataVlanId:
            description: VLAN that clients who use data will be placed on when RADIUS authentication fails. Will be null if hostMode is Multi-Auth.
            type: int
          suspendPortBounce:
            description: Enable to suspend port bounce when RADIUS servers are unreachable.
            type: bool
          voiceVlanId:
            description: VLAN that clients who use voice will be placed on when RADIUS authentication fails. Will be null if hostMode is Multi-Auth.
            type: int
        type: dict
      failedAuthVlanId:
        description: VLAN that clients will be placed on when RADIUS authentication fails. Will be null if hostMode is Multi-Auth.
        type: int
      reAuthenticationInterval:
        description: Re-authentication period in seconds. Will be null if hostMode is Multi-Auth.
        type: int
    type: dict
  radiusAccountingEnabled:
    description: Enable to send start, interim-update and stop messages to a configured RADIUS accounting server for tracking connected clients.
    type: bool
  radiusAccountingServers:
    description: List of RADIUS accounting servers to require connecting devices to authenticate against before granting network access.
    elements: dict
    suboptions:
      host:
        description: Public IP address of the RADIUS accounting server.
        type: str
      organizationRadiusServerId:
        description: Organization wide RADIUS server ID. If this field is provided, the host, port and secret field will be ignored.
        type: str
      port:
        description: UDP port that the RADIUS Accounting server listens on for access requests.
        type: int
      secret:
        description: RADIUS client shared secret.
        type: str
    type: list
  radiusCoaSupportEnabled:
    description: Change of authentication for RADIUS re-authentication and disconnection.
    type: bool
  radiusGroupAttribute:
    description: Acceptable values are `""` for None, or `"11"` for Group Policies ACL.
    type: str
  radiusServers:
    description: List of RADIUS servers to require connecting devices to authenticate against before granting network access.
    elements: dict
    suboptions:
      host:
        description: Public IP address of the RADIUS server.
        type: str
      organizationRadiusServerId:
        description: Organization wide RADIUS server ID. If this field is provided, the host, port and secret field will be ignored.
        type: str
      port:
        description: UDP port that the RADIUS server listens on for access requests.
        type: int
      secret:
        description: RADIUS client shared secret.
        type: str
    type: list
  radiusTestingEnabled:
    description: If enabled, Meraki devices will periodically send access-request messages to these RADIUS servers.
    type: bool
  urlRedirectWalledGardenEnabled:
    description: Enable to restrict access for clients to a specific set of IP addresses or hostnames prior to authentication.
    type: bool
  urlRedirectWalledGardenRanges:
    description: IP address ranges, in CIDR notation, to restrict access for clients to a specific set of IP addresses or hostnames prior to authentication.
    elements: str
    type: list
  voiceVlanClients:
    description: CDP/LLDP capable voice clients will be able to use this VLAN. Automatically true when hostMode is 'Multi-Domain'.
    type: bool
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch createNetworkSwitchAccessPolicy
    description: Complete reference of the createNetworkSwitchAccessPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-switch-access-policy
  - name: Cisco Meraki documentation for switch deleteNetworkSwitchAccessPolicy
    description: Complete reference of the deleteNetworkSwitchAccessPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-switch-access-policy
  - name: Cisco Meraki documentation for switch updateNetworkSwitchAccessPolicy
    description: Complete reference of the updateNetworkSwitchAccessPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-access-policy
notes:
  - SDK Method used are
    switch.Switch.create_network_switch_access_policy,
    switch.Switch.delete_network_switch_access_policy,
    switch.Switch.update_network_switch_access_policy,
  - Paths used are
    post /networks/{networkId}/switch/accessPolicies,
    delete /networks/{networkId}/switch/accessPolicies/{accessPolicyNumber},
    put /networks/{networkId}/switch/accessPolicies/{accessPolicyNumber},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_switch_access_policies:
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
    accessPolicyType: Hybrid authentication
    dot1x:
      controlDirection: inbound
    guestPortBouncing: false
    guestVlanId: 100
    hostMode: Single-Host
    increaseAccessSpeed: false
    name: 'Access policy #1'
    networkId: string
    radius:
      cache:
        enabled: false
        timeout: 24
      criticalAuth:
        dataVlanId: 100
        suspendPortBounce: true
        voiceVlanId: 100
      failedAuthVlanId: 100
      reAuthenticationInterval: 120
    radiusAccountingEnabled: true
    radiusAccountingServers:
      - host: 1.2.3.4
        organizationRadiusServerId: '42'
        port: 22
        secret: secret
    radiusCoaSupportEnabled: false
    radiusGroupAttribute: '11'
    radiusServers:
      - host: 1.2.3.4
        organizationRadiusServerId: '42'
        port: 22
        secret: secret
    radiusTestingEnabled: false
    urlRedirectWalledGardenEnabled: true
    urlRedirectWalledGardenRanges:
      - 192.168.1.0/24
    voiceVlanClients: true
- name: Delete by id
  cisco.meraki.networks_switch_access_policies:
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
    accessPolicyNumber: string
    networkId: string
- name: Update by id
  cisco.meraki.networks_switch_access_policies:
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
    accessPolicyNumber: string
    accessPolicyType: Hybrid authentication
    dot1x:
      controlDirection: inbound
    guestPortBouncing: false
    guestVlanId: 100
    hostMode: Single-Host
    increaseAccessSpeed: false
    name: 'Access policy #1'
    networkId: string
    radius:
      cache:
        enabled: false
        timeout: 24
      criticalAuth:
        dataVlanId: 100
        suspendPortBounce: true
        voiceVlanId: 100
      failedAuthVlanId: 100
      reAuthenticationInterval: 120
    radiusAccountingEnabled: true
    radiusAccountingServers:
      - host: 1.2.3.4
        organizationRadiusServerId: '42'
        port: 22
        secret: secret
        serverId: '2'
    radiusCoaSupportEnabled: false
    radiusGroupAttribute: '11'
    radiusServers:
      - host: 1.2.3.4
        organizationRadiusServerId: '42'
        port: 22
        secret: secret
        serverId: '1'
    radiusTestingEnabled: false
    urlRedirectWalledGardenEnabled: true
    urlRedirectWalledGardenRanges:
      - 192.168.1.0/24
    voiceVlanClients: true
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "accessPolicyType": "string",
      "counts": {
        "ports": {
          "withThisPolicy": 0
        }
      },
      "dot1x": {
        "controlDirection": "string"
      },
      "guestPortBouncing": true,
      "guestVlanId": 0,
      "hostMode": "string",
      "increaseAccessSpeed": true,
      "name": "string",
      "radius": {
        "cache": {
          "enabled": true,
          "timeout": 0
        },
        "criticalAuth": {
          "dataVlanId": 0,
          "suspendPortBounce": true,
          "voiceVlanId": 0
        },
        "failedAuthVlanId": 0,
        "reAuthenticationInterval": 0
      },
      "radiusAccountingEnabled": true,
      "radiusAccountingServers": [
        {
          "host": "string",
          "organizationRadiusServerId": "string",
          "port": 0,
          "serverId": "string"
        }
      ],
      "radiusCoaSupportEnabled": true,
      "radiusGroupAttribute": "string",
      "radiusServers": [
        {
          "host": "string",
          "organizationRadiusServerId": "string",
          "port": 0,
          "serverId": "string"
        }
      ],
      "radiusTestingEnabled": true,
      "urlRedirectWalledGardenEnabled": true,
      "urlRedirectWalledGardenRanges": [
        "string"
      ],
      "voiceVlanClients": true
    }
"""
