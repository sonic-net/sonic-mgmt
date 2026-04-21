#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_clients_provision
short_description: Resource module for networks _clients _provision
description:
  - Manage operation create of the resource networks _clients _provision.
  - Provisions a client with a name and policy. Clients can be provisioned before they associate to the network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  clients:
    description: The array of clients to provision.
    elements: dict
    suboptions:
      mac:
        description: The MAC address of the client. Required.
        type: str
      name:
        description: The display name for the client. Optional. Limited to 255 bytes.
        type: str
    type: list
  devicePolicy:
    description: The policy to apply to the specified client. Can be 'Group policy', 'Allowed', 'Blocked', 'Per connection' or 'Normal'. Required.
    type: str
  groupPolicyId:
    description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise this
      is ignored.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  policiesBySecurityAppliance:
    description: An object, describing what the policy-connection association is for the security appliance. (Only relevant if the security appliance
      is actually within the network).
    suboptions:
      devicePolicy:
        description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked' or 'Normal'. Required.
        type: str
    type: dict
  policiesBySsid:
    description: An object, describing the policy-connection associations for each active SSID within the network. Keys should be the number of
      enabled SSIDs, mapping to an object describing the client's policy.
    suboptions:
      '0':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '1':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '10':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '11':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '12':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '13':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '14':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '2':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '3':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '4':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '5':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '6':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '7':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '8':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
      '9':
        description: The number for the SSID.
        suboptions:
          devicePolicy:
            description: The policy to apply to the specified client. Can be 'Allowed', 'Blocked', 'Normal' or 'Group policy'. Required.
            type: str
          groupPolicyId:
            description: The ID of the desired group policy to apply to the client. Required if 'devicePolicy' is set to "Group policy". Otherwise
              this is ignored.
            type: str
        type: dict
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks provisionNetworkClients
    description: Complete reference of the provisionNetworkClients API.
    link: https://developer.cisco.com/meraki/api-v1/#!provision-network-clients
notes:
  - SDK Method used are
    networks.Networks.provision_network_clients,
  - Paths used are
    post /networks/{networkId}/clients/provision,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_clients_provision:
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
    clients:
      - mac: 00:11:22:33:44:55
        name: Miles's phone
    devicePolicy: Group policy
    groupPolicyId: '101'
    networkId: string
    policiesBySecurityAppliance:
      devicePolicy: Normal
    policiesBySsid:
      '0':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '1':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '10':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '11':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '12':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '13':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '14':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '2':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '3':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '4':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '5':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '6':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '7':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '8':
        devicePolicy: Group policy
        groupPolicyId: '101'
      '9':
        devicePolicy: Group policy
        groupPolicyId: '101'
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "clients": [
        {
          "clientId": "string",
          "mac": "string",
          "message": "string",
          "name": "string"
        }
      ],
      "devicePolicy": "string",
      "groupPolicyId": "string"
    }
"""
