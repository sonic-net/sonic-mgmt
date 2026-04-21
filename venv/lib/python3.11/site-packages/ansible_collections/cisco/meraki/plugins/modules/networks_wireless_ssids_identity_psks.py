#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_ssids_identity_psks
short_description: Resource module for networks _wireless _ssids _identity _psks
description:
  - Manage operations create, update and delete of the resource networks _wireless _ssids _identity _psks.
  - Create an Identity PSK.
  - Delete an Identity PSK.
  - Update an Identity PSK.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  expiresAt:
    description: Timestamp for when the Identity PSK expires. Will not expire if left blank.
    type: str
  groupPolicyId:
    description: The group policy to be applied to clients.
    type: str
  identityPskId:
    description: IdentityPskId path parameter. Identity psk ID.
    type: str
  name:
    description: The name of the Identity PSK.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  number:
    description: Number path parameter.
    type: str
  passphrase:
    description: The passphrase for client authentication. If left blank, one will be auto-generated.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless createNetworkWirelessSsidIdentityPsk
    description: Complete reference of the createNetworkWirelessSsidIdentityPsk API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-wireless-ssid-identity-psk
  - name: Cisco Meraki documentation for wireless deleteNetworkWirelessSsidIdentityPsk
    description: Complete reference of the deleteNetworkWirelessSsidIdentityPsk API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-wireless-ssid-identity-psk
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessSsidIdentityPsk
    description: Complete reference of the updateNetworkWirelessSsidIdentityPsk API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-ssid-identity-psk
notes:
  - SDK Method used are
    wireless.Wireless.create_network_wireless_ssid_identity_psk,
    wireless.Wireless.delete_network_wireless_ssid_identity_psk,
    wireless.Wireless.update_network_wireless_ssid_identity_psk,
  - Paths used are
    post /networks/{networkId}/wireless/ssids/{number}/identityPsks,
    delete /networks/{networkId}/wireless/ssids/{number}/identityPsks/{identityPskId},
    put /networks/{networkId}/wireless/ssids/{number}/identityPsks/{identityPskId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_wireless_ssids_identity_psks:
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
    expiresAt: '2018-02-11T00:00:00.090210Z'
    groupPolicyId: '101'
    name: Sample Identity PSK
    networkId: string
    number: string
    passphrase: secret
- name: Delete by id
  cisco.meraki.networks_wireless_ssids_identity_psks:
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
    identityPskId: string
    networkId: string
    number: string
- name: Update by id
  cisco.meraki.networks_wireless_ssids_identity_psks:
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
    expiresAt: '2018-02-11T00:00:00.090210Z'
    groupPolicyId: '101'
    identityPskId: string
    name: Sample Identity PSK
    networkId: string
    number: string
    passphrase: secret
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "email": "string",
      "expiresAt": "string",
      "groupPolicyId": "string",
      "id": "string",
      "name": "string",
      "passphrase": "string",
      "wifiPersonalNetworkId": "string"
    }
"""
