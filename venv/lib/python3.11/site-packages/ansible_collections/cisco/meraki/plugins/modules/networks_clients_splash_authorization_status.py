#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_clients_splash_authorization_status
short_description: Resource module for networks _clients _splash _authorization _status
description:
  - Manage operation update of the resource networks _clients _splash _authorization _status. - > Update a client's splash authorization. Clients
    can be identified by a client key or either the MAC or IP depending on whether the network uses Track-by-IP.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  clientId:
    description: ClientId path parameter. Client ID.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  ssids:
    description: The target SSIDs. Each SSID must be enabled and must have Click-through splash enabled. For each SSID where isAuthorized is true,
      the expiration time will automatically be set according to the SSID's splash frequency. Not all networks support configuring all SSIDs.
    suboptions:
      '0':
        description: Splash authorization for SSID 0.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '1':
        description: Splash authorization for SSID 1.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '10':
        description: Splash authorization for SSID 10.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '11':
        description: Splash authorization for SSID 11.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '12':
        description: Splash authorization for SSID 12.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '13':
        description: Splash authorization for SSID 13.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '14':
        description: Splash authorization for SSID 14.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '2':
        description: Splash authorization for SSID 2.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '3':
        description: Splash authorization for SSID 3.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '4':
        description: Splash authorization for SSID 4.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '5':
        description: Splash authorization for SSID 5.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '6':
        description: Splash authorization for SSID 6.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '7':
        description: Splash authorization for SSID 7.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '8':
        description: Splash authorization for SSID 8.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
      '9':
        description: Splash authorization for SSID 9.
        suboptions:
          isAuthorized:
            description: New authorization status for the SSID (true, false).
            type: bool
        type: dict
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks updateNetworkClientSplashAuthorizationStatus
    description: Complete reference of the updateNetworkClientSplashAuthorizationStatus API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-client-splash-authorization-status
notes:
  - SDK Method used are
    networks.Networks.update_network_client_splash_authorization_status,
  - Paths used are
    put /networks/{networkId}/clients/{clientId}/splashAuthorizationStatus,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_clients_splash_authorization_status:
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
    clientId: string
    networkId: string
    ssids:
      '0':
        isAuthorized: true
      '2':
        isAuthorized: false
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
