#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_camera_wireless_profiles
short_description: Resource module for networks _camera _wireless _profiles
description:
  - Manage operations create, update and delete of the resource networks _camera _wireless _profiles.
  - Creates a new camera wireless profile for this network.
  - Delete an existing camera wireless profile for this network.
  - Update an existing camera wireless profile in this network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  identity:
    description: The identity of the wireless profile. Required for creating wireless profiles in 8021x-radius auth mode.
    suboptions:
      password:
        description: The password of the identity.
        type: str
      username:
        description: The username of the identity.
        type: str
    type: dict
  name:
    description: The name of the camera wireless profile. This parameter is required.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  ssid:
    description: The details of the SSID config.
    suboptions:
      authMode:
        description: The auth mode of the SSID. It can be set to ('psk', '8021x-radius').
        type: str
      encryptionMode:
        description: The encryption mode of the SSID. It can be set to ('wpa', 'wpa-eap'). With 'wpa' mode, the authMode should be 'psk' and with
          'wpa-eap' the authMode should be '8021x-radius'.
        type: str
      name:
        description: The name of the SSID.
        type: str
      psk:
        description: The pre-shared key of the SSID.
        type: str
    type: dict
  wirelessProfileId:
    description: WirelessProfileId path parameter. Wireless profile ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for camera createNetworkCameraWirelessProfile
    description: Complete reference of the createNetworkCameraWirelessProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-camera-wireless-profile
  - name: Cisco Meraki documentation for camera deleteNetworkCameraWirelessProfile
    description: Complete reference of the deleteNetworkCameraWirelessProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-camera-wireless-profile
  - name: Cisco Meraki documentation for camera updateNetworkCameraWirelessProfile
    description: Complete reference of the updateNetworkCameraWirelessProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-camera-wireless-profile
notes:
  - SDK Method used are
    camera.Camera.create_network_camera_wireless_profile,
    camera.Camera.delete_network_camera_wireless_profile,
    camera.Camera.update_network_camera_wireless_profile,
  - Paths used are
    post /networks/{networkId}/camera/wirelessProfiles,
    delete /networks/{networkId}/camera/wirelessProfiles/{wirelessProfileId},
    put /networks/{networkId}/camera/wirelessProfiles/{wirelessProfileId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_camera_wireless_profiles:
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
    identity:
      password: password123
      username: identityname
    name: wireless profile A
    networkId: string
    ssid:
      authMode: 8021x-radius
      encryptionMode: wpa-eap
      name: ssid test
      psk: sampleKey
- name: Delete by id
  cisco.meraki.networks_camera_wireless_profiles:
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
    networkId: string
    wirelessProfileId: string
- name: Update by id
  cisco.meraki.networks_camera_wireless_profiles:
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
    identity:
      password: password123
      username: identityname
    name: wireless profile A
    networkId: string
    ssid:
      authMode: 8021x-radius
      encryptionMode: wpa-eap
      name: ssid test
      psk: sampleKey
    wirelessProfileId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "appliedDeviceCount": 0,
      "id": "string",
      "identity": {
        "password": "string",
        "username": "string"
      },
      "name": "string",
      "ssid": {
        "authMode": "string",
        "encryptionMode": "string",
        "name": "string",
        "psk": "string"
      }
    }
"""
