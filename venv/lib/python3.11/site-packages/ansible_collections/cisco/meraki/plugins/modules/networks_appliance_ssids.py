#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_ssids
short_description: Resource module for networks _appliance _ssids
description:
  - Manage operation update of the resource networks _appliance _ssids.
  - Update the attributes of an MX SSID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  authMode:
    description: The association control method for the SSID ('open', 'psk', '8021x-meraki' or '8021x-radius').
    type: str
  defaultVlanId:
    description: The VLAN ID of the VLAN associated to this SSID. This parameter is only valid if the network is in routed mode.
    type: int
  dhcpEnforcedDeauthentication:
    description: DHCP Enforced Deauthentication enables the disassociation of wireless clients in addition to Mandatory DHCP. This param is only
      valid on firmware versions >= MX 17.0 where the associated LAN has Mandatory DHCP Enabled.
    suboptions:
      enabled:
        description: Enable DCHP Enforced Deauthentication on the SSID.
        type: bool
    type: dict
  dot11w:
    description: The current setting for Protected Management Frames (802.11w).
    suboptions:
      enabled:
        description: Whether 802.11w is enabled or not.
        type: bool
      required:
        description: (Optional) Whether 802.11w is required or not.
        type: bool
    type: dict
  enabled:
    description: Whether or not the SSID is enabled.
    type: bool
  encryptionMode:
    description: The psk encryption mode for the SSID ('wep' or 'wpa'). This param is only valid if the authMode is 'psk'.
    type: str
  name:
    description: The name of the SSID.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  number:
    description: Number path parameter.
    type: str
  psk:
    description: The passkey for the SSID. This param is only valid if the authMode is 'psk'.
    type: str
  radiusServers:
    description: The RADIUS 802.1x servers to be used for authentication. This param is only valid if the authMode is '8021x-radius'.
    elements: dict
    suboptions:
      host:
        description: The IP address of your RADIUS server.
        type: str
      port:
        description: The UDP port your RADIUS servers listens on for Access-requests.
        type: int
      secret:
        description: The RADIUS client shared secret.
        type: str
    type: list
  visible:
    description: Boolean indicating whether the MX should advertise or hide this SSID.
    type: bool
  wpaEncryptionMode:
    description: The types of WPA encryption. ('WPA1 and WPA2', 'WPA2 only', 'WPA3 Transition Mode' or 'WPA3 only'). This param is only valid
      if (1) the authMode is 'psk' & the encryptionMode is 'wpa' OR (2) the authMode is '8021x-meraki' OR (3) the authMode is '8021x-radius'.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceSsid
    description: Complete reference of the updateNetworkApplianceSsid API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-ssid
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_ssid,
  - Paths used are
    put /networks/{networkId}/appliance/ssids/{number},
"""

EXAMPLES = r"""
- name: Update by id
  cisco.meraki.networks_appliance_ssids:
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
    authMode: 8021x-radius
    defaultVlanId: 1
    dhcpEnforcedDeauthentication:
      enabled: true
    dot11w:
      enabled: true
      required: true
    enabled: true
    encryptionMode: wpa
    name: My SSID
    networkId: string
    number: string
    psk: psk
    radiusServers:
      - host: 0.0.0.0
        port: 1000
        secret: secret
    visible: true
    wpaEncryptionMode: WPA2 only
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "authMode": "string",
      "defaultVlanId": 0,
      "enabled": true,
      "encryptionMode": "string",
      "name": "string",
      "number": 0,
      "radiusServers": [
        {
          "host": "string",
          "port": 0
        }
      ],
      "visible": true,
      "wpaEncryptionMode": "string"
    }
"""
