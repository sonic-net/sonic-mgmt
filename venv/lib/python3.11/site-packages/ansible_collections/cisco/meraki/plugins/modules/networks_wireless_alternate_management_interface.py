#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_alternate_management_interface
short_description: Resource module for networks _wireless _alternate _management _interface
description:
  - Manage operation update of the resource networks _wireless _alternate _management _interface.
  - Update alternate management interface and device static IP.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  accessPoints:
    description: Array of access point serial number and IP assignment. Note accessPoints IP assignment is not applicable for template networks,
      in other words, do not put 'accessPoints' in the body when updating template networks. Also, an empty 'accessPoints' array will remove all
      previous static IP assignments.
    elements: dict
    suboptions:
      alternateManagementIp:
        description: Wireless alternate management interface device IP. Provide an empty string to remove alternate management IP assignment.
        type: str
      dns1:
        description: Primary DNS must be in IP format.
        type: str
      dns2:
        description: Optional secondary DNS must be in IP format.
        type: str
      gateway:
        description: Gateway must be in IP format.
        type: str
      serial:
        description: Serial number of access point to be configured with alternate management IP.
        type: str
      subnetMask:
        description: Subnet mask must be in IP format.
        type: str
    type: list
  enabled:
    description: Boolean value to enable or disable alternate management interface.
    type: bool
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  protocols:
    description: Can be one or more of the following values 'radius', 'snmp', 'syslog' or 'ldap'.
    elements: str
    type: list
  vlanId:
    description: Alternate management interface VLAN, must be between 1 and 4094.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessAlternateManagementInterface
    description: Complete reference of the updateNetworkWirelessAlternateManagementInterface API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-alternate-management-interface
notes:
  - SDK Method used are
    wireless.Wireless.update_network_wireless_alternate_management_interface,
  - Paths used are
    put /networks/{networkId}/wireless/alternateManagementInterface,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_wireless_alternate_management_interface:
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
    accessPoints:
      - alternateManagementIp: 1.2.3.4
        dns1: 8.8.8.8
        dns2: 8.8.4.4
        gateway: 1.2.3.5
        serial: Q234-ABCD-5678
        subnetMask: 255.255.255.0
    enabled: true
    networkId: string
    protocols:
      - radius
      - snmp
      - syslog
      - ldap
    vlanId: 100
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
