#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_alternate_management_interface
short_description: Resource module for networks _switch _alternate _management _interface
description:
  - Manage operation update of the resource networks _switch _alternate _management _interface.
  - Update the switch alternate management interface for the network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  enabled:
    description: Boolean value to enable or disable AMI configuration. If enabled, VLAN and protocols must be set.
    type: bool
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  protocols:
    description: Can be one or more of the following values 'radius', 'snmp' or 'syslog'.
    elements: str
    type: list
  switches:
    description: Array of switch serial number and IP assignment. If parameter is present, it cannot have empty body. Note switches parameter
      is not applicable for template networks, in other words, do not put 'switches' in the body when updating template networks. Also, an empty
      'switches' array will remove all previous assignments.
    elements: dict
    suboptions:
      alternateManagementIp:
        description: Switch alternative management IP. To remove a prior IP setting, provide an empty string.
        type: str
      gateway:
        description: Switch gateway must be in IP format. Only and must be specified for Polaris switches.
        type: str
      serial:
        description: Switch serial number.
        type: str
      subnetMask:
        description: Switch subnet mask must be in IP format. Only and must be specified for Polaris switches.
        type: str
    type: list
  vlanId:
    description: Alternate management VLAN, must be between 1 and 4094.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch updateNetworkSwitchAlternateManagementInterface
    description: Complete reference of the updateNetworkSwitchAlternateManagementInterface API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-alternate-management-interface
notes:
  - SDK Method used are
    switch.Switch.update_network_switch_alternate_management_interface,
  - Paths used are
    put /networks/{networkId}/switch/alternateManagementInterface,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_switch_alternate_management_interface:
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
    enabled: true
    networkId: string
    protocols:
      - radius
      - snmp
      - syslog
    switches:
      - alternateManagementIp: 1.2.3.4
        gateway: 1.2.3.5
        serial: Q234-ABCD-5678
        subnetMask: 255.255.255.0
    vlanId: 100
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "enabled": true,
      "protocols": [
        "string"
      ],
      "switches": [
        {
          "alternateManagementIp": "string",
          "gateway": "string",
          "serial": "string",
          "subnetMask": "string"
        }
      ],
      "vlanId": 0
    }
"""
