#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_cellular_sims
short_description: Resource module for devices _cellular _sims
description:
  - Manage operation update of the resource devices _cellular _sims.
  - Updates the SIM and APN configurations for a cellular device.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  serial:
    description: Serial path parameter.
    type: str
  simFailover:
    description: SIM Failover settings.
    suboptions:
      enabled:
        description: Failover to secondary SIM (optional).
        type: bool
      timeout:
        description: Failover timeout in seconds (optional).
        type: int
    type: dict
  simOrdering:
    description: Specifies the ordering of all SIMs for an MG primary, secondary, and not-in-use (when applicable). It's required for devices
      with 3 or more SIMs and can be used in place of 'isPrimary' for dual-SIM devices. To indicate eSIM, use 'sim3'. Sim failover will occur
      only between primary and secondary sim slots.
    elements: str
    type: list
  sims:
    description: List of SIMs. If a SIM was previously configured and not specified in this request, it will remain unchanged.
    elements: dict
    suboptions:
      apns:
        description: APN configurations. If empty, the default APN will be used.
        elements: dict
        suboptions:
          allowedIpTypes:
            description: IP versions to support (permitted values include 'ipv4', 'ipv6').
            elements: str
            type: list
          authentication:
            description: APN authentication configurations.
            suboptions:
              password:
                description: APN password, if type is set (if APN password is not supplied, the password is left unchanged).
                type: str
              type:
                description: APN auth type.
                type: str
              username:
                description: APN username, if type is set.
                type: str
            type: dict
          name:
            description: APN name.
            type: str
        type: list
      isPrimary:
        description: If true, this SIM is activated on platform bootup. It must be true on single-SIM devices and is a required field for dual-SIM
          MGs unless it is being configured using 'simOrdering'.
        type: bool
      simOrder:
        description: Priority of SIM slot being configured. Use a value between 1 and total number of SIMs available. The value must be unique
          for each SIM.
        type: int
      slot:
        description: SIM slot being configured. Must be 'sim1' on single-sim devices. Use 'sim3' for eSIM.
        type: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for devices updateDeviceCellularSims
    description: Complete reference of the updateDeviceCellularSims API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-cellular-sims
notes:
  - SDK Method used are
    devices.Devices.update_device_cellular_sims,
  - Paths used are
    put /devices/{serial}/cellular/sims,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.devices_cellular_sims:
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
    serial: string
    simFailover:
      enabled: true
      timeout: 300
    simOrdering:
      - sim1
      - sim2
      - sim3
    sims:
      - apns:
          - allowedIpTypes:
              - ipv4
              - ipv6
            authentication:
              password: secret
              type: pap
              username: milesmeraki
            name: internet
        isPrimary: false
        simOrder: 3
        slot: sim1
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "simFailover": {
        "enabled": true,
        "timeout": 0
      },
      "simOrdering": [
        "string"
      ],
      "sims": [
        {
          "apns": [
            {
              "allowedIpTypes": [
                "string"
              ],
              "authentication": {
                "password": "string",
                "type": "string",
                "username": "string"
              },
              "name": "string"
            }
          ],
          "isPrimary": true,
          "slot": "string"
        }
      ]
    }
"""
