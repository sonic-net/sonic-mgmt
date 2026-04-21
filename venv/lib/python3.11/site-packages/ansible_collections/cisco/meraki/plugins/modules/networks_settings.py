#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_settings
short_description: Resource module for networks _settings
description:
  - Manage operation update of the resource networks _settings.
  - Update the settings for a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  localStatusPage:
    description: A hash of Local Status page(s)' authentication options applied to the Network.
    suboptions:
      authentication:
        description: A hash of Local Status page(s)' authentication options applied to the Network.
        suboptions:
          enabled:
            description: Enables / disables the authentication on Local Status page(s).
            type: bool
          password:
            description: The password used for Local Status Page(s). Set this to null to clear the password.
            type: str
          username:
            description: The username used for Local Status Page(s).
            type: str
        type: dict
    type: dict
  localStatusPageEnabled:
    description: Enables / disables the local device status pages (<a target='_blank' href='http //my.meraki.com/'>my.meraki.com, </a><a target='_blank'
      href='http //ap.meraki.com/'>ap.meraki.com, </a><a target='_blank' href='http //switch.meraki.com/'>switch.meraki.com, </a><a target='_blank'
      href='http //wired.meraki.com/'>wired.meraki.com</a>). Optional (defaults to false).
    type: bool
  namedVlans:
    description: A hash of Named VLANs options applied to the Network.
    suboptions:
      enabled:
        description: Enables / disables Named VLANs on the Network.
        type: bool
    type: dict
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  remoteStatusPageEnabled:
    description: Enables / disables access to the device status page (<a target='_blank'>http //device's LAN IP)</a>. Optional. Can only be set
      if localStatusPageEnabled is set to true.
    type: bool
  securePort:
    description: A hash of SecureConnect options applied to the Network.
    suboptions:
      enabled:
        description: Enables / disables SecureConnect on the network. Optional.
        type: bool
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks updateNetworkSettings
    description: Complete reference of the updateNetworkSettings API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-settings
notes:
  - SDK Method used are
    networks.Networks.update_network_settings,
  - Paths used are
    put /networks/{networkId}/settings,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_settings:
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
    localStatusPage:
      authentication:
        enabled: false
        password: miles123
        username: admin
    localStatusPageEnabled: true
    namedVlans:
      enabled: true
    networkId: string
    remoteStatusPageEnabled: true
    securePort:
      enabled: false
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "fips": {
        "enabled": true
      },
      "localStatusPage": {
        "authentication": {
          "enabled": true,
          "username": "string"
        }
      },
      "localStatusPageEnabled": true,
      "namedVlans": {
        "enabled": true
      },
      "remoteStatusPageEnabled": true,
      "securePort": {
        "enabled": true
      }
    }
"""
