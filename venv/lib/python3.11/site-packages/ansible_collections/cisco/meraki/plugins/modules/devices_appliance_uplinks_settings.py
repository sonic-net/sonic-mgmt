#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_appliance_uplinks_settings
short_description: Resource module for devices _appliance _uplinks _settings
description:
  - Manage operation update of the resource devices _appliance _uplinks _settings.
  - Update the uplink settings for an MX appliance.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  interfaces:
    description: Interface settings.
    suboptions:
      wan1:
        description: WAN 1 settings.
        suboptions:
          enabled:
            description: Enable or disable the interface.
            type: bool
          pppoe:
            description: Configuration options for PPPoE.
            suboptions:
              authentication:
                description: Settings for PPPoE Authentication.
                suboptions:
                  enabled:
                    description: Whether PPPoE authentication is enabled.
                    type: bool
                  password:
                    description: Password for PPPoE authentication. This parameter is not returned.
                    type: str
                  username:
                    description: Username for PPPoE authentication.
                    type: str
                type: dict
              enabled:
                description: Whether PPPoE is enabled.
                type: bool
            type: dict
          svis:
            description: SVI settings by protocol.
            suboptions:
              ipv4:
                description: IPv4 settings for static/dynamic mode.
                suboptions:
                  address:
                    description: IP address and subnet mask when in static mode.
                    type: str
                  assignmentMode:
                    description: The assignment mode for this SVI. Applies only when PPPoE is disabled.
                    type: str
                  gateway:
                    description: Gateway IP address when in static mode.
                    type: str
                  nameservers:
                    description: The nameserver settings for this SVI.
                    suboptions:
                      addresses:
                        description: Up to 2 nameserver addresses to use, ordered in priority from highest to lowest priority.
                        elements: str
                        type: list
                    type: dict
                type: dict
              ipv6:
                description: IPv6 settings for static/dynamic mode.
                suboptions:
                  address:
                    description: Static address that will override the one(s) received by SLAAC.
                    type: str
                  assignmentMode:
                    description: The assignment mode for this SVI. Applies only when PPPoE is disabled.
                    type: str
                  gateway:
                    description: Static gateway that will override the one received by autoconf.
                    type: str
                  nameservers:
                    description: The nameserver settings for this SVI.
                    suboptions:
                      addresses:
                        description: Up to 2 nameserver addresses to use, ordered in priority from highest to lowest priority.
                        elements: str
                        type: list
                    type: dict
                type: dict
            type: dict
          vlanTagging:
            description: VLAN tagging settings.
            suboptions:
              enabled:
                description: Whether VLAN tagging is enabled.
                type: bool
              vlanId:
                description: The ID of the VLAN to use for VLAN tagging.
                type: int
            type: dict
        type: dict
      wan2:
        description: WAN 2 settings.
        suboptions:
          enabled:
            description: Enable or disable the interface.
            type: bool
          pppoe:
            description: Configuration options for PPPoE.
            suboptions:
              authentication:
                description: Settings for PPPoE Authentication.
                suboptions:
                  enabled:
                    description: Whether PPPoE authentication is enabled.
                    type: bool
                  password:
                    description: Password for PPPoE authentication. This parameter is not returned.
                    type: str
                  username:
                    description: Username for PPPoE authentication.
                    type: str
                type: dict
              enabled:
                description: Whether PPPoE is enabled.
                type: bool
            type: dict
          svis:
            description: SVI settings by protocol.
            suboptions:
              ipv4:
                description: IPv4 settings for static/dynamic mode.
                suboptions:
                  address:
                    description: IP address and subnet mask when in static mode.
                    type: str
                  assignmentMode:
                    description: The assignment mode for this SVI. Applies only when PPPoE is disabled.
                    type: str
                  gateway:
                    description: Gateway IP address when in static mode.
                    type: str
                  nameservers:
                    description: The nameserver settings for this SVI.
                    suboptions:
                      addresses:
                        description: Up to 2 nameserver addresses to use, ordered in priority from highest to lowest priority.
                        elements: str
                        type: list
                    type: dict
                type: dict
              ipv6:
                description: IPv6 settings for static/dynamic mode.
                suboptions:
                  address:
                    description: Static address that will override the one(s) received by SLAAC.
                    type: str
                  assignmentMode:
                    description: The assignment mode for this SVI. Applies only when PPPoE is disabled.
                    type: str
                  gateway:
                    description: Static gateway that will override the one received by autoconf.
                    type: str
                  nameservers:
                    description: The nameserver settings for this SVI.
                    suboptions:
                      addresses:
                        description: Up to 2 nameserver addresses to use, ordered in priority from highest to lowest priority.
                        elements: str
                        type: list
                    type: dict
                type: dict
            type: dict
          vlanTagging:
            description: VLAN tagging settings.
            suboptions:
              enabled:
                description: Whether VLAN tagging is enabled.
                type: bool
              vlanId:
                description: The ID of the VLAN to use for VLAN tagging.
                type: int
            type: dict
        type: dict
    type: dict
  serial:
    description: Serial path parameter.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateDeviceApplianceUplinksSettings
    description: Complete reference of the updateDeviceApplianceUplinksSettings API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-appliance-uplinks-settings
notes:
  - SDK Method used are
    appliance.Appliance.update_device_appliance_uplinks_settings,
  - Paths used are
    put /devices/{serial}/appliance/uplinks/settings,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.devices_appliance_uplinks_settings:
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
    interfaces:
      wan1:
        enabled: true
        pppoe:
          authentication:
            enabled: true
            password: password
            username: username
          enabled: true
        svis:
          ipv4:
            address: 9.10.11.10/16
            assignmentMode: static
            gateway: 13.14.15.16
            nameservers:
              addresses:
                - 1.2.3.4
          ipv6:
            address: 1:2:3::4
            assignmentMode: static
            gateway: 1:2:3::5
            nameservers:
              addresses:
                - 1001:4860:4860::8888
                - 1001:4860:4860::8844
        vlanTagging:
          enabled: true
          vlanId: 1
      wan2:
        enabled: true
        pppoe:
          authentication:
            enabled: true
            password: password
            username: username
          enabled: true
        svis:
          ipv4:
            address: 9.10.11.10/16
            assignmentMode: static
            gateway: 13.14.15.16
            nameservers:
              addresses:
                - 1.2.3.4
          ipv6:
            address: 1:2:3::4
            assignmentMode: static
            gateway: 1:2:3::5
            nameservers:
              addresses:
                - 1001:4860:4860::8888
                - 1001:4860:4860::8844
        vlanTagging:
          enabled: true
          vlanId: 1
    serial: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "wan1": {
        "enabled": true,
        "pppoe": {
          "authentication": {
            "enabled": true,
            "username": "string"
          },
          "enabled": true
        },
        "svis": {
          "ipv4": {
            "address": "string",
            "assignmentMode": "string",
            "gateway": "string",
            "nameservers": {
              "addresses": [
                "string"
              ]
            }
          },
          "ipv6": {
            "address": "string",
            "assignmentMode": "string",
            "gateway": "string",
            "nameservers": {
              "addresses": [
                "string"
              ]
            }
          }
        },
        "vlanTagging": {
          "enabled": true,
          "vlanId": 0
        }
      },
      "wan2": {
        "enabled": true,
        "pppoe": {
          "authentication": {
            "enabled": true,
            "username": "string"
          },
          "enabled": true
        },
        "svis": {
          "ipv4": {
            "address": "string",
            "assignmentMode": "string",
            "gateway": "string",
            "nameservers": {
              "addresses": [
                "string"
              ]
            }
          },
          "ipv6": {
            "address": "string",
            "assignmentMode": "string",
            "gateway": "string",
            "nameservers": {
              "addresses": [
                "string"
              ]
            }
          }
        },
        "vlanTagging": {
          "enabled": true,
          "vlanId": 0
        }
      }
    }
"""
