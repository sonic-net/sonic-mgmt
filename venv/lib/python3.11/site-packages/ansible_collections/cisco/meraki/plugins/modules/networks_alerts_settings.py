#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_alerts_settings
short_description: Resource module for networks _alerts _settings
description:
  - Manage operation update of the resource networks _alerts _settings.
  - Update the alert configuration for this network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  alerts:
    description: Alert-specific configuration for each type. Only alerts that pertain to the network can be updated.
    elements: dict
    suboptions:
      alertDestinations:
        description: A hash of destinations for this specific alert.
        suboptions:
          allAdmins:
            description: If true, then all network admins will receive emails for this alert.
            type: bool
          emails:
            description: A list of emails that will receive information about the alert.
            elements: str
            type: list
          httpServerIds:
            description: A list of HTTP server IDs to send a Webhook to for this alert.
            elements: str
            type: list
          smsNumbers:
            description: A list of phone numbers that will receive text messages about the alert. Only available for sensors status alerts.
            elements: str
            type: list
          snmp:
            description: If true, then an SNMP trap will be sent for this alert if there is an SNMP trap server configured for this network.
            type: bool
        type: dict
      enabled:
        description: A boolean depicting if the alert is turned on or off.
        type: bool
      filters:
        description: A hash of specific configuration data for the alert. Only filters specific to the alert will be updated.
        suboptions:
          conditions:
            description: Conditions.
            elements: dict
            suboptions:
              direction:
                description: Direction.
                type: str
              duration:
                description: Duration.
                type: int
              threshold:
                description: Threshold.
                type: float
              type:
                description: Type of condition.
                type: str
              unit:
                description: Unit.
                type: str
            type: list
          failureType:
            description: Failure Type.
            type: str
          lookbackWindow:
            description: Loopback Window (in sec).
            type: int
          minDuration:
            description: Min Duration.
            type: int
          name:
            description: Name.
            type: str
          period:
            description: Period.
            type: int
          priority:
            description: Priority.
            type: str
          regex:
            description: Regex.
            type: str
          selector:
            description: Selector.
            type: str
          serials:
            description: Serials.
            elements: str
            type: list
          ssidNum:
            description: SSID Number.
            type: int
          tag:
            description: Tag.
            type: str
          threshold:
            description: Threshold.
            type: int
          timeout:
            description: Timeout.
            type: int
        type: dict
      type:
        description: The type of alert.
        type: str
    type: list
  defaultDestinations:
    description: The network-wide destinations for all alerts on the network.
    suboptions:
      allAdmins:
        description: If true, then all network admins will receive emails.
        type: bool
      emails:
        description: A list of emails that will receive the alert(s).
        elements: str
        type: list
      httpServerIds:
        description: A list of HTTP server IDs to send a Webhook to.
        elements: str
        type: list
      snmp:
        description: If true, then an SNMP trap will be sent if there is an SNMP trap server configured for this network.
        type: bool
    type: dict
  muting:
    description: Mute alerts under certain conditions.
    suboptions:
      byPortSchedules:
        description: Mute wireless unreachable alerts based on switch port schedules.
        suboptions:
          enabled:
            description: If true, then wireless unreachable alerts will be muted when caused by a port schedule.
            type: bool
        type: dict
    type: dict
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks updateNetworkAlertsSettings
    description: Complete reference of the updateNetworkAlertsSettings API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-alerts-settings
notes:
  - SDK Method used are
    networks.Networks.update_network_alerts_settings,
  - Paths used are
    put /networks/{networkId}/alerts/settings,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_alerts_settings:
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
    alerts:
      - alertDestinations:
          allAdmins: false
          emails:
            - miles@meraki.com
          httpServerIds:
            - aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vd2ViaG9va3M=
          smsNumbers:
            - '+15555555555'
          snmp: false
        enabled: true
        filters:
          conditions:
            - direction: +
              duration: 0
              threshold: 72.5
              type: temperature
              unit: celsius
          failureType: 802.1X auth fail
          lookbackWindow: 360
          minDuration: 60
          name: Filter
          period: 1800
          priority: ''
          regex: '[a-z]'
          selector: '{"smartSensitivity":"medium","smartEnabled":false,"eventReminderPeriodSecs":10800}'
          serials:
            - Q234-ABCD-0001
            - Q234-ABCD-0002
            - Q234-ABCD-0003
          ssidNum: 1
          tag: tag1
          threshold: 30
          timeout: 60
        type: gatewayDown
    defaultDestinations:
      allAdmins: true
      emails:
        - miles@meraki.com
      httpServerIds:
        - aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vd2ViaG9va3M=
      snmp: true
    muting:
      byPortSchedules:
        enabled: true
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "alerts": [
        {
          "alertDestinations": {
            "allAdmins": true,
            "emails": [
              "string"
            ],
            "httpServerIds": [
              "string"
            ],
            "smsNumbers": [
              "string"
            ],
            "snmp": true
          },
          "enabled": true,
          "filters": {
            "conditions": [
              {
                "direction": "string",
                "duration": 0,
                "threshold": 0,
                "type": "string",
                "unit": "string"
              }
            ],
            "failureType": "string",
            "lookbackWindow": 0,
            "minDuration": 0,
            "name": "string",
            "period": 0,
            "priority": "string",
            "regex": "string",
            "selector": "string",
            "serials": [
              "string"
            ],
            "ssidNum": 0,
            "tag": "string",
            "threshold": 0,
            "timeout": 0
          },
          "type": "string"
        }
      ],
      "defaultDestinations": {
        "allAdmins": true,
        "emails": [
          "string"
        ],
        "httpServerIds": [
          "string"
        ],
        "snmp": true
      },
      "muting": {
        "byPortSchedules": {
          "enabled": true
        }
      }
    }
"""
