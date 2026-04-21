#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_alerts_profiles
short_description: Resource module for organizations _alerts _profiles
description:
  - Manage operations create, update and delete of the resource organizations _alerts _profiles.
  - Create an organization-wide alert configuration.
  - Removes an organization-wide alert config.
  - Update an organization-wide alert config.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  alertCondition:
    description: The conditions that determine if the alert triggers.
    suboptions:
      bit_rate_bps:
        description: The threshold the metric must cross to be valid for alerting. Used only for WAN Utilization alerts.
        type: int
      duration:
        description: The total duration in seconds that the threshold should be crossed before alerting.
        type: int
      interface:
        description: The uplink observed for the alert. Interface must be one of the following wan1, wan2, wan3, cellular.
        type: str
      jitter_ms:
        description: The threshold the metric must cross to be valid for alerting. Used only for VoIP Jitter alerts.
        type: int
      latency_ms:
        description: The threshold the metric must cross to be valid for alerting. Used only for WAN Latency alerts.
        type: int
      loss_ratio:
        description: The threshold the metric must cross to be valid for alerting. Used only for Packet Loss alerts.
        type: float
      mos:
        description: The threshold the metric must drop below to be valid for alerting. Used only for VoIP MOS alerts.
        type: float
      window:
        description: The look back period in seconds for sensing the alert.
        type: int
    type: dict
  alertConfigId:
    description: AlertConfigId path parameter. Alert config ID.
    type: str
  description:
    description: User supplied description of the alert.
    type: str
  enabled:
    description: Is the alert config enabled.
    type: bool
  networkTags:
    description: Networks with these tags will be monitored for the alert.
    elements: str
    type: list
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  recipients:
    description: List of recipients that will recieve the alert.
    suboptions:
      emails:
        description: A list of emails that will receive information about the alert.
        elements: str
        type: list
      httpServerIds:
        description: A list base64 encoded urls of webhook endpoints that will receive information about the alert.
        elements: str
        type: list
    type: dict
  type:
    description: The alert type.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations createOrganizationAlertsProfile
    description: Complete reference of the createOrganizationAlertsProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-alerts-profile
  - name: Cisco Meraki documentation for organizations deleteOrganizationAlertsProfile
    description: Complete reference of the deleteOrganizationAlertsProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-organization-alerts-profile
  - name: Cisco Meraki documentation for organizations updateOrganizationAlertsProfile
    description: Complete reference of the updateOrganizationAlertsProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-alerts-profile
notes:
  - SDK Method used are
    organizations.Organizations.create_organization_alerts_profile,
    organizations.Organizations.delete_organization_alerts_profile,
    organizations.Organizations.update_organization_alerts_profile,
  - Paths used are
    post /organizations/{organizationId}/alerts/profiles,
    delete /organizations/{organizationId}/alerts/profiles/{alertConfigId},
    put /organizations/{organizationId}/alerts/profiles/{alertConfigId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_alerts_profiles:
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
    alertCondition:
      bit_rate_bps: 10000
      duration: 60
      interface: wan1
      jitter_ms: 100
      latency_ms: 100
      loss_ratio: 0.1
      mos: 3.5
      window: 600
    description: WAN 1 high utilization
    networkTags:
      - tag1
      - tag2
    organizationId: string
    recipients:
      emails:
        - admin@example.org
      httpServerIds:
        - aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vcGF0aA==
    type: wanUtilization
- name: Delete by id
  cisco.meraki.organizations_alerts_profiles:
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
    alertConfigId: string
    organizationId: string
- name: Update by id
  cisco.meraki.organizations_alerts_profiles:
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
    alertCondition:
      bit_rate_bps: 10000
      duration: 60
      interface: wan1
      jitter_ms: 100
      latency_ms: 100
      loss_ratio: 0.1
      mos: 3.5
      window: 600
    alertConfigId: string
    description: WAN 1 high utilization
    enabled: true
    networkTags:
      - tag1
      - tag2
    organizationId: string
    recipients:
      emails:
        - admin@example.org
      httpServerIds:
        - aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vcGF0aA==
    type: wanUtilization
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "alertCondition": {
        "bit_rate_bps": 0,
        "duration": 0,
        "interface": "string",
        "window": 0
      },
      "description": "string",
      "enabled": true,
      "id": "string",
      "networkTags": [
        "string"
      ],
      "recipients": {
        "emails": [
          "string"
        ],
        "httpServerIds": [
          "string"
        ]
      },
      "type": "string"
    }
"""
