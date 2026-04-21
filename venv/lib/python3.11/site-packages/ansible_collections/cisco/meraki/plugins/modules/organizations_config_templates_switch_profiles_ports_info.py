#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_config_templates_switch_profiles_ports_info
short_description: Information module for organizations _config _templates _switch _profiles _ports
description:
  - Get all organizations _config _templates _switch _profiles _ports.
  - Get organizations _config _templates _switch _profiles _ports by id.
  - Return a switch template port.
  - Return all the ports of a switch template.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  organizationId:
    description:
      - OrganizationId path parameter. Organization ID.
    type: str
  configTemplateId:
    description:
      - ConfigTemplateId path parameter. Config template ID.
    type: str
  profileId:
    description:
      - ProfileId path parameter. Profile ID.
    type: str
  portId:
    description:
      - PortId path parameter. Port ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch getOrganizationConfigTemplateSwitchProfilePort
    description: Complete reference of the getOrganizationConfigTemplateSwitchProfilePort API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-config-template-switch-profile-port
  - name: Cisco Meraki documentation for switch getOrganizationConfigTemplateSwitchProfilePorts
    description: Complete reference of the getOrganizationConfigTemplateSwitchProfilePorts API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-config-template-switch-profile-ports
notes:
  - SDK Method used are
    switch.Switch.get_organization_config_template_switch_profile_port,
    switch.Switch.get_organization_config_template_switch_profile_ports,
  - Paths used are
    get /organizations/{organizationId}/configTemplates/{configTemplateId}/switch/profiles/{profileId}/ports,
    get /organizations/{organizationId}/configTemplates/{configTemplateId}/switch/profiles/{profileId}/ports/{portId},
"""

EXAMPLES = r"""
- name: Get all organizations _config _templates _switch _profiles _ports
  cisco.meraki.organizations_config_templates_switch_profiles_ports_info:
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
    organizationId: string
    configTemplateId: string
    profileId: string
  register: result
- name: Get organizations _config _templates _switch _profiles _ports by id
  cisco.meraki.organizations_config_templates_switch_profiles_ports_info:
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
    organizationId: string
    configTemplateId: string
    profileId: string
    portId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "accessPolicyNumber": 0,
      "accessPolicyType": "string",
      "allowedVlans": "string",
      "daiTrusted": true,
      "dot3az": {
        "enabled": true
      },
      "enabled": true,
      "flexibleStackingEnabled": true,
      "isolationEnabled": true,
      "linkNegotiation": "string",
      "linkNegotiationCapabilities": [
        "string"
      ],
      "macAllowList": [
        "string"
      ],
      "mirror": {
        "mode": "string"
      },
      "module": {
        "model": "string"
      },
      "name": "string",
      "poeEnabled": true,
      "portId": "string",
      "portScheduleId": "string",
      "profile": {
        "enabled": true,
        "id": "string",
        "iname": "string"
      },
      "rstpEnabled": true,
      "schedule": {
        "id": "string",
        "name": "string"
      },
      "stackwiseVirtual": {
        "isDualActiveDetector": true,
        "isStackWiseVirtualLink": true
      },
      "stickyMacAllowList": [
        "string"
      ],
      "stickyMacAllowListLimit": 0,
      "stormControlEnabled": true,
      "stpGuard": "string",
      "tags": [
        "string"
      ],
      "type": "string",
      "udld": "string",
      "vlan": 0,
      "voiceVlan": 0
    }
"""
