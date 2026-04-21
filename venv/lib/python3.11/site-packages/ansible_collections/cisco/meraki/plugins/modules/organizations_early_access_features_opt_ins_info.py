#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_early_access_features_opt_ins_info
short_description: Information module for organizations _early _access _features _opt _ins
description:
  - Get all organizations _early _access _features _opt _ins.
  - Get organizations _early _access _features _opt _ins by id.
  - List the early access feature opt-ins for an organization.
  - Show an early access feature opt-in for an organization.
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
  optInId:
    description:
      - OptInId path parameter. Opt in ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations getOrganizationEarlyAccessFeaturesOptIn
    description: Complete reference of the getOrganizationEarlyAccessFeaturesOptIn API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-early-access-features-opt-in
  - name: Cisco Meraki documentation for organizations getOrganizationEarlyAccessFeaturesOptIns
    description: Complete reference of the getOrganizationEarlyAccessFeaturesOptIns API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-early-access-features-opt-ins
notes:
  - SDK Method used are
    organizations.Organizations.get_organization_early_access_features_opt_in,
    organizations.Organizations.get_organization_early_access_features_opt_ins,
  - Paths used are
    get /organizations/{organizationId}/earlyAccess/features/optIns,
    get /organizations/{organizationId}/earlyAccess/features/optIns/{optInId},
"""

EXAMPLES = r"""
- name: Get all organizations _early _access _features _opt _ins
  cisco.meraki.organizations_early_access_features_opt_ins_info:
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
  register: result
- name: Get organizations _early _access _features _opt _ins by id
  cisco.meraki.organizations_early_access_features_opt_ins_info:
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
    optInId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "createdAt": "string",
      "id": "string",
      "limitScopeToNetworks": [
        {
          "id": "string",
          "name": "string"
        }
      ],
      "optOutEligibility": {
        "eligible": true,
        "help": {
          "label": "string",
          "url": "string"
        },
        "reason": "string"
      },
      "shortName": "string"
    }
"""
