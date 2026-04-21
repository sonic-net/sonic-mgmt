#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_early_access_features_opt_ins
short_description: Resource module for organizations _early _access _features _opt _ins
description:
  - Manage operations create, update and delete of the resource organizations _early _access _features _opt _ins.
  - Create a new early access feature opt-in for an organization.
  - Delete an early access feature opt-in.
  - Update an early access feature opt-in for an organization.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  limitScopeToNetworks:
    description: A list of network IDs to apply the opt-in to.
    elements: str
    type: list
  optInId:
    description: OptInId path parameter. Opt in ID.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  shortName:
    description: Short name of the early access feature.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations createOrganizationEarlyAccessFeaturesOptIn
    description: Complete reference of the createOrganizationEarlyAccessFeaturesOptIn API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-early-access-features-opt-in
  - name: Cisco Meraki documentation for organizations deleteOrganizationEarlyAccessFeaturesOptIn
    description: Complete reference of the deleteOrganizationEarlyAccessFeaturesOptIn API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-organization-early-access-features-opt-in
  - name: Cisco Meraki documentation for organizations updateOrganizationEarlyAccessFeaturesOptIn
    description: Complete reference of the updateOrganizationEarlyAccessFeaturesOptIn API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-early-access-features-opt-in
notes:
  - SDK Method used are
    organizations.Organizations.create_organization_early_access_features_opt_in,
    organizations.Organizations.delete_organization_early_access_features_opt_in,
    organizations.Organizations.update_organization_early_access_features_opt_in,
  - Paths used are
    post /organizations/{organizationId}/earlyAccess/features/optIns,
    delete /organizations/{organizationId}/earlyAccess/features/optIns/{optInId},
    put /organizations/{organizationId}/earlyAccess/features/optIns/{optInId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_early_access_features_opt_ins:
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
    limitScopeToNetworks:
      - N_12345
    organizationId: string
    shortName: has_beta_api
- name: Delete by id
  cisco.meraki.organizations_early_access_features_opt_ins:
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
    optInId: string
    organizationId: string
- name: Update by id
  cisco.meraki.organizations_early_access_features_opt_ins:
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
    limitScopeToNetworks:
      - N_12345
    optInId: string
    organizationId: string
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
