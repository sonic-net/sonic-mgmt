#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_branding_policies_info
short_description: Information module for organizations _branding _policies
description:
  - Get all organizations _branding _policies.
  - Get organizations _branding _policies by id.
  - List the branding policies of an organization.
  - Return a branding policy.
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
  brandingPolicyId:
    description:
      - BrandingPolicyId path parameter. Branding policy ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations getOrganizationBrandingPolicies
    description: Complete reference of the getOrganizationBrandingPolicies API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-branding-policies
  - name: Cisco Meraki documentation for organizations getOrganizationBrandingPolicy
    description: Complete reference of the getOrganizationBrandingPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-branding-policy
notes:
  - SDK Method used are
    organizations.Organizations.get_organization_branding_policies,
    organizations.Organizations.get_organization_branding_policy,
  - Paths used are
    get /organizations/{organizationId}/brandingPolicies,
    get /organizations/{organizationId}/brandingPolicies/{brandingPolicyId},
"""

EXAMPLES = r"""
- name: Get all organizations _branding _policies
  cisco.meraki.organizations_branding_policies_info:
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
- name: Get organizations _branding _policies by id
  cisco.meraki.organizations_branding_policies_info:
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
    brandingPolicyId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "adminSettings": {
        "appliesTo": "string",
        "values": [
          "string"
        ]
      },
      "customLogo": {
        "enabled": true,
        "image": {
          "preview": {
            "expiresAt": "string",
            "url": "string"
          }
        }
      },
      "enabled": true,
      "helpSettings": {
        "apiDocsSubtab": "string",
        "casesSubtab": "string",
        "ciscoMerakiProductDocumentation": "string",
        "communitySubtab": "string",
        "dataProtectionRequestsSubtab": "string",
        "firewallInfoSubtab": "string",
        "getHelpSubtab": "string",
        "getHelpSubtabKnowledgeBaseSearch": "string",
        "hardwareReplacementsSubtab": "string",
        "helpTab": "string",
        "helpWidget": "string",
        "newFeaturesSubtab": "string",
        "smForums": "string",
        "supportContactInfo": "string",
        "universalSearchKnowledgeBaseSearch": "string"
      },
      "name": "string"
    }
"""
