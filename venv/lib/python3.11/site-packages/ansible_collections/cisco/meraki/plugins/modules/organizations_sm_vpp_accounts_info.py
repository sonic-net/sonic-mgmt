#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_sm_vpp_accounts_info
short_description: Information module for organizations _sm _vpp _accounts
description:
  - Get all organizations _sm _vpp _accounts.
  - Get organizations _sm _vpp _accounts by id.
  - Get a hash containing the unparsed token of the VPP account with the given ID.
  - List the VPP accounts in the organization.
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
  vppAccountId:
    description:
      - VppAccountId path parameter. Vpp account ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for sm getOrganizationSmVppAccount
    description: Complete reference of the getOrganizationSmVppAccount API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-sm-vpp-account
  - name: Cisco Meraki documentation for sm getOrganizationSmVppAccounts
    description: Complete reference of the getOrganizationSmVppAccounts API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-sm-vpp-accounts
notes:
  - SDK Method used are
    sm.Sm.get_organization_sm_vpp_account,
    sm.Sm.get_organization_sm_vpp_accounts,
  - Paths used are
    get /organizations/{organizationId}/sm/vppAccounts,
    get /organizations/{organizationId}/sm/vppAccounts/{vppAccountId},
"""

EXAMPLES = r"""
- name: Get all organizations _sm _vpp _accounts
  cisco.meraki.organizations_sm_vpp_accounts_info:
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
- name: Get organizations _sm _vpp _accounts by id
  cisco.meraki.organizations_sm_vpp_accounts_info:
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
    vppAccountId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "allowedAdmins": "string",
      "assignableNetworkIds": [
        "string"
      ],
      "assignableNetworks": "string",
      "contentToken": "string",
      "email": "string",
      "id": "string",
      "lastForceSyncedAt": "string",
      "lastSyncedAt": "string",
      "name": "string",
      "networkIdAdmins": "string",
      "parsedToken": {
        "expiresAt": "string",
        "hashedToken": "string",
        "orgName": "string"
      },
      "vppAccountId": "string",
      "vppLocationId": "string",
      "vppLocationName": "string",
      "vppServiceToken": "string"
    }
"""
