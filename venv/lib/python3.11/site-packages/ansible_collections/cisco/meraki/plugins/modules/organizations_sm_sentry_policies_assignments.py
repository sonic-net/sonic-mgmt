#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_sm_sentry_policies_assignments
short_description: Resource module for organizations _sm _sentry _policies _assignments
description:
  - Manage operation update of the resource organizations _sm _sentry _policies _assignments. - > Update an Organizations Sentry Policies using
    the provided list. Sentry Policies are ordered in descending order of priority i.e. Highest priority at the bottom, this is opposite the Dashboard
    UI. Policies not present in the request will be deleted.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  items:
    description: Sentry Group Policies for the Organization keyed by Network Id.
    elements: dict
    suboptions:
      networkId:
        description: The Id of the Network.
        type: str
      policies:
        description: Array of Sentry Group Policies for the Network.
        elements: dict
        suboptions:
          groupPolicyId:
            description: The Group Policy Id.
            type: str
          policyId:
            description: The Sentry Policy Id, if updating an existing Sentry Policy.
            type: str
          scope:
            description: The scope of the Sentry Policy.
            type: str
          smNetworkId:
            description: The Id of the Systems Manager Network.
            type: str
          tags:
            description: The tags for the Sentry Policy.
            elements: str
            type: list
        type: list
    type: list
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for sm updateOrganizationSmSentryPoliciesAssignments
    description: Complete reference of the updateOrganizationSmSentryPoliciesAssignments API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-sm-sentry-policies-assignments
notes:
  - SDK Method used are
    sm.Sm.update_organization_sm_sentry_policies_assignments,
  - Paths used are
    put /organizations/{organizationId}/sm/sentry/policies/assignments,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.organizations_sm_sentry_policies_assignments:
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
    items:
      - networkId: N_24329156
        policies:
          - groupPolicyId: '1284392014819'
            policyId: '1284392014819'
            scope: withAny
            smNetworkId: N_24329156
            tags:
              - tag1
              - tag2
    organizationId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "items": [
        {
          "networkId": "string",
          "policies": [
            {
              "createdAt": "string",
              "groupNumber": "string",
              "groupPolicyId": "string",
              "lastUpdatedAt": "string",
              "networkId": "string",
              "policyId": "string",
              "priority": "string",
              "scope": "string",
              "smNetworkId": "string",
              "tags": [
                "string"
              ]
            }
          ]
        }
      ]
    }
"""
