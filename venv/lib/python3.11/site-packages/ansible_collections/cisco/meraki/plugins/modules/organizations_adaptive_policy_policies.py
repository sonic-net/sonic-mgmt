#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_adaptive_policy_policies
short_description: Resource module for organizations _adaptive _policy _policies
description:
  - Manage operations create, update and delete of the resource organizations _adaptive _policy _policies.
  - Add an Adaptive Policy.
  - Delete an Adaptive Policy.
  - Update an Adaptive Policy.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  acls:
    description: An ordered array of adaptive policy ACLs (each requires one unique attribute) that apply to this policy (default ).
    elements: dict
    suboptions:
      id:
        description: The ID of the adaptive policy ACL.
        type: str
      name:
        description: The name of the adaptive policy ACL.
        type: str
    type: list
  destinationGroup:
    description: The destination adaptive policy group (requires one unique attribute).
    suboptions:
      id:
        description: The ID of the destination adaptive policy group.
        type: str
      name:
        description: The name of the destination adaptive policy group.
        type: str
      sgt:
        description: The SGT of the destination adaptive policy group.
        type: int
    type: dict
  id:
    description: Id path parameter.
    type: str
  lastEntryRule:
    description: The rule to apply if there is no matching ACL (default "default").
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  sourceGroup:
    description: The source adaptive policy group (requires one unique attribute).
    suboptions:
      id:
        description: The ID of the source adaptive policy group.
        type: str
      name:
        description: The name of the source adaptive policy group.
        type: str
      sgt:
        description: The SGT of the source adaptive policy group.
        type: int
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations createOrganizationAdaptivePolicyPolicy
    description: Complete reference of the createOrganizationAdaptivePolicyPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-adaptive-policy-policy
  - name: Cisco Meraki documentation for organizations deleteOrganizationAdaptivePolicyPolicy
    description: Complete reference of the deleteOrganizationAdaptivePolicyPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-organization-adaptive-policy-policy
  - name: Cisco Meraki documentation for organizations updateOrganizationAdaptivePolicyPolicy
    description: Complete reference of the updateOrganizationAdaptivePolicyPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-adaptive-policy-policy
notes:
  - SDK Method used are
    organizations.Organizations.create_organization_adaptive_policy_policy,
    organizations.Organizations.delete_organization_adaptive_policy_policy,
    organizations.Organizations.update_organization_adaptive_policy_policy,
  - Paths used are
    post /organizations/{organizationId}/adaptivePolicy/policies,
    delete /organizations/{organizationId}/adaptivePolicy/policies/{id},
    put /organizations/{organizationId}/adaptivePolicy/policies/{id},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_adaptive_policy_policies:
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
    acls:
      - id: '444'
        name: Block web
    destinationGroup:
      id: '333'
      name: IoT Servers
      sgt: 51
    lastEntryRule: allow
    organizationId: string
    sourceGroup:
      id: '222'
      name: IoT Devices
      sgt: 50
- name: Delete by id
  cisco.meraki.organizations_adaptive_policy_policies:
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
    id: string
    organizationId: string
- name: Update by id
  cisco.meraki.organizations_adaptive_policy_policies:
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
    acls:
      - id: '444'
        name: Block web
    destinationGroup:
      id: '333'
      name: IoT Servers
      sgt: 51
    id: string
    lastEntryRule: allow
    organizationId: string
    sourceGroup:
      id: '222'
      name: IoT Devices
      sgt: 50
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "acls": [
        {
          "id": "string",
          "name": "string"
        }
      ],
      "adaptivePolicyId": "string",
      "createdAt": "string",
      "destinationGroup": {
        "id": "string",
        "name": "string",
        "sgt": 0
      },
      "lastEntryRule": "string",
      "sourceGroup": {
        "id": "string",
        "name": "string",
        "sgt": 0
      },
      "updatedAt": "string"
    }
"""
