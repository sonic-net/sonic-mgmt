#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_adaptive_policy_groups
short_description: Resource module for organizations _adaptive _policy _groups
description:
  - Manage operations create, update and delete of the resource organizations _adaptive _policy _groups.
  - Creates a new adaptive policy group.
  - Deletes the specified adaptive policy group and any associated policies and references.
  - Updates an adaptive policy group. If updating "Infrastructure", only the SGT is allowed. Cannot update "Unknown".
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  description:
    description: Description of the group (default "").
    type: str
  id:
    description: Id path parameter.
    type: str
  name:
    description: Name of the group.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  policyObjects:
    description: The policy objects that belong to this group; traffic from addresses specified by these policy objects will be tagged with this
      group's SGT value if no other tagging scheme is being used (each requires one unique attribute) (default ).
    elements: dict
    suboptions:
      id:
        description: The ID of the policy object.
        type: str
      name:
        description: The name of the policy object.
        type: str
    type: list
  sgt:
    description: SGT value of the group.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations createOrganizationAdaptivePolicyGroup
    description: Complete reference of the createOrganizationAdaptivePolicyGroup API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-adaptive-policy-group
  - name: Cisco Meraki documentation for organizations deleteOrganizationAdaptivePolicyGroup
    description: Complete reference of the deleteOrganizationAdaptivePolicyGroup API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-organization-adaptive-policy-group
  - name: Cisco Meraki documentation for organizations updateOrganizationAdaptivePolicyGroup
    description: Complete reference of the updateOrganizationAdaptivePolicyGroup API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-adaptive-policy-group
notes:
  - SDK Method used are
    organizations.Organizations.create_organization_adaptive_policy_group,
    organizations.Organizations.delete_organization_adaptive_policy_group,
    organizations.Organizations.update_organization_adaptive_policy_group,
  - Paths used are
    post /organizations/{organizationId}/adaptivePolicy/groups,
    delete /organizations/{organizationId}/adaptivePolicy/groups/{id},
    put /organizations/{organizationId}/adaptivePolicy/groups/{id},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_adaptive_policy_groups:
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
    description: Group of XYZ Corp Employees
    name: Employee Group
    organizationId: string
    policyObjects:
      - id: '2345'
        name: Example Policy Object
    sgt: 1000
- name: Delete by id
  cisco.meraki.organizations_adaptive_policy_groups:
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
  cisco.meraki.organizations_adaptive_policy_groups:
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
    description: Group of XYZ Corp Employees
    id: string
    name: Employee Group
    organizationId: string
    policyObjects:
      - id: '2345'
        name: Example Policy Object
    sgt: 1000
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "createdAt": "string",
      "description": "string",
      "groupId": "string",
      "isDefaultGroup": true,
      "name": "string",
      "policyObjects": [
        {
          "id": "string",
          "name": "string"
        }
      ],
      "requiredIpMappings": [
        "string"
      ],
      "sgt": 0,
      "updatedAt": "string"
    }
"""
