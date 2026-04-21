#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_policy_objects_groups
short_description: Resource module for organizations _policy _objects _groups
description:
  - Manage operations create, update and delete of the resource organizations _policy _objects _groups.
  - Creates a new Policy Object Group.
  - Deletes a Policy Object Group.
  - Updates a Policy Object Group.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  category:
    description: Category of a policy object group (one of NetworkObjectGroup, GeoLocationGroup, PortObjectGroup, ApplicationGroup).
    type: str
  name:
    description: A name for the group of network addresses, unique within the organization (alphanumeric, space, dash, or underscore characters
      only).
    type: str
  objectIds:
    description: A list of Policy Object ID's that this NetworkObjectGroup should be associated to (note these ID's will replace the existing
      associated Policy Objects).
    elements: int
    type: list
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  policyObjectGroupId:
    description: PolicyObjectGroupId path parameter. Policy object group ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations createOrganizationPolicyObjectsGroup
    description: Complete reference of the createOrganizationPolicyObjectsGroup API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-policy-objects-group
  - name: Cisco Meraki documentation for organizations deleteOrganizationPolicyObjectsGroup
    description: Complete reference of the deleteOrganizationPolicyObjectsGroup API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-organization-policy-objects-group
  - name: Cisco Meraki documentation for organizations updateOrganizationPolicyObjectsGroup
    description: Complete reference of the updateOrganizationPolicyObjectsGroup API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-policy-objects-group
notes:
  - SDK Method used are
    organizations.Organizations.create_organization_policy_objects_group,
    organizations.Organizations.delete_organization_policy_objects_group,
    organizations.Organizations.update_organization_policy_objects_group,
  - Paths used are
    post /organizations/{organizationId}/policyObjects/groups,
    delete /organizations/{organizationId}/policyObjects/groups/{policyObjectGroupId},
    put /organizations/{organizationId}/policyObjects/groups/{policyObjectGroupId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_policy_objects_groups:
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
    category: NetworkObjectGroup
    name: Web Servers - Datacenter 10
    objectIds:
      - 100
    organizationId: string
- name: Delete by id
  cisco.meraki.organizations_policy_objects_groups:
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
    organizationId: string
    policyObjectGroupId: string
- name: Update by id
  cisco.meraki.organizations_policy_objects_groups:
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
    name: Web Servers - Datacenter 10
    objectIds:
      - 100
    organizationId: string
    policyObjectGroupId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "category": "string",
      "createdAt": "string",
      "id": "string",
      "name": "string",
      "networkIds": [
        "string"
      ],
      "objectIds": [
        0
      ],
      "updatedAt": "string"
    }
"""
