#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_policy_objects
short_description: Resource module for organizations _policy _objects
description:
  - Manage operations create, update and delete of the resource organizations _policy _objects.
  - Creates a new Policy Object.
  - Deletes a Policy Object.
  - Updates a Policy Object.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  category:
    description: Category of a policy object (one of adaptivePolicy, network).
    type: str
  cidr:
    description: CIDR Value of a policy object (e.g. 10.11.12.1/24").
    type: str
  fqdn:
    description: Fully qualified domain name of policy object (e.g. "example.com").
    type: str
  groupIds:
    description: The IDs of policy object groups the policy object belongs to.
    elements: str
    type: list
  ip:
    description: IP Address of a policy object (e.g. "1.2.3.4").
    type: str
  mask:
    description: Mask of a policy object (e.g. "255.255.0.0").
    type: str
  name:
    description: Name of a policy object, unique within the organization (alphanumeric, space, dash, or underscore characters only).
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  policyObjectId:
    description: PolicyObjectId path parameter. Policy object ID.
    type: str
  type:
    description: Type of a policy object (one of adaptivePolicyIpv4Cidr, cidr, fqdn, ipAndMask).
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations createOrganizationPolicyObject
    description: Complete reference of the createOrganizationPolicyObject API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-policy-object
  - name: Cisco Meraki documentation for organizations deleteOrganizationPolicyObject
    description: Complete reference of the deleteOrganizationPolicyObject API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-organization-policy-object
  - name: Cisco Meraki documentation for organizations updateOrganizationPolicyObject
    description: Complete reference of the updateOrganizationPolicyObject API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-policy-object
notes:
  - SDK Method used are
    organizations.Organizations.create_organization_policy_object,
    organizations.Organizations.delete_organization_policy_object,
    organizations.Organizations.update_organization_policy_object,
  - Paths used are
    post /organizations/{organizationId}/policyObjects,
    delete /organizations/{organizationId}/policyObjects/{policyObjectId},
    put /organizations/{organizationId}/policyObjects/{policyObjectId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_policy_objects:
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
    category: network
    cidr: 10.0.0.0/24
    fqdn: example.com
    groupIds:
      - '8'
    ip: 1.2.3.4
    mask: 255.255.0.0
    name: Web Servers - Datacenter 10
    organizationId: string
    type: cidr
- name: Delete by id
  cisco.meraki.organizations_policy_objects:
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
    policyObjectId: string
- name: Update by id
  cisco.meraki.organizations_policy_objects:
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
    cidr: 10.0.0.0/24
    fqdn: example.com
    groupIds:
      - '8'
    ip: 1.2.3.4
    mask: 255.255.0.0
    name: Web Servers - Datacenter 10
    organizationId: string
    policyObjectId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "category": "string",
      "cidr": "string",
      "createdAt": "string",
      "groupIds": [
        "string"
      ],
      "id": "string",
      "name": "string",
      "networkIds": [
        "string"
      ],
      "type": "string",
      "updatedAt": "string"
    }
"""
