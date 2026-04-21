#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_saml_roles
short_description: Resource module for organizations _saml _roles
description:
  - Manage operations create, update and delete of the resource organizations _saml _roles.
  - Create a SAML role.
  - Remove a SAML role.
  - Update a SAML role.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  networks:
    description: The list of networks that the SAML administrator has privileges on.
    elements: dict
    suboptions:
      access:
        description: The privilege of the SAML administrator on the network. Can be one of 'full', 'read-only', 'guest-ambassador', 'monitor-only',
          'ssid-admin' or 'port-tags'.
        type: str
      id:
        description: The network ID.
        type: str
    type: list
  orgAccess:
    description: The privilege of the SAML administrator on the organization. Can be one of 'none', 'read-only', 'full' or 'enterprise'.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  role:
    description: The role of the SAML administrator.
    type: str
  samlRoleId:
    description: SamlRoleId path parameter. Saml role ID.
    type: str
  tags:
    description: The list of tags that the SAML administrator has privileges on.
    elements: dict
    suboptions:
      access:
        description: The privilege of the SAML administrator on the tag. Can be one of 'full', 'read-only', 'guest-ambassador' or 'monitor-only'.
        type: str
      tag:
        description: The name of the tag.
        type: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations createOrganizationSamlRole
    description: Complete reference of the createOrganizationSamlRole API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-saml-role
  - name: Cisco Meraki documentation for organizations deleteOrganizationSamlRole
    description: Complete reference of the deleteOrganizationSamlRole API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-organization-saml-role
  - name: Cisco Meraki documentation for organizations updateOrganizationSamlRole
    description: Complete reference of the updateOrganizationSamlRole API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-saml-role
notes:
  - SDK Method used are
    organizations.Organizations.create_organization_saml_role,
    organizations.Organizations.delete_organization_saml_role,
    organizations.Organizations.update_organization_saml_role,
  - Paths used are
    post /organizations/{organizationId}/samlRoles,
    delete /organizations/{organizationId}/samlRoles/{samlRoleId},
    put /organizations/{organizationId}/samlRoles/{samlRoleId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_saml_roles:
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
    networks:
      - access: full
        id: N_24329156
    orgAccess: none
    organizationId: string
    role: myrole
    tags:
      - access: read-only
        tag: west
- name: Delete by id
  cisco.meraki.organizations_saml_roles:
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
    samlRoleId: string
- name: Update by id
  cisco.meraki.organizations_saml_roles:
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
    networks:
      - access: full
        id: N_24329156
    orgAccess: none
    organizationId: string
    role: myrole
    samlRoleId: string
    tags:
      - access: read-only
        tag: west
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "camera": [
        {
          "access": "string",
          "orgWide": true
        }
      ],
      "id": "string",
      "networks": [
        {
          "access": "string",
          "id": "string"
        }
      ],
      "orgAccess": "string",
      "role": "string",
      "tags": [
        {
          "access": "string",
          "tag": "string"
        }
      ]
    }
"""
