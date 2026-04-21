#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_admins
short_description: Resource module for organizations _admins
description:
  - Manage operations create, update and delete of the resource organizations _admins.
  - Create a new dashboard administrator.
  - Revoke all access for a dashboard administrator within this organization.
  - Update an administrator.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  adminId:
    description: AdminId path parameter. Admin ID.
    type: str
  authenticationMethod:
    description: No longer used as of Cisco SecureX end-of-life. Can be one of 'Email'. The default is Email authentication.
    type: str
  email:
    description: The email of the dashboard administrator. This attribute can not be updated.
    type: str
  name:
    description: The name of the dashboard administrator.
    type: str
  networks:
    description: The list of networks that the dashboard administrator has privileges on.
    elements: dict
    suboptions:
      access:
        description: The privilege of the dashboard administrator on the network. Can be one of 'full', 'read-only', 'guest-ambassador' or 'monitor-only'.
        type: str
      id:
        description: The network ID.
        type: str
    type: list
  orgAccess:
    description: The privilege of the dashboard administrator on the organization. Can be one of 'full', 'read-only', 'enterprise' or 'none'.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  tags:
    description: The list of tags that the dashboard administrator has privileges on.
    elements: dict
    suboptions:
      access:
        description: The privilege of the dashboard administrator on the tag. Can be one of 'full', 'read-only', 'guest-ambassador' or 'monitor-only'.
        type: str
      tag:
        description: The name of the tag.
        type: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations createOrganizationAdmin
    description: Complete reference of the createOrganizationAdmin API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-admin
  - name: Cisco Meraki documentation for organizations deleteOrganizationAdmin
    description: Complete reference of the deleteOrganizationAdmin API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-organization-admin
  - name: Cisco Meraki documentation for organizations updateOrganizationAdmin
    description: Complete reference of the updateOrganizationAdmin API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-admin
notes:
  - SDK Method used are
    organizations.Organizations.create_organization_admin,
    organizations.Organizations.delete_organization_admin,
    organizations.Organizations.update_organization_admin,
  - Paths used are
    post /organizations/{organizationId}/admins,
    delete /organizations/{organizationId}/admins/{adminId},
    put /organizations/{organizationId}/admins/{adminId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_admins:
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
    authenticationMethod: Email
    email: miles@meraki.com
    name: Miles Meraki
    networks:
      - access: full
        id: N_24329156
    orgAccess: none
    organizationId: string
    tags:
      - access: read-only
        tag: west
- name: Delete by id
  cisco.meraki.organizations_admins:
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
    adminId: string
    organizationId: string
- name: Update by id
  cisco.meraki.organizations_admins:
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
    adminId: string
    name: Miles Meraki
    networks:
      - access: full
        id: N_24329156
    orgAccess: none
    organizationId: string
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
      "accountStatus": "string",
      "authenticationMethod": "string",
      "email": "string",
      "hasApiKey": true,
      "id": "string",
      "lastActive": "string",
      "name": "string",
      "networks": [
        {
          "access": "string",
          "id": "string"
        }
      ],
      "orgAccess": "string",
      "tags": [
        {
          "access": "string",
          "tag": "string"
        }
      ],
      "twoFactorAuthEnabled": true
    }
"""
