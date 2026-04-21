#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_sm_admins_roles
short_description: Resource module for organizations _sm _admins _roles
description:
  - Manage operations create, update and delete of the resource organizations _sm _admins _roles.
  - Create a Limited Access Role.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  name:
    description: The name of the Limited Access Role.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  scope:
    description: The scope of the Limited Access Role.
    type: str
  tags:
    description: The tags of the Limited Access Role.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for sm createOrganizationSmAdminsRole
    description: Complete reference of the createOrganizationSmAdminsRole API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-sm-admins-role
notes:
  - SDK Method used are
    sm.Sm.create_organization_sm_admins_role,
  - Paths used are
    post /organizations/{organizationId}/sm/admins/roles,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_sm_admins_roles:
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
    name: sample name
    organizationId: string
    scope: all_tags
    tags:
      - tag
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "name": "string",
      "roleId": "string",
      "scope": "string",
      "tags": [
        "string"
      ]
    }
"""
