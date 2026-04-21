#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_devices_details_bulk_update
short_description: Resource module for organizations _devices _details _bulk _update
description:
  - Manage operation create of the resource organizations _devices _details _bulk _update.
  - Updating device details currently only used for Catalyst devices .
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  details:
    description: An array of details.
    elements: dict
    suboptions:
      name:
        description: Name of device detail.
        type: str
      value:
        description: Value of device detail.
        type: str
    type: list
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  serials:
    description: A list of serials of devices to update.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations bulkUpdateOrganizationDevicesDetails
    description: Complete reference of the bulkUpdateOrganizationDevicesDetails API.
    link: https://developer.cisco.com/meraki/api-v1/#!bulk-update-organization-devices-details
notes:
  - SDK Method used are
    organizations.Organizations.bulk_update_organization_devices_details,
  - Paths used are
    post /organizations/{organizationId}/devices/details/bulkUpdate,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_devices_details_bulk_update:
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
    details:
      - name: username
        value: ABC
      - name: password
        value: ABC123
      - name: enable password
        value: ABC123
    organizationId: string
    serials:
      - Q234-ABCD-0001
      - Q234-ABCD-0002
      - Q234-ABCD-0003
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "serials": [
        "string"
      ]
    }
"""
