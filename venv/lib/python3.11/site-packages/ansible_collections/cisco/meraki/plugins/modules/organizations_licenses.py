#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_licenses
short_description: Resource module for organizations _licenses
description:
  - Manage operation update of the resource organizations _licenses.
  - Update a license.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  deviceSerial:
    description: The serial number of the device to assign this license to. Set this to null to unassign the license. If a different license is
      already active on the device, this parameter will control queueing/dequeuing this license.
    type: str
  licenseId:
    description: LicenseId path parameter. License ID.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations updateOrganizationLicense
    description: Complete reference of the updateOrganizationLicense API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-license
notes:
  - SDK Method used are
    organizations.Organizations.update_organization_license,
  - Paths used are
    put /organizations/{organizationId}/licenses/{licenseId},
"""

EXAMPLES = r"""
- name: Update by id
  cisco.meraki.organizations_licenses:
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
    deviceSerial: Q234-ABCD-5678
    licenseId: string
    organizationId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "activationDate": "string",
      "claimDate": "string",
      "deviceSerial": "string",
      "durationInDays": 0,
      "expirationDate": "string",
      "headLicenseId": "string",
      "id": "string",
      "licenseKey": "string",
      "licenseType": "string",
      "networkId": "string",
      "orderNumber": "string",
      "permanentlyQueuedLicenses": [
        {
          "durationInDays": 0,
          "id": "string",
          "licenseKey": "string",
          "licenseType": "string",
          "orderNumber": "string"
        }
      ],
      "seatCount": 0,
      "state": "string",
      "totalDurationInDays": 0
    }
"""
