#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_licenses_renew_seats
short_description: Resource module for organizations _licenses _renew _seats
description:
  - Manage operation create of the resource organizations _licenses _renew _seats. - > Renew SM seats of a license. This will extend the license
    expiration date of managed SM devices covered by this license.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  licenseIdToRenew:
    description: The ID of the SM license to renew. This license must already be assigned to an SM network.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  unusedLicenseId:
    description: The SM license to use to renew the seats on 'licenseIdToRenew'. This license must have at least as many seats available as there
      are seats on 'licenseIdToRenew'.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations renewOrganizationLicensesSeats
    description: Complete reference of the renewOrganizationLicensesSeats API.
    link: https://developer.cisco.com/meraki/api-v1/#!renew-organization-licenses-seats
notes:
  - SDK Method used are
    organizations.Organizations.renew_organization_licenses_seats,
  - Paths used are
    post /organizations/{organizationId}/licenses/renewSeats,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_licenses_renew_seats:
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
    licenseIdToRenew: '123'
    organizationId: string
    unusedLicenseId: '1234'
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "resultingLicenses": [
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
      ]
    }
"""
