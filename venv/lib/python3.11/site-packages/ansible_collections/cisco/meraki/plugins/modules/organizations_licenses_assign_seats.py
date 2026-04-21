#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_licenses_assign_seats
short_description: Resource module for organizations _licenses _assign _seats
description:
  - Manage operation create of the resource organizations _licenses _assign _seats.
  - Assign SM seats to a network. This will increase the managed SM device limit of the network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  licenseId:
    description: The ID of the SM license to assign seats from.
    type: str
  networkId:
    description: The ID of the SM network to assign the seats to.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  seatCount:
    description: The number of seats to assign to the SM network. Must be less than or equal to the total number of seats of the license.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations assignOrganizationLicensesSeats
    description: Complete reference of the assignOrganizationLicensesSeats API.
    link: https://developer.cisco.com/meraki/api-v1/#!assign-organization-licenses-seats
notes:
  - SDK Method used are
    organizations.Organizations.assign_organization_licenses_seats,
  - Paths used are
    post /organizations/{organizationId}/licenses/assignSeats,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_licenses_assign_seats:
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
    licenseId: '1234'
    networkId: N_24329156
    organizationId: string
    seatCount: 20
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
