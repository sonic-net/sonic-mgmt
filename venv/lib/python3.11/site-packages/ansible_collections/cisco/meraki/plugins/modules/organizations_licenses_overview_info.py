#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_licenses_overview_info
short_description: Information module for organizations _licenses _overview
description:
  - Get all organizations _licenses _overview.
  - Return an overview of the license state for an organization.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  organizationId:
    description:
      - OrganizationId path parameter. Organization ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations getOrganizationLicensesOverview
    description: Complete reference of the getOrganizationLicensesOverview API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-licenses-overview
notes:
  - SDK Method used are
    organizations.Organizations.get_organization_licenses_overview,
  - Paths used are
    get /organizations/{organizationId}/licenses/overview,
"""

EXAMPLES = r"""
- name: Get all organizations _licenses _overview
  cisco.meraki.organizations_licenses_overview_info:
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
    organizationId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "expirationDate": "string",
      "licenseCount": 0,
      "licenseTypes": [
        {
          "counts": {
            "unassigned": 0
          },
          "licenseType": "string"
        }
      ],
      "licensedDeviceCounts": {},
      "states": {
        "active": {
          "count": 0
        },
        "expired": {
          "count": 0
        },
        "expiring": {
          "count": 0,
          "critical": {
            "expiringCount": 0,
            "thresholdInDays": 0
          },
          "warning": {
            "expiringCount": 0,
            "thresholdInDays": 0
          }
        },
        "recentlyQueued": {
          "count": 0
        },
        "unused": {
          "count": 0,
          "soonestActivation": {
            "activationDate": "string",
            "toActivateCount": 0
          }
        },
        "unusedActive": {
          "count": 0,
          "oldestActivation": {
            "activationDate": "string",
            "activeCount": 0
          }
        }
      },
      "status": "string",
      "systemsManager": {
        "counts": {
          "activeSeats": 0,
          "orgwideEnrolledDevices": 0,
          "totalSeats": 0,
          "unassignedSeats": 0
        }
      }
    }
"""
