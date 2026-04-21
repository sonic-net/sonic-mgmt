#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_appliance_dns_local_records
short_description: Resource module for organizations _appliance _dns _local _records
description:
  - Manage operation create of the resource organizations _appliance _dns _local _records.
  - Create a new local DNS record.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  address:
    description: IP for the DNS record.
    type: str
  hostname:
    description: Hostname for the DNS record.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  profile:
    description: The profile the DNS record is associated with.
    suboptions:
      id:
        description: Profile ID.
        type: str
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance createOrganizationApplianceDnsLocalRecord
    description: Complete reference of the createOrganizationApplianceDnsLocalRecord API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-appliance-dns-local-record
notes:
  - SDK Method used are
    appliance.Appliance.create_organization_appliance_dns_local_record,
  - Paths used are
    post /organizations/{organizationId}/appliance/dns/local/records,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_appliance_dns_local_records:
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
    address: 10.1.1.0
    hostname: www.test.com
    organizationId: string
    profile:
      id: '1'
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: list
  sample: >
    [
      {
        "address": "string",
        "hostname": "string",
        "profile": {
          "id": "string"
        },
        "recordId": "string"
      }
    ]
"""
