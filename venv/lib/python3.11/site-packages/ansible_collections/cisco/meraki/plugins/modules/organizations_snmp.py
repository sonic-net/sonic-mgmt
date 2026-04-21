#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_snmp
short_description: Resource module for organizations _snmp
description:
  - Manage operation update of the resource organizations _snmp.
  - Update the SNMP settings for an organization.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  peerIps:
    description: The list of IPv4 addresses that are allowed to access the SNMP server.
    elements: str
    type: list
  v2cEnabled:
    description: Boolean indicating whether SNMP version 2c is enabled for the organization.
    type: bool
  v3AuthMode:
    description: The SNMP version 3 authentication mode. Can be either 'MD5' or 'SHA'.
    type: str
  v3AuthPass:
    description: The SNMP version 3 authentication password. Must be at least 8 characters if specified.
    type: str
  v3Enabled:
    description: Boolean indicating whether SNMP version 3 is enabled for the organization.
    type: bool
  v3PrivMode:
    description: The SNMP version 3 privacy mode. Can be either 'DES' or 'AES128'.
    type: str
  v3PrivPass:
    description: The SNMP version 3 privacy password. Must be at least 8 characters if specified.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations updateOrganizationSnmp
    description: Complete reference of the updateOrganizationSnmp API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-snmp
notes:
  - SDK Method used are
    organizations.Organizations.update_organization_snmp,
  - Paths used are
    put /organizations/{organizationId}/snmp,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.organizations_snmp:
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
    organizationId: string
    peerIps:
      - 123.123.123.1
    v2cEnabled: false
    v3AuthMode: SHA
    v3AuthPass: password
    v3Enabled: true
    v3PrivMode: AES128
    v3PrivPass: password
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "hostname": "string",
      "peerIps": [
        "string"
      ],
      "port": 0,
      "v2CommunityString": "string",
      "v2cEnabled": true,
      "v3AuthMode": "string",
      "v3Enabled": true,
      "v3PrivMode": "string",
      "v3User": "string"
    }
"""
