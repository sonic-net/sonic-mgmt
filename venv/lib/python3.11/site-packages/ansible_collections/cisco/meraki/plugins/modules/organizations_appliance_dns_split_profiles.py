#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_appliance_dns_split_profiles
short_description: Resource module for organizations _appliance _dns _split _profiles
description:
  - Manage operation create of the resource organizations _appliance _dns _split _profiles.
  - Create a new split DNS profile.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  hostnames:
    description: The hostname patterns to match for redirection. For more information on Split DNS hostname pattern formatting, please consult
      the Split DNS KB.
    elements: str
    type: list
  name:
    description: Name of profile.
    type: str
  nameservers:
    description: Contains the nameserver information for redirection.
    suboptions:
      addresses:
        description: The nameserver address(es) to use for redirection. A maximum of one address is supported.
        elements: str
        type: list
    type: dict
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance createOrganizationApplianceDnsSplitProfile
    description: Complete reference of the createOrganizationApplianceDnsSplitProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-appliance-dns-split-profile
notes:
  - SDK Method used are
    appliance.Appliance.create_organization_appliance_dns_split_profile,
  - Paths used are
    post /organizations/{organizationId}/appliance/dns/split/profiles,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_appliance_dns_split_profiles:
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
    hostnames:
      - '*.test1.com'
      - '*.test2.com'
    name: Default profile
    nameservers:
      addresses:
        - 12.1.10.1
    organizationId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "hostnames": [
        "string"
      ],
      "name": "string",
      "nameservers": {
        "addresses": [
          "string"
        ]
      },
      "profileId": "string"
    }
"""
