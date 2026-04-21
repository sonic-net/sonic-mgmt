#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_wireless_ssids_firewall_isolation_allowlist_entries
short_description: Resource module for organizations _wireless _ssids _firewall _isolation _allowlist _entries
description:
  - Manage operations create, update and delete of the resource organizations _wireless _ssids _firewall _isolation _allowlist _entries.
  - Create isolation allow list MAC entry for this organization.
  - Destroy isolation allow list MAC entry for this organization.
  - Update isolation allow list MAC entry info.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  client:
    description: The client of allowlist.
    suboptions:
      mac:
        description: L2 Isolation mac address.
        type: str
    type: dict
  description:
    description: The description of mac address.
    type: str
  entryId:
    description: EntryId path parameter. Entry ID.
    type: str
  network:
    description: The Network that allowlist belongs to.
    suboptions:
      id:
        description: The ID of network.
        type: str
    type: dict
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  ssid:
    description: The SSID that allowlist belongs to.
    suboptions:
      number:
        description: The number of SSID.
        type: int
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless createOrganizationWirelessSsidsFirewallIsolationAllowlistEntry
    description: Complete reference of the createOrganizationWirelessSsidsFirewallIsolationAllowlistEntry API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-wireless-ssids-firewall-isolation-allowlist-entry
  - name: Cisco Meraki documentation for wireless deleteOrganizationWirelessSsidsFirewallIsolationAllowlistEntry
    description: Complete reference of the deleteOrganizationWirelessSsidsFirewallIsolationAllowlistEntry API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-organization-wireless-ssids-firewall-isolation-allowlist-entry
  - name: Cisco Meraki documentation for wireless updateOrganizationWirelessSsidsFirewallIsolationAllowlistEntry
    description: Complete reference of the updateOrganizationWirelessSsidsFirewallIsolationAllowlistEntry API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-wireless-ssids-firewall-isolation-allowlist-entry
notes:
  - SDK Method used are
    wireless.Wireless.create_organization_wireless_ssids_firewall_isolation_allowlist_entry,
    wireless.Wireless.delete_organization_wireless_ssids_firewall_isolation_allowlist_entry,
    wireless.Wireless.update_organization_wireless_ssids_firewall_isolation_allowlist_entry,
  - Paths used are
    post /organizations/{organizationId}/wireless/ssids/firewall/isolation/allowlist/entries,
    delete /organizations/{organizationId}/wireless/ssids/firewall/isolation/allowlist/entries/{entryId},
    put /organizations/{organizationId}/wireless/ssids/firewall/isolation/allowlist/entries/{entryId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_wireless_ssids_firewall_isolation_allowlist_entries:
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
    client:
      mac: A1:B2:C3:D4:E5:F6
    description: Example mac address
    network:
      id: N_123
    organizationId: string
    ssid:
      number: 2
- name: Delete by id
  cisco.meraki.organizations_wireless_ssids_firewall_isolation_allowlist_entries:
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
    entryId: string
    organizationId: string
- name: Update by id
  cisco.meraki.organizations_wireless_ssids_firewall_isolation_allowlist_entries:
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
    client:
      mac: A1:B2:C3:D4:E5:F6
    description: Example mac address
    entryId: string
    organizationId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "client": {
        "mac": "string"
      },
      "createdAt": "string",
      "description": "string",
      "entryId": "string",
      "lastUpdatedAt": "string",
      "network": {
        "id": "string",
        "name": "string"
      },
      "ssid": {
        "id": "string",
        "name": "string",
        "number": 0
      }
    }
"""
