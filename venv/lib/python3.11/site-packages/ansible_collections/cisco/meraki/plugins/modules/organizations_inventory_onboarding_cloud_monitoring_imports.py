#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_inventory_onboarding_cloud_monitoring_imports
short_description: Resource module for organizations _inventory _onboarding _cloud _monitoring _imports
description:
  - Manage operation create of the resource organizations _inventory _onboarding _cloud _monitoring _imports.
  - Commits the import operation to complete the onboarding of a device into Dashboard for monitoring.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  devices:
    description: A set of device imports to commit.
    elements: dict
    suboptions:
      deviceId:
        description: Import ID from the Import operation.
        type: str
      networkId:
        description: Network Id.
        type: str
      udi:
        description: Device UDI certificate.
        type: str
    type: list
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations createOrganizationInventoryOnboardingCloudMonitoringImport
    description: Complete reference of the createOrganizationInventoryOnboardingCloudMonitoringImport API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-inventory-onboarding-cloud-monitoring-import
notes:
  - SDK Method used are
    organizations.Organizations.create_organization_inventory_onboarding_cloud_monitoring_import,
  - Paths used are
    post /organizations/{organizationId}/inventory/onboarding/cloudMonitoring/imports,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_inventory_onboarding_cloud_monitoring_imports:
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
    devices:
      - deviceId: 161b2602-a713-4aac-b1eb-d9b55205353d
        networkId: '1338481'
        udi: PID:C9200L-24P-4G SN:JAE25220R2K
    organizationId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: list
  sample: >
    [
      {
        "importId": "string",
        "message": "string",
        "status": "string"
      }
    ]
"""
