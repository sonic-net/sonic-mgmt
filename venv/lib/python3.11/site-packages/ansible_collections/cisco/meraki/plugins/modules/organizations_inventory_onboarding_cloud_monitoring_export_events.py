#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_inventory_onboarding_cloud_monitoring_export_events
short_description: Resource module for organizations _inventory _onboarding _cloud _monitoring _export _events
description:
  - Manage operation create of the resource organizations _inventory _onboarding _cloud _monitoring _export _events.
  - Imports event logs related to the onboarding app into elastisearch.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  logEvent:
    description: The type of log event this is recording, e.g. Download or opening a banner.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  request:
    description: Used to describe if this event was the result of a redirect. E.g. A query param if an info banner is being used.
    type: str
  targetOS:
    description: The name of the onboarding distro being downloaded.
    type: str
  timestamp:
    description: A JavaScript UTC datetime stamp for when the even occurred.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations createOrganizationInventoryOnboardingCloudMonitoringExportEvent
    description: Complete reference of the createOrganizationInventoryOnboardingCloudMonitoringExportEvent API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-inventory-onboarding-cloud-monitoring-export-event
notes:
  - SDK Method used are
    organizations.Organizations.create_organization_inventory_onboarding_cloud_monitoring_export_event,
  - Paths used are
    post /organizations/{organizationId}/inventory/onboarding/cloudMonitoring/exportEvents,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_inventory_onboarding_cloud_monitoring_export_events:
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
    logEvent: download
    organizationId: string
    request: r=cb
    targetOS: mac
    timestamp: 1526087474
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
