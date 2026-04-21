#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_insight_monitored_media_servers
short_description: Resource module for organizations _insight _monitored _media _servers
description:
  - Manage operations create, update and delete of the resource organizations _insight _monitored _media _servers.
  - Add a media server to be monitored for this organization. Only valid for organizations with Meraki Insight.
  - Delete a monitored media server from this organization. Only valid for organizations with Meraki Insight.
  - Update a monitored media server for this organization. Only valid for organizations with Meraki Insight.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  address:
    description: The IP address (IPv4 only) or hostname of the media server to monitor.
    type: str
  bestEffortMonitoringEnabled:
    description: Indicates that if the media server doesn't respond to ICMP pings, the nearest hop will be used in its stead.
    type: bool
  monitoredMediaServerId:
    description: MonitoredMediaServerId path parameter. Monitored media server ID.
    type: str
  name:
    description: The name of the VoIP provider.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for insight createOrganizationInsightMonitoredMediaServer
    description: Complete reference of the createOrganizationInsightMonitoredMediaServer API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-insight-monitored-media-server
  - name: Cisco Meraki documentation for insight deleteOrganizationInsightMonitoredMediaServer
    description: Complete reference of the deleteOrganizationInsightMonitoredMediaServer API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-organization-insight-monitored-media-server
  - name: Cisco Meraki documentation for insight updateOrganizationInsightMonitoredMediaServer
    description: Complete reference of the updateOrganizationInsightMonitoredMediaServer API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-organization-insight-monitored-media-server
notes:
  - SDK Method used are
    insight.Insight.create_organization_insight_monitored_media_server,
    insight.Insight.delete_organization_insight_monitored_media_server,
    insight.Insight.update_organization_insight_monitored_media_server,
  - Paths used are
    post /organizations/{organizationId}/insight/monitoredMediaServers,
    delete /organizations/{organizationId}/insight/monitoredMediaServers/{monitoredMediaServerId},
    put /organizations/{organizationId}/insight/monitoredMediaServers/{monitoredMediaServerId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_insight_monitored_media_servers:
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
    address: 123.123.123.1
    bestEffortMonitoringEnabled: true
    name: Sample VoIP Provider
    organizationId: string
- name: Delete by id
  cisco.meraki.organizations_insight_monitored_media_servers:
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
    monitoredMediaServerId: string
    organizationId: string
- name: Update by id
  cisco.meraki.organizations_insight_monitored_media_servers:
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
    address: 123.123.123.1
    bestEffortMonitoringEnabled: true
    monitoredMediaServerId: string
    name: Sample VoIP Provider
    organizationId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "address": "string",
      "bestEffortMonitoringEnabled": true,
      "id": "string",
      "name": "string"
    }
"""
