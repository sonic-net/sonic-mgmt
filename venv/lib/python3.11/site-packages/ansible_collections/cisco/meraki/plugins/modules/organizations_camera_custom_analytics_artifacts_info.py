#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_camera_custom_analytics_artifacts_info
short_description: Information module for organizations _camera _custom _analytics _artifacts
description:
  - Get all organizations _camera _custom _analytics _artifacts.
  - Get organizations _camera _custom _analytics _artifacts by id.
  - Get Custom Analytics Artifact.
  - List Custom Analytics Artifacts.
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
  artifactId:
    description:
      - ArtifactId path parameter. Artifact ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for camera getOrganizationCameraCustomAnalyticsArtifact
    description: Complete reference of the getOrganizationCameraCustomAnalyticsArtifact API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-camera-custom-analytics-artifact
  - name: Cisco Meraki documentation for camera getOrganizationCameraCustomAnalyticsArtifacts
    description: Complete reference of the getOrganizationCameraCustomAnalyticsArtifacts API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-camera-custom-analytics-artifacts
notes:
  - SDK Method used are
    camera.Camera.get_organization_camera_custom_analytics_artifact,
    camera.Camera.get_organization_camera_custom_analytics_artifacts,
  - Paths used are
    get /organizations/{organizationId}/camera/customAnalytics/artifacts,
    get /organizations/{organizationId}/camera/customAnalytics/artifacts/{artifactId},
"""

EXAMPLES = r"""
- name: Get all organizations _camera _custom _analytics _artifacts
  cisco.meraki.organizations_camera_custom_analytics_artifacts_info:
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
- name: Get organizations _camera _custom _analytics _artifacts by id
  cisco.meraki.organizations_camera_custom_analytics_artifacts_info:
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
    artifactId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "artifactId": "string",
      "name": "string",
      "organizationId": "string",
      "status": {
        "message": "string",
        "type": "string"
      }
    }
"""
