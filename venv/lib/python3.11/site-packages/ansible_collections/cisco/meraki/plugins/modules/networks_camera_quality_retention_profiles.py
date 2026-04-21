#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_camera_quality_retention_profiles
short_description: Resource module for networks _camera _quality _retention _profiles
description:
  - Manage operations create, update and delete of the resource networks _camera _quality _retention _profiles.
  - Creates new quality retention profile for this network.
  - Delete an existing quality retention profile for this network.
  - Update an existing quality retention profile for this network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  audioRecordingEnabled:
    description: Whether or not to record audio. Can be either true or false. Defaults to false.
    type: bool
  cloudArchiveEnabled:
    description: Create redundant video backup using Cloud Archive. Can be either true or false. Defaults to false.
    type: bool
  maxRetentionDays:
    description: The maximum number of days for which the data will be stored, or 'null' to keep data until storage space runs out. If the former,
      it can be in the range of one to ninety days.
    type: int
  motionBasedRetentionEnabled:
    description: Deletes footage older than 3 days in which no motion was detected. Can be either true or false. Defaults to false. This setting
      does not apply to MV2 cameras.
    type: bool
  motionDetectorVersion:
    description: The version of the motion detector that will be used by the camera. Only applies to Gen 2 cameras. Defaults to v2.
    type: int
  name:
    description: The name of the new profile. Must be unique. This parameter is required.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  qualityRetentionProfileId:
    description: QualityRetentionProfileId path parameter. Quality retention profile ID.
    type: str
  restrictedBandwidthModeEnabled:
    description: Disable features that require additional bandwidth such as Motion Recap. Can be either true or false. Defaults to false. This
      setting does not apply to MV2 cameras.
    type: bool
  scheduleId:
    description: Schedule for which this camera will record video, or 'null' to always record.
    type: str
  smartRetention:
    description: Smart Retention records footage in two qualities and intelligently retains higher quality when motion, people or vehicles are
      detected.
    suboptions:
      enabled:
        description: Boolean indicating if Smart Retention is enabled(true) or disabled(false).
        type: bool
    type: dict
  videoSettings:
    description: Video quality and resolution settings for all the camera models.
    suboptions:
      MV12/MV22/MV72:
        description: Quality and resolution for MV12/MV22/MV72 camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1280x720' or '1920x1080'.
            type: str
        type: dict
      MV12WE:
        description: Quality and resolution for MV12WE camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1280x720' or '1920x1080'.
            type: str
        type: dict
      MV13:
        description: Quality and resolution for MV13 camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1920x1080', '2688x1512' or '3840x2160'.
            type: str
        type: dict
      MV13M:
        description: Quality and resolution for MV13M camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1920x1080', '2688x1512' or '3840x2160'.
            type: str
        type: dict
      MV21/MV71:
        description: Quality and resolution for MV21/MV71 camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1280x720'.
            type: str
        type: dict
      MV22X/MV72X:
        description: Quality and resolution for MV22X/MV72X camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1280x720', '1920x1080' or '2688x1512'.
            type: str
        type: dict
      MV23:
        description: Quality and resolution for MV23 camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1920x1080', '2688x1512' or '3840x2160'.
            type: str
        type: dict
      MV23M:
        description: Quality and resolution for MV23M camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1920x1080', '2688x1512' or '3840x2160'.
            type: str
        type: dict
      MV23X:
        description: Quality and resolution for MV23X camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1920x1080', '2688x1512' or '3840x2160'.
            type: str
        type: dict
      MV32:
        description: Quality and resolution for MV32 camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1080x1080' or '2112x2112'.
            type: str
        type: dict
      MV33:
        description: Quality and resolution for MV33 camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1080x1080', '2112x2112' or '2880x2880'.
            type: str
        type: dict
      MV33M:
        description: Quality and resolution for MV33M camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1080x1080', '2112x2112' or '2880x2880'.
            type: str
        type: dict
      MV52:
        description: Quality and resolution for MV52 camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1280x720', '1920x1080', '2688x1512' or '3840x2160'.
            type: str
        type: dict
      MV53X:
        description: Quality and resolution for MV53X camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1920x1080', '2688x1512' or '3840x2160'.
            type: str
        type: dict
      MV63:
        description: Quality and resolution for MV63 camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1920x1080', '2688x1512' or '3840x2160'.
            type: str
        type: dict
      MV63M:
        description: Quality and resolution for MV63M camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1920x1080', '2688x1512' or '3840x2160'.
            type: str
        type: dict
      MV63X:
        description: Quality and resolution for MV63X camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1920x1080', '2688x1512' or '3840x2160'.
            type: str
        type: dict
      MV73:
        description: Quality and resolution for MV73 camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1920x1080', '2688x1512' or '3840x2160'.
            type: str
        type: dict
      MV73M:
        description: Quality and resolution for MV73M camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1920x1080', '2688x1512' or '3840x2160'.
            type: str
        type: dict
      MV73X:
        description: Quality and resolution for MV73X camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1920x1080', '2688x1512' or '3840x2160'.
            type: str
        type: dict
      MV84X:
        description: Quality and resolution for MV84X camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard' or 'Enhanced'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1440x1080' or '2560x1920'.
            type: str
        type: dict
      MV93:
        description: Quality and resolution for MV93 camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1080x1080', '2112x2112' or '2880x2880'.
            type: str
        type: dict
      MV93M:
        description: Quality and resolution for MV93M camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1080x1080', '2112x2112' or '2880x2880'.
            type: str
        type: dict
      MV93X:
        description: Quality and resolution for MV93X camera models.
        suboptions:
          quality:
            description: Quality of the camera. Can be one of 'Standard', 'Enhanced' or 'High'.
            type: str
          resolution:
            description: Resolution of the camera. Can be one of '1080x1080', '2112x2112' or '2880x2880'.
            type: str
        type: dict
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for camera createNetworkCameraQualityRetentionProfile
    description: Complete reference of the createNetworkCameraQualityRetentionProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-camera-quality-retention-profile
  - name: Cisco Meraki documentation for camera deleteNetworkCameraQualityRetentionProfile
    description: Complete reference of the deleteNetworkCameraQualityRetentionProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-camera-quality-retention-profile
  - name: Cisco Meraki documentation for camera updateNetworkCameraQualityRetentionProfile
    description: Complete reference of the updateNetworkCameraQualityRetentionProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-camera-quality-retention-profile
notes:
  - SDK Method used are
    camera.Camera.create_network_camera_quality_retention_profile,
    camera.Camera.delete_network_camera_quality_retention_profile,
    camera.Camera.update_network_camera_quality_retention_profile,
  - Paths used are
    post /networks/{networkId}/camera/qualityRetentionProfiles,
    delete /networks/{networkId}/camera/qualityRetentionProfiles/{qualityRetentionProfileId},
    put /networks/{networkId}/camera/qualityRetentionProfiles/{qualityRetentionProfileId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_camera_quality_retention_profiles:
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
    name: Sample quality retention profile
    networkId: string
- name: Delete by id
  cisco.meraki.networks_camera_quality_retention_profiles:
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
    networkId: string
    qualityRetentionProfileId: string
- name: Update by id
  cisco.meraki.networks_camera_quality_retention_profiles:
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
    audioRecordingEnabled: true
    cloudArchiveEnabled: true
    maxRetentionDays: 0
    motionBasedRetentionEnabled: true
    motionDetectorVersion: 0
    name: string
    networkId: string
    qualityRetentionProfileId: string
    restrictedBandwidthModeEnabled: true
    scheduleId: string
    smartRetention:
      enabled: true
    videoSettings:
      MV12/MV22/MV72:
        quality: string
        resolution: string
      MV12WE:
        quality: string
        resolution: string
      MV13:
        quality: string
        resolution: string
      MV13M:
        quality: string
        resolution: string
      MV21/MV71:
        quality: string
        resolution: string
      MV22X/MV72X:
        quality: string
        resolution: string
      MV23:
        quality: string
        resolution: string
      MV23M:
        quality: string
        resolution: string
      MV23X:
        quality: string
        resolution: string
      MV32:
        quality: string
        resolution: string
      MV33:
        quality: string
        resolution: string
      MV33M:
        quality: string
        resolution: string
      MV52:
        quality: string
        resolution: string
      MV53X:
        quality: string
        resolution: string
      MV63:
        quality: string
        resolution: string
      MV63M:
        quality: string
        resolution: string
      MV63X:
        quality: string
        resolution: string
      MV73:
        quality: string
        resolution: string
      MV73M:
        quality: string
        resolution: string
      MV73X:
        quality: string
        resolution: string
      MV84X:
        quality: string
        resolution: string
      MV93:
        quality: string
        resolution: string
      MV93M:
        quality: string
        resolution: string
      MV93X:
        quality: string
        resolution: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
