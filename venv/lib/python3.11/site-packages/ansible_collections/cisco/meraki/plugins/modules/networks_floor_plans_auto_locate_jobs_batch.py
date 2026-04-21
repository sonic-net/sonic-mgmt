#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_floor_plans_auto_locate_jobs_batch
short_description: Resource module for networks _floor _plans _auto _locate _jobs _batch
description:
  - Manage operation create of the resource networks _floor _plans _auto _locate _jobs _batch.
  - Schedule auto locate jobs for one or more floor plans in a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  jobs:
    description: The list of auto locate jobs to be scheduled. Up to 100 jobs can be provided in a request.
    elements: dict
    suboptions:
      floorPlanId:
        description: The ID of the floor plan to run auto locate for.
        type: str
      refresh:
        description: The types of location data that should be refreshed for this job. The list must either contain both 'gnss' and 'ranging'
          or be empty, as we currently only support refreshing both 'gnss' and 'ranging', or neither.
        elements: str
        type: list
      scheduledAt:
        description: Timestamp in ISO8601 format which indicates when the auto locate job should be run. If omitted, the auto locate job will
          start immediately.
        type: str
    type: list
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks batchNetworkFloorPlansAutoLocateJobs
    description: Complete reference of the batchNetworkFloorPlansAutoLocateJobs API.
    link: https://developer.cisco.com/meraki/api-v1/#!batch-network-floor-plans-auto-locate-jobs
notes:
  - SDK Method used are
    networks.Networks.batch_network_floor_plans_auto_locate_jobs,
  - Paths used are
    post /networks/{networkId}/floorPlans/autoLocate/jobs/batch,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_floor_plans_auto_locate_jobs_batch:
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
    jobs:
      - floorPlanId: g_2176982374
        refresh:
          - gnss
          - ranging
        scheduledAt: '2018-02-11T00:00:00Z'
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "jobs": [
        {
          "completed": {
            "percentage": 0
          },
          "errors": [
            {
              "source": "string",
              "type": "string"
            }
          ],
          "floorPlanId": "string",
          "gnss": {
            "completed": {
              "percentage": 0
            },
            "status": "string"
          },
          "id": "string",
          "networkId": "string",
          "ranging": {
            "completed": {
              "percentage": 0
            },
            "status": "string"
          },
          "scheduledAt": "string",
          "status": "string"
        }
      ]
    }
"""
