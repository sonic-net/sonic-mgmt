#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_bind
short_description: Resource module for networks _bind
description:
  - Manage operation create of the resource networks _bind.
  - Bind a network to a template.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  autoBind:
    description: Optional boolean indicating whether the network's switches should automatically bind to profiles of the same model. Defaults
      to false if left unspecified. This option only affects switch networks and switch templates. Auto-bind is not valid unless the switch template
      has at least one profile and has at most one profile per switch model.
    type: bool
  configTemplateId:
    description: The ID of the template to which the network should be bound.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks bindNetwork
    description: Complete reference of the bindNetwork API.
    link: https://developer.cisco.com/meraki/api-v1/#!bind-network
notes:
  - SDK Method used are
    networks.Networks.bind_network,
  - Paths used are
    post /networks/{networkId}/bind,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_bind:
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
    autoBind: false
    configTemplateId: N_23952905
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "configTemplateId": "string",
      "enrollmentString": "string",
      "id": "string",
      "isBoundToConfigTemplate": true,
      "name": "string",
      "notes": "string",
      "organizationId": "string",
      "productTypes": [
        "string"
      ],
      "tags": [
        "string"
      ],
      "timeZone": "string",
      "url": "string"
    }
"""
