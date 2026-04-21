#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_webhooks_payload_templates
short_description: Resource module for networks _webhooks _payload _templates
description:
  - Manage operations create, update and delete of the resource networks _webhooks _payload _templates.
  - Create a webhook payload template for a network. - > Destroy a webhook payload template for a network. Does not work for included templates
    'wpt_00001', 'wpt_00002', 'wpt_00003', 'wpt_00004', 'wpt_00005' or 'wpt_00006' .
  - Update a webhook payload template for a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  body:
    description: The liquid template used for the body of the webhook message. Either `body` or `bodyFile` must be specified.
    type: str
  bodyFile:
    description: A Base64 encoded file containing liquid template used for the body of the webhook message. Either `body` or `bodyFile` must be
      specified.
    type: str
  headers:
    description: The liquid template used with the webhook headers.
    elements: dict
    suboptions:
      name:
        description: The name of the header template.
        type: str
      template:
        description: The liquid template for the headers.
        type: str
    type: list
  headersFile:
    description: A Base64 encoded file containing the liquid template used with the webhook headers.
    type: str
  name:
    description: The name of the new template.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  payloadTemplateId:
    description: PayloadTemplateId path parameter. Payload template ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks createNetworkWebhooksPayloadTemplate
    description: Complete reference of the createNetworkWebhooksPayloadTemplate API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-webhooks-payload-template
  - name: Cisco Meraki documentation for networks deleteNetworkWebhooksPayloadTemplate
    description: Complete reference of the deleteNetworkWebhooksPayloadTemplate API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-webhooks-payload-template
  - name: Cisco Meraki documentation for networks updateNetworkWebhooksPayloadTemplate
    description: Complete reference of the updateNetworkWebhooksPayloadTemplate API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-webhooks-payload-template
notes:
  - SDK Method used are
    networks.Networks.create_network_webhooks_payload_template,
    networks.Networks.delete_network_webhooks_payload_template,
    networks.Networks.update_network_webhooks_payload_template,
  - Paths used are
    post /networks/{networkId}/webhooks/payloadTemplates,
    delete /networks/{networkId}/webhooks/payloadTemplates/{payloadTemplateId},
    put /networks/{networkId}/webhooks/payloadTemplates/{payloadTemplateId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_webhooks_payload_templates:
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
    body: '{"event_type":"{{alertTypeId}}","client_payload":{"text":"{{alertData}}"}}'
    bodyFile: Qm9keSBGaWxl
    headers:
      - name: Authorization
        template: Bearer {{sharedSecret}}
    headersFile: SGVhZGVycyBGaWxl
    name: Custom Template
    networkId: string
- name: Delete by id
  cisco.meraki.networks_webhooks_payload_templates:
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
    payloadTemplateId: string
- name: Update by id
  cisco.meraki.networks_webhooks_payload_templates:
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
    body: '{"event_type":"{{alertTypeId}}","client_payload":{"text":"{{alertData}}"}}'
    bodyFile: Qm9keSBGaWxl
    headers:
      - name: Authorization
        template: Bearer {{sharedSecret}}
    headersFile: SGVhZGVycyBGaWxl
    name: Custom Template
    networkId: string
    payloadTemplateId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "body": "string",
      "headers": [
        {
          "name": "string",
          "template": "string"
        }
      ],
      "name": "string",
      "payloadTemplateId": "string",
      "sharing": {
        "byNetwork": {
          "adminsCanModify": true
        }
      },
      "type": "string"
    }
"""
