#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_webhooks_http_servers
short_description: Resource module for networks _webhooks _http _servers
description:
  - Manage operations create, update and delete of the resource networks _webhooks _http _servers.
  - Add an HTTP server to a network.
  - Delete an HTTP server from a network.
  - Update an HTTP server. To change a URL, create a new HTTP server.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  httpServerId:
    description: HttpServerId path parameter. Http server ID.
    type: str
  name:
    description: A name for easy reference to the HTTP server.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  payloadTemplate:
    description: The payload template to use when posting data to the HTTP server.
    suboptions:
      name:
        description: The name of the payload template.
        type: str
      payloadTemplateId:
        description: The ID of the payload template. Defaults to 'wpt_00001' for the Meraki template. For Meraki-included templates for the Webex
          (included) template use 'wpt_00002'; for the Slack (included) template use 'wpt_00003'; for the Microsoft Teams (included) template
          use 'wpt_00004'; for the ServiceNow (included) template use 'wpt_00006'.
        type: str
    type: dict
  sharedSecret:
    description: A shared secret that will be included in POSTs sent to the HTTP server. This secret can be used to verify that the request was
      sent by Meraki.
    type: str
  url:
    description: The URL of the HTTP server. Once set, cannot be updated.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks createNetworkWebhooksHttpServer
    description: Complete reference of the createNetworkWebhooksHttpServer API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-webhooks-http-server
  - name: Cisco Meraki documentation for networks deleteNetworkWebhooksHttpServer
    description: Complete reference of the deleteNetworkWebhooksHttpServer API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-webhooks-http-server
  - name: Cisco Meraki documentation for networks updateNetworkWebhooksHttpServer
    description: Complete reference of the updateNetworkWebhooksHttpServer API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-webhooks-http-server
notes:
  - SDK Method used are
    networks.Networks.create_network_webhooks_http_server,
    networks.Networks.delete_network_webhooks_http_server,
    networks.Networks.update_network_webhooks_http_server,
  - Paths used are
    post /networks/{networkId}/webhooks/httpServers,
    delete /networks/{networkId}/webhooks/httpServers/{httpServerId},
    put /networks/{networkId}/webhooks/httpServers/{httpServerId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_webhooks_http_servers:
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
    name: Example Webhook Server
    networkId: string
    payloadTemplate:
      name: Meraki (included)
      payloadTemplateId: wpt_00001
    sharedSecret: shhh
    url: https://example.com
- name: Delete by id
  cisco.meraki.networks_webhooks_http_servers:
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
    httpServerId: string
    networkId: string
- name: Update by id
  cisco.meraki.networks_webhooks_http_servers:
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
    httpServerId: string
    name: Example Webhook Server
    networkId: string
    payloadTemplate:
      payloadTemplateId: wpt_00001
    sharedSecret: shhh
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "name": "string",
      "networkId": "string",
      "payloadTemplate": {
        "name": "string",
        "payloadTemplateId": "string"
      },
      "url": "string"
    }
"""
