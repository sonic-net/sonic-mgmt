#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_mqtt_brokers
short_description: Resource module for networks _mqtt _brokers
description:
  - Manage operation create of the resource networks _mqtt _brokers.
  - Add an MQTT broker.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  authentication:
    description: Authentication settings of the MQTT broker.
    suboptions:
      password:
        description: Password for the MQTT broker.
        type: str
      username:
        description: Username for the MQTT broker.
        type: str
    type: dict
  host:
    description: Host name/IP address where the MQTT broker runs.
    type: str
  name:
    description: Name of the MQTT broker.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  port:
    description: Host port though which the MQTT broker can be reached.
    type: int
  security:
    description: Security settings of the MQTT broker.
    suboptions:
      mode:
        description: Security protocol of the MQTT broker.
        type: str
      tls:
        description: TLS settings of the MQTT broker.
        suboptions:
          caCertificate:
            description: CA Certificate of the MQTT broker.
            type: str
          verifyHostnames:
            description: Whether the TLS hostname verification is enabled for the MQTT broker.
            type: bool
        type: dict
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks createNetworkMqttBroker
    description: Complete reference of the createNetworkMqttBroker API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-mqtt-broker
notes:
  - SDK Method used are
    networks.Networks.create_network_mqtt_broker,
  - Paths used are
    post /networks/{networkId}/mqttBrokers,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_mqtt_brokers:
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
    authentication:
      password: '*****'
      username: milesmeraki
    host: 1.2.3.4
    name: MQTT_Broker_1
    networkId: string
    port: 443
    security:
      mode: tls
      tls:
        caCertificate: '*****'
        verifyHostnames: true
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "authentication": {
        "username": "string"
      },
      "host": "string",
      "id": "string",
      "name": "string",
      "port": 0,
      "security": {
        "mode": "string",
        "tls": {
          "hasCaCertificate": true,
          "verifyHostnames": true
        }
      }
    }
"""
