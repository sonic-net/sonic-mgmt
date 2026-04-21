#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_syslog_servers
short_description: Resource module for networks _syslog _servers
description:
  - Manage operation update of the resource networks _syslog _servers.
  - Update the syslog servers for a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  servers:
    description: A list of the syslog servers for this network.
    elements: dict
    suboptions:
      host:
        description: The IP address or FQDN of the syslog server.
        type: str
      port:
        description: The port of the syslog server.
        type: int
      roles:
        description: A list of roles for the syslog server. Options (case-insensitive) 'Wireless event log', 'Appliance event log', 'Switch event
          log', 'Air Marshal events', 'Flows', 'URLs', 'IDS alerts', 'Security events'.
        elements: str
        type: list
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks updateNetworkSyslogServers
    description: Complete reference of the updateNetworkSyslogServers API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-syslog-servers
notes:
  - SDK Method used are
    networks.Networks.update_network_syslog_servers,
  - Paths used are
    put /networks/{networkId}/syslogServers,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_syslog_servers:
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
    networkId: string
    servers:
      - host: 1.2.3.4
        port: 443
        roles:
          - Wireless event log
          - URLs
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    [
      {
        "host": "string",
        "port": 0,
        "roles": [
          "string"
        ]
      }
    ]
"""
