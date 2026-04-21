#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_qos_rules_order
short_description: Resource module for networks _switch _qos _rules _order
description:
  - Manage operations create, update and delete of the resource networks _switch _qos _rules _order.
  - Add a quality of service rule.
  - Delete a quality of service rule.
  - Update a quality of service rule.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  dscp:
    description: DSCP tag for the incoming packet. Set this to -1 to trust incoming DSCP. Default value is 0.
    type: int
  dstPort:
    description: The destination port of the incoming packet. Applicable only if protocol is TCP or UDP.
    type: int
  dstPortRange:
    description: The destination port range of the incoming packet. Applicable only if protocol is set to TCP or UDP.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  protocol:
    description: The protocol of the incoming packet. Default value is "ANY".
    type: str
  qosRuleId:
    description: QosRuleId path parameter. Qos rule ID.
    type: str
  srcPort:
    description: The source port of the incoming packet. Applicable only if protocol is TCP or UDP.
    type: int
  srcPortRange:
    description: The source port range of the incoming packet. Applicable only if protocol is set to TCP or UDP.
    type: str
  vlan:
    description: The VLAN of the incoming packet. A null value will match any VLAN.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch createNetworkSwitchQosRule
    description: Complete reference of the createNetworkSwitchQosRule API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-switch-qos-rule
  - name: Cisco Meraki documentation for switch deleteNetworkSwitchQosRule
    description: Complete reference of the deleteNetworkSwitchQosRule API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-switch-qos-rule
  - name: Cisco Meraki documentation for switch updateNetworkSwitchQosRule
    description: Complete reference of the updateNetworkSwitchQosRule API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-qos-rule
notes:
  - SDK Method used are
    switch.Switch.create_network_switch_qos_rule,
    switch.Switch.delete_network_switch_qos_rule,
    switch.Switch.update_network_switch_qos_rule,
  - Paths used are
    post /networks/{networkId}/switch/qosRules,
    delete /networks/{networkId}/switch/qosRules/{qosRuleId},
    put /networks/{networkId}/switch/qosRules/{qosRuleId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_switch_qos_rules_order:
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
    dscp: 0
    dstPort: 3000
    dstPortRange: 3000-3100
    networkId: string
    protocol: TCP
    srcPort: 2000
    srcPortRange: 70-80
    vlan: 100
- name: Delete by id
  cisco.meraki.networks_switch_qos_rules_order:
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
    qosRuleId: string
- name: Update by id
  cisco.meraki.networks_switch_qos_rules_order:
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
    dscp: 0
    dstPort: 3000
    dstPortRange: 3000-3100
    networkId: string
    protocol: TCP
    qosRuleId: string
    srcPort: 2000
    srcPortRange: 70-80
    vlan: 100
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "dscp": 0,
      "dstPort": 0,
      "dstPortRange": "string",
      "id": "string",
      "protocol": "string",
      "srcPort": 0,
      "srcPortRange": "string",
      "vlan": 0
    }
"""
