#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_stacks_routing_interfaces
short_description: Resource module for networks _switch _stacks _routing _interfaces
description:
  - Manage operations create, update and delete of the resource networks _switch _stacks _routing _interfaces.
  - Create a layer 3 interface for a switch stack.
  - Delete a layer 3 interface from a switch stack.
  - Update a layer 3 interface for a switch stack.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  defaultGateway:
    description: The next hop for any traffic that isn't going to a directly connected subnet or over a static route. This IP address must exist
      in a subnet with a L3 interface. Required if this is the first IPv4 interface.
    type: str
  interfaceId:
    description: InterfaceId path parameter. Interface ID.
    type: str
  interfaceIp:
    description: The IP address that will be used for Layer 3 routing on this VLAN or subnet. This cannot be the same as the device management
      IP.
    type: str
  ipv6:
    description: The IPv6 settings of the interface.
    suboptions:
      address:
        description: The IPv6 address of the interface. Required if assignmentMode is 'static'. Must not be included if assignmentMode is 'eui-64'.
        type: str
      assignmentMode:
        description: The IPv6 assignment mode for the interface. Can be either 'eui-64' or 'static'.
        type: str
      gateway:
        description: The IPv6 default gateway of the interface. Required if prefix is defined and this is the first interface with IPv6 configured.
        type: str
      prefix:
        description: The IPv6 prefix of the interface. Required if IPv6 object is included.
        type: str
    type: dict
  multicastRouting:
    description: Enable multicast support if, multicast routing between VLANs is required. Options are 'disabled', 'enabled' or 'IGMP snooping
      querier'. Default is 'disabled'.
    type: str
  name:
    description: A friendly name or description for the interface or VLAN.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  ospfSettings:
    description: The OSPF routing settings of the interface.
    suboptions:
      area:
        description: The OSPF area to which this interface should belong. Can be either 'disabled' or the identifier of an existing OSPF area.
          Defaults to 'disabled'.
        type: str
      cost:
        description: The path cost for this interface. Defaults to 1, but can be increased up to 65535 to give lower priority.
        type: int
      isPassiveEnabled:
        description: When enabled, OSPF will not run on the interface, but the subnet will still be advertised.
        type: bool
    type: dict
  subnet:
    description: The network that this L3 interface is on, in CIDR notation (ex. 10.1.1.0/24).
    type: str
  switchStackId:
    description: SwitchStackId path parameter. Switch stack ID.
    type: str
  vlanId:
    description: The VLAN this L3 interface is on. VLAN must be between 1 and 4094.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch createNetworkSwitchStackRoutingInterface
    description: Complete reference of the createNetworkSwitchStackRoutingInterface API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-switch-stack-routing-interface
  - name: Cisco Meraki documentation for switch deleteNetworkSwitchStackRoutingInterface
    description: Complete reference of the deleteNetworkSwitchStackRoutingInterface API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-switch-stack-routing-interface
  - name: Cisco Meraki documentation for switch updateNetworkSwitchStackRoutingInterface
    description: Complete reference of the updateNetworkSwitchStackRoutingInterface API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-stack-routing-interface
notes:
  - SDK Method used are
    switch.Switch.create_network_switch_stack_routing_interface,
    switch.Switch.delete_network_switch_stack_routing_interface,
    switch.Switch.update_network_switch_stack_routing_interface,
  - Paths used are
    post /networks/{networkId}/switch/stacks/{switchStackId}/routing/interfaces,
    delete /networks/{networkId}/switch/stacks/{switchStackId}/routing/interfaces/{interfaceId},
    put /networks/{networkId}/switch/stacks/{switchStackId}/routing/interfaces/{interfaceId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_switch_stacks_routing_interfaces:
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
    defaultGateway: 192.168.1.1
    interfaceIp: 192.168.1.2
    ipv6:
      address: 2001:db8::1
      assignmentMode: static
      gateway: 2001:db8::2
      prefix: 2001:db8::/32
    multicastRouting: disabled
    name: L3 interface
    networkId: string
    ospfSettings:
      area: '0'
      cost: 1
      isPassiveEnabled: true
    subnet: 192.168.1.0/24
    switchStackId: string
    vlanId: 100
- name: Delete by id
  cisco.meraki.networks_switch_stacks_routing_interfaces:
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
    interfaceId: string
    networkId: string
    switchStackId: string
- name: Update by id
  cisco.meraki.networks_switch_stacks_routing_interfaces:
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
    defaultGateway: 192.168.1.1
    interfaceId: string
    interfaceIp: 192.168.1.2
    ipv6:
      address: 2001:db8::1
      assignmentMode: static
      gateway: 2001:db8::2
      prefix: 2001:db8::/32
    multicastRouting: disabled
    name: L3 interface
    networkId: string
    ospfSettings:
      area: '0'
      cost: 1
      isPassiveEnabled: true
    subnet: 192.168.1.0/24
    switchStackId: string
    vlanId: 100
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "defaultGateway": "string",
      "interfaceId": "string",
      "interfaceIp": "string",
      "ipv6": {
        "address": "string",
        "assignmentMode": "string",
        "gateway": "string",
        "prefix": "string"
      },
      "multicastRouting": "string",
      "name": "string",
      "ospfSettings": {
        "area": "string",
        "cost": 0,
        "isPassiveEnabled": true
      },
      "ospfV3": {
        "area": "string",
        "cost": 0,
        "isPassiveEnabled": true
      },
      "subnet": "string",
      "uplinkV4": true,
      "uplinkV6": true,
      "vlanId": 0
    }
"""
