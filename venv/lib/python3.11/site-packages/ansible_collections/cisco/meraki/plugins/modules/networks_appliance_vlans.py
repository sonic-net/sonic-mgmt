#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_vlans
short_description: Resource module for networks _appliance _vlans
description:
  - Manage operations create, update and delete of the resource networks _appliance _vlans.
  - Add a VLAN.
  - Delete a VLAN from a network.
  - Update a VLAN.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  applianceIp:
    description: The local IP of the appliance on the VLAN.
    type: str
  cidr:
    description: CIDR of the pool of subnets. Applicable only for template network. Each network bound to the template will automatically pick
      a subnet from this pool to build its own VLAN.
    type: str
  dhcpBootFilename:
    description: DHCP boot option for boot filename.
    type: str
  dhcpBootNextServer:
    description: DHCP boot option to direct boot clients to the server to load the boot file from.
    type: str
  dhcpBootOptionsEnabled:
    description: Use DHCP boot options specified in other properties.
    type: bool
  dhcpHandling:
    description: The appliance's handling of DHCP requests on this VLAN. One of 'Run a DHCP server', 'Relay DHCP to another server' or 'Do not
      respond to DHCP requests'.
    type: str
  dhcpLeaseTime:
    description: The term of DHCP leases if the appliance is running a DHCP server on this VLAN. One of '30 minutes', '1 hour', '4 hours', '12
      hours', '1 day' or '1 week'.
    type: str
  dhcpOptions:
    description: The list of DHCP options that will be included in DHCP responses. Each object in the list should have "code", "type", and "value"
      properties.
    elements: dict
    suboptions:
      code:
        description: The code for the DHCP option. This should be an integer between 2 and 254.
        type: str
      type:
        description: The type for the DHCP option. One of 'text', 'ip', 'hex' or 'integer'.
        type: str
      value:
        description: The value for the DHCP option.
        type: str
    type: list
  dhcpRelayServerIps:
    description: The IPs of the DHCP servers that DHCP requests should be relayed to.
    elements: str
    type: list
  dnsNameservers:
    description: The DNS nameservers used for DHCP responses, either "upstream_dns", "google_dns", "opendns", or a newline seperated string of
      IP addresses or domain names.
    type: str
  fixedIpAssignments:
    description: The DHCP fixed IP assignments on the VLAN. This should be an object that contains mappings from MAC addresses to objects that
      themselves each contain "ip" and "name" string fields. See the sample request/response for more details.
    type: dict
  groupPolicyId:
    description: The id of the desired group policy to apply to the VLAN.
    type: str
  id:
    description: The VLAN ID of the new VLAN (must be between 1 and 4094).
    type: str
  ipv6:
    description: IPv6 configuration on the VLAN.
    suboptions:
      enabled:
        description: Enable IPv6 on VLAN.
        type: bool
      prefixAssignments:
        description: Prefix assignments on the VLAN.
        elements: dict
        suboptions:
          autonomous:
            description: Auto assign a /64 prefix from the origin to the VLAN.
            type: bool
          origin:
            description: The origin of the prefix.
            suboptions:
              interfaces:
                description: Interfaces associated with the prefix.
                elements: str
                type: list
              type:
                description: Type of the origin.
                type: str
            type: dict
          staticApplianceIp6:
            description: Manual configuration of the IPv6 Appliance IP.
            type: str
          staticPrefix:
            description: Manual configuration of a /64 prefix on the VLAN.
            type: str
        type: list
    type: dict
  mandatoryDhcp:
    description: Mandatory DHCP will enforce that clients connecting to this VLAN must use the IP address assigned by the DHCP server. Clients
      who use a static IP address won't be able to associate. Only available on firmware versions 17.0 and above.
    suboptions:
      enabled:
        description: Enable Mandatory DHCP on VLAN.
        type: bool
    type: dict
  mask:
    description: Mask used for the subnet of all bound to the template networks. Applicable only for template network.
    type: int
  name:
    description: The name of the new VLAN.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  reservedIpRanges:
    description: The DHCP reserved IP ranges on the VLAN.
    elements: dict
    suboptions:
      comment:
        description: A text comment for the reserved range.
        type: str
      end:
        description: The last IP in the reserved range.
        type: str
      start:
        description: The first IP in the reserved range.
        type: str
    type: list
  subnet:
    description: The subnet of the VLAN.
    type: str
  templateVlanType:
    description: Type of subnetting of the VLAN. Applicable only for template network.
    type: str
  vlanId:
    description: VlanId path parameter. Vlan ID.
    type: str
  vpnNatSubnet:
    description: The translated VPN subnet if VPN and VPN subnet translation are enabled on the VLAN.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance createNetworkApplianceVlan
    description: Complete reference of the createNetworkApplianceVlan API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-appliance-vlan
  - name: Cisco Meraki documentation for appliance deleteNetworkApplianceVlan
    description: Complete reference of the deleteNetworkApplianceVlan API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-appliance-vlan
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceVlan
    description: Complete reference of the updateNetworkApplianceVlan API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-vlan
notes:
  - SDK Method used are
    appliance.Appliance.create_network_appliance_vlan,
    appliance.Appliance.delete_network_appliance_vlan,
    appliance.Appliance.update_network_appliance_vlan,
  - Paths used are
    post /networks/{networkId}/appliance/vlans,
    delete /networks/{networkId}/appliance/vlans/{vlanId},
    put /networks/{networkId}/appliance/vlans/{vlanId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_appliance_vlans:
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
    applianceIp: 192.168.1.2
    cidr: 192.168.1.0/24
    dhcpBootOptionsEnabled: true
    dhcpHandling: Run a DHCP server
    dhcpLeaseTime: 30 minutes
    dhcpOptions:
      - code: '3'
        type: text
        value: five
    groupPolicyId: '101'
    id: '1234'
    ipv6:
      enabled: true
      prefixAssignments:
        - autonomous: false
          origin:
            interfaces:
              - wan0
            type: internet
          staticApplianceIp6: 2001:db8:3c4d:15::1
          staticPrefix: 2001:db8:3c4d:15::/64
    mandatoryDhcp:
      enabled: true
    mask: 28
    name: My VLAN
    networkId: string
    subnet: 192.168.1.0/24
    templateVlanType: same
- name: Delete by id
  cisco.meraki.networks_appliance_vlans:
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
    vlanId: string
- name: Update by id
  cisco.meraki.networks_appliance_vlans:
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
    adaptivePolicyGroupId: '1234'
    applianceIp: 192.168.1.2
    cidr: 192.168.1.0/24
    dhcpBootFilename: sample.file
    dhcpBootNextServer: 1.2.3.4
    dhcpBootOptionsEnabled: false
    dhcpHandling: Run a DHCP server
    dhcpLeaseTime: 1 day
    dhcpOptions:
      - code: '5'
        type: text
        value: five
    dhcpRelayServerIps:
      - 192.168.1.0/24
      - 192.168.128.0/24
    dnsNameservers: google_dns
    fixedIpAssignments:
      22:33:44:55:66:77:
        ip: 1.2.3.4
        name: Some client name
    groupPolicyId: '101'
    ipv6:
      enabled: true
      prefixAssignments:
        - autonomous: false
          origin:
            interfaces:
              - wan0
            type: internet
          staticApplianceIp6: 2001:db8:3c4d:15::1
          staticPrefix: 2001:db8:3c4d:15::/64
    mandatoryDhcp:
      enabled: true
    mask: 28
    name: My VLAN
    networkId: string
    reservedIpRanges:
      - comment: A reserved IP range
        end: 192.168.1.1
        start: 192.168.1.0
    subnet: 192.168.1.0/24
    templateVlanType: same
    vlanId: string
    vpnNatSubnet: 192.168.1.0/24
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "applianceIp": "string",
      "cidr": "string",
      "groupPolicyId": "string",
      "id": "string",
      "interfaceId": "string",
      "ipv6": {
        "enabled": true,
        "prefixAssignments": [
          {
            "autonomous": true,
            "origin": {
              "interfaces": [
                "string"
              ],
              "type": "string"
            },
            "staticApplianceIp6": "string",
            "staticPrefix": "string"
          }
        ]
      },
      "mandatoryDhcp": {
        "enabled": true
      },
      "mask": 0,
      "name": "string",
      "subnet": "string",
      "templateVlanType": "string"
    }
"""
