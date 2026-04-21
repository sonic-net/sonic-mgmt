#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: cp_mgmt_vsx_provisioning_tool
short_description: Run the VSX provisioning tool with the specified parameters.
description:
  - Run the VSX provisioning tool with the specified parameters. Note - An automatic session publish is part of all the operations in this API.
  - All operations are performed over Web Services API.
  - Available from R82 management version.
version_added: "6.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  operation:
    description:
      - The name of the provisioning operation to run. Each operation has its own specific parameters.<br> The available operations
        are,<ul><li><i>add-vsx-gateway</i> - Adds a new VSX gateway</li><li><i>add-vsx-cluster</i> - Adds a new VSX
        cluster*</li><li><i>add-vsx-cluster-member</i> - Adds a new VSX cluster member*</li><li><i>add-vd</i> - Adds a new Virtual Device (VS/VSB/VSW/VR) to a
        VSX gateway or VSX cluster</li><li><i>add-vd-interface</i> - Adds a new virtual interface to a Virtual Device</li><li><i>add-physical-interface</i> -
        Adds a physical interface to a VSX gateway or VSX cluster</li><li><i>add-route</i> - Adds a route to a Virtual Device</li><li><i>attach-bridge</i> -
        Attaches a bridge interface to a Virtual System</li><li><i>remove-vsx</i> - Removes a VSX gateway or VSX cluster</li><li><i>remove-vd</i> - Removes a
        Virtual Device</li><li><i>remove-vd-interface</i> - Removes an interface from a Virtual Device</li><li><i>remove-physical-interface</i> - Removes a
        physical interface from a VSX gateway or VSX cluster</li><li><i>remove-route</i> - Removes a route from a Virtual Device</li><li><i>set-vd</i> -
        Modifies a Virtual Device</li><li><i>set-vd-interface</i> - Modifies an interface on a Virtual Device</li><li><i>set-physical-interface</i> - Modifies
        a physical interface on a VSX cluster or VSX gateway</li></ul><br> * When adding a VSX Cluster, you must also add at least 2 cluster members<br> *
        Adding cluster members is only allowed when adding a new VSX cluster<br> * To add members to an existing cluster, use vsx-run-operation.
    type: str
    choices: ['attach-bridge', 'add-route', 'add-physical-interface', 'add-vd-interface', 'add-vsx-gateway', 'add-vsx-cluster', 'add-vd',
             'remove-route', 'remove-vd', 'remove-vsx', 'remove-physical-interface', 'remove-vd-interface', 'set-vd', 'set-physical-interface',
             'set-vd-interface']
  add_physical_interface_params:
    description:
      - Parameters for the operation to add a physical interface to a VSX gateway or VSX Cluster.
    type: dict
    suboptions:
      name:
        description:
          - Name of the interface.
        type: str
      vsx_name:
        description:
          - Name of the VSX Gateway or Cluster object.
        type: str
      vlan_trunk:
        description:
          - True if this interface is a VLAN trunk.
        type: bool
  add_route_params:
    description:
      - Parameters for the operation to add a route to a Virtual System or Virtual Router.
    type: dict
    suboptions:
      destination:
        description:
          - Route destination. To specify the default route, use 'default' for IPv4 and 'default6' for IPv6.
        type: str
      next_hop:
        description:
          - Next hop IP address.
        type: str
      leads_to:
        description:
          - Virtual Router for this route<br/>This VD must have an existing connection to the VR.
        type: str
      vd:
        description:
          - Name of the Virtual System, Virtual Switch, or Virtual Router.
        type: str
      netmask:
        description:
          - Subnet mask for this route.
        type: str
      prefix:
        description:
          - CIDR prefix for this route.
        type: str
      propagate:
        description:
          - Propagate this route to adjacent virtual devices.
        type: bool
  add_vd_interface_params:
    description:
      - Parameters for the operation to add a new interface to a Virtual Device.
    type: dict
    suboptions:
      leads_to:
        description:
          - Virtual Switch or Virtual Router for this interface.
        type: str
      name:
        description:
          - Name of the interface.
        type: str
      vd:
        description:
          - Name of the Virtual System, Virtual Switch, or Virtual Router.
        type: str
      anti_spoofing:
        description:
          - The anti-spoofing enforcement setting of this interface.
        type: str
        choices: ['prevent', 'detect', 'off']
      anti_spoofing_tracking:
        description:
          - The anti-spoofing tracking setting of this interface.
        type: str
        choices: ['none', 'alert', 'log']
      ipv4_address:
        description:
          - IPv4 Address of this interface with optional CIDR prefix.<br/>Required if this interface belongs to a Virtual System or Virtual Router.
        type: str
      ipv4_netmask:
        description:
          - IPv4 Subnet mask of this interface.
        type: str
      ipv4_prefix:
        description:
          - IPv4 CIDR prefix of this interface.
        type: str
      ipv6_address:
        description:
          - IPv6 Address of this interface<br/>Required if this interface belongs to a Virtual System or Virtual Router.
        type: str
      ipv6_netmask:
        description:
          - IPv6 Subnet mask of this interface.
        type: str
      ipv6_prefix:
        description:
          - IPv6 CIDR prefix of this interface.
        type: str
      mtu:
        description:
          - MTU of this interface.
        type: int
      propagate:
        description:
          - Propagate IPv4 route to adjacent virtual devices.
        type: bool
      propagate6:
        description:
          - Propagate IPv6 route to adjacent virtual devices.
        type: bool
      specific_group:
        description:
          - Specific group for interface topology.<br/>Only for use with topology option 'internal_specific'.
        type: str
      topology:
        description:
          - Topology of this interface.<br/>Automatic topology calculation based on routes must be disabled for this VS.
        type: str
        choices: ['external', 'internal_undefined', 'internal_this_network', 'internal_specific', 'defined_by_routes']
      vti_settings:
        description:
          - VTI settings for this interface. This Virtual System must have VPN blade enabled.
        type: dict
        suboptions:
          local_ipv4_address:
            description:
              - The IPv4 address of the VPN tunnel on this Virtual System.
            type: str
          peer_name:
            description:
              - The name of the remote peer object as defined in the VPN community.
            type: str
          remote_ipv4_address:
            description:
              - The IPv4 address of the VPN tunnel on the remote VPN peer.
            type: str
          tunnel_id:
            description:
              - Optional unique Tunnel ID.<br/>Automatically assigned by the system if empty.
            type: str
  add_vd_params:
    description:
      - Parameters for the operation to add a new Virtual Device (VS/VSB/VSW/VR).
    type: dict
    suboptions:
      interfaces:
        description:
          - The list of interfaces for this new Virtual Device.<br/>Optional if this new VD is a Virtual Switch.
        type: list
        elements: dict
        suboptions:
          leads_to:
            description:
              - Virtual Switch or Virtual Router for this interface.
            type: str
          name:
            description:
              - Name of the interface.
            type: str
          anti_spoofing:
            description:
              - The anti-spoofing enforcement setting of this interface.
            type: str
            choices: ['prevent', 'detect', 'off']
          anti_spoofing_tracking:
            description:
              - The anti-spoofing tracking setting of this interface.
            type: str
            choices: ['none', 'alert', 'log']
          ipv4_address:
            description:
              - IPv4 Address of this interface with optional CIDR prefix.<br/>Required if this interface belongs to a Virtual System or Virtual Router.
            type: str
          ipv4_netmask:
            description:
              - IPv4 Subnet mask of this interface.
            type: str
          ipv4_prefix:
            description:
              - IPv4 CIDR prefix of this interface.
            type: str
          ipv6_address:
            description:
              - IPv6 Address of this interface<br/>Required if this interface belongs to a Virtual System or Virtual Router.
            type: str
          ipv6_netmask:
            description:
              - IPv6 Subnet mask of this interface.
            type: str
          ipv6_prefix:
            description:
              - IPv6 CIDR prefix of this interface.
            type: str
          mtu:
            description:
              - MTU of this interface.
            type: int
          propagate:
            description:
              - Propagate IPv4 route to adjacent virtual devices.
            type: bool
          propagate6:
            description:
              - Propagate IPv6 route to adjacent virtual devices.
            type: bool
          specific_group:
            description:
              - Specific group for interface topology.<br/>Only for use with topology option 'internal_specific'.
            type: str
          topology:
            description:
              - Topology of this interface.<br/>Automatic topology calculation based on routes must be disabled for this VS.
            type: str
            choices: ['external', 'internal_undefined', 'internal_this_network', 'internal_specific', 'defined_by_routes']
      type:
        description:
          - Type of the Virtual Device <br><br>vs - Virtual Firewall<br>vr - Virtual Router<br>vsw - Virtual Switch<br>vsbm - Virtual Firewall in bridge mode.
        type: str
        choices: ['vs', 'vr', 'vsw', 'vsbm']
      vd:
        description:
          - Name of the Virtual System, Virtual Switch, or Virtual Router.
        type: str
      vsx_name:
        description:
          - Name of the VSX Gateway or Cluster object.
        type: str
      calc_topology_auto:
        description:
          - Calculate interface topology automatically based on routes.<br/>Relevant only for Virtual Systems.<br/>Do not use for virtual devices.
        type: bool
      ipv4_address:
        description:
          - Main IPv4 Address.<br/>Required if this device is a Virtual System.<br/>Do not use for other virtual devices.
        type: str
      ipv4_instances:
        description:
          - Number of IPv4 instances for the Virtual System.<br/>Must be greater or equal to 1.<br/>Only relevant for Virtual Systems and Virtual
            Systems in bridge mode.
        type: int
      ipv6_address:
        description:
          - Main IPv6 Address.<br/>Required if this device is a Virtual System.<br/>Do not use for other virtual devices.
        type: str
      ipv6_instances:
        description:
          - Number of IPv6 instances for the Virtual System.<br/>Only relevant for Virtual Systems and Virtual Systems in bridge mode.
        type: int
      routes:
        description:
          - The list of routes for this new Virtual Device (VS or VR only).
        type: list
        elements: dict
        suboptions:
          destination:
            description:
              - Route destination. To specify the default route, use 'default' for IPv4 and 'default6' for IPv6.
            type: str
          next_hop:
            description:
              - Next hop IP address.
            type: str
          leads_to:
            description:
              - Virtual Router for this route<br/>This VD must have an existing connection to the VR.
            type: str
          netmask:
            description:
              - Subnet mask for this route.
            type: str
          prefix:
            description:
              - CIDR prefix for this route.
            type: str
          propagate:
            description:
              - Propagate this route to adjacent virtual devices.
            type: bool
      vs_mtu:
        description:
          - MTU of the Virtual System.<br/>Only relevant for Virtual Systems in bridge mode.<br/>Do not use for other virtual devices.
        type: int
  add_vsx_cluster_params:
    description:
      - Parameters for the operation to add a new VSX Cluster.
    type: dict
    suboptions:
      cluster_type:
        description:
          - Cluster type for the VSX Cluster Object.<br/>Starting in R81.10, only VSLS can be configured during cluster creation.<br/>To use High
            Availability ('ha'), first create the cluster as VSLS and then run vsx_util on the Management.
        type: str
        choices: ['vsls', 'ha']
      ipv4_address:
        description:
          - Main IPv4 Address of the VSX Gateway or Cluster object.<br/>Optional if main IPv6 Address is defined.
        type: str
      ipv6_address:
        description:
          - Main IPv6 Address of the VSX Gateway or Cluster object.<br/>Optional if main IPv4 Address is defined.
        type: str
      members:
        description:
          - The list of cluster members for this new VSX Cluster. Minimum, 2.
        type: list
        elements: dict
        suboptions:
          ipv4_address:
            description:
              - Main IPv4 Address of the VSX Cluster member.<br/>Mandatory if the VSX Cluster has an IPv4 Address.
            type: str
          ipv6_address:
            description:
              - Main IPv6 Address of the VSX Cluster member.<br/>Mandatory if the VSX Cluster has an IPv6 Address.
            type: str
          name:
            description:
              - Name of the new VSX Cluster member.
            type: str
          sic_otp:
            description:
              - SIC one-time-password of the VSX Gateway or Cluster member.<br/>Password must be between 4-127 characters in length.
            type: str
          sync_ip:
            description:
              - Sync IP address for the VSX Cluster member.
            type: str
      sync_if_name:
        description:
          - Sync interface name for the VSX Cluster.
        type: str
      sync_netmask:
        description:
          - Sync interface netmask for the VSX Cluster.
        type: str
      vsx_version:
        description:
          - Version of the VSX Gateway or Cluster object.
        type: str
      vsx_name:
        description:
          - Name of the VSX Gateway or Cluster object.
        type: str
      rule_drop:
        description:
          - Add a default drop rule to the VSX Gateway or Cluster initial policy.
        type: str
        choices: ['enable', 'disable']
      rule_https:
        description:
          - Add a rule to allow HTTPS traffic to the VSX Gateway or Cluster initial policy.
        type: str
        choices: ['enable', 'disable']
      rule_ping:
        description:
          - Add a rule to allow ping traffic to the VSX Gateway or Cluster initial policy.
        type: str
        choices: ['enable', 'disable']
      rule_ping6:
        description:
          - Add a rule to allow ping6 traffic to the VSX Gateway or Cluster initial policy.
        type: str
        choices: ['enable', 'disable']
      rule_snmp:
        description:
          - Add a rule to allow SNMP traffic to the VSX Gateway or Cluster initial policy.
        type: str
        choices: ['enable', 'disable']
      rule_ssh:
        description:
          - Add a rule to allow SSH traffic to the VSX Gateway or Cluster initial policy.
        type: str
        choices: ['enable', 'disable']
  add_vsx_gateway_params:
    description:
      - Parameters for the operation to add a new VSX Gateway.
    type: dict
    suboptions:
      ipv4_address:
        description:
          - Main IPv4 Address of the VSX Gateway or Cluster object.<br/>Optional if main IPv6 Address is defined.
        type: str
      ipv6_address:
        description:
          - Main IPv6 Address of the VSX Gateway or Cluster object.<br/>Optional if main IPv4 Address is defined.
        type: str
      sic_otp:
        description:
          - SIC one-time-password of the VSX Gateway or Cluster member.<br/>Password must be between 4-127 characters in length.
        type: str
      vsx_version:
        description:
          - Version of the VSX Gateway or Cluster object.
        type: str
      vsx_name:
        description:
          - Name of the VSX Gateway or Cluster object.
        type: str
      rule_drop:
        description:
          - Add a default drop rule to the VSX Gateway or Cluster initial policy.
        type: str
        choices: ['enable', 'disable']
      rule_https:
        description:
          - Add a rule to allow HTTPS traffic to the VSX Gateway or Cluster initial policy.
        type: str
        choices: ['enable', 'disable']
      rule_ping:
        description:
          - Add a rule to allow ping traffic to the VSX Gateway or Cluster initial policy.
        type: str
        choices: ['enable', 'disable']
      rule_ping6:
        description:
          - Add a rule to allow ping6 traffic to the VSX Gateway or Cluster initial policy.
        type: str
        choices: ['enable', 'disable']
      rule_snmp:
        description:
          - Add a rule to allow SNMP traffic to the VSX Gateway or Cluster initial policy.
        type: str
        choices: ['enable', 'disable']
      rule_ssh:
        description:
          - Add a rule to allow SSH traffic to the VSX Gateway or Cluster initial policy.
        type: str
        choices: ['enable', 'disable']
  attach_bridge_params:
    description:
      - Parameters for the operation to attach a new bridge interface to a Virtual System.
    type: dict
    suboptions:
      ifs1:
        description:
          - Name of the first interface for the bridge.
        type: str
      ifs2:
        description:
          - Name of the second interface for the bridge.
        type: str
      vd:
        description:
          - Name of the Virtual System, Virtual Switch, or Virtual Router.
        type: str
  remove_physical_interface_params:
    description:
      - Parameters for the operation to remove a physical interface from a VSX (Gateway or Cluster).
    type: dict
    suboptions:
      name:
        description:
          - Name of the interface.
        type: str
      vsx_name:
        description:
          - Name of the VSX Gateway or Cluster object.
        type: str
  remove_route_params:
    description:
      - Parameters for the operation to remove a route from a Virtual System or Virtual Router.
    type: dict
    suboptions:
      destination:
        description:
          - Route destination. To specify the default route, use 'default' for IPv4 and 'default6' for IPv6.
        type: str
      vd:
        description:
          - Name of the Virtual System, Virtual Switch, or Virtual Router.
        type: str
      netmask:
        description:
          - Subnet mask for this route.
        type: str
      prefix:
        description:
          - CIDR prefix for this route.
        type: str
  remove_vd_interface_params:
    description:
      - Parameters for the operation to remove a logical interface from a Virtual Device.
    type: dict
    suboptions:
      leads_to:
        description:
          - Virtual Switch or Virtual Router for this interface.
        type: str
      name:
        description:
          - Name of the interface.
        type: str
      vd:
        description:
          - Name of the Virtual System, Virtual Switch, or Virtual Router.
        type: str
  remove_vd_params:
    description:
      - Parameters for the operation to remove a Virtual Device.
    type: dict
    suboptions:
      vd:
        description:
          - Name of the Virtual System, Virtual Switch, or Virtual Router.
        type: str
  remove_vsx_params:
    description:
      - Parameters for the operation to remove a VSX Gateway or VSX Cluster.
    type: dict
    suboptions:
      vsx_name:
        description:
          - Name of the VSX Gateway or Cluster object.
        type: str
  set_physical_interface_params:
    description:
      - Parameters for the operation to change the configuration of a physical interface.
    type: dict
    suboptions:
      name:
        description:
          - Name of the interface.
        type: str
      vlan_trunk:
        description:
          - True if this interface is a VLAN trunk.
        type: bool
      vsx_name:
        description:
          - Name of the VSX Gateway or Cluster object.
        type: str
  set_vd_interface_params:
    description:
      - Parameters for the operation to change the configuration of a logical interface.
    type: dict
    suboptions:
      leads_to:
        description:
          - Virtual Switch or Virtual Router for this interface.
        type: str
      name:
        description:
          - Name of the interface.
        type: str
      vd:
        description:
          - Name of the Virtual System, Virtual Switch, or Virtual Router.
        type: str
      anti_spoofing:
        description:
          - The anti-spoofing enforcement setting of this interface.
        type: str
        choices: ['prevent', 'detect', 'off']
      anti_spoofing_tracking:
        description:
          - The anti-spoofing tracking setting of this interface.
        type: str
        choices: ['none', 'alert', 'log']
      ipv4_address:
        description:
          - IPv4 Address of this interface with optional CIDR prefix.<br/>Required if this interface belongs to a Virtual System or Virtual Router.
        type: str
      ipv6_address:
        description:
          - IPv6 Address of this interface<br/>Required if this interface belongs to a Virtual System or Virtual Router.
        type: str
      mtu:
        description:
          - MTU of this interface.
        type: int
      new_leads_to:
        description:
          - New Virtual Switch or Virtual Router for this interface.
        type: str
      propagate:
        description:
          - Propagate IPv4 route to adjacent virtual devices.
        type: bool
      propagate6:
        description:
          - Propagate IPv6 route to adjacent virtual devices.
        type: bool
      specific_group:
        description:
          - Specific group for interface topology.<br/>Only for use with topology option 'internal_specific'.
        type: str
      topology:
        description:
          - Topology of this interface.<br/>Automatic topology calculation based on routes must be disabled for this VS.
        type: str
        choices: ['external', 'internal_undefined', 'internal_this_network', 'internal_specific', 'defined_by_routes']
  set_vd_params:
    description:
      - Parameters for the operation to change the configuration of a Virtual Device.
    type: dict
    suboptions:
      vd:
        description:
          - Name of the Virtual System, Virtual Switch, or Virtual Router.
        type: str
      calc_topology_auto:
        description:
          - Calculate interface topology automatically based on routes.<br/>Relevant only for Virtual Systems.<br/>Do not use for virtual devices.
        type: bool
      ipv4_address:
        description:
          - Main IPv4 Address.<br/>Relevant only if this device is a Virtual System.<br/>Do not use for other virtual devices.
        type: str
      ipv4_instances:
        description:
          - Number of IPv4 instances for the Virtual System.<br/>Must be greater or equal to 1.<br/>Only relevant for Virtual Systems and Virtual
            Systems in bridge mode.
        type: int
      ipv6_address:
        description:
          - Main IPv6 Address.<br/>Relevant only if this device is a Virtual System.<br/>Do not use for other virtual devices.
        type: str
      ipv6_instances:
        description:
          - Number of IPv6 instances for the Virtual System.<br/>Only relevant for Virtual Systems and Virtual Systems in bridge mode.
        type: int
      vs_mtu:
        description:
          - MTU of the Virtual System.<br/>Only relevant for Virtual Systems in bridge mode.<br/>Do not use for other virtual devices.
        type: int
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: vsx-provisioning-tool
  cp_mgmt_vsx_provisioning_tool:
    add_vsx_cluster_params:
      cluster_type: vsls
      ipv4_address: 10.1.1.15
      members:
        - ipv4_address: 10.1.1.1
          name: VSX1
          sic_otp: sicotp123
          sync_ip: 192.168.1.1
        - ipv4_address: 10.1.1.2
          name: VSX2
          sic_otp: sicotp123
          sync_ip: 192.168.1.2
      rule_drop: enable
      rule_ping: enable
      sync_if_name: eth3
      sync_netmask: 255.255.255.0
      vsx_version: R81.10
      vsx_name: VSX_CLUSTER
    operation: add-vsx-cluster
"""

RETURN = """
cp_mgmt_vsx_provisioning_tool:
  description: The checkpoint vsx-provisioning-tool output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        operation=dict(type='str', choices=['attach-bridge', 'add-route', 'add-physical-interface',
                                            'add-vd-interface', 'add-vsx-gateway', 'add-vsx-cluster', 'add-vd', 'remove-route', 'remove-vd', 'remove-vsx',
                                            'remove-physical-interface', 'remove-vd-interface', 'set-vd', 'set-physical-interface', 'set-vd-interface']),
        add_physical_interface_params=dict(type='dict', options=dict(
            name=dict(type='str'),
            vsx_name=dict(type='str'),
            vlan_trunk=dict(type='bool')
        )),
        add_route_params=dict(type='dict', options=dict(
            destination=dict(type='str'),
            next_hop=dict(type='str'),
            leads_to=dict(type='str'),
            vd=dict(type='str'),
            netmask=dict(type='str'),
            prefix=dict(type='str'),
            propagate=dict(type='bool')
        )),
        add_vd_interface_params=dict(type='dict', options=dict(
            leads_to=dict(type='str'),
            name=dict(type='str'),
            vd=dict(type='str'),
            anti_spoofing=dict(type='str', choices=['prevent', 'detect', 'off']),
            anti_spoofing_tracking=dict(type='str', choices=['none', 'alert', 'log']),
            ipv4_address=dict(type='str'),
            ipv4_netmask=dict(type='str'),
            ipv4_prefix=dict(type='str'),
            ipv6_address=dict(type='str'),
            ipv6_netmask=dict(type='str'),
            ipv6_prefix=dict(type='str'),
            mtu=dict(type='int'),
            propagate=dict(type='bool'),
            propagate6=dict(type='bool'),
            specific_group=dict(type='str'),
            topology=dict(type='str', choices=['external', 'internal_undefined', 'internal_this_network', 'internal_specific', 'defined_by_routes']),
            vti_settings=dict(type='dict', options=dict(
                local_ipv4_address=dict(type='str'),
                peer_name=dict(type='str'),
                remote_ipv4_address=dict(type='str'),
                tunnel_id=dict(type='str')
            ))
        )),
        add_vd_params=dict(type='dict', options=dict(
            interfaces=dict(type='list', elements="dict", options=dict(
                leads_to=dict(type='str'),
                name=dict(type='str'),
                anti_spoofing=dict(type='str', choices=['prevent', 'detect', 'off']),
                anti_spoofing_tracking=dict(type='str', choices=['none', 'alert', 'log']),
                ipv4_address=dict(type='str'),
                ipv4_netmask=dict(type='str'),
                ipv4_prefix=dict(type='str'),
                ipv6_address=dict(type='str'),
                ipv6_netmask=dict(type='str'),
                ipv6_prefix=dict(type='str'),
                mtu=dict(type='int'),
                propagate=dict(type='bool'),
                propagate6=dict(type='bool'),
                specific_group=dict(type='str'),
                topology=dict(type='str', choices=['external', 'internal_undefined', 'internal_this_network', 'internal_specific', 'defined_by_routes'])
            )),
            type=dict(type='str', choices=['vs', 'vr', 'vsw', 'vsbm']),
            vd=dict(type='str'),
            vsx_name=dict(type='str'),
            calc_topology_auto=dict(type='bool'),
            ipv4_address=dict(type='str'),
            ipv4_instances=dict(type='int'),
            ipv6_address=dict(type='str'),
            ipv6_instances=dict(type='int'),
            routes=dict(type='list', elements="dict", options=dict(
                destination=dict(type='str'),
                next_hop=dict(type='str'),
                leads_to=dict(type='str'),
                netmask=dict(type='str'),
                prefix=dict(type='str'),
                propagate=dict(type='bool')
            )),
            vs_mtu=dict(type='int')
        )),
        add_vsx_cluster_params=dict(type='dict', options=dict(
            cluster_type=dict(type='str', choices=['vsls', 'ha']),
            ipv4_address=dict(type='str'),
            ipv6_address=dict(type='str'),
            members=dict(type='list', elements="dict", options=dict(
                ipv4_address=dict(type='str'),
                ipv6_address=dict(type='str'),
                name=dict(type='str'),
                sic_otp=dict(type='str'),
                sync_ip=dict(type='str')
            )),
            sync_if_name=dict(type='str'),
            sync_netmask=dict(type='str'),
            vsx_version=dict(type='str'),
            vsx_name=dict(type='str'),
            rule_drop=dict(type='str', choices=['enable', 'disable']),
            rule_https=dict(type='str', choices=['enable', 'disable']),
            rule_ping=dict(type='str', choices=['enable', 'disable']),
            rule_ping6=dict(type='str', choices=['enable', 'disable']),
            rule_snmp=dict(type='str', choices=['enable', 'disable']),
            rule_ssh=dict(type='str', choices=['enable', 'disable'])
        )),
        add_vsx_gateway_params=dict(type='dict', options=dict(
            ipv4_address=dict(type='str'),
            ipv6_address=dict(type='str'),
            sic_otp=dict(type='str'),
            vsx_version=dict(type='str'),
            vsx_name=dict(type='str'),
            rule_drop=dict(type='str', choices=['enable', 'disable']),
            rule_https=dict(type='str', choices=['enable', 'disable']),
            rule_ping=dict(type='str', choices=['enable', 'disable']),
            rule_ping6=dict(type='str', choices=['enable', 'disable']),
            rule_snmp=dict(type='str', choices=['enable', 'disable']),
            rule_ssh=dict(type='str', choices=['enable', 'disable'])
        )),
        attach_bridge_params=dict(type='dict', options=dict(
            ifs1=dict(type='str'),
            ifs2=dict(type='str'),
            vd=dict(type='str')
        )),
        remove_physical_interface_params=dict(type='dict', options=dict(
            name=dict(type='str'),
            vsx_name=dict(type='str')
        )),
        remove_route_params=dict(type='dict', options=dict(
            destination=dict(type='str'),
            vd=dict(type='str'),
            netmask=dict(type='str'),
            prefix=dict(type='str')
        )),
        remove_vd_interface_params=dict(type='dict', options=dict(
            leads_to=dict(type='str'),
            name=dict(type='str'),
            vd=dict(type='str')
        )),
        remove_vd_params=dict(type='dict', options=dict(
            vd=dict(type='str')
        )),
        remove_vsx_params=dict(type='dict', options=dict(
            vsx_name=dict(type='str')
        )),
        set_physical_interface_params=dict(type='dict', options=dict(
            name=dict(type='str'),
            vlan_trunk=dict(type='bool'),
            vsx_name=dict(type='str')
        )),
        set_vd_interface_params=dict(type='dict', options=dict(
            leads_to=dict(type='str'),
            name=dict(type='str'),
            vd=dict(type='str'),
            anti_spoofing=dict(type='str', choices=['prevent', 'detect', 'off']),
            anti_spoofing_tracking=dict(type='str', choices=['none', 'alert', 'log']),
            ipv4_address=dict(type='str'),
            ipv6_address=dict(type='str'),
            mtu=dict(type='int'),
            new_leads_to=dict(type='str'),
            propagate=dict(type='bool'),
            propagate6=dict(type='bool'),
            specific_group=dict(type='str'),
            topology=dict(type='str', choices=['external', 'internal_undefined', 'internal_this_network', 'internal_specific', 'defined_by_routes'])
        )),
        set_vd_params=dict(type='dict', options=dict(
            vd=dict(type='str'),
            calc_topology_auto=dict(type='bool'),
            ipv4_address=dict(type='str'),
            ipv4_instances=dict(type='int'),
            ipv6_address=dict(type='str'),
            ipv6_instances=dict(type='int'),
            vs_mtu=dict(type='int')
        ))
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "vsx-provisioning-tool"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
