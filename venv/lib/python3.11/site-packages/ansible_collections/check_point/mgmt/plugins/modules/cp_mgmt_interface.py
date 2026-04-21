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
module: cp_mgmt_interface
short_description: Manages interface objects on Checkpoint over Web Services API
description:
  - Manages interface objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R82 management version.
version_added: "6.2.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Network interface name.
    type: str
    required: True
  gateway_uid:
    description:
      - Gateway or cluster object uid that the interface belongs to.
    type: str
    required: True
  anti_spoofing:
    description:
      - Enable anti-spoofing.
    type: bool
  anti_spoofing_settings:
    description:
      - Anti Spoofing Settings.
    type: dict
    suboptions:
      action:
        description:
          - If packets will be rejected (the Prevent option) or whether the packets will be monitored (the Detect option).
        type: str
        choices: ['prevent', 'detect']
      exclude_packets:
        description:
          - Don't check packets from excluded network.
        type: bool
      excluded_network_name:
        description:
          - Excluded network name.
        type: str
      excluded_network_uid:
        description:
          - Excluded network UID.
        type: str
      spoof_tracking:
        description:
          - Spoof tracking.
        type: str
        choices: ['none', 'log', 'alert']
  cluster_members:
    description:
      - Network interface settings for cluster members.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Cluster member network interface name.
        type: str
      member_name:
        description:
          - Cluster member object name.
        type: str
      ip_address:
        description:
          - IPv4 or IPv6 address. If both addresses are required use ipv4-address and ipv6-address fields explicitly.
        type: str
      ipv4_address:
        description:
          - IPv4 address.
        type: str
      ipv6_address:
        description:
          - IPv6 address.
        type: str
      network_mask:
        description:
          - IPv4 or IPv6 network mask. If both masks are required use ipv4-network-mask and ipv6-network-mask fields explicitly. Instead of
            providing mask itself it is possible to specify IPv4 or IPv6 mask length in mask-length field. If both masks length are required use
            ipv4-mask-length and  ipv6-mask-length fields explicitly.
        type: str
      ipv4_network_mask:
        description:
          - IPv4 network address.
        type: str
      ipv6_network_mask:
        description:
          - IPv6 network address.
        type: str
      mask_length:
        description:
          - IPv4 or IPv6 network mask length.
        type: str
      ipv4_mask_length:
        description:
          - IPv4 network mask length.
        type: str
      ipv6_mask_length:
        description:
          - IPv6 network mask length.
        type: str
      tags:
        description:
          - Collection of tag identifiers.
        type: list
        elements: str
      color:
        description:
          - Color of the object. Should be one of existing colors.
        type: str
        choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange',
                 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray',
                 'light green', 'lemon chiffon', 'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive',
                 'orange', 'red', 'sienna', 'yellow']
      comments:
        description:
          - Comments string.
        type: str
      details_level:
        description:
          - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
            representation of the object.
        type: str
        choices: ['uid', 'standard', 'full']
      ignore_warnings:
        description:
          - Apply changes ignoring warnings.
        type: bool
      ignore_errors:
        description:
          - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
        type: bool
  cluster_network_type:
    description:
      - Cluster interface type.
    type: str
    choices: ['cluster', 'sync', 'cluster + sync', 'private']
  dynamic_ip:
    description:
      - Enable dynamic interface.
    type: bool
  ipv4_address:
    description:
      - IPv4 network address.
    type: str
  ipv4_mask_length:
    description:
      - IPv4 mask length.
    type: int
  ipv4_network_mask:
    description:
      - IPv4 network mask.
    type: str
  ipv6_address:
    description:
      - IPv6 address.
    type: str
  ipv6_mask_length:
    description:
      - IPv6 mask length.
    type: int
  ipv6_network_mask:
    description:
      - IPv6 network mask.
    type: str
  monitored_by_cluster:
    description:
      - When Private is selected as the Cluster interface type, cluster can monitor or not monitor the interface.
    type: bool
  network_interface_type:
    description:
      - Network Interface Type.
    type: str
    choices: ['alias', 'bond', 'bridge', 'bridge member', 'ethernet', 'loopback', '6 in 4 tunnel', 'pppoe', 'vpn tunnel', 'vlan']
  security_zone_settings:
    description:
      - Security Zone Settings.
    type: dict
    suboptions:
      auto_calculated:
        description:
          - Security Zone is calculated according to where the interface leads to.
        type: bool
      specific_zone:
        description:
          - Security Zone specified manually.
        type: str
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
  topology:
    description:
      - Topology configuration.
    type: str
    choices: ['automatic', 'external', 'internal']
  topology_settings:
    description:
      - Topology Settings.
    type: dict
    suboptions:
      interface_leads_to_dmz:
        description:
          - Whether this interface leads to demilitarized zone (perimeter network).
        type: bool
      ip_address_behind_this_interface:
        description:
          - Network settings behind this interface.
        type: str
        choices: ['not defined', 'network defined by the interface ip and net mask', 'network defined by routing', 'specific']
      specific_network:
        description:
          - Network behind this interface.
        type: str
      specific_network_uid:
        description:
          - N/A
        type: str
  color:
    description:
      - Color of the object. Should be one of existing colors.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  domains_to_process:
    description:
      - Indicates which domains to process the commands on. It cannot be used with the details-level full, must be run from the System Domain only and
        with ignore-warnings true. Valid values are, CURRENT_DOMAIN, ALL_DOMAINS_ON_THIS_SERVER.
    type: list
    elements: str
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-interface
  cp_mgmt_interface:
    anti_spoofing: true
    anti_spoofing_settings:
      action: detect
      exclude_packets: false
      spoof_tracking: log
    cluster_members:
      - ipv4_address: 2.2.2.1
        ipv4_mask_length: 24
        ipv4_network_mask: 255.255.255.0
        member_name: member1
        name: eth4
      - ipv4_address: 2.2.2.2
        ipv4_mask_length: 24
        ipv4_network_mask: 255.255.255.0
        member_name: member2
        name: eth4
    cluster_network_type: cluster
    gateway_uid: 20ec49e8-8cd8-4ad4-b204-0de8ae4e0e17
    ignore_warnings: false
    ipv4_address: 1.1.1.111
    ipv4_mask_length: 24
    name: eth0
    security_zone_settings:
      auto_calculated: false
      specific_zone: InternalZone
    state: present
    topology: internal
    topology_settings:
      interface_leads_to_dmz: false
      ip_address_behind_this_interface: network defined by routing

- name: set-interface
  cp_mgmt_interface:
    cluster_members:
      - ipv4_address: 4.4.4.1
        ipv4_mask_length: 22
        member_name: memberReal1
        uid: db4f8a63-5a94-46d8-b9e0-a63870bded3d
      - ipv4_address: 4.4.4.2
        ipv4_mask_length: 22
        member_name: memberReal2
        uid: baca571e-8ada-4be9-8966-145388f8e238
    cluster_network_type: cluster + sync
    ipv4_address: 4.4.4.111
    ipv4_mask_length: 22
    state: present
    topology: internal
    topology_settings:
      ip_address_behind_this_interface: network defined by routing
    name: eth0
    gateway_uid: 20ec49e8-8cd8-4ad4-b204-0de8ae4e0e17

- name: delete-interface
  cp_mgmt_interface:
    state: absent
    name: eth0
    gateway_uid: 20ec49e8-8cd8-4ad4-b204-0de8ae4e0e17
"""

RETURN = """
cp_mgmt_interface:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        gateway_uid=dict(type='str', required=True),
        anti_spoofing=dict(type='bool'),
        anti_spoofing_settings=dict(type='dict', options=dict(
            action=dict(type='str', choices=['prevent', 'detect']),
            exclude_packets=dict(type='bool'),
            excluded_network_name=dict(type='str'),
            excluded_network_uid=dict(type='str'),
            spoof_tracking=dict(type='str', choices=['none', 'log', 'alert'])
        )),
        cluster_members=dict(type='list', elements='dict', options=dict(
            name=dict(type='str'),
            member_name=dict(type='str'),
            ip_address=dict(type='str'),
            ipv4_address=dict(type='str'),
            ipv6_address=dict(type='str'),
            network_mask=dict(type='str'),
            ipv4_network_mask=dict(type='str'),
            ipv6_network_mask=dict(type='str'),
            mask_length=dict(type='str'),
            ipv4_mask_length=dict(type='str'),
            ipv6_mask_length=dict(type='str'),
            tags=dict(type='list', elements='str'),
            color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan',
                                            'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick',
                                            'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral',
                                            'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red',
                                            'sienna', 'yellow']),
            comments=dict(type='str'),
            details_level=dict(type='str', choices=['uid', 'standard', 'full']),
            ignore_warnings=dict(type='bool'),
            ignore_errors=dict(type='bool')
        )),
        cluster_network_type=dict(type='str', choices=['cluster', 'sync', 'cluster + sync', 'private']),
        dynamic_ip=dict(type='bool'),
        ipv4_address=dict(type='str'),
        ipv4_mask_length=dict(type='int'),
        ipv4_network_mask=dict(type='str'),
        ipv6_address=dict(type='str'),
        ipv6_mask_length=dict(type='int'),
        ipv6_network_mask=dict(type='str'),
        monitored_by_cluster=dict(type='bool'),
        network_interface_type=dict(type='str', choices=['alias', 'bond', 'bridge', 'bridge member',
                                                         'ethernet', 'loopback', '6 in 4 tunnel', 'pppoe', 'vpn tunnel', 'vlan']),
        security_zone_settings=dict(type='dict', options=dict(
            auto_calculated=dict(type='bool'),
            specific_zone=dict(type='str')
        )),
        tags=dict(type='list', elements='str'),
        topology=dict(type='str', choices=['automatic', 'external', 'internal']),
        topology_settings=dict(type='dict', options=dict(
            interface_leads_to_dmz=dict(type='bool'),
            ip_address_behind_this_interface=dict(type='str', choices=['not defined',
                                                                       'network defined by the interface ip and net mask', 'network defined by routing',
                                                                       'specific']),
            specific_network=dict(type='str'),
            specific_network_uid=dict(type='str')
        )),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        domains_to_process=dict(type='list', elements='str'),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'interface'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
