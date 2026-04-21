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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: cp_mgmt_interoperable_device
short_description: Manages interoperable-device objects on Checkpoint over Web Services API
description:
  - Manages interoperable-device objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R81.20 management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  ip_address:
    description:
      - IPv4 or IPv6 address.
    type: str
  ipv4_address:
    description:
      - IPv4 address of the Interoperable Device.
    type: str
  ipv6_address:
    description:
      - IPv6 address of the Interoperable Device.
    type: str
  interfaces:
    description:
      - Network interfaces.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Object name. Must be unique in the domain.
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
      topology:
        description:
          - Topology configuration.
        type: str
        choices: ['external', 'internal']
      topology_settings:
        description:
          - Internal topology settings.
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
      domains_to_process:
        description:
          - Indicates which domains to process the commands on. It cannot be used with the details-level full, must be run from the System Domain
            only and with ignore-warnings true. Valid values are, CURRENT_DOMAIN, ALL_DOMAINS_ON_THIS_SERVER.
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
  vpn_settings:
    description:
      - VPN domain properties for the Interoperable Device.
    type: dict
    suboptions:
      vpn_domain:
        description:
          - Network group representing the customized encryption domain. Must be set when vpn-domain-type is set to 'manual' option.
        type: str
      vpn_domain_exclude_external_ip_addresses:
        description:
          - Exclude the external IP addresses from the VPN domain of this Interoperable device.
        type: bool
      vpn_domain_type:
        description:
          - Indicates the encryption domain.
        type: str
        choices: ['manual', 'addresses_behind_gw']
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
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
  groups:
    description:
      - Collection of group identifiers.
    type: list
    elements: str
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-interoperable-device
  cp_mgmt_interoperable_device:
    ip_address: 192.168.1.6
    name: NewInteroperableDevice
    state: present

- name: set-interoperable-device
  cp_mgmt_interoperable_device:
    ip_address: 192.168.1.6
    name: NewInteroperableDevice
    state: present

- name: delete-interoperable-device
  cp_mgmt_interoperable_device:
    name: NewInteroperableDevice
    state: absent
"""

RETURN = """
cp_mgmt_interoperable_device:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_objects,
    api_call,
)


def main():
    argument_spec = dict(
        name=dict(type="str", required=True),
        ip_address=dict(type="str"),
        ipv4_address=dict(type="str"),
        ipv6_address=dict(type="str"),
        interfaces=dict(
            type="list",
            elements="dict",
            options=dict(
                name=dict(type="str"),
                ip_address=dict(type="str"),
                ipv4_address=dict(type="str"),
                ipv6_address=dict(type="str"),
                network_mask=dict(type="str"),
                ipv4_network_mask=dict(type="str"),
                ipv6_network_mask=dict(type="str"),
                mask_length=dict(type="str"),
                ipv4_mask_length=dict(type="str"),
                ipv6_mask_length=dict(type="str"),
                tags=dict(type="list", elements="str"),
                topology=dict(type="str", choices=["external", "internal"]),
                topology_settings=dict(
                    type="dict",
                    options=dict(
                        interface_leads_to_dmz=dict(type="bool"),
                        ip_address_behind_this_interface=dict(
                            type="str",
                            choices=[
                                "not defined",
                                "network defined by the interface ip and net mask",
                                "network defined by routing",
                                "specific",
                            ],
                        ),
                        specific_network=dict(type="str"),
                    ),
                ),
                color=dict(
                    type="str",
                    choices=[
                        "aquamarine",
                        "black",
                        "blue",
                        "crete blue",
                        "burlywood",
                        "cyan",
                        "dark green",
                        "khaki",
                        "orchid",
                        "dark orange",
                        "dark sea green",
                        "pink",
                        "turquoise",
                        "dark blue",
                        "firebrick",
                        "brown",
                        "forest green",
                        "gold",
                        "dark gold",
                        "gray",
                        "dark gray",
                        "light green",
                        "lemon chiffon",
                        "coral",
                        "sea green",
                        "sky blue",
                        "magenta",
                        "purple",
                        "slate blue",
                        "violet red",
                        "navy blue",
                        "olive",
                        "orange",
                        "red",
                        "sienna",
                        "yellow",
                    ],
                ),
                comments=dict(type="str"),
                details_level=dict(
                    type="str", choices=["uid", "standard", "full"]
                ),
                domains_to_process=dict(type="list", elements="str"),
                ignore_warnings=dict(type="bool"),
                ignore_errors=dict(type="bool"),
            ),
        ),
        vpn_settings=dict(
            type="dict",
            options=dict(
                vpn_domain=dict(type="str"),
                vpn_domain_exclude_external_ip_addresses=dict(type="bool"),
                vpn_domain_type=dict(
                    type="str", choices=["manual", "addresses_behind_gw"]
                ),
            ),
        ),
        tags=dict(type="list", elements="str"),
        color=dict(
            type="str",
            choices=[
                "aquamarine",
                "black",
                "blue",
                "crete blue",
                "burlywood",
                "cyan",
                "dark green",
                "khaki",
                "orchid",
                "dark orange",
                "dark sea green",
                "pink",
                "turquoise",
                "dark blue",
                "firebrick",
                "brown",
                "forest green",
                "gold",
                "dark gold",
                "gray",
                "dark gray",
                "light green",
                "lemon chiffon",
                "coral",
                "sea green",
                "sky blue",
                "magenta",
                "purple",
                "slate blue",
                "violet red",
                "navy blue",
                "olive",
                "orange",
                "red",
                "sienna",
                "yellow",
            ],
        ),
        comments=dict(type="str"),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
        domains_to_process=dict(type="list", elements="str"),
        ignore_warnings=dict(type="bool"),
        groups=dict(type="list", elements="str"),
        ignore_errors=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )
    api_call_object = "interoperable-device"

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
