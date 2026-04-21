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
module: cp_mgmt_lsm_gateway
short_description: Manages lsm-gateway objects on Checkpoint over Web Services API
description:
  - Manages lsm-gateway objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R81.10 management version.
version_added: "2.3.0"
author: "Shiran Golzar (@chkp-shirango)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  security_profile:
    description:
      - LSM profile.
    type: str
  device_id:
    description:
      - Device ID.
      - Available from R81.20 management version.
    type: str
    version_added: "6.3.0"
  dynamic_objects:
    description:
      - Dynamic Objects.
      - Available from R81.20 management version.
    type: list
    elements: dict
    version_added: "6.3.0"
    suboptions:
      name:
        description:
          - Object name. Must be unique in the domain.
        type: str
      resolved_ip_addresses:
        description:
          - Single IP-address or a range of addresses.
        type: list
        elements: dict
        suboptions:
          ipv4_address:
            description:
              - IPv4 Address.
            type: str
          ipv4_address_range:
            description:
              - IPv4 Address range.
            type: dict
            suboptions:
              from_ipv4_address:
                description:
                  - First IPv4 address of the IP address range.
                type: str
              to_ipv4_address:
                description:
                  - Last IPv4 address of the IP address range.
                type: str
  provisioning_settings:
    description:
      - Provisioning settings.
    type: dict
    suboptions:
      provisioning_profile:
        description:
          - Provisioning profile.
        type: str
  provisioning_state:
    description:
      - Provisioning state. By default the state is 'manual'- enable provisioning but not attach to profile.
      - If 'using-profile' state is provided a provisioning profile must be provided in provisioning-settings.
    type: str
    choices: ['off', 'manual', 'using-profile']
  sic:
    description:
      - Secure Internal Communication.
    type: dict
    suboptions:
      ip_address:
        description:
          - IP address. When IP address is provided- initiate trusted communication immediately using this IP address.
        type: str
      one_time_password:
        description:
          - One-time password. When one-time password is provided without ip-address- trusted communication is automatically initiated  when the
            gateway connects to the Security Management server for the first time.
        type: str
  topology:
    description:
      - Topology.
      - Available from R81.20 management version.
    type: dict
    version_added: "6.3.0"
    suboptions:
      manual_vpn_domain:
        description:
          - A list of IP-addresses ranges, defined the VPN community network.
          - This field is relevant only when 'manual' option of vpn-domain is checked.
        type: list
        elements: dict
        suboptions:
          comments:
            description:
              - Comments string.
            type: str
          from_ipv4_address:
            description:
              - First IPv4 address of the IP address range.
            type: str
          to_ipv4_address:
            description:
              - Last IPv4 address of the IP address range.
            type: str
      vpn_domain:
        description:
          - VPN Domain type. 'external-interfaces-only' is relevnt only for Gaia devices.
            'hide-behind-gateway-external-ip-address' is relevant only for SMB devices.
        type: str
        choices: ['not-defined', 'external-ip-addresses-only', 'hide-behind-gateway-external-ip-address', 'all-ip-addresses-behind-the-gateway', 'manual']
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
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
    version_added: "6.3.0"
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
- name: add-lsm-gateway
  cp_mgmt_lsm_gateway:
    name: lsm_gateway
    provisioning_settings:
      provisioning_profile: prv_profile
    provisioning_state: using-profile
    security_profile: lsm_profile
    sic:
      ip_address: 1.2.3.4
      one_time_password: aaaa
    state: present

- name: set-lsm-gateway
  cp_mgmt_lsm_gateway:
    name: lsm_gateway
    provisioning_settings:
      provisioning_profile: prv_profile
    provisioning_state: using-profile
    security_profile: lsm_profile
    sic:
      ip_address: 1.2.3.4
      one_time_password: aaaa
    state: present

- name: delete-lsm-gateway
  cp_mgmt_lsm_gateway:
    name: lsm_gateway
    state: absent
"""

RETURN = """
cp_mgmt_lsm_gateway:
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
        security_profile=dict(type="str"),
        device_id=dict(type='str'),
        dynamic_objects=dict(type='list', elements="dict", options=dict(
            name=dict(type='str'),
            resolved_ip_addresses=dict(type='list', elements="dict", options=dict(
                ipv4_address=dict(type='str'),
                ipv4_address_range=dict(type='dict', options=dict(
                    from_ipv4_address=dict(type='str'),
                    to_ipv4_address=dict(type='str')
                ))
            ))
        )),
        provisioning_settings=dict(
            type="dict", options=dict(provisioning_profile=dict(type="str"))
        ),
        provisioning_state=dict(
            type="str", choices=["off", "manual", "using-profile"]
        ),
        sic=dict(
            type="dict",
            options=dict(
                ip_address=dict(type="str"),
                one_time_password=dict(type="str", no_log=True),
            ),
        ),
        topology=dict(type='dict', options=dict(
            manual_vpn_domain=dict(type='list', elements="dict", options=dict(
                comments=dict(type='str'),
                from_ipv4_address=dict(type='str'),
                to_ipv4_address=dict(type='str')
            )),
            vpn_domain=dict(type='str', choices=['not-defined',
                                                 'external-ip-addresses-only',
                                                 'hide-behind-gateway-external-ip-address',
                                                 'all-ip-addresses-behind-the-gateway',
                                                 'manual'])
        )),
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
        tags=dict(type="list", elements="str"),
        ignore_warnings=dict(type="bool"),
        ignore_errors=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )
    api_call_object = "lsm-gateway"

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
