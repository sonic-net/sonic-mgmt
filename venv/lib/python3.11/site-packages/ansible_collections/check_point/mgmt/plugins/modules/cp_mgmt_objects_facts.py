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
module: cp_mgmt_objects_facts
short_description: Get objects objects facts on Checkpoint over Web Services API
description:
  - Get objects facts on Checkpoint devices.
  - All operations are performed over Web Services API.
  - This module handles both operations, get a specific object and get several objects,
    For getting a specific object use the parameter 'name'.
  - Available from R80 management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  uid:
    description:
    - Object unique identifier.
    type: str
  uids:
    description:
      - List of UIDs of the objects to retrieve.
      - Available from R81.10 JHF management version.
    type: list
    elements: str
  filter:
    description:
      - Search expression to filter objects by. The provided text should be exactly the same as it would be given in Smart Console. The logical
        operators in the expression ('AND', 'OR') should be provided in capital letters. By default, the search involves both a textual search and a IP
        search. To use IP search only, set the "ip-only" parameter to true.
      - Available from R80.10 management version.
    type: str
  ip_only:
    description:
      - If using "filter", use this field to search objects by their IP address only, without involving the textual search.<br><br>IP search use
        cases<br>&nbsp;&nbsp;&nbsp;&nbsp; <ul><li>Full IPv4 address matches for,<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - Hosts, Check Point
        Hosts and Gateways with exact IPv4 match or with interfaces which subnet contains the search
        address<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - IPv4 Networks and IPv4 Address Ranges that contain the search address</li>
        <br>&nbsp;&nbsp;&nbsp;&nbsp; <li>Partial IPv4 address matches for,<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - Hosts, Networks, Check Point
        Hosts and Gateways with IPv4 address that starts from the search address<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - Hosts, Check Point
        Hosts and Gateways with interfaces which subnet address starts from the search address<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - IPv4
        Address Ranges with first address or last address that starts from the search address<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - IPv4
        Networks and IPv4 Address Ranges that contain the network derived from the search address supplemented with missing octets (all
        zeroes)<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - Hosts, Check Point Hosts and Gateways with interfaces which subnet contains the network
        derived from the search address supplemented with missing octets (all zeroes)</li><br>&nbsp;&nbsp;&nbsp;&nbsp; <li>IPv6
        address,<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - Not supported</li></ul><br><br> * Check Point Host is a server of type Network Policy
        Management, Logging & Status, SmartEvent, etc.<br> * When one IP address is checked to start from another (partial) IP address - only full octets are
        considered <br> * Check Examples part for IP search examples.
      - Available from R80.10 management version.
    type: bool
  limit:
    description:
      - The maximal number of returned results.
        This parameter is relevant only for getting a specific object.
    type: int
  offset:
    description:
      - Number of the results to initially skip.
        This parameter is relevant only for getting a specific object.
    type: int
  order:
    description:
      - Sorts the results by search criteria. Automatically sorts the results by Name, in the ascending order.
        This parameter is relevant only for getting a specific object.
    type: list
    elements: dict
    suboptions:
      ASC:
        description:
          - Sorts results by the given field in ascending order.
        type: str
        choices: ['name']
      DESC:
        description:
          - Sorts results by the given field in descending order.
        type: str
        choices: ['name']
  type:
    description:
      - The objects' type, e.g., host, service-tcp, network, address-range...
    type: str
  dereference_group_members:
    description:
      - Indicates whether to dereference "members" field by details level for every object in reply.
      - Available from R80.10 management version.
    type: bool
  show_membership:
    description:
      - Indicates whether to calculate and show "groups" field for every object in reply.
      - Available from R80.10 management version.
    type: bool
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
      - Available from R81 management version.
    type: list
    elements: str
extends_documentation_fragment: check_point.mgmt.checkpoint_facts
"""

EXAMPLES = """
- name: show-objects
  cp_mgmt_objects_facts:
    limit: 50
    offset: 0
    order:
      - ASC: name
    type: group

- name: show-object
  cp_mgmt_objects_facts:
    uid: ef82887c-d08f-49a3-a18f-a376be633848
"""

RETURN = """
ansible_facts:
  description: The checkpoint object facts.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_facts,
    api_call_facts,
)


def main():
    argument_spec = dict(
        uid=dict(type="str"),
        uids=dict(type="list", elements="str"),
        filter=dict(type="str"),
        ip_only=dict(type="bool"),
        limit=dict(type="int"),
        offset=dict(type="int"),
        order=dict(
            type="list",
            elements="dict",
            options=dict(
                ASC=dict(type="str", choices=["name"]),
                DESC=dict(type="str", choices=["name"]),
            ),
        ),
        type=dict(type="str"),
        dereference_group_members=dict(type="bool"),
        show_membership=dict(type="bool"),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
        domains_to_process=dict(type="list", elements="str"),
    )
    argument_spec.update(checkpoint_argument_spec_for_facts)

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )

    api_call_object = "object"
    api_call_object_plural_version = "objects"

    result = api_call_facts(
        module, api_call_object, api_call_object_plural_version
    )
    module.exit_json(ansible_facts=result)


if __name__ == "__main__":
    main()
