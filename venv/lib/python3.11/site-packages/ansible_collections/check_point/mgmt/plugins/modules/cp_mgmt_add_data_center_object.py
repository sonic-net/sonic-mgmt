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
module: cp_mgmt_add_data_center_object
short_description: Imports a Data Center Object from a Data Center Server.<br> Data Center Object represents an object in the cloud environment.
description:
  - Imports a Data Center Object from a Data Center Server.<br> Data Center Object represents an object in the cloud environment, e.g. a virtual machine,
    cluster, network and more.<br> Use the show-data-center-content command to see the Data Center Objects that can be imported from a Data Center Server.
  - All operations are performed over Web Services API.
  - Available from R80.10 management version.
version_added: "2.0.0"
author: "Or Soffer (@chkp-orso)"
options:
  data_center_name:
    description:
      - Name of the Data Center Server the object is in.
    type: str
  data_center_uid:
    description:
      - Unique identifier of the Data Center Server the object is in.
    type: str
  uri:
    description:
      - URI of the object in the Data Center Server.
    type: str
  uid_in_data_center:
    description:
      - Unique identifier of the object in the Data Center Server.
    type: str
  name:
    description:
      - Override default name on data-center.
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
  groups:
    description:
      - Collection of group identifiers.
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
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: add-data-center-object
  cp_mgmt_add_data_center_object:
    data_center_name: vCenter 1
    name: VM1 mgmt name
    uri: /Datacenters/VMs/My VM1
"""

RETURN = """
cp_mgmt_add_data_center_object:
  description: The checkpoint add-data-center-object output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_commands,
    api_command,
)


def main():
    argument_spec = dict(
        data_center_name=dict(type="str"),
        data_center_uid=dict(type="str"),
        uri=dict(type="str"),
        uid_in_data_center=dict(type="str"),
        name=dict(type="str"),
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
        groups=dict(type="list", elements="str"),
        ignore_warnings=dict(type="bool"),
        ignore_errors=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "add-data-center-object"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
