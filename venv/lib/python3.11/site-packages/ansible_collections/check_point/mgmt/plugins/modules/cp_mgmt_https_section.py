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
module: cp_mgmt_https_section
short_description: Manages https-section objects on Checkpoint over Web Services API
description:
  - Manages https-section objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R80.40 management version.
version_added: "2.0.0"
author: "Or Soffer (@chkp-orso)"
options:
  layer:
    description:
      - Layer that holds the Object. Identified by the Name or UID.
    type: str
  position:
    description:
      - Position in the rulebase.
    type: str
  relative_position:
    description:
      - Position in the rulebase.
      - Use of this field is relevant only for "add" operation.
    type: dict
    version_added: "6.0.0"
    suboptions:
      below:
        description:
          - Add section below specific rule/section identified by name.
        type: str
      above:
        description:
          - Add section above specific rule/section identified by name.
        type: str
      top:
        description:
          - Add section to the top of a specific section identified by name.
        type: str
      bottom:
        description:
          - Add section to the bottom of a specific section identified by name.
        type: str
  name:
    description:
      - Object name.
    type: str
    required: True
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
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-https-section
  cp_mgmt_https_section:
    layer: Default Layer
    name: New Section 1
    position: 1
    state: present

- name: set-https-section
  cp_mgmt_https_section:
    layer: Default Layer
    name: New Section 1
    state: present

- name: delete-https-section
  cp_mgmt_https_section:
    layer: Default Layer
    name: New Section 2
    state: absent
"""

RETURN = """
cp_mgmt_https_section:
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
        layer=dict(type="str"),
        position=dict(type="str"),
        relative_position=dict(
            type="dict",
            options=dict(
                below=dict(type="str"),
                above=dict(type="str"),
                top=dict(type="str"),
                bottom=dict(type="str"),
            ),
        ),
        name=dict(type="str", required=True),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
        ignore_warnings=dict(type="bool"),
        ignore_errors=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )
    api_call_object = "https-section"

    if module.params["relative_position"] is not None:
        if module.params["position"] is not None:
            raise AssertionError(
                "The use of both 'relative_position' and 'position' arguments isn't allowed"
            )
        module.params["position"] = module.params["relative_position"]
    module.params.pop("relative_position")

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
