#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-dict-literal,too-many-branches,too-many-locals,line-too-long,wrong-import-position

"""This module sends events to Infinibox."""

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: infini_event
version_added: 2.16.0
short_description:  Create custom events on Infinibox
description:
    - This module creates events on Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  description_template:
    description:
      - The content of the custom event
    type: str
    required: true
  visibility:
    description:
      - The event's visibility
    type: str
    required: false
    choices:
      - CUSTOMER
      - INFINIDAT
    default: CUSTOMER
  level:
    description:
      - The level of the custom event
    type: str
    required: true
    choices:
      - INFO
      - WARNING
      - ERROR
      - CRITICAL
  state:
    description:
      - Creates a custom event when present. Stat is not yet implemented. There is no way to remove events once posted, so abent is also not implemented.
    type: str
    required: false
    default: present
    choices: [ "present" ]

extends_documentation_fragment:
    - infinibox
"""

EXAMPLES = r"""
- name: Create custom info event
  infini_event:
    description_template: Message content
    level: INFO
    state: present
    user: admin
    password: secret
    system: ibox001
"""

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    HAS_INFINISDK,
    execute_state_cleanup,
    get_system,
    infinibox_api_post,
    infinibox_argument_spec,
)


def handle_stat(module):
    """Handle stat state"""
    msg = "handle_stat() is not implemented"
    module.exit_json(msg=msg)


def handle_present(module):
    """Handle present state"""
    system = get_system(module)
    description_template = module.params["description_template"]
    level = module.params["level"]
    visibility = module.params["visibility"]

    path = "events/custom"
    json_data = {
        "description_template": description_template,
        "level": level,
        "visibility": visibility,
    }
    infinibox_api_post(module, path, json_data)
    module.exit_json(changed=True, msg="Event posted")


def execute_state(module):
    """Handle states"""
    state = module.params["state"]
    try:
        if state == "stat":
            handle_stat(module)
        elif state == "present":
            handle_present(module)
        else:
            module.exit_json(msg=f"Internal handler error. Invalid state: {state}")
    finally:
        execute_state_cleanup(module)


def main():
    """ Main """
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            description_template=dict(required=True),
            level=dict(required=True, choices=["INFO", "WARNING", "ERROR", "CRITICAL"]),
            state=dict(required=False, default="present", choices=["present"]),
            visibility=dict(default="CUSTOMER", required=False, choices=["CUSTOMER", "INFINIDAT"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.exit_json(msg=missing_required_lib("infinisdk"))

    execute_state(module)


if __name__ == "__main__":
    main()
