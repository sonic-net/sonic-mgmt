#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefb_bladename
version_added: '1.0.0'
short_description: Configure Pure Storage FlashBlade name
description:
- Configure name of Pure Storage FlashBlades.
- Ideal for Day 0 initial configuration.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Set the FlashBlade name
    type: str
    default: present
    choices: [ present ]
  name:
    description:
    - Name of the FlashBlade. Must conform to correct naming schema.
    type: str
    required: true
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Set new FlashBlade name
  purestorage.flashblade.purefb_bladename:
    name: new-flashblade-name
    state: present
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""


HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import Array
except ImportError:
    HAS_PYPURECLIENT = False


import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def update_name(module, blade):
    """Change aray name"""
    changed = True
    if not module.check_mode:
        blade_settings = Array(name=module.params["name"])
        res = blade.patch_arrays(array=blade_settings)
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to change array name to {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )

    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            state=dict(type="str", default="present", choices=["present"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PYPURECLIENT:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    blade = get_system(module)
    pattern = re.compile("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,54}[a-zA-Z0-9])?$")
    if not pattern.match(module.params["name"]):
        module.fail_json(
            msg="FlashBlade name {0} does not conform to array name rules".format(
                module.params["name"]
            )
        )
    if module.params["name"] != list(blade.get_arrays().items)[0].name:
        update_name(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
