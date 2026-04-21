#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2020, Simon Dodsley (simon@purestorage.com)
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
module: purefb_banner
version_added: '1.4.0'
short_description: Configure Pure Storage FlashBlade GUI and SSH MOTD message
description:
- Configure MOTD for Pure Storage FlashBlades.
- This will be shown during an SSH or GUI login to the system.
- Multiple line messages can be achieved using \\n.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Set ot delete the MOTD
    default: present
    type: str
    choices: [ present, absent ]
  banner:
    description:
    - Banner text, or MOTD, to use
    type: str
    default: "Welcome to the machine..."
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Set new banner text
  purestorage.flashblade.purefb_banner:
    banner: "Banner over\ntwo lines"
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete banner text
  purestorage.flashblade.purefb_banner:
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = r"""
"""

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import Array
except ImportError:
    HAS_PYPURECLIENT = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def set_banner(module, blade):
    """Set MOTD banner text"""
    changed = True
    if not module.check_mode:
        if not module.params["banner"]:
            module.fail_json(msg="Invalid MOTD banner given")
        blade_settings = Array(banner=module.params["banner"])
        res = blade.patch_arrays(array=blade_settings)
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to set MOTD banner text. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_banner(module, blade):
    """Delete MOTD banner text"""
    changed = True
    if not module.check_mode:
        blade_settings = Array(banner="")
        res = blade.patch_arrays(array=blade_settings)
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete current MOTD banner text. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            banner=dict(type="str", default="Welcome to the machine..."),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        )
    )

    required_if = [("state", "present", ["banner"])]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )
    if not HAS_PYPURECLIENT:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    state = module.params["state"]
    blade = get_system(module)
    current_banner = list(blade.get_arrays().items)[0].banner

    # set banner if empty value or value differs
    if state == "present" and (
        not current_banner or current_banner != module.params["banner"]
    ):
        set_banner(module, blade)
    # clear banner if it has a value
    elif state == "absent" and current_banner:
        delete_banner(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
