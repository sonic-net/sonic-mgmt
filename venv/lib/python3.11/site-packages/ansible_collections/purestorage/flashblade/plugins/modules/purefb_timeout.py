#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021, Simon Dodsley (simon@purestorage.com)
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
module: purefb_timeout
version_added: '1.6.0'
short_description: Configure Pure Storage FlashBlade GUI idle timeout
description:
- Configure GUI idle timeout for Pure Storage FlashBlade.
- This does not affect existing GUI sessions.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Set or disable the GUI idle timeout
    default: present
    type: str
    choices: [ present, absent ]
  timeout:
    description:
    - Minutes for idle timeout.
    type: int
    default: 30
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Set GUI idle timeout to 25 minutes
  purestorage.flashblade.purefb_timeout:
    timeout: 25
    state: present
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: Disable idle timeout
  purestorage.flashblade.purefb_timeout:
    state: absent
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flashblade
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def set_timeout(module, blade):
    """Set GUI idle timeout"""
    changed = True
    if not module.check_mode:
        res = blade.patch_arrays(
            flashblade.Array(idle_timeout=module.params["timeout"] * 60000)
        )
        if res.status_code != 200:
            module.fail_json(msg="Failed to set GUI idle timeout")

    module.exit_json(changed=changed)


def disable_timeout(module, blade):
    """Disable idle timeout"""
    changed = True
    if not module.check_mode:
        res = blade.patch_arrays(flashblade.Array(idle_timeout=0))
        if res.status_code != 200:
            module.fail_json(msg="Failed to disable GUI idle timeout")
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            timeout=dict(type="int", default=30),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    blade = get_system(module)

    state = module.params["state"]
    if 5 < module.params["timeout"] > 180 and module.params["timeout"] != 0:
        module.fail_json(msg="Timeout value must be between 5 and 180 minutes")
    blade = get_system(module)
    current_timeout = list(blade.get_arrays().items)[0].idle_timeout / 60000
    if state == "present" and current_timeout != module.params["timeout"]:
        set_timeout(module, blade)
    elif state == "absent" and current_timeout != 0:
        disable_timeout(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
