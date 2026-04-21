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
module: purefa_maintenance
version_added: '1.7.0'
short_description: Configure Pure Storage FlashArray Maintence Windows
description:
- Configuration for Pure Storage FlashArray Maintenance Windows.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete maintennance window
    type: str
    default: present
    choices: [ absent, present ]
  timeout :
    type: int
    default: 3600
    description:
    - Maintenance window period, specified in seconds.
    - Range allowed is 1 hour (3600 seconds) to 48 hours (172800 seconds)
    - Default setting is 1 hour (3600 seconds)
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Delete exisitng maintenance window
  purestorage.flasharray.purefa_maintenance:
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Set maintnence window to default of 1 hour
  purestorage.flasharray.purefa_maintenance:
    state: present
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Update existing maintnence window
  purestorage.flasharray.purefa_maintenance:
    state: present
    timeout: 86400
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import MaintenanceWindowPost
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)


def delete_window(module, array):
    """Delete Maintenance Window"""
    changed = False
    if list(array.get_maintenance_windows().items):
        changed = True
        if not module.check_mode:
            state = array.delete_maintenance_windows(names=["environment"])
            if state.status_code != 200:
                changed = False
    module.exit_json(changed=changed)


def set_window(module, array):
    """Set Maintenace Window"""
    changed = True
    if not 3600 <= module.params["timeout"] <= 172800:
        module.fail_json(
            msg="Maintenance Window Timeout is out of range (3600 to 172800)"
        )
    window = MaintenanceWindowPost(timeout=module.params["timeout"] * 1000)
    if not module.check_mode:
        state = array.post_maintenance_windows(
            names=["environment"], maintenance_window=window
        )
        if state.status_code != 200:
            module.fail_json(msg="Setting maintenance window failed")
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            timeout=dict(type="int", default=3600),
            state=dict(type="str", default="present", choices=["absent", "present"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_array(module)

    if module.params["state"] == "absent":
        delete_window(module, array)
    else:
        set_window(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
