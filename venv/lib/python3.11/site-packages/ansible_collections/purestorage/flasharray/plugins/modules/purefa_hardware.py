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
module: purefa_hardware
version_added: '1.24.0'
short_description: Manage FlashArray Hardware Identification
description:
- Enable or disable FlashArray visual identification lights
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of hardware component
    type: str
    required: true
  enabled:
    description:
    - State of the component identification LED
    type: bool
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Enable identification LED
  purestorage.flasharray.purefa_hardware:
    name: "CH1.FB1"
    enabled: true
    fa_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: Disable identification LED
  purestorage.flasharray.purefa_hardware:
    name: "CH1.FB1"
    enabled: false
    fa_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            enabled=dict(type="bool"),
            name=dict(type="str", required=True),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_array(module)
    changed = False
    res = array.get_hardware(names=[module.params["name"]])
    if res.status_code == 200:
        id_state = getattr(list(res.items)[0], "identify_enabled", None)
        if id_state is not None and id_state != module.params["enabled"]:
            changed = True
            if not module.check_mode:
                res = array.patch_hardware(
                    names=[module.params["name"]],
                    hardware=flasharray.Hardware(
                        identify_enabled=module.params["enabled"]
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to set identification LED for {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )

    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()
