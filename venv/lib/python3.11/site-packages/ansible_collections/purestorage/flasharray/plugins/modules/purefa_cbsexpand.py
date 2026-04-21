#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2023, Simon Dodsley (simon@purestorage.com)
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
module: purefa_cbsexpand
version_added: '1.0.0'
short_description: Modify the CBS array capacity
description:
- Expand the CBS array capacity. Capacity can only be updated to specific values.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Action to be performed on the CBS array.
    - I{list) will provide the options that I(capacity), in bytes, can be set to.
    default: show
    choices: [ show, expand ]
    type: str
  capacity:
    description:
    - Requested capacity of CBS array in bytes.
    type: int
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Show available expansion capacities
  purestorage.flasharray.purefa_cbsexpand:
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Expand CBS to new capacity
  purestorage.flasharray.purefa_cbsexpand:
    state: expand
    capacity: 10995116277760
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)


EXPAND_API_VERSION = "2.29"


def _is_cbs(array):
    """Is the selected array a Cloud Block Store"""
    model = list(array.get_hardware(filter="type='controller'").items)[0].model
    is_cbs = bool("CBS" in model)
    return is_cbs


def list_capacity(module, array):
    """Get avaible expansion points"""
    steps = list(array.get_arrays_cloud_capacity_supported_steps().items)
    available = []
    for step in range(0, len(steps)):
        available.append(steps[step].supported_capacity)
    module.exit_json(changed=True, available=available)


def update_capacity(module, array):
    """Expand CBS capacity"""
    steps = list(array.get_arrays_cloud_capacity_supported_steps().items)
    available = []
    for step in range(0, len(steps)):
        available.append(steps[step].supported_capacity)
    if module.params["capacity"] not in available:
        module.fail_json(
            msg="Selected capacity is not available. "
            "Run this module with `list` to get available capapcity points."
        )
    expanded = array.patch_arrays_cloud_capacity(
        capacity=flasharray.CloudCapacityStatus(
            requested_capacity=module.params["capacity"]
        )
    )
    if expanded.sttaus_code != 200:
        module.fail_json(
            msg="Expansion request failed. Error: {0}".format(
                expanded.errors[0].message
            )
        )


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="show", choices=["show", "expand"]),
            capacity=dict(type="int"),
        )
    )

    required_if = [["state", "expand", ["capacity"]]]
    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    array = get_array(module)
    if not HAS_PURESTORAGE:
        module.fail_json(
            msg="py-pure-client sdk is required to support 'count' parameter"
        )
    if not _is_cbs(array):
        module.fail_json(msg="Module only valid on Cloud Block Store array")
    api_version = array.get_rest_version()
    if LooseVersion(EXPAND_API_VERSION) > LooseVersion(api_version):
        module.fail_json(
            msg="FlashArray REST version not supported. "
            "Minimum version required: {0}".format(EXPAND_API_VERSION)
        )
    if module.params["state"] == "show":
        list_capacity(module, array)
    else:
        update_capacity(module, array)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
