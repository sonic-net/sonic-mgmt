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
module: purefb_target
version_added: '1.0.0'
short_description: Manage remote S3-capable targets for a FlashBlade
description:
- Manage remote S3-capable targets for a FlashBlade system
- Use this for non-FlashBlade targets.
- Use I(purestorage.flashblade.purefb_connect) for FlashBlade targets.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete remote target
    default: present
    type: str
    choices: [ absent, present ]
  name:
    description:
    - Name of S3-capable target (IP or FQDN)
    type: str
    required: true
  address:
    description:
    - Address of S3-capable target (IP or FQDN)
    type: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create a connection to remote S3-capable target
  purestorage.flashblade.purefb_target:
    name: target_1
    address: 10.10.10.20
    fb_url: 10.10.10.2
    api_token: T-89faa581-c668-483d-b77d-23c5d88ba35c
- name: Delete connection to remote S3-capable system
  purestorage.flashblade.purefb_target:
    state: absent
    name: target_1
    target_api: 9c0b56bc-f941-f7a6-9f85-dcc3e9a8f7d6
    fb_url: 10.10.10.2
    api_token: T-89faa581-c668-483d-b77d-23c5d88ba35c
"""

RETURN = r"""
"""

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import TargetPost, Target
except ImportError:
    HAS_PYPURECLIENT = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def _check_replication_configured(module, blade):
    interfaces = list(blade.get_network_interfaces().items)
    repl_ok = False
    for link in range(len(interfaces)):
        if "replication" in interfaces[link].services:
            repl_ok = True
    if not repl_ok:
        module.fail_json(
            msg="Replication network interface required to configure a target"
        )


def _check_connected(module, blade):
    connected_targets = list(blade.get_targets().items)
    for target in range(len(connected_targets)):
        if connected_targets[target].name == module.params["name"]:
            return connected_targets[target]
    return None


def break_connection(module, blade):
    """Break connection to remote target"""
    changed = True
    if not module.check_mode:
        res = blade.delete_targets(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to disconnect target {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def create_connection(module, blade):
    """Create connection to remote target"""
    changed = True
    if not module.check_mode:
        connected_targets = list(blade.get_targets().items)
        for target in range(len(connected_targets)):
            if connected_targets[target].address == module.params["address"]:
                module.fail_json(
                    msg="Target already exists with same connection address"
                )

        target = TargetPost(address=module.params["address"])
        res = blade.post_targets(names=[module.params["name"]], target=target)
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to connect to remote target {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_connection(module, blade, connection):
    """Update target connection address"""
    changed = False
    connected_targets = list(blade.get_targets().items)
    for target in range(len(connected_targets)):
        if (
            connected_targets[target].address == module.params["address"]
            and connected_targets[target].name != module.params["name"]
        ):
            module.fail_json(msg="Target already exists with same connection address")
    if module.params["address"] != connection.address:
        changed = True
        if not module.check_mode:
            new_address = Target(
                name=module.params["name"], address=module.params["address"]
            )
            res = blade.targets.update_targets(
                names=[connection.name], target=new_address
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to change address for target {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            name=dict(type="str", required=True),
            address=dict(type="str"),
        )
    )

    required_if = [["state", "present", ["address"]]]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PYPURECLIENT:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    state = module.params["state"]
    blade = get_system(module)
    _check_replication_configured(module, blade)
    target = _check_connected(module, blade)
    if state == "present" and not target:
        create_connection(module, blade)
    elif state == "present" and target:
        update_connection(module, blade, target)
    elif state == "absent" and target:
        break_connection(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
