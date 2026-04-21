#!/usr/bin/python
# -*- coding: utf-8 -*-

# 2018, Simon Dodsley (simon@purestorage.com)
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
module: purefa_alert
version_added: '1.0.0'
short_description: Configure Pure Storage FlashArray alert email settings
description:
- Configure alert email configuration for Pure Storage FlashArrays.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    type: str
    description:
    - Create, delete or test alert email
    default: present
    choices: [ absent, present, test ]
  address:
    type: str
    description:
    - Email address (valid format required)
    required: true
  enabled:
    type: bool
    default: true
    description:
    - Set specified email address to be enabled or disabled
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Add new email recipient and enable, or enable existing email
  purestorage.flasharray.purefa_alert:
    address: "user@domain.com"
    enabled: true
    state: present
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
- name: Delete existing email recipient
  purestorage.flasharray.purefa_alert:
    state: absent
    address: "user@domain.com"
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import AlertWatcherPost, AlertWatcherPatch
except ImportError:
    HAS_PURESTORAGE = False


def test_alert(module, array):
    """Test alert watchers"""
    test_response = []
    response = list(
        array.get_alert_watchers_test(names=[module.params["address"]]).items
    )
    for component in range(0, len(response)):
        if response[component].enabled:
            enabled = "true"
        else:
            enabled = "false"
        if response[component].success:
            success = "true"
        else:
            success = "false"
        test_response.append(
            {
                "component_address": response[component].component_address,
                "component_name": response[component].component_name,
                "description": response[component].description,
                "destination": response[component].destination,
                "enabled": enabled,
                "result_details": getattr(response[component], "result_details", ""),
                "success": success,
                "test_type": response[component].test_type,
                "resource_name": response[component].resource.name,
            }
        )
    module.exit_json(changed=True, test_response=test_response)


def create_alert(module, array):
    """Create Alert Email"""
    changed = True
    if not module.check_mode:
        res = array.post_alert_watchers(
            names=[module.params["address"]],
            alert_watcher=AlertWatcherPost(enabled=module.params["enabled"]),
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create alert email: {0}. Error: {1}".format(
                    module.params["address"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_alert(module, array, enabled):
    """Update Alert Email State"""
    changed = False
    if enabled != module.params["enabled"]:
        changed = True
        if not module.check_mode:
            res = array.patch_alert_watchers(
                names=[module.params["address"]],
                alert_watcher=AlertWatcherPatch(enabled=module.params["enabled"]),
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to change alert email state: {0}. Error: {1}".format(
                        module.params["address"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def delete_alert(module, array):
    """Delete Alert Email"""
    changed = True
    if module.params["address"] == "flasharray-alerts@purestorage.com":
        module.fail_json(
            msg="Built-in address {0} cannot be deleted.".format(
                module.params["address"]
            )
        )
    if not module.check_mode:
        res = array.delete_alert_watchers(names=[module.params["address"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete alert email: {0}. Error: {1}".format(
                    module.params["address"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            address=dict(type="str", required=True),
            enabled=dict(type="bool", default=True),
            state=dict(
                type="str", default="present", choices=["absent", "present", "test"]
            ),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    pattern = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    if not pattern.match(module.params["address"]):
        module.fail_json(msg="Valid email address not provided.")

    array = get_array(module)

    exists = False
    res = array.get_alert_watchers()
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to get exisitng email list. Error: {0}".format(
                res.errors[0].message
            )
        )
    else:
        watchers = list(res.items)
    for watcher in range(0, len(watchers)):
        if watchers[watcher].name == module.params["address"]:
            exists = True
            enabled = watchers[watcher].enabled
            break
    if module.params["state"] == "present" and not exists:
        create_alert(module, array)
    elif module.params["state"] == "present" and exists:
        update_alert(module, array, enabled)
    elif module.params["state"] == "absent" and exists:
        delete_alert(module, array)
    elif module.params["state"] == "test":
        test_alert(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
