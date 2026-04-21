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
module: purefb_alert
version_added: '1.0.0'
short_description: Configure Pure Storage FlashBlade alert email settings
description:
- Configure alert email configuration for Pure Storage FlashArrays.
- Add or delete an individual syslog server to the existing
  list of serves.
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
  severity:
    type: str
    description:
    - The minimum severity that an alert must have in order for
      emails to be sent to the array's alert watchers
    default: info
    choices: [ info, warning, critical ]
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Add new email recipient and enable, or enable existing email
  purestorage.flashblade.purefb_alert:
    address: "user@domain.com"
    enabled: true
    state: present
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
- name: Delete existing email recipient
  purestorage.flashblade.purefb_alert:
    state: absent
    address: "user@domain.com"
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""


HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import AlertWatcher, AlertWatcherPost
except ImportError:
    HAS_PYPURECLIENT = False


import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def create_alert(module, blade):
    """Create Alert Email"""
    changed = True
    if not module.check_mode:
        watcher_settings = AlertWatcherPost(
            minimum_notification_severity=module.params["severity"]
        )
        res = blade.post_alert_watchers(
            names=[module.params["address"]], alert_watcher=watcher_settings
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create alert email {0}. Error: {1}".format(
                    module.params["address"], res.errors[0].message
                )
            )
        if not module.params["enabled"]:
            watcher_settings = AlertWatcher(enabled=module.params["enabled"])
            res = blade.patch_alert_watchers(
                names=[module.params["address"]], alert_watcher=watcher_settings
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to disable during create alert email {0}. Error: {1}".format(
                        module.params["address"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def update_alert(module, blade):
    """Update alert Watcher"""
    mod_alert = False
    res = blade.get_alert_watchers(names=[module.params["address"]])
    if res.status_code == 200:
        alert = list(res.items)[0]
    else:
        module.fail_json(
            msg="Failed to get information for alert email {0}. Error: {1}".format(
                module.params["address"], res.errors[0].message
            )
        )
    current_state = {
        "enabled": alert.items[0].enabled,
        "severity": alert.items[0].minimum_notification_severity,
    }
    if current_state["enabled"] != module.params["enabled"]:
        enabled = module.params["enabled"]
        mod_alert = True
    else:
        enabled = current_state["enabled"]
    if current_state["severity"] != module.params["severity"]:
        severity = module.params["severity"]
        mod_alert = True
    else:
        severity = current_state["severity"]
    if mod_alert:
        changed = True
        if not module.check_mode:
            watcher_settings = AlertWatcher(
                enabled=enabled,
                minimum_notification_severity=severity,
            )
            res = blade.patch_alert_watchers(
                names=[module.params["address"]], alert_watcher=watcher_settings
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update alert email {0}: Error: {1}".format(
                        module.params["address"], res.errors[0].message
                    )
                )
    else:
        changed = False
    module.exit_json(changed=changed)


def delete_alert(module, blade):
    """Delete Alert Email"""
    changed = True
    if not module.check_mode:
        res = blade.delete_alert_watchers(names=[module.params["address"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete alert email {0}. Error: {1}".format(
                    module.params["address"], res.errors[0].message
                )
            )

    module.exit_json(changed=changed)


def test_alert(module, blade):
    """Test alert watchers"""
    test_response = []
    response = list(
        blade.get_alert_watchers_test(names=[module.params["address"]]).items
    )
    for component in range(len(response)):
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
    module.exit_json(changed=False, test_response=test_response)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            address=dict(type="str", required=True),
            enabled=dict(type="bool", default=True),
            severity=dict(
                type="str", default="info", choices=["info", "warning", "critical"]
            ),
            state=dict(
                type="str", default="present", choices=["absent", "present", "test"]
            ),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PYPURECLIENT:
        module.fail_json(msg="py-pure-client SDK is required for this module")

    pattern = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    if not pattern.match(module.params["address"]):
        module.fail_json(msg="Valid email address not provided.")

    blade = get_system(module)

    exists = False
    res = blade.get_alert_watchers()
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to get exisitng email list. Error: {0}".format(
                res.errors[0].message
            )
        )
    emails = list(res.items)
    for email in range(len(emails)):
        if emails[email].name == module.params["address"]:
            exists = True
            break
    if module.params["state"] == "present" and not exists:
        create_alert(module, blade)
    elif module.params["state"] == "present" and exists:
        update_alert(module, blade)
    elif module.params["state"] == "absent" and exists:
        delete_alert(module, blade)
    elif module.params["state"] == "test":
        test_alert(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
