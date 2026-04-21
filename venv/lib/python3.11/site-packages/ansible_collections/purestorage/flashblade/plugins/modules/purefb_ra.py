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
module: purefb_ra
version_added: '1.0.0'
short_description: Enable or Disable Pure Storage FlashBlade Remote Assist
description:
- Enablke or Disable Remote Assist for a Pure Storage FlashBlade.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Define state of remote assist
    - When set to I(enable) the RA port can be exposed using the
      I(debug) module.
    type: str
    default: present
    choices: [ present, absent, test ]
  duration:
    description:
    - Specifies the duration of the remote-assist session in hours
    - It determines the length of time the session will remain active after
      it's initiated.
    type: int
    default: 24
    version_added: '1.18.0'
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Enable Remote Assist port
  purestorage.flashblade.purefb_ra:
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Disable Remote Assist port
  purestorage.flashblade.purefb_ra:
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import Support
except ImportError:
    HAS_PYPURECLIENT = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


DURATION_API = "2.14"


def enable_ra(module, blade):
    """Enable Remote Assist"""
    changed = True
    if not module.check_mode:
        if DURATION_API in list(blade.get_versions().items):
            duration = module.params["duration"] * 3600000
            ra_settings = Support(
                remote_assist_active=True, remote_assist_duration=duration
            )
        else:
            ra_settings = Support(remote_assist_active=True)
        res = blade.patch_support(support=ra_settings)
        if res.status_code != 200:
            module.fail_json(
                msg="Enabling Remote Assist failed. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def disable_ra(module, blade):
    """Disable Remote Assist"""
    changed = True
    if not module.check_mode:
        ra_settings = Support(remote_assist_active=False)
        res = blade.patch_support(support=ra_settings)
        if res.status_code != 200:
            module.fail_json(
                msg="Disabling Remote Assist failed. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def test_ra(module, blade):
    """Test support/remote assist configuration"""
    test_response = []
    response = list(blade.get_support_test(test_type="remote-assist").items)
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
            }
        )
    module.exit_json(changed=False, test_response=test_response)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(
                type="str", default="present", choices=["present", "absent", "test"]
            ),
            duration=dict(type="int", default=24),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    blade = get_system(module)

    if not HAS_PYPURECLIENT:
        module.fail_json(msg="pypureclient SDK is required for this module")
    active = list(blade.get_support().items)[0].remote_assist_active
    if module.params["state"] == "present" and not active:
        enable_ra(module, blade)
    elif module.params["state"] == "absent" and active:
        disable_ra(module, blade)
    elif module.params["state"] == "test":
        test_ra(module, blade)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
