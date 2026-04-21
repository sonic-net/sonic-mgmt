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
module: purefa_ra
version_added: '1.0.0'
short_description: Enable or Disable Pure Storage FlashArray Remote Assist
description:
- Enable or Disable Remote Assist for a Pure Storage FlashArray.
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
    choices: [ enable, disable, absent, present, test ]
  duration:
    description:
    - Number of hours Remote Assist port stays open for.
    - Must be an integer between 4 and 48
    type: int
    default: 24
    version_added: 1.33.0
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Enable Remote Assist port
  purestorage.flasharray.purefa_ra:
    duration: 12
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
  register: result

  debug:
    msg: "Remote Assist: {{ result['ra_info'] }}"

- name: Disable Remote Assist port
  purestorage.flasharray.purefa_ra:
    state: disable
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import SupportPatch
except ImportError:
    HAS_PURESTORAGE = False

DURATION_API = "2.35"


def test_ra(module, array):
    """Test support/remote assist configuration"""
    test_response = []
    response = list(array.get_support_test().items)
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


def enable_ra(module, array):
    """Enable Remote Assist"""
    changed = False
    ra_facts = {}
    if not list(array.get_support().items)[0].remote_assist_status in [
        "connected",
        "connecting",
        "enabled",
    ]:
        changed = True
        res = {}
        api_version = array.get_rest_version()
        if not module.check_mode:
            if LooseVersion(DURATION_API) > LooseVersion(api_version):
                if not 4 <= module.params["duration"] <= 48:
                    module.fail_json(msg="The duration must be between 4-48 hours.")
                else:
                    duration = module.params["duration"] * 3600000
                    res = array.patch_support(
                        support=SupportPatch(
                            remote_assist_duration=duration, remote_assist_active=True
                        )
                    )
            else:
                res = array.patch_support(
                    support=SupportPatch(remote_assist_active=True)
                )
            if res.status_code == 200:
                ra_data = list(res.items)[0]
                ra_facts["fa_ra"] = {
                    "name": ra_data.remote_assist_paths[0].component_name,
                    "port": None,
                }
            else:
                module.fail_json(
                    msg="Enabling Remote Assist failed. Error: {0}".format(
                        res.errors[0].message
                    )
                )
    else:
        res = array.get_support()
        if res.status_code == 200:
            ra_data = list(res.items)[0]
            ra_facts["fa_ra"] = {
                "name": ra_data.remote_assist_paths[0].component_name,
                "port": None,
            }
        else:
            module.fail_json(
                msg="Getting Remote Assist failed. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed, ra_info=ra_facts)


def disable_ra(module, array):
    """Disable Remote Assist"""
    changed = False
    if list(array.get_support().items)[0].remote_assist_status in [
        "connected",
        "connecting",
        "enabled",
    ]:
        changed = True
        if not module.check_mode:
            res = array.patch_support(support=SupportPatch(remote_assist_active=False))
            if res.status_code != 200:
                module.fail_json(
                    msg="Disabling Remote Assist failed. Error: {0}".format(
                        res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(
                type="str",
                default="present",
                choices=["enable", "disable", "absent", "present", "test"],
            ),
            duration=dict(type="int", default=24),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_array(module)

    if module.params["state"] in ["enable", "present"]:
        enable_ra(module, array)
    elif module.params["state"] == "test":
        test_ra(module, array)
    else:
        disable_ra(module, array)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
