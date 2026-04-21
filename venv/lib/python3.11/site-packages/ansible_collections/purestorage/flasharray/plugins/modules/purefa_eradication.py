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
module: purefa_eradication
version_added: '1.9.0'
short_description: Configure Pure Storage FlashArray Eradication Timer
description:
- Configure the eradication timer for destroyed items on a FlashArray.
- Valid values are integer days from 1 to 30. Default is 1.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  timer:
    description:
    - Set the eradication timer for the FlashArray
    - Allowed values are integers from 1 to 30. Default is 1
    - This parameter is not allowed to be specified with I(disabled_delay)
      or I(enabled_delay)
    type: int
  disabled_delay:
    description:
    - Configures the eradication delay
      for destroyed objects that I(are) protected by SafeMode (objects for which
      eradication is disabled)
    - Allowed values are integers from 1 to 30. Default is 1
    default: 1
    type: int
    version_added: "1.22.0"
  enabled_delay:
    description:
    - Configures the eradication delay
      for destroyed objects that I(are not) protected by SafeMode (objects for which
      eradication is disabled)
    - Allowed values are integers from 1 to 30. Default is 1
    default: 1
    type: int
    version_added: "1.22.0"
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: '1.39.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Set eradication timer to 30 days
  purestorage.flasharray.purefa_eradication:
    timer: 30
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Set eradication timer to 1 day
  purestorage.flasharray.purefa_eradication:
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import Arrays, EradicationConfig
except ImportError:
    HAS_PURESTORAGE = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

SEC_PER_DAY = 86400000
ERADICATION_API_VERSION = "2.6"
DELAY_API_VERSION = "2.26"
CONTEXT_VERSION = "2.38"


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            timer=dict(type="int"),
            disabled_delay=dict(type="int", default=1),
            enabled_delay=dict(type="int", default=1),
            context=dict(type="str", default=""),
        )
    )
    mutually_exclusive = [["timer", "disabled_delay"], ["timer", "enabled_delay"]]
    module = AnsibleModule(
        argument_spec, supports_check_mode=True, mutually_exclusive=mutually_exclusive
    )
    if module.params["timer"] and not 30 >= module.params["timer"] >= 1:
        module.fail_json(msg="Eradication Timer must be between 1 and 30 days.")
    if not 30 >= module.params["disabled_delay"] >= 1:
        module.fail_json(msg="disabled_delay must be between 1 and 30 days.")
    if not 30 >= module.params["enabled_delay"] >= 1:
        module.fail_json(msg="enabled_delay must be between 1 and 30 days.")
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")
    array = get_array(module)
    api_version = array.get_rest_version()
    changed = False
    current_disabled = None
    current_enabled = None
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        current_eradication_config = list(
            array.get_arrays(context_names=[module.params["context"]]).items
        )[0].eradication_config
    else:
        current_eradication_config = list(array.get_arrays().items)[
            0
        ].eradication_config
    if LooseVersion(ERADICATION_API_VERSION) <= LooseVersion(api_version):
        base_eradication_timer = getattr(
            current_eradication_config, "eradication_delay", None
        )
        if base_eradication_timer:
            current_eradication_timer = int(base_eradication_timer / SEC_PER_DAY)
            if not module.params["timer"]:
                module.params["timer"] = current_eradication_timer
        if LooseVersion(DELAY_API_VERSION) <= LooseVersion(api_version):
            current_disabled = int(
                current_eradication_config.disabled_delay / SEC_PER_DAY
            )
            current_enabled = int(
                current_eradication_config.enabled_delay / SEC_PER_DAY
            )
        if (
            base_eradication_timer
            and module.params["timer"] != current_eradication_timer
        ):
            if module.params["timer"] != current_eradication_timer:
                target_timer = module.params["timer"]
            else:
                target_timer = current_eradication_timer
            changed = True
            if not module.check_mode:
                new_timer = SEC_PER_DAY * target_timer
                eradication_config = EradicationConfig(eradication_delay=new_timer)
                if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                    res = array.patch_arrays(
                        context_names=[module.params["context"]],
                        array=Arrays(eradication_config=eradication_config),
                    )
                else:
                    res = array.patch_arrays(
                        array=Arrays(eradication_config=eradication_config)
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change Eradication Timer. Error: {0}".format(
                            res.errors[0].message
                        )
                    )
        if current_disabled and (
            module.params["enabled_delay"] != current_enabled
            or module.params["disabled_delay"] != current_disabled
        ):
            changed = True
            if not module.check_mode:
                new_disabled = SEC_PER_DAY * module.params["disabled_delay"]
                new_enabled = SEC_PER_DAY * module.params["enabled_delay"]
                eradication_config = EradicationConfig(
                    enabled_delay=new_enabled, disabled_delay=new_disabled
                )
                if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                    res = array.patch_arrays(
                        context_names=[module.params["context"]],
                        array=Arrays(eradication_config=eradication_config),
                    )
                else:
                    res = array.patch_arrays(
                        array=Arrays(eradication_config=eradication_config)
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change Eradication Timers. Error: {0}".format(
                            res.errors[0].message
                        )
                    )
    else:
        module.fail_json(
            msg="Purity version does not support changing Eradication Timer"
        )
    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()
