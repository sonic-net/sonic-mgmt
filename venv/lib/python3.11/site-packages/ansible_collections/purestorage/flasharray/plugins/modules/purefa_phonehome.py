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
module: purefa_phonehome
version_added: '1.0.0'
short_description: Enable or Disable Pure Storage FlashArray Phonehome
description:
- Enablke or Disable Phonehome for a Pure Storage FlashArray.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Define state of phonehome
    type: str
    default: present
    choices: [ present, absent ]
  excludes:
    description:
    - Items that are excluded from phonehome data collection
    type: list
    elements: str
    choices: [ "application-insights" ]
    version_added: '1.40.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Enable Phonehome
  purestorage.flasharray.purefa_phonehome:
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Disable Phonehome
  purestorage.flasharray.purefa_phonehome:
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import SupportPatch
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

EXCLUDES_API_VERSION = "2.47"


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["present", "absent"]),
            excludes=dict(
                type="list", elements="str", choices=["application-insights"]
            ),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required to for this module")

    array = get_array(module)
    api_version = array.get_rest_version()
    support = list(array.get_support().items)[0]
    phonehome = support.phonehome_enabled
    excludes = getattr(support, "phonehome_excludes", None)
    changed = False
    if module.params["state"] == "present" and not phonehome:
        changed = True
        if not module.check_mode:
            res = array.patch_support(support=SupportPatch(phonehome_enabled=True))
            if res.status_code != 200:
                module.fail_json(
                    msg="Enabling Phonehome failed. Error: {0}".format(
                        res.errors[0].message
                    )
                )
            if (
                LooseVersion(EXCLUDES_API_VERSION) <= LooseVersion(api_version)
                and module.params["excludes"]
            ):
                res = array.patch_support(
                    support=SupportPatch(phonehome_excludes=module.params["excludes"])
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Updating Phonehome failed. Error: {0}".format(
                            res.errors[0].message
                        )
                    )
    elif module.params["state"] == "present" and phonehome:
        if LooseVersion(EXCLUDES_API_VERSION) <= LooseVersion(api_version):
            if module.params["excludes"] != excludes:
                changed = True
                if not module.check_mode:
                    res = array.patch_support(
                        support=SupportPatch(
                            phonehome_excludes=module.params["excludes"]
                        )
                    )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Updating Phonehome failed. Error: {0}".format(
                                res.errors[0].message
                            )
                        )
    elif module.params["state"] == "absent" and phonehome:
        changed = True
        if not module.check_mode:
            res = array.patch_support(support=SupportPatch(phonehome_enabled=False))
            if res.status_code != 200:
                module.fail_json(
                    msg="Disabling Phonehome failed. Error: {0}".format(
                        res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()
