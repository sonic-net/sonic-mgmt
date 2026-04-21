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
module: purefa_eula
version_added: '1.0.0'
short_description: Sign Pure Storage FlashArray EULA
description:
- Sign the FlashArray EULA for Day 0 config, or change signatory.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  company:
    description:
    - Full legal name of the entity.
    - The value must be between 1 and 64 characters in length.
    type: str
  name:
    description:
    - Full legal name of the individual at the company who has the authority to accept the terms of the agreement.
    - The value must be between 1 and 64 characters in length.
    type: str
  title:
    description:
    - Individual's job title at the company.
    - The value must be between 1 and 64 characters in length.
    type: str
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Sign EULA for FlashArray
  purestorage.flasharray.purefa_eula:
    company: "ACME Storage, Inc."
    name: "Fred Bloggs"
    title: "Storage Manager"
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
    from pypureclient.flasharray import Eula, EulaSignature
except ImportError:
    HAS_PURESTORAGE = False


EULA_V2 = "2.30"


def set_eula(module, array):
    """Sign EULA"""
    changed = False
    res = array.get_arrays_eula()
    if res.status_code == 200:
        current_eula = list(res.items)[0]
    else:
        module.fail_json(
            msg="Failed to get current EULA. Error: {0}".format(res.errors[0].message)
        )
    if not hasattr(current_eula, "signature.accepted"):
        changed = True
        if not module.check_mode:
            res = array.patch_arrays_eula(
                eula=Eula(
                    signature=EulaSignature(
                        company=module.params["company"],
                        title=module.params["title"],
                        name=module.params["name"],
                    )
                )
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Signing EULA failed. Error: {0}".format(res.erroros[0].message)
                )
    else:
        module.warn("EULA already signed")
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            company=dict(type="str"),
            name=dict(type="str"),
            title=dict(type="str"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_array(module)
    api_version = array.get_rest_version()
    if LooseVersion(EULA_V2) > LooseVersion(api_version):
        if not (
            module.params["company"]
            and module.params["title"]
            and module.params["name"]
        ):
            module.fail_json(msg="missing required arguments: company, name, title")
    set_eula(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
