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
module: purefa_smis
version_added: '1.0.0'
short_description: Enable or disable FlashArray SMI-S features
description:
- Enable or disable FlashArray SMI-S Provider and/or SLP
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  slp:
    description:
    - Enable/Disable Service Locator Protocol
    - Ports used are TCP 427 and UDP 427
    type: bool
    default: true
  smis:
    description:
    - Enable/Disable SMI-S Provider
    - Port used is TCP 5989
    type: bool
    default: true
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Enable SMI-S and SLP
  purestorage.flasharray.purefa_smis:
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Disable SMI-S and SLP
  purestorage.flasharray.purefa_smis:
    smis: false
    slp: false
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
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

MIN_REQUIRED_API_VERSION = "2.2"


def update_smis(module, array):
    """Update SMI-S features"""
    changed = smis_changed = False
    current = list(array.get_smi_s().items)[0]
    slp_enabled = current.slp_enabled
    wbem_enabled = current.wbem_https_enabled
    if slp_enabled != module.params["slp"]:
        slp_enabled = module.params["slp"]
        smis_changed = True
    if wbem_enabled != module.params["smis"]:
        wbem_enabled = module.params["smis"]
        smis_changed = True
    if smis_changed:
        smi_s = flasharray.Smis(
            slp_enabled=slp_enabled, wbem_https_enabled=wbem_enabled
        )
        changed = True
        if not module.check_mode:
            res = array.patch_smi_s(smi_s=smi_s)
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to change SMI-S settings. Error: {0}".format(
                        res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            smis=dict(type="bool", default=True),
            slp=dict(type="bool", default=True),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_array(module)
    api_version = array.get_rest_version()

    if LooseVersion(MIN_REQUIRED_API_VERSION) > LooseVersion(api_version):
        module.fail_json(
            msg="FlashArray REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )

    update_smis(module, array)


if __name__ == "__main__":
    main()
