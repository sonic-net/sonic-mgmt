#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["deprecated"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefa_sso
version_added: '1.9.0'
deprecated:
    removed_in: '2.0.0'
    why: Superceeded by M(purestorage.flasharray.purefa_admin)
    alternative: Use M(purestorage.flasharray.purefa_admin) instead.
short_description: Configure Pure Storage FlashArray Single Sign-On
description:
- Enable or disable Single Sign-On (SSO) to give LDAP users the ability
  to navigate seamlessly from Pure1 Manage to the current array through a
  single login.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Enable or disable the array Signle Sign-On from Pure1 Manage
    default: present
    type: str
    choices: [ present, absent ]
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Enable SSO
  purestorage.flasharray.purefa_sso:
    state: present
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Disable SSO
  purestorage.flasharray.purefa_sso:
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import AdminSettings
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

SSO_API_VERSION = "2.2"


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    state = module.params["state"]
    array = get_array(module)
    api_version = array.get_rest_version()
    changed = False
    if LooseVersion(SSO_API_VERSION) <= LooseVersion(api_version):
        current_sso = list(array.get_admins_settings().items)[0].single_sign_on_enabled
        if (state == "present" and not current_sso) or (
            state == "absent" and current_sso
        ):
            changed = True
            if not module.check_mode:
                res = array.patch_admins_settings(
                    admin_settings=AdminSettings(
                        single_sign_on_enabled=bool(state == "present")
                    )
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change Single Sign-On status. Error: {0}".format(
                            res.errors[0].message
                        )
                    )
    else:
        module.fail_json(msg="Purity version does not support Single Sign-On")
    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()
