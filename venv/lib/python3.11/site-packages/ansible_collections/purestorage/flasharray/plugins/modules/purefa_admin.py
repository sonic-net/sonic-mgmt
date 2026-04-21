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
module: purefa_admin
version_added: '1.12.0'
short_description: Configure Pure Storage FlashArray Global Admin settings
description:
- Set global admin settings for the FlashArray
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  sso:
    description:
    - Enable or disable the array Signle Sign-On from Pure1 Manage
    default: false
    type: bool
  max_login:
    description:
    - Maximum number of failed logins before account is locked
    type: int
  min_password:
    description:
    - Minimum user password length
    default: 1
    type: int
  lockout:
    description:
    - Account lockout duration, in seconds, after max_login exceeded
    - Range between 1 second and 90 days (7776000 seconds)
    type: int
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Set global login parameters
  purestorage.flasharray.purefa_admin:
    sso: false
    max_login: 5
    min_password: 10
    lockout: 300
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

MIN_API_VERSION = "2.2"


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            sso=dict(type="bool", default=False),
            max_login=dict(type="int"),
            min_password=dict(type="int", default=1, no_log=False),
            lockout=dict(type="int"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")
    if module.params["lockout"] and not 1 <= module.params["lockout"] <= 7776000:
        module.fail_json(msg="Lockout must be between 1 and 7776000 seconds")
    array = get_array(module)
    api_version = array.get_rest_version()
    changed = False
    if LooseVersion(MIN_API_VERSION) <= LooseVersion(api_version):
        current_settings = list(array.get_admins_settings().items)[0]
        if (
            module.params["sso"]
            and module.params["sso"] != current_settings.single_sign_on_enabled
        ):
            changed = True
            sso = module.params["sso"]
        else:
            sso = current_settings.single_sign_on_enabled
        if (
            module.params["min_password"]
            and module.params["min_password"] != current_settings.min_password_length
        ):
            changed = True
            min_password = module.params["min_password"]
        else:
            min_password = current_settings.min_password_length
        lockout = getattr(current_settings, "lockout_duration", None)
        if (
            lockout
            and module.params["lockout"]
            and lockout != module.params["lockout"] * 1000
        ):
            changed = True
            lockout = module.params["lockout"] * 1000
        elif not lockout and module.params["lockout"]:
            changed = True
            lockout = module.params["lockout"] * 1000
        max_login = getattr(current_settings, "max_login_attempts", None)
        if (
            max_login
            and module.params["max_login"]
            and max_login != module.params["max_login"]
        ):
            changed = True
            max_login = module.params["max_login"]
        elif not max_login and module.params["max_login"]:
            changed = True
            max_login = module.params["max_login"]
        if changed and not module.check_mode:
            if max_login:
                admin = AdminSettings(
                    single_sign_on_enabled=sso,
                    min_password_length=min_password,
                    max_login_attempts=max_login,
                )
            if lockout:
                admin = AdminSettings(
                    single_sign_on_enabled=sso,
                    min_password_length=min_password,
                    lockout_duration=lockout,
                )
            if lockout and max_login:
                admin = AdminSettings(
                    single_sign_on_enabled=sso,
                    min_password_length=min_password,
                    lockout_duration=lockout,
                    max_login_attempts=max_login,
                )
            if not lockout and not max_login:
                admin = AdminSettings(
                    single_sign_on_enabled=sso,
                    min_password_length=min_password,
                )
            res = array.patch_admins_settings(admin_settings=admin)
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to change Global Admin settings. Error: {0}".format(
                        res.errors[0].message
                    )
                )
    else:
        module.fail_json(msg="Purity version does not support Global Admin settings")
    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()
