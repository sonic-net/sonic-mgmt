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
module: purefa_token
version_added: '1.0.0'
short_description: Create or delete an API token for an existing admin user
description:
- Create or delete an API token for an existing admin user.
- Uses username/password to create/delete the API token.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete API token
    type: str
    default: present
    choices: [ present, absent ]
  recreate:
    description:
    - Recreates the API token, overwriting the existing API token if present
    type: bool
    default: false
  username:
    description:
    - Username of the admin user to create API token for
    type: str
  password:
    description:
    - Password of the admin user to create API token for.
    type: str
  fa_url:
    description:
      - FlashArray management IPv4 address or Hostname.
    type: str
  timeout:
    description:
      - The duration of API token validity.
      - Valid values are weeks (w), days(d), hours(h), minutes(m) and seconds(s).
    type: str
  disable_warnings:
    description:
     - Disable insecure certificate warnings in debug logs
    type: bool
    default: false
    version_added: '1.31.0'
"""

EXAMPLES = r"""
- name: Create API token with no expiration
  purefa_token:
    username: pureuser
    password: secret
    state: present
    fa_url: 10.10.10.2
- name: Create API token with 23 days expiration
  purefa_token:
    username: pureuser
    password: secret
    state: present
    timeout: 23d
    fa_url: 10.10.10.2
- name: Delete API token
  purefa_token:
    username: pureuser
    password: secret
    state: absent
    fa_url: 10.10.10.2
"""

RETURN = r"""
purefa_token:
  description: API token for user
  returned: changed
  type: str
  sample: e649f439-49be-3806-f774-a35cbbc4c2d2
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.common import (
    convert_time_to_millisecs,
)
from os import environ
import platform

VERSION = 1.5
USER_AGENT_BASE = "Ansible_token"
TIMEOUT_API_VERSION = "2.2"

HAS_URLLIB3 = True
try:
    import urllib3
except ImportError:
    HAS_URLLIB3 = False

HAS_DISTRO = True
try:
    import distro
except ImportError:
    HAS_DISTRO = False

HAS_PURESTORAGE = True
try:
    from purestorage import purestorage
except ImportError:
    HAS_PURESTORAGE = False


def get_session(module):
    """Return System Object or Fail"""
    if HAS_URLLIB3 and module.params["disable_warnings"]:
        urllib3.disable_warnings()
    if HAS_DISTRO:
        user_agent = "%(base)s %(class)s/%(version)s (%(platform)s)" % {
            "base": USER_AGENT_BASE,
            "class": __name__,
            "version": VERSION,
            "platform": distro.name(pretty=True),
        }
    else:
        user_agent = "%(base)s %(class)s/%(version)s (%(platform)s)" % {
            "base": USER_AGENT_BASE,
            "class": __name__,
            "version": VERSION,
            "platform": platform.platform(),
        }

    array_name = module.params["fa_url"]
    username = module.params["username"]
    password = module.params["password"]

    if HAS_PURESTORAGE:
        if array_name and username and password:
            system = purestorage.FlashArray(
                array_name, username=username, password=password, user_agent=user_agent
            )
        elif environ.get("PUREFA_URL"):
            if environ.get("PUREFA_USERNAME") and environ.get("PUREFA_PASSWORD"):
                url = environ.get("PUREFA_URL")
                username = environ.get("PUREFA_USERNAME")
                password = environ.get("PUREFA_PASSWORD")
                system = purestorage.FlashArray(
                    url, username=username, password=password, user_agent=user_agent
                )
        else:
            module.fail_json(
                msg="You must set PUREFA_URL and PUREFA_USERNAME, PUREFA_PASSWORD "
                "environment variables or the fa_url, username and password "
                "module arguments"
            )
        try:
            system.get()
        except Exception:
            module.fail_json(
                msg="Pure Storage FlashArray authentication failed. Check your credentials"
            )
    else:
        module.fail_json(msg="purestorage SDK is not installed.")
    return system


def main():
    argument_spec = dict(
        fa_url=dict(required=False),
        username=dict(type="str", required=False),
        password=dict(no_log=True, required=False),
        state=dict(type="str", default="present", choices=["absent", "present"]),
        recreate=dict(type="bool", default=False),
        timeout=dict(type="str"),
        disable_warnings=dict(type="bool", default=False),
    )

    module = AnsibleModule(argument_spec, supports_check_mode=False)
    array = get_session(module)
    changed = False

    if module.params["username"]:
        username = module.params["username"]
    else:
        username = environ.get("PUREFA_USERNAME")
    state = module.params["state"]
    recreate = module.params["recreate"]

    result = array.get_api_token(admin=username)
    api_version = array._list_available_rest_versions()
    if state == "present" and result["api_token"] is None:
        result = array.create_api_token(admin=username)
        changed = True
    elif state == "present" and recreate:
        result = array.delete_api_token(admin=username)
        result = array.create_api_token(admin=username)
        changed = True
    elif state == "absent" and result["api_token"]:
        result = array.delete_api_token(admin=username)
        changed = True

    api_token = result["api_token"]

    if (
        TIMEOUT_API_VERSION in api_version
        and module.params["timeout"]
        and state == "present"
    ):
        module.params["api_token"] = api_token
        array6 = get_array(module)
        ttl = convert_time_to_millisecs(module.params["timeout"])
        if ttl != 0:
            changed = True
            array6.delete_admins_api_tokens(names=[username])
            res = array6.post_admins_api_tokens(names=[username], timeout=ttl)
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to set token lifetime. Error: {0}".format(
                        res.errors[0].message
                    )
                )
            else:
                api_token = list(res.items)[0].api_token.token
    module.exit_json(changed=changed, purefa_token=api_token)


if __name__ == "__main__":
    main()
