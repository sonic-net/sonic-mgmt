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
module: purefb_tz
version_added: '1.10.0'
short_description: Configure Pure Storage FlashBlade timezone
description:
- Configure the timezone for a Pure Storage FlashBlade.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  timezone:
    description:
    - If not provided, the module will attempt to get the current local timezone from the server
    type: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Set FlashBlade Timezone to Americas/Los_Angeles
  purestorage.flashblade.purefb_tz:
    timezone: "America/Los_Angeles"
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flashblade
except ImportError:
    HAS_PURESTORAGE = False

HAS_PYTZ = True
try:
    import pytz
except ImportError:
    HAS_PYTX = False

import os
import re
import platform

from ansible.module_utils.common.process import get_bin_path
from ansible.module_utils.facts.utils import get_file_content
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def _findstr(text, match):
    for line in text.splitlines():
        if match in line:
            found = line
    return found


def _get_local_tz(module, timezone="UTC"):
    """
    We will attempt to get the local timezone of the server running the module and use that.
    If we can't get the timezone then we will set the default to be UTC

    Linnux has been tested and other opersting systems should be OK.
    Failures cause assumption of UTC

    Windows is not supported and will assume UTC
    """
    if platform.system() == "Linux":
        timedatectl = get_bin_path("timedatectl")
        if timedatectl is not None:
            rcode, stdout, _stderr = module.run_command(timedatectl)
            if rcode == 0 and stdout:
                line = _findstr(stdout, "Time zone")
                full_tz = line.split(":", 1)[1].rstrip()
                timezone = full_tz.split()[0]
                return timezone
            module.warn("Incorrect timedatectl output. Timezone will be set to UTC")
        else:
            if os.path.exists("/etc/timezone"):
                timezone = get_file_content("/etc/timezone")
            else:
                module.warn("Could not find /etc/timezone. Assuming UTC")

    elif platform.system() == "SunOS":
        if os.path.exists("/etc/default/init"):
            for line in get_file_content("/etc/default/init", "").splitlines():
                if line.startswith("TZ="):
                    timezone = line.split("=", 1)[1]
                    return timezone
        else:
            module.warn("Could not find /etc/default/init. Assuming UTC")

    elif re.match("^Darwin", platform.platform()):
        systemsetup = get_bin_path("systemsetup")
        if systemsetup is not None:
            rcode, stdout, _stderr = module.execute(systemsetup, "-gettimezone")
            if rcode == 0 and stdout:
                timezone = stdout.split(":", 1)[1].lstrip()
            else:
                module.warn("Could not run systemsetup. Assuming UTC")
        else:
            module.warn("Could not find systemsetup. Assuming UTC")

    elif re.match("^(Free|Net|Open)BSD", platform.platform()):
        if os.path.exists("/etc/timezone"):
            timezone = get_file_content("/etc/timezone")
        else:
            module.warn("Could not find /etc/timezone. Assuming UTC")

    elif platform.system() == "AIX":
        aix_oslevel = int(platform.version() + platform.release())
        if aix_oslevel >= 61:
            if os.path.exists("/etc/environment"):
                for line in get_file_content("/etc/environment", "").splitlines():
                    if line.startswith("TZ="):
                        timezone = line.split("=", 1)[1]
                        return timezone
            else:
                module.warn("Could not find /etc/environment. Assuming UTC")
        else:
            module.warn(
                "Cannot determine timezone when AIX os level < 61. Assuming UTC"
            )

    else:
        module.warn("Could not find /etc/timezone. Assuming UTC")

    return timezone


def set_timezone(module, blade):
    """Set timezone"""
    changed = True
    if not module.check_mode:
        res = blade.patch_arrays(flashblade.Array(time_zone=module.params["timezone"]))
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to timezone. Error: {0}".format(res.errors[0].message)
            )

    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            timezone=dict(type="str"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")
    if not HAS_PYTZ:
        module.fail_json(msg="pytz is required for this module")

    blade = get_system(module)

    if not module.params["timezone"]:
        module.params["timezone"] = _get_local_tz(module)
        if module.params["timezone"] not in pytz.all_timezones_set:
            module.fail_json(
                msg="Timezone {0} is not valid".format(module.params["timezone"])
            )

    blade = get_system(module)
    current_tz = list(blade.get_arrays().items)[0].time_zone
    if current_tz != module.params["timezone"]:
        set_timezone(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
