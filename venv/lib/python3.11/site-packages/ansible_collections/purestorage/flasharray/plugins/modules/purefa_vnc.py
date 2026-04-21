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
module: purefa_vnc
version_added: '1.0.0'
short_description: Enable or Disable VNC port for installed apps
description:
- Enablke or Disable VNC access for installed apps
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Define state of VNC
    type: str
    default: present
    choices: [ present, absent ]
  name:
    description:
    - Name of app
    type: str
    required: true
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Enable VNC for application test
  purestorage.flasharray.purefa_vnc:
    name: test
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Disable VNC for application test
  purestorage.flasharray.purefa_vnc:
    name: test
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
vnc:
  description: VNC port information for application
  type: dict
  returned: success
  contains:
    status:
        description: Status of application
        type: str
        sample: 'healthy'
    index:
        description: Application index number
        type: int
    version:
        description: Application version installed
        type: str
        sample: '5.2.1'
    vnc:
        description: IP address and port number for VNC connection
        type: list
        sample: ['10.21.200.34:5900']
    name:
        description: Application name
        type: str
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import App
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

MAX_API_VERSION = "2.36"


def enable_vnc(module, array, app):
    """Enable VNC port"""
    changed = False
    vnc_fact = []
    if not app.vnc_enabled:
        changed = True
        if not module.check_mode:
            res = array.patch_apps(
                names=[module.params["name"]], app=App(vnc_enabled=True)
            )
            if res.status_code == 200:
                vnc_nodes = list(
                    array.get_apps_nodes(app_names=[module.params["name"]]).items
                )[0]
                vnc_fact = {
                    "status": vnc_nodes.status,
                    "index": vnc_nodes.index,
                    "version": vnc_nodes.version,
                    "vnc": vnc_nodes.vnc,
                    "name": module.params["name"],
                }
            else:
                module.fail_json(
                    msg="Enabling VNC for {0} failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed, vnc=vnc_fact)


def disable_vnc(module, array, app):
    """Disable VNC port"""
    changed = False
    if app.vnc_enabled:
        changed = True
        if not module.check_mode:
            res = array.patch_apps(
                names=[module.params["name"]], app=App(vnc_enabled=False)
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Disabling VNC for {0} failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["present", "absent"]),
            name=dict(type="str", required=True),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_array(module)
    api_version = array.get_rest_version()
    if LooseVersion(MAX_API_VERSION) <= LooseVersion(api_version):
        module.warn("VNC feature deprecated from Purity//FA 6.8.0 and higher")
        module.exit_json(changed=False)
    res = array.get_apps(names=[module.params["name"]])
    if res.status_code != 200:
        module.fail_json(
            msg="Selected application {0} does not exist".format(module.params["name"])
        )
    app = list(res.items)[0]
    if not app.enabled:
        module.fail_json(
            msg="Application {0} is not enabled".format(module.params["name"])
        )
    if module.params["state"] == "present":
        enable_vnc(module, array, app)
    else:
        disable_vnc(module, array, app)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
