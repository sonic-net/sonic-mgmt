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
module: purefb_virtualhost
version_added: '1.6.0'
short_description: Manage FlashBlade Object Store Virtual Hosts
description:
- Add or delete FlashBlade Object Store Virtual Hosts
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the Object Store Virtual Host
    - A hostname or domain by which the array can be addressed for virtual
      hosted-style S3 requests.
    type: str
    required: true
  state:
    description:
    - Define whether the Object Store Virtual Host should be added or deleted
    default: present
    choices: [ absent, present ]
    type: str
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: "1.22.0"
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Add Object Store Virtual Host
  purestorage.flashblade.purefb_virtualhost:
    name: "s3.acme.com"
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: Delete Object Store Virtual Host
  purestorage.flashblade.purefb_virtualhost:
    name: "nohost.acme.com"
    state: absent
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

MAX_HOST_COUNT = 10
CONTEXT_API_VERSION = "2.17"


def delete_host(module, blade):
    """Delete Object Store Virtual Host"""
    changed = False
    api_version = list(blade.get_versions().items)
    if module.params["name"] == "s3.amazonaws.com":
        module.warn("s3.amazonaws.com is a reserved name and cannot be deleted")
    else:
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in api_version:
                res = blade.delete_object_store_virtual_hosts(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_object_store_virtual_hosts(
                    names=[module.params["name"]]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete Object Store Virtual Host {0}".format(
                        module.params["name"]
                    )
                )
    module.exit_json(changed=changed)


def add_host(module, blade):
    """Add Object Store Virtual Host"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in api_version:
            res = blade.post_object_store_virtual_hosts(
                names=[module.params["name"]], context_names=[module.params["context"]]
            )
        else:
            res = blade.post_object_store_virtual_hosts(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to add Object Store Virtual Host {0}".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            name=dict(type="str", required=True),
            context=dict(type="str", default=""),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    blade = get_system(module)
    api_version = list(blade.get_versions().items)
    state = module.params["state"]

    if CONTEXT_API_VERSION in api_version:
        exists = bool(
            blade.get_object_store_virtual_hosts(
                names=[module.params["name"]], context_names=[module.params["context"]]
            ).status_code
            == 200
        )
    else:
        exists = bool(
            blade.get_object_store_virtual_hosts(
                names=[module.params["name"]]
            ).status_code
            == 200
        )
    if CONTEXT_API_VERSION in api_version:
        vhosts = blade.get_object_store_virtual_hosts(
            context_names=[module.params["context"]]
        )
    else:
        vhosts = blade.get_object_store_virtual_hosts()
    if vhosts.total_item_count < MAX_HOST_COUNT:
        if not exists and state == "present":
            add_host(module, blade)
        elif exists and state == "absent":
            delete_host(module, blade)
    else:
        module.warn("Maximum Object Store Virtual Host reached.")

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
