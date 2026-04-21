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
module: purefb_certgrp
version_added: '1.4.0'
short_description: Manage FlashBlade Certifcate Groups
description:
- Manage certifcate groups for FlashBlades
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete certifcate group
    default: present
    type: str
    choices: [ absent, present ]
  name:
    description:
    - Name of the certificate group
    type: str
  certificates:
    description:
    - List of certifcates to add to a policy on creation
    type: list
    elements: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create a certifcate group
  purestorage.flashblade.purefb_certgrp:
    name: test_grp
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a cerifcate group and add existing certificates
  purestorage.flashblade.purefb_certgrp:
    name: test_grp
    certifcates:
    - cert1
    - cert2
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a certifcate from a group
  purestorage.flashblade.purefb_certgrp:
    name: test_grp
    certificates:
    - cert2
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a certifcate group
  purestorage.flashblade.purefb_certgrp:
    name: test_grp
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def delete_certgrp(module, blade):
    """Delete certifcate group"""
    changed = True
    if not module.check_mode:
        res = blade.delete_certificate_groups(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete certifcate group {0}.".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def create_certgrp(module, blade):
    """Create certifcate group"""
    changed = True
    if not module.check_mode:
        res = blade.post_certificate_groups(names=[module.params["name"]])
        if res.sttaus_code != 200:
            module.fail_json(
                msg="Failed to create certificate group {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if module.params["certificates"]:
            res = blade.post_certificate_groups_certificates(
                certificate_names=module.params["certificates"],
                certificate_group_names=[module.params["name"]],
            )
            if res.status_code != 200:
                blade.delete_certificate_groups(names=[module.params["name"]])
                module.fail_json(
                    msg="Failed to add certifcates {0}. Error: {1}".format(
                        module.params["certificates"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def update_certgrp(module, blade):
    """Update certificate group"""
    changed = False
    res = blade.get_certificate_group_certificates(
        certificate_group_names=[module.params["name"]]
    )
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to get certifates list for group {0}. Error: {1}".format(
                module.params["name"], res.errors[0].message
            )
        )
    certs = list(res.items)
    if certs:
        if module.params["state"] == "present":
            changed = True
            if not module.check_mode:
                res = blade.post_certificate_group_certificates(
                    certificate_names=module.params["certificates"],
                    certificate_group_names=[module.params["name"]],
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to add certifcates {0}. Error: {1}".format(
                            module.params["certificates"], res.errors[0].message
                        )
                    )
    else:
        current = []
        for cert in range(len(certs)):
            current.append(certs[cert].member.name)
        for new_cert in range(len(module.params["certificates"])):
            certificate = module.params["certificates"][new_cert]
            if certificate in current:
                if module.params["state"] == "absent":
                    changed = True
                    if not module.check_mode:
                        res = blade.delete_certificate_group_certificates(
                            certificate_names=[certificate],
                            certificate_group_names=[module.params["name"]],
                        )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to delete certifcate {0} from group {1}. Error: {2}".format(
                                    certificate,
                                    module.params["name"],
                                    res.errors[0].message,
                                )
                            )
            else:
                if module.params["state"] == "present":
                    changed = True
                    if not module.check_mode:
                        res = blade.post_certificate_group_certificates(
                            certificate_names=[certificate],
                            certificate_group_names=[module.params["name"]],
                        )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to add certifcate {0} to group {1}. Error: {2}".format(
                                    certificate,
                                    module.params["name"],
                                    res.errors[0].message,
                                )
                            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            name=dict(type="str"),
            certificates=dict(type="list", elements="str"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    blade = get_system(module)

    certgrp = bool(
        blade.get_certificate_groups(names=[module.params["name"]]).status_code == 200
    )

    if certgrp and state == "present" and module.params["certificates"]:
        update_certgrp(module, blade)
    elif state == "present" and not certgrp:
        create_certgrp(module, blade)
    elif state == "absent" and certgrp:
        if module.params["certificates"]:
            update_certgrp(module, blade)
        else:
            delete_certgrp(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
