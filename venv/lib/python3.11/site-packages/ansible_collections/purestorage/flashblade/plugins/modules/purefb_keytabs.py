#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: purefb_keytabs
version_added: '1.6.0'
short_description: Manage FlashBlade Kerberos Keytabs
description:
- Manage Kerberos Keytabs for FlashBlades
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Manage Kerberos Keytabs
    default: import
    type: str
    choices: [ absent, import, export, rotate ]
  name:
    description:
    - Name of the Keytab
    - Must include prefix and suffix
    type: str
  prefix:
    description:
    - Only required for I(import) or I(rotate)
    - Prefix to use for naming the files slots
    - Specifying a file entry prefix is required because a single keytab file can contain
      multiple keytab entries in multiple slots.
    - If not provided for I(import) the current AD Account name will be used.
    type: str
  keytab_file:
    description:
    - Name of file holding Keytab
    type: str
  filetype:
    description:
    - Format of the keytab file
    type: str
    choices: [ binary, base64 ]
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Import a binary keytab
  purestorage.flashblade.purefb_keytabs:
    state: import
    prefix: example
    keytab_file: pure_krb.keytab
    filetype: binary
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6

- name: Import a base64 keytab
  purestorage.flashblade.purefb_keytabs:
    state: import
    prefix: example
    keytab_file: pure_krb.keytab.mime
    filetype: base64
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6

- name: Export a keytab
  purestorage.flashblade.purefb_keytabs:
    state: export
    name: example.3
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
  register: download_file

- name: Delete a keytab
  purestorage.flashblade.purefb_keytabs:
    state: absent
    name: example.3
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6

- name: Rotate current AD account keytabs
  purestorage.flashblade.purefb_keytabs:
    state: rotate
    fb_url: 10.10.10.2

- name: Rotate AD account keytabs by creating new series
  purestorage.flashblade.purefb_keytabs:
    state: rotate
    name: next_prefix
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
download_file:
  description:
  - Name of file containing exported keytab
  returned: When using I(export) option
  type: str
  sample: "/tmp/pure_krb8939478070214877726.keytab"
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flashblade import KeytabPost, Reference
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def rotate_keytab(module, blade):
    """Rotate keytab"""
    changed = True
    account = Reference(
        name=list(blade.get_active_directory().items)[0].name,
        resource_type="active-directory",
    )
    keytab = KeytabPost(source=account)
    if not module.check_mode:
        res = blade.post_keytabs(keytab=keytab, name_prefixes=module.params["prefix"])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to rotate AD account keytabs, prefix {0}.".format(
                    module.params["prefix"]
                )
            )
    module.exit_json(changed=changed)


def delete_keytab(module, blade):
    """Delete keytab"""
    changed = False
    if blade.get_keytabs(names=[module.params["name"]]).status_code == 200:
        changed = True
        if not module.check_mode:
            res = blade.delete_keytabs(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete keytab {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def import_keytab(module, blade):
    """Import keytab"""
    changed = True
    if not module.check_mode:
        if module.params["filetype"] == "binary":
            readtype = "rb"
        else:
            readtype = "r"
        with open(module.params["keytab_file"], readtype) as keytab_file:
            keytab_data = keytab_file.read()
        short_name = module.params["keytab_file"].split("/")[-1]
        res = blade.post_keytabs_upload(
            name_prefixes=module.params["prefix"], keytab_file=(short_name, keytab_data)
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to import keytab file {0}. Error: {1}".format(
                    module.params["keytab_file"], res.errors[0].message
                )
            )

    module.exit_json(changed=changed)


def export_keytab(module, blade):
    """Export keytab"""
    changed = False
    download_file = ""
    if blade.get_keytabs(names=[module.params["name"]]).status_code == 200:
        changed = True
        if not module.check_mode:
            res = blade.get_keytabs_download(keytab_names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to export keytab {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
            else:
                download_file = list(res.items)[0]
    module.exit_json(changed=changed, download_file=download_file)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(
                type="str",
                default="import",
                choices=["absent", "rotate", "import", "export"],
            ),
            name=dict(type="str"),
            prefix=dict(type="str"),
            keytab_file=dict(type="str"),
            filetype=dict(type="str", choices=["binary", "base64"]),
        )
    )

    required_if = [["state", "import", ["prefix"]]]
    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    state = module.params["state"]
    blade = get_system(module)

    if not module.params["prefix"]:
        res = blade.get_active_directory()
        if res.total_item_count == 0:
            module.fail_json(msg="No active directory configred to provide prefix")
        module.params["prefix"] = list(res.items)[0].name

    if state == "import":
        import_keytab(module, blade)
    elif state == "export":
        export_keytab(module, blade)
    elif state == "rotate":
        rotate_keytab(module, blade)
    elif state == "absent":
        delete_keytab(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
