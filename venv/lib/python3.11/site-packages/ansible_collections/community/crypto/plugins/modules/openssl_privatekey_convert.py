#!/usr/bin/python
# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: openssl_privatekey_convert
short_description: Convert OpenSSL private keys
version_added: 2.1.0
description:
  - This module allows one to convert OpenSSL private keys.
  - The default mode for the private key file will be V(0600) if O(mode) is not explicitly set.
author:
  - Felix Fontein (@felixfontein)
extends_documentation_fragment:
  - ansible.builtin.files
  - community.crypto._attributes
  - community.crypto._attributes.files
  - community.crypto._module_privatekey_convert
attributes:
  check_mode:
    support: full
  safe_file_operations:
    support: full
options:
  dest_path:
    description:
      - Name of the file in which the generated TLS/SSL private key will be written. It will have V(0600) mode if O(mode)
        is not explicitly set.
    type: path
    required: true
  backup:
    description:
      - Create a backup file including a timestamp so you can get the original private key back if you overwrote it with a
        new one by accident.
    type: bool
    default: false
seealso: []
"""

EXAMPLES = r"""
---
- name: Convert private key to PKCS8 format with passphrase
  community.crypto.openssl_privatekey_convert:
    src_path: /etc/ssl/private/ansible.com.pem
    dest_path: /etc/ssl/private/ansible.com.key
    dest_passphrase: '{{ private_key_passphrase }}'
    format: pkcs8
"""

RETURN = r"""
backup_file:
  description: Name of backup file created.
  returned: changed and if O(backup) is V(true)
  type: str
  sample: /path/to/privatekey.pem.2019-03-09@11:22~
"""

import os
import typing as t

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.privatekey_convert import (
    get_privatekey_argument_spec,
    select_backend,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    OpenSSLObject,
)
from ansible_collections.community.crypto.plugins.module_utils._io import (
    load_file_if_exists,
    write_file,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.privatekey_convert import (  # pragma: no cover
        PrivateKeyConvertBackend,
    )


class PrivateKeyConvertModule(OpenSSLObject):
    def __init__(
        self, module: AnsibleModule, module_backend: PrivateKeyConvertBackend
    ) -> None:
        super().__init__(
            path=module.params["dest_path"],
            state="present",
            force=False,
            check_mode=module.check_mode,
        )
        self.module_backend = module_backend

        self.backup: bool = module.params["backup"]
        self.backup_file: str | None = None

        module.params["path"] = module.params["dest_path"]
        if module.params["mode"] is None:
            module.params["mode"] = "0600"

        module_backend.set_existing_destination(
            privatekey_bytes=load_file_if_exists(path=self.path, module=module)
        )

    def generate(self, module: AnsibleModule) -> None:
        """Do conversion."""

        if self.module_backend.needs_conversion():
            # Convert
            privatekey_data = self.module_backend.get_private_key_data()
            if privatekey_data is None:
                raise AssertionError(
                    "Contract violation: privatekey_data is None"
                )  # pragma: no cover
            if not self.check_mode:
                if self.backup:
                    self.backup_file = module.backup_local(self.path)
                write_file(module=module, content=privatekey_data, default_mode=0o600)
            self.changed = True

        file_args = module.load_file_common_arguments(module.params)
        if module.check_file_absent_if_check_mode(file_args["path"]):
            self.changed = True
        else:
            self.changed = module.set_fs_attributes_if_different(
                file_args, self.changed
            )

    def dump(self) -> dict[str, t.Any]:
        """Serialize the object into a dictionary."""

        result = self.module_backend.dump()
        result["changed"] = self.changed
        if self.backup_file:
            result["backup_file"] = self.backup_file

        return result


def main() -> t.NoReturn:
    argument_spec = get_privatekey_argument_spec()
    argument_spec.argument_spec.update(
        {
            "dest_path": {"type": "path", "required": True},
            "backup": {"type": "bool", "default": False},
        }
    )
    module = argument_spec.create_ansible_module(
        supports_check_mode=True,
        add_file_common_args=True,
    )

    base_dir = os.path.dirname(module.params["dest_path"]) or "."
    if not os.path.isdir(base_dir):
        module.fail_json(
            name=base_dir,
            msg=f"The directory {base_dir} does not exist or the file is not a directory",
        )

    module_backend = select_backend(module=module)

    try:
        private_key = PrivateKeyConvertModule(module, module_backend)

        private_key.generate(module)

        result = private_key.dump()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
