#!/usr/bin/python
# Copyright (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: openssl_privatekey
short_description: Generate OpenSSL private keys
description:
  - This module allows one to (re)generate OpenSSL private keys.
  - The default mode for the private key file will be V(0600) if O(mode) is not explicitly set.
  - Please note that the module regenerates private keys if they do not match the module's options. In particular, if you
    provide another passphrase (or specify none), change the keysize, and so on, the private key will be regenerated.
    If you are concerned that this could B(overwrite your private key), consider using the O(backup) option.
author:
  - Yanis Guenane (@Spredzy)
  - Felix Fontein (@felixfontein)
extends_documentation_fragment:
  - ansible.builtin.files
  - community.crypto._attributes
  - community.crypto._attributes.files
  - community.crypto._module_privatekey
attributes:
  check_mode:
    support: full
  safe_file_operations:
    support: full
options:
  state:
    description:
      - Whether the private key should exist or not, taking action if the state is different from what is stated.
    type: str
    default: present
    choices: [absent, present]
  force:
    description:
      - Should the key be regenerated even if it already exists.
    type: bool
    default: false
  path:
    description:
      - Name of the file in which the generated TLS/SSL private key will be written. It will have V(0600) mode if O(mode)
        is not explicitly set.
    type: path
    required: true
  format:
    version_added: '1.0.0'
  format_mismatch:
    version_added: '1.0.0'
  backup:
    description:
      - Create a backup file including a timestamp so you can get the original private key back if you overwrote it with a
        new one by accident.
    type: bool
    default: false
  return_content:
    description:
      - If set to V(true), will return the (current or generated) private key's content as RV(privatekey).
      - Note that especially if the private key is not encrypted, you have to make sure that the returned value is treated
        appropriately and not accidentally written to logs, and so on! Use with care!
      - Use Ansible's C(no_log) task option to avoid the output being shown. See also
        U(https://docs.ansible.com/ansible/latest/reference_appendices/faq.html#how-do-i-keep-secret-data-in-my-playbook).
    type: bool
    default: false
    version_added: '1.0.0'
  regenerate:
    version_added: '1.0.0'
seealso:
  - module: community.crypto.openssl_privatekey_pipe
  - module: community.crypto.openssl_privatekey_info
"""

EXAMPLES = r"""
---
- name: Generate an OpenSSL private key with the default values (4096 bits, RSA)
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem

- name: Generate an OpenSSL private key with the default values (4096 bits, RSA) and a passphrase
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem
    passphrase: ansible
    cipher: auto

- name: Generate an OpenSSL private key with a different size (2048 bits)
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem
    size: 2048

- name: Force regenerate an OpenSSL private key if it already exists
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem
    force: true

- name: Generate an OpenSSL private key with a different algorithm (DSA)
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem
    type: DSA

- name: Generate an OpenSSL private key with elliptic curve cryptography (ECC)
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem
    type: ECC
    curve: secp256r1
"""

RETURN = r"""
size:
  description: Size (in bits) of the TLS/SSL private key.
  returned: changed or success
  type: int
  sample: 4096
type:
  description: Algorithm used to generate the TLS/SSL private key.
  returned: changed or success
  type: str
  sample: RSA
curve:
  description: Elliptic curve used to generate the TLS/SSL private key.
  returned: changed or success, and O(type) is V(ECC)
  type: str
  sample: secp256r1
filename:
  description: Path to the generated TLS/SSL private key file.
  returned: changed or success
  type: str
  sample: /etc/ssl/private/ansible.com.pem
fingerprint:
  description:
    - The fingerprint of the public key. Fingerprint will be generated for each C(hashlib.algorithms) available.
  returned: changed or success
  type: dict
  sample:
    md5: "84:75:71:72:8d:04:b5:6c:4d:37:6d:66:83:f5:4c:29"
    sha1: "51:cc:7c:68:5d:eb:41:43:88:7e:1a:ae:c7:f8:24:72:ee:71:f6:10"
    sha224: "b1:19:a6:6c:14:ac:33:1d:ed:18:50:d3:06:5c:b2:32:91:f1:f1:52:8c:cb:d5:75:e9:f5:9b:46"
    sha256: "41:ab:c7:cb:d5:5f:30:60:46:99:ac:d4:00:70:cf:a1:76:4f:24:5d:10:24:57:5d:51:6e:09:97:df:2f:de:c7"
    sha384: "85:39:50:4e:de:d9:19:33:40:70:ae:10:ab:59:24:19:51:c3:a2:e4:0b:1c:b1:6e:dd:b3:0c:d9:9e:6a:46:af:da:18:f8:ef:ae:2e:c0:9a:75:2c:9b:b3:0f:3a:5f:3d"
    sha512: "fd:ed:5e:39:48:5f:9f:fe:7f:25:06:3f:79:08:cd:ee:a5:e7:b3:3d:13:82:87:1f:84:e1:f5:c7:28:77:53:94:86:56:38:69:f0:d9:35:22:01:1e:a6:60:...:0f:9b"
backup_file:
  description: Name of backup file created.
  returned: changed and if O(backup) is V(true)
  type: str
  sample: /path/to/privatekey.pem.2019-03-09@11:22~
privatekey:
  description:
    - The (current or generated) private key's content.
    - Will be Base64-encoded if the key is in raw format.
  returned: if O(state) is V(present) and O(return_content) is V(true)
  type: str
  version_added: '1.0.0'
"""

import os
import typing as t

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.privatekey import (
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

    from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.privatekey import (  # pragma: no cover
        PrivateKeyBackend,
    )


class PrivateKeyModule(OpenSSLObject):
    def __init__(
        self, module: AnsibleModule, module_backend: PrivateKeyBackend
    ) -> None:
        super().__init__(
            path=module.params["path"],
            state=module.params["state"],
            force=module.params["force"],
            check_mode=module.check_mode,
        )
        self.module_backend = module_backend
        self.return_content: bool = module.params["return_content"]
        if self.force:
            module_backend.regenerate = "always"

        self.backup: str | None = module.params["backup"]
        self.backup_file: str | None = None

        if module.params["mode"] is None:
            module.params["mode"] = "0600"

        module_backend.set_existing(
            privatekey_bytes=load_file_if_exists(path=self.path, module=module)
        )

    def generate(self, module: AnsibleModule) -> None:
        """Generate a keypair."""

        if self.module_backend.needs_regeneration():
            # Regenerate
            if not self.check_mode:
                if self.backup:
                    self.backup_file = module.backup_local(self.path)
                self.module_backend.generate_private_key()
                privatekey_data = self.module_backend.get_private_key_data()
                write_file(module=module, content=privatekey_data, default_mode=0o600)
            self.changed = True
        elif self.module_backend.needs_conversion():
            # Convert
            if not self.check_mode:
                if self.backup:
                    self.backup_file = module.backup_local(self.path)
                self.module_backend.convert_private_key()
                privatekey_data = self.module_backend.get_private_key_data()
                write_file(module=module, content=privatekey_data, default_mode=0o600)
            self.changed = True

        file_args = module.load_file_common_arguments(module.params)
        if module.check_file_absent_if_check_mode(file_args["path"]):
            self.changed = True
        else:
            self.changed = module.set_fs_attributes_if_different(
                file_args, self.changed
            )

    def remove(self, module: AnsibleModule) -> None:
        self.module_backend.set_existing(privatekey_bytes=None)
        if self.backup and not self.check_mode:
            self.backup_file = module.backup_local(self.path)
        super().remove(module)

    def dump(self) -> dict[str, t.Any]:
        """Serialize the object into a dictionary."""

        result = self.module_backend.dump(include_key=self.return_content)
        result["filename"] = self.path
        result["changed"] = self.changed
        if self.backup_file:
            result["backup_file"] = self.backup_file

        return result


def main() -> t.NoReturn:
    argument_spec = get_privatekey_argument_spec()
    argument_spec.argument_spec.update(
        {
            "state": {
                "type": "str",
                "default": "present",
                "choices": ["present", "absent"],
            },
            "force": {"type": "bool", "default": False},
            "path": {"type": "path", "required": True},
            "backup": {"type": "bool", "default": False},
            "return_content": {"type": "bool", "default": False},
        }
    )
    module = argument_spec.create_ansible_module(
        supports_check_mode=True,
        add_file_common_args=True,
    )

    base_dir = os.path.dirname(module.params["path"]) or "."
    if not os.path.isdir(base_dir):
        module.fail_json(
            name=base_dir,
            msg=f"The directory {base_dir} does not exist or the file is not a directory",
        )

    module_backend = select_backend(module=module)

    try:
        private_key = PrivateKeyModule(module, module_backend)

        if private_key.state == "present":
            private_key.generate(module)
        else:
            private_key.remove(module)

        result = private_key.dump()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
