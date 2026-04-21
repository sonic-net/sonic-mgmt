#!/usr/bin/python
# Copyright (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: openssl_publickey
short_description: Generate an OpenSSL public key from its private key
description:
  - This module allows one to (re)generate public keys from their private keys.
  - Public keys are generated in PEM or OpenSSH format. Private keys must be OpenSSL PEM keys. B(OpenSSH private keys are
    not supported), use the M(community.crypto.openssh_keypair) module to manage these.
  - The module uses the cryptography Python library.
author:
  - Yanis Guenane (@Spredzy)
  - Felix Fontein (@felixfontein)
extends_documentation_fragment:
  - ansible.builtin.files
  - community.crypto._attributes
  - community.crypto._attributes.files
  - community.crypto._cryptography_dep.minimum
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  safe_file_operations:
    support: full
  idempotent:
    support: partial
    details:
      - The module is not idempotent if O(force=true).
options:
  state:
    description:
      - Whether the public key should exist or not, taking action if the state is different from what is stated.
    type: str
    default: present
    choices: [absent, present]
  force:
    description:
      - Should the key be regenerated even it it already exists.
    type: bool
    default: false
  format:
    description:
      - The format of the public key.
    type: str
    default: PEM
    choices: [OpenSSH, PEM]
  path:
    description:
      - Name of the file in which the generated TLS/SSL public key will be written.
    type: path
    required: true
  privatekey_path:
    description:
      - Path to the TLS/SSL private key from which to generate the public key.
      - Either O(privatekey_path) or O(privatekey_content) must be specified, but not both. If O(state) is V(present), one
        of them is required.
    type: path
  privatekey_content:
    description:
      - The content of the TLS/SSL private key from which to generate the public key.
      - Either O(privatekey_path) or O(privatekey_content) must be specified, but not both. If O(state) is V(present), one
        of them is required.
    type: str
    version_added: '1.0.0'
  privatekey_passphrase:
    description:
      - The passphrase for the private key.
    type: str
  backup:
    description:
      - Create a backup file including a timestamp so you can get the original public key back if you overwrote it with a
        different one by accident.
    type: bool
    default: false
  select_crypto_backend:
    description:
      - Determines which crypto backend to use.
      - The default choice is V(auto), which tries to use C(cryptography) if available.
      - If set to V(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
      - Note that with community.crypto 3.0.0, all values behave the same.
        This option will be deprecated in a later version.
        We recommend to not set it explicitly.
    type: str
    default: auto
    choices: [auto, cryptography]
  return_content:
    description:
      - If set to V(true), will return the (current or generated) public key's content as RV(publickey).
    type: bool
    default: false
    version_added: '1.0.0'
seealso:
  - module: community.crypto.x509_certificate
  - module: community.crypto.x509_certificate_pipe
  - module: community.crypto.openssl_csr
  - module: community.crypto.openssl_csr_pipe
  - module: community.crypto.openssl_dhparam
  - module: community.crypto.openssl_pkcs12
  - module: community.crypto.openssl_privatekey
  - module: community.crypto.openssl_privatekey_pipe
"""

EXAMPLES = r"""
---
- name: Generate an OpenSSL public key in PEM format
  community.crypto.openssl_publickey:
    path: /etc/ssl/public/ansible.com.pem
    privatekey_path: /etc/ssl/private/ansible.com.pem

- name: Generate an OpenSSL public key in PEM format from an inline key
  community.crypto.openssl_publickey:
    path: /etc/ssl/public/ansible.com.pem
    privatekey_content: "{{ private_key_content }}"

- name: Generate an OpenSSL public key in OpenSSH v2 format
  community.crypto.openssl_publickey:
    path: /etc/ssl/public/ansible.com.pem
    privatekey_path: /etc/ssl/private/ansible.com.pem
    format: OpenSSH

- name: Generate an OpenSSL public key with a passphrase protected private key
  community.crypto.openssl_publickey:
    path: /etc/ssl/public/ansible.com.pem
    privatekey_path: /etc/ssl/private/ansible.com.pem
    privatekey_passphrase: ansible

- name: Force regenerate an OpenSSL public key if it already exists
  community.crypto.openssl_publickey:
    path: /etc/ssl/public/ansible.com.pem
    privatekey_path: /etc/ssl/private/ansible.com.pem
    force: true

- name: Remove an OpenSSL public key
  community.crypto.openssl_publickey:
    path: /etc/ssl/public/ansible.com.pem
    state: absent
"""

RETURN = r"""
privatekey:
  description:
    - Path to the TLS/SSL private key the public key was generated from.
    - Will be V(none) if the private key has been provided in O(privatekey_content).
  returned: changed or success
  type: str
  sample: /etc/ssl/private/ansible.com.pem
format:
  description: The format of the public key (PEM, OpenSSH, ...).
  returned: changed or success
  type: str
  sample: PEM
filename:
  description: Path to the generated TLS/SSL public key file.
  returned: changed or success
  type: str
  sample: /etc/ssl/public/ansible.com.pem
fingerprint:
  description:
    - The fingerprint of the public key. Fingerprint will be generated for each hashlib.algorithms available.
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
  sample: /path/to/publickey.pem.2019-03-09@11:22~
publickey:
  description: The (current or generated) public key's content.
  returned: if O(state) is V(present) and O(return_content) is V(true)
  type: str
  version_added: '1.0.0'
"""

import os
import typing as t

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLBadPassphraseError,
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.publickey_info import (
    PublicKeyParseError,
    get_publickey_info,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    OpenSSLObject,
    get_fingerprint,
    load_privatekey,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)
from ansible_collections.community.crypto.plugins.module_utils._io import (
    load_file_if_exists,
    write_file,
)


MINIMAL_CRYPTOGRAPHY_VERSION = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION

try:
    from cryptography.hazmat.primitives import serialization as crypto_serialization
except ImportError:
    pass

if t.TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import (  # pragma: no cover
        PrivateKeyTypes,
        PublicKeyTypes,
    )


class PublicKeyError(OpenSSLObjectError):
    pass


class PublicKey(OpenSSLObject):
    def __init__(self, module: AnsibleModule) -> None:
        super().__init__(
            path=module.params["path"],
            state=module.params["state"],
            force=module.params["force"],
            check_mode=module.check_mode,
        )
        self.module = module
        self.format: t.Literal["OpenSSH", "PEM"] = module.params["format"]
        self.privatekey_path: str | None = module.params["privatekey_path"]
        privatekey_content: str | None = module.params["privatekey_content"]
        if privatekey_content is not None:
            self.privatekey_content: bytes | None = privatekey_content.encode("utf-8")
        else:
            self.privatekey_content = None
        self.privatekey_passphrase: str | None = module.params["privatekey_passphrase"]
        self.privatekey: PrivateKeyTypes | None = None
        self.publickey_bytes: bytes | None = None
        self.return_content: bool = module.params["return_content"]
        self.fingerprint: dict[str, str] = {}

        self.backup: bool = module.params["backup"]
        self.backup_file: str | None = None

        self.diff_before = self._get_info(None)
        self.diff_after = self._get_info(None)

    def _get_info(self, data: bytes | None) -> dict[str, t.Any]:
        if data is None:
            return {}
        result = {"can_parse_key": False}
        try:
            result.update(
                get_publickey_info(
                    module=self.module, content=data, prefer_one_fingerprint=True
                )
            )
            result["can_parse_key"] = True
        except PublicKeyParseError as exc:
            result.update(exc.result)
        except Exception:
            pass
        return result

    def _create_publickey(self, module: AnsibleModule) -> bytes:
        self.privatekey = load_privatekey(
            path=self.privatekey_path,
            content=self.privatekey_content,
            passphrase=self.privatekey_passphrase,
        )
        if self.format == "OpenSSH":
            return self.privatekey.public_key().public_bytes(
                crypto_serialization.Encoding.OpenSSH,
                crypto_serialization.PublicFormat.OpenSSH,
            )
        return self.privatekey.public_key().public_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def generate(self, module: AnsibleModule) -> None:
        """Generate the public key."""

        if self.privatekey_path is not None and not os.path.exists(
            self.privatekey_path
        ):
            raise PublicKeyError(
                f"The private key {self.privatekey_path} does not exist"
            )

        if not self.check(module, perms_required=False) or self.force:
            try:
                publickey_content = self._create_publickey(module)
                self.diff_after = self._get_info(publickey_content)
                if self.return_content:
                    self.publickey_bytes = publickey_content

                if self.backup:
                    self.backup_file = module.backup_local(self.path)
                write_file(module=module, content=publickey_content)

                self.changed = True
            except OpenSSLBadPassphraseError as exc:
                raise PublicKeyError(exc) from exc
            except (IOError, OSError) as exc:
                raise PublicKeyError(exc) from exc

        self.fingerprint = get_fingerprint(
            path=self.privatekey_path,
            content=self.privatekey_content,
            passphrase=self.privatekey_passphrase,
        )
        file_args = module.load_file_common_arguments(module.params)
        if module.check_file_absent_if_check_mode(
            file_args["path"]
        ) or module.set_fs_attributes_if_different(file_args, False):
            self.changed = True

    def check(self, module: AnsibleModule, *, perms_required: bool = True) -> bool:
        """Ensure the resource is in its desired state."""

        state_and_perms = super().check(module=module, perms_required=perms_required)

        def _check_privatekey() -> bool:
            if self.privatekey_path is not None and not os.path.exists(
                self.privatekey_path
            ):
                return False

            current_publickey: PublicKeyTypes
            try:
                with open(self.path, "rb") as public_key_fh:
                    publickey_content = public_key_fh.read()
                self.diff_before = self.diff_after = self._get_info(publickey_content)
                if self.return_content:
                    self.publickey_bytes = publickey_content
                if self.format == "OpenSSH":
                    # Read and dump public key. Makes sure that the comment is stripped off.
                    current_publickey = crypto_serialization.load_ssh_public_key(
                        publickey_content
                    )
                    publickey_content = current_publickey.public_bytes(
                        crypto_serialization.Encoding.OpenSSH,
                        crypto_serialization.PublicFormat.OpenSSH,
                    )
                else:
                    current_publickey = crypto_serialization.load_pem_public_key(
                        publickey_content
                    )
                    publickey_content = current_publickey.public_bytes(
                        crypto_serialization.Encoding.PEM,
                        crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
            except Exception:
                return False

            try:
                desired_publickey = self._create_publickey(module)
            except OpenSSLBadPassphraseError as exc:
                raise PublicKeyError(exc) from exc

            return publickey_content == desired_publickey

        if not state_and_perms:
            return state_and_perms

        return _check_privatekey()

    def remove(self, module: AnsibleModule) -> None:
        if self.backup:
            self.backup_file = module.backup_local(self.path)
        super().remove(module)

    def dump(self) -> dict[str, t.Any]:
        """Serialize the object into a dictionary."""

        result: dict[str, t.Any] = {
            "privatekey": self.privatekey_path,
            "filename": self.path,
            "format": self.format,
            "changed": self.changed,
            "fingerprint": self.fingerprint,
        }
        if self.backup_file:
            result["backup_file"] = self.backup_file
        if self.return_content:
            if self.publickey_bytes is None:
                self.publickey_bytes = load_file_if_exists(
                    path=self.path, ignore_errors=True
                )
            result["publickey"] = (
                self.publickey_bytes.decode("utf-8") if self.publickey_bytes else None
            )

        result["diff"] = {
            "before": self.diff_before,
            "after": self.diff_after,
        }

        return result


def main() -> t.NoReturn:
    module = AnsibleModule(
        argument_spec={
            "state": {
                "type": "str",
                "default": "present",
                "choices": ["present", "absent"],
            },
            "force": {"type": "bool", "default": False},
            "path": {"type": "path", "required": True},
            "privatekey_path": {"type": "path"},
            "privatekey_content": {"type": "str", "no_log": True},
            "format": {"type": "str", "default": "PEM", "choices": ["OpenSSH", "PEM"]},
            "privatekey_passphrase": {"type": "str", "no_log": True},
            "backup": {"type": "bool", "default": False},
            "select_crypto_backend": {
                "type": "str",
                "choices": ["auto", "cryptography"],
                "default": "auto",
            },
            "return_content": {"type": "bool", "default": False},
        },
        supports_check_mode=True,
        add_file_common_args=True,
        required_if=[
            ("state", "present", ["privatekey_path", "privatekey_content"], True)
        ],
        mutually_exclusive=(["privatekey_path", "privatekey_content"],),
    )

    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )

    base_dir = os.path.dirname(module.params["path"]) or "."
    if not os.path.isdir(base_dir):
        module.fail_json(
            name=base_dir,
            msg=f"The directory '{base_dir}' does not exist or the file is not a directory",
        )

    try:
        public_key = PublicKey(module)

        if public_key.state == "present":
            if module.check_mode:
                result = public_key.dump()
                result["changed"] = module.params["force"] or not public_key.check(
                    module
                )
                module.exit_json(**result)

            public_key.generate(module)
        else:
            if module.check_mode:
                result = public_key.dump()
                result["changed"] = os.path.exists(module.params["path"])
                module.exit_json(**result)

            public_key.remove(module)

        result = public_key.dump()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
