#!/usr/bin/python
# Copyright (c) 2019, Patrick Pichler <ppichler+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: openssl_signature
version_added: 1.1.0
short_description: Sign data with openssl
description:
  - This module allows one to sign data using a private key.
  - The module uses the cryptography Python library.
author:
  - Patrick Pichler (@aveexy)
  - Markus Teufelberger (@MarkusTeufelberger)
extends_documentation_fragment:
  - community.crypto._attributes
  - community.crypto._cryptography_dep.minimum
attributes:
  check_mode:
    support: full
    details:
      - This action does not modify state.
  diff_mode:
    support: none
  idempotent:
    support: partial
    details:
      - Signature algorithms are generally not deterministic. Thus the generated signature
        can change from one invocation to the next.
options:
  privatekey_path:
    description:
      - The path to the private key to use when signing.
      - Either O(privatekey_path) or O(privatekey_content) must be specified, but not both.
    type: path
  privatekey_content:
    description:
      - The content of the private key to use when signing the certificate signing request.
      - Either O(privatekey_path) or O(privatekey_content) must be specified, but not both.
    type: str
  privatekey_passphrase:
    description:
      - The passphrase for the private key.
      - This is required if the private key is password protected.
    type: str
  path:
    description:
      - The file to sign.
      - This file will only be read and not modified.
    type: path
    required: true
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
seealso:
  - module: community.crypto.openssl_signature_info
  - module: community.crypto.openssl_privatekey
"""

EXAMPLES = r"""
---
- name: Sign example file
  community.crypto.openssl_signature:
    privatekey_path: private.key
    path: /tmp/example_file
  register: sig

- name: Verify signature of example file
  community.crypto.openssl_signature_info:
    certificate_path: cert.pem
    path: /tmp/example_file
    signature: "{{ sig.signature }}"
  register: verify

- name: Make sure the signature is valid
  ansible.builtin.assert:
    that:
      - verify.valid
"""

RETURN = r"""
signature:
  description: Base64 encoded signature.
  returned: success
  type: str
"""

import base64
import os
import typing as t

from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)
from ansible_collections.community.crypto.plugins.module_utils._version import (
    LooseVersion,
)


MINIMAL_CRYPTOGRAPHY_VERSION = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION

try:
    import cryptography
    import cryptography.hazmat.primitives.asymmetric.padding
    import cryptography.hazmat.primitives.hashes

except ImportError:
    CRYPTOGRAPHY_VERSION = LooseVersion("0.0")  # pylint: disable=invalid-name
else:
    # pylint: disable-next=invalid-name
    CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    OpenSSLObject,
    load_privatekey,
)


class SignatureBase(OpenSSLObject):
    def __init__(self, module: AnsibleModule) -> None:
        super().__init__(
            path=module.params["path"],
            state="present",
            force=False,
            check_mode=module.check_mode,
        )

        self.module = module
        self.privatekey_path: str | None = module.params["privatekey_path"]
        privatekey_content: str | None = module.params["privatekey_content"]
        if privatekey_content is not None:
            self.privatekey_content: bytes | None = privatekey_content.encode("utf-8")
        else:
            self.privatekey_content = None
        self.privatekey_passphrase: str | None = module.params["privatekey_passphrase"]

    def generate(self, module: AnsibleModule) -> None:
        # Empty method because OpenSSLObject wants this
        pass

    def dump(self) -> dict[str, t.Any]:
        # Empty method because OpenSSLObject wants this
        return {}


# Implementation with using cryptography
class SignatureCryptography(SignatureBase):
    def __init__(self, module: AnsibleModule) -> None:
        super().__init__(module)

    def run(self) -> dict[str, t.Any]:
        _padding = cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15()
        _hash = cryptography.hazmat.primitives.hashes.SHA256()

        result: dict[str, t.Any] = {}

        try:
            with open(self.path, "rb") as f:
                _in = f.read()

            private_key = load_privatekey(
                path=self.privatekey_path,
                content=self.privatekey_content,
                passphrase=self.privatekey_passphrase,
            )

            signature = None

            if isinstance(
                private_key,
                cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey,
            ):
                signature = private_key.sign(_in, _hash)

            elif isinstance(
                private_key,
                cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey,
            ):
                signature = private_key.sign(
                    _in, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(_hash)
                )

            elif isinstance(
                private_key,
                (
                    cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey,
                    cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey,
                ),
            ):
                signature = private_key.sign(_in)

            elif isinstance(
                private_key,
                cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey,
            ):
                signature = private_key.sign(_in, _padding, _hash)

            if signature is None:
                self.module.fail_json(
                    msg=f"Unsupported key type. Your cryptography version is {CRYPTOGRAPHY_VERSION}"
                )

            result["signature"] = base64.b64encode(signature)
            return result

        except Exception as e:
            raise OpenSSLObjectError(e) from e


def main() -> t.NoReturn:
    module = AnsibleModule(
        argument_spec={
            "privatekey_path": {"type": "path"},
            "privatekey_content": {"type": "str", "no_log": True},
            "privatekey_passphrase": {"type": "str", "no_log": True},
            "path": {"type": "path", "required": True},
            "select_crypto_backend": {
                "type": "str",
                "choices": ["auto", "cryptography"],
                "default": "auto",
            },
        },
        mutually_exclusive=(["privatekey_path", "privatekey_content"],),
        required_one_of=(["privatekey_path", "privatekey_content"],),
        supports_check_mode=True,
    )

    if not os.path.isfile(module.params["path"]):
        module.fail_json(
            name=module.params["path"],
            msg=f"The file {module.params['path']} does not exist",
        )

    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )

    try:
        _sign = SignatureCryptography(module)

        result = _sign.run()

        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
