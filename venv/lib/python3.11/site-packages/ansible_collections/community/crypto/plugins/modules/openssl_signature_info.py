#!/usr/bin/python
# Copyright (c) 2019, Patrick Pichler <ppichler+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: openssl_signature_info
version_added: 1.1.0
short_description: Verify signatures with openssl
description:
  - This module allows one to verify a signature for a file by a certificate.
  - The module uses the cryptography Python library.
author:
  - Patrick Pichler (@aveexy)
  - Markus Teufelberger (@MarkusTeufelberger)
extends_documentation_fragment:
  - community.crypto._attributes
  - community.crypto._attributes.info_module
  - community.crypto._attributes.idempotent_not_modify_state
  - community.crypto._cryptography_dep.minimum
options:
  path:
    description:
      - The signed file to verify.
      - This file will only be read and not modified.
    type: path
    required: true
  certificate_path:
    description:
      - The path to the certificate used to verify the signature.
      - Either O(certificate_path) or O(certificate_content) must be specified, but not both.
    type: path
  certificate_content:
    description:
      - The content of the certificate used to verify the signature.
      - Either O(certificate_path) or O(certificate_content) must be specified, but not both.
    type: str
  signature:
    description: Base64 encoded signature.
    type: str
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
  - module: community.crypto.openssl_signature
  - module: community.crypto.x509_certificate
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
valid:
  description: V(true) means the signature was valid for the given file, V(false) means it was not.
  returned: success
  type: bool
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
    load_certificate,
)


class SignatureInfoBase(OpenSSLObject):
    def __init__(self, module: AnsibleModule) -> None:
        super().__init__(
            path=module.params["path"],
            state="present",
            force=False,
            check_mode=module.check_mode,
        )

        self.module = module
        self.signature: str = module.params["signature"]
        self.certificate_path: str | None = module.params["certificate_path"]
        certificate_content: str | None = module.params["certificate_content"]
        if certificate_content is not None:
            self.certificate_content: bytes | None = certificate_content.encode("utf-8")
        else:
            self.certificate_content = None

    def generate(self, module: AnsibleModule) -> None:
        # Empty method because OpenSSLObject wants this
        pass

    def dump(self) -> dict[str, t.Any]:
        # Empty method because OpenSSLObject wants this
        return {}


# Implementation with using cryptography
class SignatureInfoCryptography(SignatureInfoBase):
    def __init__(self, module: AnsibleModule) -> None:
        super().__init__(module)

    def run(self) -> dict[str, t.Any]:
        _padding = cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15()
        _hash = cryptography.hazmat.primitives.hashes.SHA256()

        result: dict[str, t.Any] = {}

        try:
            with open(self.path, "rb") as f:
                _in = f.read()

            _signature = base64.b64decode(self.signature)
            certificate = load_certificate(
                path=self.certificate_path,
                content=self.certificate_content,
            )
            public_key = certificate.public_key()
            verified = False
            valid = False

            try:
                if isinstance(
                    public_key,
                    cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey,
                ):
                    public_key.verify(_signature, _in, _hash)
                    verified = True
                    valid = True

                elif isinstance(
                    public_key,
                    cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
                ):
                    public_key.verify(
                        _signature,
                        _in,
                        cryptography.hazmat.primitives.asymmetric.ec.ECDSA(_hash),
                    )
                    verified = True
                    valid = True

                elif isinstance(
                    public_key,
                    (
                        cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey,
                        cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey,
                    ),
                ):
                    public_key.verify(_signature, _in)
                    verified = True
                    valid = True

                elif isinstance(
                    public_key,
                    cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey,
                ):
                    public_key.verify(_signature, _in, _padding, _hash)
                    verified = True
                    valid = True
            except cryptography.exceptions.InvalidSignature:
                verified = True
                valid = False

            if not verified:
                self.module.fail_json(
                    msg=f"Unsupported key type. Your cryptography version is {CRYPTOGRAPHY_VERSION}"
                )
            result["valid"] = valid
            return result

        except Exception as e:
            raise OpenSSLObjectError(e) from e


def main() -> t.NoReturn:
    module = AnsibleModule(
        argument_spec={
            "certificate_path": {"type": "path"},
            "certificate_content": {"type": "str"},
            "path": {"type": "path", "required": True},
            "signature": {"type": "str", "required": True},
            "select_crypto_backend": {
                "type": "str",
                "choices": ["auto", "cryptography"],
                "default": "auto",
            },
        },
        mutually_exclusive=(["certificate_path", "certificate_content"],),
        required_one_of=(["certificate_path", "certificate_content"],),
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
        _sign = SignatureInfoCryptography(module)

        result = _sign.run()

        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
