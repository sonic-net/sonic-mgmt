# Copyright (c) 2020-2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import typing as t

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    get_fingerprint_of_bytes,
    load_publickey,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.types import (  # pragma: no cover
        PublicKeyTypes,
    )

    from ansible_collections.community.crypto.plugins.plugin_utils._action_module import (  # pragma: no cover
        AnsibleActionModule,
    )
    from ansible_collections.community.crypto.plugins.plugin_utils._filter_module import (  # pragma: no cover
        FilterModuleMock,
    )

    GeneralAnsibleModule = t.Union[  # noqa: UP007
        AnsibleModule, AnsibleActionModule, FilterModuleMock
    ]  # pragma: no cover


MINIMAL_CRYPTOGRAPHY_VERSION = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION

try:
    import cryptography
    import cryptography.hazmat.primitives.asymmetric.ed448
    import cryptography.hazmat.primitives.asymmetric.ed25519
    import cryptography.hazmat.primitives.asymmetric.x448
    import cryptography.hazmat.primitives.asymmetric.x25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass


def _get_cryptography_public_key_info(
    key: PublicKeyTypes,
) -> tuple[str, dict[str, t.Any]]:
    key_public_data: dict[str, t.Any] = {}
    if isinstance(key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
        key_type = "RSA"
        rsa_public_numbers = key.public_numbers()
        key_public_data["size"] = key.key_size
        key_public_data["modulus"] = rsa_public_numbers.n
        key_public_data["exponent"] = rsa_public_numbers.e
    elif isinstance(key, cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey):
        key_type = "DSA"
        dsa_parameter_numbers = key.parameters().parameter_numbers()
        dsa_public_numbers = key.public_numbers()
        key_public_data["size"] = key.key_size
        key_public_data["p"] = dsa_parameter_numbers.p
        key_public_data["q"] = dsa_parameter_numbers.q
        key_public_data["g"] = dsa_parameter_numbers.g
        key_public_data["y"] = dsa_public_numbers.y
    elif isinstance(
        key, cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey
    ):
        key_type = "X25519"
    elif isinstance(key, cryptography.hazmat.primitives.asymmetric.x448.X448PublicKey):
        key_type = "X448"
    elif isinstance(
        key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey
    ):
        key_type = "Ed25519"
    elif isinstance(
        key, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey
    ):
        key_type = "Ed448"
    elif isinstance(
        key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
    ):
        key_type = "ECC"
        ecc_public_numbers = key.public_numbers()
        key_public_data["curve"] = key.curve.name
        key_public_data["x"] = ecc_public_numbers.x
        key_public_data["y"] = ecc_public_numbers.y
        key_public_data["exponent_size"] = key.curve.key_size
    else:
        key_type = f"unknown ({type(key)})"
    return key_type, key_public_data


class PublicKeyParseError(OpenSSLObjectError):
    def __init__(self, msg: str, *, result: dict[str, t.Any]) -> None:
        super().__init__(msg)
        self.error_message = msg
        self.result = result


class PublicKeyInfoRetrieval:
    def __init__(
        self,
        *,
        module: GeneralAnsibleModule,
        content: bytes | None = None,
        key: PublicKeyTypes | None = None,
    ) -> None:
        # content must be a bytes string
        self.module = module
        self.content = content
        self.key = key

    def _get_public_key(self, binary: bool) -> bytes:
        if self.key is None:
            raise AssertionError("key must be set")  # pragma: no cover
        return self.key.public_bytes(
            serialization.Encoding.DER if binary else serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _get_key_info(self) -> tuple[str, dict[str, t.Any]]:
        if self.key is None:
            raise AssertionError("key must be set")  # pragma: no cover
        return _get_cryptography_public_key_info(self.key)

    def get_info(self, *, prefer_one_fingerprint: bool = False) -> dict[str, t.Any]:
        result: dict[str, t.Any] = {}
        if self.key is None:
            try:
                self.key = load_publickey(content=self.content)
            except OpenSSLObjectError as e:
                raise PublicKeyParseError(str(e), result={}) from e

        pk = self._get_public_key(binary=True)
        result["fingerprints"] = (
            get_fingerprint_of_bytes(pk, prefer_one=prefer_one_fingerprint)
            if pk is not None
            else {}
        )

        key_type, key_public_data = self._get_key_info()
        result["type"] = key_type
        result["public_data"] = key_public_data
        return result


def get_publickey_info(
    *,
    module: GeneralAnsibleModule,
    content: bytes | None = None,
    key: PublicKeyTypes | None = None,
    prefer_one_fingerprint: bool = False,
) -> dict[str, t.Any]:
    info = PublicKeyInfoRetrieval(module=module, content=content, key=key)
    return info.get_info(prefer_one_fingerprint=prefer_one_fingerprint)


def select_backend(
    *,
    module: GeneralAnsibleModule,
    content: bytes | None = None,
    key: PublicKeyTypes | None = None,
) -> PublicKeyInfoRetrieval:
    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )
    return PublicKeyInfoRetrieval(module=module, content=content, key=key)


__all__ = (
    "PublicKeyParseError",
    "PublicKeyInfoRetrieval",
    "get_publickey_info",
    "select_backend",
)
