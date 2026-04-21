# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import typing as t
from collections.abc import Callable

from ansible.module_utils.common.text.converters import to_bytes, to_text

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.math import (
    binary_exp_mod,
    quick_is_not_prime,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.publickey_info import (
    _get_cryptography_public_key_info,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    get_fingerprint_of_bytes,
    load_privatekey,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.types import (  # pragma: no cover
        PrivateKeyTypes,
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
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass

SIGNATURE_TEST_DATA = b"1234"


def _get_cryptography_private_key_info(
    key: PrivateKeyTypes, *, need_private_key_data: bool = False
) -> tuple[str, dict[str, t.Any], dict[str, t.Any]]:
    key_type, key_public_data = _get_cryptography_public_key_info(key.public_key())
    key_private_data: dict[str, t.Any] = {}
    if need_private_key_data:
        if isinstance(key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
            rsa_private_numbers = key.private_numbers()
            key_private_data["p"] = rsa_private_numbers.p
            key_private_data["q"] = rsa_private_numbers.q
            key_private_data["exponent"] = rsa_private_numbers.d
        elif isinstance(
            key, cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey
        ):
            dsa_private_numbers = key.private_numbers()
            key_private_data["x"] = dsa_private_numbers.x
        elif isinstance(
            key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
        ):
            ecc_private_numbers = key.private_numbers()
            key_private_data["multiplier"] = ecc_private_numbers.private_value
    return key_type, key_public_data, key_private_data


def _check_dsa_consistency(
    *, key_public_data: dict[str, t.Any], key_private_data: dict[str, t.Any]
) -> bool | None:
    # Get parameters
    p: int | None = key_public_data.get("p")
    if p is None:
        return None
    q: int | None = key_public_data.get("q")
    if q is None:
        return None
    g: int | None = key_public_data.get("g")
    if g is None:
        return None
    y: int | None = key_public_data.get("y")
    if y is None:
        return None
    x: int | None = key_private_data.get("x")
    if x is None:
        return None
    # Make sure that g is not 0, 1 or -1 in Z/pZ
    if g < 2 or g >= p - 1:
        return False
    # Make sure that x is in range
    if x < 1 or x >= q:
        return False
    # Check whether q divides p-1
    if (p - 1) % q != 0:
        return False
    # Check that g**q mod p == 1
    if binary_exp_mod(g, q, m=p) != 1:
        return False
    # Check whether g**x mod p == y
    if binary_exp_mod(g, x, m=p) != y:
        return False
    # Check (quickly) whether p or q are not primes
    return not (quick_is_not_prime(q) or quick_is_not_prime(p))


def _is_cryptography_key_consistent(
    key: PrivateKeyTypes,
    *,
    key_public_data: dict[str, t.Any],
    key_private_data: dict[str, t.Any],
    warn_func: Callable[[str], None] | None = None,
) -> bool | None:
    if isinstance(key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
        # key._backend was removed in cryptography 42.0.0
        backend = getattr(key, "_backend", None)
        if backend is not None:
            return bool(backend._lib.RSA_check_key(key._rsa_cdata))  # type: ignore  # pylint: disable=protected-access
    if isinstance(key, cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey):
        result = _check_dsa_consistency(
            key_public_data=key_public_data, key_private_data=key_private_data
        )
        if result is not None:
            return result
        signature = key.sign(
            SIGNATURE_TEST_DATA, cryptography.hazmat.primitives.hashes.SHA256()
        )
        try:
            key.public_key().verify(
                signature,
                SIGNATURE_TEST_DATA,
                cryptography.hazmat.primitives.hashes.SHA256(),
            )
            return True
        except cryptography.exceptions.InvalidSignature:
            return False
    if isinstance(
        key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
    ):
        signature = key.sign(
            SIGNATURE_TEST_DATA,
            cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                cryptography.hazmat.primitives.hashes.SHA256()
            ),
        )
        try:
            key.public_key().verify(
                signature,
                SIGNATURE_TEST_DATA,
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                    cryptography.hazmat.primitives.hashes.SHA256()
                ),
            )
            return True
        except cryptography.exceptions.InvalidSignature:
            return False
    has_simple_sign_function = False
    if isinstance(
        key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey
    ):
        has_simple_sign_function = True
    if isinstance(key, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey):
        has_simple_sign_function = True
    if has_simple_sign_function:
        signature = key.sign(SIGNATURE_TEST_DATA)  # type: ignore
        try:
            key.public_key().verify(signature, SIGNATURE_TEST_DATA)  # type: ignore
            return True
        except cryptography.exceptions.InvalidSignature:
            return False
    # For X25519 and X448, there's no test yet.
    if warn_func is not None:
        warn_func(f"Cannot determine consistency for key of type {type(key)}")
    return None


class PrivateKeyConsistencyError(OpenSSLObjectError):
    def __init__(self, msg: str, *, result: dict[str, t.Any]) -> None:
        super().__init__(msg)
        self.error_message = msg
        self.result = result


class PrivateKeyParseError(OpenSSLObjectError):
    def __init__(self, msg: str, *, result: dict[str, t.Any]) -> None:
        super().__init__(msg)
        self.error_message = msg
        self.result = result


class PrivateKeyInfoRetrieval:
    key: PrivateKeyTypes

    def __init__(
        self,
        *,
        module: GeneralAnsibleModule,
        content: bytes,
        passphrase: str | None = None,
        return_private_key_data: bool = False,
        check_consistency: bool = False,
    ):
        self.module = module
        self.content = content
        self.passphrase = passphrase
        self.return_private_key_data = return_private_key_data
        self.check_consistency = check_consistency

    def _get_public_key(self, *, binary: bool) -> bytes:
        return self.key.public_key().public_bytes(
            serialization.Encoding.DER if binary else serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _get_key_info(
        self, *, need_private_key_data: bool = False
    ) -> tuple[str, dict[str, t.Any], dict[str, t.Any]]:
        return _get_cryptography_private_key_info(
            self.key, need_private_key_data=need_private_key_data
        )

    def _is_key_consistent(
        self, *, key_public_data: dict[str, t.Any], key_private_data: dict[str, t.Any]
    ) -> bool | None:
        return _is_cryptography_key_consistent(
            self.key,
            key_public_data=key_public_data,
            key_private_data=key_private_data,
            warn_func=self.module.warn,
        )

    def get_info(self, *, prefer_one_fingerprint: bool = False) -> dict[str, t.Any]:
        result: dict[str, t.Any] = {
            "can_parse_key": False,
            "key_is_consistent": None,
        }
        priv_key_detail = self.content
        try:
            self.key = load_privatekey(
                path=None,
                content=priv_key_detail,
                passphrase=(
                    to_bytes(self.passphrase)
                    if self.passphrase is not None
                    else self.passphrase
                ),
            )
            result["can_parse_key"] = True
        except OpenSSLObjectError as exc:
            raise PrivateKeyParseError(str(exc), result=result) from exc

        result["public_key"] = to_text(self._get_public_key(binary=False))
        pk = self._get_public_key(binary=True)
        result["public_key_fingerprints"] = (
            get_fingerprint_of_bytes(pk, prefer_one=prefer_one_fingerprint)
            if pk is not None
            else {}
        )

        key_type, key_public_data, key_private_data = self._get_key_info(
            need_private_key_data=self.return_private_key_data or self.check_consistency
        )
        result["type"] = key_type
        result["public_data"] = key_public_data
        if self.return_private_key_data:
            result["private_data"] = key_private_data

        if self.check_consistency:
            result["key_is_consistent"] = self._is_key_consistent(
                key_public_data=key_public_data, key_private_data=key_private_data
            )
            if result["key_is_consistent"] is False:
                # Only fail when it is False, to avoid to fail on None (which means "we do not know")
                msg = "Private key is not consistent! (See https://blog.hboeck.de/archives/888-How-I-tricked-Symantec-with-a-Fake-Private-Key.html)"
                raise PrivateKeyConsistencyError(msg, result=result)
        return result


def get_privatekey_info(
    *,
    module: GeneralAnsibleModule,
    content: bytes,
    passphrase: str | None = None,
    return_private_key_data: bool = False,
    prefer_one_fingerprint: bool = False,
) -> dict[str, t.Any]:
    info = PrivateKeyInfoRetrieval(
        module=module,
        content=content,
        passphrase=passphrase,
        return_private_key_data=return_private_key_data,
    )
    return info.get_info(prefer_one_fingerprint=prefer_one_fingerprint)


def select_backend(
    *,
    module: GeneralAnsibleModule,
    content: bytes,
    passphrase: str | None = None,
    return_private_key_data: bool = False,
    check_consistency: bool = False,
) -> PrivateKeyInfoRetrieval:
    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )
    return PrivateKeyInfoRetrieval(
        module=module,
        content=content,
        passphrase=passphrase,
        return_private_key_data=return_private_key_data,
        check_consistency=check_consistency,
    )


__all__ = (
    "PrivateKeyConsistencyError",
    "PrivateKeyParseError",
    "PrivateKeyInfoRetrieval",
    "get_privatekey_info",
    "select_backend",
)
