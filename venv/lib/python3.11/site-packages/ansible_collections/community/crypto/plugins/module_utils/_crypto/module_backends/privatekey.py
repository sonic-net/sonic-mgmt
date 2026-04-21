# Copyright (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import base64
import traceback
import typing as t

from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.community.crypto.plugins.module_utils._argspec import (
    ArgumentSpec,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.privatekey_info import (
    PrivateKeyConsistencyError,
    PrivateKeyParseError,
    get_privatekey_info,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.pem import (
    identify_private_key_format,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    get_fingerprint_of_privatekey,
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

    GeneralAnsibleModule = t.Union[  # noqa: UP007
        AnsibleModule, AnsibleActionModule
    ]  # pragma: no cover


MINIMAL_CRYPTOGRAPHY_VERSION = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION

try:
    import cryptography
    import cryptography.exceptions
    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.asymmetric.dsa
    import cryptography.hazmat.primitives.asymmetric.ec
    import cryptography.hazmat.primitives.asymmetric.ed448
    import cryptography.hazmat.primitives.asymmetric.ed25519
    import cryptography.hazmat.primitives.asymmetric.rsa
    import cryptography.hazmat.primitives.asymmetric.utils
    import cryptography.hazmat.primitives.asymmetric.x448
    import cryptography.hazmat.primitives.asymmetric.x25519
    import cryptography.hazmat.primitives.serialization
except ImportError:
    pass


class PrivateKeyError(OpenSSLObjectError):
    pass


# From the object called `module`, only the following properties are used:
#
#  - module.params[]
#  - module.warn(msg: str)
#  - module.fail_json(msg: str, **kwargs)


class _Curve:
    def __init__(
        self,
        *,
        name: str,
        ectype: str,
        deprecated: bool,
    ) -> None:
        self.name = name
        self.ectype = ectype
        self.deprecated = deprecated

    def _get_ec_class(
        self, *, module: GeneralAnsibleModule
    ) -> type[cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve]:
        ecclass: (
            type[cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve] | None
        ) = cryptography.hazmat.primitives.asymmetric.ec.__dict__.get(self.ectype)
        if ecclass is None:
            module.fail_json(
                msg=f"Your cryptography version does not support {self.ectype}"
            )
        return ecclass

    def create(
        self, *, size: int, module: GeneralAnsibleModule
    ) -> cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve:
        ecclass = self._get_ec_class(module=module)
        return ecclass()

    def verify(
        self,
        *,
        privatekey: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey,
        module: GeneralAnsibleModule,
    ) -> bool:
        ecclass = self._get_ec_class(module=module)
        return isinstance(privatekey.private_numbers().public_numbers.curve, ecclass)


class PrivateKeyBackend:
    def _add_curve(
        self,
        name: str,
        ectype: str,
        *,
        deprecated: bool = False,
    ) -> None:
        self.curves[name] = _Curve(name=name, ectype=ectype, deprecated=deprecated)

    def __init__(self, *, module: GeneralAnsibleModule) -> None:
        self.module = module
        self.type: t.Literal[
            "DSA", "ECC", "Ed25519", "Ed448", "RSA", "X25519", "X448"
        ] = module.params["type"]
        self.size: int = module.params["size"]
        self.curve: str | None = module.params["curve"]
        self.passphrase: str | None = module.params["passphrase"]
        self.cipher: str = module.params["cipher"]
        self.format: t.Literal["pkcs1", "pkcs8", "raw", "auto", "auto_ignore"] = (
            module.params["format"]
        )
        self.format_mismatch: t.Literal["regenerate", "convert"] = module.params.get(
            "format_mismatch", "regenerate"
        )
        self.regenerate: t.Literal[
            "never", "fail", "partial_idempotence", "full_idempotence", "always"
        ] = module.params.get("regenerate", "full_idempotence")

        self.private_key: PrivateKeyTypes | None = None

        self.existing_private_key: PrivateKeyTypes | None = None
        self.existing_private_key_bytes: bytes | None = None

        self.diff_before = self._get_info(data=None)
        self.diff_after = self._get_info(data=None)

        self.curves: dict[str, _Curve] = {}
        self._add_curve("secp224r1", "SECP224R1")
        self._add_curve("secp256k1", "SECP256K1")
        self._add_curve("secp256r1", "SECP256R1")
        self._add_curve("secp384r1", "SECP384R1")
        self._add_curve("secp521r1", "SECP521R1")
        self._add_curve("secp192r1", "SECP192R1", deprecated=True)
        self._add_curve("sect163k1", "SECT163K1", deprecated=True)
        self._add_curve("sect163r2", "SECT163R2", deprecated=True)
        self._add_curve("sect233k1", "SECT233K1", deprecated=True)
        self._add_curve("sect233r1", "SECT233R1", deprecated=True)
        self._add_curve("sect283k1", "SECT283K1", deprecated=True)
        self._add_curve("sect283r1", "SECT283R1", deprecated=True)
        self._add_curve("sect409k1", "SECT409K1", deprecated=True)
        self._add_curve("sect409r1", "SECT409R1", deprecated=True)
        self._add_curve("sect571k1", "SECT571K1", deprecated=True)
        self._add_curve("sect571r1", "SECT571R1", deprecated=True)
        self._add_curve("brainpoolP256r1", "BrainpoolP256R1", deprecated=True)
        self._add_curve("brainpoolP384r1", "BrainpoolP384R1", deprecated=True)
        self._add_curve("brainpoolP512r1", "BrainpoolP512R1", deprecated=True)

    def _get_info(self, *, data: bytes | None) -> dict[str, t.Any]:
        if data is None:
            return {}
        result: dict[str, t.Any] = {"can_parse_key": False}
        try:
            result.update(
                get_privatekey_info(
                    module=self.module,
                    content=data,
                    passphrase=self.passphrase,
                    return_private_key_data=False,
                    prefer_one_fingerprint=True,
                )
            )
        except PrivateKeyConsistencyError as exc:
            result.update(exc.result)
        except PrivateKeyParseError as exc:
            result.update(exc.result)
        except Exception:
            pass
        return result

    def _get_wanted_format(self) -> t.Literal["pkcs1", "pkcs8", "raw"]:
        if self.format not in ("auto", "auto_ignore"):
            return self.format  # type: ignore
        if self.type in ("X25519", "X448", "Ed25519", "Ed448"):
            return "pkcs8"
        return "pkcs1"

    def generate_private_key(self) -> None:
        """(Re-)Generate private key."""
        try:
            if self.type == "RSA":
                self.private_key = (
                    cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
                        public_exponent=65537,  # OpenSSL always uses this
                        key_size=self.size,
                    )
                )
            if self.type == "DSA":
                self.private_key = (
                    cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key(
                        key_size=self.size
                    )
                )
            if self.type == "X25519":
                self.private_key = (
                    cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate()
                )
            if self.type == "X448":
                self.private_key = (
                    cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey.generate()
                )
            if self.type == "Ed25519":
                self.private_key = (
                    cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate()
                )
            if self.type == "Ed448":
                self.private_key = (
                    cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.generate()
                )
            if self.type == "ECC" and self.curve in self.curves:
                if self.curves[self.curve].deprecated:
                    self.module.warn(
                        f"Elliptic curves of type {self.curve} should not be used for new keys!"
                    )
                self.private_key = (
                    cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
                        curve=self.curves[self.curve].create(
                            size=self.size, module=self.module
                        ),
                    )
                )
        except cryptography.exceptions.UnsupportedAlgorithm:
            self.module.fail_json(
                msg=f"Cryptography backend does not support the algorithm required for {self.type}"
            )

    def convert_private_key(self) -> None:
        """Convert existing private key (self.existing_private_key) to new private key (self.private_key).

        This is effectively a copy without active conversion. The conversion is done
        during load and store; get_private_key_data() uses the destination format to
        serialize the key.
        """
        self._ensure_existing_private_key_loaded()
        self.private_key = self.existing_private_key

    def get_private_key_data(self) -> bytes:
        """Return bytes for self.private_key"""
        if self.private_key is None:
            raise AssertionError("private_key not set")  # pragma: no cover
        # Select export format and encoding
        try:
            export_format_txt = self._get_wanted_format()
            export_encoding = cryptography.hazmat.primitives.serialization.Encoding.PEM
            if export_format_txt == "pkcs1":
                # "TraditionalOpenSSL" format is PKCS1
                export_format = (
                    cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL
                )
            elif export_format_txt == "pkcs8":
                export_format = (
                    cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8
                )
            elif export_format_txt == "raw":
                export_format = (
                    cryptography.hazmat.primitives.serialization.PrivateFormat.Raw
                )
                export_encoding = (
                    cryptography.hazmat.primitives.serialization.Encoding.Raw
                )
            else:
                # pylint does not notice that all possible values for export_format_txt have been covered.
                raise AssertionError("Can never be reached")  # pragma: no cover
        except AttributeError:
            self.module.fail_json(
                msg=f'Cryptography backend does not support the selected output format "{self.format}"'
            )

        # Select key encryption
        encryption_algorithm: (
            cryptography.hazmat.primitives.serialization.KeySerializationEncryption
        ) = cryptography.hazmat.primitives.serialization.NoEncryption()
        if self.cipher and self.passphrase:
            if self.cipher == "auto":
                encryption_algorithm = cryptography.hazmat.primitives.serialization.BestAvailableEncryption(
                    to_bytes(self.passphrase)
                )
            else:
                self.module.fail_json(
                    msg='Cryptography backend can only use "auto" for cipher option.'
                )

        # Serialize key
        try:
            return self.private_key.private_bytes(
                encoding=export_encoding,
                format=export_format,
                encryption_algorithm=encryption_algorithm,
            )
        except ValueError:
            self.module.fail_json(
                msg=f'Cryptography backend cannot serialize the private key in the required format "{self.format}"'
            )
        except Exception:
            self.module.fail_json(
                msg=f'Error while serializing the private key in the required format "{self.format}"',
                exception=traceback.format_exc(),
            )

    def set_existing(self, *, privatekey_bytes: bytes | None) -> None:
        """Set existing private key bytes. None indicates that the key does not exist."""
        self.existing_private_key_bytes = privatekey_bytes
        self.diff_after = self.diff_before = self._get_info(
            data=self.existing_private_key_bytes
        )

    def has_existing(self) -> bool:
        """Query whether an existing private key is/has been there."""
        return self.existing_private_key_bytes is not None

    def _load_privatekey(self) -> PrivateKeyTypes:
        data = self.existing_private_key_bytes
        if data is None:
            raise AssertionError(
                "existing_private_key_bytes not set"
            )  # pragma: no cover
        try:
            # Interpret bytes depending on format.
            key_format = identify_private_key_format(data)
            if key_format == "raw":
                if len(data) == 56:
                    return cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey.from_private_bytes(
                        data
                    )
                if len(data) == 57:
                    return cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.from_private_bytes(
                        data
                    )
                if len(data) == 32:
                    if self.type == "X25519":
                        return cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.from_private_bytes(
                            data
                        )
                    if self.type == "Ed25519":
                        return cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(
                            data
                        )
                    try:
                        return cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.from_private_bytes(
                            data
                        )
                    except Exception:
                        return cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(
                            data
                        )
                raise PrivateKeyError("Cannot load raw key")

            return cryptography.hazmat.primitives.serialization.load_pem_private_key(
                data,
                None if self.passphrase is None else to_bytes(self.passphrase),
            )
        except Exception as e:
            raise PrivateKeyError(e) from e

    def _ensure_existing_private_key_loaded(self) -> None:
        """Make sure that self.existing_private_key is populated from self.existing_private_key_bytes."""
        if self.existing_private_key is None and self.has_existing():
            self.existing_private_key = self._load_privatekey()

    def _check_passphrase(self) -> bool:
        """Check whether provided passphrase matches, assuming self.existing_private_key_bytes has been populated."""
        if self.existing_private_key_bytes is None:
            raise AssertionError(
                "existing_private_key_bytes not set"
            )  # pragma: no cover
        try:
            key_format = identify_private_key_format(self.existing_private_key_bytes)
            if key_format == "raw":
                # Raw keys cannot be encrypted. To avoid incompatibilities, we try to
                # actually load the key (and return False when this fails).
                self._load_privatekey()
                # Loading the key succeeded. Only return True when no passphrase was
                # provided.
                return self.passphrase is None
            return bool(
                cryptography.hazmat.primitives.serialization.load_pem_private_key(
                    self.existing_private_key_bytes,
                    None if self.passphrase is None else to_bytes(self.passphrase),
                )
            )
        except Exception:
            return False

    def _check_size_and_type(self) -> bool:
        """Check whether provided size and type matches, assuming self.existing_private_key has been populated."""
        if isinstance(
            self.existing_private_key,
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey,
        ):
            return (
                self.type == "RSA" and self.size == self.existing_private_key.key_size
            )
        if isinstance(
            self.existing_private_key,
            cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey,
        ):
            return (
                self.type == "DSA" and self.size == self.existing_private_key.key_size
            )
        if isinstance(
            self.existing_private_key,
            cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey,
        ):
            return self.type == "X25519"
        if isinstance(
            self.existing_private_key,
            cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey,
        ):
            return self.type == "X448"
        if isinstance(
            self.existing_private_key,
            cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey,
        ):
            return self.type == "Ed25519"
        if isinstance(
            self.existing_private_key,
            cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey,
        ):
            return self.type == "Ed448"
        if isinstance(
            self.existing_private_key,
            cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey,
        ):
            if self.type != "ECC":
                return False
            if self.curve not in self.curves:
                return False
            return self.curves[self.curve].verify(
                privatekey=self.existing_private_key, module=self.module
            )

        return False

    def _check_format(self) -> bool:
        """Check whether the key file format, assuming self.existing_private_key and self.existing_private_key_bytes has been populated."""
        if self.existing_private_key_bytes is None:
            raise AssertionError(
                "existing_private_key_bytes not set"
            )  # pragma: no cover
        if self.format == "auto_ignore":
            return True
        try:
            key_format = identify_private_key_format(self.existing_private_key_bytes)
            return key_format == self._get_wanted_format()
        except Exception:
            return False

    def needs_regeneration(self) -> bool:
        """Check whether a regeneration is necessary."""
        if self.regenerate == "always":
            return True
        if not self.has_existing():
            # key does not exist
            return True
        if not self._check_passphrase():
            if self.regenerate == "full_idempotence":
                return True
            self.module.fail_json(
                msg="Unable to read the key. The key is protected with a another passphrase / no passphrase or broken."
                " Will not proceed. To force regeneration, call the module with `generate`"
                " set to `full_idempotence` or `always`, or with `force=true`."
            )
        self._ensure_existing_private_key_loaded()
        if self.regenerate != "never" and not self._check_size_and_type():
            if self.regenerate in ("partial_idempotence", "full_idempotence"):
                return True
            self.module.fail_json(
                msg="Key has wrong type and/or size."
                " Will not proceed. To force regeneration, call the module with `generate`"
                " set to `partial_idempotence`, `full_idempotence` or `always`, or with `force=true`."
            )
        # During generation step, regenerate if format does not match and format_mismatch == 'regenerate'
        if (
            self.format_mismatch == "regenerate"
            and self.regenerate != "never"
            and not self._check_format()
        ):
            if self.regenerate in ("partial_idempotence", "full_idempotence"):
                return True
            self.module.fail_json(
                msg="Key has wrong format."
                " Will not proceed. To force regeneration, call the module with `generate`"
                " set to `partial_idempotence`, `full_idempotence` or `always`, or with `force=true`."
                " To convert the key, set `format_mismatch` to `convert`."
            )
        return False

    def needs_conversion(self) -> bool:
        """Check whether a conversion is necessary. Must only be called if needs_regeneration() returned False."""
        # During conversion step, convert if format does not match and format_mismatch == 'convert'
        self._ensure_existing_private_key_loaded()
        return (
            self.has_existing()
            and self.format_mismatch == "convert"
            and not self._check_format()
        )

    def _get_fingerprint(self) -> dict[str, str] | None:
        if self.private_key:
            return get_fingerprint_of_privatekey(self.private_key)
        try:
            self._ensure_existing_private_key_loaded()
        except Exception:
            # Ignore errors
            pass
        if self.existing_private_key:
            return get_fingerprint_of_privatekey(self.existing_private_key)
        return None

    def dump(self, *, include_key: bool) -> dict[str, t.Any]:
        """Serialize the object into a dictionary."""

        if not self.private_key:
            try:
                self._ensure_existing_private_key_loaded()
            except Exception:
                # Ignore errors
                pass
        result: dict[str, t.Any] = {
            "type": self.type,
            "size": self.size,
            "fingerprint": self._get_fingerprint(),
        }
        if self.type == "ECC":
            result["curve"] = self.curve
        # Get hold of private key bytes
        pk_bytes = self.existing_private_key_bytes
        if self.private_key is not None:
            pk_bytes = self.get_private_key_data()
        self.diff_after = self._get_info(data=pk_bytes)
        if include_key:
            # Store result
            if pk_bytes:
                if identify_private_key_format(pk_bytes) == "raw":
                    result["privatekey"] = base64.b64encode(pk_bytes)
                else:
                    result["privatekey"] = pk_bytes.decode("utf-8")
            else:
                result["privatekey"] = None

        result["diff"] = {
            "before": self.diff_before,
            "after": self.diff_after,
        }
        return result


def select_backend(module: GeneralAnsibleModule) -> PrivateKeyBackend:
    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )
    return PrivateKeyBackend(module=module)


def get_privatekey_argument_spec() -> ArgumentSpec:
    return ArgumentSpec(
        argument_spec={
            "size": {"type": "int", "default": 4096},
            "type": {
                "type": "str",
                "default": "RSA",
                "choices": ["DSA", "ECC", "Ed25519", "Ed448", "RSA", "X25519", "X448"],
            },
            "curve": {
                "type": "str",
                "choices": [
                    "secp224r1",
                    "secp256k1",
                    "secp256r1",
                    "secp384r1",
                    "secp521r1",
                    "secp192r1",
                    "brainpoolP256r1",
                    "brainpoolP384r1",
                    "brainpoolP512r1",
                    "sect163k1",
                    "sect163r2",
                    "sect233k1",
                    "sect233r1",
                    "sect283k1",
                    "sect283r1",
                    "sect409k1",
                    "sect409r1",
                    "sect571k1",
                    "sect571r1",
                ],
            },
            "passphrase": {"type": "str", "no_log": True},
            "cipher": {"type": "str", "default": "auto"},
            "format": {
                "type": "str",
                "default": "auto_ignore",
                "choices": ["pkcs1", "pkcs8", "raw", "auto", "auto_ignore"],
            },
            "format_mismatch": {
                "type": "str",
                "default": "regenerate",
                "choices": ["regenerate", "convert"],
            },
            "select_crypto_backend": {
                "type": "str",
                "choices": ["auto", "cryptography"],
                "default": "auto",
            },
            "regenerate": {
                "type": "str",
                "default": "full_idempotence",
                "choices": [
                    "never",
                    "fail",
                    "partial_idempotence",
                    "full_idempotence",
                    "always",
                ],
            },
        },
        required_if=[
            ("type", "ECC", ["curve"]),
        ],
    )


__all__ = (
    "PrivateKeyError",
    "PrivateKeyBackend",
    "select_backend",
    "get_privatekey_argument_spec",
)
