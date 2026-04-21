# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import traceback
import typing as t

from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.community.crypto.plugins.module_utils._argspec import (
    ArgumentSpec,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    cryptography_compare_private_keys,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.pem import (
    identify_private_key_format,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)
from ansible_collections.community.crypto.plugins.module_utils._io import load_file


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.types import (  # pragma: no cover
        PrivateKeyTypes,
    )


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


class PrivateKeyConvertBackend:
    def __init__(self, *, module: AnsibleModule) -> None:
        self.module = module
        self.src_path: str | None = module.params["src_path"]
        self.src_content: str | None = module.params["src_content"]
        self.src_passphrase: str | None = module.params["src_passphrase"]
        self.format: t.Literal["pkcs1", "pkcs8", "raw"] = module.params["format"]
        self.dest_passphrase: str | None = module.params["dest_passphrase"]

        self.src_private_key: PrivateKeyTypes | None = None
        if self.src_path is not None:
            self.src_private_key_bytes = load_file(path=self.src_path, module=module)
        else:
            if self.src_content is None:
                raise AssertionError("src_content is None")  # pragma: no cover
            self.src_private_key_bytes = self.src_content.encode("utf-8")

        self.dest_private_key: PrivateKeyTypes | None = None
        self.dest_private_key_bytes: bytes | None = None

    def get_private_key_data(self) -> bytes:
        """Return bytes for self.src_private_key in output format"""
        if self.src_private_key is None:
            raise AssertionError("src_private_key not set")  # pragma: no cover
        # Select export format and encoding
        try:
            export_encoding = cryptography.hazmat.primitives.serialization.Encoding.PEM
            if self.format == "pkcs1":
                # "TraditionalOpenSSL" format is PKCS1
                export_format = (
                    cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL
                )
            elif self.format == "pkcs8":
                export_format = (
                    cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8
                )
            elif self.format == "raw":
                export_format = (
                    cryptography.hazmat.primitives.serialization.PrivateFormat.Raw
                )
                export_encoding = (
                    cryptography.hazmat.primitives.serialization.Encoding.Raw
                )
            else:
                # pylint does not notice that all possible values for self.format have been covered.
                raise AssertionError("Can never be reached")  # pragma: no cover
        except AttributeError:
            self.module.fail_json(
                msg=f'Cryptography backend does not support the selected output format "{self.format}"'
            )

        # Select key encryption
        encryption_algorithm: (
            cryptography.hazmat.primitives.serialization.KeySerializationEncryption
        ) = cryptography.hazmat.primitives.serialization.NoEncryption()
        if self.dest_passphrase:
            encryption_algorithm = (
                cryptography.hazmat.primitives.serialization.BestAvailableEncryption(
                    to_bytes(self.dest_passphrase)
                )
            )

        # Serialize key
        try:
            return self.src_private_key.private_bytes(
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

    def set_existing_destination(self, *, privatekey_bytes: bytes | None) -> None:
        """Set existing private key bytes. None indicates that the key does not exist."""
        self.dest_private_key_bytes = privatekey_bytes

    def has_existing_destination(self) -> bool:
        """Query whether an existing private key is/has been there."""
        return self.dest_private_key_bytes is not None

    def _load_private_key(
        self,
        *,
        data: bytes,
        passphrase: str | None,
        current_hint: PrivateKeyTypes | None = None,
    ) -> tuple[str, PrivateKeyTypes]:
        """Check whether data can be loaded as a private key with the provided passphrase. Return tuple (type, private_key)."""
        try:
            # Interpret bytes depending on format.
            key_format = identify_private_key_format(data)
            if key_format == "raw":
                if passphrase is not None:
                    raise PrivateKeyError("Cannot load raw key with passphrase")
                if len(data) == 56:
                    return (
                        key_format,
                        cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey.from_private_bytes(
                            data
                        ),
                    )
                if len(data) == 57:
                    return (
                        key_format,
                        cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.from_private_bytes(
                            data
                        ),
                    )
                if len(data) == 32:
                    if isinstance(
                        current_hint,
                        cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey,
                    ):
                        try:
                            return (
                                key_format,
                                cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.from_private_bytes(
                                    data
                                ),
                            )
                        except Exception:
                            return (
                                key_format,
                                cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(
                                    data
                                ),
                            )
                    else:
                        try:
                            return (
                                key_format,
                                cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(
                                    data
                                ),
                            )
                        except Exception:
                            return (
                                key_format,
                                cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.from_private_bytes(
                                    data
                                ),
                            )
                raise PrivateKeyError("Cannot load raw key")

            return (
                key_format,
                cryptography.hazmat.primitives.serialization.load_pem_private_key(
                    data,
                    None if passphrase is None else to_bytes(passphrase),
                ),
            )
        except Exception as e:
            raise PrivateKeyError(e) from e

    def needs_conversion(self) -> bool:
        """Check whether a conversion is necessary. Must only be called if needs_regeneration() returned False."""
        dummy, self.src_private_key = self._load_private_key(
            data=self.src_private_key_bytes, passphrase=self.src_passphrase
        )

        if not self.has_existing_destination():
            return True
        assert self.dest_private_key_bytes is not None

        try:
            key_format, self.dest_private_key = self._load_private_key(
                data=self.dest_private_key_bytes,
                passphrase=self.dest_passphrase,
                current_hint=self.src_private_key,
            )
        except Exception:
            return True

        return key_format != self.format or not cryptography_compare_private_keys(
            self.dest_private_key, self.src_private_key
        )

    def dump(self) -> dict[str, t.Any]:
        """Serialize the object into a dictionary."""
        return {}


def select_backend(module: AnsibleModule) -> PrivateKeyConvertBackend:
    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )
    return PrivateKeyConvertBackend(module=module)


def get_privatekey_argument_spec() -> ArgumentSpec:
    return ArgumentSpec(
        argument_spec={
            "src_path": {"type": "path"},
            "src_content": {"type": "str"},
            "src_passphrase": {"type": "str", "no_log": True},
            "dest_passphrase": {"type": "str", "no_log": True},
            "format": {
                "type": "str",
                "required": True,
                "choices": ["pkcs1", "pkcs8", "raw"],
            },
        },
        mutually_exclusive=[
            ["src_path", "src_content"],
        ],
        required_one_of=[
            ["src_path", "src_content"],
        ],
    )


__all__ = (
    "PrivateKeyError",
    "PrivateKeyConvertBackend",
    "select_backend",
    "get_privatekey_argument_spec",
)
