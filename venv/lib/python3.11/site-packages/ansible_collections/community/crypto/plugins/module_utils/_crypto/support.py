# Copyright (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import abc
import errno
import hashlib
import os
import typing as t

from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    is_potential_certificate_issuer_private_key,
    is_potential_certificate_private_key,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.pem import (
    identify_pem_format,
)


try:
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
except ImportError:
    # Error handled in the calling module.
    pass

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLBadPassphraseError,
    OpenSSLObjectError,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.types import (  # pragma: no cover
        CertificateIssuerPrivateKeyTypes,
        PrivateKeyTypes,
        PublicKeyTypes,
    )

    from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (  # pragma: no cover
        CertificatePrivateKeyTypes,
    )


# This list of preferred fingerprints is used when prefer_one=True is supplied to the
# fingerprinting methods.
PREFERRED_FINGERPRINTS = (
    "sha256",
    "sha3_256",
    "sha512",
    "sha3_512",
    "sha384",
    "sha3_384",
    "sha1",
    "md5",
)


def get_fingerprint_of_bytes(
    source: bytes, *, prefer_one: bool = False
) -> dict[str, str]:
    """Generate the fingerprint of the given bytes."""

    fingerprint = {}

    algorithms: t.Iterable[str] = hashlib.algorithms_guaranteed

    if prefer_one:
        # Sort algorithms to have the ones in PREFERRED_FINGERPRINTS at the beginning
        prefered_algorithms = [
            algorithm for algorithm in PREFERRED_FINGERPRINTS if algorithm in algorithms
        ]
        prefered_algorithms += sorted(
            [
                algorithm
                for algorithm in algorithms
                if algorithm not in PREFERRED_FINGERPRINTS
            ]
        )
        algorithms = prefered_algorithms

    for algo in algorithms:
        f = getattr(hashlib, algo)
        try:
            h = f(source)
        except ValueError:
            # This can happen for hash algorithms not supported in FIPS mode
            # (https://github.com/ansible/ansible/issues/67213)
            continue
        try:
            # Certain hash functions have a hexdigest() which expects a length parameter
            pubkey_digest = h.hexdigest()
        except TypeError:
            pubkey_digest = h.hexdigest(32)
        fingerprint[algo] = ":".join(
            pubkey_digest[i : i + 2] for i in range(0, len(pubkey_digest), 2)
        )
        if prefer_one:
            break

    return fingerprint


def get_fingerprint_of_privatekey(
    privatekey: PrivateKeyTypes, *, prefer_one: bool = False
) -> dict[str, str]:
    """Generate the fingerprint of the public key."""

    publickey = privatekey.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return get_fingerprint_of_bytes(publickey, prefer_one=prefer_one)


def get_fingerprint(
    *,
    path: os.PathLike | str | None = None,
    passphrase: str | bytes | None = None,
    content: bytes | None = None,
    prefer_one: bool = False,
) -> dict[str, str]:
    """Generate the fingerprint of the public key."""

    privatekey = load_privatekey(
        path=path,
        passphrase=passphrase,
        content=content,
        check_passphrase=False,
    )

    return get_fingerprint_of_privatekey(privatekey, prefer_one=prefer_one)


def load_privatekey(
    *,
    path: os.PathLike | str | None = None,
    passphrase: str | bytes | None = None,
    check_passphrase: bool = True,
    content: bytes | None = None,
) -> PrivateKeyTypes:
    """Load the specified OpenSSL private key.

    The content can also be specified via content; in that case,
    this function will not load the key from disk.
    """

    try:
        if content is None:
            if path is None:
                raise OpenSSLObjectError("Must provide either path or content")
            with open(path, "rb") as b_priv_key_fh:
                priv_key_detail = b_priv_key_fh.read()
        else:
            priv_key_detail = content
    except (IOError, OSError) as exc:
        raise OpenSSLObjectError(exc) from exc

    try:
        return load_pem_private_key(
            priv_key_detail,
            None if passphrase is None else to_bytes(passphrase),
        )
    except UnsupportedAlgorithm as exc:
        raise OpenSSLBadPassphraseError(f"Unsupported private key type: {exc}") from exc
    except TypeError as exc:
        raise OpenSSLBadPassphraseError(
            "Wrong or empty passphrase provided for private key"
        ) from exc
    except ValueError as exc:
        raise OpenSSLBadPassphraseError(
            f"Wrong passphrase provided for private key, or private key cannot be parsed: {exc}"
        ) from exc


def load_certificate_privatekey(
    *,
    path: os.PathLike | str | None = None,
    content: bytes | None = None,
    passphrase: str | bytes | None = None,
    check_passphrase: bool = True,
) -> CertificatePrivateKeyTypes:
    """
    Load the specified OpenSSL private key that can be used as a private key for certificates.
    """
    private_key = load_privatekey(
        path=path,
        passphrase=passphrase,
        check_passphrase=check_passphrase,
        content=content,
    )
    if not is_potential_certificate_private_key(private_key):
        raise OpenSSLObjectError(
            f"Key of type {type(private_key)} not supported for certificates"
        )
    return private_key


def load_certificate_issuer_privatekey(
    *,
    path: os.PathLike | str | None = None,
    content: bytes | None = None,
    passphrase: str | bytes | None = None,
    check_passphrase: bool = True,
) -> CertificateIssuerPrivateKeyTypes:
    """
    Load the specified OpenSSL private key that can be used for issuing certificates.
    """
    private_key = load_privatekey(
        path=path,
        passphrase=passphrase,
        check_passphrase=check_passphrase,
        content=content,
    )
    if not is_potential_certificate_issuer_private_key(private_key):
        raise OpenSSLObjectError(
            f"Key of type {type(private_key)} not supported for issuing certificates"
        )
    return private_key


def load_publickey(
    *, path: os.PathLike | str | None = None, content: bytes | None = None
) -> PublicKeyTypes:
    if content is None:
        if path is None:
            raise OpenSSLObjectError("Must provide either path or content")
        try:
            with open(path, "rb") as b_priv_key_fh:
                content = b_priv_key_fh.read()
        except (IOError, OSError) as exc:
            raise OpenSSLObjectError(exc) from exc

    try:
        return serialization.load_pem_public_key(content)
    except Exception as e:
        raise OpenSSLObjectError(f"Error while deserializing key: {e}") from e


def load_certificate(
    *,
    path: os.PathLike | str | None = None,
    content: bytes | None = None,
    der_support_enabled: bool = False,
) -> x509.Certificate:
    """Load the specified certificate."""

    try:
        if content is None:
            if path is None:
                raise OpenSSLObjectError("Must provide either path or content")
            with open(path, "rb") as cert_fh:
                cert_content = cert_fh.read()
        else:
            cert_content = content
    except (IOError, OSError) as exc:
        raise OpenSSLObjectError(exc) from exc
    if der_support_enabled is False or identify_pem_format(cert_content):
        try:
            return x509.load_pem_x509_certificate(cert_content)
        except ValueError as exc:
            raise OpenSSLObjectError(exc) from exc
    elif der_support_enabled:
        try:
            return x509.load_der_x509_certificate(cert_content)
        except ValueError as exc:
            raise OpenSSLObjectError(f"Cannot parse DER certificate: {exc}") from exc


def load_certificate_request(
    *, path: os.PathLike | str | None = None, content: bytes | None = None
) -> x509.CertificateSigningRequest:
    """Load the specified certificate signing request."""
    try:
        if content is None:
            if path is None:
                raise OpenSSLObjectError("Must provide either path or content")
            with open(path, "rb") as csr_fh:
                csr_content = csr_fh.read()
        else:
            csr_content = content
    except (IOError, OSError) as exc:
        raise OpenSSLObjectError(exc) from exc
    try:
        return x509.load_pem_x509_csr(csr_content)
    except ValueError as exc:
        raise OpenSSLObjectError(exc) from exc


@t.overload
def parse_name_field(
    input_dict: dict[str, list[str] | str],
    *,
    name_field_name: str | None = None,
) -> list[tuple[str, str]]: ...


@t.overload
def parse_name_field(
    input_dict: dict[str, list[str | bytes] | str | bytes],
    *,
    name_field_name: str | None = None,
) -> list[tuple[str, str | bytes]]: ...


def parse_name_field(
    input_dict: dict[str, t.Any],
    *,
    name_field_name: str | None = None,
) -> list:
    """Take a dict with key: value or key: list_of_values mappings and return a list of tuples"""

    def error_str(key: str) -> str:
        if name_field_name is None:
            return f"{key}"
        return f"{key} in {name_field_name}"

    result = []
    for key, value in input_dict.items():
        if isinstance(value, list):
            for entry in value:
                if not isinstance(entry, (str, bytes)):
                    raise TypeError(f"Values {error_str(key)} must be strings")
                if not entry:
                    raise ValueError(
                        f"Values for {error_str(key)} must not be empty strings"
                    )
                result.append((key, entry))
        elif isinstance(value, (str, bytes)):
            if not value:
                raise ValueError(
                    f"Value for {error_str(key)} must not be an empty string"
                )
            result.append((key, value))
        else:
            raise TypeError(
                f"Value for {error_str(key)} must be either a string or a list of strings"
            )
    return result


@t.overload
def parse_ordered_name_field(
    input_list: list[dict[str, list[str] | str]],
    *,
    name_field_name: str,
) -> list[tuple[str, str]]: ...


@t.overload
def parse_ordered_name_field(
    input_list: list[dict[str, list[str | bytes] | str | bytes]],
    *,
    name_field_name: str,
) -> list[tuple[str, str | bytes]]: ...


def parse_ordered_name_field(
    input_list: list[dict[str, t.Any]],
    *,
    name_field_name: str,
) -> list:
    """Take a dict with key: value or key: list_of_values mappings and return a list of tuples"""

    result = []
    for index, entry in enumerate(input_list):
        if len(entry) != 1:
            raise ValueError(
                f"Entry #{index + 1} in {name_field_name} must be a dictionary with exactly one key-value pair"
            )
        try:
            result.extend(parse_name_field(entry, name_field_name=name_field_name))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Error while processing entry #{index + 1} in {name_field_name}: {exc}"
            ) from exc
    return result


@t.overload
def select_message_digest(
    digest_string: t.Literal["sha256", "sha384", "sha512", "sha1", "md5"],
) -> hashes.SHA256 | hashes.SHA384 | hashes.SHA512 | hashes.SHA1 | hashes.MD5: ...


@t.overload
def select_message_digest(
    digest_string: str,
) -> (
    hashes.SHA256 | hashes.SHA384 | hashes.SHA512 | hashes.SHA1 | hashes.MD5 | None
): ...


def select_message_digest(
    digest_string: str,
) -> hashes.SHA256 | hashes.SHA384 | hashes.SHA512 | hashes.SHA1 | hashes.MD5 | None:
    if digest_string == "sha256":
        return hashes.SHA256()
    if digest_string == "sha384":
        return hashes.SHA384()
    if digest_string == "sha512":
        return hashes.SHA512()
    if digest_string == "sha1":
        return hashes.SHA1()
    if digest_string == "md5":
        return hashes.MD5()
    return None


class OpenSSLObject(metaclass=abc.ABCMeta):
    def __init__(self, *, path: str, state: str, force: bool, check_mode: bool) -> None:
        self.path = path
        self.state = state
        self.force = force
        self.name = os.path.basename(path)
        self.changed = False
        self.check_mode = check_mode

    def check(self, module: AnsibleModule, *, perms_required: bool = True) -> bool:
        """Ensure the resource is in its desired state."""

        def _check_state() -> bool:
            return os.path.exists(self.path)

        def _check_perms(module: AnsibleModule) -> bool:
            file_args = module.load_file_common_arguments(module.params)
            if module.check_file_absent_if_check_mode(file_args["path"]):
                return False
            return not module.set_fs_attributes_if_different(file_args, False)

        if not perms_required:
            return _check_state()

        return _check_state() and _check_perms(module)

    @abc.abstractmethod
    def dump(self) -> dict[str, t.Any]:
        """Serialize the object into a dictionary."""

    @abc.abstractmethod
    def generate(self, module: AnsibleModule) -> None:
        """Generate the resource."""

    def remove(self, module: AnsibleModule) -> None:
        """Remove the resource from the filesystem."""
        if self.check_mode:
            if os.path.exists(self.path):
                self.changed = True
            return

        try:
            os.remove(self.path)
            self.changed = True
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise OpenSSLObjectError(exc) from exc


__all__ = (
    "get_fingerprint_of_bytes",
    "get_fingerprint_of_privatekey",
    "get_fingerprint",
    "load_privatekey",
    "load_certificate_privatekey",
    "load_certificate_issuer_privatekey",
    "load_publickey",
    "load_certificate",
    "load_certificate_request",
    "parse_name_field",
    "parse_ordered_name_field",
    "select_message_digest",
    "OpenSSLObject",
)
