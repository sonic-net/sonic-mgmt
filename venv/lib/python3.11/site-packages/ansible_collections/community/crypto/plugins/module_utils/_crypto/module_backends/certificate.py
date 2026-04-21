# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import abc
import typing as t

from ansible_collections.community.crypto.plugins.module_utils._argspec import (
    ArgumentSpec,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLBadPassphraseError,
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    cryptography_compare_public_keys,
    get_not_valid_after,
    get_not_valid_before,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.certificate_info import (
    get_certificate_info,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    load_certificate,
    load_certificate_privatekey,
    load_certificate_request,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)


if t.TYPE_CHECKING:
    import datetime  # pragma: no cover

    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (  # pragma: no cover
        CertificatePrivateKeyTypes,
    )


MINIMAL_CRYPTOGRAPHY_VERSION = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION

try:
    import cryptography
    from cryptography import x509
except ImportError:
    pass


class CertificateError(OpenSSLObjectError):
    pass


class CertificateBackend(metaclass=abc.ABCMeta):
    def __init__(self, *, module: AnsibleModule) -> None:
        self.module = module

        self.force: bool = module.params["force"]
        self.ignore_timestamps: bool = module.params["ignore_timestamps"]
        self.privatekey_path: str | None = module.params["privatekey_path"]
        privatekey_content: str | None = module.params["privatekey_content"]
        if privatekey_content is not None:
            self.privatekey_content: bytes | None = privatekey_content.encode("utf-8")
        else:
            self.privatekey_content = None
        self.privatekey_passphrase: str | None = module.params["privatekey_passphrase"]
        self.csr_path: str | None = module.params["csr_path"]
        csr_content = module.params["csr_content"]
        if csr_content is not None:
            self.csr_content: bytes | None = csr_content.encode("utf-8")
        else:
            self.csr_content = None

        # The following are default values which make sure check() works as
        # before if providers do not explicitly change these properties.
        self.create_subject_key_identifier: str = "never_create"
        self.create_authority_key_identifier: bool = False

        self.privatekey: CertificatePrivateKeyTypes | None = None
        self.csr: x509.CertificateSigningRequest | None = None
        self.cert: x509.Certificate | None = None
        self.existing_certificate: x509.Certificate | None = None
        self.existing_certificate_bytes: bytes | None = None

        self.check_csr_subject: bool = True
        self.check_csr_extensions: bool = True

        self.diff_before = self._get_info(None)
        self.diff_after = self._get_info(None)

    def _get_info(self, data: bytes | None) -> dict[str, t.Any]:
        if data is None:
            return {}
        try:
            result = get_certificate_info(
                module=self.module, content=data, prefer_one_fingerprint=True
            )
            result["can_parse_certificate"] = True
            return result
        except Exception:
            return {"can_parse_certificate": False}

    @abc.abstractmethod
    def generate_certificate(self) -> None:
        """(Re-)Generate certificate."""

    @abc.abstractmethod
    def get_certificate_data(self) -> bytes:
        """Return bytes for self.cert."""

    def set_existing(self, certificate_bytes: bytes | None) -> None:
        """Set existing certificate bytes. None indicates that the key does not exist."""
        self.existing_certificate_bytes = certificate_bytes
        self.diff_after = self.diff_before = self._get_info(
            self.existing_certificate_bytes
        )

    def has_existing(self) -> bool:
        """Query whether an existing certificate is/has been there."""
        return self.existing_certificate_bytes is not None

    def _ensure_private_key_loaded(self) -> None:
        """Load the provided private key into self.privatekey."""
        if self.privatekey is not None:
            return
        if self.privatekey_path is None and self.privatekey_content is None:
            return
        try:
            self.privatekey = load_certificate_privatekey(
                path=self.privatekey_path,
                content=self.privatekey_content,
                passphrase=self.privatekey_passphrase,
            )
        except OpenSSLBadPassphraseError as exc:
            raise CertificateError(exc) from exc

    def _ensure_csr_loaded(self) -> None:
        """Load the CSR into self.csr."""
        if self.csr is not None:
            return
        if self.csr_path is None and self.csr_content is None:
            return
        self.csr = load_certificate_request(
            path=self.csr_path,
            content=self.csr_content,
        )

    def _ensure_existing_certificate_loaded(self) -> None:
        """Load the existing certificate into self.existing_certificate."""
        if self.existing_certificate is not None:
            return
        if self.existing_certificate_bytes is None:
            return
        self.existing_certificate = load_certificate(
            path=None,
            content=self.existing_certificate_bytes,
        )

    def _check_privatekey(self) -> bool:
        """Check whether provided parameters match, assuming self.existing_certificate and self.privatekey have been populated."""
        if self.existing_certificate is None:
            raise AssertionError(  # pragma: no cover
                "Contract violation: existing_certificate has not been populated"
            )
        if self.privatekey is None:
            raise AssertionError(  # pragma: no cover
                "Contract violation: privatekey has not been populated"
            )
        return cryptography_compare_public_keys(
            self.existing_certificate.public_key(), self.privatekey.public_key()
        )

    def _check_csr(self) -> bool:
        """Check whether provided parameters match, assuming self.existing_certificate and self.csr have been populated."""
        if self.existing_certificate is None:
            raise AssertionError(  # pragma: no cover
                "Contract violation: existing_certificate has not been populated"
            )
        if self.csr is None:
            raise AssertionError(
                "Contract violation: csr has not been populated"
            )  # pragma: no cover
        # Verify that CSR is signed by certificate's private key
        if not self.csr.is_signature_valid:
            return False
        if not cryptography_compare_public_keys(
            self.csr.public_key(), self.existing_certificate.public_key()
        ):
            return False
        # Check subject
        if (
            self.check_csr_subject
            and self.csr.subject != self.existing_certificate.subject
        ):
            return False
        # Check extensions
        if not self.check_csr_extensions:
            return True
        cert_exts = list(self.existing_certificate.extensions)
        csr_exts = list(self.csr.extensions)
        if self.create_subject_key_identifier != "never_create":
            # Filter out SubjectKeyIdentifier extension before comparison
            cert_exts = list(
                filter(
                    lambda x: not isinstance(x.value, x509.SubjectKeyIdentifier),
                    cert_exts,
                )
            )
            csr_exts = list(
                filter(
                    lambda x: not isinstance(x.value, x509.SubjectKeyIdentifier),
                    csr_exts,
                )
            )
        if self.create_authority_key_identifier:
            # Filter out AuthorityKeyIdentifier extension before comparison
            cert_exts = list(
                filter(
                    lambda x: not isinstance(x.value, x509.AuthorityKeyIdentifier),
                    cert_exts,
                )
            )
            csr_exts = list(
                filter(
                    lambda x: not isinstance(x.value, x509.AuthorityKeyIdentifier),
                    csr_exts,
                )
            )
        if len(cert_exts) != len(csr_exts):
            return False
        for cert_ext in cert_exts:
            try:
                csr_ext = self.csr.extensions.get_extension_for_oid(cert_ext.oid)
                if cert_ext != csr_ext:
                    return False
            except cryptography.x509.ExtensionNotFound:
                return False
        return True

    def _check_subject_key_identifier(self) -> bool:
        """Check whether Subject Key Identifier matches, assuming self.existing_certificate and self.csr have been populated."""
        if self.existing_certificate is None:
            raise AssertionError(  # pragma: no cover
                "Contract violation: existing_certificate has not been populated"
            )
        if self.csr is None:
            raise AssertionError(
                "Contract violation: csr has not been populated"
            )  # pragma: no cover
        # Get hold of certificate's SKI
        try:
            ext = self.existing_certificate.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            )
        except cryptography.x509.ExtensionNotFound:
            return False
        # Get hold of CSR's SKI for 'create_if_not_provided'
        csr_ext = None
        if self.create_subject_key_identifier == "create_if_not_provided":
            try:
                csr_ext = self.csr.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                )
            except cryptography.x509.ExtensionNotFound:
                pass
        if csr_ext is None:
            # If CSR had no SKI, or we chose to ignore it ('always_create'), compare with created SKI
            if (
                ext.value.digest
                != x509.SubjectKeyIdentifier.from_public_key(
                    self.existing_certificate.public_key()
                ).digest
            ):
                return False
        else:
            # If CSR had SKI and we did not ignore it ('create_if_not_provided'), compare SKIs
            if ext.value.digest != csr_ext.value.digest:
                return False
        return True

    def needs_regeneration(
        self,
        *,
        not_before: datetime.datetime | None = None,
        not_after: datetime.datetime | None = None,
    ) -> bool:
        """Check whether a regeneration is necessary."""
        if self.force or self.existing_certificate_bytes is None:
            return True

        try:
            self._ensure_existing_certificate_loaded()
        except Exception:
            return True
        assert self.existing_certificate is not None

        # Check whether private key matches
        self._ensure_private_key_loaded()
        if self.privatekey is not None and not self._check_privatekey():
            return True

        # Check whether CSR matches
        self._ensure_csr_loaded()
        if self.csr is not None and not self._check_csr():
            return True

        # Check SubjectKeyIdentifier
        if (
            self.create_subject_key_identifier != "never_create"
            and not self._check_subject_key_identifier()
        ):
            return True

        # Check not before
        if (
            not_before is not None
            and not self.ignore_timestamps
            and get_not_valid_before(self.existing_certificate) != not_before
        ):
            return True

        # Check not after
        return bool(
            not_after is not None
            and not self.ignore_timestamps
            and get_not_valid_after(self.existing_certificate) != not_after
        )

    def dump(self, *, include_certificate: bool) -> dict[str, t.Any]:
        """Serialize the object into a dictionary."""
        result: dict[str, t.Any] = {
            "privatekey": self.privatekey_path,
            "csr": self.csr_path,
        }
        # Get hold of certificate bytes
        certificate_bytes = self.existing_certificate_bytes
        if self.cert is not None:
            certificate_bytes = self.get_certificate_data()
        self.diff_after = self._get_info(certificate_bytes)
        if include_certificate:
            # Store result
            result["certificate"] = (
                certificate_bytes.decode("utf-8") if certificate_bytes else None
            )

        result["diff"] = {
            "before": self.diff_before,
            "after": self.diff_after,
        }
        return result


class CertificateProvider(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def validate_module_args(self, module: AnsibleModule) -> None:
        """Check module arguments"""

    @abc.abstractmethod
    def create_backend(self, module: AnsibleModule) -> CertificateBackend:
        """Create an implementation for a backend.

        Return value must be instance of CertificateBackend.
        """


def select_backend(
    *, module: AnsibleModule, provider: CertificateProvider
) -> CertificateBackend:
    provider.validate_module_args(module)

    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )

    return provider.create_backend(module)


def get_certificate_argument_spec() -> ArgumentSpec:
    return ArgumentSpec(
        argument_spec={
            "provider": {
                "type": "str",
                "choices": [],
            },  # choices will be filled by add_XXX_provider_to_argument_spec() in certificate_xxx.py
            "force": {
                "type": "bool",
                "default": False,
            },
            "csr_path": {"type": "path"},
            "csr_content": {"type": "str"},
            "ignore_timestamps": {"type": "bool", "default": True},
            "select_crypto_backend": {
                "type": "str",
                "default": "auto",
                "choices": ["auto", "cryptography"],
            },
            # General properties of a certificate
            "privatekey_path": {"type": "path"},
            "privatekey_content": {"type": "str", "no_log": True},
            "privatekey_passphrase": {"type": "str", "no_log": True},
        },
        mutually_exclusive=[
            ["csr_path", "csr_content"],
            ["privatekey_path", "privatekey_content"],
        ],
    )


__all__ = (
    "CertificateError",
    "CertificateBackend",
    "CertificateProvider",
    "get_certificate_argument_spec",
)
