# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import os
import typing as t
from random import randrange

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLBadPassphraseError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    CRYPTOGRAPHY_TIMEZONE,
    cryptography_compare_public_keys,
    cryptography_key_needs_digest_for_signing,
    cryptography_verify_certificate_signature,
    get_not_valid_after,
    get_not_valid_before,
    is_potential_certificate_issuer_public_key,
    set_not_valid_after,
    set_not_valid_before,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.certificate import (
    CertificateBackend,
    CertificateError,
    CertificateProvider,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    load_certificate,
    load_certificate_issuer_privatekey,
    select_message_digest,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    get_relative_time_option,
)


if t.TYPE_CHECKING:
    import datetime  # pragma: no cover

    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.module_utils._argspec import (  # pragma: no cover
        ArgumentSpec,
    )


try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
except ImportError:
    pass


class OwnCACertificateBackendCryptography(CertificateBackend):
    def __init__(self, *, module: AnsibleModule) -> None:
        super().__init__(module=module)

        self.create_subject_key_identifier: t.Literal[
            "create_if_not_provided", "always_create", "never_create"
        ] = module.params["ownca_create_subject_key_identifier"]
        self.create_authority_key_identifier: bool = module.params[
            "ownca_create_authority_key_identifier"
        ]
        self.not_before = get_relative_time_option(
            module.params["ownca_not_before"],
            input_name="ownca_not_before",
            with_timezone=CRYPTOGRAPHY_TIMEZONE,
        )
        self.not_after = get_relative_time_option(
            module.params["ownca_not_after"],
            input_name="ownca_not_after",
            with_timezone=CRYPTOGRAPHY_TIMEZONE,
        )
        self.digest = select_message_digest(module.params["ownca_digest"])
        self.serial_number = x509.random_serial_number()
        self.ca_cert_path: str | None = module.params["ownca_path"]
        ca_cert_content: str | None = module.params["ownca_content"]
        if ca_cert_content is not None:
            self.ca_cert_content: bytes | None = ca_cert_content.encode("utf-8")
        else:
            self.ca_cert_content = None
        self.ca_privatekey_path: str | None = module.params["ownca_privatekey_path"]
        ca_privatekey_content: str | None = module.params["ownca_privatekey_content"]
        if ca_privatekey_content is not None:
            self.ca_privatekey_content: bytes | None = ca_privatekey_content.encode(
                "utf-8"
            )
        else:
            self.ca_privatekey_content = None
        self.ca_privatekey_passphrase: str | None = module.params[
            "ownca_privatekey_passphrase"
        ]

        if self.csr_content is None:
            if self.csr_path is None:
                raise CertificateError(
                    "csr_path or csr_content is required for ownca provider"
                )
            if not os.path.exists(self.csr_path):
                raise CertificateError(
                    f"The certificate signing request file {self.csr_path} does not exist"
                )
        if self.ca_cert_path is not None and not os.path.exists(self.ca_cert_path):
            raise CertificateError(
                f"The CA certificate file {self.ca_cert_path} does not exist"
            )
        if self.ca_privatekey_path is not None and not os.path.exists(
            self.ca_privatekey_path
        ):
            raise CertificateError(
                f"The CA private key file {self.ca_privatekey_path} does not exist"
            )

        self._ensure_csr_loaded()
        self.ca_cert = load_certificate(
            path=self.ca_cert_path,
            content=self.ca_cert_content,
        )
        if not is_potential_certificate_issuer_public_key(self.ca_cert.public_key()):
            raise CertificateError(
                "CA certificate's public key cannot be used to sign certificates"
            )
        try:
            self.ca_private_key = load_certificate_issuer_privatekey(
                path=self.ca_privatekey_path,
                content=self.ca_privatekey_content,
                passphrase=self.ca_privatekey_passphrase,
            )
        except OpenSSLBadPassphraseError as exc:
            module.fail_json(msg=str(exc))

        if not cryptography_compare_public_keys(
            self.ca_cert.public_key(), self.ca_private_key.public_key()
        ):
            raise CertificateError(
                "The CA private key does not belong to the CA certificate"
            )

        if cryptography_key_needs_digest_for_signing(self.ca_private_key):
            if self.digest is None:
                raise CertificateError(
                    f"The digest {module.params['ownca_digest']} is not supported with the cryptography backend"
                )
        else:
            self.digest = None

    def generate_certificate(self) -> None:
        """(Re-)Generate certificate."""
        if self.csr is None:
            raise AssertionError(
                "Contract violation: csr has not been populated"
            )  # pragma: no cover
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(self.csr.subject)
        cert_builder = cert_builder.issuer_name(self.ca_cert.subject)
        cert_builder = cert_builder.serial_number(self.serial_number)
        cert_builder = set_not_valid_before(cert_builder, self.not_before)
        cert_builder = set_not_valid_after(cert_builder, self.not_after)
        cert_builder = cert_builder.public_key(self.csr.public_key())
        has_ski = False
        for extension in self.csr.extensions:
            if isinstance(extension.value, x509.SubjectKeyIdentifier):
                if self.create_subject_key_identifier == "always_create":
                    continue
                has_ski = True
            if self.create_authority_key_identifier and isinstance(
                extension.value, x509.AuthorityKeyIdentifier
            ):
                continue
            cert_builder = cert_builder.add_extension(
                extension.value, critical=extension.critical
            )
        if not has_ski and self.create_subject_key_identifier != "never_create":
            cert_builder = cert_builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.csr.public_key()),
                critical=False,
            )
        if self.create_authority_key_identifier:
            try:
                ext = self.ca_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                )
                cert_builder = cert_builder.add_extension(
                    (
                        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                            ext.value
                        )
                    ),
                    critical=False,
                )
            except cryptography.x509.ExtensionNotFound:
                public_key = self.ca_cert.public_key()
                assert is_potential_certificate_issuer_public_key(public_key)
                cert_builder = cert_builder.add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
                    critical=False,
                )

        certificate = cert_builder.sign(
            private_key=self.ca_private_key,
            algorithm=self.digest,
        )

        self.cert = certificate

    def get_certificate_data(self) -> bytes:
        """Return bytes for self.cert."""
        if self.cert is None:
            raise AssertionError(
                "Contract violation: cert has not been populated"
            )  # pragma: no cover
        return self.cert.public_bytes(Encoding.PEM)

    def needs_regeneration(
        self,
        *,
        not_before: datetime.datetime | None = None,
        not_after: datetime.datetime | None = None,
    ) -> bool:
        if super().needs_regeneration(
            not_before=self.not_before, not_after=self.not_after
        ):
            return True

        self._ensure_existing_certificate_loaded()
        assert self.existing_certificate is not None

        # Check whether certificate is signed by CA certificate
        if not cryptography_verify_certificate_signature(
            certificate=self.existing_certificate,
            signer_public_key=self.ca_cert.public_key(),
        ):
            return True

        # Check subject
        if self.ca_cert.subject != self.existing_certificate.issuer:
            return True

        # Check AuthorityKeyIdentifier
        if self.create_authority_key_identifier:
            try:
                ext_ski = self.ca_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                )
                expected_ext = (
                    x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                        ext_ski.value
                    )
                )
            except cryptography.x509.ExtensionNotFound:
                public_key = self.ca_cert.public_key()
                assert is_potential_certificate_issuer_public_key(public_key)
                expected_ext = x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    public_key
                )

            try:
                ext_aki = self.existing_certificate.extensions.get_extension_for_class(
                    x509.AuthorityKeyIdentifier
                )
                if ext_aki.value != expected_ext:
                    return True
            except cryptography.x509.ExtensionNotFound:
                return True

        return False

    def dump(self, *, include_certificate: bool) -> dict[str, t.Any]:
        result = super().dump(include_certificate=include_certificate)
        result.update(
            {
                "ca_cert": self.ca_cert_path,
                "ca_privatekey": self.ca_privatekey_path,
            }
        )

        if self.module.check_mode:
            result.update(
                {
                    "notBefore": self.not_before.strftime("%Y%m%d%H%M%SZ"),
                    "notAfter": self.not_after.strftime("%Y%m%d%H%M%SZ"),
                    "serial_number": self.serial_number,
                }
            )
        else:
            if self.cert is None:
                self.cert = self.existing_certificate
            assert self.cert is not None
            result.update(
                {
                    "notBefore": get_not_valid_before(self.cert).strftime(
                        "%Y%m%d%H%M%SZ"
                    ),
                    "notAfter": get_not_valid_after(self.cert).strftime(
                        "%Y%m%d%H%M%SZ"
                    ),
                    "serial_number": self.cert.serial_number,
                }
            )

        return result


def generate_serial_number() -> int:
    """Generate a serial number for a certificate"""
    while True:
        result = randrange(0, 1 << 160)
        if result >= 1000:
            return result


class OwnCACertificateProvider(CertificateProvider):
    def validate_module_args(self, module: AnsibleModule) -> None:
        if (
            module.params["ownca_path"] is None
            and module.params["ownca_content"] is None
        ):
            module.fail_json(
                msg="One of ownca_path and ownca_content must be specified for the ownca provider."
            )
        if (
            module.params["ownca_privatekey_path"] is None
            and module.params["ownca_privatekey_content"] is None
        ):
            module.fail_json(
                msg="One of ownca_privatekey_path and ownca_privatekey_content must be specified for the ownca provider."
            )

    def create_backend(
        self, module: AnsibleModule
    ) -> OwnCACertificateBackendCryptography:
        return OwnCACertificateBackendCryptography(module=module)


def add_ownca_provider_to_argument_spec(argument_spec: ArgumentSpec) -> None:
    argument_spec.argument_spec["provider"]["choices"].append("ownca")
    argument_spec.argument_spec.update(
        {
            "ownca_path": {"type": "path"},
            "ownca_content": {"type": "str"},
            "ownca_privatekey_path": {"type": "path"},
            "ownca_privatekey_content": {"type": "str", "no_log": True},
            "ownca_privatekey_passphrase": {"type": "str", "no_log": True},
            "ownca_digest": {"type": "str", "default": "sha256"},
            "ownca_version": {"type": "int", "default": 3, "choices": [3]},  # not used
            "ownca_not_before": {"type": "str", "default": "+0s"},
            "ownca_not_after": {"type": "str", "default": "+3650d"},
            "ownca_create_subject_key_identifier": {
                "type": "str",
                "default": "create_if_not_provided",
                "choices": ["create_if_not_provided", "always_create", "never_create"],
            },
            "ownca_create_authority_key_identifier": {"type": "bool", "default": True},
        }
    )
    argument_spec.mutually_exclusive.extend(
        [
            ["ownca_path", "ownca_content"],
            ["ownca_privatekey_path", "ownca_privatekey_content"],
        ]
    )


__all__ = (
    "OwnCACertificateBackendCryptography",
    "OwnCACertificateProvider",
    "add_ownca_provider_to_argument_spec",
)
