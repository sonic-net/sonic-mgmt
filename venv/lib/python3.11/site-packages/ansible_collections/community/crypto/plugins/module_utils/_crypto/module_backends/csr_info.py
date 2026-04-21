# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import binascii
import typing as t

from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    cryptography_decode_name,
    cryptography_get_extensions_from_csr,
    cryptography_oid_to_name,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.publickey_info import (
    get_publickey_info,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    load_certificate_request,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.types import (  # pragma: no cover
        CertificatePublicKeyTypes,
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
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass


TIMESTAMP_FORMAT = "%Y%m%d%H%M%SZ"


class CSRInfoRetrieval:
    csr: x509.CertificateSigningRequest

    def __init__(
        self, *, module: GeneralAnsibleModule, content: bytes, validate_signature: bool
    ) -> None:
        self.module = module
        self.content = content
        self.validate_signature = validate_signature
        self.name_encoding: t.Literal["ignore", "idna", "unicode"] = module.params.get(
            "name_encoding", "ignore"
        )

    def _get_subject_ordered(self) -> list[list[str]]:
        result: list[list[str]] = []
        for attribute in self.csr.subject:
            result.append(
                [cryptography_oid_to_name(attribute.oid), to_text(attribute.value)]
            )
        return result

    def _get_key_usage(self) -> tuple[list[str] | None, bool]:
        try:
            current_key_ext = self.csr.extensions.get_extension_for_class(x509.KeyUsage)
            current_key_usage = current_key_ext.value
            key_usage = {
                "digital_signature": current_key_usage.digital_signature,
                "content_commitment": current_key_usage.content_commitment,
                "key_encipherment": current_key_usage.key_encipherment,
                "data_encipherment": current_key_usage.data_encipherment,
                "key_agreement": current_key_usage.key_agreement,
                "key_cert_sign": current_key_usage.key_cert_sign,
                "crl_sign": current_key_usage.crl_sign,
                "encipher_only": False,
                "decipher_only": False,
            }
            if key_usage["key_agreement"]:
                key_usage.update(
                    {
                        "encipher_only": current_key_usage.encipher_only,
                        "decipher_only": current_key_usage.decipher_only,
                    }
                )

            key_usage_names = {
                "digital_signature": "Digital Signature",
                "content_commitment": "Non Repudiation",
                "key_encipherment": "Key Encipherment",
                "data_encipherment": "Data Encipherment",
                "key_agreement": "Key Agreement",
                "key_cert_sign": "Certificate Sign",
                "crl_sign": "CRL Sign",
                "encipher_only": "Encipher Only",
                "decipher_only": "Decipher Only",
            }
            return (
                sorted(
                    [
                        key_usage_names[name]
                        for name, value in key_usage.items()
                        if value
                    ]
                ),
                current_key_ext.critical,
            )
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_extended_key_usage(self) -> tuple[list[str] | None, bool]:
        try:
            ext_keyusage_ext = self.csr.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            )
            return (
                sorted(
                    [cryptography_oid_to_name(eku) for eku in ext_keyusage_ext.value]
                ),
                ext_keyusage_ext.critical,
            )
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_basic_constraints(self) -> tuple[list[str] | None, bool]:
        try:
            ext_keyusage_ext = self.csr.extensions.get_extension_for_class(
                x509.BasicConstraints
            )
            result = [f"CA:{'TRUE' if ext_keyusage_ext.value.ca else 'FALSE'}"]
            if ext_keyusage_ext.value.path_length is not None:
                result.append(f"pathlen:{ext_keyusage_ext.value.path_length}")
            return sorted(result), ext_keyusage_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_ocsp_must_staple(self) -> tuple[bool | None, bool]:
        try:
            # This only works with cryptography >= 2.1
            tlsfeature_ext = self.csr.extensions.get_extension_for_class(
                x509.TLSFeature
            )
            value = (
                cryptography.x509.TLSFeatureType.status_request in tlsfeature_ext.value
            )
            return value, tlsfeature_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_subject_alt_name(self) -> tuple[list[str] | None, bool]:
        try:
            san_ext = self.csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            result = [
                cryptography_decode_name(san, idn_rewrite=self.name_encoding)
                for san in san_ext.value
            ]
            return result, san_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_name_constraints(self) -> tuple[list[str] | None, list[str] | None, bool]:
        try:
            nc_ext = self.csr.extensions.get_extension_for_class(x509.NameConstraints)
            permitted = [
                cryptography_decode_name(san, idn_rewrite=self.name_encoding)
                for san in nc_ext.value.permitted_subtrees or []
            ]
            excluded = [
                cryptography_decode_name(san, idn_rewrite=self.name_encoding)
                for san in nc_ext.value.excluded_subtrees or []
            ]
            return permitted, excluded, nc_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, None, False

    def _get_public_key_pem(self) -> bytes:
        return self.csr.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _get_public_key_object(self) -> CertificatePublicKeyTypes:
        return self.csr.public_key()

    def _get_subject_key_identifier(self) -> bytes | None:
        try:
            ext = self.csr.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            return ext.value.digest
        except cryptography.x509.ExtensionNotFound:
            return None

    def _get_authority_key_identifier(
        self,
    ) -> tuple[bytes | None, list[str] | None, int | None]:
        try:
            ext = self.csr.extensions.get_extension_for_class(
                x509.AuthorityKeyIdentifier
            )
            issuer = None
            if ext.value.authority_cert_issuer is not None:
                issuer = [
                    cryptography_decode_name(san, idn_rewrite=self.name_encoding)
                    for san in ext.value.authority_cert_issuer
                ]
            return (
                ext.value.key_identifier,
                issuer,
                ext.value.authority_cert_serial_number,
            )
        except cryptography.x509.ExtensionNotFound:
            return None, None, None

    def _get_all_extensions(self) -> dict[str, dict[str, bool | str]]:
        return cryptography_get_extensions_from_csr(self.csr)

    def _is_signature_valid(self) -> bool:
        return self.csr.is_signature_valid

    def get_info(self, *, prefer_one_fingerprint: bool = False) -> dict[str, t.Any]:
        result: dict[str, t.Any] = {}
        self.csr = load_certificate_request(
            content=self.content,
        )

        subject = self._get_subject_ordered()
        result["subject"] = {}
        for k, v in subject:
            result["subject"][k] = v
        result["subject_ordered"] = subject
        result["key_usage"], result["key_usage_critical"] = self._get_key_usage()
        result["extended_key_usage"], result["extended_key_usage_critical"] = (
            self._get_extended_key_usage()
        )
        result["basic_constraints"], result["basic_constraints_critical"] = (
            self._get_basic_constraints()
        )
        result["ocsp_must_staple"], result["ocsp_must_staple_critical"] = (
            self._get_ocsp_must_staple()
        )
        result["subject_alt_name"], result["subject_alt_name_critical"] = (
            self._get_subject_alt_name()
        )
        (
            result["name_constraints_permitted"],
            result["name_constraints_excluded"],
            result["name_constraints_critical"],
        ) = self._get_name_constraints()

        result["public_key"] = to_text(self._get_public_key_pem())

        public_key_info = get_publickey_info(
            module=self.module,
            key=self._get_public_key_object(),
            prefer_one_fingerprint=prefer_one_fingerprint,
        )
        result.update(
            {
                "public_key_type": public_key_info["type"],
                "public_key_data": public_key_info["public_data"],
                "public_key_fingerprints": public_key_info["fingerprints"],
            }
        )

        ski_bytes = self._get_subject_key_identifier()
        ski = None
        if ski_bytes is not None:
            ski = binascii.hexlify(ski_bytes).decode("ascii")
            ski = ":".join([ski[i : i + 2] for i in range(0, len(ski), 2)])
        result["subject_key_identifier"] = ski

        aki_bytes, aci, acsn = self._get_authority_key_identifier()
        aki = None
        if aki_bytes is not None:
            aki = binascii.hexlify(aki_bytes).decode("ascii")
            aki = ":".join([aki[i : i + 2] for i in range(0, len(aki), 2)])
        result["authority_key_identifier"] = aki
        result["authority_cert_issuer"] = aci
        result["authority_cert_serial_number"] = acsn

        result["extensions_by_oid"] = self._get_all_extensions()

        result["signature_valid"] = self._is_signature_valid()
        if self.validate_signature and not result["signature_valid"]:
            self.module.fail_json(msg="CSR signature is invalid!", **result)
        return result


def get_csr_info(
    *,
    module: GeneralAnsibleModule,
    content: bytes,
    validate_signature: bool = True,
    prefer_one_fingerprint: bool = False,
) -> dict[str, t.Any]:
    info = CSRInfoRetrieval(
        module=module, content=content, validate_signature=validate_signature
    )
    return info.get_info(prefer_one_fingerprint=prefer_one_fingerprint)


def select_backend(
    *, module: GeneralAnsibleModule, content: bytes, validate_signature: bool = True
) -> CSRInfoRetrieval:
    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )
    return CSRInfoRetrieval(
        module=module, content=content, validate_signature=validate_signature
    )


__all__ = ("CSRInfoRetrieval", "get_csr_info", "select_backend")
