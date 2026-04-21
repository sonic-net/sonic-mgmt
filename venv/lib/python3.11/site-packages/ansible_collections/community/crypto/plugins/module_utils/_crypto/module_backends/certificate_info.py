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
    CRYPTOGRAPHY_TIMEZONE,
    cryptography_decode_name,
    cryptography_get_extensions_from_cert,
    cryptography_oid_to_name,
    get_not_valid_after,
    get_not_valid_before,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.publickey_info import (
    get_publickey_info,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    get_fingerprint_of_bytes,
    load_certificate,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    get_now_datetime,
)


if t.TYPE_CHECKING:
    import datetime  # pragma: no cover

    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.types import (
        PublicKeyTypes,  # pragma: no cover
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


class CertificateInfoRetrieval:
    cert: x509.Certificate

    def __init__(self, *, module: GeneralAnsibleModule, content: bytes) -> None:
        # content must be a bytes string
        self.module = module
        self.content = content
        self.name_encoding = module.params.get("name_encoding", "ignore")

    def _get_der_bytes(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    def _get_signature_algorithm(self) -> str:
        return cryptography_oid_to_name(self.cert.signature_algorithm_oid)

    def _get_subject_ordered(self) -> list[list[str]]:
        result: list[list[str]] = []
        for attribute in self.cert.subject:
            result.append(
                [cryptography_oid_to_name(attribute.oid), to_text(attribute.value)]
            )
        return result

    def _get_issuer_ordered(self) -> list[list[str]]:
        result = []
        for attribute in self.cert.issuer:
            result.append(
                [cryptography_oid_to_name(attribute.oid), to_text(attribute.value)]
            )
        return result

    def _get_version(self) -> int | str:
        if self.cert.version == x509.Version.v1:
            return 1
        if self.cert.version == x509.Version.v3:
            return 3
        return "unknown"  # type: ignore[unreachable]

    def _get_key_usage(self) -> tuple[list[str] | None, bool]:
        try:
            current_key_ext = self.cert.extensions.get_extension_for_class(
                x509.KeyUsage
            )
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
            ext_keyusage_ext = self.cert.extensions.get_extension_for_class(
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
            ext_keyusage_ext = self.cert.extensions.get_extension_for_class(
                x509.BasicConstraints
            )
            result = []
            result.append(f"CA:{'TRUE' if ext_keyusage_ext.value.ca else 'FALSE'}")
            if ext_keyusage_ext.value.path_length is not None:
                result.append(f"pathlen:{ext_keyusage_ext.value.path_length}")
            return sorted(result), ext_keyusage_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_ocsp_must_staple(self) -> tuple[bool | None, bool]:
        try:
            tlsfeature_ext = self.cert.extensions.get_extension_for_class(
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
            san_ext = self.cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            result = [
                cryptography_decode_name(san, idn_rewrite=self.name_encoding)
                for san in san_ext.value
            ]
            return result, san_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def get_not_before(self) -> datetime.datetime:
        return get_not_valid_before(self.cert)

    def get_not_after(self) -> datetime.datetime:
        return get_not_valid_after(self.cert)

    def _get_public_key_pem(self) -> bytes:
        return self.cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _get_public_key_object(self) -> PublicKeyTypes:
        return self.cert.public_key()

    def _get_subject_key_identifier(self) -> bytes | None:
        try:
            ext = self.cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            )
            return ext.value.digest
        except cryptography.x509.ExtensionNotFound:
            return None

    def _get_authority_key_identifier(
        self,
    ) -> tuple[bytes | None, list[str] | None, int | None]:
        try:
            ext = self.cert.extensions.get_extension_for_class(
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

    def _get_serial_number(self) -> int:
        return self.cert.serial_number

    def _get_all_extensions(self) -> dict[str, dict[str, bool | str]]:
        return cryptography_get_extensions_from_cert(self.cert)

    def _get_ocsp_uri(self) -> str | None:
        try:
            ext = self.cert.extensions.get_extension_for_class(
                x509.AuthorityInformationAccess
            )
            for desc in ext.value:
                if (
                    desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP
                    and isinstance(desc.access_location, x509.UniformResourceIdentifier)
                ):
                    return desc.access_location.value
        except x509.ExtensionNotFound:
            pass
        return None

    def _get_issuer_uri(self) -> str | None:
        try:
            ext = self.cert.extensions.get_extension_for_class(
                x509.AuthorityInformationAccess
            )
            for desc in ext.value:
                if (
                    desc.access_method
                    == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
                ) and isinstance(desc.access_location, x509.UniformResourceIdentifier):
                    return desc.access_location.value
        except x509.ExtensionNotFound:
            pass
        return None

    def get_info(
        self, *, prefer_one_fingerprint: bool = False, der_support_enabled: bool = False
    ) -> dict[str, t.Any]:
        result: dict[str, t.Any] = {}
        self.cert = load_certificate(
            content=self.content,
            der_support_enabled=der_support_enabled,
        )

        result["signature_algorithm"] = self._get_signature_algorithm()
        subject = self._get_subject_ordered()
        issuer = self._get_issuer_ordered()
        result["subject"] = {}
        for k, v in subject:
            result["subject"][k] = v
        result["subject_ordered"] = subject
        result["issuer"] = {}
        for k, v in issuer:
            result["issuer"][k] = v
        result["issuer_ordered"] = issuer
        result["version"] = self._get_version()
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

        not_before = self.get_not_before()
        not_after = self.get_not_after()
        result["not_before"] = not_before.strftime(TIMESTAMP_FORMAT)
        result["not_after"] = not_after.strftime(TIMESTAMP_FORMAT)
        result["expired"] = not_after < get_now_datetime(
            with_timezone=CRYPTOGRAPHY_TIMEZONE
        )

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

        result["fingerprints"] = get_fingerprint_of_bytes(
            self._get_der_bytes(), prefer_one=prefer_one_fingerprint
        )

        ski_bytes = self._get_subject_key_identifier()
        if ski_bytes is not None:
            ski = binascii.hexlify(ski_bytes).decode("ascii")
            ski = ":".join([ski[i : i + 2] for i in range(0, len(ski), 2)])
        else:
            ski = None
        result["subject_key_identifier"] = ski

        aki_bytes, aci, acsn = self._get_authority_key_identifier()
        if aki_bytes is not None:
            aki = binascii.hexlify(aki_bytes).decode("ascii")
            aki = ":".join([aki[i : i + 2] for i in range(0, len(aki), 2)])
        else:
            aki = None
        result["authority_key_identifier"] = aki
        result["authority_cert_issuer"] = aci
        result["authority_cert_serial_number"] = acsn

        result["serial_number"] = self._get_serial_number()
        result["extensions_by_oid"] = self._get_all_extensions()
        result["ocsp_uri"] = self._get_ocsp_uri()
        result["issuer_uri"] = self._get_issuer_uri()

        return result


def get_certificate_info(
    *,
    module: GeneralAnsibleModule,
    content: bytes,
    prefer_one_fingerprint: bool = False,
) -> dict[str, t.Any]:
    info = CertificateInfoRetrieval(module=module, content=content)
    return info.get_info(prefer_one_fingerprint=prefer_one_fingerprint)


def select_backend(
    *, module: GeneralAnsibleModule, content: bytes
) -> CertificateInfoRetrieval:
    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )
    return CertificateInfoRetrieval(module=module, content=content)


__all__ = ("CertificateInfoRetrieval", "get_certificate_info", "select_backend")
