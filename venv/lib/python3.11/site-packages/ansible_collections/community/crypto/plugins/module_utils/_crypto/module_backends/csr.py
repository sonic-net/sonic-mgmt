# Copyright (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import binascii
import typing as t

from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.crypto.plugins.module_utils._argspec import (
    ArgumentSpec,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLBadPassphraseError,
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_crl import (
    REVOCATION_REASON_MAP,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    cryptography_get_basic_constraints,
    cryptography_get_name,
    cryptography_key_needs_digest_for_signing,
    cryptography_name_to_oid,
    cryptography_parse_key_usage_params,
    cryptography_parse_relative_distinguished_name,
    is_potential_certificate_issuer_public_key,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.csr_info import (
    get_csr_info,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    load_certificate_issuer_privatekey,
    load_certificate_request,
    parse_name_field,
    parse_ordered_name_field,
    select_message_digest,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.types import (  # pragma: no cover
        CertificateIssuerPrivateKeyTypes,
    )

    _ET = t.TypeVar("_ET", bound="cryptography.x509.ExtensionType")  # pragma: no cover


MINIMAL_CRYPTOGRAPHY_VERSION = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION

try:
    import cryptography
    import cryptography.exceptions
    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.hashes
    import cryptography.hazmat.primitives.serialization
    import cryptography.x509
    import cryptography.x509.oid
except ImportError:
    pass


class CertificateSigningRequestError(OpenSSLObjectError):
    pass


# From the object called `module`, only the following properties are used:
#
#  - module.params[]
#  - module.warn(msg: str)
#  - module.fail_json(msg: str, **kwargs)


def parse_crl_distribution_points(
    *, module: AnsibleModule, crl_distribution_points: list[dict[str, t.Any]]
) -> list[cryptography.x509.DistributionPoint]:
    result = []
    for index, parse_crl_distribution_point in enumerate(crl_distribution_points):
        try:
            full_name = None
            relative_name = None
            crl_issuer = None
            reasons = None
            if parse_crl_distribution_point["full_name"] is not None:
                if not parse_crl_distribution_point["full_name"]:
                    raise OpenSSLObjectError("full_name must not be empty")
                full_name = [
                    cryptography_get_name(name, what="full name")
                    for name in parse_crl_distribution_point["full_name"]
                ]
            if parse_crl_distribution_point["relative_name"] is not None:
                if not parse_crl_distribution_point["relative_name"]:
                    raise OpenSSLObjectError("relative_name must not be empty")
                relative_name = cryptography_parse_relative_distinguished_name(
                    parse_crl_distribution_point["relative_name"]
                )
            if parse_crl_distribution_point["crl_issuer"] is not None:
                if not parse_crl_distribution_point["crl_issuer"]:
                    raise OpenSSLObjectError("crl_issuer must not be empty")
                crl_issuer = [
                    cryptography_get_name(name, what="CRL issuer")
                    for name in parse_crl_distribution_point["crl_issuer"]
                ]
            if parse_crl_distribution_point["reasons"] is not None:
                reasons_list = []
                for reason in parse_crl_distribution_point["reasons"]:
                    reasons_list.append(REVOCATION_REASON_MAP[reason])
                reasons = frozenset(reasons_list)
            result.append(
                cryptography.x509.DistributionPoint(
                    full_name=full_name,
                    relative_name=relative_name,
                    crl_issuer=crl_issuer,
                    reasons=reasons,
                )
            )
        except (OpenSSLObjectError, ValueError) as e:
            raise OpenSSLObjectError(
                f"Error while parsing CRL distribution point #{index}: {e}"
            ) from e
    return result


class CertificateSigningRequestBackend:
    def __init__(self, *, module: AnsibleModule) -> None:
        self.module = module
        self.digest: str = module.params["digest"]
        self.privatekey_path: str | None = module.params["privatekey_path"]
        privatekey_content: str | None = module.params["privatekey_content"]
        if privatekey_content is not None:
            self.privatekey_content: bytes | None = privatekey_content.encode("utf-8")
        else:
            self.privatekey_content = None
        self.privatekey_passphrase: str | None = module.params["privatekey_passphrase"]
        self.version: t.Literal[1] = module.params["version"]
        self.subject_alt_name: list[str] | None = module.params["subject_alt_name"]
        self.subject_alt_name_critical: bool = module.params[
            "subject_alt_name_critical"
        ]
        self.key_usage: list[str] | None = module.params["key_usage"]
        self.key_usage_critical: bool = module.params["key_usage_critical"]
        self.extended_key_usage: list[str] | None = module.params["extended_key_usage"]
        self.extended_key_usage_critical: bool = module.params[
            "extended_key_usage_critical"
        ]
        self.basic_constraints: list[str] | None = module.params["basic_constraints"]
        self.basic_constraints_critical: bool = module.params[
            "basic_constraints_critical"
        ]
        self.ocsp_must_staple: bool = module.params["ocsp_must_staple"]
        self.ocsp_must_staple_critical: bool = module.params[
            "ocsp_must_staple_critical"
        ]
        self.name_constraints_permitted: list[str] = (
            module.params["name_constraints_permitted"] or []
        )
        self.name_constraints_excluded: list[str] = (
            module.params["name_constraints_excluded"] or []
        )
        self.name_constraints_critical: bool = module.params[
            "name_constraints_critical"
        ]
        self.create_subject_key_identifier: bool = module.params[
            "create_subject_key_identifier"
        ]
        subject_key_identifier: str | None = module.params["subject_key_identifier"]
        authority_key_identifier: str | None = module.params["authority_key_identifier"]
        self.authority_cert_issuer: list[str] | None = module.params[
            "authority_cert_issuer"
        ]
        self.authority_cert_serial_number: int | None = module.params[
            "authority_cert_serial_number"
        ]
        self.crl_distribution_points: (
            list[cryptography.x509.DistributionPoint] | None
        ) = None
        self.csr: cryptography.x509.CertificateSigningRequest | None = None
        self.privatekey: CertificateIssuerPrivateKeyTypes | None = None

        if self.create_subject_key_identifier and subject_key_identifier is not None:
            module.fail_json(
                msg="subject_key_identifier cannot be specified if create_subject_key_identifier is true"
            )

        self.ordered_subject = False
        subject = [
            ("C", module.params["country_name"]),
            ("ST", module.params["state_or_province_name"]),
            ("L", module.params["locality_name"]),
            ("O", module.params["organization_name"]),
            ("OU", module.params["organizational_unit_name"]),
            ("CN", module.params["common_name"]),
            ("emailAddress", module.params["email_address"]),
        ]
        self.subject: list[tuple[str, str]] = [
            (entry[0], entry[1]) for entry in subject if entry[1]
        ]

        try:
            if module.params["subject"]:
                self.subject = self.subject + parse_name_field(
                    module.params["subject"], name_field_name="subject"
                )
            if module.params["subject_ordered"]:
                if self.subject:
                    raise CertificateSigningRequestError(
                        "subject_ordered cannot be combined with any other subject field"
                    )
                self.subject = parse_ordered_name_field(
                    module.params["subject_ordered"], name_field_name="subject_ordered"
                )
                self.ordered_subject = True
        except ValueError as exc:
            raise CertificateSigningRequestError(str(exc)) from exc

        self.using_common_name_for_san = False
        if not self.subject_alt_name and module.params["use_common_name_for_san"]:
            for sub in self.subject:
                if sub[0] in ("commonName", "CN"):
                    self.subject_alt_name = [f"DNS:{sub[1]}"]
                    self.using_common_name_for_san = True
                    break

        self.subject_key_identifier: bytes | None = None
        if subject_key_identifier is not None:
            try:
                self.subject_key_identifier = binascii.unhexlify(
                    subject_key_identifier.replace(":", "")
                )
            except Exception as e:
                raise CertificateSigningRequestError(
                    f"Cannot parse subject_key_identifier: {e}"
                ) from e

        self.authority_key_identifier: bytes | None = None
        if authority_key_identifier is not None:
            try:
                self.authority_key_identifier = binascii.unhexlify(
                    authority_key_identifier.replace(":", "")
                )
            except Exception as e:
                raise CertificateSigningRequestError(
                    f"Cannot parse authority_key_identifier: {e}"
                ) from e

        self.existing_csr: cryptography.x509.CertificateSigningRequest | None = None
        self.existing_csr_bytes: bytes | None = None

        self.diff_before = self._get_info(data=None)
        self.diff_after = self._get_info(data=None)

        crl_distribution_points: list[dict[str, t.Any]] | None = module.params[
            "crl_distribution_points"
        ]
        if crl_distribution_points:
            self.crl_distribution_points = parse_crl_distribution_points(
                module=module, crl_distribution_points=crl_distribution_points
            )

    def _get_info(self, *, data: bytes | None) -> dict[str, t.Any]:
        if data is None:
            return {}
        try:
            result = get_csr_info(
                module=self.module,
                content=data,
                validate_signature=False,
                prefer_one_fingerprint=True,
            )
            result["can_parse_csr"] = True
            return result
        except Exception:
            return {"can_parse_csr": False}

    def generate_csr(self) -> None:
        """(Re-)Generate CSR."""
        self._ensure_private_key_loaded()
        assert self.privatekey is not None

        csr = cryptography.x509.CertificateSigningRequestBuilder()
        try:
            csr = csr.subject_name(
                cryptography.x509.Name(
                    [
                        cryptography.x509.NameAttribute(
                            cryptography_name_to_oid(entry[0]), to_text(entry[1])
                        )
                        for entry in self.subject
                    ]
                )
            )
        except ValueError as e:
            raise CertificateSigningRequestError(e) from e

        if self.subject_alt_name:
            csr = csr.add_extension(
                cryptography.x509.SubjectAlternativeName(
                    [cryptography_get_name(name) for name in self.subject_alt_name]
                ),
                critical=self.subject_alt_name_critical,
            )

        if self.key_usage:
            params = cryptography_parse_key_usage_params(self.key_usage)
            csr = csr.add_extension(
                cryptography.x509.KeyUsage(**params), critical=self.key_usage_critical
            )

        if self.extended_key_usage:
            usages = [
                cryptography_name_to_oid(usage) for usage in self.extended_key_usage
            ]
            csr = csr.add_extension(
                cryptography.x509.ExtendedKeyUsage(usages),
                critical=self.extended_key_usage_critical,
            )

        if self.basic_constraints:
            params = {}
            ca, path_length = cryptography_get_basic_constraints(self.basic_constraints)
            csr = csr.add_extension(
                cryptography.x509.BasicConstraints(ca, path_length),
                critical=self.basic_constraints_critical,
            )

        if self.ocsp_must_staple:
            csr = csr.add_extension(
                cryptography.x509.TLSFeature(
                    [cryptography.x509.TLSFeatureType.status_request]
                ),
                critical=self.ocsp_must_staple_critical,
            )

        if self.name_constraints_permitted or self.name_constraints_excluded:
            try:
                csr = csr.add_extension(
                    cryptography.x509.NameConstraints(
                        [
                            cryptography_get_name(
                                name, what="name constraints permitted"
                            )
                            for name in self.name_constraints_permitted
                        ]
                        or None,
                        [
                            cryptography_get_name(
                                name, what="name constraints excluded"
                            )
                            for name in self.name_constraints_excluded
                        ]
                        or None,
                    ),
                    critical=self.name_constraints_critical,
                )
            except TypeError as e:
                raise OpenSSLObjectError(
                    f"Error while parsing name constraint: {e}"
                ) from e

        if self.create_subject_key_identifier:
            if not is_potential_certificate_issuer_public_key(
                self.privatekey.public_key()
            ):
                raise OpenSSLObjectError(
                    "Private key can not be used to create subject key identifier"
                )
            csr = csr.add_extension(
                cryptography.x509.SubjectKeyIdentifier.from_public_key(
                    self.privatekey.public_key()
                ),
                critical=False,
            )
        elif self.subject_key_identifier is not None:
            csr = csr.add_extension(
                cryptography.x509.SubjectKeyIdentifier(self.subject_key_identifier),
                critical=False,
            )

        if (
            self.authority_key_identifier is not None
            or self.authority_cert_issuer is not None
            or self.authority_cert_serial_number is not None
        ):
            issuers = None
            if self.authority_cert_issuer is not None:
                issuers = [
                    cryptography_get_name(n, what="authority cert issuer")
                    for n in self.authority_cert_issuer
                ]
            csr = csr.add_extension(
                cryptography.x509.AuthorityKeyIdentifier(
                    self.authority_key_identifier,
                    issuers,
                    self.authority_cert_serial_number,
                ),
                critical=False,
            )

        if self.crl_distribution_points:
            csr = csr.add_extension(
                cryptography.x509.CRLDistributionPoints(self.crl_distribution_points),
                critical=False,
            )

        # csr.sign() does not accept some digests we theoretically could have in digest.
        # For that reason we use type t.Any here. csr.sign() will complain if
        # the digest is not acceptable.
        digest: t.Any | None = None
        if cryptography_key_needs_digest_for_signing(self.privatekey):
            digest = select_message_digest(self.digest)
            if digest is None:
                raise CertificateSigningRequestError(
                    f'Unsupported digest "{self.digest}"'
                )
        try:
            self.csr = csr.sign(self.privatekey, digest)
        except UnicodeError as e:
            # This catches IDNAErrors, which happens when a bad name is passed as a SAN
            # (https://github.com/ansible-collections/community.crypto/issues/105).
            # For older cryptography versions, this is handled by idna, which raises
            # an idna.core.IDNAError. Later versions of cryptography deprecated and stopped
            # requiring idna, whence we cannot easily handle this error. Fortunately, in
            # most versions of idna, IDNAError extends UnicodeError. There is only version
            # 2.3 where it extends Exception instead (see
            # https://github.com/kjd/idna/commit/ebefacd3134d0f5da4745878620a6a1cba86d130
            # and then
            # https://github.com/kjd/idna/commit/ea03c7b5db7d2a99af082e0239da2b68aeea702a).
            msg = f"Error while creating CSR: {e}\n"
            if self.using_common_name_for_san:
                self.module.fail_json(
                    msg=msg
                    + "This is probably caused because the Common Name is used as a SAN. Specifying use_common_name_for_san=false might fix this."
                )
            self.module.fail_json(
                msg=msg
                + "This is probably caused by an invalid Subject Alternative DNS Name."
            )

    def get_csr_data(self) -> bytes:
        """Return bytes for self.csr."""
        if self.csr is None:
            raise AssertionError(
                "Violated contract: csr is not populated"
            )  # pragma: no cover
        return self.csr.public_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.PEM
        )

    def set_existing(self, *, csr_bytes: bytes | None) -> None:
        """Set existing CSR bytes. None indicates that the CSR does not exist."""
        self.existing_csr_bytes = csr_bytes
        self.diff_after = self.diff_before = self._get_info(
            data=self.existing_csr_bytes
        )

    def has_existing(self) -> bool:
        """Query whether an existing CSR is/has been there."""
        return self.existing_csr_bytes is not None

    def _ensure_private_key_loaded(self) -> None:
        """Load the provided private key into self.privatekey."""
        if self.privatekey is not None:
            return
        try:
            self.privatekey = load_certificate_issuer_privatekey(
                path=self.privatekey_path,
                content=self.privatekey_content,
                passphrase=self.privatekey_passphrase,
            )
        except OpenSSLBadPassphraseError as exc:
            raise CertificateSigningRequestError(exc) from exc

    def _check_csr(self) -> bool:
        """Check whether provided parameters, assuming self.existing_csr and self.privatekey have been populated."""
        if self.existing_csr is None:
            raise AssertionError(
                "Violated contract: existing_csr is not populated"
            )  # pragma: no cover
        if self.privatekey is None:
            raise AssertionError(
                "Violated contract: privatekey is not populated"
            )  # pragma: no cover

        def _check_subject(csr: cryptography.x509.CertificateSigningRequest) -> bool:
            subject = [
                (cryptography_name_to_oid(entry[0]), to_text(entry[1]))
                for entry in self.subject
            ]
            current_subject = [(sub.oid, sub.value) for sub in csr.subject]
            if self.ordered_subject:
                return subject == current_subject
            return set(subject) == set(current_subject)

        def _find_extension(
            extensions: cryptography.x509.Extensions, exttype: type[_ET]
        ) -> cryptography.x509.Extension[_ET] | None:
            return next(
                (ext for ext in extensions if isinstance(ext.value, exttype)), None
            )

        def _check_subject_alt_name(extensions: cryptography.x509.Extensions) -> bool:
            current_altnames_ext = _find_extension(
                extensions, cryptography.x509.SubjectAlternativeName
            )
            current_altnames = (
                [to_text(altname) for altname in current_altnames_ext.value]
                if current_altnames_ext
                else []
            )
            altnames = (
                [
                    to_text(cryptography_get_name(altname))
                    for altname in self.subject_alt_name
                ]
                if self.subject_alt_name
                else []
            )
            if set(altnames) != set(current_altnames):
                return False
            return not (
                altnames
                and current_altnames_ext
                and current_altnames_ext.critical != self.subject_alt_name_critical
            )

        def _check_key_usage(extensions: cryptography.x509.Extensions) -> bool:
            current_keyusage_ext = _find_extension(
                extensions, cryptography.x509.KeyUsage
            )
            if not self.key_usage:
                return current_keyusage_ext is None
            if current_keyusage_ext is None:
                return False
            params = cryptography_parse_key_usage_params(self.key_usage)
            for param, value in params.items():
                try:
                    # param in ('encipher_only', 'decipher_only') can result in ValueError()
                    # being raised if key_agreement == False.
                    current_value = getattr(current_keyusage_ext.value, param)
                except ValueError:
                    # In that case, assume that the value is False.
                    current_value = False
                if current_value != value:
                    return False
            return current_keyusage_ext.critical == self.key_usage_critical

        def _check_extended_key_usage(extensions: cryptography.x509.Extensions) -> bool:
            current_usages_ext = _find_extension(
                extensions, cryptography.x509.ExtendedKeyUsage
            )
            current_usages = (
                [str(usage) for usage in current_usages_ext.value]
                if current_usages_ext
                else []
            )
            usages = (
                [
                    str(cryptography_name_to_oid(usage))
                    for usage in self.extended_key_usage
                ]
                if self.extended_key_usage
                else []
            )
            if set(current_usages) != set(usages):
                return False
            return not (
                usages
                and current_usages_ext
                and current_usages_ext.critical != self.extended_key_usage_critical
            )

        def _check_basic_constraints(extensions: cryptography.x509.Extensions) -> bool:
            bc_ext = _find_extension(extensions, cryptography.x509.BasicConstraints)
            current_ca = bc_ext.value.ca if bc_ext else False
            current_path_length = bc_ext.value.path_length if bc_ext else None
            ca, path_length = cryptography_get_basic_constraints(self.basic_constraints)
            # Check CA flag
            if ca != current_ca:
                return False
            # Check path length
            if path_length != current_path_length:
                return False
            # Check criticality
            if self.basic_constraints:
                return (
                    bc_ext is not None
                    and bc_ext.critical == self.basic_constraints_critical
                )
            return bc_ext is None

        def _check_ocsp_must_staple(extensions: cryptography.x509.Extensions) -> bool:
            tlsfeature_ext = _find_extension(extensions, cryptography.x509.TLSFeature)
            if self.ocsp_must_staple:
                if (
                    not tlsfeature_ext
                    or tlsfeature_ext.critical != self.ocsp_must_staple_critical
                ):
                    return False
                return (
                    cryptography.x509.TLSFeatureType.status_request
                    in tlsfeature_ext.value
                )
            return tlsfeature_ext is None

        def _check_name_constraints(extensions: cryptography.x509.Extensions) -> bool:
            current_nc_ext = _find_extension(
                extensions, cryptography.x509.NameConstraints
            )
            current_nc_perm = (
                [
                    to_text(altname)
                    for altname in current_nc_ext.value.permitted_subtrees or []
                ]
                if current_nc_ext
                else []
            )
            current_nc_excl = (
                [
                    to_text(altname)
                    for altname in current_nc_ext.value.excluded_subtrees or []
                ]
                if current_nc_ext
                else []
            )
            nc_perm = [
                to_text(
                    cryptography_get_name(altname, what="name constraints permitted")
                )
                for altname in self.name_constraints_permitted
            ]
            nc_excl = [
                to_text(
                    cryptography_get_name(altname, what="name constraints excluded")
                )
                for altname in self.name_constraints_excluded
            ]
            if set(nc_perm) != set(current_nc_perm) or set(nc_excl) != set(
                current_nc_excl
            ):
                return False
            return not (
                (nc_perm or nc_excl)
                and current_nc_ext
                and current_nc_ext.critical != self.name_constraints_critical
            )

        def _check_subject_key_identifier(
            extensions: cryptography.x509.Extensions,
        ) -> bool:
            ext = _find_extension(extensions, cryptography.x509.SubjectKeyIdentifier)
            if (
                self.create_subject_key_identifier
                or self.subject_key_identifier is not None
            ):
                if not ext or ext.critical:
                    return False
                if self.create_subject_key_identifier:
                    assert self.privatekey is not None
                    digest = cryptography.x509.SubjectKeyIdentifier.from_public_key(
                        self.privatekey.public_key()
                    ).digest
                    return ext.value.digest == digest
                return ext.value.digest == self.subject_key_identifier
            return ext is None

        def _check_authority_key_identifier(
            extensions: cryptography.x509.Extensions,
        ) -> bool:
            ext = _find_extension(extensions, cryptography.x509.AuthorityKeyIdentifier)
            if (
                self.authority_key_identifier is not None
                or self.authority_cert_issuer is not None
                or self.authority_cert_serial_number is not None
            ):
                if not ext or ext.critical:
                    return False
                aci = None
                csr_aci = None
                if self.authority_cert_issuer is not None:
                    aci = [
                        to_text(cryptography_get_name(n, what="authority cert issuer"))
                        for n in self.authority_cert_issuer
                    ]
                if ext.value.authority_cert_issuer is not None:
                    csr_aci = [to_text(n) for n in ext.value.authority_cert_issuer]
                return (
                    ext.value.key_identifier == self.authority_key_identifier
                    and csr_aci == aci
                    and ext.value.authority_cert_serial_number
                    == self.authority_cert_serial_number
                )
            return ext is None

        def _check_crl_distribution_points(
            extensions: cryptography.x509.Extensions,
        ) -> bool:
            ext = _find_extension(extensions, cryptography.x509.CRLDistributionPoints)
            if self.crl_distribution_points is None:
                return ext is None
            if not ext:
                return False
            return list(ext.value) == self.crl_distribution_points

        def _check_extensions(csr: cryptography.x509.CertificateSigningRequest) -> bool:
            extensions = csr.extensions
            return (
                _check_subject_alt_name(extensions)
                and _check_key_usage(extensions)
                and _check_extended_key_usage(extensions)
                and _check_basic_constraints(extensions)
                and _check_ocsp_must_staple(extensions)
                and _check_subject_key_identifier(extensions)
                and _check_authority_key_identifier(extensions)
                and _check_name_constraints(extensions)
                and _check_crl_distribution_points(extensions)
            )

        def _check_signature(csr: cryptography.x509.CertificateSigningRequest) -> bool:
            if not csr.is_signature_valid:
                return False
            # To check whether public key of CSR belongs to private key,
            # encode both public keys and compare PEMs.
            key_a = csr.public_key().public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.PEM,
                cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            assert self.privatekey is not None
            key_b = self.privatekey.public_key().public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.PEM,
                cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return key_a == key_b

        return (
            _check_subject(self.existing_csr)
            and _check_extensions(self.existing_csr)
            and _check_signature(self.existing_csr)
        )

    def needs_regeneration(self) -> bool:
        """Check whether a regeneration is necessary."""
        if self.existing_csr_bytes is None:
            return True
        try:
            self.existing_csr = load_certificate_request(
                content=self.existing_csr_bytes,
            )
        except Exception:
            return True
        self._ensure_private_key_loaded()
        return not self._check_csr()

    def dump(self, *, include_csr: bool) -> dict[str, t.Any]:
        """Serialize the object into a dictionary."""
        result: dict[str, t.Any] = {
            "privatekey": self.privatekey_path,
            "subject": self.subject,
            "subjectAltName": self.subject_alt_name,
            "keyUsage": self.key_usage,
            "extendedKeyUsage": self.extended_key_usage,
            "basicConstraints": self.basic_constraints,
            "ocspMustStaple": self.ocsp_must_staple,
            "name_constraints_permitted": self.name_constraints_permitted,
            "name_constraints_excluded": self.name_constraints_excluded,
        }
        # Get hold of CSR bytes
        csr_bytes = self.existing_csr_bytes
        if self.csr is not None:
            csr_bytes = self.get_csr_data()
        self.diff_after = self._get_info(data=csr_bytes)
        if include_csr:
            # Store result
            result["csr"] = csr_bytes.decode("utf-8") if csr_bytes else None

        result["diff"] = {
            "before": self.diff_before,
            "after": self.diff_after,
        }
        return result


def select_backend(
    module: AnsibleModule,
) -> CertificateSigningRequestBackend:
    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )
    return CertificateSigningRequestBackend(module=module)


def get_csr_argument_spec() -> ArgumentSpec:
    return ArgumentSpec(
        argument_spec={
            "digest": {"type": "str", "default": "sha256"},
            "privatekey_path": {"type": "path"},
            "privatekey_content": {"type": "str", "no_log": True},
            "privatekey_passphrase": {"type": "str", "no_log": True},
            "version": {"type": "int", "default": 1, "choices": [1]},
            "subject": {"type": "dict"},
            "subject_ordered": {"type": "list", "elements": "dict"},
            "country_name": {"type": "str", "aliases": ["C", "countryName"]},
            "state_or_province_name": {
                "type": "str",
                "aliases": ["ST", "stateOrProvinceName"],
            },
            "locality_name": {"type": "str", "aliases": ["L", "localityName"]},
            "organization_name": {"type": "str", "aliases": ["O", "organizationName"]},
            "organizational_unit_name": {
                "type": "str",
                "aliases": ["OU", "organizationalUnitName"],
            },
            "common_name": {"type": "str", "aliases": ["CN", "commonName"]},
            "email_address": {"type": "str", "aliases": ["E", "emailAddress"]},
            "subject_alt_name": {
                "type": "list",
                "elements": "str",
                "aliases": ["subjectAltName"],
            },
            "subject_alt_name_critical": {
                "type": "bool",
                "default": False,
                "aliases": ["subjectAltName_critical"],
            },
            "use_common_name_for_san": {
                "type": "bool",
                "default": True,
                "aliases": ["useCommonNameForSAN"],
            },
            "key_usage": {"type": "list", "elements": "str", "aliases": ["keyUsage"]},
            "key_usage_critical": {
                "type": "bool",
                "default": False,
                "aliases": ["keyUsage_critical"],
            },
            "extended_key_usage": {
                "type": "list",
                "elements": "str",
                "aliases": ["extKeyUsage", "extendedKeyUsage"],
            },
            "extended_key_usage_critical": {
                "type": "bool",
                "default": False,
                "aliases": ["extKeyUsage_critical", "extendedKeyUsage_critical"],
            },
            "basic_constraints": {
                "type": "list",
                "elements": "str",
                "aliases": ["basicConstraints"],
            },
            "basic_constraints_critical": {
                "type": "bool",
                "default": False,
                "aliases": ["basicConstraints_critical"],
            },
            "ocsp_must_staple": {
                "type": "bool",
                "default": False,
                "aliases": ["ocspMustStaple"],
            },
            "ocsp_must_staple_critical": {
                "type": "bool",
                "default": False,
                "aliases": ["ocspMustStaple_critical"],
            },
            "name_constraints_permitted": {"type": "list", "elements": "str"},
            "name_constraints_excluded": {"type": "list", "elements": "str"},
            "name_constraints_critical": {"type": "bool", "default": False},
            "create_subject_key_identifier": {"type": "bool", "default": False},
            "subject_key_identifier": {"type": "str"},
            "authority_key_identifier": {"type": "str"},
            "authority_cert_issuer": {"type": "list", "elements": "str"},
            "authority_cert_serial_number": {"type": "int"},
            "crl_distribution_points": {
                "type": "list",
                "elements": "dict",
                "options": {
                    "full_name": {"type": "list", "elements": "str"},
                    "relative_name": {"type": "list", "elements": "str"},
                    "crl_issuer": {"type": "list", "elements": "str"},
                    "reasons": {
                        "type": "list",
                        "elements": "str",
                        "choices": [
                            "key_compromise",
                            "ca_compromise",
                            "affiliation_changed",
                            "superseded",
                            "cessation_of_operation",
                            "certificate_hold",
                            "privilege_withdrawn",
                            "aa_compromise",
                        ],
                    },
                },
                "mutually_exclusive": [("full_name", "relative_name")],
                "required_one_of": [("full_name", "relative_name", "crl_issuer")],
            },
            "select_crypto_backend": {
                "type": "str",
                "default": "auto",
                "choices": ["auto", "cryptography"],
            },
        },
        required_together=[
            ["authority_cert_issuer", "authority_cert_serial_number"],
        ],
        mutually_exclusive=[
            ["privatekey_path", "privatekey_content"],
            ["subject", "subject_ordered"],
        ],
        required_one_of=[
            ["privatekey_path", "privatekey_content"],
        ],
    )


__all__ = (
    "CertificateSigningRequestError",
    "CertificateSigningRequestBackend",
    "select_backend",
    "get_csr_argument_spec",
)
