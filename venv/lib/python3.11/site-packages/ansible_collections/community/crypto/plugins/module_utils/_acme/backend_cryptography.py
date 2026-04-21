# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import base64
import binascii
import os
import traceback
import typing as t

from ansible.module_utils.common.text.converters import to_bytes, to_text

from ansible_collections.community.crypto.plugins.module_utils._acme.backends import (
    CertificateInformation,
    CryptoBackend,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.certificates import (
    ChainMatcher,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    BackendException,
    KeyParsingError,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.io import read_file
from ansible_collections.community.crypto.plugins.module_utils._acme.utils import (
    nopad_b64,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    CRYPTOGRAPHY_TIMEZONE,
    cryptography_name_to_oid,
    get_not_valid_after,
    get_not_valid_before,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.math import (
    convert_int_to_bytes,
    convert_int_to_hex,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.pem import (
    extract_first_pem,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    parse_name_field,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    add_or_remove_timezone,
)
from ansible_collections.community.crypto.plugins.module_utils._version import (
    LooseVersion,
)


CRYPTOGRAPHY_MINIMAL_VERSION = "1.5"

CRYPTOGRAPHY_ERROR: None | str
try:
    import cryptography
    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.asymmetric.ec
    import cryptography.hazmat.primitives.asymmetric.padding
    import cryptography.hazmat.primitives.asymmetric.rsa
    import cryptography.hazmat.primitives.asymmetric.utils
    import cryptography.hazmat.primitives.hashes
    import cryptography.hazmat.primitives.hmac
    import cryptography.hazmat.primitives.serialization
    import cryptography.x509
    import cryptography.x509.oid
except ImportError:
    HAS_CURRENT_CRYPTOGRAPHY = False  # pylint: disable=invalid-name
    CRYPTOGRAPHY_VERSION = None  # pylint: disable=invalid-name
    CRYPTOGRAPHY_ERROR = traceback.format_exc()  # pylint: disable=invalid-name
else:
    CRYPTOGRAPHY_VERSION = cryptography.__version__  # pylint: disable=invalid-name
    HAS_CURRENT_CRYPTOGRAPHY = LooseVersion(CRYPTOGRAPHY_VERSION) >= LooseVersion(
        CRYPTOGRAPHY_MINIMAL_VERSION
    )
    CRYPTOGRAPHY_ERROR = None  # pylint: disable=invalid-name

if t.TYPE_CHECKING:
    import datetime  # pragma: no cover

    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.module_utils._acme.certificates import (  # pragma: no cover
        CertificateChain,
        Criterium,
    )


class CryptographyChainMatcher(ChainMatcher):
    @staticmethod
    def _parse_key_identifier(
        *,
        key_identifier: str | None,
        name: str,
        criterium_idx: int,
        module: AnsibleModule,
    ) -> bytes | None:
        if key_identifier:
            try:
                return binascii.unhexlify(key_identifier.replace(":", ""))
            except Exception:
                module.warn(
                    f"Criterium {criterium_idx} in select_chain has invalid {name} value. Ignoring criterium."
                )
        return None

    def __init__(self, *, criterium: Criterium, module: AnsibleModule) -> None:
        self.criterium = criterium
        self.test_certificates = criterium.test_certificates
        self.subject: list[tuple[cryptography.x509.oid.ObjectIdentifier, str]] = []
        self.issuer: list[tuple[cryptography.x509.oid.ObjectIdentifier, str]] = []
        if criterium.subject:
            self.subject = [
                (cryptography_name_to_oid(k), to_text(v))
                for k, v in parse_name_field(
                    criterium.subject, name_field_name="subject"
                )
            ]
        if criterium.issuer:
            self.issuer = [
                (cryptography_name_to_oid(k), to_text(v))
                for k, v in parse_name_field(criterium.issuer, name_field_name="issuer")
            ]
        self.subject_key_identifier = CryptographyChainMatcher._parse_key_identifier(
            key_identifier=criterium.subject_key_identifier,
            name="subject_key_identifier",
            criterium_idx=criterium.index,
            module=module,
        )
        self.authority_key_identifier = CryptographyChainMatcher._parse_key_identifier(
            key_identifier=criterium.authority_key_identifier,
            name="authority_key_identifier",
            criterium_idx=criterium.index,
            module=module,
        )
        self.module = module

    def _match_subject(
        self,
        *,
        x509_subject: cryptography.x509.Name,
        match_subject: list[tuple[cryptography.x509.oid.ObjectIdentifier, str]],
    ) -> bool:
        for oid, value in match_subject:
            found = False
            for attribute in x509_subject:
                if attribute.oid == oid and value == to_text(attribute.value):
                    found = True
                    break
            if not found:
                return False
        return True

    def match(self, *, certificate: CertificateChain) -> bool:
        """
        Check whether an alternate chain matches the specified criterium.
        """
        chain = certificate.chain
        if self.test_certificates == "last":
            chain = chain[-1:]
        elif self.test_certificates == "first":
            chain = chain[:1]
        for cert in chain:
            try:
                x509 = cryptography.x509.load_pem_x509_certificate(to_bytes(cert))
                matches = True
                if not self._match_subject(
                    x509_subject=x509.subject, match_subject=self.subject
                ):
                    matches = False
                if not self._match_subject(
                    x509_subject=x509.issuer, match_subject=self.issuer
                ):
                    matches = False
                if self.subject_key_identifier:
                    try:
                        ext_ski = x509.extensions.get_extension_for_class(
                            cryptography.x509.SubjectKeyIdentifier
                        )
                        if self.subject_key_identifier != ext_ski.value.digest:
                            matches = False
                    except cryptography.x509.ExtensionNotFound:
                        matches = False
                if self.authority_key_identifier:
                    try:
                        ext_aki = x509.extensions.get_extension_for_class(
                            cryptography.x509.AuthorityKeyIdentifier
                        )
                        if (
                            self.authority_key_identifier
                            != ext_aki.value.key_identifier
                        ):
                            matches = False
                    except cryptography.x509.ExtensionNotFound:
                        matches = False
                if matches:
                    return True
            except Exception as e:
                self.module.warn(f"Error while loading certificate {cert}: {e}")
        return False


class CryptographyBackend(CryptoBackend):
    def __init__(self, *, module: AnsibleModule) -> None:
        super().__init__(module=module, with_timezone=CRYPTOGRAPHY_TIMEZONE)

    def parse_key(
        self,
        *,
        key_file: str | os.PathLike | None = None,
        key_content: str | None = None,
        passphrase: str | None = None,
    ) -> dict[str, t.Any]:
        """
        Parses an RSA or Elliptic Curve key file in PEM format and returns key_data.
        Raises KeyParsingError in case of errors.
        """
        # If key_content is not given, read key_file
        if key_content is None:
            if key_file is None:
                raise KeyParsingError(
                    "one of key_file and key_content must be specified"
                )
            b_key_content = read_file(key_file)
        else:
            b_key_content = to_bytes(key_content)
        # Parse key
        try:
            key = cryptography.hazmat.primitives.serialization.load_pem_private_key(
                b_key_content,
                password=to_bytes(passphrase) if passphrase is not None else None,
            )
        except Exception as e:
            raise KeyParsingError(f"error while loading key: {e}") from e
        if isinstance(key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
            rsa_pk = key.public_key().public_numbers()
            return {
                "key_obj": key,
                "type": "rsa",
                "alg": "RS256",
                "jwk": {
                    "kty": "RSA",
                    "e": nopad_b64(convert_int_to_bytes(rsa_pk.e)),
                    "n": nopad_b64(convert_int_to_bytes(rsa_pk.n)),
                },
                "hash": "sha256",
            }
        if isinstance(
            key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
        ):
            ec_pk = key.public_key().public_numbers()
            if ec_pk.curve.name == "secp256r1":
                bits = 256
                alg = "ES256"
                hashalg = "sha256"
                point_size = 32
                curve = "P-256"
            elif ec_pk.curve.name == "secp384r1":
                bits = 384
                alg = "ES384"
                hashalg = "sha384"
                point_size = 48
                curve = "P-384"
            elif ec_pk.curve.name == "secp521r1":
                # Not yet supported on Let's Encrypt side, see
                # https://github.com/letsencrypt/boulder/issues/2217
                bits = 521
                alg = "ES512"
                hashalg = "sha512"
                point_size = 66
                curve = "P-521"
            else:
                raise KeyParsingError(f"unknown elliptic curve: {ec_pk.curve.name}")
            num_bytes = (bits + 7) // 8
            return {
                "key_obj": key,
                "type": "ec",
                "alg": alg,
                "jwk": {
                    "kty": "EC",
                    "crv": curve,
                    "x": nopad_b64(convert_int_to_bytes(ec_pk.x, count=num_bytes)),
                    "y": nopad_b64(convert_int_to_bytes(ec_pk.y, count=num_bytes)),
                },
                "hash": hashalg,
                "point_size": point_size,
            }
        raise KeyParsingError(f'unknown key type "{type(key)}"')

    def sign(
        self, *, payload64: str, protected64: str, key_data: dict[str, t.Any]
    ) -> dict[str, t.Any]:
        sign_payload = f"{protected64}.{payload64}".encode("utf8")
        hashalg: type[cryptography.hazmat.primitives.hashes.HashAlgorithm]
        if "mac_obj" in key_data:
            mac = key_data["mac_obj"]()
            mac.update(sign_payload)
            signature = mac.finalize()
        elif isinstance(
            key_data["key_obj"],
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey,
        ):
            padding = cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15()
            hashalg = cryptography.hazmat.primitives.hashes.SHA256
            signature = key_data["key_obj"].sign(sign_payload, padding, hashalg())
        elif isinstance(
            key_data["key_obj"],
            cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey,
        ):
            if key_data["hash"] == "sha256":
                hashalg = cryptography.hazmat.primitives.hashes.SHA256
            elif key_data["hash"] == "sha384":
                hashalg = cryptography.hazmat.primitives.hashes.SHA384
            elif key_data["hash"] == "sha512":
                hashalg = cryptography.hazmat.primitives.hashes.SHA512
            ecdsa = cryptography.hazmat.primitives.asymmetric.ec.ECDSA(hashalg())
            r, s = cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature(
                key_data["key_obj"].sign(sign_payload, ecdsa)
            )
            rr = convert_int_to_hex(r, digits=2 * key_data["point_size"])
            ss = convert_int_to_hex(s, digits=2 * key_data["point_size"])
            signature = binascii.unhexlify(rr) + binascii.unhexlify(ss)
        else:
            raise AssertionError("Can never be reached")  # pragma: no cover

        return {
            "protected": protected64,
            "payload": payload64,
            "signature": nopad_b64(signature),
        }

    def create_mac_key(self, *, alg: str, key: str) -> dict[str, t.Any]:
        """Create a MAC key."""
        hashalg: type[cryptography.hazmat.primitives.hashes.HashAlgorithm]
        if alg == "HS256":
            hashalg = cryptography.hazmat.primitives.hashes.SHA256
            hashbytes = 32
        elif alg == "HS384":
            hashalg = cryptography.hazmat.primitives.hashes.SHA384
            hashbytes = 48
        elif alg == "HS512":
            hashalg = cryptography.hazmat.primitives.hashes.SHA512
            hashbytes = 64
        else:
            raise BackendException(
                f"Unsupported MAC key algorithm for cryptography backend: {alg}"
            )
        key_bytes = base64.urlsafe_b64decode(key)
        if len(key_bytes) < hashbytes:
            raise BackendException(
                f"{alg} key must be at least {hashbytes} bytes long (after Base64 decoding)"
            )
        return {
            "mac_obj": lambda: cryptography.hazmat.primitives.hmac.HMAC(
                key_bytes, hashalg()
            ),
            "type": "hmac",
            "alg": alg,
            "jwk": {
                "kty": "oct",
                "k": key,
            },
        }

    def get_ordered_csr_identifiers(
        self,
        *,
        csr_filename: str | os.PathLike | None = None,
        csr_content: str | bytes | None = None,
    ) -> list[tuple[str, str]]:
        """
        Return a list of requested identifiers (CN and SANs) for the CSR.
        Each identifier is a pair (type, identifier), where type is either
        'dns' or 'ip'.

        The list is deduplicated, and if a CNAME is present, it will be returned
        as the first element in the result.
        """
        if csr_content is None:
            if csr_filename is None:
                raise BackendException(
                    "One of csr_content and csr_filename has to be provided"
                )
            b_csr_content = read_file(csr_filename)
        else:
            b_csr_content = to_bytes(csr_content)
        csr = cryptography.x509.load_pem_x509_csr(b_csr_content)

        identifiers = set()
        result = []

        def add_identifier(identifier: tuple[str, str]) -> None:
            if identifier in identifiers:
                return
            identifiers.add(identifier)
            result.append(identifier)

        for sub in csr.subject:
            if sub.oid == cryptography.x509.oid.NameOID.COMMON_NAME:
                add_identifier(("dns", t.cast(str, sub.value)))
        for extension in csr.extensions:
            if (
                extension.oid
                == cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ):
                for name in extension.value:
                    if isinstance(name, cryptography.x509.DNSName):
                        add_identifier(("dns", name.value))
                    elif isinstance(name, cryptography.x509.IPAddress):
                        add_identifier(("ip", name.value.compressed))
                    else:
                        raise BackendException(
                            f"Found unsupported SAN identifier {name}"
                        )
        return result

    def get_csr_identifiers(
        self,
        *,
        csr_filename: str | os.PathLike | None = None,
        csr_content: str | bytes | bytes | None = None,
    ) -> set[tuple[str, str]]:
        """
        Return a set of requested identifiers (CN and SANs) for the CSR.
        Each identifier is a pair (type, identifier), where type is either
        'dns' or 'ip'.
        """
        return set(
            self.get_ordered_csr_identifiers(
                csr_filename=csr_filename, csr_content=csr_content
            )
        )

    def get_cert_days(
        self,
        *,
        cert_filename: str | os.PathLike | None = None,
        cert_content: str | bytes | None = None,
        now: datetime.datetime | None = None,
    ) -> int:
        """
        Return the days the certificate in cert_filename remains valid and -1
        if the file was not found. If cert_filename contains more than one
        certificate, only the first one will be considered.

        If now is not specified, datetime.datetime.now() is used.
        """
        if cert_filename is not None:
            cert_content = None
            if os.path.exists(cert_filename):
                cert_content = read_file(cert_filename)
        else:
            cert_content = to_bytes(cert_content)

        if cert_content is None:
            return -1

        # Make sure we have at most one PEM. Otherwise cryptography 36.0.0 will barf.
        b_cert_content = to_bytes(extract_first_pem(to_text(cert_content)) or "")

        try:
            cert = cryptography.x509.load_pem_x509_certificate(b_cert_content)
        except Exception as e:
            if cert_filename is None:
                raise BackendException(f"Cannot parse certificate: {e}") from e
            raise BackendException(
                f"Cannot parse certificate {cert_filename}: {e}"
            ) from e

        if now is None:
            now = self.get_now()
        else:
            now = add_or_remove_timezone(now, with_timezone=CRYPTOGRAPHY_TIMEZONE)
        return (get_not_valid_after(cert) - now).days

    def create_chain_matcher(self, *, criterium: Criterium) -> ChainMatcher:
        """
        Given a Criterium object, creates a ChainMatcher object.
        """
        return CryptographyChainMatcher(criterium=criterium, module=self.module)

    def get_cert_information(
        self,
        *,
        cert_filename: str | os.PathLike | None = None,
        cert_content: str | bytes | None = None,
    ) -> CertificateInformation:
        """
        Return some information on a X.509 certificate as a CertificateInformation object.
        """
        if cert_filename is not None:
            cert_content = read_file(cert_filename)
        else:
            cert_content = to_bytes(cert_content)

        # Make sure we have at most one PEM. Otherwise cryptography 36.0.0 will barf.
        b_cert_content = to_bytes(extract_first_pem(to_text(cert_content)) or "")

        try:
            cert = cryptography.x509.load_pem_x509_certificate(b_cert_content)
        except Exception as e:
            if cert_filename is None:
                raise BackendException(f"Cannot parse certificate: {e}") from e
            raise BackendException(
                f"Cannot parse certificate {cert_filename}: {e}"
            ) from e

        ski = None
        try:
            ext_ski = cert.extensions.get_extension_for_class(
                cryptography.x509.SubjectKeyIdentifier
            )
            ski = ext_ski.value.digest
        except cryptography.x509.ExtensionNotFound:
            pass

        aki = None
        try:
            ext_aki = cert.extensions.get_extension_for_class(
                cryptography.x509.AuthorityKeyIdentifier
            )
            aki = ext_aki.value.key_identifier
        except cryptography.x509.ExtensionNotFound:
            pass

        return CertificateInformation(
            not_valid_after=get_not_valid_after(cert),
            not_valid_before=get_not_valid_before(cert),
            serial_number=cert.serial_number,
            subject_key_identifier=ski,
            authority_key_identifier=aki,
        )


__all__ = (
    "CRYPTOGRAPHY_MINIMAL_VERSION",
    "CRYPTOGRAPHY_ERROR",
    "CRYPTOGRAPHY_VERSION",
    "CRYPTOGRAPHY_ERROR",
    "CryptographyBackend",
)
