# Copyright (c) 2019, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import typing as t

from ansible_collections.community.crypto.plugins.module_utils._version import (
    LooseVersion as _LooseVersion,
)


try:
    import cryptography
    from cryptography import x509
except ImportError:
    # Error handled in the calling module.
    pass

from ansible_collections.community.crypto.plugins.module_utils._crypto._obj2txt import (
    obj2txt,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    HAS_CRYPTOGRAPHY,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    CRYPTOGRAPHY_TIMEZONE,
    cryptography_decode_name,
)


if t.TYPE_CHECKING:
    import datetime  # pragma: no cover


# TODO: once cryptography has a _utc variant of InvalidityDate.invalidity_date, set this
#       to True and adjust get_invalidity_date() accordingly.
#       (https://github.com/pyca/cryptography/issues/10818)
CRYPTOGRAPHY_TIMEZONE_INVALIDITY_DATE = False  # pylint: disable=invalid-name
if HAS_CRYPTOGRAPHY:
    CRYPTOGRAPHY_TIMEZONE_INVALIDITY_DATE = _LooseVersion(
        cryptography.__version__
    ) >= _LooseVersion("43.0.0")

TIMESTAMP_FORMAT = "%Y%m%d%H%M%SZ"


if HAS_CRYPTOGRAPHY:
    REVOCATION_REASON_MAP = {
        "unspecified": x509.ReasonFlags.unspecified,
        "key_compromise": x509.ReasonFlags.key_compromise,
        "ca_compromise": x509.ReasonFlags.ca_compromise,
        "affiliation_changed": x509.ReasonFlags.affiliation_changed,
        "superseded": x509.ReasonFlags.superseded,
        "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
        "certificate_hold": x509.ReasonFlags.certificate_hold,
        "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
        "aa_compromise": x509.ReasonFlags.aa_compromise,
        "remove_from_crl": x509.ReasonFlags.remove_from_crl,
    }
    REVOCATION_REASON_MAP_INVERSE = {}
    for k, v in REVOCATION_REASON_MAP.items():
        REVOCATION_REASON_MAP_INVERSE[v] = k

else:
    REVOCATION_REASON_MAP = {}
    REVOCATION_REASON_MAP_INVERSE = {}


def cryptography_decode_revoked_certificate(
    cert: x509.RevokedCertificate,
) -> dict[str, t.Any]:
    result = {
        "serial_number": cert.serial_number,
        "revocation_date": get_revocation_date(cert),
        "issuer": None,
        "issuer_critical": False,
        "reason": None,
        "reason_critical": False,
        "invalidity_date": None,
        "invalidity_date_critical": False,
    }
    try:
        ext_ci = cert.extensions.get_extension_for_class(x509.CertificateIssuer)
        result["issuer"] = list(ext_ci.value)
        result["issuer_critical"] = ext_ci.critical
    except x509.ExtensionNotFound:
        pass
    try:
        ext_cr = cert.extensions.get_extension_for_class(x509.CRLReason)
        result["reason"] = ext_cr.value.reason
        result["reason_critical"] = ext_cr.critical
    except x509.ExtensionNotFound:
        pass
    try:
        ext_id = cert.extensions.get_extension_for_class(x509.InvalidityDate)
        result["invalidity_date"] = get_invalidity_date(ext_id.value)
        result["invalidity_date_critical"] = ext_id.critical
    except x509.ExtensionNotFound:
        pass
    return result


def cryptography_dump_revoked(
    entry: dict[str, t.Any],
    *,
    idn_rewrite: t.Literal["ignore", "idna", "unicode"] = "ignore",
) -> dict[str, t.Any]:
    return {
        "serial_number": entry["serial_number"],
        "revocation_date": entry["revocation_date"].strftime(TIMESTAMP_FORMAT),
        "issuer": (
            [
                cryptography_decode_name(issuer, idn_rewrite=idn_rewrite)
                for issuer in entry["issuer"]
            ]
            if entry["issuer"] is not None
            else None
        ),
        "issuer_critical": entry["issuer_critical"],
        "reason": (
            REVOCATION_REASON_MAP_INVERSE.get(entry["reason"])
            if entry["reason"] is not None
            else None
        ),
        "reason_critical": entry["reason_critical"],
        "invalidity_date": (
            entry["invalidity_date"].strftime(TIMESTAMP_FORMAT)
            if entry["invalidity_date"] is not None
            else None
        ),
        "invalidity_date_critical": entry["invalidity_date_critical"],
    }


def cryptography_get_signature_algorithm_oid_from_crl(
    crl: x509.CertificateRevocationList,
) -> x509.oid.ObjectIdentifier:
    try:
        return crl.signature_algorithm_oid
    except AttributeError:
        # Older cryptography versions do not have signature_algorithm_oid yet
        dotted = obj2txt(
            crl._backend._lib,  # type: ignore[attr-defined]  # pylint: disable=protected-access
            crl._backend._ffi,  # type: ignore[attr-defined]  # pylint: disable=protected-access
            crl._x509_crl.sig_alg.algorithm,  # type: ignore[attr-defined]  # pylint: disable=protected-access
        )
        return x509.oid.ObjectIdentifier(dotted)


def get_next_update(obj: x509.CertificateRevocationList) -> datetime.datetime | None:
    if CRYPTOGRAPHY_TIMEZONE:
        return obj.next_update_utc
    return obj.next_update


def get_last_update(obj: x509.CertificateRevocationList) -> datetime.datetime:
    if CRYPTOGRAPHY_TIMEZONE:
        return obj.last_update_utc
    return obj.last_update


def get_revocation_date(obj: x509.RevokedCertificate) -> datetime.datetime:
    if CRYPTOGRAPHY_TIMEZONE:
        return obj.revocation_date_utc
    return obj.revocation_date


def get_invalidity_date(obj: x509.InvalidityDate) -> datetime.datetime:
    if CRYPTOGRAPHY_TIMEZONE_INVALIDITY_DATE:
        return obj.invalidity_date_utc
    return obj.invalidity_date


def set_next_update(
    builder: x509.CertificateRevocationListBuilder, *, value: datetime.datetime
) -> x509.CertificateRevocationListBuilder:
    return builder.next_update(value)


def set_last_update(
    builder: x509.CertificateRevocationListBuilder, *, value: datetime.datetime
) -> x509.CertificateRevocationListBuilder:
    return builder.last_update(value)


def set_revocation_date(
    builder: x509.RevokedCertificateBuilder, *, value: datetime.datetime
) -> x509.RevokedCertificateBuilder:
    return builder.revocation_date(value)


__all__ = (
    "REVOCATION_REASON_MAP",
    "REVOCATION_REASON_MAP_INVERSE",
    "cryptography_decode_revoked_certificate",
    "cryptography_dump_revoked",
    "cryptography_get_signature_algorithm_oid_from_crl",
    "get_next_update",
    "get_last_update",
    "get_revocation_date",
    "get_invalidity_date",
    "set_next_update",
    "set_last_update",
    "set_revocation_date",
)
