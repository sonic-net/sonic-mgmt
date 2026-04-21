# Copyright (c) 2019, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import traceback
import typing as t
from urllib.parse import (
    ParseResult,
    urlparse,
    urlunparse,
)

from ansible.module_utils.common.text.converters import to_bytes, to_text

from ansible_collections.community.crypto.plugins.module_utils._crypto._asn1 import (
    serialize_asn1_string_as_der,
)
from ansible_collections.community.crypto.plugins.module_utils._version import (
    LooseVersion,
)


try:
    import cryptography
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        load_key_and_certificates as _load_key_and_certificates,
    )

    _HAS_CRYPTOGRAPHY = True
except ImportError:
    # Error handled in the calling module.
    _HAS_CRYPTOGRAPHY = False

try:
    import cryptography.hazmat.primitives.asymmetric.dh
    import cryptography.hazmat.primitives.asymmetric.ed448
    import cryptography.hazmat.primitives.asymmetric.ed25519
    import cryptography.hazmat.primitives.asymmetric.rsa
    import cryptography.hazmat.primitives.asymmetric.x448
    import cryptography.hazmat.primitives.asymmetric.x25519
except ImportError:
    pass

try:
    # This is a separate try/except since this is only present in cryptography 36.0.0 or newer
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        load_pkcs12 as _load_pkcs12,
    )
except ImportError:
    # Error handled in the calling module.
    _load_pkcs12 = None  # type: ignore

try:
    import idna

    HAS_IDNA = True
except ImportError:
    HAS_IDNA = False
    IDNA_IMP_ERROR = traceback.format_exc()

from ansible.module_utils.basic import missing_required_lib

from ansible_collections.community.crypto.plugins.module_utils._crypto._obj2txt import (
    obj2txt,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto._objects import (
    NORMALIZE_NAMES,
    NORMALIZE_NAMES_SHORT,
    OID_LOOKUP,
    OID_MAP,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)


if t.TYPE_CHECKING:
    import datetime  # pragma: no cover

    from cryptography.hazmat.primitives import hashes  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.dh import (  # pragma: no cover
        DHPrivateKey,
        DHPublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.dsa import (  # pragma: no cover
        DSAPrivateKey,
        DSAPublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ec import (  # pragma: no cover
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (  # pragma: no cover
        RSAPrivateKey,
        RSAPublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.types import (  # pragma: no cover
        CertificateIssuerPrivateKeyTypes,
        CertificateIssuerPublicKeyTypes,
        CertificatePublicKeyTypes,
        PrivateKeyTypes,
        PublicKeyTypes,
    )

    CertificatePrivateKeyTypes = t.Union[  # noqa: UP007
        CertificateIssuerPrivateKeyTypes,
        cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey,
        cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey,
    ]  # pragma: no cover
    PublicKeyTypesWOEdwards = t.Union[  # noqa: UP007 # pylint: disable=invalid-name
        DHPublicKey, DSAPublicKey, EllipticCurvePublicKey, RSAPublicKey
    ]  # pragma: no cover
    PrivateKeyTypesWOEdwards = t.Union[  # noqa: UP007 # pylint: disable=invalid-name
        DHPrivateKey, DSAPrivateKey, EllipticCurvePrivateKey, RSAPrivateKey
    ]  # pragma: no cover
else:
    PublicKeyTypesWOEdwards = None  # pylint: disable=invalid-name
    PrivateKeyTypesWOEdwards = None  # pylint: disable=invalid-name


CRYPTOGRAPHY_TIMEZONE = False  # pylint: disable=invalid-name
_CRYPTOGRAPHY_36_0_OR_NEWER = False  # pylint: disable=invalid-name
if _HAS_CRYPTOGRAPHY:
    CRYPTOGRAPHY_TIMEZONE = LooseVersion(cryptography.__version__) >= LooseVersion(
        "42.0.0"
    )

    _CRYPTOGRAPHY_36_0_OR_NEWER = LooseVersion(
        cryptography.__version__
    ) >= LooseVersion("36.0")

DOTTED_OID = re.compile(r"^\d+(?:\.\d+)+$")


def cryptography_get_extensions_from_cert(
    cert: x509.Certificate,
) -> dict[str, dict[str, bool | str]]:
    result = {}

    if _CRYPTOGRAPHY_36_0_OR_NEWER:
        for ext in cert.extensions:
            result[ext.oid.dotted_string] = {
                "critical": ext.critical,
                "value": base64.b64encode(ext.value.public_bytes()).decode("ascii"),
            }
    else:
        # Since cryptography will not give us the DER value for an extension
        # (that is only stored for unrecognized extensions), we have to re-do
        # the extension parsing ourselves.
        from cryptography.hazmat.backends import default_backend

        backend = default_backend()

        # We access a *lot* of internal APIs here, so let's disable that message...
        # pylint: disable=protected-access

        x509_obj = cert._x509  # type: ignore
        # With cryptography 35.0.0, we can no longer use obj2txt. Unfortunately it still does
        # not allow to get the raw value of an extension, so we have to use this ugly hack:
        exts = list(cert.extensions)

        for i in range(backend._lib.X509_get_ext_count(x509_obj)):
            ext = backend._lib.X509_get_ext(x509_obj, i)
            if ext == backend._ffi.NULL:
                continue
            crit = backend._lib.X509_EXTENSION_get_critical(ext)
            data = backend._lib.X509_EXTENSION_get_data(ext)
            backend.openssl_assert(data != backend._ffi.NULL)
            der = backend._ffi.buffer(data.data, data.length)[:]
            entry = {
                "critical": (crit == 1),
                "value": base64.b64encode(der).decode("ascii"),
            }
            try:
                oid = obj2txt(
                    backend._lib,
                    backend._ffi,
                    backend._lib.X509_EXTENSION_get_object(ext),
                )
            except AttributeError:
                oid = exts[i].oid.dotted_string
            result[oid] = entry

    return result


def cryptography_get_extensions_from_csr(
    csr: x509.CertificateSigningRequest,
) -> dict[str, dict[str, bool | str]]:
    result = {}

    if _CRYPTOGRAPHY_36_0_OR_NEWER:
        for ext in csr.extensions:
            result[ext.oid.dotted_string] = {
                "critical": ext.critical,
                "value": base64.b64encode(ext.value.public_bytes()).decode("ascii"),
            }

    else:
        # Since cryptography will not give us the DER value for an extension
        # (that is only stored for unrecognized extensions), we have to re-do
        # the extension parsing ourselves.
        from cryptography.hazmat.backends import default_backend

        backend = default_backend()

        # We access a *lot* of internal APIs here, so let's disable that message...
        # pylint: disable=protected-access

        extensions = backend._lib.X509_REQ_get_extensions(csr._x509_req)  # type: ignore
        extensions = backend._ffi.gc(
            extensions,
            lambda ext: backend._lib.sk_X509_EXTENSION_pop_free(
                ext,
                backend._ffi.addressof(
                    backend._lib._original_lib, "X509_EXTENSION_free"
                ),
            ),
        )

        # With cryptography 35.0.0, we can no longer use obj2txt. Unfortunately it still does
        # not allow to get the raw value of an extension, so we have to use this ugly hack:
        exts = list(csr.extensions)

        for i in range(backend._lib.sk_X509_EXTENSION_num(extensions)):
            ext = backend._lib.sk_X509_EXTENSION_value(extensions, i)
            if ext == backend._ffi.NULL:
                continue
            crit = backend._lib.X509_EXTENSION_get_critical(ext)
            data = backend._lib.X509_EXTENSION_get_data(ext)
            backend.openssl_assert(data != backend._ffi.NULL)
            der: bytes = backend._ffi.buffer(data.data, data.length)[:]  # type: ignore
            entry = {
                "critical": (crit == 1),
                "value": base64.b64encode(der).decode("ascii"),
            }
            try:
                oid = obj2txt(
                    backend._lib,
                    backend._ffi,
                    backend._lib.X509_EXTENSION_get_object(ext),
                )
            except AttributeError:
                oid = exts[i].oid.dotted_string
            result[oid] = entry

    return result


def cryptography_name_to_oid(name: str) -> x509.oid.ObjectIdentifier:
    dotted = OID_LOOKUP.get(name)
    if dotted is None:
        if DOTTED_OID.match(name):
            return x509.oid.ObjectIdentifier(name)
        raise OpenSSLObjectError(f'Cannot find OID for "{name}"')
    return x509.oid.ObjectIdentifier(dotted)


def cryptography_oid_to_name(
    oid: x509.oid.ObjectIdentifier, *, short: bool = False
) -> str:
    dotted_string = oid.dotted_string
    names = OID_MAP.get(dotted_string)
    if names:
        name = names[0]
    else:
        try:
            name = oid._name  # pylint: disable=protected-access
            if name == "Unknown OID":
                name = dotted_string
        except AttributeError:
            name = dotted_string
    if short:
        return NORMALIZE_NAMES_SHORT.get(name, name)
    return NORMALIZE_NAMES.get(name, name)


def _get_hex(bytesstr: bytes) -> str:
    data = binascii.hexlify(bytesstr)
    return to_text(b":".join(data[i : i + 2] for i in range(0, len(data), 2)))


@t.overload
def _parse_hex(bytesstr: bytes | str) -> bytes: ...


@t.overload
def _parse_hex(bytesstr: bytes | str | None) -> bytes | None: ...


def _parse_hex(bytesstr: bytes | str | None) -> bytes | None:
    if bytesstr is None:
        return bytesstr
    data = "".join(
        [
            ("0" * (2 - len(p)) + p) if len(p) < 2 else p
            for p in to_text(bytesstr).split(":")
        ]
    )
    return binascii.unhexlify(data)


DN_COMPONENT_START_RE = re.compile(b"^ *([a-zA-z0-9.]+) *= *")
DN_HEX_LETTER = b"0123456789abcdef"


def _int_to_byte(value: int) -> bytes:
    return bytes((value,))


def _parse_dn_component(
    name: bytes, *, sep: bytes = b",", decode_remainder: bool = True
) -> tuple[x509.NameAttribute, bytes]:
    m = DN_COMPONENT_START_RE.match(name)
    if not m:
        raise OpenSSLObjectError(f'cannot start part in "{to_text(name)}"')
    oid = cryptography_name_to_oid(to_text(m.group(1)))
    idx = len(m.group(0))
    decoded_name = []
    sep_str = sep + b"\\"
    if decode_remainder:
        length = len(name)
        if length > idx and name[idx : idx + 1] == b"#":
            # Decoding a hex string
            idx += 1
            while idx + 1 < length:
                ch1 = name[idx : idx + 1]
                ch2 = name[idx + 1 : idx + 2]
                idx1 = DN_HEX_LETTER.find(ch1.lower())
                idx2 = DN_HEX_LETTER.find(ch2.lower())
                if idx1 < 0 or idx2 < 0:
                    raise OpenSSLObjectError(
                        f'Invalid hex sequence entry "{to_text(ch1 + ch2)}"'
                    )
                idx += 2
                decoded_name.append(_int_to_byte(idx1 * 16 + idx2))
        else:
            # Decoding a regular string
            while idx < length:
                i = idx
                while i < length and name[i : i + 1] not in sep_str:
                    i += 1
                if i > idx:
                    decoded_name.append(name[idx:i])
                    idx = i
                while idx + 1 < length and name[idx : idx + 1] == b"\\":
                    ch = name[idx + 1 : idx + 2]
                    idx1 = DN_HEX_LETTER.find(ch.lower())
                    if idx1 >= 0:
                        if idx + 2 >= length:
                            raise OpenSSLObjectError(
                                f'Hex escape sequence "\\{to_text(ch)}" incomplete at end of string'
                            )
                        ch2 = name[idx + 2 : idx + 3]
                        idx2 = DN_HEX_LETTER.find(ch2.lower())
                        if idx2 < 0:
                            raise OpenSSLObjectError(
                                f'Hex escape sequence "\\{to_text(ch + ch2)}" has invalid second letter'
                            )
                        ch = _int_to_byte(idx1 * 16 + idx2)
                        idx += 1
                    idx += 2
                    decoded_name.append(ch)
                if idx < length and name[idx : idx + 1] == sep:
                    break
    else:
        decoded_name.append(name[idx:])
        idx = len(name)
    return x509.NameAttribute(oid, to_text(b"".join(decoded_name))), name[idx:]


def _parse_dn(name: bytes) -> list[x509.NameAttribute]:
    """
    Parse a Distinguished Name.

    Can be of the form ``CN=Test, O = Something`` or ``CN = Test,O= Something``.
    """
    original_name = name
    name = name.lstrip()
    sep = b","
    if name.startswith(b"/"):
        sep = b"/"
        name = name[1:]
    result = []
    while name:
        try:
            attribute, name = _parse_dn_component(name, sep=sep)
        except OpenSSLObjectError as e:
            raise OpenSSLObjectError(
                f"Error while parsing distinguished name {to_text(original_name)!r}: {e}"
            ) from e
        result.append(attribute)
        if name:
            if name[0:1] != sep or len(name) < 2:
                raise OpenSSLObjectError(
                    f"Error while parsing distinguished name {to_text(original_name)!r}: unexpected end of string"
                )
            name = name[1:]
    return result


def cryptography_parse_relative_distinguished_name(
    rdn: list[str | bytes],
) -> cryptography.x509.RelativeDistinguishedName:
    names = []
    for part in rdn:
        try:
            names.append(_parse_dn_component(to_bytes(part), decode_remainder=False)[0])
        except OpenSSLObjectError as e:
            raise OpenSSLObjectError(
                f"Error while parsing relative distinguished name {to_text(part)!r}: {e}"
            ) from e
    return cryptography.x509.RelativeDistinguishedName(names)


def _is_ascii(value: str) -> bool:
    """Check whether the Unicode string `value` contains only ASCII characters."""
    try:
        value.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def _adjust_idn(
    value: str, *, idn_rewrite: t.Literal["ignore", "idna", "unicode"]
) -> str:
    if idn_rewrite == "ignore" or not value:
        return value
    if idn_rewrite == "idna" and _is_ascii(value):
        return value
    if idn_rewrite not in ("idna", "unicode"):
        raise ValueError(f'Invalid value for idn_rewrite: "{idn_rewrite}"')
    if not HAS_IDNA:
        what = "IDNA" if idn_rewrite == "unicode" else "Unicode"
        dest = "Unicode" if idn_rewrite == "unicode" else "IDNA"
        raise OpenSSLObjectError(
            missing_required_lib(
                "idna",
                reason=f'to transform {what} DNS name "{value}" to {dest}',
            )
        )
    # Since IDNA does not like '*' or empty labels (except one empty label at the end),
    # we split and let IDNA only handle labels that are neither empty or '*'.
    parts = value.split(".")
    for index, part in enumerate(parts):
        if part in ("", "*"):
            continue
        try:
            if idn_rewrite == "idna":
                parts[index] = idna.encode(part).decode("ascii")
            elif idn_rewrite == "unicode" and part.startswith("xn--"):
                parts[index] = idna.decode(part)
        except idna.IDNAError as exc2008:
            try:
                if idn_rewrite == "idna":
                    parts[index] = part.encode("idna").decode("ascii")
                elif idn_rewrite == "unicode" and part.startswith("xn--"):
                    parts[index] = part.encode("ascii").decode("idna")
            except Exception as exc2003:
                what = "IDNA" if idn_rewrite == "unicode" else "Unicode"
                dest = "Unicode" if idn_rewrite == "unicode" else "IDNA"
                raise OpenSSLObjectError(
                    f'Error while transforming part "{part}" of {what} DNS name "{value}" to {dest}.'
                    f' IDNA2008 transformation resulted in "{exc2008}", IDNA2003 transformation resulted in "{exc2003}".'
                ) from exc2003
    return ".".join(parts)


def _adjust_idn_email(
    value: str, *, idn_rewrite: t.Literal["ignore", "idna", "unicode"]
) -> str:
    idx = value.find("@")
    if idx < 0:
        return value
    return f"{value[:idx]}@{_adjust_idn(value[idx + 1 :], idn_rewrite=idn_rewrite)}"


def _adjust_idn_url(
    value: str, *, idn_rewrite: t.Literal["ignore", "idna", "unicode"]
) -> str:
    url = urlparse(value)
    host = _adjust_idn(url.hostname, idn_rewrite=idn_rewrite) if url.hostname else None
    if url.username is not None and url.password is not None:
        host = f"{url.username}:{url.password}@{host}"
    elif url.username is not None:
        host = f"{url.username}@{host}"
    if url.port is not None:
        host = f"{host}:{url.port}"
    return urlunparse(
        ParseResult(
            scheme=url.scheme,
            netloc=host or "",
            path=url.path,
            params=url.params,
            query=url.query,
            fragment=url.fragment,
        )
    )


def cryptography_get_name(
    name: str, *, what: str = "Subject Alternative Name"
) -> x509.GeneralName:
    """
    Given a name string, returns a cryptography x509.GeneralName object.
    Raises an OpenSSLObjectError if the name is unknown or cannot be parsed.
    """
    try:
        if name.startswith("DNS:"):
            return x509.DNSName(_adjust_idn(to_text(name[4:]), idn_rewrite="idna"))
        if name.startswith("IP:"):
            address = to_text(name[3:])
            if "/" in address:
                return x509.IPAddress(ipaddress.ip_network(address))
            return x509.IPAddress(ipaddress.ip_address(address))
        if name.startswith("email:"):
            return x509.RFC822Name(
                _adjust_idn_email(to_text(name[6:]), idn_rewrite="idna")
            )
        if name.startswith("URI:"):
            return x509.UniformResourceIdentifier(
                _adjust_idn_url(to_text(name[4:]), idn_rewrite="idna")
            )
        if name.startswith("RID:"):
            m = re.match(r"^([0-9]+(?:\.[0-9]+)*)$", to_text(name[4:]))
            if not m:
                raise OpenSSLObjectError(f'Cannot parse {what} "{name}"')
            return x509.RegisteredID(x509.oid.ObjectIdentifier(m.group(1)))
        if name.startswith("otherName:"):
            # otherName can either be a raw ASN.1 hex string or in the format that OpenSSL works with.
            m = re.match(
                r"^([0-9]+(?:\.[0-9]+)*);([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2})*)$",
                to_text(name[10:]),
            )
            if m:
                return x509.OtherName(
                    x509.oid.ObjectIdentifier(m.group(1)), _parse_hex(m.group(2))
                )

            # See https://www.openssl.org/docs/man1.0.2/man5/x509v3_config.html - Subject Alternative Name for more
            # defailts on the format expected.
            name = to_text(name[10:], errors="surrogate_or_strict")
            if ";" not in name:
                raise OpenSSLObjectError(
                    f'Cannot parse {what} otherName "{name}", must be in the '
                    'format "otherName:<OID>;<ASN.1 OpenSSL Encoded String>" or '
                    '"otherName:<OID>;<hex string>"'
                )

            oid, value = name.split(";", 1)
            b_value = serialize_asn1_string_as_der(value)
            return x509.OtherName(x509.ObjectIdentifier(oid), b_value)
        if name.startswith("dirName:"):
            return x509.DirectoryName(
                x509.Name(reversed(_parse_dn(to_bytes(name[8:]))))
            )
    except Exception as e:
        raise OpenSSLObjectError(f'Cannot parse {what} "{name}": {e}') from e
    if ":" not in name:
        raise OpenSSLObjectError(
            f'Cannot parse {what} "{name}" (forgot "DNS:" prefix?)'
        )
    raise OpenSSLObjectError(
        f'Cannot parse {what} "{name}" (potentially unsupported by cryptography backend)'
    )


def _dn_escape_value(value: str) -> str:
    """
    Escape Distinguished Name's attribute value.
    """
    value = value.replace("\\", "\\\\")
    for ch in [",", "+", "<", ">", ";", '"']:
        value = value.replace(ch, f"\\{ch}")
    value = value.replace("\0", "\\00")
    if value.startswith((" ", "#")):
        value = f"\\{value[0]}{value[1:]}"
    if value.endswith(" "):
        value = f"{value[:-1]}\\ "
    return value


def cryptography_decode_name(
    name: x509.GeneralName,
    *,
    idn_rewrite: t.Literal["ignore", "idna", "unicode"] = "ignore",
) -> str:
    """
    Given a cryptography x509.GeneralName object, returns a string.
    Raises an OpenSSLObjectError if the name is not supported.
    """
    if idn_rewrite not in ("ignore", "idna", "unicode"):
        raise AssertionError(  # pragma: no cover
            'idn_rewrite must be one of "ignore", "idna", or "unicode"'
        )
    if isinstance(name, x509.DNSName):
        return f"DNS:{_adjust_idn(name.value, idn_rewrite=idn_rewrite)}"
    if isinstance(name, x509.IPAddress):
        if isinstance(name.value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return f"IP:{name.value.network_address.compressed}/{name.value.prefixlen}"
        return f"IP:{name.value.compressed}"
    if isinstance(name, x509.RFC822Name):
        return f"email:{_adjust_idn_email(name.value, idn_rewrite=idn_rewrite)}"
    if isinstance(name, x509.UniformResourceIdentifier):
        return f"URI:{_adjust_idn_url(name.value, idn_rewrite=idn_rewrite)}"
    if isinstance(name, x509.DirectoryName):
        # According to https://datatracker.ietf.org/doc/html/rfc4514.html#section-2.1 the
        # list needs to be reversed, and joined by commas
        return "dirName:" + ",".join(
            [
                f"{to_text(cryptography_oid_to_name(attribute.oid, short=True))}={_dn_escape_value(to_text(attribute.value))}"
                for attribute in reversed(list(name.value))
            ]
        )
    if isinstance(name, x509.RegisteredID):
        return f"RID:{name.value.dotted_string}"
    if isinstance(name, x509.OtherName):
        return f"otherName:{name.type_id.dotted_string};{_get_hex(name.value)}"
    raise OpenSSLObjectError(f'Cannot decode name "{name}"')


def _cryptography_get_keyusage(usage: str) -> str:
    """
    Given a key usage identifier string, returns the parameter name used by cryptography's x509.KeyUsage().
    Raises an OpenSSLObjectError if the identifier is unknown.
    """
    if usage in ("Digital Signature", "digitalSignature"):
        return "digital_signature"
    if usage in ("Non Repudiation", "nonRepudiation"):
        return "content_commitment"
    if usage in ("Key Encipherment", "keyEncipherment"):
        return "key_encipherment"
    if usage in ("Data Encipherment", "dataEncipherment"):
        return "data_encipherment"
    if usage in ("Key Agreement", "keyAgreement"):
        return "key_agreement"
    if usage in ("Certificate Sign", "keyCertSign"):
        return "key_cert_sign"
    if usage in ("CRL Sign", "cRLSign"):
        return "crl_sign"
    if usage in ("Encipher Only", "encipherOnly"):
        return "encipher_only"
    if usage in ("Decipher Only", "decipherOnly"):
        return "decipher_only"
    raise OpenSSLObjectError(f'Unknown key usage "{usage}"')


def cryptography_parse_key_usage_params(usages: t.Iterable[str]) -> dict[str, bool]:
    """
    Given a list of key usage identifier strings, returns the parameters for cryptography's x509.KeyUsage().
    Raises an OpenSSLObjectError if an identifier is unknown.
    """
    params = {
        "digital_signature": False,
        "content_commitment": False,
        "key_encipherment": False,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": False,
        "crl_sign": False,
        "encipher_only": False,
        "decipher_only": False,
    }
    for usage in usages:
        params[_cryptography_get_keyusage(usage)] = True
    return params


def cryptography_get_basic_constraints(
    constraints: t.Iterable[str] | None,
) -> tuple[bool, int | None]:
    """
    Given a list of constraints, returns a tuple (ca, path_length).
    Raises an OpenSSLObjectError if a constraint is unknown or cannot be parsed.
    """
    ca = False
    path_length: int | None = None
    if constraints:
        for constraint in constraints:
            if constraint.startswith("CA:"):
                if constraint == "CA:TRUE":
                    ca = True
                elif constraint == "CA:FALSE":
                    ca = False
                else:
                    raise OpenSSLObjectError(
                        f'Unknown basic constraint value "{constraint[3:]}" for CA'
                    )
            elif constraint.startswith("pathlen:"):
                v = constraint[len("pathlen:") :]
                try:
                    path_length = int(v)
                except Exception as e:
                    raise OpenSSLObjectError(
                        f'Cannot parse path length constraint "{v}" ({e})'
                    ) from e
            else:
                raise OpenSSLObjectError(f'Unknown basic constraint "{constraint}"')
    return ca, path_length


def cryptography_key_needs_digest_for_signing(
    key: CertificateIssuerPrivateKeyTypes,
) -> bool:
    """Tests whether the given private key requires a digest algorithm for signing.

    Ed25519 and Ed448 keys do not; they need None to be passed as the digest algorithm.
    """
    if isinstance(
        key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey
    ):
        return False
    return not isinstance(
        key, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey
    )


def _compare_public_keys(
    key1: PublicKeyTypes, key2: PublicKeyTypes, *, clazz: type[PublicKeyTypes]
) -> bool | None:
    a = isinstance(key1, clazz)
    b = isinstance(key2, clazz)
    if not (a or b):
        return None
    if not a or not b:
        return False
    a_bytes = key1.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    b_bytes = key2.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return a_bytes == b_bytes


def cryptography_compare_public_keys(
    key1: PublicKeyTypes, key2: PublicKeyTypes
) -> bool:
    """Tests whether two public keys are the same.

    Needs special logic for Ed25519 and Ed448 keys, since they do not have public_numbers().
    """
    res = _compare_public_keys(
        key1,
        key2,
        clazz=cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey,
    )
    if res is not None:
        return res
    res = _compare_public_keys(
        key1,
        key2,
        clazz=cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey,
    )
    if res is not None:
        return res
    res = _compare_public_keys(
        key1, key2, clazz=cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey
    )
    if res is not None:
        return res
    res = _compare_public_keys(
        key1, key2, clazz=cryptography.hazmat.primitives.asymmetric.x448.X448PublicKey
    )
    if res is not None:
        return res
    return (
        t.cast(PublicKeyTypesWOEdwards, key1).public_numbers()
        == t.cast(PublicKeyTypesWOEdwards, key2).public_numbers()
    )


def _compare_private_keys(
    key1: PrivateKeyTypes, key2: PrivateKeyTypes, *, clazz: type[PrivateKeyTypes]
) -> bool | None:
    a = isinstance(key1, clazz)
    b = isinstance(key2, clazz)
    if not (a or b):
        return None
    if not a or not b:
        return False
    encryption_algorithm = cryptography.hazmat.primitives.serialization.NoEncryption()
    a_bytes = key1.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        encryption_algorithm=encryption_algorithm,
    )
    b_bytes = key2.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        encryption_algorithm=encryption_algorithm,
    )
    return a_bytes == b_bytes


def cryptography_compare_private_keys(
    key1: PrivateKeyTypes, key2: PrivateKeyTypes
) -> bool:
    """Tests whether two private keys are the same.

    Needs special logic for Ed25519, X25519, and Ed448 keys, since they do not have private_numbers().
    """
    res = _compare_private_keys(
        key1,
        key2,
        clazz=cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey,
    )
    if res is not None:
        return res
    res = _compare_private_keys(
        key1,
        key2,
        clazz=cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey,
    )
    if res is not None:
        return res
    res = _compare_private_keys(
        key1,
        key2,
        clazz=cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey,
    )
    if res is not None:
        return res
    res = _compare_private_keys(
        key1, key2, clazz=cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey
    )
    if res is not None:
        return res
    return (
        t.cast(PrivateKeyTypesWOEdwards, key1).private_numbers()
        == t.cast(PrivateKeyTypesWOEdwards, key2).private_numbers()
    )


def parse_pkcs12(
    pkcs12_bytes: bytes, *, passphrase: bytes | str | None = None
) -> tuple[
    PrivateKeyTypes | None,
    x509.Certificate | None,
    list[x509.Certificate],
    bytes | None,
]:
    """Returns a tuple (private_key, certificate, additional_certificates, friendly_name)."""
    passphrase_bytes = None
    if passphrase is not None:
        passphrase_bytes = to_bytes(passphrase)

    # Main code for cryptography 36.0.0 and forward
    if _load_pkcs12 is not None:
        return _parse_pkcs12_36_0_0(pkcs12_bytes, passphrase=passphrase_bytes)

    if LooseVersion(cryptography.__version__) >= LooseVersion("35.0"):  # type: ignore[unreachable]
        return _parse_pkcs12_35_0_0(pkcs12_bytes, passphrase=passphrase_bytes)

    return _parse_pkcs12_legacy(pkcs12_bytes, passphrase=passphrase_bytes)


def _parse_pkcs12_36_0_0(
    pkcs12_bytes: bytes, *, passphrase: bytes | None = None
) -> tuple[
    PrivateKeyTypes | None,
    x509.Certificate | None,
    list[x509.Certificate],
    bytes | None,
]:
    # Requires cryptography 36.0.0 or newer
    pkcs12 = _load_pkcs12(pkcs12_bytes, passphrase)
    additional_certificates = [cert.certificate for cert in pkcs12.additional_certs]
    private_key = pkcs12.key
    certificate = None
    friendly_name = None
    if pkcs12.cert:
        certificate = pkcs12.cert.certificate
        friendly_name = pkcs12.cert.friendly_name
    return private_key, certificate, additional_certificates, friendly_name


def _parse_pkcs12_35_0_0(
    pkcs12_bytes: bytes, *, passphrase: bytes | None = None
) -> tuple[
    PrivateKeyTypes | None,
    x509.Certificate | None,
    list[x509.Certificate],
    bytes | None,
]:
    # Backwards compatibility code for cryptography 35.x
    private_key, certificate, additional_certificates = _load_key_and_certificates(
        pkcs12_bytes, passphrase
    )

    friendly_name = None
    if certificate:
        # See https://github.com/pyca/cryptography/issues/5760#issuecomment-842687238
        from cryptography.hazmat.backends import default_backend

        backend = default_backend()

        # We access a *lot* of internal APIs here, so let's disable that message...
        # pylint: disable=protected-access

        # This code basically does what load_key_and_certificates() does, but without error-checking.
        # Since load_key_and_certificates succeeded, it should not fail.
        pkcs12 = backend._ffi.gc(
            backend._lib.d2i_PKCS12_bio(
                backend._bytes_to_bio(pkcs12_bytes).bio,  # pylint: disable=no-member
                backend._ffi.NULL,
            ),
            backend._lib.PKCS12_free,
        )
        certificate_x509_ptr = backend._ffi.new("X509 **")
        with backend._zeroed_null_terminated_buf(  # pylint: disable=no-member
            to_bytes(passphrase) if passphrase is not None else None
        ) as passphrase_buffer:
            backend._lib.PKCS12_parse(
                pkcs12,
                passphrase_buffer,
                backend._ffi.new("EVP_PKEY **"),
                certificate_x509_ptr,
                backend._ffi.new("Cryptography_STACK_OF_X509 **"),
            )
        if certificate_x509_ptr[0] != backend._ffi.NULL:
            maybe_name = backend._lib.X509_alias_get0(
                certificate_x509_ptr[0], backend._ffi.NULL
            )
            if maybe_name != backend._ffi.NULL:
                friendly_name = backend._ffi.string(maybe_name)

    return private_key, certificate, additional_certificates, friendly_name


def _parse_pkcs12_legacy(
    pkcs12_bytes: bytes, *, passphrase: bytes | None = None
) -> tuple[
    PrivateKeyTypes | None,
    x509.Certificate | None,
    list[x509.Certificate],
    bytes | None,
]:
    # Backwards compatibility code for cryptography < 35.0.0
    private_key, certificate, additional_certificates = _load_key_and_certificates(
        pkcs12_bytes, passphrase
    )

    # We access a *lot* of internal APIs here, so let's disable that message...
    # pylint: disable=protected-access

    friendly_name = None
    if certificate:
        # See https://github.com/pyca/cryptography/issues/5760#issuecomment-842687238
        backend = certificate._backend  # type: ignore
        maybe_name = backend._lib.X509_alias_get0(certificate._x509, backend._ffi.NULL)  # type: ignore
        if maybe_name != backend._ffi.NULL:
            friendly_name = backend._ffi.string(maybe_name)
    return private_key, certificate, additional_certificates, friendly_name


def cryptography_verify_signature(
    *,
    signature: bytes,
    data: bytes,
    hash_algorithm: hashes.HashAlgorithm | None,
    signer_public_key: PublicKeyTypes,
) -> bool:
    """
    Check whether the given signature of the given data was signed by the given public key object.
    """
    try:
        if isinstance(
            signer_public_key,
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey,
        ):
            if hash_algorithm is None:
                raise OpenSSLObjectError("Need hash_algorithm for RSA keys")
            signer_public_key.verify(
                signature, data, padding.PKCS1v15(), hash_algorithm
            )
            return True
        if isinstance(
            signer_public_key,
            cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
        ):
            if hash_algorithm is None:
                raise OpenSSLObjectError("Need hash_algorithm for ECC keys")
            signer_public_key.verify(
                signature,
                data,
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(hash_algorithm),
            )
            return True
        if isinstance(
            signer_public_key,
            cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey,
        ):
            if hash_algorithm is None:
                raise OpenSSLObjectError("Need hash_algorithm for DSA keys")
            signer_public_key.verify(signature, data, hash_algorithm)
            return True
        if isinstance(
            signer_public_key,
            cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey,
        ):
            signer_public_key.verify(signature, data)
            return True
        if isinstance(
            signer_public_key,
            cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey,
        ):
            signer_public_key.verify(signature, data)
            return True
        raise OpenSSLObjectError(
            f"Unsupported public key type {type(signer_public_key)}"
        )
    except InvalidSignature:
        return False


def cryptography_verify_certificate_signature(
    *, certificate: x509.Certificate, signer_public_key: PublicKeyTypes
) -> bool:
    """
    Check whether the given X509 certificate object was signed by the given public key object.
    """
    return cryptography_verify_signature(
        signature=certificate.signature,
        data=certificate.tbs_certificate_bytes,
        hash_algorithm=certificate.signature_hash_algorithm,
        signer_public_key=signer_public_key,
    )


def get_not_valid_after(obj: x509.Certificate) -> datetime.datetime:
    if CRYPTOGRAPHY_TIMEZONE:
        return obj.not_valid_after_utc
    return obj.not_valid_after


def get_not_valid_before(obj: x509.Certificate) -> datetime.datetime:
    if CRYPTOGRAPHY_TIMEZONE:
        return obj.not_valid_before_utc
    return obj.not_valid_before


def set_not_valid_after(
    builder: x509.CertificateBuilder, value: datetime.datetime
) -> x509.CertificateBuilder:
    return builder.not_valid_after(value)


def set_not_valid_before(
    builder: x509.CertificateBuilder, value: datetime.datetime
) -> x509.CertificateBuilder:
    return builder.not_valid_before(value)


def is_potential_certificate_private_key(
    key: PrivateKeyTypes,
) -> t.TypeGuard[CertificatePrivateKeyTypes]:
    return not isinstance(
        key, cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey
    )


def is_potential_certificate_issuer_private_key(
    key: PrivateKeyTypes,
) -> t.TypeGuard[CertificateIssuerPrivateKeyTypes]:
    return not isinstance(
        key,
        (
            cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey,
            cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey,
            cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey,
        ),
    )


def is_potential_certificate_public_key(
    key: PublicKeyTypes,
) -> t.TypeGuard[CertificatePublicKeyTypes]:
    return not isinstance(key, DHPublicKey)


def is_potential_certificate_issuer_public_key(
    key: PublicKeyTypes,
) -> t.TypeGuard[CertificateIssuerPublicKeyTypes]:
    return not isinstance(
        key,
        (
            cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey,
            cryptography.hazmat.primitives.asymmetric.x448.X448PublicKey,
            cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey,
        ),
    )


__all__ = (
    "CRYPTOGRAPHY_TIMEZONE",
    "cryptography_get_extensions_from_cert",
    "cryptography_get_extensions_from_csr",
    "cryptography_name_to_oid",
    "cryptography_oid_to_name",
    "cryptography_parse_relative_distinguished_name",
    "cryptography_get_name",
    "cryptography_decode_name",
    "cryptography_parse_key_usage_params",
    "cryptography_get_basic_constraints",
    "cryptography_key_needs_digest_for_signing",
    "cryptography_compare_public_keys",
    "cryptography_compare_private_keys",
    "parse_pkcs12",
    "cryptography_verify_signature",
    "cryptography_verify_certificate_signature",
    "get_not_valid_after",
    "get_not_valid_before",
    "set_not_valid_after",
    "set_not_valid_before",
    "is_potential_certificate_private_key",
    "is_potential_certificate_issuer_private_key",
    "is_potential_certificate_public_key",
    "is_potential_certificate_issuer_public_key",
)
