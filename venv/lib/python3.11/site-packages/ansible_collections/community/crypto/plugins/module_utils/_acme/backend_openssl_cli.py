# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import base64
import binascii
import datetime
import ipaddress
import os
import re
import tempfile
import traceback
import typing as t

from ansible.module_utils.common.text.converters import to_bytes, to_text

from ansible_collections.community.crypto.plugins.module_utils._acme.backends import (
    CertificateInformation,
    CryptoBackend,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    BackendException,
    KeyParsingError,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.utils import (
    nopad_b64,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.math import (
    convert_bytes_to_int,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    ensure_utc_timezone,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.module_utils._acme.certificates import (  # pragma: no cover
        Criterium,
    )


_OPENSSL_ENVIRONMENT_UPDATE = {
    "LANG": "C",
    "LC_ALL": "C",
    "LC_MESSAGES": "C",
    "LC_CTYPE": "C",
}


def _extract_date(
    out_text: str, *, name: str, cert_filename_suffix: str = ""
) -> datetime.datetime:
    matcher = re.search(rf"\s+{name}\s*:\s+(.*)", out_text)
    if matcher is None:
        raise BackendException(f"No '{name}' date found{cert_filename_suffix}")
    date_str = matcher.group(1)
    try:
        # For some reason Python's strptime() does not return any timezone information,
        # even though the information is there and a supported timezone for all supported
        # Python implementations (GMT). So we have to modify the datetime object by
        # replacing it by UTC.
        return ensure_utc_timezone(
            datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        )
    except ValueError as exc:
        raise BackendException(
            f"Failed to parse '{name}' date{cert_filename_suffix}: {exc}"
        ) from exc


def _decode_octets(octets_text: str) -> bytes:
    return binascii.unhexlify(re.sub(r"(\s|:)", "", octets_text).encode("utf-8"))


@t.overload
def _extract_octets(
    out_text: str,
    *,
    name: str,
    required: t.Literal[False],
    potential_prefixes: t.Iterable[str] | None = None,
) -> bytes | None: ...


@t.overload
def _extract_octets(
    out_text: str,
    *,
    name: str,
    required: t.Literal[True],
    potential_prefixes: t.Iterable[str] | None = None,
) -> bytes: ...


def _extract_octets(
    out_text: str,
    *,
    name: str,
    required: bool = True,
    potential_prefixes: t.Iterable[str] | None = None,
) -> bytes | None:
    part = (
        f"(?:{'|'.join(re.escape(pp) for pp in potential_prefixes)})"
        if potential_prefixes
        else ""
    )
    regexp = rf"\s+{name}:\s*\n\s+{part}([A-Fa-f0-9]{{2}}(?::[A-Fa-f0-9]{{2}})*)\s*\n"
    match = re.search(regexp, out_text, re.MULTILINE | re.DOTALL)
    if match is not None:
        return _decode_octets(match.group(1))
    if not required:
        return None
    raise BackendException(f"No '{name}' octet string found")


class OpenSSLCLIBackend(CryptoBackend):
    def __init__(
        self, *, module: AnsibleModule, openssl_binary: str | None = None
    ) -> None:
        super().__init__(module=module, with_timezone=True)
        if openssl_binary is None:
            openssl_binary = module.get_bin_path("openssl", True)
        self.openssl_binary = openssl_binary

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
        if passphrase is not None:
            raise KeyParsingError("openssl backend does not support key passphrases")
        # If key_file is not given, but key_content, write that to a temporary file
        if key_file is None:
            if key_content is None:
                raise KeyParsingError(
                    "one of key_file and key_content must be specified"
                )
            fd, tmpsrc = tempfile.mkstemp()
            self.module.add_cleanup_file(tmpsrc)  # Ansible will delete the file on exit
            f = os.fdopen(fd, "wb")
            try:
                f.write(key_content.encode("utf-8"))
                key_file = tmpsrc
            except Exception as err:
                try:
                    f.close()
                except Exception:
                    pass
                raise KeyParsingError(
                    f"failed to create temporary content file: {err}",
                    exception=traceback.format_exc(),
                ) from err
            f.close()
        # Parse key
        account_key_type = None
        with open(key_file, "r", encoding="utf-8") as fi:
            for line in fi:
                m = re.match(
                    r"^\s*-{5,}BEGIN\s+(EC|RSA)\s+PRIVATE\s+KEY-{5,}\s*$", line
                )
                if m is not None:
                    account_key_type = m.group(1).lower()
                    break
        if account_key_type is None:
            # This happens for example if openssl_privatekey created this key
            # (as opposed to the OpenSSL binary). For now, we assume this is
            # an RSA key.
            # FIXME: add some kind of auto-detection
            account_key_type = "rsa"
        if account_key_type not in ("rsa", "ec"):
            raise KeyParsingError(f'unknown key type "{account_key_type}"')

        openssl_keydump_cmd = [
            self.openssl_binary,
            account_key_type,
            "-in",
            str(key_file),
            "-noout",
            "-text",
        ]
        rc, out, stderr = self.module.run_command(
            openssl_keydump_cmd,
            check_rc=False,
            environ_update=_OPENSSL_ENVIRONMENT_UPDATE,
        )
        if rc != 0:
            raise BackendException(
                f"Error while running {' '.join(openssl_keydump_cmd)}: {stderr}"
            )

        out_text = to_text(out, errors="surrogate_or_strict")

        if account_key_type == "rsa":
            matcher = re.search(
                r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent",
                out_text,
                re.MULTILINE | re.DOTALL,
            )
            if matcher is None:
                raise KeyParsingError("cannot parse RSA key: modulus not found")
            pub_hex = matcher.group(1)

            matcher = re.search(
                r"\npublicExponent: ([0-9]+)", out_text, re.MULTILINE | re.DOTALL
            )
            if matcher is None:
                raise KeyParsingError("cannot parse RSA key: public exponent not found")
            pub_exp = matcher.group(1)
            pub_exp = f"{int(pub_exp):x}"
            if len(pub_exp) % 2:
                pub_exp = f"0{pub_exp}"

            return {
                "key_file": str(key_file),
                "type": "rsa",
                "alg": "RS256",
                "jwk": {
                    "kty": "RSA",
                    "e": nopad_b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
                    "n": nopad_b64(_decode_octets(pub_hex)),
                },
                "hash": "sha256",
            }
        if account_key_type == "ec":
            pub_data = re.search(
                r"pub:\s*\n\s+04:([a-f0-9\:\s]+?)\nASN1 OID: (\S+)(?:\nNIST CURVE: (\S+))?",
                out_text,
                re.MULTILINE | re.DOTALL,
            )
            if pub_data is None:
                raise KeyParsingError("cannot parse elliptic curve key")
            pub_hex = _decode_octets(pub_data.group(1))
            asn1_oid_curve = pub_data.group(2).lower()
            nist_curve = pub_data.group(3).lower() if pub_data.group(3) else None
            if asn1_oid_curve == "prime256v1" or nist_curve == "p-256":
                bits = 256
                alg = "ES256"
                hashalg = "sha256"
                point_size = 32
                curve = "P-256"
            elif asn1_oid_curve == "secp384r1" or nist_curve == "p-384":
                bits = 384
                alg = "ES384"
                hashalg = "sha384"
                point_size = 48
                curve = "P-384"
            elif asn1_oid_curve == "secp521r1" or nist_curve == "p-521":
                # Not yet supported on Let's Encrypt side, see
                # https://github.com/letsencrypt/boulder/issues/2217
                bits = 521
                alg = "ES512"
                hashalg = "sha512"
                point_size = 66
                curve = "P-521"
            else:
                raise KeyParsingError(
                    f"unknown elliptic curve: {asn1_oid_curve} / {nist_curve}"
                )
            num_bytes = (bits + 7) // 8
            if len(pub_hex) != 2 * num_bytes:
                raise KeyParsingError(
                    f"bad elliptic curve point ({asn1_oid_curve} / {nist_curve})"
                )
            return {
                "key_file": key_file,
                "type": "ec",
                "alg": alg,
                "jwk": {
                    "kty": "EC",
                    "crv": curve,
                    "x": nopad_b64(pub_hex[:num_bytes]),
                    "y": nopad_b64(pub_hex[num_bytes:]),
                },
                "hash": hashalg,
                "point_size": point_size,
            }
        raise KeyParsingError(
            f"Internal error: unexpected account_key_type = {account_key_type!r}"
        )

    def sign(
        self, *, payload64: str, protected64: str, key_data: dict[str, t.Any]
    ) -> dict[str, t.Any]:
        sign_payload = f"{protected64}.{payload64}".encode("utf8")
        if key_data["type"] == "hmac":
            hex_key = (
                binascii.hexlify(base64.urlsafe_b64decode(key_data["jwk"]["k"]))
            ).decode("ascii")
            cmd_postfix = [
                "-mac",
                "hmac",
                "-macopt",
                f"hexkey:{hex_key}",
                "-binary",
            ]
        else:
            cmd_postfix = ["-sign", key_data["key_file"]]
        openssl_sign_cmd = [
            self.openssl_binary,
            "dgst",
            f"-{key_data['hash']}",
        ] + cmd_postfix

        out: bytes | str

        rc, out, err = self.module.run_command(
            openssl_sign_cmd,
            data=sign_payload,
            check_rc=False,
            binary_data=True,
            environ_update=_OPENSSL_ENVIRONMENT_UPDATE,
        )
        if rc != 0:
            raise BackendException(
                f"Error while running {' '.join(openssl_sign_cmd)}: {err}"
            )

        if key_data["type"] == "ec":
            dummy, der_out, dummy2 = self.module.run_command(
                [self.openssl_binary, "asn1parse", "-inform", "DER"],
                data=out,
                binary_data=True,
                environ_update=_OPENSSL_ENVIRONMENT_UPDATE,
            )
            expected_len = 2 * key_data["point_size"]
            sig = re.findall(
                rf"prim:\s+INTEGER\s+:([0-9A-F]{{1,{expected_len}}})\n",
                to_text(der_out, errors="surrogate_or_strict"),
            )
            if len(sig) != 2:
                der_output = to_text(der_out, errors="surrogate_or_strict")
                raise BackendException(
                    f"failed to generate Elliptic Curve signature; cannot parse DER output: {der_output}"
                )
            sig[0] = (expected_len - len(sig[0])) * "0" + sig[0]
            sig[1] = (expected_len - len(sig[1])) * "0" + sig[1]
            out = binascii.unhexlify(sig[0]) + binascii.unhexlify(sig[1])

        return {
            "protected": protected64,
            "payload": payload64,
            "signature": nopad_b64(to_bytes(out)),
        }

    def create_mac_key(self, *, alg: str, key: str) -> dict[str, t.Any]:
        """Create a MAC key."""
        if alg == "HS256":
            hashalg = "sha256"
            hashbytes = 32
        elif alg == "HS384":
            hashalg = "sha384"
            hashbytes = 48
        elif alg == "HS512":
            hashalg = "sha512"
            hashbytes = 64
        else:
            raise BackendException(
                f"Unsupported MAC key algorithm for OpenSSL backend: {alg}"
            )
        key_bytes = base64.urlsafe_b64decode(key)
        if len(key_bytes) < hashbytes:
            raise BackendException(
                f"{alg} key must be at least {hashbytes} bytes long (after Base64 decoding)"
            )
        return {
            "type": "hmac",
            "alg": alg,
            "jwk": {
                "kty": "oct",
                "k": key,
            },
            "hash": hashalg,
        }

    @staticmethod
    def _normalize_ip(ip: str) -> str:
        try:
            return ipaddress.ip_address(ip).compressed
        except ValueError:
            # We do not want to error out on something IPAddress() cannot parse
            return ip

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
        filename = csr_filename
        data = None
        if csr_content is not None:
            filename = "/dev/stdin"
            data = to_bytes(csr_content)

        openssl_csr_cmd = [
            self.openssl_binary,
            "req",
            "-in",
            str(filename),
            "-noout",
            "-text",
        ]
        rc, out, err = self.module.run_command(
            openssl_csr_cmd,
            data=data,
            check_rc=False,
            binary_data=True,
            environ_update=_OPENSSL_ENVIRONMENT_UPDATE,
        )
        if rc != 0:
            raise BackendException(
                f"Error while running {' '.join(openssl_csr_cmd)}: {err}"
            )

        identifiers = set()
        result = []

        def add_identifier(identifier: tuple[str, str]) -> None:
            if identifier in identifiers:
                return
            identifiers.add(identifier)
            result.append(identifier)

        common_name = re.search(
            r"Subject:.* CN\s?=\s?([^\s,;/]+)",
            to_text(out, errors="surrogate_or_strict"),
        )
        if common_name is not None:
            add_identifier(("dns", common_name.group(1)))
        subject_alt_names = re.search(
            r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n",
            to_text(out, errors="surrogate_or_strict"),
            re.MULTILINE | re.DOTALL,
        )
        if subject_alt_names is not None:
            for san in subject_alt_names.group(1).split(", "):
                if san.lower().startswith("dns:"):
                    add_identifier(("dns", san[4:]))
                elif san.lower().startswith("ip:"):
                    add_identifier(("ip", self._normalize_ip(san[3:])))
                elif san.lower().startswith("ip address:"):
                    add_identifier(("ip", self._normalize_ip(san[11:])))
                else:
                    raise BackendException(f'Found unsupported SAN identifier "{san}"')
        return result

    def get_csr_identifiers(
        self,
        *,
        csr_filename: str | os.PathLike | None = None,
        csr_content: str | bytes | None = None,
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
        filename = cert_filename
        data = None
        if cert_content is not None:
            filename = "/dev/stdin"
            data = to_bytes(cert_content)
            cert_filename_suffix = ""
        elif cert_filename is not None:
            if not os.path.exists(cert_filename):
                return -1
            cert_filename_suffix = f" in {cert_filename}"
        else:
            return -1

        openssl_cert_cmd = [
            self.openssl_binary,
            "x509",
            "-in",
            str(filename),
            "-noout",
            "-text",
        ]
        rc, out, err = self.module.run_command(
            openssl_cert_cmd,
            data=data,
            check_rc=False,
            binary_data=True,
            environ_update=_OPENSSL_ENVIRONMENT_UPDATE,
        )
        if rc != 0:
            raise BackendException(
                f"Error while running {' '.join(openssl_cert_cmd)}: {err}"
            )

        out_text = to_text(out, errors="surrogate_or_strict")
        not_after = _extract_date(
            out_text, name="Not After", cert_filename_suffix=cert_filename_suffix
        )
        if now is None:
            now = self.get_now()
        else:
            now = ensure_utc_timezone(now)
        return (not_after - now).days

    def create_chain_matcher(self, *, criterium: Criterium) -> t.NoReturn:
        """
        Given a Criterium object, creates a ChainMatcher object.
        """
        raise BackendException(
            'Alternate chain matching can only be used with the "cryptography" backend.'
        )

    def get_cert_information(
        self,
        *,
        cert_filename: str | os.PathLike | None = None,
        cert_content: str | bytes | None = None,
    ) -> CertificateInformation:
        """
        Return some information on a X.509 certificate as a CertificateInformation object.
        """
        filename = cert_filename
        data = None
        if cert_filename is not None:
            cert_filename_suffix = f" in {cert_filename}"
        else:
            filename = "/dev/stdin"
            data = to_bytes(cert_content)
            cert_filename_suffix = ""

        openssl_cert_cmd = [
            self.openssl_binary,
            "x509",
            "-in",
            str(filename),
            "-noout",
            "-text",
        ]
        rc, out, err = self.module.run_command(
            openssl_cert_cmd,
            data=data,
            check_rc=False,
            binary_data=True,
            environ_update=_OPENSSL_ENVIRONMENT_UPDATE,
        )
        if rc != 0:
            raise BackendException(
                f"Error while running {' '.join(openssl_cert_cmd)}: {err}"
            )

        out_text = to_text(out, errors="surrogate_or_strict")

        not_after = _extract_date(
            out_text, name="Not After", cert_filename_suffix=cert_filename_suffix
        )
        not_before = _extract_date(
            out_text, name="Not Before", cert_filename_suffix=cert_filename_suffix
        )

        sn = re.search(
            r" Serial Number: ([0-9]+)",
            to_text(out, errors="surrogate_or_strict"),
            re.MULTILINE | re.DOTALL,
        )
        if sn:
            serial = int(sn.group(1))
        else:
            serial = convert_bytes_to_int(
                _extract_octets(out_text, name="Serial Number", required=True)
            )

        ski = _extract_octets(
            out_text, name="X509v3 Subject Key Identifier", required=False
        )
        aki = _extract_octets(
            out_text,
            name="X509v3 Authority Key Identifier",
            required=False,
            potential_prefixes=["keyid:", ""],
        )

        return CertificateInformation(
            not_valid_after=not_after,
            not_valid_before=not_before,
            serial_number=serial,
            subject_key_identifier=ski,
            authority_key_identifier=aki,
        )


__all__ = ("OpenSSLCLIBackend",)
