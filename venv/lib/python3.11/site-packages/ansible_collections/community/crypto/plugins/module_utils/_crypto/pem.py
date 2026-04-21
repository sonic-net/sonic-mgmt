# Copyright (c) 2019, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import typing as t


PEM_START = "-----BEGIN "
PEM_END_START = "-----END "
PEM_END = "-----"
PKCS8_PRIVATEKEY_NAMES = ("PRIVATE KEY", "ENCRYPTED PRIVATE KEY")
PKCS1_PRIVATEKEY_SUFFIX = " PRIVATE KEY"


def identify_pem_format(content: bytes, *, encoding: str = "utf-8") -> bool:
    """Given the contents of a binary file, tests whether this could be a PEM file."""
    try:
        first_pem = extract_first_pem(content.decode(encoding))
        if first_pem is None:
            return False
        lines = first_pem.splitlines(False)
        if (
            lines[0].startswith(PEM_START)
            and lines[0].endswith(PEM_END)
            and len(lines[0]) > len(PEM_START) + len(PEM_END)
        ):
            return True
    except UnicodeDecodeError:
        pass
    return False


def identify_private_key_format(
    content: bytes, *, encoding: str = "utf-8"
) -> t.Literal["raw", "pkcs1", "pkcs8", "unknown-pem"]:
    """Given the contents of a private key file, identifies its format."""
    # See https://github.com/openssl/openssl/blob/master/crypto/pem/pem_pkey.c#L40-L85
    # (PEM_read_bio_PrivateKey)
    # and https://github.com/openssl/openssl/blob/master/include/openssl/pem.h#L46-L47
    # (PEM_STRING_PKCS8, PEM_STRING_PKCS8INF)
    try:
        first_pem = extract_first_pem(content.decode(encoding))
        if first_pem is None:
            return "raw"
        lines = first_pem.splitlines(False)
        if (
            lines[0].startswith(PEM_START)
            and lines[0].endswith(PEM_END)
            and len(lines[0]) > len(PEM_START) + len(PEM_END)
        ):
            name = lines[0][len(PEM_START) : -len(PEM_END)]
            if name in PKCS8_PRIVATEKEY_NAMES:
                return "pkcs8"
            if len(name) > len(PKCS1_PRIVATEKEY_SUFFIX) and name.endswith(
                PKCS1_PRIVATEKEY_SUFFIX
            ):
                return "pkcs1"
            return "unknown-pem"
    except UnicodeDecodeError:
        pass
    return "raw"


def split_pem_list(text: str, *, keep_inbetween: bool = False) -> list[str]:
    """
    Split concatenated PEM objects into a list of strings, where each is one PEM object.
    """
    result = []
    current: list[str] | None = [] if keep_inbetween else None
    for line in text.splitlines(True):
        if line.strip():
            if not keep_inbetween and line.startswith("-----BEGIN "):
                current = []
            if current is not None:
                current.append(line)
                if line.startswith("-----END "):
                    result.append("".join(current))
                    current = [] if keep_inbetween else None
    return result


def extract_first_pem(text: str) -> str | None:
    """
    Given one PEM or multiple concatenated PEM objects, return only the first one, or None if there is none.
    """
    all_pems = split_pem_list(text)
    if not all_pems:
        return None
    return all_pems[0]


def _extract_type(line: str, *, start: str = PEM_START) -> str | None:
    if not line.startswith(start):
        return None
    if not line.endswith(PEM_END):
        return None
    return line[len(start) : -len(PEM_END)]


def extract_pem(content: str, *, strict: bool = False) -> tuple[str, str]:
    lines = content.splitlines()
    if len(lines) < 3:
        raise ValueError(f"PEM must have at least 3 lines, have only {len(lines)}")
    header_type = _extract_type(lines[0])
    if header_type is None:
        raise ValueError(
            f"First line is not of format {PEM_START}...{PEM_END}: {lines[0]!r}"
        )
    footer_type = _extract_type(lines[-1], start=PEM_END_START)
    if strict:
        if header_type != footer_type:
            raise ValueError(
                f"Header type ({header_type}) is different from footer type ({footer_type})"
            )
        for idx, line in enumerate(lines[1:-2]):
            if len(line) != 64:
                raise ValueError(f"Line {idx} has length {len(line)} instead of 64")
        if not (0 < len(lines[-2]) <= 64):
            raise ValueError(
                f"Last line has length {len(lines[-2])}, should be in (0, 64]"
            )
    return header_type, "".join(lines[1:-1])


__all__ = (
    "PEM_START",
    "PEM_END_START",
    "PEM_END",
    "PKCS8_PRIVATEKEY_NAMES",
    "PKCS1_PRIVATEKEY_SUFFIX",
    "identify_pem_format",
    "identify_private_key_format",
    "split_pem_list",
    "extract_first_pem",
    "extract_pem",
)
