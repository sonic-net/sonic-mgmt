# Copyright (c) 2020, Doug Stanley <doug+ansible@technologixllc.com>
# Copyright (c) 2021, Andrew Pantuso (@ajpantuso) <ajpantuso@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import os
import re
import typing as t
from contextlib import contextmanager
from struct import Struct


# Protocol References
# -------------------
# https://datatracker.ietf.org/doc/html/rfc4251
# https://datatracker.ietf.org/doc/html/rfc4253
# https://datatracker.ietf.org/doc/html/rfc5656
# https://datatracker.ietf.org/doc/html/rfc8032
#
# Inspired by:
# ------------
# https://github.com/pyca/cryptography/blob/main/src/cryptography/hazmat/primitives/serialization/ssh.py
# https://github.com/paramiko/paramiko/blob/master/paramiko/message.py

# 0 (False) or 1 (True) encoded as a single byte
_BOOLEAN = Struct(b"?")
# Unsigned 8-bit integer in network-byte-order
_UBYTE = Struct(b"!B")
_UBYTE_MAX = 0xFF
# Unsigned 32-bit integer in network-byte-order
_UINT32 = Struct(b"!I")
# Unsigned 32-bit little endian integer
_UINT32_LE = Struct(b"<I")
_UINT32_MAX = 0xFFFFFFFF
# Unsigned 64-bit integer in network-byte-order
_UINT64 = Struct(b"!Q")
_UINT64_MAX = 0xFFFFFFFFFFFFFFFF


_T = t.TypeVar("_T")


def any_in(sequence: t.Iterable[_T], *elements: _T) -> bool:
    return any(e in sequence for e in elements)


def file_mode(path: str | os.PathLike) -> int:
    if not os.path.exists(path):
        return 0o000
    return os.stat(path).st_mode & 0o777


def parse_openssh_version(version_string: str) -> str | None:
    """Parse the version output of ssh -V and return version numbers that can be compared"""

    parsed_result = re.match(
        r"^.*openssh_(?P<version>[0-9.]+)(p?[0-9]+)[^0-9]*.*$", version_string.lower()
    )
    if parsed_result is not None:
        version = parsed_result.group("version").strip()
    else:
        version = None

    return version


@contextmanager
def secure_open(*, path: str | os.PathLike, mode: int) -> t.Iterator[int]:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        yield fd
    finally:
        os.close(fd)


def secure_write(*, path: str | os.PathLike, mode: int, content: bytes) -> None:
    with secure_open(path=path, mode=mode) as fd:
        os.write(fd, content)


# See https://datatracker.ietf.org/doc/html/rfc4251#section-5 for SSH data types
class OpensshParser:
    """Parser for OpenSSH encoded objects"""

    BOOLEAN_OFFSET = 1
    UINT32_OFFSET = 4
    UINT64_OFFSET = 8

    def __init__(self, *, data: bytes | bytearray) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"Data must be bytes-like not {type(data)}")

        self._data = memoryview(data)
        self._pos = 0

    def boolean(self) -> bool:
        next_pos = self._check_position(self.BOOLEAN_OFFSET)

        value: bool = _BOOLEAN.unpack(self._data[self._pos : next_pos])[0]
        self._pos = next_pos
        return value

    def uint32(self) -> int:
        next_pos = self._check_position(self.UINT32_OFFSET)

        value: int = _UINT32.unpack(self._data[self._pos : next_pos])[0]
        self._pos = next_pos
        return value

    def uint64(self) -> int:
        next_pos = self._check_position(self.UINT64_OFFSET)

        value: int = _UINT64.unpack(self._data[self._pos : next_pos])[0]
        self._pos = next_pos
        return value

    def string(self) -> bytes:
        length = self.uint32()

        next_pos = self._check_position(length)

        value = self._data[self._pos : next_pos]
        self._pos = next_pos
        # Cast to bytes is required as a memoryview slice is itself a memoryview
        return bytes(value)

    def mpint(self) -> int:
        return self._big_int(self.string(), "big", signed=True)

    def name_list(self) -> list[str]:
        raw_string = self.string()
        return raw_string.decode("ASCII").split(",")

    # Convenience function, but not an official data type from SSH
    def string_list(self) -> list[bytes]:
        result = []
        raw_string = self.string()

        if raw_string:
            parser = OpensshParser(data=raw_string)
            while parser.remaining_bytes():
                result.append(parser.string())

        return result

    # Convenience function, but not an official data type from SSH
    def option_list(self) -> list[tuple[bytes, bytes]]:
        result = []
        raw_string = self.string()

        if raw_string:
            parser = OpensshParser(data=raw_string)

            while parser.remaining_bytes():
                name = parser.string()
                data = parser.string()
                if data:
                    # data is doubly-encoded
                    data = OpensshParser(data=data).string()
                result.append((name, data))

        return result

    def seek(self, offset: int) -> int:
        self._pos = self._check_position(offset)

        return self._pos

    def remaining_bytes(self) -> int:
        return len(self._data) - self._pos

    def _check_position(self, offset: int) -> int:
        if self._pos + offset > len(self._data):
            raise ValueError(f"Insufficient data remaining at position: {self._pos}")
        if self._pos + offset < 0:
            raise ValueError("Position cannot be less than zero.")
        return self._pos + offset

    @classmethod
    def signature_data(cls, *, signature_string: bytes) -> dict[str, bytes | int]:
        signature_data: dict[str, bytes | int] = {}

        parser = cls(data=signature_string)
        signature_type = parser.string()
        signature_blob = parser.string()

        blob_parser = cls(data=signature_blob)
        if signature_type in (b"ssh-rsa", b"rsa-sha2-256", b"rsa-sha2-512"):
            # https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
            # https://datatracker.ietf.org/doc/html/rfc8332#section-3
            signature_data["s"] = cls._big_int(signature_blob, "big")
        elif signature_type == b"ssh-dss":
            # https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
            signature_data["r"] = cls._big_int(signature_blob[:20], "big")
            signature_data["s"] = cls._big_int(signature_blob[20:], "big")
        elif signature_type in (
            b"ecdsa-sha2-nistp256",
            b"ecdsa-sha2-nistp384",
            b"ecdsa-sha2-nistp521",
        ):
            # https://datatracker.ietf.org/doc/html/rfc5656#section-3.1.2
            signature_data["r"] = blob_parser.mpint()
            signature_data["s"] = blob_parser.mpint()
        elif signature_type == b"ssh-ed25519":
            # https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.2
            signature_data["R"] = cls._big_int(signature_blob[:32], "little")
            signature_data["S"] = cls._big_int(signature_blob[32:], "little")
        else:
            raise ValueError(f"{signature_type!r} is not a valid signature type")

        signature_data["signature_type"] = signature_type

        return signature_data

    @classmethod
    def _big_int(
        cls,
        raw_string: bytes,
        byte_order: t.Literal["big", "little"],
        signed: bool = False,
    ) -> int:
        if byte_order not in ("big", "little"):
            raise ValueError(
                f"Byte_order must be one of (big, little) not {byte_order}"
            )

        return int.from_bytes(raw_string, byte_order, signed=signed)


class _OpensshWriter:
    """Writes SSH encoded values to a bytes-like buffer

    .. warning::
        This class is a private API and must not be exported outside of the openssh module_utils.
        It is not to be used to construct Openssh objects, but rather as a utility to assist
        in validating parsed material.
    """

    def __init__(self, *, buffer: bytearray | None = None):
        if buffer is not None:
            if not isinstance(buffer, bytearray):
                raise TypeError(f"Buffer must be a bytearray, not {type(buffer)}")
        else:
            buffer = bytearray()

        self._buff: bytearray = buffer

    def boolean(self, value: bool) -> t.Self:
        if not isinstance(value, bool):
            raise TypeError(f"Value must be of type bool not {type(value)}")

        self._buff.extend(_BOOLEAN.pack(value))

        return self

    def uint32(self, value: int) -> t.Self:
        if not isinstance(value, int):
            raise TypeError(f"Value must be of type int not {type(value)}")
        if value < 0 or value > _UINT32_MAX:
            raise ValueError(
                f"Value must be a positive integer less than {_UINT32_MAX}"
            )

        self._buff.extend(_UINT32.pack(value))

        return self

    def uint64(self, value: int) -> t.Self:
        if not isinstance(value, int):
            raise TypeError(f"Value must be of type int not {type(value)}")
        if value < 0 or value > _UINT64_MAX:
            raise ValueError(
                f"Value must be a positive integer less than {_UINT64_MAX}"
            )

        self._buff.extend(_UINT64.pack(value))

        return self

    def string(self, value: bytes | bytearray) -> t.Self:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"Value must be bytes-like not {type(value)}")
        self.uint32(len(value))
        self._buff.extend(value)

        return self

    def mpint(self, value: int) -> t.Self:
        if not isinstance(value, int):
            raise TypeError(f"Value must be of type int not {type(value)}")

        self.string(self._int_to_mpint(value))

        return self

    def name_list(self, value: list[str]) -> t.Self:
        if not isinstance(value, list):
            raise TypeError(f"Value must be a list of byte strings not {type(value)}")

        try:
            self.string(",".join(value).encode("ASCII"))
        except UnicodeEncodeError as e:
            raise ValueError(
                f"Name-list's must consist of US-ASCII characters: {e}"
            ) from e

        return self

    def string_list(self, value: list[bytes]) -> t.Self:
        if not isinstance(value, list):
            raise TypeError(f"Value must be a list of byte string not {type(value)}")

        writer = _OpensshWriter()
        for s in value:
            writer.string(s)

        self.string(writer.bytes())

        return self

    def option_list(self, value: list[tuple[bytes, bytes]]) -> t.Self:
        if not isinstance(value, list) or (value and not isinstance(value[0], tuple)):
            raise TypeError("Value must be a list of tuples")

        writer = _OpensshWriter()
        for name, data in value:
            writer.string(name)
            # SSH option data is encoded twice though this behavior is not documented
            writer.string(_OpensshWriter().string(data).bytes() if data else b"")

        self.string(writer.bytes())

        return self

    @staticmethod
    def _int_to_mpint(num: int) -> bytes:
        byte_length = (num.bit_length() + 7) // 8
        try:
            return num.to_bytes(byte_length, "big", signed=True)
        # Handles values which require \x00 or \xFF to pad sign-bit
        except OverflowError:
            return num.to_bytes(byte_length + 1, "big", signed=True)

    def bytes(self) -> bytes:
        return bytes(self._buff)


__all__ = (
    "any_in",
    "file_mode",
    "parse_openssh_version",
    "secure_open",
    "secure_write",
    "OpensshParser",
)
