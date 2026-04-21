# Copyright (c) 2021, Andrew Pantuso (@ajpantuso) <ajpantuso@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import abc
import binascii
import datetime as _datetime
import os
import typing as t
from base64 import b64encode
from datetime import datetime
from hashlib import sha256

from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.crypto.plugins.module_utils._openssh.utils import (
    OpensshParser,
    _OpensshWriter,
)
from ansible_collections.community.crypto.plugins.module_utils._time import UTC as _UTC
from ansible_collections.community.crypto.plugins.module_utils._time import (
    add_or_remove_timezone as _add_or_remove_timezone,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    convert_relative_to_datetime,
)


if t.TYPE_CHECKING:
    from ansible_collections.community.crypto.plugins.module_utils._openssh.cryptography import (  # pragma: no cover
        KeyType,
    )

    DateFormat = t.Literal["human_readable", "openssh", "timestamp"]  # pragma: no cover
    DateFormatStr = t.Literal["human_readable", "openssh"]  # pragma: no cover
    DateFormatInt = t.Literal["timestamp"]  # pragma: no cover
else:
    KeyType = None  # pylint: disable=invalid-name


# Protocol References
# -------------------
# https://datatracker.ietf.org/doc/html/rfc4251
# https://datatracker.ietf.org/doc/html/rfc4253
# https://datatracker.ietf.org/doc/html/rfc5656
# https://datatracker.ietf.org/doc/html/rfc8032
# https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
#
# Inspired by:
# ------------
# https://github.com/pyca/cryptography/blob/main/src/cryptography/hazmat/primitives/serialization/ssh.py
# https://github.com/paramiko/paramiko/blob/master/paramiko/message.py


# See https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
_USER_TYPE = 1
_HOST_TYPE = 2

_SSH_TYPE_STRINGS: dict[KeyType | str, bytes] = {
    "rsa": b"ssh-rsa",
    "dsa": b"ssh-dss",
    "ecdsa-nistp256": b"ecdsa-sha2-nistp256",
    "ecdsa-nistp384": b"ecdsa-sha2-nistp384",
    "ecdsa-nistp521": b"ecdsa-sha2-nistp521",
    "ed25519": b"ssh-ed25519",
}
_CERT_SUFFIX_V01 = b"-cert-v01@openssh.com"

# See https://datatracker.ietf.org/doc/html/rfc5656#section-6.1
_ECDSA_CURVE_IDENTIFIERS = {
    "ecdsa-nistp256": b"nistp256",
    "ecdsa-nistp384": b"nistp384",
    "ecdsa-nistp521": b"nistp521",
}
_ECDSA_CURVE_IDENTIFIERS_LOOKUP = {
    b"nistp256": "ecdsa-nistp256",
    b"nistp384": "ecdsa-nistp384",
    b"nistp521": "ecdsa-nistp521",
}

_ALWAYS = _add_or_remove_timezone(datetime(1970, 1, 1), with_timezone=True)
_FOREVER = datetime(9999, 12, 31, 23, 59, 59, 999999, _UTC)

_CRITICAL_OPTIONS = (
    "force-command",
    "source-address",
    "verify-required",
)

_DIRECTIVES = (
    "clear",
    "no-x11-forwarding",
    "no-agent-forwarding",
    "no-port-forwarding",
    "no-pty",
    "no-user-rc",
)

_EXTENSIONS = (
    "permit-x11-forwarding",
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-pty",
    "permit-user-rc",
)


class OpensshCertificateTimeParameters:
    def __init__(
        self, *, valid_from: str | bytes | int, valid_to: str | bytes | int
    ) -> None:
        self._valid_from = self.to_datetime(valid_from)
        self._valid_to = self.to_datetime(valid_to)

        if self._valid_from > self._valid_to:
            raise ValueError(
                f"Valid from: {valid_from!r} must not be greater than Valid to: {valid_to!r}"
            )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return (
            self._valid_from == other._valid_from and self._valid_to == other._valid_to
        )

    def __ne__(self, other: object) -> bool:
        return not self == other

    @property
    def validity_string(self) -> str:
        if not (self._valid_from == _ALWAYS and self._valid_to == _FOREVER):
            return f"{self.valid_from(date_format='openssh')}:{self.valid_to(date_format='openssh')}"
        return ""

    @t.overload
    def valid_from(self, date_format: DateFormatStr) -> str: ...

    @t.overload
    def valid_from(self, date_format: DateFormatInt) -> int: ...

    @t.overload
    def valid_from(self, date_format: DateFormat) -> str | int: ...

    def valid_from(self, date_format: DateFormat) -> str | int:
        return self.format_datetime(self._valid_from, date_format=date_format)

    @t.overload
    def valid_to(self, date_format: DateFormatStr) -> str: ...

    @t.overload
    def valid_to(self, date_format: DateFormatInt) -> int: ...

    @t.overload
    def valid_to(self, date_format: DateFormat) -> str | int: ...

    def valid_to(self, date_format: DateFormat) -> str | int:
        return self.format_datetime(self._valid_to, date_format=date_format)

    def within_range(self, valid_at: str | bytes | int | None) -> bool:
        if valid_at is not None:
            valid_at_datetime = self.to_datetime(valid_at)
            return self._valid_from <= valid_at_datetime <= self._valid_to
        return True

    @t.overload
    @staticmethod
    def format_datetime(dt: datetime, *, date_format: DateFormatStr) -> str: ...

    @t.overload
    @staticmethod
    def format_datetime(dt: datetime, *, date_format: DateFormatInt) -> int: ...

    @t.overload
    @staticmethod
    def format_datetime(dt: datetime, *, date_format: DateFormat) -> str | int: ...

    @staticmethod
    def format_datetime(dt: datetime, *, date_format: DateFormat) -> str | int:
        if date_format in ("human_readable", "openssh"):
            if dt == _ALWAYS:
                return "always"
            if dt == _FOREVER:
                return "forever"
            return (
                dt.isoformat().replace("+00:00", "")
                if date_format == "human_readable"
                else dt.strftime("%Y%m%d%H%M%S")
            )
        if date_format == "timestamp":
            td = dt - _ALWAYS
            return int(
                (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10**6
            )
        raise ValueError(f"{date_format} is not a valid format")

    @staticmethod
    def to_datetime(time_string_or_timestamp: str | bytes | int) -> datetime:
        if isinstance(time_string_or_timestamp, (str, bytes)):
            return OpensshCertificateTimeParameters._time_string_to_datetime(
                to_text(time_string_or_timestamp.strip())
            )
        if isinstance(time_string_or_timestamp, int):
            return OpensshCertificateTimeParameters._timestamp_to_datetime(
                time_string_or_timestamp
            )
        raise ValueError(
            f"Value must be of type (str, unicode, int) not {type(time_string_or_timestamp)}"
        )

    @staticmethod
    def _timestamp_to_datetime(timestamp: int) -> datetime:
        if timestamp == 0x0:
            return _ALWAYS
        if timestamp == 0xFFFFFFFFFFFFFFFF:
            return _FOREVER
        try:
            return datetime.fromtimestamp(timestamp, tz=_datetime.timezone.utc)
        except OverflowError as e:
            raise ValueError from e

    @staticmethod
    def _time_string_to_datetime(time_string: str) -> datetime:
        if time_string == "always":
            return _ALWAYS
        if time_string == "forever":
            return _FOREVER
        if is_relative_time_string(time_string):
            result = convert_relative_to_datetime(time_string, with_timezone=True)
            if result is None:
                raise ValueError
            return result
        result = None
        for time_format in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                result = _add_or_remove_timezone(
                    datetime.strptime(time_string, time_format),
                    with_timezone=True,
                )
            except ValueError:
                pass
        if result is None:
            raise ValueError
        return result


_OpensshCertificateOption = t.TypeVar(
    "_OpensshCertificateOption", bound="OpensshCertificateOption"
)


class OpensshCertificateOption:
    def __init__(
        self,
        *,
        option_type: t.Literal["critical", "extension"],
        name: str | bytes,
        data: str | bytes,
    ):
        if option_type not in ("critical", "extension"):
            raise ValueError("type must be either 'critical' or 'extension'")

        if not isinstance(name, (str, bytes)):
            raise TypeError(f"name must be a string not {type(name)}")

        if not isinstance(data, (str, bytes)):
            raise TypeError(f"data must be a string not {type(data)}")

        self._option_type = option_type
        self._name = name.lower()
        self._data = data

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented

        return all(
            [
                self._option_type == other._option_type,
                self._name == other._name,
                self._data == other._data,
            ]
        )

    def __hash__(self) -> int:
        return hash((self._option_type, self._name, self._data))

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __str__(self) -> str:
        if self._data:
            return f"{self._name!r}={self._data!r}"
        return f"{self._name!r}"

    @property
    def data(self) -> str | bytes:
        return self._data

    @property
    def name(self) -> str | bytes:
        return self._name

    @property
    def type(self) -> t.Literal["critical", "extension"]:
        return self._option_type

    @classmethod
    def from_string(
        cls: t.Type[_OpensshCertificateOption], option_string: str  # noqa: UP006
    ) -> _OpensshCertificateOption:
        if not isinstance(option_string, str):
            raise ValueError(
                f"option_string must be a string not {type(option_string)}"
            )
        option_type = None

        if ":" in option_string:
            option_type, value = option_string.strip().split(":", 1)
            if "=" in value:
                name, data = value.split("=", 1)
            else:
                name, data = value, ""
        elif "=" in option_string:
            name, data = option_string.strip().split("=", 1)
        else:
            name, data = option_string.strip(), ""

        return cls(
            # We have str, but we're expecting a specific literal:
            option_type=option_type or get_option_type(name.lower()),  # type: ignore
            name=name,
            data=data,
        )


if t.TYPE_CHECKING:

    class _OpensshCertificateInfoKwarg(t.TypedDict):
        nonce: t.NotRequired[bytes | None]
        serial: t.NotRequired[int | None]
        cert_type: t.NotRequired[int | None]
        key_id: t.NotRequired[bytes | None]
        principals: t.NotRequired[list[bytes] | None]
        valid_after: t.NotRequired[int | None]
        valid_before: t.NotRequired[int | None]
        critical_options: t.NotRequired[list[tuple[bytes, bytes]] | None]
        extensions: t.NotRequired[list[tuple[bytes, bytes]] | None]
        reserved: t.NotRequired[bytes | None]
        signing_key: t.NotRequired[bytes | None]


class OpensshCertificateInfo(metaclass=abc.ABCMeta):
    """Encapsulates all certificate information which is signed by a CA key"""

    def __init__(
        self,
        *,
        nonce: bytes | None = None,
        serial: int | None = None,
        cert_type: int | None = None,
        key_id: bytes | None = None,
        principals: list[bytes] | None = None,
        valid_after: int | None = None,
        valid_before: int | None = None,
        critical_options: list[tuple[bytes, bytes]] | None = None,
        extensions: list[tuple[bytes, bytes]] | None = None,
        reserved: bytes | None = None,
        signing_key: bytes | None = None,
    ):
        self.nonce = nonce
        self.serial = serial
        self._cert_type: int | None = cert_type
        self.key_id = key_id
        self.principals = principals
        self.valid_after = valid_after
        self.valid_before = valid_before
        self.critical_options = critical_options
        self.extensions = extensions
        self.reserved = reserved
        self.signing_key = signing_key

        self.type_string: bytes | None = None

    @property
    def cert_type(self) -> t.Literal["user", "host", ""]:
        if self._cert_type == _USER_TYPE:
            return "user"
        if self._cert_type == _HOST_TYPE:
            return "host"
        return ""

    @cert_type.setter
    def cert_type(self, cert_type: t.Literal["user", "host"] | int) -> None:
        if cert_type in ("user", _USER_TYPE):
            self._cert_type = _USER_TYPE
        elif cert_type in ("host", _HOST_TYPE):
            self._cert_type = _HOST_TYPE
        else:
            raise ValueError(f"{cert_type} is not a valid certificate type")

    def signing_key_fingerprint(self) -> bytes:
        if self.signing_key is None:
            raise ValueError("signing_key not present")
        return fingerprint(self.signing_key)

    @abc.abstractmethod
    def public_key_fingerprint(self) -> bytes:
        pass

    @abc.abstractmethod
    def parse_public_numbers(self, parser: OpensshParser) -> None:
        pass


class OpensshRSACertificateInfo(OpensshCertificateInfo):
    def __init__(
        self,
        *,
        e: int | None = None,
        n: int | None = None,
        **kwargs: t.Unpack[_OpensshCertificateInfoKwarg],
    ) -> None:
        super().__init__(**kwargs)
        self.type_string = _SSH_TYPE_STRINGS["rsa"] + _CERT_SUFFIX_V01
        self.e = e
        self.n = n

    # See https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
    def public_key_fingerprint(self) -> bytes:
        if self.e is None or self.n is None:
            return b""

        writer = _OpensshWriter()
        writer.string(_SSH_TYPE_STRINGS["rsa"])
        writer.mpint(self.e)
        writer.mpint(self.n)

        return fingerprint(writer.bytes())

    def parse_public_numbers(self, parser: OpensshParser) -> None:
        self.e = parser.mpint()
        self.n = parser.mpint()


class OpensshDSACertificateInfo(OpensshCertificateInfo):
    def __init__(
        self,
        *,
        p: int | None = None,
        q: int | None = None,
        g: int | None = None,
        y: int | None = None,
        **kwargs: t.Unpack[_OpensshCertificateInfoKwarg],
    ) -> None:
        super().__init__(**kwargs)
        self.type_string = _SSH_TYPE_STRINGS["dsa"] + _CERT_SUFFIX_V01
        self.p = p
        self.q = q
        self.g = g
        self.y = y

    # See https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
    def public_key_fingerprint(self) -> bytes:
        if self.p is None or self.q is None or self.g is None or self.y is None:
            return b""

        writer = _OpensshWriter()
        writer.string(_SSH_TYPE_STRINGS["dsa"])
        writer.mpint(self.p)
        writer.mpint(self.q)
        writer.mpint(self.g)
        writer.mpint(self.y)

        return fingerprint(writer.bytes())

    def parse_public_numbers(self, parser: OpensshParser) -> None:
        self.p = parser.mpint()
        self.q = parser.mpint()
        self.g = parser.mpint()
        self.y = parser.mpint()


class OpensshECDSACertificateInfo(OpensshCertificateInfo):
    def __init__(
        self,
        *,
        curve: bytes | None = None,
        public_key: bytes | None = None,
        **kwargs: t.Unpack[_OpensshCertificateInfoKwarg],
    ):
        super().__init__(**kwargs)
        self._curve: bytes | None = None
        if curve is not None:
            self.curve = curve

        self.public_key = public_key

    @property
    def curve(self) -> bytes | None:
        return self._curve

    @curve.setter
    def curve(self, curve: bytes) -> None:
        if curve in _ECDSA_CURVE_IDENTIFIERS.values():
            self._curve = curve
            self.type_string = (
                _SSH_TYPE_STRINGS[_ECDSA_CURVE_IDENTIFIERS_LOOKUP[curve]]
                + _CERT_SUFFIX_V01
            )
        else:
            raise ValueError(
                "Curve must be one of {(b','.join(_ECDSA_CURVE_IDENTIFIERS.values())).decode('UTF-8')}"
            )

    # See https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
    def public_key_fingerprint(self) -> bytes:
        if self.curve is None or self.public_key is None:
            return b""

        writer = _OpensshWriter()
        writer.string(_SSH_TYPE_STRINGS[_ECDSA_CURVE_IDENTIFIERS_LOOKUP[self.curve]])
        writer.string(self.curve)
        writer.string(self.public_key)

        return fingerprint(writer.bytes())

    def parse_public_numbers(self, parser: OpensshParser) -> None:
        self.curve = parser.string()
        self.public_key = parser.string()


class OpensshED25519CertificateInfo(OpensshCertificateInfo):
    def __init__(
        self,
        *,
        pk: bytes | None = None,
        **kwargs: t.Unpack[_OpensshCertificateInfoKwarg],
    ) -> None:
        super().__init__(**kwargs)
        self.type_string = _SSH_TYPE_STRINGS["ed25519"] + _CERT_SUFFIX_V01
        self.pk = pk

    def public_key_fingerprint(self) -> bytes:
        if self.pk is None:
            return b""

        writer = _OpensshWriter()
        writer.string(_SSH_TYPE_STRINGS["ed25519"])
        writer.string(self.pk)

        return fingerprint(writer.bytes())

    def parse_public_numbers(self, parser: OpensshParser) -> None:
        self.pk = parser.string()


_OpensshCertificate = t.TypeVar("_OpensshCertificate", bound="OpensshCertificate")


# See https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
class OpensshCertificate:
    """Encapsulates a formatted OpenSSH certificate including signature and signing key"""

    def __init__(self, *, cert_info: OpensshCertificateInfo, signature: bytes):
        self._cert_info = cert_info
        self.signature = signature

    @classmethod
    def load(
        cls: t.Type[_OpensshCertificate], path: str | os.PathLike  # noqa: UP006
    ) -> _OpensshCertificate:
        if not os.path.exists(path):
            raise ValueError(f"{path} is not a valid path.")

        try:
            with open(path, "rb") as cert_file:
                data = cert_file.read()
        except (IOError, OSError) as e:
            raise ValueError(f"{path} cannot be opened for reading: {e}") from e

        try:
            format_identifier, b64_cert = data.split(b" ")[:2]
            cert = binascii.a2b_base64(b64_cert)
        except (binascii.Error, ValueError) as e:
            raise ValueError("Certificate not in OpenSSH format") from e

        for key_type, string in _SSH_TYPE_STRINGS.items():
            if format_identifier == string + _CERT_SUFFIX_V01:
                pub_key_type = t.cast(KeyType, key_type)
                break
        else:
            raise ValueError(
                f"Invalid certificate format identifier: {format_identifier!r}"
            )

        parser = OpensshParser(data=cert)

        if format_identifier != parser.string():
            raise ValueError("Certificate formats do not match")

        try:
            cert_info = cls._parse_cert_info(pub_key_type, parser)
            signature = parser.string()
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid certificate data: {e}") from e

        if parser.remaining_bytes():
            raise ValueError(
                f"{parser.remaining_bytes()} bytes of additional data was not parsed while loading {path}"
            )

        return cls(
            cert_info=cert_info,
            signature=signature,
        )

    @property
    def type_string(self) -> str:
        return to_text(self._cert_info.type_string)

    @property
    def nonce(self) -> bytes:
        if self._cert_info.nonce is None:
            raise ValueError
        return self._cert_info.nonce

    @property
    def public_key(self) -> str:
        return to_text(self._cert_info.public_key_fingerprint())

    @property
    def serial(self) -> int:
        if self._cert_info.serial is None:
            raise ValueError
        return self._cert_info.serial

    @property
    def type(self) -> t.Literal["user", "host"]:
        result = self._cert_info.cert_type
        if result == "":
            raise ValueError
        return result

    @property
    def key_id(self) -> str:
        return to_text(self._cert_info.key_id)

    @property
    def principals(self) -> list[str]:
        if self._cert_info.principals is None:
            raise ValueError
        return [to_text(p) for p in self._cert_info.principals]

    @property
    def valid_after(self) -> int:
        if self._cert_info.valid_after is None:
            raise ValueError
        return self._cert_info.valid_after

    @property
    def valid_before(self) -> int:
        if self._cert_info.valid_before is None:
            raise ValueError
        return self._cert_info.valid_before

    @property
    def critical_options(self) -> list[OpensshCertificateOption]:
        if self._cert_info.critical_options is None:
            raise ValueError
        return [
            OpensshCertificateOption(
                option_type="critical", name=to_text(n), data=to_text(d)
            )
            for n, d in self._cert_info.critical_options
        ]

    @property
    def extensions(self) -> list[OpensshCertificateOption]:
        if self._cert_info.extensions is None:
            raise ValueError
        return [
            OpensshCertificateOption(
                option_type="extension", name=to_text(n), data=to_text(d)
            )
            for n, d in self._cert_info.extensions
        ]

    @property
    def reserved(self) -> bytes:
        if self._cert_info.reserved is None:
            raise ValueError
        return self._cert_info.reserved

    @property
    def signing_key(self) -> str:
        return to_text(self._cert_info.signing_key_fingerprint())

    @property
    def signature_type(self) -> str:
        signature_data = OpensshParser.signature_data(signature_string=self.signature)
        return to_text(signature_data["signature_type"])

    @staticmethod
    def _parse_cert_info(
        pub_key_type: KeyType, parser: OpensshParser
    ) -> OpensshCertificateInfo:
        cert_info = get_cert_info_object(pub_key_type)
        cert_info.nonce = parser.string()
        cert_info.parse_public_numbers(parser)
        cert_info.serial = parser.uint64()
        # mypy doesn't understand that the setter accepts other types than the getter:
        cert_info.cert_type = parser.uint32()  # type: ignore
        cert_info.key_id = parser.string()
        cert_info.principals = parser.string_list()
        cert_info.valid_after = parser.uint64()
        cert_info.valid_before = parser.uint64()
        cert_info.critical_options = parser.option_list()
        cert_info.extensions = parser.option_list()
        cert_info.reserved = parser.string()
        cert_info.signing_key = parser.string()

        return cert_info

    def to_dict(self) -> dict[str, t.Any]:
        time_parameters = OpensshCertificateTimeParameters(
            valid_from=self.valid_after, valid_to=self.valid_before
        )
        return {
            "type_string": self.type_string,
            "nonce": self.nonce,
            "serial": self.serial,
            "cert_type": self.type,
            "identifier": self.key_id,
            "principals": self.principals,
            "valid_after": time_parameters.valid_from(date_format="human_readable"),
            "valid_before": time_parameters.valid_to(date_format="human_readable"),
            "critical_options": [
                str(critical_option) for critical_option in self.critical_options
            ],
            "extensions": [str(extension) for extension in self.extensions],
            "reserved": self.reserved,
            "public_key": self.public_key,
            "signing_key": self.signing_key,
        }


def apply_directives(directives: t.Iterable[str]) -> list[OpensshCertificateOption]:
    if any(d not in _DIRECTIVES for d in directives):
        raise ValueError(f"directives must be one of {', '.join(_DIRECTIVES)}")

    directive_to_option = {
        "no-x11-forwarding": OpensshCertificateOption(
            option_type="extension", name="permit-x11-forwarding", data=""
        ),
        "no-agent-forwarding": OpensshCertificateOption(
            option_type="extension", name="permit-agent-forwarding", data=""
        ),
        "no-port-forwarding": OpensshCertificateOption(
            option_type="extension", name="permit-port-forwarding", data=""
        ),
        "no-pty": OpensshCertificateOption(
            option_type="extension", name="permit-pty", data=""
        ),
        "no-user-rc": OpensshCertificateOption(
            option_type="extension", name="permit-user-rc", data=""
        ),
    }

    if "clear" in directives:
        return []
    return list(
        set(default_options()) - set(directive_to_option[d] for d in directives)
    )


def default_options() -> list[OpensshCertificateOption]:
    return [
        OpensshCertificateOption(option_type="extension", name=name, data="")
        for name in _EXTENSIONS
    ]


def fingerprint(public_key: bytes) -> bytes:
    """Generates a SHA256 hash and formats output to resemble ``ssh-keygen``"""
    h = sha256()
    h.update(public_key)
    return b"SHA256:" + b64encode(h.digest()).rstrip(b"=")


def get_cert_info_object(key_type: KeyType) -> OpensshCertificateInfo:
    if key_type == "rsa":
        return OpensshRSACertificateInfo()
    if key_type == "dsa":
        return OpensshDSACertificateInfo()
    if key_type in ("ecdsa-nistp256", "ecdsa-nistp384", "ecdsa-nistp521"):
        return OpensshECDSACertificateInfo()
    if key_type == "ed25519":
        return OpensshED25519CertificateInfo()
    raise ValueError(f"{key_type} is not a valid key type")


def get_option_type(name: str) -> t.Literal["critical", "extension"]:
    if name in _CRITICAL_OPTIONS:
        return "critical"
    if name in _EXTENSIONS:
        return "extension"
    raise ValueError(
        f"{name} is not a valid option. Custom options must start with 'critical:' or 'extension:' to indicate type"
    )


def is_relative_time_string(time_string: str) -> bool:
    return time_string.startswith("+") or time_string.startswith("-")


def parse_option_list(
    option_list: t.Iterable[str],
) -> tuple[list[OpensshCertificateOption], list[OpensshCertificateOption]]:
    critical_options = []
    directives = []
    extensions = []

    for option in option_list:
        if option.lower() in _DIRECTIVES:
            directives.append(option.lower())
        else:
            option_object = OpensshCertificateOption.from_string(option)
            if option_object.type == "critical":
                critical_options.append(option_object)
            else:
                extensions.append(option_object)

    return critical_options, list(set(extensions + apply_directives(directives)))


__all__ = (
    "OpensshCertificateTimeParameters",
    "OpensshCertificateOption",
    "OpensshCertificateInfo",
    "OpensshRSACertificateInfo",
    "OpensshDSACertificateInfo",
    "OpensshECDSACertificateInfo",
    "OpensshED25519CertificateInfo",
    "OpensshCertificate",
    "apply_directives",
    "default_options",
    "fingerprint",
    "get_cert_info_object",
    "get_option_type",
    "is_relative_time_string",
    "parse_option_list",
)
