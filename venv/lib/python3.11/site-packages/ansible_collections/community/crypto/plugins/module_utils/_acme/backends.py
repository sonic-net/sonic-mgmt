# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import abc
import datetime
import re
import typing as t

from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    BackendException,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    UTC,
    ensure_utc_timezone,
    from_epoch_seconds,
    get_epoch_seconds,
    get_now_datetime,
    get_relative_time_option,
    remove_timezone,
)


if t.TYPE_CHECKING:
    import os  # pragma: no cover

    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.module_utils._acme.certificates import (  # pragma: no cover
        ChainMatcher,
        Criterium,
    )


class CertificateInformation(t.NamedTuple):
    not_valid_after: datetime.datetime
    not_valid_before: datetime.datetime
    serial_number: int
    subject_key_identifier: bytes | None
    authority_key_identifier: bytes | None


_FRACTIONAL_MATCHER = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(|\.\d+)(Z|[+-]\d{2}:?\d{2}.*)$"
)


def _reduce_fractional_digits(timestamp_str: str) -> str:
    """
    Given a RFC 3339 timestamp that includes too many digits for the fractional seconds part, reduces these to at most 6.
    """
    # RFC 3339 (https://www.rfc-editor.org/info/rfc3339)
    m = _FRACTIONAL_MATCHER.match(timestamp_str)
    if not m:
        raise BackendException(f"Cannot parse ISO 8601 timestamp {timestamp_str!r}")
    timestamp, fractional, timezone = m.groups()
    if len(fractional) > 7:
        # Python does not support anything smaller than microseconds
        # (Golang supports nanoseconds, Boulder often emits more fractional digits, which Python chokes on)
        fractional = fractional[:7]
    return f"{timestamp}{fractional}{timezone}"


def _parse_acme_timestamp(
    timestamp_str: str, *, with_timezone: bool
) -> datetime.datetime:
    """
    Parses a RFC 3339 timestamp.
    """
    # RFC 3339 (https://www.rfc-editor.org/info/rfc3339)
    timestamp_str = _reduce_fractional_digits(timestamp_str)
    for time_format in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
    ):
        try:
            result = datetime.datetime.strptime(timestamp_str, time_format)
        except ValueError:
            pass
        else:
            return (
                ensure_utc_timezone(result)
                if with_timezone
                else remove_timezone(result)
            )
    raise BackendException(f"Cannot parse ISO 8601 timestamp {timestamp_str!r}")


class CryptoBackend(metaclass=abc.ABCMeta):
    def __init__(self, *, module: AnsibleModule, with_timezone: bool = False) -> None:
        self.module = module
        self._with_timezone = with_timezone

    def get_now(self) -> datetime.datetime:
        return get_now_datetime(with_timezone=self._with_timezone)

    def parse_acme_timestamp(self, timestamp_str: str) -> datetime.datetime:
        # RFC 3339 (https://www.rfc-editor.org/info/rfc3339)
        return _parse_acme_timestamp(timestamp_str, with_timezone=self._with_timezone)

    def parse_module_parameter(self, *, value: str, name: str) -> datetime.datetime:
        try:
            result = get_relative_time_option(
                value, input_name=name, with_timezone=self._with_timezone
            )
            if result is None:
                raise BackendException(f"Invalid value for {name}: {value!r}")
            return result
        except OpenSSLObjectError as exc:
            raise BackendException(str(exc)) from exc

    def interpolate_timestamp(
        self,
        timestamp_start: datetime.datetime,
        timestamp_end: datetime.datetime,
        *,
        percentage: float,
    ) -> datetime.datetime:
        start = get_epoch_seconds(timestamp_start)
        end = get_epoch_seconds(timestamp_end)
        return from_epoch_seconds(
            start + percentage * (end - start), with_timezone=self._with_timezone
        )

    def get_utc_datetime(
        self,
        year: int,
        month: int,
        day: int,
        hour: int = 0,
        minute: int = 0,
        second: int = 0,
        microsecond: int = 0,
        tzinfo: datetime.timezone | None = None,
    ) -> datetime.datetime:
        has_tzinfo = tzinfo is not None
        if self._with_timezone and not has_tzinfo:
            tzinfo = UTC
        result = datetime.datetime(
            year, month, day, hour, minute, second, microsecond, tzinfo
        )
        if self._with_timezone and has_tzinfo:
            result = ensure_utc_timezone(result)
        return result

    @abc.abstractmethod
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

    @abc.abstractmethod
    def sign(
        self, *, payload64: str, protected64: str, key_data: dict[str, t.Any]
    ) -> dict[str, t.Any]:
        pass

    @abc.abstractmethod
    def create_mac_key(self, *, alg: str, key: str) -> dict[str, t.Any]:
        """Create a MAC key."""

    @abc.abstractmethod
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

    @abc.abstractmethod
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

    @abc.abstractmethod
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

    @abc.abstractmethod
    def create_chain_matcher(self, *, criterium: Criterium) -> ChainMatcher:
        """
        Given a Criterium object, creates a ChainMatcher object.
        """

    @abc.abstractmethod
    def get_cert_information(
        self,
        *,
        cert_filename: str | os.PathLike | None = None,
        cert_content: str | bytes | None = None,
    ) -> CertificateInformation:
        """
        Return some information on a X.509 certificate as a CertificateInformation object.
        """


__all__ = ("CertificateInformation", "CryptoBackend")
