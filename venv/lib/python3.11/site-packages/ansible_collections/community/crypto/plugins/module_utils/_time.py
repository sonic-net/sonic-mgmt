# Copyright (c) 2024, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import datetime
import re

from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)


UTC = datetime.timezone.utc


def get_now_datetime(*, with_timezone: bool) -> datetime.datetime:
    if with_timezone:
        return datetime.datetime.now(tz=UTC)
    return datetime.datetime.utcnow()


def ensure_utc_timezone(timestamp: datetime.datetime) -> datetime.datetime:
    if timestamp.tzinfo is UTC:
        return timestamp
    if timestamp.tzinfo is None:
        # We assume that naive datetime objects use timezone UTC!
        return timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC)


def remove_timezone(timestamp: datetime.datetime) -> datetime.datetime:
    # Convert to native datetime object
    if timestamp.tzinfo is None:
        return timestamp
    if timestamp.tzinfo is not UTC:
        timestamp = timestamp.astimezone(UTC)
    return timestamp.replace(tzinfo=None)


def add_or_remove_timezone(
    timestamp: datetime.datetime, *, with_timezone: bool
) -> datetime.datetime:
    return (
        ensure_utc_timezone(timestamp) if with_timezone else remove_timezone(timestamp)
    )


def get_epoch_seconds(timestamp: datetime.datetime) -> float:
    if timestamp.tzinfo is None:
        # timestamp.timestamp() is offset by the local timezone if timestamp has no timezone
        timestamp = ensure_utc_timezone(timestamp)
    return timestamp.timestamp()


def from_epoch_seconds(
    timestamp: int | float, *, with_timezone: bool
) -> datetime.datetime:
    if with_timezone:
        return datetime.datetime.fromtimestamp(timestamp, UTC)
    return datetime.datetime.utcfromtimestamp(timestamp)


def convert_relative_to_datetime(
    relative_time_string: str,
    *,
    with_timezone: bool = False,
    now: datetime.datetime | None = None,
) -> datetime.datetime | None:
    """Get a datetime.datetime or None from a string in the time format described in sshd_config(5)"""

    parsed_result = re.match(
        r"^(?P<prefix>[+-])((?P<weeks>\d+)[wW])?((?P<days>\d+)[dD])?((?P<hours>\d+)[hH])?((?P<minutes>\d+)[mM])?((?P<seconds>\d+)[sS]?)?$",
        relative_time_string,
    )

    if parsed_result is None or len(relative_time_string) == 1:
        # not matched or only a single "+" or "-"
        return None

    offset = datetime.timedelta(0)
    if parsed_result.group("weeks") is not None:
        offset += datetime.timedelta(weeks=int(parsed_result.group("weeks")))
    if parsed_result.group("days") is not None:
        offset += datetime.timedelta(days=int(parsed_result.group("days")))
    if parsed_result.group("hours") is not None:
        offset += datetime.timedelta(hours=int(parsed_result.group("hours")))
    if parsed_result.group("minutes") is not None:
        offset += datetime.timedelta(minutes=int(parsed_result.group("minutes")))
    if parsed_result.group("seconds") is not None:
        offset += datetime.timedelta(seconds=int(parsed_result.group("seconds")))

    if now is None:
        now = get_now_datetime(with_timezone=with_timezone)
    else:
        now = add_or_remove_timezone(now, with_timezone=with_timezone)

    if parsed_result.group("prefix") == "+":
        return now + offset
    return now - offset


def get_relative_time_option(
    input_string: str,
    *,
    input_name: str,
    with_timezone: bool = False,
    now: datetime.datetime | None = None,
) -> datetime.datetime:
    """
    Return an absolute timespec if a relative timespec or an ASN1 formatted
    string is provided.

    The return value will be a datetime object.
    """
    result = to_text(input_string)
    if result is None:
        raise OpenSSLObjectError(
            f'The timespec "{input_string}" for {input_name} is not valid'
        )
    # Relative time
    if result.startswith("+") or result.startswith("-"):
        res = convert_relative_to_datetime(result, with_timezone=with_timezone, now=now)
        if res is None:
            raise OpenSSLObjectError(
                f'The timespec "{input_string}" for {input_name} is invalid'
            )
        return res
    # Absolute time
    for date_fmt, length in [
        (
            "%Y%m%d%H%M%SZ",
            15,
        ),  # this also parses '202401020304Z', but as datetime(2024, 1, 2, 3, 0, 4)
        ("%Y%m%d%H%MZ", 13),
        (
            "%Y%m%d%H%M%S%z",
            14 + 5,
        ),  # this also parses '202401020304+0000', but as datetime(2024, 1, 2, 3, 0, 4, tzinfo=...)
        ("%Y%m%d%H%M%z", 12 + 5),
    ]:
        if len(result) != length:
            continue
        try:
            res = datetime.datetime.strptime(result, date_fmt)
        except ValueError:
            pass
        else:
            return add_or_remove_timezone(res, with_timezone=with_timezone)

    raise OpenSSLObjectError(
        f'The time spec "{input_string}" for {input_name} is invalid'
    )


__all__ = (
    "get_now_datetime",
    "ensure_utc_timezone",
    "remove_timezone",
    "add_or_remove_timezone",
    "get_epoch_seconds",
    "from_epoch_seconds",
    "convert_relative_to_datetime",
    "get_relative_time_option",
)
