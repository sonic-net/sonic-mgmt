# -*- coding: utf-8 -*-
#
# Copyright (c) 2017-2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import sys


if sys.version_info >= (3, 6):
    import typing

    if typing.TYPE_CHECKING:
        from .record import DNSRecord  # pragma: no cover


class DNSZone(object):
    def __init__(
        self,
        name,  # type: str
        info=None,  # type: dict[str, typing.Any] | None
    ):  # type: (...) -> None
        self.id = None  # type: str | None
        self.name = name  # type: str
        self.info = info or {}  # type: dict[str, typing.Any]

    def __str__(self):  # type: (...) -> str
        data = []
        if self.id is not None:
            data.append('id: {0}'.format(self.id))
        data.append('name: {0}'.format(self.name))
        data.append('info: {0}'.format(self.info))
        return 'DNSZone(' + ', '.join(data) + ')'

    def __repr__(self):  # type: (...) -> str
        return self.__str__()


class DNSZoneWithRecords(object):
    def __init__(
        self,
        zone,  # type: DNSZone
        records,  # type: list[DNSRecord]
    ):  # type: (...) -> None
        self.zone = zone  # type: DNSZone
        self.records = records  # type: list[DNSRecord]

    def __str__(self):  # type: (...) -> str
        return '({0}, {1})'.format(self.zone, self.records)

    def __repr__(self):  # type: (...) -> str
        return 'DNSZoneWithRecords({0!r}, {1!r})'.format(self.zone, self.records)
