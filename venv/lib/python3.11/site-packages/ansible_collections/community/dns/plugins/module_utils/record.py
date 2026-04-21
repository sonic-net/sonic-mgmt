# -*- coding: utf-8 -*-
#
# Copyright (c) 2017-2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


def format_ttl(ttl):
    if ttl is None:
        return 'default'
    sec = ttl % 60
    ttl //= 60
    mins = ttl % 60
    ttl //= 60
    h = ttl
    result = []
    if h:
        result.append('{0}h'.format(h))
    if mins:
        result.append('{0}m'.format(mins))
    if sec:
        result.append('{0}s'.format(sec))
    return ' '.join(result)


class DNSRecord(object):
    def __init__(self):
        self.id = None
        self.type = None
        self.prefix = None
        self.target = None
        self.ttl = 86400  # 24 * 60 * 60
        self.extra = {}

    def clone(self):
        result = DNSRecord()
        result.id = self.id
        result.type = self.type
        result.prefix = self.prefix
        result.target = self.target
        result.ttl = self.ttl
        result.extra = dict(self.extra)
        return result

    def __str__(self):
        data = []
        if self.id:
            data.append('id: {0}'.format(self.id))
        data.append('type: {0}'.format(self.type))
        if self.prefix:
            data.append('prefix: "{0}"'.format(self.prefix))
        else:
            data.append('prefix: (none)')
        data.append('target: "{0}"'.format(self.target))
        data.append('ttl: {0}'.format(format_ttl(self.ttl)))
        if self.extra:
            data.append('extra: {0}'.format(self.extra))
        return 'DNSRecord(' + ', '.join(data) + ')'

    def __repr__(self):
        return self.__str__()


def sorted_ttls(ttls):
    return sorted(ttls, key=lambda ttl: 0 if ttl is None else ttl)


def format_records_for_output(records, record_name, prefix=None, record_converter=None):
    ttls = sorted_ttls({record.ttl for record in records})
    entry = {
        'prefix': prefix or '',
        'type': min(record.type for record in records) if records else None,
        'ttl': ttls[0] if len(ttls) > 0 else None,
        'value': [record.target for record in records],
    }
    if record_converter:
        entry['value'] = record_converter.process_values_to_user(entry['type'], entry['value'])
    if record_name is not None:
        entry['record'] = record_name
    if len(ttls) > 1:
        entry['ttls'] = ttls
    return entry


def format_record_for_output(record, record_name, prefix=None, record_converter=None):
    entry = {
        'prefix': prefix or '',
        'type': record.type,
        'ttl': record.ttl,
        'value': record.target,
        'extra': record.extra,
    }
    if record_converter:
        entry['value'] = record_converter.process_value_to_user(entry['type'], entry['value'])
    if record_name is not None:
        entry['record'] = record_name
    return entry
