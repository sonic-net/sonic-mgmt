# Copyright (c) 2024, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Parse go logfmt messages.

See https://pkg.go.dev/github.com/kr/logfmt?utm_source=godoc for information on the format.
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


# The format is defined in https://pkg.go.dev/github.com/kr/logfmt?utm_source=godoc
# (look for "EBNFish")


class InvalidLogFmt(Exception):
    pass


class _Mode(object):
    GARBAGE = 0
    KEY = 1
    EQUAL = 2
    IDENT_VALUE = 3
    QUOTED_VALUE = 4


_ESCAPE_DICT = {
    '"': '"',
    '\\': '\\',
    "'": "'",
    '/': '/',
    'b': '\b',
    'f': '\f',
    'n': '\n',
    'r': '\r',
    't': '\t',
}

_HEX_DICT = {
    '0': 0,
    '1': 1,
    '2': 2,
    '3': 3,
    '4': 4,
    '5': 5,
    '6': 6,
    '7': 7,
    '8': 8,
    '9': 9,
    'a': 0xA,
    'b': 0xB,
    'c': 0xC,
    'd': 0xD,
    'e': 0xE,
    'f': 0xF,
    'A': 0xA,
    'B': 0xB,
    'C': 0xC,
    'D': 0xD,
    'E': 0xE,
    'F': 0xF,
}


def _is_ident(cur):
    return cur > ' ' and cur not in ('"', '=')


class _Parser(object):
    def __init__(self, line):
        self.line = line
        self.index = 0
        self.length = len(line)

    def done(self):
        return self.index >= self.length

    def cur(self):
        return self.line[self.index]

    def next(self):
        self.index += 1

    def prev(self):
        self.index -= 1

    def parse_unicode_sequence(self):
        if self.index + 6 > self.length:
            raise InvalidLogFmt('Not enough space for unicode escape')
        if self.line[self.index:self.index + 2] != '\\u':
            raise InvalidLogFmt('Invalid unicode escape start')
        v = 0
        for i in range(self.index + 2, self.index + 6):
            v <<= 4
            try:
                v += _HEX_DICT[self.line[self.index]]
            except KeyError:
                raise InvalidLogFmt('Invalid unicode escape digit {digit!r}'.format(digit=self.line[self.index]))
        self.index += 6
        return chr(v)


def parse_line(line, logrus_mode=False):
    result = {}
    parser = _Parser(line)
    key = []
    value = []
    mode = _Mode.GARBAGE

    def handle_kv(has_no_value=False):
        k = ''.join(key)
        v = None if has_no_value else ''.join(value)
        result[k] = v
        del key[:]
        del value[:]

    def parse_garbage(cur):
        if _is_ident(cur):
            return _Mode.KEY
        parser.next()
        return _Mode.GARBAGE

    def parse_key(cur):
        if _is_ident(cur):
            key.append(cur)
            parser.next()
            return _Mode.KEY
        elif cur == '=':
            parser.next()
            return _Mode.EQUAL
        else:
            if logrus_mode:
                raise InvalidLogFmt('Key must always be followed by "=" in logrus mode')
            handle_kv(has_no_value=True)
            parser.next()
            return _Mode.GARBAGE

    def parse_equal(cur):
        if _is_ident(cur):
            value.append(cur)
            parser.next()
            return _Mode.IDENT_VALUE
        elif cur == '"':
            parser.next()
            return _Mode.QUOTED_VALUE
        else:
            handle_kv()
            parser.next()
            return _Mode.GARBAGE

    def parse_ident_value(cur):
        if _is_ident(cur):
            value.append(cur)
            parser.next()
            return _Mode.IDENT_VALUE
        else:
            handle_kv()
            parser.next()
            return _Mode.GARBAGE

    def parse_quoted_value(cur):
        if cur == '\\':
            parser.next()
            if parser.done():
                raise InvalidLogFmt('Unterminated escape sequence in quoted string')
            cur = parser.cur()
            if cur in _ESCAPE_DICT:
                value.append(_ESCAPE_DICT[cur])
            elif cur != 'u':
                raise InvalidLogFmt('Unknown escape sequence {seq!r}'.format(seq='\\' + cur))
            else:
                parser.prev()
                value.append(parser.parse_unicode_sequence())
            parser.next()
            return _Mode.QUOTED_VALUE
        elif cur == '"':
            handle_kv()
            parser.next()
            return _Mode.GARBAGE
        elif cur < ' ':
            raise InvalidLogFmt('Control characters in quoted string are not allowed')
        else:
            value.append(cur)
            parser.next()
            return _Mode.QUOTED_VALUE

    parsers = {
        _Mode.GARBAGE: parse_garbage,
        _Mode.KEY: parse_key,
        _Mode.EQUAL: parse_equal,
        _Mode.IDENT_VALUE: parse_ident_value,
        _Mode.QUOTED_VALUE: parse_quoted_value,
    }
    while not parser.done():
        mode = parsers[mode](parser.cur())
    if mode == _Mode.KEY and logrus_mode:
        raise InvalidLogFmt('Key must always be followed by "=" in logrus mode')
    if mode == _Mode.KEY or mode == _Mode.EQUAL:
        handle_kv(has_no_value=True)
    elif mode == _Mode.IDENT_VALUE:
        handle_kv()
    elif mode == _Mode.QUOTED_VALUE:
        raise InvalidLogFmt('Unterminated quoted string')
    return result
