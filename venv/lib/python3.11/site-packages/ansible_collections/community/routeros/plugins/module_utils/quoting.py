# -*- coding: utf-8 -*-

# Copyright (c) 2021, Felix Fontein (@felixfontein) <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import sys

from ansible.module_utils.common.text.converters import to_native, to_bytes


class ParseError(Exception):
    pass


ESCAPE_SEQUENCES = {
    b'"': b'"',
    b'\\': b'\\',
    b'?': b'?',
    b'$': b'$',
    b'_': b' ',
    b'a': b'\a',
    b'b': b'\b',
    b'f': b'\xFF',
    b'n': b'\n',
    b'r': b'\r',
    b't': b'\t',
    b'v': b'\v',
}

ESCAPE_SEQUENCE_REVERSED = dict([(v, k) for k, v in ESCAPE_SEQUENCES.items()])

ESCAPE_DIGITS = b'0123456789ABCDEF'


if sys.version_info[0] < 3:
    _int_to_byte = chr
else:
    def _int_to_byte(value):
        return bytes((value, ))


def parse_argument_value(line, start_index=0, must_match_everything=True):
    '''
    Parse an argument value (quoted or not quoted) from ``line``.

    Will start at offset ``start_index``. Returns pair ``(parsed_value,
    end_index)``, where ``end_index`` is the first character after the
    attribute.

    If ``must_match_everything`` is ``True`` (default), will fail if
    ``end_index < len(line)``.
    '''
    line = to_bytes(line)
    length = len(line)
    index = start_index
    if index == length:
        raise ParseError('Expected value, but found end of string')
    quoted = False
    if line[index:index + 1] == b'"':
        quoted = True
        index += 1
    current = []
    while index < length:
        ch = line[index:index + 1]
        index += 1
        if not quoted and ch == b' ':
            index -= 1
            break
        elif ch == b'"':
            if quoted:
                quoted = False
                if line[index:index + 1] not in (b'', b' '):
                    raise ParseError('Ending \'"\' must be followed by space or end of string')
                break
            raise ParseError('\'"\' must not appear in an unquoted value')
        elif ch == b'\\':
            if not quoted:
                raise ParseError('Escape sequences can only be used inside double quotes')
            if index == length:
                raise ParseError('\'\\\' must not be at the end of the line')
            ch = line[index:index + 1]
            index += 1
            if ch in ESCAPE_SEQUENCES:
                current.append(ESCAPE_SEQUENCES[ch])
            else:
                d1 = ESCAPE_DIGITS.find(ch)
                if d1 < 0:
                    raise ParseError('Invalid escape sequence \'\\{0}\''.format(to_native(ch)))
                if index == length:
                    raise ParseError('Hex escape sequence cut off at end of line')
                ch2 = line[index:index + 1]
                d2 = ESCAPE_DIGITS.find(ch2)
                index += 1
                if d2 < 0:
                    raise ParseError('Invalid hex escape sequence \'\\{0}\''.format(to_native(ch + ch2)))
                current.append(_int_to_byte(d1 * 16 + d2))
        else:
            if not quoted and ch in (b"'", b'=', b'(', b')', b'$', b'[', b'{', b'`'):
                raise ParseError('"{0}" can only be used inside double quotes'.format(to_native(ch)))
            if ch == b'?':
                raise ParseError('"{0}" can only be used in escaped form'.format(to_native(ch)))
            current.append(ch)
    if quoted:
        raise ParseError('Unexpected end of string during escaped parameter')
    if must_match_everything and index < length:
        raise ParseError('Unexpected data at end of value')
    return to_native(b''.join(current)), index


def split_routeros_command(line):
    line = to_bytes(line)
    result = []
    current = []
    index = 0
    length = len(line)
    parsing_attribute_name = False
    while index < length:
        ch = line[index:index + 1]
        index += 1
        if ch == b' ':
            if parsing_attribute_name:
                parsing_attribute_name = False
                result.append(b''.join(current))
                current = []
        elif ch == b'=' and parsing_attribute_name:
            current.append(ch)
            value, index = parse_argument_value(line, start_index=index, must_match_everything=False)
            current.append(to_bytes(value))
            parsing_attribute_name = False
            result.append(b''.join(current))
            current = []
        elif ch in (b'"', b'\\', b"'", b'=', b'(', b')', b'$', b'[', b'{', b'`', b'?'):
            raise ParseError('Found unexpected "{0}"'.format(to_native(ch)))
        else:
            current.append(ch)
            parsing_attribute_name = True
    if parsing_attribute_name and current:
        result.append(b''.join(current))
    return [to_native(part) for part in result]


def quote_routeros_argument_value(argument):
    argument = to_bytes(argument)
    result = []
    quote = False
    length = len(argument)
    index = 0
    while index < length:
        letter = argument[index:index + 1]
        index += 1
        if letter in ESCAPE_SEQUENCE_REVERSED:
            result.append(b'\\%s' % ESCAPE_SEQUENCE_REVERSED[letter])
            quote = True
            continue
        elif ord(letter) < 32:
            v = ord(letter)
            v1 = v % 16
            v2 = v // 16
            result.append(b'\\%s%s' % (ESCAPE_DIGITS[v2:v2 + 1], ESCAPE_DIGITS[v1:v1 + 1]))
            quote = True
            continue
        elif letter in (b' ', b'=', b';', b"'"):
            quote = True
        result.append(letter)
    argument = to_native(b''.join(result))
    if quote or not argument:
        argument = '"%s"' % argument
    return argument


def quote_routeros_argument(argument):
    def check_attribute(attribute):
        if ' ' in attribute:
            raise ParseError('Attribute names must not contain spaces')
        return attribute

    if '=' not in argument:
        check_attribute(argument)
        return argument

    attribute, value = argument.split('=', 1)
    check_attribute(attribute)
    value = quote_routeros_argument_value(value)
    return '%s=%s' % (attribute, value)


def join_routeros_command(arguments):
    return ' '.join([quote_routeros_argument(argument) for argument in arguments])


def convert_list_to_dictionary(string_list, require_assignment=True, skip_empty_values=False):
    dictionary = {}
    for p in string_list:
        if '=' not in p:
            if require_assignment:
                raise ParseError("missing '=' after '%s'" % p)
            dictionary[p] = None
            continue
        p = p.split('=', 1)
        if not skip_empty_values or p[1]:
            dictionary[p[0]] = p[1]
    return dictionary
