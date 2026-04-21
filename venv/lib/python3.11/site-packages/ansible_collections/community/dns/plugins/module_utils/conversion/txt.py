# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import sys
import warnings

from ansible.module_utils.common.text.converters import to_bytes, to_text
from ansible_collections.community.dns.plugins.module_utils.conversion.base import (
    DNSConversionError,
)


_DECIMAL_DIGITS = b'0123456789'

_STATE_OUTSIDE = 0
_STATE_QUOTED_STRING = 1
_STATE_UNQUOTED_STRING = 3


if sys.version_info[0] < 3:
    _int_to_byte = chr
else:
    def _int_to_byte(value):
        return bytes((value, ))


def _parse_quoted(value, index, use_octal):
    if index == len(value):
        raise DNSConversionError(u'Unexpected backslash at end of string')
    letter = value[index:index + 1]
    index += 1
    if letter in (b'\\', b'"'):
        return letter, index
    # This must be a decimal sequence
    v2 = _DECIMAL_DIGITS.find(letter)
    if v2 < 0 or (use_octal and v2 >= 8):
        # It is apparently not - error out
        raise DNSConversionError(
            u'A backslash must not be followed by "{letter}" (index {index})'.format(letter=to_text(letter), index=index))
    if index + 1 >= len(value):
        # We need more letters for a three-digit decimal sequence
        raise DNSConversionError(
            u'The {type} sequence at the end requires {missing} more digit(s)'.format(
                type='octal' if use_octal else 'decimal', missing=index + 2 - len(value)))
    letter = value[index:index + 1]
    index += 1
    v1 = _DECIMAL_DIGITS.find(letter)
    if v1 < 0 or (use_octal and v1 >= 8):
        raise DNSConversionError(
            u'The second letter of the {type} sequence at index {index} is not a {type} digit, but "{letter}"'.format(
                type='octal' if use_octal else 'decimal', letter=to_text(letter), index=index))
    letter = value[index:index + 1]
    index += 1
    v0 = _DECIMAL_DIGITS.find(letter)
    if v0 < 0 or (use_octal and v0 >= 8):
        raise DNSConversionError(
            u'The third letter of the {type} sequence at index {index} is not a {type} digit, but "{letter}"'.format(
                type='octal' if use_octal else 'decimal', letter=to_text(letter), index=index))
    if use_octal:
        return _int_to_byte(v2 * 64 + v1 * 8 + v0), index
    return _int_to_byte(v2 * 100 + v1 * 10 + v0), index


_SENTINEL = object()


def decode_txt_value(value, character_encoding=_SENTINEL):
    """
    Given an encoded TXT value, decodes it.

    Raises DNSConversionError in case of errors.
    """
    if character_encoding is _SENTINEL:
        warnings.warn(
            'The default value of the decode_txt_value parameter character_encoding is deprecated.'
            ' Set explicitly to "octal" for the old behavior, or set to "decimal" for the new and correct behavior.',
            DeprecationWarning,
        )
        character_encoding = 'octal'
    if character_encoding not in ('octal', 'decimal'):
        raise ValueError('character_encoding must be set to "octal" or "decimal"')
    value = to_bytes(value)
    state = _STATE_OUTSIDE
    index = 0
    length = len(value)
    result = []
    while index < length:
        letter = value[index:index + 1]
        index += 1
        if letter == b' ':
            if state == _STATE_QUOTED_STRING:
                result.append(letter)
            else:
                state = _STATE_OUTSIDE
        elif letter == b'\\':
            if state != _STATE_QUOTED_STRING:
                state = _STATE_UNQUOTED_STRING
            letter, index = _parse_quoted(value, index, character_encoding == 'octal')
            result.append(letter)
        elif letter == b'"':
            if state == _STATE_QUOTED_STRING:
                state = _STATE_OUTSIDE
            elif state == _STATE_OUTSIDE:
                state = _STATE_QUOTED_STRING
            else:
                raise DNSConversionError(
                    u'Unexpected double quotation mark inside an unquoted block at position {index}'.format(index=index))
        else:
            if state != _STATE_QUOTED_STRING:
                state = _STATE_UNQUOTED_STRING
            result.append(letter)

    if state == _STATE_QUOTED_STRING:
        raise DNSConversionError(u'Missing double quotation mark at the end of value')

    return to_text(b''.join(result))


def _get_utf8_length(first_byte_value):
    """
    Given the byte value of a UTF-8 letter, returns the length of the UTF-8 character.
    """
    if first_byte_value & 0xE0 == 0xC0:
        return 2
    if first_byte_value & 0xF0 == 0xE0:
        return 3
    if first_byte_value & 0xF8 == 0xF0:
        return 4
    # Should not happen
    return 1


def encode_txt_value(value, always_quote=False, use_character_encoding=_SENTINEL, use_octal=_SENTINEL, character_encoding=_SENTINEL):
    """
    Given a decoded TXT value, encodes it.

    If always_quote is set to True, always use double quotes for all strings.
    If use_character_encoding (default: True) is set to False, do not use octal encoding.
    """
    if use_octal is not _SENTINEL:
        warnings.warn(
            'The encode_txt_value parameter use_octal is deprecated. Use use_character_encoding instead.',
            DeprecationWarning,
        )
        if use_character_encoding is not _SENTINEL:
            raise ValueError('Cannot use both use_character_encoding and use_octal. Use only use_character_encoding!')
        use_character_encoding = use_octal
    if use_character_encoding is _SENTINEL:
        use_character_encoding = True
    if character_encoding is _SENTINEL:
        warnings.warn(
            'The default value of the encode_txt_value parameter character_encoding is deprecated.'
            ' Set explicitly to "octal" for the old behavior, or set to "decimal" for the new and correct behavior.',
            DeprecationWarning,
        )
        character_encoding = 'octal'
    if character_encoding not in ('octal', 'decimal'):
        raise ValueError('character_encoding must be set to "octal" or "decimal"')

    value = to_bytes(value)
    buffer = []
    output = []

    def append(buffer):
        value = b''.join(buffer)
        if b' ' in value or not value or always_quote:
            value = b'"%s"' % value
        output.append(value)

    index = 0
    length = len(value)
    while index < length:
        letter = value[index:index + 1]
        index += 1

        # Add letter
        if letter in (b'"', b'\\'):
            # Make sure that we do not split up an escape sequence over multiple TXT strings
            if len(buffer) + 2 > 255:
                append(buffer[:255])
                buffer = buffer[255:]
            buffer.append(b'\\')
            buffer.append(letter)
        elif use_character_encoding and not 0x20 <= ord(letter) < 0x7F:
            # Make sure that we do not split up a decimal sequence over multiple TXT strings
            if len(buffer) + 4 > 255:
                append(buffer[:255])
                buffer = buffer[255:]
            letter_value = ord(letter)
            buffer.append(b'\\')
            if character_encoding == 'octal':
                v2 = (letter_value >> 6) & 7
                v1 = (letter_value >> 3) & 7
                v0 = letter_value & 7
            else:
                v2 = (letter_value // 100) % 10
                v1 = (letter_value // 10) % 10
                v0 = letter_value % 10
            buffer.append(_DECIMAL_DIGITS[v2:v2 + 1])
            buffer.append(_DECIMAL_DIGITS[v1:v1 + 1])
            buffer.append(_DECIMAL_DIGITS[v0:v0 + 1])
        elif not use_character_encoding and (ord(letter) & 0x80) != 0:
            utf8_length = min(_get_utf8_length(ord(letter)), length - index + 1)
            # Make sure that we do not split up a UTF-8 letter over multiple TXT strings
            if len(buffer) + utf8_length > 255:
                append(buffer[:255])
                buffer = buffer[255:]
            buffer.append(letter)
            while utf8_length > 1:
                buffer.append(value[index:index + 1])
                index += 1
                utf8_length -= 1
        else:
            buffer.append(letter)

        # Split if too long
        if len(buffer) >= 255:
            append(buffer[:255])
            buffer = buffer[255:]

    if buffer or not output:
        append(buffer)

    return to_text(b' '.join(output))
