# -*- coding: utf-8 -*-

# Copyright (c) 2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.routeros.plugins.module_utils.quoting import (
    ParseError,
    convert_list_to_dictionary,
    join_routeros_command,
    quote_routeros_argument,
    quote_routeros_argument_value,
    split_routeros_command,
)


def wrap_exception(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ParseError as e:
        raise AnsibleFilterError(to_text(e))


def split(line):
    '''
    Split a command into arguments.

    Example:
        'add name=wrap comment="with space"'
    is converted to:
        ['add', 'name=wrap', 'comment=with space']
    '''
    return wrap_exception(split_routeros_command, line)


def quote_argument_value(argument):
    '''
    Quote an argument value.

    Example:
        'with "space"'
    is converted to:
        r'"with \"space\""'
    '''
    return wrap_exception(quote_routeros_argument_value, argument)


def quote_argument(argument):
    '''
    Quote an argument.

    Example:
        'comment=with "space"'
    is converted to:
        r'comment="with \"space\""'
    '''
    return wrap_exception(quote_routeros_argument, argument)


def join(arguments):
    '''
    Join a list of arguments to a command.

    Example:
        ['add', 'name=wrap', 'comment=with space']
    is converted to:
        'add name=wrap comment="with space"'
    '''
    return wrap_exception(join_routeros_command, arguments)


def list_to_dict(string_list, require_assignment=True, skip_empty_values=False):
    '''
    Convert a list of arguments to a list of dictionary.

    Example:
        ['foo=bar', 'comment=with space', 'additional=']
    is converted to:
        {'foo': 'bar', 'comment': 'with space', 'additional': ''}

    If require_assignment is True (default), arguments without assignments are
    rejected. (Example: in ['add', 'name=foo'], 'add' is an argument without
    assignment.) If it is False, these are given value None.

    If skip_empty_values is True, arguments with empty value are removed from
    the result. (Example: in ['name='], 'name' has an empty value.)
    If it is False (default), these are kept.

    '''
    return wrap_exception(
        convert_list_to_dictionary,
        string_list,
        require_assignment=require_assignment,
        skip_empty_values=skip_empty_values,
    )


class FilterModule(object):
    '''Ansible jinja2 filters for RouterOS command quoting and unquoting'''

    def filters(self):
        return {
            'split': split,
            'quote_argument': quote_argument,
            'quote_argument_value': quote_argument_value,
            'join': join,
            'list_to_dict': list_to_dict,
        }
