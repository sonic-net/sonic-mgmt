# -*- coding: utf-8 -*-
# Copyright (c) 2022, Felix Fontein (@felixfontein) <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# The data inside here is private to this collection. If you use this from outside the collection,
# you are on your own. There can be random changes to its format even in bugfix releases!

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re

from ansible.module_utils.common.text.converters import to_text


def value_to_str(value, compat_bool=False, none_to_empty=False):
    if value is None:
        return '' if none_to_empty else None
    if value is True:
        return 'true' if compat_bool else 'yes'
    if value is False:
        return 'false' if compat_bool else 'no'
    return to_text(value)


def validate_and_prepare_restrict(module, path_info, compat=True):
    restrict = module.params['restrict']
    if restrict is None:
        return None
    restrict_data = []
    for rule in restrict:
        field = rule['field']
        if field.startswith('!'):
            module.fail_json(msg='restrict: the field name "{0}" must not start with "!"'.format(field))
        f = path_info.fields.get(field)
        if f is None:
            module.fail_json(msg='restrict: the field "{0}" does not exist for this path'.format(field))

        new_rule = dict(
            field=field,
            match_disabled=rule['match_disabled'],
            invert=rule['invert'],
        )
        if rule['values'] is not None:
            if compat:
                new_rule['values'] = rule['values']
            else:
                new_rule['values'] = [value_to_str(v, none_to_empty=False) for v in rule['values']]
        if rule['regex'] is not None:
            regex = rule['regex']
            try:
                new_rule['regex'] = re.compile(regex)
                new_rule['regex_source'] = regex
            except Exception as exc:
                module.fail_json(msg='restrict: invalid regular expression "{0}": {1}'.format(regex, exc))
        restrict_data.append(new_rule)
    return restrict_data


def _test_rule_except_invert(value, rule, compat=False):
    if value is None and rule['match_disabled']:
        return True
    if 'values' in rule:
        v = value if compat else value_to_str(value, none_to_empty=False)
        if v in rule['values']:
            return True
    if 'regex' in rule and value is not None and rule['regex'].match(value_to_str(value, compat_bool=compat)):
        return True
    return False


def restrict_entry_accepted(entry, path_info, restrict_data, compat=True):
    if restrict_data is None:
        return True
    for rule in restrict_data:
        # Obtain field and value
        field = rule['field']
        field_info = path_info.fields[field]
        value = entry.get(field)
        if value is None:
            value = field_info.default
        if field not in entry and field_info.absent_value:
            value = field_info.absent_value

        # Check
        matches_rule = _test_rule_except_invert(value, rule, compat=compat)
        if rule['invert']:
            matches_rule = not matches_rule
        if not matches_rule:
            return False
    return True


def restrict_argument_spec():
    return dict(
        restrict=dict(
            type='list',
            elements='dict',
            options=dict(
                field=dict(type='str', required=True),
                match_disabled=dict(type='bool', default=False),
                values=dict(type='list', elements='raw'),
                regex=dict(type='str'),
                invert=dict(type='bool', default=False),
            ),
        ),
    )
