# -*- coding: utf-8 -*-

# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import sys

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.parsing.convert_bool import boolean


if sys.version_info[0] == 2:
    string_types = (basestring,)  # noqa: F821, pylint: disable=undefined-variable
else:
    string_types = (str,)

try:
    from collections.abc import Mapping
except ImportError:
    # Python 2.x
    from collections import Mapping  # pylint: disable=deprecated-class


_ALLOWED_KEYS = ("include", "exclude")


def parse_filters(filters):
    """
    Parse get_option('filter') and return normalized version to be fed into filter_host().
    """
    result = []
    if filters is None:
        return result
    for index, a_filter in enumerate(filters):
        if not isinstance(a_filter, Mapping):
            raise AnsibleError(
                "filter[{index}] must be a dictionary".format(
                    index=index + 1,
                )
            )
        a_filter = dict(  # pylint: disable=consider-using-dict-comprehension
            [
                (k, v)
                for k, v in a_filter.items()
                if k not in _ALLOWED_KEYS or v is not None
            ]
        )
        if len(a_filter) != 1:
            raise AnsibleError(
                "filter[{index}] must have exactly one key-value pair".format(
                    index=index + 1,
                )
            )
        key, value = list(a_filter.items())[0]
        if key not in _ALLOWED_KEYS:
            raise AnsibleError(
                'filter[{index}] must have a {allowed_keys} key, not "{key}"'.format(
                    index=index + 1,
                    key=key,
                    allowed_keys=" or ".join(
                        '"{key}"'.format(key=key) for key in _ALLOWED_KEYS
                    ),
                )
            )
        if not isinstance(value, (string_types, bool)):
            raise AnsibleError(
                "filter[{index}].{key} must be a string, not {value_type}".format(
                    index=index + 1,
                    key=key,
                    value_type=type(value),
                )
            )
        result.append(a_filter)
    return result


def filter_host(inventory_plugin, host, host_vars, filters):
    """
    Determine whether a host should be accepted (``True``) or not (``False``).
    """
    template_vars = {
        "inventory_hostname": host,
    }
    if host_vars:
        template_vars.update(host_vars)

    def evaluate(condition):
        if isinstance(condition, bool):
            return condition
        templar = inventory_plugin.templar
        old_vars = templar.available_variables
        try:
            templar.available_variables = template_vars
            if hasattr(templar, "evaluate_expression"):
                # This is available since the Data Tagging PR has been merged
                return templar.evaluate_conditional(condition)
            conditional = (
                "{%% if %s %%} True {%% else %%} False {%% endif %%}" % condition
            )
            return boolean(templar.template(conditional))
        except Exception as e:
            raise AnsibleParserError(
                "Could not evaluate filter condition {condition!r} for host {host}: {err}".format(
                    host=host,
                    condition=condition,
                    err=to_native(e),
                )
            )
        finally:
            templar.available_variables = old_vars

    for a_filter in filters:
        if "include" in a_filter:
            expr = a_filter["include"]
            if evaluate(expr):
                return True
        if "exclude" in a_filter:
            expr = a_filter["exclude"]
            if evaluate(expr):
                return False

    return True
