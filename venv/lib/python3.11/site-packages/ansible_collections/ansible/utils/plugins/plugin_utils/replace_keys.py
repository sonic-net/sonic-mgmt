#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The replace_keys plugin code
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

import re

from ansible.errors import AnsibleFilterError


def _raise_error(msg):
    """Raise an error message, prepend with filter name
    :param msg: The message
    :type msg: str
    :raises: AnsibleError
    """
    error = "Error when using plugin 'replace_keys': {msg}".format(msg=msg)
    raise AnsibleFilterError(error)


def replace_keys_from_dict_n_list(data, target, matching_parameter):
    if isinstance(data, dict):
        for key in target:
            for k in list(data.keys()):
                if matching_parameter == "regex":
                    if re.match(key.get("before"), k):
                        data[key.get("after")] = data.pop(k)
                elif matching_parameter == "starts_with":
                    if k.startswith(key.get("before")):
                        data[key.get("after")] = data.pop(k)
                elif matching_parameter == "ends_with":
                    if k.endswith(key.get("before")):
                        data[key.get("after")] = data.pop(k)
                else:
                    if k == key.get("before"):
                        data[key.get("after")] = data.pop(k)
        for k, v in data.items():
            replace_keys_from_dict_n_list(v, target, matching_parameter)
    elif isinstance(data, list):
        for i in data:
            replace_keys_from_dict_n_list(i, target, matching_parameter)
    return data


def replace_keys(data, target, matching_parameter="equality"):
    """replaces specific keys with mentioned after data"
    :param data: The data passed in (data|replace_keys(...))
    :type data: raw
    :param target: List of keys on with operation is to be performed
    :type data: list
    :type elements: string
    :param matching_parameter: matching type of the target keys with data keys
    :type data: list
    :type elements: dict
    """
    if not isinstance(data, (list, dict)):
        _raise_error("Input is not valid for replace operation")
    data = replace_keys_from_dict_n_list(data, target, matching_parameter)
    return data
