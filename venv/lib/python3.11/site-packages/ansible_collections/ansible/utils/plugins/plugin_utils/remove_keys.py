#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The remove_keys plugin code
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
    error = "Error when using plugin 'remove_keys': {msg}".format(msg=msg)
    raise AnsibleFilterError(error)


def remove_keys_from_dict_n_list(data, target, matching_parameter):
    if isinstance(data, dict):
        for key in set(target):
            for k in list(data.keys()):
                if matching_parameter == "regex":
                    if re.match(key, k):
                        del data[k]
                elif matching_parameter == "starts_with":
                    if k.startswith(key):
                        del data[k]
                elif matching_parameter == "ends_with":
                    if k.endswith(key):
                        del data[k]
                else:
                    if k == key:
                        del data[k]
        for k, v in data.items():
            remove_keys_from_dict_n_list(v, target, matching_parameter)
    elif isinstance(data, list):
        for i in data:
            remove_keys_from_dict_n_list(i, target, matching_parameter)
    return data


def clear_empty_data(data):
    if isinstance(data, dict):
        # for k in list(data.keys()):
        #     if not data.get(k, {}):
        #         del data[k]
        for k, v in data.items():
            data[k] = clear_empty_data(v)
    if isinstance(data, list):
        temp = []
        for i in data:
            if i:
                temp.append(clear_empty_data(i))
        return temp
    return data


def remove_keys(data, target, matching_parameter="equality"):
    """Remove unwanted keys recursively from a given data"
    :param data: The data passed in (data|remove_keys(...))
    :type data: raw
    :param target: List of keys on with operation is to be performed
    :type data: list
    :type elements: string
    :param matching_parameter: matching type of the target keys with data keys
    :type data: str
    """
    if not isinstance(data, (list, dict)):
        _raise_error("Input is not valid for attribute removal")
    data = remove_keys_from_dict_n_list(data, target, matching_parameter)
    data = clear_empty_data(data)
    return data
