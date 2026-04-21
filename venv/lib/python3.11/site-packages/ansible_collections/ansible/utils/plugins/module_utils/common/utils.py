# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

from copy import deepcopy

from ansible.module_utils.common._collections_compat import Mapping
from ansible.module_utils.six import iteritems


def sort_list(val):
    if isinstance(val, list):
        if isinstance(val[0], dict):
            sorted_keys = [tuple(sorted(dict_.keys())) for dict_ in val]
            # All keys should be identical
            if len(set(sorted_keys)) != 1:
                raise ValueError("dictionaries do not match")

            return sorted(val, key=lambda d: tuple(d[k] for k in sorted_keys[0]))
        return sorted(val)
    return val


def dict_merge(base, other):
    """Return a new dict object that combines base and other

    This will create a new dict object that is a combination of the key/value
    pairs from base and other.  When both keys exist, the value will be
    selected from other.

    If the value in base is a list, and the value in other is a list
    the base list will be extended with the values from the other list that were
    not already present in the base list

    If the value in base is a list, and the value in other is a list
    and the two have the same entries, the value from other will be
    used, preserving the order from the other list

    If the value in base is a list, and the value in other is not a list
    the value from other will be used

    :param base: dict object to serve as base
    :param other: dict object to combine with base

    :returns: new combined dict object
    """
    if not isinstance(base, dict):
        raise AssertionError("`base` must be of type <dict>")
    if not isinstance(other, dict):
        raise AssertionError("`other` must be of type <dict>")

    combined = dict()

    for key, value in iteritems(deepcopy(base)):
        if isinstance(value, dict):
            if key in other:
                item = other.get(key)
                if item is not None:
                    if isinstance(other[key], Mapping):
                        combined[key] = dict_merge(value, other[key])
                    else:
                        combined[key] = other[key]
                else:
                    combined[key] = item
            else:
                combined[key] = value
        elif isinstance(value, list):
            if key in other:
                item = other.get(key)
                if isinstance(item, list):
                    if sort_list(value) == sort_list(item):
                        combined[key] = item
                    else:
                        value.extend([i for i in item if i not in value])
                        combined[key] = value
                else:
                    combined[key] = item
            else:
                combined[key] = value
        else:
            if key in other:
                other_value = other.get(key)
                if other_value is not None:
                    if sort_list(base[key]) != sort_list(other_value):
                        combined[key] = other_value
                    else:
                        combined[key] = value
                else:
                    combined[key] = other_value
            else:
                combined[key] = value

    for key in set(other.keys()).difference(base.keys()):
        combined[key] = other.get(key)

    return combined


def to_list(val):
    if isinstance(val, (list, tuple, set)):
        return list(val)
    elif val is not None:
        return [val]
    else:
        return list()
