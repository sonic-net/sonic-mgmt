# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


def normalize_str_values(d):
    """
    Return a new dict with all keys as str and values as str (None -> "").
    """
    if not d:
        return {}
    return {str(k): ("" if v is None else str(v)) for k, v in d.items()}


def validate_kv(d, name, allow_none):
    """
    Generic KV validator/normalizer.
    Returns: (ok: bool, normalized: dict|None, err: str|None)
    """
    if d is None:
        if allow_none:
            return True, {}, None
        return False, None, "{} must be a dict.".format(name)

    if not isinstance(d, dict):
        return False, None, "{} must be a dict.".format(name)

    return True, normalize_str_values(d), None


def diff_kv(desired, current):
    """
    Compare desired vs current (normalized) and return only the keys that differ.
    """
    desired_n = normalize_str_values(desired or {})
    current_n = normalize_str_values(current or {})
    to_apply = {}

    for k, dv in desired_n.items():
        if current_n.get(k) != dv:
            to_apply[k] = dv

    return to_apply
