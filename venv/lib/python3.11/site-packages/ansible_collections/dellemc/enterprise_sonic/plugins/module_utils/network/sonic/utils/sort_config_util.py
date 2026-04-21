#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import (
    deepcopy
)


def get_dict_list_key_set(dict_conf):
    key_set = set(dict_conf.keys())
    dict_list_key_set = set()
    for key in key_set:
        if dict_conf[key] not in [None, [], {}]:
            if isinstance(dict_conf[key], (list, dict)):
                dict_list_key_set.add(key)
    return dict_list_key_set


def get_test_key_tuple(key, test_keys):
    s_key_tub = tuple()
    if not key or not test_keys:
        return s_key_tub

    s_info = next((s_key_item[key] for s_key_item in test_keys if key in s_key_item), None)
    if s_info:
        s_key_tub = s_info.get('__test_keys', tuple())

    return s_key_tub


def get_sort_op(key, test_keys):
    sk_op = __SORT_OP_DEFAULT
    if not key or not test_keys:
        return sk_op

    s_info = next((s_key_item[key] for s_key_item in test_keys if key in s_key_item), None)
    if s_info:
        sk_op = s_info.get('__sort_op', __SORT_OP_DEFAULT)

    return sk_op


"""
This is default sort operation.
It is supposed that the values of config[key] should not be None.
If any value may be None, the sort operation should be customized.
"""


def __SORT_OP_DEFAULT(key_tuple, config):
    val_tub = tuple()
    for key in key_tuple:
        val_tub = val_tub + tuple([config[key]])
    return val_tub


def sort_config(config, test_keys=None):

    if not config:
        return config

    if isinstance(config, list):
        new_conf_dict = sort_config_dict({"config": config}, test_keys)
        new_conf = new_conf_dict.get("config", [])
    elif isinstance(config, dict):
        new_conf = sort_config_dict(config, test_keys)
    else:
        new_conf = config

    return new_conf


def sort_config_dict(config, test_keys=None):

    if not config:
        return []

    if test_keys is None:
        test_keys = []

    new_conf = dict(sorted(config.items()))

    dict_list_key_set = get_dict_list_key_set(new_conf)
    for key in dict_list_key_set:

        conf_value = new_conf[key]

        if isinstance(conf_value, list):
            c_list = conf_value
            not_dict_item = False
            new_conf_list = list()
            for c_item in c_list:
                if isinstance(c_item, dict):
                    new_conf_dict = sort_config_dict(c_item, test_keys)
                    new_conf_list.append(new_conf_dict)
                else:
                    not_dict_item = True
                    break

            if not_dict_item:
                new_conf[key].sort()
            elif new_conf_list:
                conf_value = new_conf_list
                s_key_tuple = get_test_key_tuple(key, test_keys)
                s_key_op = get_sort_op(key, test_keys)
                if s_key_tuple:
                    conf_value = sorted(conf_value, key=lambda x: s_key_op(s_key_tuple, x))
                new_conf[key] = conf_value

        elif isinstance(conf_value, dict):
            new_conf[key] = sort_config_dict(conf_value, test_keys)

        else:
            continue

    return new_conf


def remove_void_config(config, test_keys=None):

    if not config:
        return config

    if isinstance(config, list):
        new_conf_dict = remove_void_config_dict({"config": config}, test_keys)
        new_conf = new_conf_dict.get("config", [])
    elif isinstance(config, dict):
        new_conf = remove_void_config_dict(config, test_keys)
    else:
        new_conf = config

    return new_conf


def remove_void_config_dict(config, test_keys=None, key_tuple=None):

    if not config:
        return []

    if test_keys is None:
        test_keys = []

    if key_tuple is None:
        key_tuple = tuple()

    new_conf = deepcopy(config)

    dict_list_key_set = get_dict_list_key_set(new_conf)
    for key in dict_list_key_set:

        conf_value = new_conf[key]
        t_key_tuple = get_test_key_tuple(key, test_keys)

        if isinstance(conf_value, list):
            c_list = conf_value
            not_dict_item = False
            new_conf_list = list()
            for c_item in c_list:
                if isinstance(c_item, dict):
                    new_conf_dict = remove_void_config_dict(c_item, test_keys, t_key_tuple)
                    if new_conf_dict:
                        new_conf_list.append(new_conf_dict)
                else:
                    not_dict_item = True
                    break

            if not not_dict_item:
                new_conf[key] = new_conf_list

        elif isinstance(conf_value, dict):
            new_conf[key] = remove_void_config_dict(conf_value, test_keys, t_key_tuple)

        else:
            continue

    n_keys = []
    for n_key in new_conf:
        if new_conf[n_key] in [None, [], {}]:
            n_keys.append(n_key)
    for n_key in n_keys:
        del new_conf[n_key]
    if len(new_conf.keys()) <= len(key_tuple):
        new_conf = []

    return new_conf
