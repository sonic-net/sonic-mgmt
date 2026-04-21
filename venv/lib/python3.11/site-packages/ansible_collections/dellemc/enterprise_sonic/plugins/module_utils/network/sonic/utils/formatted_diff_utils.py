#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
from copy import (
    deepcopy
)
from difflib import (
    context_diff
)


def get_key_sets(dict_conf):
    key_set = set(dict_conf.keys())
    trival_key_set = set()
    dict_list_key_set = set()
    for key in key_set:
        if dict_conf[key] not in [None, [], {}]:
            if isinstance(dict_conf[key], (list, dict)):
                dict_list_key_set.add(key)
            else:
                trival_key_set.add(key)
    return trival_key_set, dict_list_key_set


def get_test_key_set(key, test_keys):
    tst_keys = deepcopy(test_keys)
    t_key_set = set()
    if not tst_keys or not key:
        return t_key_set

    t_keys = next((t_key_item[key] for t_key_item in tst_keys if key in t_key_item), None)
    if t_keys:
        t_keys.pop('__merge_op', None)
        t_keys.pop('__delete_op', None)
        t_keys.pop('__key_match_op', None)
        t_key_set = set(t_keys.keys())

    return t_key_set


#
# Pre-defined Key Match Operations
#


"""
Default key match operation.
"""


def __KEY_MATCH_OP_DEFAULT(key_set, command, exist_conf):
    trival_cmd_key_set, dict_list_cmd_key_set = get_key_sets(command)
    trival_exist_key_set, dict_list_exist_key_set = get_key_sets(exist_conf)

    common_trival_key_set = trival_cmd_key_set.intersection(trival_exist_key_set)
    common_dict_list_key_set = dict_list_cmd_key_set.intersection(dict_list_exist_key_set)

    key_matched_cnt = 0
    key_present_cnt = 0
    common_keys = common_trival_key_set.union(common_dict_list_key_set)
    for key in key_set:
        if key in common_keys:
            key_present_cnt += 1
            if command[key] == exist_conf[key]:
                key_matched_cnt += 1

    key_matched = (key_matched_cnt == key_present_cnt)
    return key_matched


def get_key_match_op(key, test_keys):
    k_match_op = __KEY_MATCH_OP_DEFAULT
    t_key_set = set()
    if not test_keys or not key:
        return k_match_op

    t_keys = next((t_key_item[key] for t_key_item in test_keys if key in t_key_item), None)
    if t_keys:
        k_match_op = t_keys.get('__key_match_op', __KEY_MATCH_OP_DEFAULT)

    return k_match_op


#
# Pre-defined Merge Operations
#


"""
Default key match operation: simply merge command to existing config.
"""


def __MERGE_OP_DEFAULT(key_set, command, exist_conf):
    new_conf = exist_conf
    trival_cmd_key_set, dict_list_cmd_key_set = get_key_sets(command)
    nu, dict_list_exist_key_set = get_key_sets(new_conf)

    for key in trival_cmd_key_set:
        new_conf[key] = command[key]

    only_cmd_dict_list_key_set = dict_list_cmd_key_set.difference(dict_list_exist_key_set)
    for key in only_cmd_dict_list_key_set:
        new_conf[key] = command[key]

    return False, new_conf


merge_op_dft = __MERGE_OP_DEFAULT


def get_merge_op(key, test_keys):
    mrg_op = merge_op_dft
    if not test_keys:
        return mrg_op
    if not key:
        key = '__default_ops'
    t_keys = next((t_key_item[key] for t_key_item in test_keys if key in t_key_item), None)
    if t_keys:
        mrg_op = t_keys.get('__merge_op', merge_op_dft)

    return mrg_op


#
# Pre-defined Delete Operations
#


"""
Delete entire configuration.
"""


def __DELETE_CONFIG(key_set, command, exist_conf):
    new_conf = []
    return True, new_conf


"""
Delete entire configuration if there is no sub-configuration.
"""


def __DELETE_CONFIG_IF_NO_SUBCONFIG(key_set, command, exist_conf):
    nu, dict_list_cmd_key_set = get_key_sets(command)
    if len(dict_list_cmd_key_set) == 0:
        new_conf = []
        return True, new_conf
    else:
        new_conf = exist_conf
        return False, new_conf


"""
Delete sub-configuration and leaf configuration, if any.
"""


def __DELETE_SUBCONFIG_AND_LEAFS(key_set, command, exist_conf):
    new_conf = exist_conf

    trival_cmd_key_set, dict_list_cmd_key_set = get_key_sets(command)
    trival_cmd_key_not_key_set = trival_cmd_key_set.difference(key_set)
    for key in trival_cmd_key_not_key_set:
        new_conf.pop(key, None)

    nu, dict_list_exist_key_set = get_key_sets(exist_conf)
    common_dict_list_key_set = dict_list_cmd_key_set.intersection(dict_list_exist_key_set)
    if len(common_dict_list_key_set) != 0:
        for key in common_dict_list_key_set:
            new_conf.pop(key, None)

    return True, new_conf


"""
Delete sub-configuration only, if any.
"""


def __DELETE_SUBCONFIG_ONLY(key_set, command, exist_conf):
    new_conf = exist_conf
    nu, dict_list_cmd_key_set = get_key_sets(command)
    nu, dict_list_exist_key_set = get_key_sets(exist_conf)
    common_dict_list_key_set = dict_list_cmd_key_set.intersection(dict_list_exist_key_set)
    for key in common_dict_list_key_set:
        new_conf.pop(key, None)
    return True, new_conf


"""
Delete configuration if there is no non-key leaf, and
delete non-key leaf configuration, if any.
"""


def __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf):
    new_conf = exist_conf
    trival_cmd_key_set, dict_list_cmd_key_set = get_key_sets(command)

    if (len(key_set) == len(trival_cmd_key_set)) and \
       (len(dict_list_cmd_key_set) == 0):
        new_conf = []
        return True, new_conf

    trival_cmd_key_not_key_set = trival_cmd_key_set.difference(key_set)
    for key in trival_cmd_key_not_key_set:
        new_conf.pop(key, None)

    return False, new_conf


"""
Delete non-key leafs, if any. Then
delete configuration if no non-key leaf.
"""


def __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf):
    new_conf = exist_conf
    trival_cmd_key_set, dict_list_cmd_key_set = get_key_sets(command)

    trival_cmd_key_not_key_set = trival_cmd_key_set.difference(key_set)
    for key in trival_cmd_key_not_key_set:
        new_conf.pop(key, None)

    trival_exist_key_set, dict_list_exist_key_set = get_key_sets(new_conf)
    trival_exist_key_not_key_set = trival_exist_key_set.difference(key_set)
    if len(trival_exist_key_not_key_set) == 0 and len(dict_list_exist_key_set) == 0:
        new_conf = []
        return True, new_conf

    return False, new_conf


"""
Delete non-key leafs with same values, if any. Then
delete configuration if no non-key leaf.
"""


def __DELETE_SAME_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf):
    new_conf = exist_conf
    trival_cmd_key_set, dict_list_cmd_key_set = get_key_sets(command)

    trival_cmd_key_not_key_set = trival_cmd_key_set.difference(key_set)
    for key in trival_cmd_key_not_key_set:
        command_val = command.get(key, None)
        new_conf_val = new_conf.get(key, None)
        if command_val == new_conf_val:
            new_conf.pop(key, None)

    trival_exist_key_set, dict_list_exist_key_set = get_key_sets(new_conf)
    trival_exist_key_not_key_set = trival_exist_key_set.difference(key_set)
    if len(trival_exist_key_not_key_set) == 0 and len(dict_list_exist_key_set) == 0:
        new_conf = []
        return True, new_conf

    return False, new_conf


"""
Delete configuration if no non-key leaf or sub-configuration.
"""


def __DELETE_CONFIG_IF_NO_NON_KEY_LEAF_OR_SUBCONFIG(key_set, command, exist_conf):
    new_conf = exist_conf
    trival_cmd_key_set, dict_list_cmd_key_set = get_key_sets(command)

    trival_cmd_key_not_key_set = trival_cmd_key_set.difference(key_set)
    if len(trival_cmd_key_not_key_set) == 0 and len(dict_list_cmd_key_set) == 0:
        new_conf = []
        return True, new_conf

    return False, new_conf


"""
This is default deletion operation.
Delete configuration if there is no non-key leaf, and
delete non-key leaf configuration, if any, if the values of non-key leaf are
equal between command and existing configuration.
"""


def __DELETE_OP_DEFAULT(key_set, command, exist_conf):
    new_conf = exist_conf
    trival_cmd_key_set, dict_list_cmd_key_set = get_key_sets(command)

    if (len(key_set) == len(trival_cmd_key_set)) and \
       (len(dict_list_cmd_key_set) == 0):
        new_conf = []
        return True, new_conf

    trival_cmd_key_not_key_set = trival_cmd_key_set.difference(key_set)
    for key in trival_cmd_key_not_key_set:
        command_val = command.get(key, None)
        new_conf_val = new_conf.get(key, None)
        if command_val == new_conf_val:
            new_conf.pop(key, None)

    return False, new_conf


delete_op_dft = __DELETE_OP_DEFAULT


def get_delete_op(key, test_keys):
    del_op = delete_op_dft
    if not test_keys:
        return del_op
    if not key:
        key = '__default_ops'
    t_keys = next((t_key_item[key] for t_key_item in test_keys if key in t_key_item), None)
    if t_keys:
        del_op = t_keys.get('__delete_op', delete_op_dft)

    return del_op


def get_new_config(commands, exist_conf, test_keys=None):

    if not commands:
        return exist_conf

    cmds = deepcopy(commands)

    n_conf = list()
    e_conf = exist_conf
    for cmd in cmds:
        state = cmd['state']
        cmd.pop('state')

        if state == 'merged':
            n_conf = derive_config_from_merged_cmd(cmd, e_conf, test_keys)
        elif state == 'deleted':
            n_conf = derive_config_from_deleted_cmd(cmd, e_conf, test_keys)
        elif state == 'replaced':
            n_conf = derive_config_from_merged_cmd(cmd, e_conf, test_keys)
        elif state == 'overridden':
            n_conf = derive_config_from_merged_cmd(cmd, e_conf, test_keys)
            # If the "cmd" is derived from playbook, that is "want", the below
            # line should be good enough:
            # n_conf = cmd

        e_conf = n_conf

    return n_conf


def derive_config_from_merged_cmd(command, exist_conf, test_keys=None):

    global merge_op_dft

    if not command:
        return exist_conf

    merge_op_dft = get_merge_op('__default_ops', test_keys)

    if isinstance(command, list) and isinstance(exist_conf, list):
        nu, new_conf_dict = derive_config_from_merged_cmd_dict({"config": command},
                                                               {"config": exist_conf},
                                                               test_keys)
        new_conf = new_conf_dict.get("config", [])
    elif isinstance(command, dict) and isinstance(exist_conf, dict):
        root_merge_op = get_merge_op('config', test_keys)
        nu, new_conf = derive_config_from_merged_cmd_dict(command, exist_conf,
                                                          test_keys, None,
                                                          None, root_merge_op)
    elif isinstance(command, dict) and isinstance(exist_conf, list):
        nu, new_conf_dict = derive_config_from_merged_cmd_dict({"config": [command]},
                                                               {"config": exist_conf},
                                                               test_keys)
        new_conf = new_conf_dict.get("config", [])
    else:
        new_conf = exist_conf

    return new_conf


def derive_config_from_merged_cmd_dict(command, exist_conf, test_keys=None, key_set=None,
                                       key_match_op=None, merge_op=None):

    if test_keys is None:
        test_keys = []
    if key_set is None:
        key_set = set()
    if key_match_op is None:
        key_match_op = __KEY_MATCH_OP_DEFAULT
    if merge_op is None:
        merge_op = merge_op_dft

    new_conf = deepcopy(exist_conf)
    if not command:
        return False, new_conf

    trival_cmd_key_set, dict_list_cmd_key_set = get_key_sets(command)
    trival_exist_key_set, dict_list_exist_key_set = get_key_sets(new_conf)

    common_trival_key_set = trival_cmd_key_set.intersection(trival_exist_key_set)
    common_dict_list_key_set = dict_list_cmd_key_set.intersection(dict_list_exist_key_set)

    key_matched = key_match_op(key_set, command, new_conf)
    if key_matched:
        done, new_conf = merge_op(key_set, command, new_conf)
        if done:
            return key_matched, new_conf
        else:
            nu, dict_list_exist_key_set = get_key_sets(new_conf)
            common_dict_list_key_set = dict_list_cmd_key_set.intersection(dict_list_exist_key_set)
    else:
        return key_matched, new_conf

    for key in key_set:
        common_dict_list_key_set.discard(key)

    for key in common_dict_list_key_set:

        cmd_value = command[key]
        exist_value = new_conf[key]

        t_key_set = get_test_key_set(key, test_keys)
        t_key_match_op = get_key_match_op(key, test_keys)
        t_merge_op = get_merge_op(key, test_keys)

        if (isinstance(cmd_value, list) and isinstance(exist_value, list)):
            c_list = cmd_value
            e_list = exist_value

            new_conf_list = list()
            not_dict_item = False
            dict_no_key_item = False
            for c_item in c_list:
                matched_key_dict = False
                for e_item in e_list:
                    if (isinstance(c_item, dict) and isinstance(e_item, dict)):
                        if t_key_set:
                            remaining_keys = [t_key_item for t_key_item in test_keys if key not in t_key_item]
                            k_mtchd, new_conf_dict = derive_config_from_merged_cmd_dict(c_item,
                                                                                        e_item,
                                                                                        remaining_keys,
                                                                                        t_key_set,
                                                                                        t_key_match_op,
                                                                                        t_merge_op)
                            if k_mtchd:
                                new_conf[key].remove(e_item)
                                if new_conf_dict:
                                    new_conf_list.append(new_conf_dict)
                                matched_key_dict = True
                                break
                        else:
                            dict_no_key_item = True
                            break

                    else:
                        not_dict_item = True
                        break

                if not matched_key_dict:
                    new_conf_list.append(c_item)

                if not_dict_item or dict_no_key_item:
                    break

            if dict_no_key_item:
                new_conf_list = e_list + c_list

            if not_dict_item:
                c_set = set(c_list)
                e_set = set(e_list)
                merge_set = c_set.union(e_set)
                if merge_set:
                    new_conf[key] = list(merge_set)
            elif new_conf_list:
                new_conf[key].extend(new_conf_list)

        elif (isinstance(cmd_value, dict) and isinstance(exist_value, dict)):
            k_mtchd, new_conf_dict = derive_config_from_merged_cmd_dict(cmd_value,
                                                                        exist_value,
                                                                        test_keys,
                                                                        None,
                                                                        t_key_match_op,
                                                                        t_merge_op)
            if k_mtchd and new_conf_dict:
                new_conf[key] = new_conf_dict

        elif (isinstance(cmd_value, (list, dict)) or isinstance(exist_value, (list, dict))):
            new_conf[key] = exist_value
            break

        else:
            continue

    return key_matched, new_conf


def derive_config_from_deleted_cmd(command, exist_conf, test_keys=None):

    global delete_op_dft

    if not command or not exist_conf:
        return exist_conf

    delete_op_dft = get_delete_op('__default_ops', test_keys)

    if isinstance(command, list) and isinstance(exist_conf, list):
        nu, new_conf_dict = derive_config_from_deleted_cmd_dict({"config": command},
                                                                {"config": exist_conf},
                                                                test_keys)
        new_conf = new_conf_dict.get("config", [])
    elif isinstance(command, dict) and isinstance(exist_conf, dict):
        root_delete_op = get_delete_op('config', test_keys)
        nu, new_conf = derive_config_from_deleted_cmd_dict(command, exist_conf,
                                                           test_keys, None,
                                                           None, root_delete_op)
    elif isinstance(command, dict) and isinstance(exist_conf, list):
        nu, new_conf_dict = derive_config_from_deleted_cmd_dict({"config": [command]},
                                                                {"config": exist_conf},
                                                                test_keys)
        new_conf = new_conf_dict.get("config", [])
    else:
        new_conf = exist_conf

    return new_conf


def derive_config_from_deleted_cmd_dict(command, exist_conf, test_keys=None, key_set=None,
                                        key_match_op=None, delete_op=None):

    if test_keys is None:
        test_keys = []
    if key_set is None:
        key_set = set()
    if key_match_op is None:
        key_match_op = __KEY_MATCH_OP_DEFAULT
    if delete_op is None:
        delete_op = delete_op_dft

    new_conf = deepcopy(exist_conf)
    if not command:
        return True, []

    trival_cmd_key_set, dict_list_cmd_key_set = get_key_sets(command)
    trival_exist_key_set, dict_list_exist_key_set = get_key_sets(new_conf)

    common_trival_key_set = trival_cmd_key_set.intersection(trival_exist_key_set)
    common_dict_list_key_set = dict_list_cmd_key_set.intersection(dict_list_exist_key_set)

    key_matched = key_match_op(key_set, command, new_conf)
    if key_matched:
        done, new_conf = delete_op(key_set, command, new_conf)
        if done:
            return key_matched, new_conf
        else:
            nu, dict_list_exist_key_set = get_key_sets(new_conf)
            common_dict_list_key_set = dict_list_cmd_key_set.intersection(dict_list_exist_key_set)
    else:
        return key_matched, new_conf

    for key in key_set:
        common_dict_list_key_set.discard(key)

    for key in common_dict_list_key_set:

        cmd_value = command[key]
        exist_value = new_conf[key]

        t_key_set = get_test_key_set(key, test_keys)
        t_key_match_op = get_key_match_op(key, test_keys)
        t_delete_op = get_delete_op(key, test_keys)

        if (isinstance(cmd_value, list) and isinstance(exist_value, list)):
            c_list = cmd_value
            e_list = exist_value

            new_conf_list = list()
            not_dict_item = False
            dict_no_key_item = False
            for c_item in c_list:
                for e_item in e_list:
                    if (isinstance(c_item, dict) and isinstance(e_item, dict)):
                        if t_key_set:
                            remaining_keys = [t_key_item for t_key_item in test_keys if key not in t_key_item]
                            k_mtchd, new_conf_dict = derive_config_from_deleted_cmd_dict(c_item, e_item,
                                                                                         remaining_keys,
                                                                                         t_key_set,
                                                                                         t_key_match_op,
                                                                                         t_delete_op)
                            if k_mtchd:
                                new_conf[key].remove(e_item)
                                if new_conf_dict:
                                    new_conf_list.append(new_conf_dict)
                                break
                        else:
                            dict_no_key_item = True
                            break

                    else:
                        not_dict_item = True
                        break

                if not_dict_item or dict_no_key_item:
                    break

            if not_dict_item:
                c_set = set(c_list)
                e_set = set(e_list)
                delete_set = e_set.difference(c_set)
                if delete_set:
                    new_conf[key] = list(delete_set)
                else:
                    new_conf[key] = []
            elif dict_no_key_item:
                new_conf[key] = e_list
            elif new_conf_list:
                new_conf[key].extend(new_conf_list)

        elif (isinstance(cmd_value, dict) and isinstance(exist_value, dict)):
            k_mtchd, new_conf_dict = derive_config_from_deleted_cmd_dict(cmd_value,
                                                                         exist_value,
                                                                         test_keys,
                                                                         None,
                                                                         t_key_match_op,
                                                                         t_delete_op)
            if k_mtchd:
                new_conf.pop(key, None)
                if new_conf_dict:
                    new_conf[key] = new_conf_dict

        elif (isinstance(cmd_value, (list, dict)) or isinstance(exist_value, (list, dict))):
            new_conf[key] = exist_value
            break

        else:
            continue

    return key_matched, new_conf


def get_formatted_config_diff(exist_conf, new_conf, verbosity=0):

    exist_conf = json.dumps(exist_conf, sort_keys=True, indent=4, separators=(u',', u': ')) + u'\n'
    new_conf = json.dumps(new_conf, sort_keys=True, indent=4, separators=(u',', u': ')) + u'\n'

    bfr = exist_conf.replace("\"", "\'")
    aft = new_conf.replace("\"", "\'")

    bfr_list = bfr.splitlines(True)
    aft_list = aft.splitlines(True)
    diffs = context_diff(bfr_list, aft_list, fromfile='before', tofile='after')

    if verbosity >= 3:
        formatted_diff = list()
        for diff in diffs:
            formatted_diff.append(diff.rstrip('\n'))

    else:
        formatted_diff = {'prepared': u''.join(diffs)}

    return formatted_diff
