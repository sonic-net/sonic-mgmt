#
# -*- coding: utf-8 -*-
# Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# utils

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
import json
import ast
from copy import copy
from itertools import (count, groupby)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties
)
from ansible.module_utils.common.network import (
    is_masklen,
    to_netmask,
)
from ansible.module_utils.common.validation import check_required_arguments
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

DEFAULT_TEST_KEY = {'config': {'name': ''}}
GET = 'get'

intf_naming_mode = ""


def remove_matching_defaults(root, default_entry):
    if isinstance(root, list):
        for list_item in root:
            remove_matching_defaults(list_item, default_entry)
    elif isinstance(root, dict):
        nextobj = root.get(default_entry[0]['name'])
        if nextobj is not None:
            if len(default_entry) > 1:
                remove_matching_defaults(nextobj, default_entry[1:])
            else:
                # Leaf
                if nextobj == default_entry[0]['default']:
                    root.pop(default_entry[0]['name'])


def add_config_defaults(root, default_entry):
    if isinstance(root, list):
        for list_item in root:
            add_config_defaults(list_item, default_entry)
    elif isinstance(root, dict):
        nextobj = root.get(default_entry[0]['name'])
        if nextobj is not None:
            if len(default_entry) > 1:
                add_config_defaults(nextobj, default_entry[1:])
        else:
            if len(default_entry) == 1:
                root[default_entry[0]['name']] = default_entry[0]['default']


def get_diff(base_data, compare_with_data, test_keys=None, is_skeleton=None):
    diff = []
    if is_skeleton is None:
        is_skeleton = False

    test_keys = normalize_testkeys(test_keys)

    if isinstance(base_data, list) and isinstance(compare_with_data, list):
        dict_diff = get_diff_dict({"config": base_data}, {"config": compare_with_data}, test_keys, is_skeleton)
        diff = dict_diff.get("config", [])

    else:
        new_base, new_compare = convert_dict_to_single_entry_list(base_data, compare_with_data, test_keys)
        diff = get_diff_dict(new_base, new_compare, test_keys, is_skeleton)
        if diff:
            diff = convert_single_entry_list_to_dict(diff)
        else:
            diff = {}

    return diff


def get_diff_dict(base_data, compare_with_data, test_keys=None, is_skeleton=None):
    if is_skeleton is None:
        is_skeleton = False

    if test_keys is None:
        test_keys = []

    if not base_data:
        return base_data

    planned_set = set(base_data.keys())
    discovered_set = set(compare_with_data.keys())
    intersect_set = planned_set.intersection(discovered_set)
    changed_dict = {}
    has_dict_item = None
    added_set = planned_set - intersect_set
    # Keys part of added are new and put into changed_dict
    if added_set:
        for key in added_set:
            if is_skeleton:
                changed_dict[key] = base_data[key]
            elif base_data[key] is not None:
                if isinstance(base_data[key], dict):
                    val_dict = remove_empties(base_data[key])
                    if val_dict:
                        changed_dict[key] = remove_empties(base_data[key])
                elif isinstance(base_data[key], list):
                    val_list = remove_empties_from_list(base_data[key])
                    if val_list:
                        changed_dict[key] = remove_empties_from_list(base_data[key])
                else:
                    changed_dict[key] = base_data[key]
    for key in intersect_set:
        has_dict_item = False
        value = base_data[key]
        if isinstance(value, list):
            p_list = base_data[key] if key in base_data else []
            d_list = compare_with_data[key] if key in compare_with_data else []
            keys_to_compare = next((test_key_item[key] for test_key_item in test_keys if key in test_key_item), None)
            changed_list = []
            if p_list and d_list:
                for p_list_item in p_list:
                    matched = False
                    has_diff = False
                    for d_list_item in d_list:
                        if (isinstance(p_list_item, dict) and isinstance(d_list_item, dict)):
                            if keys_to_compare:
                                key_matched_cnt = 0
                                test_keys_present_cnt = 0
                                common_keys = set(p_list_item).intersection(d_list_item)
                                for test_key in keys_to_compare:
                                    if test_key in common_keys:
                                        test_keys_present_cnt += 1
                                        if p_list_item[test_key] == d_list_item[test_key]:
                                            key_matched_cnt += 1
                                if key_matched_cnt and key_matched_cnt == test_keys_present_cnt:
                                    remaining_keys = [test_key_item for test_key_item in test_keys if key not in test_key_item]
                                    dict_diff = get_diff_dict(p_list_item, d_list_item, remaining_keys, is_skeleton)
                                    matched = True
                                    if dict_diff:
                                        has_diff = True
                                        for test_key in keys_to_compare:
                                            dict_diff.update({test_key: p_list_item[test_key]})
                                    break
                            else:
                                dict_diff = get_diff_dict(p_list_item, d_list_item, test_keys, is_skeleton)
                                if not dict_diff:
                                    matched = True
                                    break
                        else:
                            if p_list_item == d_list_item:
                                matched = True
                                break
                    if not matched:
                        if is_skeleton:
                            changed_list.append(p_list_item)
                        else:
                            if isinstance(p_list_item, dict):
                                val_dict = remove_empties(p_list_item)
                                if val_dict is not None:
                                    changed_list.append(val_dict)
                            elif isinstance(p_list_item, list):
                                val_list = remove_empties_from_list(p_list_item)
                                if val_list is not None:
                                    changed_list.append(val_list)
                            else:
                                if p_list_item is not None:
                                    changed_list.append(p_list_item)
                    elif has_diff and dict_diff:
                        changed_list.append(dict_diff)
                if changed_list:
                    changed_dict.update({key: changed_list})
            elif p_list and (not d_list):
                changed_dict[key] = p_list
        elif (isinstance(value, dict) and isinstance(compare_with_data[key], dict)):
            dict_diff = get_diff_dict(base_data[key], compare_with_data[key], test_keys, is_skeleton)
            if dict_diff:
                changed_dict[key] = dict_diff
        elif value is not None:
            if not is_skeleton:
                if compare_with_data[key] != base_data[key]:
                    changed_dict[key] = base_data[key]
    return changed_dict


def convert_dict_to_single_entry_list(base_data, compare_with_data, test_keys):
    # if it is dict comparision convert dict into single entry list by adding 'config' as key
    new_base = {'config': [base_data]}
    new_compare = {'config': [compare_with_data]}

    # get testkey of 'config'
    config_testkey = None
    for item in test_keys:
        for key, val in item.items():
            if key == 'config':
                config_testkey = list(val)[0]
                break
        if config_testkey:
            break
    # if testkey of 'config' is not in base data, introduce single entry list
    # with 'temp_key' as config testkey and base_data as data.
    if config_testkey and base_data and config_testkey not in base_data:
        new_base = {'config': [{config_testkey: 'temp_key', 'data': base_data}]}
        new_compare = {'config': [{config_testkey: 'temp_key', 'data': compare_with_data}]}

    return new_base, new_compare


def convert_single_entry_list_to_dict(diff):
    diff = diff['config'][0]
    if 'data' in diff:
        diff = diff['data']
    return diff


def normalize_testkeys(test_keys):
    if test_keys is None:
        test_keys = []

    if not any(test_key_item for test_key_item in test_keys if "config" in test_key_item):
        test_keys.append(DEFAULT_TEST_KEY)

    return test_keys


def update_states(commands, state):
    ret_list = list()
    if commands:
        if isinstance(commands, list):
            for command in commands:
                ret = command.copy()
                ret.update({"state": state})
                ret_list.append(ret)
        elif isinstance(commands, dict):
            ret_list.append(commands.copy())
            ret_list[0].update({"state": state})
    return ret_list


def dict_to_set(sample_dict):
    # Generate a set with passed dictionary for comparison
    test_dict = dict()
    if isinstance(sample_dict, dict):
        for k, v in sample_dict.items():
            if v is not None:
                if isinstance(v, list):
                    if isinstance(v[0], dict):
                        li = []
                        for each in v:
                            for key, value in each.items():
                                if isinstance(value, list):
                                    each[key] = tuple(value)
                            li.append(tuple(each.items()))
                        v = tuple(li)
                    else:
                        v = tuple(v)
                elif isinstance(v, dict):
                    li = []
                    for key, value in v.items():
                        if isinstance(value, list):
                            v[key] = tuple(value)
                    li.extend(tuple(v.items()))
                    v = tuple(li)
                test_dict.update({k: v})
        return_set = set(tuple(test_dict.items()))
    else:
        return_set = set(sample_dict)
    return return_set


def validate_ipv4(value, module):
    if value:
        address = value.split("/")
        if len(address) != 2:
            module.fail_json(
                msg="address format is <ipv4 address>/<mask>, got invalid format {0}".format(
                    value
                )
            )

        if not is_masklen(address[1]):
            module.fail_json(
                msg="invalid value for mask: {0}, mask should be in range 0-32".format(
                    address[1]
                )
            )


def validate_ipv6(value, module):
    if value:
        address = value.split("/")
        if len(address) != 2:
            module.fail_json(
                msg="address format is <ipv6 address>/<mask>, got invalid format {0}".format(
                    value
                )
            )
        else:
            if not 0 <= int(address[1]) <= 128:
                module.fail_json(
                    msg="invalid value for mask: {0}, mask should be in range 0-128".format(
                        address[1]
                    )
                )


def validate_n_expand_ipv4(module, want):
    # Check if input IPV4 is valid IP and expand IPV4 with its subnet mask
    ip_addr_want = want.get("address")
    if len(ip_addr_want.split(" ")) > 1:
        return ip_addr_want
    validate_ipv4(ip_addr_want, module)
    ip = ip_addr_want.split("/")
    if len(ip) == 2:
        ip_addr_want = "{0} {1}".format(ip[0], to_netmask(ip[1]))

    return ip_addr_want


def netmask_to_cidr(netmask):
    bit_range = [128, 64, 32, 16, 8, 4, 2, 1]
    count = 0
    cidr = 0
    netmask_list = netmask.split(".")
    netmask_calc = [i for i in netmask_list if int(i) != 255 and int(i) != 0]
    if netmask_calc:
        netmask_calc_index = netmask_list.index(netmask_calc[0])
    elif sum(list(map(int, netmask_list))) == 0:
        return "32"
    else:
        return "24"
    for each in bit_range:
        if cidr == int(netmask.split(".")[2]):
            if netmask_calc_index == 1:
                return str(8 + count)
            elif netmask_calc_index == 2:
                return str(8 * 2 + count)
            elif netmask_calc_index == 3:
                return str(8 * 3 + count)
            break
        cidr += each
        count += 1


def remove_empties_from_list(config_list):
    ret_config = []
    if not config_list or not isinstance(config_list, list):
        return ret_config
    for config in config_list:
        if isinstance(config, dict):
            ret_config.append(remove_empties(config))
        else:
            ret_config.append(copy(config))
    return ret_config


def remove_none(config):
    '''goes through nested dictionary items and removes any keys that have None as value.
    enables using empty list/dict to specify clear everything for that section and differentiate this
    'clear everything' case from when no value was given
    Note: This function is provided as an alternative to the "remove_empties" function in
    ansible utils because the Ansible 'remove_empties' function will remove empty lists
    and dicts as well as None'''
    if isinstance(config, dict):
        for k, v in list(config.items()):
            if v is not None:
                remove_none(v)
            if v is None:
                del config[k]
    elif isinstance(config, list):
        for item in list(config):
            if item is not None:
                remove_none(item)
            if item is None:
                config.remove(item)
    return config


def get_device_interface_naming_mode(module):
    intf_naming_mode = ""
    request = {"path": "data/sonic-device-metadata:sonic-device-metadata/DEVICE_METADATA/DEVICE_METADATA_LIST=localhost", "method": GET}
    try:
        response = edit_config(module, to_request(module, request))
    except ConnectionError as exc:
        module.fail_json(msg=str(exc), code=exc.code)

    if 'sonic-device-metadata:DEVICE_METADATA_LIST' in response[0][1]:
        device_meta_data = response[0][1].get('sonic-device-metadata:DEVICE_METADATA_LIST', [])
        if device_meta_data:
            intf_naming_mode = device_meta_data[0].get('intf_naming_mode', 'native')

    return intf_naming_mode


STANDARD_ETH_REGEXP = r"[e|E]th\s*\d+/\d+"
NATIVE_ETH_REGEXP = r"[e|E]th*\d+$"
NATIVE_MODE = "native"
STANDARD_MODE = "standard"


def find_intf_naming_mode(intf_name):
    ret_intf_naming_mode = NATIVE_MODE

    if re.search(STANDARD_ETH_REGEXP, intf_name):
        ret_intf_naming_mode = STANDARD_MODE

    return ret_intf_naming_mode


def validate_intf_naming_mode(intf_name, module):
    global intf_naming_mode
    compatible_input_naming_modes = {
        'native': [NATIVE_MODE],
        'standard': [STANDARD_MODE],
        'standard-ext': [STANDARD_MODE]
    }

    if intf_naming_mode == "":
        intf_naming_mode = get_device_interface_naming_mode(module)

    if intf_naming_mode != "":
        ansible_intf_naming_mode = find_intf_naming_mode(intf_name)
        if ansible_intf_naming_mode not in compatible_input_naming_modes[intf_naming_mode]:
            err = "Interface naming mode configured on switch {naming_mode}, {intf_name} is not valid".format(naming_mode=intf_naming_mode, intf_name=intf_name)
            module.fail_json(msg=err, code=400)


def normalize_interface_name(configs, module, namekey=None):
    if not namekey:
        namekey = 'name'

    if configs:
        for conf in configs:
            if conf.get(namekey, None):
                conf[namekey] = get_normalize_interface_name(conf[namekey], module)


def normalize_interface_name_list(configs, module):
    norm_configs = []
    if configs:
        for conf in configs:
            conf = get_normalize_interface_name(conf, module)
            norm_configs.append(conf)

    return norm_configs


def get_normalize_interface_name(intf_name, module):
    change_flag = False
    # remove the space in the given string
    ret_intf_name = re.sub(r"\s+", "", intf_name, flags=re.UNICODE)
    ret_intf_name = ret_intf_name.capitalize()

    # search the numeric character(digit)
    match = re.search(r"\d", ret_intf_name)
    if match:
        change_flag = True
        start_pos = match.start()
        name = ret_intf_name[0:start_pos]
        intf_id = ret_intf_name[start_pos:]

        # Interface naming mode affects only ethernet ports
        if name.startswith("Eth"):
            validate_intf_naming_mode(intf_name, module)

        if ret_intf_name.startswith("Management") or ret_intf_name.startswith("Mgmt"):
            name = "eth"
            intf_id = "0"
        elif re.search(STANDARD_ETH_REGEXP, ret_intf_name):
            name = "Eth"
        elif re.search(NATIVE_ETH_REGEXP, ret_intf_name):
            name = "Ethernet"
        elif name.startswith("Po"):
            name = "PortChannel"
        elif name.startswith("Vlan"):
            name = "Vlan"
        elif name.startswith("Lo"):
            name = "Loopback"
        else:
            change_flag = False

        ret_intf_name = name + intf_id

    if not change_flag:
        ret_intf_name = intf_name

    return ret_intf_name


def get_speed_from_breakout_mode(breakout_mode):
    return 'SPEED_' + breakout_mode.split('x')[1].replace('G', 'GB')


def get_breakout_mode(module, name):
    response = None
    mode = None
    component_name = name
    if "/" in name:
        component_name = name.replace("/", "%2f")
    url = "data/openconfig-platform:components/component=%s" % (component_name)
    request = [{"path": url, "method": GET}]
    try:
        response = edit_config(module, to_request(module, request))
    except ConnectionError as exc:
        try:
            json_obj = json.loads(str(exc).replace("'", '"'))
            if json_obj and isinstance(json_obj, dict) and 404 == json_obj['code']:
                response = None
            else:
                module.fail_json(msg=str(exc), code=exc.code)
        except Exception as err:
            module.fail_json(msg=str(exc), code=exc.code)

    if response and "openconfig-platform:component" in response[0][1]:
        raw_port_breakout = response[0][1]['openconfig-platform:component'][0]
        port_name = raw_port_breakout.get('name', None)
        port_data = raw_port_breakout.get('port', None)
        if port_name and port_data and 'openconfig-platform-port:breakout-mode' in port_data:
            if 'groups' in port_data['openconfig-platform-port:breakout-mode']:
                group = port_data['openconfig-platform-port:breakout-mode']['groups']['group'][0]
                if 'config' in group:
                    cfg = group.get('config', None)
                    breakout_speed = cfg.get('breakout-speed', None)
                    num_breakouts = cfg.get('num-breakouts', None)
                    if breakout_speed and num_breakouts:
                        speed = breakout_speed.replace('openconfig-if-ethernet:SPEED_', '')
                        speed = speed.replace('GB', 'G')
                        mode = str(num_breakouts) + 'x' + speed
    return mode


def command_list_str_to_dict(module, warnings, cmd_list_in, exec_cmd=False):
    cmd_list_out = []
    for cmd in cmd_list_in:
        cmd_out = dict()
        nested_cmd_is_dict = False
        if isinstance(cmd, dict):
            cmd_out = cmd
        else:
            try:
                nest_dict = ast.literal_eval(cmd)
                nested_cmd_is_dict = isinstance(nest_dict, dict)
            except Exception:
                nested_cmd_is_dict = False

            if nested_cmd_is_dict:
                for key, value in nest_dict.items():
                    cmd_out[key] = value
            else:
                cmd_out = cmd

        if exec_cmd and module.check_mode and not cmd_out['command'].startswith('show'):
            warnings.append(
                'Only show commands are supported when using check mode, not '
                'executing %s' % cmd_out['command']
            )
        else:
            cmd_list_out.append(cmd_out)

    return cmd_list_out


def send_requests(module, requests):

    reply = dict()
    response = []
    if not module.check_mode and requests:
        try:
            response = edit_config(module, to_request(module, requests))
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        reply = response[0][1]

    return reply


def get_replaced_config(new_conf, exist_conf, test_keys=None):

    replace_conf = []
    if not new_conf or not exist_conf:
        return replace_conf

    if isinstance(new_conf, list) and isinstance(exist_conf, list):

        replace_conf_dict = get_replaced_config_dict({"config": new_conf},
                                                     {"config": exist_conf},
                                                     test_keys)
        replaced_conf = replace_conf_dict.get("config", [])
    else:
        replaced_conf = get_replaced_config_dict(new_conf, exist_conf, test_keys)

    return replaced_conf


def get_replaced_config_dict(new_conf, exist_conf, test_keys=None, key_set=None):

    replaced_conf = dict()

    if test_keys is None:
        test_keys = []
    if key_set is None:
        key_set = []

    if not new_conf:
        return replaced_conf

    new_key_set = set(new_conf.keys())
    exist_key_set = set(exist_conf.keys())

    trival_new_key_set = set()
    dict_list_new_key_set = set()
    for key in new_key_set:
        if new_conf[key] not in [None, [], {}]:
            if isinstance(new_conf[key], (list, dict)):
                dict_list_new_key_set.add(key)
            else:
                trival_new_key_set.add(key)

    trival_exist_key_set = set()
    dict_list_exist_key_set = set()
    for key in exist_key_set:
        if exist_conf[key] not in [None, [], {}]:
            if isinstance(exist_conf[key], (list, dict)):
                dict_list_exist_key_set.add(key)
            else:
                trival_exist_key_set.add(key)

    common_trival_key_set = trival_new_key_set.intersection(trival_exist_key_set)
    common_dict_list_key_set = dict_list_new_key_set.intersection(dict_list_exist_key_set)

    key_matched_cnt = 0
    common_trival_key_matched = True
    for key in common_trival_key_set:
        if new_conf[key] == exist_conf[key]:
            if key in key_set:
                key_matched_cnt += 1
        else:
            if key not in key_set:
                common_trival_key_matched = False

    for key in common_dict_list_key_set:
        if new_conf[key] == exist_conf[key]:
            if key in key_set:
                key_matched_cnt += 1

    key_matched = (key_matched_cnt == len(key_set))
    if key_matched:
        extra_trival_new_key_set = trival_new_key_set - common_trival_key_set
        extra_trival_exist_key_set = trival_exist_key_set - common_trival_key_set
        if extra_trival_new_key_set or extra_trival_exist_key_set or \
           not common_trival_key_matched:
            # Replace whole dict.
            replaced_conf = exist_conf
            return replaced_conf
    else:
        replaced_conf = []
        return replaced_conf

    for key in key_set:
        common_dict_list_key_set.discard(key)

    replace_whole_dict = False
    replace_some_list = False
    replace_some_dict = False
    for key in common_dict_list_key_set:

        new_value = new_conf[key]
        exist_value = exist_conf[key]

        if (isinstance(new_value, list) and isinstance(exist_value, list)):
            n_list = new_value
            e_list = exist_value
            t_keys = next((t_key_item[key] for t_key_item in test_keys if key in t_key_item), None)
            t_key_set = set()
            if t_keys:
                t_key_set = set(t_keys.keys())

            replaced_list = list()
            not_dict_item = False
            dict_no_key_item = False
            for n_item in n_list:
                for e_item in e_list:
                    if (isinstance(n_item, dict) and isinstance(e_item, dict)):
                        if t_keys:
                            remaining_keys = [t_key_item for t_key_item in test_keys if key not in t_key_item]
                            replaced_dict = get_replaced_config_dict(n_item, e_item,
                                                                     remaining_keys, t_key_set)
                        else:
                            dict_no_key_item = True
                            break

                        if replaced_dict:
                            replaced_list.append(replaced_dict)
                            break
                    else:
                        not_dict_item = True
                        break

                if not_dict_item or dict_no_key_item:
                    break

            if dict_no_key_item:
                replaced_list = e_list

            if not_dict_item:
                n_set = set(n_list)
                e_set = set(e_list)
                diff_set = n_set.symmetric_difference(e_set)
                if diff_set:
                    replaced_conf[key] = e_list
                    replace_some_list = True

            elif replaced_list:
                replaced_conf[key] = replaced_list
                replace_some_list = True

        elif (isinstance(new_value, dict) and isinstance(exist_value, dict)):
            replaced_dict = get_replaced_config_dict(new_conf[key], exist_conf[key], test_keys)
            if replaced_dict:
                replaced_conf[key] = replaced_dict
                replace_some_dict = True

        elif (isinstance(new_value, (list, dict)) or isinstance(exist_value, (list, dict))):
            # Replace whole dict.
            replaced_conf = exist_conf
            replace_whole_dict = True
            break

        else:
            continue

    if ((replace_some_dict or replace_some_list) and (not replace_whole_dict)):
        for key in key_set:
            replaced_conf[key] = exist_conf[key]

    return replaced_conf


def check_required(module, required_parameters, parameters, options_context=None):
    '''This utility is a wrapper for the Ansible "check_required_arguments"
    function. The "required_parameters" input list provides a list of
    key names that are required in the dictionary specified by "parameters".
    The optional "options_context" parameter specifies the context/path
    from the top level parent dict to the dict being checked.'''
    if required_parameters:
        spec = {}
        for parameter in required_parameters:
            spec[parameter] = {'required': True}

        try:
            check_required_arguments(spec, parameters, options_context)
        except TypeError as exc:
            module.fail_json(msg=str(exc))


def get_ranges_in_list(num_list):
    """Returns a generator for list(s) of consecutive numbers
    present in the given sorted list of numbers
    """
    for key, group in groupby(num_list, lambda num, i=count(): num - next(i)):
        yield list(group)


def sort_lists_by_interface_name(conf_list, key):
    """
    Sorts a list of dictionaries based on the value of a specified key.
    """

    def retrieve_sort_keys(name):
        group = re.match(r"(.*)(\d+)$", name)
        if group:
            return group[1], int(group[2])
        return name, name

    conf_list.sort(key=lambda x: retrieve_sort_keys(x[key]))
