#
# -*- coding: utf-8 -*-
# Copyright 2021 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


def poe_enum2str(enum_name):
    '''translates values from rest API to resource module argspec'''
    # config section setting appears in is comment in this vvv column
    poe_enum_to_ui_str_map = {
        "FOUR_PT_DOT3AF": "4pt-dot3af",                 # detection mode
        "FOUR_PT_DOT3AF_LEG": "4pt-dot3af+legacy",      # detection mode
        "TWO_PT_DOT3AF": "2pt-dot3af",                  # detection mode
        "TWO_PT_DOT3AF_LEG": "2pt-dot3af+legacy",       # detection mode
        "DOT3BT": "dot3bt",                             # detection mode
        "DOT3BT_LEG": "dot3bt+legacy",                  # detection mode
        "LEGACY": "legacy",                             # detection mode
        "STATIC": "static",                             # power management model
        "STATIC_PRIORITY": "static-priority",           # power management model
        "DYNAMIC": "dynamic",                           # power management model
        "DYNAMIC_PRIORITY": "dynamic-priority",         # power management model
        "CLASS": "class",                               # power management model
        "AC": "ac",                                     # disconnect type
        "DC": "dc",                                     # disconnect type
        "IEEE_8023AF": "dot3af",                        # powerup mode
        "HIGH_INRUSH": "high-inrush",                   # powerup mode
        "PRE_8023AT": "pre-dot3at",                     # powerup mode
        "IEEE_8023AT": "dot3at",                        # powerup mode
        "PRE_8023BT": "pre-dot3bt",                     # powerup mode
        "IEEE_8023BT_TYPE3": "dot3bt-type3",            # powerup mode
        "IEEE_8023BT_TYPE4": "dot3bt-type4",            # powerup mode
        "IEEE_8023BT": "dot3bt",                        # powerup mode
        "USER": "user-defined",                         # power limit type
        "CLASS_BASED": "class-based",                   # power limit type
    }

    if enum_name is None:
        return None
    elif enum_name in poe_enum_to_ui_str_map:
        return poe_enum_to_ui_str_map[enum_name]
    elif isinstance(enum_name, str):
        # other strings and such.
        # values for priority, power pairs, and power classification mode go here, which work because they are an easy to read word
        return enum_name.lower()
    else:
        return enum_name


def poe_str2enum(str_key):
    '''translates values from resource module argspec to rest API
    IMOPORTANT TO NOTE: dot3bt appears both in detection and powerup mode, and has two different values in REST API.
    To differentiate, all detection values should have 'detection-' prepended when passing in'''
    # config section setting appears in is comment in this vvv column
    poe_ui_str_to_enum_map = {
        "detection-4pt-dot3af": "FOUR_PT_DOT3AF",                 # detection mode
        "detection-4pt-dot3af+legacy": "FOUR_PT_DOT3AF_LEG",      # detection mode
        "detection-2pt-dot3af": "TWO_PT_DOT3AF",                  # detection mode
        "detection-2pt-dot3af+legacy": "TWO_PT_DOT3AF_LEG",       # detection mode
        "detection-dot3bt": "DOT3BT",                             # detection mode
        "detection-dot3bt+legacy": "DOT3BT_LEG",                  # detection mode
        "detection-legacy": "LEGACY",                             # detection mode
        "static": "STATIC",                             # power management model
        "static-priority": "STATIC_PRIORITY",           # power management model
        "dynamic": "DYNAMIC",                           # power management model
        "dynamic-priority": "DYNAMIC_PRIORITY",         # power management model
        "class": "CLASS",                               # power management model
        "ac": "AC",                                     # disconnect type
        "dc": "DC",                                     # disconnect type
        "dot3af": "IEEE_8023AF",                        # powerup mode
        "high-inrush": "HIGH_INRUSH",                   # powerup mode
        "pre-dot3at": "PRE_8023AT",                     # powerup mode
        "dot3at": "IEEE_8023AT",                        # powerup mode
        "pre-dot3bt": "PRE_8023BT",                     # powerup mode
        "dot3bt-type3": "IEEE_8023BT_TYPE3",            # powerup mode
        "dot3bt-type4": "IEEE_8023BT_TYPE4",            # powerup mode
        "dot3bt": "IEEE_8023BT",                        # powerup mode
        "user-defined": "USER",                         # power limit type
        "class-based": "CLASS_BASED",                   # power limit type
    }

    if str_key is None:
        return None
    elif str_key in poe_ui_str_to_enum_map:
        return poe_ui_str_to_enum_map[str_key]
    elif isinstance(str_key, str):
        # values for priority, power pairs, and power classification mode go here, which work because they are an easy to read word
        return str_key.upper()
    else:
        # there are config with other types, so catch that just to make sure this function doesn't break
        return str_key


def remove_none(config):
    '''goes through nested dictionary items and removes any keys that have None as value.
    enables using empty list/dict to specify clear everything for that section and differentiate this
    'clear everything' case from when no value was given
    remove_empties in ansible utils will remove empty lists and dicts as well as None'''
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
