# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note: This utility is considered private, and can only be referenced from inside the vmware.vmware collection.
#       It may be made public at a later date

import traceback

PYVMOMI_IMP_ERR = None
try:
    from pyVmomi import vim, VmomiSupport
    HAS_PYVMOMI = True
except ImportError:
    PYVMOMI_IMP_ERR = traceback.format_exc()
    HAS_PYVMOMI = False


def diff_dict_and_vmodl_options_set(py_dict, vmodl_options_set, truthy_strings_as_bool=True):
    '''
    Based on the method option_diff in community.vmware.
    Compares a regular dictionary against a list/set of vmodl values from vcenter
    and returns the key/value pairs from the dict that are different as vmodl options.
    A common use case is converting module inputs from a dict to a usable config object
    that can be applied to vcenter
    Args:
        py_dict: The python dictionary with key/values to compare against the vmodl options
        vmodl_options_set: A list or set of OptionValue objects that should be compared against
        truthy_strings_as_bool: True if strings like 'yes' or 'on' should be treated as booleans
    Returns:
        list of OptionValues that are missing/different than the ones in the original vmodl
        option set
    '''
    diffed_options = []
    if not py_dict:
        return diffed_options

    vmodl_options_dict = convert_vmodl_option_set_to_py_dict(vmodl_options_set)
    for key, value in py_dict.items():
        try:
            vmodl_value = convert_py_primitive_to_vmodl_type(value, truthy_strings_as_bool=truthy_strings_as_bool)
        except TypeError:
            vmodl_value = value

        if key not in vmodl_options_dict.keys() or vmodl_options_dict[key] != vmodl_value:
            diffed_options.append(vim.option.OptionValue(key=key, value=vmodl_value))

    return diffed_options


def convert_vmodl_option_set_to_py_dict(vmodl_options_set):
    vmodl_option_dict = {}
    for option in vmodl_options_set:
        vmodl_option_dict[option.key] = option.value
    return vmodl_option_dict


def convert_py_primitive_to_vmodl_type(value, truthy_strings_as_bool=True):
    if truthy_strings_as_bool and is_boolean(value):
        return VmomiSupport.vmodlTypes['bool'](is_truthy(value))

    elif isinstance(value, int):
        return VmomiSupport.vmodlTypes['int'](value)

    elif isinstance(value, float):
        return VmomiSupport.vmodlTypes['float'](value)

    elif isinstance(value, str):
        return VmomiSupport.vmodlTypes['string'](value)

    else:
        raise TypeError("Unable to convert variable of type %s to vmodl type" % type(value))


def is_integer(value, type_of='int'):
    try:
        VmomiSupport.vmodlTypes[type_of](value)
        return True
    except (TypeError, ValueError):
        return False


def is_boolean(value):
    if str(value).lower() in ['true', 'on', 'yes', 'false', 'off', 'no']:
        return True
    return False


def is_truthy(value):
    if str(value).lower() in ['true', 'on', 'yes']:
        return True
    return False
