#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2025, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.common import validation


def validate_str(item, param_spec, param_name, invalid_params, module=None):
    """
    This function checks that the input `item` is a valid string and conforms to
    the constraints specified in `param_spec`. If the string is not valid or does
    not meet the constraints, an error message is added to `invalid_params`.

    Args:
        item (str): The input string to be validated.
        param_spec (dict): The parameter's specification, including validation constraints.
        param_name (str): The name of the parameter being validated.
        invalid_params (list): A list to collect validation error messages.
        module (object, optional): Ansible module object, required if any parameter has `no_log` enabled.

    Returns:
        str: The validated and possibly normalized string.

    Example `param_spec`:
        {
            "type": "str",
            "length_max": 255 # Optional: maximum allowed length
        }
    """

    try:
        item = validation.check_type_str(item, False)
    except TypeError as e:
        invalid_params.append(
            f"'{param_name}': '{item}' is invalid. Reason: {str(e)}. "
        )
        return item

    max_length = param_spec.get("length_max")
    if max_length:
        if 1 <= len(item) <= max_length:
            return item
        else:
            invalid_params.append(
                "{0}:{1} : The string exceeds the allowed "
                "range of max {2} char".format(
                    param_name, item, param_spec.get("length_max")
                )
            )

    return item


def validate_integer_within_range(
    item, param_spec, param_name, invalid_params, module=None
):
    """
    This function checks that the input `item` is a valid integer and conforms to
    the constraints specified in `param_spec`. If the integer is not valid or does
    not meet the constraints, an error message is added to `invalid_params`.

    Args:
        item (int): The input integer to be validated.
        param_spec (dict): The parameter's specification, including validation constraints.
        param_name (str): The name of the parameter being validated.
        invalid_params (list): A list to collect validation error messages.
        module (object, optional): Ansible module object, required if any parameter has `no_log` enabled.

    Returns:
        int: The validated integer.

    Example `param_spec`:
        {
            "type": "int",
            "range_min": 1,     # Optional: minimum allowed value
            "range_max": 100    # Optional: maximum allowed value
        }
    """
    try:
        item = validation.check_type_int(item)
    except TypeError as e:
        invalid_params.append(
            f"'{param_name}': '{item}' is invalid. Reason: {str(e)}. "
        )
        return item

    min_value = param_spec.get("range_min", 1)
    if param_spec.get("range_max") and not (
        min_value <= item <= param_spec["range_max"]
    ):
        invalid_params.append(
            "{0}: {1} : The item exceeds the allowed range of min: {2} and max: {3}".format(
                param_name,
                item,
                param_spec.get("range_min"),
                param_spec.get("range_max"),
            )
        )

    return item


def validate_bool(item, param_spec, param_name, invalid_params, module=None):
    """
    This function checks that the input `item` is a valid boolean value. If it does
    not represent a valid boolean value, an error message is added to `invalid_params`.

    Args:
        item (bool): The input boolean value to be validated.
        param_spec (dict): The parameter's specification, including validation constraints.
        param_name (str): The name of the parameter being validated.
        invalid_params (list): A list to collect validation error messages.
        module (object, optional): Ansible module object, required if any parameter has `no_log` enabled.

    Returns:
        bool: The validated boolean value.
    """
    try:
        item = validation.check_type_bool(item)
    except TypeError as e:
        invalid_params.append(
            f"'{param_name}': '{item}' is invalid. Reason: {str(e)}. "
        )

    return item


def validate_list(item, param_spec, param_name, invalid_params, module=None):
    """
    This function checks if the input `item` is a valid list based on the specified `param_spec`.
    It also verifies that the elements of the list match the expected data type specified in the
    `param_spec`. If any validation errors occur, they are appended to the `invalid_params` list.

    Args:
        item (list): The input list to be validated.
        param_spec (dict): The parameter's specification, including validation constraints.
        param_name (str): The name of the parameter being validated.
        invalid_params (list): A list to collect validation error messages.
        module (object, optional): Ansible module object, required if any parameter has `no_log` enabled.

    Returns:
        list: The validated list, potentially normalized based on the specification.
    """

    try:
        if param_spec.get("type") == type(item).__name__:
            keys_list = []
            for dict_key in param_spec:
                keys_list.append(dict_key)
            if len(keys_list) == 1:
                return validation.check_type_list(item)

            temp_dict = {keys_list[1]: param_spec[keys_list[1]]}
            try:
                if param_spec["elements"]:
                    if param_spec["elements"] == "dict":
                        common_defaults = {
                            "type",
                            "elements",
                            "required",
                            "default",
                            "choices",
                            "no_log",
                        }
                        filtered_param_spec = {
                            key: value
                            for key, value in param_spec.items()
                            if key not in common_defaults
                        }
                        if filtered_param_spec:
                            item, list_invalid_params = validate_list_of_dicts(
                                item, filtered_param_spec
                            )
                            invalid_params.extend(list_invalid_params)

                    get_spec_type = param_spec["type"]
                    get_spec_element = param_spec["elements"]
                    if type(item).__name__ == get_spec_type:
                        for element in item:
                            if type(element).__name__ != get_spec_element:
                                invalid_params.append(
                                    "{0} is not of the same datatype as expected which is {1}".format(
                                        element, get_spec_element
                                    )
                                )
                    else:
                        invalid_params.append(
                            "{0} is not of the same datatype as expected which is {1}".format(
                                item, get_spec_type
                            )
                        )
            except Exception as e:
                item, list_invalid_params = validate_list_of_dicts(item, temp_dict)
                invalid_params.extend(list_invalid_params)
        else:
            invalid_params.append(
                f"'{param_name}': '{item}' is invalid. Reason: expected type: '{param_spec.get('type')}'. "
                f"Provided type: '{type(item).__name__}'. "
            )
    except Exception as e:
        invalid_params.append("{0} : comes into the exception".format(e))

    return item


def validate_dict(item, param_spec, param_name, invalid_params, module=None):
    """
    This function checks if the input `item` is a valid dictionary based on the specified `param_spec`.
    If the dictionary does not match the expected data type specified in the `param_spec`,
    a validation error is appended to the `invalid_params` list.

    Args:
        item (dict): The input dictionary to be validated.
        param_spec (dict): The parameter's specification, including validation constraints.
        param_name (str): The name of the parameter being validated.
        invalid_params (list): A list to collect validation error messages.
        module (object, optional): Ansible module object, required if any parameter has `no_log` enabled.

    Returns:
        dict: The validated dictionary.
    """
    if param_spec.get("type") != type(item).__name__:
        invalid_params.append(
            f"'{param_name}': '{item}' is invalid. Reason: expected type: '{param_spec.get('type')}'. "
            f"Provided type: '{type(item).__name__}'. "
        )
        return item

    if param_spec.get("type") == "dict":
        common_defaults = {
            "type",
            "elements",
            "required",
            "default",
            "choices",
            "no_log",
        }
        filtered_param_spec = {
            key: value
            for key, value in param_spec.items()
            if key not in common_defaults
        }

        valid_params_dict = {}

        if filtered_param_spec:
            for param in filtered_param_spec:
                curr_item = item.get(param)
                if curr_item is None:
                    if filtered_param_spec[param].get("required"):
                        invalid_params.append(
                            "{0} : Required parameter not found".format(param)
                        )
                    else:
                        curr_item = filtered_param_spec[param].get("default")
                        valid_params_dict[param] = curr_item
                    continue
                data_type = filtered_param_spec[param].get("type")
                switch = {
                    "str": validate_str,
                    "int": validate_integer_within_range,
                    "bool": validate_bool,
                    "list": validate_list,
                    "dict": validate_dict,
                    "raw": lambda item, *_: item,
                }

                validator = switch.get(data_type)
                if validator:
                    curr_item = validator(
                        curr_item,
                        filtered_param_spec[param],
                        param,
                        invalid_params,
                        module,
                    )
                else:
                    invalid_params.append(
                        "{0}:{1} : Unsupported data type {2}.".format(
                            param, curr_item, data_type
                        )
                    )

                choice = filtered_param_spec[param].get("choices")
                if choice:
                    if curr_item not in choice:
                        invalid_params.append(
                            "{0} : Invalid choice provided".format(curr_item)
                        )

                no_log = filtered_param_spec[param].get("no_log")
                if no_log:
                    if module is not None:
                        module.no_log_values.add(curr_item)
                    else:
                        msg = "\n\n'{0}' is a no_log parameter".format(param)
                        msg += "\nAnsible module object must be passed to this "
                        msg += "\nfunction to ensure it is not logged\n\n"
                        raise Exception(msg)

                valid_params_dict[param] = curr_item
            item = valid_params_dict

    return validation.check_type_dict(item)


def validate_list_of_dicts(param_list, spec, module=None):
    """Validate/Normalize playbook params. Will raise when invalid parameters found.
    param_list: a playbook parameter list of dicts
    spec: an argument spec dict
        e.g. spec = dict(ip=dict(required=True, type='bool'),
                        foo=dict(type='str', default='bar'))
    return: list of normalized input data
    """

    v = validation
    normalized = []
    invalid_params = []
    for list_entry in param_list:
        valid_params_dict = {}
        if not spec:
            # Handle the case when spec becomes empty but param list is still there
            invalid_params.append("No more spec to validate, but parameters remain")
            break
        for param in spec:
            item = list_entry.get(param)
            if item is None:
                if spec[param].get("required"):
                    invalid_params.append(
                        "{0} : Required parameter not found".format(param)
                    )
                else:
                    item = spec[param].get("default")
                    valid_params_dict[param] = item
                continue
            data_type = spec[param].get("type")
            switch = {
                "str": validate_str,
                "int": validate_integer_within_range,
                "bool": validate_bool,
                "list": validate_list,
                "dict": validate_dict,
                "raw": lambda item, *_: item,
            }

            validator = switch.get(data_type)
            if validator:
                item = validator(item, spec[param], param, invalid_params, module)
            else:
                invalid_params.append(
                    "{0}:{1} : Unsupported data type {2}.".format(
                        param, item, data_type
                    )
                )

            choice = spec[param].get("choices")
            if choice:
                if item not in choice:
                    invalid_params.append("{0} : Invalid choice provided".format(item))

            no_log = spec[param].get("no_log")
            if no_log:
                if module is not None:
                    module.no_log_values.add(item)
                else:
                    msg = "\n\n'{0}' is a no_log parameter".format(param)
                    msg += "\nAnsible module object must be passed to this "
                    msg += "\nfunction to ensure it is not logged\n\n"
                    raise Exception(msg)

            valid_params_dict[param] = item
        normalized.append(valid_params_dict)

    return normalized, invalid_params
