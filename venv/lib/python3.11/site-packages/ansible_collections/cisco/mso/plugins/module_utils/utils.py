# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
import copy


def generate_api_endpoint(path, **kwargs):
    """
    Generates an API endpoint with query strings based on the provided keyword arguments.

    :param path: The base URL of the API endpoint. -> Str
    :param kwargs: Keyword arguments representing query parameters. -> Dict
    :return: A string representing the full API endpoint with query parameters. -> Str
    """
    return path if not kwargs else "{0}?{1}".format(path, "&".join(["{0}={1}".format(key, value) for key, value in kwargs.items()]))


def append_update_ops_data(ops, existing_data, update_path, replace_data=None, remove_data=None):
    """
    Append Update ops payload data.
    :param ops: Variable which contains the PATCH replace actions for the update operation -> List
    :param existing_data: Variable which contains the existing data -> Dict
    :param update_path: The object path is used to update an existing object -> Str
    :param replace_data: Defaults to None when not specified, expected a dictionary object. Which contains the attribute to be updated and its new value -> Dict
    :param remove_data: Defaults to None when not specified, expected a list of string or tuple, value used to clear the existing configuration -> List
    :return: None
                If attributes is not empty then the ops and existing_data are updated with the input value.

    Sample Existing Data:
    ---------------------
    existing_data = {
        "name": "name",
        "description": "description",
        "bfdMultiHopPol": {
            "adminState": "enabled",
            "minRxInterval": 250,
            "ifControl": {"adminState": "enabled"},
        },
        "bfdPol": {
            "adminState": "enabled",
            "detectionMultiplier": 3,
        }
    }

    ops = []
    update_path = "/tenantPolicyTemplate/template/l3OutIntfPolGroups/0"
    replace_data = {
        ("name"): "new_name",
        "description": "new_description",
        ("ospfIntfPol"): dict(ifControl=dict(adminState="disabled"), cost=0),
    }
    remove_data = [("bfdMultiHopPol", "ifControl", "adminState"), "bfdPol"]

    append_update_ops_data(ops, existing_data, update_path, replace_data, remove_data)

    Standard Output Data:
    ---------------------
    {
        "bfdMultiHopPol": {
            "adminState": "enabled",
            "minRxInterval": 250,
            "ifControl": {},
        },
        "name": "new_name",
        "description": "new_description",
        "ospfIntfPol": {
            "ifControl": {
                "adminState": "disabled",
            },
            "cost": 0,
        },
    }

    API Input Data:
    ---------------
    [
        {"op": "replace", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/name", "value": "new_name"},
        {"op": "replace", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/description", "value": "new_description"},
        {
            "op": "replace",
            "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/ospfIntfPol",
            "value": {"ifControl": {"adminState": "disabled"}, "cost": 0},
        },
        {"op": "remove", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/bfdPol"},
        {"op": "remove", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/bfdMultiHopPol/ifControl/adminState"},
    ]
    """

    def recursive_add_replace(data, path, keys, new_value):
        key = keys[0]
        if len(keys) == 1:
            # Update the existing configuration
            if new_value is not None and data.get(key) != new_value:
                operation = "replace" if data.get(key) is not None else "add"
                data[key] = new_value
                ops.append(
                    dict(
                        op=operation,
                        path="{}/{}".format(path, key),
                        value=copy.deepcopy(new_value),
                    )
                )
        elif key in data:
            recursive_add_replace(data[key], "{}/{}".format(path, key), keys[1:], new_value)

    def recursive_delete(data, path, keys):
        key = keys[0]
        if len(keys) == 1:
            # Clear the existing configuration
            if key in data:
                data.pop(key)
                ops.append(
                    dict(
                        op="remove",
                        path="{}/{}".format(path, key),
                    )
                )
        elif key in data:
            recursive_delete(data[key], "{}/{}".format(path, key), keys[1:])

    if replace_data:
        if not isinstance(replace_data, dict):
            raise TypeError("replace_data must be a dict")

        for key, value in replace_data.items():
            recursive_add_replace(existing_data, update_path, key if isinstance(key, tuple) else (key,), value)

    if remove_data:
        if not isinstance(remove_data, list):
            raise TypeError("remove_data must be a list of string or tuples")

        for key in remove_data:
            recursive_delete(existing_data, update_path, key if isinstance(key, tuple) else (key,))


def check_if_all_elements_are_none(values):
    """
    Checks if all elements in the provided iterable are None

    :param values: An iterable containing values to be checked -> Iterable[Any]
    :return: True if all elements are None, False otherwise -> Bool
    """
    return all(value is None for value in values)


def snake_to_camel(snake_str, upper_case_components=None):
    if snake_str is not None and "_" in snake_str:
        if upper_case_components is None:
            upper_case_components = []
        components = snake_str.split("_")
        camel_case_str = components[0]

        for component in components[1:]:
            if component in upper_case_components:
                camel_case_str += component.upper()
            else:
                camel_case_str += component.title()

        return camel_case_str
    else:
        return snake_str


def delete_none_values(obj_to_sanitize, recursive=True):
    """
    Removes keys with None values from a Python object, which can be either a list or a dictionary.
    Optionally performs the operation recursively on nested structures.

    :param obj_to_sanitize: The Python object to sanitize from None values. -> List or Dict
    :param recursive: A boolean flag indicating whether to recursively sanitize nested objects. Defaults to True. -> bool
    :return: A sanitized copy of the original Python object, with all keys with None values removed. -> List or Dict
    """
    if isinstance(obj_to_sanitize, dict):
        sanitized_dict = {}
        for item_key, item_value in obj_to_sanitize.items():
            if recursive and isinstance(item_value, (dict, list)):
                sanitized_dict[item_key] = delete_none_values(item_value, recursive)
            elif item_value is not None:
                sanitized_dict[item_key] = item_value
        return sanitized_dict

    elif isinstance(obj_to_sanitize, list):
        sanitized_list = []
        for item in obj_to_sanitize:
            if recursive and isinstance(item, (dict, list)):
                sanitized_list.append(delete_none_values(item, recursive))
            elif item is not None:
                sanitized_list.append(item)
        return sanitized_list

    else:
        raise TypeError("Object to sanitize must be of type list or dict. Got {}".format(type(obj_to_sanitize)))
