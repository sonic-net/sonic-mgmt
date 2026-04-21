#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type
try:
    import meraki
    from meraki import exceptions
except ImportError:
    MERAKI_SDK_IS_INSTALLED = False
else:
    MERAKI_SDK_IS_INSTALLED = True
from ansible.module_utils.basic import env_fallback
from ansible.module_utils._text import to_native
try:
    from ansible.errors import AnsibleActionFail
except ImportError:
    ANSIBLE_ERRORS_INSTALLED = False
else:
    ANSIBLE_ERRORS_INSTALLED = True

import os.path

lowercase_change_words = ["deny", "any"]


def is_list_complex(x):
    return isinstance(x[0], dict) or isinstance(x[0], list)


def has_diff_elem(ls1, ls2):
    """Checks if there are different elements between two lists."""
    if len(ls1) != len(ls2):
        return True
    return any(elem not in ls1 for elem in ls2)


def compare_dicts(dict1, dict2, common_keys):
    """Compares two dictionaries considering the defined rules."""
    for key in dict1:
        if key in dict2 and key in common_keys:
            val1, val2 = dict1[key], dict2[key]

            if isinstance(val1, str) and have_to_change_to_lowercase(val1.lower()):
                if val1.lower() != val2.lower():
                    return True
            elif isinstance(val1, list):
                if has_diff_elem(val1, val2):
                    return True
            else:
                if isinstance(val1, dict) and isinstance(val2, dict):
                    # common_keys between val1 and val2
                    new_common_keys = set(val1.keys()) & set(val2.keys())
                    compare_dicts(val1, val2, new_common_keys)
                    if compare_dicts(val1, val2, new_common_keys):
                        return True
                else:
                    if str(val1) != str(val2):
                        return True
    return False


def has_diff_elem2(ls1, ls2):
    """Compares two lists, with dictionaries inside them, to detect differences."""
    if len(ls1) != len(ls2):
        return True

    # Check if first elements are dictionaries before accessing keys
    if not (isinstance(ls1[0], dict) and isinstance(ls2[0], dict)):
        # If not both dicts, fall back to simple comparison
        for i, elem in enumerate(ls2):
            if str(ls1[i]) != str(elem):
                return True
        return False

    # Only compare common keys between ls1 and ls2
    common_keys = set(ls1[0].keys()) & set(ls2[0].keys())
    for i, elem in enumerate(ls2):
        if isinstance(elem, dict):
            # Ensure ls1[i] is also a dictionary
            if not isinstance(ls1[i], dict):
                return True
            if compare_dicts(ls1[i], elem, common_keys):
                return True
        else:
            # If elements are not dictionaries, compare them directly
            if str(ls1[i]) != str(elem):
                return True

    return False


def have_to_change_to_lowercase(attr):
    return attr in lowercase_change_words


def delete_default_rule(ls):
    index = 0
    for elem in ls:
        if elem["comment"].lower() == "default rule":
            del ls[index]
            break
        index = index + 1
    return ls


def compare_list(list1, list2):
    len_list1 = len(list1)
    len_list2 = len(list2)
    if len_list1 != len_list2:
        return False

    if len_list1 == 0:
        return True

    attempt_std_cmp = list1 == list2
    if attempt_std_cmp:
        return True

    if not is_list_complex(list1) and not is_list_complex(list2):
        return set(list1) == set(list2)

    # Compare normally if it exceeds expected size * 2 (len_list1==len_list2)
    MAX_SIZE_CMP = 100
    # Fail fast if elem not in list, thanks to any and generators
    if len_list1 > MAX_SIZE_CMP:
        return attempt_std_cmp
    else:
        # not changes 'has diff elem' to list1 != list2 ':lists are not equal'
        if isinstance(list1[0], dict):
            return not (has_diff_elem2(list1, list2)) or not (has_diff_elem2(list2, list1))
        else:
            return not (has_diff_elem(list1, list2)) or not (has_diff_elem(list2, list1))


def fn_comp_key(k, dict1, dict2):
    return meraki_compare_equality(dict1.get(k), dict2.get(k))


def meraki_compare_equality(current_value, requested_value):
    # print("meraki_compare_equality", current_value, requested_value)
    if requested_value is None:
        return True
    if current_value is None:
        if requested_value is not None:
            return False
        return True
    if isinstance(current_value, dict) and isinstance(requested_value, dict):
        all_dict_params = list(current_value.keys()) + \
            list(requested_value.keys())
        return not any((not fn_comp_key(param, current_value, requested_value) for param in all_dict_params))
    elif isinstance(current_value, list) and isinstance(requested_value, list):
        return compare_list(current_value, requested_value)
    else:
        return current_value == requested_value


def meraki_compare_equality2(current_value, requested_value):
    # print("meraki_compare_equality", current_value, requested_value)
    if requested_value is not None and current_value is None:
        # print("requested_value is not None and current_value is None", False)
        return False
    if requested_value is None:
        # print("requested_value is None", True)
        return True
    if current_value is None:
        # print("current_value", True)
        return True
    if isinstance(current_value, dict) and isinstance(requested_value, dict):
        all_dict_params = list(current_value.keys()) + \
            list(requested_value.keys())
        return not any((not fn_comp_key(param, current_value, requested_value) for param in all_dict_params))
    elif isinstance(current_value, list) and isinstance(requested_value, list):
        return compare_list(current_value, requested_value)
    else:
        # print("current_value == requested_value", current_value == requested_value)
        return current_value == requested_value


def simple_cmp(obj1, obj2):
    return obj1 == obj2


def get_dict_result(result, key, value, cmp_fn=simple_cmp):
    if isinstance(result, list):
        if len(result) == 1:
            if isinstance(result[0], dict):
                result = result[0]
                if result.get(key) is not None and result.get(key) != value:
                    result = None
            else:
                result = None
        else:
            for item in result:
                if isinstance(item, dict) and (item.get(key) is None or item.get(key) == value):
                    result = item
                    return result
            result = None
    elif not isinstance(result, dict):
        result = None
    elif result.get(key) is not None and result.get(key) != value:
        result = None
    return result


def meraki_argument_spec():
    argument_spec = dict(
        meraki_api_key=dict(type="str", fallback=(
            env_fallback, ['MERAKI_DASHBOARD_API_KEY']), required=True),
        meraki_base_url=dict(
            type="str", default="https://api.meraki.com/api/v1"),
        meraki_single_request_timeout=dict(type="int", default=60),
        meraki_certificate_path=dict(type="str", default=""),
        meraki_requests_proxy=dict(type="str", default=""),
        meraki_wait_on_rate_limit=dict(type="bool", default=True),
        meraki_nginx_429_retry_wait_time=dict(type="int", default=60),
        meraki_action_batch_retry_wait_time=dict(type="int", default=60),
        meraki_retry_4xx_error=dict(type="bool", default=False),
        meraki_retry_4xx_error_wait_time=dict(type="int", default=60),
        meraki_maximum_retries=dict(type="int", default=2),
        meraki_output_log=dict(type="bool", default=True),
        meraki_log_path=dict(type="str", default=""),
        meraki_log_file_prefix=dict(type="str", default="meraki_api_"),
        meraki_print_console=dict(type="bool", default=True),
        meraki_suppress_logging=dict(type="bool", default=True),
        meraki_simulate=dict(type="bool", default=False),
        meraki_be_geo_id=dict(type="str", fallback=(
            env_fallback, ['BE_GEO_ID']), default=""),
        meraki_use_iterator_for_get_pages=dict(type="bool", default=False),
        meraki_inherit_logging_config=dict(type="bool", default=False),
    )
    return argument_spec


class MERAKI(object):
    def __init__(self, params):
        self.result = dict(changed=False, result="")
        # self.validate_response_schema = params.get("validate_response_schema")
        if MERAKI_SDK_IS_INSTALLED:
            self.api = meraki.DashboardAPI(
                api_key=params.get("meraki_api_key"),
                base_url=params.get("meraki_base_url"),
                single_request_timeout=params.get(
                    "meraki_single_request_timeout"),
                certificate_path=params.get("meraki_certificate_path"),
                requests_proxy=params.get("meraki_requests_proxy"),
                wait_on_rate_limit=params.get("meraki_wait_on_rate_limit"),
                nginx_429_retry_wait_time=params.get(
                    "meraki_nginx_429_retry_wait_time"),
                action_batch_retry_wait_time=params.get(
                    "meraki_action_batch_retry_wait_time"),
                retry_4xx_error=params.get("meraki_retry_4xx_error"),
                retry_4xx_error_wait_time=params.get(
                    "meraki_retry_4xx_error_wait_time"),
                maximum_retries=params.get("meraki_maximum_retries"),
                output_log=params.get("meraki_output_log"),
                log_path=params.get("meraki_log_path"),
                log_file_prefix=params.get("meraki_log_file_prefix"),
                print_console=params.get("meraki_print_console"),
                suppress_logging=params.get("meraki_suppress_logging"),
                simulate=params.get("meraki_simulate"),
                be_geo_id=params.get("meraki_be_geo_id"),
                caller="MerakiAnsibleCollection/2.21.2 Cisco",
                use_iterator_for_get_pages=params.get(
                    "meraki_use_iterator_for_get_pages"),
                inherit_logging_config=params.get(
                    "meraki_inherit_logging_config"),
            )
            # if params.get("meraki_debug") and LOGGING_IN_STANDARD:
            #     logging.getLogger('merakientersdk').addHandler(logging.StreamHandler())
        else:
            self.fail_json(
                msg="Meraki SDK is not installed. Execute 'pip install meraki'")

    def changed(self):
        self.result["changed"] = True

    def object_created(self):
        self.changed()
        self.result["result"] = "Object created"

    def object_updated(self):
        self.changed()
        self.result["result"] = "Object updated"

    def object_deleted(self):
        self.changed()
        self.result["result"] = "Object deleted"

    def object_already_absent(self):
        self.result["result"] = "Object already absent"

    def object_already_present(self):
        self.result["result"] = "Object already present"

    def object_present_and_different(self):
        self.result["result"] = "Object already present, but it has different values to the requested"

    def object_modify_result(self, changed=None, result=None):
        if result is not None:
            self.result["result"] = result
        if changed:
            self.changed()

    def is_file(self, file_path):
        return os.path.isfile(file_path)

    def extract_file_name(self, file_path):
        return os.path.basename(file_path)

    def exec_meraki(self, family, function, params=None, op_modifies=False, **kwargs):
        try:
            family = getattr(self.api, family)
            func = getattr(family, function)
        except Exception as e:
            self.fail_json(msg=e)

        try:
            if params:
                file_paths_params = kwargs.get('file_paths', [])
                # This substitution is for the import file operation
                if file_paths_params and isinstance(file_paths_params, list):
                    multipart_fields = {}
                    for (key, value) in file_paths_params:
                        if isinstance(params.get(key), str) and self.is_file(params[key]):
                            file_name = self.extract_file_name(params[key])
                            file_path = params[key]
                            multipart_fields[value] = (
                                file_name, open(file_path, 'rb'))

                    params.setdefault("multipart_fields", multipart_fields)
                    params.setdefault("multipart_monitor_callback", None)

                # if not self.validate_response_schema and op_modifies:
                #     params["active_validation"] = False

                response = func(**params)
            else:
                response = func()
        except exceptions.APIError as e:
            self.fail_json(
                msg=(
                    "An error occurred when executing operation."
                    "The error was: {error}"
                ).format(error=to_native(e))
            )
        return response

    def fail_json(self, msg, **kwargs):
        self.result.update(**kwargs)
        raise AnsibleActionFail(msg, kwargs)

    def exit_json(self):
        return self.result

    def verify_array(self, verify_interface, **kwargs):
        if verify_interface is None:
            return list()

        if isinstance(verify_interface, list):
            if len(verify_interface) == 0:
                return list()
            if verify_interface[0] is None:
                return list()
        return verify_interface


def main():
    pass


if __name__ == "__main__":
    main()
