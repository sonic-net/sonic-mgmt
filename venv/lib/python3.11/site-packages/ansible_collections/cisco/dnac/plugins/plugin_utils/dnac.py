#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
try:
    from dnacentersdk import api, exceptions
except ImportError:
    DNAC_SDK_IS_INSTALLED = False
else:
    DNAC_SDK_IS_INSTALLED = True
from ansible.module_utils.basic import env_fallback
from ansible.module_utils._text import to_native

try:
    import logging
except ImportError:
    LOGGING_IN_STANDARD = False
else:
    LOGGING_IN_STANDARD = True
import os.path

ANSIBLE_SUCCESS_STATUS = 200


def is_list_complex(x):
    return isinstance(x[0], dict) or isinstance(x[0], list)


def has_diff_elem(ls1, ls2):
    return any((elem not in ls1 for elem in ls2))


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
        has_diff_1 = has_diff_elem(list1, list2)
        has_diff_2 = has_diff_elem(list2, list1)
        return not has_diff_1 or not has_diff_2


def fn_comp_key(k, dict1, dict2):
    return dnac_compare_equality(dict1.get(k), dict2.get(k))


def dnac_compare_equality(current_value, requested_value):
    # print("dnac_compare_equality", current_value, requested_value)
    if requested_value is None:
        return True
    if current_value is None:
        return True
    if isinstance(current_value, dict) and isinstance(requested_value, dict):
        all_dict_params = list(current_value.keys()) + list(requested_value.keys())
        return not any(
            (
                not fn_comp_key(param, current_value, requested_value)
                for param in all_dict_params
            )
        )
    elif isinstance(current_value, list) and isinstance(requested_value, list):
        return compare_list(current_value, requested_value)
    else:
        return current_value == requested_value


def fn_comp_key2(k, dict1, dict2):
    return dnac_compare_equality2(dict1.get(k), dict2.get(k))


def dnac_compare_equality2(current_value, requested_value, is_query_param=False):
    if is_query_param:
        return True
    if requested_value is None and current_value is None:
        return True
    if requested_value is None:
        return False
    if current_value is None:
        return False
    if isinstance(current_value, dict) and isinstance(requested_value, dict):
        all_dict_params = list(current_value.keys()) + list(requested_value.keys())
        return not any(
            (
                not fn_comp_key2(param, current_value, requested_value)
                for param in all_dict_params
            )
        )
    elif isinstance(current_value, list) and isinstance(requested_value, list):
        return compare_list(current_value, requested_value)
    else:
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
                if isinstance(item, dict) and (
                    item.get(key) is None or item.get(key) == value
                ):
                    result = item
                    return result
            result = None
    elif not isinstance(result, dict):
        result = None
    elif result.get(key) is not None and result.get(key) != value:
        result = None
    return result


def dnac_argument_spec():
    argument_spec = dict(
        dnac_host=dict(
            type="str", fallback=(env_fallback, ["DNAC_HOST"]), required=True
        ),
        dnac_port=dict(
            type="int",
            fallback=(env_fallback, ["DNAC_PORT"]),
            required=False,
            default=443,
        ),
        dnac_username=dict(
            type="str",
            fallback=(env_fallback, ["DNAC_USERNAME"]),
            default="admin",
            aliases=["user"],
        ),
        dnac_password=dict(
            type="str", fallback=(env_fallback, ["DNAC_PASSWORD"]), no_log=True
        ),
        dnac_verify=dict(
            type="bool", fallback=(env_fallback, ["DNAC_VERIFY"]), default=True
        ),
        dnac_version=dict(
            type="str", fallback=(env_fallback, ["DNAC_VERSION"]), default="2.3.7.6"
        ),
        dnac_debug=dict(
            type="bool", fallback=(env_fallback, ["DNAC_DEBUG"]), default=False
        ),
        validate_response_schema=dict(
            type="bool",
            fallback=(env_fallback, ["VALIDATE_RESPONSE_SCHEMA"]),
            default=True,
        ),
    )
    return argument_spec


class DNACSDK(object):
    def __init__(self, params):
        self.result = dict(changed=False, result="")
        self.validate_response_schema = params.get("validate_response_schema")
        if DNAC_SDK_IS_INSTALLED:
            self.api = api.DNACenterAPI(
                username=params.get("dnac_username"),
                password=params.get("dnac_password"),
                base_url="https://{dnac_host}:{dnac_port}".format(
                    dnac_host=params.get("dnac_host"), dnac_port=params.get("dnac_port")
                ),
                version=params.get("dnac_version"),
                verify=params.get("dnac_verify"),
                debug=params.get("dnac_debug"),
            )
            if params.get("dnac_debug") and LOGGING_IN_STANDARD:
                logging.getLogger("dnacentersdk").addHandler(logging.StreamHandler())
        else:
            self.fail_json(
                msg="DNA Center Python SDK is not installed. Execute 'pip install dnacentersdk'"
            )

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
        self.result["result"] = (
            "Object already present, but it has different values to the requested"
        )

    def object_modify_result(self, changed=None, result=None):
        if result is not None:
            self.result["result"] = result
        if changed:
            self.changed()

    def is_file(self, file_path):
        return os.path.isfile(file_path)

    def extract_file_name(self, file_path):
        return os.path.basename(file_path)

    def exec(self, family, function, params=None, op_modifies=False, **kwargs):
        try:
            family = getattr(self.api, family)
            func = getattr(family, function)
        except Exception as e:
            self.fail_json(msg=e)

        try:
            if params:
                file_paths_params = kwargs.get("file_paths", [])
                # This substitution is for the import file operation
                if file_paths_params and isinstance(file_paths_params, list):
                    multipart_fields = {}
                    for key, value in file_paths_params:
                        if isinstance(params.get(key), str) and self.is_file(
                            params[key]
                        ):
                            file_name = self.extract_file_name(params[key])
                            file_path = params[key]
                            multipart_fields[value] = (file_name, open(file_path, "rb"))

                    params.setdefault("multipart_fields", multipart_fields)
                    params.setdefault("multipart_monitor_callback", None)

                if not self.validate_response_schema and op_modifies:
                    params["active_validation"] = False

                response = func(**params)

                self.result.update(
                    {
                        "status": ANSIBLE_SUCCESS_STATUS,
                        "failed": False,
                        "msg": None,
                    }
                )
            else:
                response = func()
        except exceptions.dnacentersdkException as e:
            self.fail_json(
                msg=(
                    "An error occured when executing operation."
                    " The error was: {error}"
                ).format(error=to_native(e)),
                status=e.status_code,
            )
            response = None
        return response

    def fail_json(self, msg, **kwargs):
        self.result.update(
            {
                "failed": True,
                "changed": False,
                "status": kwargs.get("status"),
                "msg": msg,
            }
        )
        return self.result

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
