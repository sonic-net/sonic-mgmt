# Copyright (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import time
import traceback

from ansible.module_utils._text import to_text
import json
from ansible_collections.fortinet.fortios.plugins.module_utils.common.type_utils import (
    underscore_to_hyphen,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.secret_field import (
    is_secret_field,
)

try:
    import urllib.parse as urlencoding
except ImportError:
    import urllib as urlencoding

# BEGIN DEPRECATED

# check for pyFG lib
try:
    from pyFG import FortiOS, FortiConfig
    from pyFG.exceptions import FailedCommit

    HAS_PYFG = True
except ImportError:
    HAS_PYFG = False

fortios_required_if = [
    ["file_mode", False, ["host", "username", "password"]],
    ["file_mode", True, ["config_file"]],
    ["backup", True, ["backup_path"]],
]

fortios_mutually_exclusive = [
    ["config_file", "host"],
    ["config_file", "username"],
    ["config_file", "password"],
]

fortios_error_codes = {"-3": "Object not found", "-61": "Command error"}


def check_legacy_fortiosapi(module):
    legacy_schemas = ["host", "username", "password", "ssl_verify", "https"]
    legacy_params = []
    for param in legacy_schemas:
        if param in module.params:
            legacy_params.append(param)
    if len(legacy_params):
        error_message = (
            "Legacy fortiosapi parameters %s detected, please use HTTPAPI instead!"
            % (str(legacy_params))
        )
        module.fail_json(msg=error_message)


def schema_to_module_spec(schema):
    rdata = dict()
    if "type" not in schema:
        raise AssertionError("Invalid Schema")
    if schema["type"] == "dict" or (schema["type"] == "list" and "children" in schema):
        if "children" not in schema:
            raise AssertionError()
        rdata["type"] = schema["type"]
        if schema["type"] == "list":
            rdata["elements"] = schema.get("elements")
        rdata["required"] = schema["required"] if "required" in schema else False
        rdata["options"] = dict()
        for child in schema["children"]:
            child_value = schema["children"][child]
            rdata["options"][child] = schema_to_module_spec(child_value)
            if is_secret_field(child):
                rdata["options"][child]["no_log"] = True
    elif schema["type"] in ["integer", "string"] or (
        schema["type"] == "list" and "children" not in schema
    ):
        if schema["type"] == "integer":
            rdata["type"] = "int"
        elif schema["type"] == "string":
            rdata["type"] = "str"
        elif schema["type"] == "list":
            rdata["type"] = "list"
            rdata["elements"] = schema.get("elements")
        else:
            raise AssertionError()
        rdata["required"] = schema["required"] if "required" in schema else False
        if "options" in schema:
            # see mantis #0690570, if the semantic meaning changes, remove choices as well
            # also see accept_auth_by_cert of module fortios_system_csf.
            # ansible-test now requires choices are present in spec
            rdata["choices"] = [option["value"] for option in schema["options"]]
    else:
        raise AssertionError()
    return rdata


def __convert_version_to_number(version):
    version = version[1:] if version.startswith("v") else version
    seg = version.split(".")
    if len(seg) != 3:
        raise Exception(
            "Invalid fortios system version number: "
            + version
            + ". Should be of format [major].[minor].[patch]"
        )
    return int(seg[0]) * 10000 + int(seg[1]) * 100 + int(seg[2])


def __format_single_range_desc(one_range):
    if len(one_range) != 2:
        raise Exception(
            "Incorrect version range, expecting [start, end]: " + str(one_range)
        )

    if one_range[0] == one_range[1]:
        return one_range[0]
    elif one_range[1] == "":
        return one_range[0] + " -> latest"
    else:
        return one_range[0] + " -> " + one_range[1]


def __check_if_system_version_is_supported(v_range, version):
    """check the current system version is supported in v_range"""

    if not v_range:
        return {"supported": True}
    system_version_number = __convert_version_to_number(version)

    v_range_desc = ", ".join(list(map(__format_single_range_desc, v_range)))
    for [single_range_start, single_range_end] in v_range:
        single_range_start_number = __convert_version_to_number(single_range_start)
        if system_version_number < single_range_start_number:

            return {
                "supported": False,
                "reason": "Supported version ranges are " + v_range_desc,
            }

        if (
            single_range_end == ""
            or system_version_number <= __convert_version_to_number(single_range_end)
        ):
            return {"supported": True}

    return {
        "supported": False,
        "reason": "Supported version ranges are " + v_range_desc,
    }


def __check_version(revisions, version):
    result = dict()
    resolved_versions = list(revisions.keys())
    resolved_versions.sort(
        key=lambda x: int(x.split(".")[0][1]) * 10000
        + int(x.split(".")[1]) * 100
        + int(x.split(".")[2])
    )
    # try to detect the versioning gaps and mark them as violations:
    nearest_index = -1
    for i in range(len(resolved_versions)):
        if resolved_versions[i] <= version:
            nearest_index = i
    if nearest_index == -1:
        # even it's not supported in earliest version
        result["supported"] = False
        result["reason"] = "not supported until in %s" % (resolved_versions[0])
    else:
        if revisions[resolved_versions[nearest_index]] is False:
            latest_index = -1
            for i in range(nearest_index + 1, len(resolved_versions)):
                if revisions[resolved_versions[i]] is True:
                    latest_index = i
                    break
            earliest_index = nearest_index
            while earliest_index >= 0:
                if revisions[resolved_versions[earliest_index]] is True:
                    break
                earliest_index -= 1
            earliest_index = 0 if earliest_index < 0 else earliest_index
            if latest_index == -1:
                result["reason"] = "not supported since %s" % (
                    resolved_versions[earliest_index]
                )
            else:
                result["reason"] = "not supported since %s, before %s" % (
                    resolved_versions[earliest_index],
                    resolved_versions[latest_index],
                )
            result["supported"] = False
        else:
            result["supported"] = True
    return result


def __concat_attribute_sequence(trace_path):
    rdata = ""
    if not isinstance(trace_path, list):
        raise AssertionError()
    if len(trace_path) >= 1:
        rdata += str(trace_path[0])
    for item in trace_path[1:]:
        rdata += "." + str(item)
    return rdata


def check_schema_versioning_internal(results, trace, schema, params, version):
    if not schema or not params:
        return
    matched = __check_if_system_version_is_supported(
        schema["v_range"] if "v_range" in schema else {}, version
    )
    if matched["supported"] is False:
        results["mismatches"].append(
            "option %s %s" % (__concat_attribute_sequence(trace), matched["reason"])
        )

    if "type" not in schema:
        return

    if schema["type"] == "list":
        if not isinstance(params, list):
            raise AssertionError()
        if "children" in schema:
            if "options" in schema:
                raise AssertionError()
            for list_item in params:
                if not isinstance(list_item, dict):
                    # Parameter inconsistency here is not covered by Ansible, we gracefully throw a warning
                    results["mismatches"].append(
                        "option [%s]' playload is inconsistent with schema."
                        % (__concat_attribute_sequence(trace))
                    )
                    continue
                for key in list_item:
                    value = list_item[key]
                    key_string = (
                        "%s(%s)" % (key, value)
                        if type(value) in [int, bool, str]
                        else key
                    )
                    trace.append(key_string)
                    check_schema_versioning_internal(
                        results, trace, schema["children"][key], value, version
                    )
                    del trace[-1]
        elif "options" in schema:
            for param in params:
                if type(param) not in [int, bool, str]:
                    raise AssertionError()
                target_option = None
                for option in schema["options"]:
                    if option["value"] == param:
                        target_option = option
                        break
                if not target_option:
                    raise AssertionError()
                trace.append("[%s]" % param)
                check_schema_versioning_internal(
                    results, trace, target_option, param, version
                )
                del trace[-1]
    elif schema["type"] == "dict":
        if not isinstance(params, dict):
            raise AssertionError()
        if "children" in schema:
            for dict_item_key in params:
                dict_item_value = params[dict_item_key]
                if dict_item_key not in schema["children"]:
                    raise AssertionError()
                key_string = (
                    "%s(%s)" % (dict_item_key, dict_item_value)
                    if type(dict_item_value) in [int, bool, str]
                    else dict_item_key
                )
                trace.append(key_string)
                check_schema_versioning_internal(
                    results,
                    trace,
                    schema["children"][dict_item_key],
                    dict_item_value,
                    version,
                )
                del trace[-1]
    else:
        if type(params) not in [int, str, bool]:
            raise AssertionError()


def check_schema_versioning(fos, versioned_schema, top_level_param):
    trace = list()
    results = dict()
    results["matched"] = True
    results["mismatches"] = list()

    system_version = fos._conn.get_system_version()
    params = fos._module.params[top_level_param]
    results["system_version"] = system_version
    if not params:
        # in case no top level parameters are given.
        # see module: fortios_firewall_policy
        return results
    v_range = versioned_schema["v_range"]
    module_matched = __check_if_system_version_is_supported(v_range, system_version)
    if not module_matched["supported"]:
        results["matched"] = False
        results["mismatches"].append(
            "module fortios_%s %s" % (top_level_param, module_matched["reason"])
        )
        return results

    for param_name in params:
        param_value = params[param_name]
        if not param_value or param_name not in versioned_schema["children"]:
            continue
        key_string = (
            "%s(%s)" % (param_name, param_value)
            if type(param_value) in [int, bool, str]
            else param_name
        )
        trace.append(key_string)
        check_schema_versioning_internal(
            results,
            trace,
            versioned_schema["children"][param_name],
            param_value,
            system_version,
        )
        del trace[-1]
    if len(results["mismatches"]):
        results["matched"] = False

    return results


# END DEPRECATED


class FortiOSHandler(object):

    def __init__(self, conn, mod, module_mkeyname=None):
        self._conn = conn
        self._module = mod
        self._mkeyname = module_mkeyname

    def _trace_to_string(self, trace):
        trace_string = ""
        for _trace in trace:
            trace_string += "%s%s" % (_trace, "." if _trace != trace[-1] else "")
        return trace_string

    def _validate_member_parameter(
        self, trace, trace_param, trace_url_tokens, attr_blobs, attr_params
    ):
        attr_blob = attr_blobs[0]
        current_attr_name = attr_blob["name"]
        current_attr_mkey = attr_blob["mkey"]
        trace.append(current_attr_name)
        if not attr_params:
            self._module.fail_json(
                "parameter %s is empty" % (self._trace_to_string(trace))
            )

        if type(attr_params) not in [list, dict]:
            raise AssertionError("Invalid attribute type")
        if isinstance(attr_params, dict):
            trace_param_item = dict()
            trace_param_item[current_attr_name] = (None, attr_params)
            trace_param.append(trace_param_item)
            if len(attr_blobs) <= 1:
                raise AssertionError("Invalid attribute blob")
            next_attr_blob = attr_blobs[1]
            next_attr_name = next_attr_blob["name"]
            self._validate_member_parameter(
                trace,
                trace_param,
                trace_url_tokens,
                attr_blobs[1:],
                attr_params[next_attr_name],
            )
            del trace_param[-1]
            return

        # when attr_params is a list
        for param in attr_params:
            if current_attr_mkey not in param or not param[current_attr_mkey]:
                self._module.fail_json(
                    "parameter %s.%s is empty"
                    % (self._trace_to_string(trace), current_attr_mkey)
                )
            trace_param_item = dict()
            trace_param_item[current_attr_name] = (param[current_attr_mkey], param)
            trace_param.append(trace_param_item)
            if len(attr_blobs) > 1:
                next_attr_blob = attr_blobs[1]
                next_attr_name = next_attr_blob["name"]
                if next_attr_name in param:
                    self._validate_member_parameter(
                        trace,
                        trace_param,
                        trace_url_tokens,
                        attr_blobs[1:],
                        param[next_attr_name],
                    )
                else:
                    # attribute terminated
                    url_tokens = list()
                    for token in trace_param:
                        url_tokens.append(token)
                    trace_url_tokens.append(url_tokens)
            else:
                # terminated normally as last level parameter.
                url_tokens = list()
                for token in trace_param:
                    url_tokens.append(token)
                trace_url_tokens.append(url_tokens)
            del trace_param[-1]

    def _process_sub_object(
        self, all_urls, toplevel_url_token, traced_url_tokens, path, name
    ):
        vdom = (
            self._module.params["vdom"]
            if "vdom" in self._module.params and self._module.params["vdom"]
            else None
        )
        url_prefix = self.cmdb_url(path, name)
        url_suffix = ""
        if vdom == "global":
            url_suffix = "?global=1"
        elif vdom:
            url_suffix = "?vdom=" + vdom
        for url_tokens in traced_url_tokens:
            url = dict()
            url_get = toplevel_url_token
            url_put = toplevel_url_token
            url_post = toplevel_url_token
            url_put_payload = dict()
            url_post_payload = dict()
            for token in url_tokens:
                token_name = str(list(token.keys())[0])
                token_value = str(token[token_name][0])
                token_payload = underscore_to_hyphen(token[token_name][1])
                token_islast = token == url_tokens[-1]
                if token[token_name][0]:
                    url_get += "/%s/%s" % (
                        token_name.replace("_", "-"),
                        urlencoding.quote(token_value, safe=""),
                    )
                    url_put += "/%s/%s" % (
                        token_name.replace("_", "-"),
                        urlencoding.quote(token_value, safe=""),
                    )
                else:
                    url_get += "/%s" % (token_name.replace("_", "-"))
                    url_put += "/%s" % (token_name.replace("_", "-"))
                if not token_islast:
                    if token[token_name][0]:
                        url_post += "/%s/%s" % (
                            token_name.replace("_", "-"),
                            urlencoding.quote(token_value, safe=""),
                        )
                    else:
                        url_post += "/%s" % (token_name.replace("_", "-"))
                else:
                    url_post += "/%s" % (token_name.replace("_", "-"))
                    url_post_payload = token_payload
                    url_put_payload = token_payload
            url["get"] = url_prefix + url_get + url_suffix
            url["put"] = url_prefix + url_put + url_suffix
            url["post"] = url_prefix + url_post + url_suffix
            url["put_payload"] = url_put_payload
            url["post_payload"] = url_post_payload
            # DELETE share same url with GET
            url["delete"] = url["get"]
            url["vdom"] = vdom
            all_urls.append(url)

    def _request_sub_object(self, sub_obj):
        directive_state = self._module.params["member_state"]
        if directive_state not in ["present", "absent"]:
            raise AssertionError("Not invalid member_state directive.")
        status = None
        result_data = None
        if directive_state == "present":
            status, result_data = self._conn.send_request(
                url=sub_obj["get"], params=None, method="GET"
            )
            if status == 200:
                status, result_data = self._conn.send_request(
                    url=sub_obj["put"],
                    data=json.dumps(sub_obj["put_payload"]),
                    method="PUT",
                )
                if status == 405:
                    status, result_data = self._conn.send_request(
                        url=sub_obj["post"],
                        data=json.dumps(sub_obj["post_payload"]),
                        method="POST",
                    )
            else:
                status, result_data = self._conn.send_request(
                    url=sub_obj["post"],
                    data=json.dumps(sub_obj["post_payload"]),
                    method="POST",
                )
        else:
            status, result_data = self._conn.send_request(
                url=sub_obj["delete"], params=None, method="DELETE"
            )
        result_data = self.formatresponse(result_data, status, vdom=sub_obj["vdom"])
        return result_data

    def _process_sub_object_result(self, results):
        meta = list()
        failed = False
        changed = False

        for result in results:
            sub_obj = result[0]
            result_data = result[1]
            url = sub_obj["get"]
            suffix_index = url.find("?")
            if suffix_index >= 0:
                url = url[:suffix_index]
            result_data["object_path"] = url[12:]
            meta.append(result_data)
            if "status" in result_data:
                if result_data["status"] == "error":
                    failed = True
                elif result_data["status"] == "success":
                    if (
                        "revision_changed" in result_data
                        and result_data["revision_changed"] is True
                    ):
                        changed = True
                    elif "revision_changed" not in result_data:
                        changed = True
        self._module.exit_json(meta=meta, changed=changed, failed=failed)

    def do_member_operation(self, path, name, data):
        toplevel_name = (
            (path + "_" + name).replace("-", "_").replace(".", "_").replace("+", "plus")
        )
        if not data["member_state"]:
            return
        if not data["member_path"]:
            self._module.fail_json(
                "member_path is empty while member_state is %s" % (data["member_state"])
            )
        attribute_path = list()
        for attr in data["member_path"].split("/"):
            if attr == "":
                continue
            attribute_path.append(attr.strip(" "))
        if not len(attribute_path):
            raise AssertionError("member_path should have at least one attribute")
        state_present = "state" in data
        if state_present and not self._mkeyname:
            raise AssertionError("Invalid mkey scheme!")
        if state_present and (
            not data[toplevel_name] or not data[toplevel_name][self._mkeyname]
        ):
            raise AssertionError(
                "parameter %s or %s.%s empty!"
                % (toplevel_name, toplevel_name, self._mkeyname)
            )
        toplevel_url_token = ""
        if state_present:
            toplevel_url_token = "/%s" % urlencoding.quote(
                str(data[toplevel_name][self._mkeyname])
            )

        # here we get both module arg spec and provided params
        arg_spec = self._module.argument_spec[toplevel_name]["options"]
        attr_spec = arg_spec

        attr_params = data[toplevel_name]
        if not attr_params:
            raise AssertionError("Parameter %s is empty" % (toplevel_name))

        # collect attribute metadata.
        attr_blobs = list()
        for attr_pair in attribute_path:
            attr_pair_split = attr_pair.split(":")
            attr = attr_pair_split[0]
            if attr not in attr_spec:
                self._module.fail_json(
                    "Attribute %s not as part of module schema" % (attr)
                )
            attr_spec = attr_spec[attr]
            attr_type = attr_spec["type"]

            if len(attr_pair_split) != 2 and attr_type != "dict":
                self._module.fail_json("wrong attribute format: %s" % (attr_pair))
            attr_mkey = attr_pair_split[1] if attr_type == "list" else None

            if "options" not in attr_spec:
                raise AssertionError(
                    "Attribute %s not member operable, no children options" % (attr)
                )

            attr_blob = dict()
            attr_blob["name"] = attr
            attr_blob["mkey"] = attr_mkey
            attr_blob["schema"] = attr_spec["options"]
            attr_spec = attr_spec["options"]
            attr_blobs.append(attr_blob)

        # validate parameters on attributes path.
        trace = list()
        trace_param = list()
        trace_url_tokens = list()
        urls = list()
        results = list()
        trace.append(toplevel_name)
        self._validate_member_parameter(
            trace,
            trace_param,
            trace_url_tokens,
            attr_blobs,
            attr_params[attr_blobs[0]["name"]],
        )
        self._process_sub_object(urls, toplevel_url_token, trace_url_tokens, path, name)
        for sub_obj in urls:
            result = self._request_sub_object(sub_obj)
            results.append((sub_obj, result))
        self._process_sub_object_result(results)

    def cmdb_url(self, path, name, vdom=None, mkey=None):

        url = "/api/v2/cmdb/" + path + "/" + name
        if mkey is not None:
            url = url + "/" + urlencoding.quote(str(mkey), safe="")
        if vdom is not None:
            if vdom == "global":
                url += "?global=1"
            else:
                if vdom == "":
                    url += "?vdom=root"
                else:
                    url += "?vdom=" + vdom
        return url

    def mon_url(self, path, name, vdom=None, mkey=None):
        url = "/api/v2/monitor/" + path + "/" + name
        if mkey is not None:
            url = url + "/" + urlencoding.quote(str(mkey), safe="")
        if vdom is not None:
            if vdom == "global":
                url += "?global=1"
            else:
                if vdom == "":
                    url += "?vdom=root"
                else:
                    url += "?vdom=" + vdom
        return url

    def log_url(self, path, name, mkey=None):
        url = "/api/v2/log/" + path + "/" + name
        if mkey:
            url = url + "/" + urlencoding.quote(str(mkey), safe="")
        return url

    def schema(self, path, name, vdom=None):
        if vdom is None:
            url = self.cmdb_url(path, name) + "?action=schema"
        else:
            url = self.cmdb_url(path, name, vdom=vdom) + "&action=schema"

        status, result_data = self._conn.send_request(url=url)

        if status == 200:
            if vdom == "global":
                return json.loads(to_text(result_data))[0]["results"]
            else:
                return json.loads(to_text(result_data))["results"]
        else:
            return json.loads(to_text(result_data))

    def get_mkeyname(self, path, name, vdom=None):
        return self._mkeyname

    def get_mkey(self, path, name, data, vdom=None):

        keyname = self.get_mkeyname(path, name, vdom)
        if not keyname:
            return None
        else:
            try:
                mkey = (
                    data[keyname]
                    if keyname in data
                    else data[keyname.replace("_", "-")]
                )
            except KeyError:
                return None
        return mkey

    def log_get(self, url, parameters=None):
        slash_index = url.find("/")
        full_url = self.log_url(url[:slash_index], url[slash_index + 1 :])

        http_status, result_data = self._conn.send_request(
            url=full_url, params=parameters, method="GET"
        )

        return self.formatresponse(result_data, http_status)

    def monitor_get(self, url, vdom=None, parameters=None):
        slash_index = url.find("/")
        full_url = self.mon_url(url[:slash_index], url[slash_index + 1 :], vdom)
        http_status, result_data = self._conn.send_request(
            url=full_url, params=parameters, method="GET"
        )
        return self.formatresponse(result_data, http_status, vdom=vdom)

    def monitor_post(self, url, data=None, vdom=None, mkey=None, parameters=None):
        slash_index = url.find("/")
        url = self.mon_url(url[:slash_index], url[slash_index + 1 :], vdom)

        http_status, result_data = self._conn.send_request(
            url=url, params=parameters, data=json.dumps(data), method="POST"
        )

        return self.formatresponse(result_data, http_status, vdom=vdom)

    def get(self, path, name, vdom=None, mkey=None, parameters=None):
        url = self.cmdb_url(path, name, vdom, mkey=mkey)

        http_status, result_data = self._conn.send_request(
            url=url, params=parameters, method="GET"
        )

        return self.formatresponse(result_data, http_status, vdom=vdom)

    def monitor(self, path, name, vdom=None, mkey=None, parameters=None):
        url = self.mon_url(path, name, vdom, mkey)

        http_status, result_data = self._conn.send_request(
            url=url, params=parameters, method="GET"
        )

        return self.formatresponse(result_data, http_status, vdom=vdom)

    def set(self, path, name, data, mkey=None, vdom=None, parameters=None):

        if mkey is None:
            mkey = self.get_mkey(path, name, data, vdom=vdom)
        url = self.cmdb_url(path, name, vdom, mkey)

        # raise AssertionError(
        #     "mkeyname: %s, mkey %s ; test url %s, %s"
        #     % (self.get_mkeyname(None, None), mkey, url, data)
        # )
        if parameters and "action" in parameters and parameters["action"] == "move":
            # Handle the 'move' action logic here, as it is only supported in PUT requests.
            # Failing to address this will result in an API issue, since action=move will be included
            # in the parameters for a GET request.
            http_status, result_data = self._conn.send_request(
                url=url, params=parameters, data=json.dumps(data), method="PUT"
            )
            return self.formatresponse(result_data, http_status, vdom=vdom)

        http_get_status, unused_response_data = self._conn.send_request(
            url=url, params=parameters, method="GET"
        )
        if http_get_status != 200:
            return self.post(path, name, data, vdom, mkey)

        http_status, result_data = self._conn.send_request(
            url=url, params=parameters, data=json.dumps(data), method="PUT"
        )

        return self.formatresponse(result_data, http_status, vdom=vdom)

    def post(self, path, name, data, vdom=None, mkey=None, parameters=None):

        if mkey:
            mkeyname = self.get_mkeyname(path, name, vdom)
            data[mkeyname] = mkey

        url = self.cmdb_url(path, name, vdom, mkey=None)

        http_status, result_data = self._conn.send_request(
            url=url, params=parameters, data=json.dumps(data), method="POST"
        )

        return self.formatresponse(result_data, http_status, vdom=vdom)

    def execute(
        self, path, name, data, vdom=None, mkey=None, parameters=None, timeout=300
    ):
        url = self.mon_url(path, name, vdom, mkey=mkey)

        http_status, result_data = self._conn.send_request(
            url=url,
            params=parameters,
            data=json.dumps(data),
            method="POST",
            timeout=timeout,
        )

        return self.formatresponse(result_data, http_status, vdom=vdom)

    def delete(self, path, name, vdom=None, mkey=None, parameters=None, data=None):
        if not mkey:
            mkey = self.get_mkey(path, name, data, vdom=vdom)
        url = self.cmdb_url(path, name, vdom, mkey)
        http_status, result_data = self._conn.send_request(
            url=url, params=parameters, data=json.dumps(data), method="DELETE"
        )
        return self.formatresponse(result_data, http_status, vdom=vdom)

    def __to_local(self, data, http_status, is_array=False):
        try:
            resp = json.loads(data)
        except Exception:
            resp = {"raw": data}
        if is_array and not isinstance(resp, list):
            resp = [resp]
        if is_array and "http_status" not in resp[0]:
            resp[0]["http_status"] = http_status
        elif not is_array and "status" not in resp:
            resp["http_status"] = http_status
        return resp

    def formatresponse(self, res, http_status=500, vdom=None):
        if vdom == "global":
            resp = self.__to_local(to_text(res), http_status, True)[0]
            resp["vdom"] = "global"
        else:
            resp = self.__to_local(to_text(res), http_status, False)
        return resp

    def jsonraw(self, method, path, data, specific_params, vdom=None, parameters=None):
        url = urlencoding.quote(path)
        bvdom = False
        if vdom:
            if vdom == "global":
                url += "?global=1"
            else:
                url += "?vdom=" + vdom
            bvdom = True
        if specific_params:
            if bvdom:
                url += "&"
            else:
                url += "?"
            url += specific_params

        if method == "GET":
            http_status, result_data = self._conn.send_request(
                url=url, method="GET", params=parameters
            )
        else:
            http_status, result_data = self._conn.send_request(
                url=url, method=method, data=json.dumps(data), params=parameters
            )

        return self.formatresponse(result_data, http_status, vdom=vdom)


# BEGIN DEPRECATED


def backup(module, running_config):
    backup_path = module.params["backup_path"]
    backup_filename = module.params["backup_filename"]
    if not os.path.exists(backup_path):
        try:
            os.mkdir(backup_path)
        except Exception:
            module.fail_json(
                msg="Can't create directory {0} Permission denied ?".format(backup_path)
            )
    tstamp = time.strftime("%Y-%m-%d@%H:%M:%S", time.localtime(time.time()))
    if 0 < len(backup_filename):
        filename = "%s/%s" % (backup_path, backup_filename)
    else:
        filename = "%s/%s_config.%s" % (backup_path, module.params["host"], tstamp)
    try:
        open(filename, "w").write(running_config)
    except Exception:
        module.fail_json(
            msg="Can't create backup file {0} Permission denied ?".format(filename)
        )


class AnsibleFortios(object):
    def __init__(self, module):
        if not HAS_PYFG:
            module.fail_json(
                msg="Could not import the python library pyFG required by this module"
            )

        self.result = {
            "changed": False,
        }
        self.module = module

    def _connect(self):
        if self.module.params["file_mode"]:
            self.forti_device = FortiOS("")
        else:
            host = self.module.params["host"]
            username = self.module.params["username"]
            password = self.module.params["password"]
            timeout = self.module.params["timeout"]
            vdom = self.module.params["vdom"]

            self.forti_device = FortiOS(
                host, username=username, password=password, timeout=timeout, vdom=vdom
            )

            try:
                self.forti_device.open()
            except Exception as e:
                self.module.fail_json(
                    msg="Error connecting device. %s" % to_text(e),
                    exception=traceback.format_exc(),
                )

    def load_config(self, path):
        self.path = path
        self._connect()
        # load in file_mode
        if self.module.params["file_mode"]:
            try:
                f = open(self.module.params["config_file"], "r")
                running = f.read()
                f.close()
            except IOError as e:
                self.module.fail_json(
                    msg="Error reading configuration file. %s" % to_text(e),
                    exception=traceback.format_exc(),
                )
            self.forti_device.load_config(config_text=running, path=path)

        else:
            # get  config
            try:
                self.forti_device.load_config(path=path)
            except Exception as e:
                self.forti_device.close()
                self.module.fail_json(
                    msg="Error reading running config. %s" % to_text(e),
                    exception=traceback.format_exc(),
                )

        # set configs in object
        self.result["running_config"] = self.forti_device.running_config.to_text()
        self.candidate_config = self.forti_device.candidate_config

        # backup if needed
        if self.module.params["backup"]:
            backup(self.module, self.forti_device.running_config.to_text())

    def apply_changes(self):
        change_string = self.forti_device.compare_config()
        if change_string:
            self.result["change_string"] = change_string
            self.result["changed"] = True

        # Commit if not check mode
        if change_string and not self.module.check_mode:
            if self.module.params["file_mode"]:
                try:
                    f = open(self.module.params["config_file"], "w")
                    f.write(self.candidate_config.to_text())
                    f.close()
                except IOError as e:
                    self.module.fail_json(
                        msg="Error writing configuration file. %s" % to_text(e),
                        exception=traceback.format_exc(),
                    )
            else:
                try:
                    self.forti_device.commit()
                except FailedCommit as e:
                    # Something's wrong (rollback is automatic)
                    self.forti_device.close()
                    error_list = self.get_error_infos(e)
                    self.module.fail_json(
                        msg_error_list=error_list,
                        msg="Unable to commit change, check your args, the error was %s"
                        % e.message,
                    )

                self.forti_device.close()
        self.module.exit_json(**self.result)

    def del_block(self, block_id):
        self.forti_device.candidate_config[self.path].del_block(block_id)

    def add_block(self, block_id, block):
        self.forti_device.candidate_config[self.path][block_id] = block

    def get_error_infos(self, cli_errors):
        error_list = []
        for errors in cli_errors.args:
            for error in errors:
                error_code = error[0]
                error_string = error[1]
                error_type = fortios_error_codes.get(error_code, "unknown")
                error_list.append(
                    dict(
                        error_code=error_code,
                        error_type=error_type,
                        error_string=error_string,
                    )
                )

        return error_list

    def get_empty_configuration_block(self, block_name, block_type):
        return FortiConfig(block_name, block_type)


# END DEPRECATED
