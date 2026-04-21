#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_web_proxy_profile
short_description: Configure web proxy profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify web_proxy feature and profile category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

    - The module supports check_mode.

requirements:
    - ansible>=2.15
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    web_proxy_profile:
        description:
            - Configure web proxy profiles.
        default: null
        type: dict
        suboptions:
            header_client_ip:
                description:
                    - 'Action to take on the HTTP client-IP header in forwarded requests: forwards (pass), adds, or removes the HTTP header.'
                type: str
                choices:
                    - 'pass'
                    - 'add'
                    - 'remove'
            header_front_end_https:
                description:
                    - 'Action to take on the HTTP front-end-HTTPS header in forwarded requests: forwards (pass), adds, or removes the HTTP header.'
                type: str
                choices:
                    - 'pass'
                    - 'add'
                    - 'remove'
            header_via_request:
                description:
                    - 'Action to take on the HTTP via header in forwarded requests: forwards (pass), adds, or removes the HTTP header.'
                type: str
                choices:
                    - 'pass'
                    - 'add'
                    - 'remove'
            header_via_response:
                description:
                    - 'Action to take on the HTTP via header in forwarded responses: forwards (pass), adds, or removes the HTTP header.'
                type: str
                choices:
                    - 'pass'
                    - 'add'
                    - 'remove'
            header_x_authenticated_groups:
                description:
                    - 'Action to take on the HTTP x-authenticated-groups header in forwarded requests: forwards (pass), adds, or removes the HTTP header.'
                type: str
                choices:
                    - 'pass'
                    - 'add'
                    - 'remove'
            header_x_authenticated_user:
                description:
                    - 'Action to take on the HTTP x-authenticated-user header in forwarded requests: forwards (pass), adds, or removes the HTTP header.'
                type: str
                choices:
                    - 'pass'
                    - 'add'
                    - 'remove'
            header_x_forwarded_client_cert:
                description:
                    - 'Action to take on the HTTP x-forwarded-client-cert header in forwarded requests: forwards (pass), adds, or removes the HTTP header.'
                type: str
                choices:
                    - 'pass'
                    - 'add'
                    - 'remove'
            header_x_forwarded_for:
                description:
                    - 'Action to take on the HTTP x-forwarded-for header in forwarded requests: forwards (pass), adds, or removes the HTTP header.'
                type: str
                choices:
                    - 'pass'
                    - 'add'
                    - 'remove'
            headers:
                description:
                    - Configure HTTP forwarded requests headers.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Configure adding, removing, or logging of the HTTP header entry in HTTP requests and responses.
                        type: str
                        choices:
                            - 'add-to-request'
                            - 'add-to-response'
                            - 'remove-from-request'
                            - 'remove-from-response'
                            - 'monitor-request'
                            - 'monitor-response'
                    add_option:
                        description:
                            - Configure options to append content to existing HTTP header or add new HTTP header.
                        type: str
                        choices:
                            - 'append'
                            - 'new-on-not-found'
                            - 'new'
                            - 'replace'
                            - 'replace-when-match'
                    base64_encoding:
                        description:
                            - Enable/disable use of base64 encoding of HTTP content.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    content:
                        description:
                            - 'HTTP header content (max length: 3999 characters).'
                        type: str
                    dstaddr:
                        description:
                            - Destination address and address group names.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address name. Source firewall.address.name firewall.addrgrp.name.
                                required: true
                                type: str
                    dstaddr6:
                        description:
                            - Destination address and address group names (IPv6).
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                                required: true
                                type: str
                    id:
                        description:
                            - HTTP forwarded header id. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    name:
                        description:
                            - HTTP forwarded header name.
                        type: str
                    protocol:
                        description:
                            - Configure protocol(s) to take add-option action on (HTTP, HTTPS, or both).
                        type: list
                        elements: str
                        choices:
                            - 'https'
                            - 'http'
            log_header_change:
                description:
                    - Enable/disable logging HTTP header changes.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            strip_encoding:
                description:
                    - Enable/disable stripping unsupported encoding from the request header.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure web proxy profiles.
  fortinet.fortios.fortios_web_proxy_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      web_proxy_profile:
          header_client_ip: "pass"
          header_front_end_https: "pass"
          header_via_request: "pass"
          header_via_response: "pass"
          header_x_authenticated_groups: "pass"
          header_x_authenticated_user: "pass"
          header_x_forwarded_client_cert: "pass"
          header_x_forwarded_for: "pass"
          headers:
              -
                  action: "add-to-request"
                  add_option: "append"
                  base64_encoding: "disable"
                  content: "<your_own_value>"
                  dstaddr:
                      -
                          name: "default_name_17 (source firewall.address.name firewall.addrgrp.name)"
                  dstaddr6:
                      -
                          name: "default_name_19 (source firewall.address6.name firewall.addrgrp6.name)"
                  id: "20"
                  name: "default_name_21"
                  protocol: "https"
          log_header_change: "enable"
          name: "default_name_24"
          strip_encoding: "enable"
"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    find_current_values,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    unify_data_format,
)


def filter_web_proxy_profile_data(json):
    option_list = [
        "header_client_ip",
        "header_front_end_https",
        "header_via_request",
        "header_via_response",
        "header_x_authenticated_groups",
        "header_x_authenticated_user",
        "header_x_forwarded_client_cert",
        "header_x_forwarded_for",
        "headers",
        "log_header_change",
        "name",
        "strip_encoding",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or (not data[path[index]] and not isinstance(data[path[index]], list))
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
        if len(data[path[index]]) == 0:
            data[path[index]] = None
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["headers", "protocol"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def web_proxy_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    web_proxy_profile_data = data["web_proxy_profile"]

    filtered_data = filter_web_proxy_profile_data(web_proxy_profile_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("web-proxy", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("web-proxy", "profile", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and (
                mkeyname
                and isinstance(current_data.get("results"), list)
                and len(current_data["results"]) > 0
                or not mkeyname
                and current_data["results"]  # global object response
            )
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)
            unified_filtered_data = unify_data_format(copied_filtered_data)

            current_data_results = current_data.get("results", {})
            current_config = (
                current_data_results[0]
                if mkeyname
                and isinstance(current_data_results, list)
                and len(current_data_results) > 0
                else current_data_results
            )
            if is_existed:
                unified_current_values = find_current_values(
                    unified_filtered_data,
                    unify_data_format(current_config),
                )

                is_same = is_same_comparison(
                    serialize(unified_current_values), serialize(unified_filtered_data)
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": unified_current_values, "after": unified_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}
    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["web_proxy_profile"] = filtered_data
    fos.do_member_operation(
        "web-proxy",
        "profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("web-proxy", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "web-proxy", "profile", mkey=converted_data["name"], vdom=vdom
        )
    else:
        fos._module.fail_json(msg="state must be present or absent!")


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_web_proxy(data, fos, check_mode):

    if data["web_proxy_profile"]:
        resp = web_proxy_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("web_proxy_profile"))
    if isinstance(resp, tuple) and len(resp) == 4:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "header_client_ip": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "pass"}, {"value": "add"}, {"value": "remove"}],
        },
        "header_via_request": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "pass"}, {"value": "add"}, {"value": "remove"}],
        },
        "header_via_response": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "pass"}, {"value": "add"}, {"value": "remove"}],
        },
        "header_x_forwarded_for": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "pass"}, {"value": "add"}, {"value": "remove"}],
        },
        "header_x_forwarded_client_cert": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "pass"}, {"value": "add"}, {"value": "remove"}],
        },
        "header_front_end_https": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "pass"}, {"value": "add"}, {"value": "remove"}],
        },
        "header_x_authenticated_user": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "pass"}, {"value": "add"}, {"value": "remove"}],
        },
        "header_x_authenticated_groups": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "pass"}, {"value": "add"}, {"value": "remove"}],
        },
        "strip_encoding": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log_header_change": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "headers": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "name": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "dstaddr": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.2.0", ""]],
                },
                "dstaddr6": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.2.0", ""]],
                },
                "action": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "add-to-request"},
                        {"value": "add-to-response"},
                        {"value": "remove-from-request"},
                        {"value": "remove-from-response"},
                        {"value": "monitor-request", "v_range": [["v7.4.0", ""]]},
                        {"value": "monitor-response", "v_range": [["v7.4.0", ""]]},
                    ],
                },
                "content": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "base64_encoding": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "add_option": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "append"},
                        {"value": "new-on-not-found"},
                        {"value": "new"},
                        {"value": "replace", "v_range": [["v7.6.1", ""]]},
                        {"value": "replace-when-match", "v_range": [["v7.6.1", ""]]},
                    ],
                },
                "protocol": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [{"value": "https"}, {"value": "http"}],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "web_proxy_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["web_proxy_profile"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["web_proxy_profile"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "web_proxy_profile"
        )

        is_error, has_changed, result, diff = fortios_web_proxy(
            module.params, fos, module.check_mode
        )

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
