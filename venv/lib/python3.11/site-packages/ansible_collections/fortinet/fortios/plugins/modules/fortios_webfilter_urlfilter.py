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
module: fortios_webfilter_urlfilter
short_description: Configure URL filter lists in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify webfilter feature and urlfilter category.
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
    - We highly recommend using your own value as the id instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
       available number for the object, it does have limitations. Please find more details in Q&A.
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
    webfilter_urlfilter:
        description:
            - Configure URL filter lists.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Optional comments.
                type: str
            entries:
                description:
                    - URL filter entries.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action to take for URL filter matches.
                        type: str
                        choices:
                            - 'exempt'
                            - 'block'
                            - 'allow'
                            - 'monitor'
                    antiphish_action:
                        description:
                            - Action to take for AntiPhishing matches.
                        type: str
                        choices:
                            - 'block'
                            - 'log'
                    comment:
                        description:
                            - Comment.
                        type: str
                    dns_address_family:
                        description:
                            - Resolve IPv4 address, IPv6 address, or both from DNS server.
                        type: str
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                            - 'both'
                    exempt:
                        description:
                            - If action is set to exempt, select the security profile operations that exempt URLs skip. Separate multiple options with a space.
                        type: list
                        elements: str
                        choices:
                            - 'av'
                            - 'web-content'
                            - 'activex-java-cookie'
                            - 'dlp'
                            - 'fortiguard'
                            - 'range-block'
                            - 'pass'
                            - 'antiphish'
                            - 'all'
                    id:
                        description:
                            - Id. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    referrer_host:
                        description:
                            - Referrer host name.
                        type: str
                    status:
                        description:
                            - Enable/disable this URL filter.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    type:
                        description:
                            - Filter type (simple, regex, or wildcard).
                        type: str
                        choices:
                            - 'simple'
                            - 'regex'
                            - 'wildcard'
                    url:
                        description:
                            - URL to be filtered.
                        type: str
                    web_proxy_profile:
                        description:
                            - Web proxy profile. Source web-proxy.profile.name.
                        type: str
            id:
                description:
                    - ID. see <a href='#notes'>Notes</a>.
                required: true
                type: int
            include_subdomains:
                description:
                    - Enable/disable matching subdomains. Applies only to simple type .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ip_addr_block:
                description:
                    - Enable/disable blocking URLs when the hostname appears as an IP address.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ip4_mapped_ip6:
                description:
                    - Enable/disable matching of IPv4 mapped IPv6 URLs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Name of URL filter list.
                type: str
            one_arm_ips_urlfilter:
                description:
                    - Enable/disable DNS resolver for one-arm IPS URL filter operation.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure URL filter lists.
  fortinet.fortios.fortios_webfilter_urlfilter:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      webfilter_urlfilter:
          comment: "Optional comments."
          entries:
              -
                  action: "exempt"
                  antiphish_action: "block"
                  comment: "Comment."
                  dns_address_family: "ipv4"
                  exempt: "av"
                  id: "10"
                  referrer_host: "myhostname"
                  status: "enable"
                  type: "simple"
                  url: "myurl.com"
                  web_proxy_profile: "<your_own_value> (source web-proxy.profile.name)"
          id: "16"
          include_subdomains: "enable"
          ip_addr_block: "enable"
          ip4_mapped_ip6: "enable"
          name: "default_name_20"
          one_arm_ips_urlfilter: "enable"
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


def filter_webfilter_urlfilter_data(json):
    option_list = [
        "comment",
        "entries",
        "id",
        "include_subdomains",
        "ip_addr_block",
        "ip4_mapped_ip6",
        "name",
        "one_arm_ips_urlfilter",
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
        ["entries", "exempt"],
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


def webfilter_urlfilter(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    webfilter_urlfilter_data = data["webfilter_urlfilter"]

    filtered_data = filter_webfilter_urlfilter_data(webfilter_urlfilter_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("webfilter", "urlfilter", filtered_data, vdom=vdom)
        current_data = fos.get("webfilter", "urlfilter", vdom=vdom, mkey=mkey)
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
    data_copy["webfilter_urlfilter"] = filtered_data
    fos.do_member_operation(
        "webfilter",
        "urlfilter",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("webfilter", "urlfilter", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "webfilter", "urlfilter", mkey=converted_data["id"], vdom=vdom
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


def fortios_webfilter(data, fos, check_mode):

    if data["webfilter_urlfilter"]:
        resp = webfilter_urlfilter(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("webfilter_urlfilter"))
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
        "id": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "one_arm_ips_urlfilter": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ip_addr_block": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ip4_mapped_ip6": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "include_subdomains": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "entries": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "url": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "simple"},
                        {"value": "regex"},
                        {"value": "wildcard"},
                    ],
                },
                "action": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "exempt"},
                        {"value": "block"},
                        {"value": "allow"},
                        {"value": "monitor"},
                    ],
                },
                "antiphish_action": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "block"}, {"value": "log"}],
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "exempt": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "av"},
                        {"value": "web-content"},
                        {"value": "activex-java-cookie"},
                        {"value": "dlp"},
                        {"value": "fortiguard"},
                        {"value": "range-block"},
                        {"value": "pass"},
                        {"value": "antiphish", "v_range": [["v6.4.0", ""]]},
                        {"value": "all"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "web_proxy_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "referrer_host": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "dns_address_family": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ipv4"},
                        {"value": "ipv6"},
                        {"value": "both"},
                    ],
                },
                "comment": {"v_range": [["v7.6.4", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "id"
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
        "webfilter_urlfilter": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["webfilter_urlfilter"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["webfilter_urlfilter"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "webfilter_urlfilter"
        )

        is_error, has_changed, result, diff = fortios_webfilter(
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
