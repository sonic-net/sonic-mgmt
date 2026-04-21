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
module: fortios_wanopt_content_delivery_network_rule
short_description: Configure WAN optimization content delivery network rules in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wanopt feature and content_delivery_network_rule category.
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
    wanopt_content_delivery_network_rule:
        description:
            - Configure WAN optimization content delivery network rules.
        default: null
        type: dict
        suboptions:
            category:
                description:
                    - Content delivery network rule category.
                type: str
                choices:
                    - 'vcache'
                    - 'youtube'
            comment:
                description:
                    - Comment about this CDN-rule.
                type: str
            host_domain_name_suffix:
                description:
                    - Suffix portion of the fully qualified domain name. For example, fortinet.com in "www.fortinet.com".
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Suffix portion of the fully qualified domain name.
                        required: true
                        type: str
            name:
                description:
                    - Name of table.
                required: true
                type: str
            request_cache_control:
                description:
                    - Enable/disable HTTP request cache control.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            response_cache_control:
                description:
                    - Enable/disable HTTP response cache control.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            response_expires:
                description:
                    - Enable/disable HTTP response cache expires.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rules:
                description:
                    - WAN optimization content delivery network rule entries.
                type: list
                elements: dict
                suboptions:
                    content_id:
                        description:
                            - Content ID settings.
                        type: dict
                        suboptions:
                            end_direction:
                                description:
                                    - Search direction from end-str match.
                                type: str
                                choices:
                                    - 'forward'
                                    - 'backward'
                            end_skip:
                                description:
                                    - Number of characters in URL to skip after end-str has been matched.
                                type: int
                            end_str:
                                description:
                                    - String from which to end search.
                                type: str
                            range_str:
                                description:
                                    - Name of content ID within the start string and end string.
                                type: str
                            start_direction:
                                description:
                                    - Search direction from start-str match.
                                type: str
                                choices:
                                    - 'forward'
                                    - 'backward'
                            start_skip:
                                description:
                                    - Number of characters in URL to skip after start-str has been matched.
                                type: int
                            start_str:
                                description:
                                    - String from which to start search.
                                type: str
                            target:
                                description:
                                    - Option in HTTP header or URL parameter to match.
                                type: str
                                choices:
                                    - 'path'
                                    - 'parameter'
                                    - 'referrer'
                                    - 'youtube-map'
                                    - 'youtube-id'
                                    - 'youku-id'
                                    - 'hls-manifest'
                                    - 'dash-manifest'
                                    - 'hls-fragment'
                                    - 'dash-fragment'
                    match_entries:
                        description:
                            - List of entries to match.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Rule ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            pattern:
                                description:
                                    - Pattern string for matching target (Referrer or URL pattern). For example, a, a*c, *a*, a*c*e, and *.
                                type: list
                                elements: dict
                                suboptions:
                                    string:
                                        description:
                                            - Pattern strings.
                                        required: true
                                        type: str
                            target:
                                description:
                                    - Option in HTTP header or URL parameter to match.
                                type: str
                                choices:
                                    - 'path'
                                    - 'parameter'
                                    - 'referrer'
                                    - 'youtube-map'
                                    - 'youtube-id'
                                    - 'youku-id'
                    match_mode:
                        description:
                            - Match criteria for collecting content ID.
                        type: str
                        choices:
                            - 'all'
                            - 'any'
                    name:
                        description:
                            - WAN optimization content delivery network rule name.
                        required: true
                        type: str
                    skip_entries:
                        description:
                            - List of entries to skip.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Rule ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            pattern:
                                description:
                                    - Pattern string for matching target (Referrer or URL pattern). For example, a, a*c, *a*, a*c*e, and *.
                                type: list
                                elements: dict
                                suboptions:
                                    string:
                                        description:
                                            - Pattern strings.
                                        required: true
                                        type: str
                            target:
                                description:
                                    - Option in HTTP header or URL parameter to match.
                                type: str
                                choices:
                                    - 'path'
                                    - 'parameter'
                                    - 'referrer'
                                    - 'youtube-map'
                                    - 'youtube-id'
                                    - 'youku-id'
                    skip_rule_mode:
                        description:
                            - Skip mode when evaluating skip-rules.
                        type: str
                        choices:
                            - 'all'
                            - 'any'
            status:
                description:
                    - Enable/disable WAN optimization content delivery network rules.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            text_response_vcache:
                description:
                    - Enable/disable caching of text responses.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            updateserver:
                description:
                    - Enable/disable update server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure WAN optimization content delivery network rules.
  fortinet.fortios.fortios_wanopt_content_delivery_network_rule:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wanopt_content_delivery_network_rule:
          category: "vcache"
          comment: "Comment about this CDN-rule."
          host_domain_name_suffix:
              -
                  name: "default_name_6"
          name: "default_name_7"
          request_cache_control: "enable"
          response_cache_control: "enable"
          response_expires: "enable"
          rules:
              -
                  content_id:
                      end_direction: "forward"
                      end_skip: "0"
                      end_str: "<your_own_value>"
                      range_str: "<your_own_value>"
                      start_direction: "forward"
                      start_skip: "0"
                      start_str: "<your_own_value>"
                      target: "path"
                  match_entries:
                      -
                          id: "22"
                          pattern:
                              -
                                  string: "<your_own_value>"
                          target: "path"
                  match_mode: "all"
                  name: "default_name_27"
                  skip_entries:
                      -
                          id: "29"
                          pattern:
                              -
                                  string: "<your_own_value>"
                          target: "path"
                  skip_rule_mode: "all"
          status: "enable"
          text_response_vcache: "enable"
          updateserver: "enable"
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


def filter_wanopt_content_delivery_network_rule_data(json):
    option_list = [
        "category",
        "comment",
        "host_domain_name_suffix",
        "name",
        "request_cache_control",
        "response_cache_control",
        "response_expires",
        "rules",
        "status",
        "text_response_vcache",
        "updateserver",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


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


def wanopt_content_delivery_network_rule(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    wanopt_content_delivery_network_rule_data = data[
        "wanopt_content_delivery_network_rule"
    ]

    filtered_data = filter_wanopt_content_delivery_network_rule_data(
        wanopt_content_delivery_network_rule_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey(
            "wanopt", "content-delivery-network-rule", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "wanopt", "content-delivery-network-rule", vdom=vdom, mkey=mkey
        )
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
    data_copy["wanopt_content_delivery_network_rule"] = filtered_data
    fos.do_member_operation(
        "wanopt",
        "content-delivery-network-rule",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "wanopt", "content-delivery-network-rule", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "wanopt",
            "content-delivery-network-rule",
            mkey=converted_data["name"],
            vdom=vdom,
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


def fortios_wanopt(data, fos, check_mode):

    if data["wanopt_content_delivery_network_rule"]:
        resp = wanopt_content_delivery_network_rule(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("wanopt_content_delivery_network_rule")
        )
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
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "host_domain_name_suffix": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "category": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "vcache"}, {"value": "youtube"}],
        },
        "request_cache_control": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "response_cache_control": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "response_expires": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "updateserver": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rules": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "match_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "all"}, {"value": "any"}],
                },
                "skip_rule_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "all"}, {"value": "any"}],
                },
                "match_entries": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "target": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "path"},
                                {"value": "parameter"},
                                {"value": "referrer"},
                                {"value": "youtube-map"},
                                {"value": "youtube-id"},
                                {"value": "youku-id"},
                            ],
                        },
                        "pattern": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "string": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v6.0.0", ""]],
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "skip_entries": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "target": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "path"},
                                {"value": "parameter"},
                                {"value": "referrer"},
                                {"value": "youtube-map"},
                                {"value": "youtube-id"},
                                {"value": "youku-id"},
                            ],
                        },
                        "pattern": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "string": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v6.0.0", ""]],
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "content_id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "target": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "path"},
                                {"value": "parameter"},
                                {"value": "referrer"},
                                {"value": "youtube-map"},
                                {"value": "youtube-id"},
                                {"value": "youku-id"},
                                {"value": "hls-manifest"},
                                {"value": "dash-manifest"},
                                {"value": "hls-fragment"},
                                {"value": "dash-fragment"},
                            ],
                        },
                        "start_str": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "start_skip": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "start_direction": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "forward"}, {"value": "backward"}],
                        },
                        "end_str": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "end_skip": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "end_direction": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "forward"}, {"value": "backward"}],
                        },
                        "range_str": {"v_range": [["v6.0.0", ""]], "type": "string"},
                    },
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "text_response_vcache": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "wanopt_content_delivery_network_rule": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wanopt_content_delivery_network_rule"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["wanopt_content_delivery_network_rule"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "wanopt_content_delivery_network_rule"
        )

        is_error, has_changed, result, diff = fortios_wanopt(
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
