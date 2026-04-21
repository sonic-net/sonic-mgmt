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
module: fortios_casb_user_activity
short_description: Configure CASB user activity in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify casb feature and user_activity category.
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
    casb_user_activity:
        description:
            - Configure CASB user activity.
        default: null
        type: dict
        suboptions:
            application:
                description:
                    - CASB SaaS application name. Source casb.saas-application.name.
                type: str
            casb_name:
                description:
                    - CASB user activity signature name.
                type: str
            category:
                description:
                    - CASB user activity category.
                type: str
                choices:
                    - 'activity-control'
                    - 'tenant-control'
                    - 'domain-control'
                    - 'safe-search-control'
                    - 'advanced-tenant-control'
                    - 'other'
            control_options:
                description:
                    - CASB control options.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - CASB control option name.
                        required: true
                        type: str
                    operations:
                        description:
                            - CASB control option operations.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                description:
                                    - CASB operation action.
                                type: str
                                choices:
                                    - 'append'
                                    - 'prepend'
                                    - 'replace'
                                    - 'new'
                                    - 'new-on-not-found'
                                    - 'delete'
                            case_sensitive:
                                description:
                                    - CASB operation search case sensitive.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            direction:
                                description:
                                    - CASB operation direction.
                                type: str
                                choices:
                                    - 'request'
                                    - 'response'
                            header_name:
                                description:
                                    - CASB operation header name to search.
                                type: str
                            name:
                                description:
                                    - CASB control option operation name.
                                required: true
                                type: str
                            search_key:
                                description:
                                    - CASB operation key to search.
                                type: str
                            search_pattern:
                                description:
                                    - CASB operation search pattern.
                                type: str
                                choices:
                                    - 'simple'
                                    - 'substr'
                                    - 'regexp'
                            target:
                                description:
                                    - CASB operation target.
                                type: str
                                choices:
                                    - 'header'
                                    - 'path'
                                    - 'body'
                            value_from_input:
                                description:
                                    - Enable/disable value from user input.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            value_name_from_input:
                                description:
                                    - CASB operation value name from user input.
                                type: str
                            values:
                                description:
                                    - CASB operation new values.
                                type: list
                                elements: dict
                                suboptions:
                                    value:
                                        description:
                                            - Operation value.
                                        required: true
                                        type: str
                    status:
                        description:
                            - CASB control option status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            description:
                description:
                    - CASB user activity description.
                type: str
            match:
                description:
                    - CASB user activity match rules.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - CASB user activity match rules ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    rules:
                        description:
                            - CASB user activity rules.
                        type: list
                        elements: dict
                        suboptions:
                            body_type:
                                description:
                                    - CASB user activity match rule body type.
                                type: str
                                choices:
                                    - 'json'
                            case_sensitive:
                                description:
                                    - CASB user activity match case sensitive.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            domains:
                                description:
                                    - CASB user activity domain list.
                                type: list
                                elements: dict
                                suboptions:
                                    domain:
                                        description:
                                            - Domain list separated by space.
                                        required: true
                                        type: str
                            header_name:
                                description:
                                    - CASB user activity rule header name.
                                type: str
                            id:
                                description:
                                    - CASB user activity rule ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            jq:
                                description:
                                    - CASB user activity rule match jq script.
                                type: str
                            match_pattern:
                                description:
                                    - CASB user activity rule match pattern.
                                type: str
                                choices:
                                    - 'simple'
                                    - 'substr'
                                    - 'regexp'
                            match_value:
                                description:
                                    - CASB user activity rule match value.
                                type: str
                            methods:
                                description:
                                    - CASB user activity method list.
                                type: list
                                elements: dict
                                suboptions:
                                    method:
                                        description:
                                            - User activity method.
                                        required: true
                                        type: str
                            negate:
                                description:
                                    - Enable/disable what the matching strategy must not be.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            type:
                                description:
                                    - CASB user activity rule type.
                                type: str
                                choices:
                                    - 'domains'
                                    - 'host'
                                    - 'path'
                                    - 'header'
                                    - 'header-value'
                                    - 'method'
                                    - 'body'
                    strategy:
                        description:
                            - CASB user activity rules strategy.
                        type: str
                        choices:
                            - 'and'
                            - 'or'
                    tenant_extraction:
                        description:
                            - CASB user activity tenant extraction.
                        type: dict
                        suboptions:
                            filters:
                                description:
                                    - CASB user activity tenant extraction filters.
                                type: list
                                elements: dict
                                suboptions:
                                    body_type:
                                        description:
                                            - CASB tenant extraction filter body type.
                                        type: str
                                        choices:
                                            - 'json'
                                    direction:
                                        description:
                                            - CASB tenant extraction filter direction.
                                        type: str
                                        choices:
                                            - 'request'
                                            - 'response'
                                    header_name:
                                        description:
                                            - CASB tenant extraction filter header name.
                                        type: str
                                    id:
                                        description:
                                            - CASB tenant extraction filter ID. see <a href='#notes'>Notes</a>.
                                        required: true
                                        type: int
                                    place:
                                        description:
                                            - CASB tenant extraction filter place type.
                                        type: str
                                        choices:
                                            - 'path'
                                            - 'header'
                                            - 'body'
                            jq:
                                description:
                                    - CASB user activity tenant extraction jq script.
                                type: str
                            status:
                                description:
                                    - Enable/disable CASB tenant extraction.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            type:
                                description:
                                    - CASB user activity tenant extraction type.
                                type: str
                                choices:
                                    - 'json-query'
            match_strategy:
                description:
                    - CASB user activity match strategy.
                type: str
                choices:
                    - 'and'
                    - 'or'
            name:
                description:
                    - CASB user activity name.
                required: true
                type: str
            status:
                description:
                    - CASB user activity status.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            type:
                description:
                    - CASB user activity type.
                type: str
                choices:
                    - 'built-in'
                    - 'customized'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
"""

EXAMPLES = """
- name: Configure CASB user activity.
  fortinet.fortios.fortios_casb_user_activity:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      casb_user_activity:
          application: "<your_own_value> (source casb.saas-application.name)"
          casb_name: "<your_own_value>"
          category: "activity-control"
          control_options:
              -
                  name: "default_name_7"
                  operations:
                      -
                          action: "append"
                          case_sensitive: "enable"
                          direction: "request"
                          header_name: "<your_own_value>"
                          name: "default_name_13"
                          search_key: "<your_own_value>"
                          search_pattern: "simple"
                          target: "header"
                          value_from_input: "enable"
                          value_name_from_input: "<your_own_value>"
                          values:
                              -
                                  value: "<your_own_value>"
                  status: "enable"
          description: "<your_own_value>"
          match:
              -
                  id: "24"
                  rules:
                      -
                          body_type: "json"
                          case_sensitive: "enable"
                          domains:
                              -
                                  domain: "<your_own_value>"
                          header_name: "<your_own_value>"
                          id: "31"
                          jq: "<your_own_value>"
                          match_pattern: "simple"
                          match_value: "<your_own_value>"
                          methods:
                              -
                                  method: "<your_own_value>"
                          negate: "enable"
                          type: "domains"
                  strategy: "and"
                  tenant_extraction:
                      filters:
                          -
                              body_type: "json"
                              direction: "request"
                              header_name: "<your_own_value>"
                              id: "45"
                              place: "path"
                      jq: "<your_own_value>"
                      status: "disable"
                      type: "json-query"
          match_strategy: "and"
          name: "default_name_51"
          status: "enable"
          type: "built-in"
          uuid: "<your_own_value>"
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


def filter_casb_user_activity_data(json):
    option_list = [
        "application",
        "casb_name",
        "category",
        "control_options",
        "description",
        "match",
        "match_strategy",
        "name",
        "status",
        "type",
        "uuid",
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


def casb_user_activity(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    casb_user_activity_data = data["casb_user_activity"]

    filtered_data = filter_casb_user_activity_data(casb_user_activity_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("casb", "user-activity", filtered_data, vdom=vdom)
        current_data = fos.get("casb", "user-activity", vdom=vdom, mkey=mkey)
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
    data_copy["casb_user_activity"] = filtered_data
    fos.do_member_operation(
        "casb",
        "user-activity",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("casb", "user-activity", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "casb", "user-activity", mkey=converted_data["name"], vdom=vdom
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


def fortios_casb(data, fos, check_mode):

    if data["casb_user_activity"]:
        resp = casb_user_activity(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("casb_user_activity"))
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
        "name": {"v_range": [["v7.4.1", ""]], "type": "string", "required": True},
        "uuid": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "status": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "description": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "type": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "built-in"}, {"value": "customized"}],
        },
        "casb_name": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "application": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "category": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [
                {"value": "activity-control"},
                {"value": "tenant-control"},
                {"value": "domain-control"},
                {"value": "safe-search-control"},
                {"value": "advanced-tenant-control", "v_range": [["v7.6.4", ""]]},
                {"value": "other"},
            ],
        },
        "match_strategy": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "and"}, {"value": "or"}],
        },
        "match": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "integer",
                    "required": True,
                },
                "strategy": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [{"value": "and"}, {"value": "or"}],
                },
                "rules": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "type": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "domains"},
                                {"value": "host"},
                                {"value": "path"},
                                {"value": "header"},
                                {"value": "header-value"},
                                {"value": "method"},
                                {"value": "body", "v_range": [["v7.6.1", ""]]},
                            ],
                        },
                        "domains": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "domain": {
                                    "v_range": [["v7.4.1", ""]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v7.4.1", ""]],
                        },
                        "methods": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "method": {
                                    "v_range": [["v7.4.1", ""]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v7.4.1", ""]],
                        },
                        "match_pattern": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "simple"},
                                {"value": "substr"},
                                {"value": "regexp"},
                            ],
                        },
                        "match_value": {"v_range": [["v7.4.1", ""]], "type": "string"},
                        "header_name": {"v_range": [["v7.4.1", ""]], "type": "string"},
                        "body_type": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "string",
                            "options": [{"value": "json"}],
                        },
                        "jq": {"v_range": [["v7.6.1", ""]], "type": "string"},
                        "case_sensitive": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "negate": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                    },
                    "v_range": [["v7.4.1", ""]],
                },
                "tenant_extraction": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "type": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "string",
                            "options": [{"value": "json-query"}],
                        },
                        "jq": {"v_range": [["v7.6.1", ""]], "type": "string"},
                        "filters": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "id": {
                                    "v_range": [["v7.6.1", ""]],
                                    "type": "integer",
                                    "required": True,
                                },
                                "direction": {
                                    "v_range": [["v7.6.1", ""]],
                                    "type": "string",
                                    "options": [
                                        {"value": "request"},
                                        {"value": "response"},
                                    ],
                                },
                                "place": {
                                    "v_range": [["v7.6.1", ""]],
                                    "type": "string",
                                    "options": [
                                        {"value": "path"},
                                        {"value": "header"},
                                        {"value": "body"},
                                    ],
                                },
                                "header_name": {
                                    "v_range": [["v7.6.1", ""]],
                                    "type": "string",
                                },
                                "body_type": {
                                    "v_range": [["v7.6.1", ""]],
                                    "type": "string",
                                    "options": [{"value": "json"}],
                                },
                            },
                            "v_range": [["v7.6.1", ""]],
                        },
                    },
                },
            },
            "v_range": [["v7.4.1", ""]],
        },
        "control_options": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "required": True,
                },
                "status": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "operations": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "target": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "header"},
                                {"value": "path"},
                                {"value": "body", "v_range": [["v7.6.1", ""]]},
                            ],
                        },
                        "action": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "append"},
                                {"value": "prepend"},
                                {"value": "replace"},
                                {"value": "new"},
                                {"value": "new-on-not-found"},
                                {"value": "delete"},
                            ],
                        },
                        "direction": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "request"},
                                {"value": "response", "v_range": [["v7.6.1", ""]]},
                            ],
                        },
                        "header_name": {"v_range": [["v7.4.1", ""]], "type": "string"},
                        "search_pattern": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "simple"},
                                {"value": "substr"},
                                {"value": "regexp"},
                            ],
                        },
                        "search_key": {"v_range": [["v7.4.1", ""]], "type": "string"},
                        "case_sensitive": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "value_from_input": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "value_name_from_input": {
                            "v_range": [["v7.6.4", ""]],
                            "type": "string",
                        },
                        "values": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "value": {
                                    "v_range": [["v7.4.1", ""]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v7.4.1", ""]],
                        },
                    },
                    "v_range": [["v7.4.1", ""]],
                },
            },
            "v_range": [["v7.4.1", ""]],
        },
    },
    "v_range": [["v7.4.1", ""]],
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
        "casb_user_activity": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["casb_user_activity"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["casb_user_activity"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "casb_user_activity"
        )

        is_error, has_changed, result, diff = fortios_casb(
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
