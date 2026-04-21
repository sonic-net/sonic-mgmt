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
module: fortios_pfcp_message_filter
short_description: Message filter for PFCP messages in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify pfcp feature and message_filter category.
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
    pfcp_message_filter:
        description:
            - Message filter for PFCP messages.
        default: null
        type: dict
        suboptions:
            association_release:
                description:
                    - Allow or deny PFCP association release request (9) and PFCP association release response (10).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            association_setup:
                description:
                    - Allow or deny PFCP association setup request (5) and PFCP association setup response (6).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            association_update:
                description:
                    - Allow or deny PFCP association update request (7) and PFCP association update response (8).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            heartbeat:
                description:
                    - Allow or deny PFCP heartbeat request (1) and PFCP heartbeat response (2).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            name:
                description:
                    - Message filter name.
                required: true
                type: str
            node_report:
                description:
                    - Allow or deny PFCP node report request (12) and PFCP node report response (13).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            pfd_management:
                description:
                    - Allow or deny PFCP PFD management request (3) and PFCP PFD management response (4).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            session_deletion:
                description:
                    - Allow or deny PFCP session deletion request (54) and PFCP session deletion response (55).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            session_establish:
                description:
                    - Allow or deny PFCP session establishment request (50) and PFCP session establishment response (51).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            session_modification:
                description:
                    - Allow or deny PFCP session modification request (52) and PFCP session modification response (53).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            session_report:
                description:
                    - Allow or deny PFCP session report request (56) and PFCP session report response (57).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            session_set_deletion:
                description:
                    - Allow or deny PFCP session set deletion request (14) and PFCP session set deletion response (15).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            unknown_message:
                description:
                    - Allow or deny unknown messages.
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            unknown_message_allow_list:
                description:
                    - Allow list of unknown messages.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Message IDs (range from 1 to 255). see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            version_not_support:
                description:
                    - Allow or deny PFCP version not supported response (11).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
"""

EXAMPLES = """
- name: Message filter for PFCP messages.
  fortinet.fortios.fortios_pfcp_message_filter:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      pfcp_message_filter:
          association_release: "allow"
          association_setup: "allow"
          association_update: "allow"
          heartbeat: "allow"
          name: "default_name_7"
          node_report: "allow"
          pfd_management: "allow"
          session_deletion: "allow"
          session_establish: "allow"
          session_modification: "allow"
          session_report: "allow"
          session_set_deletion: "allow"
          unknown_message: "allow"
          unknown_message_allow_list:
              -
                  id: "17"
          version_not_support: "allow"
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


def filter_pfcp_message_filter_data(json):
    option_list = [
        "association_release",
        "association_setup",
        "association_update",
        "heartbeat",
        "name",
        "node_report",
        "pfd_management",
        "session_deletion",
        "session_establish",
        "session_modification",
        "session_report",
        "session_set_deletion",
        "unknown_message",
        "unknown_message_allow_list",
        "version_not_support",
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


def pfcp_message_filter(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    pfcp_message_filter_data = data["pfcp_message_filter"]

    filtered_data = filter_pfcp_message_filter_data(pfcp_message_filter_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("pfcp", "message-filter", filtered_data, vdom=vdom)
        current_data = fos.get("pfcp", "message-filter", vdom=vdom, mkey=mkey)
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
    data_copy["pfcp_message_filter"] = filtered_data
    fos.do_member_operation(
        "pfcp",
        "message-filter",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("pfcp", "message-filter", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "pfcp", "message-filter", mkey=converted_data["name"], vdom=vdom
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


def fortios_pfcp(data, fos, check_mode):

    if data["pfcp_message_filter"]:
        resp = pfcp_message_filter(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("pfcp_message_filter"))
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
        "name": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "required": True,
        },
        "unknown_message": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "unknown_message_allow_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [
                        ["v7.0.1", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
        },
        "heartbeat": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "pfd_management": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "version_not_support": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "session_establish": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "session_modification": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "session_deletion": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "session_report": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "association_setup": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "association_update": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "association_release": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "node_report": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "session_set_deletion": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
    },
    "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
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
        "pfcp_message_filter": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["pfcp_message_filter"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["pfcp_message_filter"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "pfcp_message_filter"
        )

        is_error, has_changed, result, diff = fortios_pfcp(
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
