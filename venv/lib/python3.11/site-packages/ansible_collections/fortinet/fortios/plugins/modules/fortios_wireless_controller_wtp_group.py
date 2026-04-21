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
module: fortios_wireless_controller_wtp_group
short_description: Configure WTP groups in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and wtp_group category.
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
    wireless_controller_wtp_group:
        description:
            - Configure WTP groups.
        default: null
        type: dict
        suboptions:
            ble_major_id:
                description:
                    - Override BLE Major ID.
                type: int
            name:
                description:
                    - WTP group name.
                required: true
                type: str
            platform_type:
                description:
                    - FortiAP models to define the WTP group platform type.
                type: str
                choices:
                    - 'AP-11N'
                    - 'C24JE'
                    - '421E'
                    - '423E'
                    - '221E'
                    - '222E'
                    - '223E'
                    - '224E'
                    - '231E'
                    - '321E'
                    - '431F'
                    - '431FL'
                    - '432F'
                    - '432FR'
                    - '433F'
                    - '433FL'
                    - '231F'
                    - '231FL'
                    - '234F'
                    - '23JF'
                    - '831F'
                    - '231G'
                    - '233G'
                    - '234G'
                    - '431G'
                    - '432G'
                    - '433G'
                    - '231K'
                    - '23JK'
                    - '222KL'
                    - '241K'
                    - '243K'
                    - '244K'
                    - '441K'
                    - '443K'
                    - 'U421E'
                    - 'U422EV'
                    - 'U423E'
                    - 'U221EV'
                    - 'U223EV'
                    - 'U24JEV'
                    - 'U321EV'
                    - 'U323EV'
                    - 'U431F'
                    - 'U433F'
                    - 'U231F'
                    - 'U234F'
                    - 'U432F'
                    - 'U231G'
                    - '220B'
                    - '210B'
                    - '222B'
                    - '112B'
                    - '320B'
                    - '11C'
                    - '14C'
                    - '223B'
                    - '28C'
                    - '320C'
                    - '221C'
                    - '25D'
                    - '222C'
                    - '224D'
                    - '214B'
                    - '21D'
                    - '24D'
                    - '112D'
                    - '223C'
                    - '321C'
                    - 'C220C'
                    - 'C225C'
                    - 'C23JD'
                    - 'S321C'
                    - 'S322C'
                    - 'S323C'
                    - 'S311C'
                    - 'S313C'
                    - 'S321CR'
                    - 'S322CR'
                    - 'S323CR'
                    - 'S421E'
                    - 'S422E'
                    - 'S423E'
                    - 'S221E'
                    - 'S223E'
                    - 'U441G'
            wtps:
                description:
                    - WTP list.
                type: list
                elements: dict
                suboptions:
                    wtp_id:
                        description:
                            - WTP ID. Source wireless-controller.wtp.wtp-id.
                        required: true
                        type: str
"""

EXAMPLES = """
- name: Configure WTP groups.
  fortinet.fortios.fortios_wireless_controller_wtp_group:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wireless_controller_wtp_group:
          ble_major_id: "0"
          name: "default_name_4"
          platform_type: "AP-11N"
          wtps:
              -
                  wtp_id: "<your_own_value> (source wireless-controller.wtp.wtp-id)"
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


def filter_wireless_controller_wtp_group_data(json):
    option_list = ["ble_major_id", "name", "platform_type", "wtps"]

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


def wireless_controller_wtp_group(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    wireless_controller_wtp_group_data = data["wireless_controller_wtp_group"]

    filtered_data = filter_wireless_controller_wtp_group_data(
        wireless_controller_wtp_group_data
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
            "wireless-controller", "wtp-group", filtered_data, vdom=vdom
        )
        current_data = fos.get("wireless-controller", "wtp-group", vdom=vdom, mkey=mkey)
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
    data_copy["wireless_controller_wtp_group"] = filtered_data
    fos.do_member_operation(
        "wireless-controller",
        "wtp-group",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "wireless-controller", "wtp-group", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "wireless-controller", "wtp-group", mkey=converted_data["name"], vdom=vdom
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


def fortios_wireless_controller(data, fos, check_mode):

    if data["wireless_controller_wtp_group"]:
        resp = wireless_controller_wtp_group(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("wireless_controller_wtp_group")
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
        "platform_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "AP-11N"},
                {"value": "C24JE"},
                {"value": "421E"},
                {"value": "423E"},
                {"value": "221E"},
                {"value": "222E"},
                {"value": "223E"},
                {"value": "224E"},
                {"value": "231E", "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]]},
                {"value": "321E", "v_range": [["v6.2.0", ""]]},
                {"value": "431F", "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]]},
                {"value": "431FL", "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]]},
                {
                    "value": "432F",
                    "v_range": [
                        ["v6.2.0", "v6.2.0"],
                        ["v6.2.5", "v6.4.0"],
                        ["v6.4.4", ""],
                    ],
                },
                {"value": "432FR", "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]]},
                {"value": "433F", "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]]},
                {"value": "433FL", "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]]},
                {
                    "value": "231F",
                    "v_range": [
                        ["v6.2.0", "v6.2.0"],
                        ["v6.2.5", "v6.4.0"],
                        ["v6.4.4", ""],
                    ],
                },
                {"value": "231FL", "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]]},
                {
                    "value": "234F",
                    "v_range": [
                        ["v6.2.0", "v6.2.0"],
                        ["v6.2.5", "v6.4.0"],
                        ["v6.4.4", ""],
                    ],
                },
                {
                    "value": "23JF",
                    "v_range": [
                        ["v6.2.0", "v6.2.0"],
                        ["v6.2.5", "v6.4.0"],
                        ["v6.4.4", ""],
                    ],
                },
                {"value": "831F", "v_range": [["v6.4.4", ""]]},
                {"value": "231G", "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]]},
                {"value": "233G", "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]]},
                {"value": "234G", "v_range": [["v7.4.0", ""]]},
                {"value": "431G", "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]]},
                {"value": "432G", "v_range": [["v7.4.2", ""]]},
                {"value": "433G", "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]]},
                {"value": "231K", "v_range": [["v7.6.1", ""]]},
                {"value": "23JK", "v_range": [["v7.6.1", ""]]},
                {"value": "222KL", "v_range": [["v7.6.4", ""]]},
                {"value": "241K", "v_range": [["v7.4.2", ""]]},
                {"value": "243K", "v_range": [["v7.4.2", ""]]},
                {"value": "244K", "v_range": [["v7.6.4", ""]]},
                {"value": "441K", "v_range": [["v7.4.2", ""]]},
                {"value": "443K", "v_range": [["v7.4.2", ""]]},
                {"value": "U421E"},
                {"value": "U422EV"},
                {"value": "U423E"},
                {"value": "U221EV"},
                {"value": "U223EV"},
                {"value": "U24JEV"},
                {"value": "U321EV"},
                {"value": "U323EV"},
                {"value": "U431F", "v_range": [["v6.2.0", ""]]},
                {"value": "U433F", "v_range": [["v6.2.0", ""]]},
                {"value": "U231F", "v_range": [["v6.4.4", ""]]},
                {"value": "U234F", "v_range": [["v6.4.4", ""]]},
                {"value": "U432F", "v_range": [["v6.4.4", ""]]},
                {"value": "U231G", "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]]},
                {"value": "220B", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "210B", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "222B", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "112B", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "320B", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "11C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "14C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "223B", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "28C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "320C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "221C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "25D", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "222C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "224D", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "214B", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "21D", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "24D", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "112D", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "223C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "321C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "C220C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "C225C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "C23JD", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "S321C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "S322C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "S323C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "S311C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "S313C", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "S321CR", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "S322CR", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "S323CR", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "S421E", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "S422E", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "S423E", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "S221E", "v_range": [["v6.0.0", "v7.2.4"]]},
                {"value": "S223E", "v_range": [["v6.0.0", "v7.2.4"]]},
                {
                    "value": "U441G",
                    "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", "v7.2.4"]],
                },
            ],
        },
        "ble_major_id": {"v_range": [["v7.4.1", ""]], "type": "integer"},
        "wtps": {
            "type": "list",
            "elements": "dict",
            "children": {
                "wtp_id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
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
        "wireless_controller_wtp_group": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_wtp_group"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_wtp_group"]["options"][attribute_name][
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
            fos, versioned_schema, "wireless_controller_wtp_group"
        )

        is_error, has_changed, result, diff = fortios_wireless_controller(
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
