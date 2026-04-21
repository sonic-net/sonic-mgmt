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
module: fortios_system_speed_test_schedule
short_description: Speed test schedule for each interface in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and speed_test_schedule category.
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
    system_speed_test_schedule:
        description:
            - Speed test schedule for each interface.
        default: null
        type: dict
        suboptions:
            ctrl_port:
                description:
                    - Port of the controller to get access token.
                type: int
            diffserv:
                description:
                    - DSCP used for speed test.
                type: str
            dynamic_server:
                description:
                    - Enable/disable dynamic server option.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            interface:
                description:
                    - Interface name. Source system.interface.name.
                required: true
                type: str
            mode:
                description:
                    - Protocol Auto(default), TCP or UDP used for speed test.
                type: str
                choices:
                    - 'UDP'
                    - 'TCP'
                    - 'Auto'
            schedules:
                description:
                    - Schedules for the interface.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Name of a firewall recurring schedule. Source firewall.schedule.recurring.name.
                        required: true
                        type: str
            server_name:
                description:
                    - Speed test server name.
                type: str
            server_port:
                description:
                    - Port of the server to run speed test.
                type: int
            status:
                description:
                    - Enable/disable scheduled speed test.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            update_inbandwidth:
                description:
                    - Enable/disable bypassing interface"s inbound bandwidth setting.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            update_inbandwidth_maximum:
                description:
                    - Maximum downloading bandwidth (kbps) to be used in a speed test.
                type: int
            update_inbandwidth_minimum:
                description:
                    - Minimum downloading bandwidth (kbps) to be considered effective.
                type: int
            update_outbandwidth:
                description:
                    - Enable/disable bypassing interface"s outbound bandwidth setting.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            update_outbandwidth_maximum:
                description:
                    - Maximum uploading bandwidth (kbps) to be used in a speed test.
                type: int
            update_outbandwidth_minimum:
                description:
                    - Minimum uploading bandwidth (kbps) to be considered effective.
                type: int
            update_shaper:
                description:
                    - Set egress shaper based on the test result.
                type: str
                choices:
                    - 'disable'
                    - 'local'
                    - 'remote'
                    - 'both'
"""

EXAMPLES = """
- name: Speed test schedule for each interface.
  fortinet.fortios.fortios_system_speed_test_schedule:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_speed_test_schedule:
          ctrl_port: "5200"
          diffserv: "<your_own_value>"
          dynamic_server: "disable"
          interface: "<your_own_value> (source system.interface.name)"
          mode: "UDP"
          schedules:
              -
                  name: "default_name_9 (source firewall.schedule.recurring.name)"
          server_name: "<your_own_value>"
          server_port: "5201"
          status: "disable"
          update_inbandwidth: "disable"
          update_inbandwidth_maximum: "0"
          update_inbandwidth_minimum: "0"
          update_outbandwidth: "disable"
          update_outbandwidth_maximum: "0"
          update_outbandwidth_minimum: "0"
          update_shaper: "disable"
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


def filter_system_speed_test_schedule_data(json):
    option_list = [
        "ctrl_port",
        "diffserv",
        "dynamic_server",
        "interface",
        "mode",
        "schedules",
        "server_name",
        "server_port",
        "status",
        "update_inbandwidth",
        "update_inbandwidth_maximum",
        "update_inbandwidth_minimum",
        "update_outbandwidth",
        "update_outbandwidth_maximum",
        "update_outbandwidth_minimum",
        "update_shaper",
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


def system_speed_test_schedule(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_speed_test_schedule_data = data["system_speed_test_schedule"]

    filtered_data = filter_system_speed_test_schedule_data(
        system_speed_test_schedule_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "speed-test-schedule", filtered_data, vdom=vdom)
        current_data = fos.get("system", "speed-test-schedule", vdom=vdom, mkey=mkey)
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
    data_copy["system_speed_test_schedule"] = filtered_data
    fos.do_member_operation(
        "system",
        "speed-test-schedule",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "speed-test-schedule", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system", "speed-test-schedule", mkey=converted_data["interface"], vdom=vdom
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


def fortios_system(data, fos, check_mode):

    if data["system_speed_test_schedule"]:
        resp = system_speed_test_schedule(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("system_speed_test_schedule")
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
        "interface": {"v_range": [["v7.0.0", ""]], "type": "string", "required": True},
        "status": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "diffserv": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "server_name": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "mode": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "UDP"}, {"value": "TCP"}, {"value": "Auto"}],
        },
        "schedules": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.0", ""]],
        },
        "dynamic_server": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ctrl_port": {"v_range": [["v7.4.2", ""]], "type": "integer"},
        "server_port": {"v_range": [["v7.4.2", ""]], "type": "integer"},
        "update_shaper": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "local"},
                {"value": "remote"},
                {"value": "both"},
            ],
        },
        "update_inbandwidth": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "update_outbandwidth": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "update_inbandwidth_maximum": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "update_inbandwidth_minimum": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "update_outbandwidth_maximum": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "update_outbandwidth_minimum": {"v_range": [["v7.0.0", ""]], "type": "integer"},
    },
    "v_range": [["v7.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "interface"
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
        "system_speed_test_schedule": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_speed_test_schedule"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_speed_test_schedule"]["options"][attribute_name][
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
            fos, versioned_schema, "system_speed_test_schedule"
        )

        is_error, has_changed, result, diff = fortios_system(
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
