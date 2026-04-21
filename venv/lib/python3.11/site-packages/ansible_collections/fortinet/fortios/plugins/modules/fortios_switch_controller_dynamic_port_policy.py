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
module: fortios_switch_controller_dynamic_port_policy
short_description: Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify switch_controller feature and dynamic_port_policy category.
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
    switch_controller_dynamic_port_policy:
        description:
            - Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device.
        default: null
        type: dict
        suboptions:
            description:
                description:
                    - Description for the Dynamic port policy.
                type: str
            fortilink:
                description:
                    - FortiLink interface for which this Dynamic port policy belongs to. Source system.interface.name.
                type: str
            name:
                description:
                    - Dynamic port policy name.
                required: true
                type: str
            policy:
                description:
                    - Port policies with matching criteria and actions.
                type: list
                elements: dict
                suboptions:
                    set_802_1x:
                        description:
                            - 802.1x security policy to be applied when using this policy. Source switch-controller.security-policy.802-1X.name
                               switch-controller.security-policy.captive-portal.name.
                        type: str
                    bounce_port_duration:
                        description:
                            - Bounce duration in seconds of a switch port where this policy is applied.
                        type: int
                    bounce_port_link:
                        description:
                            - Enable/disable bouncing (administratively bring the link down, up) of a switch port where this policy is applied. Helps to clear
                               and reassign VLAN from lldp-profile.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    category:
                        description:
                            - Category of Dynamic port policy.
                        type: str
                        choices:
                            - 'device'
                            - 'interface-tag'
                    description:
                        description:
                            - Description for the policy.
                        type: str
                    family:
                        description:
                            - Match policy based on family.
                        type: str
                    host:
                        description:
                            - Match policy based on host.
                        type: str
                    hw_vendor:
                        description:
                            - Match policy based on hardware vendor.
                        type: str
                    interface_tags:
                        description:
                            - Match policy based on the FortiSwitch interface object tags.
                        type: list
                        elements: dict
                        suboptions:
                            tag_name:
                                description:
                                    - FortiSwitch port tag name. Source switch-controller.switch-interface-tag.name.
                                required: true
                                type: str
                    lldp_profile:
                        description:
                            - LLDP profile to be applied when using this policy. Source switch-controller.lldp-profile.name.
                        type: str
                    mac:
                        description:
                            - Match policy based on MAC address.
                        type: str
                    match_period:
                        description:
                            - Number of days the matched devices will be retained (0 - 120, 0 = always retain).
                        type: int
                    match_remove:
                        description:
                            - Options to remove the matched override devices.
                        type: str
                        choices:
                            - 'default'
                            - 'link-down'
                    match_type:
                        description:
                            - Match and retain the devices based on the type.
                        type: str
                        choices:
                            - 'dynamic'
                            - 'override'
                    name:
                        description:
                            - Policy name.
                        required: true
                        type: str
                    poe_reset:
                        description:
                            - Enable/disable POE reset of a switch port where this policy is applied.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    qos_policy:
                        description:
                            - QoS policy to be applied when using this policy. Source switch-controller.qos.qos-policy.name.
                        type: str
                    status:
                        description:
                            - Enable/disable policy.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    type:
                        description:
                            - Match policy based on type.
                        type: str
                    vlan_policy:
                        description:
                            - VLAN policy to be applied when using this policy. Source switch-controller.vlan-policy.name.
                        type: str
"""

EXAMPLES = """
- name: Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device.
  fortinet.fortios.fortios_switch_controller_dynamic_port_policy:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      switch_controller_dynamic_port_policy:
          description: "<your_own_value>"
          fortilink: "<your_own_value> (source system.interface.name)"
          name: "default_name_5"
          policy:
              -
                  set_802_1x: "<your_own_value> (source switch-controller.security-policy.802-1X.name switch-controller.security-policy.captive-portal.name)"
                  bounce_port_duration: "5"
                  bounce_port_link: "disable"
                  category: "device"
                  description: "<your_own_value>"
                  family: "<your_own_value>"
                  host: "myhostname"
                  hw_vendor: "<your_own_value>"
                  interface_tags:
                      -
                          tag_name: "<your_own_value> (source switch-controller.switch-interface-tag.name)"
                  lldp_profile: "<your_own_value> (source switch-controller.lldp-profile.name)"
                  mac: "<your_own_value>"
                  match_period: "0"
                  match_remove: "default"
                  match_type: "dynamic"
                  name: "default_name_22"
                  poe_reset: "disable"
                  qos_policy: "<your_own_value> (source switch-controller.qos.qos-policy.name)"
                  status: "enable"
                  type: "<your_own_value>"
                  vlan_policy: "<your_own_value> (source switch-controller.vlan-policy.name)"
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


def filter_switch_controller_dynamic_port_policy_data(json):
    option_list = ["description", "fortilink", "name", "policy"]

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


def valid_attr_to_invalid_attr(data):
    speciallist = {"802_1x": "set_802_1x"}

    for k, v in speciallist.items():
        if v == data:
            return k

    return data


def valid_attr_to_invalid_attrs(data):
    if isinstance(data, list):
        new_data = []
        for elem in data:
            elem = valid_attr_to_invalid_attrs(elem)
            new_data.append(elem)
        data = new_data
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[valid_attr_to_invalid_attr(k)] = valid_attr_to_invalid_attrs(v)
        data = new_data

    return valid_attr_to_invalid_attr(data)


def switch_controller_dynamic_port_policy(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    switch_controller_dynamic_port_policy_data = data[
        "switch_controller_dynamic_port_policy"
    ]

    filtered_data = filter_switch_controller_dynamic_port_policy_data(
        switch_controller_dynamic_port_policy_data
    )
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey(
            "switch-controller", "dynamic-port-policy", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "switch-controller", "dynamic-port-policy", vdom=vdom, mkey=mkey
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
    data_copy["switch_controller_dynamic_port_policy"] = filtered_data
    fos.do_member_operation(
        "switch-controller",
        "dynamic-port-policy",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "switch-controller", "dynamic-port-policy", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "switch-controller",
            "dynamic-port-policy",
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


def fortios_switch_controller(data, fos, check_mode):

    if data["switch_controller_dynamic_port_policy"]:
        resp = switch_controller_dynamic_port_policy(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("switch_controller_dynamic_port_policy")
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
        "name": {"v_range": [["v7.0.0", ""]], "type": "string", "required": True},
        "description": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "fortilink": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "policy": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "description": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "category": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "device"}, {"value": "interface-tag"}],
                },
                "match_type": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "dynamic"}, {"value": "override"}],
                },
                "match_period": {"v_range": [["v7.4.4", ""]], "type": "integer"},
                "match_remove": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "options": [{"value": "default"}, {"value": "link-down"}],
                },
                "interface_tags": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "tag_name": {
                            "v_range": [["v7.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.0.0", ""]],
                },
                "mac": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "hw_vendor": {"v_range": [["v7.0.4", ""]], "type": "string"},
                "type": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "family": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "host": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "lldp_profile": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "qos_policy": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "vlan_policy": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "bounce_port_link": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "bounce_port_duration": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "integer",
                },
                "poe_reset": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "set_802_1x": {"v_range": [["v7.0.0", ""]], "type": "string"},
            },
            "v_range": [["v7.0.0", ""]],
        },
    },
    "v_range": [["v7.0.0", ""]],
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
        "switch_controller_dynamic_port_policy": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["switch_controller_dynamic_port_policy"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["switch_controller_dynamic_port_policy"]["options"][attribute_name][
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
            fos, versioned_schema, "switch_controller_dynamic_port_policy"
        )

        is_error, has_changed, result, diff = fortios_switch_controller(
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
