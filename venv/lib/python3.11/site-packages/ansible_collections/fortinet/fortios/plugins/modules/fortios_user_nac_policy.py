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
module: fortios_user_nac_policy
short_description: Configure NAC policy matching pattern to identify matching NAC devices in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify user feature and nac_policy category.
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
    user_nac_policy:
        description:
            - Configure NAC policy matching pattern to identify matching NAC devices.
        default: null
        type: dict
        suboptions:
            category:
                description:
                    - Category of NAC policy.
                type: str
                choices:
                    - 'device'
                    - 'firewall-user'
                    - 'ems-tag'
                    - 'fortivoice-tag'
                    - 'vulnerability'
            description:
                description:
                    - Description for the NAC policy matching pattern.
                type: str
            ems_tag:
                description:
                    - NAC policy matching EMS tag. Source firewall.address.name.
                type: str
            family:
                description:
                    - NAC policy matching family.
                type: str
            firewall_address:
                description:
                    - Dynamic firewall address to associate MAC which match this policy. Source firewall.address.name.
                type: str
            fortivoice_tag:
                description:
                    - NAC policy matching FortiVoice tag. Source firewall.address.name.
                type: str
            host:
                description:
                    - NAC policy matching host.
                type: str
            hw_vendor:
                description:
                    - NAC policy matching hardware vendor.
                type: str
            hw_version:
                description:
                    - NAC policy matching hardware version.
                type: str
            mac:
                description:
                    - NAC policy matching MAC address.
                type: str
            match_period:
                description:
                    - Number of days the matched devices will be retained (0 - always retain)
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
                    - NAC policy name.
                required: true
                type: str
            os:
                description:
                    - NAC policy matching operating system.
                type: str
            severity:
                description:
                    - NAC policy matching devices vulnerability severity lists.
                type: list
                elements: dict
                suboptions:
                    severity_num:
                        description:
                            - Enter multiple severity levels, where 0 = Info, 1 = Low, ..., 4 = Critical see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            src:
                description:
                    - NAC policy matching source.
                type: str
            ssid_policy:
                description:
                    - SSID policy to be applied on the matched NAC policy. Source wireless-controller.ssid-policy.name.
                type: str
            status:
                description:
                    - Enable/disable NAC policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sw_version:
                description:
                    - NAC policy matching software version.
                type: str
            switch_auto_auth:
                description:
                    - NAC device auto authorization when discovered and nac-policy matched.
                type: str
                choices:
                    - 'global'
                    - 'disable'
                    - 'enable'
            switch_fortilink:
                description:
                    - FortiLink interface for which this NAC policy belongs to. Source system.interface.name.
                type: str
            switch_group:
                description:
                    - List of managed FortiSwitch groups on which NAC policy can be applied.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Managed FortiSwitch group name from available options. Source switch-controller.switch-group.name.
                        required: true
                        type: str
            switch_mac_policy:
                description:
                    - Switch MAC policy action to be applied on the matched NAC policy. Source switch-controller.mac-policy.name.
                type: str
            switch_port_policy:
                description:
                    - switch-port-policy to be applied on the matched NAC policy. Source switch-controller.port-policy.name.
                type: str
            switch_scope:
                description:
                    - List of managed FortiSwitches on which NAC policy can be applied.
                type: list
                elements: dict
                suboptions:
                    switch_id:
                        description:
                            - Managed FortiSwitch name from available options. Source switch-controller.managed-switch.switch-id.
                        required: true
                        type: str
            type:
                description:
                    - NAC policy matching type.
                type: str
            user:
                description:
                    - NAC policy matching user.
                type: str
            user_group:
                description:
                    - NAC policy matching user group. Source user.group.name.
                type: str
"""

EXAMPLES = """
- name: Configure NAC policy matching pattern to identify matching NAC devices.
  fortinet.fortios.fortios_user_nac_policy:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      user_nac_policy:
          category: "device"
          description: "<your_own_value>"
          ems_tag: "<your_own_value> (source firewall.address.name)"
          family: "<your_own_value>"
          firewall_address: "<your_own_value> (source firewall.address.name)"
          fortivoice_tag: "<your_own_value> (source firewall.address.name)"
          host: "myhostname"
          hw_vendor: "<your_own_value>"
          hw_version: "<your_own_value>"
          mac: "<your_own_value>"
          match_period: "0"
          match_remove: "default"
          match_type: "dynamic"
          name: "default_name_16"
          os: "<your_own_value>"
          severity:
              -
                  severity_num: "<you_own_value>"
          src: "<your_own_value>"
          ssid_policy: "<your_own_value> (source wireless-controller.ssid-policy.name)"
          status: "enable"
          sw_version: "<your_own_value>"
          switch_auto_auth: "global"
          switch_fortilink: "<your_own_value> (source system.interface.name)"
          switch_group:
              -
                  name: "default_name_27 (source switch-controller.switch-group.name)"
          switch_mac_policy: "<your_own_value> (source switch-controller.mac-policy.name)"
          switch_port_policy: "<your_own_value> (source switch-controller.port-policy.name)"
          switch_scope:
              -
                  switch_id: "<your_own_value> (source switch-controller.managed-switch.switch-id)"
          type: "<your_own_value>"
          user: "<your_own_value>"
          user_group: "<your_own_value> (source user.group.name)"
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


def filter_user_nac_policy_data(json):
    option_list = [
        "category",
        "description",
        "ems_tag",
        "family",
        "firewall_address",
        "fortivoice_tag",
        "host",
        "hw_vendor",
        "hw_version",
        "mac",
        "match_period",
        "match_remove",
        "match_type",
        "name",
        "os",
        "severity",
        "src",
        "ssid_policy",
        "status",
        "sw_version",
        "switch_auto_auth",
        "switch_fortilink",
        "switch_group",
        "switch_mac_policy",
        "switch_port_policy",
        "switch_scope",
        "type",
        "user",
        "user_group",
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


def user_nac_policy(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    user_nac_policy_data = data["user_nac_policy"]

    filtered_data = filter_user_nac_policy_data(user_nac_policy_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("user", "nac-policy", filtered_data, vdom=vdom)
        current_data = fos.get("user", "nac-policy", vdom=vdom, mkey=mkey)
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
    data_copy["user_nac_policy"] = filtered_data
    fos.do_member_operation(
        "user",
        "nac-policy",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("user", "nac-policy", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("user", "nac-policy", mkey=converted_data["name"], vdom=vdom)
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


def fortios_user(data, fos, check_mode):

    if data["user_nac_policy"]:
        resp = user_nac_policy(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("user_nac_policy"))
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
        "name": {"v_range": [["v6.4.0", ""]], "type": "string", "required": True},
        "description": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "category": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [
                {"value": "device"},
                {"value": "firewall-user"},
                {"value": "ems-tag", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "fortivoice-tag", "v_range": [["v7.4.4", ""]]},
                {"value": "vulnerability", "v_range": [["v7.4.0", ""]]},
            ],
        },
        "status": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "mac": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "hw_vendor": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "type": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "family": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "os": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "hw_version": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "sw_version": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "host": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "user": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "src": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "user_group": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "ems_tag": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "fortivoice_tag": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "severity": {
            "type": "list",
            "elements": "dict",
            "children": {
                "severity_num": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v7.4.0", ""]],
        },
        "switch_fortilink": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "switch_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.2", ""]],
        },
        "switch_mac_policy": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "firewall_address": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "ssid_policy": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "switch_scope": {
            "type": "list",
            "elements": "dict",
            "children": {
                "switch_id": {
                    "v_range": [["v6.4.0", "v7.0.1"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.4.0", "v7.0.1"]],
        },
        "switch_auto_auth": {
            "v_range": [["v6.4.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "global"}, {"value": "disable"}, {"value": "enable"}],
        },
        "switch_port_policy": {"v_range": [["v6.4.0", "v6.4.4"]], "type": "string"},
    },
    "v_range": [["v6.4.0", ""]],
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
        "user_nac_policy": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["user_nac_policy"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["user_nac_policy"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "user_nac_policy"
        )

        is_error, has_changed, result, diff = fortios_user(
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
