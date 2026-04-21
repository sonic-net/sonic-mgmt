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
module: fortios_extension_controller_extender_vap
short_description: FortiExtender wifi vap configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify extension_controller feature and extender_vap category.
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
    extension_controller_extender_vap:
        description:
            - FortiExtender wifi vap configuration.
        default: null
        type: dict
        suboptions:
            allowaccess:
                description:
                    - Control management access to the managed extender. Separate entries with a space.
                type: list
                elements: str
                choices:
                    - 'ping'
                    - 'telnet'
                    - 'http'
                    - 'https'
                    - 'ssh'
                    - 'snmp'
            auth_server_address:
                description:
                    - Wi-Fi Authentication Server Address (IPv4 format).
                type: str
            auth_server_port:
                description:
                    - Wi-Fi Authentication Server Port.
                type: int
            auth_server_secret:
                description:
                    - Wi-Fi Authentication Server Secret.
                type: str
            broadcast_ssid:
                description:
                    - Wi-Fi broadcast SSID enable / disable.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            bss_color_partial:
                description:
                    - Wi-Fi 802.11AX bss color partial enable / disable, default = enable.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            dtim:
                description:
                    - Wi-Fi DTIM (1 - 255) default = 1.
                type: int
            end_ip:
                description:
                    - End ip address.
                type: str
            ip_address:
                description:
                    - Extender ip address.
                type: str
            max_clients:
                description:
                    - Wi-Fi max clients (0 - 512))
                type: int
            mu_mimo:
                description:
                    - Wi-Fi multi-user MIMO enable / disable, default = enable.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            name:
                description:
                    - Wi-Fi VAP name.
                required: true
                type: str
            passphrase:
                description:
                    - Wi-Fi passphrase.
                type: str
            pmf:
                description:
                    - Wi-Fi pmf enable/disable, default = disable.
                type: str
                choices:
                    - 'disabled'
                    - 'optional'
                    - 'required'
            rts_threshold:
                description:
                    - Wi-Fi RTS Threshold (256 - 2347)).
                type: int
            sae_password:
                description:
                    - Wi-Fi SAE Password.
                type: str
            security:
                description:
                    - Wi-Fi security.
                type: str
                choices:
                    - 'OPEN'
                    - 'WPA2-Personal'
                    - 'WPA-WPA2-Personal'
                    - 'WPA3-SAE'
                    - 'WPA3-SAE-Transition'
                    - 'WPA2-Enterprise'
                    - 'WPA3-Enterprise-only'
                    - 'WPA3-Enterprise-transition'
                    - 'WPA3-Enterprise-192-bit'
            ssid:
                description:
                    - Wi-Fi SSID.
                type: str
            start_ip:
                description:
                    - Start ip address.
                type: str
            target_wake_time:
                description:
                    - Wi-Fi 802.11AX target wake time enable / disable, default = enable.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            type:
                description:
                    - Wi-Fi VAP type local-vap / lan-extension-vap.
                type: str
                choices:
                    - 'local-vap'
                    - 'lan-ext-vap'
"""

EXAMPLES = """
- name: FortiExtender wifi vap configuration.
  fortinet.fortios.fortios_extension_controller_extender_vap:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      extension_controller_extender_vap:
          allowaccess: "ping"
          auth_server_address: "<your_own_value>"
          auth_server_port: "0"
          auth_server_secret: "<your_own_value>"
          broadcast_ssid: "disable"
          bss_color_partial: "disable"
          dtim: "1"
          end_ip: "<your_own_value>"
          ip_address: "<your_own_value>"
          max_clients: "0"
          mu_mimo: "disable"
          name: "default_name_14"
          passphrase: "<your_own_value>"
          pmf: "disabled"
          rts_threshold: "2347"
          sae_password: "<your_own_value>"
          security: "OPEN"
          ssid: "<your_own_value>"
          start_ip: "<your_own_value>"
          target_wake_time: "disable"
          type: "local-vap"
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


def filter_extension_controller_extender_vap_data(json):
    option_list = [
        "allowaccess",
        "auth_server_address",
        "auth_server_port",
        "auth_server_secret",
        "broadcast_ssid",
        "bss_color_partial",
        "dtim",
        "end_ip",
        "ip_address",
        "max_clients",
        "mu_mimo",
        "name",
        "passphrase",
        "pmf",
        "rts_threshold",
        "sae_password",
        "security",
        "ssid",
        "start_ip",
        "target_wake_time",
        "type",
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
        ["allowaccess"],
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


def extension_controller_extender_vap(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    extension_controller_extender_vap_data = data["extension_controller_extender_vap"]

    filtered_data = filter_extension_controller_extender_vap_data(
        extension_controller_extender_vap_data
    )
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey(
            "extension-controller", "extender-vap", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "extension-controller", "extender-vap", vdom=vdom, mkey=mkey
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
    data_copy["extension_controller_extender_vap"] = filtered_data
    fos.do_member_operation(
        "extension-controller",
        "extender-vap",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "extension-controller", "extender-vap", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "extension-controller",
            "extender-vap",
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


def fortios_extension_controller(data, fos, check_mode):

    if data["extension_controller_extender_vap"]:
        resp = extension_controller_extender_vap(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("extension_controller_extender_vap")
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
        "name": {"v_range": [["v7.4.4", ""]], "type": "string", "required": True},
        "type": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "local-vap"}, {"value": "lan-ext-vap"}],
        },
        "ssid": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "max_clients": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "broadcast_ssid": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "security": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [
                {"value": "OPEN"},
                {"value": "WPA2-Personal"},
                {"value": "WPA-WPA2-Personal"},
                {"value": "WPA3-SAE"},
                {"value": "WPA3-SAE-Transition"},
                {"value": "WPA2-Enterprise"},
                {"value": "WPA3-Enterprise-only"},
                {"value": "WPA3-Enterprise-transition"},
                {"value": "WPA3-Enterprise-192-bit"},
            ],
        },
        "dtim": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "rts_threshold": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "pmf": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [
                {"value": "disabled"},
                {"value": "optional"},
                {"value": "required"},
            ],
        },
        "target_wake_time": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "bss_color_partial": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "mu_mimo": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "passphrase": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "sae_password": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "auth_server_address": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "auth_server_port": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "auth_server_secret": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "ip_address": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "start_ip": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "end_ip": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "allowaccess": {
            "v_range": [["v7.4.4", ""]],
            "type": "list",
            "options": [
                {"value": "ping"},
                {"value": "telnet"},
                {"value": "http"},
                {"value": "https"},
                {"value": "ssh"},
                {"value": "snmp"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
    },
    "v_range": [["v7.4.4", ""]],
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
        "extension_controller_extender_vap": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["extension_controller_extender_vap"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["extension_controller_extender_vap"]["options"][attribute_name][
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
            fos, versioned_schema, "extension_controller_extender_vap"
        )

        is_error, has_changed, result, diff = fortios_extension_controller(
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
