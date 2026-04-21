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
module: fortios_system_central_management
short_description: Configure central management in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and central_management category.
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

    system_central_management:
        description:
            - Configure central management.
        default: null
        type: dict
        suboptions:
            allow_monitor:
                description:
                    - Enable/disable allowing the central management server to remotely monitor this FortiGate unit.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            allow_push_configuration:
                description:
                    - Enable/disable allowing the central management server to push configuration changes to this FortiGate.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            allow_push_firmware:
                description:
                    - Enable/disable allowing the central management server to push firmware updates to this FortiGate.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            allow_remote_firmware_upgrade:
                description:
                    - Enable/disable remotely upgrading the firmware on this FortiGate from the central management server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ca_cert:
                description:
                    - CA certificate to be used by FGFM protocol. Source certificate.ca.name.
                type: str
            enc_algorithm:
                description:
                    - Encryption strength for communications between the FortiGate and central management.
                type: str
                choices:
                    - 'default'
                    - 'high'
                    - 'low'
            fmg:
                description:
                    - IP address or FQDN of the FortiManager.
                type: str
            fmg_source_ip:
                description:
                    - IPv4 source address that this FortiGate uses when communicating with FortiManager.
                type: str
            fmg_source_ip6:
                description:
                    - IPv6 source address that this FortiGate uses when communicating with FortiManager.
                type: str
            fmg_update_http_header:
                description:
                    - Enable/disable inclusion of HTTP header in update request.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fmg_update_port:
                description:
                    - Port used to communicate with FortiManager that is acting as a FortiGuard update server.
                type: str
                choices:
                    - '8890'
                    - '443'
            fortigate_cloud_sso_default_profile:
                description:
                    - Override access profile. Source system.accprofile.name.
                type: str
            include_default_servers:
                description:
                    - Enable/disable inclusion of public FortiGuard servers in the override server list.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            interface:
                description:
                    - Specify outgoing interface to reach server. Source system.interface.name.
                type: str
            interface_select_method:
                description:
                    - Specify how to select outgoing interface to reach server.
                type: str
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            local_cert:
                description:
                    - Certificate to be used by FGFM protocol. Source certificate.local.name.
                type: str
            mode:
                description:
                    - Central management mode.
                type: str
                choices:
                    - 'normal'
                    - 'backup'
            schedule_config_restore:
                description:
                    - Enable/disable allowing the central management server to restore the configuration of this FortiGate.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            schedule_script_restore:
                description:
                    - Enable/disable allowing the central management server to restore the scripts stored on this FortiGate.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            serial_number:
                description:
                    - Serial number.
                type: str
            server_list:
                description:
                    - Additional severs that the FortiGate can use for updates (for AV, IPS, updates) and ratings (for web filter and antispam ratings)
                       servers.
                type: list
                elements: dict
                suboptions:
                    addr_type:
                        description:
                            - Indicate whether the FortiGate communicates with the override server using an IPv4 address, an IPv6 address or a FQDN.
                        type: str
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                            - 'fqdn'
                    fqdn:
                        description:
                            - FQDN address of override server.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    server_address:
                        description:
                            - IPv4 address of override server.
                        type: str
                    server_address6:
                        description:
                            - IPv6 address of override server.
                        type: str
                    server_type:
                        description:
                            - FortiGuard service type.
                        type: list
                        elements: str
                        choices:
                            - 'update'
                            - 'rating'
                            - 'vpatch-query'
                            - 'iot-collect'
                            - 'iot-query'
            type:
                description:
                    - Central management type.
                type: str
                choices:
                    - 'fortimanager'
                    - 'fortiguard'
                    - 'none'
            vdom:
                description:
                    - Virtual domain (VDOM) name to use when communicating with FortiManager. Source system.vdom.name.
                type: str
            vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
"""

EXAMPLES = """
- name: Configure central management.
  fortinet.fortios.fortios_system_central_management:
      vdom: "{{ vdom }}"
      system_central_management:
          allow_monitor: "enable"
          allow_push_configuration: "enable"
          allow_push_firmware: "enable"
          allow_remote_firmware_upgrade: "enable"
          ca_cert: "<your_own_value> (source certificate.ca.name)"
          enc_algorithm: "default"
          fmg: "<your_own_value>"
          fmg_source_ip: "<your_own_value>"
          fmg_source_ip6: "<your_own_value>"
          fmg_update_http_header: "enable"
          fmg_update_port: "8890"
          fortigate_cloud_sso_default_profile: "<your_own_value> (source system.accprofile.name)"
          include_default_servers: "enable"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          local_cert: "<your_own_value> (source certificate.local.name)"
          mode: "normal"
          schedule_config_restore: "enable"
          schedule_script_restore: "enable"
          serial_number: "<your_own_value>"
          server_list:
              -
                  addr_type: "ipv4"
                  fqdn: "<your_own_value>"
                  id: "26"
                  server_address: "<your_own_value>"
                  server_address6: "<your_own_value>"
                  server_type: "update"
          type: "fortimanager"
          vdom: "<your_own_value> (source system.vdom.name)"
          vrf_select: "0"
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


def filter_system_central_management_data(json):
    option_list = [
        "allow_monitor",
        "allow_push_configuration",
        "allow_push_firmware",
        "allow_remote_firmware_upgrade",
        "ca_cert",
        "enc_algorithm",
        "fmg",
        "fmg_source_ip",
        "fmg_source_ip6",
        "fmg_update_http_header",
        "fmg_update_port",
        "fortigate_cloud_sso_default_profile",
        "include_default_servers",
        "interface",
        "interface_select_method",
        "local_cert",
        "mode",
        "schedule_config_restore",
        "schedule_script_restore",
        "serial_number",
        "server_list",
        "type",
        "vdom",
        "vrf_select",
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
        ["server_list", "server_type"],
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


def system_central_management(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_central_management_data = data["system_central_management"]

    filtered_data = filter_system_central_management_data(
        system_central_management_data
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
        mkey = fos.get_mkey("system", "central-management", filtered_data, vdom=vdom)
        current_data = fos.get("system", "central-management", vdom=vdom, mkey=mkey)
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
    data_copy["system_central_management"] = filtered_data
    fos.do_member_operation(
        "system",
        "central-management",
        data_copy,
    )

    return fos.set("system", "central-management", data=converted_data, vdom=vdom)


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

    if data["system_central_management"]:
        resp = system_central_management(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("system_central_management")
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
    "v_range": [["v6.0.0", ""]],
    "type": "dict",
    "children": {
        "mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "normal"}, {"value": "backup"}],
        },
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "fortimanager"},
                {"value": "fortiguard"},
                {"value": "none"},
            ],
        },
        "fortigate_cloud_sso_default_profile": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
        },
        "schedule_config_restore": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "schedule_script_restore": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "allow_push_configuration": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "allow_push_firmware": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "allow_remote_firmware_upgrade": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "allow_monitor": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "serial_number": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "fmg": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "fmg_source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "fmg_source_ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "local_cert": {
            "v_range": [["v6.0.0", "v6.0.0"], ["v6.0.11", ""]],
            "type": "string",
        },
        "ca_cert": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "vdom": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "server_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "server_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "update"},
                        {"value": "rating"},
                        {"value": "vpatch-query", "v_range": [["v7.6.0", ""]]},
                        {"value": "iot-collect", "v_range": [["v7.2.1", ""]]},
                        {"value": "iot-query", "v_range": [["v7.2.1", "v7.4.4"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "addr_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ipv4"},
                        {"value": "ipv6"},
                        {"value": "fqdn"},
                    ],
                },
                "server_address": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "server_address6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "fqdn": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "fmg_update_port": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "8890"}, {"value": "443"}],
        },
        "fmg_update_http_header": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "include_default_servers": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "enc_algorithm": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "default"}, {"value": "high"}, {"value": "low"}],
        },
        "interface_select_method": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
        },
        "vrf_select": {"v_range": [["v7.6.1", ""]], "type": "integer"},
    },
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
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
        "system_central_management": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_central_management"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_central_management"]["options"][attribute_name][
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
            fos, versioned_schema, "system_central_management"
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
