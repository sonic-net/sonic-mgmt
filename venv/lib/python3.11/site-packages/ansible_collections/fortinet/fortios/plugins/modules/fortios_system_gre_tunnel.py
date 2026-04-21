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
module: fortios_system_gre_tunnel
short_description: Configure GRE tunnel in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and gre_tunnel category.
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
    system_gre_tunnel:
        description:
            - Configure GRE tunnel.
        default: null
        type: dict
        suboptions:
            auto_asic_offload:
                description:
                    - Enable/disable automatic ASIC offloading.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            checksum_reception:
                description:
                    - Enable/disable validating checksums in received GRE packets.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            checksum_transmission:
                description:
                    - Enable/disable including checksums in transmitted GRE packets.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode:
                description:
                    - DiffServ setting to be applied to GRE tunnel outer IP header.
                type: str
            dscp_copying:
                description:
                    - Enable/disable DSCP copying.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            interface:
                description:
                    - Interface name. Source system.interface.name.
                type: str
            ip_version:
                description:
                    - IP version to use for VPN interface.
                type: str
                choices:
                    - '4'
                    - '6'
            keepalive_failtimes:
                description:
                    - Number of consecutive unreturned keepalive messages before a GRE connection is considered down (1 - 255).
                type: int
            keepalive_interval:
                description:
                    - Keepalive message interval (0 - 32767, 0 = disabled).
                type: int
            key_inbound:
                description:
                    - Require received GRE packets contain this key (0 - 4294967295).
                type: int
            key_outbound:
                description:
                    - Include this key in transmitted GRE packets (0 - 4294967295).
                type: int
            local_gw:
                description:
                    - IP address of the local gateway.
                type: str
            local_gw6:
                description:
                    - IPv6 address of the local gateway.
                type: str
            name:
                description:
                    - Tunnel name.
                required: true
                type: str
            remote_gw:
                description:
                    - IP address of the remote gateway.
                type: str
            remote_gw6:
                description:
                    - IPv6 address of the remote gateway.
                type: str
            sequence_number_reception:
                description:
                    - Enable/disable validating sequence numbers in received GRE packets.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            sequence_number_transmission:
                description:
                    - Enable/disable including of sequence numbers in transmitted GRE packets.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            use_sdwan:
                description:
                    - Enable/disable use of SD-WAN to reach remote gateway.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
"""

EXAMPLES = """
- name: Configure GRE tunnel.
  fortinet.fortios.fortios_system_gre_tunnel:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_gre_tunnel:
          auto_asic_offload: "enable"
          checksum_reception: "disable"
          checksum_transmission: "disable"
          diffservcode: "<your_own_value>"
          dscp_copying: "disable"
          interface: "<your_own_value> (source system.interface.name)"
          ip_version: "4"
          keepalive_failtimes: "10"
          keepalive_interval: "0"
          key_inbound: "0"
          key_outbound: "0"
          local_gw: "<your_own_value>"
          local_gw6: "<your_own_value>"
          name: "default_name_16"
          remote_gw: "<your_own_value>"
          remote_gw6: "<your_own_value>"
          sequence_number_reception: "disable"
          sequence_number_transmission: "disable"
          use_sdwan: "disable"
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


def filter_system_gre_tunnel_data(json):
    option_list = [
        "auto_asic_offload",
        "checksum_reception",
        "checksum_transmission",
        "diffservcode",
        "dscp_copying",
        "interface",
        "ip_version",
        "keepalive_failtimes",
        "keepalive_interval",
        "key_inbound",
        "key_outbound",
        "local_gw",
        "local_gw6",
        "name",
        "remote_gw",
        "remote_gw6",
        "sequence_number_reception",
        "sequence_number_transmission",
        "use_sdwan",
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


def system_gre_tunnel(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_gre_tunnel_data = data["system_gre_tunnel"]

    filtered_data = filter_system_gre_tunnel_data(system_gre_tunnel_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "gre-tunnel", filtered_data, vdom=vdom)
        current_data = fos.get("system", "gre-tunnel", vdom=vdom, mkey=mkey)
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
    data_copy["system_gre_tunnel"] = filtered_data
    fos.do_member_operation(
        "system",
        "gre-tunnel",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "gre-tunnel", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system", "gre-tunnel", mkey=converted_data["name"], vdom=vdom
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

    if data["system_gre_tunnel"]:
        resp = system_gre_tunnel(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_gre_tunnel"))
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
        "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip_version": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "4"}, {"value": "6"}],
        },
        "remote_gw6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "local_gw6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "remote_gw": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "local_gw": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "use_sdwan": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "sequence_number_transmission": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v7.2.0", "v7.2.0"], ["v7.4.0", ""]],
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.0.0", "v7.2.2"],
                        ["v7.4.0", ""],
                    ],
                },
                {
                    "value": "enable",
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.0.0", "v7.2.2"],
                        ["v7.4.0", ""],
                    ],
                },
            ],
        },
        "sequence_number_reception": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v7.2.0", "v7.2.0"], ["v7.4.0", ""]],
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.0.0", "v7.2.2"],
                        ["v7.4.0", ""],
                    ],
                },
                {
                    "value": "enable",
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.0.0", "v7.2.2"],
                        ["v7.4.0", ""],
                    ],
                },
            ],
        },
        "checksum_transmission": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v7.2.0", "v7.2.0"], ["v7.4.0", ""]],
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.0.0", "v7.2.2"],
                        ["v7.4.0", ""],
                    ],
                },
                {
                    "value": "enable",
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.0.0", "v7.2.2"],
                        ["v7.4.0", ""],
                    ],
                },
            ],
        },
        "checksum_reception": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v7.2.0", "v7.2.0"], ["v7.4.0", ""]],
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.0.0", "v7.2.2"],
                        ["v7.4.0", ""],
                    ],
                },
                {
                    "value": "enable",
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.0.0", "v7.2.2"],
                        ["v7.4.0", ""],
                    ],
                },
            ],
        },
        "key_outbound": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v7.2.0", "v7.2.0"], ["v7.4.0", ""]],
            "type": "integer",
        },
        "key_inbound": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v7.2.0", "v7.2.0"], ["v7.4.0", ""]],
            "type": "integer",
        },
        "dscp_copying": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "diffservcode": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "keepalive_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "keepalive_failtimes": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auto_asic_offload": {
            "v_range": [["v7.4.2", "v7.4.2"]],
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
        "system_gre_tunnel": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_gre_tunnel"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_gre_tunnel"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_gre_tunnel"
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
