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
module: fortios_system_pppoe_interface
short_description: Configure the PPPoE interfaces in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and pppoe_interface category.
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
    system_pppoe_interface:
        description:
            - Configure the PPPoE interfaces.
        default: null
        type: dict
        suboptions:
            ac_name:
                description:
                    - PPPoE AC name.
                type: str
            auth_type:
                description:
                    - PPP authentication type to use.
                type: str
                choices:
                    - 'auto'
                    - 'pap'
                    - 'chap'
                    - 'mschapv1'
                    - 'mschapv2'
            device:
                description:
                    - Name for the physical interface. Source system.interface.name.
                type: str
            dial_on_demand:
                description:
                    - Enable/disable dial on demand to dial the PPPoE interface when packets are routed to the PPPoE interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            disc_retry_timeout:
                description:
                    - PPPoE discovery init timeout value in (0-4294967295 sec).
                type: int
            idle_timeout:
                description:
                    - PPPoE auto disconnect after idle timeout (0-4294967295 sec).
                type: int
            ipunnumbered:
                description:
                    - PPPoE unnumbered IP.
                type: str
            ipv6:
                description:
                    - Enable/disable IPv6 Control Protocol (IPv6CP).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            lcp_echo_interval:
                description:
                    - Time in seconds between PPPoE Link Control Protocol (LCP) echo requests.
                type: int
            lcp_max_echo_fails:
                description:
                    - Maximum missed LCP echo messages before disconnect.
                type: int
            name:
                description:
                    - Name of the PPPoE interface.
                required: true
                type: str
            padt_retry_timeout:
                description:
                    - PPPoE terminate timeout value in (0-4294967295 sec).
                type: int
            password:
                description:
                    - Enter the password.
                type: str
            pppoe_egress_cos:
                description:
                    - CoS in VLAN tag for outgoing PPPoE/PPP packets.
                type: str
                choices:
                    - 'cos0'
                    - 'cos1'
                    - 'cos2'
                    - 'cos3'
                    - 'cos4'
                    - 'cos5'
                    - 'cos6'
                    - 'cos7'
            pppoe_unnumbered_negotiate:
                description:
                    - Enable/disable PPPoE unnumbered negotiation.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            service_name:
                description:
                    - PPPoE service name.
                type: str
            username:
                description:
                    - User name.
                type: str
"""

EXAMPLES = """
- name: Configure the PPPoE interfaces.
  fortinet.fortios.fortios_system_pppoe_interface:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_pppoe_interface:
          ac_name: "<your_own_value>"
          auth_type: "auto"
          device: "<your_own_value> (source system.interface.name)"
          dial_on_demand: "enable"
          disc_retry_timeout: "1"
          idle_timeout: "0"
          ipunnumbered: "<your_own_value>"
          ipv6: "enable"
          lcp_echo_interval: "5"
          lcp_max_echo_fails: "3"
          name: "default_name_13"
          padt_retry_timeout: "1"
          password: "<your_own_value>"
          pppoe_egress_cos: "cos0"
          pppoe_unnumbered_negotiate: "enable"
          service_name: "<your_own_value>"
          username: "<your_own_value>"
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


def filter_system_pppoe_interface_data(json):
    option_list = [
        "ac_name",
        "auth_type",
        "device",
        "dial_on_demand",
        "disc_retry_timeout",
        "idle_timeout",
        "ipunnumbered",
        "ipv6",
        "lcp_echo_interval",
        "lcp_max_echo_fails",
        "name",
        "padt_retry_timeout",
        "password",
        "pppoe_egress_cos",
        "pppoe_unnumbered_negotiate",
        "service_name",
        "username",
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


def system_pppoe_interface(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_pppoe_interface_data = data["system_pppoe_interface"]

    filtered_data = filter_system_pppoe_interface_data(system_pppoe_interface_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "pppoe-interface", filtered_data, vdom=vdom)
        current_data = fos.get("system", "pppoe-interface", vdom=vdom, mkey=mkey)
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
    data_copy["system_pppoe_interface"] = filtered_data
    fos.do_member_operation(
        "system",
        "pppoe-interface",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "pppoe-interface", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system", "pppoe-interface", mkey=converted_data["name"], vdom=vdom
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

    if data["system_pppoe_interface"]:
        resp = system_pppoe_interface(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_pppoe_interface"))
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
        "dial_on_demand": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipv6": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "device": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "username": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "pppoe_egress_cos": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [
                {"value": "cos0"},
                {"value": "cos1"},
                {"value": "cos2"},
                {"value": "cos3"},
                {"value": "cos4"},
                {"value": "cos5"},
                {"value": "cos6"},
                {"value": "cos7"},
            ],
        },
        "auth_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "auto"},
                {"value": "pap"},
                {"value": "chap"},
                {"value": "mschapv1"},
                {"value": "mschapv2"},
            ],
        },
        "ipunnumbered": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "pppoe_unnumbered_negotiate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "idle_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "disc_retry_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "padt_retry_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "service_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ac_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "lcp_echo_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "lcp_max_echo_fails": {"v_range": [["v6.0.0", ""]], "type": "integer"},
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
        "system_pppoe_interface": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_pppoe_interface"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_pppoe_interface"]["options"][attribute_name][
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
            fos, versioned_schema, "system_pppoe_interface"
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
