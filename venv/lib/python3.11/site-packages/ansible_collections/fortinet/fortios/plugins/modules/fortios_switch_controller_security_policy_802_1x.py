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
module: fortios_switch_controller_security_policy_802_1x
short_description: Configure 802.1x MAC Authentication Bypass (MAB) policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify switch_controller_security_policy feature and 802_1x category.
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
    switch_controller_security_policy_802_1x:
        description:
            - Configure 802.1x MAC Authentication Bypass (MAB) policies.
        default: null
        type: dict
        suboptions:
            auth_fail_vlan:
                description:
                    - Enable to allow limited access to clients that cannot authenticate.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            auth_fail_vlan_id:
                description:
                    - VLAN ID on which authentication failed. Source system.interface.name.
                type: str
            auth_fail_vlanid:
                description:
                    - VLAN ID on which authentication failed.
                type: int
            auth_order:
                description:
                    - Configure authentication order.
                type: str
                choices:
                    - 'dot1x-mab'
                    - 'mab-dot1x'
                    - 'mab'
            auth_priority:
                description:
                    - Configure authentication priority.
                type: str
                choices:
                    - 'legacy'
                    - 'dot1x-mab'
                    - 'mab-dot1x'
            authserver_timeout_period:
                description:
                    - Authentication server timeout period (3 - 15 sec).
                type: int
            authserver_timeout_tagged:
                description:
                    - Configure timeout option for the tagged VLAN which allows limited access when the authentication server is unavailable.
                type: str
                choices:
                    - 'disable'
                    - 'lldp-voice'
                    - 'static'
            authserver_timeout_tagged_vlanid:
                description:
                    - Tagged VLAN name for which the timeout option is applied to (only one VLAN ID). Source system.interface.name.
                type: str
            authserver_timeout_vlan:
                description:
                    - Enable/disable the authentication server timeout VLAN to allow limited access when RADIUS is unavailable.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            authserver_timeout_vlanid:
                description:
                    - Authentication server timeout VLAN name. Source system.interface.name.
                type: str
            dacl:
                description:
                    - Enable/disable dynamic access control list on this interface.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            eap_auto_untagged_vlans:
                description:
                    - Enable/disable automatic inclusion of untagged VLANs.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            eap_passthru:
                description:
                    - Enable/disable EAP pass-through mode, allowing protocols (such as LLDP) to pass through ports for more flexible authentication.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            framevid_apply:
                description:
                    - Enable/disable the capability to apply the EAP/MAB frame VLAN to the port native VLAN.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            guest_auth_delay:
                description:
                    - Guest authentication delay (1 - 900  sec).
                type: int
            guest_vlan:
                description:
                    - Enable the guest VLAN feature to allow limited access to non-802.1X-compliant clients.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            guest_vlan_id:
                description:
                    - Guest VLAN name. Source system.interface.name.
                type: str
            guest_vlanid:
                description:
                    - Guest VLAN ID.
                type: int
            mac_auth_bypass:
                description:
                    - Enable/disable MAB for this policy.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            name:
                description:
                    - Policy name.
                required: true
                type: str
            open_auth:
                description:
                    - Enable/disable open authentication for this policy.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            policy_type:
                description:
                    - Policy type.
                type: str
                choices:
                    - '802.1X'
            radius_timeout_overwrite:
                description:
                    - Enable to override the global RADIUS session timeout.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            security_mode:
                description:
                    - Port or MAC based 802.1X security mode.
                type: str
                choices:
                    - '802.1X'
                    - '802.1X-mac-based'
            user_group:
                description:
                    - Name of user-group to assign to this MAC Authentication Bypass (MAB) policy.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Group name. Source user.group.name.
                        required: true
                        type: str
"""

EXAMPLES = """
- name: Configure 802.1x MAC Authentication Bypass (MAB) policies.
  fortinet.fortios.fortios_switch_controller_security_policy_802_1x:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      switch_controller_security_policy_802_1x:
          auth_fail_vlan: "disable"
          auth_fail_vlan_id: "<your_own_value> (source system.interface.name)"
          auth_fail_vlanid: "32767"
          auth_order: "dot1x-mab"
          auth_priority: "legacy"
          authserver_timeout_period: "3"
          authserver_timeout_tagged: "disable"
          authserver_timeout_tagged_vlanid: "<your_own_value> (source system.interface.name)"
          authserver_timeout_vlan: "disable"
          authserver_timeout_vlanid: "<your_own_value> (source system.interface.name)"
          dacl: "disable"
          eap_auto_untagged_vlans: "disable"
          eap_passthru: "disable"
          framevid_apply: "disable"
          guest_auth_delay: "30"
          guest_vlan: "disable"
          guest_vlan_id: "<your_own_value> (source system.interface.name)"
          guest_vlanid: "32767"
          mac_auth_bypass: "disable"
          name: "default_name_22"
          open_auth: "disable"
          policy_type: "802.1X"
          radius_timeout_overwrite: "disable"
          security_mode: "802.1X"
          user_group:
              -
                  name: "default_name_28 (source user.group.name)"
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


def filter_switch_controller_security_policy_802_1x_data(json):
    option_list = [
        "auth_fail_vlan",
        "auth_fail_vlan_id",
        "auth_fail_vlanid",
        "auth_order",
        "auth_priority",
        "authserver_timeout_period",
        "authserver_timeout_tagged",
        "authserver_timeout_tagged_vlanid",
        "authserver_timeout_vlan",
        "authserver_timeout_vlanid",
        "dacl",
        "eap_auto_untagged_vlans",
        "eap_passthru",
        "framevid_apply",
        "guest_auth_delay",
        "guest_vlan",
        "guest_vlan_id",
        "guest_vlanid",
        "mac_auth_bypass",
        "name",
        "open_auth",
        "policy_type",
        "radius_timeout_overwrite",
        "security_mode",
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


def switch_controller_security_policy_802_1x(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    switch_controller_security_policy_802_1x_data = data[
        "switch_controller_security_policy_802_1x"
    ]

    filtered_data = filter_switch_controller_security_policy_802_1x_data(
        switch_controller_security_policy_802_1x_data
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
            "switch-controller.security-policy", "802-1X", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "switch-controller.security-policy", "802-1X", vdom=vdom, mkey=mkey
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
    data_copy["switch_controller_security_policy_802_1x"] = filtered_data
    fos.do_member_operation(
        "switch-controller.security-policy",
        "802-1X",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "switch-controller.security-policy",
            "802-1X",
            data=converted_data,
            vdom=vdom,
        )

    elif state == "absent":
        return fos.delete(
            "switch-controller.security-policy",
            "802-1X",
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


def fortios_switch_controller_security_policy(data, fos, check_mode):

    if data["switch_controller_security_policy_802_1x"]:
        resp = switch_controller_security_policy_802_1x(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("switch_controller_security_policy_802_1x")
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
        "security_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "802.1X"}, {"value": "802.1X-mac-based"}],
        },
        "user_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "mac_auth_bypass": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "auth_order": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [
                {"value": "dot1x-mab"},
                {"value": "mab-dot1x"},
                {"value": "mab"},
            ],
        },
        "auth_priority": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [
                {"value": "legacy"},
                {"value": "dot1x-mab"},
                {"value": "mab-dot1x"},
            ],
        },
        "open_auth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "eap_passthru": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "eap_auto_untagged_vlans": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "guest_vlan": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "guest_vlan_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "guest_auth_delay": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auth_fail_vlan": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "auth_fail_vlan_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "framevid_apply": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "radius_timeout_overwrite": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "policy_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "802.1X"}],
        },
        "authserver_timeout_period": {"v_range": [["v6.4.4", ""]], "type": "integer"},
        "authserver_timeout_vlan": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "authserver_timeout_vlanid": {"v_range": [["v6.4.4", ""]], "type": "string"},
        "authserver_timeout_tagged": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "lldp-voice"},
                {"value": "static"},
            ],
        },
        "authserver_timeout_tagged_vlanid": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
        },
        "dacl": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "guest_vlanid": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "integer",
        },
        "auth_fail_vlanid": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "integer",
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
        "switch_controller_security_policy_802_1x": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["switch_controller_security_policy_802_1x"]["options"][
            attribute_name
        ] = module_spec["options"][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_controller_security_policy_802_1x"]["options"][
                attribute_name
            ]["required"] = True

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
            fos, versioned_schema, "switch_controller_security_policy_802_1x"
        )

        is_error, has_changed, result, diff = fortios_switch_controller_security_policy(
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
