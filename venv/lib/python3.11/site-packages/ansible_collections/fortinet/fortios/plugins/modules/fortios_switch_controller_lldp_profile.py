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
module: fortios_switch_controller_lldp_profile
short_description: Configure FortiSwitch LLDP profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify switch_controller feature and lldp_profile category.
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
    switch_controller_lldp_profile:
        description:
            - Configure FortiSwitch LLDP profiles.
        default: null
        type: dict
        suboptions:
            tlvs_802dot1:
                description:
                    - Transmitted IEEE 802.1 TLVs.
                type: list
                elements: str
                choices:
                    - 'port-vlan-id'
            tlvs_802dot3:
                description:
                    - Transmitted IEEE 802.3 TLVs.
                type: list
                elements: str
                choices:
                    - 'max-frame-size'
                    - 'power-negotiation'
            auto_isl:
                description:
                    - Enable/disable auto inter-switch LAG.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            auto_isl_auth:
                description:
                    - Auto inter-switch LAG authentication mode.
                type: str
                choices:
                    - 'legacy'
                    - 'strict'
                    - 'relax'
            auto_isl_auth_encrypt:
                description:
                    - Auto inter-switch LAG encryption mode.
                type: str
                choices:
                    - 'none'
                    - 'mixed'
                    - 'must'
            auto_isl_auth_identity:
                description:
                    - Auto inter-switch LAG authentication identity.
                type: str
            auto_isl_auth_macsec_profile:
                description:
                    - Auto inter-switch LAG macsec profile for encryption.
                type: str
            auto_isl_auth_reauth:
                description:
                    - Auto inter-switch LAG authentication reauth period in seconds(10 - 3600).
                type: int
            auto_isl_auth_user:
                description:
                    - Auto inter-switch LAG authentication user certificate.
                type: str
            auto_isl_hello_timer:
                description:
                    - Auto inter-switch LAG hello timer duration (1 - 30 sec).
                type: int
            auto_isl_port_group:
                description:
                    - Auto inter-switch LAG port group ID (0 - 9).
                type: int
            auto_isl_receive_timeout:
                description:
                    - Auto inter-switch LAG timeout if no response is received (3 - 90 sec).
                type: int
            auto_mclag_icl:
                description:
                    - Enable/disable MCLAG inter chassis link.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            custom_tlvs:
                description:
                    - Configuration method to edit custom TLV entries.
                type: list
                elements: dict
                suboptions:
                    information_string:
                        description:
                            - Organizationally defined information string (0 - 507 hexadecimal bytes).
                        type: str
                    name:
                        description:
                            - TLV name (not sent).
                        required: true
                        type: str
                    oui:
                        description:
                            - Organizationally unique identifier (OUI), a 3-byte hexadecimal number, for this TLV.
                        type: str
                    subtype:
                        description:
                            - Organizationally defined subtype (0 - 255).
                        type: int
            med_location_service:
                description:
                    - Configuration method to edit Media Endpoint Discovery (MED) location service type-length-value (TLV) categories.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Location service type name.
                        required: true
                        type: str
                    status:
                        description:
                            - Enable or disable this TLV.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    sys_location_id:
                        description:
                            - Location service ID. Source switch-controller.location.name.
                        type: str
            med_network_policy:
                description:
                    - Configuration method to edit Media Endpoint Discovery (MED) network policy type-length-value (TLV) categories.
                type: list
                elements: dict
                suboptions:
                    assign_vlan:
                        description:
                            - Enable/disable VLAN assignment when this profile is applied on managed FortiSwitch port.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    dscp:
                        description:
                            - Advertised Differentiated Services Code Point (DSCP) value, a packet header value indicating the level of service requested for
                               traffic, such as high priority or best effort delivery.
                        type: int
                    name:
                        description:
                            - Policy type name.
                        required: true
                        type: str
                    priority:
                        description:
                            - Advertised Layer 2 priority (0 - 7; from lowest to highest priority).
                        type: int
                    status:
                        description:
                            - Enable or disable this TLV.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    vlan:
                        description:
                            - ID of VLAN to advertise, if configured on port (0 - 4094, 0 = priority tag).
                        type: int
                    vlan_intf:
                        description:
                            - VLAN interface to advertise; if configured on port. Source system.interface.name.
                        type: str
            med_tlvs:
                description:
                    - Transmitted LLDP-MED TLVs (type-length-value descriptions).
                type: list
                elements: str
                choices:
                    - 'inventory-management'
                    - 'network-policy'
                    - 'power-management'
                    - 'location-identification'
            name:
                description:
                    - Profile name.
                required: true
                type: str
"""

EXAMPLES = """
- name: Configure FortiSwitch LLDP profiles.
  fortinet.fortios.fortios_switch_controller_lldp_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      switch_controller_lldp_profile:
          tlvs_802dot1: "port-vlan-id"
          tlvs_802dot3: "max-frame-size"
          auto_isl: "disable"
          auto_isl_auth: "legacy"
          auto_isl_auth_encrypt: "none"
          auto_isl_auth_identity: "<your_own_value>"
          auto_isl_auth_macsec_profile: "<your_own_value>"
          auto_isl_auth_reauth: "3600"
          auto_isl_auth_user: "<your_own_value>"
          auto_isl_hello_timer: "3"
          auto_isl_port_group: "0"
          auto_isl_receive_timeout: "60"
          auto_mclag_icl: "disable"
          custom_tlvs:
              -
                  information_string: "<your_own_value>"
                  name: "default_name_18"
                  oui: "<your_own_value>"
                  subtype: "0"
          med_location_service:
              -
                  name: "default_name_22"
                  status: "disable"
                  sys_location_id: "<your_own_value> (source switch-controller.location.name)"
          med_network_policy:
              -
                  assign_vlan: "disable"
                  dscp: "0"
                  name: "default_name_28"
                  priority: "0"
                  status: "disable"
                  vlan: "2047"
                  vlan_intf: "<your_own_value> (source system.interface.name)"
          med_tlvs: "inventory-management"
          name: "default_name_34"
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


def filter_switch_controller_lldp_profile_data(json):
    option_list = [
        "tlvs_802dot1",
        "tlvs_802dot3",
        "auto_isl",
        "auto_isl_auth",
        "auto_isl_auth_encrypt",
        "auto_isl_auth_identity",
        "auto_isl_auth_macsec_profile",
        "auto_isl_auth_reauth",
        "auto_isl_auth_user",
        "auto_isl_hello_timer",
        "auto_isl_port_group",
        "auto_isl_receive_timeout",
        "auto_mclag_icl",
        "custom_tlvs",
        "med_location_service",
        "med_network_policy",
        "med_tlvs",
        "name",
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
        ["med_tlvs"],
        ["tlvs_802dot1"],
        ["tlvs_802dot3"],
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


def valid_attr_to_invalid_attr(data):
    speciallist = {"802.1_tlvs": "tlvs_802dot1", "802.3_tlvs": "tlvs_802dot3"}

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


def switch_controller_lldp_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    switch_controller_lldp_profile_data = data["switch_controller_lldp_profile"]

    filtered_data = filter_switch_controller_lldp_profile_data(
        switch_controller_lldp_profile_data
    )
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey(
            "switch-controller", "lldp-profile", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "switch-controller", "lldp-profile", vdom=vdom, mkey=mkey
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
    data_copy["switch_controller_lldp_profile"] = filtered_data
    fos.do_member_operation(
        "switch-controller",
        "lldp-profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "switch-controller", "lldp-profile", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "switch-controller", "lldp-profile", mkey=converted_data["name"], vdom=vdom
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

    if data["switch_controller_lldp_profile"]:
        resp = switch_controller_lldp_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("switch_controller_lldp_profile")
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
        "med_tlvs": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "inventory-management"},
                {"value": "network-policy"},
                {"value": "power-management", "v_range": [["v6.2.0", ""]]},
                {"value": "location-identification", "v_range": [["v6.2.0", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "auto_isl": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "auto_isl_hello_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auto_isl_receive_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auto_isl_port_group": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auto_mclag_icl": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "auto_isl_auth": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "legacy"}, {"value": "strict"}, {"value": "relax"}],
        },
        "auto_isl_auth_user": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "auto_isl_auth_identity": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "auto_isl_auth_reauth": {"v_range": [["v7.4.1", ""]], "type": "integer"},
        "auto_isl_auth_encrypt": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "mixed"}, {"value": "must"}],
        },
        "auto_isl_auth_macsec_profile": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "med_network_policy": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "vlan_intf": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "assign_vlan": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "dscp": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "vlan": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "integer",
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "med_location_service": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "sys_location_id": {"v_range": [["v6.2.0", ""]], "type": "string"},
            },
            "v_range": [["v6.2.0", ""]],
        },
        "custom_tlvs": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "oui": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "subtype": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "information_string": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "tlvs_802dot1": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [{"value": "port-vlan-id"}],
            "multiple_values": True,
            "elements": "str",
        },
        "tlvs_802dot3": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "max-frame-size"},
                {"value": "power-negotiation", "v_range": [["v6.2.0", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
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
        "switch_controller_lldp_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["switch_controller_lldp_profile"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["switch_controller_lldp_profile"]["options"][attribute_name][
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
            fos, versioned_schema, "switch_controller_lldp_profile"
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
