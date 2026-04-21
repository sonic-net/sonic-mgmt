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
module: fortios_vpn_ocvpn
short_description: Configure Overlay Controller VPN settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify vpn feature and ocvpn category.
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

    vpn_ocvpn:
        description:
            - Configure Overlay Controller VPN settings.
        default: null
        type: dict
        suboptions:
            auto_discovery:
                description:
                    - Enable/disable auto-discovery shortcuts.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auto_discovery_shortcut_mode:
                description:
                    - Control deletion of child short-cut tunnels when the parent tunnel goes down.
                type: str
                choices:
                    - 'independent'
                    - 'dependent'
            eap:
                description:
                    - Enable/disable EAP client authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eap_users:
                description:
                    - EAP authentication user group. Source user.group.name.
                type: str
            forticlient_access:
                description:
                    - Configure FortiClient settings.
                type: dict
                suboptions:
                    auth_groups:
                        description:
                            - FortiClient user authentication groups.
                        type: list
                        elements: dict
                        suboptions:
                            auth_group:
                                description:
                                    - Authentication user group for FortiClient access. Source user.group.name.
                                type: str
                            name:
                                description:
                                    - Group name.
                                required: true
                                type: str
                            overlays:
                                description:
                                    - OCVPN overlays to allow access to.
                                type: list
                                elements: dict
                                suboptions:
                                    overlay_name:
                                        description:
                                            - Overlay name. Source vpn.ocvpn.overlays.overlay-name.
                                        required: true
                                        type: str
                    psksecret:
                        description:
                            - Pre-shared secret for FortiClient PSK authentication (ASCII string or hexadecimal encoded with a leading 0x).
                        type: str
                    status:
                        description:
                            - Enable/disable FortiClient to access OCVPN networks.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            ha_alias:
                description:
                    - Hidden HA alias.
                type: str
            ip_allocation_block:
                description:
                    - Class B subnet reserved for private IP address assignment.
                type: str
            multipath:
                description:
                    - Enable/disable multipath redundancy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            nat:
                description:
                    - Enable/disable NAT support.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            overlays:
                description:
                    - Network overlays to register with Overlay Controller VPN service.
                type: list
                elements: dict
                suboptions:
                    assign_ip:
                        description:
                            - Enable/disable mode-cfg address assignment.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    id:
                        description:
                            - ID.
                        type: int
                    inter_overlay:
                        description:
                            - Allow or deny traffic from other overlays.
                        type: str
                        choices:
                            - 'allow'
                            - 'deny'
                    ipv4_end_ip:
                        description:
                            - End of IPv4 range.
                        type: str
                    ipv4_start_ip:
                        description:
                            - Start of IPv4 range.
                        type: str
                    name:
                        description:
                            - Overlay name.
                        type: str
                    overlay_name:
                        description:
                            - Overlay name.
                        required: true
                        type: str
                    subnets:
                        description:
                            - Internal subnets to register with OCVPN service.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            interface:
                                description:
                                    - LAN interface. Source system.interface.name.
                                type: str
                            subnet:
                                description:
                                    - IPv4 address and subnet mask.
                                type: str
                            type:
                                description:
                                    - Subnet type.
                                type: str
                                choices:
                                    - 'subnet'
                                    - 'interface'
            poll_interval:
                description:
                    - Overlay Controller VPN polling interval.
                type: int
            role:
                description:
                    - Set device role.
                type: str
                choices:
                    - 'spoke'
                    - 'primary-hub'
                    - 'secondary-hub'
            sdwan:
                description:
                    - Enable/disable adding OCVPN tunnels to SD-WAN.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sdwan_zone:
                description:
                    - Set SD-WAN zone. Source system.sdwan.zone.name.
                type: str
            status:
                description:
                    - Enable/disable Overlay Controller cloud assisted VPN.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            subnets:
                description:
                    - Internal subnets to register with Overlay Controller VPN service.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    interface:
                        description:
                            - LAN interface. Source system.interface.name.
                        type: str
                    subnet:
                        description:
                            - IPv4 address and subnet mask.
                        type: str
                    type:
                        description:
                            - Subnet type.
                        type: str
                        choices:
                            - 'subnet'
                            - 'interface'
            wan_interface:
                description:
                    - FortiGate WAN interfaces to use with OCVPN.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
"""

EXAMPLES = """
- name: Configure Overlay Controller VPN settings.
  fortinet.fortios.fortios_vpn_ocvpn:
      vdom: "{{ vdom }}"
      vpn_ocvpn:
          auto_discovery: "enable"
          auto_discovery_shortcut_mode: "independent"
          eap: "enable"
          eap_users: "<your_own_value> (source user.group.name)"
          forticlient_access:
              auth_groups:
                  -
                      auth_group: "<your_own_value> (source user.group.name)"
                      name: "default_name_10"
                      overlays:
                          -
                              overlay_name: "<your_own_value> (source vpn.ocvpn.overlays.overlay-name)"
              psksecret: "<your_own_value>"
              status: "enable"
          ha_alias: "<your_own_value>"
          ip_allocation_block: "<your_own_value>"
          multipath: "enable"
          nat: "enable"
          overlays:
              -
                  assign_ip: "enable"
                  id: "21"
                  inter_overlay: "allow"
                  ipv4_end_ip: "<your_own_value>"
                  ipv4_start_ip: "<your_own_value>"
                  name: "default_name_25"
                  overlay_name: "<your_own_value>"
                  subnets:
                      -
                          id: "28"
                          interface: "<your_own_value> (source system.interface.name)"
                          subnet: "<your_own_value>"
                          type: "subnet"
          poll_interval: "30"
          role: "spoke"
          sdwan: "enable"
          sdwan_zone: "<your_own_value> (source system.sdwan.zone.name)"
          status: "enable"
          subnets:
              -
                  id: "38"
                  interface: "<your_own_value> (source system.interface.name)"
                  subnet: "<your_own_value>"
                  type: "subnet"
          wan_interface:
              -
                  name: "default_name_43 (source system.interface.name)"
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


def filter_vpn_ocvpn_data(json):
    option_list = [
        "auto_discovery",
        "auto_discovery_shortcut_mode",
        "eap",
        "eap_users",
        "forticlient_access",
        "ha_alias",
        "ip_allocation_block",
        "multipath",
        "nat",
        "overlays",
        "poll_interval",
        "role",
        "sdwan",
        "sdwan_zone",
        "status",
        "subnets",
        "wan_interface",
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


def vpn_ocvpn(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    vpn_ocvpn_data = data["vpn_ocvpn"]

    filtered_data = filter_vpn_ocvpn_data(vpn_ocvpn_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("vpn", "ocvpn", filtered_data, vdom=vdom)
        current_data = fos.get("vpn", "ocvpn", vdom=vdom, mkey=mkey)
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
    data_copy["vpn_ocvpn"] = filtered_data
    fos.do_member_operation(
        "vpn",
        "ocvpn",
        data_copy,
    )

    return fos.set("vpn", "ocvpn", data=converted_data, vdom=vdom)


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


def fortios_vpn(data, fos, check_mode):

    if data["vpn_ocvpn"]:
        resp = vpn_ocvpn(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("vpn_ocvpn"))
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
    "v_range": [["v6.0.0", "v7.2.4"]],
    "type": "dict",
    "children": {
        "status": {
            "v_range": [["v6.0.0", "v7.2.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "role": {
            "v_range": [["v6.2.0", "v7.2.4"]],
            "type": "string",
            "options": [
                {"value": "spoke"},
                {"value": "primary-hub"},
                {"value": "secondary-hub"},
            ],
        },
        "multipath": {
            "v_range": [["v6.4.0", "v7.2.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sdwan": {
            "v_range": [["v6.4.0", "v7.2.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sdwan_zone": {"v_range": [["v7.0.0", "v7.2.4"]], "type": "string"},
        "wan_interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", "v7.2.4"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.4.0", "v7.2.4"]],
        },
        "nat": {
            "v_range": [["v6.2.0", "v7.2.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ip_allocation_block": {"v_range": [["v6.4.0", "v7.2.4"]], "type": "string"},
        "overlays": {
            "type": "list",
            "elements": "dict",
            "children": {
                "overlay_name": {
                    "v_range": [["v6.4.0", "v7.2.4"]],
                    "type": "string",
                    "required": True,
                },
                "inter_overlay": {
                    "v_range": [["v6.4.0", "v7.2.4"]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "deny"}],
                },
                "subnets": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.2.0", "v7.2.4"]],
                            "type": "integer",
                            "required": True,
                        },
                        "type": {
                            "v_range": [["v6.2.0", "v7.2.4"]],
                            "type": "string",
                            "options": [{"value": "subnet"}, {"value": "interface"}],
                        },
                        "subnet": {"v_range": [["v6.2.0", "v7.2.4"]], "type": "string"},
                        "interface": {
                            "v_range": [["v6.2.0", "v7.2.4"]],
                            "type": "string",
                        },
                    },
                    "v_range": [["v6.2.0", "v7.2.4"]],
                },
                "assign_ip": {
                    "v_range": [["v6.2.0", "v7.0.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ipv4_start_ip": {"v_range": [["v6.2.0", "v7.0.0"]], "type": "string"},
                "ipv4_end_ip": {"v_range": [["v6.2.0", "v7.0.0"]], "type": "string"},
                "id": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "integer"},
                "name": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
            },
            "v_range": [["v6.2.0", "v7.2.4"]],
        },
        "forticlient_access": {
            "v_range": [["v6.4.0", "v7.2.4"]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.4.0", "v7.2.4"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "psksecret": {"v_range": [["v6.4.0", "v7.2.4"]], "type": "string"},
                "auth_groups": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", "v7.2.4"]],
                            "type": "string",
                            "required": True,
                        },
                        "auth_group": {
                            "v_range": [["v6.4.0", "v7.2.4"]],
                            "type": "string",
                        },
                        "overlays": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "overlay_name": {
                                    "v_range": [["v6.4.0", "v7.2.4"]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v6.4.0", "v7.2.4"]],
                        },
                    },
                    "v_range": [["v6.4.0", "v7.2.4"]],
                },
            },
        },
        "auto_discovery": {
            "v_range": [["v6.2.0", "v7.2.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auto_discovery_shortcut_mode": {
            "v_range": [["v7.0.1", "v7.2.4"]],
            "type": "string",
            "options": [{"value": "independent"}, {"value": "dependent"}],
        },
        "poll_interval": {"v_range": [["v6.0.0", "v7.2.4"]], "type": "integer"},
        "eap": {
            "v_range": [["v6.2.0", "v7.2.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "eap_users": {"v_range": [["v6.2.0", "v7.2.4"]], "type": "string"},
        "ha_alias": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "subnets": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "integer",
                    "required": True,
                },
                "type": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [{"value": "subnet"}, {"value": "interface"}],
                },
                "subnet": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
                "interface": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
            },
            "v_range": [["v6.0.0", "v6.0.11"]],
        },
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
        "vpn_ocvpn": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["vpn_ocvpn"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["vpn_ocvpn"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "vpn_ocvpn"
        )

        is_error, has_changed, result, diff = fortios_vpn(
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
