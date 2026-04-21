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
module: fortios_switch_controller_global
short_description: Configure FortiSwitch global settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify switch_controller feature and global category.
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

    switch_controller_global:
        description:
            - Configure FortiSwitch global settings.
        default: null
        type: dict
        suboptions:
            allow_multiple_interfaces:
                description:
                    - Enable/disable multiple FortiLink interfaces for redundant connections between a managed FortiSwitch and FortiGate.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bounce_quarantined_link:
                description:
                    - Enable/disable bouncing (administratively bring the link down, up) of a switch port where a quarantined device was seen last. Helps to
                       re-initiate the DHCP process for a device.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            custom_command:
                description:
                    - List of custom commands to be pushed to all FortiSwitches in the VDOM.
                type: list
                elements: dict
                suboptions:
                    command_entry:
                        description:
                            - List of FortiSwitch commands.
                        required: true
                        type: str
                    command_name:
                        description:
                            - Name of custom command to push to all FortiSwitches in VDOM. Source switch-controller.custom-command.command-name.
                        type: str
            default_virtual_switch_vlan:
                description:
                    - Default VLAN for ports when added to the virtual-switch. Source system.interface.name.
                type: str
            dhcp_option82_circuit_id:
                description:
                    - List the parameters to be included to inform about client identification.
                type: list
                elements: str
                choices:
                    - 'intfname'
                    - 'vlan'
                    - 'hostname'
                    - 'mode'
                    - 'description'
            dhcp_option82_format:
                description:
                    - DHCP option-82 format string.
                type: str
                choices:
                    - 'ascii'
                    - 'legacy'
            dhcp_option82_remote_id:
                description:
                    - List the parameters to be included to inform about client identification.
                type: list
                elements: str
                choices:
                    - 'mac'
                    - 'hostname'
                    - 'ip'
            dhcp_server_access_list:
                description:
                    - Enable/disable DHCP snooping server access list.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dhcp_snoop_client_db_exp:
                description:
                    - Expiry time for DHCP snooping server database entries (300 - 259200 sec).
                type: int
            dhcp_snoop_client_req:
                description:
                    - Client DHCP packet broadcast mode.
                type: str
                choices:
                    - 'drop-untrusted'
                    - 'forward-untrusted'
            dhcp_snoop_db_per_port_learn_limit:
                description:
                    - Per Interface dhcp-server entries learn limit (0 - 1024).
                type: int
            disable_discovery:
                description:
                    - Prevent this FortiSwitch from discovering.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - FortiSwitch Serial-number.
                        required: true
                        type: str
            fips_enforce:
                description:
                    - Enable/disable enforcement of FIPS on managed FortiSwitch devices.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            firewall_auth_user_hold_period:
                description:
                    - Time period in minutes to hold firewall authenticated MAC users (5 - 1440).
                type: int
            firmware_provision_on_authorization:
                description:
                    - Enable/disable automatic provisioning of latest firmware on authorization.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            https_image_push:
                description:
                    - Enable/disable image push to FortiSwitch using HTTPS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            log_mac_limit_violations:
                description:
                    - Enable/disable logs for Learning Limit Violations.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mac_aging_interval:
                description:
                    - Time after which an inactive MAC is aged out (10 - 1000000 sec).
                type: int
            mac_event_logging:
                description:
                    - Enable/disable MAC address event logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mac_retention_period:
                description:
                    - Time in hours after which an inactive MAC is removed from client DB (0 = aged out based on mac-aging-interval).
                type: int
            mac_violation_timer:
                description:
                    - Set timeout for Learning Limit Violations (0 = disabled).
                type: int
            quarantine_mode:
                description:
                    - Quarantine mode.
                type: str
                choices:
                    - 'by-vlan'
                    - 'by-redirect'
            sn_dns_resolution:
                description:
                    - Enable/disable DNS resolution of the FortiSwitch unit"s IP address with switch name.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_on_deauth:
                description:
                    - No-operation/Factory-reset the managed FortiSwitch on deauthorization.
                type: str
                choices:
                    - 'no-op'
                    - 'factory-reset'
            update_user_device:
                description:
                    - Control which sources update the device user list.
                type: list
                elements: str
                choices:
                    - 'mac-cache'
                    - 'lldp'
                    - 'dhcp-snooping'
                    - 'l2-db'
                    - 'l3-db'
            vlan_all_mode:
                description:
                    - VLAN configuration mode, user-defined-vlans or all-possible-vlans.
                type: str
                choices:
                    - 'all'
                    - 'defined'
            vlan_identity:
                description:
                    - Identity of the VLAN. Commonly used for RADIUS Tunnel-Private-Group-Id.
                type: str
                choices:
                    - 'description'
                    - 'name'
            vlan_optimization:
                description:
                    - FortiLink VLAN optimization.
                type: str
                choices:
                    - 'prune'
                    - 'configured'
                    - 'none'
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure FortiSwitch global settings.
  fortinet.fortios.fortios_switch_controller_global:
      vdom: "{{ vdom }}"
      switch_controller_global:
          allow_multiple_interfaces: "enable"
          bounce_quarantined_link: "disable"
          custom_command:
              -
                  command_entry: "<your_own_value>"
                  command_name: "<your_own_value> (source switch-controller.custom-command.command-name)"
          default_virtual_switch_vlan: "<your_own_value> (source system.interface.name)"
          dhcp_option82_circuit_id: "intfname"
          dhcp_option82_format: "ascii"
          dhcp_option82_remote_id: "mac"
          dhcp_server_access_list: "enable"
          dhcp_snoop_client_db_exp: "86400"
          dhcp_snoop_client_req: "drop-untrusted"
          dhcp_snoop_db_per_port_learn_limit: "64"
          disable_discovery:
              -
                  name: "default_name_17"
          fips_enforce: "disable"
          firewall_auth_user_hold_period: "5"
          firmware_provision_on_authorization: "enable"
          https_image_push: "enable"
          log_mac_limit_violations: "enable"
          mac_aging_interval: "300"
          mac_event_logging: "enable"
          mac_retention_period: "24"
          mac_violation_timer: "0"
          quarantine_mode: "by-vlan"
          sn_dns_resolution: "enable"
          switch_on_deauth: "no-op"
          update_user_device: "mac-cache"
          vlan_all_mode: "all"
          vlan_identity: "description"
          vlan_optimization: "prune"
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


def filter_switch_controller_global_data(json):
    option_list = [
        "allow_multiple_interfaces",
        "bounce_quarantined_link",
        "custom_command",
        "default_virtual_switch_vlan",
        "dhcp_option82_circuit_id",
        "dhcp_option82_format",
        "dhcp_option82_remote_id",
        "dhcp_server_access_list",
        "dhcp_snoop_client_db_exp",
        "dhcp_snoop_client_req",
        "dhcp_snoop_db_per_port_learn_limit",
        "disable_discovery",
        "fips_enforce",
        "firewall_auth_user_hold_period",
        "firmware_provision_on_authorization",
        "https_image_push",
        "log_mac_limit_violations",
        "mac_aging_interval",
        "mac_event_logging",
        "mac_retention_period",
        "mac_violation_timer",
        "quarantine_mode",
        "sn_dns_resolution",
        "switch_on_deauth",
        "update_user_device",
        "vlan_all_mode",
        "vlan_identity",
        "vlan_optimization",
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
        ["dhcp_option82_circuit_id"],
        ["dhcp_option82_remote_id"],
        ["update_user_device"],
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


def switch_controller_global(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    switch_controller_global_data = data["switch_controller_global"]

    filtered_data = filter_switch_controller_global_data(switch_controller_global_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("switch-controller", "global", filtered_data, vdom=vdom)
        current_data = fos.get("switch-controller", "global", vdom=vdom, mkey=mkey)
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
    data_copy["switch_controller_global"] = filtered_data
    fos.do_member_operation(
        "switch-controller",
        "global",
        data_copy,
    )

    return fos.set("switch-controller", "global", data=converted_data, vdom=vdom)


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

    if data["switch_controller_global"]:
        resp = switch_controller_global(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("switch_controller_global")
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
        "mac_aging_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "https_image_push": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vlan_all_mode": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "all"}, {"value": "defined"}],
        },
        "vlan_optimization": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "prune", "v_range": [["v7.6.1", ""]]},
                {"value": "configured", "v_range": [["v7.6.1", ""]]},
                {"value": "none", "v_range": [["v7.6.1", ""]]},
                {"value": "enable", "v_range": [["v6.2.0", "v7.6.0"]]},
                {"value": "disable", "v_range": [["v6.2.0", "v7.6.0"]]},
            ],
        },
        "vlan_identity": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "description"}, {"value": "name"}],
        },
        "disable_discovery": {
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
        "mac_retention_period": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "default_virtual_switch_vlan": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dhcp_server_access_list": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dhcp_option82_format": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "ascii"}, {"value": "legacy"}],
        },
        "dhcp_option82_circuit_id": {
            "v_range": [["v7.4.0", ""]],
            "type": "list",
            "options": [
                {"value": "intfname"},
                {"value": "vlan"},
                {"value": "hostname"},
                {"value": "mode"},
                {"value": "description"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "dhcp_option82_remote_id": {
            "v_range": [["v7.4.0", ""]],
            "type": "list",
            "options": [{"value": "mac"}, {"value": "hostname"}, {"value": "ip"}],
            "multiple_values": True,
            "elements": "str",
        },
        "dhcp_snoop_client_req": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "drop-untrusted"}, {"value": "forward-untrusted"}],
        },
        "dhcp_snoop_client_db_exp": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "dhcp_snoop_db_per_port_learn_limit": {
            "v_range": [["v7.4.0", ""]],
            "type": "integer",
        },
        "log_mac_limit_violations": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mac_violation_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "sn_dns_resolution": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mac_event_logging": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "bounce_quarantined_link": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "quarantine_mode": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "by-vlan"}, {"value": "by-redirect"}],
        },
        "update_user_device": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "list",
            "options": [
                {"value": "mac-cache"},
                {"value": "lldp"},
                {"value": "dhcp-snooping"},
                {"value": "l2-db"},
                {"value": "l3-db"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "custom_command": {
            "type": "list",
            "elements": "dict",
            "children": {
                "command_entry": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "command_name": {"v_range": [["v6.2.0", ""]], "type": "string"},
            },
            "v_range": [["v6.2.0", ""]],
        },
        "fips_enforce": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "firmware_provision_on_authorization": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "switch_on_deauth": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "no-op"}, {"value": "factory-reset"}],
        },
        "firewall_auth_user_hold_period": {
            "v_range": [["v7.6.4", ""]],
            "type": "integer",
        },
        "allow_multiple_interfaces": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "switch_controller_global": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["switch_controller_global"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_controller_global"]["options"][attribute_name][
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
            fos, versioned_schema, "switch_controller_global"
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
