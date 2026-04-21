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
module: fortios_wireless_controller_global
short_description: Configure wireless controller global settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and global category.
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

    wireless_controller_global:
        description:
            - Configure wireless controller global settings.
        default: null
        type: dict
        suboptions:
            acd_process_count:
                description:
                    - Configure the number cw_acd daemons for multi-core CPU support .
                type: int
            ap_log_server:
                description:
                    - Enable/disable configuring FortiGate to redirect wireless event log messages or FortiAPs to send UTM log messages to a syslog server .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ap_log_server_ip:
                description:
                    - IP address that FortiGate or FortiAPs send log messages to.
                type: str
            ap_log_server_port:
                description:
                    - Port that FortiGate or FortiAPs send log messages to.
                type: int
            control_message_offload:
                description:
                    - Configure CAPWAP control message data channel offload.
                type: list
                elements: str
                choices:
                    - 'ebp-frame'
                    - 'aeroscout-tag'
                    - 'ap-list'
                    - 'sta-list'
                    - 'sta-cap-list'
                    - 'stats'
                    - 'aeroscout-mu'
                    - 'sta-health'
                    - 'spectral-analysis'
            data_ethernet_II:
                description:
                    - Configure the wireless controller to use Ethernet II or 802.3 frames with 802.3 data tunnel mode .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dfs_lab_test:
                description:
                    - Enable/disable DFS certificate lab test mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            discovery_mc_addr:
                description:
                    - Multicast IP address for AP discovery .
                type: str
            fiapp_eth_type:
                description:
                    - Ethernet type for Fortinet Inter-Access Point Protocol (IAPP), or IEEE 802.11f, packets (0 - 65535).
                type: int
            image_download:
                description:
                    - Enable/disable WTP image download at join time.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipsec_base_ip:
                description:
                    - Base IP address for IPsec VPN tunnels between the access points and the wireless controller .
                type: str
            link_aggregation:
                description:
                    - Enable/disable calculating the CAPWAP transmit hash to load balance sessions to link aggregation nodes .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            location:
                description:
                    - Description of the location of the wireless controller.
                type: str
            max_ble_device:
                description:
                    - Maximum number of BLE devices stored on the controller .
                type: int
            max_clients:
                description:
                    - Maximum number of clients that can connect simultaneously .
                type: int
            max_retransmit:
                description:
                    - Maximum number of tunnel packet retransmissions (0 - 64).
                type: int
            max_rogue_ap:
                description:
                    - Maximum number of rogue APs stored on the controller .
                type: int
            max_rogue_ap_wtp:
                description:
                    - Maximum number of rogue AP"s wtp info stored on the controller (1 - 16).
                type: int
            max_rogue_sta:
                description:
                    - Maximum number of rogue stations stored on the controller .
                type: int
            max_sta_cap:
                description:
                    - Maximum number of station cap stored on the controller .
                type: int
            max_sta_cap_wtp:
                description:
                    - Maximum number of station cap"s wtp info stored on the controller (1 - 16).
                type: int
            max_sta_offline:
                description:
                    - Maximum number of station offline stored on the controller .
                type: int
            max_sta_offline_ip2mac:
                description:
                    - Maximum number of station offline ip2mac stored on the controller .
                type: int
            max_wids_entry:
                description:
                    - Maximum number of wids entries stored on the controller .
                type: int
            mesh_eth_type:
                description:
                    - Mesh Ethernet identifier included in backhaul packets (0 - 65535).
                type: int
            nac_interval:
                description:
                    - Interval in seconds between two WiFi network access control (NAC) checks (10 - 600).
                type: int
            name:
                description:
                    - Name of the wireless controller.
                type: str
            rogue_scan_mac_adjacency:
                description:
                    - Maximum numerical difference between an AP"s Ethernet and wireless MAC values to match for rogue detection (0 - 31).
                type: int
            rolling_wtp_upgrade:
                description:
                    - Enable/disable rolling WTP upgrade .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rolling_wtp_upgrade_threshold:
                description:
                    - Minimum signal level/threshold in dBm required for the managed WTP to be included in rolling WTP upgrade (-95 to -20).
                type: str
            tunnel_mode:
                description:
                    - Compatible/strict tunnel mode.
                type: str
                choices:
                    - 'compatible'
                    - 'strict'
            wpad_process_count:
                description:
                    - Wpad daemon process count for multi-core CPU support.
                type: int
            wtp_share:
                description:
                    - Enable/disable sharing of WTPs between VDOMs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure wireless controller global settings.
  fortinet.fortios.fortios_wireless_controller_global:
      vdom: "{{ vdom }}"
      wireless_controller_global:
          acd_process_count: "0"
          ap_log_server: "enable"
          ap_log_server_ip: "<your_own_value>"
          ap_log_server_port: "0"
          control_message_offload: "ebp-frame"
          data_ethernet_II: "enable"
          dfs_lab_test: "enable"
          discovery_mc_addr: "<your_own_value>"
          fiapp_eth_type: "5252"
          image_download: "enable"
          ipsec_base_ip: "<your_own_value>"
          link_aggregation: "enable"
          location: "<your_own_value>"
          max_ble_device: "0"
          max_clients: "0"
          max_retransmit: "3"
          max_rogue_ap: "0"
          max_rogue_ap_wtp: "16"
          max_rogue_sta: "0"
          max_sta_cap: "0"
          max_sta_cap_wtp: "8"
          max_sta_offline: "0"
          max_sta_offline_ip2mac: "0"
          max_wids_entry: "0"
          mesh_eth_type: "8755"
          nac_interval: "120"
          name: "default_name_29"
          rogue_scan_mac_adjacency: "7"
          rolling_wtp_upgrade: "enable"
          rolling_wtp_upgrade_threshold: "<your_own_value>"
          tunnel_mode: "compatible"
          wpad_process_count: "0"
          wtp_share: "enable"
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


def filter_wireless_controller_global_data(json):
    option_list = [
        "acd_process_count",
        "ap_log_server",
        "ap_log_server_ip",
        "ap_log_server_port",
        "control_message_offload",
        "data_ethernet_II",
        "dfs_lab_test",
        "discovery_mc_addr",
        "fiapp_eth_type",
        "image_download",
        "ipsec_base_ip",
        "link_aggregation",
        "location",
        "max_ble_device",
        "max_clients",
        "max_retransmit",
        "max_rogue_ap",
        "max_rogue_ap_wtp",
        "max_rogue_sta",
        "max_sta_cap",
        "max_sta_cap_wtp",
        "max_sta_offline",
        "max_sta_offline_ip2mac",
        "max_wids_entry",
        "mesh_eth_type",
        "nac_interval",
        "name",
        "rogue_scan_mac_adjacency",
        "rolling_wtp_upgrade",
        "rolling_wtp_upgrade_threshold",
        "tunnel_mode",
        "wpad_process_count",
        "wtp_share",
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
        ["control_message_offload"],
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


def wireless_controller_global(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    wireless_controller_global_data = data["wireless_controller_global"]

    filtered_data = filter_wireless_controller_global_data(
        wireless_controller_global_data
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
        mkey = fos.get_mkey("wireless-controller", "global", filtered_data, vdom=vdom)
        current_data = fos.get("wireless-controller", "global", vdom=vdom, mkey=mkey)
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
    data_copy["wireless_controller_global"] = filtered_data
    fos.do_member_operation(
        "wireless-controller",
        "global",
        data_copy,
    )

    return fos.set("wireless-controller", "global", data=converted_data, vdom=vdom)


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


def fortios_wireless_controller(data, fos, check_mode):

    if data["wireless_controller_global"]:
        resp = wireless_controller_global(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("wireless_controller_global")
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
        "name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "location": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "acd_process_count": {"v_range": [["v7.2.4", ""]], "type": "integer"},
        "wpad_process_count": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "image_download": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rolling_wtp_upgrade": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rolling_wtp_upgrade_threshold": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
        },
        "max_retransmit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "control_message_offload": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "ebp-frame"},
                {"value": "aeroscout-tag"},
                {"value": "ap-list"},
                {"value": "sta-list"},
                {"value": "sta-cap-list"},
                {"value": "stats"},
                {"value": "aeroscout-mu"},
                {"value": "sta-health", "v_range": [["v6.2.0", ""]]},
                {"value": "spectral-analysis", "v_range": [["v6.4.0", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "data_ethernet_II": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "link_aggregation": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mesh_eth_type": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "fiapp_eth_type": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "discovery_mc_addr": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "max_clients": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "rogue_scan_mac_adjacency": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ipsec_base_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "wtp_share": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tunnel_mode": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "compatible"}, {"value": "strict"}],
        },
        "nac_interval": {"v_range": [["v7.0.2", ""]], "type": "integer"},
        "ap_log_server": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ap_log_server_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ap_log_server_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "max_sta_offline": {"v_range": [["v7.6.3", ""]], "type": "integer"},
        "max_sta_offline_ip2mac": {"v_range": [["v7.6.3", ""]], "type": "integer"},
        "max_sta_cap": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "max_sta_cap_wtp": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "max_rogue_ap": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "max_rogue_ap_wtp": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "max_rogue_sta": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "max_wids_entry": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "max_ble_device": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "dfs_lab_test": {
            "v_range": [["v7.0.12", "v7.0.12"], ["v7.2.1", ""]],
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
        "wireless_controller_global": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_global"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_global"]["options"][attribute_name][
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
            fos, versioned_schema, "wireless_controller_global"
        )

        is_error, has_changed, result, diff = fortios_wireless_controller(
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
