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
module: fortios_wireless_controller_timers
short_description: Configure CAPWAP timers in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and timers category.
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

    wireless_controller_timers:
        description:
            - Configure CAPWAP timers.
        default: null
        type: dict
        suboptions:
            ap_reboot_wait_interval1:
                description:
                    - Time in minutes to wait before AP reboots when there is no controller detected (5 - 65535).
                type: int
            ap_reboot_wait_interval2:
                description:
                    - Time in minutes to wait before AP reboots when there is no controller detected and standalone SSIDs are pushed to the AP in the previous
                       session (5 - 65535).
                type: int
            ap_reboot_wait_time:
                description:
                    - 'Time to reboot the AP when there is no controller detected and standalone SSIDs are pushed to the AP in the previous session, format hh
                      :mm.'
                type: str
            auth_timeout:
                description:
                    - Time after which a client is considered failed in RADIUS authentication and times out (5 - 30 sec).
                type: int
            ble_device_cleanup:
                description:
                    - Time period in minutes to keep BLE device after it is gone .
                type: int
            ble_scan_report_intv:
                description:
                    - Time between running Bluetooth Low Energy (BLE) reports (10 - 3600 sec).
                type: int
            client_idle_rehome_timeout:
                description:
                    - Time after which a client is considered idle and disconnected from the home controller (2 - 3600 sec).
                type: int
            client_idle_timeout:
                description:
                    - Time after which a client is considered idle and times out (20 - 3600 sec).
                type: int
            darrp_day:
                description:
                    - Weekday on which to run DARRP optimization.
                type: str
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
            darrp_optimize:
                description:
                    - Time for running Dynamic Automatic Radio Resource Provisioning (DARRP) optimizations (0 - 86400 sec).
                type: int
            darrp_time:
                description:
                    - Time at which DARRP optimizations run (you can add up to 8 times).
                type: list
                elements: dict
                suboptions:
                    time:
                        description:
                            - Time.
                        required: true
                        type: str
            discovery_interval:
                description:
                    - Time between discovery requests (2 - 180 sec).
                type: int
            drma_interval:
                description:
                    - Dynamic radio mode assignment (DRMA) schedule interval in minutes (1 - 1440).
                type: int
            echo_interval:
                description:
                    - Time between echo requests sent by the managed WTP, AP, or FortiAP (1 - 255 sec).
                type: int
            fake_ap_log:
                description:
                    - Time between recording logs about fake APs if periodic fake AP logging is configured (1 - 1440 min).
                type: int
            ipsec_intf_cleanup:
                description:
                    - Time period to keep IPsec VPN interfaces up after WTP sessions are disconnected (30 - 3600 sec).
                type: int
            nat_session_keep_alive:
                description:
                    - Maximal time in seconds between control requests sent by the managed WTP, AP, or FortiAP (0 - 255 sec).
                type: int
            radio_stats_interval:
                description:
                    - Time between running radio reports (1 - 255 sec).
                type: int
            rogue_ap_cleanup:
                description:
                    - Time period in minutes to keep rogue AP after it is gone .
                type: int
            rogue_ap_log:
                description:
                    - Time between logging rogue AP messages if periodic rogue AP logging is configured (0 - 1440 min).
                type: int
            rogue_sta_cleanup:
                description:
                    - Time period in minutes to keep rogue station after it is gone .
                type: int
            sta_cap_cleanup:
                description:
                    - Time period in minutes to keep station capability data after it is gone .
                type: int
            sta_capability_interval:
                description:
                    - Time between running station capability reports (1 - 255 sec).
                type: int
            sta_locate_timer:
                description:
                    - Time between running client presence flushes to remove clients that are listed but no longer present (0 - 86400 sec).
                type: int
            sta_offline_cleanup:
                description:
                    - Time period in seconds to keep station offline data after it is gone .
                type: int
            sta_offline_ip2mac_cleanup:
                description:
                    - Time period in seconds to keep station offline Ip2mac data after it is gone .
                type: int
            sta_stats_interval:
                description:
                    - Time between running client (station) reports (1 - 255 sec).
                type: int
            vap_stats_interval:
                description:
                    - Time between running Virtual Access Point (VAP) reports (1 - 255 sec).
                type: int
            wids_entry_cleanup:
                description:
                    - Time period in minutes to keep wids entry after it is gone .
                type: int
"""

EXAMPLES = """
- name: Configure CAPWAP timers.
  fortinet.fortios.fortios_wireless_controller_timers:
      vdom: "{{ vdom }}"
      wireless_controller_timers:
          ap_reboot_wait_interval1: "0"
          ap_reboot_wait_interval2: "0"
          ap_reboot_wait_time: "<your_own_value>"
          auth_timeout: "5"
          ble_device_cleanup: "60"
          ble_scan_report_intv: "30"
          client_idle_rehome_timeout: "20"
          client_idle_timeout: "300"
          darrp_day: "sunday"
          darrp_optimize: "43200"
          darrp_time:
              -
                  time: "<your_own_value>"
          discovery_interval: "5"
          drma_interval: "60"
          echo_interval: "30"
          fake_ap_log: "1"
          ipsec_intf_cleanup: "120"
          nat_session_keep_alive: "0"
          radio_stats_interval: "15"
          rogue_ap_cleanup: "0"
          rogue_ap_log: "0"
          rogue_sta_cleanup: "0"
          sta_cap_cleanup: "0"
          sta_capability_interval: "30"
          sta_locate_timer: "1800"
          sta_offline_cleanup: "300"
          sta_offline_ip2mac_cleanup: "300"
          sta_stats_interval: "10"
          vap_stats_interval: "15"
          wids_entry_cleanup: "0"
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


def filter_wireless_controller_timers_data(json):
    option_list = [
        "ap_reboot_wait_interval1",
        "ap_reboot_wait_interval2",
        "ap_reboot_wait_time",
        "auth_timeout",
        "ble_device_cleanup",
        "ble_scan_report_intv",
        "client_idle_rehome_timeout",
        "client_idle_timeout",
        "darrp_day",
        "darrp_optimize",
        "darrp_time",
        "discovery_interval",
        "drma_interval",
        "echo_interval",
        "fake_ap_log",
        "ipsec_intf_cleanup",
        "nat_session_keep_alive",
        "radio_stats_interval",
        "rogue_ap_cleanup",
        "rogue_ap_log",
        "rogue_sta_cleanup",
        "sta_cap_cleanup",
        "sta_capability_interval",
        "sta_locate_timer",
        "sta_offline_cleanup",
        "sta_offline_ip2mac_cleanup",
        "sta_stats_interval",
        "vap_stats_interval",
        "wids_entry_cleanup",
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


def wireless_controller_timers(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    wireless_controller_timers_data = data["wireless_controller_timers"]

    filtered_data = filter_wireless_controller_timers_data(
        wireless_controller_timers_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("wireless-controller", "timers", filtered_data, vdom=vdom)
        current_data = fos.get("wireless-controller", "timers", vdom=vdom, mkey=mkey)
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
    data_copy["wireless_controller_timers"] = filtered_data
    fos.do_member_operation(
        "wireless-controller",
        "timers",
        data_copy,
    )

    return fos.set("wireless-controller", "timers", data=converted_data, vdom=vdom)


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

    if data["wireless_controller_timers"]:
        resp = wireless_controller_timers(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("wireless_controller_timers")
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
        "echo_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "nat_session_keep_alive": {"v_range": [["v7.4.2", ""]], "type": "integer"},
        "discovery_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "client_idle_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "client_idle_rehome_timeout": {"v_range": [["v7.2.0", ""]], "type": "integer"},
        "auth_timeout": {"v_range": [["v7.0.6", ""]], "type": "integer"},
        "rogue_ap_log": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "fake_ap_log": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "sta_offline_cleanup": {"v_range": [["v7.6.3", ""]], "type": "integer"},
        "sta_offline_ip2mac_cleanup": {"v_range": [["v7.6.3", ""]], "type": "integer"},
        "sta_cap_cleanup": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "rogue_ap_cleanup": {"v_range": [["v7.0.6", ""]], "type": "integer"},
        "rogue_sta_cleanup": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "wids_entry_cleanup": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "ble_device_cleanup": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "sta_stats_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "vap_stats_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "radio_stats_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "sta_capability_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "sta_locate_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ipsec_intf_cleanup": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ble_scan_report_intv": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "drma_interval": {"v_range": [["v6.4.4", ""]], "type": "integer"},
        "ap_reboot_wait_interval1": {"v_range": [["v7.4.2", ""]], "type": "integer"},
        "ap_reboot_wait_time": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "ap_reboot_wait_interval2": {"v_range": [["v7.4.2", ""]], "type": "integer"},
        "darrp_optimize": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "integer"},
        "darrp_day": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [
                {"value": "sunday"},
                {"value": "monday"},
                {"value": "tuesday"},
                {"value": "wednesday"},
                {"value": "thursday"},
                {"value": "friday"},
                {"value": "saturday"},
            ],
        },
        "darrp_time": {
            "type": "list",
            "elements": "dict",
            "children": {
                "time": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "required": True,
                }
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
        "wireless_controller_timers": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_timers"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_timers"]["options"][attribute_name][
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
            fos, versioned_schema, "wireless_controller_timers"
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
