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
module: fortios_extender_controller_extender_profile
short_description: FortiExtender extender profile configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify extender_controller feature and extender_profile category.
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
    extender_controller_extender_profile:
        description:
            - FortiExtender extender profile configuration.
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
            bandwidth_limit:
                description:
                    - FortiExtender LAN extension bandwidth limit (Mbps).
                type: int
            cellular:
                description:
                    - FortiExtender cellular configuration.
                type: dict
                suboptions:
                    controller_report:
                        description:
                            - FortiExtender controller report configuration.
                        type: dict
                        suboptions:
                            interval:
                                description:
                                    - Controller report interval.
                                type: int
                            signal_threshold:
                                description:
                                    - Controller report signal threshold.
                                type: int
                            status:
                                description:
                                    - FortiExtender controller report status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                    dataplan:
                        description:
                            - Dataplan names.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Dataplan name. Source extender-controller.dataplan.name.
                                required: true
                                type: str
                    modem1:
                        description:
                            - Configuration options for modem 1.
                        type: dict
                        suboptions:
                            auto_switch:
                                description:
                                    - FortiExtender auto switch configuration.
                                type: dict
                                suboptions:
                                    dataplan:
                                        description:
                                            - Automatically switch based on data usage.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect:
                                        description:
                                            - Auto switch by disconnect.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect_period:
                                        description:
                                            - Automatically switch based on disconnect period.
                                        type: int
                                    disconnect_threshold:
                                        description:
                                            - Automatically switch based on disconnect threshold.
                                        type: int
                                    signal:
                                        description:
                                            - Automatically switch based on signal strength.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    switch_back:
                                        description:
                                            - Auto switch with switch back multi-options.
                                        type: list
                                        elements: str
                                        choices:
                                            - 'time'
                                            - 'timer'
                                    switch_back_time:
                                        description:
                                            - 'Automatically switch over to preferred SIM/carrier at a specified time in UTC (HH:MM).'
                                        type: str
                                    switch_back_timer:
                                        description:
                                            - Automatically switch over to preferred SIM/carrier after the given time (3600 - 2147483647 sec).
                                        type: int
                            conn_status:
                                description:
                                    - Connection status.
                                type: int
                            default_sim:
                                description:
                                    - Default SIM selection.
                                type: str
                                choices:
                                    - 'sim1'
                                    - 'sim2'
                                    - 'carrier'
                                    - 'cost'
                            gps:
                                description:
                                    - FortiExtender GPS enable/disable.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            preferred_carrier:
                                description:
                                    - Preferred carrier.
                                type: str
                            redundant_intf:
                                description:
                                    - Redundant interface.
                                type: str
                            redundant_mode:
                                description:
                                    - FortiExtender mode.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1_pin:
                                description:
                                    - SIM #1 PIN status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1_pin_code:
                                description:
                                    - SIM #1 PIN password.
                                type: str
                            sim2_pin:
                                description:
                                    - SIM #2 PIN status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim2_pin_code:
                                description:
                                    - SIM #2 PIN password.
                                type: str
                    modem2:
                        description:
                            - Configuration options for modem 2.
                        type: dict
                        suboptions:
                            auto_switch:
                                description:
                                    - FortiExtender auto switch configuration.
                                type: dict
                                suboptions:
                                    dataplan:
                                        description:
                                            - Automatically switch based on data usage.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect:
                                        description:
                                            - Auto switch by disconnect.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect_period:
                                        description:
                                            - Automatically switch based on disconnect period.
                                        type: int
                                    disconnect_threshold:
                                        description:
                                            - Automatically switch based on disconnect threshold.
                                        type: int
                                    signal:
                                        description:
                                            - Automatically switch based on signal strength.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    switch_back:
                                        description:
                                            - Auto switch with switch back multi-options.
                                        type: list
                                        elements: str
                                        choices:
                                            - 'time'
                                            - 'timer'
                                    switch_back_time:
                                        description:
                                            - 'Automatically switch over to preferred SIM/carrier at a specified time in UTC (HH:MM).'
                                        type: str
                                    switch_back_timer:
                                        description:
                                            - Automatically switch over to preferred SIM/carrier after the given time (3600 - 2147483647 sec).
                                        type: int
                            conn_status:
                                description:
                                    - Connection status.
                                type: int
                            default_sim:
                                description:
                                    - Default SIM selection.
                                type: str
                                choices:
                                    - 'sim1'
                                    - 'sim2'
                                    - 'carrier'
                                    - 'cost'
                            gps:
                                description:
                                    - FortiExtender GPS enable/disable.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            preferred_carrier:
                                description:
                                    - Preferred carrier.
                                type: str
                            redundant_intf:
                                description:
                                    - Redundant interface.
                                type: str
                            redundant_mode:
                                description:
                                    - FortiExtender mode.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1_pin:
                                description:
                                    - SIM #1 PIN status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1_pin_code:
                                description:
                                    - SIM #1 PIN password.
                                type: str
                            sim2_pin:
                                description:
                                    - SIM #2 PIN status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim2_pin_code:
                                description:
                                    - SIM #2 PIN password.
                                type: str
                    sms_notification:
                        description:
                            - FortiExtender cellular SMS notification configuration.
                        type: dict
                        suboptions:
                            alert:
                                description:
                                    - SMS alert list.
                                type: dict
                                suboptions:
                                    data_exhausted:
                                        description:
                                            - Display string when data exhausted.
                                        type: str
                                    fgt_backup_mode_switch:
                                        description:
                                            - Display string when FortiGate backup mode switched.
                                        type: str
                                    low_signal_strength:
                                        description:
                                            - Display string when signal strength is low.
                                        type: str
                                    mode_switch:
                                        description:
                                            - Display string when mode is switched.
                                        type: str
                                    os_image_fallback:
                                        description:
                                            - Display string when falling back to a previous OS image.
                                        type: str
                                    session_disconnect:
                                        description:
                                            - Display string when session disconnected.
                                        type: str
                                    system_reboot:
                                        description:
                                            - Display string when system rebooted.
                                        type: str
                            receiver:
                                description:
                                    - SMS notification receiver list.
                                type: list
                                elements: dict
                                suboptions:
                                    alert:
                                        description:
                                            - Alert multi-options.
                                        type: list
                                        elements: str
                                        choices:
                                            - 'system-reboot'
                                            - 'data-exhausted'
                                            - 'session-disconnect'
                                            - 'low-signal-strength'
                                            - 'mode-switch'
                                            - 'os-image-fallback'
                                            - 'fgt-backup-mode-switch'
                                    name:
                                        description:
                                            - FortiExtender SMS notification receiver name.
                                        required: true
                                        type: str
                                    phone_number:
                                        description:
                                            - 'Receiver phone number. Format: [+][country code][area code][local phone number]. For example, +16501234567.'
                                        type: str
                                    status:
                                        description:
                                            - SMS notification receiver status.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                            status:
                                description:
                                    - FortiExtender SMS notification status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
            enforce_bandwidth:
                description:
                    - Enable/disable enforcement of bandwidth on LAN extension interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            extension:
                description:
                    - Extension option.
                type: str
                choices:
                    - 'wan-extension'
                    - 'lan-extension'
            id:
                description:
                    - ID.
                type: int
            lan_extension:
                description:
                    - FortiExtender lan extension configuration.
                type: dict
                suboptions:
                    backhaul:
                        description:
                            - LAN extension backhaul tunnel configuration.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - FortiExtender LAN extension backhaul name.
                                required: true
                                type: str
                            port:
                                description:
                                    - FortiExtender uplink port.
                                type: str
                                choices:
                                    - 'wan'
                                    - 'lte1'
                                    - 'lte2'
                                    - 'port1'
                                    - 'port2'
                                    - 'port3'
                                    - 'port4'
                                    - 'port5'
                                    - 'sfp'
                            role:
                                description:
                                    - FortiExtender uplink port.
                                type: str
                                choices:
                                    - 'primary'
                                    - 'secondary'
                            weight:
                                description:
                                    - WRR weight parameter.
                                type: int
                    backhaul_interface:
                        description:
                            - IPsec phase1 interface. Source system.interface.name.
                        type: str
                    backhaul_ip:
                        description:
                            - IPsec phase1 IPv4/FQDN. Used to specify the external IP/FQDN when the FortiGate unit is behind a NAT device.
                        type: str
                    ipsec_tunnel:
                        description:
                            - IPsec tunnel name.
                        type: str
                    link_loadbalance:
                        description:
                            - LAN extension link load balance strategy.
                        type: str
                        choices:
                            - 'activebackup'
                            - 'loadbalance'
            login_password:
                description:
                    - Set the managed extender"s administrator password.
                type: str
            login_password_change:
                description:
                    - Change or reset the administrator password of a managed extender (yes, default, or no).
                type: str
                choices:
                    - 'yes'
                    - 'default'
                    - 'no'
            model:
                description:
                    - Model.
                type: str
                choices:
                    - 'FX201E'
                    - 'FX211E'
                    - 'FX200F'
                    - 'FXA11F'
                    - 'FXE11F'
                    - 'FXA21F'
                    - 'FXE21F'
                    - 'FXA22F'
                    - 'FXE22F'
                    - 'FX212F'
                    - 'FX311F'
                    - 'FX312F'
                    - 'FX511F'
                    - 'FVG21F'
                    - 'FVA21F'
                    - 'FVG22F'
                    - 'FVA22F'
                    - 'FX04DA'
                    - 'FX04DN'
                    - 'FX04DI'
            name:
                description:
                    - FortiExtender profile name.
                required: true
                type: str
"""

EXAMPLES = """
- name: FortiExtender extender profile configuration.
  fortinet.fortios.fortios_extender_controller_extender_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      extender_controller_extender_profile:
          allowaccess: "ping"
          bandwidth_limit: "1024"
          cellular:
              controller_report:
                  interval: "300"
                  signal_threshold: "10"
                  status: "disable"
              dataplan:
                  -
                      name: "default_name_11 (source extender-controller.dataplan.name)"
              modem1:
                  auto_switch:
                      dataplan: "disable"
                      disconnect: "disable"
                      disconnect_period: "600"
                      disconnect_threshold: "3"
                      signal: "disable"
                      switch_back: "time"
                      switch_back_time: "<your_own_value>"
                      switch_back_timer: "86400"
                  conn_status: "0"
                  default_sim: "sim1"
                  gps: "disable"
                  preferred_carrier: "<your_own_value>"
                  redundant_intf: "<your_own_value>"
                  redundant_mode: "disable"
                  sim1_pin: "disable"
                  sim1_pin_code: "<your_own_value>"
                  sim2_pin: "disable"
                  sim2_pin_code: "<your_own_value>"
              modem2:
                  auto_switch:
                      dataplan: "disable"
                      disconnect: "disable"
                      disconnect_period: "600"
                      disconnect_threshold: "3"
                      signal: "disable"
                      switch_back: "time"
                      switch_back_time: "<your_own_value>"
                      switch_back_timer: "86400"
                  conn_status: "0"
                  default_sim: "sim1"
                  gps: "disable"
                  preferred_carrier: "<your_own_value>"
                  redundant_intf: "<your_own_value>"
                  redundant_mode: "disable"
                  sim1_pin: "disable"
                  sim1_pin_code: "<your_own_value>"
                  sim2_pin: "disable"
                  sim2_pin_code: "<your_own_value>"
              sms_notification:
                  alert:
                      data_exhausted: "<your_own_value>"
                      fgt_backup_mode_switch: "<your_own_value>"
                      low_signal_strength: "<your_own_value>"
                      mode_switch: "<your_own_value>"
                      os_image_fallback: "<your_own_value>"
                      session_disconnect: "<your_own_value>"
                      system_reboot: "<your_own_value>"
                  receiver:
                      -
                          alert: "system-reboot"
                          name: "default_name_63"
                          phone_number: "<your_own_value>"
                          status: "disable"
                  status: "disable"
          enforce_bandwidth: "enable"
          extension: "wan-extension"
          id: "69"
          lan_extension:
              backhaul:
                  -
                      name: "default_name_72"
                      port: "wan"
                      role: "primary"
                      weight: "1"
              backhaul_interface: "<your_own_value> (source system.interface.name)"
              backhaul_ip: "<your_own_value>"
              ipsec_tunnel: "<your_own_value>"
              link_loadbalance: "activebackup"
          login_password: "<your_own_value>"
          login_password_change: "yes"
          model: "FX201E"
          name: "default_name_83"
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


def filter_extender_controller_extender_profile_data(json):
    option_list = [
        "allowaccess",
        "bandwidth_limit",
        "cellular",
        "enforce_bandwidth",
        "extension",
        "id",
        "lan_extension",
        "login_password",
        "login_password_change",
        "model",
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
        ["allowaccess"],
        ["cellular", "sms_notification", "receiver", "alert"],
        ["cellular", "modem1", "auto_switch", "switch_back"],
        ["cellular", "modem2", "auto_switch", "switch_back"],
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


def extender_controller_extender_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    extender_controller_extender_profile_data = data[
        "extender_controller_extender_profile"
    ]

    filtered_data = filter_extender_controller_extender_profile_data(
        extender_controller_extender_profile_data
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
            "extender-controller", "extender-profile", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "extender-controller", "extender-profile", vdom=vdom, mkey=mkey
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
    data_copy["extender_controller_extender_profile"] = filtered_data
    fos.do_member_operation(
        "extender-controller",
        "extender-profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "extender-controller", "extender-profile", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "extender-controller",
            "extender-profile",
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


def fortios_extender_controller(data, fos, check_mode):

    if data["extender_controller_extender_profile"]:
        resp = extender_controller_extender_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("extender_controller_extender_profile")
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
        "name": {"v_range": [["v7.0.2", "v7.2.0"]], "type": "string", "required": True},
        "id": {"v_range": [["v7.0.2", "v7.2.0"]], "type": "integer"},
        "model": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "string",
            "options": [
                {"value": "FX201E"},
                {"value": "FX211E"},
                {"value": "FX200F"},
                {"value": "FXA11F"},
                {"value": "FXE11F"},
                {"value": "FXA21F"},
                {"value": "FXE21F"},
                {"value": "FXA22F"},
                {"value": "FXE22F"},
                {"value": "FX212F"},
                {"value": "FX311F"},
                {"value": "FX312F"},
                {"value": "FX511F"},
                {"value": "FVG21F"},
                {"value": "FVA21F"},
                {"value": "FVG22F"},
                {"value": "FVA22F"},
                {"value": "FX04DA"},
                {"value": "FX04DN", "v_range": [["v7.0.8", "v7.0.12"]]},
                {"value": "FX04DI", "v_range": [["v7.0.8", "v7.0.12"]]},
            ],
        },
        "extension": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "wan-extension"}, {"value": "lan-extension"}],
        },
        "allowaccess": {
            "v_range": [["v7.0.2", "v7.2.0"]],
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
        "login_password_change": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "yes"}, {"value": "default"}, {"value": "no"}],
        },
        "login_password": {"v_range": [["v7.0.2", "v7.2.0"]], "type": "string"},
        "enforce_bandwidth": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "bandwidth_limit": {"v_range": [["v7.0.2", "v7.2.0"]], "type": "integer"},
        "cellular": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "dict",
            "children": {
                "dataplan": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.0.2", "v7.2.0"]],
                },
                "controller_report": {
                    "v_range": [["v7.0.2", "v7.2.0"]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "interval": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "integer",
                        },
                        "signal_threshold": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "integer",
                        },
                    },
                },
                "sms_notification": {
                    "v_range": [["v7.0.2", "v7.2.0"]],
                    "type": "dict",
                    "children": {
                        "status": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "alert": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "dict",
                            "children": {
                                "system_reboot": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                },
                                "data_exhausted": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                },
                                "session_disconnect": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                },
                                "low_signal_strength": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                },
                                "os_image_fallback": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                },
                                "mode_switch": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                },
                                "fgt_backup_mode_switch": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                },
                            },
                        },
                        "receiver": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "name": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                    "required": True,
                                },
                                "status": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                    "options": [
                                        {"value": "disable"},
                                        {"value": "enable"},
                                    ],
                                },
                                "phone_number": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                },
                                "alert": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "list",
                                    "options": [
                                        {"value": "system-reboot"},
                                        {"value": "data-exhausted"},
                                        {"value": "session-disconnect"},
                                        {"value": "low-signal-strength"},
                                        {"value": "mode-switch"},
                                        {"value": "os-image-fallback"},
                                        {"value": "fgt-backup-mode-switch"},
                                    ],
                                    "multiple_values": True,
                                    "elements": "str",
                                },
                            },
                            "v_range": [["v7.0.2", "v7.2.0"]],
                        },
                    },
                },
                "modem1": {
                    "v_range": [["v7.0.2", "v7.2.0"]],
                    "type": "dict",
                    "children": {
                        "redundant_mode": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "redundant_intf": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                        },
                        "conn_status": {
                            "v_range": [["v7.0.2", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                            "type": "integer",
                        },
                        "default_sim": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [
                                {"value": "sim1"},
                                {"value": "sim2"},
                                {"value": "carrier"},
                                {"value": "cost"},
                            ],
                        },
                        "gps": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "sim1_pin": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "sim2_pin": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "sim1_pin_code": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                        },
                        "sim2_pin_code": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                        },
                        "preferred_carrier": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                        },
                        "auto_switch": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "dict",
                            "children": {
                                "disconnect": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                    "options": [
                                        {"value": "disable"},
                                        {"value": "enable"},
                                    ],
                                },
                                "disconnect_threshold": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "integer",
                                },
                                "disconnect_period": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "integer",
                                },
                                "signal": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                    "options": [
                                        {"value": "disable"},
                                        {"value": "enable"},
                                    ],
                                },
                                "dataplan": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                    "options": [
                                        {"value": "disable"},
                                        {"value": "enable"},
                                    ],
                                },
                                "switch_back": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "list",
                                    "options": [{"value": "time"}, {"value": "timer"}],
                                    "multiple_values": True,
                                    "elements": "str",
                                },
                                "switch_back_time": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                },
                                "switch_back_timer": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "integer",
                                },
                            },
                        },
                    },
                },
                "modem2": {
                    "v_range": [["v7.0.2", "v7.2.0"]],
                    "type": "dict",
                    "children": {
                        "redundant_mode": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "redundant_intf": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                        },
                        "conn_status": {
                            "v_range": [["v7.0.2", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                            "type": "integer",
                        },
                        "default_sim": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [
                                {"value": "sim1"},
                                {"value": "sim2"},
                                {"value": "carrier"},
                                {"value": "cost"},
                            ],
                        },
                        "gps": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "sim1_pin": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "sim2_pin": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "sim1_pin_code": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                        },
                        "sim2_pin_code": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                        },
                        "preferred_carrier": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                        },
                        "auto_switch": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "dict",
                            "children": {
                                "disconnect": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                    "options": [
                                        {"value": "disable"},
                                        {"value": "enable"},
                                    ],
                                },
                                "disconnect_threshold": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "integer",
                                },
                                "disconnect_period": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "integer",
                                },
                                "signal": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                    "options": [
                                        {"value": "disable"},
                                        {"value": "enable"},
                                    ],
                                },
                                "dataplan": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                    "options": [
                                        {"value": "disable"},
                                        {"value": "enable"},
                                    ],
                                },
                                "switch_back": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "list",
                                    "options": [{"value": "time"}, {"value": "timer"}],
                                    "multiple_values": True,
                                    "elements": "str",
                                },
                                "switch_back_time": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "string",
                                },
                                "switch_back_timer": {
                                    "v_range": [["v7.0.2", "v7.2.0"]],
                                    "type": "integer",
                                },
                            },
                        },
                    },
                },
            },
        },
        "lan_extension": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "dict",
            "children": {
                "link_loadbalance": {
                    "v_range": [["v7.0.2", "v7.2.0"]],
                    "type": "string",
                    "options": [{"value": "activebackup"}, {"value": "loadbalance"}],
                },
                "ipsec_tunnel": {"v_range": [["v7.0.2", "v7.2.0"]], "type": "string"},
                "backhaul_interface": {
                    "v_range": [["v7.0.2", "v7.2.0"]],
                    "type": "string",
                },
                "backhaul_ip": {"v_range": [["v7.0.2", "v7.2.0"]], "type": "string"},
                "backhaul": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "required": True,
                        },
                        "port": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [
                                {"value": "wan"},
                                {"value": "lte1"},
                                {"value": "lte2"},
                                {"value": "port1"},
                                {"value": "port2"},
                                {"value": "port3"},
                                {"value": "port4"},
                                {"value": "port5"},
                                {"value": "sfp"},
                            ],
                        },
                        "role": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "string",
                            "options": [{"value": "primary"}, {"value": "secondary"}],
                        },
                        "weight": {
                            "v_range": [["v7.0.2", "v7.2.0"]],
                            "type": "integer",
                        },
                    },
                    "v_range": [["v7.0.2", "v7.2.0"]],
                },
            },
        },
    },
    "v_range": [["v7.0.2", "v7.2.0"]],
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
        "extender_controller_extender_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["extender_controller_extender_profile"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["extender_controller_extender_profile"]["options"][attribute_name][
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
            fos, versioned_schema, "extender_controller_extender_profile"
        )

        is_error, has_changed, result, diff = fortios_extender_controller(
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
