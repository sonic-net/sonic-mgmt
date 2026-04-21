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
module: fortios_extender_controller_extender
short_description: Extender controller configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify extender_controller feature and extender category.
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
    extender_controller_extender:
        description:
            - Extender controller configuration.
        default: null
        type: dict
        suboptions:
            aaa_shared_secret:
                description:
                    - AAA shared secret.
                type: str
            access_point_name:
                description:
                    - Access point name(APN).
                type: str
            admin:
                description:
                    - FortiExtender Administration (enable or disable).
                type: str
                choices:
                    - 'disable'
                    - 'discovered'
                    - 'enable'
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
            at_dial_script:
                description:
                    - Initialization AT commands specific to the MODEM.
                type: str
            authorized:
                description:
                    - FortiExtender Administration (enable or disable).
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            bandwidth_limit:
                description:
                    - FortiExtender LAN extension bandwidth limit (Mbps).
                type: int
            billing_start_day:
                description:
                    - Billing start day.
                type: int
            cdma_aaa_spi:
                description:
                    - CDMA AAA SPI.
                type: str
            cdma_ha_spi:
                description:
                    - CDMA HA SPI.
                type: str
            cdma_nai:
                description:
                    - NAI for CDMA MODEMS.
                type: str
            conn_status:
                description:
                    - Connection status.
                type: int
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
            description:
                description:
                    - Description.
                type: str
            device_id:
                description:
                    - Device ID.
                type: int
            dial_mode:
                description:
                    - Dial mode (dial-on-demand or always-connect).
                type: str
                choices:
                    - 'dial-on-demand'
                    - 'always-connect'
            dial_status:
                description:
                    - Dial status.
                type: int
            enforce_bandwidth:
                description:
                    - Enable/disable enforcement of bandwidth on LAN extension interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ext_name:
                description:
                    - FortiExtender name.
                type: str
            extension_type:
                description:
                    - Extension type for this FortiExtender.
                type: str
                choices:
                    - 'wan-extension'
                    - 'lan-extension'
            ha_shared_secret:
                description:
                    - HA shared secret.
                type: str
            id:
                description:
                    - FortiExtender serial number.
                type: str
            ifname:
                description:
                    - FortiExtender interface name. Source system.interface.name.
                type: str
            initiated_update:
                description:
                    - Allow/disallow network initiated updates to the MODEM.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
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
            mode:
                description:
                    - FortiExtender mode.
                type: str
                choices:
                    - 'standalone'
                    - 'redundant'
            modem_passwd:
                description:
                    - MODEM password.
                type: str
            modem_type:
                description:
                    - MODEM type (CDMA, GSM/LTE or WIMAX).
                type: str
                choices:
                    - 'cdma'
                    - 'gsm/lte'
                    - 'wimax'
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
                    ifname:
                        description:
                            - FortiExtender interface name. Source system.interface.name.
                        type: str
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
                    ifname:
                        description:
                            - FortiExtender interface name. Source system.interface.name.
                        type: str
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
            multi_mode:
                description:
                    - MODEM mode of operation(3G,LTE,etc).
                type: str
                choices:
                    - 'auto'
                    - 'auto-3g'
                    - 'force-lte'
                    - 'force-3g'
                    - 'force-2g'
            name:
                description:
                    - FortiExtender entry name.
                required: true
                type: str
            override_allowaccess:
                description:
                    - Enable to override the extender profile management access configuration.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            override_enforce_bandwidth:
                description:
                    - Enable to override the extender profile enforce-bandwidth setting.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            override_login_password_change:
                description:
                    - Enable to override the extender profile login-password (administrator password) setting.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ppp_auth_protocol:
                description:
                    - PPP authentication protocol (PAP,CHAP or auto).
                type: str
                choices:
                    - 'auto'
                    - 'pap'
                    - 'chap'
            ppp_echo_request:
                description:
                    - Enable/disable PPP echo request.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ppp_password:
                description:
                    - PPP password.
                type: str
            ppp_username:
                description:
                    - PPP username.
                type: str
            primary_ha:
                description:
                    - Primary HA.
                type: str
            profile:
                description:
                    - FortiExtender profile configuration. Source extender-controller.extender-profile.name.
                type: str
            quota_limit_mb:
                description:
                    - Monthly quota limit (MB).
                type: int
            redial:
                description:
                    - Number of redials allowed based on failed attempts.
                type: str
                choices:
                    - 'none'
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
                    - '6'
                    - '7'
                    - '8'
                    - '9'
                    - '10'
            redundant_intf:
                description:
                    - Redundant interface.
                type: str
            roaming:
                description:
                    - Enable/disable MODEM roaming.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            role:
                description:
                    - FortiExtender work role(Primary, Secondary, None).
                type: str
                choices:
                    - 'none'
                    - 'primary'
                    - 'secondary'
            secondary_ha:
                description:
                    - Secondary HA.
                type: str
            sim_pin:
                description:
                    - SIM PIN.
                type: str
            vdom:
                description:
                    - VDOM.
                type: int
            wan_extension:
                description:
                    - FortiExtender wan extension configuration.
                type: dict
                suboptions:
                    modem1_extension:
                        description:
                            - FortiExtender interface name. Source system.interface.name.
                        type: str
                    modem2_extension:
                        description:
                            - FortiExtender interface name. Source system.interface.name.
                        type: str
            wimax_auth_protocol:
                description:
                    - WiMax authentication protocol(TLS or TTLS).
                type: str
                choices:
                    - 'tls'
                    - 'ttls'
            wimax_carrier:
                description:
                    - WiMax carrier.
                type: str
            wimax_realm:
                description:
                    - WiMax realm.
                type: str
"""

EXAMPLES = """
- name: Extender controller configuration.
  fortinet.fortios.fortios_extender_controller_extender:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      extender_controller_extender:
          aaa_shared_secret: "<your_own_value>"
          access_point_name: "<your_own_value>"
          admin: "disable"
          allowaccess: "ping"
          at_dial_script: "<your_own_value>"
          authorized: "disable"
          bandwidth_limit: "1024"
          billing_start_day: "14"
          cdma_aaa_spi: "<your_own_value>"
          cdma_ha_spi: "<your_own_value>"
          cdma_nai: "<your_own_value>"
          conn_status: "2147483647"
          controller_report:
              interval: "300"
              signal_threshold: "10"
              status: "disable"
          description: "<your_own_value>"
          device_id: "1024"
          dial_mode: "dial-on-demand"
          dial_status: "2147483647"
          enforce_bandwidth: "enable"
          ext_name: "<your_own_value>"
          extension_type: "wan-extension"
          ha_shared_secret: "<your_own_value>"
          id: "27"
          ifname: "<your_own_value> (source system.interface.name)"
          initiated_update: "enable"
          login_password: "<your_own_value>"
          login_password_change: "yes"
          mode: "standalone"
          modem_passwd: "<your_own_value>"
          modem_type: "cdma"
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
              ifname: "<your_own_value> (source system.interface.name)"
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
              ifname: "<your_own_value> (source system.interface.name)"
              preferred_carrier: "<your_own_value>"
              redundant_intf: "<your_own_value>"
              redundant_mode: "disable"
              sim1_pin: "disable"
              sim1_pin_code: "<your_own_value>"
              sim2_pin: "disable"
              sim2_pin_code: "<your_own_value>"
          multi_mode: "auto"
          name: "default_name_78"
          override_allowaccess: "enable"
          override_enforce_bandwidth: "enable"
          override_login_password_change: "enable"
          ppp_auth_protocol: "auto"
          ppp_echo_request: "enable"
          ppp_password: "<your_own_value>"
          ppp_username: "<your_own_value>"
          primary_ha: "<your_own_value>"
          profile: "<your_own_value> (source extender-controller.extender-profile.name)"
          quota_limit_mb: "5242880"
          redial: "none"
          redundant_intf: "<your_own_value>"
          roaming: "enable"
          role: "none"
          secondary_ha: "<your_own_value>"
          sim_pin: "<your_own_value>"
          vdom: "0"
          wan_extension:
              modem1_extension: "<your_own_value> (source system.interface.name)"
              modem2_extension: "<your_own_value> (source system.interface.name)"
          wimax_auth_protocol: "tls"
          wimax_carrier: "<your_own_value>"
          wimax_realm: "<your_own_value>"
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


def filter_extender_controller_extender_data(json):
    option_list = [
        "aaa_shared_secret",
        "access_point_name",
        "admin",
        "allowaccess",
        "at_dial_script",
        "authorized",
        "bandwidth_limit",
        "billing_start_day",
        "cdma_aaa_spi",
        "cdma_ha_spi",
        "cdma_nai",
        "conn_status",
        "controller_report",
        "description",
        "device_id",
        "dial_mode",
        "dial_status",
        "enforce_bandwidth",
        "ext_name",
        "extension_type",
        "ha_shared_secret",
        "id",
        "ifname",
        "initiated_update",
        "login_password",
        "login_password_change",
        "mode",
        "modem_passwd",
        "modem_type",
        "modem1",
        "modem2",
        "multi_mode",
        "name",
        "override_allowaccess",
        "override_enforce_bandwidth",
        "override_login_password_change",
        "ppp_auth_protocol",
        "ppp_echo_request",
        "ppp_password",
        "ppp_username",
        "primary_ha",
        "profile",
        "quota_limit_mb",
        "redial",
        "redundant_intf",
        "roaming",
        "role",
        "secondary_ha",
        "sim_pin",
        "vdom",
        "wan_extension",
        "wimax_auth_protocol",
        "wimax_carrier",
        "wimax_realm",
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
        ["modem1", "auto_switch", "switch_back"],
        ["modem2", "auto_switch", "switch_back"],
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


def extender_controller_extender(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    extender_controller_extender_data = data["extender_controller_extender"]

    filtered_data = filter_extender_controller_extender_data(
        extender_controller_extender_data
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
        mkey = fos.get_mkey("extender-controller", "extender", filtered_data, vdom=vdom)
        current_data = fos.get("extender-controller", "extender", vdom=vdom, mkey=mkey)
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
    data_copy["extender_controller_extender"] = filtered_data
    fos.do_member_operation(
        "extender-controller",
        "extender",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "extender-controller", "extender", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "extender-controller", "extender", mkey=converted_data["name"], vdom=vdom
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

    if data["extender_controller_extender"]:
        resp = extender_controller_extender(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("extender_controller_extender")
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
        "name": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
            "required": True,
        },
        "id": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "string"},
        "authorized": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ext_name": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "string"},
        "description": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "string"},
        "vdom": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "device_id": {"v_range": [["v7.0.2", "v7.2.0"]], "type": "integer"},
        "extension_type": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "wan-extension"}, {"value": "lan-extension"}],
        },
        "profile": {"v_range": [["v7.0.2", "v7.2.0"]], "type": "string"},
        "override_allowaccess": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "override_login_password_change": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "login_password_change": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "yes"}, {"value": "default"}, {"value": "no"}],
        },
        "login_password": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
        },
        "override_enforce_bandwidth": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "enforce_bandwidth": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "bandwidth_limit": {"v_range": [["v7.0.2", "v7.2.0"]], "type": "integer"},
        "wan_extension": {
            "v_range": [["v7.0.2", "v7.2.0"]],
            "type": "dict",
            "children": {
                "modem1_extension": {
                    "v_range": [["v7.0.2", "v7.2.0"]],
                    "type": "string",
                },
                "modem2_extension": {
                    "v_range": [["v7.0.2", "v7.2.0"]],
                    "type": "string",
                },
            },
        },
        "controller_report": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "interval": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "integer",
                },
                "signal_threshold": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "integer",
                },
            },
        },
        "modem1": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
            "type": "dict",
            "children": {
                "ifname": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                },
                "redundant_mode": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "redundant_intf": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                },
                "conn_status": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "integer",
                },
                "default_sim": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                    "options": [
                        {"value": "sim1"},
                        {"value": "sim2"},
                        {"value": "carrier"},
                        {"value": "cost"},
                    ],
                },
                "gps": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "sim1_pin": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "sim2_pin": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "sim1_pin_code": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                },
                "sim2_pin_code": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                },
                "preferred_carrier": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                },
                "auto_switch": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "dict",
                    "children": {
                        "disconnect": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "disconnect_threshold": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "integer",
                        },
                        "disconnect_period": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "integer",
                        },
                        "signal": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "dataplan": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "switch_back": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "list",
                            "options": [{"value": "time"}, {"value": "timer"}],
                            "multiple_values": True,
                            "elements": "str",
                        },
                        "switch_back_time": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "string",
                        },
                        "switch_back_timer": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "integer",
                        },
                    },
                },
            },
        },
        "modem2": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
            "type": "dict",
            "children": {
                "ifname": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                },
                "redundant_mode": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "redundant_intf": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                },
                "conn_status": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "integer",
                },
                "default_sim": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                    "options": [
                        {"value": "sim1"},
                        {"value": "sim2"},
                        {"value": "carrier"},
                        {"value": "cost"},
                    ],
                },
                "gps": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "sim1_pin": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "sim2_pin": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "sim1_pin_code": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                },
                "sim2_pin_code": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                },
                "preferred_carrier": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "string",
                },
                "auto_switch": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                    "type": "dict",
                    "children": {
                        "disconnect": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "disconnect_threshold": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "integer",
                        },
                        "disconnect_period": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "integer",
                        },
                        "signal": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "dataplan": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "switch_back": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "list",
                            "options": [{"value": "time"}, {"value": "timer"}],
                            "multiple_values": True,
                            "elements": "str",
                        },
                        "switch_back_time": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "string",
                        },
                        "switch_back_timer": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.1"]],
                            "type": "integer",
                        },
                    },
                },
            },
        },
        "admin": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "discovered"},
                {"value": "enable"},
            ],
        },
        "ifname": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "role": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "primary"},
                {"value": "secondary"},
            ],
        },
        "mode": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "standalone"}, {"value": "redundant"}],
        },
        "dial_mode": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "dial-on-demand"}, {"value": "always-connect"}],
        },
        "redial": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "1"},
                {"value": "2"},
                {"value": "3"},
                {"value": "4"},
                {"value": "5"},
                {"value": "6"},
                {"value": "7"},
                {"value": "8"},
                {"value": "9"},
                {"value": "10"},
            ],
        },
        "redundant_intf": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "dial_status": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "integer",
        },
        "conn_status": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "integer",
        },
        "quota_limit_mb": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "integer",
        },
        "billing_start_day": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "integer",
        },
        "at_dial_script": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "modem_passwd": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "initiated_update": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "modem_type": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "cdma"}, {"value": "gsm/lte"}, {"value": "wimax"}],
        },
        "ppp_username": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "ppp_password": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "ppp_auth_protocol": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "pap"}, {"value": "chap"}],
        },
        "ppp_echo_request": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wimax_carrier": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "wimax_realm": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "wimax_auth_protocol": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "tls"}, {"value": "ttls"}],
        },
        "sim_pin": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "access_point_name": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "multi_mode": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [
                {"value": "auto"},
                {"value": "auto-3g"},
                {"value": "force-lte"},
                {"value": "force-3g"},
                {"value": "force-2g"},
            ],
        },
        "roaming": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cdma_nai": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "aaa_shared_secret": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "ha_shared_secret": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "primary_ha": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "secondary_ha": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "cdma_aaa_spi": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
        "cdma_ha_spi": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
        },
    },
    "v_range": [["v6.0.0", "v7.2.0"]],
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
        "extender_controller_extender": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["extender_controller_extender"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["extender_controller_extender"]["options"][attribute_name][
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
            fos, versioned_schema, "extender_controller_extender"
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
