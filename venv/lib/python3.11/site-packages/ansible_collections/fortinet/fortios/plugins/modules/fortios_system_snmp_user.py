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
module: fortios_system_snmp_user
short_description: SNMP user configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system_snmp feature and user category.
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
    system_snmp_user:
        description:
            - SNMP user configuration.
        default: null
        type: dict
        suboptions:
            auth_proto:
                description:
                    - Authentication protocol.
                type: str
                choices:
                    - 'md5'
                    - 'sha'
                    - 'sha224'
                    - 'sha256'
                    - 'sha384'
                    - 'sha512'
            auth_pwd:
                description:
                    - Password for authentication protocol.
                type: str
            events:
                description:
                    - SNMP notifications (traps) to send.
                type: list
                elements: str
                choices:
                    - 'cpu-high'
                    - 'mem-low'
                    - 'log-full'
                    - 'intf-ip'
                    - 'vpn-tun-up'
                    - 'vpn-tun-down'
                    - 'ha-switch'
                    - 'ha-hb-failure'
                    - 'ips-signature'
                    - 'ips-anomaly'
                    - 'av-virus'
                    - 'av-oversize'
                    - 'av-pattern'
                    - 'av-fragmented'
                    - 'fm-if-change'
                    - 'fm-conf-change'
                    - 'bgp-established'
                    - 'bgp-backward-transition'
                    - 'ha-member-up'
                    - 'ha-member-down'
                    - 'ent-conf-change'
                    - 'av-conserve'
                    - 'av-bypass'
                    - 'av-oversize-passed'
                    - 'av-oversize-blocked'
                    - 'ips-pkg-update'
                    - 'ips-fail-open'
                    - 'temperature-high'
                    - 'voltage-alert'
                    - 'power-supply'
                    - 'faz-disconnect'
                    - 'faz'
                    - 'fan-failure'
                    - 'wc-ap-up'
                    - 'wc-ap-down'
                    - 'fswctl-session-up'
                    - 'fswctl-session-down'
                    - 'load-balance-real-server-down'
                    - 'device-new'
                    - 'per-cpu-high'
                    - 'dhcp'
                    - 'pool-usage'
                    - 'ippool'
                    - 'interface'
                    - 'ospf-nbr-state-change'
                    - 'ospf-virtnbr-state-change'
                    - 'power-supply-failure'
            ha_direct:
                description:
                    - Enable/disable direct management of HA cluster members.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            interface:
                description:
                    - Specify outgoing interface to reach server. Source system.interface.name.
                type: str
            interface_select_method:
                description:
                    - Specify how to select outgoing interface to reach server.
                type: str
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            mib_view:
                description:
                    - SNMP access control MIB view. Source system.snmp.mib-view.name.
                type: str
            name:
                description:
                    - SNMP user name.
                required: true
                type: str
            notify_hosts:
                description:
                    - SNMP managers to send notifications (traps) to.
                type: list
                elements: str
            notify_hosts6:
                description:
                    - IPv6 SNMP managers to send notifications (traps) to.
                type: list
                elements: str
            priv_proto:
                description:
                    - Privacy (encryption) protocol.
                type: str
                choices:
                    - 'aes'
                    - 'des'
                    - 'aes256'
                    - 'aes256cisco'
            priv_pwd:
                description:
                    - Password for privacy (encryption) protocol.
                type: str
            queries:
                description:
                    - Enable/disable SNMP queries for this user.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            query_port:
                description:
                    - SNMPv3 query port .
                type: int
            security_level:
                description:
                    - Security level for message authentication and encryption.
                type: str
                choices:
                    - 'no-auth-no-priv'
                    - 'auth-no-priv'
                    - 'auth-priv'
            source_ip:
                description:
                    - Source IP for SNMP trap.
                type: str
            source_ipv6:
                description:
                    - Source IPv6 for SNMP trap.
                type: str
            status:
                description:
                    - Enable/disable this SNMP user.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            trap_lport:
                description:
                    - SNMPv3 local trap port .
                type: int
            trap_rport:
                description:
                    - SNMPv3 trap remote port .
                type: int
            trap_status:
                description:
                    - Enable/disable traps for this SNMP user.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vdoms:
                description:
                    - SNMP access control VDOMs.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - VDOM name. Source system.vdom.name.
                        required: true
                        type: str
            vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
"""

EXAMPLES = """
- name: SNMP user configuration.
  fortinet.fortios.fortios_system_snmp_user:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_snmp_user:
          auth_proto: "md5"
          auth_pwd: "<your_own_value>"
          events: "cpu-high"
          ha_direct: "enable"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          mib_view: "<your_own_value> (source system.snmp.mib-view.name)"
          name: "default_name_10"
          notify_hosts: "<your_own_value>"
          notify_hosts6: "<your_own_value>"
          priv_proto: "aes"
          priv_pwd: "<your_own_value>"
          queries: "enable"
          query_port: "161"
          security_level: "no-auth-no-priv"
          source_ip: "84.230.14.43"
          source_ipv6: "<your_own_value>"
          status: "enable"
          trap_lport: "162"
          trap_rport: "162"
          trap_status: "enable"
          vdoms:
              -
                  name: "default_name_25 (source system.vdom.name)"
          vrf_select: "0"
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


def filter_system_snmp_user_data(json):
    option_list = [
        "auth_proto",
        "auth_pwd",
        "events",
        "ha_direct",
        "interface",
        "interface_select_method",
        "mib_view",
        "name",
        "notify_hosts",
        "notify_hosts6",
        "priv_proto",
        "priv_pwd",
        "queries",
        "query_port",
        "security_level",
        "source_ip",
        "source_ipv6",
        "status",
        "trap_lport",
        "trap_rport",
        "trap_status",
        "vdoms",
        "vrf_select",
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
        ["notify_hosts"],
        ["notify_hosts6"],
        ["events"],
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


def system_snmp_user(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_snmp_user_data = data["system_snmp_user"]

    filtered_data = filter_system_snmp_user_data(system_snmp_user_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system.snmp", "user", filtered_data, vdom=vdom)
        current_data = fos.get("system.snmp", "user", vdom=vdom, mkey=mkey)
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
    data_copy["system_snmp_user"] = filtered_data
    fos.do_member_operation(
        "system.snmp",
        "user",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system.snmp", "user", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("system.snmp", "user", mkey=converted_data["name"], vdom=vdom)
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


def fortios_system_snmp(data, fos, check_mode):

    if data["system_snmp_user"]:
        resp = system_snmp_user(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_snmp_user"))
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
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "trap_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "trap_lport": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "trap_rport": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "queries": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "query_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "notify_hosts": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "notify_hosts6": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "source_ipv6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ha_direct": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "events": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "cpu-high"},
                {"value": "mem-low"},
                {"value": "log-full"},
                {"value": "intf-ip"},
                {"value": "vpn-tun-up"},
                {"value": "vpn-tun-down"},
                {"value": "ha-switch"},
                {"value": "ha-hb-failure"},
                {"value": "ips-signature"},
                {"value": "ips-anomaly"},
                {"value": "av-virus"},
                {"value": "av-oversize"},
                {"value": "av-pattern"},
                {"value": "av-fragmented"},
                {"value": "fm-if-change"},
                {"value": "fm-conf-change"},
                {"value": "bgp-established"},
                {"value": "bgp-backward-transition"},
                {"value": "ha-member-up"},
                {"value": "ha-member-down"},
                {"value": "ent-conf-change"},
                {"value": "av-conserve"},
                {"value": "av-bypass"},
                {"value": "av-oversize-passed"},
                {"value": "av-oversize-blocked"},
                {"value": "ips-pkg-update"},
                {"value": "ips-fail-open"},
                {"value": "temperature-high"},
                {"value": "voltage-alert"},
                {"value": "power-supply", "v_range": [["v7.4.2", ""]]},
                {"value": "faz-disconnect"},
                {"value": "faz", "v_range": [["v7.4.1", ""]]},
                {"value": "fan-failure"},
                {"value": "wc-ap-up"},
                {"value": "wc-ap-down"},
                {"value": "fswctl-session-up"},
                {"value": "fswctl-session-down"},
                {"value": "load-balance-real-server-down"},
                {"value": "device-new"},
                {"value": "per-cpu-high"},
                {"value": "dhcp", "v_range": [["v6.4.0", ""]]},
                {
                    "value": "pool-usage",
                    "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", ""]],
                },
                {"value": "ippool", "v_range": [["v7.6.0", ""]]},
                {"value": "interface", "v_range": [["v7.6.0", ""]]},
                {"value": "ospf-nbr-state-change", "v_range": [["v7.0.0", ""]]},
                {"value": "ospf-virtnbr-state-change", "v_range": [["v7.0.0", ""]]},
                {"value": "power-supply-failure", "v_range": [["v6.0.0", "v7.4.1"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "mib_view": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "vdoms": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.0", ""]],
        },
        "security_level": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "no-auth-no-priv"},
                {"value": "auth-no-priv"},
                {"value": "auth-priv"},
            ],
        },
        "auth_proto": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "md5"},
                {"value": "sha"},
                {"value": "sha224", "v_range": [["v6.2.0", ""]]},
                {"value": "sha256", "v_range": [["v6.2.0", ""]]},
                {"value": "sha384", "v_range": [["v6.2.0", ""]]},
                {"value": "sha512", "v_range": [["v6.2.0", ""]]},
            ],
        },
        "auth_pwd": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "priv_proto": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "aes"},
                {"value": "des"},
                {"value": "aes256"},
                {"value": "aes256cisco"},
            ],
        },
        "priv_pwd": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "interface_select_method": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {"v_range": [["v7.6.0", ""]], "type": "string"},
        "vrf_select": {"v_range": [["v7.6.1", ""]], "type": "integer"},
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
        "system_snmp_user": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_snmp_user"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_snmp_user"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_snmp_user"
        )

        is_error, has_changed, result, diff = fortios_system_snmp(
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
