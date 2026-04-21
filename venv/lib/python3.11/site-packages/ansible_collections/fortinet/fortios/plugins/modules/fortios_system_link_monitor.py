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
module: fortios_system_link_monitor
short_description: Configure Link Health Monitor in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and link_monitor category.
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
    system_link_monitor:
        description:
            - Configure Link Health Monitor.
        default: null
        type: dict
        suboptions:
            addr_mode:
                description:
                    - Address mode (IPv4 or IPv6).
                type: str
                choices:
                    - 'ipv4'
                    - 'ipv6'
            class_id:
                description:
                    - Traffic class ID. Source firewall.traffic-class.class-id.
                type: int
            diffservcode:
                description:
                    - Differentiated services code point (DSCP) in the IP header of the probe packet.
                type: str
            fail_weight:
                description:
                    - Threshold weight to trigger link failure alert.
                type: int
            failtime:
                description:
                    - Number of retry attempts before the server is considered down (1 - 3600).
                type: int
            gateway_ip:
                description:
                    - Gateway IP address used to probe the server.
                type: str
            gateway_ip6:
                description:
                    - Gateway IPv6 address used to probe the server.
                type: str
            ha_priority:
                description:
                    - HA election priority (1 - 50).
                type: int
            http_agent:
                description:
                    - String in the http-agent field in the HTTP header.
                type: str
            http_get:
                description:
                    - If you are monitoring an HTML server you can send an HTTP-GET request with a custom string. Use this option to define the string.
                type: str
            http_match:
                description:
                    - String that you expect to see in the HTTP-GET requests of the traffic to be monitored.
                type: str
            interval:
                description:
                    - Detection interval in milliseconds (20 - 3600 * 1000 msec).
                type: int
            name:
                description:
                    - Link monitor name.
                required: true
                type: str
            packet_size:
                description:
                    - Packet size of a TWAMP test session (124/158 - 1024).
                type: int
            password:
                description:
                    - TWAMP controller password in authentication mode.
                type: str
            port:
                description:
                    - Port number of the traffic to be used to monitor the server.
                type: int
            probe_count:
                description:
                    - Number of most recent probes that should be used to calculate latency and jitter (5 - 30).
                type: int
            probe_timeout:
                description:
                    - Time to wait before a probe packet is considered lost (20 - 5000 msec).
                type: int
            protocol:
                description:
                    - Protocols used to monitor the server.
                type: list
                elements: str
                choices:
                    - 'ping'
                    - 'tcp-echo'
                    - 'udp-echo'
                    - 'http'
                    - 'https'
                    - 'twamp'
                    - 'ping6'
            recoverytime:
                description:
                    - Number of successful responses received before server is considered recovered (1 - 3600).
                type: int
            route:
                description:
                    - Subnet to monitor.
                type: list
                elements: dict
                suboptions:
                    subnet:
                        description:
                            - IP and netmask (x.x.x.x/y).
                        required: true
                        type: str
            security_mode:
                description:
                    - Twamp controller security mode.
                type: str
                choices:
                    - 'none'
                    - 'authentication'
            server:
                description:
                    - IP address of the server(s) to be monitored.
                type: list
                elements: dict
                suboptions:
                    address:
                        description:
                            - Server address.
                        required: true
                        type: str
            server_config:
                description:
                    - Mode of server configuration.
                type: str
                choices:
                    - 'default'
                    - 'individual'
            server_list:
                description:
                    - Servers for link-monitor to monitor.
                type: list
                elements: dict
                suboptions:
                    dst:
                        description:
                            - IP address of the server to be monitored.
                        type: str
                    id:
                        description:
                            - Server ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    port:
                        description:
                            - Port number of the traffic to be used to monitor the server.
                        type: int
                    protocol:
                        description:
                            - Protocols used to monitor the server.
                        type: list
                        elements: str
                        choices:
                            - 'ping'
                            - 'tcp-echo'
                            - 'udp-echo'
                            - 'http'
                            - 'https'
                            - 'twamp'
                    weight:
                        description:
                            - Weight of the monitor to this dst (0 - 255).
                        type: int
            server_type:
                description:
                    - Server type (static or dynamic).
                type: str
                choices:
                    - 'static'
                    - 'dynamic'
            service_detection:
                description:
                    - Only use monitor to read quality values. If enabled, static routes and cascade interfaces will not be updated.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            source_ip:
                description:
                    - Source IP address used in packet to the server.
                type: str
            source_ip6:
                description:
                    - Source IPv6 address used in packet to the server.
                type: str
            srcintf:
                description:
                    - Interface that receives the traffic to be monitored. Source system.interface.name.
                type: str
            status:
                description:
                    - Enable/disable this link monitor.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            update_cascade_interface:
                description:
                    - Enable/disable update cascade interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            update_policy_route:
                description:
                    - Enable/disable updating the policy route.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            update_static_route:
                description:
                    - Enable/disable updating the static route.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure Link Health Monitor.
  fortinet.fortios.fortios_system_link_monitor:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_link_monitor:
          addr_mode: "ipv4"
          class_id: "0"
          diffservcode: "<your_own_value>"
          fail_weight: "0"
          failtime: "5"
          gateway_ip: "<your_own_value>"
          gateway_ip6: "<your_own_value>"
          ha_priority: "1"
          http_agent: "<your_own_value>"
          http_get: "<your_own_value>"
          http_match: "<your_own_value>"
          interval: "500"
          name: "default_name_15"
          packet_size: "124"
          password: "<your_own_value>"
          port: "0"
          probe_count: "30"
          probe_timeout: "500"
          protocol: "ping"
          recoverytime: "5"
          route:
              -
                  subnet: "<your_own_value>"
          security_mode: "none"
          server:
              -
                  address: "<your_own_value>"
          server_config: "default"
          server_list:
              -
                  dst: "<your_own_value>"
                  id: "31"
                  port: "0"
                  protocol: "ping"
                  weight: "0"
          server_type: "static"
          service_detection: "enable"
          source_ip: "84.230.14.43"
          source_ip6: "<your_own_value>"
          srcintf: "<your_own_value> (source system.interface.name)"
          status: "enable"
          update_cascade_interface: "enable"
          update_policy_route: "enable"
          update_static_route: "enable"
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


def filter_system_link_monitor_data(json):
    option_list = [
        "addr_mode",
        "class_id",
        "diffservcode",
        "fail_weight",
        "failtime",
        "gateway_ip",
        "gateway_ip6",
        "ha_priority",
        "http_agent",
        "http_get",
        "http_match",
        "interval",
        "name",
        "packet_size",
        "password",
        "port",
        "probe_count",
        "probe_timeout",
        "protocol",
        "recoverytime",
        "route",
        "security_mode",
        "server",
        "server_config",
        "server_list",
        "server_type",
        "service_detection",
        "source_ip",
        "source_ip6",
        "srcintf",
        "status",
        "update_cascade_interface",
        "update_policy_route",
        "update_static_route",
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
        ["protocol"],
        ["server_list", "protocol"],
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


def system_link_monitor(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_link_monitor_data = data["system_link_monitor"]

    filtered_data = filter_system_link_monitor_data(system_link_monitor_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "link-monitor", filtered_data, vdom=vdom)
        current_data = fos.get("system", "link-monitor", vdom=vdom, mkey=mkey)
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
    data_copy["system_link_monitor"] = filtered_data
    fos.do_member_operation(
        "system",
        "link-monitor",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "link-monitor", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system", "link-monitor", mkey=converted_data["name"], vdom=vdom
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

    if data["system_link_monitor"]:
        resp = system_link_monitor(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_link_monitor"))
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
        "addr_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "ipv4"}, {"value": "ipv6"}],
        },
        "srcintf": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "server_config": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "default"}, {"value": "individual"}],
        },
        "server_type": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "static"}, {"value": "dynamic"}],
        },
        "server": {
            "type": "list",
            "elements": "dict",
            "children": {
                "address": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "protocol": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "ping"},
                {"value": "tcp-echo"},
                {"value": "udp-echo"},
                {"value": "http"},
                {"value": "https", "v_range": [["v7.4.1", ""]]},
                {"value": "twamp"},
                {
                    "value": "ping6",
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                },
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "gateway_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "gateway_ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "route": {
            "type": "list",
            "elements": "dict",
            "children": {
                "subnet": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.0", ""]],
        },
        "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "source_ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "http_get": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "http_agent": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "http_match": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "probe_timeout": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "integer",
        },
        "failtime": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "recoverytime": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "probe_count": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "security_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "authentication"}],
        },
        "password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "packet_size": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ha_priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "fail_weight": {"v_range": [["v7.0.1", ""]], "type": "integer"},
        "update_cascade_interface": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "update_static_route": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "update_policy_route": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffservcode": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "class_id": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "service_detection": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "server_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "integer",
                    "required": True,
                },
                "dst": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "protocol": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "list",
                    "options": [
                        {"value": "ping"},
                        {"value": "tcp-echo"},
                        {"value": "udp-echo"},
                        {"value": "http"},
                        {"value": "https", "v_range": [["v7.4.1", ""]]},
                        {"value": "twamp"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "port": {"v_range": [["v7.0.1", ""]], "type": "integer"},
                "weight": {"v_range": [["v7.0.1", ""]], "type": "integer"},
            },
            "v_range": [["v7.0.1", ""]],
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
        "system_link_monitor": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_link_monitor"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_link_monitor"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_link_monitor"
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
