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
module: fortios_firewall_vip64
short_description: Configure IPv6 to IPv4 virtual IPs in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and vip64 category.
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
    firewall_vip64:
        description:
            - Configure IPv6 to IPv4 virtual IPs.
        default: null
        type: dict
        suboptions:
            arp_reply:
                description:
                    - Enable ARP reply.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            color:
                description:
                    - Color of icon on the GUI.
                type: int
            comment:
                description:
                    - Comment.
                type: str
            extip:
                description:
                    - Start-external-IPv6-address [-end-external-IPv6-address].
                type: str
            extport:
                description:
                    - External service port.
                type: str
            id:
                description:
                    - Custom defined id.
                type: int
            ldb_method:
                description:
                    - Load balance method.
                type: str
                choices:
                    - 'static'
                    - 'round-robin'
                    - 'weighted'
                    - 'least-session'
                    - 'least-rtt'
                    - 'first-alive'
            mappedip:
                description:
                    - Start-mapped-IP [-end-mapped-IP].
                type: str
            mappedport:
                description:
                    - Mapped service port.
                type: str
            monitor:
                description:
                    - Health monitors.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Health monitor name. Source firewall.ldb-monitor.name.
                        required: true
                        type: str
            name:
                description:
                    - VIP64 name.
                required: true
                type: str
            portforward:
                description:
                    - Enable port forwarding.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            protocol:
                description:
                    - Mapped port protocol.
                type: str
                choices:
                    - 'tcp'
                    - 'udp'
            realservers:
                description:
                    - Real servers.
                type: list
                elements: dict
                suboptions:
                    client_ip:
                        description:
                            - Restrict server to a client IP in this range.
                        type: str
                    healthcheck:
                        description:
                            - Per server health check.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'vip'
                    holddown_interval:
                        description:
                            - Hold down interval.
                        type: int
                    id:
                        description:
                            - Real server ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ip:
                        description:
                            - Mapped server IP.
                        type: str
                    max_connections:
                        description:
                            - Maximum number of connections allowed to server.
                        type: int
                    monitor:
                        description:
                            - Health monitors. Source firewall.ldb-monitor.name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Health monitor name. Source firewall.ldb-monitor.name.
                                required: true
                                type: str
                    port:
                        description:
                            - Mapped server port.
                        type: int
                    status:
                        description:
                            - Server administrative status.
                        type: str
                        choices:
                            - 'active'
                            - 'standby'
                            - 'disable'
                    weight:
                        description:
                            - weight
                        type: int
            server_type:
                description:
                    - Server type.
                type: str
                choices:
                    - 'http'
                    - 'tcp'
                    - 'udp'
                    - 'ip'
            src_filter:
                description:
                    - 'Source IP6 filter (x:x:x:x:x:x:x:x/x).'
                type: list
                elements: dict
                suboptions:
                    range:
                        description:
                            - Src-filter range.
                        required: true
                        type: str
            type:
                description:
                    - 'VIP type: static NAT or server load balance.'
                type: str
                choices:
                    - 'static-nat'
                    - 'server-load-balance'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
"""

EXAMPLES = """
- name: Configure IPv6 to IPv4 virtual IPs.
  fortinet.fortios.fortios_firewall_vip64:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_vip64:
          arp_reply: "disable"
          color: "0"
          comment: "Comment."
          extip: "<your_own_value>"
          extport: "<your_own_value>"
          id: "8"
          ldb_method: "static"
          mappedip: "<your_own_value>"
          mappedport: "<your_own_value>"
          monitor:
              -
                  name: "default_name_13 (source firewall.ldb-monitor.name)"
          name: "default_name_14"
          portforward: "disable"
          protocol: "tcp"
          realservers:
              -
                  client_ip: "<your_own_value>"
                  healthcheck: "disable"
                  holddown_interval: "300"
                  id: "21"
                  ip: "<your_own_value>"
                  max_connections: "0"
                  monitor:
                      -
                          name: "default_name_25 (source firewall.ldb-monitor.name)"
                  port: "0"
                  status: "active"
                  weight: "1"
          server_type: "http"
          src_filter:
              -
                  range: "<your_own_value>"
          type: "static-nat"
          uuid: "<your_own_value>"
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


def filter_firewall_vip64_data(json):
    option_list = [
        "arp_reply",
        "color",
        "comment",
        "extip",
        "extport",
        "id",
        "ldb_method",
        "mappedip",
        "mappedport",
        "monitor",
        "name",
        "portforward",
        "protocol",
        "realservers",
        "server_type",
        "src_filter",
        "type",
        "uuid",
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


def firewall_vip64(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_vip64_data = data["firewall_vip64"]

    filtered_data = filter_firewall_vip64_data(firewall_vip64_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "vip64", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "vip64", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_vip64"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "vip64",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "vip64", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("firewall", "vip64", mkey=converted_data["name"], vdom=vdom)
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


def fortios_firewall(data, fos, check_mode):

    if data["firewall_vip64"]:
        resp = firewall_vip64(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_vip64"))
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
        "name": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string", "required": True},
        "id": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "integer"},
        "uuid": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
        "comment": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
        "type": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "static-nat"}, {"value": "server-load-balance"}],
        },
        "src_filter": {
            "type": "list",
            "elements": "dict",
            "children": {
                "range": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.0.0"]],
        },
        "extip": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
        "mappedip": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
        "arp_reply": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "portforward": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "protocol": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "tcp"}, {"value": "udp"}],
        },
        "extport": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
        "mappedport": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
        "color": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "integer"},
        "ldb_method": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [
                {"value": "static"},
                {"value": "round-robin"},
                {"value": "weighted"},
                {"value": "least-session"},
                {"value": "least-rtt"},
                {"value": "first-alive"},
            ],
        },
        "server_type": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [
                {"value": "http"},
                {"value": "tcp"},
                {"value": "udp"},
                {"value": "ip"},
            ],
        },
        "realservers": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "integer",
                    "required": True,
                },
                "ip": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
                "port": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "integer"},
                "status": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "string",
                    "options": [
                        {"value": "active"},
                        {"value": "standby"},
                        {"value": "disable"},
                    ],
                },
                "weight": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "integer"},
                "holddown_interval": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "integer",
                },
                "healthcheck": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "enable"},
                        {"value": "vip"},
                    ],
                },
                "max_connections": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "integer",
                },
                "monitor": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.4", "v7.0.0"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v7.0.0"]],
                },
                "client_ip": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
            },
            "v_range": [["v6.0.0", "v7.0.0"]],
        },
        "monitor": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.0.0"]],
        },
    },
    "v_range": [["v6.0.0", "v7.0.0"]],
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
        "firewall_vip64": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_vip64"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_vip64"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "firewall_vip64"
        )

        is_error, has_changed, result, diff = fortios_firewall(
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
