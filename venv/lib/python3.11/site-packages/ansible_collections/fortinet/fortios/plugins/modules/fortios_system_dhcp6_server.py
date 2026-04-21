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
module: fortios_system_dhcp6_server
short_description: Configure DHCPv6 servers in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system_dhcp6 feature and server category.
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
    - We highly recommend using your own value as the id instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
       available number for the object, it does have limitations. Please find more details in Q&A.
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
    system_dhcp6_server:
        description:
            - Configure DHCPv6 servers.
        default: null
        type: dict
        suboptions:
            delegated_prefix_iaid:
                description:
                    - IAID of obtained delegated-prefix from the upstream interface.
                type: int
            delegated_prefix_route:
                description:
                    - Enable/disable automatically adding of routing for delegated prefix.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            dns_search_list:
                description:
                    - DNS search list options.
                type: str
                choices:
                    - 'delegated'
                    - 'specify'
            dns_server1:
                description:
                    - DNS server 1.
                type: str
            dns_server2:
                description:
                    - DNS server 2.
                type: str
            dns_server3:
                description:
                    - DNS server 3.
                type: str
            dns_server4:
                description:
                    - DNS server 4.
                type: str
            dns_service:
                description:
                    - Options for assigning DNS servers to DHCPv6 clients.
                type: str
                choices:
                    - 'delegated'
                    - 'default'
                    - 'specify'
            domain:
                description:
                    - Domain name suffix for the IP addresses that the DHCP server assigns to clients.
                type: str
            id:
                description:
                    - ID. see <a href='#notes'>Notes</a>.
                required: true
                type: int
            interface:
                description:
                    - DHCP server can assign IP configurations to clients connected to this interface. Source system.interface.name.
                type: str
            ip_mode:
                description:
                    - Method used to assign client IP.
                type: str
                choices:
                    - 'range'
                    - 'delegated'
            ip_range:
                description:
                    - DHCP IP range configuration.
                type: list
                elements: dict
                suboptions:
                    end_ip:
                        description:
                            - End of IP range.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    start_ip:
                        description:
                            - Start of IP range.
                        type: str
                    vci_match:
                        description:
                            - Enable/disable vendor class option matching. When enabled only DHCP requests with a matching VC are served with this range.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    vci_string:
                        description:
                            - One or more VCI strings in quotes separated by spaces.
                        type: list
                        elements: dict
                        suboptions:
                            vci_string:
                                description:
                                    - VCI strings.
                                required: true
                                type: str
            lease_time:
                description:
                    - Lease time in seconds, 0 means unlimited.
                type: int
            option1:
                description:
                    - Option 1.
                type: str
            option2:
                description:
                    - Option 2.
                type: str
            option3:
                description:
                    - Option 3.
                type: str
            options:
                description:
                    - DHCPv6 options.
                type: list
                elements: dict
                suboptions:
                    code:
                        description:
                            - DHCPv6 option code.
                        type: int
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ip6:
                        description:
                            - DHCP option IP6s.
                        type: list
                        elements: str
                    type:
                        description:
                            - DHCPv6 option type.
                        type: str
                        choices:
                            - 'hex'
                            - 'string'
                            - 'ip6'
                            - 'fqdn'
                    value:
                        description:
                            - DHCPv6 option value (hexadecimal value must be even).
                        type: str
                    vci_match:
                        description:
                            - Enable/disable vendor class option matching. When enabled only DHCP requests with a matching VCI are served with this option.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    vci_string:
                        description:
                            - One or more VCI strings in quotes separated by spaces.
                        type: list
                        elements: dict
                        suboptions:
                            vci_string:
                                description:
                                    - VCI strings.
                                required: true
                                type: str
            prefix_mode:
                description:
                    - Assigning a prefix from a DHCPv6 client or RA.
                type: str
                choices:
                    - 'dhcp6'
                    - 'ra'
            prefix_range:
                description:
                    - DHCP prefix configuration.
                type: list
                elements: dict
                suboptions:
                    end_prefix:
                        description:
                            - End of prefix range.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    prefix_length:
                        description:
                            - Prefix length.
                        type: int
                    start_prefix:
                        description:
                            - Start of prefix range.
                        type: str
            rapid_commit:
                description:
                    - Enable/disable allow/disallow rapid commit.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            status:
                description:
                    - Enable/disable this DHCPv6 configuration.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            subnet:
                description:
                    - Subnet or subnet-id if the IP mode is delegated.
                type: str
            upstream_interface:
                description:
                    - Interface name from where delegated information is provided. Source system.interface.name.
                type: str
"""

EXAMPLES = """
- name: Configure DHCPv6 servers.
  fortinet.fortios.fortios_system_dhcp6_server:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_dhcp6_server:
          delegated_prefix_iaid: "0"
          delegated_prefix_route: "disable"
          dns_search_list: "delegated"
          dns_server1: "<your_own_value>"
          dns_server2: "<your_own_value>"
          dns_server3: "<your_own_value>"
          dns_server4: "<your_own_value>"
          dns_service: "delegated"
          domain: "<your_own_value>"
          id: "12"
          interface: "<your_own_value> (source system.interface.name)"
          ip_mode: "range"
          ip_range:
              -
                  end_ip: "<your_own_value>"
                  id: "17"
                  start_ip: "<your_own_value>"
                  vci_match: "disable"
                  vci_string:
                      -
                          vci_string: "<your_own_value>"
          lease_time: "604800"
          option1: "<your_own_value>"
          option2: "<your_own_value>"
          option3: "<your_own_value>"
          options:
              -
                  code: "0"
                  id: "28"
                  ip6: "<your_own_value>"
                  type: "hex"
                  value: "<your_own_value>"
                  vci_match: "disable"
                  vci_string:
                      -
                          vci_string: "<your_own_value>"
          prefix_mode: "dhcp6"
          prefix_range:
              -
                  end_prefix: "<your_own_value>"
                  id: "38"
                  prefix_length: "0"
                  start_prefix: "<your_own_value>"
          rapid_commit: "disable"
          status: "disable"
          subnet: "<your_own_value>"
          upstream_interface: "<your_own_value> (source system.interface.name)"
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


def filter_system_dhcp6_server_data(json):
    option_list = [
        "delegated_prefix_iaid",
        "delegated_prefix_route",
        "dns_search_list",
        "dns_server1",
        "dns_server2",
        "dns_server3",
        "dns_server4",
        "dns_service",
        "domain",
        "id",
        "interface",
        "ip_mode",
        "ip_range",
        "lease_time",
        "option1",
        "option2",
        "option3",
        "options",
        "prefix_mode",
        "prefix_range",
        "rapid_commit",
        "status",
        "subnet",
        "upstream_interface",
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
        ["options", "ip6"],
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


def system_dhcp6_server(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_dhcp6_server_data = data["system_dhcp6_server"]

    filtered_data = filter_system_dhcp6_server_data(system_dhcp6_server_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system.dhcp6", "server", filtered_data, vdom=vdom)
        current_data = fos.get("system.dhcp6", "server", vdom=vdom, mkey=mkey)
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
    data_copy["system_dhcp6_server"] = filtered_data
    fos.do_member_operation(
        "system.dhcp6",
        "server",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system.dhcp6", "server", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system.dhcp6", "server", mkey=converted_data["id"], vdom=vdom
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


def fortios_system_dhcp6(data, fos, check_mode):

    if data["system_dhcp6_server"]:
        resp = system_dhcp6_server(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_dhcp6_server"))
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
        "id": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "rapid_commit": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "lease_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dns_service": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "delegated"},
                {"value": "default"},
                {"value": "specify"},
            ],
        },
        "dns_search_list": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "delegated"}, {"value": "specify"}],
        },
        "dns_server1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dns_server2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dns_server3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dns_server4": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "domain": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "subnet": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "delegated_prefix_route": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "options": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "code": {"v_range": [["v7.6.0", ""]], "type": "integer"},
                "type": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "hex"},
                        {"value": "string"},
                        {"value": "ip6"},
                        {"value": "fqdn"},
                    ],
                },
                "value": {"v_range": [["v7.6.0", ""]], "type": "string"},
                "ip6": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "vci_match": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "vci_string": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vci_string": {
                            "v_range": [["v7.6.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.6.0", ""]],
                },
            },
            "v_range": [["v7.6.0", ""]],
        },
        "upstream_interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "delegated_prefix_iaid": {"v_range": [["v7.0.2", ""]], "type": "integer"},
        "ip_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "range"}, {"value": "delegated"}],
        },
        "prefix_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "dhcp6"}, {"value": "ra"}],
        },
        "prefix_range": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "start_prefix": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "end_prefix": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "prefix_length": {"v_range": [["v6.0.0", ""]], "type": "integer"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ip_range": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "start_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "end_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "vci_match": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "vci_string": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vci_string": {
                            "v_range": [["v7.6.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.6.0", ""]],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "option1": {"v_range": [["v6.0.0", "v7.4.4"]], "type": "string"},
        "option2": {"v_range": [["v6.0.0", "v7.4.4"]], "type": "string"},
        "option3": {"v_range": [["v6.0.0", "v7.4.4"]], "type": "string"},
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "id"
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
        "system_dhcp6_server": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_dhcp6_server"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_dhcp6_server"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_dhcp6_server"
        )

        is_error, has_changed, result, diff = fortios_system_dhcp6(
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
