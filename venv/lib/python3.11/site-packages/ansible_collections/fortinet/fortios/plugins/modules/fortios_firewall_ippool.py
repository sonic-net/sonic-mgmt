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
module: fortios_firewall_ippool
short_description: Configure IPv4 IP pools in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and ippool category.
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
    firewall_ippool:
        description:
            - Configure IPv4 IP pools.
        default: null
        type: dict
        suboptions:
            add_nat64_route:
                description:
                    - Enable/disable adding NAT64 route.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            arp_intf:
                description:
                    - Select an interface from available options that will reply to ARP requests. (If blank, any is selected). Source system.interface.name.
                type: str
            arp_reply:
                description:
                    - Enable/disable replying to ARP requests when an IP Pool is added to a policy .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            associated_interface:
                description:
                    - Associated interface name. Source system.interface.name.
                type: str
            block_size:
                description:
                    - Number of addresses in a block (64 - 4096).
                type: int
            client_prefix_length:
                description:
                    - Subnet length of a single deterministic NAT64 client (1 - 128).
                type: int
            comments:
                description:
                    - Comment.
                type: str
            endip:
                description:
                    - 'Final IPv4 address (inclusive) in the range for the address pool (format xxx.xxx.xxx.xxx).'
                type: str
            endport:
                description:
                    - 'Final port number (inclusive) in the range for the address pool (1024 - 65535).'
                type: int
            icmp_session_quota:
                description:
                    - Maximum number of concurrent ICMP sessions allowed per client (0 - 2097000).
                type: int
            name:
                description:
                    - IP pool name.
                required: true
                type: str
            nat64:
                description:
                    - Enable/disable NAT64.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            num_blocks_per_user:
                description:
                    - Number of addresses blocks that can be used by a user (1 to 128).
                type: int
            pba_interim_log:
                description:
                    - Port block allocation interim logging interval (600 - 86400 seconds).
                type: int
            pba_timeout:
                description:
                    - Port block allocation timeout (seconds).
                type: int
            permit_any_host:
                description:
                    - Enable/disable full cone NAT.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            port_per_user:
                description:
                    - Number of port for each user (32 - 60416).
                type: int
            privileged_port_use_pba:
                description:
                    - Enable/disable selection of the external port from the port block allocation for NAT"ing privileged ports (deafult = disable).
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            source_endip:
                description:
                    - 'Final IPv4 address (inclusive) in the range of the source addresses to be translated (format xxx.xxx.xxx.xxx).'
                type: str
            source_prefix6:
                description:
                    - 'Source IPv6 network to be translated (format = xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xxx).'
                type: str
            source_startip:
                description:
                    - First IPv4 address (inclusive) in the range of the source addresses to be translated (format = xxx.xxx.xxx.xxx).
                type: str
            startip:
                description:
                    - 'First IPv4 address (inclusive) in the range for the address pool (format xxx.xxx.xxx.xxx).'
                type: str
            startport:
                description:
                    - 'First port number (inclusive) in the range for the address pool (1024 - 65535).'
                type: int
            subnet_broadcast_in_ippool:
                description:
                    - Enable/disable inclusion of the subnetwork address and broadcast IP address in the NAT64 IP pool.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            tcp_session_quota:
                description:
                    - Maximum number of concurrent TCP sessions allowed per client (0 - 2097000).
                type: int
            type:
                description:
                    - 'IP pool type: overload, one-to-one, fixed-port-range, port-block-allocation, cgn-resource-allocation (hyperscale vdom only)'
                type: str
                choices:
                    - 'overload'
                    - 'one-to-one'
                    - 'fixed-port-range'
                    - 'port-block-allocation'
            udp_session_quota:
                description:
                    - Maximum number of concurrent UDP sessions allowed per client (0 - 2097000).
                type: int
"""

EXAMPLES = """
- name: Configure IPv4 IP pools.
  fortinet.fortios.fortios_firewall_ippool:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_ippool:
          add_nat64_route: "disable"
          arp_intf: "<your_own_value> (source system.interface.name)"
          arp_reply: "disable"
          associated_interface: "<your_own_value> (source system.interface.name)"
          block_size: "128"
          client_prefix_length: "64"
          comments: "<your_own_value>"
          endip: "<your_own_value>"
          endport: "65533"
          icmp_session_quota: "0"
          name: "default_name_13"
          nat64: "disable"
          num_blocks_per_user: "8"
          pba_interim_log: "0"
          pba_timeout: "30"
          permit_any_host: "disable"
          port_per_user: "0"
          privileged_port_use_pba: "disable"
          source_endip: "<your_own_value>"
          source_prefix6: "<your_own_value>"
          source_startip: "<your_own_value>"
          startip: "<your_own_value>"
          startport: "5117"
          subnet_broadcast_in_ippool: "disable"
          tcp_session_quota: "0"
          type: "overload"
          udp_session_quota: "0"
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


def filter_firewall_ippool_data(json):
    option_list = [
        "add_nat64_route",
        "arp_intf",
        "arp_reply",
        "associated_interface",
        "block_size",
        "client_prefix_length",
        "comments",
        "endip",
        "endport",
        "icmp_session_quota",
        "name",
        "nat64",
        "num_blocks_per_user",
        "pba_interim_log",
        "pba_timeout",
        "permit_any_host",
        "port_per_user",
        "privileged_port_use_pba",
        "source_endip",
        "source_prefix6",
        "source_startip",
        "startip",
        "startport",
        "subnet_broadcast_in_ippool",
        "tcp_session_quota",
        "type",
        "udp_session_quota",
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


def firewall_ippool(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_ippool_data = data["firewall_ippool"]

    filtered_data = filter_firewall_ippool_data(firewall_ippool_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "ippool", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "ippool", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_ippool"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "ippool",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "ippool", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("firewall", "ippool", mkey=converted_data["name"], vdom=vdom)
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

    if data["firewall_ippool"]:
        resp = firewall_ippool(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_ippool"))
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
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "overload"},
                {"value": "one-to-one"},
                {"value": "fixed-port-range"},
                {"value": "port-block-allocation"},
            ],
        },
        "startip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "endip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "startport": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "endport": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "source_startip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "source_endip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "block_size": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "port_per_user": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "num_blocks_per_user": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "pba_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "pba_interim_log": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "permit_any_host": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "arp_reply": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "arp_intf": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "associated_interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "nat64": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "add_nat64_route": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "source_prefix6": {"v_range": [["v7.6.0", ""]], "type": "string"},
        "client_prefix_length": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "tcp_session_quota": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "udp_session_quota": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "icmp_session_quota": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "privileged_port_use_pba": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "subnet_broadcast_in_ippool": {
            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {
                    "value": "enable",
                    "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", "v7.4.4"]],
                },
            ],
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
        "firewall_ippool": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_ippool"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_ippool"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "firewall_ippool"
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
