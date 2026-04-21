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
module: fortios_system_fabric_vpn
short_description: Setup for self orchestrated fabric auto discovery VPN in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and fabric_vpn category.
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

    system_fabric_vpn:
        description:
            - Setup for self orchestrated fabric auto discovery VPN.
        default: null
        type: dict
        suboptions:
            advertised_subnets:
                description:
                    - Local advertised subnets.
                type: list
                elements: dict
                suboptions:
                    access:
                        description:
                            - Access policy direction.
                        type: str
                        choices:
                            - 'inbound'
                            - 'bidirectional'
                    bgp_network:
                        description:
                            - Underlying BGP network. Source router.bgp.network.id.
                        type: int
                    firewall_address:
                        description:
                            - Underlying firewall address. Source firewall.address.name.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    policies:
                        description:
                            - Underlying policies. Source firewall.policy.policyid.
                        type: list
                        elements: int
                    prefix:
                        description:
                            - Network prefix.
                        type: str
            bgp_as:
                description:
                    - BGP Router AS number, asplain/asdot/asdot+ format.
                type: str
            branch_name:
                description:
                    - Branch name.
                type: str
            health_checks:
                description:
                    - Underlying health checks. Source system.sdwan.health-check.name.
                type: list
                elements: str
            loopback_address_block:
                description:
                    - 'IPv4 address and subnet mask for hub"s loopback address, syntax: X.X.X.X/24.'
                type: str
            loopback_advertised_subnet:
                description:
                    - Loopback advertised subnet reference. Source system.fabric-vpn.advertised-subnets.id.
                type: int
            loopback_interface:
                description:
                    - Loopback interface. Source system.interface.name.
                type: str
            overlays:
                description:
                    - Local overlay interfaces table.
                type: list
                elements: dict
                suboptions:
                    bgp_neighbor:
                        description:
                            - Underlying BGP neighbor entry. Source router.bgp.neighbor.ip.
                        type: str
                    bgp_neighbor_group:
                        description:
                            - Underlying BGP neighbor group entry. Source router.bgp.neighbor-group.name.
                        type: str
                    bgp_neighbor_range:
                        description:
                            - Underlying BGP neighbor range entry. Source router.bgp.neighbor-range.id.
                        type: int
                    bgp_network:
                        description:
                            - Underlying BGP network. Source router.bgp.network.id.
                        type: int
                    interface:
                        description:
                            - Underlying interface name. Source system.interface.name.
                        type: str
                    ipsec_network_id:
                        description:
                            - VPN gateway network ID.
                        type: int
                    ipsec_phase1:
                        description:
                            - IPsec interface. Source vpn.ipsec.phase1-interface.name.
                        type: str
                    name:
                        description:
                            - Overlay name.
                        required: true
                        type: str
                    overlay_policy:
                        description:
                            - The overlay policy to allow ADVPN thru traffic. Source firewall.policy.policyid.
                        type: int
                    overlay_tunnel_block:
                        description:
                            - 'IPv4 address and subnet mask for the overlay tunnel , syntax: X.X.X.X/24.'
                        type: str
                    remote_gw:
                        description:
                            - IP address of the hub gateway (Set by hub).
                        type: str
                    route_policy:
                        description:
                            - Underlying router policy. Source router.policy.seq-num.
                        type: int
                    sdwan_member:
                        description:
                            - Reference to SD-WAN member entry. Source system.sdwan.members.seq-num.
                        type: int
            policy_rule:
                description:
                    - Policy creation rule.
                type: str
                choices:
                    - 'health-check'
                    - 'manual'
                    - 'auto'
            psksecret:
                description:
                    - Pre-shared secret for ADVPN.
                type: str
            sdwan_zone:
                description:
                    - Reference to created SD-WAN zone. Source system.sdwan.zone.name.
                type: str
            status:
                description:
                    - Enable/disable Fabric VPN.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sync_mode:
                description:
                    - Setting synchronised by fabric or manual.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vpn_role:
                description:
                    - Fabric VPN role.
                type: str
                choices:
                    - 'hub'
                    - 'spoke'
"""

EXAMPLES = """
- name: Setup for self orchestrated fabric auto discovery VPN.
  fortinet.fortios.fortios_system_fabric_vpn:
      vdom: "{{ vdom }}"
      system_fabric_vpn:
          advertised_subnets:
              -
                  access: "inbound"
                  bgp_network: "0"
                  firewall_address: "<your_own_value> (source firewall.address.name)"
                  id: "7"
                  policies: "<your_own_value> (source firewall.policy.policyid)"
                  prefix: "<your_own_value>"
          bgp_as: "<your_own_value>"
          branch_name: "<your_own_value>"
          health_checks: "<your_own_value> (source system.sdwan.health-check.name)"
          loopback_address_block: "<your_own_value>"
          loopback_advertised_subnet: "0"
          loopback_interface: "<your_own_value> (source system.interface.name)"
          overlays:
              -
                  bgp_neighbor: "<your_own_value> (source router.bgp.neighbor.ip)"
                  bgp_neighbor_group: "<your_own_value> (source router.bgp.neighbor-group.name)"
                  bgp_neighbor_range: "0"
                  bgp_network: "0"
                  interface: "<your_own_value> (source system.interface.name)"
                  ipsec_network_id: "0"
                  ipsec_phase1: "<your_own_value> (source vpn.ipsec.phase1-interface.name)"
                  name: "default_name_24"
                  overlay_policy: "0"
                  overlay_tunnel_block: "<your_own_value>"
                  remote_gw: "<your_own_value>"
                  route_policy: "0"
                  sdwan_member: "0"
          policy_rule: "health-check"
          psksecret: "<your_own_value>"
          sdwan_zone: "<your_own_value> (source system.sdwan.zone.name)"
          status: "enable"
          sync_mode: "enable"
          vpn_role: "hub"
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


def filter_system_fabric_vpn_data(json):
    option_list = [
        "advertised_subnets",
        "bgp_as",
        "branch_name",
        "health_checks",
        "loopback_address_block",
        "loopback_advertised_subnet",
        "loopback_interface",
        "overlays",
        "policy_rule",
        "psksecret",
        "sdwan_zone",
        "status",
        "sync_mode",
        "vpn_role",
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
        ["advertised_subnets", "policies"],
        ["health_checks"],
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


def system_fabric_vpn(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_fabric_vpn_data = data["system_fabric_vpn"]

    filtered_data = filter_system_fabric_vpn_data(system_fabric_vpn_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "fabric-vpn", filtered_data, vdom=vdom)
        current_data = fos.get("system", "fabric-vpn", vdom=vdom, mkey=mkey)
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
    data_copy["system_fabric_vpn"] = filtered_data
    fos.do_member_operation(
        "system",
        "fabric-vpn",
        data_copy,
    )

    return fos.set("system", "fabric-vpn", data=converted_data, vdom=vdom)


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

    if data["system_fabric_vpn"]:
        resp = system_fabric_vpn(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_fabric_vpn"))
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
    "v_range": [["v7.2.4", ""]],
    "type": "dict",
    "children": {
        "status": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sync_mode": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "branch_name": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "policy_rule": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [
                {"value": "health-check"},
                {"value": "manual"},
                {"value": "auto"},
            ],
        },
        "vpn_role": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "hub"}, {"value": "spoke"}],
        },
        "overlays": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "required": True,
                },
                "ipsec_network_id": {"v_range": [["v7.6.3", ""]], "type": "integer"},
                "overlay_tunnel_block": {"v_range": [["v7.2.4", ""]], "type": "string"},
                "remote_gw": {"v_range": [["v7.2.4", ""]], "type": "string"},
                "interface": {"v_range": [["v7.2.4", ""]], "type": "string"},
                "bgp_neighbor": {"v_range": [["v7.2.4", ""]], "type": "string"},
                "overlay_policy": {"v_range": [["v7.2.4", ""]], "type": "integer"},
                "bgp_network": {"v_range": [["v7.2.4", ""]], "type": "integer"},
                "route_policy": {"v_range": [["v7.2.4", ""]], "type": "integer"},
                "bgp_neighbor_group": {"v_range": [["v7.2.4", ""]], "type": "string"},
                "bgp_neighbor_range": {"v_range": [["v7.2.4", ""]], "type": "integer"},
                "ipsec_phase1": {"v_range": [["v7.2.4", ""]], "type": "string"},
                "sdwan_member": {"v_range": [["v7.2.4", ""]], "type": "integer"},
            },
            "v_range": [["v7.2.4", ""]],
        },
        "advertised_subnets": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "integer",
                    "required": True,
                },
                "prefix": {"v_range": [["v7.2.4", ""]], "type": "string"},
                "access": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [{"value": "inbound"}, {"value": "bidirectional"}],
                },
                "bgp_network": {"v_range": [["v7.2.4", ""]], "type": "integer"},
                "firewall_address": {"v_range": [["v7.2.4", ""]], "type": "string"},
                "policies": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
            },
            "v_range": [["v7.2.4", ""]],
        },
        "loopback_address_block": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "loopback_interface": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "loopback_advertised_subnet": {"v_range": [["v7.2.4", ""]], "type": "integer"},
        "psksecret": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "bgp_as": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "sdwan_zone": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "health_checks": {
            "v_range": [["v7.2.4", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
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
        "system_fabric_vpn": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_fabric_vpn"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_fabric_vpn"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_fabric_vpn"
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
