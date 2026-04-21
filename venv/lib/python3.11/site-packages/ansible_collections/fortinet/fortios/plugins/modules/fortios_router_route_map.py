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
module: fortios_router_route_map
short_description: Configure route maps in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify router feature and route_map category.
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
    router_route_map:
        description:
            - Configure route maps.
        default: null
        type: dict
        suboptions:
            comments:
                description:
                    - Optional comments.
                type: str
            name:
                description:
                    - Name.
                required: true
                type: str
            rule:
                description:
                    - Rule.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - 'permit'
                            - 'deny'
                    id:
                        description:
                            - Rule ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    match_as_path:
                        description:
                            - Match BGP AS path list. Source router.aspath-list.name.
                        type: str
                    match_community:
                        description:
                            - Match BGP community list. Source router.community-list.name.
                        type: str
                    match_community_exact:
                        description:
                            - Enable/disable exact matching of communities.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    match_extcommunity:
                        description:
                            - Match BGP extended community list. Source router.extcommunity-list.name.
                        type: str
                    match_extcommunity_exact:
                        description:
                            - Enable/disable exact matching of extended communities.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    match_flags:
                        description:
                            - BGP flag value to match (0 - 65535)
                        type: int
                    match_interface:
                        description:
                            - Match interface configuration. Source system.interface.name.
                        type: str
                    match_ip_address:
                        description:
                            - Match IP address permitted by access-list or prefix-list. Source router.access-list.name router.prefix-list.name.
                        type: str
                    match_ip_nexthop:
                        description:
                            - Match next hop IP address passed by access-list or prefix-list. Source router.access-list.name router.prefix-list.name.
                        type: str
                    match_ip6_address:
                        description:
                            - Match IPv6 address permitted by access-list6 or prefix-list6. Source router.access-list6.name router.prefix-list6.name.
                        type: str
                    match_ip6_nexthop:
                        description:
                            - Match next hop IPv6 address passed by access-list6 or prefix-list6. Source router.access-list6.name router.prefix-list6.name.
                        type: str
                    match_metric:
                        description:
                            - Match metric for redistribute routes.
                        type: int
                    match_origin:
                        description:
                            - Match BGP origin code.
                        type: str
                        choices:
                            - 'none'
                            - 'egp'
                            - 'igp'
                            - 'incomplete'
                    match_route_type:
                        description:
                            - Match route type.
                        type: str
                        choices:
                            - 'external-type1'
                            - 'external-type2'
                            - 'none'
                            - '1'
                            - '2'
                    match_tag:
                        description:
                            - Match tag.
                        type: int
                    match_vrf:
                        description:
                            - Match VRF ID.
                        type: int
                    set_aggregator_as:
                        description:
                            - BGP aggregator AS.
                        type: int
                    set_aggregator_ip:
                        description:
                            - BGP aggregator IP.
                        type: str
                    set_aspath:
                        description:
                            - Prepend BGP AS path attribute.
                        type: list
                        elements: dict
                        suboptions:
                            as:
                                description:
                                    - AS number (0 - 4294967295). Use quotes for repeating numbers, For example, "1 1 2".
                                required: true
                                type: str
                    set_aspath_action:
                        description:
                            - Specify preferred action of set-aspath.
                        type: str
                        choices:
                            - 'prepend'
                            - 'replace'
                    set_atomic_aggregate:
                        description:
                            - Enable/disable BGP atomic aggregate attribute.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    set_community:
                        description:
                            - BGP community attribute.
                        type: list
                        elements: dict
                        suboptions:
                            community:
                                description:
                                    - 'Attribute: AA|AA:NN|internet|local-AS|no-advertise|no-export (exact match required for well known communities).'
                                required: true
                                type: str
                    set_community_additive:
                        description:
                            - Enable/disable adding set-community to existing community.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    set_community_delete:
                        description:
                            - Delete communities matching community list. Source router.community-list.name.
                        type: str
                    set_dampening_max_suppress:
                        description:
                            - Maximum duration to suppress a route (1 - 255 min, 0 = unset).
                        type: int
                    set_dampening_reachability_half_life:
                        description:
                            - Reachability half-life time for the penalty (1 - 45 min, 0 = unset).
                        type: int
                    set_dampening_reuse:
                        description:
                            - Value to start reusing a route (1 - 20000, 0 = unset).
                        type: int
                    set_dampening_suppress:
                        description:
                            - Value to start suppressing a route (1 - 20000, 0 = unset).
                        type: int
                    set_dampening_unreachability_half_life:
                        description:
                            - Unreachability Half-life time for the penalty (1 - 45 min, 0 = unset).
                        type: int
                    set_extcommunity_rt:
                        description:
                            - Route Target extended community.
                        type: list
                        elements: dict
                        suboptions:
                            community:
                                description:
                                    - 'AA:NN.'
                                required: true
                                type: str
                    set_extcommunity_soo:
                        description:
                            - Site-of-Origin extended community.
                        type: list
                        elements: dict
                        suboptions:
                            community:
                                description:
                                    - 'Community (format = AA:NN).'
                                required: true
                                type: str
                    set_flags:
                        description:
                            - BGP flags value (0 - 65535)
                        type: int
                    set_ip_nexthop:
                        description:
                            - IP address of next hop.
                        type: str
                    set_ip_prefsrc:
                        description:
                            - IP address of preferred source.
                        type: str
                    set_ip6_nexthop:
                        description:
                            - IPv6 global address of next hop.
                        type: str
                    set_ip6_nexthop_local:
                        description:
                            - IPv6 local address of next hop.
                        type: str
                    set_local_preference:
                        description:
                            - BGP local preference path attribute.
                        type: int
                    set_metric:
                        description:
                            - Metric value.
                        type: int
                    set_metric_type:
                        description:
                            - Metric type.
                        type: str
                        choices:
                            - 'external-type1'
                            - 'external-type2'
                            - 'none'
                            - '1'
                            - '2'
                    set_origin:
                        description:
                            - BGP origin code.
                        type: str
                        choices:
                            - 'none'
                            - 'egp'
                            - 'igp'
                            - 'incomplete'
                    set_originator_id:
                        description:
                            - BGP originator ID attribute.
                        type: str
                    set_priority:
                        description:
                            - Priority for routing table.
                        type: int
                    set_route_tag:
                        description:
                            - Route tag for routing table.
                        type: int
                    set_tag:
                        description:
                            - Tag value.
                        type: int
                    set_vpnv4_nexthop:
                        description:
                            - IP address of VPNv4 next-hop.
                        type: str
                    set_vpnv6_nexthop:
                        description:
                            - IPv6 global address of VPNv6 next-hop.
                        type: str
                    set_vpnv6_nexthop_local:
                        description:
                            - IPv6 link-local address of VPNv6 next-hop.
                        type: str
                    set_weight:
                        description:
                            - BGP weight for routing table.
                        type: int
"""

EXAMPLES = """
- name: Configure route maps.
  fortinet.fortios.fortios_router_route_map:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      router_route_map:
          comments: "<your_own_value>"
          name: "default_name_4"
          rule:
              -
                  action: "permit"
                  id: "7"
                  match_as_path: "<your_own_value> (source router.aspath-list.name)"
                  match_community: "<your_own_value> (source router.community-list.name)"
                  match_community_exact: "enable"
                  match_extcommunity: "<your_own_value> (source router.extcommunity-list.name)"
                  match_extcommunity_exact: "enable"
                  match_flags: "32767"
                  match_interface: "<your_own_value> (source system.interface.name)"
                  match_ip_address: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
                  match_ip_nexthop: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
                  match_ip6_address: "<your_own_value> (source router.access-list6.name router.prefix-list6.name)"
                  match_ip6_nexthop: "<your_own_value> (source router.access-list6.name router.prefix-list6.name)"
                  match_metric: ""
                  match_origin: "none"
                  match_route_type: "external-type1"
                  match_tag: ""
                  match_vrf: ""
                  set_aggregator_as: "0"
                  set_aggregator_ip: "<your_own_value>"
                  set_aspath:
                      -
                          as: "<your_own_value>"
                  set_aspath_action: "prepend"
                  set_atomic_aggregate: "enable"
                  set_community:
                      -
                          community: "<your_own_value>"
                  set_community_additive: "enable"
                  set_community_delete: "<your_own_value> (source router.community-list.name)"
                  set_dampening_max_suppress: "0"
                  set_dampening_reachability_half_life: "0"
                  set_dampening_reuse: "0"
                  set_dampening_suppress: "0"
                  set_dampening_unreachability_half_life: "0"
                  set_extcommunity_rt:
                      -
                          community: "<your_own_value>"
                  set_extcommunity_soo:
                      -
                          community: "<your_own_value>"
                  set_flags: "32767"
                  set_ip_nexthop: "<your_own_value>"
                  set_ip_prefsrc: "<your_own_value>"
                  set_ip6_nexthop: "<your_own_value>"
                  set_ip6_nexthop_local: "<your_own_value>"
                  set_local_preference: ""
                  set_metric: ""
                  set_metric_type: "external-type1"
                  set_origin: "none"
                  set_originator_id: "<your_own_value>"
                  set_priority: ""
                  set_route_tag: ""
                  set_tag: ""
                  set_vpnv4_nexthop: "<your_own_value>"
                  set_vpnv6_nexthop: "<your_own_value>"
                  set_vpnv6_nexthop_local: "<your_own_value>"
                  set_weight: ""
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


def filter_router_route_map_data(json):
    option_list = ["comments", "name", "rule"]

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


def router_route_map(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    router_route_map_data = data["router_route_map"]

    filtered_data = filter_router_route_map_data(router_route_map_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("router", "route-map", filtered_data, vdom=vdom)
        current_data = fos.get("router", "route-map", vdom=vdom, mkey=mkey)
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
    data_copy["router_route_map"] = filtered_data
    fos.do_member_operation(
        "router",
        "route-map",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("router", "route-map", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("router", "route-map", mkey=converted_data["name"], vdom=vdom)
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


def fortios_router(data, fos, check_mode):

    if data["router_route_map"]:
        resp = router_route_map(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_route_map"))
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
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "rule": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "action": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "permit"}, {"value": "deny"}],
                },
                "match_as_path": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "match_community": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "match_extcommunity": {"v_range": [["v7.2.4", ""]], "type": "string"},
                "match_community_exact": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "match_extcommunity_exact": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "match_origin": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "egp"},
                        {"value": "igp"},
                        {"value": "incomplete"},
                    ],
                },
                "match_interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "match_ip_address": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "match_ip6_address": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "match_ip_nexthop": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "match_ip6_nexthop": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "match_metric": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "match_route_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "external-type1", "v_range": [["v7.0.0", ""]]},
                        {"value": "external-type2", "v_range": [["v7.0.0", ""]]},
                        {"value": "none"},
                        {"value": "1", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "2", "v_range": [["v6.0.0", "v6.4.4"]]},
                    ],
                },
                "match_tag": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "match_vrf": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "set_aggregator_as": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "set_aggregator_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "set_aspath_action": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "prepend"}, {"value": "replace"}],
                },
                "set_aspath": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "as": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "set_atomic_aggregate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "set_community_delete": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "set_community": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "community": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "set_community_additive": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "set_dampening_reachability_half_life": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "set_dampening_reuse": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "set_dampening_suppress": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "set_dampening_max_suppress": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "set_dampening_unreachability_half_life": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "set_extcommunity_rt": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "community": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "set_extcommunity_soo": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "community": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "set_ip_nexthop": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "set_ip_prefsrc": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "set_vpnv4_nexthop": {"v_range": [["v7.4.1", ""]], "type": "string"},
                "set_ip6_nexthop": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "set_ip6_nexthop_local": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                },
                "set_vpnv6_nexthop": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "set_vpnv6_nexthop_local": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "set_local_preference": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "set_metric": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "set_metric_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "external-type1", "v_range": [["v7.0.0", ""]]},
                        {"value": "external-type2", "v_range": [["v7.0.0", ""]]},
                        {"value": "none"},
                        {"value": "1", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "2", "v_range": [["v6.0.0", "v6.4.4"]]},
                    ],
                },
                "set_originator_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "set_origin": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "egp"},
                        {"value": "igp"},
                        {"value": "incomplete"},
                    ],
                },
                "set_tag": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "set_weight": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "set_route_tag": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "set_priority": {"v_range": [["v7.2.0", ""]], "type": "integer"},
                "set_flags": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "integer"},
                "match_flags": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "integer"},
            },
            "v_range": [["v6.0.0", ""]],
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
        "router_route_map": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_route_map"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_route_map"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "router_route_map"
        )

        is_error, has_changed, result, diff = fortios_router(
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
