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
module: fortios_router_multicast
short_description: Configure router multicast in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify router feature and multicast category.
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

    router_multicast:
        description:
            - Configure router multicast.
        default: null
        type: dict
        suboptions:
            interface:
                description:
                    - PIM interfaces.
                type: list
                elements: dict
                suboptions:
                    bfd:
                        description:
                            - Enable/disable Protocol Independent Multicast (PIM) Bidirectional Forwarding Detection (BFD).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    cisco_exclude_genid:
                        description:
                            - Exclude GenID from hello packets (compatibility with old Cisco IOS).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    dr_priority:
                        description:
                            - DR election priority.
                        type: int
                    hello_holdtime:
                        description:
                            - Time before old neighbor information expires (0 - 65535 sec).
                        type: int
                    hello_interval:
                        description:
                            - Interval between sending PIM hello messages (0 - 65535 sec).
                        type: int
                    igmp:
                        description:
                            - IGMP configuration options.
                        type: dict
                        suboptions:
                            access_group:
                                description:
                                    - Groups IGMP hosts are allowed to join. Source router.access-list.name.
                                type: str
                            immediate_leave_group:
                                description:
                                    - Groups to drop membership for immediately after receiving IGMPv2 leave. Source router.access-list.name.
                                type: str
                            last_member_query_count:
                                description:
                                    - Number of group specific queries before removing group (2 - 7).
                                type: int
                            last_member_query_interval:
                                description:
                                    - Timeout between IGMPv2 leave and removing group (1 - 65535 msec).
                                type: int
                            query_interval:
                                description:
                                    - Interval between queries to IGMP hosts (1 - 65535 sec).
                                type: int
                            query_max_response_time:
                                description:
                                    - Maximum time to wait for a IGMP query response (1 - 25 sec).
                                type: int
                            query_timeout:
                                description:
                                    - Timeout between queries before becoming querying unit for network (60 - 900).
                                type: int
                            router_alert_check:
                                description:
                                    - Enable/disable require IGMP packets contain router alert option.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            version:
                                description:
                                    - Maximum version of IGMP to support.
                                type: str
                                choices:
                                    - '3'
                                    - '2'
                                    - '1'
                    join_group:
                        description:
                            - Join multicast groups.
                        type: list
                        elements: dict
                        suboptions:
                            address:
                                description:
                                    - Multicast group IP address.
                                required: true
                                type: str
                    multicast_flow:
                        description:
                            - Acceptable source for multicast group. Source router.multicast-flow.name.
                        type: str
                    name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
                    neighbour_filter:
                        description:
                            - Routers acknowledged as neighbor routers. Source router.access-list.name.
                        type: str
                    passive:
                        description:
                            - Enable/disable listening to IGMP but not participating in PIM.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    pim_mode:
                        description:
                            - PIM operation mode.
                        type: str
                        choices:
                            - 'sparse-mode'
                            - 'dense-mode'
                    propagation_delay:
                        description:
                            - Delay flooding packets on this interface (100 - 5000 msec).
                        type: int
                    rp_candidate:
                        description:
                            - Enable/disable compete to become RP in elections.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rp_candidate_group:
                        description:
                            - Multicast groups managed by this RP. Source router.access-list.name.
                        type: str
                    rp_candidate_interval:
                        description:
                            - RP candidate advertisement interval (1 - 16383 sec).
                        type: int
                    rp_candidate_priority:
                        description:
                            - Router"s priority as RP.
                        type: int
                    rpf_nbr_fail_back:
                        description:
                            - Enable/disable fail back for RPF neighbor query.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rpf_nbr_fail_back_filter:
                        description:
                            - Filter for fail back RPF neighbors. Source router.access-list.name.
                        type: str
                    state_refresh_interval:
                        description:
                            - Interval between sending state-refresh packets (1 - 100 sec).
                        type: int
                    static_group:
                        description:
                            - Statically set multicast groups to forward out. Source router.multicast-flow.name.
                        type: str
                    ttl_threshold:
                        description:
                            - Minimum TTL of multicast packets that will be forwarded (applied only to new multicast routes) (1 - 255).
                        type: int
            multicast_routing:
                description:
                    - Enable/disable IP multicast routing.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pim_sm_global:
                description:
                    - PIM sparse-mode global settings.
                type: dict
                suboptions:
                    accept_register_list:
                        description:
                            - Sources allowed to register packets with this Rendezvous Point (RP). Source router.access-list.name.
                        type: str
                    accept_source_list:
                        description:
                            - Sources allowed to send multicast traffic. Source router.access-list.name.
                        type: str
                    bsr_allow_quick_refresh:
                        description:
                            - Enable/disable accept BSR quick refresh packets from neighbors.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bsr_candidate:
                        description:
                            - Enable/disable allowing this router to become a bootstrap router (BSR).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bsr_hash:
                        description:
                            - BSR hash length (0 - 32).
                        type: int
                    bsr_interface:
                        description:
                            - Interface to advertise as candidate BSR. Source system.interface.name.
                        type: str
                    bsr_priority:
                        description:
                            - BSR priority (0 - 255).
                        type: int
                    cisco_crp_prefix:
                        description:
                            - Enable/disable making candidate RP compatible with old Cisco IOS.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    cisco_ignore_rp_set_priority:
                        description:
                            - Use only hash for RP selection (compatibility with old Cisco IOS).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    cisco_register_checksum:
                        description:
                            - Checksum entire register packet(for old Cisco IOS compatibility).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    cisco_register_checksum_group:
                        description:
                            - Cisco register checksum only these groups. Source router.access-list.name.
                        type: str
                    join_prune_holdtime:
                        description:
                            - Join/prune holdtime (1 - 65535).
                        type: int
                    message_interval:
                        description:
                            - Period of time between sending periodic PIM join/prune messages in seconds (1 - 65535).
                        type: int
                    null_register_retries:
                        description:
                            - Maximum retries of null register (1 - 20).
                        type: int
                    pim_use_sdwan:
                        description:
                            - Enable/disable use of SDWAN when checking RPF neighbor and sending of REG packet.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    register_rate_limit:
                        description:
                            - Limit of packets/sec per source registered through this RP (0 - 65535).
                        type: int
                    register_rp_reachability:
                        description:
                            - Enable/disable check RP is reachable before registering packets.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    register_source:
                        description:
                            - Override source address in register packets.
                        type: str
                        choices:
                            - 'disable'
                            - 'interface'
                            - 'ip-address'
                    register_source_interface:
                        description:
                            - Override with primary interface address. Source system.interface.name.
                        type: str
                    register_source_ip:
                        description:
                            - Override with local IP address.
                        type: str
                    register_supression:
                        description:
                            - Period of time to honor register-stop message (1 - 65535 sec).
                        type: int
                    rp_address:
                        description:
                            - Statically configure RP addresses.
                        type: list
                        elements: dict
                        suboptions:
                            group:
                                description:
                                    - Groups to use this RP. Source router.access-list.name.
                                type: str
                            id:
                                description:
                                    - ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            ip_address:
                                description:
                                    - RP router address.
                                type: str
                    rp_register_keepalive:
                        description:
                            - Timeout for RP receiving data on (S,G) tree (1 - 65535 sec).
                        type: int
                    spt_threshold:
                        description:
                            - Enable/disable switching to source specific trees.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    spt_threshold_group:
                        description:
                            - Groups allowed to switch to source tree. Source router.access-list.name.
                        type: str
                    ssm:
                        description:
                            - Enable/disable source specific multicast.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssm_range:
                        description:
                            - Groups allowed to source specific multicast. Source router.access-list.name.
                        type: str
            pim_sm_global_vrf:
                description:
                    - per-VRF PIM sparse-mode global settings.
                type: list
                elements: dict
                suboptions:
                    bsr_allow_quick_refresh:
                        description:
                            - Enable/disable accept BSR quick refresh packets from neighbors.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bsr_candidate:
                        description:
                            - Enable/disable allowing this router to become a bootstrap router (BSR).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bsr_hash:
                        description:
                            - BSR hash length (0 - 32).
                        type: int
                    bsr_interface:
                        description:
                            - Interface to advertise as candidate BSR. Source system.interface.name.
                        type: str
                    bsr_priority:
                        description:
                            - BSR priority (0 - 255).
                        type: int
                    cisco_crp_prefix:
                        description:
                            - Enable/disable making candidate RP compatible with old Cisco IOS.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rp_address:
                        description:
                            - Statically configure RP addresses.
                        type: list
                        elements: dict
                        suboptions:
                            group:
                                description:
                                    - Groups to use this RP. Source router.access-list.name.
                                type: str
                            id:
                                description:
                                    - ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            ip_address:
                                description:
                                    - RP router address.
                                type: str
                    vrf:
                        description:
                            - VRF ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            route_limit:
                description:
                    - Maximum number of multicast routes.
                type: int
            route_threshold:
                description:
                    - Generate warnings when the number of multicast routes exceeds this number, must not be greater than route-limit.
                type: int
"""

EXAMPLES = """
- name: Configure router multicast.
  fortinet.fortios.fortios_router_multicast:
      vdom: "{{ vdom }}"
      router_multicast:
          interface:
              -
                  bfd: "enable"
                  cisco_exclude_genid: "enable"
                  dr_priority: "1"
                  hello_holdtime: "105"
                  hello_interval: "30"
                  igmp:
                      access_group: "<your_own_value> (source router.access-list.name)"
                      immediate_leave_group: "<your_own_value> (source router.access-list.name)"
                      last_member_query_count: "2"
                      last_member_query_interval: "1000"
                      query_interval: "125"
                      query_max_response_time: "10"
                      query_timeout: "255"
                      router_alert_check: "enable"
                      version: "3"
                  join_group:
                      -
                          address: "<your_own_value>"
                  multicast_flow: "<your_own_value> (source router.multicast-flow.name)"
                  name: "default_name_22 (source system.interface.name)"
                  neighbour_filter: "<your_own_value> (source router.access-list.name)"
                  passive: "enable"
                  pim_mode: "sparse-mode"
                  propagation_delay: "500"
                  rp_candidate: "enable"
                  rp_candidate_group: "<your_own_value> (source router.access-list.name)"
                  rp_candidate_interval: "60"
                  rp_candidate_priority: "192"
                  rpf_nbr_fail_back: "enable"
                  rpf_nbr_fail_back_filter: "<your_own_value> (source router.access-list.name)"
                  state_refresh_interval: "60"
                  static_group: "<your_own_value> (source router.multicast-flow.name)"
                  ttl_threshold: "1"
          multicast_routing: "enable"
          pim_sm_global:
              accept_register_list: "<your_own_value> (source router.access-list.name)"
              accept_source_list: "<your_own_value> (source router.access-list.name)"
              bsr_allow_quick_refresh: "enable"
              bsr_candidate: "enable"
              bsr_hash: "10"
              bsr_interface: "<your_own_value> (source system.interface.name)"
              bsr_priority: "0"
              cisco_crp_prefix: "enable"
              cisco_ignore_rp_set_priority: "enable"
              cisco_register_checksum: "enable"
              cisco_register_checksum_group: "<your_own_value> (source router.access-list.name)"
              join_prune_holdtime: "210"
              message_interval: "60"
              null_register_retries: "1"
              pim_use_sdwan: "enable"
              register_rate_limit: "0"
              register_rp_reachability: "enable"
              register_source: "disable"
              register_source_interface: "<your_own_value> (source system.interface.name)"
              register_source_ip: "<your_own_value>"
              register_supression: "60"
              rp_address:
                  -
                      group: "<your_own_value> (source router.access-list.name)"
                      id: "61"
                      ip_address: "<your_own_value>"
              rp_register_keepalive: "185"
              spt_threshold: "enable"
              spt_threshold_group: "<your_own_value> (source router.access-list.name)"
              ssm: "enable"
              ssm_range: "<your_own_value> (source router.access-list.name)"
          pim_sm_global_vrf:
              -
                  bsr_allow_quick_refresh: "enable"
                  bsr_candidate: "enable"
                  bsr_hash: "10"
                  bsr_interface: "<your_own_value> (source system.interface.name)"
                  bsr_priority: "0"
                  cisco_crp_prefix: "enable"
                  rp_address:
                      -
                          group: "<your_own_value> (source router.access-list.name)"
                          id: "77"
                          ip_address: "<your_own_value>"
                  vrf: "<you_own_value>"
          route_limit: "2147483647"
          route_threshold: ""
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


def filter_router_multicast_data(json):
    option_list = [
        "interface",
        "multicast_routing",
        "pim_sm_global",
        "pim_sm_global_vrf",
        "route_limit",
        "route_threshold",
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


def router_multicast(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    router_multicast_data = data["router_multicast"]

    filtered_data = filter_router_multicast_data(router_multicast_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("router", "multicast", filtered_data, vdom=vdom)
        current_data = fos.get("router", "multicast", vdom=vdom, mkey=mkey)
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
    data_copy["router_multicast"] = filtered_data
    fos.do_member_operation(
        "router",
        "multicast",
        data_copy,
    )

    return fos.set("router", "multicast", data=converted_data, vdom=vdom)


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

    if data["router_multicast"]:
        resp = router_multicast(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_multicast"))
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
        "route_threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "route_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "multicast_routing": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pim_sm_global": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "message_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "join_prune_holdtime": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "accept_register_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "accept_source_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "bsr_candidate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bsr_interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "bsr_priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "bsr_hash": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "bsr_allow_quick_refresh": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "cisco_crp_prefix": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "cisco_register_checksum": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "cisco_register_checksum_group": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                },
                "cisco_ignore_rp_set_priority": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "register_rp_reachability": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "register_source": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "interface"},
                        {"value": "ip-address"},
                    ],
                },
                "register_source_interface": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                },
                "register_source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "register_supression": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "null_register_retries": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "rp_register_keepalive": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "spt_threshold": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "spt_threshold_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ssm": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ssm_range": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "register_rate_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "pim_use_sdwan": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rp_address": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "ip_address": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "group": {"v_range": [["v6.0.0", ""]], "type": "string"},
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
        },
        "pim_sm_global_vrf": {
            "type": "list",
            "elements": "dict",
            "children": {
                "vrf": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "integer",
                    "required": True,
                },
                "bsr_candidate": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bsr_interface": {"v_range": [["v7.6.1", ""]], "type": "string"},
                "bsr_priority": {"v_range": [["v7.6.1", ""]], "type": "integer"},
                "bsr_hash": {"v_range": [["v7.6.1", ""]], "type": "integer"},
                "bsr_allow_quick_refresh": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "cisco_crp_prefix": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rp_address": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.6.1", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "ip_address": {"v_range": [["v7.6.1", ""]], "type": "string"},
                        "group": {"v_range": [["v7.6.1", ""]], "type": "string"},
                    },
                    "v_range": [["v7.6.1", ""]],
                },
            },
            "v_range": [["v7.6.1", ""]],
        },
        "interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "ttl_threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "pim_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "sparse-mode"}, {"value": "dense-mode"}],
                },
                "passive": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bfd": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "neighbour_filter": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "hello_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "hello_holdtime": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "cisco_exclude_genid": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "dr_priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "propagation_delay": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "state_refresh_interval": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "rp_candidate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rp_candidate_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "rp_candidate_priority": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "rp_candidate_interval": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "multicast_flow": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "static_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "rpf_nbr_fail_back": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rpf_nbr_fail_back_filter": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                },
                "join_group": {
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
                "igmp": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "access_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "version": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "3"}, {"value": "2"}, {"value": "1"}],
                        },
                        "immediate_leave_group": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                        },
                        "last_member_query_interval": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "last_member_query_count": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "query_max_response_time": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "query_interval": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "query_timeout": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "router_alert_check": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                    },
                },
            },
            "v_range": [["v6.0.0", ""]],
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
        "router_multicast": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_multicast"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_multicast"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "router_multicast"
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
