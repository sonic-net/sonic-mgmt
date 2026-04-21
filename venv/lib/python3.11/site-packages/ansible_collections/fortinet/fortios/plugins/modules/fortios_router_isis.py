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
module: fortios_router_isis
short_description: Configure IS-IS in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify router feature and isis category.
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

    router_isis:
        description:
            - Configure IS-IS.
        default: null
        type: dict
        suboptions:
            adjacency_check:
                description:
                    - Enable/disable adjacency check.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            adjacency_check6:
                description:
                    - Enable/disable IPv6 adjacency check.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            adv_passive_only:
                description:
                    - Enable/disable IS-IS advertisement of passive interfaces only.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            adv_passive_only6:
                description:
                    - Enable/disable IPv6 IS-IS advertisement of passive interfaces only.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_keychain_l1:
                description:
                    - Authentication key-chain for level 1 PDUs. Source router.key-chain.name.
                type: str
            auth_keychain_l2:
                description:
                    - Authentication key-chain for level 2 PDUs. Source router.key-chain.name.
                type: str
            auth_mode_l1:
                description:
                    - Level 1 authentication mode.
                type: str
                choices:
                    - 'password'
                    - 'md5'
            auth_mode_l2:
                description:
                    - Level 2 authentication mode.
                type: str
                choices:
                    - 'password'
                    - 'md5'
            auth_password_l1:
                description:
                    - Authentication password for level 1 PDUs.
                type: str
            auth_password_l2:
                description:
                    - Authentication password for level 2 PDUs.
                type: str
            auth_sendonly_l1:
                description:
                    - Enable/disable level 1 authentication send-only.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_sendonly_l2:
                description:
                    - Enable/disable level 2 authentication send-only.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            default_originate:
                description:
                    - Enable/disable distribution of default route information.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            default_originate6:
                description:
                    - Enable/disable distribution of default IPv6 route information.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dynamic_hostname:
                description:
                    - Enable/disable dynamic hostname.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ignore_lsp_errors:
                description:
                    - Enable/disable ignoring of LSP errors with bad checksums.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            is_type:
                description:
                    - IS type.
                type: str
                choices:
                    - 'level-1-2'
                    - 'level-1'
                    - 'level-2-only'
            isis_interface:
                description:
                    - IS-IS interface configuration.
                type: list
                elements: dict
                suboptions:
                    auth_keychain_l1:
                        description:
                            - Authentication key-chain for level 1 PDUs. Source router.key-chain.name.
                        type: str
                    auth_keychain_l2:
                        description:
                            - Authentication key-chain for level 2 PDUs. Source router.key-chain.name.
                        type: str
                    auth_mode_l1:
                        description:
                            - Level 1 authentication mode.
                        type: str
                        choices:
                            - 'md5'
                            - 'password'
                    auth_mode_l2:
                        description:
                            - Level 2 authentication mode.
                        type: str
                        choices:
                            - 'md5'
                            - 'password'
                    auth_password_l1:
                        description:
                            - Authentication password for level 1 PDUs.
                        type: str
                    auth_password_l2:
                        description:
                            - Authentication password for level 2 PDUs.
                        type: str
                    auth_send_only_l1:
                        description:
                            - Enable/disable authentication send-only for level 1 PDUs.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    auth_send_only_l2:
                        description:
                            - Enable/disable authentication send-only for level 2 PDUs.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    circuit_type:
                        description:
                            - IS-IS interface"s circuit type.
                        type: str
                        choices:
                            - 'level-1-2'
                            - 'level-1'
                            - 'level-2'
                    csnp_interval_l1:
                        description:
                            - Level 1 CSNP interval.
                        type: int
                    csnp_interval_l2:
                        description:
                            - Level 2 CSNP interval.
                        type: int
                    hello_interval_l1:
                        description:
                            - Level 1 hello interval.
                        type: int
                    hello_interval_l2:
                        description:
                            - Level 2 hello interval.
                        type: int
                    hello_multiplier_l1:
                        description:
                            - Level 1 multiplier for Hello holding time.
                        type: int
                    hello_multiplier_l2:
                        description:
                            - Level 2 multiplier for Hello holding time.
                        type: int
                    hello_padding:
                        description:
                            - Enable/disable padding to IS-IS hello packets.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    lsp_interval:
                        description:
                            - LSP transmission interval (milliseconds).
                        type: int
                    lsp_retransmit_interval:
                        description:
                            - LSP retransmission interval (sec).
                        type: int
                    mesh_group:
                        description:
                            - Enable/disable IS-IS mesh group.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    mesh_group_id:
                        description:
                            - 'Mesh group ID <0-4294967295>, 0: mesh-group blocked.'
                        type: int
                    metric_l1:
                        description:
                            - Level 1 metric for interface.
                        type: int
                    metric_l2:
                        description:
                            - Level 2 metric for interface.
                        type: int
                    name:
                        description:
                            - IS-IS interface name. Source system.interface.name.
                        required: true
                        type: str
                    network_type:
                        description:
                            - IS-IS interface"s network type.
                        type: str
                        choices:
                            - 'broadcast'
                            - 'point-to-point'
                            - 'loopback'
                    priority_l1:
                        description:
                            - Level 1 priority.
                        type: int
                    priority_l2:
                        description:
                            - Level 2 priority.
                        type: int
                    status:
                        description:
                            - Enable/disable interface for IS-IS.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status6:
                        description:
                            - Enable/disable IPv6 interface for IS-IS.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    wide_metric_l1:
                        description:
                            - Level 1 wide metric for interface.
                        type: int
                    wide_metric_l2:
                        description:
                            - Level 2 wide metric for interface.
                        type: int
            isis_net:
                description:
                    - IS-IS net configuration.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ISIS network ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    net:
                        description:
                            - IS-IS networks (format = xx.xxxx.  .xxxx.xx.).
                        type: str
            lsp_gen_interval_l1:
                description:
                    - Minimum interval for level 1 LSP regenerating.
                type: int
            lsp_gen_interval_l2:
                description:
                    - Minimum interval for level 2 LSP regenerating.
                type: int
            lsp_refresh_interval:
                description:
                    - LSP refresh time in seconds.
                type: int
            max_lsp_lifetime:
                description:
                    - Maximum LSP lifetime in seconds.
                type: int
            metric_style:
                description:
                    - Use old-style (ISO 10589) or new-style packet formats.
                type: str
                choices:
                    - 'narrow'
                    - 'wide'
                    - 'transition'
                    - 'narrow-transition'
                    - 'narrow-transition-l1'
                    - 'narrow-transition-l2'
                    - 'wide-l1'
                    - 'wide-l2'
                    - 'wide-transition'
                    - 'wide-transition-l1'
                    - 'wide-transition-l2'
                    - 'transition-l1'
                    - 'transition-l2'
            overload_bit:
                description:
                    - Enable/disable signal other routers not to use us in SPF.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            overload_bit_on_startup:
                description:
                    - Overload-bit only temporarily after reboot.
                type: int
            overload_bit_suppress:
                description:
                    - Suppress overload-bit for the specific prefixes.
                type: list
                elements: str
                choices:
                    - 'external'
                    - 'interlevel'
            redistribute:
                description:
                    - IS-IS redistribute protocols.
                type: list
                elements: dict
                suboptions:
                    level:
                        description:
                            - Level.
                        type: str
                        choices:
                            - 'level-1-2'
                            - 'level-1'
                            - 'level-2'
                    metric:
                        description:
                            - Metric.
                        type: int
                    metric_type:
                        description:
                            - Metric type.
                        type: str
                        choices:
                            - 'external'
                            - 'internal'
                    protocol:
                        description:
                            - Protocol name.
                        required: true
                        type: str
                    routemap:
                        description:
                            - Route map name. Source router.route-map.name.
                        type: str
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            redistribute_l1:
                description:
                    - Enable/disable redistribution of level 1 routes into level 2.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            redistribute_l1_list:
                description:
                    - Access-list for route redistribution from l1 to l2. Source router.access-list.name.
                type: str
            redistribute_l2:
                description:
                    - Enable/disable redistribution of level 2 routes into level 1.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            redistribute_l2_list:
                description:
                    - Access-list for route redistribution from l2 to l1. Source router.access-list.name.
                type: str
            redistribute6:
                description:
                    - IS-IS IPv6 redistribution for routing protocols.
                type: list
                elements: dict
                suboptions:
                    level:
                        description:
                            - Level.
                        type: str
                        choices:
                            - 'level-1-2'
                            - 'level-1'
                            - 'level-2'
                    metric:
                        description:
                            - Metric.
                        type: int
                    metric_type:
                        description:
                            - Metric type.
                        type: str
                        choices:
                            - 'external'
                            - 'internal'
                    protocol:
                        description:
                            - Protocol name.
                        required: true
                        type: str
                    routemap:
                        description:
                            - Route map name. Source router.route-map.name.
                        type: str
                    status:
                        description:
                            - Enable/disable redistribution.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            redistribute6_l1:
                description:
                    - Enable/disable redistribution of level 1 IPv6 routes into level 2.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            redistribute6_l1_list:
                description:
                    - Access-list for IPv6 route redistribution from l1 to l2. Source router.access-list6.name.
                type: str
            redistribute6_l2:
                description:
                    - Enable/disable redistribution of level 2 IPv6 routes into level 1.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            redistribute6_l2_list:
                description:
                    - Access-list for IPv6 route redistribution from l2 to l1. Source router.access-list6.name.
                type: str
            spf_interval_exp_l1:
                description:
                    - Level 1 SPF calculation delay.
                type: str
            spf_interval_exp_l2:
                description:
                    - Level 2 SPF calculation delay.
                type: str
            summary_address:
                description:
                    - IS-IS summary addresses.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Summary address entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    level:
                        description:
                            - Level.
                        type: str
                        choices:
                            - 'level-1-2'
                            - 'level-1'
                            - 'level-2'
                    prefix:
                        description:
                            - Prefix.
                        type: str
            summary_address6:
                description:
                    - IS-IS IPv6 summary address.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Prefix entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    level:
                        description:
                            - Level.
                        type: str
                        choices:
                            - 'level-1-2'
                            - 'level-1'
                            - 'level-2'
                    prefix6:
                        description:
                            - IPv6 prefix.
                        type: str
"""

EXAMPLES = """
- name: Configure IS-IS.
  fortinet.fortios.fortios_router_isis:
      vdom: "{{ vdom }}"
      router_isis:
          adjacency_check: "enable"
          adjacency_check6: "enable"
          adv_passive_only: "enable"
          adv_passive_only6: "enable"
          auth_keychain_l1: "<your_own_value> (source router.key-chain.name)"
          auth_keychain_l2: "<your_own_value> (source router.key-chain.name)"
          auth_mode_l1: "password"
          auth_mode_l2: "password"
          auth_password_l1: "<your_own_value>"
          auth_password_l2: "<your_own_value>"
          auth_sendonly_l1: "enable"
          auth_sendonly_l2: "enable"
          default_originate: "enable"
          default_originate6: "enable"
          dynamic_hostname: "enable"
          ignore_lsp_errors: "enable"
          is_type: "level-1-2"
          isis_interface:
              -
                  auth_keychain_l1: "<your_own_value> (source router.key-chain.name)"
                  auth_keychain_l2: "<your_own_value> (source router.key-chain.name)"
                  auth_mode_l1: "md5"
                  auth_mode_l2: "md5"
                  auth_password_l1: "<your_own_value>"
                  auth_password_l2: "<your_own_value>"
                  auth_send_only_l1: "enable"
                  auth_send_only_l2: "enable"
                  circuit_type: "level-1-2"
                  csnp_interval_l1: "10"
                  csnp_interval_l2: "10"
                  hello_interval_l1: "10"
                  hello_interval_l2: "10"
                  hello_multiplier_l1: "3"
                  hello_multiplier_l2: "3"
                  hello_padding: "enable"
                  lsp_interval: "33"
                  lsp_retransmit_interval: "5"
                  mesh_group: "enable"
                  mesh_group_id: "0"
                  metric_l1: "10"
                  metric_l2: "10"
                  name: "default_name_43 (source system.interface.name)"
                  network_type: "broadcast"
                  priority_l1: "64"
                  priority_l2: "64"
                  status: "enable"
                  status6: "enable"
                  wide_metric_l1: "10"
                  wide_metric_l2: "10"
          isis_net:
              -
                  id: "52"
                  net: "<your_own_value>"
          lsp_gen_interval_l1: "30"
          lsp_gen_interval_l2: "30"
          lsp_refresh_interval: "900"
          max_lsp_lifetime: "1200"
          metric_style: "narrow"
          overload_bit: "enable"
          overload_bit_on_startup: "0"
          overload_bit_suppress: "external"
          redistribute:
              -
                  level: "level-1-2"
                  metric: "0"
                  metric_type: "external"
                  protocol: "<your_own_value>"
                  routemap: "<your_own_value> (source router.route-map.name)"
                  status: "enable"
          redistribute_l1: "enable"
          redistribute_l1_list: "<your_own_value> (source router.access-list.name)"
          redistribute_l2: "enable"
          redistribute_l2_list: "<your_own_value> (source router.access-list.name)"
          redistribute6:
              -
                  level: "level-1-2"
                  metric: "0"
                  metric_type: "external"
                  protocol: "<your_own_value>"
                  routemap: "<your_own_value> (source router.route-map.name)"
                  status: "enable"
          redistribute6_l1: "enable"
          redistribute6_l1_list: "<your_own_value> (source router.access-list6.name)"
          redistribute6_l2: "enable"
          redistribute6_l2_list: "<your_own_value> (source router.access-list6.name)"
          spf_interval_exp_l1: "<your_own_value>"
          spf_interval_exp_l2: "<your_own_value>"
          summary_address:
              -
                  id: "87"
                  level: "level-1-2"
                  prefix: "<your_own_value>"
          summary_address6:
              -
                  id: "91"
                  level: "level-1-2"
                  prefix6: "<your_own_value>"
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


def filter_router_isis_data(json):
    option_list = [
        "adjacency_check",
        "adjacency_check6",
        "adv_passive_only",
        "adv_passive_only6",
        "auth_keychain_l1",
        "auth_keychain_l2",
        "auth_mode_l1",
        "auth_mode_l2",
        "auth_password_l1",
        "auth_password_l2",
        "auth_sendonly_l1",
        "auth_sendonly_l2",
        "default_originate",
        "default_originate6",
        "dynamic_hostname",
        "ignore_lsp_errors",
        "is_type",
        "isis_interface",
        "isis_net",
        "lsp_gen_interval_l1",
        "lsp_gen_interval_l2",
        "lsp_refresh_interval",
        "max_lsp_lifetime",
        "metric_style",
        "overload_bit",
        "overload_bit_on_startup",
        "overload_bit_suppress",
        "redistribute",
        "redistribute_l1",
        "redistribute_l1_list",
        "redistribute_l2",
        "redistribute_l2_list",
        "redistribute6",
        "redistribute6_l1",
        "redistribute6_l1_list",
        "redistribute6_l2",
        "redistribute6_l2_list",
        "spf_interval_exp_l1",
        "spf_interval_exp_l2",
        "summary_address",
        "summary_address6",
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
        ["overload_bit_suppress"],
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


def router_isis(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    router_isis_data = data["router_isis"]

    filtered_data = filter_router_isis_data(router_isis_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("router", "isis", filtered_data, vdom=vdom)
        current_data = fos.get("router", "isis", vdom=vdom, mkey=mkey)
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
    data_copy["router_isis"] = filtered_data
    fos.do_member_operation(
        "router",
        "isis",
        data_copy,
    )

    return fos.set("router", "isis", data=converted_data, vdom=vdom)


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

    if data["router_isis"]:
        resp = router_isis(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_isis"))
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
        "is_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "level-1-2"},
                {"value": "level-1"},
                {"value": "level-2-only"},
            ],
        },
        "adv_passive_only": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "adv_passive_only6": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_mode_l1": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "password"}, {"value": "md5"}],
        },
        "auth_mode_l2": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "password"}, {"value": "md5"}],
        },
        "auth_password_l1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "auth_password_l2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "auth_keychain_l1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "auth_keychain_l2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "auth_sendonly_l1": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_sendonly_l2": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ignore_lsp_errors": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "lsp_gen_interval_l1": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "lsp_gen_interval_l2": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "lsp_refresh_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "max_lsp_lifetime": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "spf_interval_exp_l1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "spf_interval_exp_l2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dynamic_hostname": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "adjacency_check": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "adjacency_check6": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "overload_bit": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "overload_bit_suppress": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [{"value": "external"}, {"value": "interlevel"}],
            "multiple_values": True,
            "elements": "str",
        },
        "overload_bit_on_startup": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "default_originate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "default_originate6": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "metric_style": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "narrow"},
                {"value": "wide"},
                {"value": "transition"},
                {"value": "narrow-transition"},
                {"value": "narrow-transition-l1"},
                {"value": "narrow-transition-l2"},
                {"value": "wide-l1"},
                {"value": "wide-l2"},
                {"value": "wide-transition"},
                {"value": "wide-transition-l1"},
                {"value": "wide-transition-l2"},
                {"value": "transition-l1"},
                {"value": "transition-l2"},
            ],
        },
        "redistribute_l1": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "redistribute_l1_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "redistribute_l2": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "redistribute_l2_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "redistribute6_l1": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "redistribute6_l1_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "redistribute6_l2": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "redistribute6_l2_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "isis_net": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "net": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "isis_interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "status6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "network_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "broadcast"},
                        {"value": "point-to-point"},
                        {"value": "loopback"},
                    ],
                },
                "circuit_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "level-1-2"},
                        {"value": "level-1"},
                        {"value": "level-2"},
                    ],
                },
                "csnp_interval_l1": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "csnp_interval_l2": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "hello_interval_l1": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "hello_interval_l2": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "hello_multiplier_l1": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "hello_multiplier_l2": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "hello_padding": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "lsp_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "lsp_retransmit_interval": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "metric_l1": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "metric_l2": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "wide_metric_l1": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "wide_metric_l2": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "auth_password_l1": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "auth_password_l2": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "auth_keychain_l1": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "auth_keychain_l2": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "auth_send_only_l1": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "auth_send_only_l2": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "auth_mode_l1": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "md5"}, {"value": "password"}],
                },
                "auth_mode_l2": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "md5"}, {"value": "password"}],
                },
                "priority_l1": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "priority_l2": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "mesh_group": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "mesh_group_id": {"v_range": [["v6.0.0", ""]], "type": "integer"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "summary_address": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "prefix": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "level": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "level-1-2"},
                        {"value": "level-1"},
                        {"value": "level-2"},
                    ],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "summary_address6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "prefix6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "level": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "level-1-2"},
                        {"value": "level-1"},
                        {"value": "level-2"},
                    ],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "redistribute": {
            "type": "list",
            "elements": "dict",
            "children": {
                "protocol": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "metric": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "metric_type": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "options": [{"value": "external"}, {"value": "internal"}],
                },
                "level": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "options": [
                        {"value": "level-1-2"},
                        {"value": "level-1"},
                        {"value": "level-2"},
                    ],
                },
                "routemap": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
            },
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
        },
        "redistribute6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "protocol": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "metric": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "metric_type": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "options": [{"value": "external"}, {"value": "internal"}],
                },
                "level": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "options": [
                        {"value": "level-1-2"},
                        {"value": "level-1"},
                        {"value": "level-2"},
                    ],
                },
                "routemap": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
            },
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
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
        "router_isis": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_isis"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_isis"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "router_isis"
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
