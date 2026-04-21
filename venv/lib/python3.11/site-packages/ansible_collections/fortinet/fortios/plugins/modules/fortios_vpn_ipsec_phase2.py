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
module: fortios_vpn_ipsec_phase2
short_description: Configure VPN autokey tunnel in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify vpn_ipsec feature and phase2 category.
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
    vpn_ipsec_phase2:
        description:
            - Configure VPN autokey tunnel.
        default: null
        type: dict
        suboptions:
            add_route:
                description:
                    - Enable/disable automatic route addition.
                type: str
                choices:
                    - 'phase1'
                    - 'enable'
                    - 'disable'
            addke1:
                description:
                    - phase2 ADDKE1 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            addke2:
                description:
                    - phase2 ADDKE2 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            addke3:
                description:
                    - phase2 ADDKE3 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            addke4:
                description:
                    - phase2 ADDKE4 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            addke5:
                description:
                    - phase2 ADDKE5 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            addke6:
                description:
                    - phase2 ADDKE6 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            addke7:
                description:
                    - phase2 ADDKE7 group.
                type: list
                elements: str
                choices:
                    - '0'
                    - '35'
                    - '36'
                    - '37'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
            auto_negotiate:
                description:
                    - Enable/disable IPsec SA auto-negotiation.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            comments:
                description:
                    - Comment.
                type: str
            dhcp_ipsec:
                description:
                    - Enable/disable DHCP-IPsec.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dhgrp:
                description:
                    - Phase2 DH group.
                type: list
                elements: str
                choices:
                    - '1'
                    - '2'
                    - '5'
                    - '14'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '21'
                    - '27'
                    - '28'
                    - '29'
                    - '30'
                    - '31'
                    - '32'
            diffserv:
                description:
                    - Enable/disable applying DSCP value to the IPsec tunnel outer IP header.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            diffservcode:
                description:
                    - DSCP value to be applied to the IPsec tunnel outer IP header.
                type: str
            dst_addr_type:
                description:
                    - Remote proxy ID type.
                type: str
                choices:
                    - 'subnet'
                    - 'range'
                    - 'ip'
                    - 'name'
            dst_end_ip:
                description:
                    - Remote proxy ID IPv4 end.
                type: str
            dst_end_ip6:
                description:
                    - Remote proxy ID IPv6 end.
                type: str
            dst_name:
                description:
                    - Remote proxy ID name. Source firewall.address.name firewall.addrgrp.name.
                type: str
            dst_name6:
                description:
                    - Remote proxy ID name. Source firewall.address6.name firewall.addrgrp6.name.
                type: str
            dst_port:
                description:
                    - Quick mode destination port (1 - 65535 or 0 for all).
                type: int
            dst_start_ip:
                description:
                    - Remote proxy ID IPv4 start.
                type: str
            dst_start_ip6:
                description:
                    - Remote proxy ID IPv6 start.
                type: str
            dst_subnet:
                description:
                    - Remote proxy ID IPv4 subnet.
                type: str
            dst_subnet6:
                description:
                    - Remote proxy ID IPv6 subnet.
                type: str
            encapsulation:
                description:
                    - ESP encapsulation mode.
                type: str
                choices:
                    - 'tunnel-mode'
                    - 'transport-mode'
            inbound_dscp_copy:
                description:
                    - Enable/disable copying of the DSCP in the ESP header to the inner IP header.
                type: str
                choices:
                    - 'phase1'
                    - 'enable'
                    - 'disable'
            initiator_ts_narrow:
                description:
                    - Enable/disable traffic selector narrowing for IKEv2 initiator.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv4_df:
                description:
                    - Enable/disable setting and resetting of IPv4 "Don"t Fragment" bit.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            keepalive:
                description:
                    - Enable/disable keep alive.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            keylife_type:
                description:
                    - Keylife type.
                type: str
                choices:
                    - 'seconds'
                    - 'kbs'
                    - 'both'
            keylifekbs:
                description:
                    - Phase2 key life in number of kilobytes of traffic (5120 - 4294967295).
                type: int
            keylifeseconds:
                description:
                    - Phase2 key life in time in seconds (120 - 172800).
                type: int
            l2tp:
                description:
                    - Enable/disable L2TP over IPsec.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - IPsec tunnel name.
                required: true
                type: str
            pfs:
                description:
                    - Enable/disable PFS feature.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            phase1name:
                description:
                    - Phase 1 determines the options required for phase 2. Source vpn.ipsec.phase1.name.
                type: str
            proposal:
                description:
                    - Phase2 proposal.
                type: list
                elements: str
                choices:
                    - 'null-md5'
                    - 'null-sha1'
                    - 'null-sha256'
                    - 'null-sha384'
                    - 'null-sha512'
                    - 'des-null'
                    - 'des-md5'
                    - 'des-sha1'
                    - 'des-sha256'
                    - 'des-sha384'
                    - 'des-sha512'
                    - '3des-null'
                    - '3des-md5'
                    - '3des-sha1'
                    - '3des-sha256'
                    - '3des-sha384'
                    - '3des-sha512'
                    - 'aes128-null'
                    - 'aes128-md5'
                    - 'aes128-sha1'
                    - 'aes128-sha256'
                    - 'aes128-sha384'
                    - 'aes128-sha512'
                    - 'aes128gcm'
                    - 'aes192-null'
                    - 'aes192-md5'
                    - 'aes192-sha1'
                    - 'aes192-sha256'
                    - 'aes192-sha384'
                    - 'aes192-sha512'
                    - 'aes256-null'
                    - 'aes256-md5'
                    - 'aes256-sha1'
                    - 'aes256-sha256'
                    - 'aes256-sha384'
                    - 'aes256-sha512'
                    - 'aes256gcm'
                    - 'chacha20poly1305'
                    - 'aria128-null'
                    - 'aria128-md5'
                    - 'aria128-sha1'
                    - 'aria128-sha256'
                    - 'aria128-sha384'
                    - 'aria128-sha512'
                    - 'aria192-null'
                    - 'aria192-md5'
                    - 'aria192-sha1'
                    - 'aria192-sha256'
                    - 'aria192-sha384'
                    - 'aria192-sha512'
                    - 'aria256-null'
                    - 'aria256-md5'
                    - 'aria256-sha1'
                    - 'aria256-sha256'
                    - 'aria256-sha384'
                    - 'aria256-sha512'
                    - 'seed-null'
                    - 'seed-md5'
                    - 'seed-sha1'
                    - 'seed-sha256'
                    - 'seed-sha384'
                    - 'seed-sha512'
            protocol:
                description:
                    - Quick mode protocol selector (1 - 255 or 0 for all).
                type: int
            replay:
                description:
                    - Enable/disable replay detection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            route_overlap:
                description:
                    - Action for overlapping routes.
                type: str
                choices:
                    - 'use-old'
                    - 'use-new'
                    - 'allow'
            selector_match:
                description:
                    - Match type to use when comparing selectors.
                type: str
                choices:
                    - 'exact'
                    - 'subset'
                    - 'auto'
            single_source:
                description:
                    - Enable/disable single source IP restriction.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            src_addr_type:
                description:
                    - Local proxy ID type.
                type: str
                choices:
                    - 'subnet'
                    - 'range'
                    - 'ip'
                    - 'name'
            src_end_ip:
                description:
                    - Local proxy ID end.
                type: str
            src_end_ip6:
                description:
                    - Local proxy ID IPv6 end.
                type: str
            src_name:
                description:
                    - Local proxy ID name. Source firewall.address.name firewall.addrgrp.name.
                type: str
            src_name6:
                description:
                    - Local proxy ID name. Source firewall.address6.name firewall.addrgrp6.name.
                type: str
            src_port:
                description:
                    - Quick mode source port (1 - 65535 or 0 for all).
                type: int
            src_start_ip:
                description:
                    - Local proxy ID start.
                type: str
            src_start_ip6:
                description:
                    - Local proxy ID IPv6 start.
                type: str
            src_subnet:
                description:
                    - Local proxy ID subnet.
                type: str
            src_subnet6:
                description:
                    - Local proxy ID IPv6 subnet.
                type: str
            use_natip:
                description:
                    - Enable to use the FortiGate public IP as the source selector when outbound NAT is used.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure VPN autokey tunnel.
  fortinet.fortios.fortios_vpn_ipsec_phase2:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      vpn_ipsec_phase2:
          add_route: "phase1"
          addke1: "0"
          addke2: "0"
          addke3: "0"
          addke4: "0"
          addke5: "0"
          addke6: "0"
          addke7: "0"
          auto_negotiate: "enable"
          comments: "<your_own_value>"
          dhcp_ipsec: "enable"
          dhgrp: "1"
          diffserv: "enable"
          diffservcode: "<your_own_value>"
          dst_addr_type: "subnet"
          dst_end_ip: "<your_own_value>"
          dst_end_ip6: "<your_own_value>"
          dst_name: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
          dst_name6: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
          dst_port: "0"
          dst_start_ip: "<your_own_value>"
          dst_start_ip6: "<your_own_value>"
          dst_subnet: "<your_own_value>"
          dst_subnet6: "<your_own_value>"
          encapsulation: "tunnel-mode"
          inbound_dscp_copy: "phase1"
          initiator_ts_narrow: "enable"
          ipv4_df: "enable"
          keepalive: "enable"
          keylife_type: "seconds"
          keylifekbs: "5120"
          keylifeseconds: "43200"
          l2tp: "enable"
          name: "default_name_36"
          pfs: "enable"
          phase1name: "<your_own_value> (source vpn.ipsec.phase1.name)"
          proposal: "null-md5"
          protocol: "0"
          replay: "enable"
          route_overlap: "use-old"
          selector_match: "exact"
          single_source: "enable"
          src_addr_type: "subnet"
          src_end_ip: "<your_own_value>"
          src_end_ip6: "<your_own_value>"
          src_name: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
          src_name6: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
          src_port: "0"
          src_start_ip: "<your_own_value>"
          src_start_ip6: "<your_own_value>"
          src_subnet: "<your_own_value>"
          src_subnet6: "<your_own_value>"
          use_natip: "enable"
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


def filter_vpn_ipsec_phase2_data(json):
    option_list = [
        "add_route",
        "addke1",
        "addke2",
        "addke3",
        "addke4",
        "addke5",
        "addke6",
        "addke7",
        "auto_negotiate",
        "comments",
        "dhcp_ipsec",
        "dhgrp",
        "diffserv",
        "diffservcode",
        "dst_addr_type",
        "dst_end_ip",
        "dst_end_ip6",
        "dst_name",
        "dst_name6",
        "dst_port",
        "dst_start_ip",
        "dst_start_ip6",
        "dst_subnet",
        "dst_subnet6",
        "encapsulation",
        "inbound_dscp_copy",
        "initiator_ts_narrow",
        "ipv4_df",
        "keepalive",
        "keylife_type",
        "keylifekbs",
        "keylifeseconds",
        "l2tp",
        "name",
        "pfs",
        "phase1name",
        "proposal",
        "protocol",
        "replay",
        "route_overlap",
        "selector_match",
        "single_source",
        "src_addr_type",
        "src_end_ip",
        "src_end_ip6",
        "src_name",
        "src_name6",
        "src_port",
        "src_start_ip",
        "src_start_ip6",
        "src_subnet",
        "src_subnet6",
        "use_natip",
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
        ["proposal"],
        ["dhgrp"],
        ["addke1"],
        ["addke2"],
        ["addke3"],
        ["addke4"],
        ["addke5"],
        ["addke6"],
        ["addke7"],
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


def vpn_ipsec_phase2(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    vpn_ipsec_phase2_data = data["vpn_ipsec_phase2"]

    filtered_data = filter_vpn_ipsec_phase2_data(vpn_ipsec_phase2_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("vpn.ipsec", "phase2", filtered_data, vdom=vdom)
        current_data = fos.get("vpn.ipsec", "phase2", vdom=vdom, mkey=mkey)
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
    data_copy["vpn_ipsec_phase2"] = filtered_data
    fos.do_member_operation(
        "vpn.ipsec",
        "phase2",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("vpn.ipsec", "phase2", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("vpn.ipsec", "phase2", mkey=converted_data["name"], vdom=vdom)
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


def fortios_vpn_ipsec(data, fos, check_mode):

    if data["vpn_ipsec_phase2"]:
        resp = vpn_ipsec_phase2(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("vpn_ipsec_phase2"))
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
        "phase1name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dhcp_ipsec": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "use_natip": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "selector_match": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "exact"}, {"value": "subset"}, {"value": "auto"}],
        },
        "proposal": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "null-md5"},
                {"value": "null-sha1"},
                {"value": "null-sha256"},
                {"value": "null-sha384"},
                {"value": "null-sha512"},
                {"value": "des-null"},
                {"value": "des-md5"},
                {"value": "des-sha1"},
                {"value": "des-sha256"},
                {"value": "des-sha384"},
                {"value": "des-sha512"},
                {"value": "3des-null"},
                {"value": "3des-md5"},
                {"value": "3des-sha1"},
                {"value": "3des-sha256"},
                {"value": "3des-sha384"},
                {"value": "3des-sha512"},
                {"value": "aes128-null"},
                {"value": "aes128-md5"},
                {"value": "aes128-sha1"},
                {"value": "aes128-sha256"},
                {"value": "aes128-sha384"},
                {"value": "aes128-sha512"},
                {"value": "aes128gcm"},
                {"value": "aes192-null"},
                {"value": "aes192-md5"},
                {"value": "aes192-sha1"},
                {"value": "aes192-sha256"},
                {"value": "aes192-sha384"},
                {"value": "aes192-sha512"},
                {"value": "aes256-null"},
                {"value": "aes256-md5"},
                {"value": "aes256-sha1"},
                {"value": "aes256-sha256"},
                {"value": "aes256-sha384"},
                {"value": "aes256-sha512"},
                {"value": "aes256gcm"},
                {"value": "chacha20poly1305"},
                {"value": "aria128-null"},
                {"value": "aria128-md5"},
                {"value": "aria128-sha1"},
                {"value": "aria128-sha256"},
                {"value": "aria128-sha384"},
                {"value": "aria128-sha512"},
                {"value": "aria192-null"},
                {"value": "aria192-md5"},
                {"value": "aria192-sha1"},
                {"value": "aria192-sha256"},
                {"value": "aria192-sha384"},
                {"value": "aria192-sha512"},
                {"value": "aria256-null"},
                {"value": "aria256-md5"},
                {"value": "aria256-sha1"},
                {"value": "aria256-sha256"},
                {"value": "aria256-sha384"},
                {"value": "aria256-sha512"},
                {"value": "seed-null"},
                {"value": "seed-md5"},
                {"value": "seed-sha1"},
                {"value": "seed-sha256"},
                {"value": "seed-sha384"},
                {"value": "seed-sha512"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "pfs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dhgrp": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "1"},
                {"value": "2"},
                {"value": "5"},
                {"value": "14"},
                {"value": "15"},
                {"value": "16"},
                {"value": "17"},
                {"value": "18"},
                {"value": "19"},
                {"value": "20"},
                {"value": "21"},
                {"value": "27"},
                {"value": "28"},
                {"value": "29"},
                {"value": "30"},
                {"value": "31"},
                {"value": "32", "v_range": [["v6.2.0", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke1": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke2": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke3": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke4": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke5": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke6": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "addke7": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "options": [
                {"value": "0"},
                {"value": "35", "v_range": [["v7.6.1", ""]]},
                {"value": "36", "v_range": [["v7.6.1", ""]]},
                {"value": "37", "v_range": [["v7.6.1", ""]]},
                {"value": "1080"},
                {"value": "1081"},
                {"value": "1082"},
                {"value": "1083", "v_range": [["v7.6.1", ""]]},
                {"value": "1084", "v_range": [["v7.6.1", ""]]},
                {"value": "1085", "v_range": [["v7.6.1", ""]]},
                {"value": "1089", "v_range": [["v7.6.1", ""]]},
                {"value": "1090", "v_range": [["v7.6.1", ""]]},
                {"value": "1091", "v_range": [["v7.6.1", ""]]},
                {"value": "1092", "v_range": [["v7.6.1", ""]]},
                {"value": "1093", "v_range": [["v7.6.1", ""]]},
                {"value": "1094", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "replay": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "keepalive": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auto_negotiate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "add_route": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "phase1"}, {"value": "enable"}, {"value": "disable"}],
        },
        "inbound_dscp_copy": {
            "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "phase1"}, {"value": "enable"}, {"value": "disable"}],
        },
        "keylifeseconds": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "keylifekbs": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "keylife_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "seconds"}, {"value": "kbs"}, {"value": "both"}],
        },
        "single_source": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "route_overlap": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "use-old"}, {"value": "use-new"}, {"value": "allow"}],
        },
        "encapsulation": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "tunnel-mode"}, {"value": "transport-mode"}],
        },
        "l2tp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "initiator_ts_narrow": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffserv": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffservcode": {"v_range": [["v6.4.4", ""]], "type": "string"},
        "protocol": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "src_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "src_name6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "src_addr_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "subnet"},
                {"value": "range"},
                {"value": "ip"},
                {"value": "name"},
            ],
        },
        "src_start_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "src_start_ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "src_end_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "src_end_ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "src_subnet": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "src_subnet6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "src_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dst_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dst_name6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dst_addr_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "subnet"},
                {"value": "range"},
                {"value": "ip"},
                {"value": "name"},
            ],
        },
        "dst_start_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dst_start_ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dst_end_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dst_end_ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dst_subnet": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dst_subnet6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dst_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ipv4_df": {
            "v_range": [["v6.2.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "vpn_ipsec_phase2": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["vpn_ipsec_phase2"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["vpn_ipsec_phase2"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "vpn_ipsec_phase2"
        )

        is_error, has_changed, result, diff = fortios_vpn_ipsec(
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
