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
module: fortios_system_np6
short_description: Configure NP6 attributes in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and np6 category.
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
    system_np6:
        description:
            - Configure NP6 attributes.
        default: null
        type: dict
        suboptions:
            fastpath:
                description:
                    - Enable/disable NP6 offloading (also called fast path).
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            fp_anomaly:
                description:
                    - NP6 IPv4 anomaly protection. trap-to-host forwards anomaly sessions to the CPU.
                type: dict
                suboptions:
                    icmp_csum_err:
                        description:
                            - Invalid IPv4 ICMP checksum anomalies.
                        type: str
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    icmp_frag:
                        description:
                            - Layer 3 fragmented packets that could be part of layer 4 ICMP anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    icmp_land:
                        description:
                            - ICMP land anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_csum_err:
                        description:
                            - Invalid IPv4 IP checksum anomalies.
                        type: str
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_land:
                        description:
                            - Land anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optlsrr:
                        description:
                            - Loose source record route option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optrr:
                        description:
                            - Record route option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optsecurity:
                        description:
                            - Security option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optssrr:
                        description:
                            - Strict source record route option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optstream:
                        description:
                            - Stream option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_opttimestamp:
                        description:
                            - Timestamp option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_proto_err:
                        description:
                            - Invalid layer 4 protocol anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_unknopt:
                        description:
                            - Unknown option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_daddr_err:
                        description:
                            - Destination address as unspecified or loopback address anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_land:
                        description:
                            - Land anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optendpid:
                        description:
                            - End point identification anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_opthomeaddr:
                        description:
                            - Home address option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optinvld:
                        description:
                            - Invalid option anomalies.Invalid option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optjumbo:
                        description:
                            - Jumbo options anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optnsap:
                        description:
                            - Network service access point address option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optralert:
                        description:
                            - Router alert option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_opttunnel:
                        description:
                            - Tunnel encapsulation limit option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_proto_err:
                        description:
                            - Layer 4 invalid protocol anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_saddr_err:
                        description:
                            - Source address as multicast anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_unknopt:
                        description:
                            - Unknown option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_csum_err:
                        description:
                            - Invalid IPv4 TCP checksum anomalies.
                        type: str
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    tcp_fin_noack:
                        description:
                            - TCP SYN flood with FIN flag set without ACK setting anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_fin_only:
                        description:
                            - TCP SYN flood with only FIN flag set anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_land:
                        description:
                            - TCP land anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_no_flag:
                        description:
                            - TCP SYN flood with no flag set anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_syn_data:
                        description:
                            - TCP SYN flood packets with data anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_syn_fin:
                        description:
                            - TCP SYN flood SYN/FIN flag set anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_winnuke:
                        description:
                            - TCP WinNuke anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    udp_csum_err:
                        description:
                            - Invalid IPv4 UDP checksum anomalies.
                        type: str
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udp_land:
                        description:
                            - UDP land anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
            garbage_session_collector:
                description:
                    - Enable/disable garbage session collector.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            hpe:
                description:
                    - HPE configuration.
                type: dict
                suboptions:
                    arp_max:
                        description:
                            - Maximum ARP packet rate (1K - 1G pps).
                        type: int
                    enable_shaper:
                        description:
                            - Enable/Disable NPU Host Protection Engine(HPE) for packet type shaper.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    esp_max:
                        description:
                            - Maximum ESP packet rate (1K - 1G pps).
                        type: int
                    icmp_max:
                        description:
                            - Maximum ICMP packet rate (1K - 1G pps).
                        type: int
                    ip_frag_max:
                        description:
                            - Maximum fragmented IP packet rate (1K - 1G pps).
                        type: int
                    ip_others_max:
                        description:
                            - Maximum IP packet rate for other packets (packet types that cannot be set with other options) (1K - 1G pps).
                        type: int
                    l2_others_max:
                        description:
                            - Maximum L2 packet rate for L2 packets that are not ARP packets (1K - 1G pps).
                        type: int
                    pri_type_max:
                        description:
                            - 'Maximum overflow rate of priority type traffic (1K - 1G pps). Includes L2: HA, 802.3ad LACP, heartbeats. L3: OSPF. L4_TCP: BGP.
                               L4_UDP: IKE, SLBC, BFD.'
                        type: int
                    sctp_max:
                        description:
                            - Maximum SCTP packet rate (1K - 1G pps).
                        type: int
                    tcp_max:
                        description:
                            - Maximum TCP packet rate (1K - 1G pps).
                        type: int
                    tcpfin_rst_max:
                        description:
                            - Maximum TCP carries FIN or RST flags packet rate (1K - 1G pps).
                        type: int
                    tcpsyn_ack_max:
                        description:
                            - Maximum TCP carries SYN and ACK flags packet rate (1K - 1G pps).
                        type: int
                    tcpsyn_max:
                        description:
                            - Maximum TCP SYN packet rate (1K - 1G pps).
                        type: int
                    udp_max:
                        description:
                            - Maximum UDP packet rate (1K - 1G pps).
                        type: int
            ipsec_ob_hash_function:
                description:
                    - Set hash function for IPSec outbound.
                type: str
                choices:
                    - 'global-hash'
                    - 'round-robin-global'
            ipsec_outbound_hash:
                description:
                    - Enable/disable hash function for IPsec outbound traffic.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            low_latency_mode:
                description:
                    - Enable/disable low latency mode.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            name:
                description:
                    - Device Name.
                required: true
                type: str
            per_session_accounting:
                description:
                    - Enable/disable per-session accounting.
                type: str
                choices:
                    - 'disable'
                    - 'traffic-log-only'
                    - 'enable'
            session_collector_interval:
                description:
                    - Set garbage session collection cleanup interval (1 - 100 sec).
                type: int
            session_timeout_fixed:
                description:
                    - '{disable | enable} Toggle between using fixed or random timeouts for refreshing NP6 sessions.'
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            session_timeout_interval:
                description:
                    - Set the fixed timeout for refreshing NP6 sessions (0 - 1000 sec).
                type: int
            session_timeout_random_range:
                description:
                    - Set the random timeout range for refreshing NP6 sessions (0 - 1000 sec).
                type: int
"""

EXAMPLES = """
- name: Configure NP6 attributes.
  fortinet.fortios.fortios_system_np6:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_np6:
          fastpath: "disable"
          fp_anomaly:
              icmp_csum_err: "drop"
              icmp_frag: "allow"
              icmp_land: "allow"
              ipv4_csum_err: "drop"
              ipv4_land: "allow"
              ipv4_optlsrr: "allow"
              ipv4_optrr: "allow"
              ipv4_optsecurity: "allow"
              ipv4_optssrr: "allow"
              ipv4_optstream: "allow"
              ipv4_opttimestamp: "allow"
              ipv4_proto_err: "allow"
              ipv4_unknopt: "allow"
              ipv6_daddr_err: "allow"
              ipv6_land: "allow"
              ipv6_optendpid: "allow"
              ipv6_opthomeaddr: "allow"
              ipv6_optinvld: "allow"
              ipv6_optjumbo: "allow"
              ipv6_optnsap: "allow"
              ipv6_optralert: "allow"
              ipv6_opttunnel: "allow"
              ipv6_proto_err: "allow"
              ipv6_saddr_err: "allow"
              ipv6_unknopt: "allow"
              tcp_csum_err: "drop"
              tcp_fin_noack: "allow"
              tcp_fin_only: "allow"
              tcp_land: "allow"
              tcp_no_flag: "allow"
              tcp_syn_data: "allow"
              tcp_syn_fin: "allow"
              tcp_winnuke: "allow"
              udp_csum_err: "drop"
              udp_land: "allow"
          garbage_session_collector: "disable"
          hpe:
              arp_max: "200000"
              enable_shaper: "disable"
              esp_max: "200000"
              icmp_max: "200000"
              ip_frag_max: "200000"
              ip_others_max: "200000"
              l2_others_max: "200000"
              pri_type_max: "200000"
              sctp_max: "200000"
              tcp_max: "600000"
              tcpfin_rst_max: "600000"
              tcpsyn_ack_max: "600000"
              tcpsyn_max: "600000"
              udp_max: "600000"
          ipsec_ob_hash_function: "global-hash"
          ipsec_outbound_hash: "disable"
          low_latency_mode: "disable"
          name: "default_name_59"
          per_session_accounting: "disable"
          session_collector_interval: "64"
          session_timeout_fixed: "disable"
          session_timeout_interval: "40"
          session_timeout_random_range: "8"
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


def filter_system_np6_data(json):
    option_list = [
        "fastpath",
        "fp_anomaly",
        "garbage_session_collector",
        "hpe",
        "ipsec_ob_hash_function",
        "ipsec_outbound_hash",
        "low_latency_mode",
        "name",
        "per_session_accounting",
        "session_collector_interval",
        "session_timeout_fixed",
        "session_timeout_interval",
        "session_timeout_random_range",
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


def system_np6(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_np6_data = data["system_np6"]

    filtered_data = filter_system_np6_data(system_np6_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "np6", filtered_data, vdom=vdom)
        current_data = fos.get("system", "np6", vdom=vdom, mkey=mkey)
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
    data_copy["system_np6"] = filtered_data
    fos.do_member_operation(
        "system",
        "np6",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "np6", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("system", "np6", mkey=converted_data["name"], vdom=vdom)
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

    if data["system_np6"]:
        resp = system_np6(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_np6"))
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
        "name": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "required": True,
        },
        "fastpath": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "low_latency_mode": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "per_session_accounting": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "traffic-log-only"},
                {"value": "enable"},
            ],
        },
        "garbage_session_collector": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "session_collector_interval": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "session_timeout_interval": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "session_timeout_random_range": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "session_timeout_fixed": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "hpe": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "dict",
            "children": {
                "tcpsyn_max": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "integer",
                },
                "tcpsyn_ack_max": {
                    "v_range": [["v7.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "integer",
                },
                "tcpfin_rst_max": {
                    "v_range": [["v7.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "integer",
                },
                "tcp_max": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "integer",
                },
                "udp_max": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "integer",
                },
                "icmp_max": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "integer",
                },
                "sctp_max": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "integer",
                },
                "esp_max": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "integer",
                },
                "ip_frag_max": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "integer",
                },
                "ip_others_max": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "integer",
                },
                "arp_max": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "integer",
                },
                "l2_others_max": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "integer",
                },
                "pri_type_max": {
                    "v_range": [
                        ["v6.0.0", "v6.0.0"],
                        ["v6.0.11", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "enable_shaper": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
            },
        },
        "fp_anomaly": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "dict",
            "children": {
                "tcp_syn_fin": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "tcp_fin_noack": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "tcp_fin_only": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "tcp_no_flag": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "tcp_syn_data": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "tcp_winnuke": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "tcp_land": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "udp_land": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "icmp_land": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "icmp_frag": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_land": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_proto_err": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_unknopt": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_optrr": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_optssrr": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_optlsrr": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_optstream": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_optsecurity": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_opttimestamp": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_csum_err": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [{"value": "drop"}, {"value": "trap-to-host"}],
                },
                "tcp_csum_err": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [{"value": "drop"}, {"value": "trap-to-host"}],
                },
                "udp_csum_err": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [{"value": "drop"}, {"value": "trap-to-host"}],
                },
                "icmp_csum_err": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [{"value": "drop"}, {"value": "trap-to-host"}],
                },
                "ipv6_land": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_proto_err": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_unknopt": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_saddr_err": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_daddr_err": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_optralert": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_optjumbo": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_opttunnel": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_opthomeaddr": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_optnsap": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_optendpid": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_optinvld": {
                    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
            },
        },
        "ipsec_outbound_hash": {
            "v_range": [
                ["v6.0.0", "v6.2.7"],
                ["v6.4.1", "v7.0.12"],
                ["v7.2.1", "v7.2.4"],
            ],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ipsec_ob_hash_function": {
            "v_range": [
                ["v6.0.0", "v6.2.7"],
                ["v6.4.1", "v7.0.12"],
                ["v7.2.1", "v7.2.4"],
            ],
            "type": "string",
            "options": [{"value": "global-hash"}, {"value": "round-robin-global"}],
        },
    },
    "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
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
        "system_np6": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_np6"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_np6"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_np6"
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
