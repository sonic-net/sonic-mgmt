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
module: fortios_router_ospf6
short_description: Configure IPv6 OSPF in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify router feature and ospf6 category.
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

    router_ospf6:
        description:
            - Configure IPv6 OSPF.
        default: null
        type: dict
        suboptions:
            abr_type:
                description:
                    - Area border router type.
                type: str
                choices:
                    - 'cisco'
                    - 'ibm'
                    - 'standard'
            area:
                description:
                    - OSPF6 area configuration.
                type: list
                elements: dict
                suboptions:
                    authentication:
                        description:
                            - Authentication mode.
                        type: str
                        choices:
                            - 'none'
                            - 'ah'
                            - 'esp'
                    default_cost:
                        description:
                            - Summary default cost of stub or NSSA area.
                        type: int
                    id:
                        description:
                            - Area entry IP address.
                        required: true
                        type: str
                    ipsec_auth_alg:
                        description:
                            - Authentication algorithm.
                        type: str
                        choices:
                            - 'md5'
                            - 'sha1'
                            - 'sha256'
                            - 'sha384'
                            - 'sha512'
                    ipsec_enc_alg:
                        description:
                            - Encryption algorithm.
                        type: str
                        choices:
                            - 'null'
                            - 'des'
                            - '3des'
                            - 'aes128'
                            - 'aes192'
                            - 'aes256'
                    ipsec_keys:
                        description:
                            - IPsec authentication and encryption keys.
                        type: list
                        elements: dict
                        suboptions:
                            auth_key:
                                description:
                                    - Authentication key.
                                type: str
                            enc_key:
                                description:
                                    - Encryption key.
                                type: str
                            spi:
                                description:
                                    - Security Parameters Index. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                    key_rollover_interval:
                        description:
                            - Key roll-over interval.
                        type: int
                    nssa_default_information_originate:
                        description:
                            - Enable/disable originate type 7 default into NSSA area.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    nssa_default_information_originate_metric:
                        description:
                            - OSPFv3 default metric.
                        type: int
                    nssa_default_information_originate_metric_type:
                        description:
                            - OSPFv3 metric type for default routes.
                        type: str
                        choices:
                            - '1'
                            - '2'
                    nssa_redistribution:
                        description:
                            - Enable/disable redistribute into NSSA area.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    nssa_translator_role:
                        description:
                            - NSSA translator role type.
                        type: str
                        choices:
                            - 'candidate'
                            - 'never'
                            - 'always'
                    range:
                        description:
                            - OSPF6 area range configuration.
                        type: list
                        elements: dict
                        suboptions:
                            advertise:
                                description:
                                    - Enable/disable advertise status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            id:
                                description:
                                    - Range entry ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            prefix6:
                                description:
                                    - IPv6 prefix.
                                type: str
                    stub_type:
                        description:
                            - Stub summary setting.
                        type: str
                        choices:
                            - 'no-summary'
                            - 'summary'
                    type:
                        description:
                            - Area type setting.
                        type: str
                        choices:
                            - 'regular'
                            - 'nssa'
                            - 'stub'
                    virtual_link:
                        description:
                            - OSPF6 virtual link configuration.
                        type: list
                        elements: dict
                        suboptions:
                            authentication:
                                description:
                                    - Authentication mode.
                                type: str
                                choices:
                                    - 'none'
                                    - 'ah'
                                    - 'esp'
                                    - 'area'
                            dead_interval:
                                description:
                                    - Dead interval.
                                type: int
                            hello_interval:
                                description:
                                    - Hello interval.
                                type: int
                            ipsec_auth_alg:
                                description:
                                    - Authentication algorithm.
                                type: str
                                choices:
                                    - 'md5'
                                    - 'sha1'
                                    - 'sha256'
                                    - 'sha384'
                                    - 'sha512'
                            ipsec_enc_alg:
                                description:
                                    - Encryption algorithm.
                                type: str
                                choices:
                                    - 'null'
                                    - 'des'
                                    - '3des'
                                    - 'aes128'
                                    - 'aes192'
                                    - 'aes256'
                            ipsec_keys:
                                description:
                                    - IPsec authentication and encryption keys.
                                type: list
                                elements: dict
                                suboptions:
                                    auth_key:
                                        description:
                                            - Authentication key.
                                        type: str
                                    enc_key:
                                        description:
                                            - Encryption key.
                                        type: str
                                    spi:
                                        description:
                                            - Security Parameters Index. see <a href='#notes'>Notes</a>.
                                        required: true
                                        type: int
                            key_rollover_interval:
                                description:
                                    - Key roll-over interval.
                                type: int
                            name:
                                description:
                                    - Virtual link entry name.
                                required: true
                                type: str
                            peer:
                                description:
                                    - A.B.C.D, peer router ID.
                                type: str
                            retransmit_interval:
                                description:
                                    - Retransmit interval.
                                type: int
                            transmit_delay:
                                description:
                                    - Transmit delay.
                                type: int
            auto_cost_ref_bandwidth:
                description:
                    - Reference bandwidth in terms of megabits per second.
                type: int
            bfd:
                description:
                    - Enable/disable Bidirectional Forwarding Detection (BFD).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            default_information_metric:
                description:
                    - Default information metric.
                type: int
            default_information_metric_type:
                description:
                    - Default information metric type.
                type: str
                choices:
                    - '1'
                    - '2'
            default_information_originate:
                description:
                    - Enable/disable generation of default route.
                type: str
                choices:
                    - 'enable'
                    - 'always'
                    - 'disable'
            default_information_route_map:
                description:
                    - Default information route map. Source router.route-map.name.
                type: str
            default_metric:
                description:
                    - Default metric of redistribute routes.
                type: int
            log_neighbour_changes:
                description:
                    - Log OSPFv3 neighbor changes.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ospf6_interface:
                description:
                    - OSPF6 interface configuration.
                type: list
                elements: dict
                suboptions:
                    area_id:
                        description:
                            - A.B.C.D, in IPv4 address format.
                        type: str
                    authentication:
                        description:
                            - Authentication mode.
                        type: str
                        choices:
                            - 'none'
                            - 'ah'
                            - 'esp'
                            - 'area'
                    bfd:
                        description:
                            - Enable/disable Bidirectional Forwarding Detection (BFD).
                        type: str
                        choices:
                            - 'global'
                            - 'enable'
                            - 'disable'
                    cost:
                        description:
                            - Cost of the interface, value range from 0 to 65535, 0 means auto-cost.
                        type: int
                    dead_interval:
                        description:
                            - Dead interval.
                        type: int
                    hello_interval:
                        description:
                            - Hello interval.
                        type: int
                    interface:
                        description:
                            - Configuration interface name. Source system.interface.name.
                        type: str
                    ipsec_auth_alg:
                        description:
                            - Authentication algorithm.
                        type: str
                        choices:
                            - 'md5'
                            - 'sha1'
                            - 'sha256'
                            - 'sha384'
                            - 'sha512'
                    ipsec_enc_alg:
                        description:
                            - Encryption algorithm.
                        type: str
                        choices:
                            - 'null'
                            - 'des'
                            - '3des'
                            - 'aes128'
                            - 'aes192'
                            - 'aes256'
                    ipsec_keys:
                        description:
                            - IPsec authentication and encryption keys.
                        type: list
                        elements: dict
                        suboptions:
                            auth_key:
                                description:
                                    - Authentication key.
                                type: str
                            enc_key:
                                description:
                                    - Encryption key.
                                type: str
                            spi:
                                description:
                                    - Security Parameters Index. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                    key_rollover_interval:
                        description:
                            - Key roll-over interval.
                        type: int
                    mtu:
                        description:
                            - MTU for OSPFv3 packets.
                        type: int
                    mtu_ignore:
                        description:
                            - Enable/disable ignoring MTU field in DBD packets.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    name:
                        description:
                            - Interface entry name.
                        required: true
                        type: str
                    neighbor:
                        description:
                            - OSPFv3 neighbors are used when OSPFv3 runs on non-broadcast media.
                        type: list
                        elements: dict
                        suboptions:
                            cost:
                                description:
                                    - Cost of the interface, value range from 0 to 65535, 0 means auto-cost.
                                type: int
                            ip6:
                                description:
                                    - IPv6 link local address of the neighbor.
                                required: true
                                type: str
                            poll_interval:
                                description:
                                    - Poll interval time in seconds.
                                type: int
                            priority:
                                description:
                                    - Priority.
                                type: int
                    network_type:
                        description:
                            - Network type.
                        type: str
                        choices:
                            - 'broadcast'
                            - 'point-to-point'
                            - 'non-broadcast'
                            - 'point-to-multipoint'
                            - 'point-to-multipoint-non-broadcast'
                    priority:
                        description:
                            - Priority.
                        type: int
                    retransmit_interval:
                        description:
                            - Retransmit interval.
                        type: int
                    status:
                        description:
                            - Enable/disable OSPF6 routing on this interface.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    transmit_delay:
                        description:
                            - Transmit delay.
                        type: int
            passive_interface:
                description:
                    - Passive interface configuration.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Passive interface name. Source system.interface.name.
                        required: true
                        type: str
            redistribute:
                description:
                    - Redistribute configuration.
                type: list
                elements: dict
                suboptions:
                    metric:
                        description:
                            - Redistribute metric setting.
                        type: int
                    metric_type:
                        description:
                            - Metric type.
                        type: str
                        choices:
                            - '1'
                            - '2'
                    name:
                        description:
                            - Redistribute name.
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
            restart_mode:
                description:
                    - OSPFv3 restart mode (graceful or none).
                type: str
                choices:
                    - 'none'
                    - 'graceful-restart'
            restart_on_topology_change:
                description:
                    - Enable/disable continuing graceful restart upon topology change.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            restart_period:
                description:
                    - Graceful restart period in seconds.
                type: int
            router_id:
                description:
                    - A.B.C.D, in IPv4 address format.
                type: str
            spf_timers:
                description:
                    - SPF calculation frequency.
                type: str
            summary_address:
                description:
                    - IPv6 address summary configuration.
                type: list
                elements: dict
                suboptions:
                    advertise:
                        description:
                            - Enable/disable advertise status.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        description:
                            - Summary address entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    prefix6:
                        description:
                            - IPv6 prefix.
                        type: str
                    tag:
                        description:
                            - Tag value.
                        type: int
"""

EXAMPLES = """
- name: Configure IPv6 OSPF.
  fortinet.fortios.fortios_router_ospf6:
      vdom: "{{ vdom }}"
      router_ospf6:
          abr_type: "cisco"
          area:
              -
                  authentication: "none"
                  default_cost: "10"
                  id: "7"
                  ipsec_auth_alg: "md5"
                  ipsec_enc_alg: "null"
                  ipsec_keys:
                      -
                          auth_key: "<your_own_value>"
                          enc_key: "<your_own_value>"
                          spi: "<you_own_value>"
                  key_rollover_interval: "300"
                  nssa_default_information_originate: "enable"
                  nssa_default_information_originate_metric: "10"
                  nssa_default_information_originate_metric_type: "1"
                  nssa_redistribution: "enable"
                  nssa_translator_role: "candidate"
                  range:
                      -
                          advertise: "disable"
                          id: "22"
                          prefix6: "<your_own_value>"
                  stub_type: "no-summary"
                  type: "regular"
                  virtual_link:
                      -
                          authentication: "none"
                          dead_interval: "40"
                          hello_interval: "10"
                          ipsec_auth_alg: "md5"
                          ipsec_enc_alg: "null"
                          ipsec_keys:
                              -
                                  auth_key: "<your_own_value>"
                                  enc_key: "<your_own_value>"
                                  spi: "<you_own_value>"
                          key_rollover_interval: "300"
                          name: "default_name_37"
                          peer: "<your_own_value>"
                          retransmit_interval: "5"
                          transmit_delay: "1"
          auto_cost_ref_bandwidth: "1000"
          bfd: "enable"
          default_information_metric: "10"
          default_information_metric_type: "1"
          default_information_originate: "enable"
          default_information_route_map: "<your_own_value> (source router.route-map.name)"
          default_metric: "10"
          log_neighbour_changes: "enable"
          ospf6_interface:
              -
                  area_id: "<your_own_value>"
                  authentication: "none"
                  bfd: "global"
                  cost: "0"
                  dead_interval: "0"
                  hello_interval: "0"
                  interface: "<your_own_value> (source system.interface.name)"
                  ipsec_auth_alg: "md5"
                  ipsec_enc_alg: "null"
                  ipsec_keys:
                      -
                          auth_key: "<your_own_value>"
                          enc_key: "<your_own_value>"
                          spi: "<you_own_value>"
                  key_rollover_interval: "300"
                  mtu: "0"
                  mtu_ignore: "enable"
                  name: "default_name_66"
                  neighbor:
                      -
                          cost: "0"
                          ip6: "<your_own_value>"
                          poll_interval: "10"
                          priority: "1"
                  network_type: "broadcast"
                  priority: "1"
                  retransmit_interval: "5"
                  status: "disable"
                  transmit_delay: "1"
          passive_interface:
              -
                  name: "default_name_78 (source system.interface.name)"
          redistribute:
              -
                  metric: "0"
                  metric_type: "1"
                  name: "default_name_82"
                  routemap: "<your_own_value> (source router.route-map.name)"
                  status: "enable"
          restart_mode: "none"
          restart_on_topology_change: "enable"
          restart_period: "120"
          router_id: "<your_own_value>"
          spf_timers: "<your_own_value>"
          summary_address:
              -
                  advertise: "disable"
                  id: "92"
                  prefix6: "<your_own_value>"
                  tag: "0"
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


def filter_router_ospf6_data(json):
    option_list = [
        "abr_type",
        "area",
        "auto_cost_ref_bandwidth",
        "bfd",
        "default_information_metric",
        "default_information_metric_type",
        "default_information_originate",
        "default_information_route_map",
        "default_metric",
        "log_neighbour_changes",
        "ospf6_interface",
        "passive_interface",
        "redistribute",
        "restart_mode",
        "restart_on_topology_change",
        "restart_period",
        "router_id",
        "spf_timers",
        "summary_address",
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


def router_ospf6(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    router_ospf6_data = data["router_ospf6"]

    filtered_data = filter_router_ospf6_data(router_ospf6_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("router", "ospf6", filtered_data, vdom=vdom)
        current_data = fos.get("router", "ospf6", vdom=vdom, mkey=mkey)
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
    data_copy["router_ospf6"] = filtered_data
    fos.do_member_operation(
        "router",
        "ospf6",
        data_copy,
    )

    return fos.set("router", "ospf6", data=converted_data, vdom=vdom)


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

    if data["router_ospf6"]:
        resp = router_ospf6(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_ospf6"))
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
        "abr_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "cisco"}, {"value": "ibm"}, {"value": "standard"}],
        },
        "auto_cost_ref_bandwidth": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "default_information_originate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "always"}, {"value": "disable"}],
        },
        "log_neighbour_changes": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "default_information_metric": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "default_information_metric_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "1"}, {"value": "2"}],
        },
        "default_information_route_map": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
        },
        "default_metric": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "router_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "spf_timers": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "bfd": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "restart_mode": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "graceful-restart"}],
        },
        "restart_period": {"v_range": [["v7.2.0", ""]], "type": "integer"},
        "restart_on_topology_change": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "area": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
                "default_cost": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "nssa_translator_role": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "candidate"},
                        {"value": "never"},
                        {"value": "always"},
                    ],
                },
                "stub_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "no-summary"}, {"value": "summary"}],
                },
                "type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "regular"},
                        {"value": "nssa"},
                        {"value": "stub"},
                    ],
                },
                "nssa_default_information_originate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "nssa_default_information_originate_metric": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "nssa_default_information_originate_metric_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "1"}, {"value": "2"}],
                },
                "nssa_redistribution": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "authentication": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "none"}, {"value": "ah"}, {"value": "esp"}],
                },
                "key_rollover_interval": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                },
                "ipsec_auth_alg": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "md5"},
                        {"value": "sha1"},
                        {"value": "sha256"},
                        {"value": "sha384"},
                        {"value": "sha512"},
                    ],
                },
                "ipsec_enc_alg": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "null"},
                        {"value": "des"},
                        {"value": "3des"},
                        {"value": "aes128"},
                        {"value": "aes192"},
                        {"value": "aes256"},
                    ],
                },
                "ipsec_keys": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "spi": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "auth_key": {"v_range": [["v6.2.0", ""]], "type": "string"},
                        "enc_key": {"v_range": [["v6.2.0", ""]], "type": "string"},
                    },
                    "v_range": [["v6.2.0", ""]],
                },
                "range": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "prefix6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "advertise": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "virtual_link": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "dead_interval": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "hello_interval": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "retransmit_interval": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "transmit_delay": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "peer": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "authentication": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "none"},
                                {"value": "ah"},
                                {"value": "esp"},
                                {"value": "area"},
                            ],
                        },
                        "key_rollover_interval": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "integer",
                        },
                        "ipsec_auth_alg": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "md5"},
                                {"value": "sha1"},
                                {"value": "sha256"},
                                {"value": "sha384"},
                                {"value": "sha512"},
                            ],
                        },
                        "ipsec_enc_alg": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "null"},
                                {"value": "des"},
                                {"value": "3des"},
                                {"value": "aes128"},
                                {"value": "aes192"},
                                {"value": "aes256"},
                            ],
                        },
                        "ipsec_keys": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "spi": {
                                    "v_range": [["v6.2.0", ""]],
                                    "type": "integer",
                                    "required": True,
                                },
                                "auth_key": {
                                    "v_range": [["v6.2.0", ""]],
                                    "type": "string",
                                },
                                "enc_key": {
                                    "v_range": [["v6.2.0", ""]],
                                    "type": "string",
                                },
                            },
                            "v_range": [["v6.2.0", ""]],
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ospf6_interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "area_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "retransmit_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "transmit_delay": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "cost": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "dead_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "hello_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "network_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "broadcast"},
                        {"value": "point-to-point"},
                        {"value": "non-broadcast"},
                        {"value": "point-to-multipoint"},
                        {"value": "point-to-multipoint-non-broadcast"},
                    ],
                },
                "bfd": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "global"},
                        {"value": "enable"},
                        {"value": "disable"},
                    ],
                },
                "mtu": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "mtu_ignore": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "authentication": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "ah"},
                        {"value": "esp"},
                        {"value": "area"},
                    ],
                },
                "key_rollover_interval": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                },
                "ipsec_auth_alg": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "md5"},
                        {"value": "sha1"},
                        {"value": "sha256"},
                        {"value": "sha384"},
                        {"value": "sha512"},
                    ],
                },
                "ipsec_enc_alg": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "null"},
                        {"value": "des"},
                        {"value": "3des"},
                        {"value": "aes128"},
                        {"value": "aes192"},
                        {"value": "aes256"},
                    ],
                },
                "ipsec_keys": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "spi": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "auth_key": {"v_range": [["v6.2.0", ""]], "type": "string"},
                        "enc_key": {"v_range": [["v6.2.0", ""]], "type": "string"},
                    },
                    "v_range": [["v6.2.0", ""]],
                },
                "neighbor": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "ip6": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "poll_interval": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                        },
                        "cost": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "passive_interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
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
                "prefix6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "advertise": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "tag": {"v_range": [["v6.0.0", ""]], "type": "integer"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "redistribute": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
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
                "routemap": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
                "metric_type": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "options": [{"value": "1"}, {"value": "2"}],
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
        "router_ospf6": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_ospf6"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_ospf6"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "router_ospf6"
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
