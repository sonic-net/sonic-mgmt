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
module: fortios_system_standalone_cluster
short_description: Configure FortiGate Session Life Support Protocol (FGSP) cluster attributes in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and standalone_cluster category.
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

    system_standalone_cluster:
        description:
            - Configure FortiGate Session Life Support Protocol (FGSP) cluster attributes.
        default: null
        type: dict
        suboptions:
            asymmetric_traffic_control:
                description:
                    - Asymmetric traffic control mode.
                type: str
                choices:
                    - 'cps-preferred'
                    - 'strict-anti-replay'
            cluster_peer:
                description:
                    - Configure FortiGate Session Life Support Protocol (FGSP) session synchronization.
                type: list
                elements: dict
                suboptions:
                    down_intfs_before_sess_sync:
                        description:
                            - List of interfaces to be turned down before session synchronization is complete.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Interface name. Source system.interface.name.
                                required: true
                                type: str
                    hb_interval:
                        description:
                            - Heartbeat interval (1 - 20 (100*ms). Increase to reduce false positives.
                        type: int
                    hb_lost_threshold:
                        description:
                            - Lost heartbeat threshold (1 - 60). Increase to reduce false positives.
                        type: int
                    ipsec_tunnel_sync:
                        description:
                            - Enable/disable IPsec tunnel synchronization.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    peerip:
                        description:
                            - IP address of the interface on the peer unit that is used for the session synchronization link.
                        type: str
                    peervd:
                        description:
                            - VDOM that contains the session synchronization link interface on the peer unit. Usually both peers would have the same peervd.
                               Source system.vdom.name.
                        type: str
                    secondary_add_ipsec_routes:
                        description:
                            - Enable/disable IKE route announcement on the backup unit.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    session_sync_filter:
                        description:
                            - Add one or more filters if you only want to synchronize some sessions. Use the filter to configure the types of sessions to
                               synchronize.
                        type: dict
                        suboptions:
                            custom_service:
                                description:
                                    - Only sessions using these custom services are synchronized. Use source and destination port ranges to define these
                                       custom services.
                                type: list
                                elements: dict
                                suboptions:
                                    dst_port_range:
                                        description:
                                            - Custom service destination port range.
                                        type: str
                                    id:
                                        description:
                                            - Custom service ID. see <a href='#notes'>Notes</a>.
                                        required: true
                                        type: int
                                    src_port_range:
                                        description:
                                            - Custom service source port range.
                                        type: str
                            dstaddr:
                                description:
                                    - Only sessions to this IPv4 address are synchronized.
                                type: str
                            dstaddr6:
                                description:
                                    - Only sessions to this IPv6 address are synchronized.
                                type: str
                            dstintf:
                                description:
                                    - Only sessions to this interface are synchronized. Source system.interface.name.
                                type: str
                            srcaddr:
                                description:
                                    - Only sessions from this IPv4 address are synchronized.
                                type: str
                            srcaddr6:
                                description:
                                    - Only sessions from this IPv6 address are synchronized.
                                type: str
                            srcintf:
                                description:
                                    - Only sessions from this interface are synchronized. Source system.interface.name.
                                type: str
                    sync_id:
                        description:
                            - Sync ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    syncvd:
                        description:
                            - Sessions from these VDOMs are synchronized using this session synchronization configuration.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - VDOM name. Source system.vdom.name.
                                required: true
                                type: str
            encryption:
                description:
                    - Enable/disable encryption when synchronizing sessions.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            group_member_id:
                description:
                    - Cluster member ID (0 - 15).
                type: int
            helper_traffic_bounce:
                description:
                    - Enable/disable helper related traffic bounce.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            layer2_connection:
                description:
                    - Indicate whether layer 2 connections are present among FGSP members.
                type: str
                choices:
                    - 'available'
                    - 'unavailable'
            monitor_interface:
                description:
                    - Configure a list of interfaces on which to monitor itself. Monitoring is performed on the status of the interface.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
            monitor_prefix:
                description:
                    - Configure a list of routing prefixes to monitor.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    prefix:
                        description:
                            - Prefix.
                        type: str
                    vdom:
                        description:
                            - VDOM name. Source system.vdom.name.
                        type: str
                    vrf:
                        description:
                            - VRF ID.
                        type: int
            pingsvr_monitor_interface:
                description:
                    - List of pingsvr monitor interface to check for remote IP monitoring.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
            psksecret:
                description:
                    - Pre-shared secret for session synchronization (ASCII string or hexadecimal encoded with a leading 0x).
                type: str
            session_sync_dev:
                description:
                    - Offload session-sync process to kernel and sync sessions using connected interface(s) directly. Source system.interface.name.
                type: list
                elements: str
            standalone_group_id:
                description:
                    - Cluster group ID (0 - 255). Must be the same for all members.
                type: int
            utm_traffic_bounce:
                description:
                    - Enable/disable UTM related traffic bounce.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure FortiGate Session Life Support Protocol (FGSP) cluster attributes.
  fortinet.fortios.fortios_system_standalone_cluster:
      vdom: "{{ vdom }}"
      system_standalone_cluster:
          asymmetric_traffic_control: "cps-preferred"
          cluster_peer:
              -
                  down_intfs_before_sess_sync:
                      -
                          name: "default_name_6 (source system.interface.name)"
                  hb_interval: "2"
                  hb_lost_threshold: "10"
                  ipsec_tunnel_sync: "enable"
                  peerip: "<your_own_value>"
                  peervd: "<your_own_value> (source system.vdom.name)"
                  secondary_add_ipsec_routes: "enable"
                  session_sync_filter:
                      custom_service:
                          -
                              dst_port_range: "<your_own_value>"
                              id: "16"
                              src_port_range: "<your_own_value>"
                      dstaddr: "<your_own_value>"
                      dstaddr6: "<your_own_value>"
                      dstintf: "<your_own_value> (source system.interface.name)"
                      srcaddr: "<your_own_value>"
                      srcaddr6: "<your_own_value>"
                      srcintf: "<your_own_value> (source system.interface.name)"
                  sync_id: "<you_own_value>"
                  syncvd:
                      -
                          name: "default_name_26 (source system.vdom.name)"
          encryption: "enable"
          group_member_id: "0"
          helper_traffic_bounce: "enable"
          layer2_connection: "available"
          monitor_interface:
              -
                  name: "default_name_32 (source system.interface.name)"
          monitor_prefix:
              -
                  id: "34"
                  prefix: "<your_own_value>"
                  vdom: "<your_own_value> (source system.vdom.name)"
                  vrf: "0"
          pingsvr_monitor_interface:
              -
                  name: "default_name_39 (source system.interface.name)"
          psksecret: "<your_own_value>"
          session_sync_dev: "<your_own_value> (source system.interface.name)"
          standalone_group_id: "0"
          utm_traffic_bounce: "enable"
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


def filter_system_standalone_cluster_data(json):
    option_list = [
        "asymmetric_traffic_control",
        "cluster_peer",
        "encryption",
        "group_member_id",
        "helper_traffic_bounce",
        "layer2_connection",
        "monitor_interface",
        "monitor_prefix",
        "pingsvr_monitor_interface",
        "psksecret",
        "session_sync_dev",
        "standalone_group_id",
        "utm_traffic_bounce",
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
        ["session_sync_dev"],
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


def system_standalone_cluster(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_standalone_cluster_data = data["system_standalone_cluster"]

    filtered_data = filter_system_standalone_cluster_data(
        system_standalone_cluster_data
    )
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "standalone-cluster", filtered_data, vdom=vdom)
        current_data = fos.get("system", "standalone-cluster", vdom=vdom, mkey=mkey)
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
    data_copy["system_standalone_cluster"] = filtered_data
    fos.do_member_operation(
        "system",
        "standalone-cluster",
        data_copy,
    )

    return fos.set("system", "standalone-cluster", data=converted_data, vdom=vdom)


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

    if data["system_standalone_cluster"]:
        resp = system_standalone_cluster(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("system_standalone_cluster")
        )
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
    "v_range": [["v6.4.0", ""]],
    "type": "dict",
    "children": {
        "standalone_group_id": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "group_member_id": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "layer2_connection": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "available"}, {"value": "unavailable"}],
        },
        "session_sync_dev": {
            "v_range": [["v6.4.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "encryption": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "psksecret": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "asymmetric_traffic_control": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "cps-preferred"}, {"value": "strict-anti-replay"}],
        },
        "cluster_peer": {
            "type": "list",
            "elements": "dict",
            "children": {
                "sync_id": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "integer",
                    "required": True,
                },
                "peervd": {"v_range": [["v7.2.1", ""]], "type": "string"},
                "peerip": {"v_range": [["v7.2.1", ""]], "type": "string"},
                "syncvd": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.2.1", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.1", ""]],
                },
                "down_intfs_before_sess_sync": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.2.1", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.1", ""]],
                },
                "hb_interval": {"v_range": [["v7.2.1", ""]], "type": "integer"},
                "hb_lost_threshold": {"v_range": [["v7.2.1", ""]], "type": "integer"},
                "ipsec_tunnel_sync": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "secondary_add_ipsec_routes": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "session_sync_filter": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "dict",
                    "children": {
                        "srcintf": {"v_range": [["v7.2.1", ""]], "type": "string"},
                        "dstintf": {"v_range": [["v7.2.1", ""]], "type": "string"},
                        "srcaddr": {"v_range": [["v7.2.1", ""]], "type": "string"},
                        "dstaddr": {"v_range": [["v7.2.1", ""]], "type": "string"},
                        "srcaddr6": {"v_range": [["v7.2.1", ""]], "type": "string"},
                        "dstaddr6": {"v_range": [["v7.2.1", ""]], "type": "string"},
                        "custom_service": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "id": {
                                    "v_range": [["v7.2.1", ""]],
                                    "type": "integer",
                                    "required": True,
                                },
                                "src_port_range": {
                                    "v_range": [["v7.2.1", ""]],
                                    "type": "string",
                                },
                                "dst_port_range": {
                                    "v_range": [["v7.2.1", ""]],
                                    "type": "string",
                                },
                            },
                            "v_range": [["v7.2.1", ""]],
                        },
                    },
                },
            },
            "v_range": [["v7.2.1", ""]],
        },
        "monitor_interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.0", ""]],
        },
        "pingsvr_monitor_interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.0", ""]],
        },
        "monitor_prefix": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "integer",
                    "required": True,
                },
                "vdom": {"v_range": [["v7.6.1", ""]], "type": "string"},
                "vrf": {"v_range": [["v7.6.1", ""]], "type": "integer"},
                "prefix": {"v_range": [["v7.6.1", ""]], "type": "string"},
            },
            "v_range": [["v7.6.1", ""]],
        },
        "helper_traffic_bounce": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "utm_traffic_bounce": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "system_standalone_cluster": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_standalone_cluster"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_standalone_cluster"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "system_standalone_cluster"
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
