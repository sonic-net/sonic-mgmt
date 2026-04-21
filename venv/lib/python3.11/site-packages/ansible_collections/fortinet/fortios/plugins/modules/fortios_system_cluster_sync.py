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
module: fortios_system_cluster_sync
short_description: Configure FortiGate Session Life Support Protocol (FGSP) session synchronization in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and cluster_sync category.
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
    - We highly recommend using your own value as the sync_id instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
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
    system_cluster_sync:
        description:
            - Configure FortiGate Session Life Support Protocol (FGSP) session synchronization.
        default: null
        type: dict
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
                    - Heartbeat interval (1 - 10 sec).
                type: int
            hb_lost_threshold:
                description:
                    - Lost heartbeat threshold (1 - 10).
                type: int
            ike_heartbeat_interval:
                description:
                    - IKE heartbeat interval (1 - 60 secs).
                type: int
            ike_monitor:
                description:
                    - Enable/disable IKE HA monitor.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ike_monitor_interval:
                description:
                    - IKE HA monitor interval (10 - 300 secs).
                type: int
            ike_seqjump_speed:
                description:
                    - ESP jump ahead factor (1G - 10G pps equivalent).
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
                    - VDOM that contains the session synchronization link interface on the peer unit. Usually both peers would have the same peervd. Source
                       system.vdom.name.
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
                    - Add one or more filters if you only want to synchronize some sessions. Use the filter to configure the types of sessions to synchronize.
                type: dict
                suboptions:
                    custom_service:
                        description:
                            - Only sessions using these custom services are synchronized. Use source and destination port ranges to define these custom
                               services.
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
            slave_add_ike_routes:
                description:
                    - Enable/disable IKE route announcement on the backup unit.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
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
"""

EXAMPLES = """
- name: Configure FortiGate Session Life Support Protocol (FGSP) session synchronization.
  fortinet.fortios.fortios_system_cluster_sync:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_cluster_sync:
          down_intfs_before_sess_sync:
              -
                  name: "default_name_4 (source system.interface.name)"
          hb_interval: "2"
          hb_lost_threshold: "3"
          ike_heartbeat_interval: "3"
          ike_monitor: "enable"
          ike_monitor_interval: "15"
          ike_seqjump_speed: "10"
          ipsec_tunnel_sync: "enable"
          peerip: "<your_own_value>"
          peervd: "<your_own_value> (source system.vdom.name)"
          secondary_add_ipsec_routes: "enable"
          session_sync_filter:
              custom_service:
                  -
                      dst_port_range: "<your_own_value>"
                      id: "18"
                      src_port_range: "<your_own_value>"
              dstaddr: "<your_own_value>"
              dstaddr6: "<your_own_value>"
              dstintf: "<your_own_value> (source system.interface.name)"
              srcaddr: "<your_own_value>"
              srcaddr6: "<your_own_value>"
              srcintf: "<your_own_value> (source system.interface.name)"
          slave_add_ike_routes: "enable"
          sync_id: "<you_own_value>"
          syncvd:
              -
                  name: "default_name_29 (source system.vdom.name)"
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


def filter_system_cluster_sync_data(json):
    option_list = [
        "down_intfs_before_sess_sync",
        "hb_interval",
        "hb_lost_threshold",
        "ike_heartbeat_interval",
        "ike_monitor",
        "ike_monitor_interval",
        "ike_seqjump_speed",
        "ipsec_tunnel_sync",
        "peerip",
        "peervd",
        "secondary_add_ipsec_routes",
        "session_sync_filter",
        "slave_add_ike_routes",
        "sync_id",
        "syncvd",
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


def system_cluster_sync(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_cluster_sync_data = data["system_cluster_sync"]

    filtered_data = filter_system_cluster_sync_data(system_cluster_sync_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "cluster-sync", filtered_data, vdom=vdom)
        current_data = fos.get("system", "cluster-sync", vdom=vdom, mkey=mkey)
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
    data_copy["system_cluster_sync"] = filtered_data
    fos.do_member_operation(
        "system",
        "cluster-sync",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "cluster-sync", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system", "cluster-sync", mkey=converted_data["sync-id"], vdom=vdom
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


def fortios_system(data, fos, check_mode):

    if data["system_cluster_sync"]:
        resp = system_cluster_sync(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_cluster_sync"))
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
        "sync_id": {
            "v_range": [["v6.0.0", "v7.2.0"]],
            "type": "integer",
            "required": True,
        },
        "peervd": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "string"},
        "peerip": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "string"},
        "syncvd": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.2.0"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.2.0"]],
        },
        "down_intfs_before_sess_sync": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.2.0"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.2.0"]],
        },
        "hb_interval": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "integer"},
        "hb_lost_threshold": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "integer"},
        "ipsec_tunnel_sync": {
            "v_range": [["v6.2.0", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ike_monitor": {
            "v_range": [["v7.0.0", "v7.0.7"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ike_monitor_interval": {
            "v_range": [["v7.0.0", "v7.0.7"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "ike_heartbeat_interval": {
            "v_range": [["v7.0.0", "v7.0.7"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "secondary_add_ipsec_routes": {
            "v_range": [["v7.0.1", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "session_sync_filter": {
            "v_range": [["v6.0.0", "v7.2.0"]],
            "type": "dict",
            "children": {
                "srcintf": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "string"},
                "dstintf": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "string"},
                "srcaddr": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "string"},
                "dstaddr": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "string"},
                "srcaddr6": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "string"},
                "dstaddr6": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "string"},
                "custom_service": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", "v7.2.0"]],
                            "type": "integer",
                            "required": True,
                        },
                        "src_port_range": {
                            "v_range": [["v6.0.0", "v7.2.0"]],
                            "type": "string",
                        },
                        "dst_port_range": {
                            "v_range": [["v6.0.0", "v7.2.0"]],
                            "type": "string",
                        },
                    },
                    "v_range": [["v6.0.0", "v7.2.0"]],
                },
            },
        },
        "ike_seqjump_speed": {"v_range": [["v7.0.0", "v7.0.0"]], "type": "integer"},
        "slave_add_ike_routes": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
    },
    "v_range": [["v6.0.0", "v7.2.0"]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "sync_id"
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
        "system_cluster_sync": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_cluster_sync"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_cluster_sync"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_cluster_sync"
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
