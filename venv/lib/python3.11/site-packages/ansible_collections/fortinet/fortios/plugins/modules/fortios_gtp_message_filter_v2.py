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
module: fortios_gtp_message_filter_v2
short_description: Message filter for GTPv2 messages in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify gtp feature and message_filter_v2 category.
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
    gtp_message_filter_v2:
        description:
            - Message filter for GTPv2 messages.
        default: null
        type: dict
        suboptions:
            alert_mme_notif_ack:
                description:
                    - Alert MME notification/acknowledge (notif 153, ack 154).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            bearer_resource_cmd_fail:
                description:
                    - Bearer resource (command 68, failure indication 69).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            change_notification:
                description:
                    - Change notification (req 38, resp 39).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            configuration_transfer_tunnel:
                description:
                    - Configuration transfer tunnel (141).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            context_req_res_ack:
                description:
                    - Context request/response/acknowledge (req 130, resp 131, ack 132).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            create_bearer:
                description:
                    - Create bearer (req 95, resp 96).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            create_forwarding_tunnel_req_resp:
                description:
                    - Create forwarding tunnel request/response (req 160, resp 161).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            create_indirect_forwarding_tunnel_req_resp:
                description:
                    - Create indirect data forwarding tunnel request/response (req 166, resp 167).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            create_session:
                description:
                    - Create session (req 32, resp 33).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            cs_paging:
                description:
                    - CS paging indication (151)
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            delete_bearer_cmd_fail:
                description:
                    - Delete bearer (command 66, failure indication 67).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            delete_bearer_req_resp:
                description:
                    - Delete bearer (req 99, resp 100).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            delete_indirect_forwarding_tunnel_req_resp:
                description:
                    - Delete indirect data forwarding tunnel request/response (req 168, resp 169).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            delete_pdn_connection_set:
                description:
                    - Delete PDN connection set (req 101, resp 102).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            delete_session:
                description:
                    - Delete session (req 36, resp 37).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            detach_notif_ack:
                description:
                    - Detach notification/acknowledge (notif 149, ack 150).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            dlink_data_notif_ack:
                description:
                    - Downlink data notification/acknowledge (notif 176, ack 177).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            dlink_notif_failure:
                description:
                    - Downlink data notification failure indication (70).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            echo:
                description:
                    - Echo (req 1, resp 2).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            forward_access_notif_ack:
                description:
                    - Forward access context notification/acknowledge (notif 137, ack 138).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            forward_relocation_cmp_notif_ack:
                description:
                    - Forward relocation complete notification/acknowledge (notif 135, ack 136).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            forward_relocation_req_res:
                description:
                    - Forward relocation request/response (req 133, resp 134).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            identification_req_resp:
                description:
                    - Identification request/response (req 128, resp 129).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            isr_status:
                description:
                    - ISR status indication (157).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            mbms_session_start_req_resp:
                description:
                    - MBMS session start request/response (req 231, resp 232).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            mbms_session_stop_req_resp:
                description:
                    - MBMS session stop request/response (req 235, resp 236).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            mbms_session_update_req_resp:
                description:
                    - MBMS session update request/response (req 233, resp 234).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            modify_access_req_resp:
                description:
                    - Modify access bearers request/response (req 211, resp 212).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            modify_bearer_cmd_fail:
                description:
                    - Modify bearer (command 64 , failure indication 65).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            modify_bearer_req_resp:
                description:
                    - Modify bearer (req 34, resp 35).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            name:
                description:
                    - Message filter name.
                required: true
                type: str
            pgw_dlink_notif_ack:
                description:
                    - PGW downlink triggering notification/acknowledge (notif 103, ack 104).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            pgw_restart_notif_ack:
                description:
                    - PGW restart notification/acknowledge (notif 179, ack 180).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            ran_info_relay:
                description:
                    - RAN information relay (152).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            release_access_bearer_req_resp:
                description:
                    - Release access bearers request/response (req 170, resp 171).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            relocation_cancel_req_resp:
                description:
                    - Relocation cancel request/response (req 139, resp 140).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            remote_ue_report_notif_ack:
                description:
                    - Remote UE report notification/acknowledge (notif 40, ack 41).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            reserved_for_earlier_version:
                description:
                    - Reserved for earlier version of the GTP specification (178).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            resume:
                description:
                    - Resume (notify 164 , ack 165).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            stop_paging_indication:
                description:
                    - Stop Paging Indication (73).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            suspend:
                description:
                    - Suspend (notify 162, ack 163).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            trace_session:
                description:
                    - Trace session (activation 71, deactivation 72).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            ue_activity_notif_ack:
                description:
                    - UE activity notification/acknowledge (notif 155, ack 156).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            ue_registration_query_req_resp:
                description:
                    - UE registration query request/response (req 158, resp 159).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            unknown_message:
                description:
                    - Allow or Deny unknown messages.
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            unknown_message_white_list:
                description:
                    - White list (to allow) of unknown messages.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Message IDs. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            update_bearer:
                description:
                    - Update bearer (req 97, resp 98).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            update_pdn_connection_set:
                description:
                    - Update PDN connection set (req 200, resp 201).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            version_not_support:
                description:
                    - Version not supported (3).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
"""

EXAMPLES = """
- name: Message filter for GTPv2 messages.
  fortinet.fortios.fortios_gtp_message_filter_v2:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      gtp_message_filter_v2:
          alert_mme_notif_ack: "allow"
          bearer_resource_cmd_fail: "allow"
          change_notification: "allow"
          configuration_transfer_tunnel: "allow"
          context_req_res_ack: "allow"
          create_bearer: "allow"
          create_forwarding_tunnel_req_resp: "allow"
          create_indirect_forwarding_tunnel_req_resp: "allow"
          create_session: "allow"
          cs_paging: "allow"
          delete_bearer_cmd_fail: "allow"
          delete_bearer_req_resp: "allow"
          delete_indirect_forwarding_tunnel_req_resp: "allow"
          delete_pdn_connection_set: "allow"
          delete_session: "allow"
          detach_notif_ack: "allow"
          dlink_data_notif_ack: "allow"
          dlink_notif_failure: "allow"
          echo: "allow"
          forward_access_notif_ack: "allow"
          forward_relocation_cmp_notif_ack: "allow"
          forward_relocation_req_res: "allow"
          identification_req_resp: "allow"
          isr_status: "allow"
          mbms_session_start_req_resp: "allow"
          mbms_session_stop_req_resp: "allow"
          mbms_session_update_req_resp: "allow"
          modify_access_req_resp: "allow"
          modify_bearer_cmd_fail: "allow"
          modify_bearer_req_resp: "allow"
          name: "default_name_33"
          pgw_dlink_notif_ack: "allow"
          pgw_restart_notif_ack: "allow"
          ran_info_relay: "allow"
          release_access_bearer_req_resp: "allow"
          relocation_cancel_req_resp: "allow"
          remote_ue_report_notif_ack: "allow"
          reserved_for_earlier_version: "allow"
          resume: "allow"
          stop_paging_indication: "allow"
          suspend: "allow"
          trace_session: "allow"
          ue_activity_notif_ack: "allow"
          ue_registration_query_req_resp: "allow"
          unknown_message: "allow"
          unknown_message_white_list:
              -
                  id: "49"
          update_bearer: "allow"
          update_pdn_connection_set: "allow"
          version_not_support: "allow"
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


def filter_gtp_message_filter_v2_data(json):
    option_list = [
        "alert_mme_notif_ack",
        "bearer_resource_cmd_fail",
        "change_notification",
        "configuration_transfer_tunnel",
        "context_req_res_ack",
        "create_bearer",
        "create_forwarding_tunnel_req_resp",
        "create_indirect_forwarding_tunnel_req_resp",
        "create_session",
        "cs_paging",
        "delete_bearer_cmd_fail",
        "delete_bearer_req_resp",
        "delete_indirect_forwarding_tunnel_req_resp",
        "delete_pdn_connection_set",
        "delete_session",
        "detach_notif_ack",
        "dlink_data_notif_ack",
        "dlink_notif_failure",
        "echo",
        "forward_access_notif_ack",
        "forward_relocation_cmp_notif_ack",
        "forward_relocation_req_res",
        "identification_req_resp",
        "isr_status",
        "mbms_session_start_req_resp",
        "mbms_session_stop_req_resp",
        "mbms_session_update_req_resp",
        "modify_access_req_resp",
        "modify_bearer_cmd_fail",
        "modify_bearer_req_resp",
        "name",
        "pgw_dlink_notif_ack",
        "pgw_restart_notif_ack",
        "ran_info_relay",
        "release_access_bearer_req_resp",
        "relocation_cancel_req_resp",
        "remote_ue_report_notif_ack",
        "reserved_for_earlier_version",
        "resume",
        "stop_paging_indication",
        "suspend",
        "trace_session",
        "ue_activity_notif_ack",
        "ue_registration_query_req_resp",
        "unknown_message",
        "unknown_message_white_list",
        "update_bearer",
        "update_pdn_connection_set",
        "version_not_support",
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


def gtp_message_filter_v2(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    gtp_message_filter_v2_data = data["gtp_message_filter_v2"]

    filtered_data = filter_gtp_message_filter_v2_data(gtp_message_filter_v2_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("gtp", "message-filter-v2", filtered_data, vdom=vdom)
        current_data = fos.get("gtp", "message-filter-v2", vdom=vdom, mkey=mkey)
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
    data_copy["gtp_message_filter_v2"] = filtered_data
    fos.do_member_operation(
        "gtp",
        "message-filter-v2",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("gtp", "message-filter-v2", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "gtp", "message-filter-v2", mkey=converted_data["name"], vdom=vdom
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


def fortios_gtp(data, fos, check_mode):

    if data["gtp_message_filter_v2"]:
        resp = gtp_message_filter_v2(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("gtp_message_filter_v2"))
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
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "required": True,
        },
        "unknown_message": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "unknown_message_white_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
        },
        "echo": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "version_not_support": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "create_session": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "modify_bearer_req_resp": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "delete_session": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "change_notification": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "remote_ue_report_notif_ack": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "modify_bearer_cmd_fail": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "delete_bearer_cmd_fail": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "bearer_resource_cmd_fail": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "dlink_notif_failure": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "trace_session": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "stop_paging_indication": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "create_bearer": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "update_bearer": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "delete_bearer_req_resp": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "delete_pdn_connection_set": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "pgw_dlink_notif_ack": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "identification_req_resp": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "context_req_res_ack": {
            "v_range": [["v7.0.2", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "forward_relocation_req_res": {
            "v_range": [["v7.0.2", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "forward_relocation_cmp_notif_ack": {
            "v_range": [["v7.0.2", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "forward_access_notif_ack": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "relocation_cancel_req_resp": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "configuration_transfer_tunnel": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "detach_notif_ack": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "cs_paging": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "ran_info_relay": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "alert_mme_notif_ack": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "ue_activity_notif_ack": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "isr_status": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "ue_registration_query_req_resp": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "create_forwarding_tunnel_req_resp": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "suspend": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "resume": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "create_indirect_forwarding_tunnel_req_resp": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "delete_indirect_forwarding_tunnel_req_resp": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "release_access_bearer_req_resp": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "dlink_data_notif_ack": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "reserved_for_earlier_version": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "pgw_restart_notif_ack": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "update_pdn_connection_set": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "modify_access_req_resp": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "mbms_session_start_req_resp": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "mbms_session_update_req_resp": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "mbms_session_stop_req_resp": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
    },
    "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
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
        "gtp_message_filter_v2": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["gtp_message_filter_v2"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["gtp_message_filter_v2"]["options"][attribute_name][
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
            fos, versioned_schema, "gtp_message_filter_v2"
        )

        is_error, has_changed, result, diff = fortios_gtp(
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
