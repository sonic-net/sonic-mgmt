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
module: fortios_gtp_message_filter_v0v1
short_description: Message filter for GTPv0/v1 messages in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify gtp feature and message_filter_v0v1 category.
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
    gtp_message_filter_v0v1:
        description:
            - Message filter for GTPv0/v1 messages.
        default: null
        type: dict
        suboptions:
            create_mbms:
                description:
                    - GTPv1 create MBMS context (req 100, resp 101).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            create_pdp:
                description:
                    - Create PDP context (req 16, resp 17).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            data_record:
                description:
                    - Data record transfer (req 240, resp 241).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            delete_aa_pdp:
                description:
                    - GTPv0 delete AA PDP context (req 24, resp 25).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            delete_mbms:
                description:
                    - GTPv1 delete MBMS context (req 104, resp 105).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            delete_pdp:
                description:
                    - Delete PDP context (req 20, resp 21).
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
            end_marker:
                description:
                    - GTPv1 End marker (254).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            error_indication:
                description:
                    - Error indication (26).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            failure_report:
                description:
                    - Failure report (req 34, resp 35).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            fwd_relocation:
                description:
                    - GTPv1 forward relocation (req 53, resp 54, complete 55, complete ack 59).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            fwd_srns_context:
                description:
                    - GTPv1 forward SRNS (context 58, context ack 60).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            gtp_pdu:
                description:
                    - PDU (255).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            identification:
                description:
                    - Identification (req 48, resp 49).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            mbms_de_registration:
                description:
                    - GTPv1 MBMS de-registration (req 114, resp 115).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            mbms_notification:
                description:
                    - GTPv1 MBMS notification (req 96, resp 97, reject req 98. reject resp 99).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            mbms_registration:
                description:
                    - GTPv1 MBMS registration (req 112, resp 113).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            mbms_session_start:
                description:
                    - GTPv1 MBMS session start (req 116, resp 117).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            mbms_session_stop:
                description:
                    - GTPv1 MBMS session stop (req 118, resp 119).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            mbms_session_update:
                description:
                    - GTPv1 MBMS session update (req 120, resp 121).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            ms_info_change_notif:
                description:
                    - GTPv1 MS info change notification (req 128, resp 129).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            name:
                description:
                    - Message filter name.
                required: true
                type: str
            node_alive:
                description:
                    - Node alive (req 4, resp 5).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            note_ms_present:
                description:
                    - Note MS GPRS present (req 36, resp 37).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            pdu_notification:
                description:
                    - PDU notification (req 27, resp 28, reject req 29, reject resp 30).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            ran_info:
                description:
                    - GTPv1 RAN information relay (70).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            redirection:
                description:
                    - Redirection (req 6, resp 7).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            relocation_cancel:
                description:
                    - GTPv1 relocation cancel (req 56, resp 57).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            send_route:
                description:
                    - Send routing information for GPRS (req 32, resp 33).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            sgsn_context:
                description:
                    - SGSN context (req 50, resp 51, ack 52).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            support_extension:
                description:
                    - GTPv1 supported extension headers notify (31).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            ue_registration_query:
                description:
                    - UE Registration Query (req 61, resp ack 62).
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
            update_mbms:
                description:
                    - GTPv1 update MBMS context (req 102, resp 103).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            update_pdp:
                description:
                    - Update PDP context (req 18, resp 19).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            v0_create_aa_pdp__v1_init_pdp_ctx:
                description:
                    - GTPv0 create AA PDP context (req 22, resp 23); Or GTPv1 initiate PDP context (req 22, resp 23).
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
- name: Message filter for GTPv0/v1 messages.
  fortinet.fortios.fortios_gtp_message_filter_v0v1:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      gtp_message_filter_v0v1:
          create_mbms: "allow"
          create_pdp: "allow"
          data_record: "allow"
          delete_aa_pdp: "allow"
          delete_mbms: "allow"
          delete_pdp: "allow"
          echo: "allow"
          end_marker: "allow"
          error_indication: "allow"
          failure_report: "allow"
          fwd_relocation: "allow"
          fwd_srns_context: "allow"
          gtp_pdu: "allow"
          identification: "allow"
          mbms_de_registration: "allow"
          mbms_notification: "allow"
          mbms_registration: "allow"
          mbms_session_start: "allow"
          mbms_session_stop: "allow"
          mbms_session_update: "allow"
          ms_info_change_notif: "allow"
          name: "default_name_24"
          node_alive: "allow"
          note_ms_present: "allow"
          pdu_notification: "allow"
          ran_info: "allow"
          redirection: "allow"
          relocation_cancel: "allow"
          send_route: "allow"
          sgsn_context: "allow"
          support_extension: "allow"
          ue_registration_query: "allow"
          unknown_message: "allow"
          unknown_message_white_list:
              -
                  id: "37"
          update_mbms: "allow"
          update_pdp: "allow"
          v0_create_aa_pdp__v1_init_pdp_ctx: "allow"
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


def filter_gtp_message_filter_v0v1_data(json):
    option_list = [
        "create_mbms",
        "create_pdp",
        "data_record",
        "delete_aa_pdp",
        "delete_mbms",
        "delete_pdp",
        "echo",
        "end_marker",
        "error_indication",
        "failure_report",
        "fwd_relocation",
        "fwd_srns_context",
        "gtp_pdu",
        "identification",
        "mbms_de_registration",
        "mbms_notification",
        "mbms_registration",
        "mbms_session_start",
        "mbms_session_stop",
        "mbms_session_update",
        "ms_info_change_notif",
        "name",
        "node_alive",
        "note_ms_present",
        "pdu_notification",
        "ran_info",
        "redirection",
        "relocation_cancel",
        "send_route",
        "sgsn_context",
        "support_extension",
        "ue_registration_query",
        "unknown_message",
        "unknown_message_white_list",
        "update_mbms",
        "update_pdp",
        "v0_create_aa_pdp__v1_init_pdp_ctx",
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


def gtp_message_filter_v0v1(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    gtp_message_filter_v0v1_data = data["gtp_message_filter_v0v1"]

    filtered_data = filter_gtp_message_filter_v0v1_data(gtp_message_filter_v0v1_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("gtp", "message-filter-v0v1", filtered_data, vdom=vdom)
        current_data = fos.get("gtp", "message-filter-v0v1", vdom=vdom, mkey=mkey)
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
    data_copy["gtp_message_filter_v0v1"] = filtered_data
    fos.do_member_operation(
        "gtp",
        "message-filter-v0v1",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("gtp", "message-filter-v0v1", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "gtp", "message-filter-v0v1", mkey=converted_data["name"], vdom=vdom
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

    if data["gtp_message_filter_v0v1"]:
        resp = gtp_message_filter_v0v1(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("gtp_message_filter_v0v1"))
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
        "node_alive": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "redirection": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "create_pdp": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "update_pdp": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "delete_pdp": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "v0_create_aa_pdp__v1_init_pdp_ctx": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "delete_aa_pdp": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "error_indication": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "pdu_notification": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "support_extension": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "send_route": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "failure_report": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "note_ms_present": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "identification": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "sgsn_context": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "fwd_relocation": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "relocation_cancel": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "fwd_srns_context": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "ue_registration_query": {
            "v_range": [["v7.2.1", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "ran_info": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "mbms_notification": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "create_mbms": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "update_mbms": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "delete_mbms": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "mbms_registration": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "mbms_de_registration": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "mbms_session_start": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "mbms_session_stop": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "mbms_session_update": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "ms_info_change_notif": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "data_record": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "end_marker": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "gtp_pdu": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
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
        "gtp_message_filter_v0v1": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["gtp_message_filter_v0v1"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["gtp_message_filter_v0v1"]["options"][attribute_name][
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
            fos, versioned_schema, "gtp_message_filter_v0v1"
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
