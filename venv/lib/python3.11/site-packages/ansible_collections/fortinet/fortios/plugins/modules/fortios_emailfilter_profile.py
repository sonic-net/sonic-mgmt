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
module: fortios_emailfilter_profile
short_description: Configure Email Filter profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify emailfilter feature and profile category.
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
    emailfilter_profile:
        description:
            - Configure Email Filter profiles.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Comment.
                type: str
            external:
                description:
                    - Enable/disable external Email inspection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            feature_set:
                description:
                    - Flow/proxy feature set.
                type: str
                choices:
                    - 'flow'
                    - 'proxy'
            file_filter:
                description:
                    - File filter.
                type: dict
                suboptions:
                    entries:
                        description:
                            - File filter entries.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                description:
                                    - Action taken for matched file.
                                type: str
                                choices:
                                    - 'log'
                                    - 'block'
                            comment:
                                description:
                                    - Comment.
                                type: str
                            file_type:
                                description:
                                    - Select file type.
                                type: list
                                elements: dict
                                suboptions:
                                    name:
                                        description:
                                            - File type name. Source antivirus.filetype.name.
                                        required: true
                                        type: str
                            filter:
                                description:
                                    - Add a file filter.
                                required: true
                                type: str
                            password_protected:
                                description:
                                    - Match password-protected files.
                                type: str
                                choices:
                                    - 'yes'
                                    - 'any'
                            protocol:
                                description:
                                    - Protocols to apply with.
                                type: list
                                elements: str
                                choices:
                                    - 'smtp'
                                    - 'imap'
                                    - 'pop3'
                    log:
                        description:
                            - Enable/disable file filter logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    scan_archive_contents:
                        description:
                            - Enable/disable file filter archive contents scan.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status:
                        description:
                            - Enable/disable file filter.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            gmail:
                description:
                    - Gmail.
                type: dict
                suboptions:
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            imap:
                description:
                    - IMAP.
                type: dict
                suboptions:
                    action:
                        description:
                            - Action for spam email.
                        type: str
                        choices:
                            - 'pass'
                            - 'tag'
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    tag_msg:
                        description:
                            - Subject text or header added to spam email.
                        type: str
                    tag_type:
                        description:
                            - Tag subject or header for spam email.
                        type: list
                        elements: str
                        choices:
                            - 'subject'
                            - 'header'
                            - 'spaminfo'
            mapi:
                description:
                    - MAPI.
                type: dict
                suboptions:
                    action:
                        description:
                            - Action for spam email.
                        type: str
                        choices:
                            - 'pass'
                            - 'discard'
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            msn_hotmail:
                description:
                    - MSN Hotmail.
                type: dict
                suboptions:
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            options:
                description:
                    - Options.
                type: list
                elements: str
                choices:
                    - 'bannedword'
                    - 'spambal'
                    - 'spamfsip'
                    - 'spamfssubmit'
                    - 'spamfschksum'
                    - 'spamfsurl'
                    - 'spamhelodns'
                    - 'spamraddrdns'
                    - 'spamrbl'
                    - 'spamhdrcheck'
                    - 'spamfsphish'
                    - 'spambwl'
            other_webmails:
                description:
                    - Other supported webmails.
                type: dict
                suboptions:
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            pop3:
                description:
                    - POP3.
                type: dict
                suboptions:
                    action:
                        description:
                            - Action for spam email.
                        type: str
                        choices:
                            - 'pass'
                            - 'tag'
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    tag_msg:
                        description:
                            - Subject text or header added to spam email.
                        type: str
                    tag_type:
                        description:
                            - Tag subject or header for spam email.
                        type: list
                        elements: str
                        choices:
                            - 'subject'
                            - 'header'
                            - 'spaminfo'
            replacemsg_group:
                description:
                    - Replacement message group. Source system.replacemsg-group.name.
                type: str
            smtp:
                description:
                    - SMTP.
                type: dict
                suboptions:
                    action:
                        description:
                            - Action for spam email.
                        type: str
                        choices:
                            - 'pass'
                            - 'tag'
                            - 'discard'
                    hdrip:
                        description:
                            - Enable/disable SMTP email header IP checks for spamfsip, spamrbl, and spambal filters.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    local_override:
                        description:
                            - Enable/disable local filter to override SMTP remote check result.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    tag_msg:
                        description:
                            - Subject text or header added to spam email.
                        type: str
                    tag_type:
                        description:
                            - Tag subject or header for spam email.
                        type: list
                        elements: str
                        choices:
                            - 'subject'
                            - 'header'
                            - 'spaminfo'
            spam_bal_table:
                description:
                    - Anti-spam block/allow list table ID. Source emailfilter.block-allow-list.id.
                type: int
            spam_bwl_table:
                description:
                    - Anti-spam black/white list table ID. Source emailfilter.bwl.id.
                type: int
            spam_bword_table:
                description:
                    - Anti-spam banned word table ID. Source emailfilter.bword.id.
                type: int
            spam_bword_threshold:
                description:
                    - Spam banned word threshold.
                type: int
            spam_filtering:
                description:
                    - Enable/disable spam filtering.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            spam_iptrust_table:
                description:
                    - Anti-spam IP trust table ID. Source emailfilter.iptrust.id.
                type: int
            spam_log:
                description:
                    - Enable/disable spam logging for email filtering.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            spam_log_fortiguard_response:
                description:
                    - Enable/disable logging FortiGuard spam response.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            spam_mheader_table:
                description:
                    - Anti-spam MIME header table ID. Source emailfilter.mheader.id.
                type: int
            spam_rbl_table:
                description:
                    - Anti-spam DNSBL table ID. Source emailfilter.dnsbl.id.
                type: int
            yahoo_mail:
                description:
                    - Yahoo! Mail.
                type: dict
                suboptions:
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
"""

EXAMPLES = """
- name: Configure Email Filter profiles.
  fortinet.fortios.fortios_emailfilter_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      emailfilter_profile:
          comment: "Comment."
          external: "enable"
          feature_set: "flow"
          file_filter:
              entries:
                  -
                      action: "log"
                      comment: "Comment."
                      file_type:
                          -
                              name: "default_name_11 (source antivirus.filetype.name)"
                      filter: "<your_own_value>"
                      password_protected: "yes"
                      protocol: "smtp"
              log: "enable"
              scan_archive_contents: "enable"
              status: "enable"
          gmail:
              log: "enable"
              log_all: "disable"
          imap:
              action: "pass"
              log: "enable"
              log_all: "disable"
              tag_msg: "<your_own_value>"
              tag_type: "subject"
          mapi:
              action: "pass"
              log: "enable"
              log_all: "disable"
          msn_hotmail:
              log: "enable"
              log_all: "disable"
          name: "default_name_34"
          options: "bannedword"
          other_webmails:
              log_all: "disable"
          pop3:
              action: "pass"
              log: "enable"
              log_all: "disable"
              tag_msg: "<your_own_value>"
              tag_type: "subject"
          replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
          smtp:
              action: "pass"
              hdrip: "disable"
              local_override: "disable"
              log: "enable"
              log_all: "disable"
              tag_msg: "<your_own_value>"
              tag_type: "subject"
          spam_bal_table: "0"
          spam_bwl_table: "2147483647"
          spam_bword_table: "0"
          spam_bword_threshold: "10"
          spam_filtering: "enable"
          spam_iptrust_table: "0"
          spam_log: "disable"
          spam_log_fortiguard_response: "disable"
          spam_mheader_table: "0"
          spam_rbl_table: "0"
          yahoo_mail:
              log: "enable"
              log_all: "disable"
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


def filter_emailfilter_profile_data(json):
    option_list = [
        "comment",
        "external",
        "feature_set",
        "file_filter",
        "gmail",
        "imap",
        "mapi",
        "msn_hotmail",
        "name",
        "options",
        "other_webmails",
        "pop3",
        "replacemsg_group",
        "smtp",
        "spam_bal_table",
        "spam_bwl_table",
        "spam_bword_table",
        "spam_bword_threshold",
        "spam_filtering",
        "spam_iptrust_table",
        "spam_log",
        "spam_log_fortiguard_response",
        "spam_mheader_table",
        "spam_rbl_table",
        "yahoo_mail",
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
        ["options"],
        ["imap", "tag_type"],
        ["pop3", "tag_type"],
        ["smtp", "tag_type"],
        ["file_filter", "entries", "protocol"],
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


def emailfilter_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    emailfilter_profile_data = data["emailfilter_profile"]

    filtered_data = filter_emailfilter_profile_data(emailfilter_profile_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("emailfilter", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("emailfilter", "profile", vdom=vdom, mkey=mkey)
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
    data_copy["emailfilter_profile"] = filtered_data
    fos.do_member_operation(
        "emailfilter",
        "profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("emailfilter", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "emailfilter", "profile", mkey=converted_data["name"], vdom=vdom
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


def fortios_emailfilter(data, fos, check_mode):

    if data["emailfilter_profile"]:
        resp = emailfilter_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("emailfilter_profile"))
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
        "name": {"v_range": [["v6.2.0", ""]], "type": "string", "required": True},
        "comment": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "feature_set": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "flow"}, {"value": "proxy"}],
        },
        "replacemsg_group": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "spam_log": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "spam_log_fortiguard_response": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "spam_filtering": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "external": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "options": {
            "v_range": [["v6.2.0", ""]],
            "type": "list",
            "options": [
                {"value": "bannedword"},
                {"value": "spambal", "v_range": [["v7.0.0", ""]]},
                {"value": "spamfsip"},
                {"value": "spamfssubmit"},
                {"value": "spamfschksum"},
                {"value": "spamfsurl"},
                {"value": "spamhelodns"},
                {"value": "spamraddrdns"},
                {"value": "spamrbl"},
                {"value": "spamhdrcheck"},
                {"value": "spamfsphish"},
                {"value": "spambwl", "v_range": [["v6.2.0", "v6.4.4"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "imap": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "log_all": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "action": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "pass"}, {"value": "tag"}],
                },
                "tag_type": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "subject"},
                        {"value": "header"},
                        {"value": "spaminfo"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "tag_msg": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "log": {
                    "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "pop3": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "log_all": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "action": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "pass"}, {"value": "tag"}],
                },
                "tag_type": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "subject"},
                        {"value": "header"},
                        {"value": "spaminfo"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "tag_msg": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "log": {
                    "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "smtp": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "log_all": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "action": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "pass"},
                        {"value": "tag"},
                        {"value": "discard"},
                    ],
                },
                "tag_type": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "subject"},
                        {"value": "header"},
                        {"value": "spaminfo"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "tag_msg": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "hdrip": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "local_override": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log": {
                    "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "mapi": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "log_all": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "action": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "pass"}, {"value": "discard"}],
                },
                "log": {
                    "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "msn_hotmail": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "log_all": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log": {
                    "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "yahoo_mail": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "log_all": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log": {
                    "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "gmail": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "log_all": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log": {
                    "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "other_webmails": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "dict",
            "children": {
                "log_all": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                }
            },
        },
        "spam_bword_threshold": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "spam_bword_table": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "spam_bal_table": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "spam_mheader_table": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "spam_rbl_table": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "spam_iptrust_table": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "spam_bwl_table": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "integer"},
        "file_filter": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "log": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "scan_archive_contents": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "entries": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "filter": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        },
                        "comment": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                        },
                        "protocol": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "list",
                            "options": [
                                {"value": "smtp"},
                                {"value": "imap"},
                                {"value": "pop3"},
                            ],
                            "multiple_values": True,
                            "elements": "str",
                        },
                        "action": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                            "options": [{"value": "log"}, {"value": "block"}],
                        },
                        "password_protected": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                            "options": [{"value": "yes"}, {"value": "any"}],
                        },
                        "file_type": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "name": {
                                    "v_range": [["v6.2.0", "v6.2.7"]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v6.2.0", "v6.2.7"]],
                        },
                    },
                    "v_range": [["v6.2.0", "v6.2.7"]],
                },
            },
        },
    },
    "v_range": [["v6.2.0", ""]],
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
        "emailfilter_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["emailfilter_profile"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["emailfilter_profile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "emailfilter_profile"
        )

        is_error, has_changed, result, diff = fortios_emailfilter(
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
