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
module: fortios_antivirus_quarantine
short_description: Configure quarantine options in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify antivirus feature and quarantine category.
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

    antivirus_quarantine:
        description:
            - Configure quarantine options.
        default: null
        type: dict
        suboptions:
            agelimit:
                description:
                    - Age limit for quarantined files (0 - 479 hours, 0 means forever).
                type: int
            destination:
                description:
                    - Choose whether to quarantine files to the FortiGate disk or to FortiAnalyzer or to delete them instead of quarantining them.
                type: str
                choices:
                    - 'NULL'
                    - 'disk'
                    - 'FortiAnalyzer'
            drop_blocked:
                description:
                    - Do not quarantine dropped files found in sessions using the selected protocols. Dropped files are deleted instead of being quarantined.
                type: list
                elements: str
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
            drop_heuristic:
                description:
                    - Do not quarantine files detected by heuristics found in sessions using the selected protocols. Dropped files are deleted instead of
                       being quarantined.
                type: list
                elements: str
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
            drop_infected:
                description:
                    - Do not quarantine infected files found in sessions using the selected protocols. Dropped files are deleted instead of being quarantined.
                type: list
                elements: str
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
            drop_intercepted:
                description:
                    - drop intercepted from a protocol
                type: list
                elements: str
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'ftps'
                    - 'mapi'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
            drop_machine_learning:
                description:
                    - Do not quarantine files detected by machine learning found in sessions using the selected protocols. Dropped files are deleted instead
                       of being quarantined.
                type: list
                elements: str
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
            lowspace:
                description:
                    - Select the method for handling additional files when running low on disk space.
                type: str
                choices:
                    - 'drop-new'
                    - 'ovrw-old'
            maxfilesize:
                description:
                    - Maximum file size to quarantine (0 - 500 Mbytes, 0 means unlimited).
                type: int
            quarantine_quota:
                description:
                    - The amount of disk space to reserve for quarantining files (0 - 4294967295 Mbytes, 0 means unlimited and depends on disk space).
                type: int
            store_blocked:
                description:
                    - Quarantine blocked files found in sessions using the selected protocols.
                type: list
                elements: str
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
            store_heuristic:
                description:
                    - Quarantine files detected by heuristics found in sessions using the selected protocols.
                type: list
                elements: str
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
            store_infected:
                description:
                    - Quarantine infected files found in sessions using the selected protocols.
                type: list
                elements: str
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
            store_intercepted:
                description:
                    - quarantine intercepted from a protocol
                type: list
                elements: str
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'ftps'
                    - 'mapi'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
            store_machine_learning:
                description:
                    - Quarantine files detected by machine learning found in sessions using the selected protocols.
                type: list
                elements: str
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
"""

EXAMPLES = """
- name: Configure quarantine options.
  fortinet.fortios.fortios_antivirus_quarantine:
      vdom: "{{ vdom }}"
      antivirus_quarantine:
          agelimit: "0"
          destination: "NULL"
          drop_blocked: "imap"
          drop_heuristic: "imap"
          drop_infected: "imap"
          drop_intercepted: "imap"
          drop_machine_learning: "imap"
          lowspace: "drop-new"
          maxfilesize: "0"
          quarantine_quota: "0"
          store_blocked: "imap"
          store_heuristic: "imap"
          store_infected: "imap"
          store_intercepted: "imap"
          store_machine_learning: "imap"
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


def filter_antivirus_quarantine_data(json):
    option_list = [
        "agelimit",
        "destination",
        "drop_blocked",
        "drop_heuristic",
        "drop_infected",
        "drop_intercepted",
        "drop_machine_learning",
        "lowspace",
        "maxfilesize",
        "quarantine_quota",
        "store_blocked",
        "store_heuristic",
        "store_infected",
        "store_intercepted",
        "store_machine_learning",
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
        ["drop_infected"],
        ["store_infected"],
        ["drop_machine_learning"],
        ["store_machine_learning"],
        ["drop_blocked"],
        ["store_blocked"],
        ["drop_heuristic"],
        ["store_heuristic"],
        ["drop_intercepted"],
        ["store_intercepted"],
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


def antivirus_quarantine(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    antivirus_quarantine_data = data["antivirus_quarantine"]

    filtered_data = filter_antivirus_quarantine_data(antivirus_quarantine_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("antivirus", "quarantine", filtered_data, vdom=vdom)
        current_data = fos.get("antivirus", "quarantine", vdom=vdom, mkey=mkey)
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
    data_copy["antivirus_quarantine"] = filtered_data
    fos.do_member_operation(
        "antivirus",
        "quarantine",
        data_copy,
    )

    return fos.set("antivirus", "quarantine", data=converted_data, vdom=vdom)


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


def fortios_antivirus(data, fos, check_mode):

    if data["antivirus_quarantine"]:
        resp = antivirus_quarantine(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("antivirus_quarantine"))
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
        "agelimit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "maxfilesize": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "quarantine_quota": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "drop_infected": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "imap"},
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "http"},
                {"value": "ftp"},
                {"value": "nntp"},
                {"value": "imaps"},
                {"value": "smtps"},
                {"value": "pop3s"},
                {"value": "https"},
                {"value": "ftps"},
                {"value": "mapi"},
                {"value": "cifs"},
                {"value": "ssh", "v_range": [["v6.2.0", ""]]},
                {"value": "mm1", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm3", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm4", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm7", "v_range": [["v6.0.0", "v6.2.7"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "store_infected": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "imap"},
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "http"},
                {"value": "ftp"},
                {"value": "nntp"},
                {"value": "imaps"},
                {"value": "smtps"},
                {"value": "pop3s"},
                {"value": "https"},
                {"value": "ftps"},
                {"value": "mapi"},
                {"value": "cifs"},
                {"value": "ssh", "v_range": [["v6.2.0", ""]]},
                {"value": "mm1", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm3", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm4", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm7", "v_range": [["v6.0.0", "v6.2.7"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "drop_machine_learning": {
            "v_range": [["v7.0.1", ""]],
            "type": "list",
            "options": [
                {"value": "imap"},
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "http"},
                {"value": "ftp"},
                {"value": "nntp"},
                {"value": "imaps"},
                {"value": "smtps"},
                {"value": "pop3s"},
                {"value": "https"},
                {"value": "ftps"},
                {"value": "mapi"},
                {"value": "cifs"},
                {"value": "ssh"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "store_machine_learning": {
            "v_range": [["v7.0.1", ""]],
            "type": "list",
            "options": [
                {"value": "imap"},
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "http"},
                {"value": "ftp"},
                {"value": "nntp"},
                {"value": "imaps"},
                {"value": "smtps"},
                {"value": "pop3s"},
                {"value": "https"},
                {"value": "ftps"},
                {"value": "mapi"},
                {"value": "cifs"},
                {"value": "ssh"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "lowspace": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "drop-new"}, {"value": "ovrw-old"}],
        },
        "destination": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "NULL"},
                {"value": "disk"},
                {"value": "FortiAnalyzer"},
            ],
        },
        "drop_blocked": {
            "v_range": [["v6.0.0", "v7.4.0"]],
            "type": "list",
            "options": [
                {"value": "imap"},
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "http"},
                {"value": "ftp"},
                {"value": "nntp"},
                {"value": "imaps"},
                {"value": "smtps"},
                {"value": "pop3s"},
                {"value": "https", "v_range": [["v7.4.0", "v7.4.0"]]},
                {"value": "ftps"},
                {"value": "mapi"},
                {"value": "cifs"},
                {"value": "ssh", "v_range": [["v6.2.0", "v7.4.0"]]},
                {"value": "mm1", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm3", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm4", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm7", "v_range": [["v6.0.0", "v6.2.7"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "store_blocked": {
            "v_range": [["v6.0.0", "v7.4.0"]],
            "type": "list",
            "options": [
                {"value": "imap"},
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "http"},
                {"value": "ftp"},
                {"value": "nntp"},
                {"value": "imaps"},
                {"value": "smtps"},
                {"value": "pop3s"},
                {"value": "https", "v_range": [["v7.4.0", "v7.4.0"]]},
                {"value": "ftps"},
                {"value": "mapi"},
                {"value": "cifs"},
                {"value": "ssh", "v_range": [["v6.2.0", "v7.4.0"]]},
                {"value": "mm1", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm3", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm4", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm7", "v_range": [["v6.0.0", "v6.2.7"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "drop_heuristic": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "list",
            "options": [
                {"value": "imap"},
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "http"},
                {"value": "ftp"},
                {"value": "nntp"},
                {"value": "imaps"},
                {"value": "smtps"},
                {"value": "pop3s"},
                {"value": "https"},
                {"value": "ftps"},
                {"value": "mapi"},
                {"value": "cifs"},
                {"value": "ssh", "v_range": [["v6.2.0", "v7.0.0"]]},
                {"value": "mm1", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm3", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm4", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm7", "v_range": [["v6.0.0", "v6.2.7"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "store_heuristic": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "list",
            "options": [
                {"value": "imap"},
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "http"},
                {"value": "ftp"},
                {"value": "nntp"},
                {"value": "imaps"},
                {"value": "smtps"},
                {"value": "pop3s"},
                {"value": "https"},
                {"value": "ftps"},
                {"value": "mapi"},
                {"value": "cifs"},
                {"value": "ssh", "v_range": [["v6.2.0", "v7.0.0"]]},
                {"value": "mm1", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm3", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm4", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm7", "v_range": [["v6.0.0", "v6.2.7"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "drop_intercepted": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "list",
            "options": [
                {"value": "imap"},
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "http"},
                {"value": "ftp"},
                {"value": "imaps"},
                {"value": "smtps"},
                {"value": "pop3s"},
                {"value": "https"},
                {"value": "ftps"},
                {"value": "mapi"},
                {"value": "mm1"},
                {"value": "mm3"},
                {"value": "mm4"},
                {"value": "mm7"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "store_intercepted": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "list",
            "options": [
                {"value": "imap"},
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "http"},
                {"value": "ftp"},
                {"value": "imaps"},
                {"value": "smtps"},
                {"value": "pop3s"},
                {"value": "https"},
                {"value": "ftps"},
                {"value": "mapi"},
                {"value": "mm1"},
                {"value": "mm3"},
                {"value": "mm4"},
                {"value": "mm7"},
            ],
            "multiple_values": True,
            "elements": "str",
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
        "antivirus_quarantine": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["antivirus_quarantine"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["antivirus_quarantine"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "antivirus_quarantine"
        )

        is_error, has_changed, result, diff = fortios_antivirus(
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
