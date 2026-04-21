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
module: fortios_log_disk_setting
short_description: Settings for local disk logging in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify log_disk feature and setting category.
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

    log_disk_setting:
        description:
            - Settings for local disk logging.
        default: null
        type: dict
        suboptions:
            diskfull:
                description:
                    - Action to take when disk is full. The system can overwrite the oldest log messages or stop logging when the disk is full .
                type: str
                choices:
                    - 'overwrite'
                    - 'nolog'
            dlp_archive_quota:
                description:
                    - DLP archive quota (MB).
                type: int
            full_final_warning_threshold:
                description:
                    - Log full final warning threshold as a percent (3 - 100).
                type: int
            full_first_warning_threshold:
                description:
                    - Log full first warning threshold as a percent (1 - 98).
                type: int
            full_second_warning_threshold:
                description:
                    - Log full second warning threshold as a percent (2 - 99).
                type: int
            interface:
                description:
                    - Specify outgoing interface to reach server. Source system.interface.name.
                type: str
            interface_select_method:
                description:
                    - Specify how to select outgoing interface to reach server.
                type: str
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            ips_archive:
                description:
                    - Enable/disable IPS packet archiving to the local disk.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            log_quota:
                description:
                    - Disk log quota (MB).
                type: int
            max_log_file_size:
                description:
                    - Maximum log file size before rolling (1 - 100 Mbytes).
                type: int
            max_policy_packet_capture_size:
                description:
                    - Maximum size of policy sniffer in MB (0 means unlimited).
                type: int
            maximum_log_age:
                description:
                    - Delete log files older than (days).
                type: int
            report_quota:
                description:
                    - Report db quota (MB).
                type: int
            roll_day:
                description:
                    - Day of week on which to roll log file.
                type: list
                elements: str
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
            roll_schedule:
                description:
                    - Frequency to check log file for rolling.
                type: str
                choices:
                    - 'daily'
                    - 'weekly'
            roll_time:
                description:
                    - 'Time of day to roll the log file (hh:mm).'
                type: str
            source_ip:
                description:
                    - Source IP address to use for uploading disk log files.
                type: str
            status:
                description:
                    - Enable/disable local disk logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            upload:
                description:
                    - Enable/disable uploading log files when they are rolled.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            upload_delete_files:
                description:
                    - Delete log files after uploading .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            upload_destination:
                description:
                    - The type of server to upload log files to. Only FTP is currently supported.
                type: str
                choices:
                    - 'ftp-server'
            upload_ssl_conn:
                description:
                    - Enable/disable encrypted FTPS communication to upload log files.
                type: str
                choices:
                    - 'default'
                    - 'high'
                    - 'low'
                    - 'disable'
            uploaddir:
                description:
                    - The remote directory on the FTP server to upload log files to.
                type: str
            uploadip:
                description:
                    - IP address of the FTP server to upload log files to.
                type: str
            uploadpass:
                description:
                    - Password required to log into the FTP server to upload disk log files.
                type: str
            uploadport:
                description:
                    - TCP port to use for communicating with the FTP server .
                type: int
            uploadsched:
                description:
                    - Set the schedule for uploading log files to the FTP server .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            uploadtime:
                description:
                    - 'Time of day at which log files are uploaded if uploadsched is enabled (hh:mm or hh).'
                type: str
            uploadtype:
                description:
                    - Types of log files to upload. Separate multiple entries with a space.
                type: list
                elements: str
                choices:
                    - 'traffic'
                    - 'event'
                    - 'virus'
                    - 'webfilter'
                    - 'IPS'
                    - 'emailfilter'
                    - 'dlp-archive'
                    - 'anomaly'
                    - 'voip'
                    - 'dlp'
                    - 'app-ctrl'
                    - 'waf'
                    - 'gtp'
                    - 'dns'
                    - 'ssh'
                    - 'ssl'
                    - 'file-filter'
                    - 'icap'
                    - 'virtual-patch'
                    - 'debug'
                    - 'ztna'
                    - 'cifs'
                    - 'spamfilter'
                    - 'netscan'
            uploaduser:
                description:
                    - Username required to log into the FTP server to upload disk log files.
                type: str
            vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
"""

EXAMPLES = """
- name: Settings for local disk logging.
  fortinet.fortios.fortios_log_disk_setting:
      vdom: "{{ vdom }}"
      log_disk_setting:
          diskfull: "overwrite"
          dlp_archive_quota: "0"
          full_final_warning_threshold: "95"
          full_first_warning_threshold: "75"
          full_second_warning_threshold: "90"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          ips_archive: "enable"
          log_quota: "0"
          max_log_file_size: "20"
          max_policy_packet_capture_size: "100"
          maximum_log_age: "7"
          report_quota: "0"
          roll_day: "sunday"
          roll_schedule: "daily"
          roll_time: "<your_own_value>"
          source_ip: "84.230.14.43"
          status: "enable"
          upload: "enable"
          upload_delete_files: "enable"
          upload_destination: "ftp-server"
          upload_ssl_conn: "default"
          uploaddir: "<your_own_value>"
          uploadip: "<your_own_value>"
          uploadpass: "<your_own_value>"
          uploadport: "21"
          uploadsched: "disable"
          uploadtime: "<your_own_value>"
          uploadtype: "traffic"
          uploaduser: "<your_own_value>"
          vrf_select: "0"
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


def filter_log_disk_setting_data(json):
    option_list = [
        "diskfull",
        "dlp_archive_quota",
        "full_final_warning_threshold",
        "full_first_warning_threshold",
        "full_second_warning_threshold",
        "interface",
        "interface_select_method",
        "ips_archive",
        "log_quota",
        "max_log_file_size",
        "max_policy_packet_capture_size",
        "maximum_log_age",
        "report_quota",
        "roll_day",
        "roll_schedule",
        "roll_time",
        "source_ip",
        "status",
        "upload",
        "upload_delete_files",
        "upload_destination",
        "upload_ssl_conn",
        "uploaddir",
        "uploadip",
        "uploadpass",
        "uploadport",
        "uploadsched",
        "uploadtime",
        "uploadtype",
        "uploaduser",
        "vrf_select",
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
        ["roll_day"],
        ["uploadtype"],
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


def log_disk_setting(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    log_disk_setting_data = data["log_disk_setting"]

    filtered_data = filter_log_disk_setting_data(log_disk_setting_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("log.disk", "setting", filtered_data, vdom=vdom)
        current_data = fos.get("log.disk", "setting", vdom=vdom, mkey=mkey)
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
    data_copy["log_disk_setting"] = filtered_data
    fos.do_member_operation(
        "log.disk",
        "setting",
        data_copy,
    )

    return fos.set("log.disk", "setting", data=converted_data, vdom=vdom)


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


def fortios_log_disk(data, fos, check_mode):

    if data["log_disk_setting"]:
        resp = log_disk_setting(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("log_disk_setting"))
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
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ips_archive": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "max_log_file_size": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "max_policy_packet_capture_size": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "roll_schedule": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "daily"}, {"value": "weekly"}],
        },
        "roll_day": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "sunday"},
                {"value": "monday"},
                {"value": "tuesday"},
                {"value": "wednesday"},
                {"value": "thursday"},
                {"value": "friday"},
                {"value": "saturday"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "roll_time": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "diskfull": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "overwrite"}, {"value": "nolog"}],
        },
        "log_quota": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dlp_archive_quota": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "report_quota": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "maximum_log_age": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "upload": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "upload_destination": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "ftp-server"}],
        },
        "uploadip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "uploadport": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "uploaduser": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "uploadpass": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "uploaddir": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "uploadtype": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "traffic"},
                {"value": "event"},
                {"value": "virus"},
                {"value": "webfilter"},
                {"value": "IPS"},
                {"value": "emailfilter", "v_range": [["v6.2.0", ""]]},
                {"value": "dlp-archive"},
                {"value": "anomaly"},
                {"value": "voip"},
                {"value": "dlp"},
                {"value": "app-ctrl"},
                {"value": "waf"},
                {"value": "gtp"},
                {"value": "dns"},
                {"value": "ssh", "v_range": [["v6.2.0", ""]]},
                {"value": "ssl", "v_range": [["v6.2.0", ""]]},
                {"value": "file-filter", "v_range": [["v6.2.0", ""]]},
                {"value": "icap", "v_range": [["v6.4.0", ""]]},
                {"value": "virtual-patch", "v_range": [["v7.4.1", ""]]},
                {"value": "debug", "v_range": [["v7.6.3", ""]]},
                {"value": "ztna", "v_range": [["v7.0.1", "v7.0.3"]]},
                {"value": "cifs", "v_range": [["v6.2.0", "v6.4.4"]]},
                {"value": "spamfilter", "v_range": [["v6.0.0", "v6.0.11"]]},
                {"value": "netscan", "v_range": [["v6.0.0", "v6.0.11"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "uploadsched": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "uploadtime": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "upload_delete_files": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "upload_ssl_conn": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "default"},
                {"value": "high"},
                {"value": "low"},
                {"value": "disable"},
            ],
        },
        "full_first_warning_threshold": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "full_second_warning_threshold": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "full_final_warning_threshold": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "interface_select_method": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "vrf_select": {"v_range": [["v7.6.1", ""]], "type": "integer"},
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
        "log_disk_setting": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["log_disk_setting"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["log_disk_setting"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "log_disk_setting"
        )

        is_error, has_changed, result, diff = fortios_log_disk(
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
