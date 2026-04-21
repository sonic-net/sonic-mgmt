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
module: fortios_log_syslogd3_override_setting
short_description: Override settings for remote syslog server in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify log_syslogd3 feature and override_setting category.
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

    log_syslogd3_override_setting:
        description:
            - Override settings for remote syslog server.
        default: null
        type: dict
        suboptions:
            certificate:
                description:
                    - Certificate used to communicate with Syslog server. Source certificate.local.name.
                type: str
            custom_field_name:
                description:
                    - Custom field name for CEF format logging.
                type: list
                elements: dict
                suboptions:
                    custom:
                        description:
                            - Field custom name [A-Za-z0-9_].
                        type: str
                    id:
                        description:
                            - Entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    name:
                        description:
                            - Field name [A-Za-z0-9_].
                        type: str
            enc_algorithm:
                description:
                    - Enable/disable reliable syslogging with TLS encryption.
                type: str
                choices:
                    - 'high-medium'
                    - 'high'
                    - 'low'
                    - 'disable'
            facility:
                description:
                    - Remote syslog facility.
                type: str
                choices:
                    - 'kernel'
                    - 'user'
                    - 'mail'
                    - 'daemon'
                    - 'auth'
                    - 'syslog'
                    - 'lpr'
                    - 'news'
                    - 'uucp'
                    - 'cron'
                    - 'authpriv'
                    - 'ftp'
                    - 'ntp'
                    - 'audit'
                    - 'alert'
                    - 'clock'
                    - 'local0'
                    - 'local1'
                    - 'local2'
                    - 'local3'
                    - 'local4'
                    - 'local5'
                    - 'local6'
                    - 'local7'
            format:
                description:
                    - Log format.
                type: str
                choices:
                    - 'default'
                    - 'csv'
                    - 'cef'
                    - 'rfc5424'
                    - 'json'
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
            max_log_rate:
                description:
                    - Syslog maximum log rate in MBps (0 = unlimited).
                type: int
            mode:
                description:
                    - Remote syslog logging over UDP/Reliable TCP.
                type: str
                choices:
                    - 'udp'
                    - 'legacy-reliable'
                    - 'reliable'
            override:
                description:
                    - Enable/disable override syslog settings.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            port:
                description:
                    - Server listen port.
                type: int
            priority:
                description:
                    - Set log transmission priority.
                type: str
                choices:
                    - 'default'
                    - 'low'
            server:
                description:
                    - Address of remote syslog server.
                type: str
            source_ip:
                description:
                    - Source IP address of syslog.
                type: str
            source_ip_interface:
                description:
                    - Source interface of syslog. Source system.interface.name.
                type: str
            ssl_min_proto_version:
                description:
                    - Minimum supported protocol version for SSL/TLS connections .
                type: str
                choices:
                    - 'default'
                    - 'SSLv3'
                    - 'TLSv1'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'TLSv1-3'
            status:
                description:
                    - Enable/disable remote syslog logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            syslog_type:
                description:
                    - Hidden setting index of Syslog.
                type: int
            use_management_vdom:
                description:
                    - Enable/disable use of management VDOM as source VDOM for logs sent to syslog server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
"""

EXAMPLES = """
- name: Override settings for remote syslog server.
  fortinet.fortios.fortios_log_syslogd3_override_setting:
      vdom: "{{ vdom }}"
      log_syslogd3_override_setting:
          certificate: "<your_own_value> (source certificate.local.name)"
          custom_field_name:
              -
                  custom: "<your_own_value>"
                  id: "6"
                  name: "default_name_7"
          enc_algorithm: "high-medium"
          facility: "kernel"
          format: "default"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          max_log_rate: "0"
          mode: "udp"
          override: "enable"
          port: "514"
          priority: "default"
          server: "192.168.100.40"
          source_ip: "84.230.14.43"
          source_ip_interface: "<your_own_value> (source system.interface.name)"
          ssl_min_proto_version: "default"
          status: "enable"
          syslog_type: "2147483647"
          use_management_vdom: "enable"
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


def filter_log_syslogd3_override_setting_data(json):
    option_list = [
        "certificate",
        "custom_field_name",
        "enc_algorithm",
        "facility",
        "format",
        "interface",
        "interface_select_method",
        "max_log_rate",
        "mode",
        "override",
        "port",
        "priority",
        "server",
        "source_ip",
        "source_ip_interface",
        "ssl_min_proto_version",
        "status",
        "syslog_type",
        "use_management_vdom",
        "vrf_select",
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


def log_syslogd3_override_setting(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    log_syslogd3_override_setting_data = data["log_syslogd3_override_setting"]

    filtered_data = filter_log_syslogd3_override_setting_data(
        log_syslogd3_override_setting_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey(
            "log.syslogd3", "override-setting", filtered_data, vdom=vdom
        )
        current_data = fos.get("log.syslogd3", "override-setting", vdom=vdom, mkey=mkey)
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
    data_copy["log_syslogd3_override_setting"] = filtered_data
    fos.do_member_operation(
        "log.syslogd3",
        "override-setting",
        data_copy,
    )

    return fos.set("log.syslogd3", "override-setting", data=converted_data, vdom=vdom)


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


def fortios_log_syslogd3(data, fos, check_mode):

    if data["log_syslogd3_override_setting"]:
        resp = log_syslogd3_override_setting(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("log_syslogd3_override_setting")
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
    "v_range": [["v6.2.0", ""]],
    "type": "dict",
    "children": {
        "status": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "server": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "mode": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "udp"},
                {"value": "legacy-reliable"},
                {"value": "reliable"},
            ],
        },
        "use_management_vdom": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "port": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "facility": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "kernel"},
                {"value": "user"},
                {"value": "mail"},
                {"value": "daemon"},
                {"value": "auth"},
                {"value": "syslog"},
                {"value": "lpr"},
                {"value": "news"},
                {"value": "uucp"},
                {"value": "cron"},
                {"value": "authpriv"},
                {"value": "ftp"},
                {"value": "ntp"},
                {"value": "audit"},
                {"value": "alert"},
                {"value": "clock"},
                {"value": "local0"},
                {"value": "local1"},
                {"value": "local2"},
                {"value": "local3"},
                {"value": "local4"},
                {"value": "local5"},
                {"value": "local6"},
                {"value": "local7"},
            ],
        },
        "source_ip_interface": {"v_range": [["v7.6.0", ""]], "type": "string"},
        "source_ip": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "format": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "default"},
                {"value": "csv"},
                {"value": "cef"},
                {"value": "rfc5424", "v_range": [["v7.0.0", ""]]},
                {"value": "json", "v_range": [["v7.4.1", ""]]},
            ],
        },
        "priority": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "default"}, {"value": "low"}],
        },
        "max_log_rate": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "enc_algorithm": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "high-medium"},
                {"value": "high"},
                {"value": "low"},
                {"value": "disable"},
            ],
        },
        "ssl_min_proto_version": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "default"},
                {"value": "SSLv3"},
                {"value": "TLSv1"},
                {"value": "TLSv1-1"},
                {"value": "TLSv1-2"},
                {"value": "TLSv1-3", "v_range": [["v7.4.1", ""]]},
            ],
        },
        "certificate": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "custom_field_name": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "name": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "custom": {"v_range": [["v6.2.0", ""]], "type": "string"},
            },
            "v_range": [["v6.2.0", ""]],
        },
        "interface_select_method": {
            "v_range": [["v6.2.7", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {
            "v_range": [["v6.2.7", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "vrf_select": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "override": {
            "v_range": [["v6.2.3", "v6.2.3"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "syslog_type": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "integer"},
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
        "log_syslogd3_override_setting": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["log_syslogd3_override_setting"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["log_syslogd3_override_setting"]["options"][attribute_name][
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
            fos, versioned_schema, "log_syslogd3_override_setting"
        )

        is_error, has_changed, result, diff = fortios_log_syslogd3(
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
