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
module: fortios_log_fortianalyzer3_override_setting
short_description: Override FortiAnalyzer settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify log_fortianalyzer3 feature and override_setting category.
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

    log_fortianalyzer3_override_setting:
        description:
            - Override FortiAnalyzer settings.
        default: null
        type: dict
        suboptions:
            __change_ip:
                description:
                    - Hidden attribute.
                type: int
            access_config:
                description:
                    - Enable/disable FortiAnalyzer access to configuration and data.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            alt_server:
                description:
                    - Alternate FortiAnalyzer.
                type: str
            certificate:
                description:
                    - Certificate used to communicate with FortiAnalyzer. Source certificate.local.name.
                type: str
            certificate_verification:
                description:
                    - Enable/disable identity verification of FortiAnalyzer by use of certificate.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            conn_timeout:
                description:
                    - FortiAnalyzer connection time-out in seconds (for status and log buffer).
                type: int
            enc_algorithm:
                description:
                    - Configure the level of SSL protection for secure communication with FortiAnalyzer.
                type: str
                choices:
                    - 'high-medium'
                    - 'high'
                    - 'low'
            fallback_to_primary:
                description:
                    - Enable/disable this FortiGate unit to fallback to the primary FortiAnalyzer when it is available.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            faz_type:
                description:
                    - Hidden setting index of FortiAnalyzer.
                type: int
            hmac_algorithm:
                description:
                    - OFTP login hash algorithm.
                type: str
                choices:
                    - 'sha256'
                    - 'sha1'
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
                    - Enable/disable IPS packet archive logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            max_log_rate:
                description:
                    - FortiAnalyzer maximum log rate in MBps (0 = unlimited).
                type: int
            mgmt_name:
                description:
                    - Hidden management name of FortiAnalyzer.
                type: str
            monitor_failure_retry_period:
                description:
                    - Time between FortiAnalyzer connection retries in seconds (for status and log buffer).
                type: int
            monitor_keepalive_period:
                description:
                    - Time between OFTP keepalives in seconds (for status and log buffer).
                type: int
            override:
                description:
                    - Enable/disable overriding FortiAnalyzer settings or use global settings.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            preshared_key:
                description:
                    - Preshared-key used for auto-authorization on FortiAnalyzer.
                type: str
            priority:
                description:
                    - Set log transmission priority.
                type: str
                choices:
                    - 'default'
                    - 'low'
            reliable:
                description:
                    - Enable/disable reliable logging to FortiAnalyzer.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            serial:
                description:
                    - Serial numbers of the FortiAnalyzer.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Serial Number.
                        required: true
                        type: str
            server:
                description:
                    - The remote FortiAnalyzer.
                type: str
            server_cert_ca:
                description:
                    - Mandatory CA on FortiGate in certificate chain of server. Source certificate.ca.name vpn.certificate.ca.name.
                type: str
            source_ip:
                description:
                    - Source IPv4 or IPv6 address used to communicate with FortiAnalyzer.
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
                    - Enable/disable logging to FortiAnalyzer.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            upload_day:
                description:
                    - Day of week (month) to upload logs.
                type: str
            upload_interval:
                description:
                    - Frequency to upload log files to FortiAnalyzer.
                type: str
                choices:
                    - 'daily'
                    - 'weekly'
                    - 'monthly'
            upload_option:
                description:
                    - Enable/disable logging to hard disk and then uploading to FortiAnalyzer.
                type: str
                choices:
                    - 'store-and-upload'
                    - 'realtime'
                    - '1-minute'
                    - '5-minute'
            upload_time:
                description:
                    - 'Time to upload logs (hh:mm).'
                type: str
            use_management_vdom:
                description:
                    - Enable/disable use of management VDOM IP address as source IP for logs sent to FortiAnalyzer.
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
- name: Override FortiAnalyzer settings.
  fortinet.fortios.fortios_log_fortianalyzer3_override_setting:
      vdom: "{{ vdom }}"
      log_fortianalyzer3_override_setting:
          __change_ip: "127"
          access_config: "enable"
          alt_server: "<your_own_value>"
          certificate: "<your_own_value> (source certificate.local.name)"
          certificate_verification: "enable"
          conn_timeout: "10"
          enc_algorithm: "high-medium"
          fallback_to_primary: "enable"
          faz_type: "2147483647"
          hmac_algorithm: "sha256"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          ips_archive: "enable"
          max_log_rate: "0"
          mgmt_name: "<your_own_value>"
          monitor_failure_retry_period: "5"
          monitor_keepalive_period: "5"
          override: "enable"
          preshared_key: "<your_own_value>"
          priority: "default"
          reliable: "enable"
          serial:
              -
                  name: "default_name_25"
          server: "192.168.100.40"
          server_cert_ca: "<your_own_value> (source certificate.ca.name vpn.certificate.ca.name)"
          source_ip: "84.230.14.43"
          ssl_min_proto_version: "default"
          status: "enable"
          upload_day: "<your_own_value>"
          upload_interval: "daily"
          upload_option: "store-and-upload"
          upload_time: "<your_own_value>"
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


def filter_log_fortianalyzer3_override_setting_data(json):
    option_list = [
        "__change_ip",
        "access_config",
        "alt_server",
        "certificate",
        "certificate_verification",
        "conn_timeout",
        "enc_algorithm",
        "fallback_to_primary",
        "faz_type",
        "hmac_algorithm",
        "interface",
        "interface_select_method",
        "ips_archive",
        "max_log_rate",
        "mgmt_name",
        "monitor_failure_retry_period",
        "monitor_keepalive_period",
        "override",
        "preshared_key",
        "priority",
        "reliable",
        "serial",
        "server",
        "server_cert_ca",
        "source_ip",
        "ssl_min_proto_version",
        "status",
        "upload_day",
        "upload_interval",
        "upload_option",
        "upload_time",
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


def log_fortianalyzer3_override_setting(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    log_fortianalyzer3_override_setting_data = data[
        "log_fortianalyzer3_override_setting"
    ]

    filtered_data = filter_log_fortianalyzer3_override_setting_data(
        log_fortianalyzer3_override_setting_data
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
            "log.fortianalyzer3", "override-setting", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "log.fortianalyzer3", "override-setting", vdom=vdom, mkey=mkey
        )
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
    data_copy["log_fortianalyzer3_override_setting"] = filtered_data
    fos.do_member_operation(
        "log.fortianalyzer3",
        "override-setting",
        data_copy,
    )

    return fos.set(
        "log.fortianalyzer3", "override-setting", data=converted_data, vdom=vdom
    )


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


def fortios_log_fortianalyzer3(data, fos, check_mode):

    if data["log_fortianalyzer3_override_setting"]:
        resp = log_fortianalyzer3_override_setting(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("log_fortianalyzer3_override_setting")
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
        "use_management_vdom": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "status": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ips_archive": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "server": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "alt_server": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "fallback_to_primary": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "certificate_verification": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "serial": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", ""]],
        },
        "server_cert_ca": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "preshared_key": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "access_config": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "hmac_algorithm": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "sha256"},
                {"value": "sha1", "v_range": [["v6.2.0", "v7.4.0"]]},
            ],
        },
        "enc_algorithm": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "high-medium"}, {"value": "high"}, {"value": "low"}],
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
                {"value": "TLSv1-3", "v_range": [["v7.2.0", ""]]},
            ],
        },
        "conn_timeout": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "monitor_keepalive_period": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "monitor_failure_retry_period": {
            "v_range": [["v6.2.0", ""]],
            "type": "integer",
        },
        "certificate": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "source_ip": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "upload_option": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "store-and-upload"},
                {"value": "realtime"},
                {"value": "1-minute"},
                {"value": "5-minute"},
            ],
        },
        "upload_interval": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "daily"}, {"value": "weekly"}, {"value": "monthly"}],
        },
        "upload_day": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "upload_time": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "reliable": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "priority": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "default"}, {"value": "low"}],
        },
        "max_log_rate": {"v_range": [["v6.2.0", ""]], "type": "integer"},
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
        "faz_type": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "integer"},
        "override": {
            "v_range": [["v6.2.3", "v6.2.3"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mgmt_name": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "__change_ip": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "integer"},
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
        "log_fortianalyzer3_override_setting": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["log_fortianalyzer3_override_setting"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["log_fortianalyzer3_override_setting"]["options"][attribute_name][
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
            fos, versioned_schema, "log_fortianalyzer3_override_setting"
        )

        is_error, has_changed, result, diff = fortios_log_fortianalyzer3(
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
