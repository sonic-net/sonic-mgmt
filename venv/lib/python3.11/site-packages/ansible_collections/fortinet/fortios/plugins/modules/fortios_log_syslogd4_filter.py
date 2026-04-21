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
module: fortios_log_syslogd4_filter
short_description: Filters for remote system server in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify log_syslogd4 feature and filter category.
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

    log_syslogd4_filter:
        description:
            - Filters for remote system server.
        default: null
        type: dict
        suboptions:
            anomaly:
                description:
                    - Enable/disable anomaly logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            debug:
                description:
                    - Enable/disable debug logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dns:
                description:
                    - Enable/disable detailed DNS event logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            filter:
                description:
                    - Syslog 4 filter.
                type: str
            filter_type:
                description:
                    - Include/exclude logs that match the filter.
                type: str
                choices:
                    - 'include'
                    - 'exclude'
            forti_switch:
                description:
                    - Enable/disable Forti-Switch logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forward_traffic:
                description:
                    - Enable/disable forward traffic logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            free_style:
                description:
                    - Free style filters.
                type: list
                elements: dict
                suboptions:
                    category:
                        description:
                            - Log category.
                        type: str
                        choices:
                            - 'traffic'
                            - 'event'
                            - 'virus'
                            - 'webfilter'
                            - 'attack'
                            - 'spam'
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
                    filter:
                        description:
                            - Free style filter string.
                        type: str
                    filter_type:
                        description:
                            - Include/exclude logs that match the filter.
                        type: str
                        choices:
                            - 'include'
                            - 'exclude'
                    id:
                        description:
                            - Entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            gtp:
                description:
                    - Enable/disable GTP messages logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            http_transaction:
                description:
                    - Enable/disable log HTTP transaction messages.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_traffic:
                description:
                    - Enable/disable local in or out traffic logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            multicast_traffic:
                description:
                    - Enable/disable multicast traffic logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            netscan_discovery:
                description:
                    - Enable/disable netscan discovery event logging.
                type: str
            netscan_vulnerability:
                description:
                    - Enable/disable netscan vulnerability event logging.
                type: str
            severity:
                description:
                    - Lowest severity level to log.
                type: str
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            sniffer_traffic:
                description:
                    - Enable/disable sniffer traffic logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssh:
                description:
                    - Enable/disable SSH logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            voip:
                description:
                    - Enable/disable VoIP logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ztna_traffic:
                description:
                    - Enable/disable ztna traffic logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Filters for remote system server.
  fortinet.fortios.fortios_log_syslogd4_filter:
      vdom: "{{ vdom }}"
      log_syslogd4_filter:
          anomaly: "enable"
          debug: "enable"
          dns: "enable"
          filter: "<your_own_value>"
          filter_type: "include"
          forti_switch: "enable"
          forward_traffic: "enable"
          free_style:
              -
                  category: "traffic"
                  filter: "<your_own_value>"
                  filter_type: "include"
                  id: "14"
          gtp: "enable"
          http_transaction: "enable"
          local_traffic: "enable"
          multicast_traffic: "enable"
          netscan_discovery: "<your_own_value>"
          netscan_vulnerability: "<your_own_value>"
          severity: "emergency"
          sniffer_traffic: "enable"
          ssh: "enable"
          voip: "enable"
          ztna_traffic: "enable"
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


def filter_log_syslogd4_filter_data(json):
    option_list = [
        "anomaly",
        "debug",
        "dns",
        "filter",
        "filter_type",
        "forti_switch",
        "forward_traffic",
        "free_style",
        "gtp",
        "http_transaction",
        "local_traffic",
        "multicast_traffic",
        "netscan_discovery",
        "netscan_vulnerability",
        "severity",
        "sniffer_traffic",
        "ssh",
        "voip",
        "ztna_traffic",
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


def log_syslogd4_filter(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    log_syslogd4_filter_data = data["log_syslogd4_filter"]

    filtered_data = filter_log_syslogd4_filter_data(log_syslogd4_filter_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("log.syslogd4", "filter", filtered_data, vdom=vdom)
        current_data = fos.get("log.syslogd4", "filter", vdom=vdom, mkey=mkey)
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
    data_copy["log_syslogd4_filter"] = filtered_data
    fos.do_member_operation(
        "log.syslogd4",
        "filter",
        data_copy,
    )

    return fos.set("log.syslogd4", "filter", data=converted_data, vdom=vdom)


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


def fortios_log_syslogd4(data, fos, check_mode):

    if data["log_syslogd4_filter"]:
        resp = log_syslogd4_filter(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("log_syslogd4_filter"))
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
        "severity": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "emergency"},
                {"value": "alert"},
                {"value": "critical"},
                {"value": "error"},
                {"value": "warning"},
                {"value": "notification"},
                {"value": "information"},
                {"value": "debug"},
            ],
        },
        "forward_traffic": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "local_traffic": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "multicast_traffic": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sniffer_traffic": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ztna_traffic": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "http_transaction": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "anomaly": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "voip": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gtp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forti_switch": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "debug": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "free_style": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "category": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "traffic"},
                        {"value": "event"},
                        {"value": "virus"},
                        {"value": "webfilter"},
                        {"value": "attack"},
                        {"value": "spam"},
                        {"value": "anomaly"},
                        {"value": "voip"},
                        {"value": "dlp"},
                        {"value": "app-ctrl"},
                        {"value": "waf"},
                        {"value": "gtp"},
                        {"value": "dns"},
                        {"value": "ssh"},
                        {"value": "ssl"},
                        {"value": "file-filter"},
                        {"value": "icap"},
                        {"value": "virtual-patch", "v_range": [["v7.4.1", ""]]},
                        {"value": "debug", "v_range": [["v7.6.3", ""]]},
                        {"value": "ztna", "v_range": [["v7.0.1", "v7.0.3"]]},
                    ],
                },
                "filter": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "filter_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "include"}, {"value": "exclude"}],
                },
            },
            "v_range": [["v7.0.0", ""]],
        },
        "filter": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
        "filter_type": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "include"}, {"value": "exclude"}],
        },
        "netscan_discovery": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
        "netscan_vulnerability": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
        "dns": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssh": {
            "v_range": [["v6.0.0", "v6.0.11"]],
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
        "log_syslogd4_filter": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["log_syslogd4_filter"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["log_syslogd4_filter"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "log_syslogd4_filter"
        )

        is_error, has_changed, result, diff = fortios_log_syslogd4(
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
