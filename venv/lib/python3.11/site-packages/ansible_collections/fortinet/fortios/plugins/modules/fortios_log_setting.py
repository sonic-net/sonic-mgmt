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
module: fortios_log_setting
short_description: Configure general log settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify log feature and setting category.
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

    log_setting:
        description:
            - Configure general log settings.
        default: null
        type: dict
        suboptions:
            anonymization_hash:
                description:
                    - User name anonymization hash salt.
                type: str
            brief_traffic_format:
                description:
                    - Enable/disable brief format traffic logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            custom_log_fields:
                description:
                    - Custom fields to append to all log messages.
                type: list
                elements: dict
                suboptions:
                    field_id:
                        description:
                            - Custom log field. Source log.custom-field.id.
                        required: true
                        type: str
            daemon_log:
                description:
                    - Enable/disable daemon logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            expolicy_implicit_log:
                description:
                    - Enable/disable proxy firewall implicit policy logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            extended_log:
                description:
                    - Enable/disable extended traffic logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            extended_utm_log:
                description:
                    - Enable/disable extended UTM logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            faz_override:
                description:
                    - Enable/disable override FortiAnalyzer settings.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortiview_weekly_data:
                description:
                    - Enable/disable FortiView weekly data.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fwpolicy_implicit_log:
                description:
                    - Enable/disable implicit firewall policy logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fwpolicy6_implicit_log:
                description:
                    - Enable/disable implicit firewall policy6 logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_in_allow:
                description:
                    - Enable/disable local-in-allow logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_in_deny_broadcast:
                description:
                    - Enable/disable local-in-deny-broadcast logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_in_deny_unicast:
                description:
                    - Enable/disable local-in-deny-unicast logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_in_policy_log:
                description:
                    - Enable/disable local-in-policy logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_out:
                description:
                    - Enable/disable local-out logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_out_ioc_detection:
                description:
                    - Enable/disable local-out traffic IoC detection. Requires local-out to be enabled.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            log_invalid_packet:
                description:
                    - Enable/disable invalid packet traffic logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            log_policy_comment:
                description:
                    - Enable/disable inserting policy comments into traffic logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            log_policy_name:
                description:
                    - Enable/disable inserting policy name into traffic logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            log_user_in_upper:
                description:
                    - Enable/disable logs with user-in-upper.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            long_live_session_stat:
                description:
                    - Enable/disable long-live-session statistics logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            neighbor_event:
                description:
                    - Enable/disable neighbor event logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            resolve_ip:
                description:
                    - Enable/disable adding resolved domain names to traffic logs if possible.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            resolve_port:
                description:
                    - Enable/disable adding resolved service names to traffic logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rest_api_get:
                description:
                    - Enable/disable REST API GET request logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rest_api_set:
                description:
                    - Enable/disable REST API POST/PUT/DELETE request logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            syslog_override:
                description:
                    - Enable/disable override Syslog settings.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            user_anonymize:
                description:
                    - Enable/disable anonymizing user names in log messages.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            zone_name:
                description:
                    - Enable/disable zone name logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure general log settings.
  fortinet.fortios.fortios_log_setting:
      vdom: "{{ vdom }}"
      log_setting:
          anonymization_hash: "<your_own_value>"
          brief_traffic_format: "enable"
          custom_log_fields:
              -
                  field_id: "<your_own_value> (source log.custom-field.id)"
          daemon_log: "enable"
          expolicy_implicit_log: "enable"
          extended_log: "enable"
          extended_utm_log: "enable"
          faz_override: "enable"
          fortiview_weekly_data: "enable"
          fwpolicy_implicit_log: "enable"
          fwpolicy6_implicit_log: "enable"
          local_in_allow: "enable"
          local_in_deny_broadcast: "enable"
          local_in_deny_unicast: "enable"
          local_in_policy_log: "enable"
          local_out: "enable"
          local_out_ioc_detection: "enable"
          log_invalid_packet: "enable"
          log_policy_comment: "enable"
          log_policy_name: "enable"
          log_user_in_upper: "enable"
          long_live_session_stat: "enable"
          neighbor_event: "enable"
          resolve_ip: "enable"
          resolve_port: "enable"
          rest_api_get: "enable"
          rest_api_set: "enable"
          syslog_override: "enable"
          user_anonymize: "enable"
          zone_name: "enable"
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


def filter_log_setting_data(json):
    option_list = [
        "anonymization_hash",
        "brief_traffic_format",
        "custom_log_fields",
        "daemon_log",
        "expolicy_implicit_log",
        "extended_log",
        "extended_utm_log",
        "faz_override",
        "fortiview_weekly_data",
        "fwpolicy_implicit_log",
        "fwpolicy6_implicit_log",
        "local_in_allow",
        "local_in_deny_broadcast",
        "local_in_deny_unicast",
        "local_in_policy_log",
        "local_out",
        "local_out_ioc_detection",
        "log_invalid_packet",
        "log_policy_comment",
        "log_policy_name",
        "log_user_in_upper",
        "long_live_session_stat",
        "neighbor_event",
        "resolve_ip",
        "resolve_port",
        "rest_api_get",
        "rest_api_set",
        "syslog_override",
        "user_anonymize",
        "zone_name",
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


def log_setting(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    log_setting_data = data["log_setting"]

    filtered_data = filter_log_setting_data(log_setting_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("log", "setting", filtered_data, vdom=vdom)
        current_data = fos.get("log", "setting", vdom=vdom, mkey=mkey)
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
    data_copy["log_setting"] = filtered_data
    fos.do_member_operation(
        "log",
        "setting",
        data_copy,
    )

    return fos.set("log", "setting", data=converted_data, vdom=vdom)


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


def fortios_log(data, fos, check_mode):

    if data["log_setting"]:
        resp = log_setting(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("log_setting"))
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
        "resolve_ip": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "resolve_port": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log_user_in_upper": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fwpolicy_implicit_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fwpolicy6_implicit_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "extended_log": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "local_in_allow": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "local_in_deny_unicast": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "local_in_deny_broadcast": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "local_in_policy_log": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "local_out": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "local_out_ioc_detection": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "daemon_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "neighbor_event": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "brief_traffic_format": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "user_anonymize": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fortiview_weekly_data": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "expolicy_implicit_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log_policy_comment": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "faz_override": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "syslog_override": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rest_api_set": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rest_api_get": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "long_live_session_stat": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "extended_utm_log": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "zone_name": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "custom_log_fields": {
            "type": "list",
            "elements": "dict",
            "children": {
                "field_id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "anonymization_hash": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "log_invalid_packet": {
            "v_range": [["v6.0.0", "v7.2.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log_policy_name": {
            "v_range": [["v6.0.0", "v6.2.7"]],
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
        "log_setting": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["log_setting"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["log_setting"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "log_setting"
        )

        is_error, has_changed, result, diff = fortios_log(
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
