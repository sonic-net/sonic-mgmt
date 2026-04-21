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
module: fortios_alertemail_setting
short_description: Configure alert email settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify alertemail feature and setting category.
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

    alertemail_setting:
        description:
            - Configure alert email settings.
        default: null
        type: dict
        suboptions:
            admin_login_logs:
                description:
                    - Enable/disable administrator login/logout logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            alert_interval:
                description:
                    - Alert alert interval in minutes.
                type: int
            amc_interface_bypass_mode:
                description:
                    - Enable/disable Fortinet Advanced Mezzanine Card (AMC) interface bypass mode logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            antivirus_logs:
                description:
                    - Enable/disable antivirus logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            configuration_changes_logs:
                description:
                    - Enable/disable configuration change logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            critical_interval:
                description:
                    - Critical alert interval in minutes.
                type: int
            debug_interval:
                description:
                    - Debug alert interval in minutes.
                type: int
            email_interval:
                description:
                    - Interval between sending alert emails (1 - 99999 min).
                type: int
            emergency_interval:
                description:
                    - Emergency alert interval in minutes.
                type: int
            error_interval:
                description:
                    - Error alert interval in minutes.
                type: int
            FDS_license_expiring_days:
                description:
                    - Number of days to send alert email prior to FortiGuard license expiration (1 - 100 days).
                type: int
            FDS_license_expiring_warning:
                description:
                    - Enable/disable FortiGuard license expiration warnings in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            FDS_update_logs:
                description:
                    - Enable/disable FortiGuard update logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            filter_mode:
                description:
                    - How to filter log messages that are sent to alert emails.
                type: str
                choices:
                    - 'category'
                    - 'threshold'
            FIPS_CC_errors:
                description:
                    - Enable/disable FIPS and Common Criteria error logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            firewall_authentication_failure_logs:
                description:
                    - Enable/disable firewall authentication failure logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortiguard_log_quota_warning:
                description:
                    - Enable/disable FortiCloud log quota warnings in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            FSSO_disconnect_logs:
                description:
                    - Enable/disable logging of FSSO collector agent disconnect.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            HA_logs:
                description:
                    - Enable/disable HA logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            information_interval:
                description:
                    - Information alert interval in minutes.
                type: int
            IPS_logs:
                description:
                    - Enable/disable IPS logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            IPsec_errors_logs:
                description:
                    - Enable/disable IPsec error logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            local_disk_usage:
                description:
                    - Disk usage percentage at which to send alert email (1 - 99 percent).
                type: int
            log_disk_usage_warning:
                description:
                    - Enable/disable disk usage warnings in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mailto1:
                description:
                    - Email address to send alert email to (usually a system administrator) (max. 63 characters).
                type: str
            mailto2:
                description:
                    - Optional second email address to send alert email to (max. 63 characters).
                type: str
            mailto3:
                description:
                    - Optional third email address to send alert email to (max. 63 characters).
                type: str
            notification_interval:
                description:
                    - Notification alert interval in minutes.
                type: int
            PPP_errors_logs:
                description:
                    - Enable/disable PPP error logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
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
            ssh_logs:
                description:
                    - Enable/disable SSH logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sslvpn_authentication_errors_logs:
                description:
                    - Enable/disable Agentless VPN authentication error logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            username:
                description:
                    - 'Name that appears in the From: field of alert emails (max. 63 characters).'
                type: str
            violation_traffic_logs:
                description:
                    - Enable/disable violation traffic logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            warning_interval:
                description:
                    - Warning alert interval in minutes.
                type: int
            webfilter_logs:
                description:
                    - Enable/disable web filter logs in alert email.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure alert email settings.
  fortinet.fortios.fortios_alertemail_setting:
      vdom: "{{ vdom }}"
      alertemail_setting:
          admin_login_logs: "enable"
          alert_interval: "2"
          amc_interface_bypass_mode: "enable"
          antivirus_logs: "enable"
          configuration_changes_logs: "enable"
          critical_interval: "3"
          debug_interval: "60"
          email_interval: "5"
          emergency_interval: "1"
          error_interval: "5"
          FDS_license_expiring_days: "15"
          FDS_license_expiring_warning: "enable"
          FDS_update_logs: "enable"
          filter_mode: "category"
          FIPS_CC_errors: "enable"
          firewall_authentication_failure_logs: "enable"
          fortiguard_log_quota_warning: "enable"
          FSSO_disconnect_logs: "enable"
          HA_logs: "enable"
          information_interval: "30"
          IPS_logs: "enable"
          IPsec_errors_logs: "enable"
          local_disk_usage: "75"
          log_disk_usage_warning: "enable"
          mailto1: "<your_own_value>"
          mailto2: "<your_own_value>"
          mailto3: "<your_own_value>"
          notification_interval: "20"
          PPP_errors_logs: "enable"
          severity: "emergency"
          ssh_logs: "enable"
          sslvpn_authentication_errors_logs: "enable"
          username: "<your_own_value>"
          violation_traffic_logs: "enable"
          warning_interval: "10"
          webfilter_logs: "enable"
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


def filter_alertemail_setting_data(json):
    option_list = [
        "admin_login_logs",
        "alert_interval",
        "amc_interface_bypass_mode",
        "antivirus_logs",
        "configuration_changes_logs",
        "critical_interval",
        "debug_interval",
        "email_interval",
        "emergency_interval",
        "error_interval",
        "FDS_license_expiring_days",
        "FDS_license_expiring_warning",
        "FDS_update_logs",
        "filter_mode",
        "FIPS_CC_errors",
        "firewall_authentication_failure_logs",
        "fortiguard_log_quota_warning",
        "FSSO_disconnect_logs",
        "HA_logs",
        "information_interval",
        "IPS_logs",
        "IPsec_errors_logs",
        "local_disk_usage",
        "log_disk_usage_warning",
        "mailto1",
        "mailto2",
        "mailto3",
        "notification_interval",
        "PPP_errors_logs",
        "severity",
        "ssh_logs",
        "sslvpn_authentication_errors_logs",
        "username",
        "violation_traffic_logs",
        "warning_interval",
        "webfilter_logs",
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


def alertemail_setting(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    alertemail_setting_data = data["alertemail_setting"]

    filtered_data = filter_alertemail_setting_data(alertemail_setting_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("alertemail", "setting", filtered_data, vdom=vdom)
        current_data = fos.get("alertemail", "setting", vdom=vdom, mkey=mkey)
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
    data_copy["alertemail_setting"] = filtered_data
    fos.do_member_operation(
        "alertemail",
        "setting",
        data_copy,
    )

    return fos.set("alertemail", "setting", data=converted_data, vdom=vdom)


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


def fortios_alertemail(data, fos, check_mode):

    if data["alertemail_setting"]:
        resp = alertemail_setting(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("alertemail_setting"))
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
        "username": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "mailto1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "mailto2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "mailto3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "filter_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "category"}, {"value": "threshold"}],
        },
        "email_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "IPS_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "firewall_authentication_failure_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "HA_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "IPsec_errors_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "FDS_update_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "PPP_errors_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sslvpn_authentication_errors_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "antivirus_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "webfilter_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "configuration_changes_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "violation_traffic_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "admin_login_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "FDS_license_expiring_warning": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log_disk_usage_warning": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fortiguard_log_quota_warning": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "amc_interface_bypass_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "FIPS_CC_errors": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "FSSO_disconnect_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssh_logs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "local_disk_usage": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "emergency_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "alert_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "critical_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "error_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "warning_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "notification_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "information_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "debug_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
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
        "FDS_license_expiring_days": {
            "v_range": [["v6.0.0", "v7.2.4"]],
            "type": "integer",
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
        "alertemail_setting": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["alertemail_setting"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["alertemail_setting"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "alertemail_setting"
        )

        is_error, has_changed, result, diff = fortios_alertemail(
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
