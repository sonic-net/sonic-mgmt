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
module: fortios_endpoint_control_settings
short_description: Configure endpoint control settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify endpoint_control feature and settings category.
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

    endpoint_control_settings:
        description:
            - Configure endpoint control settings.
        default: null
        type: dict
        suboptions:
            download_custom_link:
                description:
                    - Customized URL for downloading FortiClient.
                type: str
            download_location:
                description:
                    - FortiClient download location (FortiGuard or custom).
                type: str
                choices:
                    - 'fortiguard'
                    - 'custom'
            forticlient_avdb_update_interval:
                description:
                    - Period of time between FortiClient AntiVirus database updates (0 - 24 hours).
                type: int
            forticlient_dereg_unsupported_client:
                description:
                    - Enable/disable deregistering unsupported FortiClient endpoints.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forticlient_disconnect_unsupported_client:
                description:
                    - Enable/disable disconnecting of unsupported FortiClient endpoints.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forticlient_ems_rest_api_call_timeout:
                description:
                    - FortiClient EMS call timeout in milliseconds (500 - 30000 milliseconds).
                type: int
            forticlient_keepalive_interval:
                description:
                    - Interval between two KeepAlive messages from FortiClient (20 - 300 sec).
                type: int
            forticlient_offline_grace:
                description:
                    - Enable/disable grace period for offline registered clients.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forticlient_offline_grace_interval:
                description:
                    - Grace period for offline registered FortiClient (60 - 600 sec).
                type: int
            forticlient_reg_key:
                description:
                    - FortiClient registration key.
                type: str
            forticlient_reg_key_enforce:
                description:
                    - Enable/disable requiring or enforcing FortiClient registration keys.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forticlient_reg_timeout:
                description:
                    - FortiClient registration license timeout (days, min = 1, max = 180, 0 means unlimited).
                type: int
            forticlient_sys_update_interval:
                description:
                    - Interval between two system update messages from FortiClient (30 - 1440 min).
                type: int
            forticlient_user_avatar:
                description:
                    - Enable/disable uploading FortiClient user avatars.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forticlient_warning_interval:
                description:
                    - Period of time between FortiClient portal warnings (0 - 24 hours).
                type: int
            override:
                description:
                    - Override global EMS table for this VDOM.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure endpoint control settings.
  fortinet.fortios.fortios_endpoint_control_settings:
      vdom: "{{ vdom }}"
      endpoint_control_settings:
          download_custom_link: "<your_own_value>"
          download_location: "fortiguard"
          forticlient_avdb_update_interval: "12"
          forticlient_dereg_unsupported_client: "enable"
          forticlient_disconnect_unsupported_client: "enable"
          forticlient_ems_rest_api_call_timeout: "15000"
          forticlient_keepalive_interval: "150"
          forticlient_offline_grace: "enable"
          forticlient_offline_grace_interval: "300"
          forticlient_reg_key: "<your_own_value>"
          forticlient_reg_key_enforce: "enable"
          forticlient_reg_timeout: "90"
          forticlient_sys_update_interval: "720"
          forticlient_user_avatar: "enable"
          forticlient_warning_interval: "12"
          override: "enable"
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


def filter_endpoint_control_settings_data(json):
    option_list = [
        "download_custom_link",
        "download_location",
        "forticlient_avdb_update_interval",
        "forticlient_dereg_unsupported_client",
        "forticlient_disconnect_unsupported_client",
        "forticlient_ems_rest_api_call_timeout",
        "forticlient_keepalive_interval",
        "forticlient_offline_grace",
        "forticlient_offline_grace_interval",
        "forticlient_reg_key",
        "forticlient_reg_key_enforce",
        "forticlient_reg_timeout",
        "forticlient_sys_update_interval",
        "forticlient_user_avatar",
        "forticlient_warning_interval",
        "override",
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


def endpoint_control_settings(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    endpoint_control_settings_data = data["endpoint_control_settings"]

    filtered_data = filter_endpoint_control_settings_data(
        endpoint_control_settings_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("endpoint-control", "settings", filtered_data, vdom=vdom)
        current_data = fos.get("endpoint-control", "settings", vdom=vdom, mkey=mkey)
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
    data_copy["endpoint_control_settings"] = filtered_data
    fos.do_member_operation(
        "endpoint-control",
        "settings",
        data_copy,
    )

    return fos.set("endpoint-control", "settings", data=converted_data, vdom=vdom)


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


def fortios_endpoint_control(data, fos, check_mode):

    if data["endpoint_control_settings"]:
        resp = endpoint_control_settings(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("endpoint_control_settings")
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
    "v_range": [["v6.0.0", "v6.2.7"], ["v7.4.0", ""]],
    "type": "dict",
    "children": {
        "override": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forticlient_keepalive_interval": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "integer",
        },
        "forticlient_sys_update_interval": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "integer",
        },
        "forticlient_user_avatar": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forticlient_disconnect_unsupported_client": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forticlient_reg_key_enforce": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forticlient_reg_key": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
        "forticlient_reg_timeout": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "integer",
        },
        "download_custom_link": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
        "download_location": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "fortiguard"}, {"value": "custom"}],
        },
        "forticlient_offline_grace": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forticlient_offline_grace_interval": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "integer",
        },
        "forticlient_avdb_update_interval": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "integer",
        },
        "forticlient_warning_interval": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "integer",
        },
        "forticlient_dereg_unsupported_client": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forticlient_ems_rest_api_call_timeout": {
            "v_range": [["v6.0.0", "v6.0.11"]],
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
        "endpoint_control_settings": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["endpoint_control_settings"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["endpoint_control_settings"]["options"][attribute_name][
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
            fos, versioned_schema, "endpoint_control_settings"
        )

        is_error, has_changed, result, diff = fortios_endpoint_control(
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
