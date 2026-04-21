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
module: fortios_user_setting
short_description: Configure user authentication setting in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify user feature and setting category.
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

    user_setting:
        description:
            - Configure user authentication setting.
        default: null
        type: dict
        suboptions:
            auth_blackout_time:
                description:
                    - Time in seconds an IP address is denied access after failing to authenticate five times within one minute.
                type: int
            auth_ca_cert:
                description:
                    - HTTPS CA certificate for policy authentication. Source vpn.certificate.local.name.
                type: str
            auth_cert:
                description:
                    - HTTPS server certificate for policy authentication. Source vpn.certificate.local.name.
                type: str
            auth_http_basic:
                description:
                    - Enable/disable use of HTTP basic authentication for identity-based firewall policies.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_invalid_max:
                description:
                    - Maximum number of failed authentication attempts before the user is blocked.
                type: int
            auth_lockout_duration:
                description:
                    - Lockout period in seconds after too many login failures.
                type: int
            auth_lockout_threshold:
                description:
                    - Maximum number of failed login attempts before login lockout is triggered.
                type: int
            auth_on_demand:
                description:
                    - Always/implicitly trigger firewall authentication on demand.
                type: str
                choices:
                    - 'always'
                    - 'implicitly'
            auth_portal_timeout:
                description:
                    - Time in minutes before captive portal user have to re-authenticate (1 - 30 min).
                type: int
            auth_ports:
                description:
                    - Set up non-standard ports for authentication with HTTP, HTTPS, FTP, and TELNET.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    port:
                        description:
                            - Non-standard port for firewall user authentication.
                        type: int
                    type:
                        description:
                            - Service type.
                        type: str
                        choices:
                            - 'http'
                            - 'https'
                            - 'ftp'
                            - 'telnet'
            auth_secure_http:
                description:
                    - Enable/disable redirecting HTTP user authentication to more secure HTTPS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_src_mac:
                description:
                    - Enable/disable source MAC for user identity.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_ssl_allow_renegotiation:
                description:
                    - Allow/forbid SSL re-negotiation for HTTPS authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_ssl_max_proto_version:
                description:
                    - Maximum supported protocol version for SSL/TLS connections .
                type: str
                choices:
                    - 'sslv3'
                    - 'tlsv1'
                    - 'tlsv1-1'
                    - 'tlsv1-2'
                    - 'tlsv1-3'
            auth_ssl_min_proto_version:
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
            auth_ssl_sigalgs:
                description:
                    - Set signature algorithms related to HTTPS authentication (affects TLS version <= 1.2 only).
                type: str
                choices:
                    - 'no-rsa-pss'
                    - 'all'
            auth_timeout:
                description:
                    - Time in minutes before the firewall user authentication timeout requires the user to re-authenticate.
                type: int
            auth_timeout_type:
                description:
                    - Control if authenticated users have to login again after a hard timeout, after an idle timeout, or after a session timeout.
                type: str
                choices:
                    - 'idle-timeout'
                    - 'hard-timeout'
                    - 'new-session'
            auth_type:
                description:
                    - Supported firewall policy authentication protocols/methods.
                type: list
                elements: str
                choices:
                    - 'http'
                    - 'https'
                    - 'ftp'
                    - 'telnet'
            cors:
                description:
                    - Enable/disable allowed origins white list for CORS.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            cors_allowed_origins:
                description:
                    - Allowed origins white list for CORS.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Allowed origin for CORS.
                        required: true
                        type: str
            default_user_password_policy:
                description:
                    - Default password policy to apply to all local users unless otherwise specified, as defined in config user password-policy. Source user
                      .password-policy.name.
                type: str
            per_policy_disclaimer:
                description:
                    - Enable/disable per policy disclaimer.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            radius_ses_timeout_act:
                description:
                    - Set the RADIUS session timeout to a hard timeout or to ignore RADIUS server session timeouts.
                type: str
                choices:
                    - 'hard-timeout'
                    - 'ignore-timeout'
"""

EXAMPLES = """
- name: Configure user authentication setting.
  fortinet.fortios.fortios_user_setting:
      vdom: "{{ vdom }}"
      user_setting:
          auth_blackout_time: "0"
          auth_ca_cert: "<your_own_value> (source vpn.certificate.local.name)"
          auth_cert: "<your_own_value> (source vpn.certificate.local.name)"
          auth_http_basic: "enable"
          auth_invalid_max: "5"
          auth_lockout_duration: "0"
          auth_lockout_threshold: "3"
          auth_on_demand: "always"
          auth_portal_timeout: "3"
          auth_ports:
              -
                  id: "13"
                  port: "1024"
                  type: "http"
          auth_secure_http: "enable"
          auth_src_mac: "enable"
          auth_ssl_allow_renegotiation: "enable"
          auth_ssl_max_proto_version: "sslv3"
          auth_ssl_min_proto_version: "default"
          auth_ssl_sigalgs: "no-rsa-pss"
          auth_timeout: "5"
          auth_timeout_type: "idle-timeout"
          auth_type: "http"
          cors: "disable"
          cors_allowed_origins:
              -
                  name: "default_name_27"
          default_user_password_policy: "<your_own_value> (source user.password-policy.name)"
          per_policy_disclaimer: "enable"
          radius_ses_timeout_act: "hard-timeout"
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


def filter_user_setting_data(json):
    option_list = [
        "auth_blackout_time",
        "auth_ca_cert",
        "auth_cert",
        "auth_http_basic",
        "auth_invalid_max",
        "auth_lockout_duration",
        "auth_lockout_threshold",
        "auth_on_demand",
        "auth_portal_timeout",
        "auth_ports",
        "auth_secure_http",
        "auth_src_mac",
        "auth_ssl_allow_renegotiation",
        "auth_ssl_max_proto_version",
        "auth_ssl_min_proto_version",
        "auth_ssl_sigalgs",
        "auth_timeout",
        "auth_timeout_type",
        "auth_type",
        "cors",
        "cors_allowed_origins",
        "default_user_password_policy",
        "per_policy_disclaimer",
        "radius_ses_timeout_act",
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
        ["auth_type"],
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


def user_setting(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    user_setting_data = data["user_setting"]

    filtered_data = filter_user_setting_data(user_setting_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("user", "setting", filtered_data, vdom=vdom)
        current_data = fos.get("user", "setting", vdom=vdom, mkey=mkey)
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
    data_copy["user_setting"] = filtered_data
    fos.do_member_operation(
        "user",
        "setting",
        data_copy,
    )

    return fos.set("user", "setting", data=converted_data, vdom=vdom)


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


def fortios_user(data, fos, check_mode):

    if data["user_setting"]:
        resp = user_setting(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("user_setting"))
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
        "auth_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "http"},
                {"value": "https"},
                {"value": "ftp"},
                {"value": "telnet"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "auth_cert": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "auth_ca_cert": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "auth_secure_http": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_http_basic": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_ssl_allow_renegotiation": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_src_mac": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_on_demand": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "always"}, {"value": "implicitly"}],
        },
        "auth_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auth_timeout_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "idle-timeout"},
                {"value": "hard-timeout"},
                {"value": "new-session"},
            ],
        },
        "auth_portal_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "radius_ses_timeout_act": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "hard-timeout"}, {"value": "ignore-timeout"}],
        },
        "auth_blackout_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auth_invalid_max": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auth_lockout_threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auth_lockout_duration": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "per_policy_disclaimer": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_ports": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "http"},
                        {"value": "https"},
                        {"value": "ftp"},
                        {"value": "telnet"},
                    ],
                },
                "port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "auth_ssl_min_proto_version": {
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
        "auth_ssl_max_proto_version": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [
                {"value": "sslv3"},
                {"value": "tlsv1"},
                {"value": "tlsv1-1"},
                {"value": "tlsv1-2"},
                {"value": "tlsv1-3"},
            ],
        },
        "auth_ssl_sigalgs": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "no-rsa-pss"}, {"value": "all"}],
        },
        "default_user_password_policy": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "cors": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "cors_allowed_origins": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.3", ""]],
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
        "user_setting": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["user_setting"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["user_setting"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "user_setting"
        )

        is_error, has_changed, result, diff = fortios_user(
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
