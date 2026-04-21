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
module: fortios_authentication_setting
short_description: Configure authentication setting in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify authentication feature and setting category.
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

    authentication_setting:
        description:
            - Configure authentication setting.
        default: null
        type: dict
        suboptions:
            active_auth_scheme:
                description:
                    - Active authentication method (scheme name). Source authentication.scheme.name.
                type: str
            auth_https:
                description:
                    - Enable/disable redirecting HTTP user authentication to HTTPS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            captive_portal:
                description:
                    - Captive portal host name. Source firewall.address.name.
                type: str
            captive_portal_ip:
                description:
                    - Captive portal IP address.
                type: str
            captive_portal_ip6:
                description:
                    - Captive portal IPv6 address.
                type: str
            captive_portal_port:
                description:
                    - Captive portal port number (1 - 65535).
                type: int
            captive_portal_ssl_port:
                description:
                    - Captive portal SSL port number (1 - 65535).
                type: int
            captive_portal_type:
                description:
                    - Captive portal type.
                type: str
                choices:
                    - 'fqdn'
                    - 'ip'
            captive_portal6:
                description:
                    - IPv6 captive portal host name. Source firewall.address6.name.
                type: str
            cert_auth:
                description:
                    - Enable/disable redirecting certificate authentication to HTTPS portal.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cert_captive_portal:
                description:
                    - Certificate captive portal host name. Source firewall.address.name.
                type: str
            cert_captive_portal_ip:
                description:
                    - Certificate captive portal IP address.
                type: str
            cert_captive_portal_port:
                description:
                    - Certificate captive portal port number (1 - 65535).
                type: int
            cookie_max_age:
                description:
                    - Persistent web portal cookie maximum age in minutes (30 - 10080 (1 week)).
                type: int
            cookie_refresh_div:
                description:
                    - Refresh rate divider of persistent web portal cookie . Refresh value = cookie-max-age/cookie-refresh-div.
                type: int
            dev_range:
                description:
                    - Address range for the IP based device query.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            ip_auth_cookie:
                description:
                    - Enable/disable persistent cookie on IP based web portal authentication .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            persistent_cookie:
                description:
                    - Enable/disable persistent cookie on web portal authentication .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sso_auth_scheme:
                description:
                    - Single-Sign-On authentication method (scheme name). Source authentication.scheme.name.
                type: str
            update_time:
                description:
                    - Time of the last update.
                type: str
            user_cert_ca:
                description:
                    - CA certificate used for client certificate verification.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - CA certificate list. Source vpn.certificate.ca.name vpn.certificate.local.name.
                        required: true
                        type: str
"""

EXAMPLES = """
- name: Configure authentication setting.
  fortinet.fortios.fortios_authentication_setting:
      vdom: "{{ vdom }}"
      authentication_setting:
          active_auth_scheme: "<your_own_value> (source authentication.scheme.name)"
          auth_https: "enable"
          captive_portal: "<your_own_value> (source firewall.address.name)"
          captive_portal_ip: "<your_own_value>"
          captive_portal_ip6: "<your_own_value>"
          captive_portal_port: "7830"
          captive_portal_ssl_port: "7831"
          captive_portal_type: "fqdn"
          captive_portal6: "<your_own_value> (source firewall.address6.name)"
          cert_auth: "enable"
          cert_captive_portal: "<your_own_value> (source firewall.address.name)"
          cert_captive_portal_ip: "<your_own_value>"
          cert_captive_portal_port: "7832"
          cookie_max_age: "480"
          cookie_refresh_div: "2"
          dev_range:
              -
                  name: "default_name_19 (source firewall.address.name firewall.addrgrp.name)"
          ip_auth_cookie: "enable"
          persistent_cookie: "enable"
          sso_auth_scheme: "<your_own_value> (source authentication.scheme.name)"
          update_time: "<your_own_value>"
          user_cert_ca:
              -
                  name: "default_name_25 (source vpn.certificate.ca.name vpn.certificate.local.name)"
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


def filter_authentication_setting_data(json):
    option_list = [
        "active_auth_scheme",
        "auth_https",
        "captive_portal",
        "captive_portal_ip",
        "captive_portal_ip6",
        "captive_portal_port",
        "captive_portal_ssl_port",
        "captive_portal_type",
        "captive_portal6",
        "cert_auth",
        "cert_captive_portal",
        "cert_captive_portal_ip",
        "cert_captive_portal_port",
        "cookie_max_age",
        "cookie_refresh_div",
        "dev_range",
        "ip_auth_cookie",
        "persistent_cookie",
        "sso_auth_scheme",
        "update_time",
        "user_cert_ca",
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


def authentication_setting(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    authentication_setting_data = data["authentication_setting"]

    filtered_data = filter_authentication_setting_data(authentication_setting_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("authentication", "setting", filtered_data, vdom=vdom)
        current_data = fos.get("authentication", "setting", vdom=vdom, mkey=mkey)
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
    data_copy["authentication_setting"] = filtered_data
    fos.do_member_operation(
        "authentication",
        "setting",
        data_copy,
    )

    return fos.set("authentication", "setting", data=converted_data, vdom=vdom)


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


def fortios_authentication(data, fos, check_mode):

    if data["authentication_setting"]:
        resp = authentication_setting(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("authentication_setting"))
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
        "active_auth_scheme": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sso_auth_scheme": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "update_time": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "persistent_cookie": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ip_auth_cookie": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cookie_max_age": {"v_range": [["v7.2.0", ""]], "type": "integer"},
        "cookie_refresh_div": {"v_range": [["v7.2.0", ""]], "type": "integer"},
        "captive_portal_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "fqdn"}, {"value": "ip"}],
        },
        "captive_portal_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "captive_portal_ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "captive_portal": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "captive_portal6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "cert_auth": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cert_captive_portal": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "cert_captive_portal_ip": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "cert_captive_portal_port": {"v_range": [["v7.0.1", ""]], "type": "integer"},
        "captive_portal_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auth_https": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "captive_portal_ssl_port": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "user_cert_ca": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.0", ""]],
        },
        "dev_range": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.0", ""]],
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
        "authentication_setting": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["authentication_setting"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["authentication_setting"]["options"][attribute_name][
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
            fos, versioned_schema, "authentication_setting"
        )

        is_error, has_changed, result, diff = fortios_authentication(
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
