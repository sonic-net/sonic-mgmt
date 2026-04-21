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
module: fortios_ztna_web_portal
short_description: Configure ztna web-portal in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify ztna feature and web_portal category.
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

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    ztna_web_portal:
        description:
            - Configure ztna web-portal.
        default: null
        type: dict
        suboptions:
            auth_portal:
                description:
                    - Enable/disable authentication portal.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            auth_rule:
                description:
                    - Authentication Rule. Source authentication.rule.name.
                type: str
            auth_virtual_host:
                description:
                    - Virtual host for authentication portal. Source firewall.access-proxy-virtual-host.name.
                type: str
            clipboard:
                description:
                    - Enable to support RDP/VPC clipboard functionality.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cookie_age:
                description:
                    - Time in minutes that client web browsers should keep a cookie. Default is 60 minutes. 0 = no time limit.
                type: int
            customize_forticlient_download_url:
                description:
                    - Enable support of customized download URL for FortiClient.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            decrypted_traffic_mirror:
                description:
                    - Decrypted traffic mirror. Source firewall.decrypted-traffic-mirror.name.
                type: str
            default_window_height:
                description:
                    - Screen height (range from 0 - 65535).
                type: int
            default_window_width:
                description:
                    - Screen width (range from 0 - 65535).
                type: int
            display_bookmark:
                description:
                    - Enable to display the web portal bookmark widget.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            display_history:
                description:
                    - Enable to display the web portal user login history widget.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            display_status:
                description:
                    - Enable to display the web portal status widget.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            focus_bookmark:
                description:
                    - Enable to prioritize the placement of the bookmark section over the quick-connection section in the ztna web-portal.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forticlient_download:
                description:
                    - Enable/disable download option for FortiClient.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forticlient_download_method:
                description:
                    - FortiClient download method.
                type: str
                choices:
                    - 'direct'
                    - 'ssl-vpn'
            heading:
                description:
                    - Web portal heading message.
                type: str
            host:
                description:
                    - Virtual or real host name. Source firewall.access-proxy-virtual-host.name.
                type: str
            log_blocked_traffic:
                description:
                    - Enable/disable logging of blocked traffic.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            macos_forticlient_download_url:
                description:
                    - Download URL for Mac FortiClient.
                type: str
            name:
                description:
                    - ZTNA proxy name.
                required: true
                type: str
            policy_auth_sso:
                description:
                    - Enable policy sso authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            theme:
                description:
                    - Web portal color scheme.
                type: str
                choices:
                    - 'jade'
                    - 'neutrino'
                    - 'mariner'
                    - 'graphite'
                    - 'melongene'
                    - 'jet-stream'
                    - 'security-fabric'
                    - 'dark-matter'
                    - 'onyx'
                    - 'eclipse'
            vip:
                description:
                    - Virtual IP name. Source firewall.vip.name.
                type: str
            vip6:
                description:
                    - Virtual IPv6 name. Source firewall.vip6.name.
                type: str
            windows_forticlient_download_url:
                description:
                    - Download URL for Windows FortiClient.
                type: str
"""

EXAMPLES = """
- name: Configure ztna web-portal.
  fortinet.fortios.fortios_ztna_web_portal:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      ztna_web_portal:
          auth_portal: "disable"
          auth_rule: "<your_own_value> (source authentication.rule.name)"
          auth_virtual_host: "myhostname (source firewall.access-proxy-virtual-host.name)"
          clipboard: "enable"
          cookie_age: "60"
          customize_forticlient_download_url: "enable"
          decrypted_traffic_mirror: "<your_own_value> (source firewall.decrypted-traffic-mirror.name)"
          default_window_height: "768"
          default_window_width: "1024"
          display_bookmark: "enable"
          display_history: "enable"
          display_status: "enable"
          focus_bookmark: "enable"
          forticlient_download: "enable"
          forticlient_download_method: "direct"
          heading: "<your_own_value>"
          host: "myhostname (source firewall.access-proxy-virtual-host.name)"
          log_blocked_traffic: "disable"
          macos_forticlient_download_url: "<your_own_value>"
          name: "default_name_22"
          policy_auth_sso: "enable"
          theme: "jade"
          vip: "<your_own_value> (source firewall.vip.name)"
          vip6: "<your_own_value> (source firewall.vip6.name)"
          windows_forticlient_download_url: "<your_own_value>"
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


def filter_ztna_web_portal_data(json):
    option_list = [
        "auth_portal",
        "auth_rule",
        "auth_virtual_host",
        "clipboard",
        "cookie_age",
        "customize_forticlient_download_url",
        "decrypted_traffic_mirror",
        "default_window_height",
        "default_window_width",
        "display_bookmark",
        "display_history",
        "display_status",
        "focus_bookmark",
        "forticlient_download",
        "forticlient_download_method",
        "heading",
        "host",
        "log_blocked_traffic",
        "macos_forticlient_download_url",
        "name",
        "policy_auth_sso",
        "theme",
        "vip",
        "vip6",
        "windows_forticlient_download_url",
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


def ztna_web_portal(data, fos):
    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    ztna_web_portal_data = data["ztna_web_portal"]

    filtered_data = filter_ztna_web_portal_data(ztna_web_portal_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["ztna_web_portal"] = filtered_data
    fos.do_member_operation(
        "ztna",
        "web-portal",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("ztna", "web-portal", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("ztna", "web-portal", mkey=converted_data["name"], vdom=vdom)
    else:
        fos._module.fail_json(msg="state must be present or absent!")


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


def fortios_ztna(data, fos):

    if data["ztna_web_portal"]:
        resp = ztna_web_portal(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("ztna_web_portal"))

    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {"v_range": [["v7.6.1", ""]], "type": "string", "required": True},
        "vip": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "host": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "decrypted_traffic_mirror": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "log_blocked_traffic": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "auth_portal": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "auth_virtual_host": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "vip6": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "auth_rule": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "display_bookmark": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "focus_bookmark": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "display_status": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "display_history": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "policy_auth_sso": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "heading": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "theme": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [
                {"value": "jade"},
                {"value": "neutrino"},
                {"value": "mariner"},
                {"value": "graphite"},
                {"value": "melongene"},
                {"value": "jet-stream"},
                {"value": "security-fabric"},
                {"value": "dark-matter"},
                {"value": "onyx"},
                {"value": "eclipse"},
            ],
        },
        "clipboard": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "default_window_width": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "default_window_height": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "cookie_age": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "forticlient_download": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "customize_forticlient_download_url": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "windows_forticlient_download_url": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
        },
        "macos_forticlient_download_url": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
        },
        "forticlient_download_method": {
            "v_range": [["v7.6.1", "v7.6.3"]],
            "type": "string",
            "options": [{"value": "direct"}, {"value": "ssl-vpn"}],
        },
    },
    "v_range": [["v7.6.1", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
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
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "ztna_web_portal": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["ztna_web_portal"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["ztna_web_portal"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)
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
            fos, versioned_schema, "ztna_web_portal"
        )

        is_error, has_changed, result, diff = fortios_ztna(module.params, fos)

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
