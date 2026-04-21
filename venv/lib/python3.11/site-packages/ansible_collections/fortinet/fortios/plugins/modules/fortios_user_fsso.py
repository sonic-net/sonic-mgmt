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
module: fortios_user_fsso
short_description: Configure Fortinet Single Sign On (FSSO) agents in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify user feature and fsso category.
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

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    user_fsso:
        description:
            - Configure Fortinet Single Sign On (FSSO) agents.
        default: null
        type: dict
        suboptions:
            group_poll_interval:
                description:
                    - Interval in minutes within to fetch groups from FSSO server, or unset to disable.
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
            ldap_poll:
                description:
                    - Enable/disable automatic fetching of groups from LDAP server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ldap_poll_filter:
                description:
                    - Filter used to fetch groups.
                type: str
            ldap_poll_interval:
                description:
                    - Interval in minutes within to fetch groups from LDAP server.
                type: int
            ldap_server:
                description:
                    - LDAP server to get group information. Source user.ldap.name.
                type: str
            logon_timeout:
                description:
                    - Interval in minutes to keep logons after FSSO server down.
                type: int
            name:
                description:
                    - Name.
                required: true
                type: str
            password:
                description:
                    - Password of the first FSSO collector agent.
                type: str
            password2:
                description:
                    - Password of the second FSSO collector agent.
                type: str
            password3:
                description:
                    - Password of the third FSSO collector agent.
                type: str
            password4:
                description:
                    - Password of the fourth FSSO collector agent.
                type: str
            password5:
                description:
                    - Password of the fifth FSSO collector agent.
                type: str
            port:
                description:
                    - Port of the first FSSO collector agent.
                type: int
            port2:
                description:
                    - Port of the second FSSO collector agent.
                type: int
            port3:
                description:
                    - Port of the third FSSO collector agent.
                type: int
            port4:
                description:
                    - Port of the fourth FSSO collector agent.
                type: int
            port5:
                description:
                    - Port of the fifth FSSO collector agent.
                type: int
            server:
                description:
                    - Domain name or IP address of the first FSSO collector agent.
                type: str
            server2:
                description:
                    - Domain name or IP address of the second FSSO collector agent.
                type: str
            server3:
                description:
                    - Domain name or IP address of the third FSSO collector agent.
                type: str
            server4:
                description:
                    - Domain name or IP address of the fourth FSSO collector agent.
                type: str
            server5:
                description:
                    - Domain name or IP address of the fifth FSSO collector agent.
                type: str
            sni:
                description:
                    - Server Name Indication.
                type: str
            source_ip:
                description:
                    - Source IP for communications to FSSO agent.
                type: str
            source_ip6:
                description:
                    - IPv6 source for communications to FSSO agent.
                type: str
            ssl:
                description:
                    - Enable/disable use of SSL.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_server_host_ip_check:
                description:
                    - Enable/disable server host/IP verification.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_trusted_cert:
                description:
                    - Trusted server certificate or CA certificate. Source vpn.certificate.remote.name vpn.certificate.ca.name.
                type: str
            type:
                description:
                    - Server type.
                type: str
                choices:
                    - 'default'
                    - 'fortinac'
                    - 'fortiems'
                    - 'fortiems-cloud'
            user_info_server:
                description:
                    - LDAP server to get user information. Source user.ldap.name.
                type: str
            vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
"""

EXAMPLES = """
- name: Configure Fortinet Single Sign On (FSSO) agents.
  fortinet.fortios.fortios_user_fsso:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      user_fsso:
          group_poll_interval: "0"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          ldap_poll: "enable"
          ldap_poll_filter: "<your_own_value>"
          ldap_poll_interval: "180"
          ldap_server: "<your_own_value> (source user.ldap.name)"
          logon_timeout: "5"
          name: "default_name_11"
          password: "<your_own_value>"
          password2: "<your_own_value>"
          password3: "<your_own_value>"
          password4: "<your_own_value>"
          password5: "<your_own_value>"
          port: "8000"
          port2: "8000"
          port3: "8000"
          port4: "8000"
          port5: "8000"
          server: "192.168.100.40"
          server2: "<your_own_value>"
          server3: "<your_own_value>"
          server4: "<your_own_value>"
          server5: "<your_own_value>"
          sni: "<your_own_value>"
          source_ip: "84.230.14.43"
          source_ip6: "<your_own_value>"
          ssl: "enable"
          ssl_server_host_ip_check: "enable"
          ssl_trusted_cert: "<your_own_value> (source vpn.certificate.remote.name vpn.certificate.ca.name)"
          type: "default"
          user_info_server: "<your_own_value> (source user.ldap.name)"
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


def filter_user_fsso_data(json):
    option_list = [
        "group_poll_interval",
        "interface",
        "interface_select_method",
        "ldap_poll",
        "ldap_poll_filter",
        "ldap_poll_interval",
        "ldap_server",
        "logon_timeout",
        "name",
        "password",
        "password2",
        "password3",
        "password4",
        "password5",
        "port",
        "port2",
        "port3",
        "port4",
        "port5",
        "server",
        "server2",
        "server3",
        "server4",
        "server5",
        "sni",
        "source_ip",
        "source_ip6",
        "ssl",
        "ssl_server_host_ip_check",
        "ssl_trusted_cert",
        "type",
        "user_info_server",
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


def user_fsso(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    user_fsso_data = data["user_fsso"]

    filtered_data = filter_user_fsso_data(user_fsso_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("user", "fsso", filtered_data, vdom=vdom)
        current_data = fos.get("user", "fsso", vdom=vdom, mkey=mkey)
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
    data_copy["user_fsso"] = filtered_data
    fos.do_member_operation(
        "user",
        "fsso",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("user", "fsso", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("user", "fsso", mkey=converted_data["name"], vdom=vdom)
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


def fortios_user(data, fos, check_mode):

    if data["user_fsso"]:
        resp = user_fsso(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("user_fsso"))
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
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "type": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "default"},
                {"value": "fortinac"},
                {"value": "fortiems", "v_range": [["v6.2.0", "v6.2.7"]]},
                {"value": "fortiems-cloud", "v_range": [["v6.2.0", "v6.2.7"]]},
            ],
        },
        "server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "server2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "port2": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "password2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "server3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "port3": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "password3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "server4": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "port4": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "password4": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "server5": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "port5": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "password5": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "logon_timeout": {"v_range": [["v7.0.1", ""]], "type": "integer"},
        "ldap_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "group_poll_interval": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "ldap_poll": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ldap_poll_interval": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "ldap_poll_filter": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "user_info_server": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "ssl": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sni": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "ssl_server_host_ip_check": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_trusted_cert": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "source_ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "interface_select_method": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "vrf_select": {"v_range": [["v7.6.1", ""]], "type": "integer"},
    },
    "v_range": [["v6.0.0", ""]],
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
        "user_fsso": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["user_fsso"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["user_fsso"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "user_fsso"
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
