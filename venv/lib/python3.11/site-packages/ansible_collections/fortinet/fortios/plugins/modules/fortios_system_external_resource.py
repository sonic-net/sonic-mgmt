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
module: fortios_system_external_resource
short_description: Configure external resource in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and external_resource category.
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
    system_external_resource:
        description:
            - Configure external resource.
        default: null
        type: dict
        suboptions:
            address_comment_field:
                description:
                    - JSON Path to address description in generic address entry.
                type: str
            address_data_field:
                description:
                    - JSON Path to address data in generic address entry.
                type: str
            address_name_field:
                description:
                    - JSON Path to address name in generic address entry.
                type: str
            category:
                description:
                    - User resource category.
                type: int
            client_cert:
                description:
                    - Client certificate name. Source vpn.certificate.local.name.
                type: str
            client_cert_auth:
                description:
                    - Enable/disable using client certificate for TLS authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            comments:
                description:
                    - Comment.
                type: str
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
            name:
                description:
                    - External resource name.
                required: true
                type: str
            namespace:
                description:
                    - Generic external connector address namespace.
                type: str
            object_array_path:
                description:
                    - JSON Path to array of generic addresses in resource.
                type: str
            password:
                description:
                    - HTTP basic authentication password.
                type: str
            refresh_rate:
                description:
                    - Time interval to refresh external resource (1 - 43200 min).
                type: int
            resource:
                description:
                    - URL of external resource.
                type: str
            server_identity_check:
                description:
                    - Certificate verification option.
                type: str
                choices:
                    - 'none'
                    - 'basic'
                    - 'full'
            source_ip:
                description:
                    - Source IPv4 address used to communicate with server.
                type: str
            source_ip_interface:
                description:
                    - IPv4 Source interface for communication with the server. Source system.interface.name.
                type: str
            status:
                description:
                    - Enable/disable user resource.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            type:
                description:
                    - User resource type.
                type: str
                choices:
                    - 'category'
                    - 'domain'
                    - 'malware'
                    - 'address'
                    - 'mac-address'
                    - 'data'
                    - 'generic-address'
            update_method:
                description:
                    - External resource update method.
                type: str
                choices:
                    - 'feed'
                    - 'push'
            user_agent:
                description:
                    - HTTP User-Agent header .
                type: str
            username:
                description:
                    - HTTP basic authentication user name.
                type: str
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
"""

EXAMPLES = """
- name: Configure external resource.
  fortinet.fortios.fortios_system_external_resource:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_external_resource:
          address_comment_field: "<your_own_value>"
          address_data_field: "<your_own_value>"
          address_name_field: "<your_own_value>"
          category: "0"
          client_cert: "<your_own_value> (source vpn.certificate.local.name)"
          client_cert_auth: "enable"
          comments: "<your_own_value>"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          name: "default_name_12"
          namespace: "<your_own_value>"
          object_array_path: "<your_own_value>"
          password: "<your_own_value>"
          refresh_rate: "5"
          resource: "<your_own_value>"
          server_identity_check: "none"
          source_ip: "84.230.14.43"
          source_ip_interface: "<your_own_value> (source system.interface.name)"
          status: "enable"
          type: "category"
          update_method: "feed"
          user_agent: "<your_own_value>"
          username: "<your_own_value>"
          uuid: "<your_own_value>"
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


def filter_system_external_resource_data(json):
    option_list = [
        "address_comment_field",
        "address_data_field",
        "address_name_field",
        "category",
        "client_cert",
        "client_cert_auth",
        "comments",
        "interface",
        "interface_select_method",
        "name",
        "namespace",
        "object_array_path",
        "password",
        "refresh_rate",
        "resource",
        "server_identity_check",
        "source_ip",
        "source_ip_interface",
        "status",
        "type",
        "update_method",
        "user_agent",
        "username",
        "uuid",
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


def system_external_resource(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_external_resource_data = data["system_external_resource"]

    filtered_data = filter_system_external_resource_data(system_external_resource_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "external-resource", filtered_data, vdom=vdom)
        current_data = fos.get("system", "external-resource", vdom=vdom, mkey=mkey)
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
    data_copy["system_external_resource"] = filtered_data
    fos.do_member_operation(
        "system",
        "external-resource",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "external-resource", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system", "external-resource", mkey=converted_data["name"], vdom=vdom
        )
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


def fortios_system(data, fos, check_mode):

    if data["system_external_resource"]:
        resp = system_external_resource(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("system_external_resource")
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
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "uuid": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "category"},
                {"value": "domain"},
                {"value": "malware", "v_range": [["v6.2.0", ""]]},
                {"value": "address"},
                {"value": "mac-address", "v_range": [["v7.4.0", ""]]},
                {"value": "data", "v_range": [["v7.4.2", ""]]},
                {"value": "generic-address", "v_range": [["v7.6.1", ""]]},
            ],
        },
        "namespace": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "object_array_path": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "address_name_field": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "address_data_field": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "address_comment_field": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "update_method": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "feed"}, {"value": "push"}],
        },
        "category": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "username": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "password": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "client_cert_auth": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "client_cert": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "resource": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "user_agent": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "server_identity_check": {
            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "basic"}, {"value": "full"}],
        },
        "refresh_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "source_ip": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "source_ip_interface": {"v_range": [["v7.6.4", ""]], "type": "string"},
        "interface_select_method": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
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
        "system_external_resource": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_external_resource"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_external_resource"]["options"][attribute_name][
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
            fos, versioned_schema, "system_external_resource"
        )

        is_error, has_changed, result, diff = fortios_system(
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
