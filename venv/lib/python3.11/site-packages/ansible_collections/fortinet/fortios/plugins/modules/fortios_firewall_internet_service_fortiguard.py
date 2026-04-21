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
module: fortios_firewall_internet_service_fortiguard
short_description: Configure FortiGuard Internet Services in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and internet_service_fortiguard category.
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
    firewall_internet_service_fortiguard:
        description:
            - Configure FortiGuard Internet Services.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Comment.
                type: str
            entry:
                description:
                    - Entries added to the Internet Service FortiGuard database.
                type: list
                elements: dict
                suboptions:
                    addr_mode:
                        description:
                            - Address mode (IPv4 or IPv6).
                        type: str
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                    dst:
                        description:
                            - Destination address or address group name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Select the destination address or address group object from available options. Source firewall.address.name firewall
                                      .addrgrp.name.
                                required: true
                                type: str
                    dst6:
                        description:
                            - Destination address6 or address6 group name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Select the destination address6 or address group object from available options. Source firewall.address6.name firewall
                                      .addrgrp6.name.
                                required: true
                                type: str
                    id:
                        description:
                            - Entry ID(1-255). see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    port_range:
                        description:
                            - Port ranges in the custom entry.
                        type: list
                        elements: dict
                        suboptions:
                            end_port:
                                description:
                                    - Integer value for ending TCP/UDP/SCTP destination port in range (0 to 65535).
                                type: int
                            id:
                                description:
                                    - Custom entry port range ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            start_port:
                                description:
                                    - Integer value for starting TCP/UDP/SCTP destination port in range (0 to 65535).
                                type: int
                    protocol:
                        description:
                            - Integer value for the protocol type as defined by IANA (0 - 255).
                        type: int
            name:
                description:
                    - Internet Service name.
                required: true
                type: str
"""

EXAMPLES = """
- name: Configure FortiGuard Internet Services.
  fortinet.fortios.fortios_firewall_internet_service_fortiguard:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_internet_service_fortiguard:
          comment: "Comment."
          entry:
              -
                  addr_mode: "ipv4"
                  dst:
                      -
                          name: "default_name_7 (source firewall.address.name firewall.addrgrp.name)"
                  dst6:
                      -
                          name: "default_name_9 (source firewall.address6.name firewall.addrgrp6.name)"
                  id: "10"
                  port_range:
                      -
                          end_port: "65535"
                          id: "13"
                          start_port: "1"
                  protocol: "0"
          name: "default_name_16"
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


def filter_firewall_internet_service_fortiguard_data(json):
    option_list = ["comment", "entry", "name"]

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


def firewall_internet_service_fortiguard(data, fos):
    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_internet_service_fortiguard_data = data[
        "firewall_internet_service_fortiguard"
    ]

    filtered_data = filter_firewall_internet_service_fortiguard_data(
        firewall_internet_service_fortiguard_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["firewall_internet_service_fortiguard"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "internet-service-fortiguard",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "firewall", "internet-service-fortiguard", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "firewall",
            "internet-service-fortiguard",
            mkey=converted_data["name"],
            vdom=vdom,
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


def fortios_firewall(data, fos):

    if data["firewall_internet_service_fortiguard"]:
        resp = firewall_internet_service_fortiguard(data, fos)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("firewall_internet_service_fortiguard")
        )

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
        "name": {"v_range": [["v7.6.4", ""]], "type": "string", "required": True},
        "comment": {"v_range": [["v7.6.4", ""]], "type": "string"},
        "entry": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "integer",
                    "required": True,
                },
                "addr_mode": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "options": [{"value": "ipv4"}, {"value": "ipv6"}],
                },
                "protocol": {"v_range": [["v7.6.4", ""]], "type": "integer"},
                "port_range": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.6.4", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "start_port": {"v_range": [["v7.6.4", ""]], "type": "integer"},
                        "end_port": {"v_range": [["v7.6.4", ""]], "type": "integer"},
                    },
                    "v_range": [["v7.6.4", ""]],
                },
                "dst": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.6.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.6.4", ""]],
                },
                "dst6": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.6.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.6.4", ""]],
                },
            },
            "v_range": [["v7.6.4", ""]],
        },
    },
    "v_range": [["v7.6.4", ""]],
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
        "firewall_internet_service_fortiguard": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_internet_service_fortiguard"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_internet_service_fortiguard"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "firewall_internet_service_fortiguard"
        )

        is_error, has_changed, result, diff = fortios_firewall(module.params, fos)

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
