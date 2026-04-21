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
module: fortios_router_policy6
short_description: Configure IPv6 routing policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify router feature and policy6 category.
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
    - We highly recommend using your own value as the seq_num instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
       available number for the object, it does have limitations. Please find more details in Q&A.
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
    router_policy6:
        description:
            - Configure IPv6 routing policies.
        default: null
        type: dict
        suboptions:
            action:
                description:
                    - Action of the policy route.
                type: str
                choices:
                    - 'deny'
                    - 'permit'
            comments:
                description:
                    - Optional comments.
                type: str
            dst:
                description:
                    - Destination IPv6 prefix.
                type: list
                elements: dict
                suboptions:
                    addr6:
                        description:
                            - IPv6 address prefix.
                        required: true
                        type: str
            dst_negate:
                description:
                    - Enable/disable negating destination address match.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dstaddr:
                description:
                    - Destination address name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address/group name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
                        type: str
            end_port:
                description:
                    - End destination port number (1 - 65535).
                type: int
            end_source_port:
                description:
                    - End source port number (1 - 65535).
                type: int
            gateway:
                description:
                    - IPv6 address of the gateway.
                type: str
            groups:
                description:
                    - List of user groups.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Group name. Source user.group.name.
                        required: true
                        type: str
            input_device:
                description:
                    - Incoming interface name. Source system.interface.name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
            input_device_negate:
                description:
                    - Enable/disable negation of input device match.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service_custom:
                description:
                    - Custom Destination Internet Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Destination Internet Service name. Source firewall.internet-service-custom.name.
                        required: true
                        type: str
            internet_service_fortiguard:
                description:
                    - FortiGuard Destination Internet Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - FortiGuard Destination Internet Service name. Source firewall.internet-service-fortiguard.name.
                        required: true
                        type: str
            internet_service_id:
                description:
                    - Destination Internet Service ID.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Destination Internet Service ID. see <a href='#notes'>Notes</a>. Source firewall.internet-service.id.
                        required: true
                        type: int
            output_device:
                description:
                    - Outgoing interface name. Source system.interface.name system.interface.name.
                type: str
            protocol:
                description:
                    - Protocol number (0 - 255).
                type: int
            seq_num:
                description:
                    - Sequence number(1-65535). see <a href='#notes'>Notes</a>.
                required: true
                type: int
            src:
                description:
                    - Source IPv6 prefix.
                type: list
                elements: dict
                suboptions:
                    addr6:
                        description:
                            - IPv6 address prefix.
                        required: true
                        type: str
            src_negate:
                description:
                    - Enable/disable negating source address match.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            srcaddr:
                description:
                    - Source address name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address/group name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
                        type: str
            start_port:
                description:
                    - Start destination port number (1 - 65535).
                type: int
            start_source_port:
                description:
                    - Start source port number (1 - 65535).
                type: int
            status:
                description:
                    - Enable/disable this policy route.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tos:
                description:
                    - Type of service bit pattern.
                type: str
            tos_mask:
                description:
                    - Type of service evaluated bits.
                type: str
            users:
                description:
                    - List of users.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - User name. Source user.local.name.
                        required: true
                        type: str
"""

EXAMPLES = """
- name: Configure IPv6 routing policies.
  fortinet.fortios.fortios_router_policy6:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      router_policy6:
          action: "deny"
          comments: "<your_own_value>"
          dst:
              -
                  addr6: "<your_own_value>"
          dst_negate: "enable"
          dstaddr:
              -
                  name: "default_name_9 (source firewall.address6.name firewall.addrgrp6.name)"
          end_port: "65535"
          end_source_port: "65535"
          gateway: "<your_own_value>"
          groups:
              -
                  name: "default_name_14 (source user.group.name)"
          input_device:
              -
                  name: "default_name_16 (source system.interface.name)"
          input_device_negate: "enable"
          internet_service_custom:
              -
                  name: "default_name_19 (source firewall.internet-service-custom.name)"
          internet_service_fortiguard:
              -
                  name: "default_name_21 (source firewall.internet-service-fortiguard.name)"
          internet_service_id:
              -
                  id: "23 (source firewall.internet-service.id)"
          output_device: "<your_own_value> (source system.interface.name system.interface.name)"
          protocol: "0"
          seq_num: "<you_own_value>"
          src:
              -
                  addr6: "<your_own_value>"
          src_negate: "enable"
          srcaddr:
              -
                  name: "default_name_31 (source firewall.address6.name firewall.addrgrp6.name)"
          start_port: "1"
          start_source_port: "1"
          status: "enable"
          tos: "<your_own_value>"
          tos_mask: "<your_own_value>"
          users:
              -
                  name: "default_name_38 (source user.local.name)"
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


def filter_router_policy6_data(json):
    option_list = [
        "action",
        "comments",
        "dst",
        "dst_negate",
        "dstaddr",
        "end_port",
        "end_source_port",
        "gateway",
        "groups",
        "input_device",
        "input_device_negate",
        "internet_service_custom",
        "internet_service_fortiguard",
        "internet_service_id",
        "output_device",
        "protocol",
        "seq_num",
        "src",
        "src_negate",
        "srcaddr",
        "start_port",
        "start_source_port",
        "status",
        "tos",
        "tos_mask",
        "users",
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


def router_policy6(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    router_policy6_data = data["router_policy6"]

    filtered_data = filter_router_policy6_data(router_policy6_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("router", "policy6", filtered_data, vdom=vdom)
        current_data = fos.get("router", "policy6", vdom=vdom, mkey=mkey)
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
    data_copy["router_policy6"] = filtered_data
    fos.do_member_operation(
        "router",
        "policy6",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("router", "policy6", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "router", "policy6", mkey=converted_data["seq-num"], vdom=vdom
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


def fortios_router(data, fos, check_mode):

    if data["router_policy6"]:
        resp = router_policy6(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_policy6"))
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
        "seq_num": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "input_device": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "input_device_negate": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "src": {
            "type": "list",
            "elements": "dict",
            "children": {
                "addr6": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "srcaddr": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.1", ""]],
        },
        "src_negate": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dst": {
            "type": "list",
            "elements": "dict",
            "children": {
                "addr6": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "dstaddr": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.1", ""]],
        },
        "dst_negate": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "action": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "deny"}, {"value": "permit"}],
        },
        "protocol": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "start_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "end_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "start_source_port": {"v_range": [["v7.4.1", ""]], "type": "integer"},
        "end_source_port": {"v_range": [["v7.4.1", ""]], "type": "integer"},
        "gateway": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "output_device": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "tos": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "tos_mask": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "internet_service_id": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v7.2.1", ""]], "type": "integer", "required": True}
            },
            "v_range": [["v7.2.1", ""]],
        },
        "internet_service_custom": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.1", ""]],
        },
        "internet_service_fortiguard": {
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
        "users": {
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
        "groups": {
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
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "seq_num"
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
        "router_policy6": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_policy6"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_policy6"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "router_policy6"
        )

        is_error, has_changed, result, diff = fortios_router(
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
