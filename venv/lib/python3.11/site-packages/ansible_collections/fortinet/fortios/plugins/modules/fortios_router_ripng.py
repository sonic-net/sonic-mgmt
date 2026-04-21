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
module: fortios_router_ripng
short_description: Configure RIPng in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify router feature and ripng category.
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

    router_ripng:
        description:
            - Configure RIPng.
        default: null
        type: dict
        suboptions:
            aggregate_address:
                description:
                    - Aggregate address.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Aggregate address entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    prefix6:
                        description:
                            - Aggregate address prefix.
                        type: str
            default_information_originate:
                description:
                    - Enable/disable generation of default route.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            default_metric:
                description:
                    - Default metric.
                type: int
            distance:
                description:
                    - Distance.
                type: list
                elements: dict
                suboptions:
                    access_list6:
                        description:
                            - Access list for route destination. Source router.access-list6.name.
                        type: str
                    distance:
                        description:
                            - Distance (1 - 255).
                        type: int
                    id:
                        description:
                            - Distance ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    prefix6:
                        description:
                            - Distance prefix6.
                        type: str
            distribute_list:
                description:
                    - Distribute list.
                type: list
                elements: dict
                suboptions:
                    direction:
                        description:
                            - Distribute list direction.
                        type: str
                        choices:
                            - 'in'
                            - 'out'
                    id:
                        description:
                            - Distribute list ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    interface:
                        description:
                            - Distribute list interface name. Source system.interface.name.
                        type: str
                    listname:
                        description:
                            - Distribute access/prefix list name. Source router.access-list6.name router.prefix-list6.name.
                        type: str
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            garbage_timer:
                description:
                    - Garbage timer in seconds.
                type: int
            interface:
                description:
                    - RIPng interface configuration.
                type: list
                elements: dict
                suboptions:
                    flags:
                        description:
                            - Flags.
                        type: int
                    name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
                    split_horizon:
                        description:
                            - Enable/disable split horizon.
                        type: str
                        choices:
                            - 'poisoned'
                            - 'regular'
                    split_horizon_status:
                        description:
                            - Enable/disable split horizon.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            max_out_metric:
                description:
                    - Maximum metric allowed to output(0 means "not set").
                type: int
            neighbor:
                description:
                    - Neighbor.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Neighbor entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    interface:
                        description:
                            - Interface name. Source system.interface.name.
                        type: str
                    ip6:
                        description:
                            - IPv6 link-local address.
                        type: str
            network:
                description:
                    - Network.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Network entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    prefix:
                        description:
                            - Network IPv6 link-local prefix.
                        type: str
            offset_list:
                description:
                    - Offset list.
                type: list
                elements: dict
                suboptions:
                    access_list6:
                        description:
                            - IPv6 access list name. Source router.access-list6.name.
                        type: str
                    direction:
                        description:
                            - Offset list direction.
                        type: str
                        choices:
                            - 'in'
                            - 'out'
                    id:
                        description:
                            - Offset-list ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    interface:
                        description:
                            - Interface name. Source system.interface.name.
                        type: str
                    offset:
                        description:
                            - Offset.
                        type: int
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            passive_interface:
                description:
                    - Passive interface configuration.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Passive interface name. Source system.interface.name.
                        required: true
                        type: str
            redistribute:
                description:
                    - Redistribute configuration.
                type: list
                elements: dict
                suboptions:
                    metric:
                        description:
                            - Redistribute metric setting.
                        type: int
                    name:
                        description:
                            - Redistribute name.
                        required: true
                        type: str
                    routemap:
                        description:
                            - Route map name. Source router.route-map.name.
                        type: str
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            timeout_timer:
                description:
                    - Timeout timer in seconds.
                type: int
            update_timer:
                description:
                    - Update timer in seconds.
                type: int
"""

EXAMPLES = """
- name: Configure RIPng.
  fortinet.fortios.fortios_router_ripng:
      vdom: "{{ vdom }}"
      router_ripng:
          aggregate_address:
              -
                  id: "4"
                  prefix6: "<your_own_value>"
          default_information_originate: "enable"
          default_metric: "1"
          distance:
              -
                  access_list6: "<your_own_value> (source router.access-list6.name)"
                  distance: "0"
                  id: "11"
                  prefix6: "<your_own_value>"
          distribute_list:
              -
                  direction: "in"
                  id: "15"
                  interface: "<your_own_value> (source system.interface.name)"
                  listname: "<your_own_value> (source router.access-list6.name router.prefix-list6.name)"
                  status: "enable"
          garbage_timer: "120"
          interface:
              -
                  flags: "8"
                  name: "default_name_22 (source system.interface.name)"
                  split_horizon: "poisoned"
                  split_horizon_status: "enable"
          max_out_metric: "0"
          neighbor:
              -
                  id: "27"
                  interface: "<your_own_value> (source system.interface.name)"
                  ip6: "<your_own_value>"
          network:
              -
                  id: "31"
                  prefix: "<your_own_value>"
          offset_list:
              -
                  access_list6: "<your_own_value> (source router.access-list6.name)"
                  direction: "in"
                  id: "36"
                  interface: "<your_own_value> (source system.interface.name)"
                  offset: "0"
                  status: "enable"
          passive_interface:
              -
                  name: "default_name_41 (source system.interface.name)"
          redistribute:
              -
                  metric: "0"
                  name: "default_name_44"
                  routemap: "<your_own_value> (source router.route-map.name)"
                  status: "enable"
          timeout_timer: "180"
          update_timer: "30"
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


def filter_router_ripng_data(json):
    option_list = [
        "aggregate_address",
        "default_information_originate",
        "default_metric",
        "distance",
        "distribute_list",
        "garbage_timer",
        "interface",
        "max_out_metric",
        "neighbor",
        "network",
        "offset_list",
        "passive_interface",
        "redistribute",
        "timeout_timer",
        "update_timer",
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


def router_ripng(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    router_ripng_data = data["router_ripng"]

    filtered_data = filter_router_ripng_data(router_ripng_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("router", "ripng", filtered_data, vdom=vdom)
        current_data = fos.get("router", "ripng", vdom=vdom, mkey=mkey)
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
    data_copy["router_ripng"] = filtered_data
    fos.do_member_operation(
        "router",
        "ripng",
        data_copy,
    )

    return fos.set("router", "ripng", data=converted_data, vdom=vdom)


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

    if data["router_ripng"]:
        resp = router_ripng(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_ripng"))
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
        "default_information_originate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "default_metric": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "max_out_metric": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "distance": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "distance": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "prefix6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "access_list6": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "distribute_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "direction": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "in"}, {"value": "out"}],
                },
                "listname": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "neighbor": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "network": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "prefix": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "aggregate_address": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "prefix6": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "offset_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "direction": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "in"}, {"value": "out"}],
                },
                "access_list6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "offset": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "passive_interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "update_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "timeout_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "garbage_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "split_horizon_status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "split_horizon": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "poisoned"}, {"value": "regular"}],
                },
                "flags": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "redistribute": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "metric": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "routemap": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
            },
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
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
        "router_ripng": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_ripng"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_ripng"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "router_ripng"
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
