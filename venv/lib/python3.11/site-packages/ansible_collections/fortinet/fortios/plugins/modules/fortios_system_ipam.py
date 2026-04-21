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
module: fortios_system_ipam
short_description: Configure IP address management services in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and ipam category.
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

    system_ipam:
        description:
            - Configure IP address management services.
        default: null
        type: dict
        suboptions:
            automatic_conflict_resolution:
                description:
                    - Enable/disable automatic conflict resolution.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            manage_lan_addresses:
                description:
                    - Enable/disable default management of LAN interface addresses.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            manage_lan_extension_addresses:
                description:
                    - Enable/disable default management of FortiExtender LAN extension interface addresses.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            manage_ssid_addresses:
                description:
                    - Enable/disable default management of FortiAP SSID addresses.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            pool_subnet:
                description:
                    - Configure IPAM pool subnet, Class A - Class B subnet.
                type: str
            pools:
                description:
                    - Configure IPAM pools.
                type: list
                elements: dict
                suboptions:
                    description:
                        description:
                            - Description.
                        type: str
                    exclude:
                        description:
                            - Configure pool exclude subnets.
                        type: list
                        elements: dict
                        suboptions:
                            exclude_subnet:
                                description:
                                    - Configure subnet to exclude from the IPAM pool.
                                type: str
                            ID:
                                description:
                                    - Exclude ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                    name:
                        description:
                            - IPAM pool name.
                        required: true
                        type: str
                    subnet:
                        description:
                            - Configure IPAM pool subnet, Class A - Class B subnet.
                        type: str
            require_subnet_size_match:
                description:
                    - Enable/disable reassignment of subnets to make requested and actual sizes match.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            rules:
                description:
                    - Configure IPAM allocation rules.
                type: list
                elements: dict
                suboptions:
                    description:
                        description:
                            - Description.
                        type: str
                    device:
                        description:
                            - Configure serial number or wildcard of FortiGate to match.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - FortiGate serial number or wildcard.
                                required: true
                                type: str
                    dhcp:
                        description:
                            - Enable/disable DHCP server for matching IPAM interfaces.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    interface:
                        description:
                            - Configure name or wildcard of interface to match.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Interface name or wildcard.
                                required: true
                                type: str
                    name:
                        description:
                            - IPAM rule name.
                        required: true
                        type: str
                    pool:
                        description:
                            - Configure name of IPAM pool to use.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - IPAM pool name. Source system.ipam.pools.name.
                                required: true
                                type: str
                    role:
                        description:
                            - Configure role of interface to match.
                        type: str
                        choices:
                            - 'any'
                            - 'lan'
                            - 'wan'
                            - 'dmz'
                            - 'undefined'
            server_type:
                description:
                    - Configure the type of IPAM server to use.
                type: str
                choices:
                    - 'fabric-root'
                    - 'cloud'
            status:
                description:
                    - Enable/disable IP address management services.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure IP address management services.
  fortinet.fortios.fortios_system_ipam:
      vdom: "{{ vdom }}"
      system_ipam:
          automatic_conflict_resolution: "disable"
          manage_lan_addresses: "disable"
          manage_lan_extension_addresses: "disable"
          manage_ssid_addresses: "disable"
          pool_subnet: "<your_own_value>"
          pools:
              -
                  description: "<your_own_value>"
                  exclude:
                      -
                          exclude_subnet: "<your_own_value>"
                          ID: "<you_own_value>"
                  name: "default_name_13"
                  subnet: "<your_own_value>"
          require_subnet_size_match: "disable"
          rules:
              -
                  description: "<your_own_value>"
                  device:
                      -
                          name: "default_name_19"
                  dhcp: "enable"
                  interface:
                      -
                          name: "default_name_22"
                  name: "default_name_23"
                  pool:
                      -
                          name: "default_name_25 (source system.ipam.pools.name)"
                  role: "any"
          server_type: "fabric-root"
          status: "enable"
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


def filter_system_ipam_data(json):
    option_list = [
        "automatic_conflict_resolution",
        "manage_lan_addresses",
        "manage_lan_extension_addresses",
        "manage_ssid_addresses",
        "pool_subnet",
        "pools",
        "require_subnet_size_match",
        "rules",
        "server_type",
        "status",
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


def system_ipam(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_ipam_data = data["system_ipam"]

    filtered_data = filter_system_ipam_data(system_ipam_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "ipam", filtered_data, vdom=vdom)
        current_data = fos.get("system", "ipam", vdom=vdom, mkey=mkey)
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
    data_copy["system_ipam"] = filtered_data
    fos.do_member_operation(
        "system",
        "ipam",
        data_copy,
    )

    return fos.set("system", "ipam", data=converted_data, vdom=vdom)


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

    if data["system_ipam"]:
        resp = system_ipam(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_ipam"))
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
    "v_range": [["v7.0.2", ""]],
    "type": "dict",
    "children": {
        "status": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "server_type": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [
                {"value": "fabric-root"},
                {"value": "cloud", "v_range": [["v7.0.2", "v7.2.4"]]},
            ],
        },
        "automatic_conflict_resolution": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "require_subnet_size_match": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "manage_lan_addresses": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "manage_lan_extension_addresses": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "manage_ssid_addresses": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "pools": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                },
                "description": {"v_range": [["v7.2.1", ""]], "type": "string"},
                "subnet": {"v_range": [["v7.2.1", ""]], "type": "string"},
                "exclude": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "ID": {
                            "v_range": [["v7.4.4", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "exclude_subnet": {
                            "v_range": [["v7.4.4", ""]],
                            "type": "string",
                        },
                    },
                    "v_range": [["v7.4.4", ""]],
                },
            },
            "v_range": [["v7.2.1", ""]],
        },
        "rules": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                },
                "description": {"v_range": [["v7.2.1", ""]], "type": "string"},
                "device": {
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
                "interface": {
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
                "role": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "any"},
                        {"value": "lan"},
                        {"value": "wan"},
                        {"value": "dmz"},
                        {"value": "undefined"},
                    ],
                },
                "pool": {
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
                "dhcp": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
            "v_range": [["v7.2.1", ""]],
        },
        "pool_subnet": {"v_range": [["v7.0.2", "v7.2.0"]], "type": "string"},
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
        "system_ipam": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_ipam"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_ipam"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_ipam"
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
