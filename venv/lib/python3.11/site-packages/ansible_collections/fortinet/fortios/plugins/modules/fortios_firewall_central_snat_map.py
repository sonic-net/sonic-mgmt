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
module: fortios_firewall_central_snat_map
short_description: Configure IPv4 and IPv6 central SNAT policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and central_snat_map category.
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
    - We highly recommend using your own value as the policyid instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
       available number for the object, it does have limitations. Please find more details in Q&A.
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks
    - Adjust object order by moving self after(before) another.
    - Only one of [after, before] must be specified when action is moving an object.

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
    action:
        description:
            - the action indiactor to move an object in the list
        type: str
        choices:
            - 'move'
    self:
        description:
            - mkey of self identifier
        type: str
    after:
        description:
            - mkey of target identifier
        type: str
    before:
        description:
            - mkey of target identifier
        type: str

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: false
        choices:
            - 'present'
            - 'absent'
    firewall_central_snat_map:
        description:
            - Configure IPv4 and IPv6 central SNAT policies.
        default: null
        type: dict
        suboptions:
            comments:
                description:
                    - Comment.
                type: str
            dst_addr:
                description:
                    - IPv4 Destination address.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            dst_addr6:
                description:
                    - IPv6 Destination address.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
                        type: str
            dst_port:
                description:
                    - Destination port or port range (1 to 65535, 0 means any port).
                type: str
            dstintf:
                description:
                    - Destination interface name from available interfaces.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name system.sdwan.zone.name.
                        required: true
                        type: str
            nat:
                description:
                    - Enable/disable source NAT.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            nat_ippool:
                description:
                    - Name of the IP pools to be used to translate addresses from available IP Pools.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - IP pool name. Source firewall.ippool.name.
                        required: true
                        type: str
            nat_ippool6:
                description:
                    - IPv6 pools to be used for source NAT.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - IPv6 pool name. Source firewall.ippool6.name.
                        required: true
                        type: str
            nat_port:
                description:
                    - Translated port or port range (1 to 65535, 0 means any port).
                type: str
            nat46:
                description:
                    - Enable/disable NAT46.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            nat64:
                description:
                    - Enable/disable NAT64.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            orig_addr:
                description:
                    - IPv4 Original address.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name system.external-resource.name.
                        required: true
                        type: str
            orig_addr6:
                description:
                    - IPv6 Original address.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name system.external-resource.name.
                        required: true
                        type: str
            orig_port:
                description:
                    - Original TCP port (1 to 65535, 0 means any port).
                type: str
            policyid:
                description:
                    - Policy ID. see <a href='#notes'>Notes</a>.
                required: true
                type: int
            port_preserve:
                description:
                    - Enable/disable preservation of the original source port from source NAT if it has not been used.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            port_random:
                description:
                    - Enable/disable random source port selection for source NAT.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            protocol:
                description:
                    - Integer value for the protocol type (0 - 255).
                type: int
            srcintf:
                description:
                    - Source interface name from available interfaces.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name system.sdwan.zone.name.
                        required: true
                        type: str
            status:
                description:
                    - Enable/disable the active status of this policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            type:
                description:
                    - IPv4/IPv6 source NAT.
                type: str
                choices:
                    - 'ipv4'
                    - 'ipv6'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
"""

EXAMPLES = """
- name: Configure IPv4 and IPv6 central SNAT policies.
  fortinet.fortios.fortios_firewall_central_snat_map:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_central_snat_map:
          comments: "<your_own_value>"
          dst_addr:
              -
                  name: "default_name_5 (source firewall.address.name firewall.addrgrp.name)"
          dst_addr6:
              -
                  name: "default_name_7 (source firewall.address6.name firewall.addrgrp6.name)"
          dst_port: "<your_own_value>"
          dstintf:
              -
                  name: "default_name_10 (source system.interface.name system.zone.name system.sdwan.zone.name)"
          nat: "disable"
          nat_ippool:
              -
                  name: "default_name_13 (source firewall.ippool.name)"
          nat_ippool6:
              -
                  name: "default_name_15 (source firewall.ippool6.name)"
          nat_port: "<your_own_value>"
          nat46: "enable"
          nat64: "enable"
          orig_addr:
              -
                  name: "default_name_20 (source firewall.address.name firewall.addrgrp.name system.external-resource.name)"
          orig_addr6:
              -
                  name: "default_name_22 (source firewall.address6.name firewall.addrgrp6.name system.external-resource.name)"
          orig_port: "<your_own_value>"
          policyid: "<you_own_value>"
          port_preserve: "enable"
          port_random: "enable"
          protocol: "0"
          srcintf:
              -
                  name: "default_name_29 (source system.interface.name system.zone.name system.sdwan.zone.name)"
          status: "enable"
          type: "ipv4"
          uuid: "<your_own_value>"
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


def filter_firewall_central_snat_map_data(json):
    option_list = [
        "comments",
        "dst_addr",
        "dst_addr6",
        "dst_port",
        "dstintf",
        "nat",
        "nat_ippool",
        "nat_ippool6",
        "nat_port",
        "nat46",
        "nat64",
        "orig_addr",
        "orig_addr6",
        "orig_port",
        "policyid",
        "port_preserve",
        "port_random",
        "protocol",
        "srcintf",
        "status",
        "type",
        "uuid",
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


def firewall_central_snat_map(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_central_snat_map_data = data["firewall_central_snat_map"]

    filtered_data = filter_firewall_central_snat_map_data(
        firewall_central_snat_map_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "central-snat-map", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "central-snat-map", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_central_snat_map"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "central-snat-map",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "central-snat-map", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "central-snat-map", mkey=converted_data["policyid"], vdom=vdom
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


def move_fortios_firewall(data, fos):
    if not data["self"] or (not data["after"] and not data["before"]):
        fos._module.fail_json(msg="self, after(or before) must not be empty")
    vdom = data["vdom"]
    params_set = dict()
    params_set["action"] = "move"
    if data["after"]:
        params_set["after"] = data["after"]
    if data["before"]:
        params_set["before"] = data["before"]
    return fos.set(
        "firewall",
        "central-snat-map",
        data=None,
        mkey=data["self"],
        vdom=vdom,
        parameters=params_set,
    )


def fortios_firewall(data, fos, check_mode):

    if data["action"] == "move":
        resp = move_fortios_firewall(data, fos)
    elif data["firewall_central_snat_map"]:
        resp = firewall_central_snat_map(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("firewall_central_snat_map")
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
        "policyid": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "uuid": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "type": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "ipv4"}, {"value": "ipv6"}],
        },
        "srcintf": {
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
        "dstintf": {
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
        "orig_addr": {
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
        "orig_addr6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.4.0", ""]],
        },
        "dst_addr": {
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
        "dst_addr6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.4.0", ""]],
        },
        "protocol": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "orig_port": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "nat": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "nat46": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nat64": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nat_ippool": {
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
        "nat_ippool6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.4.0", ""]],
        },
        "port_preserve": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "port_random": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nat_port": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dst_port": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "policyid"
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
        "action": {"type": "str", "required": False, "choices": ["move"]},
        "self": {"type": "str", "required": False},
        "before": {"type": "str", "required": False},
        "after": {"type": "str", "required": False},
        "state": {"required": False, "type": "str", "choices": ["present", "absent"]},
        "firewall_central_snat_map": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_central_snat_map"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_central_snat_map"]["options"][attribute_name][
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
            fos, versioned_schema, "firewall_central_snat_map"
        )

        is_error, has_changed, result, diff = fortios_firewall(
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
