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
module: fortios_firewall_address6
short_description: Configure IPv6 firewall addresses in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and address6 category.
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
    firewall_address6:
        description:
            - Configure IPv6 firewall addresses.
        default: null
        type: dict
        suboptions:
            cache_ttl:
                description:
                    - Minimal TTL of individual IPv6 addresses in FQDN cache.
                type: int
            color:
                description:
                    - Integer value to determine the color of the icon in the GUI (range 1 to 32).
                type: int
            comment:
                description:
                    - Comment.
                type: str
            country:
                description:
                    - IPv6 addresses associated to a specific country.
                type: str
            end_ip:
                description:
                    - 'Final IP address (inclusive) in the range for the address (format: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx).'
                type: str
            end_mac:
                description:
                    - Last MAC address in the range.
                type: str
            epg_name:
                description:
                    - Endpoint group name.
                type: str
            fabric_object:
                description:
                    - Security Fabric global object setting.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            filter:
                description:
                    - Match criteria filter.
                type: str
            fqdn:
                description:
                    - Fully qualified domain name.
                type: str
            host:
                description:
                    - Host Address.
                type: str
            host_type:
                description:
                    - Host type.
                type: str
                choices:
                    - 'any'
                    - 'specific'
            ip6:
                description:
                    - 'IPv6 address prefix (format: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xxx).'
                type: str
            list:
                description:
                    - IP address list.
                type: list
                elements: dict
                suboptions:
                    ip:
                        description:
                            - IP.
                        required: true
                        type: str
                    net_id:
                        description:
                            - Network ID.
                        type: str
                    obj_id:
                        description:
                            - Object ID.
                        type: str
            macaddr:
                description:
                    - Multiple MAC address ranges.
                type: list
                elements: dict
                suboptions:
                    macaddr:
                        description:
                            - MAC address ranges <start>[-<end>] separated by space.
                        required: true
                        type: str
            name:
                description:
                    - Address name.
                required: true
                type: str
            obj_id:
                description:
                    - Object ID for NSX.
                type: str
            route_tag:
                description:
                    - route-tag address.
                type: int
            sdn:
                description:
                    - SDN. Source system.sdn-connector.name.
                type: str
                choices:
                    - 'nsx'
            sdn_addr_type:
                description:
                    - Type of addresses to collect.
                type: str
                choices:
                    - 'private'
                    - 'public'
                    - 'all'
            sdn_tag:
                description:
                    - SDN Tag.
                type: str
            start_ip:
                description:
                    - 'First IP address (inclusive) in the range for the address (format: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx).'
                type: str
            start_mac:
                description:
                    - First MAC address in the range.
                type: str
            subnet_segment:
                description:
                    - IPv6 subnet segments.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Name.
                        required: true
                        type: str
                    type:
                        description:
                            - Subnet segment type.
                        type: str
                        choices:
                            - 'any'
                            - 'specific'
                    value:
                        description:
                            - Subnet segment value.
                        type: str
            tagging:
                description:
                    - Config object tagging.
                type: list
                elements: dict
                suboptions:
                    category:
                        description:
                            - Tag category. Source system.object-tagging.category.
                        type: str
                    name:
                        description:
                            - Tagging entry name.
                        required: true
                        type: str
                    tags:
                        description:
                            - Tags.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Tag name. Source system.object-tagging.tags.name.
                                required: true
                                type: str
            template:
                description:
                    - IPv6 address template. Source firewall.address6-template.name.
                type: str
            tenant:
                description:
                    - Tenant.
                type: str
            type:
                description:
                    - Type of IPv6 address object .
                type: str
                choices:
                    - 'ipprefix'
                    - 'iprange'
                    - 'fqdn'
                    - 'geography'
                    - 'dynamic'
                    - 'template'
                    - 'mac'
                    - 'route-tag'
                    - 'wildcard'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            visibility:
                description:
                    - Enable/disable the visibility of the object in the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wildcard:
                description:
                    - IPv6 address and wildcard netmask.
                type: str
"""

EXAMPLES = """
- name: Configure IPv6 firewall addresses.
  fortinet.fortios.fortios_firewall_address6:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_address6:
          cache_ttl: "0"
          color: "0"
          comment: "Comment."
          country: "<your_own_value>"
          end_ip: "<your_own_value>"
          end_mac: "<your_own_value>"
          epg_name: "<your_own_value>"
          fabric_object: "enable"
          filter: "<your_own_value>"
          fqdn: "<your_own_value>"
          host: "myhostname"
          host_type: "any"
          ip6: "<your_own_value>"
          list:
              -
                  ip: "<your_own_value>"
                  net_id: "<your_own_value>"
                  obj_id: "<your_own_value>"
          macaddr:
              -
                  macaddr: "<your_own_value>"
          name: "default_name_22"
          obj_id: "<your_own_value>"
          route_tag: "0"
          sdn: "nsx"
          sdn_addr_type: "private"
          sdn_tag: "<your_own_value>"
          start_ip: "<your_own_value>"
          start_mac: "<your_own_value>"
          subnet_segment:
              -
                  name: "default_name_31"
                  type: "any"
                  value: "<your_own_value>"
          tagging:
              -
                  category: "<your_own_value> (source system.object-tagging.category)"
                  name: "default_name_36"
                  tags:
                      -
                          name: "default_name_38 (source system.object-tagging.tags.name)"
          template: "<your_own_value> (source firewall.address6-template.name)"
          tenant: "<your_own_value>"
          type: "ipprefix"
          uuid: "<your_own_value>"
          visibility: "enable"
          wildcard: "<your_own_value>"
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


def filter_firewall_address6_data(json):
    option_list = [
        "cache_ttl",
        "color",
        "comment",
        "country",
        "end_ip",
        "end_mac",
        "epg_name",
        "fabric_object",
        "filter",
        "fqdn",
        "host",
        "host_type",
        "ip6",
        "list",
        "macaddr",
        "name",
        "obj_id",
        "route_tag",
        "sdn",
        "sdn_addr_type",
        "sdn_tag",
        "start_ip",
        "start_mac",
        "subnet_segment",
        "tagging",
        "template",
        "tenant",
        "type",
        "uuid",
        "visibility",
        "wildcard",
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


def firewall_address6(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_address6_data = data["firewall_address6"]

    filtered_data = filter_firewall_address6_data(firewall_address6_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "address6", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "address6", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_address6"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "address6",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "address6", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "address6", mkey=converted_data["name"], vdom=vdom
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


def fortios_firewall(data, fos, check_mode):

    if data["firewall_address6"]:
        resp = firewall_address6(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_address6"))
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
        "uuid": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "ipprefix"},
                {"value": "iprange"},
                {"value": "fqdn"},
                {"value": "geography", "v_range": [["v6.4.0", ""]]},
                {"value": "dynamic"},
                {"value": "template"},
                {
                    "value": "mac",
                    "v_range": [
                        ["v6.2.0", "v6.2.0"],
                        ["v6.2.5", "v6.4.0"],
                        ["v6.4.4", ""],
                    ],
                },
                {"value": "route-tag", "v_range": [["v7.4.0", ""]]},
                {"value": "wildcard", "v_range": [["v7.6.4", ""]]},
            ],
        },
        "route_tag": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "macaddr": {
            "type": "list",
            "elements": "dict",
            "children": {
                "macaddr": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.0", ""]],
        },
        "sdn": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "nsx", "v_range": [["v6.0.0", "v6.0.11"]]}],
        },
        "ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "wildcard": {"v_range": [["v7.6.4", ""]], "type": "string"},
        "start_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "end_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "fqdn": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "country": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "cache_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "color": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "obj_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "tagging": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "category": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "tags": {
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
            },
            "v_range": [["v6.0.0", ""]],
        },
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "template": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "subnet_segment": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "any"}, {"value": "specific"}],
                },
                "value": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "host_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "any"}, {"value": "specific"}],
        },
        "host": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "tenant": {"v_range": [["v7.2.1", ""]], "type": "string"},
        "epg_name": {"v_range": [["v7.2.1", ""]], "type": "string"},
        "sdn_tag": {"v_range": [["v7.2.1", ""]], "type": "string"},
        "filter": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ip": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
                "obj_id": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
                "net_id": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "sdn_addr_type": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "private"}, {"value": "public"}, {"value": "all"}],
        },
        "fabric_object": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "start_mac": {
            "v_range": [
                ["v6.2.0", "v6.2.0"],
                ["v6.2.5", "v6.4.0"],
                ["v6.4.4", "v6.4.4"],
            ],
            "type": "string",
        },
        "end_mac": {
            "v_range": [
                ["v6.2.0", "v6.2.0"],
                ["v6.2.5", "v6.4.0"],
                ["v6.4.4", "v6.4.4"],
            ],
            "type": "string",
        },
        "visibility": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
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
        "firewall_address6": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_address6"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_address6"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "firewall_address6"
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
