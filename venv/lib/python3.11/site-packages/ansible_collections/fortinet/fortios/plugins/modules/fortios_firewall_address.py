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
module: fortios_firewall_address
short_description: Configure IPv4 addresses in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and address category.
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
    firewall_address:
        description:
            - Configure IPv4 addresses.
        default: null
        type: dict
        suboptions:
            agent_id:
                description:
                    - Telemetry agent id. Source telemetry-controller.agent.agent-id.
                type: str
            allow_routing:
                description:
                    - Enable/disable use of this address in routing configurations.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            associated_interface:
                description:
                    - Network interface associated with address. Source system.interface.name system.zone.name.
                type: str
            cache_ttl:
                description:
                    - Defines the minimal TTL of individual IP addresses in FQDN cache measured in seconds.
                type: int
            clearpass_spt:
                description:
                    - SPT (System Posture Token) value.
                type: str
                choices:
                    - 'unknown'
                    - 'healthy'
                    - 'quarantine'
                    - 'checkup'
                    - 'transient'
                    - 'infected'
            color:
                description:
                    - Color of icon on the GUI.
                type: int
            comment:
                description:
                    - Comment.
                type: str
            country:
                description:
                    - IP addresses associated to a specific country.
                type: str
            end_ip:
                description:
                    - Final IP address (inclusive) in the range for the address.
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
                    - Fully Qualified Domain Name address.
                type: str
            fsso_group:
                description:
                    - FSSO group(s).
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - FSSO group name. Source user.adgrp.name.
                        required: true
                        type: str
            hw_model:
                description:
                    - Dynamic address matching hardware model.
                type: str
            hw_vendor:
                description:
                    - Dynamic address matching hardware vendor.
                type: str
            interface:
                description:
                    - Name of interface whose IP address is to be used. Source system.interface.name.
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
            node_ip_only:
                description:
                    - Enable/disable collection of node addresses only in Kubernetes.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            obj_id:
                description:
                    - Object ID for NSX.
                type: str
            obj_tag:
                description:
                    - Tag of dynamic address object.
                type: str
            obj_type:
                description:
                    - Object type.
                type: str
                choices:
                    - 'ip'
                    - 'mac'
            organization:
                description:
                    - 'Organization domain name (Syntax: organization/domain).'
                type: str
            os:
                description:
                    - Dynamic address matching operating system.
                type: str
            policy_group:
                description:
                    - Policy group name.
                type: str
            route_tag:
                description:
                    - route-tag address.
                type: int
            sdn:
                description:
                    - SDN. Source system.sdn-connector.name.
                type: str
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
            sso_attribute_value:
                description:
                    - RADIUS attributes value.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - RADIUS attribute value.
                        required: true
                        type: str
            start_ip:
                description:
                    - First IP address (inclusive) in the range for the address.
                type: str
            start_mac:
                description:
                    - First MAC address in the range.
                type: str
            sub_type:
                description:
                    - Sub-type of address.
                type: str
                choices:
                    - 'sdn'
                    - 'clearpass-spt'
                    - 'fsso'
                    - 'rsso'
                    - 'ems-tag'
                    - 'fortivoice-tag'
                    - 'fortinac-tag'
                    - 'swc-tag'
                    - 'device-identification'
                    - 'external-resource'
                    - 'telemetry'
                    - 'obsolete'
                    - 'fortipolicy-tag'
            subnet:
                description:
                    - IP address and subnet mask of address.
                type: str
            subnet_name:
                description:
                    - Subnet name.
                type: str
            sw_version:
                description:
                    - Dynamic address matching software version.
                type: str
            tag_detection_level:
                description:
                    - Tag detection level of dynamic address object.
                type: str
            tag_type:
                description:
                    - Tag type of dynamic address object.
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
            tenant:
                description:
                    - Tenant.
                type: str
            type:
                description:
                    - Type of address.
                type: str
                choices:
                    - 'ipmask'
                    - 'iprange'
                    - 'fqdn'
                    - 'geography'
                    - 'wildcard'
                    - 'dynamic'
                    - 'interface-subnet'
                    - 'mac'
                    - 'route-tag'
                    - 'wildcard-fqdn'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            visibility:
                description:
                    - Enable/disable address visibility in the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wildcard:
                description:
                    - IP address and wildcard netmask.
                type: str
            wildcard_fqdn:
                description:
                    - Fully Qualified Domain Name with wildcard characters.
                type: str
"""

EXAMPLES = """
- name: Configure IPv4 addresses.
  fortinet.fortios.fortios_firewall_address:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_address:
          agent_id: "<your_own_value> (source telemetry-controller.agent.agent-id)"
          allow_routing: "enable"
          associated_interface: "<your_own_value> (source system.interface.name system.zone.name)"
          cache_ttl: "0"
          clearpass_spt: "unknown"
          color: "0"
          comment: "Comment."
          country: "<your_own_value>"
          end_ip: "<your_own_value>"
          end_mac: "<your_own_value>"
          epg_name: "<your_own_value>"
          fabric_object: "enable"
          filter: "<your_own_value>"
          fqdn: "<your_own_value>"
          fsso_group:
              -
                  name: "default_name_18 (source user.adgrp.name)"
          hw_model: "<your_own_value>"
          hw_vendor: "<your_own_value>"
          interface: "<your_own_value> (source system.interface.name)"
          list:
              -
                  ip: "<your_own_value>"
                  net_id: "<your_own_value>"
                  obj_id: "<your_own_value>"
          macaddr:
              -
                  macaddr: "<your_own_value>"
          name: "default_name_28"
          node_ip_only: "enable"
          obj_id: "<your_own_value>"
          obj_tag: "<your_own_value>"
          obj_type: "ip"
          organization: "<your_own_value>"
          os: "<your_own_value>"
          policy_group: "<your_own_value>"
          route_tag: "0"
          sdn: "<your_own_value> (source system.sdn-connector.name)"
          sdn_addr_type: "private"
          sdn_tag: "<your_own_value>"
          sso_attribute_value:
              -
                  name: "default_name_41"
          start_ip: "<your_own_value>"
          start_mac: "<your_own_value>"
          sub_type: "sdn"
          subnet: "<your_own_value>"
          subnet_name: "<your_own_value>"
          sw_version: "<your_own_value>"
          tag_detection_level: "<your_own_value>"
          tag_type: "<your_own_value>"
          tagging:
              -
                  category: "<your_own_value> (source system.object-tagging.category)"
                  name: "default_name_52"
                  tags:
                      -
                          name: "default_name_54 (source system.object-tagging.tags.name)"
          tenant: "<your_own_value>"
          type: "ipmask"
          uuid: "<your_own_value>"
          visibility: "enable"
          wildcard: "<your_own_value>"
          wildcard_fqdn: "<your_own_value>"
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


def filter_firewall_address_data(json):
    option_list = [
        "agent_id",
        "allow_routing",
        "associated_interface",
        "cache_ttl",
        "clearpass_spt",
        "color",
        "comment",
        "country",
        "end_ip",
        "end_mac",
        "epg_name",
        "fabric_object",
        "filter",
        "fqdn",
        "fsso_group",
        "hw_model",
        "hw_vendor",
        "interface",
        "list",
        "macaddr",
        "name",
        "node_ip_only",
        "obj_id",
        "obj_tag",
        "obj_type",
        "organization",
        "os",
        "policy_group",
        "route_tag",
        "sdn",
        "sdn_addr_type",
        "sdn_tag",
        "sso_attribute_value",
        "start_ip",
        "start_mac",
        "sub_type",
        "subnet",
        "subnet_name",
        "sw_version",
        "tag_detection_level",
        "tag_type",
        "tagging",
        "tenant",
        "type",
        "uuid",
        "visibility",
        "wildcard",
        "wildcard_fqdn",
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


def firewall_address(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_address_data = data["firewall_address"]

    filtered_data = filter_firewall_address_data(firewall_address_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "address", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "address", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_address"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "address",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "address", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("firewall", "address", mkey=converted_data["name"], vdom=vdom)
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

    if data["firewall_address"]:
        resp = firewall_address(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_address"))
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
        "subnet": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "ipmask"},
                {"value": "iprange"},
                {"value": "fqdn"},
                {"value": "geography"},
                {"value": "wildcard"},
                {"value": "dynamic"},
                {"value": "interface-subnet", "v_range": [["v6.2.0", ""]]},
                {"value": "mac", "v_range": [["v6.2.0", ""]]},
                {"value": "route-tag", "v_range": [["v7.4.0", ""]]},
                {"value": "wildcard-fqdn", "v_range": [["v6.0.0", "v6.0.11"]]},
            ],
        },
        "route_tag": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "sub_type": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "sdn"},
                {"value": "clearpass-spt"},
                {"value": "fsso"},
                {"value": "rsso", "v_range": [["v7.6.1", ""]]},
                {"value": "ems-tag", "v_range": [["v6.4.0", ""]]},
                {"value": "fortivoice-tag", "v_range": [["v7.0.4", ""]]},
                {"value": "fortinac-tag", "v_range": [["v7.0.4", ""]]},
                {"value": "swc-tag", "v_range": [["v7.0.1", ""]]},
                {"value": "device-identification", "v_range": [["v7.4.0", ""]]},
                {"value": "external-resource", "v_range": [["v7.6.1", ""]]},
                {"value": "telemetry", "v_range": [["v7.6.4", ""]]},
                {"value": "obsolete", "v_range": [["v7.6.3", ""]]},
                {"value": "fortipolicy-tag", "v_range": [["v7.2.4", "v7.6.2"]]},
            ],
        },
        "clearpass_spt": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "unknown"},
                {"value": "healthy"},
                {"value": "quarantine"},
                {"value": "checkup"},
                {"value": "transient"},
                {"value": "infected"},
            ],
        },
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
        "start_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "end_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "fqdn": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "country": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "wildcard_fqdn": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "cache_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "wildcard": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sdn": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "fsso_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", ""]],
        },
        "sso_attribute_value": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.1", ""]],
        },
        "interface": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "tenant": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "organization": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "epg_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "subnet_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sdn_tag": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "policy_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "obj_tag": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "obj_type": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "ip"}, {"value": "mac"}],
        },
        "tag_detection_level": {"v_range": [["v7.0.4", ""]], "type": "string"},
        "tag_type": {"v_range": [["v7.0.4", ""]], "type": "string"},
        "hw_vendor": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "hw_model": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "os": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "sw_version": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "agent_id": {"v_range": [["v7.6.4", ""]], "type": "string"},
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "associated_interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "color": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "filter": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sdn_addr_type": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "private"}, {"value": "public"}, {"value": "all"}],
        },
        "node_ip_only": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "obj_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
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
        "allow_routing": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fabric_object": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "start_mac": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
        "end_mac": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
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
        "firewall_address": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_address"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_address"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "firewall_address"
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
