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
module: fortios_system_sdn_vpn
short_description: Configure public cloud VPN service in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and sdn_vpn category.
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
    system_sdn_vpn:
        description:
            - Configure public cloud VPN service.
        default: null
        type: dict
        suboptions:
            bgp_as:
                description:
                    - BGP Router AS number.
                type: int
            cgw_gateway:
                description:
                    - Public IP address of the customer gateway.
                type: str
            cgw_name:
                description:
                    - AWS customer gateway name to be created.
                type: str
            internal_interface:
                description:
                    - Internal interface with local subnet. Source system.interface.name.
                type: str
            local_cidr:
                description:
                    - Local subnet address and subnet mask.
                type: str
            name:
                description:
                    - Public cloud VPN name.
                required: true
                type: str
            nat_traversal:
                description:
                    - Enable/disable use for NAT traversal. Please enable if your FortiGate device is behind a NAT/PAT device.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            psksecret:
                description:
                    - Pre-shared secret for PSK authentication. Auto-generated if not specified
                type: str
            remote_cidr:
                description:
                    - Remote subnet address and subnet mask.
                type: str
            remote_type:
                description:
                    - Type of remote device.
                type: str
                choices:
                    - 'vgw'
                    - 'tgw'
            routing_type:
                description:
                    - Type of routing.
                type: str
                choices:
                    - 'static'
                    - 'dynamic'
            sdn:
                description:
                    - SDN connector name. Source system.sdn-connector.name.
                type: str
            subnet_id:
                description:
                    - AWS subnet id for TGW route propagation.
                type: str
            tgw_id:
                description:
                    - Transit gateway id.
                type: str
            tunnel_interface:
                description:
                    - Tunnel interface with public IP. Source system.interface.name.
                type: str
            vgw_id:
                description:
                    - Virtual private gateway id.
                type: str
"""

EXAMPLES = """
- name: Configure public cloud VPN service.
  fortinet.fortios.fortios_system_sdn_vpn:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_sdn_vpn:
          bgp_as: "65000"
          cgw_gateway: "<your_own_value>"
          cgw_name: "<your_own_value>"
          internal_interface: "<your_own_value> (source system.interface.name)"
          local_cidr: "<your_own_value>"
          name: "default_name_8"
          nat_traversal: "disable"
          psksecret: "<your_own_value>"
          remote_cidr: "<your_own_value>"
          remote_type: "vgw"
          routing_type: "static"
          sdn: "<your_own_value> (source system.sdn-connector.name)"
          subnet_id: "<your_own_value>"
          tgw_id: "<your_own_value>"
          tunnel_interface: "<your_own_value> (source system.interface.name)"
          vgw_id: "<your_own_value>"
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


def filter_system_sdn_vpn_data(json):
    option_list = [
        "bgp_as",
        "cgw_gateway",
        "cgw_name",
        "internal_interface",
        "local_cidr",
        "name",
        "nat_traversal",
        "psksecret",
        "remote_cidr",
        "remote_type",
        "routing_type",
        "sdn",
        "subnet_id",
        "tgw_id",
        "tunnel_interface",
        "vgw_id",
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


def system_sdn_vpn(data, fos):
    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_sdn_vpn_data = data["system_sdn_vpn"]

    filtered_data = filter_system_sdn_vpn_data(system_sdn_vpn_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["system_sdn_vpn"] = filtered_data
    fos.do_member_operation(
        "system",
        "sdn-vpn",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "sdn-vpn", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("system", "sdn-vpn", mkey=converted_data["name"], vdom=vdom)
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


def fortios_system(data, fos):

    if data["system_sdn_vpn"]:
        resp = system_sdn_vpn(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_sdn_vpn"))

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
        "sdn": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "remote_type": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "vgw"}, {"value": "tgw"}],
        },
        "routing_type": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "static"}, {"value": "dynamic"}],
        },
        "vgw_id": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "tgw_id": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "subnet_id": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "bgp_as": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "cgw_gateway": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "nat_traversal": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "tunnel_interface": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "internal_interface": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "local_cidr": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "remote_cidr": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "cgw_name": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "psksecret": {"v_range": [["v7.6.1", ""]], "type": "string"},
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
        "system_sdn_vpn": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_sdn_vpn"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_sdn_vpn"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_sdn_vpn"
        )

        is_error, has_changed, result, diff = fortios_system(module.params, fos)

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
