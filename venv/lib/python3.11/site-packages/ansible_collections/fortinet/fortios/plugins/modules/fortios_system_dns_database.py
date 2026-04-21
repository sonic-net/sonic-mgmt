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
module: fortios_system_dns_database
short_description: Configure DNS databases in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and dns_database category.
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
    system_dns_database:
        description:
            - Configure DNS databases.
        default: null
        type: dict
        suboptions:
            allow_transfer:
                description:
                    - DNS zone transfer IP address list.
                type: list
                elements: str
            authoritative:
                description:
                    - Enable/disable authoritative zone.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            contact:
                description:
                    - Email address of the administrator for this zone. You can specify only the username, such as admin or the full email address, such as
                       admin@test.com When using only a username, the domain of the email will be this zone.
                type: str
            dns_entry:
                description:
                    - DNS entry.
                type: list
                elements: dict
                suboptions:
                    canonical_name:
                        description:
                            - Canonical name of the host.
                        type: str
                    hostname:
                        description:
                            - Name of the host.
                        type: str
                    id:
                        description:
                            - DNS entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ip:
                        description:
                            - IPv4 address of the host.
                        type: str
                    ipv6:
                        description:
                            - IPv6 address of the host.
                        type: str
                    preference:
                        description:
                            - DNS entry preference (0 - 65535, highest preference = 0).
                        type: int
                    status:
                        description:
                            - Enable/disable resource record status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ttl:
                        description:
                            - Time-to-live for this entry (0 to 2147483647 sec).
                        type: int
                    type:
                        description:
                            - Resource record type.
                        type: str
                        choices:
                            - 'A'
                            - 'NS'
                            - 'CNAME'
                            - 'MX'
                            - 'AAAA'
                            - 'PTR'
                            - 'PTR_V6'
            domain:
                description:
                    - Domain name.
                type: str
            forwarder:
                description:
                    - DNS zone forwarder IP address list.
                type: list
                elements: str
            forwarder6:
                description:
                    - Forwarder IPv6 address.
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
            ip_master:
                description:
                    - IP address of master DNS server. Entries in this master DNS server and imported into the DNS zone.
                type: str
            ip_primary:
                description:
                    - IP address of primary DNS server. Entries in this primary DNS server and imported into the DNS zone.
                type: str
            name:
                description:
                    - Zone name.
                required: true
                type: str
            primary_name:
                description:
                    - Domain name of the default DNS server for this zone.
                type: str
            rr_max:
                description:
                    - Maximum number of resource records (10 - 65536, 0 means infinite).
                type: int
            source_ip:
                description:
                    - Source IP for forwarding to DNS server.
                type: str
            source_ip_interface:
                description:
                    - IP address of the specified interface as the source IP address. Source system.interface.name.
                type: str
            source_ip6:
                description:
                    - IPv6 source IP address for forwarding to DNS server.
                type: str
            status:
                description:
                    - Enable/disable this DNS zone.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ttl:
                description:
                    - Default time-to-live value for the entries of this DNS zone (0 - 2147483647 sec).
                type: int
            type:
                description:
                    - Zone type (primary to manage entries directly, secondary to import entries from other zones).
                type: str
                choices:
                    - 'primary'
                    - 'secondary'
                    - 'master'
                    - 'slave'
            view:
                description:
                    - Zone view (public to serve public clients, shadow to serve internal clients).
                type: str
                choices:
                    - 'shadow'
                    - 'public'
                    - 'shadow-ztna'
                    - 'proxy'
            vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
"""

EXAMPLES = """
- name: Configure DNS databases.
  fortinet.fortios.fortios_system_dns_database:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_dns_database:
          allow_transfer: "<your_own_value>"
          authoritative: "enable"
          contact: "<your_own_value>"
          dns_entry:
              -
                  canonical_name: "<your_own_value>"
                  hostname: "myhostname"
                  id: "9"
                  ip: "<your_own_value>"
                  ipv6: "<your_own_value>"
                  preference: "10"
                  status: "enable"
                  ttl: "0"
                  type: "A"
          domain: "<your_own_value>"
          forwarder: "<your_own_value>"
          forwarder6: "<your_own_value>"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          ip_master: "<your_own_value>"
          ip_primary: "<your_own_value>"
          name: "default_name_23"
          primary_name: "<your_own_value>"
          rr_max: "16384"
          source_ip: "84.230.14.43"
          source_ip_interface: "<your_own_value> (source system.interface.name)"
          source_ip6: "<your_own_value>"
          status: "enable"
          ttl: "86400"
          type: "primary"
          view: "shadow"
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


def filter_system_dns_database_data(json):
    option_list = [
        "allow_transfer",
        "authoritative",
        "contact",
        "dns_entry",
        "domain",
        "forwarder",
        "forwarder6",
        "interface",
        "interface_select_method",
        "ip_master",
        "ip_primary",
        "name",
        "primary_name",
        "rr_max",
        "source_ip",
        "source_ip_interface",
        "source_ip6",
        "status",
        "ttl",
        "type",
        "view",
        "vrf_select",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or (not data[path[index]] and not isinstance(data[path[index]], list))
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
        if len(data[path[index]]) == 0:
            data[path[index]] = None
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["allow_transfer"],
        ["forwarder"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


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


def system_dns_database(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_dns_database_data = data["system_dns_database"]

    filtered_data = filter_system_dns_database_data(system_dns_database_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "dns-database", filtered_data, vdom=vdom)
        current_data = fos.get("system", "dns-database", vdom=vdom, mkey=mkey)
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
    data_copy["system_dns_database"] = filtered_data
    fos.do_member_operation(
        "system",
        "dns-database",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "dns-database", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system", "dns-database", mkey=converted_data["name"], vdom=vdom
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

    if data["system_dns_database"]:
        resp = system_dns_database(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_dns_database"))
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
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "domain": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "allow_transfer": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "primary", "v_range": [["v7.0.0", ""]]},
                {"value": "secondary", "v_range": [["v7.0.0", ""]]},
                {"value": "master", "v_range": [["v6.0.0", "v6.4.4"]]},
                {"value": "slave", "v_range": [["v6.0.0", "v6.4.4"]]},
            ],
        },
        "view": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "shadow"},
                {"value": "public"},
                {"value": "shadow-ztna", "v_range": [["v7.2.1", ""]]},
                {"value": "proxy", "v_range": [["v7.4.1", ""]]},
            ],
        },
        "ip_primary": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "primary_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "contact": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "authoritative": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forwarder": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "forwarder6": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "source_ip6": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "source_ip_interface": {"v_range": [["v7.6.0", ""]], "type": "string"},
        "rr_max": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "dns_entry": {
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
                "type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "A"},
                        {"value": "NS"},
                        {"value": "CNAME"},
                        {"value": "MX"},
                        {"value": "AAAA"},
                        {"value": "PTR"},
                        {"value": "PTR_V6"},
                    ],
                },
                "ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "preference": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ipv6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "hostname": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "canonical_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "interface_select_method": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "vrf_select": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "ip_master": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
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
        "system_dns_database": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_dns_database"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_dns_database"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_dns_database"
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
