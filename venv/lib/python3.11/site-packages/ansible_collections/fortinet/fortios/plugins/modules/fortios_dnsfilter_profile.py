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
module: fortios_dnsfilter_profile
short_description: Configure DNS domain filter profile in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify dnsfilter feature and profile category.
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
    dnsfilter_profile:
        description:
            - Configure DNS domain filter profile.
        default: null
        type: dict
        suboptions:
            block_action:
                description:
                    - Action to take for blocked domains.
                type: str
                choices:
                    - 'block'
                    - 'redirect'
                    - 'block-sevrfail'
            block_botnet:
                description:
                    - Enable/disable blocking botnet C&C DNS lookups.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                description:
                    - Comment.
                type: str
            dns_translation:
                description:
                    - DNS translation settings.
                type: list
                elements: dict
                suboptions:
                    addr_type:
                        description:
                            - DNS translation type (IPv4 or IPv6).
                        type: str
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                    dst:
                        description:
                            - IPv4 address or subnet on the external network to substitute for the resolved address in DNS query replies. Can be single IP
                               address or subnet on the external network, but number of addresses must equal number of mapped IP addresses in src.
                        type: str
                    dst6:
                        description:
                            - IPv6 address or subnet on the external network to substitute for the resolved address in DNS query replies. Can be single IP
                               address or subnet on the external network, but number of addresses must equal number of mapped IP addresses in src6.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    netmask:
                        description:
                            - If src and dst are subnets rather than single IP addresses, enter the netmask for both src and dst.
                        type: str
                    prefix:
                        description:
                            - If src6 and dst6 are subnets rather than single IP addresses, enter the prefix for both src6 and dst6 (1 - 128).
                        type: int
                    src:
                        description:
                            - IPv4 address or subnet on the internal network to compare with the resolved address in DNS query replies. If the resolved
                               address matches, the resolved address is substituted with dst.
                        type: str
                    src6:
                        description:
                            - IPv6 address or subnet on the internal network to compare with the resolved address in DNS query replies. If the resolved
                               address matches, the resolved address is substituted with dst6.
                        type: str
                    status:
                        description:
                            - Enable/disable this DNS translation entry.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            domain_filter:
                description:
                    - Domain filter settings.
                type: dict
                suboptions:
                    domain_filter_table:
                        description:
                            - DNS domain filter table ID. Source dnsfilter.domain-filter.id.
                        type: int
            external_ip_blocklist:
                description:
                    - One or more external IP block lists.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - External domain block list name. Source system.external-resource.name.
                        required: true
                        type: str
            ftgd_dns:
                description:
                    - FortiGuard DNS Filter settings.
                type: dict
                suboptions:
                    filters:
                        description:
                            - FortiGuard DNS domain filters.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                description:
                                    - Action to take for DNS requests matching the category.
                                type: str
                                choices:
                                    - 'block'
                                    - 'monitor'
                            category:
                                description:
                                    - Category number.
                                type: int
                            id:
                                description:
                                    - ID number. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            log:
                                description:
                                    - Enable/disable DNS filter logging for this DNS profile.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    options:
                        description:
                            - FortiGuard DNS filter options.
                        type: list
                        elements: str
                        choices:
                            - 'error-allow'
                            - 'ftgd-disable'
            log_all_domain:
                description:
                    - Enable/disable logging of all domains visited (detailed DNS logging).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            redirect_portal:
                description:
                    - IPv4 address of the SDNS redirect portal.
                type: str
            redirect_portal6:
                description:
                    - IPv6 address of the SDNS redirect portal.
                type: str
            safe_search:
                description:
                    - Enable/disable Google, Bing, YouTube, Qwant, DuckDuckGo safe search.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            sdns_domain_log:
                description:
                    - Enable/disable domain filtering and botnet domain logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sdns_ftgd_err_log:
                description:
                    - Enable/disable FortiGuard SDNS rating error logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            strip_ech:
                description:
                    - Enable/disable removal of the encrypted client hello service parameter from supporting DNS RRs.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            transparent_dns_database:
                description:
                    - Transparent DNS database zones.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - DNS database zone name. Source system.dns-database.name.
                        required: true
                        type: str
            youtube_restrict:
                description:
                    - Set safe search for YouTube restriction level.
                type: str
                choices:
                    - 'strict'
                    - 'moderate'
                    - 'none'
"""

EXAMPLES = """
- name: Configure DNS domain filter profile.
  fortinet.fortios.fortios_dnsfilter_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      dnsfilter_profile:
          block_action: "block"
          block_botnet: "disable"
          comment: "Comment."
          dns_translation:
              -
                  addr_type: "ipv4"
                  dst: "<your_own_value>"
                  dst6: "<your_own_value>"
                  id: "10"
                  netmask: "<your_own_value>"
                  prefix: "128"
                  src: "<your_own_value>"
                  src6: "<your_own_value>"
                  status: "enable"
          domain_filter:
              domain_filter_table: "0"
          external_ip_blocklist:
              -
                  name: "default_name_19 (source system.external-resource.name)"
          ftgd_dns:
              filters:
                  -
                      action: "block"
                      category: "0"
                      id: "24"
                      log: "enable"
              options: "error-allow"
          log_all_domain: "enable"
          name: "default_name_28"
          redirect_portal: "<your_own_value>"
          redirect_portal6: "<your_own_value>"
          safe_search: "disable"
          sdns_domain_log: "enable"
          sdns_ftgd_err_log: "enable"
          strip_ech: "disable"
          transparent_dns_database:
              -
                  name: "default_name_36 (source system.dns-database.name)"
          youtube_restrict: "strict"
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


def filter_dnsfilter_profile_data(json):
    option_list = [
        "block_action",
        "block_botnet",
        "comment",
        "dns_translation",
        "domain_filter",
        "external_ip_blocklist",
        "ftgd_dns",
        "log_all_domain",
        "name",
        "redirect_portal",
        "redirect_portal6",
        "safe_search",
        "sdns_domain_log",
        "sdns_ftgd_err_log",
        "strip_ech",
        "transparent_dns_database",
        "youtube_restrict",
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
        ["ftgd_dns", "options"],
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


def dnsfilter_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    dnsfilter_profile_data = data["dnsfilter_profile"]

    filtered_data = filter_dnsfilter_profile_data(dnsfilter_profile_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("dnsfilter", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("dnsfilter", "profile", vdom=vdom, mkey=mkey)
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
    data_copy["dnsfilter_profile"] = filtered_data
    fos.do_member_operation(
        "dnsfilter",
        "profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("dnsfilter", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "dnsfilter", "profile", mkey=converted_data["name"], vdom=vdom
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


def fortios_dnsfilter(data, fos, check_mode):

    if data["dnsfilter_profile"]:
        resp = dnsfilter_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("dnsfilter_profile"))
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
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "domain_filter": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "domain_filter_table": {"v_range": [["v6.0.0", ""]], "type": "integer"}
            },
        },
        "ftgd_dns": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "options": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [{"value": "error-allow"}, {"value": "ftgd-disable"}],
                    "multiple_values": True,
                    "elements": "str",
                },
                "filters": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "category": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                        "action": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "block"}, {"value": "monitor"}],
                        },
                        "log": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
        },
        "log_all_domain": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sdns_ftgd_err_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sdns_domain_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "block_action": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "block"},
                {"value": "redirect"},
                {"value": "block-sevrfail", "v_range": [["v7.0.2", ""]]},
            ],
        },
        "redirect_portal": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "redirect_portal6": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "block_botnet": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "safe_search": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "youtube_restrict": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "strict"},
                {"value": "moderate"},
                {"value": "none", "v_range": [["v7.4.4", ""]]},
            ],
        },
        "external_ip_blocklist": {
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
        "dns_translation": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "addr_type": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "ipv4"}, {"value": "ipv6"}],
                },
                "src": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "dst": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "netmask": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "status": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "src6": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "dst6": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "prefix": {"v_range": [["v6.2.0", ""]], "type": "integer"},
            },
            "v_range": [["v6.2.0", ""]],
        },
        "transparent_dns_database": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.1", ""]],
        },
        "strip_ech": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
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
        "dnsfilter_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["dnsfilter_profile"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["dnsfilter_profile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "dnsfilter_profile"
        )

        is_error, has_changed, result, diff = fortios_dnsfilter(
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
