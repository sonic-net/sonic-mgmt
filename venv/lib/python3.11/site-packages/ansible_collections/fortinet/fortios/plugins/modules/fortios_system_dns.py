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
module: fortios_system_dns
short_description: Configure DNS in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and dns category.
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

    system_dns:
        description:
            - Configure DNS.
        default: null
        type: dict
        suboptions:
            alt_primary:
                description:
                    - Alternate primary DNS server. This is not used as a failover DNS server.
                type: str
            alt_secondary:
                description:
                    - Alternate secondary DNS server. This is not used as a failover DNS server.
                type: str
            cache_notfound_responses:
                description:
                    - Enable/disable response from the DNS server when a record is not in cache.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            dns_cache_limit:
                description:
                    - Maximum number of records in the DNS cache.
                type: int
            dns_cache_ttl:
                description:
                    - Duration in seconds that the DNS cache retains information.
                type: int
            dns_over_tls:
                description:
                    - Enable/disable/enforce DNS over TLS.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
                    - 'enforce'
            domain:
                description:
                    - Search suffix list for hostname lookup.
                type: list
                elements: dict
                suboptions:
                    domain:
                        description:
                            - DNS search domain list separated by space (maximum 8 domains).
                        required: true
                        type: str
            fqdn_cache_ttl:
                description:
                    - FQDN cache time to live in seconds (0 - 86400).
                type: int
            fqdn_max_refresh:
                description:
                    - FQDN cache maximum refresh time in seconds (3600 - 86400).
                type: int
            fqdn_min_refresh:
                description:
                    - FQDN cache minimum refresh time in seconds (10 - 3600).
                type: int
            hostname_limit:
                description:
                    - Limit of the number of hostname table entries (0 - 50000).
                type: int
            hostname_ttl:
                description:
                    - TTL of hostname table entries (60 - 86400).
                type: int
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
            ip6_primary:
                description:
                    - Primary DNS server IPv6 address.
                type: str
            ip6_secondary:
                description:
                    - Secondary DNS server IPv6 address.
                type: str
            log:
                description:
                    - Local DNS log setting.
                type: str
                choices:
                    - 'disable'
                    - 'error'
                    - 'all'
            primary:
                description:
                    - Primary DNS server IP address.
                type: str
            protocol:
                description:
                    - DNS transport protocols.
                type: list
                elements: str
                choices:
                    - 'cleartext'
                    - 'dot'
                    - 'doh'
            retry:
                description:
                    - Number of times to retry (0 - 5).
                type: int
            root_servers:
                description:
                    - Configure up to two preferred servers that serve the DNS root zone .
                type: list
                elements: str
            secondary:
                description:
                    - Secondary DNS server IP address.
                type: str
            server_hostname:
                description:
                    - DNS server host name list.
                type: list
                elements: dict
                suboptions:
                    hostname:
                        description:
                            - DNS server host name list separated by space (maximum 4 domains).
                        required: true
                        type: str
            server_select_method:
                description:
                    - Specify how configured servers are prioritized.
                type: str
                choices:
                    - 'least-rtt'
                    - 'failover'
            source_ip:
                description:
                    - IP address used by the DNS server as its source IP.
                type: str
            source_ip_interface:
                description:
                    - IP address of the specified interface as the source IP address. Source system.interface.name.
                type: str
            ssl_certificate:
                description:
                    - Name of local certificate for SSL connections. Source certificate.local.name.
                type: str
            timeout:
                description:
                    - DNS query timeout interval in seconds (1 - 10).
                type: int
            vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
"""

EXAMPLES = """
- name: Configure DNS.
  fortinet.fortios.fortios_system_dns:
      vdom: "{{ vdom }}"
      system_dns:
          alt_primary: "<your_own_value>"
          alt_secondary: "<your_own_value>"
          cache_notfound_responses: "disable"
          dns_cache_limit: "5000"
          dns_cache_ttl: "1800"
          dns_over_tls: "disable"
          domain:
              -
                  domain: "<your_own_value>"
          fqdn_cache_ttl: "0"
          fqdn_max_refresh: "3600"
          fqdn_min_refresh: "60"
          hostname_limit: "5000"
          hostname_ttl: "86400"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          ip6_primary: "<your_own_value>"
          ip6_secondary: "<your_own_value>"
          log: "disable"
          primary: "<your_own_value>"
          protocol: "cleartext"
          retry: "2"
          root_servers: "<your_own_value>"
          secondary: "<your_own_value>"
          server_hostname:
              -
                  hostname: "myhostname"
          server_select_method: "least-rtt"
          source_ip: "84.230.14.43"
          source_ip_interface: "<your_own_value> (source system.interface.name)"
          ssl_certificate: "<your_own_value> (source certificate.local.name)"
          timeout: "5"
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


def filter_system_dns_data(json):
    option_list = [
        "alt_primary",
        "alt_secondary",
        "cache_notfound_responses",
        "dns_cache_limit",
        "dns_cache_ttl",
        "dns_over_tls",
        "domain",
        "fqdn_cache_ttl",
        "fqdn_max_refresh",
        "fqdn_min_refresh",
        "hostname_limit",
        "hostname_ttl",
        "interface",
        "interface_select_method",
        "ip6_primary",
        "ip6_secondary",
        "log",
        "primary",
        "protocol",
        "retry",
        "root_servers",
        "secondary",
        "server_hostname",
        "server_select_method",
        "source_ip",
        "source_ip_interface",
        "ssl_certificate",
        "timeout",
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
        ["protocol"],
        ["root_servers"],
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


def system_dns(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_dns_data = data["system_dns"]

    filtered_data = filter_system_dns_data(system_dns_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "dns", filtered_data, vdom=vdom)
        current_data = fos.get("system", "dns", vdom=vdom, mkey=mkey)
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
    data_copy["system_dns"] = filtered_data
    fos.do_member_operation(
        "system",
        "dns",
        data_copy,
    )

    return fos.set("system", "dns", data=converted_data, vdom=vdom)


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

    if data["system_dns"]:
        resp = system_dns(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_dns"))
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
        "primary": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "secondary": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "protocol": {
            "v_range": [["v7.0.0", ""]],
            "type": "list",
            "options": [{"value": "cleartext"}, {"value": "dot"}, {"value": "doh"}],
            "multiple_values": True,
            "elements": "str",
        },
        "ssl_certificate": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "server_hostname": {
            "type": "list",
            "elements": "dict",
            "children": {
                "hostname": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", ""]],
        },
        "domain": {
            "type": "list",
            "elements": "dict",
            "children": {
                "domain": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ip6_primary": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip6_secondary": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "retry": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dns_cache_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dns_cache_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "cache_notfound_responses": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "source_ip_interface": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "root_servers": {
            "v_range": [["v7.6.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "interface_select_method": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
        },
        "vrf_select": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "server_select_method": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "least-rtt"}, {"value": "failover"}],
        },
        "alt_primary": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "alt_secondary": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "log": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "error"}, {"value": "all"}],
        },
        "fqdn_cache_ttl": {"v_range": [["v7.2.1", ""]], "type": "integer"},
        "fqdn_max_refresh": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "fqdn_min_refresh": {"v_range": [["v7.2.1", ""]], "type": "integer"},
        "hostname_ttl": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "hostname_limit": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "dns_over_tls": {
            "v_range": [["v6.2.0", "v6.4.4"]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "enable"},
                {"value": "enforce"},
            ],
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
        "system_dns": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_dns"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_dns"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_dns"
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
