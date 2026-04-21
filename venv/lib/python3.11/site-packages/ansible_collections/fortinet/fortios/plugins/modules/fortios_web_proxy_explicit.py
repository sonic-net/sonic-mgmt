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
module: fortios_web_proxy_explicit
short_description: Configure explicit Web proxy settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify web_proxy feature and explicit category.
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

    web_proxy_explicit:
        description:
            - Configure explicit Web proxy settings.
        default: null
        type: dict
        suboptions:
            client_cert:
                description:
                    - Enable/disable to request client certificate.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            empty_cert_action:
                description:
                    - Action of an empty client certificate.
                type: str
                choices:
                    - 'accept'
                    - 'block'
                    - 'accept-unmanageable'
            ftp_incoming_port:
                description:
                    - Accept incoming FTP-over-HTTP requests on one or more ports (0 - 65535).
                type: str
            ftp_over_http:
                description:
                    - Enable to proxy FTP-over-HTTP sessions sent from a web browser.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            http_connection_mode:
                description:
                    - HTTP connection mode .
                type: str
                choices:
                    - 'static'
                    - 'multiplex'
                    - 'serverpool'
            http_incoming_port:
                description:
                    - Accept incoming HTTP requests on one or more ports (0 - 65535).
                type: str
            https_incoming_port:
                description:
                    - Accept incoming HTTPS requests on one or more ports (0 - 65535).
                type: str
            https_replacement_message:
                description:
                    - Enable/disable sending the client a replacement message for HTTPS requests.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            incoming_ip:
                description:
                    - Restrict the explicit HTTP proxy to only accept sessions from this IP address. An interface must have this IP address.
                type: str
            incoming_ip6:
                description:
                    - Restrict the explicit web proxy to only accept sessions from this IPv6 address. An interface must have this IPv6 address.
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
                    - 'sdwan'
                    - 'specify'
            ipv6_status:
                description:
                    - Enable/disable allowing an IPv6 web proxy destination in policies and all IPv6 related entries in this command.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            message_upon_server_error:
                description:
                    - Enable/disable displaying a replacement message when a server error is detected.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            outgoing_ip:
                description:
                    - Outgoing HTTP requests will have this IP address as their source address. An interface must have this IP address.
                type: list
                elements: str
            outgoing_ip6:
                description:
                    - Outgoing HTTP requests will leave this IPv6. Multiple interfaces can be specified. Interfaces must have these IPv6 addresses.
                type: list
                elements: str
            pac_file_data:
                description:
                    - PAC file contents enclosed in quotes (maximum of 256K bytes).
                type: str
            pac_file_name:
                description:
                    - Pac file name.
                type: str
            pac_file_server_port:
                description:
                    - Port number that PAC traffic from client web browsers uses to connect to the explicit web proxy (0 - 65535).
                type: str
            pac_file_server_status:
                description:
                    - Enable/disable Proxy Auto-Configuration (PAC) for users of this explicit proxy profile.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pac_file_through_https:
                description:
                    - Enable/disable to get Proxy Auto-Configuration (PAC) through HTTPS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pac_file_url:
                description:
                    - PAC file access URL.
                type: str
            pac_policy:
                description:
                    - PAC policies.
                type: list
                elements: dict
                suboptions:
                    comments:
                        description:
                            - Optional comments.
                        type: str
                    dstaddr:
                        description:
                            - Destination address objects.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address name. Source firewall.address.name firewall.addrgrp.name.
                                required: true
                                type: str
                    pac_file_data:
                        description:
                            - PAC file contents enclosed in quotes (maximum of 256K bytes).
                        type: str
                    pac_file_name:
                        description:
                            - Pac file name.
                        type: str
                    policyid:
                        description:
                            - Policy ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    srcaddr:
                        description:
                            - Source address objects.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address name. Source firewall.address.name firewall.addrgrp.name firewall.proxy-address.name firewall.proxy-addrgrp.name.
                                required: true
                                type: str
                    srcaddr6:
                        description:
                            - Source address6 objects.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                                required: true
                                type: str
                    status:
                        description:
                            - Enable/disable policy.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            pref_dns_result:
                description:
                    - Prefer resolving addresses using the configured IPv4 or IPv6 DNS server .
                type: str
                choices:
                    - 'ipv4'
                    - 'ipv6'
                    - 'ipv4-strict'
                    - 'ipv6-strict'
            realm:
                description:
                    - Authentication realm used to identify the explicit web proxy (maximum of 63 characters).
                type: str
            sec_default_action:
                description:
                    - Accept or deny explicit web proxy sessions when no web proxy firewall policy exists.
                type: str
                choices:
                    - 'accept'
                    - 'deny'
            secure_web_proxy:
                description:
                    - Enable/disable/require the secure web proxy for HTTP and HTTPS session.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
                    - 'secure'
            secure_web_proxy_cert:
                description:
                    - Name of certificates for secure web proxy.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Certificate list. Source vpn.certificate.local.name.
                        required: true
                        type: str
            socks:
                description:
                    - Enable/disable the SOCKS proxy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            socks_incoming_port:
                description:
                    - Accept incoming SOCKS proxy requests on one or more ports (0 - 65535).
                type: str
            ssl_algorithm:
                description:
                    - 'Relative strength of encryption algorithms accepted in HTTPS deep scan: high, medium, or low.'
                type: str
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
            ssl_dh_bits:
                description:
                    - Bit-size of Diffie-Hellman (DH) prime used in DHE-RSA negotiation .
                type: str
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
            status:
                description:
                    - Enable/disable the explicit Web proxy for HTTP and HTTPS session.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            strict_guest:
                description:
                    - Enable/disable strict guest user checking by the explicit web proxy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            trace_auth_no_rsp:
                description:
                    - Enable/disable logging timed-out authentication requests.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            unknown_http_version:
                description:
                    - How to handle HTTP sessions that do not comply with HTTP 0.9, 1.0, or 1.1.
                type: str
                choices:
                    - 'reject'
                    - 'best-effort'
                    - 'tunnel'
            user_agent_detect:
                description:
                    - Enable/disable to detect device type by HTTP user-agent if no client certificate provided.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
"""

EXAMPLES = """
- name: Configure explicit Web proxy settings.
  fortinet.fortios.fortios_web_proxy_explicit:
      vdom: "{{ vdom }}"
      web_proxy_explicit:
          client_cert: "disable"
          empty_cert_action: "accept"
          ftp_incoming_port: "<your_own_value>"
          ftp_over_http: "enable"
          http_connection_mode: "static"
          http_incoming_port: "<your_own_value>"
          https_incoming_port: "<your_own_value>"
          https_replacement_message: "enable"
          incoming_ip: "<your_own_value>"
          incoming_ip6: "<your_own_value>"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "sdwan"
          ipv6_status: "enable"
          message_upon_server_error: "enable"
          outgoing_ip: "<your_own_value>"
          outgoing_ip6: "<your_own_value>"
          pac_file_data: "<your_own_value>"
          pac_file_name: "<your_own_value>"
          pac_file_server_port: "<your_own_value>"
          pac_file_server_status: "enable"
          pac_file_through_https: "enable"
          pac_file_url: "<your_own_value>"
          pac_policy:
              -
                  comments: "<your_own_value>"
                  dstaddr:
                      -
                          name: "default_name_28 (source firewall.address.name firewall.addrgrp.name)"
                  pac_file_data: "<your_own_value>"
                  pac_file_name: "<your_own_value>"
                  policyid: "<you_own_value>"
                  srcaddr:
                      -
                          name: "default_name_33 (source firewall.address.name firewall.addrgrp.name firewall.proxy-address.name firewall.proxy-addrgrp.name)"
                  srcaddr6:
                      -
                          name: "default_name_35 (source firewall.address6.name firewall.addrgrp6.name)"
                  status: "enable"
          pref_dns_result: "ipv4"
          realm: "<your_own_value>"
          sec_default_action: "accept"
          secure_web_proxy: "disable"
          secure_web_proxy_cert:
              -
                  name: "default_name_42 (source vpn.certificate.local.name)"
          socks: "enable"
          socks_incoming_port: "<your_own_value>"
          ssl_algorithm: "high"
          ssl_dh_bits: "768"
          status: "enable"
          strict_guest: "enable"
          trace_auth_no_rsp: "enable"
          unknown_http_version: "reject"
          user_agent_detect: "disable"
          vrf_select: "-1"
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


def filter_web_proxy_explicit_data(json):
    option_list = [
        "client_cert",
        "empty_cert_action",
        "ftp_incoming_port",
        "ftp_over_http",
        "http_connection_mode",
        "http_incoming_port",
        "https_incoming_port",
        "https_replacement_message",
        "incoming_ip",
        "incoming_ip6",
        "interface",
        "interface_select_method",
        "ipv6_status",
        "message_upon_server_error",
        "outgoing_ip",
        "outgoing_ip6",
        "pac_file_data",
        "pac_file_name",
        "pac_file_server_port",
        "pac_file_server_status",
        "pac_file_through_https",
        "pac_file_url",
        "pac_policy",
        "pref_dns_result",
        "realm",
        "sec_default_action",
        "secure_web_proxy",
        "secure_web_proxy_cert",
        "socks",
        "socks_incoming_port",
        "ssl_algorithm",
        "ssl_dh_bits",
        "status",
        "strict_guest",
        "trace_auth_no_rsp",
        "unknown_http_version",
        "user_agent_detect",
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
        ["outgoing_ip"],
        ["outgoing_ip6"],
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


def web_proxy_explicit(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    web_proxy_explicit_data = data["web_proxy_explicit"]

    filtered_data = filter_web_proxy_explicit_data(web_proxy_explicit_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("web-proxy", "explicit", filtered_data, vdom=vdom)
        current_data = fos.get("web-proxy", "explicit", vdom=vdom, mkey=mkey)
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
    data_copy["web_proxy_explicit"] = filtered_data
    fos.do_member_operation(
        "web-proxy",
        "explicit",
        data_copy,
    )

    return fos.set("web-proxy", "explicit", data=converted_data, vdom=vdom)


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


def fortios_web_proxy(data, fos, check_mode):

    if data["web_proxy_explicit"]:
        resp = web_proxy_explicit(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("web_proxy_explicit"))
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
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "secure_web_proxy": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}, {"value": "secure"}],
        },
        "ftp_over_http": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "socks": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "http_incoming_port": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "http_connection_mode": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [
                {"value": "static"},
                {"value": "multiplex"},
                {"value": "serverpool"},
            ],
        },
        "https_incoming_port": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "secure_web_proxy_cert": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.0", ""]],
        },
        "client_cert": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "user_agent_detect": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "empty_cert_action": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [
                {"value": "accept"},
                {"value": "block"},
                {"value": "accept-unmanageable"},
            ],
        },
        "ssl_dh_bits": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [
                {"value": "768"},
                {"value": "1024"},
                {"value": "1536"},
                {"value": "2048"},
            ],
        },
        "ftp_incoming_port": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "socks_incoming_port": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "incoming_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "outgoing_ip": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "interface_select_method": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "vrf_select": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "ipv6_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "incoming_ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "outgoing_ip6": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "strict_guest": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pref_dns_result": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "ipv4"},
                {"value": "ipv6"},
                {"value": "ipv4-strict", "v_range": [["v7.4.4", ""]]},
                {"value": "ipv6-strict", "v_range": [["v7.4.4", ""]]},
            ],
        },
        "unknown_http_version": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "reject"},
                {"value": "best-effort"},
                {"value": "tunnel", "v_range": [["v6.4.0", "v7.0.0"]]},
            ],
        },
        "realm": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sec_default_action": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "accept"}, {"value": "deny"}],
        },
        "https_replacement_message": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "message_upon_server_error": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pac_file_server_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pac_file_server_port": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "pac_file_through_https": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pac_file_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "pac_file_data": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "pac_policy": {
            "type": "list",
            "elements": "dict",
            "children": {
                "policyid": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "srcaddr": {
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
                "srcaddr6": {
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
                "dstaddr": {
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
                "pac_file_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "pac_file_data": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ssl_algorithm": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "high"}, {"value": "medium"}, {"value": "low"}],
        },
        "trace_auth_no_rsp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pac_file_url": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
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
        "web_proxy_explicit": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["web_proxy_explicit"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["web_proxy_explicit"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "web_proxy_explicit"
        )

        is_error, has_changed, result, diff = fortios_web_proxy(
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
