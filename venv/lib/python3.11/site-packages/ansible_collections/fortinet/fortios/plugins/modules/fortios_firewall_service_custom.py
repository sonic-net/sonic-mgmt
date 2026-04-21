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
module: fortios_firewall_service_custom
short_description: Configure custom services in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall_service feature and custom category.
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
    firewall_service_custom:
        description:
            - Configure custom services.
        default: null
        type: dict
        suboptions:
            app_category:
                description:
                    - Application category ID.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Application category id. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            app_service_type:
                description:
                    - Application service type.
                type: str
                choices:
                    - 'disable'
                    - 'app-id'
                    - 'app-category'
            application:
                description:
                    - Application ID.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Application id. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            category:
                description:
                    - Service category. Source firewall.service.category.name.
                type: str
            check_reset_range:
                description:
                    - Configure the type of ICMP error message verification.
                type: str
                choices:
                    - 'disable'
                    - 'strict'
                    - 'default'
            color:
                description:
                    - Color of icon on the GUI.
                type: int
            comment:
                description:
                    - Comment.
                type: str
            fabric_object:
                description:
                    - Security Fabric global object setting.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fqdn:
                description:
                    - Fully qualified domain name.
                type: str
            helper:
                description:
                    - Helper name.
                type: str
                choices:
                    - 'auto'
                    - 'disable'
                    - 'ftp'
                    - 'tftp'
                    - 'ras'
                    - 'h323'
                    - 'tns'
                    - 'mms'
                    - 'sip'
                    - 'pptp'
                    - 'rtsp'
                    - 'dns-udp'
                    - 'dns-tcp'
                    - 'pmap'
                    - 'rsh'
                    - 'dcerpc'
                    - 'mgcp'
                    - 'gtp-c'
                    - 'gtp-u'
                    - 'gtp-b'
                    - 'pfcp'
            icmpcode:
                description:
                    - ICMP code.
                type: int
            icmptype:
                description:
                    - ICMP type.
                type: int
            iprange:
                description:
                    - Start and end of the IP range associated with service.
                type: str
            name:
                description:
                    - Custom service name.
                required: true
                type: str
            protocol:
                description:
                    - Protocol type based on IANA numbers.
                type: str
                choices:
                    - 'TCP/UDP/UDP-Lite/SCTP'
                    - 'ICMP'
                    - 'ICMP6'
                    - 'IP'
                    - 'HTTP'
                    - 'FTP'
                    - 'CONNECT'
                    - 'SOCKS-TCP'
                    - 'SOCKS-UDP'
                    - 'ALL'
                    - 'TCP/UDP/SCTP'
            protocol_number:
                description:
                    - IP protocol number.
                type: int
            proxy:
                description:
                    - Enable/disable web proxy service.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sctp_portrange:
                description:
                    - Multiple SCTP port ranges.
                type: str
            session_ttl:
                description:
                    - Session TTL (300 - 2764800, 0 = default).
                type: str
            tcp_halfclose_timer:
                description:
                    - Wait time to close a TCP session waiting for an unanswered FIN packet (1 - 86400 sec, 0 = default).
                type: int
            tcp_halfopen_timer:
                description:
                    - Wait time to close a TCP session waiting for an unanswered open session packet (1 - 86400 sec, 0 = default).
                type: int
            tcp_portrange:
                description:
                    - Multiple TCP port ranges.
                type: str
            tcp_rst_timer:
                description:
                    - Set the length of the TCP CLOSE state in seconds (5 - 300 sec, 0 = default).
                type: int
            tcp_timewait_timer:
                description:
                    - Set the length of the TCP TIME-WAIT state in seconds (1 - 300 sec, 0 = default).
                type: int
            udp_idle_timer:
                description:
                    - Number of seconds before an idle UDP/UDP-Lite connection times out (0 - 86400 sec, 0 = default).
                type: int
            udp_portrange:
                description:
                    - Multiple UDP port ranges.
                type: str
            udplite_portrange:
                description:
                    - Multiple UDP-Lite port ranges.
                type: str
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            visibility:
                description:
                    - Enable/disable the visibility of the service on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure custom services.
  fortinet.fortios.fortios_firewall_service_custom:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_service_custom:
          app_category:
              -
                  id: "4"
          app_service_type: "disable"
          application:
              -
                  id: "7"
          category: "<your_own_value> (source firewall.service.category.name)"
          check_reset_range: "disable"
          color: "0"
          comment: "Comment."
          fabric_object: "enable"
          fqdn: "<your_own_value>"
          helper: "auto"
          icmpcode: ""
          icmptype: ""
          iprange: "<your_own_value>"
          name: "default_name_18"
          protocol: "TCP/UDP/UDP-Lite/SCTP"
          protocol_number: "0"
          proxy: "enable"
          sctp_portrange: "<your_own_value>"
          session_ttl: "<your_own_value>"
          tcp_halfclose_timer: "0"
          tcp_halfopen_timer: "0"
          tcp_portrange: "<your_own_value>"
          tcp_rst_timer: "0"
          tcp_timewait_timer: "0"
          udp_idle_timer: "0"
          udp_portrange: "<your_own_value>"
          udplite_portrange: "<your_own_value>"
          uuid: "<your_own_value>"
          visibility: "enable"
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


def filter_firewall_service_custom_data(json):
    option_list = [
        "app_category",
        "app_service_type",
        "application",
        "category",
        "check_reset_range",
        "color",
        "comment",
        "fabric_object",
        "fqdn",
        "helper",
        "icmpcode",
        "icmptype",
        "iprange",
        "name",
        "protocol",
        "protocol_number",
        "proxy",
        "sctp_portrange",
        "session_ttl",
        "tcp_halfclose_timer",
        "tcp_halfopen_timer",
        "tcp_portrange",
        "tcp_rst_timer",
        "tcp_timewait_timer",
        "udp_idle_timer",
        "udp_portrange",
        "udplite_portrange",
        "uuid",
        "visibility",
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


def firewall_service_custom(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_service_custom_data = data["firewall_service_custom"]

    filtered_data = filter_firewall_service_custom_data(firewall_service_custom_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall.service", "custom", filtered_data, vdom=vdom)
        current_data = fos.get("firewall.service", "custom", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_service_custom"] = filtered_data
    fos.do_member_operation(
        "firewall.service",
        "custom",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall.service", "custom", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall.service", "custom", mkey=converted_data["name"], vdom=vdom
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


def fortios_firewall_service(data, fos, check_mode):

    if data["firewall_service_custom"]:
        resp = firewall_service_custom(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_service_custom"))
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
        "uuid": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "proxy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "category": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "protocol": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "TCP/UDP/UDP-Lite/SCTP", "v_range": [["v7.6.0", ""]]},
                {"value": "ICMP"},
                {"value": "ICMP6"},
                {"value": "IP"},
                {"value": "HTTP"},
                {"value": "FTP"},
                {"value": "CONNECT"},
                {"value": "SOCKS-TCP"},
                {"value": "SOCKS-UDP"},
                {"value": "ALL"},
                {"value": "TCP/UDP/SCTP", "v_range": [["v6.0.0", "v7.4.4"]]},
            ],
        },
        "helper": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "auto"},
                {"value": "disable"},
                {"value": "ftp"},
                {"value": "tftp"},
                {"value": "ras"},
                {"value": "h323"},
                {"value": "tns"},
                {"value": "mms"},
                {"value": "sip"},
                {"value": "pptp"},
                {"value": "rtsp"},
                {"value": "dns-udp"},
                {"value": "dns-tcp"},
                {"value": "pmap"},
                {"value": "rsh"},
                {"value": "dcerpc"},
                {"value": "mgcp"},
                {
                    "value": "gtp-c",
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                },
                {
                    "value": "gtp-u",
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                },
                {
                    "value": "gtp-b",
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                },
                {
                    "value": "pfcp",
                    "v_range": [
                        ["v7.0.1", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                },
            ],
        },
        "iprange": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "fqdn": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "protocol_number": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "icmptype": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "icmpcode": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "tcp_portrange": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "udp_portrange": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "udplite_portrange": {"v_range": [["v7.6.0", ""]], "type": "string"},
        "sctp_portrange": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "tcp_halfclose_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "tcp_halfopen_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "tcp_timewait_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "tcp_rst_timer": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "udp_idle_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "session_ttl": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "check_reset_range": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "strict"},
                {"value": "default"},
            ],
        },
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "color": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "app_service_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "app-id"},
                {"value": "app-category"},
            ],
        },
        "app_category": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True}
            },
            "v_range": [["v6.0.0", ""]],
        },
        "application": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True}
            },
            "v_range": [["v6.0.0", ""]],
        },
        "fabric_object": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "visibility": {
            "v_range": [["v6.0.0", "v7.2.2"]],
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
        "firewall_service_custom": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_service_custom"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_service_custom"]["options"][attribute_name][
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
            fos, versioned_schema, "firewall_service_custom"
        )

        is_error, has_changed, result, diff = fortios_firewall_service(
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
