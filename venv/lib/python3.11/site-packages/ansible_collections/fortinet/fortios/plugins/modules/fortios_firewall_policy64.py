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
module: fortios_firewall_policy64
short_description: Configure IPv6 to IPv4 policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and policy64 category.
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
    firewall_policy64:
        description:
            - Configure IPv6 to IPv4 policies.
        default: null
        type: dict
        suboptions:
            action:
                description:
                    - Policy action.
                type: str
                choices:
                    - 'accept'
                    - 'deny'
            comments:
                description:
                    - Comment.
                type: str
            dstaddr:
                description:
                    - Destination address name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name firewall.vip64.name firewall.vipgrp64.name.
                        required: true
                        type: str
            dstintf:
                description:
                    - Destination interface name. Source system.interface.name system.zone.name.
                type: str
            fixedport:
                description:
                    - Enable/disable policy fixed port.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ippool:
                description:
                    - Enable/disable policy64 IP pool.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            logtraffic:
                description:
                    - Enable/disable policy log traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            logtraffic_start:
                description:
                    - Record logs when a session starts and ends.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Policy name.
                type: str
            per_ip_shaper:
                description:
                    - Per-IP traffic shaper. Source firewall.shaper.per-ip-shaper.name.
                type: str
            permit_any_host:
                description:
                    - Enable/disable permit any host in.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            policyid:
                description:
                    - Policy ID (0 - 4294967294). see <a href='#notes'>Notes</a>.
                required: true
                type: int
            poolname:
                description:
                    - Policy IP pool names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - IP pool name. Source firewall.ippool.name.
                        required: true
                        type: str
            schedule:
                description:
                    - Schedule name. Source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name.
                type: str
            service:
                description:
                    - Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.service.custom.name firewall.service.group.name.
                        required: true
                        type: str
            srcaddr:
                description:
                    - Source address name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
                        type: str
            srcintf:
                description:
                    - Source interface name. Source system.zone.name system.interface.name.
                type: str
            status:
                description:
                    - Enable/disable policy status.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tcp_mss_receiver:
                description:
                    - TCP MSS value of receiver.
                type: int
            tcp_mss_sender:
                description:
                    - TCP MSS value of sender.
                type: int
            traffic_shaper:
                description:
                    - Traffic shaper. Source firewall.shaper.traffic-shaper.name.
                type: str
            traffic_shaper_reverse:
                description:
                    - Reverse traffic shaper. Source firewall.shaper.traffic-shaper.name.
                type: str
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
"""

EXAMPLES = """
- name: Configure IPv6 to IPv4 policies.
  fortinet.fortios.fortios_firewall_policy64:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_policy64:
          action: "accept"
          comments: "<your_own_value>"
          dstaddr:
              -
                  name: "default_name_6 (source firewall.address.name firewall.addrgrp.name firewall.vip64.name firewall.vipgrp64.name)"
          dstintf: "<your_own_value> (source system.interface.name system.zone.name)"
          fixedport: "enable"
          ippool: "enable"
          logtraffic: "enable"
          logtraffic_start: "enable"
          name: "default_name_12"
          per_ip_shaper: "<your_own_value> (source firewall.shaper.per-ip-shaper.name)"
          permit_any_host: "enable"
          policyid: "<you_own_value>"
          poolname:
              -
                  name: "default_name_17 (source firewall.ippool.name)"
          schedule: "<your_own_value> (source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name)"
          service:
              -
                  name: "default_name_20 (source firewall.service.custom.name firewall.service.group.name)"
          srcaddr:
              -
                  name: "default_name_22 (source firewall.address6.name firewall.addrgrp6.name)"
          srcintf: "<your_own_value> (source system.zone.name system.interface.name)"
          status: "enable"
          tcp_mss_receiver: "0"
          tcp_mss_sender: "0"
          traffic_shaper: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
          traffic_shaper_reverse: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
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


def filter_firewall_policy64_data(json):
    option_list = [
        "action",
        "comments",
        "dstaddr",
        "dstintf",
        "fixedport",
        "ippool",
        "logtraffic",
        "logtraffic_start",
        "name",
        "per_ip_shaper",
        "permit_any_host",
        "policyid",
        "poolname",
        "schedule",
        "service",
        "srcaddr",
        "srcintf",
        "status",
        "tcp_mss_receiver",
        "tcp_mss_sender",
        "traffic_shaper",
        "traffic_shaper_reverse",
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


def firewall_policy64(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_policy64_data = data["firewall_policy64"]

    filtered_data = filter_firewall_policy64_data(firewall_policy64_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "policy64", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "policy64", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_policy64"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "policy64",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "policy64", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "policy64", mkey=converted_data["policyid"], vdom=vdom
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

    if data["firewall_policy64"]:
        resp = firewall_policy64(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_policy64"))
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
        "policyid": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "integer",
            "required": True,
        },
        "name": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.0"]],
            "type": "string",
        },
        "uuid": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
        "srcintf": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
        "dstintf": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
        "srcaddr": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.0.0"]],
        },
        "dstaddr": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.0.0"]],
        },
        "action": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "accept"}, {"value": "deny"}],
        },
        "status": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "schedule": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
        "service": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.0.0"]],
        },
        "logtraffic": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "logtraffic_start": {
            "v_range": [["v6.2.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "permit_any_host": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "traffic_shaper": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
        "traffic_shaper_reverse": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
        "per_ip_shaper": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
        "fixedport": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ippool": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "poolname": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.0.0"]],
        },
        "tcp_mss_sender": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "integer"},
        "tcp_mss_receiver": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "integer"},
        "comments": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "string"},
    },
    "v_range": [["v6.0.0", "v7.0.0"]],
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
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "firewall_policy64": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_policy64"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_policy64"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "firewall_policy64"
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
