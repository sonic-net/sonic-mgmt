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
module: fortios_ips_sensor
short_description: Configure IPS sensor in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify ips feature and sensor category.
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
    ips_sensor:
        description:
            - Configure IPS sensor.
        default: null
        type: dict
        suboptions:
            block_malicious_url:
                description:
                    - Enable/disable malicious URL blocking.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                description:
                    - Comment.
                type: str
            entries:
                description:
                    - IPS sensor filter.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action taken with traffic in which signatures are detected.
                        type: str
                        choices:
                            - 'pass'
                            - 'block'
                            - 'reset'
                            - 'default'
                    application:
                        description:
                            - Operating systems to be protected. Use all for every application and other for unlisted application.
                        type: list
                        elements: str
                    cve:
                        description:
                            - List of CVE IDs of the signatures to add to the sensor.
                        type: list
                        elements: dict
                        suboptions:
                            cve_entry:
                                description:
                                    - CVE IDs or CVE wildcards.
                                required: true
                                type: str
                    default_action:
                        description:
                            - Signature default action filter.
                        type: str
                        choices:
                            - 'all'
                            - 'pass'
                            - 'block'
                    default_status:
                        description:
                            - Signature default status filter.
                        type: str
                        choices:
                            - 'all'
                            - 'enable'
                            - 'disable'
                    exempt_ip:
                        description:
                            - Traffic from selected source or destination IP addresses is exempt from this signature.
                        type: list
                        elements: dict
                        suboptions:
                            dst_ip:
                                description:
                                    - Destination IP address and netmask (applies to packet matching the signature).
                                type: str
                            id:
                                description:
                                    - Exempt IP ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            src_ip:
                                description:
                                    - Source IP address and netmask (applies to packet matching the signature).
                                type: str
                    id:
                        description:
                            - Rule ID in IPS database (0 - 4294967295). see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    last_modified:
                        description:
                            - 'Filter by signature last modified date. Formats: before <date>, after <date>, between <start-date> <end-date>.'
                        type: str
                    location:
                        description:
                            - Protect client or server traffic.
                        type: list
                        elements: str
                    log:
                        description:
                            - Enable/disable logging of signatures included in filter.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    log_attack_context:
                        description:
                            - 'Enable/disable logging of attack context: URL buffer, header buffer, body buffer, packet buffer.'
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    log_packet:
                        description:
                            - Enable/disable packet logging. Enable to save the packet that triggers the filter. You can download the packets in pcap format
                               for diagnostic use.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    os:
                        description:
                            - Operating systems to be protected. Use all for every operating system and other for unlisted operating systems.
                        type: list
                        elements: str
                    protocol:
                        description:
                            - Protocols to be examined. Use all for every protocol and other for unlisted protocols.
                        type: list
                        elements: str
                    quarantine:
                        description:
                            - Quarantine method.
                        type: str
                        choices:
                            - 'none'
                            - 'attacker'
                    quarantine_expiry:
                        description:
                            - Duration of quarantine. (Format ###d##h##m, minimum 1m, maximum 364d23h59m). Requires quarantine set to attacker.
                        type: str
                    quarantine_log:
                        description:
                            - Enable/disable quarantine logging.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    rate_count:
                        description:
                            - Count of the rate.
                        type: int
                    rate_duration:
                        description:
                            - Duration (sec) of the rate.
                        type: int
                    rate_mode:
                        description:
                            - Rate limit mode.
                        type: str
                        choices:
                            - 'periodical'
                            - 'continuous'
                    rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                            - 'dhcp-client-mac'
                            - 'dns-domain'
                    rule:
                        description:
                            - Identifies the predefined or custom IPS signatures to add to the sensor.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Rule IPS. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                    severity:
                        description:
                            - Relative severity of the signature, from info to critical. Log messages generated by the signature include the severity.
                        type: list
                        elements: str
                    status:
                        description:
                            - Status of the signatures included in filter. Only those filters with a status to enable are used.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'default'
                    vuln_type:
                        description:
                            - List of signature vulnerability types to filter by.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Vulnerability type ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
            extended_log:
                description:
                    - Enable/disable extended logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            filter:
                description:
                    - IPS sensor filter.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action of selected rules.
                        type: str
                        choices:
                            - 'pass'
                            - 'block'
                            - 'reset'
                            - 'default'
                    application:
                        description:
                            - Vulnerable application filter.
                        type: str
                    location:
                        description:
                            - Vulnerability location filter.
                        type: str
                    log:
                        description:
                            - Enable/disable logging of selected rules.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    log_packet:
                        description:
                            - Enable/disable packet logging of selected rules.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    name:
                        description:
                            - Filter name.
                        required: true
                        type: str
                    os:
                        description:
                            - Vulnerable OS filter.
                        type: str
                    protocol:
                        description:
                            - Vulnerable protocol filter.
                        type: str
                    quarantine:
                        description:
                            - Quarantine IP or interface.
                        type: str
                        choices:
                            - 'none'
                            - 'attacker'
                    quarantine_expiry:
                        description:
                            - Duration of quarantine in minute.
                        type: int
                    quarantine_log:
                        description:
                            - Enable/disable logging of selected quarantine.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        description:
                            - Vulnerability severity filter.
                        type: str
                    status:
                        description:
                            - Selected rules status.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'default'
            name:
                description:
                    - Sensor name.
                required: true
                type: str
            override:
                description:
                    - IPS override rule.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action of override rule.
                        type: str
                        choices:
                            - 'pass'
                            - 'block'
                            - 'reset'
                    exempt_ip:
                        description:
                            - Exempted IP.
                        type: list
                        elements: dict
                        suboptions:
                            dst_ip:
                                description:
                                    - Destination IP address and netmask.
                                type: str
                            id:
                                description:
                                    - Exempt IP ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            src_ip:
                                description:
                                    - Source IP address and netmask.
                                type: str
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    log_packet:
                        description:
                            - Enable/disable packet logging.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    quarantine:
                        description:
                            - Quarantine IP or interface.
                        type: str
                        choices:
                            - 'none'
                            - 'attacker'
                    quarantine_expiry:
                        description:
                            - Duration of quarantine in minute.
                        type: int
                    quarantine_log:
                        description:
                            - Enable/disable logging of selected quarantine.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    rule_id:
                        description:
                            - Override rule ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    status:
                        description:
                            - Enable/disable status of override rule.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            replacemsg_group:
                description:
                    - Replacement message group. Source system.replacemsg-group.name.
                type: str
            scan_botnet_connections:
                description:
                    - Block or monitor connections to Botnet servers, or disable Botnet scanning.
                type: str
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
"""

EXAMPLES = """
- name: Configure IPS sensor.
  fortinet.fortios.fortios_ips_sensor:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      ips_sensor:
          block_malicious_url: "disable"
          comment: "Comment."
          entries:
              -
                  action: "pass"
                  application: "<your_own_value>"
                  cve:
                      -
                          cve_entry: "<your_own_value>"
                  default_action: "all"
                  default_status: "all"
                  exempt_ip:
                      -
                          dst_ip: "<your_own_value>"
                          id: "14"
                          src_ip: "<your_own_value>"
                  id: "16"
                  last_modified: "<your_own_value>"
                  location: "<your_own_value>"
                  log: "disable"
                  log_attack_context: "disable"
                  log_packet: "disable"
                  os: "<your_own_value>"
                  protocol: "<your_own_value>"
                  quarantine: "none"
                  quarantine_expiry: "<your_own_value>"
                  quarantine_log: "disable"
                  rate_count: "0"
                  rate_duration: "60"
                  rate_mode: "periodical"
                  rate_track: "none"
                  rule:
                      -
                          id: "32"
                  severity: "<your_own_value>"
                  status: "disable"
                  vuln_type:
                      -
                          id: "36"
          extended_log: "enable"
          filter:
              -
                  action: "pass"
                  application: "<your_own_value>"
                  location: "<your_own_value>"
                  log: "disable"
                  log_packet: "disable"
                  name: "default_name_44"
                  os: "<your_own_value>"
                  protocol: "<your_own_value>"
                  quarantine: "none"
                  quarantine_expiry: "1073741823"
                  quarantine_log: "disable"
                  severity: "<your_own_value>"
                  status: "disable"
          name: "default_name_52"
          override:
              -
                  action: "pass"
                  exempt_ip:
                      -
                          dst_ip: "<your_own_value>"
                          id: "57"
                          src_ip: "<your_own_value>"
                  log: "disable"
                  log_packet: "disable"
                  quarantine: "none"
                  quarantine_expiry: "1073741823"
                  quarantine_log: "disable"
                  rule_id: "<you_own_value>"
                  status: "disable"
          replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
          scan_botnet_connections: "disable"
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


def filter_ips_sensor_data(json):
    option_list = [
        "block_malicious_url",
        "comment",
        "entries",
        "extended_log",
        "filter",
        "name",
        "override",
        "replacemsg_group",
        "scan_botnet_connections",
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
        ["entries", "location"],
        ["entries", "severity"],
        ["entries", "protocol"],
        ["entries", "os"],
        ["entries", "application"],
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


def ips_sensor(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    ips_sensor_data = data["ips_sensor"]

    filtered_data = filter_ips_sensor_data(ips_sensor_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("ips", "sensor", filtered_data, vdom=vdom)
        current_data = fos.get("ips", "sensor", vdom=vdom, mkey=mkey)
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
    data_copy["ips_sensor"] = filtered_data
    fos.do_member_operation(
        "ips",
        "sensor",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("ips", "sensor", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("ips", "sensor", mkey=converted_data["name"], vdom=vdom)
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


def fortios_ips(data, fos, check_mode):

    if data["ips_sensor"]:
        resp = ips_sensor(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("ips_sensor"))
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
        "replacemsg_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "block_malicious_url": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "scan_botnet_connections": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "block"}, {"value": "monitor"}],
        },
        "extended_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "entries": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "rule": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "location": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "severity": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "protocol": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "os": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "application": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "default_action": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "all"},
                        {"value": "pass"},
                        {"value": "block"},
                    ],
                },
                "default_status": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "all"},
                        {"value": "enable"},
                        {"value": "disable"},
                    ],
                },
                "cve": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "cve_entry": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                },
                "vuln_type": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.2.0", ""]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.0", ""]],
                },
                "last_modified": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "enable"},
                        {"value": "default"},
                    ],
                },
                "log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log_packet": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log_attack_context": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "action": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "pass"},
                        {"value": "block"},
                        {"value": "reset"},
                        {"value": "default"},
                    ],
                },
                "rate_count": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "rate_duration": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "rate_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "periodical"}, {"value": "continuous"}],
                },
                "rate_track": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                        {"value": "dhcp-client-mac"},
                        {"value": "dns-domain"},
                    ],
                },
                "exempt_ip": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "src_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "dst_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "quarantine": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "none"}, {"value": "attacker"}],
                },
                "quarantine_expiry": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "quarantine_log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "filter": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "required": True,
                },
                "location": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                },
                "severity": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                },
                "protocol": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                },
                "os": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                },
                "application": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                },
                "status": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "enable"},
                        {"value": "default"},
                    ],
                },
                "log": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log_packet": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "action": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [
                        {"value": "pass"},
                        {"value": "block"},
                        {"value": "reset"},
                        {"value": "default"},
                    ],
                },
                "quarantine": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "none"}, {"value": "attacker"}],
                },
                "quarantine_expiry": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "integer",
                },
                "quarantine_log": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
            },
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
        },
        "override": {
            "type": "list",
            "elements": "dict",
            "children": {
                "rule_id": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "integer",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log_packet": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "action": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [
                        {"value": "pass"},
                        {"value": "block"},
                        {"value": "reset"},
                    ],
                },
                "quarantine": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "none"}, {"value": "attacker"}],
                },
                "quarantine_expiry": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "integer",
                },
                "quarantine_log": {
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "exempt_ip": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                            "type": "integer",
                            "required": True,
                        },
                        "src_ip": {
                            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                            "type": "string",
                        },
                        "dst_ip": {
                            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                            "type": "string",
                        },
                    },
                    "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
                },
            },
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
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
        "ips_sensor": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["ips_sensor"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["ips_sensor"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "ips_sensor"
        )

        is_error, has_changed, result, diff = fortios_ips(
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
