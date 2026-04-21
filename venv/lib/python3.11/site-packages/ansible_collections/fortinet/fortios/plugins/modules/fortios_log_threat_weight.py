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
module: fortios_log_threat_weight
short_description: Configure threat weight settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify log feature and threat_weight category.
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

    log_threat_weight:
        description:
            - Configure threat weight settings.
        default: null
        type: dict
        suboptions:
            application:
                description:
                    - Application-control threat weight settings.
                type: list
                elements: dict
                suboptions:
                    category:
                        description:
                            - Application category.
                        type: int
                    id:
                        description:
                            - Entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    level:
                        description:
                            - Threat weight score for Application events.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
            blocked_connection:
                description:
                    - Threat weight score for blocked connections.
                type: str
                choices:
                    - 'disable'
                    - 'low'
                    - 'medium'
                    - 'high'
                    - 'critical'
            botnet_connection_detected:
                description:
                    - Threat weight score for detected botnet connections.
                type: str
                choices:
                    - 'disable'
                    - 'low'
                    - 'medium'
                    - 'high'
                    - 'critical'
            failed_connection:
                description:
                    - Threat weight score for failed connections.
                type: str
                choices:
                    - 'disable'
                    - 'low'
                    - 'medium'
                    - 'high'
                    - 'critical'
            geolocation:
                description:
                    - Geolocation-based threat weight settings.
                type: list
                elements: dict
                suboptions:
                    country:
                        description:
                            - Country code.
                        type: str
                    id:
                        description:
                            - Entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    level:
                        description:
                            - Threat weight score for Geolocation-based events.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
            ips:
                description:
                    - IPS threat weight settings.
                type: dict
                suboptions:
                    critical_severity:
                        description:
                            - Threat weight score for IPS critical severity events.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    high_severity:
                        description:
                            - Threat weight score for IPS high severity events.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    info_severity:
                        description:
                            - Threat weight score for IPS info severity events.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    low_severity:
                        description:
                            - Threat weight score for IPS low severity events.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    medium_severity:
                        description:
                            - Threat weight score for IPS medium severity events.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
            level:
                description:
                    - Score mapping for threat weight levels.
                type: dict
                suboptions:
                    critical:
                        description:
                            - Critical level score value (1 - 100).
                        type: int
                    high:
                        description:
                            - High level score value (1 - 100).
                        type: int
                    low:
                        description:
                            - Low level score value (1 - 100).
                        type: int
                    medium:
                        description:
                            - Medium level score value (1 - 100).
                        type: int
            malware:
                description:
                    - Anti-virus malware threat weight settings.
                type: dict
                suboptions:
                    botnet_connection:
                        description:
                            - Threat weight score for detected botnet connections.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    command_blocked:
                        description:
                            - Threat weight score for blocked command detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    content_disarm:
                        description:
                            - Threat weight score for virus (content disarm) detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    ems_threat_feed:
                        description:
                            - Threat weight score for virus (EMS threat feed) detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    file_blocked:
                        description:
                            - Threat weight score for blocked file detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    fortiai:
                        description:
                            - Threat weight score for FortiAI-detected virus.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    fortindr:
                        description:
                            - Threat weight score for FortiNDR-detected virus.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    fortisandbox:
                        description:
                            - Threat weight score for FortiSandbox-detected virus.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    fsa_high_risk:
                        description:
                            - Threat weight score for FortiSandbox high risk malware detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    fsa_malicious:
                        description:
                            - Threat weight score for FortiSandbox malicious malware detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    fsa_medium_risk:
                        description:
                            - Threat weight score for FortiSandbox medium risk malware detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    inline_block:
                        description:
                            - Threat weight score for malware detected by inline block.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    malware_list:
                        description:
                            - Threat weight score for virus (malware list) detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    mimefragmented:
                        description:
                            - Threat weight score for mimefragmented detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    oversized:
                        description:
                            - Threat weight score for oversized file detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    switch_proto:
                        description:
                            - Threat weight score for switch proto detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    virus_blocked:
                        description:
                            - Threat weight score for virus (blocked) detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    virus_file_type_executable:
                        description:
                            - Threat weight score for virus (file type executable) detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    virus_infected:
                        description:
                            - Threat weight score for virus (infected) detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    virus_outbreak_prevention:
                        description:
                            - Threat weight score for virus (outbreak prevention) event.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    virus_scan_error:
                        description:
                            - Threat weight score for virus (scan error) detected.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
            status:
                description:
                    - Enable/disable the threat weight feature.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            url_block_detected:
                description:
                    - Threat weight score for URL blocking.
                type: str
                choices:
                    - 'disable'
                    - 'low'
                    - 'medium'
                    - 'high'
                    - 'critical'
            web:
                description:
                    - Web filtering threat weight settings.
                type: list
                elements: dict
                suboptions:
                    category:
                        description:
                            - Threat weight score for web category filtering matches.
                        type: int
                    id:
                        description:
                            - Entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    level:
                        description:
                            - Threat weight score for web category filtering matches.
                        type: str
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
"""

EXAMPLES = """
- name: Configure threat weight settings.
  fortinet.fortios.fortios_log_threat_weight:
      vdom: "{{ vdom }}"
      log_threat_weight:
          application:
              -
                  category: "0"
                  id: "5"
                  level: "disable"
          blocked_connection: "disable"
          botnet_connection_detected: "disable"
          failed_connection: "disable"
          geolocation:
              -
                  country: "<your_own_value>"
                  id: "12"
                  level: "disable"
          ips:
              critical_severity: "disable"
              high_severity: "disable"
              info_severity: "disable"
              low_severity: "disable"
              medium_severity: "disable"
          level:
              critical: "50"
              high: "30"
              low: "5"
              medium: "10"
          malware:
              botnet_connection: "disable"
              command_blocked: "disable"
              content_disarm: "disable"
              ems_threat_feed: "disable"
              file_blocked: "disable"
              fortiai: "disable"
              fortindr: "disable"
              fortisandbox: "disable"
              fsa_high_risk: "disable"
              fsa_malicious: "disable"
              fsa_medium_risk: "disable"
              inline_block: "disable"
              malware_list: "disable"
              mimefragmented: "disable"
              oversized: "disable"
              switch_proto: "disable"
              virus_blocked: "disable"
              virus_file_type_executable: "disable"
              virus_infected: "disable"
              virus_outbreak_prevention: "disable"
              virus_scan_error: "disable"
          status: "enable"
          url_block_detected: "disable"
          web:
              -
                  category: "0"
                  id: "51"
                  level: "disable"
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


def filter_log_threat_weight_data(json):
    option_list = [
        "application",
        "blocked_connection",
        "botnet_connection_detected",
        "failed_connection",
        "geolocation",
        "ips",
        "level",
        "malware",
        "status",
        "url_block_detected",
        "web",
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


def log_threat_weight(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    log_threat_weight_data = data["log_threat_weight"]

    filtered_data = filter_log_threat_weight_data(log_threat_weight_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("log", "threat-weight", filtered_data, vdom=vdom)
        current_data = fos.get("log", "threat-weight", vdom=vdom, mkey=mkey)
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
    data_copy["log_threat_weight"] = filtered_data
    fos.do_member_operation(
        "log",
        "threat-weight",
        data_copy,
    )

    return fos.set("log", "threat-weight", data=converted_data, vdom=vdom)


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


def fortios_log(data, fos, check_mode):

    if data["log_threat_weight"]:
        resp = log_threat_weight(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("log_threat_weight"))
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
        "level": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "low": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "medium": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "high": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "critical": {"v_range": [["v6.0.0", ""]], "type": "integer"},
            },
        },
        "blocked_connection": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "low"},
                {"value": "medium"},
                {"value": "high"},
                {"value": "critical"},
            ],
        },
        "failed_connection": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "low"},
                {"value": "medium"},
                {"value": "high"},
                {"value": "critical"},
            ],
        },
        "url_block_detected": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "low"},
                {"value": "medium"},
                {"value": "high"},
                {"value": "critical"},
            ],
        },
        "botnet_connection_detected": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "low"},
                {"value": "medium"},
                {"value": "high"},
                {"value": "critical"},
            ],
        },
        "malware": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "virus_infected": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "inline_block": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "file_blocked": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "command_blocked": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "oversized": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "virus_scan_error": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "switch_proto": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "mimefragmented": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "virus_file_type_executable": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "virus_outbreak_prevention": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "content_disarm": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "malware_list": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "ems_threat_feed": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "fsa_malicious": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "fsa_high_risk": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "fsa_medium_risk": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "fortindr": {
                    "v_range": [["v7.0.8", "v7.2.4"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "fortisandbox": {
                    "v_range": [["v7.2.0", "v7.2.4"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "fortiai": {
                    "v_range": [["v7.0.1", "v7.0.7"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "virus_blocked": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "botnet_connection": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
            },
        },
        "ips": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "info_severity": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "low_severity": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "medium_severity": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "high_severity": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "critical_severity": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
            },
        },
        "web": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "category": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "level": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "geolocation": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "country": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "level": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "application": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "category": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "level": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
            },
            "v_range": [["v6.0.0", ""]],
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
        "log_threat_weight": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["log_threat_weight"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["log_threat_weight"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "log_threat_weight"
        )

        is_error, has_changed, result, diff = fortios_log(
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
