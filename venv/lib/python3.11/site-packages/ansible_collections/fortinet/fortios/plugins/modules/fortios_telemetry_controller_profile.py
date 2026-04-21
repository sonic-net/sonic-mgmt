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
module: fortios_telemetry_controller_profile
short_description: Configure FortiTelemetry profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify telemetry_controller feature and profile category.
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
    telemetry_controller_profile:
        description:
            - Configure FortiTelemetry profiles.
        default: null
        type: dict
        suboptions:
            application:
                description:
                    - Configure applications.
                type: list
                elements: dict
                suboptions:
                    app_name:
                        description:
                            - Application name. Source telemetry-controller.application.custom.app-name telemetry-controller.application.predefine.app-name.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    interval:
                        description:
                            - Time in milliseconds to check the application (1000 - 86,400 * 1000).
                        type: int
                    monitor:
                        description:
                            - Enable/disable monitoring of the application.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    sla:
                        description:
                            - Service level agreement (SLA).
                        type: dict
                        suboptions:
                            app_throughput_threshold:
                                description:
                                    - Threshold of application throughput in megabytes (0 - 10,000).
                                type: int
                            atdt_threshold:
                                description:
                                    - Threshold of application total downloading time in milliseconds (0 - 10,000,000).
                                type: int
                            dns_time_threshold:
                                description:
                                    - Threshold of 95th percentile of DNS resolution time in milliseconds (0 - 10,000,000).
                                type: int
                            experience_score_threshold:
                                description:
                                    - Threshold of experience score (0 - 10).
                                type: int
                            failure_rate_threshold:
                                description:
                                    - Threshold of failure rate (0 - 100).
                                type: int
                            jitter_threshold:
                                description:
                                    - Threshold of jitter in milliseconds (0 - 10,000,000).
                                type: int
                            latency_threshold:
                                description:
                                    - Threshold of latency in milliseconds (0 - 10,000,000).
                                type: int
                            packet_loss_threshold:
                                description:
                                    - Threshold of packet loss (0 - 100).
                                type: int
                            sla_factor:
                                description:
                                    - Criteria on which metric to SLA threshold list.
                                type: list
                                elements: str
                                choices:
                                    - 'experience-score'
                                    - 'failure-rate'
                                    - 'latency'
                                    - 'jitter'
                                    - 'packet-loss'
                                    - 'ttfb'
                                    - 'atdt'
                                    - 'tcp-rtt'
                                    - 'dns-time'
                                    - 'tls-time'
                                    - 'app-throughput'
                            tcp_rtt_threshold:
                                description:
                                    - Threshold of TCP round-trip time in milliseconds (0 - 10,000,000).
                                type: int
                            tls_time_threshold:
                                description:
                                    - Threshold of 95th percentile of TLS handshake time in milliseconds (0 - 10,000,000).
                                type: int
                            ttfb_threshold:
                                description:
                                    - Threshold of time to first byte in milliseconds (0 - 10,000,000).
                                type: int
            comment:
                description:
                    - Comment.
                type: str
            name:
                description:
                    - Name of the profile.
                required: true
                type: str
"""

EXAMPLES = """
- name: Configure FortiTelemetry profiles.
  fortinet.fortios.fortios_telemetry_controller_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      telemetry_controller_profile:
          application:
              -
                  app_name: "<your_own_value> (source telemetry-controller.application.custom.app-name telemetry-controller.application.predefine.app-name)"
                  id: "5"
                  interval: "300000"
                  monitor: "enable"
                  sla:
                      app_throughput_threshold: "2"
                      atdt_threshold: "3000"
                      dns_time_threshold: "100"
                      experience_score_threshold: "6"
                      failure_rate_threshold: "5"
                      jitter_threshold: "50"
                      latency_threshold: "100"
                      packet_loss_threshold: "5"
                      sla_factor: "experience-score"
                      tcp_rtt_threshold: "100"
                      tls_time_threshold: "200"
                      ttfb_threshold: "200"
          comment: "Comment."
          name: "default_name_22"
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


def filter_telemetry_controller_profile_data(json):
    option_list = ["application", "comment", "name"]

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
        ["application", "sla", "sla_factor"],
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


def telemetry_controller_profile(data, fos):
    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    telemetry_controller_profile_data = data["telemetry_controller_profile"]

    filtered_data = filter_telemetry_controller_profile_data(
        telemetry_controller_profile_data
    )
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["telemetry_controller_profile"] = filtered_data
    fos.do_member_operation(
        "telemetry-controller",
        "profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "telemetry-controller", "profile", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "telemetry-controller", "profile", mkey=converted_data["name"], vdom=vdom
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


def fortios_telemetry_controller(data, fos):

    if data["telemetry_controller_profile"]:
        resp = telemetry_controller_profile(data, fos)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("telemetry_controller_profile")
        )

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
        "name": {"v_range": [["v7.6.3", ""]], "type": "string", "required": True},
        "comment": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "application": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "integer",
                    "required": True,
                },
                "app_name": {"v_range": [["v7.6.3", ""]], "type": "string"},
                "monitor": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "interval": {"v_range": [["v7.6.3", ""]], "type": "integer"},
                "sla": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "dict",
                    "children": {
                        "sla_factor": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "list",
                            "options": [
                                {"value": "experience-score"},
                                {"value": "failure-rate"},
                                {"value": "latency"},
                                {"value": "jitter"},
                                {"value": "packet-loss"},
                                {"value": "ttfb"},
                                {"value": "atdt"},
                                {"value": "tcp-rtt"},
                                {"value": "dns-time"},
                                {"value": "tls-time"},
                                {"value": "app-throughput"},
                            ],
                            "multiple_values": True,
                            "elements": "str",
                        },
                        "experience_score_threshold": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "integer",
                        },
                        "failure_rate_threshold": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "integer",
                        },
                        "latency_threshold": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "integer",
                        },
                        "jitter_threshold": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "integer",
                        },
                        "packet_loss_threshold": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "integer",
                        },
                        "ttfb_threshold": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "integer",
                        },
                        "atdt_threshold": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "integer",
                        },
                        "tcp_rtt_threshold": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "integer",
                        },
                        "dns_time_threshold": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "integer",
                        },
                        "tls_time_threshold": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "integer",
                        },
                        "app_throughput_threshold": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "integer",
                        },
                    },
                },
            },
            "v_range": [["v7.6.3", ""]],
        },
    },
    "v_range": [["v7.6.3", ""]],
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
        "telemetry_controller_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["telemetry_controller_profile"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["telemetry_controller_profile"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "telemetry_controller_profile"
        )

        is_error, has_changed, result, diff = fortios_telemetry_controller(
            module.params, fos
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
