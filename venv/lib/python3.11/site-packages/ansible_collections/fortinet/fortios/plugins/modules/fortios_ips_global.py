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
module: fortios_ips_global
short_description: Configure IPS global parameter in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify ips feature and global category.
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

    ips_global:
        description:
            - Configure IPS global parameter.
        default: null
        type: dict
        suboptions:
            anomaly_mode:
                description:
                    - Global blocking mode for rate-based anomalies.
                type: str
                choices:
                    - 'periodical'
                    - 'continuous'
            av_mem_limit:
                description:
                    - Maximum percentage of system memory allowed for use on AV scanning (10 - 50). To disable set to zero. When disabled, there is no limit
                       on the AV memory usage.
                type: int
            cp_accel_mode:
                description:
                    - IPS Pattern matching acceleration/offloading to CPx processors.
                type: str
                choices:
                    - 'none'
                    - 'basic'
                    - 'advanced'
            database:
                description:
                    - Regular or extended IPS database. Regular protects against the latest common and in-the-wild attacks. Extended includes protection from
                       legacy attacks.
                type: str
                choices:
                    - 'regular'
                    - 'extended'
            deep_app_insp_db_limit:
                description:
                    - Limit on number of entries in deep application inspection database (1 - 2147483647, use recommended setting = 0).
                type: int
            deep_app_insp_timeout:
                description:
                    - Timeout for Deep application inspection (1 - 2147483647 sec., 0 = use recommended setting).
                type: int
            engine_count:
                description:
                    - Number of IPS engines running. If set to the default value of 0, FortiOS sets the number to optimize performance depending on the number
                       of CPU cores.
                type: int
            exclude_signatures:
                description:
                    - Excluded signatures.
                type: str
                choices:
                    - 'none'
                    - 'ot'
                    - 'industrial'
            fail_open:
                description:
                    - Enable to allow traffic if the IPS buffer is full. Default is disable and IPS traffic is blocked when the IPS buffer is full.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            intelligent_mode:
                description:
                    - Enable/disable IPS adaptive scanning (intelligent mode). Intelligent mode optimizes the scanning method for the type of traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ips_reserve_cpu:
                description:
                    - Enable/disable IPS daemon"s use of CPUs other than CPU 0.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            machine_learning_detection:
                description:
                    - Enable/disable machine learning detection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ngfw_max_scan_range:
                description:
                    - NGFW policy-mode app detection threshold.
                type: int
            np_accel_mode:
                description:
                    - Acceleration mode for IPS processing by NPx processors.
                type: str
                choices:
                    - 'none'
                    - 'basic'
            packet_log_queue_depth:
                description:
                    - Packet/pcap log queue depth per IPS engine.
                type: int
            session_limit_mode:
                description:
                    - Method of counting concurrent sessions used by session limit anomalies. Choose between greater accuracy (accurate) or improved
                       performance (heuristics).
                type: str
                choices:
                    - 'accurate'
                    - 'heuristic'
            skype_client_public_ipaddr:
                description:
                    - Public IP addresses of your network that receive Skype sessions. Helps identify Skype sessions. Separate IP addresses with commas.
                type: str
            socket_size:
                description:
                    - IPS socket buffer size. Max and default value depend on available memory. Can be changed to tune performance.
                type: int
            sync_session_ttl:
                description:
                    - Enable/disable use of kernel session TTL for IPS sessions.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tls_active_probe:
                description:
                    - TLS active probe configuration.
                type: dict
                suboptions:
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
                    source_ip:
                        description:
                            - Source IP address used for TLS active probe.
                        type: str
                    source_ip6:
                        description:
                            - Source IPv6 address used for TLS active probe.
                        type: str
                    vdom:
                        description:
                            - Virtual domain name for TLS active probe. Source system.vdom.name.
                        type: str
            traffic_submit:
                description:
                    - Enable/disable submitting attack data found by this FortiGate to FortiGuard.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure IPS global parameter.
  fortinet.fortios.fortios_ips_global:
      vdom: "{{ vdom }}"
      ips_global:
          anomaly_mode: "periodical"
          av_mem_limit: "0"
          cp_accel_mode: "none"
          database: "regular"
          deep_app_insp_db_limit: "0"
          deep_app_insp_timeout: "0"
          engine_count: "0"
          exclude_signatures: "none"
          fail_open: "enable"
          intelligent_mode: "enable"
          ips_reserve_cpu: "disable"
          machine_learning_detection: "enable"
          ngfw_max_scan_range: "4096"
          np_accel_mode: "none"
          packet_log_queue_depth: "128"
          session_limit_mode: "accurate"
          skype_client_public_ipaddr: "<your_own_value>"
          socket_size: "128"
          sync_session_ttl: "enable"
          tls_active_probe:
              interface: "<your_own_value> (source system.interface.name)"
              interface_select_method: "auto"
              source_ip: "84.230.14.43"
              source_ip6: "<your_own_value>"
              vdom: "<your_own_value> (source system.vdom.name)"
          traffic_submit: "enable"
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


def filter_ips_global_data(json):
    option_list = [
        "anomaly_mode",
        "av_mem_limit",
        "cp_accel_mode",
        "database",
        "deep_app_insp_db_limit",
        "deep_app_insp_timeout",
        "engine_count",
        "exclude_signatures",
        "fail_open",
        "intelligent_mode",
        "ips_reserve_cpu",
        "machine_learning_detection",
        "ngfw_max_scan_range",
        "np_accel_mode",
        "packet_log_queue_depth",
        "session_limit_mode",
        "skype_client_public_ipaddr",
        "socket_size",
        "sync_session_ttl",
        "tls_active_probe",
        "traffic_submit",
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


def ips_global(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    ips_global_data = data["ips_global"]

    filtered_data = filter_ips_global_data(ips_global_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("ips", "global", filtered_data, vdom=vdom)
        current_data = fos.get("ips", "global", vdom=vdom, mkey=mkey)
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
    data_copy["ips_global"] = filtered_data
    fos.do_member_operation(
        "ips",
        "global",
        data_copy,
    )

    return fos.set("ips", "global", data=converted_data, vdom=vdom)


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

    if data["ips_global"]:
        resp = ips_global(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("ips_global"))
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
        "fail_open": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "database": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "regular"}, {"value": "extended"}],
        },
        "traffic_submit": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "anomaly_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "periodical"}, {"value": "continuous"}],
        },
        "session_limit_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "accurate"}, {"value": "heuristic"}],
        },
        "socket_size": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "engine_count": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "sync_session_ttl": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "np_accel_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "basic"}],
        },
        "ips_reserve_cpu": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "cp_accel_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "basic"}, {"value": "advanced"}],
        },
        "deep_app_insp_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "deep_app_insp_db_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "exclude_signatures": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "ot", "v_range": [["v7.4.1", ""]]},
                {"value": "industrial", "v_range": [["v6.0.0", "v7.4.0"]]},
            ],
        },
        "packet_log_queue_depth": {"v_range": [["v6.2.7", ""]], "type": "integer"},
        "ngfw_max_scan_range": {"v_range": [["v6.4.4", ""]], "type": "integer"},
        "av_mem_limit": {"v_range": [["v7.4.2", ""]], "type": "integer"},
        "machine_learning_detection": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tls_active_probe": {
            "v_range": [["v6.2.7", "v6.2.7"], ["v6.4.4", ""]],
            "type": "dict",
            "children": {
                "interface_select_method": {
                    "v_range": [["v6.2.7", "v6.2.7"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "auto"},
                        {"value": "sdwan"},
                        {"value": "specify"},
                    ],
                },
                "interface": {
                    "v_range": [["v6.2.7", "v6.2.7"], ["v6.4.4", ""]],
                    "type": "string",
                },
                "vdom": {
                    "v_range": [["v6.2.7", "v6.2.7"], ["v6.4.4", ""]],
                    "type": "string",
                },
                "source_ip": {
                    "v_range": [["v6.2.7", "v6.2.7"], ["v6.4.4", ""]],
                    "type": "string",
                },
                "source_ip6": {
                    "v_range": [["v6.2.7", "v6.2.7"], ["v6.4.4", ""]],
                    "type": "string",
                },
            },
        },
        "intelligent_mode": {
            "v_range": [["v6.0.0", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "skype_client_public_ipaddr": {
            "v_range": [["v6.0.0", "v6.2.7"]],
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
        "ips_global": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["ips_global"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["ips_global"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "ips_global"
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
