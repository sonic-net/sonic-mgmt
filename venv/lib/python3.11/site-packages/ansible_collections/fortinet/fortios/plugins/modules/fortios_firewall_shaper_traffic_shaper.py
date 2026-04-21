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
module: fortios_firewall_shaper_traffic_shaper
short_description: Configure shared traffic shaper in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall_shaper feature and traffic_shaper category.
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
    firewall_shaper_traffic_shaper:
        description:
            - Configure shared traffic shaper.
        default: null
        type: dict
        suboptions:
            bandwidth_unit:
                description:
                    - Unit of measurement for guaranteed and maximum bandwidth for this shaper (Kbps, Mbps or Gbps).
                type: str
                choices:
                    - 'kbps'
                    - 'mbps'
                    - 'gbps'
            cos:
                description:
                    - VLAN CoS mark.
                type: str
            cos_marking:
                description:
                    - Enable/disable VLAN CoS marking.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cos_marking_method:
                description:
                    - Select VLAN CoS marking method.
                type: str
                choices:
                    - 'multi-stage'
                    - 'static'
            diffserv:
                description:
                    - Enable/disable changing the DiffServ setting applied to traffic accepted by this shaper.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            diffservcode:
                description:
                    - DiffServ setting to be applied to traffic accepted by this shaper.
                type: str
            dscp_marking_method:
                description:
                    - Select DSCP marking method.
                type: str
                choices:
                    - 'multi-stage'
                    - 'static'
            exceed_bandwidth:
                description:
                    - Exceed bandwidth used for DSCP/VLAN CoS multi-stage marking. Units depend on the bandwidth-unit setting.
                type: int
            exceed_class_id:
                description:
                    - Class ID for traffic in guaranteed-bandwidth and maximum-bandwidth. Source firewall.traffic-class.class-id.
                type: int
            exceed_cos:
                description:
                    - VLAN CoS mark for traffic in [guaranteed-bandwidth, exceed-bandwidth].
                type: str
            exceed_dscp:
                description:
                    - DSCP mark for traffic in guaranteed-bandwidth and exceed-bandwidth.
                type: str
            guaranteed_bandwidth:
                description:
                    - Amount of bandwidth guaranteed for this shaper (0 - 80000000). Units depend on the bandwidth-unit setting.
                type: int
            maximum_bandwidth:
                description:
                    - Upper bandwidth limit enforced by this shaper (0 - 80000000). 0 means no limit. Units depend on the bandwidth-unit setting.
                type: int
            maximum_cos:
                description:
                    - VLAN CoS mark for traffic in [exceed-bandwidth, maximum-bandwidth].
                type: str
            maximum_dscp:
                description:
                    - DSCP mark for traffic in exceed-bandwidth and maximum-bandwidth.
                type: str
            name:
                description:
                    - Traffic shaper name.
                required: true
                type: str
            overhead:
                description:
                    - Per-packet size overhead used in rate computations.
                type: int
            per_policy:
                description:
                    - Enable/disable applying a separate shaper for each policy. For example, if enabled the guaranteed bandwidth is applied separately for
                       each policy.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            priority:
                description:
                    - Higher priority traffic is more likely to be forwarded without delays and without compromising the guaranteed bandwidth.
                type: str
                choices:
                    - 'low'
                    - 'medium'
                    - 'high'
"""

EXAMPLES = """
- name: Configure shared traffic shaper.
  fortinet.fortios.fortios_firewall_shaper_traffic_shaper:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_shaper_traffic_shaper:
          bandwidth_unit: "kbps"
          cos: "<your_own_value>"
          cos_marking: "enable"
          cos_marking_method: "multi-stage"
          diffserv: "enable"
          diffservcode: "<your_own_value>"
          dscp_marking_method: "multi-stage"
          exceed_bandwidth: "0"
          exceed_class_id: "0"
          exceed_cos: "<your_own_value>"
          exceed_dscp: "<your_own_value>"
          guaranteed_bandwidth: "0"
          maximum_bandwidth: "0"
          maximum_cos: "<your_own_value>"
          maximum_dscp: "<your_own_value>"
          name: "default_name_18"
          overhead: "0"
          per_policy: "disable"
          priority: "low"
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


def filter_firewall_shaper_traffic_shaper_data(json):
    option_list = [
        "bandwidth_unit",
        "cos",
        "cos_marking",
        "cos_marking_method",
        "diffserv",
        "diffservcode",
        "dscp_marking_method",
        "exceed_bandwidth",
        "exceed_class_id",
        "exceed_cos",
        "exceed_dscp",
        "guaranteed_bandwidth",
        "maximum_bandwidth",
        "maximum_cos",
        "maximum_dscp",
        "name",
        "overhead",
        "per_policy",
        "priority",
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


def firewall_shaper_traffic_shaper(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_shaper_traffic_shaper_data = data["firewall_shaper_traffic_shaper"]

    filtered_data = filter_firewall_shaper_traffic_shaper_data(
        firewall_shaper_traffic_shaper_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey(
            "firewall.shaper", "traffic-shaper", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "firewall.shaper", "traffic-shaper", vdom=vdom, mkey=mkey
        )
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
    data_copy["firewall_shaper_traffic_shaper"] = filtered_data
    fos.do_member_operation(
        "firewall.shaper",
        "traffic-shaper",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "firewall.shaper", "traffic-shaper", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "firewall.shaper", "traffic-shaper", mkey=converted_data["name"], vdom=vdom
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


def fortios_firewall_shaper(data, fos, check_mode):

    if data["firewall_shaper_traffic_shaper"]:
        resp = firewall_shaper_traffic_shaper(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("firewall_shaper_traffic_shaper")
        )
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
        "guaranteed_bandwidth": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "maximum_bandwidth": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "bandwidth_unit": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "kbps"}, {"value": "mbps"}, {"value": "gbps"}],
        },
        "priority": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "low"}, {"value": "medium"}, {"value": "high"}],
        },
        "per_policy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "diffserv": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffservcode": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dscp_marking_method": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "multi-stage"}, {"value": "static"}],
        },
        "exceed_bandwidth": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "exceed_dscp": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "maximum_dscp": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "cos_marking": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cos_marking_method": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "multi-stage"}, {"value": "static"}],
        },
        "cos": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "exceed_cos": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "maximum_cos": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "overhead": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "exceed_class_id": {"v_range": [["v6.2.0", ""]], "type": "integer"},
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
        "firewall_shaper_traffic_shaper": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_shaper_traffic_shaper"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_shaper_traffic_shaper"]["options"][attribute_name][
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
            fos, versioned_schema, "firewall_shaper_traffic_shaper"
        )

        is_error, has_changed, result, diff = fortios_firewall_shaper(
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
