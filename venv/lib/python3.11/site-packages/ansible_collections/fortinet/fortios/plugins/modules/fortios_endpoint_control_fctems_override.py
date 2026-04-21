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
module: fortios_endpoint_control_fctems_override
short_description: Configure FortiClient Enterprise Management Server (EMS) entries in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify endpoint_control feature and fctems_override category.
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
    - We highly recommend using your own value as the ems_id instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
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
    endpoint_control_fctems_override:
        description:
            - Configure FortiClient Enterprise Management Server (EMS) entries.
        default: null
        type: dict
        suboptions:
            call_timeout:
                description:
                    - FortiClient EMS call timeout in seconds (1 - 180 seconds).
                type: int
            capabilities:
                description:
                    - List of EMS capabilities.
                type: list
                elements: str
                choices:
                    - 'fabric-auth'
                    - 'silent-approval'
                    - 'websocket'
                    - 'websocket-malware'
                    - 'push-ca-certs'
                    - 'common-tags-api'
                    - 'tenant-id'
                    - 'client-avatars'
                    - 'single-vdom-connector'
                    - 'fgt-sysinfo-api'
                    - 'ztna-server-info'
                    - 'used-tags'
            cloud_authentication_access_key:
                description:
                    - FortiClient EMS Cloud multitenancy access key
                type: str
            cloud_server_type:
                description:
                    - Cloud server type.
                type: str
                choices:
                    - 'production'
                    - 'alpha'
                    - 'beta'
            dirty_reason:
                description:
                    - Dirty Reason for FortiClient EMS.
                type: str
                choices:
                    - 'none'
                    - 'mismatched-ems-sn'
            ems_id:
                description:
                    - EMS ID in order (1 - 7). see <a href='#notes'>Notes</a>.
                required: true
                type: int
            fortinetone_cloud_authentication:
                description:
                    - Enable/disable authentication of FortiClient EMS Cloud through FortiCloud account.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            https_port:
                description:
                    - 'FortiClient EMS HTTPS access port number. (1 - 65535).'
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
            name:
                description:
                    - FortiClient Enterprise Management Server (EMS) name.
                type: str
            out_of_sync_threshold:
                description:
                    - Outdated resource threshold in seconds (10 - 3600).
                type: int
            preserve_ssl_session:
                description:
                    - Enable/disable preservation of EMS SSL session connection. Warning, most users should not touch this setting.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pull_avatars:
                description:
                    - Enable/disable pulling avatars from EMS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pull_malware_hash:
                description:
                    - Enable/disable pulling FortiClient malware hash from EMS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pull_sysinfo:
                description:
                    - Enable/disable pulling SysInfo from EMS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pull_tags:
                description:
                    - Enable/disable pulling FortiClient user tags from EMS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pull_vulnerabilities:
                description:
                    - Enable/disable pulling vulnerabilities from EMS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            send_tags_to_all_vdoms:
                description:
                    - Relax restrictions on tags to send all EMS tags to all VDOMs
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            serial_number:
                description:
                    - EMS Serial Number.
                type: str
            server:
                description:
                    - FortiClient EMS FQDN or IPv4 address.
                type: str
            source_ip:
                description:
                    - REST API call source IP.
                type: str
            status:
                description:
                    - Enable or disable this EMS configuration.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tenant_id:
                description:
                    - EMS Tenant ID.
                type: str
            trust_ca_cn:
                description:
                    - Enable/disable trust of the EMS certificate issuer(CA) and common name(CN) for certificate auto-renewal.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            verifying_ca:
                description:
                    - Lowest CA cert on Fortigate in verified EMS cert chain. Source certificate.ca.name vpn.certificate.ca.name.
                type: str
            websocket_override:
                description:
                    - Enable/disable override behavior for how this FortiGate unit connects to EMS using a WebSocket connection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure FortiClient Enterprise Management Server (EMS) entries.
  fortinet.fortios.fortios_endpoint_control_fctems_override:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      endpoint_control_fctems_override:
          call_timeout: "30"
          capabilities: "fabric-auth"
          cloud_authentication_access_key: "<your_own_value>"
          cloud_server_type: "production"
          dirty_reason: "none"
          ems_id: "<you_own_value>"
          fortinetone_cloud_authentication: "enable"
          https_port: "443"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          name: "default_name_13"
          out_of_sync_threshold: "180"
          preserve_ssl_session: "enable"
          pull_avatars: "enable"
          pull_malware_hash: "enable"
          pull_sysinfo: "enable"
          pull_tags: "enable"
          pull_vulnerabilities: "enable"
          send_tags_to_all_vdoms: "enable"
          serial_number: "<your_own_value>"
          server: "192.168.100.40"
          source_ip: "84.230.14.43"
          status: "enable"
          tenant_id: "<your_own_value>"
          trust_ca_cn: "enable"
          verifying_ca: "<your_own_value> (source certificate.ca.name vpn.certificate.ca.name)"
          websocket_override: "enable"
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


def filter_endpoint_control_fctems_override_data(json):
    option_list = [
        "call_timeout",
        "capabilities",
        "cloud_authentication_access_key",
        "cloud_server_type",
        "dirty_reason",
        "ems_id",
        "fortinetone_cloud_authentication",
        "https_port",
        "interface",
        "interface_select_method",
        "name",
        "out_of_sync_threshold",
        "preserve_ssl_session",
        "pull_avatars",
        "pull_malware_hash",
        "pull_sysinfo",
        "pull_tags",
        "pull_vulnerabilities",
        "send_tags_to_all_vdoms",
        "serial_number",
        "server",
        "source_ip",
        "status",
        "tenant_id",
        "trust_ca_cn",
        "verifying_ca",
        "websocket_override",
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
        ["capabilities"],
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


def endpoint_control_fctems_override(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    endpoint_control_fctems_override_data = data["endpoint_control_fctems_override"]

    filtered_data = filter_endpoint_control_fctems_override_data(
        endpoint_control_fctems_override_data
    )
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey(
            "endpoint-control", "fctems-override", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "endpoint-control", "fctems-override", vdom=vdom, mkey=mkey
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
    data_copy["endpoint_control_fctems_override"] = filtered_data
    fos.do_member_operation(
        "endpoint-control",
        "fctems-override",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "endpoint-control", "fctems-override", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "endpoint-control",
            "fctems-override",
            mkey=converted_data["ems-id"],
            vdom=vdom,
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


def fortios_endpoint_control(data, fos, check_mode):

    if data["endpoint_control_fctems_override"]:
        resp = endpoint_control_fctems_override(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("endpoint_control_fctems_override")
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
        "ems_id": {"v_range": [["v7.4.0", ""]], "type": "integer", "required": True},
        "status": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "name": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "dirty_reason": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "mismatched-ems-sn"}],
        },
        "fortinetone_cloud_authentication": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cloud_authentication_access_key": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
        },
        "server": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "https_port": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "serial_number": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "tenant_id": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "source_ip": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "pull_sysinfo": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pull_vulnerabilities": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pull_tags": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pull_malware_hash": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "capabilities": {
            "v_range": [["v7.4.0", ""]],
            "type": "list",
            "options": [
                {"value": "fabric-auth"},
                {"value": "silent-approval"},
                {"value": "websocket"},
                {"value": "websocket-malware"},
                {"value": "push-ca-certs"},
                {"value": "common-tags-api"},
                {"value": "tenant-id"},
                {"value": "client-avatars", "v_range": [["v7.4.1", ""]]},
                {"value": "single-vdom-connector"},
                {"value": "fgt-sysinfo-api", "v_range": [["v7.4.4", ""]]},
                {"value": "ztna-server-info", "v_range": [["v7.4.4", ""]]},
                {"value": "used-tags", "v_range": [["v7.6.4", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "call_timeout": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "out_of_sync_threshold": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "send_tags_to_all_vdoms": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "websocket_override": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "interface_select_method": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "trust_ca_cn": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "verifying_ca": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "pull_avatars": {
            "v_range": [["v7.4.0", "v7.4.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "preserve_ssl_session": {
            "v_range": [["v7.4.0", "v7.4.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cloud_server_type": {
            "v_range": [["v7.4.0", "v7.4.0"]],
            "type": "string",
            "options": [{"value": "production"}, {"value": "alpha"}, {"value": "beta"}],
        },
    },
    "v_range": [["v7.4.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "ems_id"
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
        "endpoint_control_fctems_override": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["endpoint_control_fctems_override"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["endpoint_control_fctems_override"]["options"][attribute_name][
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
            fos, versioned_schema, "endpoint_control_fctems_override"
        )

        is_error, has_changed, result, diff = fortios_endpoint_control(
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
