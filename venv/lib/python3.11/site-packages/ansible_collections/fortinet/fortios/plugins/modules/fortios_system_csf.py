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
module: fortios_system_csf
short_description: Add this FortiGate to a Security Fabric or set up a new Security Fabric on this FortiGate in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and csf category.
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

    system_csf:
        description:
            - Add this FortiGate to a Security Fabric or set up a new Security Fabric on this FortiGate.
        default: null
        type: dict
        suboptions:
            accept_auth_by_cert:
                description:
                    - Accept connections with unknown certificates and ask admin for approval.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            authorization_request_type:
                description:
                    - Authorization request type.
                type: str
                choices:
                    - 'serial'
                    - 'certificate'
            certificate:
                description:
                    - Certificate. Source certificate.local.name.
                type: str
            configuration_sync:
                description:
                    - Configuration sync mode.
                type: str
                choices:
                    - 'default'
                    - 'local'
            downstream_access:
                description:
                    - Enable/disable downstream device access to this device"s configuration and data.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            downstream_accprofile:
                description:
                    - Default access profile for requests from downstream devices. Source system.accprofile.name.
                type: str
            fabric_connector:
                description:
                    - Fabric connector configuration.
                type: list
                elements: dict
                suboptions:
                    accprofile:
                        description:
                            - Override access profile. Source system.accprofile.name.
                        type: str
                    configuration_write_access:
                        description:
                            - Enable/disable downstream device write access to configuration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    serial:
                        description:
                            - Serial.
                        required: true
                        type: str
                    vdom:
                        description:
                            - Virtual domains that the connector has access to. If none are set, the connector will only have access to the VDOM that it joins
                               the Security Fabric through.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Virtual domain name. Source system.vdom.name.
                                required: true
                                type: str
            fabric_device:
                description:
                    - Fabric device configuration.
                type: list
                elements: dict
                suboptions:
                    access_token:
                        description:
                            - Device access token.
                        type: str
                    device_ip:
                        description:
                            - Device IP.
                        type: str
                    device_type:
                        description:
                            - Device type.
                        type: str
                        choices:
                            - 'fortimail'
                    https_port:
                        description:
                            - HTTPS port for fabric device.
                        type: int
                    login:
                        description:
                            - Device login name.
                        type: str
                    name:
                        description:
                            - Device name.
                        required: true
                        type: str
                    password:
                        description:
                            - Device login password.
                        type: str
            fabric_object_unification:
                description:
                    - Fabric CMDB Object Unification.
                type: str
                choices:
                    - 'default'
                    - 'local'
            fabric_workers:
                description:
                    - Number of worker processes for Security Fabric daemon.
                type: int
            file_mgmt:
                description:
                    - Enable/disable Security Fabric daemon file management.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            file_quota:
                description:
                    - Maximum amount of memory that can be used by the daemon files (in bytes).
                type: int
            file_quota_warning:
                description:
                    - Warn when the set percentage of quota has been used.
                type: int
            fixed_key:
                description:
                    - Auto-generated fixed key used when this device is the root. (Will automatically be generated if not set.)
                type: str
            forticloud_account_enforcement:
                description:
                    - Fabric FortiCloud account unification.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            group_name:
                description:
                    - Security Fabric group name. All FortiGates in a Security Fabric must have the same group name.
                type: str
            group_password:
                description:
                    - Security Fabric group password. For legacy authentication, fabric members must have the same group password.
                type: str
            legacy_authentication:
                description:
                    - Enable/disable legacy authentication.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            log_unification:
                description:
                    - Enable/disable broadcast of discovery messages for log unification.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            management_ip:
                description:
                    - Management IP address of this FortiGate. Used to log into this FortiGate from another FortiGate in the Security Fabric.
                type: str
            management_port:
                description:
                    - Overriding port for management connection (Overrides admin port).
                type: int
            saml_configuration_sync:
                description:
                    - SAML setting configuration synchronization.
                type: str
                choices:
                    - 'default'
                    - 'local'
            source_ip:
                description:
                    - Source IP address for communication with the upstream FortiGate.
                type: str
            status:
                description:
                    - Enable/disable Security Fabric.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            trusted_list:
                description:
                    - Pre-authorized and blocked security fabric nodes.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Security fabric authorization action.
                        type: str
                        choices:
                            - 'accept'
                            - 'deny'
                    authorization_type:
                        description:
                            - Authorization type.
                        type: str
                        choices:
                            - 'serial'
                            - 'certificate'
                    certificate:
                        description:
                            - Certificate.
                        type: str
                    downstream_authorization:
                        description:
                            - Trust authorizations by this node"s administrator.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ha_members:
                        description:
                            - HA members.
                        type: list
                        elements: str
                    index:
                        description:
                            - Index of the downstream in tree.
                        type: int
                    name:
                        description:
                            - Name.
                        required: true
                        type: str
                    serial:
                        description:
                            - Serial.
                        type: str
            uid:
                description:
                    - Unique ID of the current CSF node
                type: str
            upstream:
                description:
                    - IP/FQDN of the FortiGate upstream from this FortiGate in the Security Fabric.
                type: str
            upstream_interface:
                description:
                    - Specify outgoing interface to reach server. Source system.interface.name.
                type: str
            upstream_interface_select_method:
                description:
                    - Specify how to select outgoing interface to reach server.
                type: str
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            upstream_ip:
                description:
                    - IP address of the FortiGate upstream from this FortiGate in the Security Fabric.
                type: str
            upstream_port:
                description:
                    - The port number to use to communicate with the FortiGate upstream from this FortiGate in the Security Fabric .
                type: int
"""

EXAMPLES = """
- name: Add this FortiGate to a Security Fabric or set up a new Security Fabric on this FortiGate.
  fortinet.fortios.fortios_system_csf:
      vdom: "{{ vdom }}"
      system_csf:
          accept_auth_by_cert: "disable"
          authorization_request_type: "serial"
          certificate: "<your_own_value> (source certificate.local.name)"
          configuration_sync: "default"
          downstream_access: "enable"
          downstream_accprofile: "<your_own_value> (source system.accprofile.name)"
          fabric_connector:
              -
                  accprofile: "<your_own_value> (source system.accprofile.name)"
                  configuration_write_access: "enable"
                  serial: "<your_own_value>"
                  vdom:
                      -
                          name: "default_name_14 (source system.vdom.name)"
          fabric_device:
              -
                  access_token: "<your_own_value>"
                  device_ip: "<your_own_value>"
                  device_type: "fortimail"
                  https_port: "443"
                  login: "<your_own_value>"
                  name: "default_name_21"
                  password: "<your_own_value>"
          fabric_object_unification: "default"
          fabric_workers: "2"
          file_mgmt: "enable"
          file_quota: "0"
          file_quota_warning: "90"
          fixed_key: "<your_own_value>"
          forticloud_account_enforcement: "enable"
          group_name: "<your_own_value>"
          group_password: "<your_own_value>"
          legacy_authentication: "disable"
          log_unification: "disable"
          management_ip: "<your_own_value>"
          management_port: "32767"
          saml_configuration_sync: "default"
          source_ip: "84.230.14.43"
          status: "enable"
          trusted_list:
              -
                  action: "accept"
                  authorization_type: "serial"
                  certificate: "<your_own_value>"
                  downstream_authorization: "enable"
                  ha_members: "<your_own_value>"
                  index: "0"
                  name: "default_name_46"
                  serial: "<your_own_value>"
          uid: "<your_own_value>"
          upstream: "<your_own_value>"
          upstream_interface: "<your_own_value> (source system.interface.name)"
          upstream_interface_select_method: "auto"
          upstream_ip: "<your_own_value>"
          upstream_port: "8013"
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


def filter_system_csf_data(json):
    option_list = [
        "accept_auth_by_cert",
        "authorization_request_type",
        "certificate",
        "configuration_sync",
        "downstream_access",
        "downstream_accprofile",
        "fabric_connector",
        "fabric_device",
        "fabric_object_unification",
        "fabric_workers",
        "file_mgmt",
        "file_quota",
        "file_quota_warning",
        "fixed_key",
        "forticloud_account_enforcement",
        "group_name",
        "group_password",
        "legacy_authentication",
        "log_unification",
        "management_ip",
        "management_port",
        "saml_configuration_sync",
        "source_ip",
        "status",
        "trusted_list",
        "uid",
        "upstream",
        "upstream_interface",
        "upstream_interface_select_method",
        "upstream_ip",
        "upstream_port",
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
        ["trusted_list", "ha_members"],
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


def system_csf(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_csf_data = data["system_csf"]

    filtered_data = filter_system_csf_data(system_csf_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "csf", filtered_data, vdom=vdom)
        current_data = fos.get("system", "csf", vdom=vdom, mkey=mkey)
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
    data_copy["system_csf"] = filtered_data
    fos.do_member_operation(
        "system",
        "csf",
        data_copy,
    )

    return fos.set("system", "csf", data=converted_data, vdom=vdom)


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

    if data["system_csf"]:
        resp = system_csf(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_csf"))
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
        "uid": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "upstream": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "source_ip": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "upstream_interface_select_method": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "upstream_interface": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "upstream_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "group_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "group_password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "accept_auth_by_cert": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "log_unification": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "authorization_request_type": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "serial"}, {"value": "certificate"}],
        },
        "certificate": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "fabric_workers": {"v_range": [["v6.4.4", ""]], "type": "integer"},
        "downstream_access": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "legacy_authentication": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "downstream_accprofile": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "configuration_sync": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "default"}, {"value": "local"}],
        },
        "fabric_object_unification": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "default"}, {"value": "local"}],
        },
        "saml_configuration_sync": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "default"}, {"value": "local"}],
        },
        "trusted_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "required": True,
                },
                "authorization_type": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "serial"}, {"value": "certificate"}],
                },
                "serial": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "certificate": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                },
                "action": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "accept"}, {"value": "deny"}],
                },
                "ha_members": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "downstream_authorization": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "index": {"v_range": [["v7.2.4", ""]], "type": "integer"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "fabric_connector": {
            "type": "list",
            "elements": "dict",
            "children": {
                "serial": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "accprofile": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "configuration_write_access": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "vdom": {
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
            },
            "v_range": [["v7.0.0", ""]],
        },
        "forticloud_account_enforcement": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "file_mgmt": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "file_quota": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "file_quota_warning": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "fabric_device": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "string",
                    "required": True,
                },
                "device_ip": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "string"},
                "https_port": {"v_range": [["v6.2.0", "v7.0.12"]], "type": "integer"},
                "access_token": {"v_range": [["v6.2.0", "v7.0.12"]], "type": "string"},
                "device_type": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [{"value": "fortimail"}],
                },
                "login": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
                "password": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
            },
            "v_range": [["v6.0.0", "v7.0.12"]],
        },
        "upstream_ip": {"v_range": [["v6.0.0", "v7.0.1"]], "type": "string"},
        "management_ip": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
        "management_port": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "integer"},
        "fixed_key": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
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
        "system_csf": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_csf"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_csf"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_csf"
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
