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
module: fortios_icap_profile
short_description: Configure ICAP profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify icap feature and profile category.
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
    icap_profile:
        description:
            - Configure ICAP profiles.
        default: null
        type: dict
        suboptions:
            response_204:
                description:
                    - Enable/disable allowance of 204 response from ICAP server.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            size_limit_204:
                description:
                    - 204 response size limit to be saved by ICAP client in megabytes (1 - 10).
                type: int
            chunk_encap:
                description:
                    - Enable/disable chunked encapsulation .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                description:
                    - Comment.
                type: str
            extension_feature:
                description:
                    - Enable/disable ICAP extension features.
                type: list
                elements: str
                choices:
                    - 'scan-progress'
            file_transfer:
                description:
                    - Configure the file transfer protocols to pass transferred files to an ICAP server as REQMOD.
                type: list
                elements: str
                choices:
                    - 'ssh'
                    - 'ftp'
            file_transfer_failure:
                description:
                    - Action to take if the ICAP server cannot be contacted when processing a file transfer.
                type: str
                choices:
                    - 'error'
                    - 'bypass'
            file_transfer_path:
                description:
                    - Path component of the ICAP URI that identifies the file transfer processing service.
                type: str
            file_transfer_server:
                description:
                    - ICAP server to use for a file transfer. Source icap.server.name icap.server-group.name.
                type: str
            icap_block_log:
                description:
                    - Enable/disable UTM log when infection found .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            icap_headers:
                description:
                    - Configure ICAP forwarded request headers.
                type: list
                elements: dict
                suboptions:
                    base64_encoding:
                        description:
                            - Enable/disable use of base64 encoding of HTTP content.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    content:
                        description:
                            - HTTP header content.
                        type: str
                    id:
                        description:
                            - HTTP forwarded header ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    name:
                        description:
                            - HTTP forwarded header name.
                        type: str
            methods:
                description:
                    - The allowed HTTP methods that will be sent to ICAP server for further processing.
                type: list
                elements: str
                choices:
                    - 'delete'
                    - 'get'
                    - 'head'
                    - 'options'
                    - 'post'
                    - 'put'
                    - 'trace'
                    - 'connect'
                    - 'other'
            name:
                description:
                    - ICAP profile name.
                required: true
                type: str
            ocr_only:
                description:
                    - Enable/disable this FortiGate unit to submit only OCR interested content to the ICAP server.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            preview:
                description:
                    - Enable/disable preview of data to ICAP server.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            preview_data_length:
                description:
                    - Preview data length to be sent to ICAP server.
                type: int
            replacemsg_group:
                description:
                    - Replacement message group. Source system.replacemsg-group.name.
                type: str
            request:
                description:
                    - Enable/disable whether an HTTP request is passed to an ICAP server.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            request_failure:
                description:
                    - Action to take if the ICAP server cannot be contacted when processing an HTTP request.
                type: str
                choices:
                    - 'error'
                    - 'bypass'
            request_path:
                description:
                    - Path component of the ICAP URI that identifies the HTTP request processing service.
                type: str
            request_server:
                description:
                    - ICAP server to use for an HTTP request. Source icap.server.name icap.server-group.name.
                type: str
            respmod_default_action:
                description:
                    - Default action to ICAP response modification (respmod) processing.
                type: str
                choices:
                    - 'forward'
                    - 'bypass'
            respmod_forward_rules:
                description:
                    - ICAP response mode forward rules.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action to be taken for ICAP server.
                        type: str
                        choices:
                            - 'forward'
                            - 'bypass'
                    header_group:
                        description:
                            - HTTP header group.
                        type: list
                        elements: dict
                        suboptions:
                            case_sensitivity:
                                description:
                                    - Enable/disable case sensitivity when matching header.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            header:
                                description:
                                    - HTTP header regular expression.
                                type: str
                            header_name:
                                description:
                                    - HTTP header.
                                type: str
                            id:
                                description:
                                    - ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                    host:
                        description:
                            - Address object for the host. Source firewall.address.name firewall.addrgrp.name firewall.proxy-address.name.
                        type: str
                    http_resp_status_code:
                        description:
                            - HTTP response status code.
                        type: list
                        elements: dict
                        suboptions:
                            code:
                                description:
                                    - HTTP response status code. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                    name:
                        description:
                            - Address name.
                        required: true
                        type: str
            response:
                description:
                    - Enable/disable whether an HTTP response is passed to an ICAP server.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            response_failure:
                description:
                    - Action to take if the ICAP server cannot be contacted when processing an HTTP response.
                type: str
                choices:
                    - 'error'
                    - 'bypass'
            response_path:
                description:
                    - Path component of the ICAP URI that identifies the HTTP response processing service.
                type: str
            response_req_hdr:
                description:
                    - Enable/disable addition of req-hdr for ICAP response modification (respmod) processing.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            response_server:
                description:
                    - ICAP server to use for an HTTP response. Source icap.server.name icap.server-group.name.
                type: str
            scan_progress_interval:
                description:
                    - Scan progress interval value.
                type: int
            streaming_content_bypass:
                description:
                    - Enable/disable bypassing of ICAP server for streaming content.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            timeout:
                description:
                    - Time (in seconds) that ICAP client waits for the response from ICAP server.
                type: int
"""

EXAMPLES = """
- name: Configure ICAP profiles.
  fortinet.fortios.fortios_icap_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      icap_profile:
          response_204: "disable"
          size_limit_204: "1"
          chunk_encap: "disable"
          comment: "Comment."
          extension_feature: "scan-progress"
          file_transfer: "ssh"
          file_transfer_failure: "error"
          file_transfer_path: "<your_own_value>"
          file_transfer_server: "<your_own_value> (source icap.server.name icap.server-group.name)"
          icap_block_log: "disable"
          icap_headers:
              -
                  base64_encoding: "disable"
                  content: "<your_own_value>"
                  id: "16"
                  name: "default_name_17"
          methods: "delete"
          name: "default_name_19"
          ocr_only: "disable"
          preview: "disable"
          preview_data_length: "0"
          replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
          request: "disable"
          request_failure: "error"
          request_path: "<your_own_value>"
          request_server: "<your_own_value> (source icap.server.name icap.server-group.name)"
          respmod_default_action: "forward"
          respmod_forward_rules:
              -
                  action: "forward"
                  header_group:
                      -
                          case_sensitivity: "disable"
                          header: "<your_own_value>"
                          header_name: "<your_own_value>"
                          id: "35"
                  host: "myhostname (source firewall.address.name firewall.addrgrp.name firewall.proxy-address.name)"
                  http_resp_status_code:
                      -
                          code: "<you_own_value>"
                  name: "default_name_39"
          response: "disable"
          response_failure: "error"
          response_path: "<your_own_value>"
          response_req_hdr: "disable"
          response_server: "<your_own_value> (source icap.server.name icap.server-group.name)"
          scan_progress_interval: "10"
          streaming_content_bypass: "disable"
          timeout: "30"
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


def filter_icap_profile_data(json):
    option_list = [
        "response_204",
        "size_limit_204",
        "chunk_encap",
        "comment",
        "extension_feature",
        "file_transfer",
        "file_transfer_failure",
        "file_transfer_path",
        "file_transfer_server",
        "icap_block_log",
        "icap_headers",
        "methods",
        "name",
        "ocr_only",
        "preview",
        "preview_data_length",
        "replacemsg_group",
        "request",
        "request_failure",
        "request_path",
        "request_server",
        "respmod_default_action",
        "respmod_forward_rules",
        "response",
        "response_failure",
        "response_path",
        "response_req_hdr",
        "response_server",
        "scan_progress_interval",
        "streaming_content_bypass",
        "timeout",
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
        ["file_transfer"],
        ["methods"],
        ["extension_feature"],
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


def valid_attr_to_invalid_attr(data):
    speciallist = {"204_response": "response_204", "204_size_limit": "size_limit_204"}

    for k, v in speciallist.items():
        if v == data:
            return k

    return data


def valid_attr_to_invalid_attrs(data):
    if isinstance(data, list):
        new_data = []
        for elem in data:
            elem = valid_attr_to_invalid_attrs(elem)
            new_data.append(elem)
        data = new_data
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[valid_attr_to_invalid_attr(k)] = valid_attr_to_invalid_attrs(v)
        data = new_data

    return valid_attr_to_invalid_attr(data)


def icap_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    icap_profile_data = data["icap_profile"]

    filtered_data = filter_icap_profile_data(icap_profile_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("icap", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("icap", "profile", vdom=vdom, mkey=mkey)
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
    data_copy["icap_profile"] = filtered_data
    fos.do_member_operation(
        "icap",
        "profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("icap", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("icap", "profile", mkey=converted_data["name"], vdom=vdom)
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


def fortios_icap(data, fos, check_mode):

    if data["icap_profile"]:
        resp = icap_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("icap_profile"))
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
        "replacemsg_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "comment": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "request": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "response": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "file_transfer": {
            "v_range": [["v7.2.0", ""]],
            "type": "list",
            "options": [{"value": "ssh"}, {"value": "ftp"}],
            "multiple_values": True,
            "elements": "str",
        },
        "streaming_content_bypass": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ocr_only": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "preview": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "preview_data_length": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "request_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "response_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "file_transfer_server": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "request_failure": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "error"}, {"value": "bypass"}],
        },
        "response_failure": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "error"}, {"value": "bypass"}],
        },
        "file_transfer_failure": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "error"}, {"value": "bypass"}],
        },
        "request_path": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "response_path": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "file_transfer_path": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "methods": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "delete"},
                {"value": "get"},
                {"value": "head"},
                {"value": "options"},
                {"value": "post"},
                {"value": "put"},
                {"value": "trace"},
                {"value": "connect", "v_range": [["v7.2.0", ""]]},
                {"value": "other"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "response_req_hdr": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "respmod_default_action": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "forward"}, {"value": "bypass"}],
        },
        "icap_block_log": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "chunk_encap": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "extension_feature": {
            "v_range": [["v7.0.2", ""]],
            "type": "list",
            "options": [{"value": "scan-progress"}],
            "multiple_values": True,
            "elements": "str",
        },
        "scan_progress_interval": {"v_range": [["v7.0.2", ""]], "type": "integer"},
        "timeout": {"v_range": [["v7.2.0", ""]], "type": "integer"},
        "icap_headers": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "name": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "content": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "base64_encoding": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
            },
            "v_range": [["v6.2.0", ""]],
        },
        "respmod_forward_rules": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "host": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "header_group": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "header_name": {"v_range": [["v6.4.0", ""]], "type": "string"},
                        "header": {"v_range": [["v6.4.0", ""]], "type": "string"},
                        "case_sensitivity": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                    },
                    "v_range": [["v6.4.0", ""]],
                },
                "action": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "forward"}, {"value": "bypass"}],
                },
                "http_resp_status_code": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "code": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
            },
            "v_range": [["v6.4.0", ""]],
        },
        "size_limit_204": {"v_range": [["v7.2.0", ""]], "type": "integer"},
        "response_204": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
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
        "icap_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["icap_profile"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["icap_profile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "icap_profile"
        )

        is_error, has_changed, result, diff = fortios_icap(
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
