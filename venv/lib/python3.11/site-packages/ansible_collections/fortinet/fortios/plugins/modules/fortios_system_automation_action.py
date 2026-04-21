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
module: fortios_system_automation_action
short_description: Action for automation stitches in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and automation_action category.
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
    system_automation_action:
        description:
            - Action for automation stitches.
        default: null
        type: dict
        suboptions:
            accprofile:
                description:
                    - Access profile for CLI script action to access FortiGate features. Source system.accprofile.name.
                type: str
            action_type:
                description:
                    - Action type.
                type: str
                choices:
                    - 'email'
                    - 'fortiexplorer-notification'
                    - 'alert'
                    - 'disable-ssid'
                    - 'system-actions'
                    - 'quarantine'
                    - 'quarantine-forticlient'
                    - 'quarantine-nsx'
                    - 'quarantine-fortinac'
                    - 'ban-ip'
                    - 'aws-lambda'
                    - 'azure-function'
                    - 'google-cloud-function'
                    - 'alicloud-function'
                    - 'webhook'
                    - 'cli-script'
                    - 'diagnose-script'
                    - 'regular-expression'
                    - 'slack-notification'
                    - 'microsoft-teams-notification'
                    - 'ios-notification'
            alicloud_access_key_id:
                description:
                    - AliCloud AccessKey ID.
                type: str
            alicloud_access_key_secret:
                description:
                    - AliCloud AccessKey secret.
                type: str
            alicloud_account_id:
                description:
                    - AliCloud account ID.
                type: str
            alicloud_function:
                description:
                    - AliCloud function name.
                type: str
            alicloud_function_authorization:
                description:
                    - AliCloud function authorization type.
                type: str
                choices:
                    - 'anonymous'
                    - 'function'
            alicloud_function_domain:
                description:
                    - AliCloud function domain.
                type: str
            alicloud_region:
                description:
                    - AliCloud region.
                type: str
            alicloud_service:
                description:
                    - AliCloud service name.
                type: str
            alicloud_version:
                description:
                    - AliCloud version.
                type: str
            aws_api_id:
                description:
                    - AWS API Gateway ID.
                type: str
            aws_api_key:
                description:
                    - AWS API Gateway API key.
                type: str
            aws_api_path:
                description:
                    - AWS API Gateway path.
                type: str
            aws_api_stage:
                description:
                    - AWS API Gateway deployment stage name.
                type: str
            aws_domain:
                description:
                    - AWS domain.
                type: str
            aws_region:
                description:
                    - AWS region.
                type: str
            azure_api_key:
                description:
                    - Azure function API key.
                type: str
            azure_app:
                description:
                    - Azure function application name.
                type: str
            azure_domain:
                description:
                    - Azure function domain.
                type: str
            azure_function:
                description:
                    - Azure function name.
                type: str
            azure_function_authorization:
                description:
                    - Azure function authorization level.
                type: str
                choices:
                    - 'anonymous'
                    - 'function'
                    - 'admin'
            delay:
                description:
                    - Delay before execution (in seconds).
                type: int
            description:
                description:
                    - Description.
                type: str
            duration:
                description:
                    - Maximum running time for this script in seconds.
                type: int
            email_body:
                description:
                    - Email body.
                type: str
            email_from:
                description:
                    - Email sender name.
                type: str
            email_subject:
                description:
                    - Email subject.
                type: str
            email_to:
                description:
                    - Email addresses.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Email address.
                        required: true
                        type: str
            execute_security_fabric:
                description:
                    - Enable/disable execution of CLI script on all or only one FortiGate unit in the Security Fabric.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            file_only:
                description:
                    - Enable/disable the output in files only.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            form_data:
                description:
                    - Form data parts for content type multipart/form-data.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    key:
                        description:
                            - Key of the part of Multipart/form-data.
                        type: str
                    value:
                        description:
                            - Value of the part of Multipart/form-data.
                        type: str
            forticare_email:
                description:
                    - Enable/disable use of your FortiCare email address as the email-to address.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fos_message:
                description:
                    - Message content.
                type: str
            gcp_function:
                description:
                    - Google Cloud function name.
                type: str
            gcp_function_domain:
                description:
                    - Google Cloud function domain.
                type: str
            gcp_function_region:
                description:
                    - Google Cloud function region.
                type: str
            gcp_project:
                description:
                    - Google Cloud Platform project name.
                type: str
            headers:
                description:
                    - Request headers.
                type: list
                elements: dict
                suboptions:
                    header:
                        description:
                            - Request header.
                        required: true
                        type: str
            http_body:
                description:
                    - Request body (if necessary). Should be serialized json string.
                type: str
            http_headers:
                description:
                    - Request headers.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    key:
                        description:
                            - Request header key.
                        type: str
                    value:
                        description:
                            - Request header value.
                        type: str
            log_debug_print:
                description:
                    - Enable/disable logging debug print output from diagnose action.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            message_type:
                description:
                    - Message type.
                type: str
                choices:
                    - 'text'
                    - 'json'
                    - 'form-data'
            method:
                description:
                    - Request method (POST, PUT, GET, PATCH or DELETE).
                type: str
                choices:
                    - 'post'
                    - 'put'
                    - 'get'
                    - 'patch'
                    - 'delete'
            minimum_interval:
                description:
                    - Limit execution to no more than once in this interval (in seconds).
                type: int
            name:
                description:
                    - Name.
                required: true
                type: str
            output_interval:
                description:
                    - Collect the outputs for each output-interval in seconds (0 = no intermediate output).
                type: int
            output_size:
                description:
                    - Number of megabytes to limit script output to (1 - 1024).
                type: int
            port:
                description:
                    - Protocol port.
                type: int
            protocol:
                description:
                    - Request protocol.
                type: str
                choices:
                    - 'http'
                    - 'https'
            regular_expression:
                description:
                    - Regular expression string.
                type: str
            replacement_message:
                description:
                    - Enable/disable replacement message.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            replacemsg_group:
                description:
                    - Replacement message group. Source system.replacemsg-group.name.
                type: str
            required:
                description:
                    - Required in action chain.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            script:
                description:
                    - CLI script.
                type: str
            sdn_connector:
                description:
                    - NSX SDN connector names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - SDN connector name. Source system.sdn-connector.name.
                        required: true
                        type: str
            security_tag:
                description:
                    - NSX security tag.
                type: str
            system_action:
                description:
                    - System action type.
                type: str
                choices:
                    - 'reboot'
                    - 'shutdown'
                    - 'backup-config'
            timeout:
                description:
                    - Maximum running time for this script in seconds (0 = no timeout).
                type: int
            tls_certificate:
                description:
                    - Custom TLS certificate for API request. Source certificate.local.name.
                type: str
            uri:
                description:
                    - Request API URI.
                type: str
            verify_host_cert:
                description:
                    - Enable/disable verification of the remote host certificate.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Action for automation stitches.
  fortinet.fortios.fortios_system_automation_action:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_automation_action:
          accprofile: "<your_own_value> (source system.accprofile.name)"
          action_type: "email"
          alicloud_access_key_id: "<your_own_value>"
          alicloud_access_key_secret: "<your_own_value>"
          alicloud_account_id: "<your_own_value>"
          alicloud_function: "<your_own_value>"
          alicloud_function_authorization: "anonymous"
          alicloud_function_domain: "<your_own_value>"
          alicloud_region: "<your_own_value>"
          alicloud_service: "<your_own_value>"
          alicloud_version: "<your_own_value>"
          aws_api_id: "<your_own_value>"
          aws_api_key: "<your_own_value>"
          aws_api_path: "<your_own_value>"
          aws_api_stage: "<your_own_value>"
          aws_domain: "<your_own_value>"
          aws_region: "<your_own_value>"
          azure_api_key: "<your_own_value>"
          azure_app: "<your_own_value>"
          azure_domain: "<your_own_value>"
          azure_function: "<your_own_value>"
          azure_function_authorization: "anonymous"
          delay: "0"
          description: "<your_own_value>"
          duration: "5"
          email_body: "<your_own_value>"
          email_from: "<your_own_value>"
          email_subject: "<your_own_value>"
          email_to:
              -
                  name: "default_name_32"
          execute_security_fabric: "enable"
          file_only: "enable"
          form_data:
              -
                  id: "36"
                  key: "<your_own_value>"
                  value: "<your_own_value>"
          forticare_email: "enable"
          fos_message: "<your_own_value>"
          gcp_function: "<your_own_value>"
          gcp_function_domain: "<your_own_value>"
          gcp_function_region: "<your_own_value>"
          gcp_project: "<your_own_value>"
          headers:
              -
                  header: "<your_own_value>"
          http_body: "<your_own_value>"
          http_headers:
              -
                  id: "49"
                  key: "<your_own_value>"
                  value: "<your_own_value>"
          log_debug_print: "enable"
          message_type: "text"
          method: "post"
          minimum_interval: "0"
          name: "default_name_56"
          output_interval: "0"
          output_size: "10"
          port: "0"
          protocol: "http"
          regular_expression: "<your_own_value>"
          replacement_message: "enable"
          replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
          required: "enable"
          script: "<your_own_value>"
          sdn_connector:
              -
                  name: "default_name_67 (source system.sdn-connector.name)"
          security_tag: "<your_own_value>"
          system_action: "reboot"
          timeout: "0"
          tls_certificate: "<your_own_value> (source certificate.local.name)"
          uri: "<your_own_value>"
          verify_host_cert: "enable"
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


def filter_system_automation_action_data(json):
    option_list = [
        "accprofile",
        "action_type",
        "alicloud_access_key_id",
        "alicloud_access_key_secret",
        "alicloud_account_id",
        "alicloud_function",
        "alicloud_function_authorization",
        "alicloud_function_domain",
        "alicloud_region",
        "alicloud_service",
        "alicloud_version",
        "aws_api_id",
        "aws_api_key",
        "aws_api_path",
        "aws_api_stage",
        "aws_domain",
        "aws_region",
        "azure_api_key",
        "azure_app",
        "azure_domain",
        "azure_function",
        "azure_function_authorization",
        "delay",
        "description",
        "duration",
        "email_body",
        "email_from",
        "email_subject",
        "email_to",
        "execute_security_fabric",
        "file_only",
        "form_data",
        "forticare_email",
        "fos_message",
        "gcp_function",
        "gcp_function_domain",
        "gcp_function_region",
        "gcp_project",
        "headers",
        "http_body",
        "http_headers",
        "log_debug_print",
        "message_type",
        "method",
        "minimum_interval",
        "name",
        "output_interval",
        "output_size",
        "port",
        "protocol",
        "regular_expression",
        "replacement_message",
        "replacemsg_group",
        "required",
        "script",
        "sdn_connector",
        "security_tag",
        "system_action",
        "timeout",
        "tls_certificate",
        "uri",
        "verify_host_cert",
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


def valid_attr_to_invalid_attr(data):
    speciallist = {"message": "fos_message"}

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


def system_automation_action(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_automation_action_data = data["system_automation_action"]

    filtered_data = filter_system_automation_action_data(system_automation_action_data)
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "automation-action", filtered_data, vdom=vdom)
        current_data = fos.get("system", "automation-action", vdom=vdom, mkey=mkey)
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
    data_copy["system_automation_action"] = filtered_data
    fos.do_member_operation(
        "system",
        "automation-action",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "automation-action", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system", "automation-action", mkey=converted_data["name"], vdom=vdom
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


def fortios_system(data, fos, check_mode):

    if data["system_automation_action"]:
        resp = system_automation_action(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("system_automation_action")
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
        "description": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "action_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "email"},
                {"value": "fortiexplorer-notification", "v_range": [["v7.0.0", ""]]},
                {"value": "alert"},
                {"value": "disable-ssid"},
                {"value": "system-actions", "v_range": [["v7.2.1", ""]]},
                {"value": "quarantine"},
                {"value": "quarantine-forticlient"},
                {"value": "quarantine-nsx", "v_range": [["v6.2.0", ""]]},
                {
                    "value": "quarantine-fortinac",
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                },
                {"value": "ban-ip"},
                {"value": "aws-lambda"},
                {"value": "azure-function", "v_range": [["v6.2.0", ""]]},
                {"value": "google-cloud-function", "v_range": [["v6.2.0", ""]]},
                {"value": "alicloud-function", "v_range": [["v6.2.0", ""]]},
                {"value": "webhook"},
                {"value": "cli-script", "v_range": [["v6.2.0", ""]]},
                {"value": "diagnose-script", "v_range": [["v7.6.1", ""]]},
                {"value": "regular-expression", "v_range": [["v7.6.1", ""]]},
                {"value": "slack-notification", "v_range": [["v6.4.0", ""]]},
                {"value": "microsoft-teams-notification", "v_range": [["v7.0.0", ""]]},
                {"value": "ios-notification", "v_range": [["v6.0.0", "v6.4.4"]]},
            ],
        },
        "system_action": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [
                {"value": "reboot"},
                {"value": "shutdown"},
                {"value": "backup-config"},
            ],
        },
        "tls_certificate": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "forticare_email": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "email_to": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "email_from": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "email_subject": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "minimum_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "aws_api_key": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "azure_function_authorization": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "anonymous"},
                {"value": "function"},
                {"value": "admin"},
            ],
        },
        "azure_api_key": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "alicloud_function_authorization": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "anonymous"}, {"value": "function"}],
        },
        "alicloud_access_key_id": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "alicloud_access_key_secret": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "message_type": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "text"},
                {"value": "json"},
                {"value": "form-data", "v_range": [["v7.6.4", ""]]},
            ],
        },
        "replacement_message": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "replacemsg_group": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "protocol": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "http"}, {"value": "https"}],
        },
        "method": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "post"},
                {"value": "put"},
                {"value": "get"},
                {"value": "patch", "v_range": [["v6.2.0", ""]]},
                {"value": "delete", "v_range": [["v6.2.0", ""]]},
            ],
        },
        "uri": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "http_body": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "http_headers": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", ""]],
                    "type": "integer",
                    "required": True,
                },
                "key": {
                    "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", ""]],
                    "type": "string",
                },
                "value": {
                    "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", ""]],
                    "type": "string",
                },
            },
            "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", ""]],
        },
        "form_data": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "integer",
                    "required": True,
                },
                "key": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "value": {"v_range": [["v7.6.4", ""]], "type": "string"},
            },
            "v_range": [["v7.6.4", ""]],
        },
        "verify_host_cert": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "script": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "output_size": {"v_range": [["v7.2.0", ""]], "type": "integer"},
        "timeout": {"v_range": [["v7.2.0", ""]], "type": "integer"},
        "duration": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "output_interval": {"v_range": [["v7.6.4", ""]], "type": "integer"},
        "file_only": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "execute_security_fabric": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "accprofile": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "regular_expression": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "log_debug_print": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "security_tag": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "sdn_connector": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", ""]],
        },
        "headers": {
            "type": "list",
            "elements": "dict",
            "children": {
                "header": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
        },
        "delay": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "integer"},
        "required": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "aws_api_id": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
        "aws_region": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
        "aws_domain": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
        "aws_api_stage": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
        "aws_api_path": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
        "azure_app": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
        "azure_function": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
        "azure_domain": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
        "gcp_function_region": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
        "gcp_project": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
        "gcp_function_domain": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
        "gcp_function": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
        "alicloud_account_id": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
        "alicloud_region": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
        "alicloud_function_domain": {
            "v_range": [["v6.2.0", "v6.4.4"]],
            "type": "string",
        },
        "alicloud_version": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
        "alicloud_service": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
        "alicloud_function": {"v_range": [["v6.2.0", "v6.4.4"]], "type": "string"},
        "email_body": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "fos_message": {"v_range": [["v6.4.0", ""]], "type": "string"},
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
        "system_automation_action": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_automation_action"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_automation_action"]["options"][attribute_name][
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
            fos, versioned_schema, "system_automation_action"
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
