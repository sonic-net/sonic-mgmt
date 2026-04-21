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
module: fortios_system_saml
short_description: Global settings for SAML authentication in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and saml category.
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

    system_saml:
        description:
            - Global settings for SAML authentication.
        default: null
        type: dict
        suboptions:
            artifact_resolution_url:
                description:
                    - SP artifact resolution URL.
                type: str
            binding_protocol:
                description:
                    - IdP Binding protocol.
                type: str
                choices:
                    - 'post'
                    - 'redirect'
            cert:
                description:
                    - Certificate to sign SAML messages. Source certificate.local.name.
                type: str
            default_login_page:
                description:
                    - Choose default login page.
                type: str
                choices:
                    - 'normal'
                    - 'sso'
            default_profile:
                description:
                    - Default profile for new SSO admin. Source system.accprofile.name.
                type: str
            entity_id:
                description:
                    - SP entity ID.
                type: str
            idp_artifact_resolution_url:
                description:
                    - IDP artifact resolution URL.
                type: str
            idp_cert:
                description:
                    - IDP certificate name. Source certificate.remote.name.
                type: str
            idp_entity_id:
                description:
                    - IDP entity ID.
                type: str
            idp_single_logout_url:
                description:
                    - IDP single logout URL.
                type: str
            idp_single_sign_on_url:
                description:
                    - IDP single sign-on URL.
                type: str
            life:
                description:
                    - Length of the range of time when the assertion is valid (in minutes).
                type: int
            portal_url:
                description:
                    - SP portal URL.
                type: str
            role:
                description:
                    - SAML role.
                type: str
                choices:
                    - 'identity-provider'
                    - 'service-provider'
            server_address:
                description:
                    - Server address.
                type: str
            service_providers:
                description:
                    - Authorized service providers.
                type: list
                elements: dict
                suboptions:
                    assertion_attributes:
                        description:
                            - Customized SAML attributes to send along with assertion.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Name.
                                required: true
                                type: str
                            type:
                                description:
                                    - Type.
                                type: str
                                choices:
                                    - 'username'
                                    - 'email'
                                    - 'profile-name'
                    idp_artifact_resolution_url:
                        description:
                            - IDP artifact resolution URL.
                        type: str
                    idp_entity_id:
                        description:
                            - IDP entity ID.
                        type: str
                    idp_single_logout_url:
                        description:
                            - IDP single logout URL.
                        type: str
                    idp_single_sign_on_url:
                        description:
                            - IDP single sign-on URL.
                        type: str
                    name:
                        description:
                            - Name.
                        required: true
                        type: str
                    prefix:
                        description:
                            - Prefix.
                        type: str
                    sp_artifact_resolution_url:
                        description:
                            - SP artifact resolution URL.
                        type: str
                    sp_binding_protocol:
                        description:
                            - SP binding protocol.
                        type: str
                        choices:
                            - 'post'
                            - 'redirect'
                    sp_cert:
                        description:
                            - SP certificate name. Source certificate.remote.name.
                        type: str
                    sp_entity_id:
                        description:
                            - SP entity ID.
                        type: str
                    sp_portal_url:
                        description:
                            - SP portal URL.
                        type: str
                    sp_single_logout_url:
                        description:
                            - SP single logout URL.
                        type: str
                    sp_single_sign_on_url:
                        description:
                            - SP single sign-on URL.
                        type: str
            single_logout_url:
                description:
                    - SP single logout URL.
                type: str
            single_sign_on_url:
                description:
                    - SP single sign-on URL.
                type: str
            status:
                description:
                    - Enable/disable SAML authentication .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tolerance:
                description:
                    - Tolerance to the range of time when the assertion is valid (in minutes).
                type: int
"""

EXAMPLES = """
- name: Global settings for SAML authentication.
  fortinet.fortios.fortios_system_saml:
      vdom: "{{ vdom }}"
      system_saml:
          artifact_resolution_url: "<your_own_value>"
          binding_protocol: "post"
          cert: "<your_own_value> (source certificate.local.name)"
          default_login_page: "normal"
          default_profile: "<your_own_value> (source system.accprofile.name)"
          entity_id: "<your_own_value>"
          idp_artifact_resolution_url: "<your_own_value>"
          idp_cert: "<your_own_value> (source certificate.remote.name)"
          idp_entity_id: "<your_own_value>"
          idp_single_logout_url: "<your_own_value>"
          idp_single_sign_on_url: "<your_own_value>"
          life: "30"
          portal_url: "<your_own_value>"
          role: "identity-provider"
          server_address: "<your_own_value>"
          service_providers:
              -
                  assertion_attributes:
                      -
                          name: "default_name_20"
                          type: "username"
                  idp_artifact_resolution_url: "<your_own_value>"
                  idp_entity_id: "<your_own_value>"
                  idp_single_logout_url: "<your_own_value>"
                  idp_single_sign_on_url: "<your_own_value>"
                  name: "default_name_26"
                  prefix: "<your_own_value>"
                  sp_artifact_resolution_url: "<your_own_value>"
                  sp_binding_protocol: "post"
                  sp_cert: "<your_own_value> (source certificate.remote.name)"
                  sp_entity_id: "<your_own_value>"
                  sp_portal_url: "<your_own_value>"
                  sp_single_logout_url: "<your_own_value>"
                  sp_single_sign_on_url: "<your_own_value>"
          single_logout_url: "<your_own_value>"
          single_sign_on_url: "<your_own_value>"
          status: "enable"
          tolerance: "5"
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


def filter_system_saml_data(json):
    option_list = [
        "artifact_resolution_url",
        "binding_protocol",
        "cert",
        "default_login_page",
        "default_profile",
        "entity_id",
        "idp_artifact_resolution_url",
        "idp_cert",
        "idp_entity_id",
        "idp_single_logout_url",
        "idp_single_sign_on_url",
        "life",
        "portal_url",
        "role",
        "server_address",
        "service_providers",
        "single_logout_url",
        "single_sign_on_url",
        "status",
        "tolerance",
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


def system_saml(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_saml_data = data["system_saml"]

    filtered_data = filter_system_saml_data(system_saml_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "saml", filtered_data, vdom=vdom)
        current_data = fos.get("system", "saml", vdom=vdom, mkey=mkey)
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
    data_copy["system_saml"] = filtered_data
    fos.do_member_operation(
        "system",
        "saml",
        data_copy,
    )

    return fos.set("system", "saml", data=converted_data, vdom=vdom)


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

    if data["system_saml"]:
        resp = system_saml(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_saml"))
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
    "v_range": [["v6.2.0", ""]],
    "type": "dict",
    "children": {
        "status": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "role": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "identity-provider"}, {"value": "service-provider"}],
        },
        "default_login_page": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "normal"}, {"value": "sso"}],
        },
        "default_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "cert": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "binding_protocol": {
            "v_range": [["v6.2.3", "v6.2.3"], ["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "post"},
                {"value": "redirect", "v_range": [["v7.0.0", ""]]},
            ],
        },
        "entity_id": {
            "v_range": [["v6.2.0", "v7.0.5"], ["v7.2.0", "v7.2.0"], ["v7.4.1", ""]],
            "type": "string",
        },
        "idp_entity_id": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "idp_single_sign_on_url": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "idp_single_logout_url": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "idp_cert": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "server_address": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "tolerance": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "life": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "service_providers": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "prefix": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "sp_binding_protocol": {
                    "v_range": [["v6.2.3", "v6.2.3"], ["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "post"},
                        {"value": "redirect", "v_range": [["v7.0.0", ""]]},
                    ],
                },
                "sp_cert": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "sp_entity_id": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "sp_single_sign_on_url": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                },
                "sp_single_logout_url": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "sp_portal_url": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "assertion_attributes": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "type": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "string",
                            "options": [
                                {"value": "username"},
                                {"value": "email"},
                                {"value": "profile-name", "v_range": [["v6.4.0", ""]]},
                            ],
                        },
                    },
                    "v_range": [["v6.2.0", ""]],
                },
                "idp_entity_id": {
                    "v_range": [["v6.2.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
                "idp_single_sign_on_url": {
                    "v_range": [["v6.2.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
                "idp_single_logout_url": {
                    "v_range": [["v6.2.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
                "sp_artifact_resolution_url": {
                    "v_range": [["v6.2.3", "v6.2.3"]],
                    "type": "string",
                },
                "idp_artifact_resolution_url": {
                    "v_range": [["v6.2.3", "v6.2.3"]],
                    "type": "string",
                },
            },
            "v_range": [["v6.2.0", ""]],
        },
        "portal_url": {
            "v_range": [["v6.2.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "single_sign_on_url": {
            "v_range": [["v6.2.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "single_logout_url": {
            "v_range": [["v6.2.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "artifact_resolution_url": {
            "v_range": [["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "idp_artifact_resolution_url": {
            "v_range": [["v6.2.3", "v6.2.3"]],
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
        "system_saml": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_saml"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_saml"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_saml"
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
