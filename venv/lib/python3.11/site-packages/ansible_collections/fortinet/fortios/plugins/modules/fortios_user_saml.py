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
module: fortios_user_saml
short_description: SAML server entry configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify user feature and saml category.
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
    user_saml:
        description:
            - SAML server entry configuration.
        default: null
        type: dict
        suboptions:
            adfs_claim:
                description:
                    - Enable/disable ADFS Claim for user/group attribute in assertion statement .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_url:
                description:
                    - URL to verify authentication.
                type: str
            cert:
                description:
                    - Certificate to sign SAML messages. Source vpn.certificate.local.name.
                type: str
            clock_tolerance:
                description:
                    - Clock skew tolerance in seconds (0 - 300).
                type: int
            digest_method:
                description:
                    - Digest method algorithm.
                type: str
                choices:
                    - 'sha1'
                    - 'sha256'
            entity_id:
                description:
                    - SP entity ID.
                type: str
            group_claim_type:
                description:
                    - Group claim in assertion statement.
                type: str
                choices:
                    - 'email'
                    - 'given-name'
                    - 'name'
                    - 'upn'
                    - 'common-name'
                    - 'email-adfs-1x'
                    - 'group'
                    - 'upn-adfs-1x'
                    - 'role'
                    - 'sur-name'
                    - 'ppid'
                    - 'name-identifier'
                    - 'authentication-method'
                    - 'deny-only-group-sid'
                    - 'deny-only-primary-sid'
                    - 'deny-only-primary-group-sid'
                    - 'group-sid'
                    - 'primary-group-sid'
                    - 'primary-sid'
                    - 'windows-account-name'
            group_name:
                description:
                    - Group name in assertion statement.
                type: str
            idp_cert:
                description:
                    - IDP Certificate name. Source vpn.certificate.remote.name.
                type: str
            idp_entity_id:
                description:
                    - IDP entity ID.
                type: str
            idp_single_logout_url:
                description:
                    - IDP single logout url.
                type: str
            idp_single_sign_on_url:
                description:
                    - IDP single sign-on URL.
                type: str
            limit_relaystate:
                description:
                    - Enable/disable limiting of relay-state parameter when it exceeds SAML 2.0 specification limits (80 bytes).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - SAML server entry name.
                required: true
                type: str
            reauth:
                description:
                    - Enable/disable signalling of IDP to force user re-authentication .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            scim_client:
                description:
                    - SCIM client name. Source user.scim.name.
                type: str
            scim_group_attr_type:
                description:
                    - Group attribute type used to match SCIM groups .
                type: str
                choices:
                    - 'display-name'
                    - 'external-id'
            scim_user_attr_type:
                description:
                    - User attribute type used to match SCIM users .
                type: str
                choices:
                    - 'user-name'
                    - 'display-name'
                    - 'external-id'
            single_logout_url:
                description:
                    - SP single logout URL.
                type: str
            single_sign_on_url:
                description:
                    - SP single sign-on URL.
                type: str
            user_claim_type:
                description:
                    - User name claim in assertion statement.
                type: str
                choices:
                    - 'email'
                    - 'given-name'
                    - 'name'
                    - 'upn'
                    - 'common-name'
                    - 'email-adfs-1x'
                    - 'group'
                    - 'upn-adfs-1x'
                    - 'role'
                    - 'sur-name'
                    - 'ppid'
                    - 'name-identifier'
                    - 'authentication-method'
                    - 'deny-only-group-sid'
                    - 'deny-only-primary-sid'
                    - 'deny-only-primary-group-sid'
                    - 'group-sid'
                    - 'primary-group-sid'
                    - 'primary-sid'
                    - 'windows-account-name'
            user_name:
                description:
                    - User name in assertion statement.
                type: str
"""

EXAMPLES = """
- name: SAML server entry configuration.
  fortinet.fortios.fortios_user_saml:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      user_saml:
          adfs_claim: "enable"
          auth_url: "<your_own_value>"
          cert: "<your_own_value> (source vpn.certificate.local.name)"
          clock_tolerance: "15"
          digest_method: "sha1"
          entity_id: "<your_own_value>"
          group_claim_type: "email"
          group_name: "<your_own_value>"
          idp_cert: "<your_own_value> (source vpn.certificate.remote.name)"
          idp_entity_id: "<your_own_value>"
          idp_single_logout_url: "<your_own_value>"
          idp_single_sign_on_url: "<your_own_value>"
          limit_relaystate: "enable"
          name: "default_name_16"
          reauth: "enable"
          scim_client: "<your_own_value> (source user.scim.name)"
          scim_group_attr_type: "display-name"
          scim_user_attr_type: "user-name"
          single_logout_url: "<your_own_value>"
          single_sign_on_url: "<your_own_value>"
          user_claim_type: "email"
          user_name: "<your_own_value>"
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


def filter_user_saml_data(json):
    option_list = [
        "adfs_claim",
        "auth_url",
        "cert",
        "clock_tolerance",
        "digest_method",
        "entity_id",
        "group_claim_type",
        "group_name",
        "idp_cert",
        "idp_entity_id",
        "idp_single_logout_url",
        "idp_single_sign_on_url",
        "limit_relaystate",
        "name",
        "reauth",
        "scim_client",
        "scim_group_attr_type",
        "scim_user_attr_type",
        "single_logout_url",
        "single_sign_on_url",
        "user_claim_type",
        "user_name",
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


def user_saml(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    user_saml_data = data["user_saml"]

    filtered_data = filter_user_saml_data(user_saml_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("user", "saml", filtered_data, vdom=vdom)
        current_data = fos.get("user", "saml", vdom=vdom, mkey=mkey)
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
    data_copy["user_saml"] = filtered_data
    fos.do_member_operation(
        "user",
        "saml",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("user", "saml", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("user", "saml", mkey=converted_data["name"], vdom=vdom)
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


def fortios_user(data, fos, check_mode):

    if data["user_saml"]:
        resp = user_saml(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("user_saml"))
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
        "name": {"v_range": [["v6.2.0", ""]], "type": "string", "required": True},
        "cert": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "entity_id": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "single_sign_on_url": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "single_logout_url": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "idp_entity_id": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "idp_single_sign_on_url": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "idp_single_logout_url": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "idp_cert": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "scim_client": {"v_range": [["v7.6.0", ""]], "type": "string"},
        "scim_user_attr_type": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [
                {"value": "user-name"},
                {"value": "display-name"},
                {"value": "external-id"},
            ],
        },
        "scim_group_attr_type": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "display-name"}, {"value": "external-id"}],
        },
        "user_name": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "group_name": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "digest_method": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "sha1"}, {"value": "sha256"}],
        },
        "limit_relaystate": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "clock_tolerance": {"v_range": [["v7.0.4", ""]], "type": "integer"},
        "adfs_claim": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "user_claim_type": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "email"},
                {"value": "given-name"},
                {"value": "name"},
                {"value": "upn"},
                {"value": "common-name"},
                {"value": "email-adfs-1x"},
                {"value": "group"},
                {"value": "upn-adfs-1x"},
                {"value": "role"},
                {"value": "sur-name"},
                {"value": "ppid"},
                {"value": "name-identifier"},
                {"value": "authentication-method"},
                {"value": "deny-only-group-sid"},
                {"value": "deny-only-primary-sid"},
                {"value": "deny-only-primary-group-sid"},
                {"value": "group-sid"},
                {"value": "primary-group-sid"},
                {"value": "primary-sid"},
                {"value": "windows-account-name"},
            ],
        },
        "group_claim_type": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "email"},
                {"value": "given-name"},
                {"value": "name"},
                {"value": "upn"},
                {"value": "common-name"},
                {"value": "email-adfs-1x"},
                {"value": "group"},
                {"value": "upn-adfs-1x"},
                {"value": "role"},
                {"value": "sur-name"},
                {"value": "ppid"},
                {"value": "name-identifier"},
                {"value": "authentication-method"},
                {"value": "deny-only-group-sid"},
                {"value": "deny-only-primary-sid"},
                {"value": "deny-only-primary-group-sid"},
                {"value": "group-sid"},
                {"value": "primary-group-sid"},
                {"value": "primary-sid"},
                {"value": "windows-account-name"},
            ],
        },
        "reauth": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_url": {"v_range": [["v7.2.1", "v7.4.1"]], "type": "string"},
    },
    "v_range": [["v6.2.0", ""]],
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
        "user_saml": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["user_saml"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["user_saml"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "user_saml"
        )

        is_error, has_changed, result, diff = fortios_user(
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
