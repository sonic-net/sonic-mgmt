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
module: fortios_authentication_scheme
short_description: Configure Authentication Schemes in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify authentication feature and scheme category.
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
    authentication_scheme:
        description:
            - Configure Authentication Schemes.
        default: null
        type: dict
        suboptions:
            digest_algo:
                description:
                    - Digest Authentication Algorithms.
                type: list
                elements: str
                choices:
                    - 'md5'
                    - 'sha-256'
            digest_rfc2069:
                description:
                    - Enable/disable support for the deprecated RFC2069 Digest Client (no cnonce field).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            domain_controller:
                description:
                    - Domain controller setting. Source user.domain-controller.name.
                type: str
            ems_device_owner:
                description:
                    - Enable/disable SSH public-key authentication with device owner .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            external_idp:
                description:
                    - External identity provider configuration. Source user.external-identity-provider.name.
                type: str
            fsso_agent_for_ntlm:
                description:
                    - FSSO agent to use for NTLM authentication. Source user.fsso.name.
                type: str
            fsso_guest:
                description:
                    - Enable/disable user fsso-guest authentication .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            group_attr_type:
                description:
                    - Group attribute type used to match SCIM groups .
                type: str
                choices:
                    - 'display-name'
                    - 'external-id'
            kerberos_keytab:
                description:
                    - Kerberos keytab setting. Source user.krb-keytab.name.
                type: str
            method:
                description:
                    - Authentication methods .
                type: list
                elements: str
                choices:
                    - 'ntlm'
                    - 'basic'
                    - 'digest'
                    - 'form'
                    - 'negotiate'
                    - 'fsso'
                    - 'rsso'
                    - 'ssh-publickey'
                    - 'cert'
                    - 'saml'
                    - 'entra-sso'
            name:
                description:
                    - Authentication scheme name.
                required: true
                type: str
            negotiate_ntlm:
                description:
                    - Enable/disable negotiate authentication for NTLM .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            require_tfa:
                description:
                    - Enable/disable two-factor authentication .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            saml_server:
                description:
                    - SAML configuration. Source user.saml.name.
                type: str
            saml_timeout:
                description:
                    - SAML authentication timeout in seconds.
                type: int
            ssh_ca:
                description:
                    - SSH CA name. Source firewall.ssh.local-ca.name.
                type: str
            user_cert:
                description:
                    - Enable/disable authentication with user certificate .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            user_database:
                description:
                    - Authentication server to contain user information; "local-user-db" (default) or "123" (for LDAP).
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Authentication server name. Source system.datasource.name user.radius.name user.tacacs+.name user.ldap.name user.group.name user
                              .scim.name.
                        required: true
                        type: str
"""

EXAMPLES = """
- name: Configure Authentication Schemes.
  fortinet.fortios.fortios_authentication_scheme:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      authentication_scheme:
          digest_algo: "md5"
          digest_rfc2069: "enable"
          domain_controller: "<your_own_value> (source user.domain-controller.name)"
          ems_device_owner: "enable"
          external_idp: "<your_own_value> (source user.external-identity-provider.name)"
          fsso_agent_for_ntlm: "<your_own_value> (source user.fsso.name)"
          fsso_guest: "enable"
          group_attr_type: "display-name"
          kerberos_keytab: "<your_own_value> (source user.krb-keytab.name)"
          method: "ntlm"
          name: "default_name_13"
          negotiate_ntlm: "enable"
          require_tfa: "enable"
          saml_server: "<your_own_value> (source user.saml.name)"
          saml_timeout: "120"
          ssh_ca: "<your_own_value> (source firewall.ssh.local-ca.name)"
          user_cert: "enable"
          user_database:
              -
                  name: "default_name_21 (source system.datasource.name user.radius.name user.tacacs+.name user.ldap.name user.group.name user.scim.name)"
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


def filter_authentication_scheme_data(json):
    option_list = [
        "digest_algo",
        "digest_rfc2069",
        "domain_controller",
        "ems_device_owner",
        "external_idp",
        "fsso_agent_for_ntlm",
        "fsso_guest",
        "group_attr_type",
        "kerberos_keytab",
        "method",
        "name",
        "negotiate_ntlm",
        "require_tfa",
        "saml_server",
        "saml_timeout",
        "ssh_ca",
        "user_cert",
        "user_database",
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
        ["method"],
        ["digest_algo"],
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


def authentication_scheme(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    authentication_scheme_data = data["authentication_scheme"]

    filtered_data = filter_authentication_scheme_data(authentication_scheme_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("authentication", "scheme", filtered_data, vdom=vdom)
        current_data = fos.get("authentication", "scheme", vdom=vdom, mkey=mkey)
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
    data_copy["authentication_scheme"] = filtered_data
    fos.do_member_operation(
        "authentication",
        "scheme",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("authentication", "scheme", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "authentication", "scheme", mkey=converted_data["name"], vdom=vdom
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


def fortios_authentication(data, fos, check_mode):

    if data["authentication_scheme"]:
        resp = authentication_scheme(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("authentication_scheme"))
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
        "method": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "ntlm"},
                {"value": "basic"},
                {"value": "digest"},
                {"value": "form"},
                {"value": "negotiate"},
                {"value": "fsso"},
                {"value": "rsso"},
                {"value": "ssh-publickey"},
                {"value": "cert", "v_range": [["v7.0.0", ""]]},
                {"value": "saml", "v_range": [["v7.0.0", ""]]},
                {"value": "entra-sso", "v_range": [["v7.6.1", ""]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "negotiate_ntlm": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "kerberos_keytab": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "domain_controller": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "saml_server": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "saml_timeout": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "fsso_agent_for_ntlm": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "require_tfa": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fsso_guest": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "user_cert": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "user_database": {
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
        "ssh_ca": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "external_idp": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "group_attr_type": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "display-name"}, {"value": "external-id"}],
        },
        "digest_algo": {
            "v_range": [["v7.6.3", ""]],
            "type": "list",
            "options": [{"value": "md5"}, {"value": "sha-256"}],
            "multiple_values": True,
            "elements": "str",
        },
        "digest_rfc2069": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ems_device_owner": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "authentication_scheme": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["authentication_scheme"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["authentication_scheme"]["options"][attribute_name][
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
            fos, versioned_schema, "authentication_scheme"
        )

        is_error, has_changed, result, diff = fortios_authentication(
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
