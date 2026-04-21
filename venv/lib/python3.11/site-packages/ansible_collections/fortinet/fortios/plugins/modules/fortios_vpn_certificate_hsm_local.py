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
module: fortios_vpn_certificate_hsm_local
short_description: Local certificates whose keys are stored on HSM in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify vpn_certificate feature and hsm_local category.
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
    vpn_certificate_hsm_local:
        description:
            - Local certificates whose keys are stored on HSM.
        default: null
        type: dict
        suboptions:
            api_version:
                description:
                    - API version for communicating with HSM.
                type: str
                choices:
                    - 'unknown'
                    - 'gch-default'
            certificate:
                description:
                    - PEM format certificate.
                type: str
            comments:
                description:
                    - Comment.
                type: str
            gch_cloud_service_name:
                description:
                    - Cloud service config name to generate access token. Source system.cloud-service.name.
                type: str
            gch_cryptokey:
                description:
                    - Google Cloud HSM cryptokey.
                type: str
            gch_cryptokey_algorithm:
                description:
                    - Google Cloud HSM cryptokey algorithm.
                type: str
                choices:
                    - 'rsa-sign-pkcs1-2048-sha256'
                    - 'rsa-sign-pkcs1-3072-sha256'
                    - 'rsa-sign-pkcs1-4096-sha256'
                    - 'rsa-sign-pkcs1-4096-sha512'
                    - 'rsa-sign-pss-2048-sha256'
                    - 'rsa-sign-pss-3072-sha256'
                    - 'rsa-sign-pss-4096-sha256'
                    - 'rsa-sign-pss-4096-sha512'
                    - 'ec-sign-p256-sha256'
                    - 'ec-sign-p384-sha384'
                    - 'ec-sign-secp256k1-sha256'
            gch_cryptokey_version:
                description:
                    - Google Cloud HSM cryptokey version.
                type: str
            gch_keyring:
                description:
                    - Google Cloud HSM keyring.
                type: str
            gch_location:
                description:
                    - Google Cloud HSM location.
                type: str
            gch_project:
                description:
                    - Google Cloud HSM project ID.
                type: str
            name:
                description:
                    - Name.
                required: true
                type: str
            range:
                description:
                    - Either a global or VDOM IP address range for the certificate.
                type: str
                choices:
                    - 'global'
                    - 'vdom'
            source:
                description:
                    - Certificate source type.
                type: str
                choices:
                    - 'factory'
                    - 'user'
                    - 'bundle'
            vendor:
                description:
                    - HSM vendor.
                type: str
                choices:
                    - 'unknown'
                    - 'gch'
"""

EXAMPLES = """
- name: Local certificates whose keys are stored on HSM.
  fortinet.fortios.fortios_vpn_certificate_hsm_local:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      vpn_certificate_hsm_local:
          api_version: "unknown"
          certificate: "<your_own_value>"
          comments: "<your_own_value>"
          gch_cloud_service_name: "<your_own_value> (source system.cloud-service.name)"
          gch_cryptokey: "<your_own_value>"
          gch_cryptokey_algorithm: "rsa-sign-pkcs1-2048-sha256"
          gch_cryptokey_version: "<your_own_value>"
          gch_keyring: "<your_own_value>"
          gch_location: "<your_own_value>"
          gch_project: "<your_own_value>"
          name: "default_name_13"
          range: "global"
          source: "factory"
          vendor: "unknown"
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


def filter_vpn_certificate_hsm_local_data(json):
    option_list = [
        "api_version",
        "certificate",
        "comments",
        "gch_cloud_service_name",
        "gch_cryptokey",
        "gch_cryptokey_algorithm",
        "gch_cryptokey_version",
        "gch_keyring",
        "gch_location",
        "gch_project",
        "name",
        "range",
        "source",
        "vendor",
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


def vpn_certificate_hsm_local(data, fos):
    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    vpn_certificate_hsm_local_data = data["vpn_certificate_hsm_local"]

    filtered_data = filter_vpn_certificate_hsm_local_data(
        vpn_certificate_hsm_local_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["vpn_certificate_hsm_local"] = filtered_data
    fos.do_member_operation(
        "vpn.certificate",
        "hsm-local",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("vpn.certificate", "hsm-local", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "vpn.certificate", "hsm-local", mkey=converted_data["name"], vdom=vdom
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


def fortios_vpn_certificate(data, fos):

    if data["vpn_certificate_hsm_local"]:
        resp = vpn_certificate_hsm_local(data, fos)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("vpn_certificate_hsm_local")
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
        "comments": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "vendor": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "unknown"}, {"value": "gch"}],
        },
        "api_version": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "unknown"}, {"value": "gch-default"}],
        },
        "certificate": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "range": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "global"}, {"value": "vdom"}],
        },
        "source": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "factory"}, {"value": "user"}, {"value": "bundle"}],
        },
        "gch_project": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "gch_location": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "gch_keyring": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "gch_cryptokey": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "gch_cryptokey_version": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "gch_cloud_service_name": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "gch_cryptokey_algorithm": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [
                {"value": "rsa-sign-pkcs1-2048-sha256"},
                {"value": "rsa-sign-pkcs1-3072-sha256"},
                {"value": "rsa-sign-pkcs1-4096-sha256"},
                {"value": "rsa-sign-pkcs1-4096-sha512"},
                {"value": "rsa-sign-pss-2048-sha256"},
                {"value": "rsa-sign-pss-3072-sha256"},
                {"value": "rsa-sign-pss-4096-sha256"},
                {"value": "rsa-sign-pss-4096-sha512"},
                {"value": "ec-sign-p256-sha256"},
                {"value": "ec-sign-p384-sha384"},
                {"value": "ec-sign-secp256k1-sha256"},
            ],
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
        "vpn_certificate_hsm_local": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["vpn_certificate_hsm_local"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["vpn_certificate_hsm_local"]["options"][attribute_name][
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
            fos, versioned_schema, "vpn_certificate_hsm_local"
        )

        is_error, has_changed, result, diff = fortios_vpn_certificate(
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
