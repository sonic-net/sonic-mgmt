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
module: fortios_vpn_certificate_local
short_description: Local keys and certificates in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify vpn_certificate feature and local category.
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
    vpn_certificate_local:
        description:
            - Local keys and certificates.
        default: null
        type: dict
        suboptions:
            acme_ca_url:
                description:
                    - The URL for the ACME CA server (Let"s Encrypt is the ).
                type: str
            acme_domain:
                description:
                    - A valid domain that resolves to this FortiGate unit.
                type: str
            acme_eab_key_hmac:
                description:
                    - External Account Binding HMAC Key (URL-encoded base64).
                type: str
            acme_eab_key_id:
                description:
                    - External Account Binding Key ID (optional setting).
                type: str
            acme_email:
                description:
                    - Contact email address that is required by some CAs like LetsEncrypt.
                type: str
            acme_renew_window:
                description:
                    - Beginning of the renewal window (in days before certificate expiration, 30 by default).
                type: int
            acme_rsa_key_size:
                description:
                    - Length of the RSA private key of the generated cert (Minimum 2048 bits).
                type: int
            auto_regenerate_days:
                description:
                    - Number of days to wait before expiry of an updated local certificate is requested (0 = disabled).
                type: int
            auto_regenerate_days_warning:
                description:
                    - Number of days to wait before an expiry warning message is generated (0 = disabled).
                type: int
            ca_identifier:
                description:
                    - CA identifier of the CA server for signing via SCEP.
                type: str
            certificate:
                description:
                    - PEM format certificate.
                type: str
            cmp_path:
                description:
                    - Path location inside CMP server.
                type: str
            cmp_regeneration_method:
                description:
                    - CMP auto-regeneration method.
                type: str
                choices:
                    - 'keyupate'
                    - 'renewal'
            cmp_server:
                description:
                    - 'Address and port for CMP server (format = address:port).'
                type: str
            cmp_server_cert:
                description:
                    - CMP server certificate. Source vpn.certificate.ca.name vpn.certificate.remote.name.
                type: str
            comments:
                description:
                    - Comment.
                type: str
            csr:
                description:
                    - Certificate Signing Request.
                type: str
            enroll_protocol:
                description:
                    - Certificate enrollment protocol.
                type: str
                choices:
                    - 'none'
                    - 'scep'
                    - 'cmpv2'
                    - 'acme2'
                    - 'est'
            est_ca_id:
                description:
                    - CA identifier of the CA server for signing via EST.
                type: str
            est_client_cert:
                description:
                    - Certificate used to authenticate this FortiGate to EST server. Source vpn.certificate.local.name.
                type: str
            est_http_password:
                description:
                    - HTTP Authentication password for signing via EST.
                type: str
            est_http_username:
                description:
                    - HTTP Authentication username for signing via EST.
                type: str
            est_regeneration_method:
                description:
                    - EST behavioral options during re-enrollment.
                type: str
                choices:
                    - 'create-new-key'
                    - 'use-existing-key'
            est_server:
                description:
                    - 'Address and port for EST server (e.g. https://example.com:1234).'
                type: str
            est_server_cert:
                description:
                    - EST server"s certificate must be verifiable by this certificate to be authenticated. Source vpn.certificate.ca.name vpn.certificate
                      .remote.name.
                type: str
            est_srp_password:
                description:
                    - EST SRP authentication password.
                type: str
            est_srp_username:
                description:
                    - EST SRP authentication username.
                type: str
            ike_localid:
                description:
                    - Local ID the FortiGate uses for authentication as a VPN client.
                type: str
            ike_localid_type:
                description:
                    - IKE local ID type.
                type: str
                choices:
                    - 'asn1dn'
                    - 'fqdn'
            last_updated:
                description:
                    - Time at which certificate was last updated.
                type: int
            name:
                description:
                    - Name.
                required: true
                type: str
            name_encoding:
                description:
                    - Name encoding method for auto-regeneration.
                type: str
                choices:
                    - 'printable'
                    - 'utf8'
            password:
                description:
                    - Password as a PEM file.
                type: str
            private_key:
                description:
                    - PEM format key encrypted with a password.
                type: str
            private_key_retain:
                description:
                    - Enable/disable retention of private key during SCEP renewal .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            range:
                description:
                    - Either a global or VDOM IP address range for the certificate.
                type: str
                choices:
                    - 'global'
                    - 'vdom'
            scep_password:
                description:
                    - SCEP server challenge password for auto-regeneration.
                type: str
            scep_url:
                description:
                    - SCEP server URL.
                type: str
            source:
                description:
                    - Certificate source type.
                type: str
                choices:
                    - 'factory'
                    - 'user'
                    - 'bundle'
            source_ip:
                description:
                    - Source IP address for communications to the SCEP server.
                type: str
            state:
                description:
                    - Certificate Signing Request State.
                type: str
"""

EXAMPLES = """
- name: Local keys and certificates.
  fortinet.fortios.fortios_vpn_certificate_local:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      vpn_certificate_local:
          acme_ca_url: "<your_own_value>"
          acme_domain: "<your_own_value>"
          acme_eab_key_hmac: "<your_own_value>"
          acme_eab_key_id: "<your_own_value>"
          acme_email: "<your_own_value>"
          acme_renew_window: "30"
          acme_rsa_key_size: "2048"
          auto_regenerate_days: "0"
          auto_regenerate_days_warning: "0"
          ca_identifier: "myId_12"
          certificate: "<your_own_value>"
          cmp_path: "<your_own_value>"
          cmp_regeneration_method: "keyupate"
          cmp_server: "<your_own_value>"
          cmp_server_cert: "<your_own_value> (source vpn.certificate.ca.name vpn.certificate.remote.name)"
          comments: "<your_own_value>"
          csr: "<your_own_value>"
          enroll_protocol: "none"
          est_ca_id: "<your_own_value>"
          est_client_cert: "<your_own_value> (source vpn.certificate.local.name)"
          est_http_password: "<your_own_value>"
          est_http_username: "<your_own_value>"
          est_regeneration_method: "create-new-key"
          est_server: "<your_own_value>"
          est_server_cert: "<your_own_value> (source vpn.certificate.ca.name vpn.certificate.remote.name)"
          est_srp_password: "<your_own_value>"
          est_srp_username: "<your_own_value>"
          ike_localid: "<your_own_value>"
          ike_localid_type: "asn1dn"
          last_updated: "2147483647"
          name: "default_name_33"
          name_encoding: "printable"
          password: "<your_own_value>"
          private_key: "<your_own_value>"
          private_key_retain: "enable"
          range: "global"
          scep_password: "<your_own_value>"
          scep_url: "<your_own_value>"
          source: "factory"
          source_ip: "84.230.14.43"
          state: "<your_own_value>"
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


def filter_vpn_certificate_local_data(json):
    option_list = [
        "acme_ca_url",
        "acme_domain",
        "acme_eab_key_hmac",
        "acme_eab_key_id",
        "acme_email",
        "acme_renew_window",
        "acme_rsa_key_size",
        "auto_regenerate_days",
        "auto_regenerate_days_warning",
        "ca_identifier",
        "certificate",
        "cmp_path",
        "cmp_regeneration_method",
        "cmp_server",
        "cmp_server_cert",
        "comments",
        "csr",
        "enroll_protocol",
        "est_ca_id",
        "est_client_cert",
        "est_http_password",
        "est_http_username",
        "est_regeneration_method",
        "est_server",
        "est_server_cert",
        "est_srp_password",
        "est_srp_username",
        "ike_localid",
        "ike_localid_type",
        "last_updated",
        "name",
        "name_encoding",
        "password",
        "private_key",
        "private_key_retain",
        "range",
        "scep_password",
        "scep_url",
        "source",
        "source_ip",
        "state",
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


def vpn_certificate_local(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    vpn_certificate_local_data = data["vpn_certificate_local"]

    filtered_data = filter_vpn_certificate_local_data(vpn_certificate_local_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("vpn.certificate", "local", filtered_data, vdom=vdom)
        current_data = fos.get("vpn.certificate", "local", vdom=vdom, mkey=mkey)
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
    data_copy["vpn_certificate_local"] = filtered_data
    fos.do_member_operation(
        "vpn.certificate",
        "local",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("vpn.certificate", "local", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "vpn.certificate", "local", mkey=converted_data["name"], vdom=vdom
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


def fortios_vpn_certificate(data, fos, check_mode):

    if data["vpn_certificate_local"]:
        resp = vpn_certificate_local(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("vpn_certificate_local"))
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
        "password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "private_key": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "certificate": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "csr": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "scep_url": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "range": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "global"}, {"value": "vdom"}],
        },
        "source": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "factory"}, {"value": "user"}, {"value": "bundle"}],
        },
        "auto_regenerate_days": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auto_regenerate_days_warning": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "scep_password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ca_identifier": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "name_encoding": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "printable"}, {"value": "utf8"}],
        },
        "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ike_localid": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ike_localid_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "asn1dn"}, {"value": "fqdn"}],
        },
        "enroll_protocol": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "scep"},
                {"value": "cmpv2"},
                {"value": "acme2", "v_range": [["v7.0.0", ""]]},
                {"value": "est", "v_range": [["v7.4.1", ""]]},
            ],
        },
        "private_key_retain": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cmp_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "cmp_path": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "cmp_server_cert": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "cmp_regeneration_method": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "keyupate"}, {"value": "renewal"}],
        },
        "acme_ca_url": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "acme_domain": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "acme_email": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "acme_eab_key_id": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "acme_eab_key_hmac": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "acme_rsa_key_size": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "acme_renew_window": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "est_server": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "est_ca_id": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "est_http_username": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "est_http_password": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "est_client_cert": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "est_server_cert": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "est_srp_username": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "est_srp_password": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "est_regeneration_method": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "create-new-key"}, {"value": "use-existing-key"}],
        },
        "state": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "last_updated": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "integer",
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
        "vpn_certificate_local": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["vpn_certificate_local"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["vpn_certificate_local"]["options"][attribute_name][
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
            fos, versioned_schema, "vpn_certificate_local"
        )

        is_error, has_changed, result, diff = fortios_vpn_certificate(
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
