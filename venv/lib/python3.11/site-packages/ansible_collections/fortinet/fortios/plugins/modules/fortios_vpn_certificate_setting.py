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
module: fortios_vpn_certificate_setting
short_description: VPN certificate setting in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify vpn_certificate feature and setting category.
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

    vpn_certificate_setting:
        description:
            - VPN certificate setting.
        default: null
        type: dict
        suboptions:
            cert_expire_warning:
                description:
                    - Number of days before a certificate expires to send a warning. Set to 0 to disable sending of the warning (0 - 100).
                type: int
            certname_dsa1024:
                description:
                    - 1024 bit DSA key certificate for re-signing server certificates for SSL inspection. Source vpn.certificate.local.name.
                type: str
            certname_dsa2048:
                description:
                    - 2048 bit DSA key certificate for re-signing server certificates for SSL inspection. Source vpn.certificate.local.name.
                type: str
            certname_ecdsa256:
                description:
                    - 256 bit ECDSA key certificate for re-signing server certificates for SSL inspection. Source vpn.certificate.local.name.
                type: str
            certname_ecdsa384:
                description:
                    - 384 bit ECDSA key certificate for re-signing server certificates for SSL inspection. Source vpn.certificate.local.name.
                type: str
            certname_ecdsa521:
                description:
                    - 521 bit ECDSA key certificate for re-signing server certificates for SSL inspection. Source vpn.certificate.local.name.
                type: str
            certname_ed25519:
                description:
                    - 253 bit EdDSA key certificate for re-signing server certificates for SSL inspection. Source vpn.certificate.local.name.
                type: str
            certname_ed448:
                description:
                    - 456 bit EdDSA key certificate for re-signing server certificates for SSL inspection. Source vpn.certificate.local.name.
                type: str
            certname_rsa1024:
                description:
                    - 1024 bit RSA key certificate for re-signing server certificates for SSL inspection. Source vpn.certificate.local.name.
                type: str
            certname_rsa2048:
                description:
                    - 2048 bit RSA key certificate for re-signing server certificates for SSL inspection. Source vpn.certificate.local.name.
                type: str
            certname_rsa4096:
                description:
                    - 4096 bit RSA key certificate for re-signing server certificates for SSL inspection. Source vpn.certificate.local.name.
                type: str
            check_ca_cert:
                description:
                    - Enable/disable verification of the user certificate and pass authentication if any CA in the chain is trusted .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            check_ca_chain:
                description:
                    - Enable/disable verification of the entire certificate chain and pass authentication only if the chain is complete and all of the CAs in
                       the chain are trusted .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cmp_key_usage_checking:
                description:
                    - Enable/disable server certificate key usage checking in CMP mode .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cmp_save_extra_certs:
                description:
                    - Enable/disable saving extra certificates in CMP mode .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cn_allow_multi:
                description:
                    - When searching for a matching certificate, allow multiple CN fields in certificate subject name .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            cn_match:
                description:
                    - When searching for a matching certificate, control how to do CN value matching with certificate subject name .
                type: str
                choices:
                    - 'substring'
                    - 'value'
            crl_verification:
                description:
                    - CRL verification options.
                type: dict
                suboptions:
                    chain_crl_absence:
                        description:
                            - CRL verification option when CRL of any certificate in chain is absent .
                        type: str
                        choices:
                            - 'ignore'
                            - 'revoke'
                    expiry:
                        description:
                            - CRL verification option when CRL is expired .
                        type: str
                        choices:
                            - 'ignore'
                            - 'revoke'
                    leaf_crl_absence:
                        description:
                            - CRL verification option when leaf CRL is absent .
                        type: str
                        choices:
                            - 'ignore'
                            - 'revoke'
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
            ocsp_default_server:
                description:
                    - Default OCSP server. Source vpn.certificate.ocsp-server.name.
                type: str
            ocsp_option:
                description:
                    - Specify whether the OCSP URL is from certificate or configured OCSP server.
                type: str
                choices:
                    - 'certificate'
                    - 'server'
            ocsp_status:
                description:
                    - Enable/disable receiving certificates using the OCSP.
                type: str
                choices:
                    - 'enable'
                    - 'mandatory'
                    - 'disable'
            proxy:
                description:
                    - Proxy server FQDN or IP for OCSP/CA queries during certificate verification.
                type: str
            proxy_password:
                description:
                    - Proxy server password.
                type: str
            proxy_port:
                description:
                    - Proxy server port (1 - 65535).
                type: int
            proxy_username:
                description:
                    - Proxy server user name.
                type: str
            source_ip:
                description:
                    - Source IP address for dynamic AIA and OCSP queries.
                type: str
            ssl_min_proto_version:
                description:
                    - Minimum supported protocol version for SSL/TLS connections .
                type: str
                choices:
                    - 'default'
                    - 'SSLv3'
                    - 'TLSv1'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'TLSv1-3'
            ssl_ocsp_option:
                description:
                    - Specify whether the OCSP URL is from the certificate or the default OCSP server.
                type: str
                choices:
                    - 'certificate'
                    - 'server'
            ssl_ocsp_source_ip:
                description:
                    - Source IP address to use to communicate with the OCSP server.
                type: str
            ssl_ocsp_status:
                description:
                    - Enable/disable SSL OCSP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            strict_crl_check:
                description:
                    - Enable/disable strict mode CRL checking.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            strict_ocsp_check:
                description:
                    - Enable/disable strict mode OCSP checking.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            subject_match:
                description:
                    - When searching for a matching certificate, control how to do RDN value matching with certificate subject name .
                type: str
                choices:
                    - 'substring'
                    - 'value'
            subject_set:
                description:
                    - When searching for a matching certificate, control how to do RDN set matching with certificate subject name .
                type: str
                choices:
                    - 'subset'
                    - 'superset'
            vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
"""

EXAMPLES = """
- name: VPN certificate setting.
  fortinet.fortios.fortios_vpn_certificate_setting:
      vdom: "{{ vdom }}"
      vpn_certificate_setting:
          cert_expire_warning: "14"
          certname_dsa1024: "<your_own_value> (source vpn.certificate.local.name)"
          certname_dsa2048: "<your_own_value> (source vpn.certificate.local.name)"
          certname_ecdsa256: "<your_own_value> (source vpn.certificate.local.name)"
          certname_ecdsa384: "<your_own_value> (source vpn.certificate.local.name)"
          certname_ecdsa521: "<your_own_value> (source vpn.certificate.local.name)"
          certname_ed25519: "<your_own_value> (source vpn.certificate.local.name)"
          certname_ed448: "<your_own_value> (source vpn.certificate.local.name)"
          certname_rsa1024: "<your_own_value> (source vpn.certificate.local.name)"
          certname_rsa2048: "<your_own_value> (source vpn.certificate.local.name)"
          certname_rsa4096: "<your_own_value> (source vpn.certificate.local.name)"
          check_ca_cert: "enable"
          check_ca_chain: "enable"
          cmp_key_usage_checking: "enable"
          cmp_save_extra_certs: "enable"
          cn_allow_multi: "disable"
          cn_match: "substring"
          crl_verification:
              chain_crl_absence: "ignore"
              expiry: "ignore"
              leaf_crl_absence: "ignore"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          ocsp_default_server: "<your_own_value> (source vpn.certificate.ocsp-server.name)"
          ocsp_option: "certificate"
          ocsp_status: "enable"
          proxy: "<your_own_value>"
          proxy_password: "<your_own_value>"
          proxy_port: "8080"
          proxy_username: "<your_own_value>"
          source_ip: "84.230.14.43"
          ssl_min_proto_version: "default"
          ssl_ocsp_option: "certificate"
          ssl_ocsp_source_ip: "<your_own_value>"
          ssl_ocsp_status: "enable"
          strict_crl_check: "enable"
          strict_ocsp_check: "enable"
          subject_match: "substring"
          subject_set: "subset"
          vrf_select: "0"
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


def filter_vpn_certificate_setting_data(json):
    option_list = [
        "cert_expire_warning",
        "certname_dsa1024",
        "certname_dsa2048",
        "certname_ecdsa256",
        "certname_ecdsa384",
        "certname_ecdsa521",
        "certname_ed25519",
        "certname_ed448",
        "certname_rsa1024",
        "certname_rsa2048",
        "certname_rsa4096",
        "check_ca_cert",
        "check_ca_chain",
        "cmp_key_usage_checking",
        "cmp_save_extra_certs",
        "cn_allow_multi",
        "cn_match",
        "crl_verification",
        "interface",
        "interface_select_method",
        "ocsp_default_server",
        "ocsp_option",
        "ocsp_status",
        "proxy",
        "proxy_password",
        "proxy_port",
        "proxy_username",
        "source_ip",
        "ssl_min_proto_version",
        "ssl_ocsp_option",
        "ssl_ocsp_source_ip",
        "ssl_ocsp_status",
        "strict_crl_check",
        "strict_ocsp_check",
        "subject_match",
        "subject_set",
        "vrf_select",
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


def vpn_certificate_setting(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    vpn_certificate_setting_data = data["vpn_certificate_setting"]

    filtered_data = filter_vpn_certificate_setting_data(vpn_certificate_setting_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("vpn.certificate", "setting", filtered_data, vdom=vdom)
        current_data = fos.get("vpn.certificate", "setting", vdom=vdom, mkey=mkey)
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
    data_copy["vpn_certificate_setting"] = filtered_data
    fos.do_member_operation(
        "vpn.certificate",
        "setting",
        data_copy,
    )

    return fos.set("vpn.certificate", "setting", data=converted_data, vdom=vdom)


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

    if data["vpn_certificate_setting"]:
        resp = vpn_certificate_setting(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("vpn_certificate_setting"))
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
        "ocsp_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "enable"},
                {"value": "mandatory", "v_range": [["v7.4.2", ""]]},
                {"value": "disable"},
            ],
        },
        "ocsp_option": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "certificate"}, {"value": "server"}],
        },
        "proxy": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "proxy_port": {"v_range": [["v7.2.4", ""]], "type": "integer"},
        "proxy_username": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "proxy_password": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "source_ip": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "ocsp_default_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "interface_select_method": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "vrf_select": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "check_ca_cert": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "check_ca_chain": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "subject_match": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "substring"}, {"value": "value"}],
        },
        "subject_set": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "subset"}, {"value": "superset"}],
        },
        "cn_match": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "substring"}, {"value": "value"}],
        },
        "cn_allow_multi": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "crl_verification": {
            "v_range": [["v7.0.1", ""]],
            "type": "dict",
            "children": {
                "expiry": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "ignore"}, {"value": "revoke"}],
                },
                "leaf_crl_absence": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "ignore"}, {"value": "revoke"}],
                },
                "chain_crl_absence": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "ignore"}, {"value": "revoke"}],
                },
            },
        },
        "strict_ocsp_check": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_min_proto_version": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "default"},
                {"value": "SSLv3"},
                {"value": "TLSv1"},
                {"value": "TLSv1-1"},
                {"value": "TLSv1-2"},
                {"value": "TLSv1-3", "v_range": [["v7.4.1", ""]]},
            ],
        },
        "cmp_save_extra_certs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cmp_key_usage_checking": {
            "v_range": [["v6.0.0", "v6.0.0"], ["v6.0.11", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cert_expire_warning": {"v_range": [["v7.2.1", ""]], "type": "integer"},
        "certname_rsa1024": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "certname_rsa2048": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "certname_rsa4096": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "certname_dsa1024": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "certname_dsa2048": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "certname_ecdsa256": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "certname_ecdsa384": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "certname_ecdsa521": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "certname_ed25519": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "certname_ed448": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "ssl_ocsp_source_ip": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", "v7.2.4"]],
            "type": "string",
        },
        "strict_crl_check": {
            "v_range": [["v6.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_ocsp_status": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_ocsp_option": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "certificate"}, {"value": "server"}],
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
        "vpn_certificate_setting": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["vpn_certificate_setting"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["vpn_certificate_setting"]["options"][attribute_name][
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
            fos, versioned_schema, "vpn_certificate_setting"
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
