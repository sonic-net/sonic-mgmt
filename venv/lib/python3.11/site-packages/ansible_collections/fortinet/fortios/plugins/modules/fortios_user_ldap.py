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
module: fortios_user_ldap
short_description: Configure LDAP server entries in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify user feature and ldap category.
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
    user_ldap:
        description:
            - Configure LDAP server entries.
        default: null
        type: dict
        suboptions:
            account_key_cert_field:
                description:
                    - Define subject identity field in certificate for user access right checking.
                type: str
                choices:
                    - 'othername'
                    - 'rfc822name'
                    - 'dnsname'
                    - 'cn'
            account_key_filter:
                description:
                    - Account key filter, using the UPN as the search filter.
                type: str
            account_key_processing:
                description:
                    - Account key processing operation. The FortiGate will keep either the whole domain or strip the domain from the subject identity.
                type: str
                choices:
                    - 'same'
                    - 'strip'
            account_key_upn_san:
                description:
                    - Define SAN in certificate for user principle name matching.
                type: str
                choices:
                    - 'othername'
                    - 'rfc822name'
                    - 'dnsname'
            antiphish:
                description:
                    - Enable/disable AntiPhishing credential backend.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ca_cert:
                description:
                    - CA certificate name. Source vpn.certificate.ca.name.
                type: str
            client_cert:
                description:
                    - Client certificate name. Source vpn.certificate.local.name.
                type: str
            client_cert_auth:
                description:
                    - Enable/disable using client certificate for TLS authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cnid:
                description:
                    - Common name identifier for the LDAP server. The common name identifier for most LDAP servers is "cn".
                type: str
            dn:
                description:
                    - Distinguished name used to look up entries on the LDAP server.
                type: str
            group_filter:
                description:
                    - Filter used for group matching.
                type: str
            group_member_check:
                description:
                    - Group member checking methods.
                type: str
                choices:
                    - 'user-attr'
                    - 'group-object'
                    - 'posix-group-object'
            group_object_filter:
                description:
                    - Filter used for group searching.
                type: str
            group_search_base:
                description:
                    - Search base used for group searching.
                type: str
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
            member_attr:
                description:
                    - Name of attribute from which to get group membership.
                type: str
            name:
                description:
                    - LDAP server entry name.
                required: true
                type: str
            obtain_user_info:
                description:
                    - Enable/disable obtaining of user information.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            password:
                description:
                    - Password for initial binding.
                type: str
            password_attr:
                description:
                    - Name of attribute to get password hash.
                type: str
            password_expiry_warning:
                description:
                    - Enable/disable password expiry warnings.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            password_renewal:
                description:
                    - Enable/disable online password renewal.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            port:
                description:
                    - Port to be used for communication with the LDAP server .
                type: int
            search_type:
                description:
                    - Search type.
                type: list
                elements: str
                choices:
                    - 'recursive'
            secondary_server:
                description:
                    - Secondary LDAP server CN domain name or IP.
                type: str
            secure:
                description:
                    - Port to be used for authentication.
                type: str
                choices:
                    - 'disable'
                    - 'starttls'
                    - 'ldaps'
            server:
                description:
                    - LDAP server CN domain name or IP.
                type: str
            server_identity_check:
                description:
                    - Enable/disable LDAP server identity check (verify server domain name/IP address against the server certificate).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            source_ip:
                description:
                    - FortiGate IP address to be used for communication with the LDAP server.
                type: str
            source_ip_interface:
                description:
                    - Source interface for communication with the LDAP server. Source system.interface.name.
                type: str
            source_port:
                description:
                    - Source port to be used for communication with the LDAP server.
                type: int
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
            status_ttl:
                description:
                    - Time for which server reachability is cached so that when a server is unreachable, it will not be retried for at least this period of
                       time (0 = cache disabled).
                type: int
            tertiary_server:
                description:
                    - Tertiary LDAP server CN domain name or IP.
                type: str
            two_factor:
                description:
                    - Enable/disable two-factor authentication.
                type: str
                choices:
                    - 'disable'
                    - 'fortitoken-cloud'
            two_factor_authentication:
                description:
                    - Authentication method by FortiToken Cloud.
                type: str
                choices:
                    - 'fortitoken'
                    - 'email'
                    - 'sms'
            two_factor_filter:
                description:
                    - Filter used to synchronize users to FortiToken Cloud.
                type: str
            two_factor_notification:
                description:
                    - Notification method for user activation by FortiToken Cloud.
                type: str
                choices:
                    - 'email'
                    - 'sms'
            type:
                description:
                    - Authentication type for LDAP searches.
                type: str
                choices:
                    - 'simple'
                    - 'anonymous'
                    - 'regular'
            user_info_exchange_server:
                description:
                    - MS Exchange server from which to fetch user information. Source user.exchange.name.
                type: str
            username:
                description:
                    - Username (full DN) for initial binding.
                type: str
            vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
"""

EXAMPLES = """
- name: Configure LDAP server entries.
  fortinet.fortios.fortios_user_ldap:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      user_ldap:
          account_key_cert_field: "othername"
          account_key_filter: "<your_own_value>"
          account_key_processing: "same"
          account_key_upn_san: "othername"
          antiphish: "enable"
          ca_cert: "<your_own_value> (source vpn.certificate.ca.name)"
          client_cert: "<your_own_value> (source vpn.certificate.local.name)"
          client_cert_auth: "enable"
          cnid: "<your_own_value>"
          dn: "<your_own_value>"
          group_filter: "<your_own_value>"
          group_member_check: "user-attr"
          group_object_filter: "<your_own_value>"
          group_search_base: "<your_own_value>"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          member_attr: "<your_own_value>"
          name: "default_name_20"
          obtain_user_info: "enable"
          password: "<your_own_value>"
          password_attr: "<your_own_value>"
          password_expiry_warning: "enable"
          password_renewal: "enable"
          port: "389"
          search_type: "recursive"
          secondary_server: "<your_own_value>"
          secure: "disable"
          server: "192.168.100.40"
          server_identity_check: "enable"
          source_ip: "84.230.14.43"
          source_ip_interface: "<your_own_value> (source system.interface.name)"
          source_port: "0"
          ssl_min_proto_version: "default"
          status_ttl: "300"
          tertiary_server: "<your_own_value>"
          two_factor: "disable"
          two_factor_authentication: "fortitoken"
          two_factor_filter: "<your_own_value>"
          two_factor_notification: "email"
          type: "simple"
          user_info_exchange_server: "<your_own_value> (source user.exchange.name)"
          username: "<your_own_value>"
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


def filter_user_ldap_data(json):
    option_list = [
        "account_key_cert_field",
        "account_key_filter",
        "account_key_processing",
        "account_key_upn_san",
        "antiphish",
        "ca_cert",
        "client_cert",
        "client_cert_auth",
        "cnid",
        "dn",
        "group_filter",
        "group_member_check",
        "group_object_filter",
        "group_search_base",
        "interface",
        "interface_select_method",
        "member_attr",
        "name",
        "obtain_user_info",
        "password",
        "password_attr",
        "password_expiry_warning",
        "password_renewal",
        "port",
        "search_type",
        "secondary_server",
        "secure",
        "server",
        "server_identity_check",
        "source_ip",
        "source_ip_interface",
        "source_port",
        "ssl_min_proto_version",
        "status_ttl",
        "tertiary_server",
        "two_factor",
        "two_factor_authentication",
        "two_factor_filter",
        "two_factor_notification",
        "type",
        "user_info_exchange_server",
        "username",
        "vrf_select",
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
        ["search_type"],
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


def user_ldap(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    user_ldap_data = data["user_ldap"]

    filtered_data = filter_user_ldap_data(user_ldap_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("user", "ldap", filtered_data, vdom=vdom)
        current_data = fos.get("user", "ldap", vdom=vdom, mkey=mkey)
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
    data_copy["user_ldap"] = filtered_data
    fos.do_member_operation(
        "user",
        "ldap",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("user", "ldap", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("user", "ldap", mkey=converted_data["name"], vdom=vdom)
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

    if data["user_ldap"]:
        resp = user_ldap(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("user_ldap"))
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
        "server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "secondary_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "tertiary_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "status_ttl": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "server_identity_check": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "source_ip_interface": {"v_range": [["v7.6.0", ""]], "type": "string"},
        "source_port": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "cnid": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dn": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "simple"},
                {"value": "anonymous"},
                {"value": "regular"},
            ],
        },
        "two_factor": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "fortitoken-cloud"}],
        },
        "two_factor_authentication": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
            "options": [{"value": "fortitoken"}, {"value": "email"}, {"value": "sms"}],
        },
        "two_factor_notification": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
            "options": [{"value": "email"}, {"value": "sms"}],
        },
        "two_factor_filter": {"v_range": [["v7.2.1", ""]], "type": "string"},
        "username": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "group_member_check": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "user-attr"},
                {"value": "group-object"},
                {"value": "posix-group-object"},
            ],
        },
        "group_search_base": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "group_object_filter": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "group_filter": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "secure": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "starttls"},
                {"value": "ldaps"},
            ],
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
        "ca_cert": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "password_expiry_warning": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "password_renewal": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "member_attr": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "account_key_processing": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "same"}, {"value": "strip"}],
        },
        "account_key_cert_field": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [
                {"value": "othername"},
                {"value": "rfc822name"},
                {"value": "dnsname"},
                {"value": "cn", "v_range": [["v7.4.4", ""]]},
            ],
        },
        "account_key_filter": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "search_type": {
            "v_range": [["v6.2.0", ""]],
            "type": "list",
            "options": [{"value": "recursive"}],
            "multiple_values": True,
            "elements": "str",
        },
        "client_cert_auth": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "client_cert": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "obtain_user_info": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "user_info_exchange_server": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "interface_select_method": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
        },
        "vrf_select": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "antiphish": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "password_attr": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "account_key_upn_san": {
            "v_range": [["v7.2.4", "v7.4.0"]],
            "type": "string",
            "options": [
                {"value": "othername"},
                {"value": "rfc822name"},
                {"value": "dnsname"},
            ],
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
        "user_ldap": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["user_ldap"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["user_ldap"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "user_ldap"
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
