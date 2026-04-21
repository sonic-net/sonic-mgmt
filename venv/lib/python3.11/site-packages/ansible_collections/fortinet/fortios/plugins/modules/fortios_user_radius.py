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
module: fortios_user_radius
short_description: Configure RADIUS server entries in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify user feature and radius category.
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
    user_radius:
        description:
            - Configure RADIUS server entries.
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
            account_key_processing:
                description:
                    - Account key processing operation. The FortiGate will keep either the whole domain or strip the domain from the subject identity.
                type: str
                choices:
                    - 'same'
                    - 'strip'
            accounting_server:
                description:
                    - Additional accounting servers.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID (0 - 4294967295). see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
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
                    port:
                        description:
                            - RADIUS accounting port number.
                        type: int
                    secret:
                        description:
                            - Secret key.
                        type: str
                    server:
                        description:
                            - Server CN domain name or IP address.
                        type: str
                    source_ip:
                        description:
                            - Source IP address for communications to the RADIUS server.
                        type: str
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    vrf_select:
                        description:
                            - VRF ID used for connection to server.
                        type: int
            acct_all_servers:
                description:
                    - Enable/disable sending of accounting messages to all configured servers .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            acct_interim_interval:
                description:
                    - Time in seconds between each accounting interim update message.
                type: int
            all_usergroup:
                description:
                    - Enable/disable automatically including this RADIUS server in all user groups.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            auth_type:
                description:
                    - Authentication methods/protocols permitted for this RADIUS server.
                type: str
                choices:
                    - 'auto'
                    - 'ms_chap_v2'
                    - 'ms_chap'
                    - 'chap'
                    - 'pap'
            ca_cert:
                description:
                    - CA of server to trust under TLS. Source vpn.certificate.ca.name.
                type: str
            call_station_id_type:
                description:
                    - Calling & Called station identifier type configuration , this option is not available for 802.1x authentication.
                type: str
                choices:
                    - 'legacy'
                    - 'IP'
                    - 'MAC'
            class:
                description:
                    - Class attribute name(s).
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Class name.
                        required: true
                        type: str
            client_cert:
                description:
                    - Client certificate to use under TLS. Source vpn.certificate.local.name.
                type: str
            delimiter:
                description:
                    - Configure delimiter to be used for separating profile group names in the SSO attribute .
                type: str
                choices:
                    - 'plus'
                    - 'comma'
            group_override_attr_type:
                description:
                    - RADIUS attribute type to override user group information.
                type: str
                choices:
                    - 'filter-Id'
                    - 'class'
            h3c_compatibility:
                description:
                    - Enable/disable compatibility with the H3C, a mechanism that performs security checking for authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
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
            mac_case:
                description:
                    - MAC authentication case .
                type: str
                choices:
                    - 'uppercase'
                    - 'lowercase'
            mac_password_delimiter:
                description:
                    - MAC authentication password delimiter .
                type: str
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac_username_delimiter:
                description:
                    - MAC authentication username delimiter .
                type: str
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            name:
                description:
                    - RADIUS server entry name.
                required: true
                type: str
            nas_id:
                description:
                    - Custom NAS identifier.
                type: str
            nas_id_type:
                description:
                    - NAS identifier type configuration .
                type: str
                choices:
                    - 'legacy'
                    - 'custom'
                    - 'hostname'
            nas_ip:
                description:
                    - IP address used to communicate with the RADIUS server and used as NAS-IP-Address and Called-Station-ID attributes.
                type: str
            password_encoding:
                description:
                    - Password encoding.
                type: str
                choices:
                    - 'auto'
                    - 'ISO-8859-1'
            password_renewal:
                description:
                    - Enable/disable password renewal.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            radius_coa:
                description:
                    - Enable to allow a mechanism to change the attributes of an authentication, authorization, and accounting session after it is
                       authenticated.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            radius_port:
                description:
                    - RADIUS service port number.
                type: int
            require_message_authenticator:
                description:
                    - Require message authenticator in authentication response.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rsso:
                description:
                    - Enable/disable RADIUS based single sign on feature.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rsso_context_timeout:
                description:
                    - Time in seconds before the logged out user is removed from the "user context list" of logged on users.
                type: int
            rsso_endpoint_attribute:
                description:
                    - RADIUS attributes used to extract the user end point identifier from the RADIUS Start record.
                type: str
                choices:
                    - 'User-Name'
                    - 'NAS-IP-Address'
                    - 'Framed-IP-Address'
                    - 'Framed-IP-Netmask'
                    - 'Filter-Id'
                    - 'Login-IP-Host'
                    - 'Reply-Message'
                    - 'Callback-Number'
                    - 'Callback-Id'
                    - 'Framed-Route'
                    - 'Framed-IPX-Network'
                    - 'Class'
                    - 'Called-Station-Id'
                    - 'Calling-Station-Id'
                    - 'NAS-Identifier'
                    - 'Proxy-State'
                    - 'Login-LAT-Service'
                    - 'Login-LAT-Node'
                    - 'Login-LAT-Group'
                    - 'Framed-AppleTalk-Zone'
                    - 'Acct-Session-Id'
                    - 'Acct-Multi-Session-Id'
            rsso_endpoint_block_attribute:
                description:
                    - RADIUS attributes used to block a user.
                type: str
                choices:
                    - 'User-Name'
                    - 'NAS-IP-Address'
                    - 'Framed-IP-Address'
                    - 'Framed-IP-Netmask'
                    - 'Filter-Id'
                    - 'Login-IP-Host'
                    - 'Reply-Message'
                    - 'Callback-Number'
                    - 'Callback-Id'
                    - 'Framed-Route'
                    - 'Framed-IPX-Network'
                    - 'Class'
                    - 'Called-Station-Id'
                    - 'Calling-Station-Id'
                    - 'NAS-Identifier'
                    - 'Proxy-State'
                    - 'Login-LAT-Service'
                    - 'Login-LAT-Node'
                    - 'Login-LAT-Group'
                    - 'Framed-AppleTalk-Zone'
                    - 'Acct-Session-Id'
                    - 'Acct-Multi-Session-Id'
            rsso_ep_one_ip_only:
                description:
                    - Enable/disable the replacement of old IP addresses with new ones for the same endpoint on RADIUS accounting Start messages.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rsso_flush_ip_session:
                description:
                    - Enable/disable flushing user IP sessions on RADIUS accounting Stop messages.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rsso_log_flags:
                description:
                    - Events to log.
                type: list
                elements: str
                choices:
                    - 'protocol-error'
                    - 'profile-missing'
                    - 'accounting-stop-missed'
                    - 'accounting-event'
                    - 'endpoint-block'
                    - 'radiusd-other'
                    - 'none'
            rsso_log_period:
                description:
                    - Time interval in seconds that group event log messages will be generated for dynamic profile events.
                type: int
            rsso_radius_response:
                description:
                    - Enable/disable sending RADIUS response packets after receiving Start and Stop records.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rsso_radius_server_port:
                description:
                    - UDP port to listen on for RADIUS Start and Stop records.
                type: int
            rsso_secret:
                description:
                    - RADIUS secret used by the RADIUS accounting server.
                type: str
            rsso_validate_request_secret:
                description:
                    - Enable/disable validating the RADIUS request shared secret in the Start or End record.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            secondary_secret:
                description:
                    - Secret key to access the secondary server.
                type: str
            secondary_server:
                description:
                    - Secondary RADIUS CN domain name or IP address.
                type: str
            secret:
                description:
                    - Pre-shared secret key used to access the primary RADIUS server.
                type: str
            server:
                description:
                    - Primary RADIUS server CN domain name or IP address.
                type: str
            server_identity_check:
                description:
                    - Enable/disable RADIUS server identity check (verify server domain name/IP address against the server certificate).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            source_ip:
                description:
                    - Source IP address for communications to the RADIUS server.
                type: str
            source_ip_interface:
                description:
                    - Source interface for communication with the RADIUS server. Source system.interface.name.
                type: str
            sso_attribute:
                description:
                    - RADIUS attribute that contains the profile group name to be extracted from the RADIUS Start record.
                type: str
                choices:
                    - 'User-Name'
                    - 'NAS-IP-Address'
                    - 'Framed-IP-Address'
                    - 'Framed-IP-Netmask'
                    - 'Filter-Id'
                    - 'Login-IP-Host'
                    - 'Reply-Message'
                    - 'Callback-Number'
                    - 'Callback-Id'
                    - 'Framed-Route'
                    - 'Framed-IPX-Network'
                    - 'Class'
                    - 'Called-Station-Id'
                    - 'Calling-Station-Id'
                    - 'NAS-Identifier'
                    - 'Proxy-State'
                    - 'Login-LAT-Service'
                    - 'Login-LAT-Node'
                    - 'Login-LAT-Group'
                    - 'Framed-AppleTalk-Zone'
                    - 'Acct-Session-Id'
                    - 'Acct-Multi-Session-Id'
            sso_attribute_key:
                description:
                    - Key prefix for SSO group value in the SSO attribute.
                type: str
            sso_attribute_value_override:
                description:
                    - Enable/disable override old attribute value with new value for the same endpoint.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            status_ttl:
                description:
                    - Time for which server reachability is cached so that when a server is unreachable, it will not be retried for at least this period of
                       time (0 = cache disabled).
                type: int
            switch_controller_acct_fast_framedip_detect:
                description:
                    - Switch controller accounting message Framed-IP detection from DHCP snooping (seconds).
                type: int
            switch_controller_nas_ip_dynamic:
                description:
                    - Enable/Disable switch-controller nas-ip dynamic to dynamically set nas-ip.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_controller_service_type:
                description:
                    - RADIUS service type.
                type: list
                elements: str
                choices:
                    - 'login'
                    - 'framed'
                    - 'callback-login'
                    - 'callback-framed'
                    - 'outbound'
                    - 'administrative'
                    - 'nas-prompt'
                    - 'authenticate-only'
                    - 'callback-nas-prompt'
                    - 'call-check'
                    - 'callback-administrative'
            tertiary_secret:
                description:
                    - Secret key to access the tertiary server.
                type: str
            tertiary_server:
                description:
                    - Tertiary RADIUS CN domain name or IP address.
                type: str
            timeout:
                description:
                    - Time in seconds to retry connecting server.
                type: int
            tls_min_proto_version:
                description:
                    - Minimum supported protocol version for TLS connections .
                type: str
                choices:
                    - 'default'
                    - 'SSLv3'
                    - 'TLSv1'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'TLSv1-3'
            transport_protocol:
                description:
                    - Transport protocol to be used .
                type: str
                choices:
                    - 'udp'
                    - 'tcp'
                    - 'tls'
            use_management_vdom:
                description:
                    - Enable/disable using management VDOM to send requests.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            username_case_sensitive:
                description:
                    - Enable/disable case sensitive user names.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
"""

EXAMPLES = """
- name: Configure RADIUS server entries.
  fortinet.fortios.fortios_user_radius:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      user_radius:
          account_key_cert_field: "othername"
          account_key_processing: "same"
          accounting_server:
              -
                  id: "6"
                  interface: "<your_own_value> (source system.interface.name)"
                  interface_select_method: "auto"
                  port: "0"
                  secret: "<your_own_value>"
                  server: "192.168.100.40"
                  source_ip: "84.230.14.43"
                  status: "enable"
                  vrf_select: "0"
          acct_all_servers: "enable"
          acct_interim_interval: "0"
          all_usergroup: "disable"
          auth_type: "auto"
          ca_cert: "<your_own_value> (source vpn.certificate.ca.name)"
          call_station_id_type: "legacy"
          class:
              -
                  name: "default_name_22"
          client_cert: "<your_own_value> (source vpn.certificate.local.name)"
          delimiter: "plus"
          group_override_attr_type: "filter-Id"
          h3c_compatibility: "enable"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          mac_case: "uppercase"
          mac_password_delimiter: "hyphen"
          mac_username_delimiter: "hyphen"
          name: "default_name_32"
          nas_id: "<your_own_value>"
          nas_id_type: "legacy"
          nas_ip: "<your_own_value>"
          password_encoding: "auto"
          password_renewal: "enable"
          radius_coa: "enable"
          radius_port: "0"
          require_message_authenticator: "enable"
          rsso: "enable"
          rsso_context_timeout: "28800"
          rsso_endpoint_attribute: "User-Name"
          rsso_endpoint_block_attribute: "User-Name"
          rsso_ep_one_ip_only: "enable"
          rsso_flush_ip_session: "enable"
          rsso_log_flags: "protocol-error"
          rsso_log_period: "0"
          rsso_radius_response: "enable"
          rsso_radius_server_port: "1813"
          rsso_secret: "<your_own_value>"
          rsso_validate_request_secret: "enable"
          secondary_secret: "<your_own_value>"
          secondary_server: "<your_own_value>"
          secret: "<your_own_value>"
          server: "192.168.100.40"
          server_identity_check: "enable"
          source_ip: "84.230.14.43"
          source_ip_interface: "<your_own_value> (source system.interface.name)"
          sso_attribute: "User-Name"
          sso_attribute_key: "<your_own_value>"
          sso_attribute_value_override: "enable"
          status_ttl: "300"
          switch_controller_acct_fast_framedip_detect: "2"
          switch_controller_nas_ip_dynamic: "enable"
          switch_controller_service_type: "login"
          tertiary_secret: "<your_own_value>"
          tertiary_server: "<your_own_value>"
          timeout: "5"
          tls_min_proto_version: "default"
          transport_protocol: "udp"
          use_management_vdom: "enable"
          username_case_sensitive: "enable"
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


def filter_user_radius_data(json):
    option_list = [
        "account_key_cert_field",
        "account_key_processing",
        "accounting_server",
        "acct_all_servers",
        "acct_interim_interval",
        "all_usergroup",
        "auth_type",
        "ca_cert",
        "call_station_id_type",
        "class",
        "client_cert",
        "delimiter",
        "group_override_attr_type",
        "h3c_compatibility",
        "interface",
        "interface_select_method",
        "mac_case",
        "mac_password_delimiter",
        "mac_username_delimiter",
        "name",
        "nas_id",
        "nas_id_type",
        "nas_ip",
        "password_encoding",
        "password_renewal",
        "radius_coa",
        "radius_port",
        "require_message_authenticator",
        "rsso",
        "rsso_context_timeout",
        "rsso_endpoint_attribute",
        "rsso_endpoint_block_attribute",
        "rsso_ep_one_ip_only",
        "rsso_flush_ip_session",
        "rsso_log_flags",
        "rsso_log_period",
        "rsso_radius_response",
        "rsso_radius_server_port",
        "rsso_secret",
        "rsso_validate_request_secret",
        "secondary_secret",
        "secondary_server",
        "secret",
        "server",
        "server_identity_check",
        "source_ip",
        "source_ip_interface",
        "sso_attribute",
        "sso_attribute_key",
        "sso_attribute_value_override",
        "status_ttl",
        "switch_controller_acct_fast_framedip_detect",
        "switch_controller_nas_ip_dynamic",
        "switch_controller_service_type",
        "tertiary_secret",
        "tertiary_server",
        "timeout",
        "tls_min_proto_version",
        "transport_protocol",
        "use_management_vdom",
        "username_case_sensitive",
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
        ["switch_controller_service_type"],
        ["rsso_log_flags"],
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


def user_radius(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    user_radius_data = data["user_radius"]

    filtered_data = filter_user_radius_data(user_radius_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("user", "radius", filtered_data, vdom=vdom)
        current_data = fos.get("user", "radius", vdom=vdom, mkey=mkey)
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
    data_copy["user_radius"] = filtered_data
    fos.do_member_operation(
        "user",
        "radius",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("user", "radius", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("user", "radius", mkey=converted_data["name"], vdom=vdom)
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

    if data["user_radius"]:
        resp = user_radius(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("user_radius"))
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
        "secret": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "secondary_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "secondary_secret": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "tertiary_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "tertiary_secret": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "status_ttl": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "all_usergroup": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "use_management_vdom": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "switch_controller_nas_ip_dynamic": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nas_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "nas_id_type": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [
                {"value": "legacy"},
                {"value": "custom"},
                {"value": "hostname"},
            ],
        },
        "call_station_id_type": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "legacy"}, {"value": "IP"}, {"value": "MAC"}],
        },
        "nas_id": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "acct_interim_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "radius_coa": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "radius_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "h3c_compatibility": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "auto"},
                {"value": "ms_chap_v2"},
                {"value": "ms_chap"},
                {"value": "chap"},
                {"value": "pap"},
            ],
        },
        "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "source_ip_interface": {"v_range": [["v7.6.0", ""]], "type": "string"},
        "username_case_sensitive": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "group_override_attr_type": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "filter-Id"}, {"value": "class"}],
        },
        "class": {
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
        "password_renewal": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "require_message_authenticator": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "password_encoding": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "ISO-8859-1"}],
        },
        "mac_username_delimiter": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [
                {"value": "hyphen"},
                {"value": "single-hyphen"},
                {"value": "colon"},
                {"value": "none"},
            ],
        },
        "mac_password_delimiter": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [
                {"value": "hyphen"},
                {"value": "single-hyphen"},
                {"value": "colon"},
                {"value": "none"},
            ],
        },
        "mac_case": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "uppercase"}, {"value": "lowercase"}],
        },
        "acct_all_servers": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "switch_controller_acct_fast_framedip_detect": {
            "v_range": [["v6.4.0", ""]],
            "type": "integer",
        },
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
        "switch_controller_service_type": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "list",
            "options": [
                {"value": "login"},
                {"value": "framed"},
                {"value": "callback-login"},
                {"value": "callback-framed"},
                {"value": "outbound"},
                {"value": "administrative"},
                {"value": "nas-prompt"},
                {"value": "authenticate-only"},
                {"value": "callback-nas-prompt"},
                {"value": "call-check"},
                {"value": "callback-administrative"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "transport_protocol": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "udp"}, {"value": "tcp"}, {"value": "tls"}],
        },
        "tls_min_proto_version": {
            "v_range": [["v7.4.0", ""]],
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
        "ca_cert": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "client_cert": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "server_identity_check": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "account_key_processing": {
            "v_range": [["v7.4.1", ""]],
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
        "rsso": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rsso_radius_server_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "rsso_radius_response": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rsso_validate_request_secret": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rsso_secret": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "rsso_endpoint_attribute": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "User-Name"},
                {"value": "NAS-IP-Address"},
                {"value": "Framed-IP-Address"},
                {"value": "Framed-IP-Netmask"},
                {"value": "Filter-Id"},
                {"value": "Login-IP-Host"},
                {"value": "Reply-Message"},
                {"value": "Callback-Number"},
                {"value": "Callback-Id"},
                {"value": "Framed-Route"},
                {"value": "Framed-IPX-Network"},
                {"value": "Class"},
                {"value": "Called-Station-Id"},
                {"value": "Calling-Station-Id"},
                {"value": "NAS-Identifier"},
                {"value": "Proxy-State"},
                {"value": "Login-LAT-Service"},
                {"value": "Login-LAT-Node"},
                {"value": "Login-LAT-Group"},
                {"value": "Framed-AppleTalk-Zone"},
                {"value": "Acct-Session-Id"},
                {"value": "Acct-Multi-Session-Id"},
            ],
        },
        "rsso_endpoint_block_attribute": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "User-Name"},
                {"value": "NAS-IP-Address"},
                {"value": "Framed-IP-Address"},
                {"value": "Framed-IP-Netmask"},
                {"value": "Filter-Id"},
                {"value": "Login-IP-Host"},
                {"value": "Reply-Message"},
                {"value": "Callback-Number"},
                {"value": "Callback-Id"},
                {"value": "Framed-Route"},
                {"value": "Framed-IPX-Network"},
                {"value": "Class"},
                {"value": "Called-Station-Id"},
                {"value": "Calling-Station-Id"},
                {"value": "NAS-Identifier"},
                {"value": "Proxy-State"},
                {"value": "Login-LAT-Service"},
                {"value": "Login-LAT-Node"},
                {"value": "Login-LAT-Group"},
                {"value": "Framed-AppleTalk-Zone"},
                {"value": "Acct-Session-Id"},
                {"value": "Acct-Multi-Session-Id"},
            ],
        },
        "sso_attribute": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "User-Name"},
                {"value": "NAS-IP-Address"},
                {"value": "Framed-IP-Address"},
                {"value": "Framed-IP-Netmask"},
                {"value": "Filter-Id"},
                {"value": "Login-IP-Host"},
                {"value": "Reply-Message"},
                {"value": "Callback-Number"},
                {"value": "Callback-Id"},
                {"value": "Framed-Route"},
                {"value": "Framed-IPX-Network"},
                {"value": "Class"},
                {"value": "Called-Station-Id"},
                {"value": "Calling-Station-Id"},
                {"value": "NAS-Identifier"},
                {"value": "Proxy-State"},
                {"value": "Login-LAT-Service"},
                {"value": "Login-LAT-Node"},
                {"value": "Login-LAT-Group"},
                {"value": "Framed-AppleTalk-Zone"},
                {"value": "Acct-Session-Id"},
                {"value": "Acct-Multi-Session-Id"},
            ],
        },
        "sso_attribute_key": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sso_attribute_value_override": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rsso_context_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "rsso_log_period": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "rsso_log_flags": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "protocol-error"},
                {"value": "profile-missing"},
                {"value": "accounting-stop-missed"},
                {"value": "accounting-event"},
                {"value": "endpoint-block"},
                {"value": "radiusd-other"},
                {"value": "none"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "rsso_flush_ip_session": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rsso_ep_one_ip_only": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "delimiter": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "plus"}, {"value": "comma"}],
        },
        "accounting_server": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "server": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "secret": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "interface_select_method": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                    "options": [
                        {"value": "auto"},
                        {"value": "sdwan"},
                        {"value": "specify"},
                    ],
                },
                "interface": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                },
                "vrf_select": {"v_range": [["v7.6.1", ""]], "type": "integer"},
            },
            "v_range": [["v6.0.0", ""]],
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
        "user_radius": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["user_radius"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["user_radius"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "user_radius"
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
