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
module: fortios_system_admin
short_description: Configure admin users in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and admin category.
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
    system_admin:
        description:
            - Configure admin users.
        default: null
        type: dict
        suboptions:
            accprofile:
                description:
                    - Access profile for this administrator. Access profiles control administrator access to FortiGate features. Source system.accprofile.name.
                type: str
            accprofile_override:
                description:
                    - Enable to use the name of an access profile provided by the remote authentication server to control the FortiGate features that this
                       administrator can access.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            allow_remove_admin_session:
                description:
                    - Enable/disable allow admin session to be removed by privileged admin users.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            comments:
                description:
                    - Comment.
                type: str
            email_to:
                description:
                    - This administrator"s email address.
                type: str
            force_password_change:
                description:
                    - Enable/disable force password change on next login.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortitoken:
                description:
                    - This administrator"s FortiToken serial number.
                type: str
            guest_auth:
                description:
                    - Enable/disable guest authentication.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            guest_lang:
                description:
                    - Guest management portal language. Source system.custom-language.name.
                type: str
            guest_usergroups:
                description:
                    - Select guest user groups.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Select guest user groups.
                        required: true
                        type: str
            gui_dashboard:
                description:
                    - GUI dashboards.
                type: list
                elements: dict
                suboptions:
                    columns:
                        description:
                            - Number of columns.
                        type: int
                    id:
                        description:
                            - Dashboard ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    layout_type:
                        description:
                            - Layout type.
                        type: str
                        choices:
                            - 'responsive'
                            - 'fixed'
                    name:
                        description:
                            - Dashboard name.
                        type: str
                    permanent:
                        description:
                            - Permanent dashboard (can"t be removed via the GUI).
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    scope:
                        description:
                            - Dashboard scope.
                        type: str
                        choices:
                            - 'global'
                            - 'vdom'
                    vdom:
                        description:
                            - Virtual domain. Source system.vdom.name.
                        type: str
                    widget:
                        description:
                            - Dashboard widgets.
                        type: list
                        elements: dict
                        suboptions:
                            fabric_device:
                                description:
                                    - Fabric device to monitor.
                                type: str
                            fabric_device_widget_name:
                                description:
                                    - Fabric device widget name.
                                type: str
                            fabric_device_widget_visualization_type:
                                description:
                                    - Visualization type for fabric device widget.
                                type: str
                            fortiview_device:
                                description:
                                    - FortiView device.
                                type: str
                            fortiview_filters:
                                description:
                                    - FortiView filters.
                                type: list
                                elements: dict
                                suboptions:
                                    id:
                                        description:
                                            - FortiView Filter ID. see <a href='#notes'>Notes</a>.
                                        required: true
                                        type: int
                                    key:
                                        description:
                                            - Filter key.
                                        type: str
                                    value:
                                        description:
                                            - Filter value.
                                        type: str
                            fortiview_sort_by:
                                description:
                                    - FortiView sort by.
                                type: str
                            fortiview_timeframe:
                                description:
                                    - FortiView timeframe.
                                type: str
                            fortiview_type:
                                description:
                                    - FortiView type.
                                type: str
                            fortiview_visualization:
                                description:
                                    - FortiView visualization.
                                type: str
                            height:
                                description:
                                    - Height.
                                type: int
                            id:
                                description:
                                    - Widget ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            industry:
                                description:
                                    - Security Audit Rating industry.
                                type: str
                                choices:
                                    - 'default'
                                    - 'custom'
                            interface:
                                description:
                                    - Interface to monitor. Source system.interface.name.
                                type: str
                            region:
                                description:
                                    - Security Audit Rating region.
                                type: str
                                choices:
                                    - 'default'
                                    - 'custom'
                            title:
                                description:
                                    - Widget title.
                                type: str
                            type:
                                description:
                                    - Widget type.
                                type: str
                                choices:
                                    - 'sysinfo'
                                    - 'licinfo'
                                    - 'forticloud'
                                    - 'cpu-usage'
                                    - 'memory-usage'
                                    - 'disk-usage'
                                    - 'log-rate'
                                    - 'sessions'
                                    - 'session-rate'
                                    - 'tr-history'
                                    - 'analytics'
                                    - 'usb-modem'
                                    - 'admins'
                                    - 'security-fabric'
                                    - 'security-fabric-ranking'
                                    - 'sensor-info'
                                    - 'ha-status'
                                    - 'vulnerability-summary'
                                    - 'host-scan-summary'
                                    - 'fortiview'
                                    - 'botnet-activity'
                                    - 'fabric-device'
                                    - 'fortimail'
                            width:
                                description:
                                    - Width.
                                type: int
                            x_pos:
                                description:
                                    - X position.
                                type: int
                            y_pos:
                                description:
                                    - Y position.
                                type: int
            gui_global_menu_favorites:
                description:
                    - Favorite GUI menu IDs for the global VDOM.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Select menu ID.
                        required: true
                        type: str
            gui_new_feature_acknowledge:
                description:
                    - Acknowledgement of new features.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Select menu ID.
                        required: true
                        type: str
            gui_vdom_menu_favorites:
                description:
                    - Favorite GUI menu IDs for VDOMs.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Select menu ID.
                        required: true
                        type: str
            hidden:
                description:
                    - Admin user hidden attribute.
                type: int
            history0:
                description:
                    - history0
                type: str
            history1:
                description:
                    - history1
                type: str
            ip6_trusthost1:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost10:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost2:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost3:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost4:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost5:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost6:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost7:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost8:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost9:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            login_time:
                description:
                    - Record user login time.
                type: list
                elements: dict
                suboptions:
                    last_failed_login:
                        description:
                            - Last failed login time.
                        type: str
                    last_login:
                        description:
                            - Last successful login time.
                        type: str
                    usr_name:
                        description:
                            - User name.
                        required: true
                        type: str
            name:
                description:
                    - User name.
                required: true
                type: str
            password:
                description:
                    - Admin user password.
                type: str
            password_expire:
                description:
                    - Password expire time.
                type: str
            peer_auth:
                description:
                    - Set to enable peer certificate authentication (for HTTPS admin access).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            peer_group:
                description:
                    - Name of peer group defined under config user group which has PKI members. Used for peer certificate authentication (for HTTPS admin
                       access).
                type: str
            radius_vdom_override:
                description:
                    - Enable to use the names of VDOMs provided by the remote authentication server to control the VDOMs that this administrator can access.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            remote_auth:
                description:
                    - Enable/disable authentication using a remote RADIUS, LDAP, or TACACS+ server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            remote_group:
                description:
                    - User group name used for remote auth.
                type: str
            schedule:
                description:
                    - Firewall schedule used to restrict when the administrator can log in. No schedule means no restrictions.
                type: str
            sms_custom_server:
                description:
                    - Custom SMS server to send SMS messages to. Source system.sms-server.name.
                type: str
            sms_phone:
                description:
                    - Phone number on which the administrator receives SMS messages.
                type: str
            sms_server:
                description:
                    - Send SMS messages using the FortiGuard SMS server or a custom server.
                type: str
                choices:
                    - 'fortiguard'
                    - 'custom'
            ssh_certificate:
                description:
                    - Select the certificate to be used by the FortiGate for authentication with an SSH client. Source certificate.remote.name.
                type: str
            ssh_public_key1:
                description:
                    - Public key of an SSH client. The client is authenticated without being asked for credentials. Create the public-private key pair in the
                       SSH client application.
                type: str
            ssh_public_key2:
                description:
                    - Public key of an SSH client. The client is authenticated without being asked for credentials. Create the public-private key pair in the
                       SSH client application.
                type: str
            ssh_public_key3:
                description:
                    - Public key of an SSH client. The client is authenticated without being asked for credentials. Create the public-private key pair in the
                       SSH client application.
                type: str
            trusthost1:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost10:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost2:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost3:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost4:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost5:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost6:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost7:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost8:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost9:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            two_factor:
                description:
                    - Enable/disable two-factor authentication.
                type: str
                choices:
                    - 'disable'
                    - 'fortitoken'
                    - 'fortitoken-cloud'
                    - 'email'
                    - 'sms'
            two_factor_authentication:
                description:
                    - Authentication method by FortiToken Cloud.
                type: str
                choices:
                    - 'fortitoken'
                    - 'email'
                    - 'sms'
            two_factor_notification:
                description:
                    - Notification method for user activation by FortiToken Cloud.
                type: str
                choices:
                    - 'email'
                    - 'sms'
            vdom:
                description:
                    - Virtual domain(s) that the administrator can access.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Virtual domain name. Source system.vdom.name.
                        required: true
                        type: str
            vdom_override:
                description:
                    - Enable to use the names of VDOMs provided by the remote authentication server to control the VDOMs that this administrator can access.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wildcard:
                description:
                    - Enable/disable wildcard RADIUS authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure admin users.
  fortinet.fortios.fortios_system_admin:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_admin:
          accprofile: "<your_own_value> (source system.accprofile.name)"
          accprofile_override: "enable"
          allow_remove_admin_session: "enable"
          comments: "<your_own_value>"
          email_to: "<your_own_value>"
          force_password_change: "enable"
          fortitoken: "<your_own_value>"
          guest_auth: "disable"
          guest_lang: "<your_own_value> (source system.custom-language.name)"
          guest_usergroups:
              -
                  name: "default_name_13"
          gui_dashboard:
              -
                  columns: "10"
                  id: "16"
                  layout_type: "responsive"
                  name: "default_name_18"
                  permanent: "disable"
                  scope: "global"
                  vdom: "<your_own_value> (source system.vdom.name)"
                  widget:
                      -
                          fabric_device: "<your_own_value>"
                          fabric_device_widget_name: "<your_own_value>"
                          fabric_device_widget_visualization_type: "<your_own_value>"
                          fortiview_device: "<your_own_value>"
                          fortiview_filters:
                              -
                                  id: "28"
                                  key: "<your_own_value>"
                                  value: "<your_own_value>"
                          fortiview_sort_by: "<your_own_value>"
                          fortiview_timeframe: "<your_own_value>"
                          fortiview_type: "<your_own_value>"
                          fortiview_visualization: "<your_own_value>"
                          height: "25"
                          id: "36"
                          industry: "default"
                          interface: "<your_own_value> (source system.interface.name)"
                          region: "default"
                          title: "<your_own_value>"
                          type: "sysinfo"
                          width: "25"
                          x_pos: "500"
                          y_pos: "500"
          gui_global_menu_favorites:
              -
                  id: "46"
          gui_new_feature_acknowledge:
              -
                  id: "48"
          gui_vdom_menu_favorites:
              -
                  id: "50"
          hidden: "127"
          history0: "<your_own_value>"
          history1: "<your_own_value>"
          ip6_trusthost1: "myhostname"
          ip6_trusthost10: "myhostname"
          ip6_trusthost2: "myhostname"
          ip6_trusthost3: "myhostname"
          ip6_trusthost4: "myhostname"
          ip6_trusthost5: "myhostname"
          ip6_trusthost6: "myhostname"
          ip6_trusthost7: "myhostname"
          ip6_trusthost8: "myhostname"
          ip6_trusthost9: "myhostname"
          login_time:
              -
                  last_failed_login: "<your_own_value>"
                  last_login: "<your_own_value>"
                  usr_name: "<your_own_value>"
          name: "default_name_68"
          password: "<your_own_value>"
          password_expire: "<your_own_value>"
          peer_auth: "enable"
          peer_group: "<your_own_value>"
          radius_vdom_override: "enable"
          remote_auth: "enable"
          remote_group: "<your_own_value>"
          schedule: "<your_own_value>"
          sms_custom_server: "<your_own_value> (source system.sms-server.name)"
          sms_phone: "<your_own_value>"
          sms_server: "fortiguard"
          ssh_certificate: "<your_own_value> (source certificate.remote.name)"
          ssh_public_key1: "<your_own_value>"
          ssh_public_key2: "<your_own_value>"
          ssh_public_key3: "<your_own_value>"
          trusthost1: "myhostname"
          trusthost10: "myhostname"
          trusthost2: "myhostname"
          trusthost3: "myhostname"
          trusthost4: "myhostname"
          trusthost5: "myhostname"
          trusthost6: "myhostname"
          trusthost7: "myhostname"
          trusthost8: "myhostname"
          trusthost9: "myhostname"
          two_factor: "disable"
          two_factor_authentication: "fortitoken"
          two_factor_notification: "email"
          vdom:
              -
                  name: "default_name_98 (source system.vdom.name)"
          vdom_override: "enable"
          wildcard: "enable"
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


def filter_system_admin_data(json):
    option_list = [
        "accprofile",
        "accprofile_override",
        "allow_remove_admin_session",
        "comments",
        "email_to",
        "force_password_change",
        "fortitoken",
        "guest_auth",
        "guest_lang",
        "guest_usergroups",
        "gui_dashboard",
        "gui_global_menu_favorites",
        "gui_new_feature_acknowledge",
        "gui_vdom_menu_favorites",
        "hidden",
        "history0",
        "history1",
        "ip6_trusthost1",
        "ip6_trusthost10",
        "ip6_trusthost2",
        "ip6_trusthost3",
        "ip6_trusthost4",
        "ip6_trusthost5",
        "ip6_trusthost6",
        "ip6_trusthost7",
        "ip6_trusthost8",
        "ip6_trusthost9",
        "login_time",
        "name",
        "password",
        "password_expire",
        "peer_auth",
        "peer_group",
        "radius_vdom_override",
        "remote_auth",
        "remote_group",
        "schedule",
        "sms_custom_server",
        "sms_phone",
        "sms_server",
        "ssh_certificate",
        "ssh_public_key1",
        "ssh_public_key2",
        "ssh_public_key3",
        "trusthost1",
        "trusthost10",
        "trusthost2",
        "trusthost3",
        "trusthost4",
        "trusthost5",
        "trusthost6",
        "trusthost7",
        "trusthost8",
        "trusthost9",
        "two_factor",
        "two_factor_authentication",
        "two_factor_notification",
        "vdom",
        "vdom_override",
        "wildcard",
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


def system_admin(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_admin_data = data["system_admin"]

    filtered_data = filter_system_admin_data(system_admin_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "admin", filtered_data, vdom=vdom)
        current_data = fos.get("system", "admin", vdom=vdom, mkey=mkey)
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
    data_copy["system_admin"] = filtered_data
    fos.do_member_operation(
        "system",
        "admin",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "admin", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("system", "admin", mkey=converted_data["name"], vdom=vdom)
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

    if data["system_admin"]:
        resp = system_admin(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_admin"))
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
        "wildcard": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "remote_auth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "remote_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "peer_auth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "peer_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trusthost1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trusthost2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trusthost3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trusthost4": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trusthost5": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trusthost6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trusthost7": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trusthost8": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trusthost9": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "trusthost10": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip6_trusthost1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip6_trusthost2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip6_trusthost3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip6_trusthost4": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip6_trusthost5": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip6_trusthost6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip6_trusthost7": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip6_trusthost8": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip6_trusthost9": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip6_trusthost10": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "accprofile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "allow_remove_admin_session": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "vdom": {
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
        "ssh_public_key1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ssh_public_key2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ssh_public_key3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ssh_certificate": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "schedule": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "accprofile_override": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vdom_override": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "password_expire": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "force_password_change": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "two_factor": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "fortitoken"},
                {"value": "fortitoken-cloud", "v_range": [["v6.2.0", ""]]},
                {"value": "email"},
                {"value": "sms"},
            ],
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
        "fortitoken": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "email_to": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sms_server": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "fortiguard"}, {"value": "custom"}],
        },
        "sms_custom_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sms_phone": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "guest_auth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "guest_usergroups": {
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
        "guest_lang": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "radius_vdom_override": {
            "v_range": [["v6.0.0", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_dashboard": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "integer",
                    "required": True,
                },
                "name": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "string",
                },
                "vdom": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
                "layout_type": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "string",
                    "options": [{"value": "responsive"}, {"value": "fixed"}],
                },
                "permanent": {
                    "v_range": [["v6.2.3", "v6.2.3"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "columns": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "integer",
                },
                "widget": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "integer",
                            "required": True,
                        },
                        "type": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "string",
                            "options": [
                                {"value": "sysinfo"},
                                {"value": "licinfo"},
                                {"value": "forticloud"},
                                {"value": "cpu-usage"},
                                {"value": "memory-usage"},
                                {"value": "disk-usage"},
                                {"value": "log-rate"},
                                {"value": "sessions"},
                                {"value": "session-rate"},
                                {"value": "tr-history"},
                                {"value": "analytics"},
                                {"value": "usb-modem"},
                                {"value": "admins"},
                                {"value": "security-fabric"},
                                {"value": "security-fabric-ranking"},
                                {"value": "sensor-info"},
                                {"value": "ha-status"},
                                {"value": "vulnerability-summary"},
                                {"value": "host-scan-summary"},
                                {"value": "fortiview"},
                                {"value": "botnet-activity"},
                                {
                                    "value": "fabric-device",
                                    "v_range": [["v6.2.3", "v6.2.3"]],
                                },
                                {
                                    "value": "fortimail",
                                    "v_range": [["v6.0.0", "v6.0.11"]],
                                },
                            ],
                        },
                        "x_pos": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "integer",
                        },
                        "y_pos": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "integer",
                        },
                        "width": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "integer",
                        },
                        "height": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "integer",
                        },
                        "interface": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "string",
                        },
                        "region": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "string",
                            "options": [{"value": "default"}, {"value": "custom"}],
                        },
                        "industry": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "string",
                            "options": [{"value": "default"}, {"value": "custom"}],
                        },
                        "fabric_device": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "string",
                        },
                        "fabric_device_widget_name": {
                            "v_range": [["v6.2.3", "v6.2.3"]],
                            "type": "string",
                        },
                        "fabric_device_widget_visualization_type": {
                            "v_range": [["v6.2.3", "v6.2.3"]],
                            "type": "string",
                        },
                        "title": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "string",
                        },
                        "fortiview_type": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "string",
                        },
                        "fortiview_sort_by": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "string",
                        },
                        "fortiview_timeframe": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "string",
                        },
                        "fortiview_visualization": {
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                            "type": "string",
                        },
                        "fortiview_device": {
                            "v_range": [["v6.2.3", "v6.2.3"]],
                            "type": "string",
                        },
                        "fortiview_filters": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "id": {
                                    "v_range": [
                                        ["v6.0.0", "v6.0.11"],
                                        ["v6.2.3", "v6.2.3"],
                                    ],
                                    "type": "integer",
                                    "required": True,
                                },
                                "key": {
                                    "v_range": [
                                        ["v6.0.0", "v6.0.11"],
                                        ["v6.2.3", "v6.2.3"],
                                    ],
                                    "type": "string",
                                },
                                "value": {
                                    "v_range": [
                                        ["v6.0.0", "v6.0.11"],
                                        ["v6.2.3", "v6.2.3"],
                                    ],
                                    "type": "string",
                                },
                            },
                            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                        },
                    },
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                },
                "scope": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "vdom"}],
                },
            },
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
        },
        "history0": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "history1": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "login_time": {
            "type": "list",
            "elements": "dict",
            "children": {
                "usr_name": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "string",
                    "required": True,
                },
                "last_login": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "string",
                },
                "last_failed_login": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "string",
                },
            },
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
        },
        "gui_global_menu_favorites": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
        },
        "gui_vdom_menu_favorites": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
        },
        "gui_new_feature_acknowledge": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.2.3", "v6.2.3"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.3", "v6.2.3"]],
        },
        "hidden": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "integer"},
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
        "system_admin": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_admin"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_admin"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_admin"
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
