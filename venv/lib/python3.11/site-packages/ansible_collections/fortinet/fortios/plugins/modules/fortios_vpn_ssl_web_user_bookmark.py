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
module: fortios_vpn_ssl_web_user_bookmark
short_description: Configure Agentless VPN user bookmark in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify vpn_ssl_web feature and user_bookmark category.
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
    vpn_ssl_web_user_bookmark:
        description:
            - Configure Agentless VPN user bookmark.
        default: null
        type: dict
        suboptions:
            bookmarks:
                description:
                    - Bookmark table.
                type: list
                elements: dict
                suboptions:
                    additional_params:
                        description:
                            - Additional parameters.
                        type: str
                    apptype:
                        description:
                            - Application type.
                        type: str
                        choices:
                            - 'ftp'
                            - 'rdp'
                            - 'sftp'
                            - 'smb'
                            - 'ssh'
                            - 'telnet'
                            - 'vnc'
                            - 'web'
                            - 'citrix'
                            - 'portforward'
                    color_depth:
                        description:
                            - Color depth per pixel.
                        type: str
                        choices:
                            - '32'
                            - '16'
                            - '8'
                    description:
                        description:
                            - Description.
                        type: str
                    domain:
                        description:
                            - Login domain.
                        type: str
                    folder:
                        description:
                            - Network shared file folder parameter.
                        type: str
                    form_data:
                        description:
                            - Form data.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Name.
                                required: true
                                type: str
                            value:
                                description:
                                    - Value.
                                type: str
                    height:
                        description:
                            - Screen height (range from 0 - 65535).
                        type: int
                    host:
                        description:
                            - Host name/IP parameter.
                        type: str
                    keyboard_layout:
                        description:
                            - Keyboard layout.
                        type: str
                        choices:
                            - 'ar-101'
                            - 'ar-102'
                            - 'ar-102-azerty'
                            - 'can-mul'
                            - 'cz'
                            - 'cz-qwerty'
                            - 'cz-pr'
                            - 'da'
                            - 'nl'
                            - 'de'
                            - 'de-ch'
                            - 'de-ibm'
                            - 'en-uk'
                            - 'en-uk-ext'
                            - 'en-us'
                            - 'en-us-dvorak'
                            - 'es'
                            - 'es-var'
                            - 'fi'
                            - 'fi-sami'
                            - 'fr'
                            - 'fr-apple'
                            - 'fr-ca'
                            - 'fr-ch'
                            - 'fr-be'
                            - 'hr'
                            - 'hu'
                            - 'hu-101'
                            - 'it'
                            - 'it-142'
                            - 'ja'
                            - 'ja-106'
                            - 'ko'
                            - 'la-am'
                            - 'lt'
                            - 'lt-ibm'
                            - 'lt-std'
                            - 'lav-std'
                            - 'lav-leg'
                            - 'mk'
                            - 'mk-std'
                            - 'no'
                            - 'no-sami'
                            - 'pol-214'
                            - 'pol-pr'
                            - 'pt'
                            - 'pt-br'
                            - 'pt-br-abnt2'
                            - 'ru'
                            - 'ru-mne'
                            - 'ru-t'
                            - 'sl'
                            - 'sv'
                            - 'sv-sami'
                            - 'tuk'
                            - 'tur-f'
                            - 'tur-q'
                            - 'zh-sym-sg-us'
                            - 'zh-sym-us'
                            - 'zh-tr-hk'
                            - 'zh-tr-mo'
                            - 'zh-tr-us'
                    listening_port:
                        description:
                            - Listening port (0 - 65535).
                        type: int
                    load_balancing_info:
                        description:
                            - The load balancing information or cookie which should be provided to the connection broker.
                        type: str
                    logon_password:
                        description:
                            - Logon password.
                        type: str
                    logon_user:
                        description:
                            - Logon user.
                        type: str
                    name:
                        description:
                            - Bookmark name.
                        required: true
                        type: str
                    port:
                        description:
                            - Remote port.
                        type: int
                    preconnection_blob:
                        description:
                            - An arbitrary string which identifies the RDP source.
                        type: str
                    preconnection_id:
                        description:
                            - The numeric ID of the RDP source (0-4294967295).
                        type: int
                    remote_port:
                        description:
                            - Remote port (0 - 65535).
                        type: int
                    restricted_admin:
                        description:
                            - Enable/disable restricted admin mode for RDP.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    security:
                        description:
                            - Security mode for RDP connection .
                        type: str
                        choices:
                            - 'any'
                            - 'rdp'
                            - 'nla'
                            - 'tls'
                    send_preconnection_id:
                        description:
                            - Enable/disable sending of preconnection ID.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    server_layout:
                        description:
                            - Server side keyboard layout.
                        type: str
                        choices:
                            - 'de-de-qwertz'
                            - 'en-gb-qwerty'
                            - 'en-us-qwerty'
                            - 'es-es-qwerty'
                            - 'fr-ca-qwerty'
                            - 'fr-fr-azerty'
                            - 'fr-ch-qwertz'
                            - 'it-it-qwerty'
                            - 'ja-jp-qwerty'
                            - 'pt-br-qwerty'
                            - 'sv-se-qwerty'
                            - 'tr-tr-qwerty'
                            - 'failsafe'
                    show_status_window:
                        description:
                            - Enable/disable showing of status window.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    sso:
                        description:
                            - Single sign-on.
                        type: str
                        choices:
                            - 'disable'
                            - 'static'
                            - 'auto'
                    sso_credential:
                        description:
                            - Single sign-on credentials.
                        type: str
                        choices:
                            - 'sslvpn-login'
                            - 'alternative'
                    sso_credential_sent_once:
                        description:
                            - Single sign-on credentials are only sent once to remote server.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    sso_password:
                        description:
                            - SSO password.
                        type: str
                    sso_username:
                        description:
                            - SSO user name.
                        type: str
                    url:
                        description:
                            - URL parameter.
                        type: str
                    vnc_keyboard_layout:
                        description:
                            - Keyboard layout.
                        type: str
                        choices:
                            - 'default'
                            - 'da'
                            - 'nl'
                            - 'en-uk'
                            - 'en-uk-ext'
                            - 'fi'
                            - 'fr'
                            - 'fr-be'
                            - 'fr-ca-mul'
                            - 'de'
                            - 'de-ch'
                            - 'it'
                            - 'it-142'
                            - 'pt'
                            - 'pt-br-abnt2'
                            - 'no'
                            - 'gd'
                            - 'es'
                            - 'sv'
                            - 'us-intl'
                    width:
                        description:
                            - Screen width (range from 0 - 65535).
                        type: int
            custom_lang:
                description:
                    - Personal language. Source system.custom-language.name.
                type: str
            name:
                description:
                    - User and group name.
                required: true
                type: str
"""

EXAMPLES = """
- name: Configure Agentless VPN user bookmark.
  fortinet.fortios.fortios_vpn_ssl_web_user_bookmark:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      vpn_ssl_web_user_bookmark:
          bookmarks:
              -
                  additional_params: "<your_own_value>"
                  apptype: "ftp"
                  color_depth: "32"
                  description: "<your_own_value>"
                  domain: "<your_own_value>"
                  folder: "<your_own_value>"
                  form_data:
                      -
                          name: "default_name_11"
                          value: "<your_own_value>"
                  height: "768"
                  host: "myhostname"
                  keyboard_layout: "ar-101"
                  listening_port: "0"
                  load_balancing_info: "<your_own_value>"
                  logon_password: "<your_own_value>"
                  logon_user: "<your_own_value>"
                  name: "default_name_20"
                  port: "0"
                  preconnection_blob: "<your_own_value>"
                  preconnection_id: "2147483648"
                  remote_port: "0"
                  restricted_admin: "enable"
                  security: "any"
                  send_preconnection_id: "enable"
                  server_layout: "de-de-qwertz"
                  show_status_window: "enable"
                  sso: "disable"
                  sso_credential: "sslvpn-login"
                  sso_credential_sent_once: "enable"
                  sso_password: "<your_own_value>"
                  sso_username: "<your_own_value>"
                  url: "myurl.com"
                  vnc_keyboard_layout: "default"
                  width: "1024"
          custom_lang: "<your_own_value> (source system.custom-language.name)"
          name: "default_name_39"
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


def filter_vpn_ssl_web_user_bookmark_data(json):
    option_list = ["bookmarks", "custom_lang", "name"]

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


def vpn_ssl_web_user_bookmark(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    vpn_ssl_web_user_bookmark_data = data["vpn_ssl_web_user_bookmark"]

    filtered_data = filter_vpn_ssl_web_user_bookmark_data(
        vpn_ssl_web_user_bookmark_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("vpn.ssl.web", "user-bookmark", filtered_data, vdom=vdom)
        current_data = fos.get("vpn.ssl.web", "user-bookmark", vdom=vdom, mkey=mkey)
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
    data_copy["vpn_ssl_web_user_bookmark"] = filtered_data
    fos.do_member_operation(
        "vpn.ssl.web",
        "user-bookmark",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("vpn.ssl.web", "user-bookmark", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "vpn.ssl.web", "user-bookmark", mkey=converted_data["name"], vdom=vdom
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


def fortios_vpn_ssl_web(data, fos, check_mode):

    if data["vpn_ssl_web_user_bookmark"]:
        resp = vpn_ssl_web_user_bookmark(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("vpn_ssl_web_user_bookmark")
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
        "custom_lang": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "bookmarks": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "apptype": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ftp"},
                        {"value": "rdp"},
                        {"value": "sftp", "v_range": [["v6.2.0", ""]]},
                        {"value": "smb"},
                        {"value": "ssh"},
                        {"value": "telnet"},
                        {"value": "vnc"},
                        {"value": "web"},
                        {"value": "citrix", "v_range": [["v6.0.0", "v6.0.11"]]},
                        {"value": "portforward", "v_range": [["v6.0.0", "v6.0.11"]]},
                    ],
                },
                "url": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "host": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "folder": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "domain": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                },
                "additional_params": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "description": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "keyboard_layout": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ar-101"},
                        {"value": "ar-102"},
                        {"value": "ar-102-azerty"},
                        {"value": "can-mul"},
                        {"value": "cz"},
                        {"value": "cz-qwerty"},
                        {"value": "cz-pr"},
                        {"value": "da"},
                        {"value": "nl"},
                        {"value": "de"},
                        {"value": "de-ch"},
                        {"value": "de-ibm"},
                        {"value": "en-uk"},
                        {"value": "en-uk-ext"},
                        {"value": "en-us"},
                        {"value": "en-us-dvorak"},
                        {"value": "es"},
                        {"value": "es-var"},
                        {"value": "fi"},
                        {"value": "fi-sami"},
                        {"value": "fr"},
                        {"value": "fr-apple", "v_range": [["v7.0.6", ""]]},
                        {"value": "fr-ca"},
                        {"value": "fr-ch"},
                        {"value": "fr-be"},
                        {"value": "hr"},
                        {"value": "hu"},
                        {"value": "hu-101"},
                        {"value": "it"},
                        {"value": "it-142"},
                        {"value": "ja"},
                        {"value": "ja-106", "v_range": [["v7.4.2", ""]]},
                        {"value": "ko"},
                        {"value": "la-am", "v_range": [["v7.4.1", ""]]},
                        {"value": "lt"},
                        {"value": "lt-ibm"},
                        {"value": "lt-std"},
                        {"value": "lav-std"},
                        {"value": "lav-leg"},
                        {"value": "mk"},
                        {"value": "mk-std"},
                        {"value": "no"},
                        {"value": "no-sami"},
                        {"value": "pol-214"},
                        {"value": "pol-pr"},
                        {"value": "pt"},
                        {"value": "pt-br"},
                        {"value": "pt-br-abnt2"},
                        {"value": "ru"},
                        {"value": "ru-mne"},
                        {"value": "ru-t"},
                        {"value": "sl"},
                        {"value": "sv"},
                        {"value": "sv-sami"},
                        {"value": "tuk"},
                        {"value": "tur-f"},
                        {"value": "tur-q"},
                        {"value": "zh-sym-sg-us"},
                        {"value": "zh-sym-us"},
                        {"value": "zh-tr-hk"},
                        {"value": "zh-tr-mo"},
                        {"value": "zh-tr-us"},
                    ],
                },
                "security": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "any"},
                        {"value": "rdp"},
                        {"value": "nla"},
                        {"value": "tls"},
                    ],
                },
                "send_preconnection_id": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "preconnection_id": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "preconnection_blob": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "load_balancing_info": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "restricted_admin": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "logon_user": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "logon_password": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "color_depth": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "32"}, {"value": "16"}, {"value": "8"}],
                },
                "sso": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "static"},
                        {"value": "auto"},
                    ],
                },
                "form_data": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "value": {"v_range": [["v6.0.0", ""]], "type": "string"},
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "sso_credential": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "sslvpn-login"}, {"value": "alternative"}],
                },
                "sso_username": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "sso_password": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "sso_credential_sent_once": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "width": {"v_range": [["v7.0.4", ""]], "type": "integer"},
                "height": {"v_range": [["v7.0.4", ""]], "type": "integer"},
                "vnc_keyboard_layout": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "default"},
                        {"value": "da"},
                        {"value": "nl"},
                        {"value": "en-uk"},
                        {"value": "en-uk-ext"},
                        {"value": "fi"},
                        {"value": "fr"},
                        {"value": "fr-be"},
                        {"value": "fr-ca-mul"},
                        {"value": "de"},
                        {"value": "de-ch"},
                        {"value": "it"},
                        {"value": "it-142"},
                        {"value": "pt"},
                        {"value": "pt-br-abnt2"},
                        {"value": "no"},
                        {"value": "gd"},
                        {"value": "es"},
                        {"value": "sv"},
                        {"value": "us-intl"},
                    ],
                },
                "listening_port": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "integer",
                },
                "remote_port": {"v_range": [["v6.0.0", "v7.0.0"]], "type": "integer"},
                "show_status_window": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "server_layout": {
                    "v_range": [["v6.0.0", "v7.0.0"]],
                    "type": "string",
                    "options": [
                        {"value": "de-de-qwertz"},
                        {"value": "en-gb-qwerty"},
                        {"value": "en-us-qwerty"},
                        {"value": "es-es-qwerty"},
                        {"value": "fr-ca-qwerty", "v_range": [["v6.2.0", "v7.0.0"]]},
                        {"value": "fr-fr-azerty"},
                        {"value": "fr-ch-qwertz"},
                        {"value": "it-it-qwerty"},
                        {"value": "ja-jp-qwerty"},
                        {"value": "pt-br-qwerty"},
                        {"value": "sv-se-qwerty"},
                        {"value": "tr-tr-qwerty"},
                        {"value": "failsafe"},
                    ],
                },
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
        "vpn_ssl_web_user_bookmark": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["vpn_ssl_web_user_bookmark"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["vpn_ssl_web_user_bookmark"]["options"][attribute_name][
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
            fos, versioned_schema, "vpn_ssl_web_user_bookmark"
        )

        is_error, has_changed, result, diff = fortios_vpn_ssl_web(
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
