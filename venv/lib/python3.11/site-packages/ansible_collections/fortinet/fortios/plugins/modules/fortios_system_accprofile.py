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
module: fortios_system_accprofile
short_description: Configure access profiles for system administrators in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and accprofile category.
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
    system_accprofile:
        description:
            - Configure access profiles for system administrators.
        default: null
        type: dict
        suboptions:
            admintimeout:
                description:
                    - Administrator timeout for this access profile (0 - 480 min).
                type: int
            admintimeout_override:
                description:
                    - Enable/disable overriding the global administrator idle timeout.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            authgrp:
                description:
                    - Administrator access to Users and Devices.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            cli_config:
                description:
                    - Enable/disable permission to run config commands.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cli_diagnose:
                description:
                    - Enable/disable permission to run diagnostic commands.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cli_exec:
                description:
                    - Enable/disable permission to run execute commands.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cli_get:
                description:
                    - Enable/disable permission to run get commands.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cli_show:
                description:
                    - Enable/disable permission to run show commands.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            comments:
                description:
                    - Comment.
                type: str
            ftviewgrp:
                description:
                    - FortiView.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fwgrp:
                description:
                    - Administrator access to the Firewall configuration.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
                    - 'custom'
            fwgrp_permission:
                description:
                    - Custom firewall permission.
                type: dict
                suboptions:
                    address:
                        description:
                            - Address Configuration.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    others:
                        description:
                            - Other Firewall Configuration.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    policy:
                        description:
                            - Policy Configuration.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    schedule:
                        description:
                            - Schedule Configuration.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    service:
                        description:
                            - Service Configuration.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
            loggrp:
                description:
                    - Administrator access to Logging and Reporting including viewing log messages.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
                    - 'custom'
            loggrp_permission:
                description:
                    - Custom Log & Report permission.
                type: dict
                suboptions:
                    config:
                        description:
                            - Log & Report configuration.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    data_access:
                        description:
                            - Log & Report Data Access.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    report_access:
                        description:
                            - Log & Report Report Access.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    threat_weight:
                        description:
                            - Log & Report Threat Weight.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            netgrp:
                description:
                    - Network Configuration.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
                    - 'custom'
            netgrp_permission:
                description:
                    - Custom network permission.
                type: dict
                suboptions:
                    cfg:
                        description:
                            - Network Configuration.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    packet_capture:
                        description:
                            - Packet Capture Configuration.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    route_cfg:
                        description:
                            - Router Configuration.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
            scope:
                description:
                    - 'Scope of admin access: global or specific VDOM(s).'
                type: str
                choices:
                    - 'vdom'
                    - 'global'
            secfabgrp:
                description:
                    - Security Fabric.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            sysgrp:
                description:
                    - System Configuration.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
                    - 'custom'
            sysgrp_permission:
                description:
                    - Custom system permission.
                type: dict
                suboptions:
                    admin:
                        description:
                            - Administrator Users.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    cfg:
                        description:
                            - System Configuration.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    mnt:
                        description:
                            - Maintenance.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    upd:
                        description:
                            - FortiGuard Updates.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
            system_diagnostics:
                description:
                    - Enable/disable permission to run system diagnostic commands.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            system_execute_ssh:
                description:
                    - Enable/disable permission to execute SSH commands.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            system_execute_telnet:
                description:
                    - Enable/disable permission to execute TELNET commands.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            utmgrp:
                description:
                    - Administrator access to Security Profiles.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
                    - 'custom'
            utmgrp_permission:
                description:
                    - Custom Security Profile permissions.
                type: dict
                suboptions:
                    antivirus:
                        description:
                            - Antivirus profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    application_control:
                        description:
                            - Application Control profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    casb:
                        description:
                            - Inline CASB filter profile and settings
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    data_leak_prevention:
                        description:
                            - DLP profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    data_loss_prevention:
                        description:
                            - DLP profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    dlp:
                        description:
                            - DLP profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    dnsfilter:
                        description:
                            - DNS Filter profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    emailfilter:
                        description:
                            - Email Filter and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    endpoint_control:
                        description:
                            - FortiClient Profiles.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    file_filter:
                        description:
                            - File-filter profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    icap:
                        description:
                            - ICAP profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    ips:
                        description:
                            - IPS profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    mmsgtp:
                        description:
                            - UTM permission.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    spamfilter:
                        description:
                            - AntiSpam filter and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    telemetry:
                        description:
                            - Telemetry profile and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    videofilter:
                        description:
                            - Video filter profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    virtual_patch:
                        description:
                            - Virtual patch profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    voip:
                        description:
                            - VoIP profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    waf:
                        description:
                            - Web Application Firewall profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    webfilter:
                        description:
                            - Web Filter profiles and settings.
                        type: str
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
            vpngrp:
                description:
                    - Administrator access to IPsec, SSL, PPTP, and L2TP VPN.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            wanoptgrp:
                description:
                    - Administrator access to WAN Opt & Cache.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            wifi:
                description:
                    - Administrator access to the WiFi controller and Switch controller.
                type: str
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
"""

EXAMPLES = """
- name: Configure access profiles for system administrators.
  fortinet.fortios.fortios_system_accprofile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_accprofile:
          admintimeout: "10"
          admintimeout_override: "enable"
          authgrp: "none"
          cli_config: "enable"
          cli_diagnose: "enable"
          cli_exec: "enable"
          cli_get: "enable"
          cli_show: "enable"
          comments: "<your_own_value>"
          ftviewgrp: "none"
          fwgrp: "none"
          fwgrp_permission:
              address: "none"
              others: "none"
              policy: "none"
              schedule: "none"
              service: "none"
          loggrp: "none"
          loggrp_permission:
              config: "none"
              data_access: "none"
              report_access: "none"
              threat_weight: "none"
          name: "default_name_26"
          netgrp: "none"
          netgrp_permission:
              cfg: "none"
              packet_capture: "none"
              route_cfg: "none"
          scope: "vdom"
          secfabgrp: "none"
          sysgrp: "none"
          sysgrp_permission:
              admin: "none"
              cfg: "none"
              mnt: "none"
              upd: "none"
          system_diagnostics: "enable"
          system_execute_ssh: "enable"
          system_execute_telnet: "enable"
          utmgrp: "none"
          utmgrp_permission:
              antivirus: "none"
              application_control: "none"
              casb: "none"
              data_leak_prevention: "none"
              data_loss_prevention: "none"
              dlp: "none"
              dnsfilter: "none"
              emailfilter: "none"
              endpoint_control: "none"
              file_filter: "none"
              icap: "none"
              ips: "none"
              mmsgtp: "none"
              spamfilter: "none"
              telemetry: "none"
              videofilter: "none"
              virtual_patch: "none"
              voip: "none"
              waf: "none"
              webfilter: "none"
          vpngrp: "none"
          wanoptgrp: "none"
          wifi: "none"
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


def filter_system_accprofile_data(json):
    option_list = [
        "admintimeout",
        "admintimeout_override",
        "authgrp",
        "cli_config",
        "cli_diagnose",
        "cli_exec",
        "cli_get",
        "cli_show",
        "comments",
        "ftviewgrp",
        "fwgrp",
        "fwgrp_permission",
        "loggrp",
        "loggrp_permission",
        "name",
        "netgrp",
        "netgrp_permission",
        "scope",
        "secfabgrp",
        "sysgrp",
        "sysgrp_permission",
        "system_diagnostics",
        "system_execute_ssh",
        "system_execute_telnet",
        "utmgrp",
        "utmgrp_permission",
        "vpngrp",
        "wanoptgrp",
        "wifi",
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


def system_accprofile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_accprofile_data = data["system_accprofile"]

    filtered_data = filter_system_accprofile_data(system_accprofile_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "accprofile", filtered_data, vdom=vdom)
        current_data = fos.get("system", "accprofile", vdom=vdom, mkey=mkey)
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
    data_copy["system_accprofile"] = filtered_data
    fos.do_member_operation(
        "system",
        "accprofile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "accprofile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system", "accprofile", mkey=converted_data["name"], vdom=vdom
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


def fortios_system(data, fos, check_mode):

    if data["system_accprofile"]:
        resp = system_accprofile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_accprofile"))
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
        "scope": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "vdom"}, {"value": "global"}],
        },
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "secfabgrp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "read"}, {"value": "read-write"}],
        },
        "ftviewgrp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "read"}, {"value": "read-write"}],
        },
        "authgrp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "read"}, {"value": "read-write"}],
        },
        "sysgrp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "read"},
                {"value": "read-write"},
                {"value": "custom"},
            ],
        },
        "netgrp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "read"},
                {"value": "read-write"},
                {"value": "custom"},
            ],
        },
        "loggrp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "read"},
                {"value": "read-write"},
                {"value": "custom"},
            ],
        },
        "fwgrp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "read"},
                {"value": "read-write"},
                {"value": "custom"},
            ],
        },
        "vpngrp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "read"}, {"value": "read-write"}],
        },
        "utmgrp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "read"},
                {"value": "read-write"},
                {"value": "custom"},
            ],
        },
        "wanoptgrp": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "none", "v_range": [["v6.0.0", ""]]},
                {"value": "read", "v_range": [["v6.0.0", ""]]},
                {"value": "read-write", "v_range": [["v6.0.0", ""]]},
            ],
        },
        "wifi": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "read"}, {"value": "read-write"}],
        },
        "netgrp_permission": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "cfg": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "packet_capture": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "route_cfg": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
            },
        },
        "sysgrp_permission": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "admin": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "upd": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "cfg": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "mnt": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
            },
        },
        "fwgrp_permission": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "policy": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "address": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "service": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "schedule": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "others": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
            },
        },
        "loggrp_permission": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "config": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "data_access": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "report_access": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "threat_weight": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
            },
        },
        "utmgrp_permission": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "antivirus": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "ips": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "webfilter": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "emailfilter": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "dlp": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "file_filter": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "application_control": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "icap": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "voip": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "waf": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "dnsfilter": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "endpoint_control": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "videofilter": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "virtual_patch": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "casb": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "telemetry": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "mmsgtp": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "data_leak_prevention": {
                    "v_range": [["v7.2.4", "v7.4.3"]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "data_loss_prevention": {
                    "v_range": [["v6.0.0", "v7.2.2"]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
                "spamfilter": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "read"},
                        {"value": "read-write"},
                    ],
                },
            },
        },
        "admintimeout_override": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "admintimeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "cli_diagnose": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cli_get": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cli_show": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cli_exec": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cli_config": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "system_execute_ssh": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "system_execute_telnet": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "system_diagnostics": {
            "v_range": [["v6.4.0", "v7.4.1"]],
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
        "system_accprofile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_accprofile"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_accprofile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_accprofile"
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
