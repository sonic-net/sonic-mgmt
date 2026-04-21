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
module: fortios_system_fortiguard
short_description: Configure FortiGuard services in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and fortiguard category.
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

    system_fortiguard:
        description:
            - Configure FortiGuard services.
        default: null
        type: dict
        suboptions:
            antispam_cache:
                description:
                    - Enable/disable FortiGuard antispam request caching. Uses a small amount of memory but improves performance.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            antispam_cache_mpercent:
                description:
                    - Maximum percentage of FortiGate memory the antispam cache is allowed to use (1 - 15).
                type: int
            antispam_cache_mpermille:
                description:
                    - Maximum permille of FortiGate memory the antispam cache is allowed to use (1 - 150).
                type: int
            antispam_cache_ttl:
                description:
                    - Time-to-live for antispam cache entries in seconds (300 - 86400). Lower times reduce the cache size. Higher times may improve
                       performance since the cache will have more entries.
                type: int
            antispam_expiration:
                description:
                    - Expiration date of the FortiGuard antispam contract.
                type: int
            antispam_force_off:
                description:
                    - Enable/disable turning off the FortiGuard antispam service.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            antispam_license:
                description:
                    - Interval of time between license checks for the FortiGuard antispam contract.
                type: int
            antispam_timeout:
                description:
                    - Antispam query time out (1 - 30 sec).
                type: int
            anycast_sdns_server_ip:
                description:
                    - IP address of the FortiGuard anycast DNS rating server.
                type: str
            anycast_sdns_server_port:
                description:
                    - Port to connect to on the FortiGuard anycast DNS rating server.
                type: int
            auto_firmware_upgrade:
                description:
                    - Enable/disable automatic patch-level firmware upgrade from FortiGuard. The FortiGate unit searches for new patches only in the same
                       major and minor version.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auto_firmware_upgrade_day:
                description:
                    - Allowed day(s) of the week to install an automatic patch-level firmware upgrade from FortiGuard . Disallow any day of the week to use
                       auto-firmware-upgrade-delay instead, which waits for designated days before installing an automatic patch-level firmware upgrade.
                type: list
                elements: str
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
            auto_firmware_upgrade_delay:
                description:
                    - Delay of day(s) before installing an automatic patch-level firmware upgrade from FortiGuard  of the week for installing an automatic
                       patch-level firmware upgrade.
                type: int
            auto_firmware_upgrade_end_hour:
                description:
                    - End time in the designated time window for automatic patch-level firmware upgrade from FortiGuard in 24 hour time (0 ~ 23). When the end
                       time is smaller than the start time, the end time is interpreted as the next day. The actual upgrade time is selected randomly within
                          the time window.
                type: int
            auto_firmware_upgrade_start_hour:
                description:
                    - Start time in the designated time window for automatic patch-level firmware upgrade from FortiGuard in 24 hour time (0 ~ 23). The actual
                       upgrade time is selected randomly within the time window.
                type: int
            auto_join_forticloud:
                description:
                    - Automatically connect to and login to FortiCloud.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ddns_server_ip:
                description:
                    - IP address of the FortiDDNS server.
                type: str
            ddns_server_ip6:
                description:
                    - IPv6 address of the FortiDDNS server.
                type: str
            ddns_server_port:
                description:
                    - Port used to communicate with FortiDDNS servers.
                type: int
            FDS_license_expiring_days:
                description:
                    - Threshold for number of days before FortiGuard license expiration to generate license expiring event log (1 - 100 days).
                type: int
            fortiguard_anycast:
                description:
                    - Enable/disable use of FortiGuard"s Anycast network.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortiguard_anycast_source:
                description:
                    - Configure which of Fortinet"s servers to provide FortiGuard services in FortiGuard"s anycast network. Default is Fortinet.
                type: str
                choices:
                    - 'fortinet'
                    - 'aws'
                    - 'debug'
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
            load_balance_servers:
                description:
                    - Number of servers to alternate between as first FortiGuard option.
                type: int
            outbreak_prevention_cache:
                description:
                    - Enable/disable FortiGuard Virus Outbreak Prevention cache.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            outbreak_prevention_cache_mpercent:
                description:
                    - Maximum percent of memory FortiGuard Virus Outbreak Prevention cache can use (1 - 15%).
                type: int
            outbreak_prevention_cache_mpermille:
                description:
                    - Maximum permille of memory FortiGuard Virus Outbreak Prevention cache can use (1 - 150 permille).
                type: int
            outbreak_prevention_cache_ttl:
                description:
                    - Time-to-live for FortiGuard Virus Outbreak Prevention cache entries (300 - 86400 sec).
                type: int
            outbreak_prevention_expiration:
                description:
                    - Expiration date of FortiGuard Virus Outbreak Prevention contract.
                type: int
            outbreak_prevention_force_off:
                description:
                    - Turn off FortiGuard Virus Outbreak Prevention service.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            outbreak_prevention_license:
                description:
                    - Interval of time between license checks for FortiGuard Virus Outbreak Prevention contract.
                type: int
            outbreak_prevention_timeout:
                description:
                    - FortiGuard Virus Outbreak Prevention time out (1 - 30 sec).
                type: int
            persistent_connection:
                description:
                    - Enable/disable use of persistent connection to receive update notification from FortiGuard.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            port:
                description:
                    - Port used to communicate with the FortiGuard servers.
                type: str
                choices:
                    - '8888'
                    - '53'
                    - '80'
                    - '443'
            protocol:
                description:
                    - Protocol used to communicate with the FortiGuard servers.
                type: str
                choices:
                    - 'udp'
                    - 'http'
                    - 'https'
            proxy_password:
                description:
                    - Proxy user password.
                type: str
            proxy_server_ip:
                description:
                    - Hostname or IPv4 address of the proxy server.
                type: str
            proxy_server_port:
                description:
                    - Port used to communicate with the proxy server.
                type: int
            proxy_username:
                description:
                    - Proxy user name.
                type: str
            sandbox_inline_scan:
                description:
                    - Enable/disable FortiCloud Sandbox inline-scan.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sandbox_region:
                description:
                    - FortiCloud Sandbox region.
                type: str
            sdns_options:
                description:
                    - Customization options for the FortiGuard DNS service.
                type: list
                elements: str
                choices:
                    - 'include-question-section'
            sdns_server_ip:
                description:
                    - IP address of the FortiGuard DNS rating server.
                type: list
                elements: str
            sdns_server_port:
                description:
                    - Port to connect to on the FortiGuard DNS rating server.
                type: int
            service_account_id:
                description:
                    - Service account ID.
                type: str
            source_ip:
                description:
                    - Source IPv4 address used to communicate with FortiGuard.
                type: str
            source_ip6:
                description:
                    - Source IPv6 address used to communicate with FortiGuard.
                type: str
            subscribe_update_notification:
                description:
                    - Enable/disable subscription to receive update notification from FortiGuard.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            update_build_proxy:
                description:
                    - Enable/disable proxy dictionary rebuild.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            update_dldb:
                description:
                    - Enable/disable DLP signature update.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            update_extdb:
                description:
                    - Enable/disable external resource update.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            update_ffdb:
                description:
                    - Enable/disable Internet Service Database update.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            update_server_location:
                description:
                    - Location from which to receive FortiGuard updates.
                type: str
                choices:
                    - 'automatic'
                    - 'usa'
                    - 'eu'
                    - 'any'
            update_uwdb:
                description:
                    - Enable/disable allowlist update.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vdom:
                description:
                    - FortiGuard Service virtual domain name. Source system.vdom.name.
                type: str
            videofilter_expiration:
                description:
                    - Expiration date of the FortiGuard video filter contract.
                type: int
            videofilter_license:
                description:
                    - Interval of time between license checks for the FortiGuard video filter contract.
                type: int
            vrf_select:
                description:
                    - VRF ID used for connection to server.
                type: int
            webfilter_cache:
                description:
                    - Enable/disable FortiGuard web filter caching.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            webfilter_cache_ttl:
                description:
                    - Time-to-live for web filter cache entries in seconds (300 - 86400).
                type: int
            webfilter_expiration:
                description:
                    - Expiration date of the FortiGuard web filter contract.
                type: int
            webfilter_force_off:
                description:
                    - Enable/disable turning off the FortiGuard web filtering service.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            webfilter_license:
                description:
                    - Interval of time between license checks for the FortiGuard web filter contract.
                type: int
            webfilter_timeout:
                description:
                    - Web filter query time out (1 - 30 sec).
                type: int
"""

EXAMPLES = """
- name: Configure FortiGuard services.
  fortinet.fortios.fortios_system_fortiguard:
      vdom: "{{ vdom }}"
      system_fortiguard:
          antispam_cache: "enable"
          antispam_cache_mpercent: "2"
          antispam_cache_mpermille: "1"
          antispam_cache_ttl: "1800"
          antispam_expiration: "0"
          antispam_force_off: "enable"
          antispam_license: "4294967295"
          antispam_timeout: "7"
          anycast_sdns_server_ip: "<your_own_value>"
          anycast_sdns_server_port: "853"
          auto_firmware_upgrade: "enable"
          auto_firmware_upgrade_day: "sunday"
          auto_firmware_upgrade_delay: "3"
          auto_firmware_upgrade_end_hour: "4"
          auto_firmware_upgrade_start_hour: "1"
          auto_join_forticloud: "enable"
          ddns_server_ip: "<your_own_value>"
          ddns_server_ip6: "<your_own_value>"
          ddns_server_port: "443"
          FDS_license_expiring_days: "15"
          fortiguard_anycast: "enable"
          fortiguard_anycast_source: "fortinet"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          load_balance_servers: "1"
          outbreak_prevention_cache: "enable"
          outbreak_prevention_cache_mpercent: "2"
          outbreak_prevention_cache_mpermille: "1"
          outbreak_prevention_cache_ttl: "300"
          outbreak_prevention_expiration: "0"
          outbreak_prevention_force_off: "enable"
          outbreak_prevention_license: "4294967295"
          outbreak_prevention_timeout: "7"
          persistent_connection: "enable"
          port: "8888"
          protocol: "udp"
          proxy_password: "<your_own_value>"
          proxy_server_ip: "<your_own_value>"
          proxy_server_port: "0"
          proxy_username: "<your_own_value>"
          sandbox_inline_scan: "enable"
          sandbox_region: "<your_own_value>"
          sdns_options: "include-question-section"
          sdns_server_ip: "<your_own_value>"
          sdns_server_port: "53"
          service_account_id: "<your_own_value>"
          source_ip: "84.230.14.43"
          source_ip6: "<your_own_value>"
          subscribe_update_notification: "enable"
          update_build_proxy: "enable"
          update_dldb: "enable"
          update_extdb: "enable"
          update_ffdb: "enable"
          update_server_location: "automatic"
          update_uwdb: "enable"
          vdom: "<your_own_value> (source system.vdom.name)"
          videofilter_expiration: "0"
          videofilter_license: "4294967295"
          vrf_select: "0"
          webfilter_cache: "enable"
          webfilter_cache_ttl: "3600"
          webfilter_expiration: "0"
          webfilter_force_off: "enable"
          webfilter_license: "4294967295"
          webfilter_timeout: "15"
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


def filter_system_fortiguard_data(json):
    option_list = [
        "antispam_cache",
        "antispam_cache_mpercent",
        "antispam_cache_mpermille",
        "antispam_cache_ttl",
        "antispam_expiration",
        "antispam_force_off",
        "antispam_license",
        "antispam_timeout",
        "anycast_sdns_server_ip",
        "anycast_sdns_server_port",
        "auto_firmware_upgrade",
        "auto_firmware_upgrade_day",
        "auto_firmware_upgrade_delay",
        "auto_firmware_upgrade_end_hour",
        "auto_firmware_upgrade_start_hour",
        "auto_join_forticloud",
        "ddns_server_ip",
        "ddns_server_ip6",
        "ddns_server_port",
        "FDS_license_expiring_days",
        "fortiguard_anycast",
        "fortiguard_anycast_source",
        "interface",
        "interface_select_method",
        "load_balance_servers",
        "outbreak_prevention_cache",
        "outbreak_prevention_cache_mpercent",
        "outbreak_prevention_cache_mpermille",
        "outbreak_prevention_cache_ttl",
        "outbreak_prevention_expiration",
        "outbreak_prevention_force_off",
        "outbreak_prevention_license",
        "outbreak_prevention_timeout",
        "persistent_connection",
        "port",
        "protocol",
        "proxy_password",
        "proxy_server_ip",
        "proxy_server_port",
        "proxy_username",
        "sandbox_inline_scan",
        "sandbox_region",
        "sdns_options",
        "sdns_server_ip",
        "sdns_server_port",
        "service_account_id",
        "source_ip",
        "source_ip6",
        "subscribe_update_notification",
        "update_build_proxy",
        "update_dldb",
        "update_extdb",
        "update_ffdb",
        "update_server_location",
        "update_uwdb",
        "vdom",
        "videofilter_expiration",
        "videofilter_license",
        "vrf_select",
        "webfilter_cache",
        "webfilter_cache_ttl",
        "webfilter_expiration",
        "webfilter_force_off",
        "webfilter_license",
        "webfilter_timeout",
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
        ["auto_firmware_upgrade_day"],
        ["sdns_server_ip"],
        ["sdns_options"],
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


def system_fortiguard(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_fortiguard_data = data["system_fortiguard"]

    filtered_data = filter_system_fortiguard_data(system_fortiguard_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "fortiguard", filtered_data, vdom=vdom)
        current_data = fos.get("system", "fortiguard", vdom=vdom, mkey=mkey)
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
    data_copy["system_fortiguard"] = filtered_data
    fos.do_member_operation(
        "system",
        "fortiguard",
        data_copy,
    )

    return fos.set("system", "fortiguard", data=converted_data, vdom=vdom)


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

    if data["system_fortiguard"]:
        resp = system_fortiguard(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_fortiguard"))
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
        "fortiguard_anycast": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fortiguard_anycast_source": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "fortinet"}, {"value": "aws"}, {"value": "debug"}],
        },
        "protocol": {
            "v_range": [["v6.0.0", "v6.0.0"], ["v6.0.11", ""]],
            "type": "string",
            "options": [{"value": "udp"}, {"value": "http"}, {"value": "https"}],
        },
        "port": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "8888"},
                {"value": "53"},
                {"value": "80"},
                {"value": "443", "v_range": [["v6.2.0", ""]]},
            ],
        },
        "service_account_id": {
            "v_range": [
                ["v6.0.0", "v6.0.11"],
                ["v6.2.3", "v6.2.3"],
                ["v7.0.12", "v7.0.12"],
                ["v7.2.1", ""],
            ],
            "type": "string",
        },
        "load_balance_servers": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "update_server_location": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "automatic", "v_range": [["v7.0.2", ""]]},
                {"value": "usa"},
                {"value": "eu", "v_range": [["v7.0.2", ""]]},
                {"value": "any", "v_range": [["v6.0.0", "v7.0.1"]]},
            ],
        },
        "sandbox_region": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "sandbox_inline_scan": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "update_ffdb": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "update_uwdb": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "update_dldb": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "update_extdb": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "update_build_proxy": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "persistent_connection": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vdom": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "auto_firmware_upgrade": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auto_firmware_upgrade_day": {
            "v_range": [["v7.2.1", ""]],
            "type": "list",
            "options": [
                {"value": "sunday"},
                {"value": "monday"},
                {"value": "tuesday"},
                {"value": "wednesday"},
                {"value": "thursday"},
                {"value": "friday"},
                {"value": "saturday"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "auto_firmware_upgrade_delay": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "auto_firmware_upgrade_start_hour": {
            "v_range": [["v7.2.1", ""]],
            "type": "integer",
        },
        "auto_firmware_upgrade_end_hour": {
            "v_range": [["v7.2.1", ""]],
            "type": "integer",
        },
        "FDS_license_expiring_days": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "subscribe_update_notification": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "antispam_force_off": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "antispam_cache": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "antispam_cache_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "antispam_cache_mpermille": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "antispam_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "outbreak_prevention_force_off": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "outbreak_prevention_cache": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "outbreak_prevention_cache_ttl": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "outbreak_prevention_cache_mpermille": {
            "v_range": [["v7.4.0", ""]],
            "type": "integer",
        },
        "outbreak_prevention_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "webfilter_force_off": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "webfilter_cache": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "webfilter_cache_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "webfilter_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "sdns_server_ip": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "sdns_server_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "anycast_sdns_server_ip": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "anycast_sdns_server_port": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "sdns_options": {
            "v_range": [["v6.4.0", ""]],
            "type": "list",
            "options": [{"value": "include-question-section"}],
            "multiple_values": True,
            "elements": "str",
        },
        "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "source_ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "proxy_server_ip": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "proxy_server_port": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "proxy_username": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "proxy_password": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "ddns_server_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ddns_server_ip6": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "ddns_server_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
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
        "auto_join_forticloud": {
            "v_range": [],
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "v_range": [
                        ["v7.0.0", "v7.0.12"],
                        ["v7.2.1", "v7.2.2"],
                        ["v7.4.0", "v7.6.1"],
                    ],
                },
                {
                    "value": "disable",
                    "v_range": [
                        ["v7.0.0", "v7.0.12"],
                        ["v7.2.1", "v7.2.2"],
                        ["v7.4.0", "v7.6.1"],
                    ],
                },
            ],
        },
        "antispam_cache_mpercent": {
            "v_range": [["v6.0.0", "v7.2.4"]],
            "type": "integer",
        },
        "outbreak_prevention_cache_mpercent": {
            "v_range": [["v6.0.0", "v7.2.4"]],
            "type": "integer",
        },
        "antispam_license": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "antispam_expiration": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "outbreak_prevention_license": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "outbreak_prevention_expiration": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "webfilter_license": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "webfilter_expiration": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "videofilter_license": {
            "v_range": [["v7.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "videofilter_expiration": {
            "v_range": [["v7.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
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
        "system_fortiguard": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_fortiguard"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_fortiguard"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_fortiguard"
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
