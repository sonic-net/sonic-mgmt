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
module: fortios_wanopt_profile
short_description: Configure WAN optimization profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wanopt feature and profile category.
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
    wanopt_profile:
        description:
            - Configure WAN optimization profiles.
        default: null
        type: dict
        suboptions:
            auth_group:
                description:
                    - Optionally add an authentication group to restrict access to the WAN Optimization tunnel to peers in the authentication group. Source
                       wanopt.auth-group.name.
                type: str
            cifs:
                description:
                    - Enable/disable CIFS (Windows sharing) WAN Optimization and configure CIFS WAN Optimization features.
                type: dict
                suboptions:
                    byte_caching:
                        description:
                            - Enable/disable byte-caching. Byte caching reduces the amount of traffic by caching file data sent across the WAN and in future
                               serving if from the cache.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_traffic:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    port:
                        description:
                            - Single port number or port number range for CIFS. Only packets with a destination port number that matches this port number or
                               range are accepted by this profile.
                        type: int
                    prefer_chunking:
                        description:
                            - Select dynamic or fixed-size data chunking for WAN Optimization.
                        type: str
                        choices:
                            - 'dynamic'
                            - 'fix'
                    protocol_opt:
                        description:
                            - Select protocol specific optimization or generic TCP optimization.
                        type: str
                        choices:
                            - 'protocol'
                            - 'tcp'
                    secure_tunnel:
                        description:
                            - Enable/disable securing the WAN Opt tunnel using SSL. Secure and non-secure tunnels use the same TCP port (7810).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status:
                        description:
                            - Enable/disable WAN Optimization.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tunnel_sharing:
                        description:
                            - Tunnel sharing mode for aggressive/non-aggressive and/or interactive/non-interactive protocols.
                        type: str
                        choices:
                            - 'shared'
                            - 'express-shared'
                            - 'private'
            comments:
                description:
                    - Comment.
                type: str
            ftp:
                description:
                    - Enable/disable FTP WAN Optimization and configure FTP WAN Optimization features.
                type: dict
                suboptions:
                    byte_caching:
                        description:
                            - Enable/disable byte-caching. Byte caching reduces the amount of traffic by caching file data sent across the WAN and in future
                               serving if from the cache.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_traffic:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    port:
                        description:
                            - Single port number or port number range for FTP. Only packets with a destination port number that matches this port number or
                               range are accepted by this profile.
                        type: int
                    prefer_chunking:
                        description:
                            - Select dynamic or fixed-size data chunking for WAN Optimization.
                        type: str
                        choices:
                            - 'dynamic'
                            - 'fix'
                    protocol_opt:
                        description:
                            - Select protocol specific optimization or generic TCP optimization.
                        type: str
                        choices:
                            - 'protocol'
                            - 'tcp'
                    secure_tunnel:
                        description:
                            - Enable/disable securing the WAN Opt tunnel using SSL. Secure and non-secure tunnels use the same TCP port (7810).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl:
                        description:
                            - Enable/disable SSL/TLS offloading (hardware acceleration) for traffic in this tunnel.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status:
                        description:
                            - Enable/disable WAN Optimization.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tunnel_sharing:
                        description:
                            - Tunnel sharing mode for aggressive/non-aggressive and/or interactive/non-interactive protocols.
                        type: str
                        choices:
                            - 'shared'
                            - 'express-shared'
                            - 'private'
            http:
                description:
                    - Enable/disable HTTP WAN Optimization and configure HTTP WAN Optimization features.
                type: dict
                suboptions:
                    byte_caching:
                        description:
                            - Enable/disable byte-caching. Byte caching reduces the amount of traffic by caching file data sent across the WAN and in future
                               serving if from the cache.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_traffic:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    port:
                        description:
                            - Single port number or port number range for HTTP. Only packets with a destination port number that matches this port number or
                               range are accepted by this profile.
                        type: int
                    prefer_chunking:
                        description:
                            - Select dynamic or fixed-size data chunking for WAN Optimization.
                        type: str
                        choices:
                            - 'dynamic'
                            - 'fix'
                    protocol_opt:
                        description:
                            - Select protocol specific optimization or generic TCP optimization.
                        type: str
                        choices:
                            - 'protocol'
                            - 'tcp'
                    secure_tunnel:
                        description:
                            - Enable/disable securing the WAN Opt tunnel using SSL. Secure and non-secure tunnels use the same TCP port (7810).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl:
                        description:
                            - Enable/disable SSL/TLS offloading (hardware acceleration) for traffic in this tunnel.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl_port:
                        description:
                            - Port on which to expect HTTPS traffic for SSL/TLS offloading.
                        type: int
                    status:
                        description:
                            - Enable/disable WAN Optimization.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tunnel_non_http:
                        description:
                            - Configure how to process non-HTTP traffic when a profile configured for HTTP traffic accepts a non-HTTP session. Can occur if an
                               application sends non-HTTP traffic using an HTTP destination port.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tunnel_sharing:
                        description:
                            - Tunnel sharing mode for aggressive/non-aggressive and/or interactive/non-interactive protocols.
                        type: str
                        choices:
                            - 'shared'
                            - 'express-shared'
                            - 'private'
                    unknown_http_version:
                        description:
                            - How to handle HTTP sessions that do not comply with HTTP 0.9, 1.0, or 1.1.
                        type: str
                        choices:
                            - 'reject'
                            - 'tunnel'
                            - 'best-effort'
            mapi:
                description:
                    - Enable/disable MAPI email WAN Optimization and configure MAPI WAN Optimization features.
                type: dict
                suboptions:
                    byte_caching:
                        description:
                            - Enable/disable byte-caching. Byte caching reduces the amount of traffic by caching file data sent across the WAN and in future
                               serving if from the cache.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_traffic:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    port:
                        description:
                            - Single port number or port number range for MAPI. Only packets with a destination port number that matches this port number or
                               range are accepted by this profile.
                        type: int
                    secure_tunnel:
                        description:
                            - Enable/disable securing the WAN Opt tunnel using SSL. Secure and non-secure tunnels use the same TCP port (7810).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status:
                        description:
                            - Enable/disable WAN Optimization.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tunnel_sharing:
                        description:
                            - Tunnel sharing mode for aggressive/non-aggressive and/or interactive/non-interactive protocols.
                        type: str
                        choices:
                            - 'shared'
                            - 'express-shared'
                            - 'private'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            tcp:
                description:
                    - Enable/disable TCP WAN Optimization and configure TCP WAN Optimization features.
                type: dict
                suboptions:
                    byte_caching:
                        description:
                            - Enable/disable byte-caching. Byte caching reduces the amount of traffic by caching file data sent across the WAN and in future
                               serving if from the cache.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    byte_caching_opt:
                        description:
                            - Select whether TCP byte-caching uses system memory only or both memory and disk space.
                        type: str
                        choices:
                            - 'mem-only'
                            - 'mem-disk'
                    log_traffic:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    port:
                        description:
                            - Port numbers or port number ranges for TCP. Only packets with a destination port number that matches this port number or range
                               are accepted by this profile.
                        type: str
                    secure_tunnel:
                        description:
                            - Enable/disable securing the WAN Opt tunnel using SSL. Secure and non-secure tunnels use the same TCP port (7810).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl:
                        description:
                            - Enable/disable SSL/TLS offloading (hardware acceleration) for traffic in this tunnel.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl_port:
                        description:
                            - Port numbers or port number ranges on which to expect HTTPS traffic for SSL/TLS offloading.
                        type: str
                    status:
                        description:
                            - Enable/disable WAN Optimization.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tunnel_sharing:
                        description:
                            - Tunnel sharing mode for aggressive/non-aggressive and/or interactive/non-interactive protocols.
                        type: str
                        choices:
                            - 'shared'
                            - 'express-shared'
                            - 'private'
            transparent:
                description:
                    - Enable/disable transparent mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure WAN optimization profiles.
  fortinet.fortios.fortios_wanopt_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wanopt_profile:
          auth_group: "<your_own_value> (source wanopt.auth-group.name)"
          cifs:
              byte_caching: "enable"
              log_traffic: "enable"
              port: "32767"
              prefer_chunking: "dynamic"
              protocol_opt: "protocol"
              secure_tunnel: "enable"
              status: "enable"
              tunnel_sharing: "shared"
          comments: "<your_own_value>"
          ftp:
              byte_caching: "enable"
              log_traffic: "enable"
              port: "32767"
              prefer_chunking: "dynamic"
              protocol_opt: "protocol"
              secure_tunnel: "enable"
              ssl: "enable"
              status: "enable"
              tunnel_sharing: "shared"
          http:
              byte_caching: "enable"
              log_traffic: "enable"
              port: "32767"
              prefer_chunking: "dynamic"
              protocol_opt: "protocol"
              secure_tunnel: "enable"
              ssl: "enable"
              ssl_port: "32767"
              status: "enable"
              tunnel_non_http: "enable"
              tunnel_sharing: "shared"
              unknown_http_version: "reject"
          mapi:
              byte_caching: "enable"
              log_traffic: "enable"
              port: "32767"
              secure_tunnel: "enable"
              status: "enable"
              tunnel_sharing: "shared"
          name: "default_name_44"
          tcp:
              byte_caching: "enable"
              byte_caching_opt: "mem-only"
              log_traffic: "enable"
              port: "<your_own_value>"
              secure_tunnel: "enable"
              ssl: "enable"
              ssl_port: "<your_own_value>"
              status: "enable"
              tunnel_sharing: "shared"
          transparent: "enable"
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


def filter_wanopt_profile_data(json):
    option_list = [
        "auth_group",
        "cifs",
        "comments",
        "ftp",
        "http",
        "mapi",
        "name",
        "tcp",
        "transparent",
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


def wanopt_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    wanopt_profile_data = data["wanopt_profile"]

    filtered_data = filter_wanopt_profile_data(wanopt_profile_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("wanopt", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("wanopt", "profile", vdom=vdom, mkey=mkey)
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
    data_copy["wanopt_profile"] = filtered_data
    fos.do_member_operation(
        "wanopt",
        "profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("wanopt", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("wanopt", "profile", mkey=converted_data["name"], vdom=vdom)
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


def fortios_wanopt(data, fos, check_mode):

    if data["wanopt_profile"]:
        resp = wanopt_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("wanopt_profile"))
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
        "transparent": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "auth_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "http": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "secure_tunnel": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "byte_caching": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ssl": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "prefer_chunking": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "dynamic"}, {"value": "fix"}],
                },
                "protocol_opt": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "protocol"}, {"value": "tcp"}],
                },
                "tunnel_sharing": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "shared"},
                        {"value": "express-shared"},
                        {"value": "private"},
                    ],
                },
                "log_traffic": {
                    "v_range": [["v6.0.0", "v7.2.2"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "port": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "ssl_port": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "unknown_http_version": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "reject"},
                        {"value": "tunnel"},
                        {"value": "best-effort"},
                    ],
                },
                "tunnel_non_http": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "cifs": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "secure_tunnel": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "byte_caching": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "prefer_chunking": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "dynamic"}, {"value": "fix"}],
                },
                "protocol_opt": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "protocol"}, {"value": "tcp"}],
                },
                "tunnel_sharing": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "shared"},
                        {"value": "express-shared"},
                        {"value": "private"},
                    ],
                },
                "log_traffic": {
                    "v_range": [["v6.0.0", "v7.2.2"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "port": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
            },
        },
        "mapi": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "secure_tunnel": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "byte_caching": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "tunnel_sharing": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "shared"},
                        {"value": "express-shared"},
                        {"value": "private"},
                    ],
                },
                "log_traffic": {
                    "v_range": [["v6.0.0", "v7.2.2"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "port": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
            },
        },
        "ftp": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "secure_tunnel": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "byte_caching": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "prefer_chunking": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "dynamic"}, {"value": "fix"}],
                },
                "protocol_opt": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "protocol"}, {"value": "tcp"}],
                },
                "tunnel_sharing": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "shared"},
                        {"value": "express-shared"},
                        {"value": "private"},
                    ],
                },
                "ssl": {
                    "v_range": [["v6.4.0", "v7.2.2"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "log_traffic": {
                    "v_range": [["v6.0.0", "v7.2.2"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "port": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
            },
        },
        "tcp": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "secure_tunnel": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "byte_caching": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "byte_caching_opt": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "mem-only"}, {"value": "mem-disk"}],
                },
                "tunnel_sharing": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "shared"},
                        {"value": "express-shared"},
                        {"value": "private"},
                    ],
                },
                "port": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ssl": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ssl_port": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "log_traffic": {
                    "v_range": [["v6.0.0", "v7.2.2"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
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
        "wanopt_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wanopt_profile"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["wanopt_profile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "wanopt_profile"
        )

        is_error, has_changed, result, diff = fortios_wanopt(
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
