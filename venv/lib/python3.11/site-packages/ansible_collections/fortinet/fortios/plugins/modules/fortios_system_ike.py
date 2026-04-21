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
module: fortios_system_ike
short_description: Configure IKE global attributes in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and ike category.
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

    system_ike:
        description:
            - Configure IKE global attributes.
        default: null
        type: dict
        suboptions:
            dh_group_1:
                description:
                    - Diffie-Hellman group 1 (MODP-768).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_14:
                description:
                    - Diffie-Hellman group 14 (MODP-2048).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_15:
                description:
                    - Diffie-Hellman group 15 (MODP-3072).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_16:
                description:
                    - Diffie-Hellman group 16 (MODP-4096).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_17:
                description:
                    - Diffie-Hellman group 17 (MODP-6144).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_18:
                description:
                    - Diffie-Hellman group 18 (MODP-8192).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_19:
                description:
                    - Diffie-Hellman group 19 (EC-P256).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_2:
                description:
                    - Diffie-Hellman group 2 (MODP-1024).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_20:
                description:
                    - Diffie-Hellman group 20 (EC-P384).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_21:
                description:
                    - Diffie-Hellman group 21 (EC-P521).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_27:
                description:
                    - Diffie-Hellman group 27 (EC-P224BP).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_28:
                description:
                    - Diffie-Hellman group 28 (EC-P256BP).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_29:
                description:
                    - Diffie-Hellman group 29 (EC-P384BP).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_30:
                description:
                    - Diffie-Hellman group 30 (EC-P512BP).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_31:
                description:
                    - Diffie-Hellman group 31 (EC-X25519).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_32:
                description:
                    - Diffie-Hellman group 32 (EC-X448).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_group_5:
                description:
                    - Diffie-Hellman group 5 (MODP-1536).
                type: dict
                suboptions:
                    keypair_cache:
                        description:
                            - Configure custom key pair cache size for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'global'
                            - 'custom'
                    keypair_count:
                        description:
                            - Number of key pairs to pre-generate for this Diffie-Hellman group (per-worker).
                        type: int
                    mode:
                        description:
                            - Use software (CPU) or hardware (CPX) to perform calculations for this Diffie-Hellman group.
                        type: str
                        choices:
                            - 'software'
                            - 'hardware'
                            - 'global'
            dh_keypair_cache:
                description:
                    - Enable/disable Diffie-Hellman key pair cache.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dh_keypair_count:
                description:
                    - Number of key pairs to pre-generate for each Diffie-Hellman group (per-worker).
                type: int
            dh_keypair_throttle:
                description:
                    - Enable/disable Diffie-Hellman key pair cache CPU throttling.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dh_mode:
                description:
                    - Use software (CPU) or hardware (CPX) to perform Diffie-Hellman calculations.
                type: str
                choices:
                    - 'software'
                    - 'hardware'
            dh_multiprocess:
                description:
                    - Enable/disable multiprocess Diffie-Hellman daemon for IKE.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dh_worker_count:
                description:
                    - Number of Diffie-Hellman workers to start.
                type: int
            embryonic_limit:
                description:
                    - Maximum number of IPsec tunnels to negotiate simultaneously.
                type: int
"""

EXAMPLES = """
- name: Configure IKE global attributes.
  fortinet.fortios.fortios_system_ike:
      vdom: "{{ vdom }}"
      system_ike:
          dh_group_1:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_14:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_15:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_16:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_17:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_18:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_19:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_2:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_20:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_21:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_27:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_28:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_29:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_30:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_31:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_32:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_group_5:
              keypair_cache: "global"
              keypair_count: "0"
              mode: "software"
          dh_keypair_cache: "enable"
          dh_keypair_count: "100"
          dh_keypair_throttle: "enable"
          dh_mode: "software"
          dh_multiprocess: "enable"
          dh_worker_count: "0"
          embryonic_limit: "10000"
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


def filter_system_ike_data(json):
    option_list = [
        "dh_group_1",
        "dh_group_14",
        "dh_group_15",
        "dh_group_16",
        "dh_group_17",
        "dh_group_18",
        "dh_group_19",
        "dh_group_2",
        "dh_group_20",
        "dh_group_21",
        "dh_group_27",
        "dh_group_28",
        "dh_group_29",
        "dh_group_30",
        "dh_group_31",
        "dh_group_32",
        "dh_group_5",
        "dh_keypair_cache",
        "dh_keypair_count",
        "dh_keypair_throttle",
        "dh_mode",
        "dh_multiprocess",
        "dh_worker_count",
        "embryonic_limit",
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


def system_ike(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_ike_data = data["system_ike"]

    filtered_data = filter_system_ike_data(system_ike_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "ike", filtered_data, vdom=vdom)
        current_data = fos.get("system", "ike", vdom=vdom, mkey=mkey)
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
    data_copy["system_ike"] = filtered_data
    fos.do_member_operation(
        "system",
        "ike",
        data_copy,
    )

    return fos.set("system", "ike", data=converted_data, vdom=vdom)


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

    if data["system_ike"]:
        resp = system_ike(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_ike"))
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
    "v_range": [["v7.0.0", ""]],
    "type": "dict",
    "children": {
        "embryonic_limit": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "dh_multiprocess": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dh_worker_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "dh_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "software"}, {"value": "hardware"}],
        },
        "dh_keypair_cache": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dh_keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "dh_keypair_throttle": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dh_group_1": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_2": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_5": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_14": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_15": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_16": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_17": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_18": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_19": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_20": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_21": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_27": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_28": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_29": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_30": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_31": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
        },
        "dh_group_32": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "mode": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "software"},
                        {"value": "hardware"},
                        {"value": "global"},
                    ],
                },
                "keypair_cache": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "custom"}],
                },
                "keypair_count": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
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
        "system_ike": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_ike"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_ike"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_ike"
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
