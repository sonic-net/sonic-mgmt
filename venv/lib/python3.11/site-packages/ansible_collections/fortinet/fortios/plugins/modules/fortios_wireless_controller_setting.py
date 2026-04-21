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
module: fortios_wireless_controller_setting
short_description: VDOM wireless controller configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and setting category.
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

    wireless_controller_setting:
        description:
            - VDOM wireless controller configuration.
        default: null
        type: dict
        suboptions:
            account_id:
                description:
                    - FortiCloud customer account ID.
                type: str
            country:
                description:
                    - Country or region in which the FortiGate is located. The country determines the 802.11 bands and channels that are available.
                type: str
                choices:
                    - '--'
                    - 'AF'
                    - 'AL'
                    - 'DZ'
                    - 'AS'
                    - 'AO'
                    - 'AR'
                    - 'AM'
                    - 'AU'
                    - 'AT'
                    - 'AZ'
                    - 'BS'
                    - 'BH'
                    - 'BD'
                    - 'BB'
                    - 'BY'
                    - 'BE'
                    - 'BZ'
                    - 'BJ'
                    - 'BM'
                    - 'BT'
                    - 'BO'
                    - 'BA'
                    - 'BW'
                    - 'BR'
                    - 'BN'
                    - 'BG'
                    - 'BF'
                    - 'KH'
                    - 'CM'
                    - 'KY'
                    - 'CF'
                    - 'TD'
                    - 'CL'
                    - 'CN'
                    - 'CX'
                    - 'CO'
                    - 'CG'
                    - 'CD'
                    - 'CR'
                    - 'HR'
                    - 'CY'
                    - 'CZ'
                    - 'DK'
                    - 'DJ'
                    - 'DM'
                    - 'DO'
                    - 'EC'
                    - 'EG'
                    - 'SV'
                    - 'ET'
                    - 'EE'
                    - 'GF'
                    - 'PF'
                    - 'FO'
                    - 'FJ'
                    - 'FI'
                    - 'FR'
                    - 'GA'
                    - 'GE'
                    - 'GM'
                    - 'DE'
                    - 'GH'
                    - 'GI'
                    - 'GR'
                    - 'GL'
                    - 'GD'
                    - 'GP'
                    - 'GU'
                    - 'GT'
                    - 'GY'
                    - 'HT'
                    - 'HN'
                    - 'HK'
                    - 'HU'
                    - 'IS'
                    - 'IN'
                    - 'ID'
                    - 'IQ'
                    - 'IE'
                    - 'IM'
                    - 'IL'
                    - 'IT'
                    - 'CI'
                    - 'JM'
                    - 'JO'
                    - 'KZ'
                    - 'KE'
                    - 'KR'
                    - 'KW'
                    - 'LA'
                    - 'LV'
                    - 'LB'
                    - 'LS'
                    - 'LR'
                    - 'LY'
                    - 'LI'
                    - 'LT'
                    - 'LU'
                    - 'MO'
                    - 'MK'
                    - 'MG'
                    - 'MW'
                    - 'MY'
                    - 'MV'
                    - 'ML'
                    - 'MT'
                    - 'MH'
                    - 'MQ'
                    - 'MR'
                    - 'MU'
                    - 'YT'
                    - 'MX'
                    - 'FM'
                    - 'MD'
                    - 'MC'
                    - 'MN'
                    - 'MA'
                    - 'MZ'
                    - 'MM'
                    - 'NA'
                    - 'NP'
                    - 'NL'
                    - 'AN'
                    - 'AW'
                    - 'NZ'
                    - 'NI'
                    - 'NE'
                    - 'NG'
                    - 'NO'
                    - 'MP'
                    - 'OM'
                    - 'PK'
                    - 'PW'
                    - 'PA'
                    - 'PG'
                    - 'PY'
                    - 'PE'
                    - 'PH'
                    - 'PL'
                    - 'PT'
                    - 'PR'
                    - 'QA'
                    - 'RE'
                    - 'RO'
                    - 'RU'
                    - 'RW'
                    - 'BL'
                    - 'KN'
                    - 'LC'
                    - 'MF'
                    - 'PM'
                    - 'VC'
                    - 'SA'
                    - 'SN'
                    - 'RS'
                    - 'ME'
                    - 'SL'
                    - 'SG'
                    - 'SK'
                    - 'SI'
                    - 'SO'
                    - 'ZA'
                    - 'ES'
                    - 'LK'
                    - 'SR'
                    - 'SZ'
                    - 'SE'
                    - 'CH'
                    - 'TW'
                    - 'TZ'
                    - 'TH'
                    - 'TL'
                    - 'TG'
                    - 'TT'
                    - 'TN'
                    - 'TR'
                    - 'TM'
                    - 'AE'
                    - 'TC'
                    - 'UG'
                    - 'UA'
                    - 'GB'
                    - 'US'
                    - 'PS'
                    - 'UY'
                    - 'UZ'
                    - 'VU'
                    - 'VE'
                    - 'VN'
                    - 'VI'
                    - 'WF'
                    - 'YE'
                    - 'ZM'
                    - 'ZW'
                    - 'JP'
                    - 'CA'
                    - 'IR'
                    - 'KP'
                    - 'SD'
                    - 'SY'
                    - 'ZB'
            darrp_optimize:
                description:
                    - Time for running Distributed Automatic Radio Resource Provisioning (DARRP) optimizations (0 - 86400 sec).
                type: int
            darrp_optimize_schedules:
                description:
                    - Firewall schedules for DARRP running time. DARRP will run periodically based on darrp-optimize within the schedules. Separate multiple
                       schedule names with a space.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Schedule name. Source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime.name.
                        required: true
                        type: str
            device_holdoff:
                description:
                    - Lower limit of creation time of device for identification in minutes (0 - 60).
                type: int
            device_idle:
                description:
                    - Upper limit of idle time of device for identification in minutes (0 - 14400).
                type: int
            device_weight:
                description:
                    - Upper limit of confidence of device for identification (0 - 255).
                type: int
            duplicate_ssid:
                description:
                    - Enable/disable allowing Virtual Access Points (VAPs) to use the same SSID name in the same VDOM.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fake_ssid_action:
                description:
                    - Actions taken for detected fake SSID.
                type: list
                elements: str
                choices:
                    - 'log'
                    - 'suppress'
            fapc_compatibility:
                description:
                    - Enable/disable FAP-C series compatibility.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            firmware_provision_on_authorization:
                description:
                    - Enable/disable automatic provisioning of latest firmware on authorization.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            offending_ssid:
                description:
                    - Configure offending SSID.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Actions taken for detected offending SSID.
                        type: list
                        elements: str
                        choices:
                            - 'log'
                            - 'suppress'
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ssid_pattern:
                        description:
                            - Define offending SSID pattern (case insensitive). For example, word, word*, *word, wo*rd.
                        type: str
            phishing_ssid_detect:
                description:
                    - Enable/disable phishing SSID detection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rolling_wtp_upgrade:
                description:
                    - Enable/disable rolling WTP upgrade .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wfa_compatibility:
                description:
                    - Enable/disable WFA compatibility.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: VDOM wireless controller configuration.
  fortinet.fortios.fortios_wireless_controller_setting:
      vdom: "{{ vdom }}"
      wireless_controller_setting:
          account_id: "<your_own_value>"
          country: "--"
          darrp_optimize: "86400"
          darrp_optimize_schedules:
              -
                  name: "default_name_7 (source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime.name)"
          device_holdoff: "5"
          device_idle: "1440"
          device_weight: "1"
          duplicate_ssid: "enable"
          fake_ssid_action: "log"
          fapc_compatibility: "enable"
          firmware_provision_on_authorization: "enable"
          offending_ssid:
              -
                  action: "log"
                  id: "17"
                  ssid_pattern: "<your_own_value>"
          phishing_ssid_detect: "enable"
          rolling_wtp_upgrade: "enable"
          wfa_compatibility: "enable"
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


def filter_wireless_controller_setting_data(json):
    option_list = [
        "account_id",
        "country",
        "darrp_optimize",
        "darrp_optimize_schedules",
        "device_holdoff",
        "device_idle",
        "device_weight",
        "duplicate_ssid",
        "fake_ssid_action",
        "fapc_compatibility",
        "firmware_provision_on_authorization",
        "offending_ssid",
        "phishing_ssid_detect",
        "rolling_wtp_upgrade",
        "wfa_compatibility",
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
        ["fake_ssid_action"],
        ["offending_ssid", "action"],
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


def wireless_controller_setting(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    wireless_controller_setting_data = data["wireless_controller_setting"]

    filtered_data = filter_wireless_controller_setting_data(
        wireless_controller_setting_data
    )
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("wireless-controller", "setting", filtered_data, vdom=vdom)
        current_data = fos.get("wireless-controller", "setting", vdom=vdom, mkey=mkey)
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
    data_copy["wireless_controller_setting"] = filtered_data
    fos.do_member_operation(
        "wireless-controller",
        "setting",
        data_copy,
    )

    return fos.set("wireless-controller", "setting", data=converted_data, vdom=vdom)


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


def fortios_wireless_controller(data, fos, check_mode):

    if data["wireless_controller_setting"]:
        resp = wireless_controller_setting(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("wireless_controller_setting")
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
    "v_range": [["v6.0.0", ""]],
    "type": "dict",
    "children": {
        "account_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "country": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "--", "v_range": [["v7.0.1", ""]]},
                {"value": "AF", "v_range": [["v7.0.0", ""]]},
                {"value": "AL"},
                {"value": "DZ"},
                {"value": "AS", "v_range": [["v7.0.0", ""]]},
                {"value": "AO"},
                {"value": "AR"},
                {"value": "AM"},
                {"value": "AU"},
                {"value": "AT"},
                {"value": "AZ"},
                {"value": "BS", "v_range": [["v6.4.0", ""]]},
                {"value": "BH"},
                {"value": "BD"},
                {"value": "BB"},
                {"value": "BY"},
                {"value": "BE"},
                {"value": "BZ"},
                {"value": "BJ", "v_range": [["v7.0.0", ""]]},
                {"value": "BM", "v_range": [["v7.0.0", ""]]},
                {"value": "BT", "v_range": [["v7.0.0", ""]]},
                {"value": "BO"},
                {"value": "BA"},
                {"value": "BW", "v_range": [["v7.0.0", ""]]},
                {"value": "BR"},
                {"value": "BN"},
                {"value": "BG"},
                {"value": "BF", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "KH"},
                {"value": "CM", "v_range": [["v7.0.0", ""]]},
                {"value": "KY", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "CF", "v_range": [["v6.2.0", ""]]},
                {"value": "TD", "v_range": [["v7.0.0", ""]]},
                {"value": "CL"},
                {"value": "CN"},
                {"value": "CX", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "CO"},
                {"value": "CG", "v_range": [["v7.0.0", ""]]},
                {"value": "CD", "v_range": [["v7.0.0", ""]]},
                {"value": "CR"},
                {"value": "HR"},
                {"value": "CY"},
                {"value": "CZ"},
                {"value": "DK"},
                {"value": "DJ", "v_range": [["v7.4.1", ""]]},
                {"value": "DM", "v_range": [["v7.0.0", ""]]},
                {"value": "DO"},
                {"value": "EC"},
                {"value": "EG"},
                {"value": "SV"},
                {"value": "ET", "v_range": [["v7.0.0", ""]]},
                {"value": "EE"},
                {"value": "GF", "v_range": [["v7.0.0", ""]]},
                {"value": "PF", "v_range": [["v7.0.0", ""]]},
                {"value": "FO", "v_range": [["v7.0.0", ""]]},
                {"value": "FJ", "v_range": [["v7.0.0", ""]]},
                {"value": "FI"},
                {"value": "FR"},
                {"value": "GA", "v_range": [["v7.4.1", ""]]},
                {"value": "GE"},
                {"value": "GM", "v_range": [["v7.4.1", ""]]},
                {"value": "DE"},
                {"value": "GH", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "GI", "v_range": [["v7.0.0", ""]]},
                {"value": "GR"},
                {"value": "GL"},
                {"value": "GD"},
                {"value": "GP", "v_range": [["v7.0.0", ""]]},
                {"value": "GU"},
                {"value": "GT"},
                {"value": "GY", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "HT"},
                {"value": "HN"},
                {"value": "HK"},
                {"value": "HU"},
                {"value": "IS"},
                {"value": "IN"},
                {"value": "ID"},
                {"value": "IQ", "v_range": [["v7.0.0", ""]]},
                {"value": "IE"},
                {"value": "IM", "v_range": [["v7.0.0", ""]]},
                {"value": "IL"},
                {"value": "IT"},
                {"value": "CI", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "JM"},
                {"value": "JO"},
                {"value": "KZ"},
                {"value": "KE"},
                {"value": "KR"},
                {"value": "KW"},
                {"value": "LA", "v_range": [["v7.0.0", ""]]},
                {"value": "LV"},
                {"value": "LB"},
                {"value": "LS", "v_range": [["v7.0.0", ""]]},
                {"value": "LR", "v_range": [["v7.4.1", ""]]},
                {"value": "LY", "v_range": [["v7.0.0", ""]]},
                {"value": "LI"},
                {"value": "LT"},
                {"value": "LU"},
                {"value": "MO"},
                {"value": "MK"},
                {"value": "MG", "v_range": [["v7.0.0", ""]]},
                {"value": "MW", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "MY"},
                {"value": "MV", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "ML", "v_range": [["v7.0.0", ""]]},
                {"value": "MT"},
                {"value": "MH", "v_range": [["v7.0.0", ""]]},
                {"value": "MQ", "v_range": [["v7.0.0", ""]]},
                {"value": "MR", "v_range": [["v7.0.0", ""]]},
                {"value": "MU", "v_range": [["v7.0.0", ""]]},
                {"value": "YT", "v_range": [["v7.0.0", ""]]},
                {"value": "MX"},
                {"value": "FM", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "MD", "v_range": [["v7.0.0", ""]]},
                {"value": "MC"},
                {"value": "MN", "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]]},
                {"value": "MA"},
                {"value": "MZ"},
                {"value": "MM"},
                {"value": "NA"},
                {"value": "NP"},
                {"value": "NL"},
                {"value": "AN"},
                {"value": "AW"},
                {"value": "NZ"},
                {"value": "NI", "v_range": [["v7.0.0", ""]]},
                {"value": "NE", "v_range": [["v7.0.0", ""]]},
                {"value": "NG", "v_range": [["v7.4.1", ""]]},
                {"value": "NO"},
                {"value": "MP", "v_range": [["v7.0.0", ""]]},
                {"value": "OM"},
                {"value": "PK"},
                {"value": "PW", "v_range": [["v7.0.0", ""]]},
                {"value": "PA"},
                {"value": "PG"},
                {"value": "PY"},
                {"value": "PE"},
                {"value": "PH"},
                {"value": "PL"},
                {"value": "PT"},
                {"value": "PR"},
                {"value": "QA"},
                {"value": "RE", "v_range": [["v7.0.0", ""]]},
                {"value": "RO"},
                {"value": "RU"},
                {"value": "RW"},
                {"value": "BL", "v_range": [["v7.0.0", ""]]},
                {"value": "KN", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "LC", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "MF", "v_range": [["v7.0.0", ""]]},
                {"value": "PM", "v_range": [["v7.0.0", ""]]},
                {"value": "VC", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "SA"},
                {"value": "SN", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "RS"},
                {"value": "ME"},
                {"value": "SL", "v_range": [["v7.0.0", ""]]},
                {"value": "SG"},
                {"value": "SK"},
                {"value": "SI"},
                {"value": "SO", "v_range": [["v7.4.1", ""]]},
                {"value": "ZA"},
                {"value": "ES"},
                {"value": "LK"},
                {"value": "SR", "v_range": [["v7.0.0", ""]]},
                {"value": "SZ", "v_range": [["v7.4.1", ""]]},
                {"value": "SE"},
                {"value": "CH"},
                {"value": "TW"},
                {"value": "TZ"},
                {"value": "TH"},
                {"value": "TL", "v_range": [["v7.6.3", ""]]},
                {"value": "TG", "v_range": [["v7.0.0", ""]]},
                {"value": "TT"},
                {"value": "TN"},
                {"value": "TR"},
                {"value": "TM", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "AE"},
                {"value": "TC", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "UG", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "UA"},
                {"value": "GB"},
                {"value": "US"},
                {"value": "PS"},
                {"value": "UY"},
                {"value": "UZ"},
                {"value": "VU", "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]]},
                {"value": "VE"},
                {"value": "VN"},
                {"value": "VI", "v_range": [["v7.0.0", ""]]},
                {"value": "WF", "v_range": [["v7.0.0", ""]]},
                {"value": "YE"},
                {"value": "ZM", "v_range": [["v7.0.0", ""]]},
                {"value": "ZW"},
                {"value": "JP"},
                {"value": "CA"},
                {"value": "IR", "v_range": [["v6.0.0", "v6.4.4"]]},
                {"value": "KP", "v_range": [["v6.0.0", "v6.4.4"]]},
                {"value": "SD", "v_range": [["v6.0.0", "v6.4.4"]]},
                {"value": "SY", "v_range": [["v6.0.0", "v6.4.4"]]},
                {"value": "ZB", "v_range": [["v6.0.0", "v6.4.4"]]},
            ],
        },
        "duplicate_ssid": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fapc_compatibility": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wfa_compatibility": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "phishing_ssid_detect": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fake_ssid_action": {
            "v_range": [["v6.2.0", ""]],
            "type": "list",
            "options": [{"value": "log"}, {"value": "suppress"}],
            "multiple_values": True,
            "elements": "str",
        },
        "offending_ssid": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "ssid_pattern": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "action": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [{"value": "log"}, {"value": "suppress"}],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
            "v_range": [["v6.2.0", ""]],
        },
        "device_weight": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "device_holdoff": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "device_idle": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "firmware_provision_on_authorization": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rolling_wtp_upgrade": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "darrp_optimize": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "darrp_optimize_schedules": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", ""]],
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
        "wireless_controller_setting": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_setting"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_setting"]["options"][attribute_name][
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
            fos, versioned_schema, "wireless_controller_setting"
        )

        is_error, has_changed, result, diff = fortios_wireless_controller(
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
