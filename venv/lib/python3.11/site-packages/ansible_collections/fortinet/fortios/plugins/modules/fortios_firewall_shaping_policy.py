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
module: fortios_firewall_shaping_policy
short_description: Configure shaping policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and shaping_policy category.
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
    - We highly recommend using your own value as the id instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
       available number for the object, it does have limitations. Please find more details in Q&A.
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks
    - Adjust object order by moving self after(before) another.
    - Only one of [after, before] must be specified when action is moving an object.

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
    action:
        description:
            - the action indiactor to move an object in the list
        type: str
        choices:
            - 'move'
    self:
        description:
            - mkey of self identifier
        type: str
    after:
        description:
            - mkey of target identifier
        type: str
    before:
        description:
            - mkey of target identifier
        type: str

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: false
        choices:
            - 'present'
            - 'absent'
    firewall_shaping_policy:
        description:
            - Configure shaping policies.
        default: null
        type: dict
        suboptions:
            app_category:
                description:
                    - IDs of one or more application categories that this shaper applies application control traffic shaping to.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Category IDs. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            app_group:
                description:
                    - One or more application group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Application group name. Source application.group.name.
                        required: true
                        type: str
            application:
                description:
                    - IDs of one or more applications that this shaper applies application control traffic shaping to.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Application IDs. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            class_id:
                description:
                    - Traffic class ID. Source firewall.traffic-class.class-id.
                type: int
            comment:
                description:
                    - Comments.
                type: str
            cos:
                description:
                    - VLAN CoS bit pattern.
                type: str
            cos_mask:
                description:
                    - VLAN CoS evaluated bits.
                type: str
            diffserv_forward:
                description:
                    - Enable to change packet"s DiffServ values to the specified diffservcode-forward value.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            diffserv_reverse:
                description:
                    - Enable to change packet"s reverse (reply) DiffServ values to the specified diffservcode-rev value.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            diffservcode_forward:
                description:
                    - Change packet"s DiffServ to this value.
                type: str
            diffservcode_rev:
                description:
                    - Change packet"s reverse (reply) DiffServ to this value.
                type: str
            dstaddr:
                description:
                    - IPv4 destination address and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            dstaddr6:
                description:
                    - IPv6 destination address and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
                        type: str
            dstintf:
                description:
                    - One or more outgoing (egress) interfaces.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name system.sdwan.zone.name.
                        required: true
                        type: str
            groups:
                description:
                    - Apply this traffic shaping policy to user groups that have authenticated with the FortiGate.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Group name. Source user.group.name.
                        required: true
                        type: str
            id:
                description:
                    - Shaping policy ID (0 - 4294967295). see <a href='#notes'>Notes</a>.
                required: true
                type: int
            internet_service:
                description:
                    - Enable/disable use of Internet Services for this policy. If enabled, destination address and service are not used.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service_custom:
                description:
                    - Custom Internet Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service name. Source firewall.internet-service-custom.name.
                        required: true
                        type: str
            internet_service_custom_group:
                description:
                    - Custom Internet Service group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service group name. Source firewall.internet-service-custom-group.name.
                        required: true
                        type: str
            internet_service_fortiguard:
                description:
                    - FortiGuard Internet Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - FortiGuard Internet Service name. Source firewall.internet-service-fortiguard.name.
                        required: true
                        type: str
            internet_service_group:
                description:
                    - Internet Service group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service group name. Source firewall.internet-service-group.name.
                        required: true
                        type: str
            internet_service_id:
                description:
                    - Internet Service ID.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Internet Service ID. see <a href='#notes'>Notes</a>. Source firewall.internet-service.id.
                        required: true
                        type: int
            internet_service_name:
                description:
                    - Internet Service ID.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service name. Source firewall.internet-service-name.name.
                        required: true
                        type: str
            internet_service_src:
                description:
                    - Enable/disable use of Internet Services in source for this policy. If enabled, source address is not used.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service_src_custom:
                description:
                    - Custom Internet Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service name. Source firewall.internet-service-custom.name.
                        required: true
                        type: str
            internet_service_src_custom_group:
                description:
                    - Custom Internet Service source group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service group name. Source firewall.internet-service-custom-group.name.
                        required: true
                        type: str
            internet_service_src_fortiguard:
                description:
                    - FortiGuard Internet Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - FortiGuard Internet Service name. Source firewall.internet-service-fortiguard.name.
                        required: true
                        type: str
            internet_service_src_group:
                description:
                    - Internet Service source group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service group name. Source firewall.internet-service-group.name.
                        required: true
                        type: str
            internet_service_src_id:
                description:
                    - Internet Service source ID.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Internet Service ID. see <a href='#notes'>Notes</a>. Source firewall.internet-service.id.
                        required: true
                        type: int
            internet_service_src_name:
                description:
                    - Internet Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service name. Source firewall.internet-service-name.name.
                        required: true
                        type: str
            ip_version:
                description:
                    - Apply this traffic shaping policy to IPv4 or IPv6 traffic.
                type: str
                choices:
                    - '4'
                    - '6'
            name:
                description:
                    - Shaping policy name.
                type: str
            per_ip_shaper:
                description:
                    - Per-IP traffic shaper to apply with this policy. Source firewall.shaper.per-ip-shaper.name.
                type: str
            schedule:
                description:
                    - Schedule name. Source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name.
                type: str
            service:
                description:
                    - Service and service group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Service name. Source firewall.service.custom.name firewall.service.group.name.
                        required: true
                        type: str
            srcaddr:
                description:
                    - IPv4 source address and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            srcaddr6:
                description:
                    - IPv6 source address and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
                        type: str
            srcintf:
                description:
                    - One or more incoming (ingress) interfaces.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name system.sdwan.zone.name.
                        required: true
                        type: str
            status:
                description:
                    - Enable/disable this traffic shaping policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tos:
                description:
                    - ToS (Type of Service) value used for comparison.
                type: str
            tos_mask:
                description:
                    - Non-zero bit positions are used for comparison while zero bit positions are ignored.
                type: str
            tos_negate:
                description:
                    - Enable negated TOS match.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            traffic_shaper:
                description:
                    - Traffic shaper to apply to traffic forwarded by the firewall policy. Source firewall.shaper.traffic-shaper.name.
                type: str
            traffic_shaper_reverse:
                description:
                    - Traffic shaper to apply to response traffic received by the firewall policy. Source firewall.shaper.traffic-shaper.name.
                type: str
            traffic_type:
                description:
                    - Traffic type.
                type: str
                choices:
                    - 'forwarding'
                    - 'local-in'
                    - 'local-out'
            url_category:
                description:
                    - IDs of one or more FortiGuard Web Filtering categories that this shaper applies traffic shaping to.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - URL category ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            users:
                description:
                    - Apply this traffic shaping policy to individual users that have authenticated with the FortiGate.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - User name. Source user.local.name.
                        required: true
                        type: str
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
"""

EXAMPLES = """
- name: Configure shaping policies.
  fortinet.fortios.fortios_firewall_shaping_policy:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_shaping_policy:
          app_category:
              -
                  id: "4"
          app_group:
              -
                  name: "default_name_6 (source application.group.name)"
          application:
              -
                  id: "8"
          class_id: "0"
          comment: "Comments."
          cos: "<your_own_value>"
          cos_mask: "<your_own_value>"
          diffserv_forward: "enable"
          diffserv_reverse: "enable"
          diffservcode_forward: "<your_own_value>"
          diffservcode_rev: "<your_own_value>"
          dstaddr:
              -
                  name: "default_name_18 (source firewall.address.name firewall.addrgrp.name)"
          dstaddr6:
              -
                  name: "default_name_20 (source firewall.address6.name firewall.addrgrp6.name)"
          dstintf:
              -
                  name: "default_name_22 (source system.interface.name system.zone.name system.sdwan.zone.name)"
          groups:
              -
                  name: "default_name_24 (source user.group.name)"
          id: "25"
          internet_service: "enable"
          internet_service_custom:
              -
                  name: "default_name_28 (source firewall.internet-service-custom.name)"
          internet_service_custom_group:
              -
                  name: "default_name_30 (source firewall.internet-service-custom-group.name)"
          internet_service_fortiguard:
              -
                  name: "default_name_32 (source firewall.internet-service-fortiguard.name)"
          internet_service_group:
              -
                  name: "default_name_34 (source firewall.internet-service-group.name)"
          internet_service_id:
              -
                  id: "36 (source firewall.internet-service.id)"
          internet_service_name:
              -
                  name: "default_name_38 (source firewall.internet-service-name.name)"
          internet_service_src: "enable"
          internet_service_src_custom:
              -
                  name: "default_name_41 (source firewall.internet-service-custom.name)"
          internet_service_src_custom_group:
              -
                  name: "default_name_43 (source firewall.internet-service-custom-group.name)"
          internet_service_src_fortiguard:
              -
                  name: "default_name_45 (source firewall.internet-service-fortiguard.name)"
          internet_service_src_group:
              -
                  name: "default_name_47 (source firewall.internet-service-group.name)"
          internet_service_src_id:
              -
                  id: "49 (source firewall.internet-service.id)"
          internet_service_src_name:
              -
                  name: "default_name_51 (source firewall.internet-service-name.name)"
          ip_version: "4"
          name: "default_name_53"
          per_ip_shaper: "<your_own_value> (source firewall.shaper.per-ip-shaper.name)"
          schedule: "<your_own_value> (source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name)"
          service:
              -
                  name: "default_name_57 (source firewall.service.custom.name firewall.service.group.name)"
          srcaddr:
              -
                  name: "default_name_59 (source firewall.address.name firewall.addrgrp.name)"
          srcaddr6:
              -
                  name: "default_name_61 (source firewall.address6.name firewall.addrgrp6.name)"
          srcintf:
              -
                  name: "default_name_63 (source system.interface.name system.zone.name system.sdwan.zone.name)"
          status: "enable"
          tos: "<your_own_value>"
          tos_mask: "<your_own_value>"
          tos_negate: "enable"
          traffic_shaper: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
          traffic_shaper_reverse: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
          traffic_type: "forwarding"
          url_category:
              -
                  id: "72"
          users:
              -
                  name: "default_name_74 (source user.local.name)"
          uuid: "<your_own_value>"
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


def filter_firewall_shaping_policy_data(json):
    option_list = [
        "app_category",
        "app_group",
        "application",
        "class_id",
        "comment",
        "cos",
        "cos_mask",
        "diffserv_forward",
        "diffserv_reverse",
        "diffservcode_forward",
        "diffservcode_rev",
        "dstaddr",
        "dstaddr6",
        "dstintf",
        "groups",
        "id",
        "internet_service",
        "internet_service_custom",
        "internet_service_custom_group",
        "internet_service_fortiguard",
        "internet_service_group",
        "internet_service_id",
        "internet_service_name",
        "internet_service_src",
        "internet_service_src_custom",
        "internet_service_src_custom_group",
        "internet_service_src_fortiguard",
        "internet_service_src_group",
        "internet_service_src_id",
        "internet_service_src_name",
        "ip_version",
        "name",
        "per_ip_shaper",
        "schedule",
        "service",
        "srcaddr",
        "srcaddr6",
        "srcintf",
        "status",
        "tos",
        "tos_mask",
        "tos_negate",
        "traffic_shaper",
        "traffic_shaper_reverse",
        "traffic_type",
        "url_category",
        "users",
        "uuid",
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


def firewall_shaping_policy(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_shaping_policy_data = data["firewall_shaping_policy"]

    filtered_data = filter_firewall_shaping_policy_data(firewall_shaping_policy_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "shaping-policy", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "shaping-policy", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_shaping_policy"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "shaping-policy",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "shaping-policy", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "shaping-policy", mkey=converted_data["id"], vdom=vdom
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


def move_fortios_firewall(data, fos):
    if not data["self"] or (not data["after"] and not data["before"]):
        fos._module.fail_json(msg="self, after(or before) must not be empty")
    vdom = data["vdom"]
    params_set = dict()
    params_set["action"] = "move"
    if data["after"]:
        params_set["after"] = data["after"]
    if data["before"]:
        params_set["before"] = data["before"]
    return fos.set(
        "firewall",
        "shaping-policy",
        data=None,
        mkey=data["self"],
        vdom=vdom,
        parameters=params_set,
    )


def fortios_firewall(data, fos, check_mode):

    if data["action"] == "move":
        resp = move_fortios_firewall(data, fos)
    elif data["firewall_shaping_policy"]:
        resp = firewall_shaping_policy(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_shaping_policy"))
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
        "id": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "uuid": {"v_range": [["v7.2.1", ""]], "type": "string"},
        "name": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ip_version": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "4"}, {"value": "6"}],
        },
        "traffic_type": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [
                {"value": "forwarding"},
                {"value": "local-in"},
                {"value": "local-out"},
            ],
        },
        "srcaddr": {
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
        "dstaddr": {
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
        "srcaddr6": {
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
        "dstaddr6": {
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
        "internet_service": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service_name": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.4.0", ""]],
        },
        "internet_service_group": {
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
        "internet_service_custom": {
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
        "internet_service_custom_group": {
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
        "internet_service_fortiguard": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.4", ""]],
        },
        "internet_service_src": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service_src_name": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.4.0", ""]],
        },
        "internet_service_src_group": {
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
        "internet_service_src_custom": {
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
        "internet_service_src_custom_group": {
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
        "internet_service_src_fortiguard": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.4", ""]],
        },
        "service": {
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
        "schedule": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "users": {
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
        "groups": {
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
        "application": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True}
            },
            "v_range": [["v6.0.0", ""]],
        },
        "app_category": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True}
            },
            "v_range": [["v6.0.0", ""]],
        },
        "app_group": {
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
        "url_category": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True}
            },
            "v_range": [["v6.0.0", ""]],
        },
        "srcintf": {
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
        "dstintf": {
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
        "tos_mask": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "tos": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "tos_negate": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "traffic_shaper": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "traffic_shaper_reverse": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "per_ip_shaper": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "class_id": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "diffserv_forward": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffserv_reverse": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffservcode_forward": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "diffservcode_rev": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "cos_mask": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "cos": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "internet_service_id": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "internet_service_src_id": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "id"
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
        "action": {"type": "str", "required": False, "choices": ["move"]},
        "self": {"type": "str", "required": False},
        "before": {"type": "str", "required": False},
        "after": {"type": "str", "required": False},
        "state": {"required": False, "type": "str", "choices": ["present", "absent"]},
        "firewall_shaping_policy": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_shaping_policy"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_shaping_policy"]["options"][attribute_name][
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
            fos, versioned_schema, "firewall_shaping_policy"
        )

        is_error, has_changed, result, diff = fortios_firewall(
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
