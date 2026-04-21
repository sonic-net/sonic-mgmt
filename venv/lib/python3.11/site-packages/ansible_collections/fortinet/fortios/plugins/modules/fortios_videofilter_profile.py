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
module: fortios_videofilter_profile
short_description: Configure VideoFilter profile in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify videofilter feature and profile category.
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
    videofilter_profile:
        description:
            - Configure VideoFilter profile.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Comment.
                type: str
            dailymotion:
                description:
                    - Enable/disable Dailymotion video source.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            default_action:
                description:
                    - Video filter default action.
                type: str
                choices:
                    - 'allow'
                    - 'monitor'
                    - 'block'
            filters:
                description:
                    - YouTube filter entries.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Video filter action.
                        type: str
                        choices:
                            - 'allow'
                            - 'monitor'
                            - 'block'
                    category:
                        description:
                            - FortiGuard category ID.
                        type: str
                    channel:
                        description:
                            - Channel ID.
                        type: str
                    comment:
                        description:
                            - Comment.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    keyword:
                        description:
                            - Video filter keyword ID. Source videofilter.keyword.id.
                        type: int
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    type:
                        description:
                            - Filter type.
                        type: str
                        choices:
                            - 'category'
                            - 'channel'
                            - 'title'
                            - 'description'
            fortiguard_category:
                description:
                    - Configure FortiGuard categories.
                type: dict
                suboptions:
                    filters:
                        description:
                            - Configure VideoFilter FortiGuard category.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                description:
                                    - VideoFilter action.
                                type: str
                                choices:
                                    - 'allow'
                                    - 'monitor'
                                    - 'block'
                                    - 'bypass'
                            category_id:
                                description:
                                    - Category ID.
                                type: int
                            id:
                                description:
                                    - ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            log:
                                description:
                                    - Enable/disable logging.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
            log:
                description:
                    - Enable/disable logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Name.
                required: true
                type: str
            replacemsg_group:
                description:
                    - Replacement message group. Source system.replacemsg-group.name.
                type: str
            vimeo:
                description:
                    - Enable/disable Vimeo video source.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vimeo_restrict:
                description:
                    - Set Vimeo-restrict ("7" = don"t show mature content, "134" = don"t show unrated and mature content). A value of cookie "content_rating".
                type: str
            youtube:
                description:
                    - Enable/disable YouTube video source.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            youtube_channel_filter:
                description:
                    - Set YouTube channel filter. Source videofilter.youtube-channel-filter.id.
                type: int
            youtube_restrict:
                description:
                    - Set YouTube-restrict mode.
                type: str
                choices:
                    - 'none'
                    - 'strict'
                    - 'moderate'
"""

EXAMPLES = """
- name: Configure VideoFilter profile.
  fortinet.fortios.fortios_videofilter_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      videofilter_profile:
          comment: "Comment."
          dailymotion: "enable"
          default_action: "allow"
          filters:
              -
                  action: "allow"
                  category: "<your_own_value>"
                  channel: "<your_own_value>"
                  comment: "Comment."
                  id: "11"
                  keyword: "0"
                  log: "enable"
                  type: "category"
          fortiguard_category:
              filters:
                  -
                      action: "allow"
                      category_id: "0"
                      id: "19"
                      log: "enable"
          log: "enable"
          name: "default_name_22"
          replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
          vimeo: "enable"
          vimeo_restrict: "<your_own_value>"
          youtube: "enable"
          youtube_channel_filter: "0"
          youtube_restrict: "none"
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


def filter_videofilter_profile_data(json):
    option_list = [
        "comment",
        "dailymotion",
        "default_action",
        "filters",
        "fortiguard_category",
        "log",
        "name",
        "replacemsg_group",
        "vimeo",
        "vimeo_restrict",
        "youtube",
        "youtube_channel_filter",
        "youtube_restrict",
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


def videofilter_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    videofilter_profile_data = data["videofilter_profile"]

    filtered_data = filter_videofilter_profile_data(videofilter_profile_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("videofilter", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("videofilter", "profile", vdom=vdom, mkey=mkey)
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
    data_copy["videofilter_profile"] = filtered_data
    fos.do_member_operation(
        "videofilter",
        "profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("videofilter", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "videofilter", "profile", mkey=converted_data["name"], vdom=vdom
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


def fortios_videofilter(data, fos, check_mode):

    if data["videofilter_profile"]:
        resp = videofilter_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("videofilter_profile"))
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
        "name": {"v_range": [["v7.0.0", ""]], "type": "string", "required": True},
        "comment": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "filters": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "integer",
                    "required": True,
                },
                "comment": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "type": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "category"},
                        {"value": "channel"},
                        {"value": "title"},
                        {"value": "description"},
                    ],
                },
                "keyword": {"v_range": [["v7.4.2", ""]], "type": "integer"},
                "category": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "channel": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "action": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "monitor"},
                        {"value": "block"},
                    ],
                },
                "log": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
            "v_range": [["v7.4.2", ""]],
        },
        "youtube": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vimeo": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dailymotion": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "replacemsg_group": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "default_action": {
            "v_range": [["v7.4.0", "v7.4.1"]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "monitor"}, {"value": "block"}],
        },
        "log": {
            "v_range": [["v7.4.0", "v7.4.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "youtube_channel_filter": {
            "v_range": [["v7.0.0", "v7.4.1"]],
            "type": "integer",
        },
        "fortiguard_category": {
            "v_range": [["v7.0.0", "v7.4.1"]],
            "type": "dict",
            "children": {
                "filters": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.0.0", "v7.4.1"]],
                            "type": "integer",
                            "required": True,
                        },
                        "action": {
                            "v_range": [["v7.0.0", "v7.4.1"]],
                            "type": "string",
                            "options": [
                                {"value": "allow", "v_range": [["v7.0.1", "v7.4.1"]]},
                                {"value": "monitor"},
                                {"value": "block"},
                                {"value": "bypass", "v_range": [["v7.0.0", "v7.0.0"]]},
                            ],
                        },
                        "category_id": {
                            "v_range": [["v7.0.0", "v7.4.1"]],
                            "type": "integer",
                        },
                        "log": {
                            "v_range": [["v7.0.0", "v7.4.1"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                    },
                    "v_range": [["v7.0.0", "v7.4.1"]],
                }
            },
        },
        "youtube_restrict": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "strict"}, {"value": "moderate"}],
        },
        "vimeo_restrict": {"v_range": [["v7.0.0", "v7.0.0"]], "type": "string"},
    },
    "v_range": [["v7.0.0", ""]],
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
        "videofilter_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["videofilter_profile"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["videofilter_profile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "videofilter_profile"
        )

        is_error, has_changed, result, diff = fortios_videofilter(
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
