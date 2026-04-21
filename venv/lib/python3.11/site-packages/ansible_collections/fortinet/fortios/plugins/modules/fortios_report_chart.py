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
module: fortios_report_chart
short_description: Report chart widget configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify report feature and chart category.
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
    report_chart:
        description:
            - Report chart widget configuration.
        default: null
        type: dict
        suboptions:
            background:
                description:
                    - Chart background.
                type: str
            category:
                description:
                    - Category.
                type: str
                choices:
                    - 'misc'
                    - 'traffic'
                    - 'event'
                    - 'virus'
                    - 'webfilter'
                    - 'attack'
                    - 'spam'
                    - 'dlp'
                    - 'app-ctrl'
                    - 'vulnerability'
            category_series:
                description:
                    - Category series of pie chart.
                type: dict
                suboptions:
                    databind:
                        description:
                            - Category series value expression.
                        type: str
                    font_size:
                        description:
                            - Font size of category-series title.
                        type: int
            color_palette:
                description:
                    - Color palette (system will pick color automatically by default).
                type: str
            column:
                description:
                    - Table column definition.
                type: list
                elements: dict
                suboptions:
                    detail_unit:
                        description:
                            - Detail unit of column.
                        type: str
                    detail_value:
                        description:
                            - Detail value of column.
                        type: str
                    footer_unit:
                        description:
                            - Footer unit of column.
                        type: str
                    footer_value:
                        description:
                            - Footer value of column.
                        type: str
                    header_value:
                        description:
                            - Display name of table header.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    mapping:
                        description:
                            - Show detail in certain display value for certain condition.
                        type: list
                        elements: dict
                        suboptions:
                            displayname:
                                description:
                                    - Display name.
                                type: str
                            id:
                                description:
                                    - id see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            op:
                                description:
                                    - Comparision operater.
                                type: str
                                choices:
                                    - 'none'
                                    - 'greater'
                                    - 'greater-equal'
                                    - 'less'
                                    - 'less-equal'
                                    - 'equal'
                                    - 'between'
                            value_type:
                                description:
                                    - Value type.
                                type: str
                                choices:
                                    - 'integer'
                                    - 'string'
                            value1:
                                description:
                                    - Value 1.
                                type: str
                            value2:
                                description:
                                    - Value 2.
                                type: str
            comments:
                description:
                    - Comment.
                type: str
            dataset:
                description:
                    - Bind dataset to chart.
                type: str
            dimension:
                description:
                    - Dimension.
                type: str
                choices:
                    - '2D'
                    - '3D'
            drill_down_charts:
                description:
                    - Drill down charts.
                type: list
                elements: dict
                suboptions:
                    chart_name:
                        description:
                            - Drill down chart name.
                        type: str
                    id:
                        description:
                            - Drill down chart ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    status:
                        description:
                            - Enable/disable this drill down chart.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            favorite:
                description:
                    - Favorite.
                type: str
                choices:
                    - 'no'
                    - 'yes'
            graph_type:
                description:
                    - Graph type.
                type: str
                choices:
                    - 'none'
                    - 'bar'
                    - 'pie'
                    - 'line'
                    - 'flow'
            legend:
                description:
                    - Enable/Disable Legend area.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            legend_font_size:
                description:
                    - Font size of legend area.
                type: int
            name:
                description:
                    - Chart Widget Name
                required: true
                type: str
            period:
                description:
                    - Time period.
                type: str
                choices:
                    - 'last24h'
                    - 'last7d'
            policy:
                description:
                    - Used by monitor policy.
                type: int
            style:
                description:
                    - Style.
                type: str
                choices:
                    - 'auto'
                    - 'manual'
            title:
                description:
                    - Chart title.
                type: str
            title_font_size:
                description:
                    - Font size of chart title.
                type: int
            type:
                description:
                    - Chart type.
                type: str
                choices:
                    - 'graph'
                    - 'table'
            value_series:
                description:
                    - Value series of pie chart.
                type: dict
                suboptions:
                    databind:
                        description:
                            - Value series value expression.
                        type: str
            x_series:
                description:
                    - X-series of chart.
                type: dict
                suboptions:
                    caption:
                        description:
                            - X-series caption.
                        type: str
                    caption_font_size:
                        description:
                            - X-series caption font size.
                        type: int
                    databind:
                        description:
                            - X-series value expression.
                        type: str
                    font_size:
                        description:
                            - X-series label font size.
                        type: int
                    is_category:
                        description:
                            - X-series represent category or not.
                        type: str
                        choices:
                            - 'yes'
                            - 'no'
                    label_angle:
                        description:
                            - X-series label angle.
                        type: str
                        choices:
                            - '45-degree'
                            - 'vertical'
                            - 'horizontal'
                    scale_direction:
                        description:
                            - Scale increase or decrease.
                        type: str
                        choices:
                            - 'decrease'
                            - 'increase'
                    scale_format:
                        description:
                            - Date/time format.
                        type: str
                        choices:
                            - 'YYYY-MM-DD-HH-MM'
                            - 'YYYY-MM-DD HH'
                            - 'YYYY-MM-DD'
                            - 'YYYY-MM'
                            - 'YYYY'
                            - 'HH-MM'
                            - 'MM-DD'
                    scale_step:
                        description:
                            - Scale step.
                        type: int
                    scale_unit:
                        description:
                            - Scale unit.
                        type: str
                        choices:
                            - 'minute'
                            - 'hour'
                            - 'day'
                            - 'month'
                            - 'year'
                    unit:
                        description:
                            - X-series unit.
                        type: str
            y_series:
                description:
                    - Y-series of chart.
                type: dict
                suboptions:
                    caption:
                        description:
                            - Y-series caption.
                        type: str
                    caption_font_size:
                        description:
                            - Y-series caption font size.
                        type: int
                    databind:
                        description:
                            - Y-series value expression.
                        type: str
                    extra_databind:
                        description:
                            - Extra Y-series value.
                        type: str
                    extra_y:
                        description:
                            - Allow another Y-series value
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    extra_y_legend:
                        description:
                            - Extra Y-series legend type/name.
                        type: str
                    font_size:
                        description:
                            - Y-series label font size.
                        type: int
                    group:
                        description:
                            - Y-series group option.
                        type: str
                    label_angle:
                        description:
                            - Y-series label angle.
                        type: str
                        choices:
                            - '45-degree'
                            - 'vertical'
                            - 'horizontal'
                    unit:
                        description:
                            - Y-series unit.
                        type: str
                    y_legend:
                        description:
                            - First Y-series legend type/name.
                        type: str
"""

EXAMPLES = """
- name: Report chart widget configuration.
  fortinet.fortios.fortios_report_chart:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      report_chart:
          background: "<your_own_value>"
          category: "misc"
          category_series:
              databind: "<your_own_value>"
              font_size: "10"
          color_palette: "<your_own_value>"
          column:
              -
                  detail_unit: "<your_own_value>"
                  detail_value: "<your_own_value>"
                  footer_unit: "<your_own_value>"
                  footer_value: "<your_own_value>"
                  header_value: "<your_own_value>"
                  id: "15"
                  mapping:
                      -
                          displayname: "<your_own_value>"
                          id: "18"
                          op: "none"
                          value_type: "integer"
                          value1: "<your_own_value>"
                          value2: "<your_own_value>"
          comments: "<your_own_value>"
          dataset: "<your_own_value>"
          dimension: "2D"
          drill_down_charts:
              -
                  chart_name: "<your_own_value>"
                  id: "28"
                  status: "enable"
          favorite: "no"
          graph_type: "none"
          legend: "enable"
          legend_font_size: "2147483647"
          name: "default_name_34"
          period: "last24h"
          policy: "2147483647"
          style: "auto"
          title: "<your_own_value>"
          title_font_size: "2147483647"
          type: "graph"
          value_series:
              databind: "<your_own_value>"
          x_series:
              caption: "<your_own_value>"
              caption_font_size: "10"
              databind: "<your_own_value>"
              font_size: "10"
              is_category: "yes"
              label_angle: "45-degree"
              scale_direction: "decrease"
              scale_format: "YYYY-MM-DD-HH-MM"
              scale_step: "32767"
              scale_unit: "minute"
              unit: "<your_own_value>"
          y_series:
              caption: "<your_own_value>"
              caption_font_size: "10"
              databind: "<your_own_value>"
              extra_databind: "<your_own_value>"
              extra_y: "enable"
              extra_y_legend: "<your_own_value>"
              font_size: "10"
              group: "<your_own_value>"
              label_angle: "45-degree"
              unit: "<your_own_value>"
              y_legend: "<your_own_value>"
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


def filter_report_chart_data(json):
    option_list = [
        "background",
        "category",
        "category_series",
        "color_palette",
        "column",
        "comments",
        "dataset",
        "dimension",
        "drill_down_charts",
        "favorite",
        "graph_type",
        "legend",
        "legend_font_size",
        "name",
        "period",
        "policy",
        "style",
        "title",
        "title_font_size",
        "type",
        "value_series",
        "x_series",
        "y_series",
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


def report_chart(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    report_chart_data = data["report_chart"]

    filtered_data = filter_report_chart_data(report_chart_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("report", "chart", filtered_data, vdom=vdom)
        current_data = fos.get("report", "chart", vdom=vdom, mkey=mkey)
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
    data_copy["report_chart"] = filtered_data
    fos.do_member_operation(
        "report",
        "chart",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("report", "chart", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("report", "chart", mkey=converted_data["name"], vdom=vdom)
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


def fortios_report(data, fos, check_mode):

    if data["report_chart"]:
        resp = report_chart(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("report_chart"))
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
        "name": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string", "required": True},
        "policy": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "integer"},
        "type": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "graph"}, {"value": "table"}],
        },
        "period": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "last24h"}, {"value": "last7d"}],
        },
        "drill_down_charts": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "integer",
                    "required": True,
                },
                "chart_name": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "status": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
            "v_range": [["v6.0.0", "v6.4.4"]],
        },
        "comments": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
        "dataset": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
        "category": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [
                {"value": "misc"},
                {"value": "traffic"},
                {"value": "event"},
                {"value": "virus"},
                {"value": "webfilter"},
                {"value": "attack"},
                {"value": "spam"},
                {"value": "dlp"},
                {"value": "app-ctrl"},
                {"value": "vulnerability"},
            ],
        },
        "favorite": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "no"}, {"value": "yes"}],
        },
        "graph_type": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "bar"},
                {"value": "pie"},
                {"value": "line"},
                {"value": "flow"},
            ],
        },
        "style": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "manual"}],
        },
        "dimension": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "2D"}, {"value": "3D"}],
        },
        "x_series": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "dict",
            "children": {
                "databind": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "caption": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "caption_font_size": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "integer",
                },
                "font_size": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "integer"},
                "label_angle": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                    "options": [
                        {"value": "45-degree"},
                        {"value": "vertical"},
                        {"value": "horizontal"},
                    ],
                },
                "is_category": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                    "options": [{"value": "yes"}, {"value": "no"}],
                },
                "scale_unit": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                    "options": [
                        {"value": "minute"},
                        {"value": "hour"},
                        {"value": "day"},
                        {"value": "month"},
                        {"value": "year"},
                    ],
                },
                "scale_step": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "integer"},
                "scale_direction": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                    "options": [{"value": "decrease"}, {"value": "increase"}],
                },
                "scale_format": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                    "options": [
                        {"value": "YYYY-MM-DD-HH-MM"},
                        {"value": "YYYY-MM-DD HH"},
                        {"value": "YYYY-MM-DD"},
                        {"value": "YYYY-MM"},
                        {"value": "YYYY"},
                        {"value": "HH-MM"},
                        {"value": "MM-DD"},
                    ],
                },
                "unit": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
            },
        },
        "y_series": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "dict",
            "children": {
                "databind": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "caption": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "caption_font_size": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "integer",
                },
                "font_size": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "integer"},
                "label_angle": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                    "options": [
                        {"value": "45-degree"},
                        {"value": "vertical"},
                        {"value": "horizontal"},
                    ],
                },
                "group": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "unit": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "extra_y": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "extra_databind": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "y_legend": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "extra_y_legend": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
            },
        },
        "category_series": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "dict",
            "children": {
                "databind": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "font_size": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "integer"},
            },
        },
        "value_series": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "dict",
            "children": {
                "databind": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"}
            },
        },
        "title": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
        "title_font_size": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "integer"},
        "background": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
        "color_palette": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
        "legend": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "legend_font_size": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "integer"},
        "column": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "integer",
                    "required": True,
                },
                "header_value": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "detail_value": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "footer_value": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "detail_unit": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "footer_unit": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                "mapping": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", "v6.4.4"]],
                            "type": "integer",
                            "required": True,
                        },
                        "op": {
                            "v_range": [["v6.0.0", "v6.4.4"]],
                            "type": "string",
                            "options": [
                                {"value": "none"},
                                {"value": "greater"},
                                {"value": "greater-equal"},
                                {"value": "less"},
                                {"value": "less-equal"},
                                {"value": "equal"},
                                {"value": "between"},
                            ],
                        },
                        "value_type": {
                            "v_range": [["v6.0.0", "v6.4.4"]],
                            "type": "string",
                            "options": [{"value": "integer"}, {"value": "string"}],
                        },
                        "value1": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                        "value2": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
                        "displayname": {
                            "v_range": [["v6.0.0", "v6.4.4"]],
                            "type": "string",
                        },
                    },
                    "v_range": [["v6.0.0", "v6.4.4"]],
                },
            },
            "v_range": [["v6.0.0", "v6.4.4"]],
        },
    },
    "v_range": [["v6.0.0", "v6.4.4"]],
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
        "report_chart": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["report_chart"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["report_chart"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "report_chart"
        )

        is_error, has_changed, result, diff = fortios_report(
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
