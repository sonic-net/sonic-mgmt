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
module: fortios_report_layout
short_description: Report layout configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify report feature and layout category.
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
    report_layout:
        description:
            - Report layout configuration.
        default: null
        type: dict
        suboptions:
            body_item:
                description:
                    - Configure report body item.
                type: list
                elements: dict
                suboptions:
                    chart:
                        description:
                            - Report item chart name.
                        type: str
                    chart_options:
                        description:
                            - Report chart options.
                        type: list
                        elements: str
                        choices:
                            - 'include-no-data'
                            - 'hide-title'
                            - 'show-caption'
                    column:
                        description:
                            - Report section column number.
                        type: int
                    content:
                        description:
                            - Report item text content.
                        type: str
                    description:
                        description:
                            - Description.
                        type: str
                    drill_down_items:
                        description:
                            - Control how drill down charts are shown.
                        type: str
                    drill_down_types:
                        description:
                            - Control whether keys from the parent being combined or not.
                        type: str
                    hide:
                        description:
                            - Enable/disable hide item in report.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    id:
                        description:
                            - Report item ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    img_src:
                        description:
                            - Report item image file name.
                        type: str
                    list:
                        description:
                            - Configure report list item.
                        type: list
                        elements: dict
                        suboptions:
                            content:
                                description:
                                    - List entry content.
                                type: str
                            id:
                                description:
                                    - List entry ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                    list_component:
                        description:
                            - Report item list component.
                        type: str
                        choices:
                            - 'bullet'
                            - 'numbered'
                    misc_component:
                        description:
                            - Report item miscellaneous component.
                        type: str
                        choices:
                            - 'hline'
                            - 'page-break'
                            - 'column-break'
                            - 'section-start'
                    parameters:
                        description:
                            - Parameters.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            name:
                                description:
                                    - Field name that match field of parameters defined in dataset.
                                type: str
                            value:
                                description:
                                    - Value to replace corresponding field of parameters defined in dataset.
                                type: str
                    style:
                        description:
                            - Report item style.
                        type: str
                    table_caption_style:
                        description:
                            - Table chart caption style.
                        type: str
                    table_column_widths:
                        description:
                            - Report item table column widths.
                        type: str
                    table_even_row_style:
                        description:
                            - Table chart even row style.
                        type: str
                    table_head_style:
                        description:
                            - Table chart head style.
                        type: str
                    table_odd_row_style:
                        description:
                            - Table chart odd row style.
                        type: str
                    text_component:
                        description:
                            - Report item text component.
                        type: str
                        choices:
                            - 'text'
                            - 'heading1'
                            - 'heading2'
                            - 'heading3'
                    title:
                        description:
                            - Report section title.
                        type: str
                    top_n:
                        description:
                            - Value of top.
                        type: int
                    type:
                        description:
                            - Report item type.
                        type: str
                        choices:
                            - 'text'
                            - 'image'
                            - 'chart'
                            - 'misc'
            cutoff_option:
                description:
                    - Cutoff-option is either run-time or custom.
                type: str
                choices:
                    - 'run-time'
                    - 'custom'
            cutoff_time:
                description:
                    - 'Custom cutoff time to generate report (format = hh:mm).'
                type: str
            day:
                description:
                    - Schedule days of week to generate report.
                type: str
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
            description:
                description:
                    - Description.
                type: str
            email_recipients:
                description:
                    - Email recipients for generated reports.
                type: str
            email_send:
                description:
                    - Enable/disable sending emails after reports are generated.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            format:
                description:
                    - Report format.
                type: list
                elements: str
                choices:
                    - 'pdf'
            max_pdf_report:
                description:
                    - Maximum number of PDF reports to keep at one time (oldest report is overwritten).
                type: int
            name:
                description:
                    - Report layout name.
                required: true
                type: str
            options:
                description:
                    - Report layout options.
                type: list
                elements: str
                choices:
                    - 'include-table-of-content'
                    - 'auto-numbering-heading'
                    - 'view-chart-as-heading'
                    - 'show-html-navbar-before-heading'
                    - 'dummy-option'
            page:
                description:
                    - Configure report page.
                type: dict
                suboptions:
                    column_break_before:
                        description:
                            - Report page auto column break before heading.
                        type: list
                        elements: str
                        choices:
                            - 'heading1'
                            - 'heading2'
                            - 'heading3'
                    footer:
                        description:
                            - Configure report page footer.
                        type: dict
                        suboptions:
                            footer_item:
                                description:
                                    - Configure report footer item.
                                type: list
                                elements: dict
                                suboptions:
                                    content:
                                        description:
                                            - Report item text content.
                                        type: str
                                    description:
                                        description:
                                            - Description.
                                        type: str
                                    id:
                                        description:
                                            - Report item ID. see <a href='#notes'>Notes</a>.
                                        required: true
                                        type: int
                                    img_src:
                                        description:
                                            - Report item image file name.
                                        type: str
                                    style:
                                        description:
                                            - Report item style.
                                        type: str
                                    type:
                                        description:
                                            - Report item type.
                                        type: str
                                        choices:
                                            - 'text'
                                            - 'image'
                            style:
                                description:
                                    - Report footer style.
                                type: str
                    header:
                        description:
                            - Configure report page header.
                        type: dict
                        suboptions:
                            header_item:
                                description:
                                    - Configure report header item.
                                type: list
                                elements: dict
                                suboptions:
                                    content:
                                        description:
                                            - Report item text content.
                                        type: str
                                    description:
                                        description:
                                            - Description.
                                        type: str
                                    id:
                                        description:
                                            - Report item ID. see <a href='#notes'>Notes</a>.
                                        required: true
                                        type: int
                                    img_src:
                                        description:
                                            - Report item image file name.
                                        type: str
                                    style:
                                        description:
                                            - Report item style.
                                        type: str
                                    type:
                                        description:
                                            - Report item type.
                                        type: str
                                        choices:
                                            - 'text'
                                            - 'image'
                            style:
                                description:
                                    - Report header style.
                                type: str
                    options:
                        description:
                            - Report page options.
                        type: list
                        elements: str
                        choices:
                            - 'header-on-first-page'
                            - 'footer-on-first-page'
                    page_break_before:
                        description:
                            - Report page auto page break before heading.
                        type: list
                        elements: str
                        choices:
                            - 'heading1'
                            - 'heading2'
                            - 'heading3'
                    paper:
                        description:
                            - Report page paper.
                        type: str
                        choices:
                            - 'a4'
                            - 'letter'
            schedule_type:
                description:
                    - Report schedule type.
                type: str
                choices:
                    - 'demand'
                    - 'daily'
                    - 'weekly'
            style_theme:
                description:
                    - Report style theme.
                type: str
            subtitle:
                description:
                    - Report subtitle.
                type: str
            time:
                description:
                    - 'Schedule time to generate report (format = hh:mm).'
                type: str
            title:
                description:
                    - Report title.
                type: str
"""

EXAMPLES = """
- name: Report layout configuration.
  fortinet.fortios.fortios_report_layout:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      report_layout:
          body_item:
              -
                  chart: "<your_own_value>"
                  chart_options: "include-no-data"
                  column: "2147483647"
                  content: "<your_own_value>"
                  description: "<your_own_value>"
                  drill_down_items: "<your_own_value>"
                  drill_down_types: "<your_own_value>"
                  hide: "enable"
                  id: "12"
                  img_src: "<your_own_value>"
                  list:
                      -
                          content: "<your_own_value>"
                          id: "16"
                  list_component: "bullet"
                  misc_component: "hline"
                  parameters:
                      -
                          id: "20"
                          name: "default_name_21"
                          value: "<your_own_value>"
                  style: "<your_own_value>"
                  table_caption_style: "<your_own_value>"
                  table_column_widths: "<your_own_value>"
                  table_even_row_style: "<your_own_value>"
                  table_head_style: "<your_own_value>"
                  table_odd_row_style: "<your_own_value>"
                  text_component: "text"
                  title: "<your_own_value>"
                  top_n: "0"
                  type: "text"
          cutoff_option: "run-time"
          cutoff_time: "<your_own_value>"
          day: "sunday"
          description: "<your_own_value>"
          email_recipients: "<your_own_value>"
          email_send: "enable"
          format: "pdf"
          max_pdf_report: "31"
          name: "default_name_41"
          options: "include-table-of-content"
          page:
              column_break_before: "heading1"
              footer:
                  footer_item:
                      -
                          content: "<your_own_value>"
                          description: "<your_own_value>"
                          id: "49"
                          img_src: "<your_own_value>"
                          style: "<your_own_value>"
                          type: "text"
                  style: "<your_own_value>"
              header:
                  header_item:
                      -
                          content: "<your_own_value>"
                          description: "<your_own_value>"
                          id: "58"
                          img_src: "<your_own_value>"
                          style: "<your_own_value>"
                          type: "text"
                  style: "<your_own_value>"
              options: "header-on-first-page"
              page_break_before: "heading1"
              paper: "a4"
          schedule_type: "demand"
          style_theme: "<your_own_value>"
          subtitle: "<your_own_value>"
          time: "<your_own_value>"
          title: "<your_own_value>"
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


def filter_report_layout_data(json):
    option_list = [
        "body_item",
        "cutoff_option",
        "cutoff_time",
        "day",
        "description",
        "email_recipients",
        "email_send",
        "format",
        "max_pdf_report",
        "name",
        "options",
        "page",
        "schedule_type",
        "style_theme",
        "subtitle",
        "time",
        "title",
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
        ["options"],
        ["format"],
        ["page", "column_break_before"],
        ["page", "page_break_before"],
        ["page", "options"],
        ["body_item", "chart_options"],
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


def report_layout(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    report_layout_data = data["report_layout"]

    filtered_data = filter_report_layout_data(report_layout_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("report", "layout", filtered_data, vdom=vdom)
        current_data = fos.get("report", "layout", vdom=vdom, mkey=mkey)
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
    data_copy["report_layout"] = filtered_data
    fos.do_member_operation(
        "report",
        "layout",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("report", "layout", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("report", "layout", mkey=converted_data["name"], vdom=vdom)
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

    if data["report_layout"]:
        resp = report_layout(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("report_layout"))
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
        "title": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "subtitle": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "description": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "style_theme": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "options": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "include-table-of-content"},
                {"value": "auto-numbering-heading"},
                {"value": "view-chart-as-heading"},
                {"value": "show-html-navbar-before-heading"},
                {"value": "dummy-option"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "format": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [{"value": "pdf"}],
            "multiple_values": True,
            "elements": "str",
        },
        "schedule_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "demand"}, {"value": "daily"}, {"value": "weekly"}],
        },
        "day": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "sunday"},
                {"value": "monday"},
                {"value": "tuesday"},
                {"value": "wednesday"},
                {"value": "thursday"},
                {"value": "friday"},
                {"value": "saturday"},
            ],
        },
        "time": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "cutoff_option": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "run-time"}, {"value": "custom"}],
        },
        "cutoff_time": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "email_send": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "email_recipients": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "max_pdf_report": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "page": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "paper": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "a4"}, {"value": "letter"}],
                },
                "column_break_before": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "heading1"},
                        {"value": "heading2"},
                        {"value": "heading3"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "page_break_before": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "heading1"},
                        {"value": "heading2"},
                        {"value": "heading3"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "options": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "header-on-first-page"},
                        {"value": "footer-on-first-page"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "header": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "style": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "header_item": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "id": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "integer",
                                    "required": True,
                                },
                                "description": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                },
                                "type": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                    "options": [{"value": "text"}, {"value": "image"}],
                                },
                                "style": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                },
                                "content": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                },
                                "img_src": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                },
                            },
                            "v_range": [["v6.0.0", ""]],
                        },
                    },
                },
                "footer": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "dict",
                    "children": {
                        "style": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "footer_item": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "id": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "integer",
                                    "required": True,
                                },
                                "description": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                },
                                "type": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                    "options": [{"value": "text"}, {"value": "image"}],
                                },
                                "style": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                },
                                "content": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                },
                                "img_src": {
                                    "v_range": [["v6.0.0", ""]],
                                    "type": "string",
                                },
                            },
                            "v_range": [["v6.0.0", ""]],
                        },
                    },
                },
            },
        },
        "body_item": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "description": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "text"},
                        {"value": "image"},
                        {"value": "chart"},
                        {"value": "misc"},
                    ],
                },
                "style": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "top_n": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "parameters": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "name": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "value": {"v_range": [["v6.0.0", ""]], "type": "string"},
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "text_component": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "text"},
                        {"value": "heading1"},
                        {"value": "heading2"},
                        {"value": "heading3"},
                    ],
                },
                "content": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "img_src": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "chart": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "chart_options": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "include-no-data"},
                        {"value": "hide-title"},
                        {"value": "show-caption"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "misc_component": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "hline"},
                        {"value": "page-break"},
                        {"value": "column-break"},
                        {"value": "section-start"},
                    ],
                },
                "title": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "hide": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "list_component": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                    "options": [{"value": "bullet"}, {"value": "numbered"}],
                },
                "list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.0.0", "v6.4.4"]],
                            "type": "integer",
                            "required": True,
                        },
                        "content": {
                            "v_range": [["v6.0.0", "v6.4.4"]],
                            "type": "string",
                        },
                    },
                    "v_range": [["v6.0.0", "v6.4.4"]],
                },
                "drill_down_items": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                },
                "drill_down_types": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                },
                "table_column_widths": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                },
                "table_caption_style": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                },
                "table_head_style": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                },
                "table_odd_row_style": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                },
                "table_even_row_style": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "string",
                },
                "column": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "integer"},
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
        "report_layout": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["report_layout"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["report_layout"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "report_layout"
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
