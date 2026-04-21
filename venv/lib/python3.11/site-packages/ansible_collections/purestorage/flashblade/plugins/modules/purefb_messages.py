#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefb_messages
version_added: '1.10.0'
short_description: List FlashBlade Alert Messages
description:
- List Alert messages based on filters provided
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  severity:
    description:
    - severity of the alerts to show
    type: list
    elements: str
    choices: [ all, critical, warning, info ]
    default: [ all ]
  state:
    description:
    - State of alerts to show
    default: open
    choices: [ all, open, closed ]
    type: str
  flagged:
    description:
    - Show alerts that have been acknowledged or not
    default: false
    type: bool
  history:
    description:
    - Historical time period to show alerts for, from present time
    - Allowed time period are hour(h), day(d), week(w) and year(y)
    type: str
    default: 1w
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Show critical alerts from past 4 weeks that haven't been acknowledged
  purefb_messages:
    history: 4w
    flagged: false
    severity:
    - critical
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
"""

RETURN = r"""
"""

import time

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

ALLOWED_PERIODS = ["h", "d", "w", "y"]
# Time periods in micro-seconds
HOUR = 3600000
DAY = HOUR * 24
WEEK = DAY * 7
YEAR = WEEK * 52


def _create_time_window(window):
    period = window[-1].lower()
    multiple = int(window[0:-1])
    if period == "h":
        return HOUR * multiple
    if period == "d":
        return DAY * multiple
    if period == "w":
        return WEEK * multiple
    if period == "y":
        return YEAR * multiple
    return None


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="open", choices=["all", "open", "closed"]),
            history=dict(type="str", default="1w"),
            flagged=dict(type="bool", default=False),
            severity=dict(
                type="list",
                elements="str",
                default=["all"],
                choices=["all", "critical", "warning", "info"],
            ),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    time_now = int(time.time() * 1000)
    blade = get_system(module)

    if module.params["history"][-1].lower() not in ALLOWED_PERIODS:
        module.fail_json(msg="historical window value is not an allowsd time period")
    since_time = str(time_now - _create_time_window(module.params["history"].lower()))
    if module.params["flagged"]:
        flagged = " and flagged='True'"
    else:
        flagged = " and flagged='False'"

    multi_sev = False
    if len(module.params["severity"]) > 1:
        if "all" in module.params["severity"]:
            module.params["severity"] = ["*"]
        else:
            multi_sev = True
    if multi_sev:
        severity = " and ("
        for level in range(len(module.params["severity"])):
            severity += "severity='" + str(module.params["severity"][level]) + "' or "
        severity = severity[0:-4] + ")"
    else:
        if module.params["severity"] == ["all"]:
            severity = " and severity='*'"
        else:
            severity = " and severity='" + str(module.params["severity"][0]) + "'"
    messages = {}
    if module.params["state"] == "all":
        state = " and state='*'"
    else:
        state = " and state='" + module.params["state"] + "'"
    filter_string = "notified>" + since_time + state + flagged + severity
    res = blade.get_alerts(filter=filter_string)
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to get alert messages. Error: {0}".format(res.errors[0].message)
        )
    alerts = list(res.items)
    for message in range(len(alerts)):
        name = alerts[message].name
        messages[name] = {
            "summary": alerts[message].summary,
            "component_type": alerts[message].component_type,
            "component_name": alerts[message].component_name,
            "description": alerts[message].description,
            "code": alerts[message].code,
            "severity": alerts[message].severity,
            "state": alerts[message].state,
            "flagged": alerts[message].flagged,
            "created": time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.gmtime(alerts[message].created / 1000),
            )
            + " UTC",
            "notified": time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.gmtime(alerts[message].notified / 1000),
            )
            + " UTC",
            "updated": time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.gmtime(alerts[message].updated / 1000),
            )
            + " UTC",
        }
    module.exit_json(changed=False, purefb_messages=messages)


if __name__ == "__main__":
    main()
