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
module: purefa_messages
version_added: '1.14.0'
short_description: List FlashArray Alert Messages
description:
- List Alert messages based on filters provided
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  severity:
    description:
    - severity of the alerts to show
    type: str
    choices: [ critical, warning, info ]
    default: info
  state:
    description:
    - State of alerts to show
    default: open
    choices: [ open, closed ]
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
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: '1.39.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Show critical alerts from past 4 weeks that haven't been acknowledged
  purefa_messages:
    history: 4w
    flagged: false
    severity: critical
    fa_url: 10.10.10.2
    api_token: 89a9356f-c203-d263-8a89-c229486a13ba
"""

RETURN = r"""
"""

import time

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

MIN_REQUIRED_API_VERSION = "2.2"
ALLOWED_PERIODS = ["h", "d", "w", "y"]
# Time periods in micro-seconds
HOUR = 3600000
DAY = HOUR * 24
WEEK = DAY * 7
YEAR = WEEK * 52
CONTEXT_VERSION = "2.38"


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
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="open", choices=["open", "closed"]),
            history=dict(type="str", default="1w"),
            flagged=dict(type="bool", default=False),
            severity=dict(
                type="str",
                default="info",
                choices=["critical", "warning", "info"],
            ),
            context=dict(type="str", default=""),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    time_now = int(time.time() * 1000)
    array = get_array(module)
    api_version = array.get_rest_version()
    if LooseVersion(MIN_REQUIRED_API_VERSION) > LooseVersion(api_version):
        module.fail_json(
            msg="FlashArray REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )
    if module.params["history"][-1].lower() not in ALLOWED_PERIODS:
        module.fail_json(msg="historical window value is not an allowsd time period")
    since_time = str(time_now - _create_time_window(module.params["history"].lower()))
    if module.params["flagged"]:
        flagged = " and flagged='True'"
    else:
        flagged = " and flagged='False'"

    messages = {}
    severity = " and severity='" + module.params["severity"] + "'"
    state = " and state='" + module.params["state"] + "'"
    filter_string = "notified>" + since_time + state + flagged + severity
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        res = array.get_alerts(
            filter=filter_string, context_names=[module.params["context"]]
        )
    else:
        res = array.get_alerts(filter=filter_string)
    if res.status_code == 200:
        alerts = list(res.items)
    else:
        module.fail_json(
            msg="Failed to get alert messages. Error: {0}".format(res.errors[0].message)
        )
    for message in range(0, len(alerts)):
        name = alerts[message].name
        messages[name] = {
            "summary": alerts[message].summary,
            "component_type": alerts[message].component_type,
            "component_name": alerts[message].component_name,
            "code": alerts[message].code,
            "severity": alerts[message].severity,
            "actual": alerts[message].actual,
            "issue": alerts[message].issue,
            "state": alerts[message].state,
            "flagged": alerts[message].flagged,
            "closed": None,
            "created": time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.gmtime(alerts[message].created / 1000),
            )
            + " UTC",
            "updated": time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.gmtime(alerts[message].updated / 1000),
            )
            + " UTC",
        }
        if alerts[message].state == "closed":
            messages[name]["closed"] = (
                time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.gmtime(alerts[message].closed / 1000)
                )
                + " UTC"
            )
    module.exit_json(changed=False, purefa_messages=messages)


if __name__ == "__main__":
    main()
