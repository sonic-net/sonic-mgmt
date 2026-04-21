#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2024, Simon Dodsley (simon@purestorage.com)
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
module: purefa_sessions
version_added: '1.29.0'
short_description: List FlashArray Sessions
description:
- List sessions based on filters provided
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  start:
    description:
    - Start date and time (based on array local time)
    - If not provided epoch is assumed
    - Expected format "YYYY-MM-DD hh:mm:ss"
    type: str
  end:
    description:
    - End date and time (based on array local time)
    - If not provided epoch is assumed
    - Expected format "YYYY-MM-DD hh:mm:ss"
    type: str
  timezone:
    description:
    - The timezone of the FlashArray
    - If not provided, the module will attempt to get the current local timezone
      from the server however from Purity//FA 6.5.3 this value will calculated
      automatically from the FlashArray
    type: str
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Show all sessions that started after the specified date/time
  purefa_sessions:
    start: "2024-06-29 12:31:34"
    fa_url: 10.10.10.2
    api_token: 89a9356f-c203-d263-8a89-c229486a13ba

- name: Show all sessions that started and ended between specified dates/times
  purefa_sessions:
    start: "2024-06-29 12:31:34"
    end: "2024-06-30 04:23:34"
    fa_url: 10.10.10.2
    api_token: 89a9356f-c203-d263-8a89-c229486a13ba

- name: Show all sessions that ended after the specified date/time
  purefa_sessions:
    end: "2024-06-30 04:23:34"
    fa_url: 10.10.10.2
    api_token: 89a9356f-c203-d263-8a89-c229486a13ba

- name: Show all sessions that have been logged by the array (to the internal limit of the array)
  purefa_sessions:
    fa_url: 10.10.10.2
    api_token: 89a9356f-c203-d263-8a89-c229486a13ba
"""

RETURN = r"""
"""

HAS_PYTZ = True
try:
    import pytz
except ImportError:
    HAS_PYTX = False

import datetime
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.common import (
    get_local_tz,
)

TZ_VERSION = "2.26"


def _get_filter_string(module, timezone):
    filter_string = ""
    if module.params["end"]:
        if module.params["end"] != "0":
            end = module.params["end"] + " " + timezone
            end_timestamp = int(
                1000
                * datetime.datetime.timestamp(
                    datetime.datetime.strptime(end, "%Y-%m-%d %H:%M:%S %z")
                )
            )
        else:
            end_timestamp = 0
    if module.params["start"]:
        if module.params["start"] != "0":
            start = module.params["start"] + " " + timezone
            start_timestamp = int(
                1000
                * datetime.datetime.timestamp(
                    datetime.datetime.strptime(start, "%Y-%m-%d %H:%M:%S %z")
                )
            )
        else:
            start_timestamp = 0
    if module.params["end"] and module.params["start"]:
        filter_string = (
            "start_time>="
            + str(start_timestamp)
            + " and end_time<="
            + str(end_timestamp)
        )
    elif module.params["end"] and not module.params["start"]:
        filter_string = "end_time<=" + str(end_timestamp)
    elif module.params["start"] and not module.params["end"]:
        filter_string = "start_time>=" + str(start_timestamp)
    return filter_string


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            start=dict(type="str"),
            end=dict(type="str"),
            timezone=dict(type="str"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PYTZ:
        module.fail_json(msg="pytz is required for this module")

    array = get_array(module)
    api_version = array.get_rest_version()
    if not module.params["timezone"] and LooseVersion(TZ_VERSION) <= LooseVersion(
        api_version
    ):
        timezone = list(array.get_arrays().items)[0].time_zone
    elif not module.params["timezone"]:
        timezone = get_local_tz(module)
    elif module.params["timezone"] not in pytz.all_timezones_set:
        module.fail_json(
            msg="Timezone {0} is not valid".format(module.params["timezone"])
        )
    else:
        timezone = module.params["timezone"]
    tzoffset = datetime.datetime.now(pytz.timezone(timezone)).strftime("%z")
    filter_string = _get_filter_string(module, tzoffset)
    session_log = {}
    if filter_string:
        res = array.get_sessions(filter=filter_string)
    else:
        res = array.get_sessions()
    if res.status_code == 200:
        sessions = list(res.items)
    else:
        module.fail_json(
            msg="Failed to get sessions. Error: {0}".format(res.errors[0].message)
        )
    for session in range(0, len(sessions)):
        name = sessions[session].name
        if hasattr(sessions[session], "start_time"):
            start_time = datetime.datetime.fromtimestamp(
                sessions[session].start_time / 1000, tz=pytz.timezone(timezone)
            ).strftime("%Y-%m-%d %H:%M:%S %Z")
        else:
            start_time = "-"
        if hasattr(sessions[session], "end_time"):
            end_time = datetime.datetime.fromtimestamp(
                sessions[session].end_time / 1000, tz=pytz.timezone(timezone)
            ).strftime("%Y-%m-%d %H:%M:%S %Z")
        else:
            end_time = "-"
        session_log[name] = {
            "start_time": start_time,
            "end_time": end_time,
            "interface": sessions[session].user_interface,
            "user": getattr(sessions[session], "user", ""),
            "location": sessions[session].location,
            "repeat": getattr(sessions[session], "event_count", ""),
            "event": sessions[session].event,
            "method": getattr(sessions[session], "method", ""),
        }
    module.exit_json(changed=False, purefa_sessions=session_log)


if __name__ == "__main__":
    main()
