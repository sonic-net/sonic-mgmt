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
module: purefa_audits
version_added: '1.29.0'
short_description: List FlashArray Audit Events
description:
- List audit events based on filters provided
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  start:
    description:
    - Start date and time (based on array local time)
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
- name: Show all audit events that started after the specified date/time and TZ
  purefa_audits:
    start: "2024-06-29 12:31:34"
    timezone: "America/New_York"
    fa_url: 10.10.10.2
    api_token: 89a9356f-c203-d263-8a89-c229486a13ba

- name: Show all audit events that have been logged by the array (to the internal limit of the array)
  purefa_audits:
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
CONTEXT_VERSION = "2.38"


def _get_filter_string(module, timezone):
    filter_string = ""
    if module.params["start"] and module.params["start"] != "0":
        start = module.params["start"] + " " + timezone
        start_timestamp = int(
            1000
            * datetime.datetime.timestamp(
                datetime.datetime.strptime(start, "%Y-%m-%d %H:%M:%S %z")
            )
        )
    else:
        start_timestamp = 0
    filter_string = "time>=" + str(start_timestamp)
    return filter_string


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            start=dict(type="str"),
            timezone=dict(type="str"),
            context=dict(type="str", default=""),
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
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            timezone = list(
                array.get_arrays(context_names=[module.params["context"]]).items
            )[0].time_zone
        else:
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
    audit_log = {}
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        if filter_string:
            res = array.get_audits(
                context_names=[module.params["context"]], filter=filter_string
            )
        else:
            res = array.get_audits(context_names=[module.params["context"]])
    else:
        if filter_string:
            res = array.get_audits(
                context_names=[module.params["context"]], filter=filter_string
            )
        else:
            res = array.get_audits(context_names=[module.params["context"]])
    if res.status_code == 200:
        audits = list(res.items)
    else:
        module.fail_json(
            msg="Failed to get audit events. Error: {0}".format(res.errors[0].message)
        )
    for audit in range(0, len(audits)):
        name = audits[audit].name
        time = datetime.datetime.fromtimestamp(
            audits[audit].time / 1000, tz=pytz.timezone(timezone)
        ).strftime("%Y-%m-%d %H:%M:%S %Z")
        audit_log[name] = {
            "time": time,
            "arguments": audits[audit].arguments,
            "user": audits[audit].user,
            "command": audits[audit].command,
            "subcommand": audits[audit].subcommand,
            "origin": audits[audit].origin.name,
        }
    module.exit_json(changed=False, purefa_audits=audit_log)


if __name__ == "__main__":
    main()
