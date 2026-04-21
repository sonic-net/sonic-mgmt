#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["deprecated"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefa_logging
version_added: '1.19.0'
short_description: Manage Pure Storage FlashArray Audit and Session logs
description:
- view the FlashArray audit trail oe session logs, newest to oldest based on (start) time
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  log_type:
    description:
    - The type of logs to be viewed
    type: str
    default: audit
    choices: [audit, session]
  limit:
    description:
    - The maximum number of audit events returned
    default: 1000
    type: int
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: List last 100 audit events
  purestorage.flasharray.purefa_logging:
    limit: 100
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: List last 24 session events
  purestorage.flasharray.purefa_logging:
    limit: 24
    log_type: session
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
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

AUDIT_API_VERSION = "2.2"


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            limit=dict(type="int", default=1000),
            log_type=dict(type="str", default="audit", choices=["audit", "session"]),
        )
    )
    module = AnsibleModule(argument_spec, supports_check_mode=True)

    array = get_array(module)
    api_version = array.get_rest_version()
    audits = []
    changed = False
    if LooseVersion(AUDIT_API_VERSION) <= LooseVersion(api_version):
        changed = True
        if not module.check_mode:
            if module.params["log_type"] == "audit":
                all_audits = list(
                    array.get_audits(
                        limit=module.params["limit"],
                        sort=["time-"],
                    ).items
                )
            else:
                all_audits = list(
                    array.get_sessions(
                        limit=module.params["limit"],
                        sort=["start_time-"],
                    ).items
                )
            for audit in range(0, len(all_audits)):
                if module.params["log_type"] == "session":
                    start_time = getattr(all_audits[audit], "start_time", None)
                    end_time = getattr(all_audits[audit], "end_time", None)
                    if start_time:
                        human_start_time = time.strftime(
                            "%Y-%m-%d %H:%M:%S", time.localtime(start_time / 1000)
                        )
                    else:
                        human_start_time = None
                    if end_time:
                        human_end_time = time.strftime(
                            "%Y-%m-%d %H:%M:%S", time.localtime(end_time / 1000)
                        )
                    else:
                        human_end_time = None

                    data = {
                        "start_time": human_start_time,
                        "end_time": human_end_time,
                        "location": getattr(all_audits[audit], "location", None),
                        "user": getattr(all_audits[audit], "user", None),
                        "event": all_audits[audit].event,
                        "event_count": getattr(all_audits[audit], "event_count", None),
                        "user_interface": getattr(
                            all_audits[audit], "user_interface", None
                        ),
                    }
                else:
                    event_time = getattr(all_audits[audit], "time", None)
                    if event_time:
                        human_event_time = time.strftime(
                            "%Y-%m-%d %H:%M:%S", time.localtime(event_time / 1000)
                        )
                    else:
                        human_event_time = None
                    data = {
                        "time": human_event_time,
                        "arguments": all_audits[audit].arguments,
                        "command": all_audits[audit].command,
                        "subcommand": all_audits[audit].subcommand,
                        "user": all_audits[audit].user,
                        "origin": getattr(all_audits[audit].origin, "name", None),
                    }
                audits.append(data)
    else:
        module.fail_json(msg="Purity version does not support audit log return")
    if module.params["log_type"] == "audit":
        module.exit_json(changed=changed, audits=audits)
    else:
        module.exit_json(changed=changed, sessions=audits)


if __name__ == "__main__":
    main()
