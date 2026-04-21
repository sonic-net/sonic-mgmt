#!/usr/bin/python
# -*- coding: utf-8 -*-
# https://github.com/ansible/ansible/issues/65816
# https://github.com/PyCQA/pylint/issues/214

# (c) 2018, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: data_input_monitor
short_description: Manage Splunk Data Inputs of type Monitor
description:
  - This module allows for addition or deletion of File and Directory Monitor Data Inputs in Splunk.
version_added: "1.0.0"
deprecated:
  alternative: splunk_data_inputs_monitor
  why: Newer and updated modules released with more functionality.
  removed_at_date: '2024-09-01'
options:
  name:
    description:
     - The file or directory path to monitor on the system.
    required: true
    type: str
  state:
    description:
      - Add or remove a data source.
    required: true
    choices:
      - "present"
      - "absent"
    type: str
  blacklist:
    description:
      - Specify a regular expression for a file path. The file path that matches this regular expression is not indexed.
    required: false
    type: str
  check_index:
    description:
      - If set to C(true), the index value is checked to ensure that it is the name of a valid index.
    required: false
    type: bool
    default: false
  check_path:
    description:
      - If set to C(true), the name value is checked to ensure that it exists.
    required: false
    type: bool
  crc_salt:
    description:
      - A string that modifies the file tracking identity for files in this input.
        The magic value <SOURCE> invokes special behavior (see admin documentation).
    required: false
    type: str
  disabled:
    description:
      - Indicates if input monitoring is disabled.
    required: false
    default: false
    type: bool
  followTail:
    description:
      - If set to C(true), files that are seen for the first time is read from the end.
    required: false
    type: bool
    default: false
  host:
    description:
      - The value to populate in the host field for events from this data input.
    required: false
    type: str
  host_regex:
    description:
      - Specify a regular expression for a file path. If the path for a file
        matches this regular expression, the captured value is used to populate
        the host field for events from this data input. The regular expression
        must have one capture group.
    required: false
    type: str
  host_segment:
    description:
      - Use the specified slash-separate segment of the filepath as the host field value.
    required: false
    type: int
  ignore_older_than:
    description:
      - Specify a time value. If the modification time of a file being monitored
        falls outside of this rolling time window, the file is no longer being monitored.
    required: false
    type: str
  index:
    description:
      - Which index events from this input should be stored in. Defaults to default.
    required: false
    type: str
  recursive:
    description:
      - Setting this to false prevents monitoring of any subdirectories encountered within this data input.
    required: false
    type: bool
    default: false
  rename_source:
    description:
      - The value to populate in the source field for events from this data input.
        The same source should not be used for multiple data inputs.
    required: false
    type: str
  sourcetype:
    description:
      - The value to populate in the sourcetype field for incoming events.
    required: false
    type: str
  time_before_close:
    description:
      - When Splunk software reaches the end of a file that is being read, the
        file is kept open for a minimum of the number of seconds specified in
        this value. After this period has elapsed, the file is checked again for
        more data.
    required: false
    type: int
  whitelist:
    description:
      - Specify a regular expression for a file path. Only file paths that match this regular expression are indexed.
    required: false
    type: str
author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>
"""

EXAMPLES = """
- name: Example adding data input monitor with splunk.es.data_input_monitor
  splunk.es.data_input_monitor:
    name: "/var/log/example.log"
    state: "present"
    recursive: true
"""

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.parse import quote_plus
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.splunk.es.plugins.module_utils.splunk import SplunkRequest


def main():
    argspec = dict(
        name=dict(required=True, type="str"),
        state=dict(choices=["present", "absent"], required=True),
        blacklist=dict(required=False, type="str", default=None),
        check_index=dict(required=False, type="bool", default=False),
        check_path=dict(required=False, type="bool", default=None),
        crc_salt=dict(required=False, type="str", default=None),
        disabled=dict(required=False, type="bool", default=False),
        followTail=dict(required=False, type="bool", default=False),
        host=dict(required=False, type="str", default=None),
        host_segment=dict(required=False, type="int", default=None),
        host_regex=dict(required=False, type="str", default=None),
        ignore_older_than=dict(required=False, type="str", default=None),
        index=dict(required=False, type="str", default=None),
        recursive=dict(required=False, type="bool", default=False),
        rename_source=dict(required=False, type="str", default=None),
        sourcetype=dict(required=False, type="str", default=None),
        time_before_close=dict(required=False, type="int", default=None),
        whitelist=dict(required=False, type="str", default=None),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    # map of keys for the splunk REST API that aren't pythonic so we have to
    # handle the substitutes
    keymap = {
        "check_index": "check-index",
        "check_path": "check-path",
        "crc_salt": "crc-salt",
        "ignore_older_than": "ignore-older-than",
        "rename_source": "rename-source",
        "time_before_close": "time-before-close",
    }

    splunk_request = SplunkRequest(
        module,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        keymap=keymap,
        not_rest_data_keys=["state"],
    )
    # This is where the splunk_* args are processed
    request_data = splunk_request.get_data()

    query_dict = splunk_request.get_by_path(
        "servicesNS/nobody/search/data/inputs/monitor/{0}".format(
            quote_plus(module.params["name"]),
        ),
    )
    query_dict = utils.remove_empties(query_dict)

    if module.params["state"] == "present":
        if query_dict:
            needs_change = False
            for arg in request_data:
                if arg in query_dict["entry"][0]["content"]:
                    if to_text(query_dict["entry"][0]["content"][arg]) != to_text(
                        request_data[arg],
                    ):
                        needs_change = True
            if not needs_change:
                module.exit_json(
                    changed=False,
                    msg="Nothing to do.",
                    splunk_data=query_dict,
                )
            if module.check_mode and needs_change:
                module.exit_json(
                    changed=True,
                    msg="A change would have been made if not in check mode.",
                    splunk_data=query_dict,
                )
            if needs_change:
                splunk_data = splunk_request.create_update(
                    "servicesNS/nobody/search/data/inputs/monitor/{0}".format(
                        quote_plus(module.params["name"]),
                    ),
                )
                module.exit_json(
                    changed=True,
                    msg="{0} updated.",
                    splunk_data=splunk_data,
                )
        else:
            # Create it
            _data = splunk_request.get_data()
            _data["name"] = module.params["name"]
            splunk_data = splunk_request.create_update(
                "servicesNS/nobody/search/data/inputs/monitor",
                data=_data,
            )
            module.exit_json(changed=True, msg="{0} created.", splunk_data=splunk_data)

    if module.params["state"] == "absent":
        if query_dict:
            splunk_data = splunk_request.delete_by_path(
                "servicesNS/nobody/search/data/inputs/monitor/{0}".format(
                    quote_plus(module.params["name"]),
                ),
            )
            module.exit_json(
                changed=True,
                msg="Deleted {0}.".format(module.params["name"]),
                splunk_data=splunk_data,
            )

    module.exit_json(changed=False, msg="Nothing to do.", splunk_data=query_dict)


if __name__ == "__main__":
    main()
