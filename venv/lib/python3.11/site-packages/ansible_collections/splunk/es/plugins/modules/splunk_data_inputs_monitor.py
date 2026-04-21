#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2022 Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: splunk_data_inputs_monitor
short_description: Splunk Data Inputs of type Monitor resource module
description:
  - Module to add/modify or delete, File and Directory Monitor Data Inputs in Splunk.
  - Tested against Splunk Enterprise Server 8.2.3
version_added: "2.1.0"
options:
  config:
    description:
      - Configure file and directory monitoring on the system
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The file or directory path to monitor on the system.
        required: true
        type: str
      blacklist:
        description:
          - Specify a regular expression for a file path. The file path that matches this regular expression is not indexed.
        type: str
      check_index:
        description:
          - If set to C(true), the index value is checked to ensure that it is the name of a valid index.
          - This parameter is not returned back by Splunk while obtaining object information.
            It is therefore left out while performing idempotency checks
        type: bool
      check_path:
        description:
          - If set to C(true), the name value is checked to ensure that it exists.
          - This parameter is not returned back by Splunk while obtaining object information.
            It is therefore left out while performing idempotency checks
        type: bool
      crc_salt:
        description:
          - A string that modifies the file tracking identity for files in this input.
            The magic value <SOURCE> invokes special behavior (see admin documentation).
        type: str
      disabled:
        description:
          - Indicates if input monitoring is disabled.
        type: bool
        default: false
      follow_tail:
        description:
          - If set to C(true), files that are seen for the first time is read from the end.
        type: bool
      host:
        description:
          - The value to populate in the host field for events from this data input.
        type: str
        default: "$decideOnStartup"
      host_regex:
        description:
          - Specify a regular expression for a file path. If the path for a file
            matches this regular expression, the captured value is used to populate
            the host field for events from this data input. The regular expression
            must have one capture group.
        type: str
      host_segment:
        description:
          - Use the specified slash-separate segment of the filepath as the host field value.
        type: int
      ignore_older_than:
        description:
          - Specify a time value. If the modification time of a file being monitored
            falls outside of this rolling time window, the file is no longer being monitored.
          - This parameter is not returned back by Splunk while obtaining object information.
            It is therefore left out while performing idempotency checks
        type: str
      index:
        description:
          - Which index events from this input should be stored in. Defaults to default.
        type: str
        default: "default"
      recursive:
        description:
          - Setting this to False prevents monitoring of any subdirectories encountered within this data input.
        type: bool
      rename_source:
        description:
          - The value to populate in the source field for events from this data input.
            The same source should not be used for multiple data inputs.
          - This parameter is not returned back by Splunk while obtaining object information.
            It is therefore left out while performing idempotency checks
        type: str
      sourcetype:
        description:
          - The value to populate in the sourcetype field for incoming events.
        type: str
      time_before_close:
        description:
          - When Splunk software reaches the end of a file that is being read, the
            file is kept open for a minimum of the number of seconds specified in
            this value. After this period has elapsed, the file is checked again for
            more data.
          - This parameter is not returned back by Splunk while obtaining object information.
            It is therefore left out while performing idempotency checks
        type: int
      whitelist:
        description:
          - Specify a regular expression for a file path. Only file paths that match this regular expression are indexed.
        type: str

  running_config:
    description:
    - The module, by default, will connect to the remote device and retrieve the current
      running-config to use as a base for comparing against the contents of source.
      There are times when it is not desirable to have the task get the current running-config
      for every task in a playbook.  The I(running_config) argument allows the implementer
      to pass in the configuration to use as the base config for comparison. This
      value of this option should be the output received from device by executing
      command.
    type: str
  state:
    description:
    - The state the configuration should be left in
    type: str
    choices:
    - merged
    - replaced
    - deleted
    - gathered
    default: merged

author: Ansible Security Automation Team (@pranav-bhatt) <https://github.com/ansible-security>
"""

EXAMPLES = """

# Using gathered
# --------------

- name: Gather config for specified Data inputs monitors
  splunk.es.splunk_data_inputs_monitor:
    config:
      - name: "/var/log"
      - name: "/var"
    state: gathered

# RUN output:
# -----------

# "gathered": [
#     {
#         "blacklist": "//var/log/[a-z0-9]/gm",
#         "crc_salt": "<SOURCE>",
#         "disabled": false,
#         "host": "$decideOnStartup",
#         "host_regex": "/(test_host)/gm",
#         "host_segment": 3,
#         "index": "default",
#         "name": "/var/log",
#         "recursive": true,
#         "sourcetype": "test_source",
#         "whitelist": "//var/log/[0-9]/gm"
#     }
# ]
#

# Using merged
# ------------

- name: Update Data inputs monitors config
  splunk.es.splunk_data_inputs_monitor:
    config:
      - name: "/var/log"
        blacklist: "//var/log/[a-z]/gm"
        check_index: true
        check_path: true
        crc_salt: <SOURCE>
        rename_source: "test"
        whitelist: "//var/log/[0-9]/gm"
    state: merged

# RUN output:
# -----------

# "after": [
#     {
#         "blacklist": "//var/log/[a-z]/gm",
#         "crc_salt": "<SOURCE>",
#         "disabled": false,
#         "host": "$decideOnStartup",
#         "host_regex": "/(test_host)/gm",
#         "host_segment": 3,
#         "index": "default",
#         "name": "/var/log",
#         "recursive": true,
#         "sourcetype": "test_source",
#         "whitelist": "//var/log/[0-9]/gm"
#     }
# ],
# "before": [
#     {
#         "blacklist": "//var/log/[a-z0-9]/gm",
#         "crc_salt": "<SOURCE>",
#         "disabled": false,
#         "host": "$decideOnStartup",
#         "host_regex": "/(test_host)/gm",
#         "host_segment": 3,
#         "index": "default",
#         "name": "/var/log",
#         "recursive": true,
#         "sourcetype": "test_source",
#         "whitelist": "//var/log/[0-9]/gm"
#     }
# ],

# Using replaced
# --------------

- name: To Replace Data inputs monitors config
  splunk.es.splunk_data_inputs_monitor:
    config:
      - name: "/var/log"
        blacklist: "//var/log/[a-z0-9]/gm"
        crc_salt: <SOURCE>
        index: default
    state: replaced

# RUN output:
# -----------

# "after": [
#     {
#         "blacklist": "//var/log/[a-z0-9]/gm",
#         "crc_salt": "<SOURCE>",
#         "disabled": false,
#         "host": "$decideOnStartup",
#         "index": "default",
#         "name": "/var/log"
#     }
# ],
# "before": [
#     {
#         "blacklist": "//var/log/[a-z0-9]/gm",
#         "crc_salt": "<SOURCE>",
#         "disabled": false,
#         "host": "$decideOnStartup",
#         "host_regex": "/(test_host)/gm",
#         "host_segment": 3,
#         "index": "default",
#         "name": "/var/log",
#         "recursive": true,
#         "sourcetype": "test_source",
#         "whitelist": "//var/log/[0-9]/gm"
#     }
# ],

# Using deleted
# -----------
- name: To Delete Data inpur monitor config
  splunk.es.splunk_data_inputs_monitor:
    config:
      - name: "/var/log"
    state: deleted

# RUN output:
# -----------
#
# "after": [],
# "before": [
#     {
#         "blacklist": "//var/log/[a-z0-9]/gm",
#         "crc_salt": "<SOURCE>",
#         "disabled": false,
#         "host": "$decideOnStartup",
#         "index": "default",
#         "name": "/var/log"
#     }
# ],
"""

RETURN = """
before:
  description: The configuration as structured data prior to module invocation.
  returned: always
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
after:
  description: The configuration as structured data after module completion.
  returned: when changed
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
"""
