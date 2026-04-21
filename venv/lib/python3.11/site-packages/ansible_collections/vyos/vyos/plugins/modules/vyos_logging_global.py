#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for vyos_logging_global
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: vyos_logging_global
version_added: 2.4.0
short_description: Logging resource module
description: This module manages the logging attributes of Vyos network devices
author: Sagar Paul (@KB-perByte)
notes:
  - Tested against VyOS 1.3.8, 1.4.2, the upcoming 1.5, and the rolling release of spring 2025
  - This module works with connection C(network_cli).
  - The Configuration defaults of the Vyos network devices
    are supposed to hinder idempotent behavior of plays
options:
  config:
    description: A list containing dictionary of logging options
    type: dict
    suboptions:
      console:
        description: logging to serial console
        type: dict
        suboptions:
          state: &state_config
            description: enable or disable the command
            type: str
            choices:
              - enabled
              - disabled
          facilities:
            description: facility configurations for console
            type: list
            elements: dict
            suboptions:
              facility: &facility
                description: Facility for logging
                type: str
                choices:
                  - all
                  - auth
                  - authpriv
                  - cron
                  - daemon
                  - kern
                  - lpr
                  - mail
                  - mark
                  - news
                  - protocols
                  - security
                  - syslog
                  - user
                  - uucp
                  - local0
                  - local1
                  - local2
                  - local3
                  - local4
                  - local5
                  - local6
                  - local7
              severity: &severity
                description: logging level
                type: str
                choices:
                  - emerg
                  - alert
                  - crit
                  - err
                  - warning
                  - notice
                  - info
                  - debug
                  - all
      files:
        description: logging to file
        type: list
        elements: dict
        suboptions:
          path:
            description: file name or path
            type: str
          archive: &archive
            description: Log file size and rotation characteristics
            type: dict
            suboptions:
              state: *state_config
              file_num:
                description: Number of saved files (default is 5)
                type: int
              size:
                description: Size of log files (in kilobytes, default is 256)
                type: int
          facilities: &params
            description: facility configurations
            type: list
            elements: dict
            suboptions:
              facility: *facility
              severity: *severity
      global_params:
        description: logging to serial console
        type: dict
        suboptions:
          state: *state_config
          archive: *archive
          facilities: *params
          marker_interval:
            description: time interval how often a mark message is being sent in seconds (default is 1200)
            type: int
          preserve_fqdn:
            description: uses FQDN for logging
            type: bool
      hosts:
        description: logging to serial console
        type: list
        elements: dict
        suboptions:
          port:
            description: Destination port (1-65535)
            type: int
          facilities:
            description: facility configurations for host
            type: list
            elements: dict
            suboptions:
              facility: *facility
              severity: *severity
              protocol:
                description: syslog communication protocol. Version 1.3 and below.
                type: str
                choices:
                  - udp
                  - tcp
          hostname:
            description: Remote host name or IP address
            type: str
          protocol:
            description: syslog communication protocol. Version 1.4+
            type: str
            choices:
              - udp
              - tcp
      syslog:
        description: logging syslog
        type: dict
        suboptions:
          state: *state_config
      users:
        description: logging to file
        type: list
        elements: dict
        suboptions:
          username:
            description: user login name
            type: str
          facilities: *params
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the VYOS device by
        executing the command B(show configuration commands | grep syslog).
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
    type: str
  state:
    choices:
      - merged
      - replaced
      - overridden
      - deleted
      - gathered
      - parsed
      - rendered
    default: merged
    description:
      - The state the configuration should be left in
      - The states I(replaced) and I(overridden) have identical
        behaviour for this module.
      - Refer to examples for more details.
    type: str
"""

EXAMPLES = """
# Using state: merged

# Before state:
# -------------

# vyos:~$show configuration commands | grep syslog

- name: Apply the provided configuration
  vyos.vyos.vyos_logging_global:
    config:
      console:
        facilities:
          - facility: local7
            severity: err
      files:
        - path: logFile
          archive:
            file_num: 2
          facilities:
            - facility: local6
              severity: emerg
      hosts:
        - hostname: 172.16.0.1
          facilities:
            - facility: local7
              severity: all
            - facility: all
              protocol: udp
          port: 223
      users:
        - username: vyos
          facilities:
            - facility: local7
              severity: debug
      global_params:
        archive:
          file_num: 2
          size: 111
        facilities:
          - facility: cron
            severity: debug
        marker_interval: 111
        preserve_fqdn: true
    state: merged

# Commands Fired:
# ---------------

# "commands": [
#     "set system syslog console facility local7 level err",
#     "set system syslog file logFile archive file 2",
#     "set system syslog host 172.16.0.1 facility local7 level all",
#     "set system syslog file logFile facility local6 level emerg",
#     "set system syslog host 172.16.0.1 facility all protocol udp",
#     "set system syslog user vyos facility local7 level debug",
#     "set system syslog host 172.16.0.1 port 223",
#     "set system syslog global facility cron level debug",
#     "set system syslog global archive file 2",
#     "set system syslog global archive size 111",
#     "set system syslog global marker interval 111",
#     "set system syslog global preserve-fqdn"
# ],

# After state:
# ------------

# vyos:~$ show configuration commands | grep syslog
# set system syslog console facility local7 level 'err'
# set system syslog file logFile archive file '2'
# set system syslog file logFile facility local6 level 'emerg'
# set system syslog global archive file '2'
# set system syslog global archive size '111'
# set system syslog global facility cron level 'debug'
# set system syslog global marker interval '111'
# set system syslog global preserve-fqdn
# set system syslog host 172.16.0.1 facility all protocol 'udp'
# set system syslog host 172.16.0.1 facility local7 level 'all'
# set system syslog host 172.16.0.1 port '223'
# set system syslog user vyos facility local7 level 'debug'

# Using state: deleted

# Before state:
# -------------

# vyos:~$show configuration commands | grep syslog
# set system syslog console facility local7 level 'err'
# set system syslog file logFile archive file '2'
# set system syslog file logFile facility local6 level 'emerg'
# set system syslog global archive file '2'
# set system syslog global archive size '111'
# set system syslog global facility cron level 'debug'
# set system syslog global marker interval '111'
# set system syslog global preserve-fqdn
# set system syslog host 172.16.0.1 facility all protocol 'udp'
# set system syslog host 172.16.0.1 facility local7 level 'all'
# set system syslog host 172.16.0.1 port '223'
# set system syslog user vyos facility local7 level 'debug'

- name: delete the existing configuration
  vyos.vyos.vyos_logging_global:
    state: deleted

# Commands Fired:
# ---------------

# "commands": [
#     "delete system syslog"
# ],

# After state:
# ------------

# vyos:~$show configuration commands | grep syslog

# Using state: overridden

# Before state:
# -------------

# vyos:~$show configuration commands | grep syslog
# set system syslog console facility local7 level 'err'
# set system syslog file logFile archive file '2'
# set system syslog file logFile facility local6 level 'emerg'
# set system syslog global archive file '2'
# set system syslog global archive size '111'
# set system syslog global facility cron level 'debug'
# set system syslog global marker interval '111'
# set system syslog global preserve-fqdn
# set system syslog host 172.16.0.1 facility all protocol 'udp'
# set system syslog host 172.16.0.1 facility local7 level 'all'
# set system syslog host 172.16.0.1 port '223'
# set system syslog user vyos facility local7 level 'debug'

- name: Override the current configuration
  vyos.vyos.vyos_logging_global:
    config:
      console:
        facilities:
          - facility: all
          - facility: local7
            severity: err
          - facility: news
            severity: debug
      files:
        - path: logFileNew
      hosts:
        - hostname: 172.16.0.2
          facilities:
            - facility: local5
              severity: all
      global_params:
        archive:
          file_num: 10
    state: overridden

# Commands Fired:
# ---------------

# "commands": [
#     "delete system syslog file logFile",
#     "delete system syslog global facility cron",
#     "delete system syslog host 172.16.0.1",
#     "delete system syslog user vyos",
#     "set system syslog console facility all",
#     "set system syslog console facility news level debug",
#     "set system syslog file logFileNew",
#     "set system syslog host 172.16.0.2 facility local5 level all",
#     "set system syslog global archive file 10",
#     "delete system syslog global archive size 111",
#     "delete system syslog global marker",
#     "delete system syslog global preserve-fqdn"
# ],

# After state:
# ------------

# vyos:~$show configuration commands | grep syslog
# set system syslog console facility all
# set system syslog console facility local7 level 'err'
# set system syslog console facility news level 'debug'
# set system syslog file logFileNew
# set system syslog global archive file '10'
# set system syslog host 172.16.0.2 facility local5 level 'all'

# Using state: replaced

# Before state:
# -------------

# vyos:~$show configuration commands | grep syslog
# set system syslog console facility all
# set system syslog console facility local7 level 'err'
# set system syslog console facility news level 'debug'
# set system syslog file logFileNew
# set system syslog global archive file '10'
# set system syslog host 172.16.0.2 facility local5 level 'all'

- name: Replace with the provided configuration
  register: result
  vyos.vyos.vyos_logging_global:
    config:
      console:
        facilities:
          - facility: local6
      users:
        - username: paul
          facilities:
            - facility: local7
              severity: err
    state: replaced


# Commands Fired:
# ---------------

# "commands": [
#     "delete system syslog console facility all",
#     "delete system syslog console facility local7",
#     "delete system syslog console facility news",
#     "delete system syslog file logFileNew",
#     "delete system syslog global archive file 10",
#     "delete system syslog host 172.16.0.2",
#     "set system syslog console facility local6",
#     "set system syslog user paul facility local7 level err"
# ],

# After state:
# ------------

# vyos:~$show configuration commands | grep syslog
# set system syslog console facility local6
# set system syslog user paul facility local7 level 'err'

# Using state: gathered

- name: Gather logging config
  vyos.vyos.vyos_logging_global:
    state: gathered

# Module Execution Result:
# ------------------------

# "gathered": {
#     "console": {
#         "facilities": [
#             {
#                 "facility": "local6"
#             },
#             {
#                 "facility": "local7",
#                 "severity": "err"
#             }
#         ]
#     },
#     "files": [
#         {
#             "archive": {
#                 "file_num": 2
#             },
#             "facilities": [
#                 {
#                     "facility": "local6",
#                     "severity": "emerg"
#                 }
#             ],
#             "path": "logFile"
#         }
#     ],
#     "global_params": {
#         "archive": {
#             "file_num": 2,
#             "size": 111
#         },
#         "facilities": [
#             {
#                 "facility": "cron",
#                 "severity": "debug"
#             }
#         ],
#         "marker_interval": 111,
#         "preserve_fqdn": true
#     },
#     "hosts": [
#         {
#             "facilities": [
#                 {
#                     "facility": "all",
#                     "protocol": "udp"
#                 },
#                 {
#                     "facility": "local7",
#                     "severity": "all"
#                 }
#             ],
#             "hostname": "172.16.0.1",
#             "port": 223
#         }
#     ],
#     "users": [
#         {
#             "facilities": [
#                 {
#                     "facility": "local7",
#                     "severity": "err"
#                 }
#             ],
#             "username": "paul"
#         },
#         {
#             "facilities": [
#                 {
#                     "facility": "local7",
#                     "severity": "debug"
#                 }
#             ],
#             "username": "vyos"
#         }
#     ]
# },

# After state:
# ------------

# vyos:~$show configuration commands | grep syslog
# set system syslog console facility local6
# set system syslog console facility local7 level 'err'
# set system syslog file logFile archive file '2'
# set system syslog file logFile facility local6 level 'emerg'
# set system syslog global archive file '2'
# set system syslog global archive size '111'
# set system syslog global facility cron level 'debug'
# set system syslog global marker interval '111'
# set system syslog global preserve-fqdn
# set system syslog host 172.16.0.1 facility all protocol 'udp'
# set system syslog host 172.16.0.1 facility local7 level 'all'
# set system syslog host 172.16.0.1 port '223'
# set system syslog user paul facility local7 level 'err'
# set system syslog user vyos facility local7 level 'debug'

# Using state: rendered

- name: Render the provided configuration
  vyos.vyos.vyos_logging_global:
    config:
      console:
        facilities:
          - facility: local7
            severity: err
      files:
        - path: logFile
          archive:
            file_num: 2
          facilities:
            - facility: local6
              severity: emerg
      hosts:
        - hostname: 172.16.0.1
          facilities:
            - facility: local7
              severity: all
            - facility: all
              protocol: udp
          port: 223
      users:
        - username: vyos
          facilities:
            - facility: local7
              severity: debug
      global_params:
        archive:
          file_num: 2
          size: 111
        facilities:
          - facility: cron
            severity: debug
        marker_interval: 111
        preserve_fqdn: true
    state: rendered

# Module Execution Result:
# ------------------------

# "rendered": [
#     "set system syslog console facility local7 level err",
#     "set system syslog file logFile facility local6 level emerg",
#     "set system syslog file logFile archive file 2",
#     "set system syslog host 172.16.0.1 facility local7 level all",
#     "set system syslog host 172.16.0.1 facility all protocol udp",
#     "set system syslog host 172.16.0.1 port 223",
#     "set system syslog user vyos facility local7 level debug",
#     "set system syslog global facility cron level debug",
#     "set system syslog global archive file 2",
#     "set system syslog global archive size 111",
#     "set system syslog global marker interval 111",
#     "set system syslog global preserve-fqdn"
# ]

# Using state: parsed

# File: parsed.cfg
# ----------------

# set system syslog console facility local6
# set system syslog console facility local7 level 'err'
# set system syslog file logFile archive file '2'
# set system syslog file logFile facility local6 level 'emerg'
# set system syslog global archive file '2'
# set system syslog global archive size '111'
# set system syslog global facility cron level 'debug'
# set system syslog global marker interval '111'
# set system syslog global preserve-fqdn
# set system syslog host 172.16.0.1 facility all protocol 'udp'
# set system syslog host 172.16.0.1 facility local7 level 'all'
# set system syslog host 172.16.0.1 port '223'
# set system syslog user paul facility local7 level 'err'
# set system syslog user vyos facility local7 level 'debug'

- name: Parse the provided configuration
  vyos.vyos.vyos_logging_global:
    running_config: "{{ lookup('file', 'parsed_vyos.cfg') }}"
    state: parsed

# Module Execution Result:
# ------------------------

# "parsed": {
#     "console": {
#         "facilities": [
#             {
#                 "facility": "local6"
#             },
#             {
#                 "facility": "local7",
#                 "severity": "err"
#             }
#         ]
#     },
#     "files": [
#         {
#             "archive": {
#                 "file_num": 2
#             },
#             "facilities": [
#                 {
#                     "facility": "local6",
#                     "severity": "emerg"
#                 }
#             ],
#             "path": "logFile"
#         }
#     ],
#     "global_params": {
#         "archive": {
#             "file_num": 2,
#             "size": 111
#         },
#         "facilities": [
#             {
#                 "facility": "cron",
#                 "severity": "debug"
#             }
#         ],
#         "marker_interval": 111,
#         "preserve_fqdn": true
#     },
#     "hosts": [
#         {
#             "facilities": [
#                 {
#                     "facility": "all",
#                     "protocol": "udp"
#                 },
#                 {
#                     "facility": "local7",
#                     "severity": "all"
#                 }
#             ],
#             "hostname": "172.16.0.1",
#             "port": 223
#         }
#     ],
#     "users": [
#         {
#             "facilities": [
#                 {
#                     "facility": "local7",
#                     "severity": "err"
#                 }
#             ],
#             "username": "paul"
#         },
#         {
#             "facilities": [
#                 {
#                     "facility": "local7",
#                     "severity": "debug"
#                 }
#             ],
#             "username": "vyos"
#         }
#     ]
#   }
# }
"""

RETURN = """
before:
  description: The configuration prior to the module execution.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
after:
  description: The resulting configuration after module execution.
  returned: when changed
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
commands:
  description: The set of commands pushed to the remote device.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: list
  sample:
    - set system syslog console facility local7 level err
    - set system syslog host 172.16.0.1 port 223
    - set system syslog global archive size 111
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - set system syslog host 172.16.0.1 port 223
    - set system syslog user vyos facility local7 level debug
    - set system syslog global facility cron level debu
gathered:
  description: Facts about the network resource gathered from the remote device as structured data.
  returned: when I(state) is C(gathered)
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
parsed:
  description: The device native config provided in I(running_config) option parsed into structured data as per module argspec.
  returned: when I(state) is C(parsed)
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.logging_global.logging_global import (
    Logging_globalArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.config.logging_global.logging_global import (
    Logging_global,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Logging_globalArgs.argument_spec,
        mutually_exclusive=[["config", "running_config"]],
        required_if=[
            ["state", "merged", ["config"]],
            ["state", "replaced", ["config"]],
            ["state", "overridden", ["config"]],
            ["state", "rendered", ["config"]],
            ["state", "parsed", ["running_config"]],
        ],
        supports_check_mode=True,
    )

    result = Logging_global(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
