#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for eos_logging_global
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: eos_logging_global
short_description: Manages logging resource module
description: This module configures and manages the attributes of  logging on Arista
  EOS platforms.
version_added: 3.0.0
author: Gomathi Selvi Srinivasan (@GomathiselviS)
notes:
- Tested against Arista EOS 4.24.6M
- This module works with connection C(network_cli). See the L(EOS Platform Options,eos_platform_options).
options:
   config:
      description: A dictionary of logging options
      type: dict
      suboptions:
        buffered:
          description:
          - Set buffered logging parameters.
          type: dict
          suboptions: &message_options
              severity: &sev
                description: Severity level .
                type: str
                choices:
                - emergencies
                - alerts
                - critical
                - errors
                - warnings
                - notifications
                - informational
                - debugging
              buffer_size:
                description: Logging buffer size
                type: int
        console:
          description:
          - Set console logging parameters.
          type: dict
          suboptions:
              severity: *sev
        event:
          description: Global events
          type: str
          choices: ["link-status", "port-channel", "spanning-tree"]
        facility:
          description: Set logging facility.
          type: str
          "choices": [
                        "auth",
                        "cron",
                        "daemon",
                        "kern",
                        "local0",
                        "local1",
                        "local2",
                        "local3",
                        "local4",
                        "local5",
                        "local6",
                        "local7",
                        "lpr",
                        "mail",
                        "news",
                        "sys10",
                        "sys11",
                        "sys12",
                        "sys13",
                        "sys14",
                        "sys9",
                        "syslog",
                        "user",
                        "uucp",
                    ]
        format:
          description: Set logging format parameters
          type: dict
          suboptions:
            hostname:
              description: Specify hostname logging format.
              type: str
            timestamp:
              description: Set timestamp logging parameters.
              type: dict
              suboptions:
                high_resolution:
                  description: RFC3339 timestamps.
                  type: bool
                traditional:
                  description: Traditional syslog timestamp format as specified in RFC3164.
                  type: dict
                  suboptions:
                    state:
                      description: When enabled traditional timestamp format is set.
                      type: str
                      choices: ["enabled", "disabled"]
                    timezone:
                      description: Show timezone in traditional format timestamp
                      type: bool
                    year:
                      description: Show year in traditional format timestamp
                      type: bool
            sequence_numbers:
              description:  No. of log messages.
              type: bool
        hosts: &host
          description: Set syslog server IP address and parameters.
          type: list
          elements: dict
          suboptions:
            name:
              description: Hostname or IP address of the syslog server.
              type: str
            add:
              description: Configure ports on the given host.
              type: bool
            remove:
              description: Remove configured ports from the given host
              type: bool
            protocol:
              description: Set syslog server transport protocol
              type: str
              choices: ["tcp", "udp"]
            port:
              description: Port of the syslog server.
              type: int
              default: 514
        level:
          description: Configure logging severity
          type: dict
          suboptions:
            facility:
              description: Facility level
              type: str
            severity: *sev
        monitor:
          description: Set terminal monitor severity
          type: str
        turn_on:
          description: Turn on logging.
          type: bool
        persistent:
          description: Save logging messages to the flash disk.
          type: dict
          suboptions:
            set:
              description: Save logging messages to the flash dis.
              type: bool
            size:
              description: The maximum size (in bytes) of logging file stored on flash disk.
              type: int
        policy:
          description: Configure logging policies.
          type: dict
          suboptions:
            invert_result:
              description: Invert the match of match-list.
              type: bool
            match_list:
              description: Configure logging message filtering.
              type: str
        qos:
          description: Set DSCP value in IP header.
          type: int
        relogging_interval:
          description: Configure relogging-interval for critical log messages
          type: int
        repeat_messages:
          description: Repeat messages instead of summarizing number of repeats
          type: bool
        source_interface: &srcint
          description: Use IP Address of interface as source IP of log messages.
          type: str
        synchronous:
          description: Set synchronizing unsolicited with solicited messages
          type: dict
          suboptions:
            set:
              description: Set synchronizing unsolicited with solicited messages.
              type: bool
            level:
              description: Configure logging severity
              type: str
        trap:
          description: Severity of messages sent to the syslog server.
          type: dict
          suboptions:
            set:
              description: Severity of messages sent to the syslog server.
              type: bool
            severity: *sev
        vrfs:
          description: Specify vrf
          type: list
          elements: dict
          suboptions:
            name:
              description: vrf name.
              type: str
            hosts: *host
            source_interface: *srcint
   running_config:
      description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the EOS device by
        executing the command B(show running-config | section access-list).
      - The states I(replaced) and I(overridden) have identical
        behaviour for this module.
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
      type: str
   state:
      description:
      - The state the configuration should be left in.
      type: str
      choices:
      - deleted
      - merged
      - overridden
      - replaced
      - gathered
      - rendered
      - parsed
      default: merged
"""
EXAMPLES = """
# Using merged
# Before state

# test(config)#show running-config | section logging
# test(config)#

- name: Merge provided configuration with device configuration
  arista.eos.eos_logging_global:
    config:
      hosts:
        - name: "host01"
          protocol: "tcp"
        - name: "11.11.11.1"
          port: 25
      vrfs:
        - name: "vrf01"
          source_interface: "Ethernet1"
        - name: "vrf02"
          hosts:
            - name: "hostvrf1"
              protocol: "tcp"
            - name: "24.1.1.1"
              port: "33"

# After State:

# test(config)#show running-config | section logging
# logging host 11.11.11.1 25
# logging host host01 514 protocol tcp
# logging vrf vrf02 host 24.1.1.1 33
# logging vrf vrf02 host hostvrf1 514 protocol tcp
# logging vrf vrf01 source-interface Ethernet1
# test(config)#
#
#
# Module Execution:
# "after": {
#         "hosts": [
#             {
#                 "name": "11.11.11.1",
#                 "port": 25
#             },
#             {
#                 "name": "host01",
#                 "port": 514,
#                 "protocol": "tcp"
#             }
#         ],
#         "vrfs": [
#             {
#                 "name": "vrf01",
#                 "source_interface": "Ethernet1"
#             },
#             {
#                 "hosts": [
#                     {
#                         "name": "24.1.1.1",
#                         "port": 33
#                     },
#                     {
#                         "name": "hostvrf1",
#                         "port": 514,
#                         "protocol": "tcp"
#                     }
#                 ],
#                 "name": "vrf02"
#             }
#         ]
#     },
#     "before": {},
#     "changed": true,
#     "commands": [
#         "logging host host01 protocol tcp",
#         "logging host 11.11.11.1 25",
#         "logging vrf vrf01 source-interface Ethernet1",
#         "logging vrf vrf02 host hostvrf1 protocol tcp",
#         "logging vrf vrf02 host 24.1.1.1 33"
#     ],
#

# Using replaced:
# Before State:

# test(config)#show running-config | section logging
# logging host 11.11.11.1 25
# logging host host01 514 protocol tcp
# logging vrf vrf02 host 24.1.1.1 33
# logging vrf vrf02 host hostvrf1 514 protocol tcp
# logging format timestamp traditional timezone
# logging vrf vrf01 source-interface Ethernet1
# logging policy match inverse-result match-list                           list01 discard
# logging persistent 4096
# !
# logging level AAA alerts
# test(config)#

- name: Repalce
  arista.eos.eos_logging_global:
    config:
      synchronous:
        set: true
      trap:
        severity: "critical"
      hosts:
        - name: "host02"
          protocol: "tcp"
      vrfs:
        - name: "vrf03"
          source_interface: "Vlan100"
        - name: "vrf04"
          hosts:
            - name: "hostvrf1"
              protocol: "tcp"

    state: replaced

# After State:
# test(config)#show running-config | section logging
# logging synchronous
# logging trap critical
# logging host host02 514 protocol tcp
# logging vrf vrf04 host hostvrf1 514 protocol tcp
# logging vrf vrf03 source-interface Vlan100
# test(config)#
#
# Module Execution:
# "after": {
#         "hosts": [
#             {
#                 "name": "host02",
#                 "port": 514,
#                 "protocol": "tcp"
#             }
#         ],
#         "synchronous": {
#             "set": true
#         },
#         "trap": {
#            "severity": "critical"
#         },
#         "vrfs": [
#             {
#                 "name": "vrf03",
#                 "source_interface": "Vlan100"
#             },
#             {
#                 "hosts": [
#                     {
#                         "name": "hostvrf1",
#                         "port": 514,
#                         "protocol": "tcp"
#                     }
#                 ],
#                 "name": "vrf04"
#             }
#         ]
#     },
#     "before": {
#         "format": {
#             "timestamp": {
#                 "traditional": {
#                     "timezone": true
#                 }
#             }
#         },
#         "hosts": [
#             {
#                 "name": "11.11.11.1",
#                 "port": 25
#             },
#             {
#                 "name": "host01",
#                 "port": 514,
#                 "protocol": "tcp"
#             }
#         ],
#         "level": {
#             "facility": "AAA",
#             "severity": "alerts"
#         },
#         "persistent": {
#             "size": 4096
#         },
#         "policy": {
#             "invert_result": true,
#             "match_list": "list01"
#         },
#         "vrfs": [
#             {
#                 "name": "vrf01",
#                 "source_interface": "Ethernet1"
#             },
#             {
#                 "hosts": [
#                     {
#                         "name": "24.1.1.1",
#                         "port": 33
#                     },
#                     {
#                         "name": "hostvrf1",
#                         "port": 514,
#                         "protocol": "tcp"
#                     }
#                 ],
#                 "name": "vrf02"
#             }
#         ]
#     },
#     "changed": true,
#     "commands": [
#         "logging host host02 protocol tcp",
#         "no logging host 11.11.11.1 25",
#         "no logging host host01 514 protocol tcp",
#         "logging vrf vrf03 source-interface Vlan100",
#         "logging vrf vrf04 host hostvrf1 protocol tcp",
#         "no logging vrf vrf01 source-interface Ethernet1",
#         "no logging vrf vrf02 host 24.1.1.1 33",
#         "no logging vrf vrf02 host hostvrf1 514 protocol tcp",
#         "no logging format timestamp traditional timezone",
#         "no logging level AAA alerts",
#         "no logging persistent 4096",
#         "no logging policy match invert-result match-list list01 discard",
#         "logging synchronous",
#         "logging trap critical"
#     ],
#
#


# Using overridden:
# Before State:

# test(config)#show running-config | section logging
# logging host 11.11.11.1 25
# logging host host01 514 protocol tcp
# logging vrf vrf02 host 24.1.1.1 33
# logging vrf vrf02 host hostvrf1 514 protocol tcp
# logging format timestamp traditional timezone
# logging vrf vrf01 source-interface Ethernet1
# logging policy match inverse-result match-list                           list01 discard
# logging persistent 4096
# !
# logging level AAA alerts
# test(config)#

- name: Repalce
  arista.eos.eos_logging_global:
    config:
      synchronous:
        set: true
      trap:
        severity: "critical"
      hosts:
        - name: "host02"
          protocol: "tcp"
      vrfs:
        - name: "vrf03"
          source_interface: "Vlan100"
        - name: "vrf04"
          hosts:
            - name: "hostvrf1"
              protocol: "tcp"

    state: overridden

# After State:
# test(config)#show running-config | section logging
# logging synchronous
# logging trap critical
# logging host host02 514 protocol tcp
# logging vrf vrf04 host hostvrf1 514 protocol tcp
# logging vrf vrf03 source-interface Vlan100
# test(config)#
#
# Module Execution:
# "after": {
#         "hosts": [
#             {
#                 "name": "host02",
#                 "port": 514,
#                 "protocol": "tcp"
#             }
#         ],
#         "synchronous": {
#             "set": true
#         },
#         "trap": {
#            "severity": "critical"
#         },
#         "vrfs": [
#             {
#                 "name": "vrf03",
#                 "source_interface": "Vlan100"
#             },
#             {
#                 "hosts": [
#                     {
#                         "name": "hostvrf1",
#                         "port": 514,
#                         "protocol": "tcp"
#                     }
#                 ],
#                 "name": "vrf04"
#             }
#         ]
#     },
#     "before": {
#         "format": {
#             "timestamp": {
#                 "traditional": {
#                     "timezone": true
#                 }
#             }
#         },
#         "hosts": [
#             {
#                 "name": "11.11.11.1",
#                 "port": 25
#             },
#             {
#                 "name": "host01",
#                 "port": 514,
#                 "protocol": "tcp"
#             }
#         ],
#         "level": {
#             "facility": "AAA",
#             "severity": "alerts"
#         },
#         "persistent": {
#             "size": 4096
#         },
#         "policy": {
#             "invert_result": true,
#             "match_list": "list01"
#         },
#         "vrfs": [
#             {
#                 "name": "vrf01",
#                 "source_interface": "Ethernet1"
#             },
#             {
#                 "hosts": [
#                     {
#                         "name": "24.1.1.1",
#                         "port": 33
#                     },
#                     {
#                         "name": "hostvrf1",
#                         "port": 514,
#                         "protocol": "tcp"
#                     }
#                 ],
#                 "name": "vrf02"
#             }
#         ]
#     },
#     "changed": true,
#     "commands": [
#         "logging host host02 protocol tcp",
#         "no logging host 11.11.11.1 25",
#         "no logging host host01 514 protocol tcp",
#         "logging vrf vrf03 source-interface Vlan100",
#         "logging vrf vrf04 host hostvrf1 protocol tcp",
#         "no logging vrf vrf01 source-interface Ethernet1",
#         "no logging vrf vrf02 host 24.1.1.1 33",
#         "no logging vrf vrf02 host hostvrf1 514 protocol tcp",
#         "no logging format timestamp traditional timezone",
#         "no logging level AAA alerts",
#         "no logging persistent 4096",
#         "no logging policy match invert-result match-list list01 discard",
#         "logging synchronous",
#         "logging trap critical"
#     ],
#
#

# Using deleted:

# Before State:
# test(config)#show running-config | section logging
# logging synchronous level critical
# logging host 11.11.11.1 25
# logging host host01 514 protocol tcp
# logging host host02 514 protocol tcp
# logging vrf vrf02 host 24.1.1.1 33
# logging vrf vrf02 host hostvrf1 514 protocol tcp
# logging vrf vrf04 host hostvrf1 514 protocol tcp
# logging vrf vrf01 source-interface Ethernet1
# logging vrf vrf03 source-interface Vlan100
# test(config)#

- name: Delete all logging configs
  arista.eos.eos_logging_global:
    state: deleted
  become: true

# After state:
# test(config)#show running-config | section logging
# test(config)#
#
# "after": {},
#     "before": {
#         "hosts": [
#             {
#                 "name": "11.11.11.1",
#                 "port": 25
#             },
#             {
#                 "name": "host01",
#                 "port": 514,
#                 "protocol": "tcp"
#             },
#             {
#                 "name": "host02",
#                 "port": 514,
#                 "protocol": "tcp"
#             }
#         ],
#         "synchronous": {
#             "level": "critical"
#         },
#         "vrfs": [
#             {
#                 "name": "vrf01",
#                 "source_interface": "Ethernet1"
#             },
#             {
#                 "hosts": [
#                     {
#                         "name": "24.1.1.1",
#                         "port": 33
#                     },
#                     {
#                         "name": "hostvrf1",
#                         "port": 514,
#                         "protocol": "tcp"
#                     }
#                 ],
#                 "name": "vrf02"
#             },
#             {
#                 "name": "vrf03",
#                 "source_interface": "Vlan100"
#             },
#             {
#                 "hosts": [
#                     {
#                         "name": "hostvrf1",
#                         "port": 514,
#                         "protocol": "tcp"
#                     }
#                 ],
#                 "name": "vrf04"
#             }
#         ]
#     },
#     "changed": true,
#     "commands": [
#         "no logging host 11.11.11.1 25",
#         "no logging host host01 514 protocol tcp",
#         "no logging host host02 514 protocol tcp",
#         "no logging vrf vrf01 source-interface Ethernet1",
#         "no logging vrf vrf02 host 24.1.1.1 33",
#         "no logging vrf vrf02 host hostvrf1 514 protocol tcp",
#         "no logging vrf vrf03 source-interface Vlan100",
#         "no logging vrf vrf04 host hostvrf1 514 protocol tcp",
#         "no logging synchronous level critical"
#     ],

# Using parsed:
# parsed.cfg

# logging host 11.11.11.1 25
# logging host host01 514 protocol tcp
# logging vrf vrf02 host 24.1.1.1 33
# logging vrf vrf02 host hostvrf1 514 protocol tcp
# logging format timestamp traditional timezone
# logging vrf vrf01 source-interface Ethernet1
# logging policy match inverse-result match-list                           list01 discard
# logging persistent 4096
# !
# logging level AAA alerts

- name: parse configs
  arista.eos.eos_logging_global:
    running_config: "{{ lookup('file', './parsed.cfg') }}"
    state: parsed

# Module Execution
# "parsed": {
#         "format": {
#             "timestamp": {
#                 "traditional": {
#                     "timezone": true
#                 }
#             }
#         },
#         "hosts": [
#             {
#                 "name": "11.11.11.1",
#                 "port": 25
#             },
#             {
#                 "name": "host01",
#                 "port": 514,
#                 "protocol": "tcp"
#             }
#         ],
#         "level": {
#             "facility": "AAA",
#             "severity": "alerts"
#         },
#         "persistent": {
#             "size": 4096
#         },
#         "policy": {
#             "invert_result": true,
#             "match_list": "list01"
#         },
#         "vrfs": [
#             {
#                 "name": "vrf01",
#                 "source_interface": "Ethernet1"
#             },
#             {
#                 "hosts": [
#                     {
#                         "name": "24.1.1.1",
#                         "port": 33
#                     },
#                     {
#                         "name": "hostvrf1",
#                         "port": 514,
#                         "protocol": "tcp"
#                     }
#                 ],
#                 "name": "vrf02"
#             }
#         ]
#     }
#

# Using gathered:
# Before State:
# test(config)#show running-config | section logging
# logging host 11.11.11.1 25
# logging host host01 514 protocol tcp
# logging vrf vrf02 host 24.1.1.1 33
# logging vrf vrf02 host hostvrf1 514 protocol tcp
# logging format timestamp traditional timezone
# logging vrf vrf01 source-interface Ethernet1
# logging policy match inverse-result match-list                           list01 discard
# logging persistent 4096
# !
# logging level AAA alerts
# test(config)#

- name: gather configs
  arista.eos.eos_logging_global:
    state: gathered

# Module Execution:
# "gathered": {
#         "format": {
#             "timestamp": {
#                 "traditional": {
#                     "timezone": true
#                 }
#             }
#         },
#         "hosts": [
#             {
#                 "name": "11.11.11.1",
#                 "port": 25
#             },
#             {
#                 "name": "host01",
#                 "port": 514,
#                 "protocol": "tcp"
#             }
#         ],
#         "level": {
#             "facility": "AAA",
#             "severity": "alerts"
#         },
#         "persistent": {
#             "size": 4096
#         },
#         "policy": {
#             "invert_result": true,
#             "match_list": "list01"
#         },
#         "vrfs": [
#             {
#                 "name": "vrf01",
#                 "source_interface": "Ethernet1"
#             },
#             {
#                 "hosts": [
#                     {
#                         "name": "24.1.1.1",
#                         "port": 33
#                     },
#                     {
#                         "name": "hostvrf1",
#                         "port": 514,
#                         "protocol": "tcp"
#                     }
#                 ],
#                 "name": "vrf02"
#             }
#         ]
#     },
#

# Using rendered:
- name: Render provided configuration
  arista.eos.eos_logging_global:
    config:
      format:
        timestamp:
          traditional:
            timezone: true
      level:
        facility: "AAA"
        severity: "alerts"
      persistent:
        size: 4096
      policy:
        invert_result: true
        match_list: "list01"
      hosts:
        - name: "host01"
          protocol: "tcp"
        - name: "11.11.11.1"
          port: 25
      vrfs:
        - name: "vrf01"
          source_interface: "Ethernet1"
        - name: "vrf02"
          hosts:
            - name: "hostvrf1"
              protocol: "tcp"
            - name: "24.1.1.1"
              port: "33"
# Module Execution:

# "rendered": [
#         "logging host host01 protocol tcp",
#         "logging host 11.11.11.1 25",
#         "logging vrf vrf01 source-interface Ethernet1",
#         "logging vrf vrf02 host hostvrf1 protocol tcp",
#         "logging vrf vrf02 host 24.1.1.1 33",
#         "logging format timestamp traditional timezone",
#         "logging level AAA alerts",
#         "logging persistent 4096",
#         "logging policy match invert-result match-list list01 discard"
#     ]
#
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.arista.eos.plugins.module_utils.network.eos.argspec.logging_global.logging_global import (
    Logging_globalArgs,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.config.logging_global.logging_global import (
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
