#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_logging_global
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: iosxr_logging_global
version_added: 2.4.0
short_description: Resource module to configure logging.
description: This module manages the logging attributes of Cisco IOSXR network devices
notes:
- Tested against IOSXR 7.0.2.
- This module works with connection C(network_cli).
author: Ashwini Mhatre (@amhatre)
options:
  config:
    description: A dictionary of logging options.
    type: dict
    suboptions:
      archive:
        description: logging to a persistent device(disk/harddisk)
        type: dict
        suboptions:
          device:
            type: str
            description: Configure the archive device
          archive_length:
            type: int
            description: The maximum no of weeks of log to maintain.
          archive_size:
            type: int
            description: The total size of the archive.
          file_size:
            type: int
            description: The maximum file size for a single log file..
          frequency:
            type: str
            description: The collection interval for logs.
            choices: ["daily", "weekly"]
          severity: &severity
            description: Logging severity level
            type: str
            choices:
              - alerts
              - critical
              - debugging
              - emergencies
              - errors
              - informational
              - notifications
              - warnings
          threshold:
            type: int
            description: Threshold percent <1-99>.
      buffered:
        description: Set buffered logging parameters
        type: dict
        suboptions:
          size: &size
            description: Logging buffer size
            type: int
          severity: *severity
          discriminator: &discriminator
            description: Establish MD-Buffer association
            type: list
            elements: dict
            suboptions:
              match_params:
                type: str
                description: Set match/no-match discriminator.
                choices: ["match1", "match2", "match3", "nomatch1", "nomatch2", "nomatch3"]
              name:
                type: str
                description: discriminator name.
      console:
        description: Set console logging parameters
        type: dict
        suboptions:
          state: &state
            description: Enable or disable logging.
            type: str
            choices: [ "enabled", "disabled" ]
          severity: &severity1
            description: Logging severity level
            type: str
            choices:
              - alerts
              - critical
              - debugging
              - emergencies
              - errors
              - informational
              - notifications
              - warning
          discriminator: *discriminator
      correlator:
        description: Configure properties of the event correlator
        type: dict
        suboptions:
          buffer_size:
            type: int
            description: Configure size of the correlator buffer.
          rules:
            type: list
            elements: dict
            description: Configure a specified correlation rule.
            suboptions:
              rule_name:
                type: str
                description: name of rule.
              rule_type:
                type: str
                choices: ["stateful", "nonstateful"]
                description: type of rule - stateful or nonstateful.
              timeout:
                type: int
                description: Specify timeout.
              timeout_rootcause:
                type: int
                description: Specify timeout for root-cause.
              context_correlation:
                type: bool
                description: Specify enable correlation on context.
              reissue_nonbistate:
                type: bool
                description: Specify reissue of non-bistate alarms on parent clear.This option is allowed for the rules whose type is stateful.
              reparent:
                type: bool
                description: Specify reparent of alarm on parent clear.This option is allowed for the rules whose type is stateful.
          rule_sets:
            type: list
            elements: dict
            description: Configure a specified correlation ruleset.
            suboptions:
              name:
                type: str
                description: Name of the ruleset
              rulename:
                type: list
                elements: str
                description: Name of the rule
      events:
        type: dict
        description: Configure event monitoring parameters.
        suboptions:
          buffer_size:
            type: int
            description: Set size of the local event buffer.
          display_location:
            type: bool
            description: Include alarm source location in message text.
          filter_match:
            type: list
            elements: str
            description: Configure filter.
          severity: *severity
          threshold:
            type: int
            description: Capacity alarm threshold.
      facility:
        description: Facility parameter for syslog messages
        type: str
        choices:
          - auth
          - cron
          - daemon
          - kern
          - local0
          - local1
          - local2
          - local3
          - local4
          - local5
          - local6
          - local7
          - lpr
          - mail
          - news
          - sys10
          - sys11
          - sys12
          - sys13
          - sys14
          - sys9
          - syslog
          - user
          - uucp
      files:
        type: list
        elements: dict
        description: Set file logging.
        suboptions:
          name:
            description: name of file.
            type: str
          path:
            description: Set file path.
            type: str
          maxfilesize:
            type: int
            description: Set max file size.
          severity:
            description: Logging severity level
            type: str
            choices:
              - alerts
              - critical
              - debugging
              - emergencies
              - errors
              - info
              - notifications
              - warning
      format:
        type: bool
        description: Enable to send the syslog message rfc5424 format .
      history:
        description: Configure syslog history table
        type: dict
        suboptions:
          state: *state
          size: *size
          severity:
            description: Logging severity level
            type: str
            choices:
              - alerts
              - critical
              - debugging
              - emergencies
              - errors
              - informational
              - notifications
              - warnings
      hostnameprefix:
        type: str
        description: Hostname prefix to add on msgs to servers.
      ipv4: &ip
        description: Mark the dscp/precedence bit for ipv4 packets.
        type: dict
        suboptions:
          dscp:
            description: Set IP DSCP (DiffServ CodePoint).Please refer vendor document for valid entries.
            type: str
          precedence:
            description: Set precedence Please refer vendor document for valid entries.
            type: str
      ipv6: *ip
      localfilesize:
        type: int
        description: Set size of the local log file
      monitor:
        description: Set terminal line (monitor) logging parameters
        type: dict
        suboptions:
          state: *state
          discriminator: *discriminator
          severity: *severity1
      source_interfaces:
        description: Specify interface for source address in logging transactions
        type: list
        elements: dict
        suboptions:
          interface:
            description: Interface name with number
            type: str
          vrf:
            description: VPN Routing/Forwarding instance name
            type: str
      suppress:
        type: dict
        description: Suppress logging behaviour.
        suboptions:
          apply_rule:
            type: str
            description: Apply suppression rule.
          duplicates:
            type: bool
            description: Suppress consecutive duplicate messages.
      tls_servers:
        type: list
        elements: dict
        description: Secure server over tls.
        suboptions:
          name:
            type: str
            description: Name for the tls peer configuration.
          severity: *severity
          tls_hostname:
            type: str
            description: Name of the logging host.
          trustpoint:
            type: str
            description: Name of the trustpoint configured.
          vrf:
            type: str
            description: name of vrf.
      trap:
        description: Set syslog server logging level
        type: dict
        suboptions:
          state: *state
          severity: *severity1
      hosts:
        description: Set syslog server IP address and parameters
        type: list
        elements: dict
        suboptions:
          severity:
            description: Logging severity level
            type: str
            choices:
              - alerts
              - critical
              - debugging
              - emergencies
              - error
              - info
              - notifications
              - warning
          host:
            description: IPv4/Ipv6 address or hostname of the syslog server
            type: str
          port:
            description: Set <0-65535>  non-default Port.
            type: str
            default: default
          vrf:
            description: Set VRF option
            type: str
            default: default
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the IOS device by
        executing the command B(show running-config | include logging).
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
    type: str
"""
EXAMPLES = """
# Using merged
# -----------------
# Before state
# RP/0/0/CPU0:10#show running-config logging
# Thu Feb  4 09:38:36.245 UTC
# % No such configuration item(s)
# RP/0/0/CPU0:10#
#
#
- name: Merge the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_logging_global:
    config:
      buffered:
        size: 2097152
        severity: warnings
      correlator:
        buffer_size: 1024
      events:
        display_location: true
      files:
        - maxfilesize: '1024'
          name: test
          path: test
          severity: info
      hostnameprefix: test
      hosts:
        - host: 1.1.1.1
          port: default
          severity: critical
          vrf: default
      ipv4:
        dscp: af11
      localfilesize: 1024
      monitor:
        severity: errors
      source_interfaces:
        - interface: GigabitEthernet0/0/0/0
          vrf: test
      tls_servers:
        - name: test
          tls_hostname: test2
          trustpoint: test2
          vrf: test
      trap:
        severity: informational
    state: merged
#
#
# After state:
# -------------------------------------------
# RP/0/0/CPU0:10#show running-config logging
# Tue Jul 20 18:09:18.491 UTC
# logging tls-server test
#  vrf test
#  trustpoint test2
#  tls-hostname test2
# !
# logging file test path test maxfilesize 1024 severity info
# logging ipv4 dscp af11
# logging trap informational
# logging events display-location
# logging monitor errors
# logging buffered 2097152
# logging buffered warnings
# logging 1.1.1.1 vrf default severity critical port default
# logging correlator buffer-size 1024
# logging localfilesize 1024
# logging source-interface GigabitEthernet0/0/0/0 vrf test
# logging hostnameprefix test
# ------------------------------------------------
# Module execution
#
#     "after": {
#         "buffered": {
#             "severity": "errors"
#         },
#         "correlator": {
#             "buffer_size": 1024
#         },
#         "files": [
#             {
#                 "maxfilesize": "1024",
#                 "name": "test",
#                 "path": "test1",
#                 "severity": "info"
#             }
#         ],
#         "hostnameprefix": "test1",
#         "hosts": [
#             {
#                 "host": "1.1.1.3",
#                 "port": "default",
#                 "severity": "critical",
#                 "vrf": "default"
#             }
#         ],
#         "ipv6": {
#             "dscp": "af11"
#         },
#         "localfilesize": 1024,
#         "source_interfaces": [
#             {
#                 "interface": "GigabitEthernet0/0/0/0",
#                 "vrf": "test1"
#             }
#         ],
#         "tls_servers": [
#             {
#                 "name": "test",
#                 "tls_hostname": "test2",
#                 "trustpoint": "test",
#                 "vrf": "test"
#             }
#         ]
#     },
#     "before": {},
#     "changed": true,
#     "commands": [
#         "logging buffered errors",
#         "logging correlator buffer-size 1024",
#         "logging hostnameprefix test1",
#         "logging ipv6 dscp af11",
#         "logging localfilesize 1024",
#         "logging trap disable",
#         "logging monitor disable",
#         "logging history disable",
#         "logging console disable",
#         "logging 1.1.1.3 vrf default severity critical port default",
#         "logging file test path test1 maxfilesize 1024 severity info",
#         "logging source-interface GigabitEthernet0/0/0/0 vrf test1",
#         "logging tls-server test tls-hostname test2",
#         "logging tls-server test trustpoint test",
#         "logging tls-server test vrf test"
#     ],
#     "invocation": {
#         "module_args": {
#             "config": {
#                 "archive": null,
#                 "buffered": {
#                     "discriminator": null,
#                     "severity": "errors",
#                     "size": null
#                 },
#                 "console": {
#                     "discriminator": null,
#                     "severity": null,
#                     "state": "disabled"
#                 },
#                 "correlator": {
#                     "buffer_size": 1024,
#                     "rule_set": null,
#                     "rules": null
#                 },
#                 "events": null,
#                 "facility": null,
#                 "files": [
#                     {
#                         "maxfilesize": "1024",
#                         "name": "test",
#                         "path": "test1",
#                         "severity": "info"
#                     }
#                 ],
#                 "format": null,
#                 "history": {
#                     "severity": null,
#                     "size": null,
#                     "state": "disabled"
#                 },
#                 "hostnameprefix": "test1",
#                 "hosts": [
#                     {
#                         "host": "1.1.1.3",
#                         "port": "default",
#                         "severity": "critical",
#                         "vrf": "default"
#                     }
#                 ],
#                 "ipv4": null,
#                 "ipv6": {
#                     "dscp": "af11",
#                     "precedence": null
#                 },
#                 "localfilesize": 1024,
#                 "monitor": {
#                     "discriminator": null,
#                     "severity": null,
#                     "state": "disabled"
#                 },
#                 "source_interfaces": [
#                     {
#                         "interface": "GigabitEthernet0/0/0/0",
#                         "vrf": "test1"
#                     }
#                 ],
#                 "suppress": null,
#                 "tls_servers": [
#                     {
#                         "name": "test",
#                         "severity": null,
#                         "tls_hostname": "test2",
#                         "trustpoint": "test",
#                         "vrf": "test"
#                     }
#                 ],
#                 "trap": {
#                     "severity": null,
#                     "state": "disabled"
#                 }
#             },
#             "running_config": null,
#             "state": "merged"
#         }
#     }
# }
#
# Using replaced:
# -----------------------------------------------------------
#
# Before state
# RP/0/0/CPU0:10#show running-config logging
# Tue Jul 20 18:09:18.491 UTC
# logging tls-server test
#  vrf test
#  trustpoint test2
#  tls-hostname test2
# !
# logging file test path test maxfilesize 1024 severity info
# logging ipv4 dscp af11
# logging trap informational
# logging events display-location
# logging monitor errors
# logging buffered 2097152
# logging buffered warnings
# logging 1.1.1.1 vrf default severity critical port default
# logging correlator buffer-size 1024
# logging localfilesize 1024
# logging source-interface GigabitEthernet0/0/0/0 vrf test
# logging hostnameprefix test
# -----------------------------------------------------------
#
- name: Replace BGP configuration with provided configuration
  cisco.iosxr.iosxr_logging_global:
    state: replaced
    config:
      buffered:
        severity: errors
      correlator:
        buffer_size: 1024
      files:
        - maxfilesize: '1024'
          name: test
          path: test1
          severity: info
      hostnameprefix: test1
      hosts:
        - host: 1.1.1.3
          port: default
          severity: critical
          vrf: default
      ipv6:
        dscp: af11
      localfilesize: 1024
      monitor:
        severity: errors
      tls_servers:
        - name: test
          tls_hostname: test2
          trustpoint: test
          vrf: test
      trap:
        severity: critical
#
# After state:
# RP/0/0/CPU0:10#show running-config logging
# Tue Jul 20 18:31:51.709 UTC
# logging tls-server test
#  vrf test
#  trustpoint test
#  tls-hostname test2
# !
# logging file test path test1 maxfilesize 1024 severity info
# logging ipv6 dscp af11
# logging trap critical
# logging monitor errors
# logging buffered errors
# logging 1.1.1.3 vrf default severity critical port default
# logging correlator buffer-size 1024
# logging localfilesize 1024
# logging hostnameprefix test1
# -----------------------------------------------------------------
#
# Module Execution:
# "after": {
#         "buffered": {
#             "severity": "errors"
#         },
#         "correlator": {
#             "buffer_size": 1024
#         },
#         "files": [
#             {
#                 "maxfilesize": "1024",
#                 "name": "test",
#                 "path": "test1",
#                 "severity": "info"
#             }
#         ],
#         "hostnameprefix": "test1",
#         "hosts": [
#             {
#                 "host": "1.1.1.3",
#                 "port": "default",
#                 "severity": "critical",
#                 "vrf": "default"
#             }
#         ],
#         "ipv6": {
#             "dscp": "af11"
#         },
#         "localfilesize": 1024,
#         "monitor": {
#             "severity": "errors"
#         },
#         "tls_servers": [
#             {
#                 "name": "test",
#                 "tls_hostname": "test2",
#                 "trustpoint": "test",
#                 "vrf": "test"
#             }
#         ],
#         "trap": {
#             "severity": "critical"
#         }
#     },
#     "before": {
#         "buffered": {
#             "severity": "warnings",
#             "size": 2097152
#         },
#         "correlator": {
#             "buffer_size": 1024
#         },
#         "events": {
#             "display_location": true
#         },
#         "files": [
#             {
#                 "maxfilesize": "1024",
#                 "name": "test",
#                 "path": "test",
#                 "severity": "info"
#             }
#         ],
#         "hostnameprefix": "test",
#         "hosts": [
#             {
#                 "host": "1.1.1.1",
#                 "port": "default",
#                 "severity": "critical",
#                 "vrf": "default"
#             }
#         ],
#         "ipv4": {
#             "dscp": "af11"
#         },
#         "localfilesize": 1024,
#         "monitor": {
#             "severity": "errors"
#         },
#         "source_interfaces": [
#             {
#                 "interface": "GigabitEthernet0/0/0/0",
#                 "vrf": "test"
#             }
#         ],
#         "tls_servers": [
#             {
#                 "name": "test",
#                 "tls_hostname": "test2",
#                 "trustpoint": "test2",
#                 "vrf": "test"
#             }
#         ],
#         "trap": {
#             "severity": "informational"
#         }
#     },
#     "changed": true,
#     "commands": [
#         "no logging buffered 2097152",
#         "no logging events display-location",
#         "no logging ipv4 dscp af11",
#         "no logging 1.1.1.1 vrf default severity critical port default",
#         "no logging source-interface GigabitEthernet0/0/0/0 vrf test",
#         "logging buffered errors",
#         "logging hostnameprefix test1",
#         "logging ipv6 dscp af11",
#         "logging trap critical",
#         "logging 1.1.1.3 vrf default severity critical port default",
#         "logging file test path test1 maxfilesize 1024 severity info",
#         "logging tls-server test trustpoint test"
#     ],
#
#
#
# Using deleted:
# -----------------------------------------------------------
# Before state:
# RP/0/0/CPU0:10#show running-config logging
# Tue Jul 20 18:09:18.491 UTC
# logging tls-server test
#  vrf test
#  trustpoint test2
#  tls-hostname test2
# !
# logging file test path test maxfilesize 1024 severity info
# logging ipv4 dscp af11
# logging trap informational
# logging events display-location
# logging monitor errors
# logging buffered 2097152
# logging buffered warnings
# logging 1.1.1.1 vrf default severity critical port default
# logging correlator buffer-size 1024
# logging localfilesize 1024
# logging source-interface GigabitEthernet0/0/0/0 vrf test
# logging hostnameprefix test
#
# -----------------------------------------------------------
- name: Delete given logging_global configuration
  cisco.iosxr.iosxr_logging_global:
    state: deleted
#
# After state:
# RP/0/0/CPU0:10#show running-config
#
# -------------------------------------------------------------
# Module Execution:
#
# "after": {},
#     "before": {
#         "buffered": {
#             "severity": "warnings",
#             "size": 2097152
#         },
#         "correlator": {
#             "buffer_size": 1024
#         },
#         "events": {
#             "display_location": true
#         },
#         "files": [
#             {
#                 "maxfilesize": "1024",
#                 "name": "test",
#                 "path": "test",
#                 "severity": "info"
#             }
#         ],
#         "hostnameprefix": "test",
#         "hosts": [
#             {
#                 "host": "1.1.1.1",
#                 "port": "default",
#                 "severity": "critical",
#                 "vrf": "default"
#             }
#         ],
#         "ipv4": {
#             "dscp": "af11"
#         },
#         "localfilesize": 1024,
#         "monitor": {
#             "severity": "errors"
#         },
#         "source_interfaces": [
#             {
#                 "interface": "GigabitEthernet0/0/0/0",
#                 "vrf": "test"
#             }
#         ],
#         "tls_servers": [
#             {
#                 "name": "test",
#                 "tls_hostname": "test2",
#                 "trustpoint": "test2",
#                 "vrf": "test"
#             }
#         ],
#         "trap": {
#             "severity": "informational"
#         }
#     },
#     "changed": true,
#     "commands": [
#         "no logging buffered 2097152",
#         "no logging buffered warnings",
#         "no logging correlator buffer-size 1024",
#         "no logging events display-location",
#         "no logging hostnameprefix test",
#         "no logging ipv4 dscp af11",
#         "no logging localfilesize 1024",
#         "no logging monitor errors",
#         "no logging trap informational",
#         "no logging 1.1.1.1 vrf default severity critical port default",
#         "no logging file test path test maxfilesize 1024 severity info",
#         "no logging source-interface GigabitEthernet0/0/0/0 vrf test",
#         "no logging tls-server test"
#     ],
#     "invocation": {
#         "module_args": {
#             "config": null,
#             "running_config": null,
#             "state": "deleted"
#         }
#     }
#
#
#
# using gathered:
# ------------------------------------------------------------
# Before state:
# RP/0/0/CPU0:10#show running-config logging
# Tue Jul 20 18:09:18.491 UTC
# logging tls-server test
#  vrf test
#  trustpoint test2
#  tls-hostname test2
# !
# logging file test path test maxfilesize 1024 severity info
# logging ipv4 dscp af11
# logging trap informational
# logging events display-location
# logging monitor errors
# logging buffered 2097152
# logging buffered warnings
# logging 1.1.1.1 vrf default severity critical port default
# logging correlator buffer-size 1024
# logging localfilesize 1024
# logging source-interface GigabitEthernet0/0/0/0 vrf test
# logging hostnameprefix test
#
#
- name: Gather iosxr_logging_global facts using gathered state
  cisco.iosxr.iosxr_logging_global:
    state: gathered
#
# -------------------------------------------------------------
# Module Execution:
#
# "changed": false,
# "gathered": {
#         "buffered": {
#             "severity": "warnings",
#             "size": 2097152
#         },
#         "correlator": {
#             "buffer_size": 1024
#         },
#         "events": {
#             "display_location": true
#         },
#         "files": [
#             {
#                 "maxfilesize": "1024",
#                 "name": "test",
#                 "path": "test",
#                 "severity": "info"
#             }
#         ],
#         "hostnameprefix": "test",
#         "hosts": [
#             {
#                 "host": "1.1.1.1",
#                 "port": "default",
#                 "severity": "critical",
#                 "vrf": "default"
#             }
#         ],
#         "ipv4": {
#             "dscp": "af11"
#         },
#         "localfilesize": 1024,
#         "monitor": {
#             "severity": "errors"
#         },
#         "source_interfaces": [
#             {
#                 "interface": "GigabitEthernet0/0/0/0",
#                 "vrf": "test"
#             }
#         ],
#         "tls_servers": [
#             {
#                 "name": "test",
#                 "tls_hostname": "test2",
#                 "trustpoint": "test2",
#                 "vrf": "test"
#             }
#         ],
#         "trap": {
#             "severity": "informational"
#         }
#     },
#     "invocation": {
#         "module_args": {
#             "config": null,
#             "running_config": null,
#             "state": "gathered"
#         }
# }
#
#
# Using parsed:
# ---------------------------------------------------------------
#
# parsed.cfg
#
# logging tls-server test
#  vrf test
#  trustpoint test2
#  tls-hostname test2
# !
# logging file test path test maxfilesize 1024 severity info
# logging ipv4 dscp af11
# logging trap informational
# logging events display-location
# logging monitor errors
# logging buffered 2097152
# logging buffered warnings
# logging 1.1.1.1 vrf default severity critical port default
# logging correlator buffer-size 1024
# logging localfilesize 1024
# logging source-interface GigabitEthernet0/0/0/0 vrf test
# logging hostnameprefix test
#
#
- name: Parse externally provided Logging global config to agnostic model
  cisco.iosxr.iosxr_logging_global:
    running_config: "{{ lookup('file', './fixtures/parsed.cfg') }}"
    state: parsed
# ----------------------------------------------------------------
# Module execution:
# "changed": false,
# "parsed": {
#         "buffered": {
#             "severity": "warnings",
#             "size": 2097152
#         },
#         "correlator": {
#             "buffer_size": 1024
#         },
#         "events": {
#             "display_location": true
#         },
#         "files": [
#             {
#                 "maxfilesize": "1024",
#                 "name": "test",
#                 "path": "test",
#                 "severity": "info"
#             }
#         ],
#         "hostnameprefix": "test",
#         "hosts": [
#             {
#                 "host": "1.1.1.1",
#                 "port": "default",
#                 "severity": "critical",
#                 "vrf": "default"
#             }
#         ],
#         "ipv4": {
#             "dscp": "af11"
#         },
#         "localfilesize": 1024,
#         "monitor": {
#             "severity": "errors"
#         },
#         "source_interfaces": [
#             {
#                 "interface": "GigabitEthernet0/0/0/0",
#                 "vrf": "test"
#             }
#         ],
#         "tls_servers": [
#             {
#                 "name": "test",
#                 "tls_hostname": "test2",
#                 "trustpoint": "test2",
#                 "vrf": "test"
#             }
#         ],
#         "trap": {
#             "severity": "informational"
#         }
#     }
#
#
# Using rendered:
# ----------------------------------------------------------------------------
- name: >-
    Render platform specific configuration lines with state rendered (without
    connecting to the device)
  cisco.iosxr.iosxr_logging_global:
    state: rendered
    config:
      buffered:
        size: 2097152
        severity: warnings
      correlator:
        buffer_size: 1024
      events:
        display_location: true
      files:
        - maxfilesize: '1024'
          name: test
          path: test
          severity: info
      hostnameprefix: test
      hosts:
        - host: 1.1.1.1
          port: default
          severity: critical
          vrf: default
      ipv4:
        dscp: af11
      localfilesize: 1024
      monitor:
        severity: errors
      source_interfaces:
        - interface: GigabitEthernet0/0/0/0
          vrf: test
      tls_servers:
        - name: test
          tls_hostname: test2
          trustpoint: test2
          vrf: test
      trap:
        severity: informational
# ----------------------------------------------------------------
# Module Execution:
# "rendered": [
#         "logging buffered errors",
#         "logging correlator buffer-size 1024",
#         "logging hostnameprefix test1",
#         "logging ipv6 dscp af11",
#         "logging localfilesize 1024",
#         "logging trap disable",
#         "logging monitor disable",
#         "logging history disable",
#         "logging console disable",
#         "logging 1.1.1.3 vrf default severity critical port default",
#         "logging file test path test1 maxfilesize 1024 severity info",
#         "logging source-interface GigabitEthernet0/0/0/0 vrf test1",
#         "logging tls-server test tls-hostname test2",
#         "logging tls-server test trustpoint test",
#         "logging tls-server test vrf test"
#     ]
#
# Using overridden:
# ---------------------------------------------------------------------------------
# Before state:
# RP/0/0/CPU0:10#show running-config logging
# Tue Jul 20 18:09:18.491 UTC
# logging tls-server test
#  vrf test
#  trustpoint test2
#  tls-hostname test2
# !
# logging file test path test maxfilesize 1024 severity info
# logging ipv4 dscp af11
# logging trap informational
# logging events display-location
# logging monitor errors
# logging buffered 2097152
# logging buffered warnings
# logging 1.1.1.1 vrf default severity critical port default
# logging correlator buffer-size 1024
# logging localfilesize 1024
# logging source-interface GigabitEthernet0/0/0/0 vrf test
# logging hostnameprefix test
#
# -----------------------------------------------------------
#
- name: Overridde logging global configuration with provided configuration
  cisco.iosxr.iosxr_logging_global:
    state: overridden
    config:
      buffered:
        severity: errors
      correlator:
        buffer_size: 1024
      files:
        - maxfilesize: '1024'
          name: test
          path: test1
          severity: info
      hostnameprefix: test1
      hosts:
        - host: 1.1.1.3
          port: default
          severity: critical
          vrf: default
      ipv6:
        dscp: af11
      localfilesize: 1024
      monitor:
        severity: errors
      tls_servers:
        - name: test
          tls_hostname: test2
          trustpoint: test
          vrf: test
      trap:
        severity: critical
#
# After state:
# RP/0/0/CPU0:10#show running-config logging
# Tue Jul 20 18:31:51.709 UTC
# logging tls-server test
#  vrf test
#  trustpoint test
#  tls-hostname test2
# !
# logging file test path test1 maxfilesize 1024 severity info
# logging ipv6 dscp af11
# logging trap critical
# logging monitor errors
# logging buffered errors
# logging 1.1.1.3 vrf default severity critical port default
# logging correlator buffer-size 1024
# logging localfilesize 1024
# logging hostnameprefix test1
# -----------------------------------------------------------------
#
# Module Execution:
# "after": {
#         "buffered": {
#             "severity": "errors"
#         },
#         "correlator": {
#             "buffer_size": 1024
#         },
#         "files": [
#             {
#                 "maxfilesize": "1024",
#                 "name": "test",
#                 "path": "test1",
#                 "severity": "info"
#             }
#         ],
#         "hostnameprefix": "test1",
#         "hosts": [
#             {
#                 "host": "1.1.1.3",
#                 "port": "default",
#                 "severity": "critical",
#                 "vrf": "default"
#             }
#         ],
#         "ipv6": {
#             "dscp": "af11"
#         },
#         "localfilesize": 1024,
#         "monitor": {
#             "severity": "errors"
#         },
#         "tls_servers": [
#             {
#                 "name": "test",
#                 "tls_hostname": "test2",
#                 "trustpoint": "test",
#                 "vrf": "test"
#             }
#         ],
#         "trap": {
#             "severity": "critical"
#         }
#     },
#     "before": {
#         "buffered": {
#             "severity": "warnings",
#             "size": 2097152
#         },
#         "correlator": {
#             "buffer_size": 1024
#         },
#         "events": {
#             "display_location": true
#         },
#         "files": [
#             {
#                 "maxfilesize": "1024",
#                 "name": "test",
#                 "path": "test",
#                 "severity": "info"
#             }
#         ],
#         "hostnameprefix": "test",
#         "hosts": [
#             {
#                 "host": "1.1.1.1",
#                 "port": "default",
#                 "severity": "critical",
#                 "vrf": "default"
#             }
#         ],
#         "ipv4": {
#             "dscp": "af11"
#         },
#         "localfilesize": 1024,
#         "monitor": {
#             "severity": "errors"
#         },
#         "source_interfaces": [
#             {
#                 "interface": "GigabitEthernet0/0/0/0",
#                 "vrf": "test"
#             }
#         ],
#         "tls_servers": [
#             {
#                 "name": "test",
#                 "tls_hostname": "test2",
#                 "trustpoint": "test2",
#                 "vrf": "test"
#             }
#         ],
#         "trap": {
#             "severity": "informational"
#         }
#     },
#     "changed": true,
#     "commands": [
#         "no logging buffered 2097152",
#         "no logging events display-location",
#         "no logging ipv4 dscp af11",
#         "no logging 1.1.1.1 vrf default severity critical port default",
#         "no logging source-interface GigabitEthernet0/0/0/0 vrf test",
#         "logging buffered errors",
#         "logging hostnameprefix test1",
#         "logging ipv6 dscp af11",
#         "logging trap critical",
#         "logging 1.1.1.3 vrf default severity critical port default",
#         "logging file test path test1 maxfilesize 1024 severity info",
#         "logging tls-server test trustpoint test"
#     ],
#
"""

RETURN = """
before:
  description: The configuration prior to the module execution.
  returned: when state is I(merged), I(replaced), I(overridden), I(deleted) or I(purged)
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
  returned: when state is I(merged), I(replaced), I(overridden), I(deleted) or I(purged)
  type: list
  sample:
    - "logging file test path test1 maxfilesize 1024 severity info"
    - "logging ipv6 dscp af11"
    - "logging trap critical"
    - "logging monitor errors"
    - "logging buffered errors"
    - "logging 1.1.1.3 vrf default severity critical port default"
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when state is I(rendered)
  type: list
  sample:
    - "logging buffered errors"
    - "logging correlator buffer-size 1024"
    - "logging hostnameprefix test1"
    - "logging ipv6 dscp af11"
    - "logging localfilesize 1024"
    - "logging trap disable"
    - "logging monitor disable"
    - "logging history disable"
    - "logging console disable"
gathered:
  description: Facts about the network resource gathered from the remote device as structured data.
  returned: when state is I(gathered)
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
parsed:
  description: The device native config provided in I(running_config) option parsed into structured data as per module argspec.
  returned: when state is I(parsed)
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.logging_global.logging_global import (
    Logging_globalArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.logging_global.logging_global import (
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
