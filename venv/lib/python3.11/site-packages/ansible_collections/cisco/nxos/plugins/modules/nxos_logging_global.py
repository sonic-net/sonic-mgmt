#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_logging_global
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_logging_global
short_description: Logging resource module.
description:
- This module manages logging configuration on devices running Cisco NX-OS.
version_added: 2.5.0
notes:
- Tested against NX-OS 9.3.6 on Cisco Nexus Switches.
- Limited Support for Cisco MDS
- This module works with connection C(network_cli) and C(httpapi).
- Tested against Cisco MDS NX-OS 9.2(2) with connection C(network_cli).
author: Nilashish Chakraborty (@NilashishC)
options:
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the NX-OS device
      by executing the command B(show running-config | include logging).
    - The state I(parsed) reads the configuration from C(running_config) option and
      transforms it into Ansible structured data as per the resource module's argspec
      and the value is then returned in the I(parsed) key within the result.
    type: str
  config:
    description: A dictionary of logging configuration.
    type: dict
    suboptions:
      console:
        description: Set console logging parameters.
        type: dict
        suboptions:
          state:
            description: Enable or disable monitor logging.
            type: str
            choices: ["enabled", "disabled"]
          severity: &sev
            description:  Set severity severity for console.
            type: str
            choices:
            - emergency
            - alert
            - critical
            - error
            - warning
            - notification
            - informational
            - debugging
      event:
        description: Interface events.
        type: dict
        suboptions:
          link_status:
            description: UPDOWN and CHANGE messages.
            type: dict
            suboptions: &event
              enable:
                description: To enable logging overriding port severity configuration.
                type: bool
              default:
                description: Default logging configuration used by interfaces not explicitly configured.
                type: bool
          trunk_status:
            description: TRUNK status messages.
            type: dict
            suboptions: *event
      history:
        description: Modifies severity severity or size for history table.
        type: dict
        suboptions:
          severity: *sev
          size:
            description: Set history table size.
            type: int
      ip:
        description:
          - IP configuration.
          - This option is unsupported on MDS switches.
        type: dict
        suboptions:
          access_list:
            description: Access-List.
            type: dict
            suboptions:
              cache:
                description: Set caching settings.
                type: dict
                suboptions:
                  entries:
                    description: Maximum number of log entries cached in software.
                    type: int
                  interval:
                    description: Log-update interval (in sec).
                    type: int
                  threshold:
                    description: Log-update threshold (number of hits)
                    type: int
              detailed:
                description: Detailed ACL information.
                type: bool
              include:
                description: Include additional fields in syslogs.
                type: dict
                suboptions:
                  sgt:
                    description: Include source group tag info in syslogs.
                    type: bool
      facilities:
        description: Facility parameter for syslog messages.
        type: list
        elements: dict
        suboptions:
          facility:
            description: Facility name.
            type: str
          severity: *sev
      logfile:
        description: Set file logging.
        type: dict
        suboptions:
          state:
            description: Enable or disable logfile.
            type: str
            choices: ["enabled", "disabled"]
          name:
            description: Logfile name.
            type: str
          severity: *sev
          persistent_threshold:
            description:
              - Set persistent logging utilization alert threshold in percentage.
              - This option is unsupported on MDS switches.
            type: int
          size:
            description: Enter the logfile size in bytes.
            type: int
      module:
        description: Set module(linecard) logging.
        type: dict
        suboptions:
          state:
            description: Enable or disable module logging.
            type: str
            choices: ["enabled", "disabled"]
          severity: *sev
      monitor:
        description: Set terminal line(monitor) logging severity.
        type: dict
        suboptions:
          state:
            description: Enable or disable monitor logging.
            type: str
            choices: ["enabled", "disabled"]
          severity: *sev
      origin_id:
        description: Enable origin information for Remote Syslog Server.
        type: dict
        suboptions:
          hostname:
            description:
              - Use hostname as origin-id of logging messages.
              - This option is mutually exclusive with I(ip) and I(string).
            type: bool
          ip:
            description:
              - Use ip address as origin-id of logging messages.
              - This option is mutually exclusive with I(hostname) and I(string).
            type: str
          string:
            description:
              - Use text string as origin-id of logging messages.
              - This option is mutually exclusive with I(hostname) and I(ip).
            type: str
      rate_limit:
        description: Enable or disable rate limit for log messages.
        type: str
        choices: ["enabled", "disabled"]
      rfc_strict:
        description:
          - Set RFC to which messages should compliant.
          - Syslogs will be compliant to RFC 5424.
          - This option is unsupported on MDS switches.
        type: bool
      hosts:
        description: Enable forwarding to Remote Syslog Servers.
        type: list
        elements: dict
        suboptions:
          host:
            description: Hostname/IPv4/IPv6 address of the Remote Syslog Server.
            type: str
          severity: *sev
          facility:
            description: Facility to use when forwarding to server.
            type: str
          port:
            description: Destination Port when forwarding to remote server.
            type: int
          secure:
            description: Enable secure connection to remote server.
            type: dict
            suboptions:
              trustpoint:
                description: Trustpoint configuration.
                type: dict
                suboptions:
                  client_identity:
                    description:
                      - Client Identity certificate for mutual authentication.
                      - Trustpoint to use for client certificate authentication.
                    type: str
          use_vrf:
            description:
              - Display per-VRF information.
              - This option is unsupported on MDS switches.
            type: str
      source_interface:
        description:
          - Enable Source-Interface for Remote Syslog Server.
          - This option is unsupported on MDS switches.
        type: str
      timestamp:
        description: Set logging timestamp granularity.
        type: str
        choices: ["microseconds", "milliseconds", "seconds"]
  state:
    description:
    - The state the configuration should be left in.
    - The states I(replaced) and I(overridden) have identical
      behaviour for this module.
    - Refer to examples for more details.
    type: str
    choices:
    - merged
    - replaced
    - overridden
    - deleted
    - parsed
    - gathered
    - rendered
    default: merged
"""
EXAMPLES = """
# Using merged

# Before state:
# -------------
# nxos-9k-rdo# show running-config | include logging
# nxos-9k-rdo#

- name: Merge the provided configuration with the existing running configuration
  cisco.nxos.nxos_logging_global:
    config:
      console:
        severity: error
      monitor:
        severity: warning
      ip:
        access_list:
          cache:
            entries: 16384
            interval: 200
            threshold: 5000
      facilities:
        - facility: auth
          severity: critical
        - facility: ospfv3
          severity: alert
        - facility: ftp
          severity: informational
      hosts:
        - host: 203.0.113.100
          severity: alert
          use_vrf: management
        - host: 203.0.113.101
          severity: error
          facility: local6
          use_vrf: default
      origin_id:
        hostname: true

# Task output
# -------------
#  before: {}
#
#  commands:
#    - "logging console 3"
#    - "logging monitor 4"
#    - "logging ip access-list cache entries 16384"
#    - "logging ip access-list cache interval 200"
#    - "logging ip access-list cache threshold 5000"
#    - "logging severity auth 2"
#    - "logging severity ospfv3 1"
#    - "logging severity ftp 6"
#    - "logging server 203.0.113.100 1 use-vrf management"
#    - "logging server 203.0.113.101 3 facility local6 use-vrf default"
#    - "logging origin-id hostname"
#
# after:
#   console:
#      severity: error
#    facilities:
#      - facility: auth
#        severity: critical
#      - facility: ftp
#        severity: informational
#      - facility: ospfv3
#        severity: alert
#    ip:
#      access_list:
#        cache:
#          entries: 16384
#          interval: 200
#          threshold: 5000
#    monitor:
#      severity: warning
#    origin_id:
#      hostname: true
#    hosts:
#      - severity: alert
#        host: 203.0.113.100
#        use_vrf: management
#      - facility: local6
#        severity: error
#        host: 203.0.113.101
#        use_vrf: default

# After state:
# ------------
# nxos-9k-rdo# show running-config | include logging
# logging console 3
# logging monitor 4
# logging ip access-list cache entries 16384
# logging ip access-list cache interval 200
# logging ip access-list cache threshold 5000
# logging severity auth 2
# logging severity ospfv3 1
# logging severity ftp 6
# logging origin-id hostname
# logging server 203.0.113.100 1 use-vrf management
# logging server 203.0.113.101 3 use-vrf default facility local6

# Using replaced

# Before state:
# ------------
# nxos-9k-rdo# show running-config | include logging
# logging console 3
# logging monitor 4
# logging ip access-list cache entries 16384
# logging ip access-list cache interval 200
# logging ip access-list cache threshold 5000
# logging severity auth 2
# logging severity ospfv3 1
# logging severity ftp 6
# logging origin-id hostname
# logging server 203.0.113.100 1 use-vrf management
# logging server 203.0.113.101 3 use-vrf default facility local6

- name: Replace logging configurations with provided config
  cisco.nxos.nxos_logging_global:
    config:
      monitor:
        severity: warning
      ip:
        access_list:
          cache:
            entries: 4096
      facilities:
        - facility: auth
          severity: critical
        - facility: ospfv3
          severity: alert
        - facility: ftp
          severity: informational
      hosts:
        - host: 203.0.113.101
          severity: error
          facility: local6
          use_vrf: default
        - host: 198.51.100.101
          severity: alert
          port: 6538
          use_vrf: management
      origin_id:
        ip: 192.0.2.100
    state: replaced

# Task output
# -------------
# before:
#   console:
#      severity: error
#    facilities:
#      - facility: auth
#        severity: critical
#      - facility: ftp
#        severity: informational
#      - facility: ospfv3
#        severity: alert
#    ip:
#      access_list:
#        cache:
#          entries: 16384
#          interval: 200
#          threshold: 5000
#    monitor:
#      severity: warning
#    origin_id:
#      hostname: true
#    hosts:
#      - severity: alert
#        host: 203.0.113.100
#        use_vrf: management
#      - facility: local6
#        severity: error
#        host: 203.0.113.101
#        use_vrf: default
#
# commands:
#   - "logging console"
#   - "logging ip access-list cache entries 4096"
#   - "no logging ip access-list cache interval 200"
#   - "no logging ip access-list cache threshold 5000"
#   - "no logging origin-id hostname"
#   - "logging origin-id ip 192.0.2.100"
#   - "logging server 198.51.100.101 1 port 6538 use-vrf management"
#   - "no logging server 203.0.113.100 1 use-vrf management"
#
#  after:
#    facilities:
#      - facility: auth
#        severity: critical
#      - facility: ftp
#        severity: informational
#      - facility: ospfv3
#        severity: alert
#    ip:
#      access_list:
#        cache:
#          entries: 4096
#    monitor:
#      severity: warning
#    origin_id:
#      ip: 192.0.2.100
#    hosts:
#      - severity: alert
#        port: 6538
#        host: 198.51.100.101
#        use_vrf: management
#      - facility: local6
#        severity: error
#        host: 203.0.113.101
#        use_vrf: default
#
# After state:
# ------------
# nxos-9k-rdo# show running-config | include logging
# logging monitor 4
# logging ip access-list cache entries 4096
# logging severity auth 2
# logging severity ospfv3 1
# logging severity ftp 6
# logging origin-id ip 192.0.2.100
# logging server 203.0.113.101 3 use-vrf default facility local6
# logging server 198.51.100.101 1 port 6538 use-vrf management

# Using deleted to delete all logging configurations

# Before state:
# ------------
# nxos-9k-rdo# show running-config | include logging
# logging console 3
# logging monitor 4
# logging ip access-list cache entries 16384
# logging ip access-list cache interval 200
# logging ip access-list cache threshold 5000
# logging severity auth 2
# logging severity ospfv3 1
# logging severity ftp 6
# logging origin-id hostname
# logging server 203.0.113.100 1 use-vrf management
# logging server 203.0.113.101 3 use-vrf default facility local6

- name: Delete all logging configuration
  cisco.nxos.nxos_logging_global:
    state: deleted

# Task output
# -------------
# before:
#   console:
#      severity: error
#    facilities:
#      - facility: auth
#        severity: critical
#      - facility: ftp
#        severity: informational
#      - facility: ospfv3
#        severity: alert
#    ip:
#      access_list:
#        cache:
#          entries: 16384
#          interval: 200
#          threshold: 5000
#    monitor:
#      severity: warning
#    origin_id:
#      hostname: true
#    hosts:
#      - severity: alert
#        host: 203.0.113.100
#        use_vrf: management
#      - facility: local6
#        severity: error
#        host: 203.0.113.101
#        use_vrf: default
#
# commands:
#   - "logging console"
#   - "logging monitor"
#   - "no logging ip access-list cache entries 16384"
#   - "no logging ip access-list cache interval 200"
#   - "no logging ip access-list cache threshold 5000"
#   - "no logging origin-id hostname"
#   - "no logging severity auth 2"
#   - "no logging severity ospfv3 1"
#   - "no logging severity ftp 6"
#   - "no logging server 203.0.113.100 1 use-vrf management"
#   - "no logging server 203.0.113.101 3 facility local6 use-vrf default"
#
# after: {}

# Using rendered

- name: Render platform specific configuration lines with state rendered (without connecting to the device)
  cisco.nxos.nxos_logging_global:
    config:
      console:
        severity: error
      monitor:
        severity: warning
      ip:
        access_list:
          cache:
            entries: 16384
            interval: 200
            threshold: 5000
      facilities:
        - facility: auth
          severity: critical
        - facility: ospfv3
          severity: alert
        - facility: ftp
          severity: informational
      hosts:
        - host: 203.0.113.100
          severity: alert
          use_vrf: management
        - host: 203.0.113.101
          severity: error
          facility: local6
          use_vrf: default
      origin_id:
        hostname: true

# Task Output (redacted)
# -----------------------
#  rendered:
#    - "logging console 3"
#    - "logging monitor 4"
#    - "logging ip access-list cache entries 16384"
#    - "logging ip access-list cache interval 200"
#    - "logging ip access-list cache threshold 5000"
#    - "logging severity auth 2"
#    - "logging severity ospfv3 1"
#    - "logging severity ftp 6"
#    - "logging server 203.0.113.100 1 use-vrf management"
#    - "logging server 203.0.113.101 3 facility local6 use-vrf default"
#    - "logging origin-id hostname"

# Using parsed

# parsed.cfg
# ------------
# logging console 3
# logging monitor 4
# logging ip access-list cache entries 16384
# logging ip access-list cache interval 200
# logging ip access-list cache threshold 5000
# logging severity auth 2
# logging severity ospfv3 1
# logging severity ftp 6
# logging origin-id hostname
# logging server 203.0.113.100 1 use-vrf management
# logging server 203.0.113.101 3 use-vrf default facility local6

- name: Parse externally provided logging configuration
  cisco.nxos.nxos_logging_global:
    running_config: "{{ lookup('file', './fixtures/parsed.cfg') }}"
    state: parsed

# Task output (redacted)
# -----------------------
# parsed:
#   console:
#      severity: error
#    facilities:
#      - facility: auth
#        severity: critical
#      - facility: ftp
#        severity: informational
#      - facility: ospfv3
#        severity: alert
#    ip:
#      access_list:
#        cache:
#          entries: 16384
#          interval: 200
#          threshold: 5000
#    monitor:
#      severity: warning
#    origin_id:
#      hostname: true
#    hosts:
#      - severity: alert
#        host: 203.0.113.100
#        use_vrf: management
#      - facility: local6
#        severity: error
#        host: 203.0.113.101
#        use_vrf: default
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
    - "logging console 3"
    - "logging monitor 4"
    - "logging ip access-list cache entries 16384"
    - "logging ip access-list cache interval 200"
    - "logging ip access-list cache threshold 5000"
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when state is I(rendered)
  type: list
  sample:
    - "logging ip access-list cache entries 4096"
    - "no logging ip access-list cache interval 200"
    - "no logging ip access-list cache threshold 5000"
    - "no logging origin-id hostname"
    - "logging origin-id ip 192.0.2.100"
    - "logging server 198.51.100.101 1 port 6538 use-vrf management"
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

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.logging_global.logging_global import (
    Logging_globalArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.logging_global.logging_global import (
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
