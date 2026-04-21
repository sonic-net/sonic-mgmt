#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_prefix_lists
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: iosxr_prefix_lists
short_description: Resource module to configure prefix lists.
description:
- This module manages prefix-lists configuration on devices running Cisco IOSXR.
version_added: 2.3.0
notes:
- Tested against IOSXR 7.0.2.
- This module works with connection C(network_cli).
author: Ashwini Mhatre (@amhatre)
options:
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the Iosxr device by
        executing the command B(show running-config prefix-list).
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
    type: str
  config:
    description: A list of prefix-lists configuration.
    type: list
    elements: dict
    suboptions:
      afi:
        description:
        - The Address Family Identifier (AFI) for the prefix-lists.
        type: str
        choices: ["ipv4", "ipv6"]
      prefix_lists:
        description: List of prefix-list configurations.
        type: list
        elements: dict
        suboptions:
          name:
            description: Name of the prefix-list.
            type: str
          entries:
            description: List of configurations for the specified prefix-list
            type: list
            elements: dict
            suboptions:
              sequence:
                description: Sequence Number.
                type: int
              action:
                description: Prefix-List permit or deny.
                type: str
                choices: ["permit", "deny", "remark"]
              description:
                description: Description of the prefix list. only applicable for action "remark".
                type: str
              prefix:
                description: IP or IPv6 prefix in A.B.C.D/LEN or A:B::C:D/LEN format. only applicable for action "permit" and "deny"
                type: str
              eq:
                description: Exact prefix length to be matched.
                type: int
              ge:
                description: Minimum prefix length to be matched.
                type: int
              le:
                description: Maximum prefix length to be matched.
                type: int
  state:
    description:
    - The state the configuration should be left in.
    - Refer to examples for more details.
    - With state I(replaced), for the listed prefix-lists,
      sequences that are in running-config but not in the task are negated.
    - With state I(overridden), all prefix-lists that are in running-config but
      not in the task are negated.
    - Please refer to examples for more details.
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


# Before state
# RP/0/0/CPU0:10#show running-config
# Thu Feb  4 09:38:36.245 UTC
# % No such configuration item(s)
# RP/0/0/CPU0:10#
#


- name: Merge the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_prefix_lists:
    state: merged
    config:
      - afi: ipv6
        prefix_lists:
          - name: pl_1
            entries:
              - prefix: '2001:db8:1234::/48'
                action: deny
                sequence: 1
          - name: pl_2
            entries:
              - sequence: 2
                action: remark
                description: TEST_PL_2_REMARK
      - afi: ipv4
        prefix_lists:
          - name: pl1
            entries:
              - sequence: 3
                action: remark
                description: TEST_PL1_2_REMARK
              - sequence: 4
                action: permit
                prefix: 10.0.0.0/24
          - name: pl2
            entries:
              - sequence: 5
                action: remark
                description: TEST_PL2_REMARK
          - name: pl3
            entries:
              - sequence: 6
                action: permit
                prefix: 35.0.0.0/8
                eq: 0

# Task Output
# -------------
# before: []
# commands:
# - ipv6 prefix-list pl_1 1 deny 2001:db8:1234::/48
# - ipv6 prefix-list pl_2 2 remark TEST_PL_2_REMARK
# - ipv4 prefix-list pl1 3 remark TEST_PL1_2_REMARK
# - ipv4 prefix-list pl1 4 permit 10.0.0.0/24
# - ipv4 prefix-list pl2 5 remark TEST_PL2_REMARK
# - ipv4 prefix-list pl3 6 permit 35.0.0.0/8 eq 0
# after:
# - afi: ipv6
#   prefix_lists:
#   - name: pl_1
#     entries:
#     - prefix: 2001:db8:1234::/48
#       action: deny
#       sequence: 1
#   - name: pl_2
#     entries:
#     - sequence: 2
#       action: remark
#       description: TEST_PL_2_REMARK
# - afi: ipv4
#   prefix_lists:
#   - name: pl1
#     entries:
#     - sequence: 3
#       action: remark
#       description: TEST_PL1_2_REMARK
#     - sequence: 4
#       action: permit
#       prefix: 10.0.0.0/24
#   - name: pl2
#     entries:
#     - sequence: 5
#       action: remark
#       description: TEST_PL2_REMARK
#   - name: pl3
#     entries:
#     - sequence: 6
#       action: permit
#       prefix: 35.0.0.0/8
#       eq: 0


# After state:
# ------------
# RP/0/0/CPU0:10#show running-config
# ipv6 prefix-list pl_1
#  1 deny 2001:db8:1234::/48
# !
# ipv6 prefix-list pl_2
#  2 remark TEST_PL_2_REMAR
# !
# ipv4 prefix-list pl1
#  3 remark TEST_PL1_2_REMARK
#  4 permit 10.0.0.0/24
# !
# ipv4 prefix-list pl2
#  5 remark TEST_PL2_REMARK
# !
# ipv4 prefix-list pl3
#  6 permit 35.0.0.0/8 eq 0
# !


# Using replaced:


# Before state:
# -------------
# RP/0/0/CPU0:10#show running-config
#
# ipv6 prefix-list pl_1
#  1 deny 2001:db8:1234::/48
# !
# ipv6 prefix-list pl_2
#  2 remark TEST_PL_2_REMARK
# !
# ipv4 prefix-list pl1
#  3 remark TEST_PL1_2_REMARK
#  4 permit 10.0.0.0/24
# !
# ipv4 prefix-list pl2
#  5 remark TEST_PL2_REMARK
# !
#


- name: >-
    Replace device configurations of listed prefix lists with provided
    configurations
  register: result
  cisco.iosxr.iosxr_prefix_lists:
    config:
      - afi: ipv4
        prefix_lists:
          - name: pl1
            entries:
              - sequence: 3
                action: permit
                prefix: 10.0.0.0/24
      - afi: ipv6
        prefix_lists:
          - name: pl_1
            entries:
              - prefix: '2001:db8:1234::/48'
                action: permit
                sequence: 1
          - name: pl_2
            entries:
              - sequence: 2
                action: remark
                description: TEST_PL1_2
    state: replaced


# Task Output
# -------------
# before:
# - afi: ipv6
#   prefix_lists:
#   - entries:
#     - action: deny
#       prefix: 2001:db8:1234::/48
#       sequence: 1
#     name: pl_1
#   - entries:
#     - action: remark
#       description: TEST_PL_2_REMARK
#       sequence: 2
#     name: pl_2
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: remark
#       description: TEST_PL1_2_REMARK
#       sequence: 3
#     - action: permit
#       prefix: 10.0.0.0/24
#       sequence: 4
#     name: pl1
#   - entries:
#     - action: remark
#       description: TEST_PL2_REMARK
#       sequence: 5
#     name: pl2
# commands:
# - no ipv4 prefix-list pl1 3 remark TEST_PL1_2_REMARK
# - no ipv4 prefix-list pl1 4 permit 10.0.0.0/24
# - ipv4 prefix-list pl1 3 permit 10.0.0.0/24
# - ipv6 prefix-list pl_2 2 remark TEST_PL1_2
# after:
# - afi: ipv6
#   prefix_lists:
#   - entries:
#     - action: deny
#       prefix: 2001:db8:1234::/48
#       sequence: 1
#     name: pl_1
#   - entries:
#     - action: remark
#       description: TEST_PL1_2
#       sequence: 2
#     name: pl_2
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: permit
#       prefix: 10.0.0.0/24
#       sequence: 3
#     name: pl1
#   - entries:
#     - action: remark
#       description: TEST_PL2_REMARK
#       sequence: 5
#     name: pl2


# After state:
# RP/0/0/CPU0:10#show running-config
#
# ipv6 prefix-list pl_1
#  1 deny 2001:db8:1234::/48
# !
# ipv6 prefix-list pl_2
#  2 remark TEST_PL1_2
# !
# ipv4 prefix-list pl1
#  3 permit 10.0.0.0/24
# !
# ipv4 prefix-list pl2
#  5 remark TEST_PL2_REMARK
#
# Module Execution:
#


# Using deleted:


# Before state:
# -------------
# RP/0/0/CPU0:10#show running-config
#
# ipv6 prefix-list pl_1
#  1 deny 2001:db8:1234::/48
# !
# ipv6 prefix-list pl_2
#  2 remark TEST_PL_2_REMARK
# !
# ipv4 prefix-list pl1
#  3 remark TEST_PL1_2_REMARK
#  4 permit 10.0.0.0/24
# !
# ipv4 prefix-list pl2
#  5 remark TEST_PL2_REMARK
# ipv4 prefix-list pl3
#  6 permit 35.0.0.0/8 eq 0

- name: Delete all prefix-lists from the device
  cisco.iosxr.iosxr_prefix_lists:
    state: deleted

# Task Output
# -------------
# before:
# - afi: ipv6
#   prefix_lists:
#   - name: pl_1
#     entries:
#     - prefix: 2001:db8:1234::/48
#       action: deny
#       sequence: 1
#   - name: pl_2
#     entries:
#     - sequence: 2
#       action: remark
#       description: TEST_PL_2_REMARK
# - afi: ipv4
#   prefix_lists:
#   - name: pl1
#     entries:
#     - sequence: 3
#       action: remark
#       description: TEST_PL1_2_REMARK
#     - sequence: 4
#       action: permit
#       prefix: 10.0.0.0/24
#   - name: pl2
#     entries:
#     - sequence: 5
#       action: remark
#       description: TEST_PL2_REMARK
#   - name: pl3
#     entries:
#     - sequence: 6
#       action: permit
#       prefix: 35.0.0.0/8
#       eq: 0
# commands:
# - no ipv6 prefix-list pl_1
# - no ipv6 prefix-list pl_2
# - no ipv4 prefix-list pl1
# - no ipv4 prefix-list pl2
# - no ipv4 prefix-list pl3
# after: []


# After state:
# RP/0/0/CPU0:10#show running-config
#

# using gathered:


# After state:
# ------------
# RP/0/0/CPU0:10#show running-config
# ipv6 prefix-list pl_1
#  1 deny 2001:db8:1234::/48
# !
# ipv6 prefix-list pl_2
#  2 remark TEST_PL_2_REMARK
# !
# ipv4 prefix-list pl1
#  3 remark TEST_PL1_2_REMARK
#  4 permit 10.0.0.0/24
# !
# ipv4 prefix-list pl2
#  5 remark TEST_PL2_REMARK
# !
# ipv4 prefix-list pl3
#  6 permit 35.0.0.0/8 eq 0
# !


- name: Gather ACL interfaces facts using gathered state
  cisco.iosxr.iosxr_prefix_lists:
    state: gathered

# gathered:
# - afi: ipv6
#   prefix_lists:
#   - name: pl_1
#     entries:
#     - prefix: 2001:db8:1234::/48
#       action: deny
#       sequence: 1
#   - name: pl_2
#     entries:
#     - sequence: 2
#       action: remark
#       description: TEST_PL_2_REMARK
# - afi: ipv4
#   prefix_lists:
#   - name: pl1
#     entries:
#     - sequence: 3
#       action: remark
#       description: TEST_PL1_2_REMARK
#     - sequence: 4
#       action: permit
#       prefix: 10.0.0.0/24
#   - name: pl2
#     entries:
#     - sequence: 5
#       action: remark
#       description: TEST_PL2_REMARK
#   - name: pl3
#     entries:
#     - sequence: 6
#       action: permit
#       prefix: 35.0.0.0/8
#       eq: 0


# Using parsed:


# parsed.cfg
# ------------------------------
# ipv6 prefix-list pl_1
#  1 deny 2001:db8:1234::/48
# !
# ipv6 prefix-list pl_2
#  2 remark TEST_PL_2_REMARK
# !
# ipv4 prefix-list pl1
#  3 remark TEST_PL1_2_REMARK
#  4 permit 10.0.0.0/24
# !
# ipv4 prefix-list pl2
#  5 remark TEST_PL2_REMARK


- name: Parse externally provided Prefix_lists config to agnostic model
  cisco.iosxr.iosxr_prefix_lists:
    running_config: '{{ lookup(''file'', ''./fixtures/parsed.cfg'') }}'
    state: parsed


# Task Output
# -------------
# parsed:
# - afi: ipv6
#   prefix_lists:
#   - name: pl_1
#     entries:
#     - prefix: 2001:db8:1234::/48
#       action: deny
#       sequence: 1
#   - name: pl_2
#     entries:
#     - sequence: 2
#       action: remark
#       description: TEST_PL_2_REMARK
# - afi: ipv4
#   prefix_lists:
#   - name: pl1
#     entries:
#     - sequence: 3
#       action: remark
#       description: TEST_PL1_2_REMARK
#     - sequence: 4
#       action: permit
#       prefix: 10.0.0.0/24
#   - name: pl2
#     entries:
#     - sequence: 5
#       action: remark
#       description: TEST_PL2_REMARK
#     - sequence: 6
#       action: permit
#       prefix: 35.0.0.0/8
#       eq: 0


# Using rendered:


- name: Render platform specific commands from task input using rendered state
  register: result
  cisco.iosxr.iosxr_prefix_lists:
    config:
      - afi: ipv6
        prefix_lists:
          - name: pl_1
            entries:
              - prefix: '2001:db8:1234::/48'
                action: deny
                sequence: 1
          - name: pl_2
            entries:
              - sequence: 2
                action: remark
                description: TEST_PL_2_REMARK
      - afi: ipv4
        prefix_lists:
          - name: pl1
            entries:
              - sequence: 3
                action: remark
                description: TEST_PL1_2_REMARK
              - sequence: 4
                action: permit
                prefix: 10.0.0.0/24
          - name: pl2
            entries:
              - sequence: 5
                action: remark
                description: TEST_PL2_REMARK
              - sequence: 6
                action: permit
                prefix: 35.0.0.0/8
                eq: 0
    state: rendered


# Task Output
# -------------
# "rendered": [
#         "ipv6 prefix-list pl_1 1 deny 2001:db8:1234::/48",
#         "ipv6 prefix-list pl_2 2 remark TEST_PL_2_REMARK",
#         "ipv4 prefix-list pl1 3 remark TEST_PL1_2_REMARK",
#         "ipv4 prefix-list pl1 4 permit 10.0.0.0/24",
#         "ipv4 prefix-list pl2 5 remark TEST_PL2_REMARK",
#         "ipv4 prefix-list pl2 6 permit 35.0.0.0/8 eq 0"
#     ]

# Using overridden:


# Before state:
# -------------
# RP/0/0/CPU0:10#show running-config
#
# ipv6 prefix-list pl_1
#  1 deny 2001:db8:1234::/48
# !
# ipv6 prefix-list pl_2
#  2 remark TEST_PL_2_REMARK
# !
# ipv4 prefix-list pl1
#  3 remark TEST_PL1_2_REMARK
#  4 permit 10.0.0.0/24
# !
# ipv4 prefix-list pl2
#  5 remark TEST_PL2_REMARK
#
- name: Overridde all Prefix_lists configuration with provided configuration
  cisco.iosxr.iosxr_prefix_lists:
    config:
      - afi: ipv4
        prefix_lists:
          - name: pl3
            entries:
              - sequence: 3
                action: remark
                description: TEST_PL1_3_REMARK
              - sequence: 4
                action: permit
                prefix: 10.0.0.0/24
              - sequence: 6
                action: permit
                prefix: 35.0.0.0/8
                eq: 0
    state: overridden


# Task Output
# -------------
# before:
# - afi: ipv6
#   prefix_lists:
#   - entries:
#     - action: deny
#       prefix: 2001:db8:1234::/48
#       sequence: 1
#     name: pl_1
#   - entries:
#     - action: remark
#       description: TEST_PL_2_REMARK
#       sequence: 2
#     name: pl_2
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: remark
#       description: TEST_PL1_2_REMARK
#       sequence: 3
#     - action: permit
#       prefix: 10.0.0.0/24
#       sequence: 4
#     name: pl1
#   - entries:
#     - action: remark
#       description: TEST_PL2_REMARK
#       sequence: 5
#     name: pl2
# commands:
# - no ipv6 prefix-list pl_1
# - no ipv6 prefix-list pl_2
# - no ipv4 prefix-list pl1
# - no ipv4 prefix-list pl2
# - ipv4 prefix-list pl3 3 remark TEST_PL1_3_REMARK
# - ipv4 prefix-list pl3 4 permit 10.0.0.0/24
# - ipv4 prefix-list pl3 6 permit 35.0.0.0/8 eq 0
# after:
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: remark
#       description: TEST_PL1_3_REMARK
#       sequence: 3
#     - action: permit
#       prefix: 10.0.0.0/24
#       sequence: 4
#     - action: permit
#       prefix: 35.0.0.0/8
#       sequence: 6
#       eq: 0
#     name: pl3


# After state:
# RP/0/0/CPU0:10#show running-config
#
# ipv4 prefix-list pl3
# 3 remark TEST_PL1_3_REMARK
# 4 permit 10.0.0.0/24
# 6 permit 35.0.0.0/8 eq 0
# !
# !
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
    - "ipv6 prefix-list pl_1 1 deny 2001:db8:1234::/48"
    - "ipv6 prefix-list pl_2 2 remark TEST_PL_2_REMARK"
    - "ipv4 prefix-list pl1 3 remark TEST_PL1_2_REMARK"
    - "ipv4 prefix-list pl1 4 permit 10.0.0.0/24"
    - "ipv4 prefix-list pl2 5 remark TEST_PL2_REMARK"
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - "ipv6 prefix-list pl_1 1 deny 2001:db8:1234::/48"
    - "ipv6 prefix-list pl_2 2 remark TEST_PL_2_REMARK"
    - "ipv4 prefix-list pl1 3 remark TEST_PL1_2_REMARK"
    - "ipv4 prefix-list pl1 4 permit 10.0.0.0/24"
    - "ipv4 prefix-list pl2 5 remark TEST_PL2_REMARK"
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

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.prefix_lists.prefix_lists import (
    Prefix_listsArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.prefix_lists.prefix_lists import (
    Prefix_lists,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Prefix_listsArgs.argument_spec,
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

    result = Prefix_lists(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
