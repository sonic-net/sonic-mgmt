#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for eos_prefix_lists
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: eos_prefix_lists
short_description: Manages Prefix lists resource module
description: This module configures and manages the attributes of Prefix lists on Arista
  EOS platforms.
version_added: 2.2.0
author: Gomathi Selvi Srinivasan (@GomathiselviS)
notes:
- Tested against Arista EOS 4.24.6F
- This module works with connection C(network_cli). See the L(EOS Platform Options,eos_platform_options).
options:
   config:
      description: A list of dictionary of prefix-list options
      type: list
      elements: dict
      suboptions:
        afi:
          description:
          - The Address Family Indicator (AFI) for the  prefix list.
          type: str
          required: true
          choices:
          - ipv4
          - ipv6
        prefix_lists:
          description:
          - A list of prefix-lists.
          type: list
          elements: dict
          suboptions:
            name:
              description: Name of the prefix-list
              type: str
              required: true
            entries:
              description: List of prefix-lists
              type: list
              elements: dict
              suboptions:
                action:
                  description: action to be performed on the specified path
                  type: str
                  choices: ['deny', 'permit']
                address:
                  description: ipv4/v6 address in prefix-mask or address-masklen format
                  type: str
                match:
                  description: match masklen
                  type: dict
                  suboptions:
                    operator:
                      description: equalto/greater than/lesser than
                      type: str
                      choices: ['eq', 'le', 'ge']
                    masklen:
                      description: Mask Length.
                      type: int
                sequence:
                  description: sequence number
                  type: int
                resequence:
                  description: Resequence the list.
                  type: dict
                  suboptions:
                    default:
                      description: Resequence with default values (10).
                      type: bool
                    start_seq:
                      description: Starting sequence number.
                      type: int
                    step:
                      description: Step to increment the sequence number.
                      type: int
   running_config:
      description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the EOS device by
        executing the command B(show running-config | section access-list).
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
# veos#show running-config | section prefix-lists
# veos#

- name: Merge provided configuration with device configuration
  arista.eos.eos_prefix_lists:
    config:
      - afi: "ipv4"
        prefix_lists:
          - name: "v401"
            entries:
              - sequence: 25
                action: "deny"
                address: "45.55.4.0/24"
              - sequence: 100
                action: "permit"
                address: "11.11.2.0/24"
                match:
                  masklen: 32
                  operator: "ge"
          - name: "v402"
            entries:
              - action: "deny"
                address: "10.1.1.0/24"
                sequence: 10
                match:
                  masklen: 32
                  operator: "ge"
      - afi: "ipv6"
        prefix_lists:
          - name: "v601"
            entries:
              - sequence: 125
                action: "deny"
                address: "5000:1::/64"

# Task Output
# -------------
# before: {}
# commands:
# - ipv6 prefix-list v601
# - seq 125 deny 5000:1::/64
# - ip prefix-list v401
# - seq 25 deny 45.55.4.0/24
# - seq 100 permit 11.11.2.0/24 ge 32
# - ip prefix-list v402
# - seq 10 deny 10.1.1.0/24 ge 32
# after:
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 45.55.4.0/24
#       sequence: 25
#     - action: permit
#       address: 11.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 100
#     name: v401
#   - entries:
#     - action: deny
#       address: 10.1.1.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 10
#     name: v402
# - afi: ipv6
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 5000:1::/64
#       sequence: 125
#     name: v601


# After state:
# ------------
# veos#
# veos#show running-config | section prefix-list
# ip prefix-list v401
#    seq 25 deny 45.55.4.0/24
#    seq 100 permit 11.11.2.0/24 ge 32
# !
# ip prefix-list v402
#    seq 10 deny 10.1.1.0/24 ge 32
# !
# ipv6 prefix-list v601
#    seq 125 deny 5000:1::/64
# veos#


# Using merged:
# Failure scenario : 'merged' should not be used when an existing prefix-list (sequence number)
# is to be modified.


# veos#show running-config | section prefix-list
# ip prefix-list v401
#    seq 25 deny 45.55.4.0/24
#    seq 100 permit 11.11.2.0/24 ge 32
# !
# ip prefix-list v402
#    seq 10 deny 10.1.1.0/24 ge 32
# !
# ipv6 prefix-list v601
#    seq 125 deny 5000:1::/64
# veos#

- name: Merge provided configuration with device configuration
  arista.eos.eos_prefix_lists:
    config:
      - afi: "ipv4"
        prefix_lists:
          - name: "v401"
            entries:
              - sequence: 25
                action: "deny"
                address: "45.55.4.0/24"
                match:
                  masklen: 32
                  operator: "ge"
              - sequence: 100
                action: "permit"
                address: "11.11.2.0/24"
                match:
                  masklen: 32
                  operator: "ge"
          - name: "v402"
            entries:
              - action: "deny"
                address: "10.1.1.0/24"
                sequence: 10
                match:
                  masklen: 32
                  operator: "ge"
      - afi: "ipv6"
        prefix_lists:
          - name: "v601"
            entries:
              - sequence: 125
                action: "deny"
                address: "5000:1::/64"
    state: merged

# Task Output
# -------------
# changed: false
# invocation:
#   module_args:
#     config:
#     - afi: ipv4
#       prefix_lists:
#       - entries:
#         - action: deny
#           address: 45.55.4.0/24
#           match:
#             masklen: 32
#             operator: ge
#           resequence:
#           sequence: 25
#         - action: permit
#           address: 11.11.2.0/24
#           match:
#             masklen: 32
#             operator: ge
#           resequence:
#           sequence: 100
#         name: v401
#       - entries:
#         - action: deny
#           address: 10.1.1.0/24
#           match:
#             masklen: 32
#             operator: ge
#           resequence:
#           sequence: 10
#         name: v402
#     - afi: ipv6
#       prefix_lists:
#       - entries:
#         - action: deny
#           address: 5000:1::/64
#           match:
#           resequence:
#           sequence: 125
#         name: v601
#     running_config:
#     state: merged
# msg: Sequence number 25 is already present. Use replaced/overridden operation to change
#   the configuration


# Using Replaced:

# Before state:
# veos#show running-config | section prefix-list
# ip prefix-list v401
#    seq 25 deny 45.55.4.0/24
#    seq 100 permit 11.11.2.0/24 ge 32
# !
# ip prefix-list v402
#    seq 10 deny 10.1.1.0/24 ge 32
# !
# ipv6 prefix-list v601
#    seq 125 deny 5000:1::/64
# veos#


- name: Replace Provided configuration with given configuration
  arista.eos.eos_prefix_lists:
    config:
      - afi: "ipv4"
        prefix_lists:
          - name: "v401"
            entries:
              - sequence: 25
                action: "deny"
                address: "45.55.4.0/24"
                match:
                  masklen: 32
                  operator: "ge"
              - sequence: 200
                action: "permit"
                address: "200.11.2.0/24"
                match:
                  masklen: 32
                  operator: "ge"
    state: replaced


# Task Output
# -------------
# before:
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 45.55.4.0/24
#       sequence: 25
#     - action: permit
#       address: 11.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 100
#     name: v401
#   - entries:
#     - action: deny
#       address: 10.1.1.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 10
#     name: v402
# - afi: ipv6
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 5000:1::/64
#       sequence: 125
#     name: v601
# commands:
# - ip prefix-list v401
# - no seq 25
# - seq 25 deny 45.55.4.0/24 ge 32
# - seq 200 permit 200.11.2.0/24 ge 32
# - no seq 100
# - no ip prefix-list v402
# after:
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 45.55.4.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 25
#     - action: permit
#       address: 200.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 200
#     name: v401
# - afi: ipv6
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 5000:1::/64
#       sequence: 125
#     name: v601


# After State:
# veos#show running-config | section prefix-list
# ip prefix-list v401
#    seq 25 deny 45.55.4.0/24 ge 32
#    seq 200 permit 200.11.2.0/24 ge 32
# !
# ipv6 prefix-list v601
#    seq 125 deny 5000:1::/64
# veos#
#
#


# Using overridden:


# Before State:
# veos#show running-config | section prefix-list
# ip prefix-list v401
#    seq 25 deny 45.55.4.0/24 ge 32
#    seq 100 permit 11.11.2.0/24 ge 32
#    seq 200 permit 200.11.2.0/24 ge 32
# !
# ip prefix-list v402
#    seq 10 deny 10.1.1.0/24 ge 32
# !
# ipv6 prefix-list v601
#    seq 125 deny 5000:1::/64
# veos#

- name: Override
  arista.eos.eos_prefix_lists:
    config:
      - afi: "ipv4"
        prefix_lists:
          - name: "v401"
            entries:
              - sequence: 25
                action: "deny"
                address: "45.55.4.0/24"
              - sequence: 300
                action: "permit"
                address: "30.11.2.0/24"
                match:
                  masklen: 32
                  operator: "ge"
          - name: "v403"
            entries:
              - action: "deny"
                address: "10.1.1.0/24"
                sequence: 10
    state: overridden


# Task Output
# -------------
# before:
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 45.55.4.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 25
#     - action: permit
#       address: 11.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 100
#     - action: permit
#       address: 200.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 200
#     name: v401
#   - entries:
#     - action: deny
#       address: 10.1.1.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 10
#     name: v402
# - afi: ipv6
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 5000:1::/64
#       sequence: 125
#     name: v601
# commands:
# - no ipv6 prefix-list v601
# - ip prefix-list v401
# - seq 25 deny 45.55.4.0/24
# - seq 300 permit 30.11.2.0/24 ge 32
# - no seq 100
# - no seq 200
# - ip prefix-list v403
# - seq 10 deny 10.1.1.0/24
# - no ip prefix-list v402
# after:
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 45.55.4.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 25
#     - action: permit
#       address: 30.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 300
#     name: v401
#   - entries:
#     - action: deny
#       address: 10.1.1.0/24
#       sequence: 10
#     name: v403


# After State
# veos#
# veos#show running-config | section prefix-list
# ip prefix-list v401
#    seq 25 deny 45.55.4.0/24 ge 32
#    seq 300 permit 30.11.2.0/24 ge 32
# !
# ip prefix-list v403
#    seq 10 deny 10.1.1.0/24
# veos#

# Using deleted:

# Before State:
# veos#show running-config | section prefix-list
# ip prefix-list v401
#    seq 25 deny 45.55.4.0/24 ge 32
#    seq 100 permit 11.11.2.0/24 ge 32
#    seq 300 permit 30.11.2.0/24 ge 32
# !
# ip prefix-list v402
#    seq 10 deny 10.1.1.0/24 ge 32
# !
# ip prefix-list v403
#    seq 10 deny 10.1.1.0/24
# !
# ipv6 prefix-list v601
#    seq 125 deny 5000:1::/64
# veos#

- name: Delete device configuration
  arista.eos.eos_prefix_lists:
    config:
      - afi: "ipv6"
    state: deleted

# Task Output
# -------------
# before:
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 45.55.4.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 25
#     - action: permit
#       address: 11.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 100
#     - action: permit
#       address: 30.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 300
#     name: v401
#   - entries:
#     - action: deny
#       address: 10.1.1.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 10
#     name: v402
#   - entries:
#     - action: deny
#       address: 10.1.1.0/24
#       sequence: 10
#     name: v403
# - afi: ipv6
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 5000:1::/64
#       sequence: 125
#     name: v601
# commands:
# - no ipv6 prefix-list v601
# after:
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 45.55.4.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 25
#     - action: permit
#       address: 11.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 100
#     - action: permit
#       address: 30.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 300
#     name: v401
#   - entries:
#     - action: deny
#       address: 10.1.1.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 10
#     name: v402
#   - entries:
#     - action: deny
#       address: 10.1.1.0/24
#       sequence: 10
#     name: v403

# after State:
# veos#show running-config | section prefix-list
# ip prefix-list v401
#    seq 25 deny 45.55.4.0/24 ge 32
#    seq 100 permit 11.11.2.0/24 ge 32
#    seq 300 permit 30.11.2.0/24 ge 32
# !
# ip prefix-list v402
#    seq 10 deny 10.1.1.0/24 ge 32
# !
# ip prefix-list v403
#    seq 10 deny 10.1.1.0/24
#


# Using deleted


# Before state:
# veos#show running-config | section prefix-list
# ip prefix-list v401
#    seq 25 deny 45.55.4.0/24 ge 32
#    seq 100 permit 11.11.2.0/24 ge 32
#    seq 300 permit 30.11.2.0/24 ge 32
# !
# ip prefix-list v402
#    seq 10 deny 10.1.1.0/24 ge 32
# !
# ip prefix-list v403
#    seq 10 deny 10.1.1.0/24
# veos#

- name: Delete device configuration
  arista.eos.eos_prefix_lists:
    state: deleted


# Task Output
# -------------
# before:
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 45.55.4.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 25
#     - action: permit
#       address: 11.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 100
#     - action: permit
#       address: 30.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 300
#     name: v401
#   - entries:
#     - action: deny
#       address: 10.1.1.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 10
#     name: v402
#   - entries:
#     - action: deny
#       address: 10.1.1.0/24
#       sequence: 10
#     name: v403
# commands:
# - no ip prefix-list v401
# - no ip prefix-list v402
# - no ip prefix-list v403
# after: {}

# After State:
# veos#show running-config | section prefix-list
# veos#


# Using parsed:


# parse_prefix_lists.cfg
# ip prefix-list v401
#    seq 25 deny 45.55.4.0/24
#    seq 100 permit 11.11.2.0/24 ge 32
# !
# ip prefix-list v402
#    seq 10 deny 10.1.1.0/24
# !
# ipv6 prefix-list v601
#    seq 125 deny 5000:1::/64
#


- name: parse configs
  arista.eos.eos_prefix_lists:
    running_config: "{{ lookup('file', './parsed_prefix_lists.cfg') }}"
    state: parsed


# Task Output
# -------------
# parsed:
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 45.55.4.0/24
#       sequence: 25
#     - action: permit
#       address: 11.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 100
#     name: v401
#   - entries:
#     - action: deny
#       address: 10.1.1.0/24
#       sequence: 10
#     name: v402
# - afi: ipv6
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 5000:1::/64
#       sequence: 125
#     name: v601


# Using rendered:

- name: Render provided configuration
  arista.eos.eos_prefix_lists:
    config:
      - afi: "ipv4"
        prefix_lists:
          - name: "v401"
            entries:
              - sequence: 25
                action: "deny"
                address: "45.55.4.0/24"
              - sequence: 200
                action: "permit"
                address: "200.11.2.0/24"
                match:
                  masklen: 32
                  operator: "ge"
          - name: "v403"
            entries:
              - action: "deny"
                address: "10.1.1.0/24"
                sequence: 10
    state: rendered

# Task Output
# -------------
# rendered:
# - ip prefix-list v401
# - seq 25 deny 45.55.4.0/24
# - seq 200 permit 200.11.2.0/24 ge 32
# - ip prefix-list v403
# - seq 10 deny 10.1.1.0/24

# using gathered:


# Device config:
# veos#show running-config | section prefix-list
# ip prefix-list v401
#    seq 25 deny 45.55.4.0/24
#    seq 100 permit 11.11.2.0/24 ge 32
# !
# ip prefix-list v402
#    seq 10 deny 10.1.1.0/24 ge 32
# !
# ipv6 prefix-list v601
#    seq 125 deny 5000:1::/64
# veos#

- name: gather configs
  arista.eos.eos_prefix_lists:
    state: gathered

# Task Output
# -------------
# gathered:
# - afi: ipv4
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 45.55.4.0/24
#       sequence: 25
#     - action: permit
#       address: 11.11.2.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 100
#     name: v401
#   - entries:
#     - action: deny
#       address: 10.1.1.0/24
#       match:
#         masklen: 32
#         operator: ge
#       sequence: 10
#     name: v402
# - afi: ipv6
#   prefix_lists:
#   - entries:
#     - action: deny
#       address: 5000:1::/64
#       sequence: 125
#     name: v601
"""
RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample:
    - ip prefix-list v401
    - seq 25 deny 45.55.4.0/24
    - seq 200 permit 200.11.2.0/24 ge 32
    - ip prefix-list v403
    - seq 10 deny 10.1.1.0/24
rendered:
  description: The set of CLI commands generated from the value in C(config) option
  returned: When C(state) is I(rendered)
  type: list
  sample: >
    - ip prefix-list v401
    - seq 25 deny 45.55.4.0/24
    - seq 200 permit 200.11.2.0/24 ge 32
    - ip prefix-list v403
    - seq 10 deny 10.1.1.0/24
gathered:
  description: The configuration as structured data transformed for the running configuration
               fetched from remote host
  returned: When C(state) is I(gathered)
  type: list
  sample: >
    The configuration returned will always be in the same format
    of the parameters above.
parsed:
  description: The configuration as structured data transformed for the value of
               C(running_config) option
  returned: When C(state) is I(parsed)
  type: list
  sample: >
    The configuration returned will always be in the same format
    of the parameters above.
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.arista.eos.plugins.module_utils.network.eos.argspec.prefix_lists.prefix_lists import (
    Prefix_listsArgs,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.config.prefix_lists.prefix_lists import (
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
