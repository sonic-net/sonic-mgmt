#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for vyos_prefix_lists
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: vyos_prefix_lists
short_description: Prefix-Lists resource module for VyOS
description:
  - This module manages prefix-lists configuration on devices running VyOS
version_added: 2.4.0
author: Priyam Sahoo (@priyamsahoo)
notes:
  - Tested against VyOS 1.3.8, 1.4.2, the upcoming 1.5, and the rolling release of spring 2025
  - This module works with connection C(network_cli)
options:
  config:
    description: A list of prefix-list options
    type: list
    elements: dict
    suboptions:
      afi:
        description: The Address Family Indicator (AFI) for the prefix-lists
        type: str
        choices: ["ipv4", "ipv6"]
        required: true
      prefix_lists:
        description: A list of prefix-list configurations
        type: list
        elements: dict
        suboptions:
          name:
            description: The name of a defined prefix-list
            type: str
            required: true
          description:
            description: A brief text description for the prefix-list
            type: str
          entries:
            description: Rule configurations for the prefix-list
            type: list
            elements: dict
            suboptions:
              sequence:
                description: A numeric identifier for the rule
                type: int
                required: true
              description:
                description: A brief text description for the prefix list rule
                type: str
              action:
                description: The action to be taken for packets matching a prefix list rule
                type: str
                choices: ["permit", "deny"]
              ge:
                description: Minimum prefix length to be matched
                type: int
              le:
                description: Maximum prefix list length to be matched
                type: int
              prefix:
                description: IPv4 or IPv6 prefix in A.B.C.D/LEN or A:B::C:D/LEN format
                type: str
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the VyOS device
        by executing the command B(show configuration commands | grep prefix-list).
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
    type: str
  state:
    description:
      - The state the configuration should be left in
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
      - gathered
      - rendered
      - parsed
    default: merged
"""

EXAMPLES = """
# # -------------------
# # 1. Using merged
# # -------------------

# # Before state:
# # -------------
#   vyos@vyos:~$ show configuration commands | grep prefix-list
#   vyos@vyos:~$

# # Task
# # -------------
#     - name: Merge the provided configuration with the existing running configuration
#         vyos.vyos.vyos_prefix_lists:
#             config:
#             - afi: "ipv4"
#                 prefix_lists:
#                 - name: "AnsibleIPv4PrefixList"
#                     description: "PL configured by ansible"
#                     entries:
#                     - sequence: 2
#                         description: "Rule 2 given by ansible"
#                         action: "permit"
#                         prefix: "92.168.10.0/26"
#                         le: 32

#                     - sequence: 3
#                         description: "Rule 3"
#                         action: "deny"
#                         prefix: "72.168.2.0/24"
#                         ge: 26

#             - afi: "ipv6"
#                 prefix_lists:
#                 - name: "AllowIPv6Prefix"
#                     description: "Configured by ansible for allowing IPv6 networks"
#                     entries:
#                     - sequence: 5
#                         description: "Permit rule"
#                         action: "permit"
#                         prefix: "2001:db8:8000::/35"
#                         le: 37

#                 - name: DenyIPv6Prefix
#                     description: "Configured by ansible for disallowing IPv6 networks"
#                     entries:
#                     - sequence: 8
#                         action: deny
#                         prefix: "2001:db8:2000::/35"
#                         le: 37
#             state: merged

# # Task output:
# # -------------
#     "after": [
#         {
#             "afi": "ipv4",
#             "prefix_lists": [
#                 {
#                     "description": "PL configured by ansible",
#                     "name": "AnsibleIPv4PrefixList",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Rule 2 given by ansible",
#                             "sequence": 2,
#                             "le": 32,
#                             "prefix": "92.168.10.0/26"
#                         },
#                         {
#                             "action": "deny",
#                             "description": "Rule 3",
#                             "ge": 26,
#                             "sequence": 3,
#                             "prefix": "72.168.2.0/24"
#                         }
#                     ]
#                 }
#             ]
#         },
#         {
#             "afi": "ipv6",
#             "prefix_lists": [
#                 {
#                     "description": "Configured by ansible for allowing IPv6 networks",
#                     "name": "AllowIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Permit rule",
#                             "sequence": 5,
#                             "le": 37,
#                             "prefix": "2001:db8:8000::/35"
#                         }
#                     ]
#                 },
#                 {
#                     "description": "Configured by ansible for disallowing IPv6 networks",
#                     "name": "DenyIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "deny",
#                             "sequence": 8,
#                             "le": 37,
#                             "prefix": "2001:db8:2000::/35"
#                         }
#                     ]
#                 }
#             ]
#         }
#     ],
#     "before": [],
#     "changed": true,
#     "commands": [
#         "set policy prefix-list AnsibleIPv4PrefixList",
#         "set policy prefix-list AnsibleIPv4PrefixList description 'PL configured by ansible'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 2",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'permit'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 2 description 'Rule 2 given by ansible'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 2 le '32'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 2 prefix '92.168.10.0/26'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 3",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 3 action 'deny'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 3 description 'Rule 3'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 3 ge '26'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 3 prefix '72.168.2.0/24'",
#         "set policy prefix-list6 AllowIPv6Prefix",
#         "set policy prefix-list6 AllowIPv6Prefix description 'Configured by ansible for allowing IPv6 networks'",
#         "set policy prefix-list6 AllowIPv6Prefix rule 5",
#         "set policy prefix-list6 AllowIPv6Prefix rule 5 action 'permit'",
#         "set policy prefix-list6 AllowIPv6Prefix rule 5 description 'Permit rule'",
#         "set policy prefix-list6 AllowIPv6Prefix rule 5 le '37'",
#         "set policy prefix-list6 AllowIPv6Prefix rule 5 prefix '2001:db8:8000::/35'",
#         "set policy prefix-list6 DenyIPv6Prefix",
#         "set policy prefix-list6 DenyIPv6Prefix description 'Configured by ansible for disallowing IPv6 networks'",
#         "set policy prefix-list6 DenyIPv6Prefix rule 8",
#         "set policy prefix-list6 DenyIPv6Prefix rule 8 action 'deny'",
#         "set policy prefix-list6 DenyIPv6Prefix rule 8 le '37'",
#         "set policy prefix-list6 DenyIPv6Prefix rule 8 prefix '2001:db8:2000::/35'"
#     ]

# After state:
# # -------------
#   vyos@vyos:~$ show configuration commands | grep prefix-list
#   set policy prefix-list AnsibleIPv4PrefixList description 'PL configured by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'permit'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 description 'Rule 2 given by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 le '32'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 prefix '92.168.10.0/26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 action 'deny'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 description 'Rule 3'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 ge '26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 prefix '72.168.2.0/24'
#   set policy prefix-list6 AllowIPv6Prefix description 'Configured by ansible for allowing IPv6 networks'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 action 'permit'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 description 'Permit rule'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 le '37'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 prefix '2001:db8:8000::/35'
#   set policy prefix-list6 DenyIPv6Prefix description 'Configured by ansible for disallowing IPv6 networks'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 action 'deny'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 le '37'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 prefix '2001:db8:2000::/35'
#   vyos@vyos:~$


# # -------------------
# # 2. Using replaced
# # -------------------

# # Before state:
# # -------------
#   vyos@vyos:~$ show configuration commands | grep prefix-list
#   set policy prefix-list AnsibleIPv4PrefixList description 'PL configured by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'permit'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 description 'Rule 2 given by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 le '32'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 prefix '92.168.10.0/26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 action 'deny'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 description 'Rule 3'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 ge '26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 prefix '72.168.2.0/24'
#   set policy prefix-list6 AllowIPv6Prefix description 'Configured by ansible for allowing IPv6 networks'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 action 'permit'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 description 'Permit rule'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 le '37'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 prefix '2001:db8:8000::/35'
#   set policy prefix-list6 DenyIPv6Prefix description 'Configured by ansible for disallowing IPv6 networks'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 action 'deny'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 le '37'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 prefix '2001:db8:2000::/35'
#   vyos@vyos:~$

# # Task:
# # -------------
#     - name: Replace prefix-lists configurations of listed prefix-lists with provided configurations
#       vyos.vyos.vyos_prefix_lists:
#         config:
#           - afi: "ipv4"
#             prefix_lists:
#               - name: "AnsibleIPv4PrefixList"
#                 description: "Configuration replaced by ansible"
#                 entries:
#                   - sequence: 3
#                     description: "Rule 3 replaced by ansible"
#                     action: "permit"
#                     prefix: "82.168.2.0/24"
#                     ge: 26
#         state: replaced

# # Task output:
# # -------------
#     "after": [
#         {
#             "afi": "ipv4",
#             "prefix_lists": [
#                 {
#                     "description": "Configuration replaced by ansible",
#                     "name": "AnsibleIPv4PrefixList",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Rule 3 replaced by ansible",
#                             "ge": 26,
#                             "sequence": 3,
#                             "prefix": "82.168.2.0/24"
#                         }
#                     ]
#                 }
#             ]
#         },
#         {
#             "afi": "ipv6",
#             "prefix_lists": [
#                 {
#                     "description": "Configured by ansible for allowing IPv6 networks",
#                     "name": "AllowIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Permit rule",
#                             "sequence": 5,
#                             "le": 37,
#                             "prefix": "2001:db8:8000::/35"
#                         }
#                     ]
#                 },
#                 {
#                     "description": "Configured by ansible for disallowing IPv6 networks",
#                     "name": "DenyIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "deny",
#                             "sequence": 8,
#                             "le": 37,
#                             "prefix": "2001:db8:2000::/35"
#                         }
#                     ]
#                 }
#             ]
#         }
#     ],
#     "before": [
#         {
#             "afi": "ipv4",
#             "prefix_lists": [
#                 {
#                     "description": "PL configured by ansible",
#                     "name": "AnsibleIPv4PrefixList",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Rule 2 given by ansible",
#                             "sequence": 2,
#                             "le": 32,
#                             "prefix": "92.168.10.0/26"
#                         },
#                         {
#                             "action": "deny",
#                             "description": "Rule 3",
#                             "ge": 26,
#                             "sequence": 3,
#                             "prefix": "72.168.2.0/24"
#                         }
#                     ]
#                 }
#             ]
#         },
#         {
#             "afi": "ipv6",
#             "prefix_lists": [
#                 {
#                     "description": "Configured by ansible for allowing IPv6 networks",
#                     "name": "AllowIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Permit rule",
#                             "sequence": 5,
#                             "le": 37,
#                             "prefix": "2001:db8:8000::/35"
#                         }
#                     ]
#                 },
#                 {
#                     "description": "Configured by ansible for disallowing IPv6 networks",
#                     "name": "DenyIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "deny",
#                             "sequence": 8,
#                             "le": 37,
#                             "prefix": "2001:db8:2000::/35"
#                         }
#                     ]
#                 }
#             ]
#         }
#     ],
#     "changed": true,
#     "commands": [
#         "set policy prefix-list AnsibleIPv4PrefixList description 'Configuration replaced by ansible'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 3 action 'permit'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 3 description 'Rule 3 replaced by ansible'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 3 prefix '82.168.2.0/24'",
#         "delete policy prefix-list AnsibleIPv4PrefixList rule 2"
#     ]

# # After state:
# # -------------
#   vyos@vyos:~$ show configuration commands | grep prefix-list
#   set policy prefix-list AnsibleIPv4PrefixList description 'Configuration replaced by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 action 'permit'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 description 'Rule 3 replaced by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 ge '26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 prefix '82.168.2.0/24'
#   set policy prefix-list6 AllowIPv6Prefix description 'Configured by ansible for allowing IPv6 networks'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 action 'permit'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 description 'Permit rule'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 le '37'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 prefix '2001:db8:8000::/35'
#   set policy prefix-list6 DenyIPv6Prefix description 'Configured by ansible for disallowing IPv6 networks'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 action 'deny'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 le '37'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 prefix '2001:db8:2000::/35'
#   vyos@vyos:~$


# # -------------------
# # 3. Using overridden
# # -------------------

# # Before state:
# # -------------
#   vyos@vyos:~$ show configuration commands | grep prefix-list
#   set policy prefix-list AnsibleIPv4PrefixList description 'PL configured by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'permit'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 description 'Rule 2 given by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 le '32'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 prefix '92.168.10.0/26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 action 'deny'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 description 'Rule 3'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 ge '26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 prefix '72.168.2.0/24'
#   set policy prefix-list6 AllowIPv6Prefix description 'Configured by ansible for allowing IPv6 networks'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 action 'permit'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 description 'Permit rule'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 le '37'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 prefix '2001:db8:8000::/35'
#   set policy prefix-list6 DenyIPv6Prefix description 'Configured by ansible for disallowing IPv6 networks'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 action 'deny'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 le '37'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 prefix '2001:db8:2000::/35'
#   vyos@vyos:~$

# # Task:
# # -------------
#     - name: Override all prefix-lists configuration with provided configuration
#       vyos.vyos.vyos_prefix_lists:
#         config:
#           - afi: "ipv4"
#             prefix_lists:
#               - name: "AnsibleIPv4PrefixList"
#                 description: Rule 2 overridden by ansible
#                 entries:
#                   - sequence: 2
#                     action: "deny"
#                     ge: 26
#                     prefix: "82.168.2.0/24"

#               - name: "OverriddenPrefixList"
#                 description: Configuration overridden by ansible
#                 entries:
#                   - sequence: 10
#                     action: permit
#                     prefix: "203.0.113.96/27"
#                     le: 32
#         state: overridden

# # Task output:
# # -------------
#     "after": [
#         {
#             "afi": "ipv4",
#             "prefix_lists": [
#                 {
#                     "description": "Rule 2 overridden by ansible",
#                     "name": "AnsibleIPv4PrefixList",
#                     "entries": [
#                         {
#                             "action": "deny",
#                             "ge": 26,
#                             "sequence": 2,
#                             "prefix": "82.168.2.0/24"
#                         }
#                     ]
#                 },
#                 {
#                     "description": "Configuration overridden by ansible",
#                     "name": "OverriddenPrefixList",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "sequence": 10,
#                             "le": 32,
#                             "prefix": "203.0.113.96/27"
#                         }
#                     ]
#                 }
#             ]
#         }
#     ],
#     "before": [
#         {
#             "afi": "ipv4",
#             "prefix_lists": [
#                 {
#                     "description": "PL configured by ansible",
#                     "name": "AnsibleIPv4PrefixList",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Rule 2 given by ansible",
#                             "sequence": 2,
#                             "le": 32,
#                             "prefix": "92.168.10.0/26"
#                         },
#                         {
#                             "action": "deny",
#                             "description": "Rule 3",
#                             "ge": 26,
#                             "sequence": 3,
#                             "prefix": "72.168.2.0/24"
#                         }
#                     ]
#                 }
#             ]
#         },
#         {
#             "afi": "ipv6",
#             "prefix_lists": [
#                 {
#                     "description": "Configured by ansible for allowing IPv6 networks",
#                     "name": "AllowIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Permit rule",
#                             "sequence": 5,
#                             "le": 37,
#                             "prefix": "2001:db8:8000::/35"
#                         }
#                     ]
#                 },
#                 {
#                     "description": "Configured by ansible for disallowing IPv6 networks",
#                     "name": "DenyIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "deny",
#                             "sequence": 8,
#                             "le": 37,
#                             "prefix": "2001:db8:2000::/35"
#                         }
#                     ]
#                 }
#             ]
#         }
#     ],
#     "changed": true,
#     "commands": [
#         "delete policy prefix-list6 AllowIPv6Prefix",
#         "delete policy prefix-list6 DenyIPv6Prefix",
#         "set policy prefix-list AnsibleIPv4PrefixList description 'Rule 2 overridden by ansible'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'deny'",
#         "delete policy prefix-list AnsibleIPv4PrefixList rule 2 description 'Rule 2 given by ansible'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 2 ge '26'",
#         "delete policy prefix-list AnsibleIPv4PrefixList rule 2 le '32'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 2 prefix '82.168.2.0/24'",
#         "delete policy prefix-list AnsibleIPv4PrefixList rule 3",
#         "set policy prefix-list OverriddenPrefixList",
#         "set policy prefix-list OverriddenPrefixList description 'Configuration overridden by ansible'",
#         "set policy prefix-list OverriddenPrefixList rule 10",
#         "set policy prefix-list OverriddenPrefixList rule 10 action 'permit'",
#         "set policy prefix-list OverriddenPrefixList rule 10 le '32'",
#         "set policy prefix-list OverriddenPrefixList rule 10 prefix '203.0.113.96/27'"
#     ]

# # After state:
# # -------------
#   vyos@vyos:~$ show configuration commands | grep prefix-list
#   set policy prefix-list AnsibleIPv4PrefixList description 'Rule 2 overridden by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'deny'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 ge '26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 prefix '82.168.2.0/24'
#   set policy prefix-list OverriddenPrefixList description 'Configuration overridden by ansible'
#   set policy prefix-list OverriddenPrefixList rule 10 action 'permit'
#   set policy prefix-list OverriddenPrefixList rule 10 le '32'
#   set policy prefix-list OverriddenPrefixList rule 10 prefix '203.0.113.96/27'
#   vyos@vyos:~$


# # -------------------
# # 4(i). Using deleted (to delete all prefix lists from the device)
# # -------------------

# # Before state:
# # -------------
#   vyos@vyos:~$ show configuration commands | grep prefix-list
#   set policy prefix-list AnsibleIPv4PrefixList description 'PL configured by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'permit'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 description 'Rule 2 given by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 le '32'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 prefix '92.168.10.0/26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 action 'deny'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 description 'Rule 3'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 ge '26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 prefix '72.168.2.0/24'
#   set policy prefix-list6 AllowIPv6Prefix description 'Configured by ansible for allowing IPv6 networks'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 action 'permit'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 description 'Permit rule'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 le '37'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 prefix '2001:db8:8000::/35'
#   set policy prefix-list6 DenyIPv6Prefix description 'Configured by ansible for disallowing IPv6 networks'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 action 'deny'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 le '37'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 prefix '2001:db8:2000::/35'
#   vyos@vyos:~$

# # Task:
# # -------------
#     - name: Delete all prefix-lists
#       vyos.vyos.vyos_prefix_lists:
#         config:
#         state: deleted

# # Task output:
# # -------------
#     "after": [],
#     "before": [
#         {
#             "afi": "ipv4",
#             "prefix_lists": [
#                 {
#                     "description": "PL configured by ansible",
#                     "name": "AnsibleIPv4PrefixList",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Rule 2 given by ansible",
#                             "sequence": 2,
#                             "le": 32,
#                             "prefix": "92.168.10.0/26"
#                         },
#                         {
#                             "action": "deny",
#                             "description": "Rule 3",
#                             "ge": 26,
#                             "sequence": 3,
#                             "prefix": "72.168.2.0/24"
#                         }
#                     ]
#                 }
#             ]
#         },
#         {
#             "afi": "ipv6",
#             "prefix_lists": [
#                 {
#                     "description": "Configured by ansible for allowing IPv6 networks",
#                     "name": "AllowIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Permit rule",
#                             "sequence": 5,
#                             "le": 37,
#                             "prefix": "2001:db8:8000::/35"
#                         }
#                     ]
#                 },
#                 {
#                     "description": "Configured by ansible for disallowing IPv6 networks",
#                     "name": "DenyIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "deny",
#                             "sequence": 8,
#                             "le": 37,
#                             "prefix": "2001:db8:2000::/35"
#                         }
#                     ]
#                 }
#             ]
#         }
#     ],
#     "changed": true,
#     "commands": [
#         "delete policy prefix-list AnsibleIPv4PrefixList",
#         "delete policy prefix-list6 AllowIPv6Prefix",
#         "delete policy prefix-list6 DenyIPv6Prefix"
#     ]

# # After state:
# # -------------
#   vyos@vyos:~$ show configuration commands | grep prefix-list
#   vyos@vyos:~$


# # -------------------
# # 4(ii). Using deleted (to delete all prefix lists for an AFI)
# # -------------------

# # Before state:
# # -------------
#   vyos@vyos:~$ show configuration commands | grep prefix-list
#   set policy prefix-list AnsibleIPv4PrefixList description 'PL configured by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'permit'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 description 'Rule 2 given by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 le '32'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 prefix '92.168.10.0/26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 action 'deny'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 description 'Rule 3'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 ge '26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 prefix '72.168.2.0/24'
#   set policy prefix-list6 AllowIPv6Prefix description 'Configured by ansible for allowing IPv6 networks'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 action 'permit'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 description 'Permit rule'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 le '37'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 prefix '2001:db8:8000::/35'
#   set policy prefix-list6 DenyIPv6Prefix description 'Configured by ansible for disallowing IPv6 networks'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 action 'deny'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 le '37'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 prefix '2001:db8:2000::/35'
#   vyos@vyos:~$

# # Task:
# # -------------
#     - name: Delete all prefix-lists for IPv6 AFI
#       vyos.vyos.vyos_prefix_lists:
#         config:
#           - afi: "ipv6"
#         state: deleted

# # Task output:
# # -------------
#     "after": [
#         {
#             "afi": "ipv4",
#             "prefix_lists": [
#                 {
#                     "description": "PL configured by ansible",
#                     "name": "AnsibleIPv4PrefixList",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Rule 2 given by ansible",
#                             "sequence": 2,
#                             "le": 32,
#                             "prefix": "92.168.10.0/26"
#                         },
#                         {
#                             "action": "deny",
#                             "description": "Rule 3",
#                             "ge": 26,
#                             "sequence": 3,
#                             "prefix": "72.168.2.0/24"
#                         }
#                     ]
#                 }
#             ]
#         }
#     ],
#     "before": [
#         {
#             "afi": "ipv4",
#             "prefix_lists": [
#                 {
#                     "description": "PL configured by ansible",
#                     "name": "AnsibleIPv4PrefixList",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Rule 2 given by ansible",
#                             "sequence": 2,
#                             "le": 32,
#                             "prefix": "92.168.10.0/26"
#                         },
#                         {
#                             "action": "deny",
#                             "description": "Rule 3",
#                             "ge": 26,
#                             "sequence": 3,
#                             "prefix": "72.168.2.0/24"
#                         }
#                     ]
#                 }
#             ]
#         },
#         {
#             "afi": "ipv6",
#             "prefix_lists": [
#                 {
#                     "description": "Configured by ansible for allowing IPv6 networks",
#                     "name": "AllowIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Permit rule",
#                             "sequence": 5,
#                             "le": 37,
#                             "prefix": "2001:db8:8000::/35"
#                         }
#                     ]
#                 },
#                 {
#                     "description": "Configured by ansible for disallowing IPv6 networks",
#                     "name": "DenyIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "deny",
#                             "sequence": 8,
#                             "le": 37,
#                             "prefix": "2001:db8:2000::/35"
#                         }
#                     ]
#                 }
#             ]
#         }
#     ],
#     "changed": true,
#     "commands": [
#         "delete policy prefix-list6 AllowIPv6Prefix",
#         "delete policy prefix-list6 DenyIPv6Prefix"
#     ]

# # After state:
# # -------------
#   vyos@vyos:~$ show configuration commands | grep prefix-list
#   set policy prefix-list AnsibleIPv4PrefixList description 'PL configured by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'permit'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 description 'Rule 2 given by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 le '32'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 prefix '92.168.10.0/26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 action 'deny'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 description 'Rule 3'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 ge '26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 prefix '72.168.2.0/24'
#   vyos@vyos:~$


# # -------------------
# # 4(iii). Using deleted (to delete single prefix list by name in different AFIs)
# # -------------------

# # Before state:
# # -------------
#   vyos@vyos:~$ show configuration commands | grep prefix-list
#   set policy prefix-list AnsibleIPv4PrefixList description 'PL configured by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'permit'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 description 'Rule 2 given by ansible'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 le '32'
#   set policy prefix-list AnsibleIPv4PrefixList rule 2 prefix '92.168.10.0/26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 action 'deny'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 description 'Rule 3'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 ge '26'
#   set policy prefix-list AnsibleIPv4PrefixList rule 3 prefix '72.168.2.0/24'
#   set policy prefix-list6 AllowIPv6Prefix description 'Configured by ansible for allowing IPv6 networks'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 action 'permit'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 description 'Permit rule'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 le '37'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 prefix '2001:db8:8000::/35'
#   set policy prefix-list6 DenyIPv6Prefix description 'Configured by ansible for disallowing IPv6 networks'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 action 'deny'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 le '37'
#   set policy prefix-list6 DenyIPv6Prefix rule 8 prefix '2001:db8:2000::/35'
#   vyos@vyos:~$

# # Task:
# # -------------
#     - name: Delete a single prefix-list from different AFIs
#       vyos.vyos.vyos_prefix_lists:
#         config:
#           - afi: "ipv4"
#             prefix_lists:
#               - name: "AnsibleIPv4PrefixList"
#           - afi: "ipv6"
#             prefix_lists:
#               - name: "DenyIPv6Prefix"
#         state: deleted

# # Task output:
# # -------------
#     "after": [
#         {
#             "afi": "ipv6",
#             "prefix_lists": [
#                 {
#                     "description": "Configured by ansible for allowing IPv6 networks",
#                     "name": "AllowIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Permit rule",
#                             "sequence": 5,
#                             "le": 37,
#                             "prefix": "2001:db8:8000::/35"
#                         }
#                     ]
#                 }
#             ]
#         }
#     ],
#     "before": [
#         {
#             "afi": "ipv4",
#             "prefix_lists": [
#                 {
#                     "description": "PL configured by ansible",
#                     "name": "AnsibleIPv4PrefixList",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Rule 2 given by ansible",
#                             "sequence": 2,
#                             "le": 32,
#                             "prefix": "92.168.10.0/26"
#                         },
#                         {
#                             "action": "deny",
#                             "description": "Rule 3",
#                             "ge": 26,
#                             "sequence": 3,
#                             "prefix": "72.168.2.0/24"
#                         }
#                     ]
#                 }
#             ]
#         },
#         {
#             "afi": "ipv6",
#             "prefix_lists": [
#                 {
#                     "description": "Configured by ansible for allowing IPv6 networks",
#                     "name": "AllowIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Permit rule",
#                             "sequence": 5,
#                             "le": 37,
#                             "prefix": "2001:db8:8000::/35"
#                         }
#                     ]
#                 },
#                 {
#                     "description": "Configured by ansible for disallowing IPv6 networks",
#                     "name": "DenyIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "deny",
#                             "sequence": 8,
#                             "le": 37,
#                             "prefix": "2001:db8:2000::/35"
#                         }
#                     ]
#                 }
#             ]
#         }
#     ],
#     "changed": true,
#     "commands": [
#         "delete policy prefix-list AnsibleIPv4PrefixList",
#         "delete policy prefix-list6 DenyIPv6Prefix"
#     ]

# # After state:
# # -------------
#   vyos@vyos:~$ show configuration commands | grep prefix-list
#   set policy prefix-list6 AllowIPv6Prefix description 'Configured by ansible for allowing IPv6 networks'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 action 'permit'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 description 'Permit rule'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 le '37'
#   set policy prefix-list6 AllowIPv6Prefix rule 5 prefix '2001:db8:8000::/35'
#   vyos@vyos:~$


# # -------------------
# # 5. Using gathered
# # -------------------

# # Task:
# # -------------
#     - name: Gather prefix-lists configurations
#       vyos.vyos.vyos_prefix_lists:
#         config:
#         state: gathered

# # Task output:
# # -------------
#     "gathered": [
#         {
#             "afi": "ipv4",
#             "prefix_lists": [
#                 {
#                     "description": "PL configured by ansible",
#                     "name": "AnsibleIPv4PrefixList",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Rule 2 given by ansible",
#                             "sequence": 2,
#                             "le": 32,
#                             "prefix": "92.168.10.0/26"
#                         },
#                         {
#                             "action": "deny",
#                             "description": "Rule 3",
#                             "ge": 26,
#                             "sequence": 3,
#                             "prefix": "72.168.2.0/24"
#                         }
#                     ]
#                 }
#             ]
#         },
#         {
#             "afi": "ipv6",
#             "prefix_lists": [
#                 {
#                     "description": "Configured by ansible for allowing IPv6 networks",
#                     "name": "AllowIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Permit rule",
#                             "sequence": 5,
#                             "le": 37,
#                             "prefix": "2001:db8:8000::/35"
#                         }
#                     ]
#                 },
#                 {
#                     "description": "Configured by ansible for disallowing IPv6 networks",
#                     "name": "DenyIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "deny",
#                             "sequence": 8,
#                             "le": 37,
#                             "prefix": "2001:db8:2000::/35"
#                         }
#                     ]
#                 }
#             ]
#         }
#     ]


# # -------------------
# # 6. Using rendered
# # -------------------

# # Task:
# # -------------
#     - name: Render commands externally for the described prefix-list configurations
#       vyos.vyos.vyos_prefix_lists:
#         config:
#           - afi: "ipv4"
#             prefix_lists:
#               - name: "AnsibleIPv4PrefixList"
#                 description: "PL configured by ansible"
#                 entries:
#                   - sequence: 2
#                     description: "Rule 2 given by ansible"
#                     action: "permit"
#                     prefix: "92.168.10.0/26"
#                     le: 32

#                   - sequence: 3
#                     description: "Rule 3"
#                     action: "deny"
#                     prefix: "72.168.2.0/24"
#                     ge: 26

#           - afi: "ipv6"
#             prefix_lists:
#               - name: "AllowIPv6Prefix"
#                 description: "Configured by ansible for allowing IPv6 networks"
#                 entries:
#                   - sequence: 5
#                     description: "Permit rule"
#                     action: "permit"
#                     prefix: "2001:db8:8000::/35"
#                     le: 37

#               - name: DenyIPv6Prefix
#                 description: "Configured by ansible for disallowing IPv6 networks"
#                 entries:
#                   - sequence: 8
#                     action: deny
#                     prefix: "2001:db8:2000::/35"
#                     le: 37
#         state: rendered

# # Task output:
# # -------------
#     "rendered": [
#         "set policy prefix-list AnsibleIPv4PrefixList",
#         "set policy prefix-list AnsibleIPv4PrefixList description 'PL configured by ansible'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 2",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'permit'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 2 description 'Rule 2 given by ansible'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 2 le '32'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 2 prefix '92.168.10.0/26'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 3",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 3 action 'deny'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 3 description 'Rule 3'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 3 ge '26'",
#         "set policy prefix-list AnsibleIPv4PrefixList rule 3 prefix '72.168.2.0/24'",
#         "set policy prefix-list6 AllowIPv6Prefix",
#         "set policy prefix-list6 AllowIPv6Prefix description 'Configured by ansible for allowing IPv6 networks'",
#         "set policy prefix-list6 AllowIPv6Prefix rule 5",
#         "set policy prefix-list6 AllowIPv6Prefix rule 5 action 'permit'",
#         "set policy prefix-list6 AllowIPv6Prefix rule 5 description 'Permit rule'",
#         "set policy prefix-list6 AllowIPv6Prefix rule 5 le '37'",
#         "set policy prefix-list6 AllowIPv6Prefix rule 5 prefix '2001:db8:8000::/35'",
#         "set policy prefix-list6 DenyIPv6Prefix",
#         "set policy prefix-list6 DenyIPv6Prefix description 'Configured by ansible for disallowing IPv6 networks'",
#         "set policy prefix-list6 DenyIPv6Prefix rule 8",
#         "set policy prefix-list6 DenyIPv6Prefix rule 8 action 'deny'",
#         "set policy prefix-list6 DenyIPv6Prefix rule 8 le '37'",
#         "set policy prefix-list6 DenyIPv6Prefix rule 8 prefix '2001:db8:2000::/35'"
#     ]


# # -------------------
# # 7. Using parsed
# # -------------------

# # sample_config.cfg:
# # -------------
# set policy prefix-list AnsibleIPv4PrefixList description 'PL configured by ansible'
# set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'permit'
# set policy prefix-list AnsibleIPv4PrefixList rule 2 description 'Rule 2 given by ansible'
# set policy prefix-list AnsibleIPv4PrefixList rule 2 le '32'
# set policy prefix-list AnsibleIPv4PrefixList rule 2 prefix '92.168.10.0/26'
# set policy prefix-list AnsibleIPv4PrefixList rule 3 action 'deny'
# set policy prefix-list AnsibleIPv4PrefixList rule 3 description 'Rule 3'
# set policy prefix-list AnsibleIPv4PrefixList rule 3 ge '26'
# set policy prefix-list AnsibleIPv4PrefixList rule 3 prefix '72.168.2.0/24'
# set policy prefix-list6 AllowIPv6Prefix description 'Configured by ansible for allowing IPv6 networks'
# set policy prefix-list6 AllowIPv6Prefix rule 5 action 'permit'
# set policy prefix-list6 AllowIPv6Prefix rule 5 description 'Permit rule'
# set policy prefix-list6 AllowIPv6Prefix rule 5 le '37'
# set policy prefix-list6 AllowIPv6Prefix rule 5 prefix '2001:db8:8000::/35'
# set policy prefix-list6 DenyIPv6Prefix description 'Configured by ansible for disallowing IPv6 networks'
# set policy prefix-list6 DenyIPv6Prefix rule 8 action 'deny'
# set policy prefix-list6 DenyIPv6Prefix rule 8 le '37'
# set policy prefix-list6 DenyIPv6Prefix rule 8 prefix '2001:db8:2000::/35'

# # Task:
# # -------------
#     - name: Parse externally provided prefix-lists configuration
#       vyos.vyos.vyos_prefix_lists:
#         running_config: "{{ lookup('file', './sample_config.cfg') }}"
#         state: parsed

# # Task output:
# # -------------
#     "parsed": [
#         {
#             "afi": "ipv4",
#             "prefix_lists": [
#                 {
#                     "description": "PL configured by ansible",
#                     "name": "AnsibleIPv4PrefixList",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Rule 2 given by ansible",
#                             "sequence": 2,
#                             "le": 32,
#                             "prefix": "92.168.10.0/26"
#                         },
#                         {
#                             "action": "deny",
#                             "description": "Rule 3",
#                             "ge": 26,
#                             "sequence": 3,
#                             "prefix": "72.168.2.0/24"
#                         }
#                     ]
#                 }
#             ]
#         },
#         {
#             "afi": "ipv6",
#             "prefix_lists": [
#                 {
#                     "description": "Configured by ansible for allowing IPv6 networks",
#                     "name": "AllowIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "permit",
#                             "description": "Permit rule",
#                             "sequence": 5,
#                             "le": 37,
#                             "prefix": "2001:db8:8000::/35"
#                         }
#                     ]
#                 },
#                 {
#                     "description": "Configured by ansible for disallowing IPv6 networks",
#                     "name": "DenyIPv6Prefix",
#                     "entries": [
#                         {
#                             "action": "deny",
#                             "sequence": 8,
#                             "le": 37,
#                             "prefix": "2001:db8:2000::/35"
#                         }
#                     ]
#                 }
#             ]
#         }
#     ]
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
    - set policy prefix-list AnsibleIPv4PrefixList description 'PL configured by ansible'
    - set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'permit'
    - set policy prefix-list6 AllowIPv6Prefix description 'Configured by ansible for allowing IPv6 networks'
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - set policy prefix-list AnsibleIPv4PrefixList description 'PL configured by ansible'
    - set policy prefix-list AnsibleIPv4PrefixList rule 2 action 'permit'
    - set policy prefix-list6 AllowIPv6Prefix description 'Configured by ansible for allowing IPv6 networks'
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

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.prefix_lists.prefix_lists import (
    Prefix_listsArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.config.prefix_lists.prefix_lists import (
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
