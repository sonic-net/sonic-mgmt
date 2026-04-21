#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for vyos_snmp_server
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: vyos_snmp_server
version_added: "1.0.0"
short_description: Manages snmp_server resource module
description: This module manages the snmp server attributes of Vyos network devices
author: Gomathi Selvi Srinivasan (@GomathiselviS)
notes:
  - Tested against VyOS 1.3.8, 1.4.2, the upcoming 1.5, and the rolling release of spring 2025, 1.4.1
  - This module works with connection C(network_cli).
  - The Configuration defaults of the Vyos network devices
    are supposed to hinder idempotent behavior of plays
options:
  config:
    description: SNMP server configuration.
    type: dict
    suboptions:
      communities:
        description: Community name configuration.
        type: list
        elements: dict
        suboptions:
          name:
            description: Community name
            type: str
          clients:
            description: IP address of SNMP client allowed to contact system
            type: list
            elements: str
          networks:
            description: Subnet of SNMP client(s) allowed to contact system
            type: list
            elements: str
          authorization_type:
            description: Authorization type (rw or ro)
            type: str
            choices: ['ro', 'rw']
      contact:
        description: Person to contact about the system.
        type: str
      description:
        description: Description information
        type: str
      listen_addresses:
        description: IP address to listen for incoming SNMP requests
        type: list
        elements: dict
        suboptions:
          address:
            description: IP address to listen for incoming SNMP requests.
            type: str
          port:
            description: Port for SNMP service
            type: int
      location:
        description: Location information
        type: str
      smux_peer:
        description: Register a subtree for SMUX-based processing.
        type: str
      trap_source:
        description:  SNMP trap source address
        type: str
      trap_target:
        description: Address of trap target
        type: dict
        suboptions:
          address:
            description: Address of trap target
            type: str
          community:
            description: Community used when sending trap information
            type: str
          port:
            description: Destination port used for trap notification
            type: int
      snmp_v3:
        description: Simple Network Management Protocol (SNMP) v3
        type: dict
        suboptions:
          engine_id:
            description: Specifies the EngineID as a hex value
            type: str
          groups:
            description: Specifies the group with name groupname
            type: list
            elements: dict
            suboptions:
              group:
                description: Specifies the group with name groupname
                type: str
              mode:
                description: Defines the read/write access
                type: str
                choices: ['ro', 'rw']
              seclevel:
                description: Defines security level
                type: str
                choices: ['auth', 'priv']
              view:
                description: Defines the name of view
                type: str
          trap_targets:
            description: Defines SNMP target for inform or traps for IP
            type: list
            elements: dict
            suboptions:
              address:
                description: IP/IPv6 address of trap target
                type: str
              authentication:
                description: Defines the authentication
                type: dict
                suboptions:
                  type:
                    description: Defines the protocol using for authentication
                    type: str
                    choices: ['md5', 'sha']
                  encrypted_key:
                    description: Defines the encrypted password for authentication
                    type: str
                  plaintext_key:
                    description: Defines the clear text password for authentication
                    type: str
              port:
                description: Specifies the TCP/UDP port of a destination for SNMP traps/informs.
                type: int
              privacy:
                description: Defines the privacy
                type: dict
                suboptions:
                  type:
                    description: Defines the protocol using for privacy
                    type: str
                    choices: ['des', 'aes']
                  encrypted_key:
                    description: Defines the encrypted password for privacy
                    type: str
                  plaintext_key:
                    description: Defines the clear text password for privacy
                    type: str
              protocol:
                description: Defines protocol for notification between TCP and UDP
                type: str
                choices: ['tcp', 'udp']
              type:
                description: Specifies the type of notification between inform and trap
                type: str
                choices: ['inform', 'trap']
          users:
            description: Defines username for authentication
            type: list
            elements: dict
            suboptions:
              user:
                description: Specifies the user with name username
                type: str
              authentication:
                description: Defines the authentication
                type: dict
                suboptions:
                  type:
                    description: Defines the protocol using for authentication
                    type: str
                    choices: ['md5', 'sha']
                  encrypted_key:
                    description: Defines the encrypted password for authentication
                    type: str
                  plaintext_key:
                    description: Defines the clear text password for authentication
                    type: str
              group:
                description: Specifies group for user name
                type: str
              mode:
                description: Specifies the mode for access rights of user, read only or write
                type: str
                choices: ['ro', 'rw']
              privacy:
                description: Defines the privacy
                type: dict
                suboptions:
                  type:
                    description: Defines the protocol using for privacy
                    type: str
                    choices: ['des', 'aes']
                  encrypted_key:
                    description: Defines the encrypted password for privacy
                    type: str
                  plaintext_key:
                    description: Defines the clear text password for privacy
                    type: str
              tsm_key:
                description: Specifies finger print or file name of TSM certificate.
                type: str
          views:
            description: Specifies the view with name viewname
            type: list
            elements: dict
            suboptions:
              view:
                description: view name
                type: str
              oid:
                description: Specify oid
                type: str
              exclude:
                description: Exclude is optional argument.
                type: str
              mask:
                description: Defines a bit-mask that is indicating which subidentifiers of the associated subtree OID should be regarded as significant.
                type: str
  running_config:
    description:
    - The state the configuration should be left in.
    - The states I(replaced) and I(overridden) have identical
       behaviour for this module.
    - Please refer to examples for more details.
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
# Before State:

# vyos@vyos:~$ show configuration commands | grep snmp
# vyos@vyos:~$

- name: Merge provided configuration with device configuration
  vyos.vyos.vyos_snmp_server:
    config:
      communities:
        - name: "switches"
          authorization_type: "rw"
        - name: "bridges"
          clients: ["1.1.1.1", "12.1.1.10"]
      contact: "admin2@ex.com"
      listen_addresses:
        - address: "20.1.1.1"
        - address: "100.1.2.1"
          port: 33
      snmp_v3:
        users:
          - user: admin_user
            authentication:
              plaintext_key: "abc1234567"
              type: "sha"
            privacy:
              plaintext_key: "abc1234567"
              type: "aes"
    state: merged

# After State:

# vyos@vyos:~$ show configuration commands | grep snmp
# set service snmp community bridges client '1.1.1.1'
# set service snmp community bridges client '12.1.1.10'
# set service snmp community switches authorization 'rw'
# set service snmp contact 'admin2@ex.com'
# set service snmp listen-address 20.1.1.1
# set service snmp listen-address 100.1.2.1 port '33'
# set service snmp v3 user admin_user auth plaintext-key 'abc1234567'
# set service snmp v3 user admin_user auth type 'sha'
# set service snmp v3 user admin_user privacy plaintext-key 'abc1234567'
# set service snmp v3 user admin_user privacy type 'aes'
# vyos@vyos:~$
#
# Module Execution:
#
# "after": {
#         "communities": [
#             {
#                 "clients": [
#                     "1.1.1.1",
#                     "12.1.1.10"
#                 ],
#                 "name": "bridges"
#             },
#             {
#                 "authorization_type": "rw",
#                 "name": "switches"
#             }
#         ],
#         "contact": "admin2@ex.com",
#         "listen_addresses": [
#             {
#                 "address": "100.1.2.1",
#                 "port": 33
#             },
#             {
#                 "address": "20.1.1.1"
#             }
#         ],
#         "snmp_v3": {
#             "users": [
#                 {
#                     "authentication": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "sha"
#                     },
#                     "privacy": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "aes"
#                     },
#                     "user": "admin_user"
#                 }
#             ]
#         }
#     },
#     "before": {},
#     "changed": true,
#     "commands": [
#         "set service snmp community switches authorization rw",
#         "set service snmp community bridges client 1.1.1.1",
#         "set service snmp community bridges client 12.1.1.10",
#         "set service snmp listen-address 20.1.1.1",
#         "set service snmp listen-address 100.1.2.1 port 33",
#         "set service snmp v3 user admin_user auth type sha",
#         "set service snmp v3 user admin_user auth plaintext-key ********",
#         "set service snmp v3 user admin_user privacy type aes",
#         "set service snmp v3 user admin_user privacy plaintext-key ********",
#         "set service snmp contact admin2@ex.com"
#     ],
#

# Using replaced

# Before State
# -------------
# vyos@vyos:~$ show configuration commands | grep snmp
# set service snmp community bridges client '1.1.1.1'
# set service snmp community bridges client '12.1.1.10'
# set service snmp community switches authorization 'rw'
# set service snmp contact 'admin2@ex.com'
# set service snmp listen-address 20.1.1.1
# set service snmp listen-address 100.1.2.1 port '33'
# set service snmp v3 user admin_user auth plaintext-key 'abc1234567'
# set service snmp v3 user admin_user auth type 'sha'
# set service snmp v3 user admin_user privacy plaintext-key 'abc1234567'
# set service snmp v3 user admin_user privacy type 'aes'

- name: Replace SNMP Server configuration
  vyos.vyos.vyos_snmp_server:
    config:
      communities:
        - name: "bridges"
          networks: ["1.1.1.0/24", "12.1.1.0/24"]
      location: "RDU, NC"
      listen_addresses:
        - address: "100.1.2.1"
          port: 33
      snmp_v3:
        groups:
          - group: "default"
            view: "default"
        users:
          - user: admin_user
            authentication:
              plaintext_key: "abc1234567"
              type: "sha"
            privacy:
              plaintext_key: "abc1234567"
              type: "aes"
            group: "default"
          - user: guest_user2
            authentication:
              plaintext_key: "opq1234567"
              type: "sha"
            privacy:
              plaintext_key: "opq1234567"
              type: "aes"
        views:
          - view: "default"
            oid: 1

    state: replaced

# After State:
# vyos@vyos:~$ show configuration commands | grep snmp
# set service snmp community bridges network '1.1.1.0/24'
# set service snmp community bridges network '12.1.1.0/24'
# set service snmp community switches
# set service snmp listen-address 100.1.2.1 port '33'
# set service snmp location 'RDU, NC'
# set service snmp v3 group default view 'default'
# set service snmp v3 user admin_user auth plaintext-key 'abc1234567'
# set service snmp v3 user admin_user auth type 'sha'
# set service snmp v3 user admin_user group 'default'
# set service snmp v3 user admin_user privacy plaintext-key 'abc1234567'
# set service snmp v3 user admin_user privacy type 'aes'
# set service snmp v3 user guest_user2 auth plaintext-key 'opq1234567'
# set service snmp v3 user guest_user2 auth type 'sha'
# set service snmp v3 user guest_user2 privacy plaintext-key 'opq1234567'
# set service snmp v3 user guest_user2 privacy type 'aes'
# set service snmp v3 view default oid 1
# vyos@vyos:~$
#
#
# Module Execution:
# "after": {
#         "communities": [
#             {
#                 "name": "bridges",
#                 "networks": [
#                     "1.1.1.0/24",
#                     "12.1.1.0/24"
#                 ]
#             },
#             {
#                 "name": "switches"
#             }
#         ],
#         "listen_addresses": [
#             {
#                 "address": "100.1.2.1",
#                 "port": 33
#             }
#         ],
#         "location": "RDU, NC",
#         "snmp_v3": {
#             "groups": [
#                 {
#                     "group": "default",
#                     "view": "default"
#                 }
#             ],
#             "users": [
#                 {
#                     "authentication": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "sha"
#                     },
#                     "group": "default",
#                     "privacy": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "aes"
#                     },
#                     "user": "admin_user"
#                 },
#                 {
#                     "authentication": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "sha"
#                     },
#                     "privacy": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "aes"
#                     },
#                     "user": "guest_user2"
#                 }
#             ],
#             "views": [
#                 {
#                     "oid": "1",
#                     "view": "default"
#                 }
#             ]
#         }
#     },
#     "before": {
#         "communities": [
#             {
#                 "clients": [
#                     "1.1.1.1",
#                     "12.1.1.10"
#                 ],
#                 "name": "bridges"
#             },
#             {
#                 "authorization_type": "rw",
#                 "name": "switches"
#             }
#         ],
#         "contact": "admin2@ex.com",
#         "listen_addresses": [
#             {
#                 "address": "100.1.2.1",
#                 "port": 33
#             },
#             {
#                 "address": "20.1.1.1"
#             }
#         ],
#         "snmp_v3": {
#             "users": [
#                 {
#                     "authentication": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "sha"
#                     },
#                     "privacy": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "aes"
#                     },
#                     "user": "admin_user"
#                 }
#             ]
#         }
#     },
#     "changed": true,
#     "commands": [
#         "delete service snmp contact admin2@ex.com",
#         "delete service snmp listen-address 20.1.1.1",
#         "delete service snmp community switches authorization rw",
#         "delete service snmp community bridges client 12.1.1.10",
#         "delete service snmp community bridges client 1.1.1.1",
#         "set service snmp community bridges network 1.1.1.0/24",
#         "set service snmp community bridges network 12.1.1.0/24",
#         "set service snmp v3 group default view default",
#         "set service snmp v3 user admin_user group default",
#         "set service snmp v3 user guest_user2 auth type sha",
#         "set service snmp v3 user guest_user2 auth plaintext-key ********",
#         "set service snmp v3 user guest_user2 privacy type aes",
#         "set service snmp v3 user guest_user2 privacy plaintext-key ********",
#         "set service snmp v3 view default oid 1",
#         "set service snmp location 'RDU, NC'"
#     ],

# Using overridden:
# Before State
# vyos@vyos:~$ show configuration commands | grep snmp
# set service snmp community bridges client '1.1.1.1'
# set service snmp community bridges client '12.1.1.10'
# set service snmp community switches authorization 'rw'
# set service snmp contact 'admin2@ex.com'
# set service snmp listen-address 20.1.1.1
# set service snmp listen-address 100.1.2.1 port '33'
# set service snmp v3 user admin_user auth plaintext-key 'abc1234567'
# set service snmp v3 user admin_user auth type 'sha'
# set service snmp v3 user admin_user privacy plaintext-key 'abc1234567'
# set service snmp v3 user admin_user privacy type 'aes'

- name: Override SNMP server config
  vyos.vyos.vyos_snmp_server:
    config:
      communities:
        - name: "bridges"
          networks: ["1.1.1.0/24", "12.1.1.0/24"]
      location: "RDU, NC"
      listen_addresses:
        - address: "100.1.2.1"
          port: 33
      snmp_v3:
        groups:
          - group: "default"
            view: "default"
        users:
          - user: admin_user
            authentication:
              plaintext_key: "abc1234567"
              type: "sha"
            privacy:
              plaintext_key: "abc1234567"
              type: "aes"
            group: "default"
          - user: guest_user2
            authentication:
              plaintext_key: "opq1234567"
              type: "sha"
            privacy:
              plaintext_key: "opq1234567"
              type: "aes"
        views:
          - view: "default"
            oid: 1
    state: overridden

# After State:
# vyos@vyos:~$ show configuration commands | grep snmp
# set service snmp community bridges network '1.1.1.0/24'
# set service snmp community bridges network '12.1.1.0/24'
# set service snmp community switches
# set service snmp listen-address 100.1.2.1 port '33'
# set service snmp location 'RDU, NC'
# set service snmp v3 group default view 'default'
# set service snmp v3 user admin_user auth plaintext-key 'abc1234567'
# set service snmp v3 user admin_user auth type 'sha'
# set service snmp v3 user admin_user group 'default'
# set service snmp v3 user admin_user privacy plaintext-key 'abc1234567'
# set service snmp v3 user admin_user privacy type 'aes'
# set service snmp v3 user guest_user2 auth plaintext-key 'opq1234567'
# set service snmp v3 user guest_user2 auth type 'sha'
# set service snmp v3 user guest_user2 privacy plaintext-key 'opq1234567'
# set service snmp v3 user guest_user2 privacy type 'aes'
# set service snmp v3 view default oid 1
# vyos@vyos:~$
#
#
# Module Execution:
# "after": {
#         "communities": [
#             {
#                 "name": "bridges",
#                 "networks": [
#                     "1.1.1.0/24",
#                     "12.1.1.0/24"
#                 ]
#             },
#             {
#                 "name": "switches"
#             }
#         ],
#         "listen_addresses": [
#             {
#                 "address": "100.1.2.1",
#                 "port": 33
#             }
#         ],
#         "location": "RDU, NC",
#         "snmp_v3": {
#             "groups": [
#                 {
#                     "group": "default",
#                     "view": "default"
#                 }
#             ],
#             "users": [
#                 {
#                     "authentication": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "sha"
#                     },
#                     "group": "default",
#                     "privacy": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "aes"
#                     },
#                     "user": "admin_user"
#                 },
#                 {
#                     "authentication": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "sha"
#                     },
#                     "privacy": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "aes"
#                     },
#                     "user": "guest_user2"
#                 }
#             ],
#             "views": [
#                 {
#                     "oid": "1",
#                     "view": "default"
#                 }
#             ]
#         }
#     },
#     "before": {
#         "communities": [
#             {
#                 "clients": [
#                     "1.1.1.1",
#                     "12.1.1.10"
#                 ],
#                 "name": "bridges"
#             },
#             {
#                 "authorization_type": "rw",
#                 "name": "switches"
#             }
#         ],
#         "contact": "admin2@ex.com",
#         "listen_addresses": [
#             {
#                 "address": "100.1.2.1",
#                 "port": 33
#             },
#             {
#                 "address": "20.1.1.1"
#             }
#         ],
#         "snmp_v3": {
#             "users": [
#                 {
#                     "authentication": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "sha"
#                     },
#                     "privacy": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "aes"
#                     },
#                     "user": "admin_user"
#                 }
#             ]
#         }
#     },
#     "changed": true,
#     "commands": [
#         "delete service snmp contact admin2@ex.com",
#         "delete service snmp listen-address 20.1.1.1",
#         "delete service snmp community switches authorization rw",
#         "delete service snmp community bridges client 12.1.1.10",
#         "delete service snmp community bridges client 1.1.1.1",
#         "set service snmp community bridges network 1.1.1.0/24",
#         "set service snmp community bridges network 12.1.1.0/24",
#         "set service snmp v3 group default view default",
#         "set service snmp v3 user admin_user group default",
#         "set service snmp v3 user guest_user2 auth type sha",
#         "set service snmp v3 user guest_user2 auth plaintext-key ********",
#         "set service snmp v3 user guest_user2 privacy type aes",
#         "set service snmp v3 user guest_user2 privacy plaintext-key ********",
#         "set service snmp v3 view default oid 1",
#         "set service snmp location 'RDU, NC'"
#     ],

# Using deleted:

# Before State:
# vyos@vyos:~$ show configuration commands | grep snmp
# set service snmp community bridges network '1.1.1.0/24'
# set service snmp community bridges network '12.1.1.0/24'
# set service snmp community switches
# set service snmp listen-address 100.1.2.1 port '33'
# set service snmp location 'RDU, NC'
# set service snmp v3 group default view 'default'
# set service snmp v3 user admin_user auth plaintext-key 'abc1234567'
# set service snmp v3 user admin_user auth type 'sha'
# set service snmp v3 user admin_user group 'default'
# set service snmp v3 user admin_user privacy plaintext-key 'abc1234567'
# set service snmp v3 user admin_user privacy type 'aes'
# set service snmp v3 user guest_user2 auth plaintext-key 'opq1234567'
# set service snmp v3 user guest_user2 auth type 'sha'
# set service snmp v3 user guest_user2 privacy plaintext-key 'opq1234567'
# set service snmp v3 user guest_user2 privacy type 'aes'
# set service snmp v3 view default oid 1

- name: Delete Config
  vyos.vyos.vyos_snmp_server:
    state: deleted

# After State:
# vyos@vyos:~$ show configuration commands | grep snmp
# vyos@vyos:~$
#
# Module Execution:
# "after": {},
#     "before": {
#         "communities": [
#             {
#                 "name": "bridges",
#                 "networks": [
#                     "1.1.1.0/24",
#                     "12.1.1.0/24"
#                 ]
#             },
#             {
#                 "name": "switches"
#             }
#         ],
#         "listen_addresses": [
#             {
#                 "address": "100.1.2.1",
#                 "port": 33
#             }
#         ],
#         "location": "RDU, NC",
#         "snmp_v3": {
#             "groups": [
#                 {
#                     "group": "default",
#                     "view": "default"
#                 }
#             ],
#             "users": [
#                 {
#                     "authentication": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "sha"
#                     },
#                     "group": "default",
#                     "privacy": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "aes"
#                     },
#                     "user": "admin_user"
#                 },
#                 {
#                     "authentication": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "sha"
#                     },
#                     "privacy": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "aes"
#                     },
#                     "user": "guest_user2"
#                 }
#             ],
#             "views": [
#                 {
#                     "oid": "1",
#                     "view": "default"
#                 }
#             ]
#         }
#     },
#     "changed": true,
#     "commands": [
#         "delete service snmp"
#     ],

# Using rendered:
- name: Render provided configuration
  vyos.vyos.vyos_snmp_server:
    config:
      communities:
        - name: "switches"
          authorization_type: "rw"
        - name: "bridges"
          clients: ["1.1.1.1", "12.1.1.10"]
      contact: "admin2@ex.com"
      listen_addresses:
        - address: "20.1.1.1"
        - address: "100.1.2.1"
          port: 33
      snmp_v3:
        users:
          - user: admin_user
            authentication:
              plaintext_key: "abc1234567"
              type: "sha"
            privacy:
              plaintext_key: "abc1234567"
              type: "aes"
    state: rendered

# Module Execution:
#  "rendered": [
#         "set service snmp community switches authorization rw",
#         "set service snmp community bridges client 1.1.1.1",
#         "set service snmp community bridges client 12.1.1.10",
#         "set service snmp listen-address 20.1.1.1",
#         "set service snmp listen-address 100.1.2.1 port 33",
#         "set service snmp v3 user admin_user auth type sha",
#         "set service snmp v3 user admin_user auth plaintext-key ********",
#         "set service snmp v3 user admin_user privacy type aes",
#         "set service snmp v3 user admin_user privacy plaintext-key ********",
#         "set service snmp contact admin2@ex.com"
#     ]
#

# Using Gathered:
# Before State:

# vyos@vyos:~$ show configuration commands | grep snmp
# set service snmp community bridges client '1.1.1.1'
# set service snmp community bridges client '12.1.1.10'
# set service snmp community switches authorization 'rw'
# set service snmp contact 'admin2@ex.com'
# set service snmp listen-address 20.1.1.1
# set service snmp listen-address 100.1.2.1 port '33'
# set service snmp v3 user admin_user auth plaintext-key 'abc1234567'
# set service snmp v3 user admin_user auth type 'sha'
# set service snmp v3 user admin_user privacy plaintext-key 'abc1234567'
# set service snmp v3 user admin_user privacy type 'aes'

- name: Gather SNMP server config
  vyos.vyos.vyos_snmp_server:
    state: gathered

# Module Execution:
#   "gathered": {
#         "communities": [
#             {
#                 "clients": [
#                     "1.1.1.1",
#                     "12.1.1.10"
#                 ],
#                 "name": "bridges"
#             },
#             {
#                 "authorization_type": "rw",
#                 "name": "switches"
#             }
#         ],
#         "contact": "admin2@ex.com",
#         "listen_addresses": [
#             {
#                 "address": "100.1.2.1",
#                 "port": 33
#             },
#             {
#                 "address": "20.1.1.1"
#             }
#         ],
#         "snmp_v3": {
#             "users": [
#                 {
#                     "authentication": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "sha"
#                     },
#                     "privacy": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "aes"
#                     },
#                     "user": "admin_user"
#                 }
#             ]
#         }
#     },

# Using parsed:

# _parsed_snmp.cfg
# set service snmp community routers authorization 'ro'
# set service snmp community routers client '203.0.113.10'
# set service snmp community routers client '203.0.113.20'
# set service snmp community routers network '192.0.2.0/24'
# set service snmp community routers network '2001::/64'
# set service snmp contact 'admin@example.com'
# set service snmp listen-address 172.16.254.36 port '161'
# set service snmp listen-address 2001::1
# set service snmp location 'UK, London'
# set service snmp trap-target 203.0.113.10
# set service snmp v3 engineid '000000000000000000000002'
# set service snmp v3 group default mode 'ro'
# set service snmp v3 group default view 'default'
# set service snmp v3 user vyos auth plaintext-key 'vyos12345678'
# set service snmp v3 user vyos auth type 'sha'
# set service snmp v3 user vyos group 'default'
# set service snmp v3 user vyos privacy plaintext-key 'vyos12345678'
# set service snmp v3 user vyos privacy type 'aes'
# set service snmp v3 view default oid 1

- name: Parse SNMP server config
  vyos.vyos.vyos_snmp_server:
    running_config: "{{ lookup('file', './_parsed_snmp.cfg') }}"
    state: parsed

# Module Execution:
# "parsed": {
#         "communities": [
#             {
#                 "authorization_type": "ro",
#                 "clients": [
#                     "203.0.113.10",
#                     "203.0.113.20"
#                 ],
#                 "name": "routers",
#                 "networks": [
#                     "192.0.2.0/24",
#                     "2001::/64"
#                 ]
#             }
#         ],
#         "contact": "admin@example.com",
#         "listen_addresses": [
#             {
#                 "address": "172.16.254.36",
#                 "port": 161
#             },
#             {
#                 "address": "2001::1"
#             }
#         ],
#         "location": "UK, London",
#         "snmp_v3": {
#             "engine_id": "000000000000000000000002",
#             "groups": [
#                 {
#                     "group": "default",
#                     "mode": "ro",
#                     "view": "default"
#                 }
#             ],
#             "users": [
#                 {
#                     "authentication": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "sha"
#                     },
#                     "group": "default",
#                     "privacy": {
#                         "plaintext_key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
#                         "type": "aes"
#                     },
#                     "user": "vyos"
#                 }
#             ],
#             "views": [
#                 {
#                     "oid": "1",
#                     "view": "default"
#                 }
#             ]
#         },
#         "trap_target": {
#             "address": "203.0.113.10"
#         }
#     }
#
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
   - "set service snmp community routers authorization 'ro'"
   - "set service snmp community routers client '203.0.113.10'"
   - "set service snmp community routers network '192.0.2.0/24'"
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
   - "set service snmp community routers authorization 'ro'"
   - "set service snmp community routers client '203.0.113.10'"
   - "set service snmp community routers network '192.0.2.0/24'"
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

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.snmp_server.snmp_server import (
    Snmp_serverArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.config.snmp_server.snmp_server import (
    Snmp_server,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Snmp_serverArgs.argument_spec,
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

    result = Snmp_server(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
