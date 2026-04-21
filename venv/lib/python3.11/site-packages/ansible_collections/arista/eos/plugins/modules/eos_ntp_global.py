#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for eos_ntp_global
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: eos_ntp_global
short_description: Manages ntp resource module
description: This module configures and manages the attributes of  ntp on Arista
  EOS platforms.
version_added: 3.1.0
author: Gomathi Selvi Srinivasan (@GomathiselviS)
notes:
- Tested against Arista EOS 4.24.60M
- This module works with connection C(network_cli). See the U(https://docs.ansible.com/ansible/latest/network/user_guide/platform_eos.html).
options:
    config:
      description: A dictionary of ntp options
      type: dict
      suboptions:
        authenticate:
          description:
          - Require authentication for NTP synchronization.
          type: dict
          suboptions:
            enable:
              description: Enable authentication for NTP synchronization.
              type: bool
            servers:
              description: Authentication required only for incoming NTP server responses.
              type: bool
        authentication_keys:
          description:
          - Define a key to use for authentication.
          type: list
          elements: dict
          suboptions:
            id:
              description: key identifier.
              type: int
            algorithm:
              description: hash algorithm,
              type: str
              choices: ["md5", "sha1"]
            encryption:
              description: key type
              type: int
              choices: [0, 7]
            key:
              description: Unobfuscated key string.
              type: str
        local_interface:
          description: Configure the interface from which the IP source address is taken.
          type: str
        qos_dscp:
          description: Set DSCP value in IP header
          type: int
        serve:
          description: Configure the switch as an NTP server.
          type: dict
          suboptions:
            all:
              description: Service NTP requests received on any interface.
              type: bool
            access_lists:
              description: Configure access control list.
              type: list
              elements: dict
              suboptions:
                afi:
                  description: ip/ipv6 config commands.
                  type: str
                acls:
                  description: Access lists to be configured under the afi
                  type: list
                  elements: dict
                  suboptions:
                    acl_name:
                      description: Name of the access list.
                      type: str
                    direction:
                      description: direction for the packets.
                      type: str
                      choices: ["in", "out"]
                    vrf:
                      description: VRF in which to apply the access control list.
                      type: str
        servers:
          description: Configure NTP server to synchronize to.
          type: list
          elements: dict
          suboptions:
            vrf:
              description: vrf name.
              type: str
            server:
              description: Hostname or A.B.C.D or A:B:C:D:E:F:G:H.
              type: str
              required: true
            burst:
              description: Send a burst of packets instead of the usual one.
              type: bool
            iburst:
              description: Send bursts of packets until the server is reached
              type: bool
            key_id:
              description: Set a key to use for authentication.
              type: int
            local_interface:
              description: Configure the interface from which the IP source address is taken.
              type: str
            source:
              description: Configure the interface from which the IP source address is taken.
              type: str
            maxpoll:
              description: Maximum poll interval.
              type: int
            minpoll:
              description: Minimum poll interval.
              type: int
            prefer:
              description: Mark this server as preferred.
              type: bool
            version:
              description: NTP version.
              type: int
        trusted_key:
          description: Configure the set of keys that are accepted for incoming messages
          type: str
    running_config:
      description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the EOS device by
        executing the command B(show running-config | section ntp).
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
      type: str
    state:
      description:
        - The state the configuration should be left in.
        - The states I(replaced) and I(overridden) have identical
          behaviour for this module.
        - Please refer to examples for more details.
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

# Before state:
# -------------
# localhost(config)#show running-config | section ntp
# localhost(config)#

- name: Merge provided configuration with device configuration
  arista.eos.eos_ntp_global:
    config:
      authenticate:
        enable: true
      authentication_keys:
        - id: 2
          algorithm: "sha1"
          encryption: 7
          key: "123456"
        - id: 23
          algorithm: "md5"
          encryption: 7
          key: "123456"
      local_interface: "Ethernet1"
      qos_dscp: 10
      trusted_key: 23
      servers:
        - server: "10.1.1.1"
          vrf: "vrf01"
          burst: true
          prefer: true
        - server: "25.1.1.1"
          vrf: "vrf01"
          maxpoll: 15
          key_id: 2
      serve:
        access_lists:
          - afi: "ip"
            acls:
              - acl_name: "acl01"
                direction: "in"
          - afi: "ipv6"
            acls:
              - acl_name: "acl02"
                direction: "in"

# After State

# localhost(config)#show running-config | section ntp
# ntp authentication-key 2 sha1 7 123456
# ntp authentication-key 23 md5 7 123456
# ntp trusted-key 23
# ntp authenticate
# ntp local-interface Ethernet1
# ntp qos dscp 10
# ntp server vrf vrf01 10.1.1.1 prefer burst
# ntp server vrf vrf01 25.1.1.1 maxpoll 15 key 2
# ntp serve ip access-group acl01 in
# ntp serve ipv6 access-group acl02 in
# localhost(config)#
#
#
# Module Execution:
# "after": {
#         "authenticate": {
#             "enable": true
#         },
#         "authentication_keys": [
#             {
#                 "algorithm": "sha1",
#                 "encryption": 7,
#                 "id": 2,
#                 "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#             },
#             {
#                 "algorithm": "md5",
#                 "encryption": 7,
#                 "id": 23,
#                 "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#             }
#         ],
#         "local_interface": "Ethernet1",
#         "qos_dscp": 10,
#         "serve": {
#             "access_lists": [
#                 {
#                     "acls": [
#                         {
#                             "acl_name": "acl01",
#                             "direction": "in"
#                         }
#                     ],
#                     "afi": "ip"
#                 },
#                 {
#                     "acls": [
#                         {
#                             "acl_name": "acl02",
#                             "direction": "in"
#                         }
#                     ],
#                     "afi": "ipv6"
#                 }
#             ]
#         },
#         "servers": [
#             {
#                 "burst": true,
#                 "prefer": true,
#                 "server": "10.1.1.1",
#                 "vrf": "vrf01"
#             },
#             {
#                 "key_id": 2,
#                 "maxpoll": 15,
#                 "server": "25.1.1.1",
#                 "vrf": "vrf01"
#             }
#         ],
#         "trusted_key": "23"
#     },
#     "before": {},
#     "changed": true,
#     "commands": [
#         "ntp serve ip access-group acl01 in",
#         "ntp serve ipv6 access-group acl02 in",
#         "ntp authentication-key 2 sha1 7 ********",
#         "ntp authentication-key 23 md5 7 ********",
#         "ntp server vrf vrf01 10.1.1.1 burst prefer",
#         "ntp server vrf vrf01 25.1.1.1 key 2 maxpoll 15",
#         "ntp authenticate",
#         "ntp local-interface Ethernet1",
#         "ntp qos dscp 10",
#         "ntp trusted-key 23"
#     ],

# Using Replaced

# Before State

# localhost(config)#show running-config | section ntp
# ntp authentication-key 2 sha1 7 123456
# ntp authentication-key 23 md5 7 123456
# ntp trusted-key 23
# ntp authenticate
# ntp local-interface Ethernet1
# ntp qos dscp 10
# ntp server vrf vrf01 10.1.1.1 prefer burst
# ntp server vrf vrf01 25.1.1.1 maxpoll 15 key 2
# ntp serve ip access-group acl01 in
# ntp serve ipv6 access-group acl02 in
# localhost(config)#

- name: Replace
  arista.eos.eos_ntp_global:
    config:
      qos_dscp: 15
      authentication_keys:
        - id: 2
          algorithm: "md5"
          encryption: 7
          key: "123456"
      servers:
        - server: "11.21.1.1"
          vrf: "vrf01"
          burst: true
          prefer: true
          minpoll: 13
      serve:
        access_lists:
          - afi: "ip"
            acls:
              - acl_name: "acl03"
                direction: "in"
    state: replaced

# After State:
# localhost(config)#show running-config | section ntp
# ntp authentication-key 2 md5 7 123456
# ntp qos dscp 15
# ntp server vrf vrf01 11.21.1.1 prefer burst minpoll 13
# ntp serve ip access-group acl03 in
# localhost(config)#
#
#
# Module Execution:
# "after": {
#        "authentication_keys": [
#            {
#                "algorithm": "md5",
#                "encryption": 7,
#                "id": 2,
#                "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#            }
#        ],
#        "qos_dscp": 15,
#        "serve": {
#            "access_lists": [
#                {
#                    "acls": [
#                        {
#                            "acl_name": "acl03",
#                            "direction": "in"
#                        }
#                    ],
#                    "afi": "ip"
#                }
#            ]
#        },
#        "servers": [
#            {
#                "burst": true,
#                "minpoll": 13,
#                "prefer": true,
#                "server": "11.21.1.1",
#                "vrf": "vrf01"
#            }
#        ]
#    },
#    "before": {
#        "authenticate": {
#            "enable": true
#        },
#        "authentication_keys": [
#            {
#                "algorithm": "sha1",
#                "encryption": 7,
#                "id": 2,
#                "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#            },
#            {
#                "algorithm": "md5",
#                "encryption": 7,
#                "id": 23,
#                "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#            }
#        ],
#        "local_interface": "Ethernet1",
#        "qos_dscp": 10,
#        "serve": {
#            "access_lists": [
#                {
#                    "acls": [
#                        {
#                            "acl_name": "acl01",
#                            "direction": "in"
#                        }
#                    ],
#                    "afi": "ip"
#                },
#                {
#                    "acls": [
#                        {
#                            "acl_name": "acl02",
#                            "direction": "in"
#                        }
#                    ],
#                    "afi": "ipv6"
#                }
#            ]
#        },
#        "servers": [
#            {
#                "burst": true,
#                "prefer": true,
#                "server": "10.1.1.1",
#                "vrf": "vrf01"
#            },
#            {
#                "key_id": 2,
#                "maxpoll": 15,
#                "server": "25.1.1.1",
#                "vrf": "vrf01"
#            }
#        ],
#        "trusted_key": "23"
#    },
#    "changed": true,
#    "commands": [
#        "no ntp serve ip access-group acl01 in",
#        "no ntp serve ipv6 access-group acl02 in",
#        "no ntp authentication-key 23 md5 7 ********",
#        "no ntp server vrf vrf01 10.1.1.1 burst prefer",
#        "no ntp server vrf vrf01 25.1.1.1 key 2 maxpoll 15",
#        "no ntp authenticate",
#        "no ntp local-interface Ethernet1",
#        "no ntp trusted-key 23",
#        "ntp serve ip access-group acl03 in",
#        "ntp authentication-key 2 md5 7 ********",
#        "ntp server vrf vrf01 11.21.1.1 burst minpoll 13 prefer",
#        "ntp qos dscp 15"
#    ],
#
# Using Overridden

# Before State

# localhost(config)#show running-config | section ntp
# ntp authentication-key 2 sha1 7 123456
# ntp authentication-key 23 md5 7 123456
# ntp trusted-key 23
# ntp authenticate
# ntp local-interface Ethernet1
# ntp qos dscp 10
# ntp server vrf vrf01 10.1.1.1 prefer burst
# ntp server vrf vrf01 25.1.1.1 maxpoll 15 key 2
# ntp serve ip access-group acl01 in
# ntp serve ipv6 access-group acl02 in
# localhost(config)#

- name: Replace
  arista.eos.eos_ntp_global:
    config:
      qos_dscp: 15
      authentication_keys:
        - id: 2
          algorithm: "md5"
          encryption: 7
          key: "123456"
      servers:
        - server: "11.21.1.1"
          vrf: "vrf01"
          burst: true
          prefer: true
          minpoll: 13
      serve:
        access_lists:
          - afi: "ip"
            acls:
              - acl_name: "acl03"
                direction: "in"
    state: overridden

# After State:
# localhost(config)#show running-config | section ntp
# ntp authentication-key 2 md5 7 123456
# ntp qos dscp 15
# ntp server vrf vrf01 11.21.1.1 prefer burst minpoll 13
# ntp serve ip access-group acl03 in
# localhost(config)#
#
#
# Module Execution:
# "after": {
#        "authentication_keys": [
#            {
#                "algorithm": "md5",
#                "encryption": 7,
#                "id": 2,
#                "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#            }
#        ],
#        "qos_dscp": 15,
#        "serve": {
#            "access_lists": [
#                {
#                    "acls": [
#                        {
#                            "acl_name": "acl03",
#                            "direction": "in"
#                        }
#                    ],
#                    "afi": "ip"
#                }
#            ]
#        },
#        "servers": [
#            {
#                "burst": true,
#                "minpoll": 13,
#                "prefer": true,
#                "server": "11.21.1.1",
#                "vrf": "vrf01"
#            }
#        ]
#    },
#    "before": {
#        "authenticate": {
#            "enable": true
#        },
#        "authentication_keys": [
#            {
#                "algorithm": "sha1",
#                "encryption": 7,
#                "id": 2,
#                "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#            },
#            {
#                "algorithm": "md5",
#                "encryption": 7,
#                "id": 23,
#                "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#            }
#        ],
#        "local_interface": "Ethernet1",
#        "qos_dscp": 10,
#        "serve": {
#            "access_lists": [
#                {
#                    "acls": [
#                        {
#                            "acl_name": "acl01",
#                            "direction": "in"
#                        }
#                    ],
#                    "afi": "ip"
#                },
#                {
#                    "acls": [
#                        {
#                            "acl_name": "acl02",
#                            "direction": "in"
#                        }
#                    ],
#                    "afi": "ipv6"
#                }
#            ]
#        },
#        "servers": [
#            {
#                "burst": true,
#                "prefer": true,
#                "server": "10.1.1.1",
#                "vrf": "vrf01"
#            },
#            {
#                "key_id": 2,
#                "maxpoll": 15,
#                "server": "25.1.1.1",
#                "vrf": "vrf01"
#            }
#        ],
#        "trusted_key": "23"
#    },
#    "changed": true,
#    "commands": [
#        "no ntp serve ip access-group acl01 in",
#        "no ntp serve ipv6 access-group acl02 in",
#        "no ntp authentication-key 23 md5 7 ********",
#        "no ntp server vrf vrf01 10.1.1.1 burst prefer",
#        "no ntp server vrf vrf01 25.1.1.1 key 2 maxpoll 15",
#        "no ntp authenticate",
#        "no ntp local-interface Ethernet1",
#        "no ntp trusted-key 23",
#        "ntp serve ip access-group acl03 in",
#        "ntp authentication-key 2 md5 7 ********",
#        "ntp server vrf vrf01 11.21.1.1 burst minpoll 13 prefer",
#        "ntp qos dscp 15"
#    ],
#

# using deleted:
# Before State

# localhost(config)#show running-config | section ntp
# ntp authentication-key 2 sha1 7 123456
# ntp authentication-key 23 md5 7 123456
# ntp trusted-key 23
# ntp authenticate
# ntp local-interface Ethernet1
# ntp qos dscp 10
# ntp server vrf vrf01 10.1.1.1 prefer burst
# ntp server vrf vrf01 11.21.1.1 prefer burst minpoll 13
# ntp server vrf vrf01 25.1.1.1 maxpoll 15 key 2
# ntp serve ip access-group acl01 in
# ntp serve ipv6 access-group acl02 in
# localhost(config)#

- name: Delete  ntp-global
  arista.eos.eos_ntp_global:
    state: deleted

# After State:
#  localhost(config)#show running-config | section ntp
# localhost(config)#
#
#
# # Module Execution
# "after": {},
#     "before": {
#         "authenticate": {
#             "enable": true
#         },
#         "authentication_keys": [
#             {
#                 "algorithm": "sha1",
#                 "encryption": 7,
#                 "id": 2,
#                 "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#             },
#             {
#                 "algorithm": "md5",
#                 "encryption": 7,
#                 "id": 23,
#                 "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#             }
#         ],
#         "local_interface": "Ethernet1",
#         "qos_dscp": 10,
#         "serve": {
#             "access_lists": [
#                 {
#                     "acls": [
#                         {
#                             "acl_name": "acl01",
#                             "direction": "in"
#                         }
#                     ],
#                     "afi": "ip"
#                 },
#                 {
#                     "acls": [
#                         {
#                             "acl_name": "acl02",
#                             "direction": "in"
#                         }
#                     ],
#                     "afi": "ipv6"
#                 }
#             ]
#         },
#         "servers": [
#             {
#                 "burst": true,
#                 "prefer": true,
#                 "server": "10.1.1.1",
#                 "vrf": "vrf01"
#             },
#             {
#                 "burst": true,
#                 "minpoll": 13,
#                 "prefer": true,
#                 "server": "11.21.1.1",
#                 "vrf": "vrf01"
#             },
#             {
#                 "key": 2,
#                 "maxpoll": 15,
#                 "server": "25.1.1.1",
#                 "vrf": "vrf01"
#             }
#         ],
#         "trusted_key": "23"
#     },
#     "changed": true,
#     "commands": [
#         "no ntp serve ip access-group acl01 in",
#         "no ntp serve ipv6 access-group acl02 in",
#         "no ntp authentication-key 2 sha1 7 ********",
#         "no ntp authentication-key 23 md5 7 ********",
#         "no ntp server vrf vrf01 10.1.1.1 burst prefer",
#         "no ntp server vrf vrf01 11.21.1.1 burst minpoll 13 prefer",
#         "no ntp server vrf vrf01 25.1.1.1 key 2 maxpoll 15",
#         "no ntp authenticate",
#         "no ntp local-interface Ethernet1",
#         "no ntp qos dscp 10",
#         "no ntp trusted-key 23"
#     ],
#

# Using parsed:
# parsed.cfg
# ntp authentication-key 2 sha1 7 123456
# ntp authentication-key 23 md5 7 123456
# ntp trusted-key 23
# ntp authenticate
# ntp local-interface Ethernet1
# ntp qos dscp 10
# ntp server vrf vrf01 10.1.1.1 prefer burst
# ntp server vrf vrf01 11.21.1.1 prefer burst minpoll 13
# ntp server vrf vrf01 25.1.1.1 maxpoll 15 key 2
# ntp serve ip access-group acl01 in
# ntp serve ipv6 access-group acl02 in

- name: parse configs
  arista.eos.eos_ntp_global:
    running_config: "{{ lookup('file', './parsed_ntp_global.cfg') }}"
    state: parsed
  tags:
    - parsed

# Module Execution
# "parsed": {
#         "authenticate": {
#             "enable": true
#         },
#         "authentication_keys": [
#             {
#                 "algorithm": "sha1",
#                 "encryption": 7,
#                 "id": 2,
#                 "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#             },
#             {
#                 "algorithm": "md5",
#                 "encryption": 7,
#                 "id": 23,
#                 "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#             }
#         ],
#         "local_interface": "Ethernet1",
#         "qos_dscp": 10,
#         "serve": {
#             "access_lists": [
#                 {
#                     "acls": [
#                         {
#                             "acl_name": "acl01",
#                             "direction": "in"
#                         }
#                     ],
#                     "afi": "ip"
#                 },
#                 {
#                     "acls": [
#                         {
#                             "acl_name": "acl02",
#                             "direction": "in"
#                         }
#                     ],
#                     "afi": "ipv6"
#                 }
#             ]
#         },
#         "servers": [
#             {
#                 "burst": true,
#                 "prefer": true,
#                 "server": "10.1.1.1",
#                 "vrf": "vrf01"
#             },
#             {
#                 "burst": true,
#                 "minpoll": 13,
#                 "prefer": true,
#                 "server": "11.21.1.1",
#                 "vrf": "vrf01"
#             },
#             {
#                 "key": 2,
#                 "maxpoll": 15,
#                 "server": "25.1.1.1",
#                 "vrf": "vrf01"
#             }
#         ],
#         "trusted_key": "23"
#     }
# }

# using Gathered
# Device config:
# localhost(config)#show running-config | section ntp
# ntp authentication-key 2 sha1 7 123456
# ntp authentication-key 23 md5 7 123456
# ntp trusted-key 23
# ntp authenticate
# ntp local-interface Ethernet1
# ntp qos dscp 10
# ntp server vrf vrf01 10.1.1.1 prefer burst
# ntp server vrf vrf01 25.1.1.1 maxpoll 15 key 2
# ntp serve ip access-group acl01 in
# ntp serve ipv6 access-group acl02 in
# localhost(config)#

- name: gather configs
  arista.eos.eos_ntp_global:
    state: gathered
  tags:
    - gathered

# Module Execution

#   "gathered": {
#         "authenticate": {
#             "enable": true
#         },
#         "authentication_keys": [
#             {
#                 "algorithm": "sha1",
#                 "encryption": 7,
#                 "id": 2,
#                 "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#             },
#             {
#                 "algorithm": "md5",
#                 "encryption": 7,
#                 "id": 23,
#                 "key": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
#             }
#         ],
#         "local_interface": "Ethernet1",
#         "qos_dscp": 10,
#         "serve": {
#             "access_lists": [
#                 {
#                     "acls": [
#                         {
#                             "acl_name": "acl01",
#                             "direction": "in"
#                         }
#                     ],
#                     "afi": "ip"
#                 },
#                 {
#                     "acls": [
#                         {
#                             "acl_name": "acl02",
#                             "direction": "in"
#                         }
#                     ],
#                     "afi": "ipv6"
#                 }
#             ]
#         },
#         "servers": [
#             {
#                 "burst": true,
#                 "prefer": true,
#                 "server": "10.1.1.1",
#                 "vrf": "vrf01"
#             },
#             {
#                 "key_id": 2,
#                 "maxpoll": 15,
#                 "server": "25.1.1.1",
#                 "vrf": "vrf01"
#             }
#         ],
#         "trusted_key": "23"
#     },
#     "invocation": {
#         "module_args": {
#             "config": null,
#             "running_config": null,
#             "state": "gathered"
#         }
#     }
# }

# using rendered:

- name: Render provided configuration
  arista.eos.eos_ntp_global:
    config:
      authenticate:
        enable: true
      authentication_keys:
        - id: 2
          algorithm: "sha1"
          encryption: 7
          key: "123456"
        - id: 23
          algorithm: "md5"
          encryption: 7
          key: "123456"
      local_interface: "Ethernet1"
      qos_dscp: 10
      trusted_key: 23
      servers:
        - server: "10.1.1.1"
          vrf: "vrf01"
          burst: true
          prefer: true
        - server: "25.1.1.1"
          vrf: "vrf01"
          maxpoll: 15
          key_id: 2
      serve:
        access_lists:
          - afi: "ip"
            acls:
              - acl_name: "acl01"
                direction: "in"
          - afi: "ipv6"
            acls:
              - acl_name: "acl02"
                direction: "in"
    state: rendered

# Module Execution:
# "rendered": [
#         "ntp serve ip access-group acl01 in",
#         "ntp serve ipv6 access-group acl02 in",
#         "ntp authentication-key 2 sha1 7 ********",
#         "ntp authentication-key 23 md5 7 ********",
#         "ntp server vrf vrf01 10.1.1.1 burst prefer",
#         "ntp server vrf vrf01 25.1.1.1 key 2 maxpoll 15",
#         "ntp authenticate",
#         "ntp local-interface Ethernet1",
#         "ntp qos dscp 10",
#         "ntp trusted-key 23"
#     ]
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
    - ntp master stratum 2
    - ntp peer 198.51.100.1 use-vrf test maxpoll 7
    - ntp authentication-key 10 md5 wawyhanx2 7
    - ntp access-group peer PeerAcl1
    - ntp access-group peer PeerAcl2
    - ntp access-group query-only QueryAcl1
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:

    - ntp authentication-key 2 sha1 7 123456
    - ntp authentication-key 23 md5 7 123456
    - ntp trusted-key 23
    - ntp authenticate
    - ntp local-interface Ethernet1
    - ntp qos dscp 10
    - ntp server vrf vrf01 10.1.1.1 prefer burst
    - ntp server vrf vrf01 25.1.1.1 maxpoll 15 key 2
    - ntp serve ip access-group acl01 in
    - ntp serve ipv6 access-group acl02 in

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

from ansible_collections.arista.eos.plugins.module_utils.network.eos.argspec.ntp_global.ntp_global import (
    Ntp_globalArgs,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.config.ntp_global.ntp_global import (
    Ntp_global,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Ntp_globalArgs.argument_spec,
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

    result = Ntp_global(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
