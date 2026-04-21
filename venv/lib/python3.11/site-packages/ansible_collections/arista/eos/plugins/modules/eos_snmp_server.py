#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for eos_snmp_server
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: eos_snmp_server
short_description: Manages snmp_server resource module
description: This module configures and manages the attributes of snmp_server on Arista
  EOS platforms.
version_added: 3.2.0
author: Gomathi Selvi Srinivasan (@GomathiselviS)
notes:
- Tested against Arista EOS 4.24.6F
- This module works with connection C(network_cli) and C(httpapi).
options:
  config:
    description: SNMP server configuration.
    type: dict
    suboptions:
      chassis_id:
        description: SNMP chassis identifier.
        type: str
      communities:
        description: Community name configuration.
        type: list
        elements: dict
        suboptions:
          name:
            description: Community name
            type: str
          acl_v4:
            description: standard access_list name
            type: str
          acl_v6:
            description: IPv6 access list name.
            type: str
          ro:
            description: Only reads are permitted.
            type: bool
          rw:
            description: Read_write access
            type: bool
          view:
            description: MIB view name
            type: str
      contact:
        description: Person to contact about the syste,.
        type: str
      traps:
        description: Enable traps to all configured recipients.
        type: dict
        suboptions:
          bgp:
            description: Enable Bgp traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              arista_backward_transition:
                description: arista_backward_transition
                type: bool
              arista_established:
                description: arista_established
                type: bool
              backward_transition:
                description: backward_transition
                type: bool
              established:
                description: established.
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          bridge:
            description: Enable Bridge traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              arista_mac_age:
                description: arista_mac_age
                type: bool
              arista_mac_learn:
                description: arista_mac_learn
                type: bool
              arista_mac_move:
                description: arista_mac_move
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          capacity:
            description: Enable Capacity traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              arista_hardware_utilization_alert:
                description: arista_hardware_utilization_alert
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          entity:
            description: Enable Entity traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              arista_ent_sensor_alarm:
                description: arista_ent_sensor_alarm
                type: bool
              ent_config_change:
                description: ent_config_change
                type: bool
              ent_state_oper:
                description: ent_state_oper
                type: bool
              ent_state_oper_disabled:
                description: ent_state_oper_disabled.
                type: bool
              ent_state_oper_enabled:
                description: ent_state_oper_enabled.
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          external_alarm:
            description: Enable external alarm traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              arista_external_alarm_asserted_notif:
                description: arista_external_alarm_asserted_notif
                type: bool
              arista_external_alarm_deasserted_notif:
                description: arista_external_alarm_deasserted_notif
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          isis:
            description: Enable isis traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              adjacency_change:
                description: adjacency_change
                type: bool
              area_mismatch:
                description: area_mismatch
                type: bool
              attempt_to_exceed_max_sequence:
                description: attempt_to_exceed_max_sequence
                type: bool
              authentication_type_failure:
                description: authentication_type_failure.
                type: bool
              database_overload:
                description: database_overload
                type: bool
              own_lsp_purge:
                description: own_lsp_purge
                type: bool
              rejected_adjacency:
                description: rejected_adjacency
                type: bool
              sequence_number_skip:
                description: sequence_number_skip.
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          lldp:
            description: Enable Lldp traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              rem_tables_change:
                description: rem_tables_change
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          mpls_ldp:
            description: Enable mpls_ldp traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              mpls_ldp_session_down:
                description: mpls_ldp_session_down
                type: bool
              mpls_ldp_session_up:
                description: mpls_ldp_session_up
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          msdp:
            description: Enable msdp traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              backward_transition:
                description: backward_transition.
                type: bool
              established:
                description: established.
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          ospf:
            description: Enable Ospf traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              if_config_error:
                description: if_config_error
                type: bool
              if_auth_failure:
                description: if_auth_failure
                type: bool
              if_state_change:
                description: if_state_change
                type: bool
              nbr_state_change:
                description: nbr_state_change.
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          ospfv3:
            description: Enable Ospfv3 traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              if_config_error:
                description: if_config_error
                type: bool
              if_rx_bad_packet:
                description: if_rx_bad_packet
                type: bool
              if_state_change:
                description: if_state_change
                type: bool
              nbr_state_change:
                description: nbr_state_change.
                type: bool
              nbr_restart_helper_status_change:
                description: Enable ospfv3NbrRestartHelperStatusChange trap
                type: bool
              nssa_translator_status_change:
                description: Enable ospfv3NssaTranslatorStatusChange trap
                type: bool
              restart_status_change:
                description: restart_status_change
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          pim:
            description: Enable Pim traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              neighbor_loss:
                description: neighbor_loss
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          snmp:
            description: Enable snmp traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              authentication:
                description: authentication
                type: bool
              link_down:
                description: link_down
                type: bool
              link_up:
                description: link_up
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          snmpConfigManEvent:
            description: Enable snmpConfigManEvent traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              arista_config_man_event:
                description: arista_config_man_event
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          switchover:
            description: Enable switchover traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              arista_redundancy_switch_over_notif:
                description: arista_redundancy_switch_over_notif
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          test:
            description: Enable test traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              arista_test_notification:
                description: arista_test_notification
                type: bool
              enabled:
                description: All traps are set.
                type: bool
          vrrp:
            description: Enable vrrp traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              trap_new_master:
                description: vrrp
                type: bool
              enabled:
                description: All traps are set.
                type: bool
      engineid:
        description: SNMPv3 engine ID configuration.
        type: dict
        suboptions:
          local:
            description:  Local SNMP agent
            type: str
          remote:
            description: Remote SNMP agent
            type: dict
            suboptions:
              host:
                description: Hostname or IP address of remote SNMP notification host
                type: str
              udp_port:
                description: The remote SNMP notification host's UDP port number.
                type: int
              id:
                description: engine ID octet string
                type: str
      extension:
        description: Configure extension script to serve an OID range
        type: dict
        suboptions:
          root_oid:
            description: Extension root oid
            type: str
          script_location:
            description: script location
            type: str
          oneshot:
            description: Use inefficient one_shot interface
            type: bool
      groups:
        description: SNMP USM group
        type: list
        elements: dict
        suboptions:
          group:
            description: SNMP group for the user
            type: str
          version:
            description: snmp security group version
            type: str
            choices: ['v1', 'v3', 'v2c']
          auth_privacy:
            description: auth and privacy config. Valid when version = v3.
            type: str
            choices: ['auth', 'noauth', 'priv']
          context:
            description: Specify a context to associate with the group
            type: str
          notify:
            description: View to restrict notifications
            type: str
          read:
            description: View to restrict read access
            type: str
          write:
            description: View to restrict write access
            type: str
      hosts:
        description: Notification destinations
        type: list
        elements: dict
        suboptions:
          host:
            description: Hostname or IP address of SNMP notification host.
            type: str
          user:
            description: Community or user name.
            type: str
          udp_port:
            description: UDP destination port for notification messages.
            type: int
          informs:
            description: Use SNMP inform messages.
            type: bool
          traps:
            description: Use SNMP trap messages
            type: bool
          version:
            description: Notification message SNMP version.
            type: str
            choices: ['1', '2c', '3 auth', '3 noauth', '3 priv']
          vrf:
            description: Specify the VRF in which the host is configured
            type: str
      acls:
        description: ipv4/ipv6 access_lists
        type: list
        elements: dict
        suboptions:
          afi:
            description: ipv4/ipv6
            type: str
            choices: ['ipv4', 'ipv6']
          acl:
            description: acl name
            type: str
          vrf:
            description: vrf name
            type: str
      local_interface:
        description: Configure the source interface for SNMP notifications.
        type: str
      location:
        description: The sysLocation string.
        type: str
      notification:
        description: Maximum number of notifications in the log
        type: int
      objects:
        description: when true Disable implementation of a group of objects
        type: dict
        suboptions:
          mac_address_tables:
            description: dot1dTpFdbTable, dot1qTpFdbTable
            type: bool
          route_tables:
            description: ipCidrRouteTable, ipCidrRouteNumber, aristaFIBStats*
            type: bool
      qos:
        description: Configure QoS parameters.
        type: int
      qosmib:
        description: Set QOS_MIB counter update interval
        type: int
      transmit:
        description: Maximum number of bytes in SNMP message (UDP/TCP payload)
        type: int
      transport:
        description: Enable snmpd transport layer protocol
        type: str
      users:
        description: SNMP user configuration.
        type: list
        elements: dict
        suboptions:
          user:
            description: SNMP user name
            type: str
          group:
            description: SNMP group for the user.
            type: str
          remote:
            description: System where an SNMPv3 user is hosted
            type: str
          udp_port:
            description: UDP port used by the remote SNMP system
            type: int
          version:
            description: snmp security version
            type: str
            choices: ['v1', 'v2c', 'v3']
          auth:
            description: User authentication settings
            type: dict
            suboptions:
              algorithm:
                description: algorithm for authentication
                type: str
              auth_passphrase:
                description: authentication passphrase hex string
                type: str
              encryption:
                description: algorithm for encryption.
                type: str
              priv_passphrase:
                description: privacy passphrase hexstring
                type: str
          localized:
            description: localized auth and privacy passphrases.
            type: dict
            suboptions:
              engineid:
                description: Engine id
                type: str
              algorithm:
                description: algorithm for authentication
                type: str
              auth_passphrase:
                description: authentication passphrase hex string
                type: str
              encryption:
                description: algorithm for encryption.
                type: str
              priv_passphrase:
                description: privacy passphrase hexstring
                type: str
      views:
        description: SNMPv2 MIB view configuration
        type: list
        elements: dict
        suboptions:
          view:
            description: SNMP view name
            type: str
          mib:
            description: SNMP MIB name
            type: str
          action:
            description: Action to be performed.
            type: str
            choices: ['excluded', 'included']
      vrfs:
        description: Specify the VRF in which the source address is used
        type: list
        elements: dict
        suboptions:
          vrf:
            description: vrf name.
            type: str
          local_interface:
            description: Configure the source interface for SNMP notifications
            type: str
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the EOS device by
      executing the command B(show running_config | section snmp_server).
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
    choices: [deleted, merged, overridden, replaced, gathered, rendered, parsed]
    default: merged
"""

EXAMPLES = """
# Using merged:

# Before State
# eos#show running-config | section snmp-server
# eos#

- name: merge given snmp_server configuration
  arista.eos.eos_snmp_server:
    config:
      communities:
        - name: "comm3"
          acl_v6: "list1"
          view: "view1"
        - name: "comm4"
          acl_v4: "list3"
          view: "view1"
        - name: "comm5"
          acl_v4: "list4"
          ro: true
      contact: "admin"
      engineid:
        remote:
          host: 1.1.1.1
          id: "1234567"
      groups:
        - group: "group1"
          version: "v1"
          read: "view1"
        - group: "group2"
          version: "v3"
          auth_privacy: "priv"
          notify: "view1"
          write: "view2"
      hosts:
        - host: "host02"
          user: "user01"
          udp_port: 23
          version: "2c"
        - host: "host01"
          user: "user01"
          udp_port: 23
          version: "3 priv"
      traps:
        capacity:
          arista_hardware_utilization_alert: true
        bgp:
          enabled: true
        external_alarm:
          arista_external_alarm_deasserted_notif: true
          arista_external_alarm_asserted_notif: true
      vrfs:
        - vrf: "vrf01"
          local_interface: "Ethernet1"

# After state
# eos#show running-config | section snmp-server
# snmp-server community comm3 view view1 ipv6 list1
# snmp-server community comm4 view view1 list3
# snmp-server community comm5 ro list4
# snmp-server group group1 v1 read view1
# snmp-server group group2 v3 priv write view2 notify view1
# snmp-server host host02 version 2c user01 udp-port 23
# snmp-server host host01 version 3 priv user01 udp-port 23
# snmp-server vrf vrf01 local-interface Ethernet1
# snmp-server contact admin
# snmp-server enable traps bgp
# snmp-server enable traps capacity arista-hardware-utilization-alert
# snmp-server enable traps external-alarm arista-external-alarm-asserted-notif arista-external-alarm-deasserted-notif
#
# Module Execution
#
# "after": {
#         "communities": [
#             {
#                 "acl_v6": "list1",
#                 "name": "comm3",
#                 "ro": true,
#                 "view": "view1"
#             },
#             {
#                 "acl_v4": "list3",
#                 "name": "comm4",
#                 "ro": true,
#                 "view": "view1"
#             },
#             {
#                 "acl_v4": "list4",
#                 "name": "comm5",
#                 "ro": true
#             }
#         ],
#         "contact": "admin",
#         "groups": [
#             {
#                 "group": "group1",
#                 "read": "view1",
#                 "version": "v1"
#             },
#             {
#                 "auth_privacy": "priv",
#                 "group": "group2",
#                 "notify": "view1",
#                 "version": "v3",
#                 "write": "view2"
#             }
#         ],
#         "hosts": [
#             {
#                 "host": "host01",
#                 "udp_port": 23,
#                 "user": "user01",
#                 "version": "3 priv"
#             },
#             {
#                 "host": "host02",
#                 "udp_port": 23,
#                 "user": "user01",
#                 "version": "2c"
#             }
#         ],
#         "traps": {
#             "bgp": {
#                 "enabled": true
#             },
#             "capacity": {
#                 "arista_hardware_utilization_alert": true
#             },
#             "external_alarm": {
#                 "arista_external_alarm_asserted_notif": true,
#                 "arista_external_alarm_deasserted_notif": true
#             }
#         },
#         "vrfs": [
#             {
#                 "local_interface": "Ethernet1",
#                 "vrf": "vrf01"
#             }
#         ]
#     },
#     "before": {},
#     "changed": true,
#     "commands": [
#         "snmp-server community comm3 view view1 ipv6 list1",
#         "snmp-server community comm4 view view1 list3",
#         "snmp-server community comm5 ro list4",
#         "snmp-server group group1 v1 read view1",
#         "snmp-server group group2 v3 priv write view2 notify view1",
#         "snmp-server host host02 version 2c user01 udp-port 23",
#         "snmp-server host host01 version 3 priv user01 udp-port 23",
#         "snmp-server vrf vrf01 local-interface Ethernet1",
#         "snmp-server contact admin",
#         "snmp-server engineID remote 1.1.1.1 1234567",
#         "snmp-server enable traps bgp",
#         "snmp-server enable traps capacity arista-hardware-utilization-alert",
#         "snmp-server enable traps external-alarm arista-external-alarm-asserted-notif arista-external-alarm-deasserted-notif"
#     ],
#

# Using replaced:

# Before State:
# eos#show running-config | section snmp-server
# snmp-server community comm3 view view1 ipv6 list1
# snmp-server community comm4 view view1 list3
# snmp-server community comm5 ro list4
# snmp-server group group1 v1 read view1
# snmp-server group group2 v3 priv write view2 notify view1
# snmp-server host host02 version 2c user01 udp-port 23
# snmp-server host host01 version 3 priv user01 udp-port 23
# snmp-server vrf vrf01 local-interface Ethernet1
# snmp-server contact admin
# snmp-server enable traps bgp
# snmp-server enable traps capacity arista-hardware-utilization-alert
# snmp-server enable traps external-alarm arista-external-alarm-asserted-notif arista-external-alarm-deasserted-notif

- name: Replace given snmp_server configuration
  become: true
  register: result
  arista.eos.eos_snmp_server: &replaced
    state: replaced
    config:
      communities:
        - name: "comm3"
          acl_v6: "list1"
          view: "view1"
        - name: "replacecomm"
          acl_v4: "list4"
      extension:
        root_oid: "123456"
        script_location: "flash:"
      traps:
        test:
          arista_test_notification: true
        bgp:
          enabled: true
      vrfs:
        - vrf: "vrf_replace"
          local_interface: "Ethernet1"

# After State:

# eos#show running-config | section snmp-server
# snmp-server community comm3 view view1 ipv6 list1
# snmp-server community replacecomm list4
# snmp-server vrf vrf_replace local-interface Ethernet1
# snmp-server extension 123456 flash:
# snmp-server enable traps test arista-test-notification
# snmp-server enable traps bgp

# Module Execution:
#    "after": {
#        "communities": [
#            {
#                "acl_v6": "list1",
#                "name": "comm3",
#                "ro": true,
#                "view": "view1"
#            },
#            {
#                "acl_v4": "list4",
#                "name": "replacecomm",
#                "ro": true
#            }
#        ],
#        "extension": {
#            "root_oid": "0.123456",
#            "script_location": "flash:"
#        },
#        "traps": {
#            "bgp": {
#                "enabled": true
#            },
#            "test": {
#                "arista_test_notification": true
#            }
#        },
#        "vrfs": [
#            {
#                "local_interface": "Ethernet1",
#                "vrf": "vrf_replace"
#            }
#        ]
#    },
#    "before": {
#        "communities": [
#            {
#                "acl_v6": "list1",
#                "name": "comm3",
#                "ro": true,
#                "view": "view1"
#            },
#            {
#                "acl_v4": "list3",
#                "name": "comm4",
#                "ro": true,
#                "view": "view1"
#            },
#            {
#                "acl_v4": "list4",
#                "name": "comm5",
#                "ro": true
#            }
#        ],
#        "contact": "admin",
#        "groups": [
#            {
#                "group": "group1",
#                "read": "view1",
#                "version": "v1"
#            },
#            {
#                "auth_privacy": "priv",
#                "group": "group2",
#                "notify": "view1",
#                "version": "v3",
#                "write": "view2"
#            }
#        ],
#        "hosts": [
#            {
#                "host": "host01",
#                "udp_port": 23,
#                "user": "user01",
#                "version": "3 priv"
#            },
#            {
#                "host": "host02",
#                "udp_port": 23,
#                "user": "user01",
#                "version": "2c"
#            }
#        ],
#        "traps": {
#            "bgp": {
#                "enabled": true
#            },
#            "capacity": {
#                "arista_hardware_utilization_alert": true
#            },
#            "external_alarm": {
#                "arista_external_alarm_asserted_notif": true,
#                "arista_external_alarm_deasserted_notif": true
#            }
#        },
#        "vrfs": [
#            {
#                "local_interface": "Ethernet1",
#                "vrf": "vrf01"
#            }
#        ]
#    },
#    "changed": true,
#    "commands": [
#        "snmp-server community comm3 view view1 ipv6 list1",
#        "snmp-server community replacecomm list4",
#        "no snmp-server community comm4 view view1 ro list3",
#        "no snmp-server community comm5 ro list4",
#        "no snmp-server group group1 v1 read view1",
#        "no snmp-server group group2 v3 priv write view2 notify view1",
#        "no snmp-server host host01 version 3 priv user01 udp-port 23",
#        "no snmp-server host host02 version 2c user01 udp-port 23",
#        "snmp-server vrf vrf_replace local-interface Ethernet1",
#        "no snmp-server vrf vrf01 local-interface Ethernet1",
#        "snmp-server extension 123456 flash:",
#        "default snmp-server enable traps capacity arista-hardware-utilization-alert",
#        "default snmp-server enable traps external-alarm arista-external-alarm-asserted-notif arista-external-alarm-deasserted-notif",
#        "snmp-server enable traps test arista-test-notification",
#        "no snmp-server contact admin"
#    ],

# Using overridden:
# Before State:
# eos#show running-config | section snmp-server
# snmp-server community comm3 view view1 ipv6 list1
# snmp-server community comm4 view view1 list3
# snmp-server community comm5 ro list4
# snmp-server group group1 v1 read view1
# snmp-server group group2 v3 priv write view2 notify view1
# snmp-server host host02 version 2c user01 udp-port 23
# snmp-server host host01 version 3 priv user01 udp-port 23
# snmp-server vrf vrf01 local-interface Ethernet1
# snmp-server contact admin
# snmp-server enable traps bgp
# snmp-server enable traps capacity arista-hardware-utilization-alert
# snmp-server enable traps external-alarm arista-external-alarm-asserted-notif arista-external-alarm-deasserted-notif

- name: Override given snmp_server configuration
  arista.eos.eos_snmp_server:
    state: overridden
    config:
      communities:
        - name: "comm3"
          acl_v6: "list1"
          view: "view1"
        - name: "replacecomm"
          acl_v4: "list4"
      extension:
        root_oid: "123456"
        script_location: "flash:"
      traps:
        test:
          arista_test_notification: true
        bgp:
          enabled: true
      vrfs:
        - vrf: "vrf_replace"
          local_interface: "Ethernet1"

# After State:

# eos#show running-config | section snmp-server
# snmp-server community comm3 view view1 ipv6 list1
# snmp-server community replacecomm list4
# snmp-server vrf vrf_replace local-interface Ethernet1
# snmp-server extension 123456 flash:
# snmp-server enable traps test arista-test-notification
# snmp-server enable traps bgp

# Module Execution:
#    "after": {
#        "communities": [
#            {
#                "acl_v6": "list1",
#                "name": "comm3",
#                "ro": true,
#                "view": "view1"
#            },
#            {
#                "acl_v4": "list4",
#                "name": "replacecomm",
#                "ro": true
#            }
#        ],
#        "extension": {
#            "root_oid": "0.123456",
#            "script_location": "flash:"
#        },
#        "traps": {
#            "bgp": {
#                "enabled": true
#            },
#            "test": {
#                "arista_test_notification": true
#            }
#        },
#        "vrfs": [
#            {
#                "local_interface": "Ethernet1",
#                "vrf": "vrf_replace"
#            }
#        ]
#    },
#    "before": {
#        "communities": [
#            {
#                "acl_v6": "list1",
#                "name": "comm3",
#                "ro": true,
#                "view": "view1"
#            },
#            {
#                "acl_v4": "list3",
#                "name": "comm4",
#                "ro": true,
#                "view": "view1"
#            },
#            {
#                "acl_v4": "list4",
#                "name": "comm5",
#                "ro": true
#            }
#        ],
#        "contact": "admin",
#        "groups": [
#            {
#                "group": "group1",
#                "read": "view1",
#                "version": "v1"
#            },
#            {
#                "auth_privacy": "priv",
#                "group": "group2",
#                "notify": "view1",
#                "version": "v3",
#                "write": "view2"
#            }
#        ],
#        "hosts": [
#            {
#                "host": "host01",
#                "udp_port": 23,
#                "user": "user01",
#                "version": "3 priv"
#            },
#            {
#                "host": "host02",
#                "udp_port": 23,
#                "user": "user01",
#                "version": "2c"
#            }
#        ],
#        "traps": {
#            "bgp": {
#                "enabled": true
#            },
#            "capacity": {
#                "arista_hardware_utilization_alert": true
#            },
#            "external_alarm": {
#                "arista_external_alarm_asserted_notif": true,
#                "arista_external_alarm_deasserted_notif": true
#            }
#        },
#        "vrfs": [
#            {
#                "local_interface": "Ethernet1",
#                "vrf": "vrf01"
#            }
#        ]
#    },
#    "changed": true,
#    "commands": [
#        "snmp-server community comm3 view view1 ipv6 list1",
#        "snmp-server community replacecomm list4",
#        "no snmp-server community comm4 view view1 ro list3",
#        "no snmp-server community comm5 ro list4",
#        "no snmp-server group group1 v1 read view1",
#        "no snmp-server group group2 v3 priv write view2 notify view1",
#        "no snmp-server host host01 version 3 priv user01 udp-port 23",
#        "no snmp-server host host02 version 2c user01 udp-port 23",
#        "snmp-server vrf vrf_replace local-interface Ethernet1",
#        "no snmp-server vrf vrf01 local-interface Ethernet1",
#        "snmp-server extension 123456 flash:",
#        "default snmp-server enable traps capacity arista-hardware-utilization-alert",
#        "default snmp-server enable traps external-alarm arista-external-alarm-asserted-notif arista-external-alarm-deasserted-notif",
#        "snmp-server enable traps test arista-test-notification",
#        "no snmp-server contact admin"
#    ],

# Using deleted:
# Before State:
# eos#show running-config | section snmp-server
# snmp-server community comm3 view view1 ipv6 list1
# snmp-server community comm4 view view1 list3
# snmp-server community comm5 ro list4
# snmp-server group group1 v1 read view1
# snmp-server group group2 v3 priv write view2 notify view1
# snmp-server host host02 version 2c user01 udp-port 23
# snmp-server host host01 version 3 priv user01 udp-port 23
# snmp-server vrf vrf01 local-interface Ethernet1
# snmp-server contact admin
# snmp-server enable traps bgp
# snmp-server enable traps capacity arista-hardware-utilization-alert
# snmp-server enable traps external-alarm arista-external-alarm-asserted-notif arista-external-alarm-deasserted-notif

- name: Delete given snmp_server configuration
  arista.eos.eos_snmp_server:
    state: deleted

# After State:
# eos#show running-config | section snmp-server
#

# Module Execution:
#   "after": {},
#    "before": {
#        "communities": [
#            {
#                "acl_v6": "list1",
#                "name": "comm3",
#                "ro": true,
#                "view": "view1"
#            },
#            {
#                "acl_v4": "list3",
#                "name": "comm4",
#                "ro": true,
#                "view": "view1"
#            },
#            {
#                "acl_v4": "list4",
#                "name": "comm5",
#                "ro": true
#            }
#        ],
#        "contact": "admin",
#        "groups": [
#            {
#                "group": "group1",
#                "read": "view1",
#                "version": "v1"
#            },
#            {
#                "auth_privacy": "priv",
#                "group": "group2",
#                "notify": "view1",
#                "version": "v3",
#                "write": "view2"
#            }
#        ],
#        "hosts": [
#            {
#                "host": "host01",
#                "udp_port": 23,
#                "user": "user01",
#                "version": "3 priv"
#            },
#            {
#                "host": "host02",
#                "udp_port": 23,
#                "user": "user01",
#                "version": "2c"
#            }
#        ],
#        "traps": {
#            "bgp": {
#                "enabled": true
#            },
#            "capacity": {
#                "arista_hardware_utilization_alert": true
#            },
#            "external_alarm": {
#                "arista_external_alarm_asserted_notif": true,
#                "arista_external_alarm_deasserted_notif": true
#            }
#        },
#        "vrfs": [
#            {
#                "local_interface": "Ethernet1",
#                "vrf": "vrf01"
#            }
#        ]
#    },
#    "changed": true,
#    "commands": [
#        "no snmp-server community comm3 view view1 ro ipv6 list1",
#        "no snmp-server community comm4 view view1 ro list3",
#        "no snmp-server community comm5 ro list4",
#        "no snmp-server group group1 v1 read view1",
#        "no snmp-server group group2 v3 priv write view2 notify view1",
#        "no snmp-server host host01 version 3 priv user01 udp-port 23",
#        "no snmp-server host host02 version 2c user01 udp-port 23",
#        "no snmp-server vrf vrf01 local-interface Ethernet1",
#        "no snmp-server contact admin",
#        "default snmp-server enable traps bgp",
#        "default snmp-server enable traps capacity arista-hardware-utilization-alert",
#        "default snmp-server enable traps external-alarm arista-external-alarm-asserted-notif arista-external-alarm-deasserted-notif"
#    ],
#

# Using parsed:

# _parsed.cfg
# snmp-server contact admin
# snmp-server vrf vrf01 local-interface Ethernet1
# snmp-server community comm3 view view1 ro ipv6 list1
# snmp-server community comm4 view view1 ro list3
# snmp-server community comm5 ro list4
# snmp-server group group1 v1 read view1
# snmp-server group group2 v3 priv write view2 notify view1
# snmp-server host host01 version 3 priv user01 udp-port 23
# snmp-server host host02 version 2c user01 udp-port 23
# snmp-server enable traps bgp
# snmp-server enable traps capacity arista-hardware-utilization-alert
# snmp-server enable traps external-alarm arista-external-alarm-asserted-notif
# snmp-server enable traps external-alarm arista-external-alarm-deasserted-notif

- name: Provide the running configuration for parsing (config to be parsed)
  arista.eos.eos_snmp_server:
    running_config: "{{ lookup('file', '_parsed.cfg') }}"
    state: parsed

# Module Execution:
#     "parsed": {
#         "communities": [
#             {
#                 "acl_v6": "list1",
#                 "name": "comm3",
#                 "ro": true,
#                 "view": "view1"
#             },
#             {
#                 "acl_v4": "list3",
#                 "name": "comm4",
#                 "ro": true,
#                 "view": "view1"
#             },
#             {
#                 "acl_v4": "list4",
#                 "name": "comm5",
#                 "ro": true
#             }
#         ],
#         "contact": "admin",
#         "groups": [
#             {
#                 "group": "group1",
#                 "read": "view1",
#                 "version": "v1"
#             },
#             {
#                 "auth_privacy": "priv",
#                 "group": "group2",
#                 "notify": "view1",
#                 "version": "v3",
#                 "write": "view2"
#             }
#         ],
#         "hosts": [
#             {
#                 "host": "host01",
#                 "udp_port": 23,
#                 "user": "user01",
#                 "version": "3 priv"
#             },
#             {
#                 "host": "host02",
#                 "udp_port": 23,
#                 "user": "user01",
#                 "version": "2c"
#             }
#         ],
#         "traps": {
#             "bgp": {
#                 "enabled": true
#             },
#             "capacity": {
#                 "arista_hardware_utilization_alert": true
#             },
#             "external_alarm": {
#                 "arista_external_alarm_asserted_notif": true,
#                 "arista_external_alarm_deasserted_notif": true
#             }
#         },
#         "vrfs": [
#             {
#                 "local_interface": "Ethernet1",
#                 "vrf": "vrf01"
#             }
#         ]
#   }

# Using rendered:
- name: Render given snmp_server configuration
  arista.eos.eos_snmp_server:
    state: "rendered"
    config:
      communities:
        - name: "comm3"
          acl_v6: "list1"
          view: "view1"
        - name: "comm4"
          acl_v4: "list3"
          view: "view1"
        - name: "comm5"
          acl_v4: "list4"
          ro: true
      contact: "admin"
      engineid:
        remote:
          host: 1.1.1.1
          id: "1234567"
      groups:
        - group: "group1"
          version: "v1"
          read: "view1"
        - group: "group2"
          version: "v3"
          auth_privacy: "priv"
          notify: "view1"
          write: "view2"
      hosts:
        - host: "host02"
          user: "user01"
          udp_port: 23
          version: "2c"
        - host: "host01"
          user: "user01"
          udp_port: 23
          version: "3 priv"
      traps:
        capacity:
          arista_hardware_utilization_alert: true
        bgp:
          enabled: true
        external_alarm:
          arista_external_alarm_deasserted_notif: true
          arista_external_alarm_asserted_notif: true
      vrfs:
        - vrf: "vrf01"
          local_interface: "Ethernet1"

# Module Execution:
#    "rendered": [
#        "snmp-server community comm3 view view1 ipv6 list1",
#        "snmp-server community comm4 view view1 list3",
#        "snmp-server community comm5 ro list4",
#        "snmp-server group group1 v1 read view1",
#        "snmp-server group group2 v3 priv write view2 notify view1",
#        "snmp-server host host02 version 2c user01 udp-port 23",
#        "snmp-server host host01 version 3 priv user01 udp-port 23",
#        "snmp-server vrf vrf01 local-interface Ethernet1",
#        "snmp-server contact admin",
#        "snmp-server engineID remote 1.1.1.1 1234567",
#        "snmp-server enable traps bgp",
#        "snmp-server enable traps capacity arista-hardware-utilization-alert",
#        "snmp-server enable traps external-alarm arista-external-alarm-asserted-notif arista-external-alarm-deasserted-notif"
#    ]

# using gathered:

# eos#show running-config | section snmp-server
# snmp-server community comm3 view view1 ipv6 list1
# snmp-server community comm4 view view1 list3
# snmp-server community comm5 ro list4
# snmp-server group group1 v1 read view1
# snmp-server group group2 v3 priv write view2 notify view1
# snmp-server host host02 version 2c user01 udp-port 23
# snmp-server host host01 version 3 priv user01 udp-port 23
# snmp-server vrf vrf01 local-interface Ethernet1
# snmp-server contact admin
# snmp-server enable traps bgp
# snmp-server enable traps capacity arista-hardware-utilization-alert
# snmp-server enable traps external-alarm arista-external-alarm-asserted-notif arista-external-alarm-deasserted-notif

- name: Gathered the provided configuration with the exisiting running configuration
  arista.eos.eos_snmp_server:
    config:
    state: gathered

# Module Execution:
#     "gathered": {
#         "communities": [
#             {
#                 "acl_v6": "list1",
#                 "name": "comm3",
#                 "ro": true,
#                 "view": "view1"
#             },
#             {
#                 "acl_v4": "list3",
#                 "name": "comm4",
#                 "ro": true,
#                 "view": "view1"
#             },
#             {
#                 "acl_v4": "list4",
#                 "name": "comm5",
#                 "ro": true
#             }
#         ],
#         "contact": "admin",
#         "groups": [
#             {
#                 "group": "group1",
#                 "read": "view1",
#                 "version": "v1"
#             },
#             {
#                 "auth_privacy": "priv",
#                 "group": "group2",
#                 "notify": "view1",
#                 "version": "v3",
#                 "write": "view2"
#             }
#         ],
#         "hosts": [
#             {
#                 "host": "host01",
#                 "udp_port": 23,
#                 "user": "user01",
#                 "version": "3 priv"
#             },
#             {
#                 "host": "host02",
#                 "udp_port": 23,
#                 "user": "user01",
#                 "version": "2c"
#             }
#         ],
#         "traps": {
#             "bgp": {
#                 "enabled": true
#             },
#             "capacity": {
#                 "arista_hardware_utilization_alert": true
#             },
#             "external_alarm": {
#                 "arista_external_alarm_asserted_notif": true,
#                 "arista_external_alarm_deasserted_notif": true
#             }
#         },
#         "vrfs": [
#             {
#                 "local_interface": "Ethernet1",
#                 "vrf": "vrf01"
#             }
#         ]
#     },
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
    - "snmp-server community comm3 view view1 ipv6 list1"
    - "snmp-server community comm4 view view1 list3"
    - "snmp-server community comm5 ro list4"
    - "snmp-server group group1 v1 read view1"
    - "snmp-server group group2 v3 priv write view2 notify view1"
    - "snmp-server host host02 version 2c user01 udp-port 23"
    - "snmp-server host host01 version 3 priv user01 udp-port 23"
    - "snmp-server vrf vrf01 local-interface Ethernet1"
    - "snmp-server contact admin"
    - "snmp-server engineID remote 1.1.1.1 1234567"
    - "snmp-server enable traps bgp"
    - "snmp-server enable traps capacity arista-hardware-utilization-alert"
    - "snmp-server enable traps external-alarm arista-external-alarm-asserted-notif arista-external-alarm-deasserted-notif"

rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - "snmp-server community comm3 view view1 ipv6 list1"
    - "snmp-server community comm4 view view1 list3"
    - "snmp-server community comm5 ro list4"
    - "snmp-server group group1 v1 read view1"
    - "snmp-server group group2 v3 priv write view2 notify view1"
    - "snmp-server host host02 version 2c user01 udp-port 23"
    - "snmp-server host host01 version 3 priv user01 udp-port 23"
    - "snmp-server vrf vrf01 local-interface Ethernet1"
    - "snmp-server contact admin"
    - "snmp-server engineID remote 1.1.1.1 1234567"
    - "snmp-server enable traps bgp"
    - "snmp-server enable traps capacity arista-hardware-utilization-alert"
    - "snmp-server enable traps external-alarm arista-external-alarm-asserted-notif arista-external-alarm-deasserted-notif"
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

from ansible_collections.arista.eos.plugins.module_utils.network.eos.argspec.snmp_server.snmp_server import (
    Snmp_serverArgs,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.config.snmp_server.snmp_server import (
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
