#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_snmp_server
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_snmp_server
short_description: SNMP Server resource module.
description:
- This module manages SNMP server configuration on devices running Cisco NX-OS.
version_added: 2.8.0
notes:
- Tested against NX-OS 9.3.6 on Cisco Nexus Switches.
- This module works with connection C(network_cli) and C(httpapi).
- Tested against Cisco MDS NX-OS 9.2(2) with connection C(network_cli).
author: Nilashish Chakraborty (@NilashishC)
options:
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the NX-OS device
      by executing the command B(show running-config | section '^snmp-server').
    - The state I(parsed) reads the configuration from C(running_config) option and
      transforms it into Ansible structured data as per the resource module's argspec
      and the value is then returned in the I(parsed) key within the result.
    type: str
  config:
    description: A dict of SNMP server configuration
    type: dict
    suboptions:
      aaa_user:
        description: Set duration for which aaa-cached snmp user exists.
        type: dict
        suboptions:
          cache_timeout:
            description: Timeout for which aaa-cached user exists(in secs).
            type: int
      communities:
        description: Set community string and access privs.
        type: list
        elements: dict
        suboptions:
          name:
            description: SNMP community string (Max Size 32).
            type: str
            aliases: ["community"]
          group:
            description: Group to which the community belongs.
            type: str
          ro:
            description: Read-only access with this community string.
            type: bool
          rw:
            description: Read-write access with this community string.
            type: bool
          use_ipv4acl:
            description:
              - Specify IPv4 ACL, the ACL name specified must be IPv4 ACL.
              - This option is unsupported on MDS switches.
            type: str
          use_ipv6acl:
            description:
              - Specify IPv6 ACL, the ACL name specified after must be IPv6 ACL.
              - This option is unsupported on MDS switches.
            type: str
      contact:
        description: Modify sysContact.
        type: str
      context:
        description: SNMP context to be mapped.
        type: dict
        suboptions:
          name:
            description: Name of the SNMP context (Max Size 32).
            type: str
          instance:
            description: Name of the protocol instance (Max Size 32).
            type: str
          topology:
            description: Topology associated with the SNMP context.
            type: str
          vrf:
            description:
              - VRF associated with the SNMP context.
              - This option is unsupported on MDS switches.
            type: str
      counter:
        description:
          - Configure port counter configuration.
          - This option is unsupported on MDS switches.
        type: dict
        suboptions:
          cache:
            description: Port stats cache.
            type: dict
            suboptions:
              enable:
                description: Enable port stats cache.
                type: bool
              timeout:
                description: Timeout for which cached port stats exists(in secs).
                type: int
      drop:
        description:
          - Silently drop unknown v3 user packets.
          - This option is unsupported on MDS switches.
        type: dict
        suboptions:
          unknown_engine_id:
            description: Unknown v3 engine id.
            type: bool
          unknown_user:
            description: Unknown v3 user.
            type: bool
      traps:
        description: Enable SNMP Traps
        type: dict
        suboptions:
          aaa:
            description: AAA traps
            type: dict
            suboptions:
              enable:
                description: Enable AAA traps.
                type: bool
              server_state_change:
                description: AAA server state change notification.
                type: bool
          bgp:
            description: SNMP BGP traps.
            type: dict
            suboptions:
              enable:
                description: Enable SNMP BGP traps.
                type: bool
          bridge:
            description:
              - Bridge traps.
              - This option is unsupported on MDS switches.
            type: dict
            suboptions:
              enable:
                description: Enable bridge traps.
                type: bool
              newroot:
                description: Enable SNMP STP Bridge MIB newroot traps.
                type: bool
              topologychange:
                description: Enable SNMP STP Bridge MIB topologychange traps.
                type: bool
          callhome:
            description: Callhome traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable callhome traps.
                  - This option is unsupported on MDS switches.
                type: bool
              event_notify:
                description: Callhome External Event Notification.
                type: bool
              smtp_send_fail:
                description: SMTP Message Send Fail notification.
                type: bool
          cfs:
            description: CFS traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable cfs traps.
                  - This option is unsupported on MDS switches.
                type: bool
              merge_failure:
                description: Merge failure notification.
                type: bool
              state_change_notif:
                description:  State change notification.
                type: bool
          config:
            description: Config traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable config traps.
                  - This option is unsupported on MDS switches.
                type: bool
              ccmCLIRunningConfigChanged:
                description: Running config change trap.
                type: bool
          entity:
            description: Entity traps.
            type: dict
            suboptions:
              enable:
                description: Enable entity traps.
                type: bool
              cefcMIBEnableStatusNotification:
                description: CefcMIBEnableStatusNotification.
                type: bool
              entity_fan_status_change:
                description: Entity Fan Status Change.
                type: bool
              entity_mib_change:
                description: Entity MIB change.
                type: bool
              entity_module_inserted:
                description: Entity Module Inserted.
                type: bool
              entity_module_removed:
                description: Entity Module Removed.
                type: bool
              entity_module_status_change:
                description: Entity Module Status Change.
                type: bool
              entity_power_out_change:
                description: Entity Power Out Change.
                type: bool
              entity_power_status_change:
                description: Entity Power Status Change.
                type: bool
              entity_sensor:
                description: Entity sensor.
                type: bool
              entity_unrecognised_module:
                description: Entity Unrecognised Module.
                type: bool
          feature_control:
            description: Feature-Control traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable feature-control traps.
                  - This option is unsupported on MDS switches.
                type: bool
              featureOpStatusChange:
                description: Feature operation status change notification.
                type: bool
              ciscoFeatOpStatusChange:
                description: Feature operation status change Notification.
                type: bool
          generic:
            description: Generic traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable generic traps.
                  - This option is unsupported on MDS switches.
                type: bool
              coldStart:
                description: Generic coldStart trap.
                type: bool
              warmStart:
                description: Generic warmStart trap.
                type: bool
          license:
            description: License traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable license traps.
                  - This option is unsupported on MDS switches.
                type: bool
              notify_license_expiry:
                description: License Expiry Notification.
                type: bool
              notify_license_expiry_warning:
                description: License Expiry Warning Notification.
                type: bool
              notify_licensefile_missing:
                description: License File Missing Notification.
                type: bool
              notify_no_license_for_feature:
                description: No License installed for feature Notification.
                type: bool
          link:
            description: Link traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable link traps.
                  - This option is unsupported on MDS switches.
                type: bool
              cErrDisableInterfaceEventRev1:
                description:
                  - Err-disable state notification.
                  - This option is unsupported on MDS switches.
                type: bool
              cieLinkDown:
                description: Cisco extended link state down notification.
                type: bool
              cieLinkUp:
                description: Cisco extended link state up notification.
                type: bool
              cisco_xcvr_mon_status_chg:
                description: Cisco interface transceiver monitor status change notification.
                type: bool
              cmn_mac_move_notification:
                description:
                  - Mac addr move trap.
                  - This option is unsupported on MDS switches.
                type: bool
              delayed_link_state_change:
                description: Delayed link state change.
                type: bool
              extended_linkDown:
                description: IETF extended link state down notification.
                type: bool
              extended_linkUp:
                description: IETF extended link state up notification.
                type: bool
              linkDown:
                description: IETF Link state down notification.
                type: bool
              linkUp:
                description: IETF Link state up notification.
                type: bool
          mmode:
            description:
              - MMode traps.
              - This option is unsupported on MDS switches.
            type: dict
            suboptions:
              enable:
                description: Enable mmode traps.
                type: bool
              cseMaintModeChangeNotify:
                description: Maint Mode Change Notification.
                type: bool
              cseNormalModeChangeNotify:
                description: Normal Mode Change Notification.
                type: bool
          ospf:
            description: SNMP OSPF traps.
            type: dict
            suboptions:
              enable:
                description: Enable SNMP OSPF traps.
                type: bool
          ospfv3:
            description: SNMP OSPFv3 traps.
            type: dict
            suboptions:
              enable:
                description: Enable SNMP OSPFv3 traps.
                type: bool
          rf:
            description: RF traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable rf traps.
                  - This option is unsupported on MDS switches.
                type: bool
              redundancy_framework:
                description: Redundancy_Framework (RF) Sup switchover MIB.
                type: bool
          rmon:
            description: RMON traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable rmon traps.
                  - This option is unsupported on MDS switches.
                type: bool
              fallingAlarm:
                description: Rmon falling alarm.
                type: bool
              hcFallingAlarm:
                description: High capacity Rmon falling alarm.
                type: bool
              hcRisingAlarm:
                description: High capacity Rmon rising alarm.
                type: bool
              risingAlarm:
                description: Rmon rising alarm.
                type: bool
          snmp:
            description: SNMP traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable snmp traps.
                  - This option is unsupported on MDS switches.
                type: bool
              authentication:
                description: SNMP authentication trap.
                type: bool
          storm_control:
            description: Storm-Control traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable storm-control traps.
                  - This option is unsupported on MDS switches.
                type: bool
              cpscEventRev1:
                description:
                  - Port-Storm-Control-Event.
                  - This option is unsupported on MDS switches.
                type: bool
              trap_rate:
                description: Number of traps per minute.
                type: bool
          stpx:
            description:
              - Stpx traps.
              - This option is unsupported on MDS switches.
            type: dict
            suboptions:
              enable:
                description: Enable stpx traps.
                type: bool
              inconsistency:
                description: Enable SNMP STPX MIB InconsistencyUpdate traps.
                type: bool
              loop_inconsistency:
                description: Enable SNMP STPX MIB LoopInconsistencyUpdate traps.
                type: bool
              root_inconsistency:
                description: Enable SNMP STPX MIB RootInconsistencyUpdate traps.
                type: bool
          syslog:
            description: Enable syslog traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable syslog traps.
                  - This option is unsupported on MDS switches.
                type: bool
              message_generated:
                description: Message Generated Notification.
                type: bool
          sysmgr:
            description: Sysmgr traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable sysmgr traps.
                  - This option is unsupported on MDS switches.
                type: bool
              cseFailSwCoreNotifyExtended:
                description: Software Core Notification.
                type: bool
          system:
            description: System traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable system traps.
                  - This option is unsupported on MDS switches.
                type: bool
              clock_change_notification:
                description: Clock-change-notification traps.
                type: bool
          upgrade:
            description: Upgrade traps.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable upgrade traps.
                  - This option is unsupported on MDS switches.
                type: bool
              upgradeJobStatusNotify:
                description: Upgrade Job Status Notification.
                type: bool
              upgradeOpNotifyOnCompletion:
                description: Upgrade Global Status Notification.
                type: bool
          vtp:
            description:
              - VTP traps.
              - This option is unsupported on MDS switches.
            type: dict
            suboptions:
              enable:
                description: Enable VTP traps.
                type: bool
              notifs:
                description:
                  - Enable vtpConfigRevNumberError vtpConfigDigestEnable vtpConfigRevNumberError vtpConfigDigestError
                    vtpServerDisabled vtpVersionOneDeviceDetected vlanTrunkPortDynamicStatusChange vtpLocalModeChanged
                    vtpVersionInUseChanged notification.
                type: bool
              vlancreate:
                description: Enable vtpVlanCreated notification.
                type: bool
              vlandelete:
                description: Enable vtpVlanDeleted notification.
                type: bool
      engine_id:
        description:
          - Configure a local SNMPv3 engineID.
          - This option is unsupported on MDS switches.
        type: dict
        suboptions:
          local:
            description: EngineID of the local agent.
            type: str
      global_enforce_priv:
        description: Globally enforce privacy for all the users.
        type: bool
      hosts:
        description:
          - Specify hosts to receive SNMP notifications.
          - SNMP hosts config lines that appear separately in running-config must be added as individual dictionaries.
        type: list
        elements: dict
        suboptions:
          host:
            description: IPv4 or IPv6 address or DNS Name of SNMP notification host.
            type: str
          community:
            description: SNMP community string or SNMPv3 user name (Max Size 32).
            type: str
          filter_vrf:
            description:
              - Filters notifications to the notification host receiver based on the configured VRF.
              - This option is unsupported on MDS switches.
            type: str
          informs:
            description: Send Inform messages to this host.
            type: bool
          source_interface:
            description: Source interface to be used for sending out SNMP notifications to this host.
            type: str
          traps:
            description: Send Traps messages to this host.
            type: bool
          use_vrf:
            description:
              - Configures SNMP to use the selected VRF to communicate with the host receiver.
              - This option is unsupported on MDS switches.
            type: str
          version:
            description: SNMP version to use for notification messages.
            type: str
            choices: ["1", "2c", "3"]
          auth:
            description: Use the SNMPv3 authNoPriv Security Level.
            type: str
          priv:
            description: Use the SNMPv3 authPriv Security Level.
            type: str
          udp_port:
            description: The notification host's UDP port number.
            type: int
      location:
        description: Modify sysLocation.
        type: str
      mib:
        description: Mib access parameters.
        type: dict
        suboptions:
          community_map:
            description: SNMP community.
            type: dict
            suboptions:
              community:
                description: SNMP community string (Max Size 32).
                type: str
              context:
                description: Name of the SNMP context (Max Size 32).
                type: str
      packetsize:
        description: Largest SNMP packet size
        type: int
      protocol:
        description: Snmp protocol operations.
        type: dict
        suboptions:
          enable:
            description: Enable/Disable snmp protocol operations.
            type: bool
      source_interface:
        description:
          - Source interface to be used for sending out SNMP notifications.
          - This option is unsupported on MDS switches.
        type: dict
        suboptions:
          informs:
            description: SNMP Inform notifications for which this source interface needs to be used.
            type: str
          traps:
            description: SNMP Trap notifications for which this source interface needs to be used.
            type: str
      system_shutdown:
        description: Configure snmp-server for reload(2).
        type: bool
      tcp_session:
        description: Enable one time authentication for snmp over tcp session.
        type: dict
        suboptions:
          enable:
            description:
              - Enable tcp-session.
              - This option is unsupported on MDS switches.
            type: bool
          auth:
            description: Enable one time authentication for snmp over tcp session.
            type: bool
      users:
        description: Define users who can access the SNMP engine.
        type: dict
        suboptions:
          auth:
            description: SNMP User authentication related settings
            type: list
            elements: dict
            suboptions:
              user:
                description: Name of the user (Max Size 28).
                type: str
              group:
                description: Group name (ignored for notif target user) (Max Size 28).
                type: str
              authentication:
                description: Authentication parameters for the user.
                type: dict
                suboptions:
                  algorithm:
                    description: Select algorithm for authentication.
                    type: str
                    choices: ["md5", "sha", "sha-256"]
                  password:
                    description:
                      - Authentication password for user (Max Size 127).
                      - If this value is localized, it has to be enclosed in quotes in the task.
                    type: str
                  engine_id:
                    description:
                      - EngineID for configuring notif target user (for V3 informs).
                      - This value needs to be enclosed in quotes in the task.
                    type: str
                  localized_key:
                    description: Specifies whether the passwords are in localized key format.
                    type: bool
                  localizedv2_key:
                    description: Specifies whether the passwords are in localized V2 key format.
                    type: bool
                  priv:
                    description: Encryption parameters for the user.
                    type: dict
                    suboptions:
                      privacy_password:
                        description:
                          - Privacy password for user (Max Size 130).
                          - If this value is localized, it has to be enclosed in quotes in the task.
                        type: str
                      aes_128:
                        description: Use 128-bit AES algorithm for privacy.
                        type: bool
          use_acls:
            description: Set IPv4 and IPv6 ACL to use.
            type: list
            elements: dict
            suboptions:
              user:
                description: Name of the user (Max Size 28).
                type: str
              ipv4:
                description: Specify IPv4 ACL, the ACL name specified after must be IPv4 ACL.
                type: str
              ipv6:
                description: Specify IPv6 ACL, the ACL name specified after must be IPv6 ACL.
                type: str
  state:
    description:
    - The state the configuration should be left in.
    - The states C(replaced) and C(overridden) have identical behaviour for this module.
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

# Before state:
# -------------
# nxos-9k-rdo# show running-config | section "^snmp-server"
# snmp-server user admin network-admin auth md5 0xcbde46b02c46e0bcd3ac5af6a8b13da9 priv 0xcbde46b02c46e0bcd3ac5af6a8b13da9 localizedkey

- name: Merge the provided configuration with the existing running configuration
  cisco.nxos.nxos_snmp_server:
    config:
      aaa_user:
        cache_timeout: 36000
      communities:
        - community: public
          group: network-operator
        - community: private
          group: network-admin
      contact: nxosswitchadmin@localhost
      location: serverroom-1
      traps:
        aaa:
          server_state_change: true
        system:
          clock_change_notification: true
      hosts:
        - host: 192.0.2.1
          traps: true
          version: '1'
          community: public
        - host: 192.0.2.1
          source_interface: Ethernet1/1
        - host: 192.0.2.2
          informs: true
          version: '3'
          auth: NMS
      users:
        auth:
          - user: snmp_user_1
            group: network-operator
            authentication:
              algorithm: md5
              password: '0x5632724fb8ac3699296af26281e1d0f1'
              localized_key: true
          - user: snmp_user_2
            group: network-operator
            authentication:
              algorithm: md5
              password: '0x5632724fb8ac3699296af26281e1d0f1'
              localized_key: true
              priv:
                privacy_password: '0x5632724fb8ac3699296af26281e1d0f1'
                aes_128: true
        use_acls:
          - user: snmp_user_1
            ipv4: acl1
            ipv6: acl2
          - user: snmp_user_2
            ipv4: acl3
            ipv6: acl4

# Task output
# -------------
# before:
#   users:
#     auth:
#       - user: admin
#         group: network-admin
#         authentication:
#           algorithm: md5
#           password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"
#           localized_key: true
#           priv:
#             privacy_password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"
#
# commands:
#   - snmp-server contact nxosswitchadmin@localhost
#   - snmp-server location serverroom-1
#   - snmp-server aaa-user cache-timeout 36000
#   - snmp-server user snmp_user_1 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
#   - snmp-server user snmp_user_2 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 priv aes-128 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
#   - snmp-server user snmp_user_1 use-ipv4acl acl1 use-ipv6acl acl2
#   - snmp-server user snmp_user_2 use-ipv4acl acl3 use-ipv6acl acl4
#   - snmp-server host 192.0.2.1 traps version 1 public
#   - snmp-server host 192.0.2.1 source-interface Ethernet1/1
#   - snmp-server host 192.0.2.2 informs version 3 auth NMS
#   - snmp-server community private group network-admin
#   - snmp-server community public group network-operator
#   - snmp-server enable traps aaa server-state-change
#   - snmp-server enable traps system Clock-change-notification
#
# after:
#   aaa_user:
#      cache_timeout: 36000
#    communities:
#      - community: private
#        group: network-admin
#      - community: public
#        group: network-operator
#    contact: nxosswitchadmin@localhost
#    location: serverroom-1
#    traps:
#      aaa:
#        server_state_change: true
#      system:
#        clock_change_notification: true
#    hosts:
#      - host: 192.0.2.1
#        traps: true
#        version: "1"
#        community: public
#
#      - host: 192.0.2.1
#        source_interface: Ethernet1/1
#
#      - host: 192.0.2.2
#        informs: true
#        version: "3"
#        auth: NMS
#    users:
#      auth:
#        - user: admin
#          group: network-admin
#          authentication:
#            algorithm: md5
#            password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"
#            localized_key: true
#            priv:
#              privacy_password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"
#
#        - user: snmp_user_1
#          group: network-operator
#          authentication:
#            algorithm: md5
#            password: "0x5632724fb8ac3699296af26281e1d0f1"
#            localized_key: true
#
#        - authentication:
#            algorithm: md5
#            localized_key: true
#            password: "0x5632724fb8ac3699296af26281e1d0f1"
#            priv:
#              aes_128: true
#              privacy_password: "0x5632724fb8ac3699296af26281e1d0f1"
#          group: network-operator
#          user: snmp_user_2
#
#      use_acls:
#        - user: snmp_user_1
#          ipv4: acl1
#          ipv6: acl2
#        - user: snmp_user_2
#          ipv4: acl3
#          ipv6: acl4

# After state:
# ------------
# nxos-9k-rdo# show running-config | section "^snmp-server"
# snmp-server contact nxosswitchadmin@localhost
# snmp-server location serverroom-1
# snmp-server aaa-user cache-timeout 36000
# snmp-server user admin network-admin auth md5 0xcbde46b02c46e0bcd3ac5af6a8b13da9 priv 0xcbde46b02c46e0bcd3ac5af6a8b13da9 localizedkey
# snmp-server user snmp_user_1 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
# snmp-server user snmp_user_2 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 priv aes-128 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
# snmp-server user snmp_user_1 use-ipv4acl acl1 use-ipv6acl acl2
# snmp-server user snmp_user_2 use-ipv4acl acl3 use-ipv6acl acl4
# snmp-server host 192.0.2.1 traps version 1 public
# snmp-server host 192.0.2.1 source-interface Ethernet1/1
# snmp-server host 192.0.2.2 informs version 3 auth NMS
# snmp-server community private group network-admin
# snmp-server community public group network-operator
# snmp-server enable traps aaa server-state-change
# snmp-server enable traps system Clock-change-notification

# Using replaced

# Before state:
# ------------
# nxos-9k-rdo# show running-config | section "^snmp-server"
# snmp-server contact nxosswitchadmin@localhost
# snmp-server location serverroom-1
# snmp-server aaa-user cache-timeout 36000
# snmp-server user admin network-admin auth md5 0xcbde46b02c46e0bcd3ac5af6a8b13da9 priv 0xcbde46b02c46e0bcd3ac5af6a8b13da9 localizedkey
# snmp-server user snmp_user_1 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
# snmp-server user snmp_user_2 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 priv aes-128 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
# snmp-server user snmp_user_1 use-ipv4acl acl1 use-ipv6acl acl2
# snmp-server user snmp_user_2 use-ipv4acl acl3 use-ipv6acl acl4
# snmp-server host 192.0.2.1 traps version 1 public
# snmp-server host 192.0.2.1 source-interface Ethernet1/1
# snmp-server host 192.0.2.2 informs version 3 auth NMS
# snmp-server community private group network-admin
# snmp-server community public group network-operator
# snmp-server enable traps aaa server-state-change
# snmp-server enable traps system Clock-change-notification

- name: Replace snmp-server configurations of listed snmp-server with provided configurations
  cisco.nxos.nxos_snmp_server:
    config:
      aaa_user:
        cache_timeout: 36000
      communities:
        - community: public
          group: network-operator
        - community: secret
          group: network-operator
      contact: nxosswitchadmin2@localhost
      location: serverroom-2
      traps:
        aaa:
          server_state_change: true
      hosts:
        - host: 192.0.2.1
          traps: true
          version: '1'
          community: public
        - host: 192.0.2.1
          source_interface: Ethernet1/1
        - host: 192.0.3.2
          informs: true
          version: '3'
          auth: NMS
      users:
        auth:
          - user: admin
            group: network-admin
            authentication:
              algorithm: md5
              password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"
              localized_key: true
              priv:
                privacy_password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"

          - user: snmp_user_1
            group: network-operator
            authentication:
              algorithm: md5
              password: '0x5632724fb8ac3699296af26281e1d0f1'
              localized_key: true

          - user: snmp_user_2
            group: network-operator
            authentication:
              algorithm: md5
              password: '0x5632724fb8ac3699296af26281e1d0f1'
              localized_key: true
              priv:
                privacy_password: '0x5632724fb8ac3699296af26281e1d0f1'
                aes_128: true
        use_acls:
          - user: snmp_user_1
            ipv4: acl1
            ipv6: acl2
    state: replaced

# Task output
# -------------
# before:
#   aaa_user:
#      cache_timeout: 36000
#    communities:
#      - community: private
#        group: network-admin
#      - community: public
#        group: network-operator
#    contact: nxosswitchadmin@localhost
#    location: serverroom-1
#    traps:
#      aaa:
#        server_state_change: true
#      system:
#        clock_change_notification: true
#    hosts:
#      - host: 192.0.2.1
#        traps: true
#        version: "1"
#        community: public
#
#      - host: 192.0.2.1
#        source_interface: Ethernet1/1
#
#      - host: 192.0.2.2
#        informs: true
#        version: "3"
#        auth: NMS
#    users:
#      auth:
#        - user: admin
#          group: network-admin
#          authentication:
#            algorithm: md5
#            password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"
#            localized_key: true
#            priv:
#              privacy_password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"
#
#        - user: snmp_user_1
#          group: network-operator
#          authentication:
#            algorithm: md5
#            password: "0x5632724fb8ac3699296af26281e1d0f1"
#            localized_key: true
#
#        - authentication:
#            algorithm: md5
#            localized_key: true
#            password: "0x5632724fb8ac3699296af26281e1d0f1"
#            priv:
#              aes_128: true
#              privacy_password: "0x5632724fb8ac3699296af26281e1d0f1"
#          group: network-operator
#          user: snmp_user_2
#
#      use_acls:
#        - user: snmp_user_1
#          ipv4: acl1
#          ipv6: acl2
#        - user: snmp_user_2
#          ipv4: acl3
#          ipv6: acl4
#
# commands:
#   - snmp-server contact nxosswitchadmin2@localhost
#   - no snmp-server enable traps system Clock-change-notification
#   - snmp-server location serverroom-2
#   - no snmp-server user snmp_user_2 use-ipv4acl acl3 use-ipv6acl acl4
#   - no snmp-server host 192.0.2.2 informs version 3 auth NMS
#   - snmp-server host 192.0.3.2 informs version 3 auth NMS
#   - no snmp-server community private group network-admin
#   - snmp-server community secret group network-operator
#
# after:
#   aaa_user:
#      cache_timeout: 36000
#    communities:
#      - community: public
#        group: network-operator
#      - community: secret
#        group: network-operator
#    contact: nxosswitchadmin2@localhost
#    location: serverroom-2
#    traps:
#      aaa:
#        server_state_change: true
#    hosts:
#      - host: 192.0.2.1
#        traps: true
#        version: '1'
#        community: public
#      - host: 192.0.2.1
#        source_interface: Ethernet1/1
#      - host: 192.0.3.2
#        informs: true
#        version: '3'
#        auth: NMS
#    users:
#      auth:
#        - user: admin
#          group: network-admin
#          authentication:
#            algorithm: md5
#            password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"
#            localized_key: true
#            priv:
#              privacy_password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"
#
#        - user: snmp_user_1
#          group: network-operator
#          authentication:
#            algorithm: md5
#            password: '0x5632724fb8ac3699296af26281e1d0f1'
#            localized_key: true
#
#        - user: snmp_user_2
#          group: network-operator
#          authentication:
#            algorithm: md5
#            password: '0x5632724fb8ac3699296af26281e1d0f1'
#            localized_key: true
#            priv:
#              privacy_password: '0x5632724fb8ac3699296af26281e1d0f1'
#              aes_128: true
#
#      use_acls:
#        - user: snmp_user_1
#          ipv4: acl1
#          ipv6: acl2
#

# After state:
# ------------
# nxos-9k-rdo# show running-config | section "^snmp-server"
# snmp-server contact nxosswitchadmin2@localhost
# snmp-server location serverroom-2
# snmp-server aaa-user cache-timeout 36000
# snmp-server user admin network-admin auth md5 0xcbde46b02c46e0bcd3ac5af6a8b13da9 priv 0xcbde46b02c46e0bcd3ac5af6a8b13da9 localizedkey
# snmp-server user snmp_user_1 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
# snmp-server user snmp_user_2 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 priv aes-128 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
# snmp-server user snmp_user_1 use-ipv4acl acl1 use-ipv6acl acl2
# snmp-server user snmp_user_2 use-ipv4acl acl3 use-ipv6acl acl4
# snmp-server host 192.0.2.1 traps version 1 public
# snmp-server host 192.0.2.1 source-interface Ethernet1/1
# snmp-server host 192.0.2.2 informs version 3 auth NMS
# snmp-server community secret group network-operator
# snmp-server community public group network-operator
# snmp-server enable traps aaa server-state-change
# snmp-server enable traps system Clock-change-notification

# Using deleted

# Before state:
# ------------
# nxos-9k-rdo# show running-config | section "^snmp-server"
# snmp-server contact nxosswitchadmin@localhost
# snmp-server location serverroom-1
# snmp-server aaa-user cache-timeout 36000
# snmp-server user admin network-admin auth md5 0xcbde46b02c46e0bcd3ac5af6a8b13da9 priv 0xcbde46b02c46e0bcd3ac5af6a8b13da9 localizedkey
# snmp-server user snmp_user_1 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
# snmp-server user snmp_user_2 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 priv aes-128 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
# snmp-server user snmp_user_1 use-ipv4acl acl1 use-ipv6acl acl2
# snmp-server user snmp_user_2 use-ipv4acl acl3 use-ipv6acl acl4
# snmp-server host 192.0.2.1 traps version 1 public
# snmp-server host 192.0.2.1 source-interface Ethernet1/1
# snmp-server host 192.0.2.2 informs version 3 auth NMS
# snmp-server community private group network-admin
# snmp-server community public group network-operator
# snmp-server enable traps aaa server-state-change
# snmp-server enable traps system Clock-change-notification

- name: Delete SNMP Server configurations from the device (admin user will not be deleted)
  cisco.nxos.nxos_snmp_server:
    state: deleted

# Task output
# -------------
# before:
#   aaa_user:
#      cache_timeout: 36000
#    communities:
#      - community: private
#        group: network-admin
#      - community: public
#        group: network-operator
#    contact: nxosswitchadmin@localhost
#    location: serverroom-1
#    traps:
#      aaa:
#        server_state_change: true
#      system:
#        clock_change_notification: true
#    hosts:
#      - host: 192.0.2.1
#        traps: true
#        version: "1"
#        community: public
#
#      - host: 192.0.2.1
#        source_interface: Ethernet1/1
#
#      - host: 192.0.2.2
#        informs: true
#        version: "3"
#        auth: NMS
#    users:
#      auth:
#        - user: admin
#          group: network-admin
#          authentication:
#            algorithm: md5
#            password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"
#            localized_key: true
#            priv:
#              privacy_password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"
#
#        - user: snmp_user_1
#          group: network-operator
#          authentication:
#            algorithm: md5
#            password: "0x5632724fb8ac3699296af26281e1d0f1"
#            localized_key: true
#
#        - authentication:
#            algorithm: md5
#            localized_key: true
#            password: "0x5632724fb8ac3699296af26281e1d0f1"
#            priv:
#              aes_128: true
#              privacy_password: "0x5632724fb8ac3699296af26281e1d0f1"
#          group: network-operator
#          user: snmp_user_2
#
#      use_acls:
#        - user: snmp_user_1
#          ipv4: acl1
#          ipv6: acl2
#        - user: snmp_user_2
#          ipv4: acl3
#          ipv6: acl4
#
# commands:
#   - no snmp-server contact nxosswitchadmin@localhost
#   - no snmp-server location serverroom-1
#   - no snmp-server aaa-user cache-timeout 36000
#   - no snmp-server user admin network-admin auth md5 0xcbde46b02c46e0bcd3ac5af6a8b13da9 priv 0xcbde46b02c46e0bcd3ac5af6a8b13da9 localizedkey
#   - no snmp-server user snmp_user_1 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
#   - no snmp-server user snmp_user_2 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 priv aes-128 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
#   - no snmp-server user snmp_user_1 use-ipv4acl acl1 use-ipv6acl acl2
#   - no snmp-server user snmp_user_2 use-ipv4acl acl3 use-ipv6acl acl4
#   - no snmp-server host 192.0.2.1 traps version 1 public
#   - no snmp-server host 192.0.2.1 source-interface Ethernet1/1
#   - no snmp-server host 192.0.2.2 informs version 3 auth NMS
#   - no snmp-server community private group network-admin
#   - no snmp-server community public group network-operator
#   - no snmp-server enable traps aaa server-state-change
#   - no snmp-server enable traps system Clock-change-notification
#
# after:
#   users:
#     auth:
#       - user: admin
#         group: network-admin
#         authentication:
#           algorithm: md5
#           password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"
#           localized_key: true
#           priv:
#             privacy_password: "0xcbde46b02c46e0bcd3ac5af6a8b13da9"

# After state:
# ------------
# nxos-9k-rdo# show running-config | section "^snmp-server"
# snmp-server user admin network-admin auth md5 0xcbde46b02c46e0bcd3ac5af6a8b13da9 priv 0xcbde46b02c46e0bcd3ac5af6a8b13da9 localizedkey

# Using rendered
# ---------------

- name: Render platform specific configuration lines with state rendered (without connecting to the device)
  cisco.nxos.nxos_snmp_server:
    config:
      aaa_user:
        cache_timeout: 36000
      communities:
        - community: public
          group: network-operator
        - community: private
          group: network-admin
      contact: nxosswitchadmin@localhost
      location: serverroom-1
      traps:
        aaa:
          server_state_change: true
        system:
          clock_change_notification: true
      hosts:
        - host: 192.0.2.1
          traps: true
          version: '1'
          community: public
        - host: 192.0.2.1
          source_interface: Ethernet1/1
        - host: 192.0.2.2
          informs: true
          version: '3'
          auth: NMS
      users:
        auth:
          - user: snmp_user_1
            group: network-operator
            authentication:
              algorithm: md5
              password: '0x5632724fb8ac3699296af26281e1d0f1'
              localized_key: true
          - user: snmp_user_2
            group: network-operator
            authentication:
              algorithm: md5
              password: '0x5632724fb8ac3699296af26281e1d0f1'
              localized_key: true
              priv:
                privacy_password: '0x5632724fb8ac3699296af26281e1d0f1'
                aes_128: true
        use_acls:
          - user: snmp_user_1
            ipv4: acl1
            ipv6: acl2
          - user: snmp_user_2
            ipv4: acl3
            ipv6: acl4
    state: rendered


# Task Output (redacted)
# -----------------------
#  rendered:
#    - snmp-server contact nxosswitchadmin@localhost
#    - snmp-server location serverroom-1
#    - snmp-server aaa-user cache-timeout 36000
#    - snmp-server user snmp_user_1 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
#    - snmp-server user snmp_user_2 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 priv aes-128 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
#    - snmp-server user snmp_user_1 use-ipv4acl acl1 use-ipv6acl acl2
#    - snmp-server user snmp_user_2 use-ipv4acl acl3 use-ipv6acl acl4
#    - snmp-server host 192.0.2.1 traps version 1 public
#    - snmp-server host 192.0.2.1 source-interface Ethernet1/1
#    - snmp-server host 192.0.2.2 informs version 3 auth NMS
#    - snmp-server community private group network-admin
#    - snmp-server community public group network-operator
#    - snmp-server enable traps aaa server-state-change
#    - snmp-server enable traps system Clock-change-notification

# Using parsed

# parsed.cfg
# ------------
# snmp-server contact nxosswitchadmin@localhost
# snmp-server location serverroom-1
# snmp-server aaa-user cache-timeout 36000
# snmp-server user snmp_user_1 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
# snmp-server user snmp_user_2 network-operator auth md5 0x5632724fb8ac3699296af26281e1d0f1 priv aes-128 0x5632724fb8ac3699296af26281e1d0f1 localizedkey
# snmp-server user snmp_user_1 use-ipv4acl acl1 use-ipv6acl acl2
# snmp-server user snmp_user_2 use-ipv4acl acl3 use-ipv6acl acl4
# snmp-server host 192.0.2.1 traps version 1 public
# snmp-server host 192.0.2.1 source-interface Ethernet1/1
# snmp-server host 192.0.2.2 informs version 3 auth NMS
# snmp-server community private group network-admin
# snmp-server community public group network-operator
# snmp-server enable traps aaa server-state-change
# snmp-server enable traps system Clock-change-notification

- name: Parse externally provided snmp-server configuration
  cisco.nxos.nxos_snmp_server:
    running_config: "{{ lookup('file', './parsed.cfg') }}"
    state: parsed

# Task output (redacted)
# -----------------------
#  parsed:
#   aaa_user:
#      cache_timeout: 36000
#    communities:
#      - community: private
#        group: network-admin
#      - community: public
#        group: network-operator
#    contact: nxosswitchadmin@localhost
#    location: serverroom-1
#    traps:
#      aaa:
#        server_state_change: true
#      system:
#        clock_change_notification: true
#    hosts:
#      - host: 192.0.2.1
#        traps: true
#        version: "1"
#        community: public
#
#      - host: 192.0.2.1
#        source_interface: Ethernet1/1
#
#      - host: 192.0.2.2
#        informs: true
#        version: "3"
#        auth: NMS
#    users:
#      auth:
#        - user: snmp_user_1
#          group: network-operator
#          authentication:
#            algorithm: md5
#            password: "0x5632724fb8ac3699296af26281e1d0f1"
#            localized_key: true
#
#        - authentication:
#            algorithm: md5
#            localized_key: true
#            password: "0x5632724fb8ac3699296af26281e1d0f1"
#            priv:
#              aes_128: true
#              privacy_password: "0x5632724fb8ac3699296af26281e1d0f1"
#          group: network-operator
#          user: snmp_user_2
#
#      use_acls:
#        - user: snmp_user_1
#          ipv4: acl1
#          ipv6: acl2
#        - user: snmp_user_2
#          ipv4: acl3
#          ipv6: acl4
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
    - sample command 1
    - sample command 2
    - sample command 3
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - sample command 1
    - sample command 2
    - sample command 3
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

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.snmp_server.snmp_server import (
    Snmp_serverArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.snmp_server.snmp_server import (
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
