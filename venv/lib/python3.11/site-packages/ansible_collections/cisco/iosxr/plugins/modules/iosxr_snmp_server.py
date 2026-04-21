#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_snmp_server
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: iosxr_snmp_server
short_description: Resource module to configure snmp server.
description: This module configures and manages the attributes of snmp-server on Cisco
  IOSXR platforms.
version_added: 2.6.0
author: Ashwini Mhatre (@amhatre)
notes:
- Tested against Cisco Iosxr 7.0.2
- This module works with connection C(network_cli).
options:
  config:
    description: SNMP server configuration.
    type: dict
    suboptions:
      chassis_id:
        description: SNMP chassis identifier.
        type: str
      communities:
        description: Enable SNMP;  set community string and access privileges.
        type: list
        elements: dict
        suboptions:
          name:
            description: Community name.
            type: str
          acl_v4:
            description: Ipv4 access list.
            type: str
          acl_v6:
            description: IPv6 access list name.
            type: str
          ro:
            description: Only reads are permitted.
            type: bool
          rw:
            description: Read-write access.
            type: bool
          sdrowner:
            type: bool
            description: SDR Owner permissions for MIB Objects.
          systemowner:
            type: bool
            description: System Owner permissions for MIB objects.
          v4_acl:
            description: V4 Access-list name.
            type: str
      community_maps:
        description: Community Mapping as per RFC-2576.
        type: list
        elements: dict
        suboptions:
          name:
            description: Community name
            type: str
          context:
            description: Context Name for the community mapping.
            type: str
          security_name:
            description: Security Name for the community mapping.
            type: str
          target_list:
            description: list of targets valid with this community.
            type: str
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
              timeout:
                type: int
                description: Specify timeout.
          rule_sets:
            type: list
            elements: dict
            description: Configure a specified correlation ruleset.
            suboptions:
              name:
                type: str
                description: Name of the ruleset
      contact:
        description: Person to contact about the syste,.
        type: str
      context:
        description: Create/Delete a context apart from default
        type: list
        elements: str
      drop:
        type: dict
        description: Silently drop SNMP packets
        suboptions:
          unknown_user:
            description: Silently drop unknown v3 user packets
            type: bool
          report_IPv4:
            description: Config to drop snmpv3 error reports matching Ipv4 ACL.
            type: str
          report_IPv6:
            description: Config to drop snmpv3 error reports matching Ipv4 ACL.
            type: str
      engineid:
        description: SNMPv3 engine ID configuration.
        type: dict
        suboptions:
          local:
            description:  Local SNMP agent
            type: str
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
          acl_v4:
            description: Ipv4 Type of Access-list
            type: str
            aliases:
              - Ipv4_acl
          acl_v6:
            description: Ipv6 Type of Access-list
            type: str
            aliases:
              - Ipv6_acl
          v4_acl:
            description: V4 Access-list name
            type: str
      hosts: &hosts
        description: Notification destinations
        type: list
        elements: dict
        suboptions:
          host:
            description: Hostname or IP address of SNMP notification host.
            type: str
          community:
            description: community string.
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
            choices: ['1', '2c', '3']
      ifindex:
        description: Enable ifindex persistence
        type: bool
      ifmib:
        type: dict
        description: IF-MIB configuration commands.
        suboptions:
          ifalias_long:
            type: bool
            description: Modify parameters for ifAlias object.
          internal_cache_max_duration:
            type: int
            description: IFMIB internal lookahead cache.
          ipsubscriber:
            type: bool
            description: Enable ipsubscriber interfaces in IFMIB.
          stats:
            type: bool
            description: Modify IF-MIB statistics parameters.
      inform:
        description: Configure SNMP Informs options
        suboptions:
          pending:
            description: Set number of unacked informs to hold
            type: int
          retries:
            description: Set retry count for informs
            type: int
          timeout:
            description: Set timeout for informs
            type: int
        type: dict
      interfaces:
        type: list
        elements: dict
        description: Enter the SNMP interface configuration commands.
        suboptions:
          name:
            type: str
            description: Name of interface.
          notification_linkupdown_disable:
            type: bool
            description: Disable linkUp and linkDown notification.
          index_persistent:
            type: bool
            description: Configure ifIndex attributes Persistency across system reloads.
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
      location:
        description: The sysLocation string.
        type: str
      logging_threshold_oid_processing:
        type: int
        description: Configure threshold to start logging slow OID requests processing.
      logging_threshold_pdu_processing:
        type: int
        description: Configure threshold to start logging slow PDU requests processing.
      mib_bulkstat_max_procmem_size:
        type: int
        description: per process memory limit in kilo bytes
      mib_object_lists:
        description: mib object lists
        type: list
        elements: str
      mib_schema:
        type: list
        elements: dict
        description: mib schema
        suboptions:
          name:
            type: str
            description: mib schema name.
          object_list:
            type: str
            description: Name of an object List.
          poll_interval:
            type: int
            description: Periodicity for polling of objects in this schema in Min.
      mib_bulkstat_transfer_ids:
        description: mib bulkstat transfer ids.
        type: list
        elements: dict
        suboptions:
          name:
            type: str
            description: mib transfer-id name.
          buffer_size:
            type: int
            description: Bulkstat data file maximum size.
          enable:
            type: bool
            description: Start Data Collection for this Configuration
          format_schemaASCI:
            type: bool
            description: format
          retain:
            type: int
            description: Retention period in Min.
          retry:
            type: int
            description: Number of Retries.
          schema:
            type: str
            description: Schema that contains objects to be collected.
          transfer_interval:
            type: int
            description: transfer-interval
      mroutemib_send_all_vrf:
        type: bool
        description: Configurations related to IPMROUTE-MIB(cisco-support).
      notification_log_mib:
        description: notification log mib.
        type: dict
        suboptions:
          GlobalSize:
            type: int
            description: GlobalSize, max number of notifications that can be logged in all logs.
          default:
            type: bool
            description: To create a default log
          disable:
            type: bool
            description: disable, to disable the logging in default log.
          size:
            description: size, The max number of notifications that this log (default) can hold.
            type: int
      oid_poll_stats:
        type: bool
        description: Enable OID poll stats oper CLI
      overload_control:
        type: dict
        description: Set overload-control params for handling incoming messages in critical processing mode.
        suboptions:
          overload_drop_time:
            type: int
            description: Overload drop time (in seconds) for incoming queue (default 1 sec).
          overload_throttle_rate:
            type: int
            description: Overload throttle rate for incoming queue (default 500 msec)
      packetsize:
        type: int
        description: Largest SNMP packet size.
      queue_length:
        type: int
        description: Queue length (default 100).
      targets:
        type: list
        elements: dict
        description: targets
        suboptions:
          name:
            type: str
            description: Name of the target list.
          host:
            type: str
            description: Specify host name.
          vrf:
            type: str
            description: Specify VRF name.
      throttle_time:
        type: int
        description: Set throttle time for handling incoming messages.
      timeouts:
        type: dict
        description: SNMP timeouts
        suboptions:
          duplicate:
            description: Duplicate request feature timeout
            type: int
          inQdrop:
            type: int
            description: incoming queue drop feature.
          pdu_stats:
            type: int
            description: SNMP pdu statistics end to end.
          subagent:
            type: int
            description: Sub-Agent Request timeout.
          threshold:
            type: int
            description: threshold incoming queue drop feature.
      trap:
        type: dict
        description: MIB trap configurations.
        suboptions:
          authentication_vrf_disable:
            type: bool
            description: Disable authentication traps for packets on a vrf.
          link_ietf:
            type: bool
            description: Link up/down trap configuratio.
          throttle_time:
            type: int
            description: Set throttle time for handling more traps.
      trap_source:
        description: Assign an interface for the source address of all traps
        type: str
      trap_timeout:
        description: Set timeout for TRAP message retransmissions
        type: int
      traps:
        description: Enable traps to all configured recipients.
        type: dict
        suboptions:
          addrpool:
            type: dict
            description: Enable SNMP Address Pool traps.
            suboptions:
              low:
                type: bool
                description: Enable SNMP Address Pool Low Threshold trap.
              high:
                type: bool
                description: Enable SNMP Address Pool High Threshold trap.
          bfd:
            type: bool
            description: Enable BFD traps.
          bgp:
            description: Enable Bgp traps.
            type: dict
            suboptions:
              cbgp2:
                type: bool
                description: Enable CISCO-BGP4-MIB v2 traps.
              updown:
                type: bool
                description: Enable CISCO-BGP4-MIB v2 up/down traps.
          bulkstat_collection:
            type: bool
            description: Enable Data-Collection-MIB Collection notifications.
          bulkstat_transfer:
            type: bool
            description: Enable Data-Collection-MIB Trnasfer notifications.
          bridgemib:
            type: bool
            description: Enable SNMP Trap for Bridge MIB.
          copy_complete:
            type: bool
            description: Enable CISCO-CONFIG-COPY-MIB ccCopyCompletion traps.
          cisco_entity_ext:
            type: bool
            description: Enable SNMP entity traps
          config:
            type: bool
            description: Enable SNMP config traps.
          diameter:
            type: dict
            description: Enable SNMP diameter traps.
            suboptions:
              peerdown:
                type: bool
                description: Enable peer connection down notification.
              peerup:
                type: bool
                description: Enable peer connection up notification.
              permanentfail:
                type: bool
                description: Enable permanent failure notification.
              protocolerror:
                type: bool
                description: Enable protocol error notifications
              transientfail:
                type: bool
                description: Enable transient failure notification.
          entity:
            type: bool
            description: Enable SNMP entity traps.
          entity_redundancy:
            type: dict
            description: Enable SNMP CISCO-ENTITY-REDUNDANCY-MIB traps.
            suboptions:
              all:
                type: bool
                description: Enable all CISCO-ENTITY-REDUNDANCY-MIB traps
              status:
                type: bool
                description: Enable status change traps
              switchover:
                type: bool
                description: Enable switchover traps.
          entity_state:
            type: dict
            description: Enable SNMP entity-state traps.
            suboptions:
              operstatus:
                type: bool
                description: Enable entity oper status enable notification.
              switchover:
                description: Enable entity state switchover notifications
                type: bool
          flash:
            type: dict
            description: Enable  flash-mib traps.
            suboptions:
              insertion:
                type: bool
                description: Enable ciscoFlashDeviceInsertedNotif.
              removal:
                type: bool
                description: Enable ciscoFlashDeviceRemovedNotif.
          fru_ctrl:
            type: bool
            description: Enable SNMP entity FRU control traps.
          hsrp:
            type: bool
            description: Enable SNMP hsrp traps.
          ipsla:
            type: bool
            description: Enable SNMP hipsla traps.
          ipsec:
            type: dict
            description: Enable SNMP IPSec traps.
            suboptions:
              start:
                type: bool
                description: Enable SNMP IPsec Tunnel Start trap.
              stop:
                type: bool
                description: Enable SNMP IPsec Tunnel Stop trap.
          isakmp:
            type: dict
            description: Enable SNMP isakmp traps.
            suboptions:
              start:
                type: bool
                description: Enable SNMP isakmp Tunnel Start trap.
              stop:
                type: bool
                description: Enable SNMP isakmp Tunnel Stop trap.

          isis:
            description: Enable isis traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              adjacency_change:
                description: adjacency-change
                type: bool
              all:
                type: bool
                description: anable all is-is traps.
              area_mismatch:
                description: area-mismatch
                type: bool
              attempt_to_exceed_max_sequence:
                description: attempt-to-exceed-max-sequence
                type: bool
              authentication_failure:
                description: authentication-failure.
                type: bool
              authentication_type_failure:
                description: authentication-type-failure.
                type: bool
              corrupted_lsp_detected:
                description: isisCorruptedLSPDetected
                type: bool
              database_overload:
                description: database-overload
                type: bool
              id_len_mismatch:
                type: bool
                description: isisIDLenMismatch
              lsp_error_detected:
                type: bool
                description: lsp-error-detected.
              lsp_too_large_to_propagate:
                type: bool
                description: lsp-too-large-to-propagate
              manual_address_drops:
                type: bool
                description: manual_address_drops
              max_area_addresses_mismatch:
                type: bool
                description: max_area_addresses_mismatch
              orig_lsp_buff_size_mismatch:
                type: bool
                description: orig-lsp-buff-size-mismatch
              version_skew:
                type: bool
                description: version-skew
              own_lsp_purge:
                description: own-lsp-purge
                type: bool
              rejected_adjacency:
                description: rejected-adjacency
                type: bool
              protocols_supported_mismatch:
                description: protocols-supported-mismatch
                type: bool
              sequence_number_skip:
                description: sequence-number-skip.
                type: bool
          l2tun:
            type: dict
            description: Enable L2TUN traps.
            suboptions:
              pseudowire_status:
                type: bool
                description: Enable L2TUN pseudowire status traps.
              sessions:
                type: bool
                description: Enable L2TUN sessions traps.
              tunnel_down:
                type: bool
                description: Enable L2TUN tunnel DOWN traps.
              tunnel_up:
                type: bool
                description: Enable L2TUN tunnel UP traps.
          l2vpn:
            type: dict
            description: Enable L2VPN traps.
            suboptions:
              all:
                type: bool
                description: Enable L2VPN ALL traps.
              cisco:
                type: bool
                description: Enable L2VPN CISCO  traps.
              vc_down:
                type: bool
                description: Enable L2VPN VC DOWN traps.
              vc_up:
                type: bool
                description: Enable L2VPN VC UP traps.
          msdp_peer_state_change:
            type: bool
            description: Enable SNMP MSDP traps
          ntp:
            type: bool
            description: Enable SNMP Cisco Ntp traps.
          ospf:
            description: Enable Ospf traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              errors:
                description: error
                type: dict
                suboptions:
                  bad_packet:
                    type: bool
                    description: bad-packet
                  authentication_failure:
                    type: bool
                    description: authentication-failure.
                  config_error:
                    type: bool
                    description: config-error
                  virt_bad_packet:
                    type: bool
                    description: virt-bad-packet
                  virt_authentication_failure:
                    type: bool
                    description: virt-authentication-failure
                  virt_config_error:
                    type: bool
                    description: virt_config_error
              lsa:
                description: lsa
                type: dict
                suboptions:
                  lsa_maxage:
                    type: bool
                    description: lsa-maxage
                  lsa_originate:
                    type: bool
                    description: lsa-originate
              retransmit:
                description: retransmit
                type: dict
                suboptions:
                  packets:
                    type: bool
                    description: packets
                  virt_packets:
                    type: bool
                    description: virt-packets
              state_change:
                description: state-change.
                type: dict
                suboptions:
                  if_state_change:
                    type: bool
                    description: if-state-change
                  neighbor_state_change:
                    type: bool
                    description: neighbor-state-change
                  virtif_state_change:
                    type: bool
                    description: virtif-state-change
                  virtneighbor_state_change:
                    type: bool
                    description: virtneighbor-state-change
          ospfv3:
            description: Enable Ospfv3 traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              errors:
                description: error
                type: dict
                suboptions:
                  bad_packet:
                    type: bool
                    description: bad-packet
                  config_error:
                    type: bool
                    description: config-error
                  virt_bad_packet:
                    type: bool
                    description: virt-bad-packet
                  virt_config_error:
                    type: bool
                    description: virt_config_error
              state_change:
                description: state-change.
                type: dict
                suboptions:
                  if_state_change:
                    type: bool
                    description: if-state-change
                  neighbor_state_change:
                    type: bool
                    description: neighbor-state-change
                  virtif_state_change:
                    type: bool
                    description: virtif-state-change
                  virtneighbor_state_change:
                    type: bool
                    description: virtneighbor-state-change
                  nssa_state_change:
                    type: bool
                    description: nssa-state-change
                  restart_status_change:
                    type: bool
                    description: restart-status-change
                  restart_helper_status_change:
                    type: bool
                    description: restart-helper-status-change
                  restart_virtual_helper_status_change:
                    type: bool
                    description: restart-virtual-helper-status-change
          power:
            type: bool
            description: Enable SNMP entity power traps.
          rf:
            type: bool
            description: Enable SNMP RF-MIB traps.
          pim:
            description: Enable Pim traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              interface_state_change :
                description: interface-state-change .
                type: bool
              invalid_message_received :
                description: invalid-message-received
                type: bool
              neighbor_change:
                description: neighbor-change.
                type: bool
              rp_mapping_change:
                description: rp-mapping-change.
                type: bool
          rsvp:
            description: Enable rsvp traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              all:
                description: enable all traps.
                type: bool
              lost_flow:
                description: lost-flow
                type: bool
              new_flow:
                description: new-flow
                type: bool
          selective_vrf_download_role_change:
            type: bool
            description: Enable selective VRF download traps.
          sensor:
            type: bool
            description: Enable SNMP entity sensor traps
          snmp:
            description: Enable snmp traps. If set to enabled , all the traps are set.
            type: dict
            suboptions:
              authentication:
                description: authentication
                type: bool
              linkdown:
                description: link-down
                type: bool
              linkup:
                description: link-up
                type: bool
              warmstart:
                description: warmstart.
                type: bool
              coldstart:
                description: coldstart.
                type: bool
          vrrp_events:
            description: vrrp
            type: bool
          syslog:
            type: bool
            description: syslog
          subscriber:
            type: dict
            description: Subscriber notification commands.
            suboptions:
              session_agg_access_interface:
                type: bool
                description: Subscriber notification at access interface level
              session_agg_node:
                type: bool
                description: Subscriber notification at node level
          system:
            type: bool
            description: Enable SNMP SYSTEMMIB-MIB traps.
          vpls:
            type: dict
            description: Enable VPLS traps
            suboptions:
              all:
                type: bool
                description: Enable all VPLS traps.
              full_clear:
                type: bool
                description: Enable VPLS Full Clear traps.
              full_raise:
                type: bool
                description: Enable VPLS Full Raise traps.
              status:
                type: bool
                description: Enable VPLS Status traps
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
          acl_v4:
            description: Ipv4 Type of Access-list
            type: str
            aliases:
              - Ipv4_acl
          acl_v6:
            description: Ipv6 Type of Access-list
            type: str
            aliases:
              - Ipv6_acl
          SDROwner:
            description:  SDR Owner permissions for MIB Objects.
            type: bool
          SystemOwner:
            description: System Owner permissions for MIB objects.
            type: bool
          v4_acl:
            type: str
            description: V4 Access-list name
          version:
            description: snmp security version
            type: str
            choices: ['v1', 'v2c', 'v3']
      vrfs:
        description: Specify the VRF in which the source address is used
        type: list
        elements: dict
        suboptions:
          vrf:
            description: vrf name.
            type: str
          context:
            description: Configure the source interface for SNMP notifications
            type: list
            elements: str
          hosts: *hosts
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the IOSXR device by
      executing the command B(show running-config snmp-server).
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
# Using state: merged
# Before state:
# -------------
# RP/0/RP0/CPU0:test2#show running-config snmp-server
# --------------------- EMPTY -----------------
# Merged play:
# ------------

- name: Merge the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_snmp_server:
    config:
      vrfs:
        - hosts:
            - community: test1
              host: 1.1.1.1
              traps: true
          vrf: vrf1
      users:
        - Ipv4_acl: test1
          Ipv6_acl: test2
          group: test2
          user: u1
          version: v1
      timeouts:
        duplicate: 0
        inQdrop: 0
      trap:
        throttle_time: 12
      targets:
        - host: 1.1.1.2
          name: test
      ifmib:
        internal_cache_max_duration: 4
      inform:
        retries: 7
      chassis_id: test2
      packetsize: 490
      queue_length: 2
      throttle_time: 60
      trap_source: GigabitEthernet0/0/0/2
      trap_timeout: 3
      context:
        - c1
        - c2
      contact: t1
      correlator:
        buffer_size: 1024
      communities:
        - name: test2
          ro: true
          sdrowner: true
          acl_v4: test
          acl_v6: test1
      community_maps:
        - name: cm1
          context: c1
          target_list: t1
          security_name: s1
      drop:
        report_IPv4: test1
        unknown_user: true
      ipv6:
        precedence: routine
      ipv4:
        dscp: af11
      location: test1
      logging_threshold_oid_processing: 1
      logging_threshold_pdu_processing: 1
      mib_bulkstat_max_procmem_size: 101
      mroutemib_send_all_vrf: true
      overload_control:
        overload_drop_time: 4
        overload_throttle_rate: 6
      notification_log_mib:
        GlobalSize: 5
        size: 5
      traps:
        hsrp: true
        ipsla: true
        ipsec:
          start: true
          stop: true
        bridgemib: true
        bulkstat_collection: true
        cisco_entity_ext: true
        config: true
        copy_complete: true
        addrpool:
          high: true
          low: true
        bfd: true
        bgp:
          cbgp2: true
        l2tun:
          sessions: true
          tunnel_down: true
          tunnel_up: true
        l2vpn:
          all: true
          vc_down: true
          vc_up: true
        msdp_peer_state_change: true

#
# Commands Fired:
# ------------
# "commands": [
#         "snmp-server chassis-id test2",
#         "snmp-server correlator buffer-size 1024",
#         "snmp-server contact t1",
#         "snmp-server ipv4 dscp af11",
#         "snmp-server ipv6 precedence routine",
#         "snmp-server location test1",
#         "snmp-server logging threshold oid-processing 1",
#         "snmp-server logging threshold pdu-processing 1",
#         "snmp-server mib bulkstat max-procmem-size 101",
#         "snmp-server mroutemib send-all-vrf",
#         "snmp-server overload-control 4 6",
#         "snmp-server packetsize 490",
#         "snmp-server queue-length 2",
#         "snmp-server throttle-time 60",
#         "snmp-server trap-source GigabitEthernet0/0/0/2",
#         "snmp-server trap-timeout 3",
#         "snmp-server drop report acl IPv4 test1",
#         "snmp-server drop unknown-user",
#         "snmp-server ifmib internal cache max-duration 4",
#         "snmp-server inform retries 7",
#         "snmp-server notification-log-mib size 5",
#         "snmp-server notification-log-mib GlobalSize 5",
#         "snmp-server trap throttle-time 12",
#         "snmp-server timeouts inQdrop 0",
#         "snmp-server timeouts duplicate 0",
#         "snmp-server traps addrpool low",
#         "snmp-server traps addrpool high",
#         "snmp-server traps bfd",
#         "snmp-server traps bgp cbgp2",
#         "snmp-server traps bulkstat collection",
#         "snmp-server traps bridgemib",
#         "snmp-server traps copy-complete",
#         "snmp-server traps cisco-entity-ext",
#         "snmp-server traps config",
#         "snmp-server traps hsrp",
#         "snmp-server traps ipsla",
#         "snmp-server traps ipsec tunnel start",
#         "snmp-server traps ipsec tunnel stop",
#         "snmp-server traps l2tun sessions",
#         "snmp-server traps l2tun tunnel-up",
#         "snmp-server traps l2tun tunnel-down",
#         "snmp-server traps l2vpn all",
#         "snmp-server traps l2vpn vc-up",
#         "snmp-server traps l2vpn vc-down",
#         "snmp-server traps msdp peer-state-change",
#         "snmp-server community test2 RO SDROwner IPv4 test IPv6 test1",
#         "snmp-server community-map cm1 context c1 security-name s1 target-list t1",
#         "snmp-server context c1",
#         "snmp-server context c2",
#         "snmp-server user u1 test2 v1 IPv4 test1 IPv6 test2",
#         "snmp-server target list test2 vrf vrf2",
#         "snmp-server target list test host 1.1.1.2",
#         "snmp-server vrf vrf1",
#         "host 1.1.1.1 traps test1"
#
#     ],
# After state:
# ------------
# RP/0/RP0/CPU0:test2#show running-config snmp-server
# Mon Nov 29 12:49:29.521 UTC
# snmp-server vrf vrf1
#  host 1.1.1.1 traps test1
# !
# snmp-server drop report acl IPv4 test1
# snmp-server drop unknown-user
# snmp-server ipv4 dscp af11
# snmp-server ipv6 precedence routine
# snmp-server user u1 test2 v1 IPv4 test1 IPv6 test2
# snmp-server community test2 RO SDROwner IPv4 test IPv6 test1
# snmp-server queue-length 2
# snmp-server trap-timeout 3
# snmp-server trap throttle-time 12
# snmp-server traps bfd
# snmp-server traps bgp cbgp2
# snmp-server traps copy-complete
# snmp-server traps hsrp
# snmp-server traps ipsla
# snmp-server traps msdp peer-state-change
# snmp-server traps ipsec tunnel stop
# snmp-server traps ipsec tunnel start
# snmp-server traps config
# snmp-server traps l2tun sessions
# snmp-server traps l2tun tunnel-up
# snmp-server traps l2tun tunnel-down
# snmp-server traps bulkstat collection
# snmp-server traps l2vpn all
# snmp-server traps l2vpn vc-up
# snmp-server traps l2vpn vc-down
# snmp-server traps bridgemib
# snmp-server traps addrpool low
# snmp-server traps addrpool high
# snmp-server traps cisco-entity-ext
# snmp-server chassis-id test2
# snmp-server contact t1
# snmp-server location test1
# snmp-server target list test host 1.1.1.2
# snmp-server target list test2 vrf vrf2
# snmp-server context c1
# snmp-server context c2
# snmp-server logging threshold oid-processing 1
# snmp-server logging threshold pdu-processing 1
# snmp-server mib bulkstat max-procmem-size 101
# snmp-server timeouts duplicate 0
# snmp-server timeouts inQdrop 0
# snmp-server packetsize 490
# snmp-server correlator buffer-size 1024
# snmp-server trap-source GigabitEthernet0/0/0/2
# snmp-server throttle-time 60
# snmp-server community-map cm1 context c1 security-name s1 target-list t1
# snmp-server inform retries 7
# snmp-server overload-control 4 6
# snmp-server ifmib internal cache max-duration 4
# snmp-server mroutemib send-all-vrf
# snmp-server notification-log-mib size 5
# snmp-server notification-log-mib GlobalSize 5
#
#
# Using state: deleted
# Before state:
# -------------
# RP/0/RP0/CPU0:test2#show running-config snmp-server
# Mon Nov 29 12:49:29.521 UTC
# snmp-server vrf vrf1
#  host 1.1.1.1 traps test1
# !
# snmp-server drop report acl IPv4 test1
# snmp-server drop unknown-user
# snmp-server ipv4 dscp af11
# snmp-server ipv6 precedence routine
# snmp-server user u1 test2 v1 IPv4 test1 IPv6 test2
# snmp-server community test2 RO SDROwner IPv4 test IPv6 test1
# snmp-server queue-length 2
# snmp-server trap-timeout 3
# snmp-server trap throttle-time 12
# snmp-server traps bfd
# snmp-server traps bgp cbgp2
# snmp-server traps copy-complete
# snmp-server traps hsrp
# snmp-server traps ipsla
# snmp-server traps msdp peer-state-change
# snmp-server traps ipsec tunnel stop
# snmp-server traps ipsec tunnel start
# snmp-server traps config
# snmp-server traps l2tun sessions
# snmp-server traps l2tun tunnel-up
# snmp-server traps l2tun tunnel-down
# snmp-server traps bulkstat collection
# snmp-server traps l2vpn all
# snmp-server traps l2vpn vc-up
# snmp-server traps l2vpn vc-down
# snmp-server traps bridgemib
# snmp-server traps addrpool low
# snmp-server traps addrpool high
# snmp-server traps cisco-entity-ext
# snmp-server chassis-id test2
# snmp-server contact t1
# snmp-server location test1
# snmp-server target list test host 1.1.1.2
# snmp-server target list test2 vrf vrf2
# snmp-server context c1
# snmp-server context c2
# snmp-server logging threshold oid-processing 1
# snmp-server logging threshold pdu-processing 1
# snmp-server mib bulkstat max-procmem-size 101
# snmp-server timeouts duplicate 0
# snmp-server timeouts inQdrop 0
# snmp-server packetsize 490
# snmp-server correlator buffer-size 1024
# snmp-server trap-source GigabitEthernet0/0/0/2
# snmp-server throttle-time 60
# snmp-server community-map cm1 context c1 security-name s1 target-list t1
# snmp-server inform retries 7
# snmp-server overload-control 4 6
# snmp-server ifmib internal cache max-duration 4
# snmp-server mroutemib send-all-vrf
# snmp-server notification-log-mib size 5
# snmp-server notification-log-mib GlobalSize 5
# Deleted play:
# -------------
- name: Remove all existing configuration
  cisco.iosxr.iosxr_snmp_server:
    state: deleted
# Commands Fired:
# ---------------
# "commands": [
#        "no snmp-server chassis-id test2",
#         "no snmp-server correlator buffer-size 1024",
#         "no snmp-server contact t1",
#         "no snmp-server ipv4 dscp af11",
#         "no snmp-server ipv6 precedence routine",
#         "no snmp-server location test1",
#         "no snmp-server logging threshold oid-processing 1",
#         "no snmp-server logging threshold pdu-processing 1",
#         "no snmp-server mib bulkstat max-procmem-size 101",
#         "no snmp-server mroutemib send-all-vrf",
#         "no snmp-server overload-control 4 6",
#         "no snmp-server packetsize 490",
#         "no snmp-server queue-length 2",
#         "no snmp-server throttle-time 60",
#         "no snmp-server trap-source GigabitEthernet0/0/0/2",
#         "no snmp-server trap-timeout 3",
#         "no snmp-server drop report acl IPv4 test1",
#         "no snmp-server drop unknown-user",
#         "no snmp-server ifmib internal cache max-duration 4",
#         "no snmp-server inform retries 7",
#         "no snmp-server notification-log-mib size 5",
#         "no snmp-server notification-log-mib GlobalSize 5",
#         "no snmp-server trap throttle-time 12",
#         "no snmp-server timeouts inQdrop 0",
#         "no snmp-server timeouts duplicate 0",
#         "no snmp-server traps addrpool low",
#         "no snmp-server traps addrpool high",
#         "no snmp-server traps bfd",
#         "no snmp-server traps bgp cbgp2",
#         "no snmp-server traps bulkstat collection",
#         "no snmp-server traps bridgemib",
#         "no snmp-server traps copy-complete",
#         "no snmp-server traps cisco-entity-ext",
#         "no snmp-server traps config",
#         "no snmp-server traps hsrp",
#         "no snmp-server traps ipsla",
#         "no snmp-server traps ipsec tunnel start",
#         "no snmp-server traps ipsec tunnel stop",
#         "no snmp-server traps l2tun sessions",
#         "no snmp-server traps l2tun tunnel-up",
#         "no snmp-server traps l2tun tunnel-down",
#         "no snmp-server traps l2vpn all",
#         "no snmp-server traps l2vpn vc-up",
#         "no snmp-server traps l2vpn vc-down",
#         "no snmp-server traps msdp peer-state-change",
#         "no snmp-server community test2 RO SDROwner IPv4 test IPv6 test1",
#         "no snmp-server community-map cm1 context c1 security-name s1 target-list t1",
#         "no snmp-server context c1",
#         "no snmp-server context c2",
#         "no snmp-server user u1 test2 v1 IPv4 test1 IPv6 test2",
#         "no snmp-server target list test host 1.1.1.2",
#         "no snmp-server target list test2 vrf vrf2",
#         "no snmp-server vrf vrf1"
#     ],
# After state:
# ------------
# RP/0/0/CPU0:10#show running-config ntp
# --------------------- EMPTY -----------------
# Using state: overridden
# Before state:
# -------------
# RP/0/0/CPU0:10#show running-config snmp-server
# snmp-server vrf vrf1
#  host 1.1.1.1 traps test1
# !
# snmp-server drop report acl IPv4 test1
# snmp-server drop unknown-user
# snmp-server ipv4 dscp af11
# snmp-server ipv6 precedence routine
# snmp-server user u1 test2 v1 IPv4 test1 IPv6 test2
# snmp-server community test2 RO SDROwner IPv4 test IPv6 test1
# snmp-server queue-length 2
# snmp-server trap-timeout 3
# snmp-server trap throttle-time 12
# snmp-server traps bfd
# snmp-server traps bgp cbgp2
# snmp-server traps copy-complete
# snmp-server traps hsrp
# snmp-server traps ipsla
# snmp-server traps msdp peer-state-change
# snmp-server traps ipsec tunnel stop
# snmp-server traps ipsec tunnel start
# snmp-server traps config
# snmp-server traps l2tun sessions
# snmp-server traps l2tun tunnel-up
# snmp-server traps l2tun tunnel-down
# snmp-server traps bulkstat collection
# snmp-server traps l2vpn all
# snmp-server traps l2vpn vc-up
# snmp-server traps l2vpn vc-down
# snmp-server traps bridgemib
# snmp-server traps addrpool low
# snmp-server traps addrpool high
# snmp-server traps cisco-entity-ext
# snmp-server chassis-id test2
# snmp-server contact t1
# snmp-server location test1
# snmp-server target list test host 1.1.1.2
# snmp-server target list test2 vrf vrf2
# snmp-server context c1
# snmp-server context c2
# snmp-server logging threshold oid-processing 1
# snmp-server logging threshold pdu-processing 1
# snmp-server mib bulkstat max-procmem-size 101
# snmp-server timeouts duplicate 0
# snmp-server timeouts inQdrop 0
# snmp-server packetsize 490
# snmp-server correlator buffer-size 1024
# snmp-server trap-source GigabitEthernet0/0/0/2
# snmp-server throttle-time 60
# snmp-server community-map cm1 context c1 security-name s1 target-list t1
# snmp-server inform retries 7
# snmp-server overload-control 4 6
# snmp-server ifmib internal cache max-duration 4
# snmp-server mroutemib send-all-vrf
# snmp-server notification-log-mib size 5
# snmp-server notification-log-mib GlobalSize 5
# Overridden play:
# ----------------
- name: Override Snmp-server configuration with provided configuration
  cisco.iosxr.iosxr_snmp_server:
    config:
      timeouts:
        duplicate: 0
        inQdrop: 0
      trap:
        throttle_time: 13
      targets:
        - host: 1.1.1.2
          name: test
      ifmib:
        internal_cache_max_duration: 5
      inform:
        retries: 7
      chassis_id: test
      packetsize: 491
      queue_length: 2
      throttle_time: 60
      trap_source: GigabitEthernet0/0/0/2
      trap_timeout: 3
      context:
        - c1
        - c2
      contact: t1
      correlator:
        buffer_size: 1025
      communities:
        - name: test1
          ro: true
          sdrowner: true
          acl_v4: test
          acl_v6: test1
      community_maps:
        - name: cm2
          context: c1
          target_list: t1
          security_name: s1
      drop:
        report_IPv4: test2
        unknown_user: true
      ipv6:
        precedence: routine
      ipv4:
        dscp: af11
      location: test1
      logging_threshold_oid_processing: 2
      logging_threshold_pdu_processing: 2
      mib_bulkstat_max_procmem_size: 101
      mroutemib_send_all_vrf: true
      overload_control:
        overload_drop_time: 4
        overload_throttle_rate: 6
      notification_log_mib:
        GlobalSize: 5
        size: 5
      traps:
        hsrp: true
        ipsla: true
        ipsec:
          start: true
          stop: true
        bridgemib: true
        bulkstat_collection: true
        cisco_entity_ext: true
        config: true
        copy_complete: true
        l2vpn:
          all: true
          vc_down: true
          vc_up: true
        msdp_peer_state_change: true
    state: overridden

# Commands Fired:
# ---------------
# "commands": [
#        "no snmp-server traps addrpool low",
#         "no snmp-server traps addrpool high",
#         "no snmp-server traps bfd",
#         "no snmp-server traps bgp cbgp2",
#         "no snmp-server traps l2tun sessions",
#         "no snmp-server traps l2tun tunnel-up",
#         "no snmp-server traps l2tun tunnel-down",
#         "no snmp-server community test2 RO SDROwner IPv4 test IPv6 test1",
#         "no snmp-server community-map cm1 context c1 security-name s1 target-list t1",
#         "no snmp-server user u1 test2 v1 IPv4 test1 IPv6 test2",
#         "no snmp-server vrf vrf1",
#         "snmp-server chassis-id test",
#         "snmp-server correlator buffer-size 1025",
#         "snmp-server logging threshold oid-processing 2",
#         "snmp-server logging threshold pdu-processing 2",
#         "snmp-server packetsize 491",
#         "snmp-server drop report acl IPv4 test2",
#         "snmp-server ifmib internal cache max-duration 5",
#         "snmp-server trap throttle-time 13",
#         "snmp-server community test1 RO SDROwner IPv4 test IPv6 test1",
#         "snmp-server community-map cm2 context c1 security-name s1 target-list t1"
#     ],
# After state:
# ------------
# RP/0/RP0/CPU0:test2#show running-config snmp-server
# Mon Nov 29 12:57:34.182 UTC
# snmp-server drop report acl IPv4 test2
# snmp-server drop unknown-user
# snmp-server ipv4 dscp af11
# snmp-server ipv6 precedence routine
# snmp-server community test1 RO SDROwner IPv4 test IPv6 test1
# snmp-server queue-length 2
# snmp-server trap-timeout 3
# snmp-server trap throttle-time 13
# snmp-server traps copy-complete
# snmp-server traps hsrp
# snmp-server traps ipsla
# snmp-server traps msdp peer-state-change
# snmp-server traps ipsec tunnel stop
# snmp-server traps ipsec tunnel start
# snmp-server traps config
# snmp-server traps bulkstat collection
# snmp-server traps l2vpn all
# snmp-server traps l2vpn vc-up
# snmp-server traps l2vpn vc-down
# snmp-server traps bridgemib
# snmp-server traps cisco-entity-ext
# snmp-server chassis-id test
# snmp-server contact t1
# snmp-server location test1
# snmp-server target list test host 1.1.1.2
# snmp-server target list test2 vrf vrf2
# snmp-server context c1
# snmp-server context c2
# snmp-server logging threshold oid-processing 2
# snmp-server logging threshold pdu-processing 2
# snmp-server mib bulkstat max-procmem-size 101
# snmp-server timeouts duplicate 0
# snmp-server timeouts inQdrop 0
# snmp-server packetsize 491
# snmp-server correlator buffer-size 1025
# snmp-server trap-source GigabitEthernet0/0/0/2
# snmp-server throttle-time 60
# snmp-server community-map cm2 context c1 security-name s1 target-list t1
# snmp-server inform retries 7
# snmp-server overload-control 4 6
# snmp-server ifmib internal cache max-duration 5
# snmp-server mroutemib send-all-vrf
# snmp-server notification-log-mib size 5
# snmp-server notification-log-mib GlobalSize 5
#
# Using state: replaced
# Before state:
# -------------
# RP/0/0/CPU0:10#show running-config snmp-server
# snmp-server vrf vrf1
#  host 1.1.1.1 traps test1
# !
# snmp-server drop report acl IPv4 test1
# snmp-server drop unknown-user
# snmp-server ipv4 dscp af11
# snmp-server ipv6 precedence routine
# snmp-server user u1 test2 v1 IPv4 test1 IPv6 test2
# snmp-server community test2 RO SDROwner IPv4 test IPv6 test1
# snmp-server queue-length 2
# snmp-server trap-timeout 3
# snmp-server trap throttle-time 12
# snmp-server traps bfd
# snmp-server traps bgp cbgp2
# snmp-server traps copy-complete
# snmp-server traps hsrp
# snmp-server traps ipsla
# snmp-server traps msdp peer-state-change
# snmp-server traps ipsec tunnel stop
# snmp-server traps ipsec tunnel start
# snmp-server traps config
# snmp-server traps l2tun sessions
# snmp-server traps l2tun tunnel-up
# snmp-server traps l2tun tunnel-down
# snmp-server traps bulkstat collection
# snmp-server traps l2vpn all
# snmp-server traps l2vpn vc-up
# snmp-server traps l2vpn vc-down
# snmp-server traps bridgemib
# snmp-server traps addrpool low
# snmp-server traps addrpool high
# snmp-server traps cisco-entity-ext
# snmp-server chassis-id test2
# snmp-server contact t1
# snmp-server location test1
# snmp-server target list test host 1.1.1.2
# snmp-server target list test2 vrf vrf2
# snmp-server context c1
# snmp-server context c2
# snmp-server logging threshold oid-processing 1
# snmp-server logging threshold pdu-processing 1
# snmp-server mib bulkstat max-procmem-size 101
# snmp-server timeouts duplicate 0
# snmp-server timeouts inQdrop 0
# snmp-server packetsize 490
# snmp-server correlator buffer-size 1024
# snmp-server trap-source GigabitEthernet0/0/0/2
# snmp-server throttle-time 60
# snmp-server community-map cm1 context c1 security-name s1 target-list t1
# snmp-server inform retries 7
# snmp-server overload-control 4 6
# snmp-server ifmib internal cache max-duration 4
# snmp-server mroutemib send-all-vrf
# snmp-server notification-log-mib size 5
# snmp-server notification-log-mib GlobalSize 5
#
#
# Replaced play:
# ----------------
- name: Replace Snmp-server configuration with provided configuration
  cisco.iosxr.iosxr_snmp_server:
    state: replaced
    config:
      timeouts:
        duplicate: 0
        inQdrop: 0
      trap:
        throttle_time: 13
      targets:
        - host: 1.1.1.2
          name: test
      ifmib:
        internal_cache_max_duration: 5
      inform:
        retries: 7
      chassis_id: test
      packetsize: 491
      queue_length: 2
      throttle_time: 60
      trap_source: GigabitEthernet0/0/0/2
      trap_timeout: 3
      context:
        - c1
        - c2
      contact: t1
      correlator:
        buffer_size: 1025
      communities:
        - name: test1
          ro: true
          sdrowner: true
          acl_v4: test
          acl_v6: test1
      community_maps:
        - name: cm2
          context: c1
          target_list: t1
          security_name: s1
      drop:
        report_IPv4: test2
        unknown_user: true
      ipv6:
        precedence: routine
      ipv4:
        dscp: af11
      location: test1
      logging_threshold_oid_processing: 2
      logging_threshold_pdu_processing: 2
      mib_bulkstat_max_procmem_size: 101
      mroutemib_send_all_vrf: true
      overload_control:
        overload_drop_time: 4
        overload_throttle_rate: 6
      notification_log_mib:
        GlobalSize: 5
        size: 5
      traps:
        hsrp: true
        ipsla: true
        ipsec:
          start: true
          stop: true
        bridgemib: true
        bulkstat_collection: true
        cisco_entity_ext: true
        config: true
        copy_complete: true
        l2vpn:
          all: true
          vc_down: true
          vc_up: true
        msdp_peer_state_change: true

#
# Commands Fired:
# ---------------
# "commands": [
#         "no snmp-server traps addrpool low",
#         "no snmp-server traps addrpool high",
#         "no snmp-server traps bfd",
#         "no snmp-server traps bgp cbgp2",
#         "no snmp-server traps l2tun sessions",
#         "no snmp-server traps l2tun tunnel-up",
#         "no snmp-server traps l2tun tunnel-down",
#         "no snmp-server community test2 RO SDROwner IPv4 test IPv6 test1",
#         "no snmp-server community-map cm1 context c1 security-name s1 target-list t1",
#         "no snmp-server user u1 test2 v1 IPv4 test1 IPv6 test2",
#         "no snmp-server vrf vrf1",
#         "snmp-server chassis-id test",
#         "snmp-server correlator buffer-size 1025",
#         "snmp-server logging threshold oid-processing 2",
#         "snmp-server logging threshold pdu-processing 2",
#         "snmp-server packetsize 491",
#         "snmp-server drop report acl IPv4 test2",
#         "snmp-server ifmib internal cache max-duration 5",
#         "snmp-server trap throttle-time 13",
#         "snmp-server community test1 RO SDROwner IPv4 test IPv6 test1",
#         "snmp-server community-map cm2 context c1 security-name s1 target-list t1"
#     ],
# After state:
# ------------
# RP/0/RP0/CPU0:ios#show running-config snmp-server
# Mon Sep 13 10:38:22.690 UTC
# RP/0/0/CPU0:10#show running-config snmp-server
# snmp-server vrf vrf1
#  host 1.1.1.1 traps test1
# !
# snmp-server drop report acl IPv4 test1
# snmp-server drop unknown-user
# snmp-server ipv4 dscp af11
# snmp-server ipv6 precedence routine
# snmp-server user u1 test2 v1 IPv4 test1 IPv6 test2
# snmp-server community test2 RO SDROwner IPv4 test IPv6 test1
# snmp-server queue-length 2
# snmp-server trap-timeout 3
# snmp-server trap throttle-time 12
# snmp-server traps bfd
# snmp-server traps bgp cbgp2
# snmp-server traps copy-complete
# snmp-server traps hsrp
# snmp-server traps ipsla
# snmp-server traps msdp peer-state-change
# snmp-server traps ipsec tunnel stop
# snmp-server traps ipsec tunnel start
# snmp-server traps config
# snmp-server traps l2tun sessions
# snmp-server traps l2tun tunnel-up
# snmp-server traps l2tun tunnel-down
# snmp-server traps bulkstat collection
# snmp-server traps l2vpn all
# snmp-server traps l2vpn vc-up
# snmp-server traps l2vpn vc-down
# snmp-server traps bridgemib
# snmp-server traps addrpool low
# snmp-server traps addrpool high
# snmp-server traps cisco-entity-ext
# snmp-server chassis-id test2
# snmp-server contact t1
# snmp-server location test1
# snmp-server target list test host 1.1.1.2
# snmp-server target list test2 vrf vrf2
# snmp-server context c1
# snmp-server context c2
# snmp-server logging threshold oid-processing 1
# snmp-server logging threshold pdu-processing 1
# snmp-server mib bulkstat max-procmem-size 101
# snmp-server timeouts duplicate 0
# snmp-server timeouts inQdrop 0
# snmp-server packetsize 490
# snmp-server correlator buffer-size 1024
# snmp-server trap-source GigabitEthernet0/0/0/2
# snmp-server throttle-time 60
# snmp-server community-map cm1 context c1 security-name s1 target-list t1
# snmp-server inform retries 7
# snmp-server overload-control 4 6
# snmp-server ifmib internal cache max-duration 4
# snmp-server mroutemib send-all-vrf
# snmp-server notification-log-mib size 5
# snmp-server notification-log-mib GlobalSize 5
#
#
# Using state: gathered
# Before state:
# -------------
# RP/0/RP0/CPU0:test2#show running-config snmp-server
# Mon Nov 29 12:49:29.521 UTC
# snmp-server vrf vrf1
#  host 1.1.1.1 traps test1
# !
# snmp-server drop report acl IPv4 test1
# snmp-server drop unknown-user
# snmp-server ipv4 dscp af11
# snmp-server ipv6 precedence routine
# snmp-server user u1 test2 v1 IPv4 test1 IPv6 test2
# snmp-server community test2 RO SDROwner IPv4 test IPv6 test1
# snmp-server queue-length 2
# snmp-server trap-timeout 3
# snmp-server trap throttle-time 12
# snmp-server traps bfd
# snmp-server traps bgp cbgp2
# snmp-server traps copy-complete
# snmp-server traps hsrp
# snmp-server traps ipsla
# snmp-server traps msdp peer-state-change
# snmp-server traps ipsec tunnel stop
# snmp-server traps ipsec tunnel start
# snmp-server traps config
# snmp-server traps l2tun sessions
# snmp-server traps l2tun tunnel-up
# snmp-server traps l2tun tunnel-down
# snmp-server traps bulkstat collection
# snmp-server traps l2vpn all
# snmp-server traps l2vpn vc-up
# snmp-server traps l2vpn vc-down
# snmp-server traps bridgemib
# snmp-server traps addrpool low
# snmp-server traps addrpool high
# snmp-server traps cisco-entity-ext
# snmp-server chassis-id test2
# snmp-server contact t1
# snmp-server location test1
# snmp-server target list test host 1.1.1.2
# snmp-server target list test2 vrf vrf2
# snmp-server context c1
# snmp-server context c2
# snmp-server logging threshold oid-processing 1
# snmp-server logging threshold pdu-processing 1
# snmp-server mib bulkstat max-procmem-size 101
# snmp-server timeouts duplicate 0
# snmp-server timeouts inQdrop 0
# snmp-server packetsize 490
# snmp-server correlator buffer-size 1024
# snmp-server trap-source GigabitEthernet0/0/0/2
# snmp-server throttle-time 60
# snmp-server community-map cm1 context c1 security-name s1 target-list t1
# snmp-server inform retries 7
# snmp-server overload-control 4 6
# snmp-server ifmib internal cache max-duration 4
# snmp-server mroutemib send-all-vrf
# snmp-server notification-log-mib size 5
# snmp-server notification-log-mib GlobalSize 5
# Gathered play:
# --------------
- name: Gather listed snmp server
  cisco.iosxr.iosxr_snmp_server:
    state: gathered
# Module Execution Result:
# ------------------------
# "gathered": {
#         "chassis_id": "test2",
#         "communities": [
#             {
#                 "acl_v4": "test",
#                 "acl_v6": "test1",
#                 "name": "test2",
#                 "ro": true,
#                 "sdrowner": true
#             }
#         ],
#         "community_maps": [
#             {
#                 "context": "c1",
#                 "name": "cm1",
#                 "security_name": "s1",
#                 "target_list": "t1"
#             }
#         ],
#         "contact": "t1",
#         "context": [
#             "c1",
#             "c2"
#         ],
#         "correlator": {
#             "buffer_size": 1024
#         },
#         "drop": {
#             "report_IPv4": "test1",
#             "unknown_user": true
#         },
#         "ifmib": {
#             "internal_cache_max_duration": 4
#         },
#         "inform": {
#             "retries": 7
#         },
#         "ipv4": {
#             "dscp": "af11"
#         },
#         "ipv6": {
#             "precedence": "routine"
#         },
#         "location": "test1",
#         "logging_threshold_oid_processing": 1,
#         "logging_threshold_pdu_processing": 1,
#         "mib_bulkstat_max_procmem_size": 101,
#         "mroutemib_send_all_vrf": true,
#         "notification_log_mib": {
#             "GlobalSize": 5,
#             "size": 5
#         },
#         "overload_control": {
#             "overload_drop_time": 4,
#             "overload_throttle_rate": 6
#         },
#         "packetsize": 490,
#         "queue_length": 2,
#         "targets": [
#             {
#                 "host": "1.1.1.2",
#                 "name": "test"
#             },
#             {
#                 "name": "test2",
#                 "vrf": "vrf2"
#             }
#         ],
#         "throttle_time": 60,
#         "timeouts": {
#             "duplicate": 0,
#             "inQdrop": 0
#         },
#         "trap": {
#             "throttle_time": 12
#         },
#         "trap_source": "GigabitEthernet0/0/0/2",
#         "trap_timeout": 3,
#         "traps": {
#             "addrpool": {
#                 "high": true,
#                 "low": true
#             },
#             "bfd": true,
#             "bgp": {
#                 "cbgp2": true
#             },
#             "bridgemib": true,
#             "bulkstat_collection": true,
#             "cisco_entity_ext": true,
#             "config": true,
#             "copy_complete": true,
#             "hsrp": true,
#             "ipsec": {
#                 "start": true,
#                 "stop": true
#             },
#             "ipsla": true,
#             "l2tun": {
#                 "sessions": true,
#                 "tunnel_down": true,
#                 "tunnel_up": true
#             },
#             "l2vpn": {
#                 "all": true,
#                 "vc_down": true,
#                 "vc_up": true
#             },
#             "msdp_peer_state_change": true
#         },
#         "users": [
#             {
#                 "Ipv4_acl": "test1",
#                 "Ipv6_acl": "test2",
#                 "group": "test2",
#                 "user": "u1",
#                 "version": "v1"
#             }
#         ],
#         "vrfs": [
#             {
#                 "hosts": [
#                     {
#                         "community": "test1",
#                         "host": "1.1.1.1",
#                         "traps": true
#                     }
#                 ],
#                 "vrf": "vrf1"
#             }
#         ]
#     }
#
#
# Using state: rendered
# Rendered play:
# --------------
- name: >-
    Render platform specific configuration lines with state rendered (without
    connecting to the device)
  cisco.iosxr.iosxr_snmp_server:
    state: rendered
    config:
      vrfs:
        - hosts:
            - community: test1
              host: 1.1.1.1
              traps: true
          vrf: vrf1
      users:
        - Ipv4_acl: test1
          Ipv6_acl: test2
          group: test2
          user: u1
          version: v1
      timeouts:
        duplicate: 0
        inQdrop: 0
      trap:
        throttle_time: 12
      targets:
        - host: 1.1.1.2
          name: test
      ifmib:
        internal_cache_max_duration: 4
      inform:
        retries: 7
      chassis_id: test2
      packetsize: 490
      queue_length: 2
      throttle_time: 60
      trap_source: GigabitEthernet0/0/0/2
      trap_timeout: 3
      context:
        - c1
        - c2
      contact: t1
      correlator:
        buffer_size: 1024
      communities:
        - name: test2
          ro: true
          sdrowner: true
          acl_v4: test
          acl_v6: test1
      community_maps:
        - name: cm1
          context: c1
          target_list: t1
          security_name: s1
      drop:
        report_IPv4: test1
        unknown_user: true
      ipv6:
        precedence: routine
      ipv4:
        dscp: af11
      location: test1
      logging_threshold_oid_processing: 1
      logging_threshold_pdu_processing: 1
      mib_bulkstat_max_procmem_size: 101
      mroutemib_send_all_vrf: true
      overload_control:
        overload_drop_time: 4
        overload_throttle_rate: 6
      notification_log_mib:
        GlobalSize: 5
        size: 5
      traps:
        hsrp: true
        ipsla: true
        ipsec:
          start: true
          stop: true
        bridgemib: true
        bulkstat_collection: true
        cisco_entity_ext: true
        config: true
        copy_complete: true
        addrpool:
          high: true
          low: true
        bfd: true
        bgp:
          cbgp2: true
        l2tun:
          sessions: true
          tunnel_down: true
          tunnel_up: true
        l2vpn:
          all: true
          vc_down: true
          vc_up: true
        msdp_peer_state_change: true
  register: result

# Module Execution Result:
# ------------------------
# "rendered": [
#         "snmp-server chassis-id test2",
#         "snmp-server correlator buffer-size 1024",
#         "snmp-server contact t1",
#         "snmp-server ipv4 dscp af11",
#         "snmp-server ipv6 precedence routine",
#         "snmp-server location test1",
#         "snmp-server logging threshold oid-processing 1",
#         "snmp-server logging threshold pdu-processing 1",
#         "snmp-server mib bulkstat max-procmem-size 101",
#         "snmp-server mroutemib send-all-vrf",
#         "snmp-server overload-control 4 6",
#         "snmp-server packetsize 490",
#         "snmp-server queue-length 2",
#         "snmp-server throttle-time 60",
#         "snmp-server trap-source GigabitEthernet0/0/0/2",
#         "snmp-server trap-timeout 3",
#         "snmp-server drop report acl IPv4 test1",
#         "snmp-server drop unknown-user",
#         "snmp-server ifmib internal cache max-duration 4",
#         "snmp-server inform retries 7",
#         "snmp-server notification-log-mib size 5",
#         "snmp-server notification-log-mib GlobalSize 5",
#         "snmp-server trap throttle-time 12",
#         "snmp-server timeouts inQdrop 0",
#         "snmp-server timeouts duplicate 0",
#         "snmp-server traps addrpool low",
#         "snmp-server traps addrpool high",
#         "snmp-server traps bfd",
#         "snmp-server traps bgp cbgp2",
#         "snmp-server traps bulkstat collection",
#         "snmp-server traps bridgemib",
#         "snmp-server traps copy-complete",
#         "snmp-server traps cisco-entity-ext",
#         "snmp-server traps config",
#         "snmp-server traps hsrp",
#         "snmp-server traps ipsla",
#         "snmp-server traps ipsec tunnel start",
#         "snmp-server traps ipsec tunnel stop",
#         "snmp-server traps l2tun sessions",
#         "snmp-server traps l2tun tunnel-up",
#         "snmp-server traps l2tun tunnel-down",
#         "snmp-server traps l2vpn all",
#         "snmp-server traps l2vpn vc-up",
#         "snmp-server traps l2vpn vc-down",
#         "snmp-server traps msdp peer-state-change",
#         "snmp-server community test2 RO SDROwner IPv4 test IPv6 test1",
#         "snmp-server community-map cm1 context c1 security-name s1 target-list t1",
#         "snmp-server context c1",
#         "snmp-server context c2",
#         "snmp-server user u1 test2 v1 IPv4 test1 IPv6 test2",
#         "snmp-server target list test2 vrf vrf2",
#         "snmp-server target list test host 1.1.1.2",
#         "snmp-server vrf vrf1",
#         "host 1.1.1.1 traps test1"
#     ],
# Using state: parsed
# File: parsed.cfg
# ----------------
# snmp-server vrf vrf1
#  host 1.1.1.1 traps test1
# !
# snmp-server drop report acl IPv4 test1
# snmp-server drop unknown-user
# snmp-server ipv4 dscp af11
# snmp-server ipv6 precedence routine
# snmp-server user u1 test2 v1 IPv4 test1 IPv6 test2
# snmp-server community test2 RO SDROwner IPv4 test IPv6 test1
# snmp-server queue-length 2
# snmp-server trap-timeout 3
# snmp-server trap throttle-time 12
# snmp-server traps bfd
# snmp-server traps bgp cbgp2
# snmp-server traps copy-complete
# snmp-server traps hsrp
# snmp-server traps ipsla
# snmp-server traps msdp peer-state-change
# snmp-server traps ipsec tunnel stop
# snmp-server traps ipsec tunnel start
# snmp-server traps config
# snmp-server traps l2tun sessions
# snmp-server traps l2tun tunnel-up
# snmp-server traps l2tun tunnel-down
# snmp-server traps bulkstat collection
# snmp-server traps l2vpn all
# snmp-server traps l2vpn vc-up
# snmp-server traps l2vpn vc-down
# snmp-server traps bridgemib
# snmp-server traps addrpool low
# snmp-server traps addrpool high
# snmp-server traps cisco-entity-ext
# snmp-server chassis-id test2
# snmp-server contact t1
# snmp-server location test1
# snmp-server target list test host 1.1.1.2
# snmp-server target list test2 vrf vrf2
# snmp-server context c1
# snmp-server context c2
# snmp-server logging threshold oid-processing 1
# snmp-server logging threshold pdu-processing 1
# snmp-server mib bulkstat max-procmem-size 101
# snmp-server timeouts duplicate 0
# snmp-server timeouts inQdrop 0
# snmp-server packetsize 490
# snmp-server correlator buffer-size 1024
# snmp-server trap-source GigabitEthernet0/0/0/2
# snmp-server throttle-time 60
# snmp-server community-map cm1 context c1 security-name s1 target-list t1
# snmp-server inform retries 7
# snmp-server overload-control 4 6
# snmp-server ifmib internal cache max-duration 4
# snmp-server mroutemib send-all-vrf
# snmp-server notification-log-mib size 5
# snmp-server notification-log-mib GlobalSize 5
# ------------
- name: Parse the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_snmp_server:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed
# Module Execution Result:
# ------------------------
# "parsed":{
#         "chassis_id": "test2",
#         "communities": [
#             {
#                 "acl_v4": "test",
#                 "acl_v6": "test1",
#                 "name": "test2",
#                 "ro": true,
#                 "sdrowner": true
#             }
#         ],
#         "community_maps": [
#             {
#                 "context": "c1",
#                 "name": "cm1",
#                 "security_name": "s1",
#                 "target_list": "t1"
#             }
#         ],
#         "contact": "t1",
#         "context": [
#             "c1",
#             "c2"
#         ],
#         "correlator": {
#             "buffer_size": 1024
#         },
#         "drop": {
#             "report_IPv4": "test1",
#             "unknown_user": true
#         },
#         "ifmib": {
#             "internal_cache_max_duration": 4
#         },
#         "inform": {
#             "retries": 7
#         },
#         "ipv4": {
#             "dscp": "af11"
#         },
#         "ipv6": {
#             "precedence": "routine"
#         },
#         "location": "test1",
#         "logging_threshold_oid_processing": 1,
#         "logging_threshold_pdu_processing": 1,
#         "mib_bulkstat_max_procmem_size": 101,
#         "mroutemib_send_all_vrf": true,
#         "notification_log_mib": {
#             "GlobalSize": 5,
#             "size": 5
#         },
#         "overload_control": {
#             "overload_drop_time": 4,
#             "overload_throttle_rate": 6
#         },
#         "packetsize": 490,
#         "queue_length": 2,
#         "targets": [
#             {
#                 "host": "1.1.1.2",
#                 "name": "test"
#             },
#             {
#                 "name": "test2",
#                 "vrf": "vrf2"
#             }
#         ],
#         "throttle_time": 60,
#         "timeouts": {
#             "duplicate": 0,
#             "inQdrop": 0
#         },
#         "trap": {
#             "throttle_time": 12
#         },
#         "trap_source": "GigabitEthernet0/0/0/2",
#         "trap_timeout": 3,
#         "traps": {
#             "addrpool": {
#                 "high": true,
#                 "low": true
#             },
#             "bfd": true,
#             "bgp": {
#                 "cbgp2": true
#             },
#             "bridgemib": true,
#             "bulkstat_collection": true,
#             "cisco_entity_ext": true,
#             "config": true,
#             "copy_complete": true,
#             "hsrp": true,
#             "ipsec": {
#                 "start": true,
#                 "stop": true
#             },
#             "ipsla": true,
#             "l2tun": {
#                 "sessions": true,
#                 "tunnel_down": true,
#                 "tunnel_up": true
#             },
#             "l2vpn": {
#                 "all": true,
#                 "vc_down": true,
#                 "vc_up": true
#             },
#             "msdp_peer_state_change": true
#         },
#         "users": [
#             {
#                 "Ipv4_acl": "test1",
#                 "Ipv6_acl": "test2",
#                 "group": "test2",
#                 "user": "u1",
#                 "version": "v1"
#             }
#         ],
#         "vrfs": [
#             {
#                 "hosts": [
#                     {
#                         "community": "test1",
#                         "host": "1.1.1.1",
#                         "traps": true
#                     }
#                 ],
#                 "vrf": "vrf1"
#             }
#         ]
#     }
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

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.snmp_server.snmp_server import (
    Snmp_serverArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.snmp_server.snmp_server import (
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
