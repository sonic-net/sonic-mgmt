#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_system_ha
short_description: Configure HA in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and ha category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

    - The module supports check_mode.

requirements:
    - ansible>=2.15
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    system_ha:
        description:
            - Configure HA.
        default: null
        type: dict
        suboptions:
            arps:
                description:
                    - Number of gratuitous ARPs (1 - 60). Lower to reduce traffic. Higher to reduce failover time.
                type: int
            arps_interval:
                description:
                    - Time between gratuitous ARPs  (1 - 20 sec). Lower to reduce failover time. Higher to reduce traffic.
                type: int
            authentication:
                description:
                    - Enable/disable heartbeat message authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auto_virtual_mac_interface:
                description:
                    - The physical interface that will be assigned an auto-generated virtual MAC address.
                type: list
                elements: dict
                suboptions:
                    interface_name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
            backup_hbdev:
                description:
                    - Backup heartbeat interfaces. Must be the same for all members.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
            bounce_intf_upon_failover:
                description:
                    - Enable/disable notification of kernel to bring down and up all monitored interfaces. The setting is used during failovers if gratuitous
                       ARPs do not update the network.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            check_secondary_dev_health:
                description:
                    - Enable/disable secondary dev health check for session load-balance in HA A-A mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cpu_threshold:
                description:
                    - Dynamic weighted load balancing CPU usage weight and high and low thresholds.
                type: str
            encryption:
                description:
                    - Enable/disable heartbeat message encryption.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            evpn_ttl:
                description:
                    - HA EVPN FDB TTL on primary box (5 - 3600 sec).
                type: int
            failover_hold_time:
                description:
                    - Time to wait before failover (0 - 300 sec), to avoid flip.
                type: int
            ftp_proxy_threshold:
                description:
                    - Dynamic weighted load balancing weight and high and low number of FTP proxy sessions.
                type: str
            gratuitous_arps:
                description:
                    - Enable/disable gratuitous ARPs. Disable if link-failed-signal enabled.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            group_id:
                description:
                    - HA group ID  (0 - 1023;  or 0 - 7 when there are more than 2 vclusters). Must be the same for all members.
                type: int
            group_name:
                description:
                    - Cluster group name. Must be the same for all members.
                type: str
            ha_direct:
                description:
                    - Enable/disable using ha-mgmt interface for syslog, remote authentication (RADIUS), FortiAnalyzer, FortiSandbox, sFlow, and Netflow.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ha_eth_type:
                description:
                    - HA heartbeat packet Ethertype (4-digit hex).
                type: str
            ha_mgmt_interfaces:
                description:
                    - Reserve interfaces to manage individual cluster units.
                type: list
                elements: dict
                suboptions:
                    dst:
                        description:
                            - Default route destination for reserved HA management interface.
                        type: str
                    dst6:
                        description:
                            - Default IPv6 destination for reserved HA management interface.
                        type: str
                    gateway:
                        description:
                            - Default route gateway for reserved HA management interface.
                        type: str
                    gateway6:
                        description:
                            - Default IPv6 gateway for reserved HA management interface.
                        type: str
                    id:
                        description:
                            - Table ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    interface:
                        description:
                            - Interface to reserve for HA management. Source system.interface.name.
                        type: str
            ha_mgmt_status:
                description:
                    - Enable to reserve interfaces to manage individual cluster units.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ha_uptime_diff_margin:
                description:
                    - Normally you would only reduce this value for failover testing.
                type: int
            hb_interval:
                description:
                    - Time between sending heartbeat packets (1 - 20). Increase to reduce false positives.
                type: int
            hb_interval_in_milliseconds:
                description:
                    - Units of heartbeat interval time between sending heartbeat packets. Default is 100ms.
                type: str
                choices:
                    - '100ms'
                    - '10ms'
            hb_lost_threshold:
                description:
                    - Number of lost heartbeats to signal a failure (1 - 60). Increase to reduce false positives.
                type: int
            hbdev:
                description:
                    - Heartbeat interfaces. Must be the same for all members.
                type: list
                elements: str
            hc_eth_type:
                description:
                    - Transparent mode HA heartbeat packet Ethertype (4-digit hex).
                type: str
            hello_holddown:
                description:
                    - Time to wait before changing from hello to work state (5 - 300 sec).
                type: int
            http_proxy_threshold:
                description:
                    - Dynamic weighted load balancing weight and high and low number of HTTP proxy sessions.
                type: str
            imap_proxy_threshold:
                description:
                    - Dynamic weighted load balancing weight and high and low number of IMAP proxy sessions.
                type: str
            inter_cluster_session_sync:
                description:
                    - Enable/disable synchronization of sessions among HA clusters.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipsec_phase2_proposal:
                description:
                    - IPsec phase2 proposal.
                type: list
                elements: str
                choices:
                    - 'aes128-sha1'
                    - 'aes128-sha256'
                    - 'aes128-sha384'
                    - 'aes128-sha512'
                    - 'aes192-sha1'
                    - 'aes192-sha256'
                    - 'aes192-sha384'
                    - 'aes192-sha512'
                    - 'aes256-sha1'
                    - 'aes256-sha256'
                    - 'aes256-sha384'
                    - 'aes256-sha512'
                    - 'aes128gcm'
                    - 'aes256gcm'
                    - 'chacha20poly1305'
            key:
                description:
                    - Key.
                type: str
            l2ep_eth_type:
                description:
                    - Telnet session HA heartbeat packet Ethertype (4-digit hex).
                type: str
            link_failed_signal:
                description:
                    - Enable to shut down all interfaces for 1 sec after a failover. Use if gratuitous ARPs do not update network.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            load_balance_all:
                description:
                    - Enable to load balance TCP sessions. Disable to load balance proxy sessions only.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            logical_sn:
                description:
                    - Enable/disable usage of the logical serial number.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            memory_based_failover:
                description:
                    - Enable/disable memory based failover.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            memory_compatible_mode:
                description:
                    - Enable/disable memory compatible mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            memory_failover_flip_timeout:
                description:
                    - Time to wait between subsequent memory based failovers in minutes (6 - 2147483647).
                type: int
            memory_failover_monitor_period:
                description:
                    - Duration of high memory usage before memory based failover is triggered in seconds (1 - 300).
                type: int
            memory_failover_sample_rate:
                description:
                    - Rate at which memory usage is sampled in order to measure memory usage in seconds (1 - 60).
                type: int
            memory_failover_threshold:
                description:
                    - Memory usage threshold to trigger memory based failover (0 means using conserve mode threshold in system.global).
                type: int
            memory_threshold:
                description:
                    - Dynamic weighted load balancing memory usage weight and high and low thresholds.
                type: str
            mode:
                description:
                    - HA mode. Must be the same for all members. FGSP requires standalone.
                type: str
                choices:
                    - 'standalone'
                    - 'a-a'
                    - 'a-p'
            monitor:
                description:
                    - Interfaces to check for port monitoring (or link failure). Source system.interface.name.
                type: list
                elements: str
            multicast_ttl:
                description:
                    - HA multicast TTL on primary (5 - 3600 sec).
                type: int
            nntp_proxy_threshold:
                description:
                    - Dynamic weighted load balancing weight and high and low number of NNTP proxy sessions.
                type: str
            override:
                description:
                    - Enable and increase the priority of the unit that should always be primary (master).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            override_wait_time:
                description:
                    - Delay negotiating if override is enabled (0 - 3600 sec). Reduces how often the cluster negotiates.
                type: int
            password:
                description:
                    - Cluster password. Must be the same for all members.
                type: str
            pingserver_failover_threshold:
                description:
                    - Remote IP monitoring failover threshold (0 - 50).
                type: int
            pingserver_flip_timeout:
                description:
                    - Time to wait in minutes before renegotiating after a remote IP monitoring failover.
                type: int
            pingserver_monitor_interface:
                description:
                    - Interfaces to check for remote IP monitoring. Source system.interface.name.
                type: list
                elements: str
            pingserver_secondary_force_reset:
                description:
                    - Enable to force the cluster to negotiate after a remote IP monitoring failover.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pingserver_slave_force_reset:
                description:
                    - Enable to force the cluster to negotiate after a remote IP monitoring failover.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pop3_proxy_threshold:
                description:
                    - Dynamic weighted load balancing weight and high and low number of POP3 proxy sessions.
                type: str
            priority:
                description:
                    - Increase the priority to select the primary unit (0 - 255).
                type: int
            route_hold:
                description:
                    - Time to wait between routing table updates to the cluster (0 - 3600 sec).
                type: int
            route_ttl:
                description:
                    - TTL for primary unit routes (5 - 3600 sec). Increase to maintain active routes during failover.
                type: int
            route_wait:
                description:
                    - Time to wait before sending new routes to the cluster (0 - 3600 sec).
                type: int
            schedule:
                description:
                    - Type of A-A load balancing. Use none if you have external load balancers.
                type: str
                choices:
                    - 'none'
                    - 'leastconnection'
                    - 'round-robin'
                    - 'weight-round-robin'
                    - 'random'
                    - 'ip'
                    - 'ipport'
                    - 'hub'
            secondary_vcluster:
                description:
                    - Configure virtual cluster 2.
                type: dict
                suboptions:
                    monitor:
                        description:
                            - Interfaces to check for port monitoring (or link failure). Source system.interface.name.
                        type: list
                        elements: str
                    override:
                        description:
                            - Enable and increase the priority of the unit that should always be primary.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_wait_time:
                        description:
                            - Delay negotiating if override is enabled (0 - 3600 sec). Reduces how often the cluster negotiates.
                        type: int
                    pingserver_failover_threshold:
                        description:
                            - Remote IP monitoring failover threshold (0 - 50).
                        type: int
                    pingserver_monitor_interface:
                        description:
                            - Interfaces to check for remote IP monitoring. Source system.interface.name.
                        type: list
                        elements: str
                    pingserver_secondary_force_reset:
                        description:
                            - Enable to force the cluster to negotiate after a remote IP monitoring failover.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    pingserver_slave_force_reset:
                        description:
                            - Enable to force the cluster to negotiate after a remote IP monitoring failover.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    priority:
                        description:
                            - Increase the priority to select the primary unit (0 - 255).
                        type: int
                    vcluster_id:
                        description:
                            - Cluster ID.
                        type: int
                    vdom:
                        description:
                            - VDOMs in virtual cluster 2.
                        type: str
            session_pickup:
                description:
                    - Enable/disable session pickup. Enabling it can reduce session down time when fail over happens.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            session_pickup_connectionless:
                description:
                    - Enable/disable UDP and ICMP session sync.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            session_pickup_delay:
                description:
                    - Enable to sync sessions longer than 30 sec. Only longer lived sessions need to be synced.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            session_pickup_expectation:
                description:
                    - Enable/disable session helper expectation session sync for FGSP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            session_pickup_nat:
                description:
                    - Enable/disable NAT session sync for FGSP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            session_sync_dev:
                description:
                    - Offload session-sync process to kernel and sync sessions using connected interface(s) directly. Source system.interface.name.
                type: list
                elements: str
            smtp_proxy_threshold:
                description:
                    - Dynamic weighted load balancing weight and high and low number of SMTP proxy sessions.
                type: str
            ssd_failover:
                description:
                    - Enable/disable automatic HA failover on SSD disk failure.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            standalone_config_sync:
                description:
                    - Enable/disable FGSP configuration synchronization.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            standalone_mgmt_vdom:
                description:
                    - Enable/disable standalone management VDOM.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sync_config:
                description:
                    - Enable/disable configuration synchronization.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sync_packet_balance:
                description:
                    - Enable/disable HA packet distribution to multiple CPUs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            unicast_gateway:
                description:
                    - Default route gateway for unicast interface.
                type: str
            unicast_hb:
                description:
                    - Enable/disable unicast heartbeat.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            unicast_hb_netmask:
                description:
                    - Unicast heartbeat netmask.
                type: str
            unicast_hb_peerip:
                description:
                    - Unicast heartbeat peer IP.
                type: str
            unicast_peers:
                description:
                    - Number of unicast peers.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Table ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    peer_ip:
                        description:
                            - Unicast peer IP.
                        type: str
            unicast_status:
                description:
                    - Enable/disable unicast connection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            uninterruptible_primary_wait:
                description:
                    - Number of minutes the primary HA unit waits before the secondary HA unit is considered upgraded and the system is started before
                       starting its own upgrade (15 - 300).
                type: int
            uninterruptible_upgrade:
                description:
                    - Enable to upgrade a cluster without blocking network traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            upgrade_mode:
                description:
                    - The mode to upgrade a cluster.
                type: str
                choices:
                    - 'simultaneous'
                    - 'uninterruptible'
                    - 'local-only'
                    - 'secondary-only'
            vcluster:
                description:
                    - Virtual cluster table.
                type: list
                elements: dict
                suboptions:
                    monitor:
                        description:
                            - Interfaces to check for port monitoring (or link failure). Source system.interface.name.
                        type: list
                        elements: str
                    override:
                        description:
                            - Enable and increase the priority of the unit that should always be primary (master).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_wait_time:
                        description:
                            - Delay negotiating if override is enabled (0 - 3600 sec). Reduces how often the cluster negotiates.
                        type: int
                    pingserver_failover_threshold:
                        description:
                            - Remote IP monitoring failover threshold (0 - 50).
                        type: int
                    pingserver_flip_timeout:
                        description:
                            - Time to wait in minutes before renegotiating after a remote IP monitoring failover.
                        type: int
                    pingserver_monitor_interface:
                        description:
                            - Interfaces to check for remote IP monitoring. Source system.interface.name.
                        type: list
                        elements: str
                    pingserver_secondary_force_reset:
                        description:
                            - Enable to force the cluster to negotiate after a remote IP monitoring failover.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    pingserver_slave_force_reset:
                        description:
                            - Enable to force the cluster to negotiate after a remote IP monitoring failover.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    priority:
                        description:
                            - Increase the priority to select the primary unit (0 - 255).
                        type: int
                    vcluster_id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    vdom:
                        description:
                            - Virtual domain(s) in the virtual cluster.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Virtual domain name. Source system.vdom.name.
                                required: true
                                type: str
            vcluster_id:
                description:
                    - Cluster ID.
                type: int
            vcluster_status:
                description:
                    - Enable/disable virtual cluster for virtual clustering.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vcluster2:
                description:
                    - Enable/disable virtual cluster 2 for virtual clustering.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vdom:
                description:
                    - VDOMs in virtual cluster 1.
                type: str
            weight:
                description:
                    - Weight-round-robin weight for each cluster unit. Syntax <priority> <weight>.
                type: str
"""

EXAMPLES = """
- name: Configure HA.
  fortinet.fortios.fortios_system_ha:
      vdom: "{{ vdom }}"
      system_ha:
          arps: "5"
          arps_interval: "8"
          authentication: "enable"
          auto_virtual_mac_interface:
              -
                  interface_name: "<your_own_value> (source system.interface.name)"
          backup_hbdev:
              -
                  name: "default_name_9 (source system.interface.name)"
          bounce_intf_upon_failover: "enable"
          check_secondary_dev_health: "enable"
          cpu_threshold: "<your_own_value>"
          encryption: "enable"
          evpn_ttl: "60"
          failover_hold_time: "0"
          ftp_proxy_threshold: "<your_own_value>"
          gratuitous_arps: "enable"
          group_id: "0"
          group_name: "<your_own_value>"
          ha_direct: "enable"
          ha_eth_type: "<your_own_value>"
          ha_mgmt_interfaces:
              -
                  dst: "<your_own_value>"
                  dst6: "<your_own_value>"
                  gateway: "<your_own_value>"
                  gateway6: "<your_own_value>"
                  id: "27"
                  interface: "<your_own_value> (source system.interface.name)"
          ha_mgmt_status: "enable"
          ha_uptime_diff_margin: "300"
          hb_interval: "2"
          hb_interval_in_milliseconds: "100ms"
          hb_lost_threshold: "6"
          hbdev: "<your_own_value>"
          hc_eth_type: "<your_own_value>"
          hello_holddown: "20"
          http_proxy_threshold: "<your_own_value>"
          imap_proxy_threshold: "<your_own_value>"
          inter_cluster_session_sync: "enable"
          ipsec_phase2_proposal: "aes128-sha1"
          key: "<your_own_value>"
          l2ep_eth_type: "<your_own_value>"
          link_failed_signal: "enable"
          load_balance_all: "enable"
          logical_sn: "enable"
          memory_based_failover: "enable"
          memory_compatible_mode: "enable"
          memory_failover_flip_timeout: "6"
          memory_failover_monitor_period: "60"
          memory_failover_sample_rate: "1"
          memory_failover_threshold: "0"
          memory_threshold: "<your_own_value>"
          mode: "standalone"
          monitor: "<your_own_value> (source system.interface.name)"
          multicast_ttl: "600"
          nntp_proxy_threshold: "<your_own_value>"
          override: "enable"
          override_wait_time: "0"
          password: "<your_own_value>"
          pingserver_failover_threshold: "0"
          pingserver_flip_timeout: "60"
          pingserver_monitor_interface: "<your_own_value> (source system.interface.name)"
          pingserver_secondary_force_reset: "enable"
          pingserver_slave_force_reset: "enable"
          pop3_proxy_threshold: "<your_own_value>"
          priority: "128"
          route_hold: "10"
          route_ttl: "10"
          route_wait: "0"
          schedule: "none"
          secondary_vcluster:
              monitor: "<your_own_value> (source system.interface.name)"
              override: "enable"
              override_wait_time: "0"
              pingserver_failover_threshold: "0"
              pingserver_monitor_interface: "<your_own_value> (source system.interface.name)"
              pingserver_secondary_force_reset: "enable"
              pingserver_slave_force_reset: "enable"
              priority: "128"
              vcluster_id: "1"
              vdom: "<your_own_value>"
          session_pickup: "enable"
          session_pickup_connectionless: "enable"
          session_pickup_delay: "enable"
          session_pickup_expectation: "enable"
          session_pickup_nat: "enable"
          session_sync_dev: "<your_own_value> (source system.interface.name)"
          smtp_proxy_threshold: "<your_own_value>"
          ssd_failover: "enable"
          standalone_config_sync: "enable"
          standalone_mgmt_vdom: "enable"
          sync_config: "enable"
          sync_packet_balance: "enable"
          unicast_gateway: "<your_own_value>"
          unicast_hb: "enable"
          unicast_hb_netmask: "<your_own_value>"
          unicast_hb_peerip: "<your_own_value>"
          unicast_peers:
              -
                  id: "99"
                  peer_ip: "<your_own_value>"
          unicast_status: "enable"
          uninterruptible_primary_wait: "30"
          uninterruptible_upgrade: "enable"
          upgrade_mode: "simultaneous"
          vcluster:
              -
                  monitor: "<your_own_value> (source system.interface.name)"
                  override: "enable"
                  override_wait_time: "0"
                  pingserver_failover_threshold: "0"
                  pingserver_flip_timeout: "60"
                  pingserver_monitor_interface: "<your_own_value> (source system.interface.name)"
                  pingserver_secondary_force_reset: "enable"
                  pingserver_slave_force_reset: "enable"
                  priority: "128"
                  vcluster_id: "<you_own_value>"
                  vdom:
                      -
                          name: "default_name_117 (source system.vdom.name)"
          vcluster_id: "0"
          vcluster_status: "enable"
          vcluster2: "enable"
          vdom: "<your_own_value>"
          weight: "<your_own_value>"
"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    find_current_values,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    unify_data_format,
)


def filter_system_ha_data(json):
    option_list = [
        "arps",
        "arps_interval",
        "authentication",
        "auto_virtual_mac_interface",
        "backup_hbdev",
        "bounce_intf_upon_failover",
        "check_secondary_dev_health",
        "cpu_threshold",
        "encryption",
        "evpn_ttl",
        "failover_hold_time",
        "ftp_proxy_threshold",
        "gratuitous_arps",
        "group_id",
        "group_name",
        "ha_direct",
        "ha_eth_type",
        "ha_mgmt_interfaces",
        "ha_mgmt_status",
        "ha_uptime_diff_margin",
        "hb_interval",
        "hb_interval_in_milliseconds",
        "hb_lost_threshold",
        "hbdev",
        "hc_eth_type",
        "hello_holddown",
        "http_proxy_threshold",
        "imap_proxy_threshold",
        "inter_cluster_session_sync",
        "ipsec_phase2_proposal",
        "key",
        "l2ep_eth_type",
        "link_failed_signal",
        "load_balance_all",
        "logical_sn",
        "memory_based_failover",
        "memory_compatible_mode",
        "memory_failover_flip_timeout",
        "memory_failover_monitor_period",
        "memory_failover_sample_rate",
        "memory_failover_threshold",
        "memory_threshold",
        "mode",
        "monitor",
        "multicast_ttl",
        "nntp_proxy_threshold",
        "override",
        "override_wait_time",
        "password",
        "pingserver_failover_threshold",
        "pingserver_flip_timeout",
        "pingserver_monitor_interface",
        "pingserver_secondary_force_reset",
        "pingserver_slave_force_reset",
        "pop3_proxy_threshold",
        "priority",
        "route_hold",
        "route_ttl",
        "route_wait",
        "schedule",
        "secondary_vcluster",
        "session_pickup",
        "session_pickup_connectionless",
        "session_pickup_delay",
        "session_pickup_expectation",
        "session_pickup_nat",
        "session_sync_dev",
        "smtp_proxy_threshold",
        "ssd_failover",
        "standalone_config_sync",
        "standalone_mgmt_vdom",
        "sync_config",
        "sync_packet_balance",
        "unicast_gateway",
        "unicast_hb",
        "unicast_hb_netmask",
        "unicast_hb_peerip",
        "unicast_peers",
        "unicast_status",
        "uninterruptible_primary_wait",
        "uninterruptible_upgrade",
        "upgrade_mode",
        "vcluster",
        "vcluster_id",
        "vcluster_status",
        "vcluster2",
        "vdom",
        "weight",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or (not data[path[index]] and not isinstance(data[path[index]], list))
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
        if len(data[path[index]]) == 0:
            data[path[index]] = None
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["hbdev"],
        ["session_sync_dev"],
        ["monitor"],
        ["pingserver_monitor_interface"],
        ["vcluster", "monitor"],
        ["vcluster", "pingserver_monitor_interface"],
        ["ipsec_phase2_proposal"],
        ["secondary_vcluster", "monitor"],
        ["secondary_vcluster", "pingserver_monitor_interface"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def system_ha(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_ha_data = data["system_ha"]

    filtered_data = filter_system_ha_data(system_ha_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "ha", filtered_data, vdom=vdom)
        current_data = fos.get("system", "ha", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and (
                mkeyname
                and isinstance(current_data.get("results"), list)
                and len(current_data["results"]) > 0
                or not mkeyname
                and current_data["results"]  # global object response
            )
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)
            unified_filtered_data = unify_data_format(copied_filtered_data)

            current_data_results = current_data.get("results", {})
            current_config = (
                current_data_results[0]
                if mkeyname
                and isinstance(current_data_results, list)
                and len(current_data_results) > 0
                else current_data_results
            )
            if is_existed:
                unified_current_values = find_current_values(
                    unified_filtered_data,
                    unify_data_format(current_config),
                )

                is_same = is_same_comparison(
                    serialize(unified_current_values), serialize(unified_filtered_data)
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": unified_current_values, "after": unified_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}
    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["system_ha"] = filtered_data
    fos.do_member_operation(
        "system",
        "ha",
        data_copy,
    )

    return fos.set("system", "ha", data=converted_data, vdom=vdom)


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_system(data, fos, check_mode):

    if data["system_ha"]:
        resp = system_ha(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_ha"))
    if isinstance(resp, tuple) and len(resp) == 4:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "v_range": [["v6.0.0", ""]],
    "type": "dict",
    "children": {
        "group_id": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "group_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "standalone"}, {"value": "a-a"}, {"value": "a-p"}],
        },
        "sync_packet_balance": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "key": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "hbdev": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "auto_virtual_mac_interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "interface_name": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.0", ""]],
        },
        "backup_hbdev": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.0", ""]],
        },
        "session_sync_dev": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "route_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "route_wait": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "route_hold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "multicast_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "evpn_ttl": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "load_balance_all": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sync_config": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "encryption": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "authentication": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "hb_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "hb_interval_in_milliseconds": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "100ms"}, {"value": "10ms"}],
        },
        "hb_lost_threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "hello_holddown": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "gratuitous_arps": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "arps": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "arps_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "session_pickup": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "session_pickup_connectionless": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "session_pickup_expectation": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "session_pickup_nat": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "session_pickup_delay": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "link_failed_signal": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "upgrade_mode": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [
                {"value": "simultaneous"},
                {"value": "uninterruptible"},
                {"value": "local-only"},
                {"value": "secondary-only"},
            ],
        },
        "uninterruptible_primary_wait": {
            "v_range": [["v7.0.2", ""]],
            "type": "integer",
        },
        "standalone_mgmt_vdom": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ha_mgmt_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ha_mgmt_interfaces": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "dst": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "gateway": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "dst6": {"v_range": [["v7.6.3", ""]], "type": "string"},
                "gateway6": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ha_eth_type": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "hc_eth_type": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "l2ep_eth_type": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ha_uptime_diff_margin": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "standalone_config_sync": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "schedule": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "leastconnection"},
                {"value": "round-robin"},
                {"value": "weight-round-robin"},
                {"value": "random"},
                {"value": "ip"},
                {"value": "ipport"},
                {"value": "hub", "v_range": [["v6.0.0", "v7.2.0"]]},
            ],
        },
        "weight": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "cpu_threshold": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "memory_threshold": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "http_proxy_threshold": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ftp_proxy_threshold": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "imap_proxy_threshold": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "nntp_proxy_threshold": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "pop3_proxy_threshold": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "smtp_proxy_threshold": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "override": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "override_wait_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "monitor": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "pingserver_monitor_interface": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "pingserver_failover_threshold": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "pingserver_secondary_force_reset": {
            "v_range": [["v6.4.4", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pingserver_flip_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "vcluster_status": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vcluster": {
            "type": "list",
            "elements": "dict",
            "children": {
                "vcluster_id": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "override": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "priority": {"v_range": [["v7.2.0", ""]], "type": "integer"},
                "override_wait_time": {"v_range": [["v7.2.0", ""]], "type": "integer"},
                "monitor": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "pingserver_monitor_interface": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "pingserver_failover_threshold": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "integer",
                },
                "pingserver_secondary_force_reset": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "pingserver_flip_timeout": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "integer",
                },
                "vdom": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.2.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.0", ""]],
                },
                "pingserver_slave_force_reset": {
                    "v_range": [["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
            "v_range": [["v7.2.0", ""]],
        },
        "ha_direct": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssd_failover": {
            "v_range": [["v6.2.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "enable", "v_range": [["v6.2.0", ""]]},
                {"value": "disable", "v_range": [["v6.2.0", ""]]},
            ],
        },
        "memory_compatible_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "memory_based_failover": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "memory_failover_threshold": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "memory_failover_monitor_period": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
        },
        "memory_failover_sample_rate": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "memory_failover_flip_timeout": {
            "v_range": [["v7.0.0", ""]],
            "type": "integer",
        },
        "failover_hold_time": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "check_secondary_dev_health": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipsec_phase2_proposal": {
            "v_range": [["v7.4.2", ""]],
            "type": "list",
            "options": [
                {"value": "aes128-sha1"},
                {"value": "aes128-sha256"},
                {"value": "aes128-sha384"},
                {"value": "aes128-sha512"},
                {"value": "aes192-sha1"},
                {"value": "aes192-sha256"},
                {"value": "aes192-sha384"},
                {"value": "aes192-sha512"},
                {"value": "aes256-sha1"},
                {"value": "aes256-sha256"},
                {"value": "aes256-sha384"},
                {"value": "aes256-sha512"},
                {"value": "aes128gcm"},
                {"value": "aes256gcm"},
                {"value": "chacha20poly1305"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "bounce_intf_upon_failover": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "unicast_hb": {
            "v_range": [],
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "v_range": [
                        ["v7.0.0", "v7.0.12"],
                        ["v7.2.1", "v7.2.2"],
                        ["v7.4.0", "v7.6.1"],
                    ],
                },
                {
                    "value": "disable",
                    "v_range": [
                        ["v7.0.0", "v7.0.12"],
                        ["v7.2.1", "v7.2.2"],
                        ["v7.4.0", "v7.6.1"],
                    ],
                },
            ],
        },
        "unicast_hb_peerip": {"v_range": [], "type": "string"},
        "unicast_hb_netmask": {"v_range": [], "type": "string"},
        "unicast_status": {
            "v_range": [],
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "v_range": [
                        ["v7.0.0", "v7.0.12"],
                        ["v7.2.1", "v7.2.2"],
                        ["v7.4.0", "v7.6.1"],
                    ],
                },
                {
                    "value": "disable",
                    "v_range": [
                        ["v7.0.0", "v7.0.12"],
                        ["v7.2.1", "v7.2.2"],
                        ["v7.4.0", "v7.6.1"],
                    ],
                },
            ],
        },
        "unicast_gateway": {"v_range": [], "type": "string"},
        "unicast_peers": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [
                        ["v7.0.0", "v7.0.12"],
                        ["v7.2.1", "v7.2.2"],
                        ["v7.4.0", "v7.6.1"],
                    ],
                    "type": "integer",
                    "required": True,
                },
                "peer_ip": {
                    "v_range": [
                        ["v7.0.0", "v7.0.12"],
                        ["v7.2.1", "v7.2.2"],
                        ["v7.4.0", "v7.6.1"],
                    ],
                    "type": "string",
                },
            },
            "v_range": [],
        },
        "logical_sn": {
            "v_range": [["v6.2.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "uninterruptible_upgrade": {
            "v_range": [["v6.0.0", "v7.4.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pingserver_slave_force_reset": {
            "v_range": [["v6.0.0", "v6.4.1"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vdom": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "string"},
        "vcluster2": {
            "v_range": [["v6.0.0", "v7.0.12"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "secondary_vcluster": {
            "v_range": [["v6.0.0", "v7.0.12"]],
            "type": "dict",
            "children": {
                "override": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "priority": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "integer"},
                "override_wait_time": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "integer",
                },
                "monitor": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "pingserver_monitor_interface": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "pingserver_failover_threshold": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "integer",
                },
                "pingserver_secondary_force_reset": {
                    "v_range": [["v6.4.4", "v7.0.12"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "vdom": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "string"},
                "vcluster_id": {"v_range": [["v6.0.0", "v7.0.5"]], "type": "integer"},
                "pingserver_slave_force_reset": {
                    "v_range": [["v6.0.0", "v6.4.1"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "vcluster_id": {"v_range": [["v6.0.0", "v7.0.5"]], "type": "integer"},
        "inter_cluster_session_sync": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
    },
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "system_ha": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_ha"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_ha"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "system_ha"
        )

        is_error, has_changed, result, diff = fortios_system(
            module.params, fos, module.check_mode
        )

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
