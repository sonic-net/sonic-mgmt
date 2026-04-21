#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_switchcontroller_managedswitch
short_description: Configure FortiSwitch devices that are managed by this FortiGate.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    switchcontroller_managedswitch:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _platform:
                type: str
                description: Platform.
            description:
                type: str
                description: Description.
            name:
                type: str
                description: Managed-switch name.
            ports:
                type: list
                elements: dict
                description: Ports.
                suboptions:
                    allowed_vlans:
                        aliases: ['allowed-vlans']
                        type: raw
                        description: (list or str) Configure switch port tagged vlans
                    allowed_vlans_all:
                        aliases: ['allowed-vlans-all']
                        type: str
                        description: Enable/disable all defined vlans on this port.
                        choices:
                            - 'disable'
                            - 'enable'
                    arp_inspection_trust:
                        aliases: ['arp-inspection-trust']
                        type: str
                        description: Trusted or untrusted dynamic ARP inspection.
                        choices:
                            - 'untrusted'
                            - 'trusted'
                    bundle:
                        type: str
                        description: Enable/disable Link Aggregation Group
                        choices:
                            - 'disable'
                            - 'enable'
                    description:
                        type: str
                        description: Description for port.
                    dhcp_snoop_option82_trust:
                        aliases: ['dhcp-snoop-option82-trust']
                        type: str
                        description: Enable/disable allowance of DHCP with option-82 on untrusted interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp_snooping:
                        aliases: ['dhcp-snooping']
                        type: str
                        description: Trusted or untrusted DHCP-snooping interface.
                        choices:
                            - 'trusted'
                            - 'untrusted'
                    discard_mode:
                        aliases: ['discard-mode']
                        type: str
                        description: Configure discard mode for port.
                        choices:
                            - 'none'
                            - 'all-untagged'
                            - 'all-tagged'
                    edge_port:
                        aliases: ['edge-port']
                        type: str
                        description: Enable/disable this interface as an edge port, bridging connections between workstations and/or computers.
                        choices:
                            - 'disable'
                            - 'enable'
                    igmp_snooping:
                        aliases: ['igmp-snooping']
                        type: str
                        description: Set IGMP snooping mode for the physical port interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    igmps_flood_reports:
                        aliases: ['igmps-flood-reports']
                        type: str
                        description: Enable/disable flooding of IGMP reports to this interface when igmp-snooping enabled.
                        choices:
                            - 'disable'
                            - 'enable'
                    igmps_flood_traffic:
                        aliases: ['igmps-flood-traffic']
                        type: str
                        description: Enable/disable flooding of IGMP snooping traffic to this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    lacp_speed:
                        aliases: ['lacp-speed']
                        type: str
                        description: End Link Aggregation Control Protocol
                        choices:
                            - 'slow'
                            - 'fast'
                    learning_limit:
                        aliases: ['learning-limit']
                        type: int
                        description: Limit the number of dynamic MAC addresses on this Port
                    lldp_profile:
                        aliases: ['lldp-profile']
                        type: str
                        description: LLDP port TLV profile.
                    lldp_status:
                        aliases: ['lldp-status']
                        type: str
                        description: LLDP transmit and receive status.
                        choices:
                            - 'disable'
                            - 'rx-only'
                            - 'tx-only'
                            - 'tx-rx'
                    loop_guard:
                        aliases: ['loop-guard']
                        type: str
                        description: Enable/disable loop-guard on this interface, an STP optimization used to prevent network loops.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    loop_guard_timeout:
                        aliases: ['loop-guard-timeout']
                        type: int
                        description: Loop-guard timeout
                    max_bundle:
                        aliases: ['max-bundle']
                        type: int
                        description: Maximum size of LAG bundle
                    mclag:
                        type: str
                        description: Enable/disable multi-chassis link aggregation
                        choices:
                            - 'disable'
                            - 'enable'
                    member_withdrawal_behavior:
                        aliases: ['member-withdrawal-behavior']
                        type: str
                        description: Port behavior after it withdraws because of loss of control packets.
                        choices:
                            - 'forward'
                            - 'block'
                    members:
                        type: raw
                        description: (list) Aggregated LAG bundle interfaces.
                    min_bundle:
                        aliases: ['min-bundle']
                        type: int
                        description: Minimum size of LAG bundle
                    mode:
                        type: str
                        description: LACP mode
                        choices:
                            - 'static'
                            - 'lacp-passive'
                            - 'lacp-active'
                    poe_pre_standard_detection:
                        aliases: ['poe-pre-standard-detection']
                        type: str
                        description: Enable/disable PoE pre-standard detection.
                        choices:
                            - 'disable'
                            - 'enable'
                    poe_status:
                        aliases: ['poe-status']
                        type: str
                        description: Enable/disable PoE status.
                        choices:
                            - 'disable'
                            - 'enable'
                    port_name:
                        aliases: ['port-name']
                        type: str
                        description: Switch port name.
                    port_owner:
                        aliases: ['port-owner']
                        type: str
                        description: Switch port name.
                    port_security_policy:
                        aliases: ['port-security-policy']
                        type: str
                        description: Switch controller authentication policy to apply to this managed switch from available options.
                    port_selection_criteria:
                        aliases: ['port-selection-criteria']
                        type: str
                        description: Algorithm for aggregate port selection.
                        choices:
                            - 'src-mac'
                            - 'dst-mac'
                            - 'src-dst-mac'
                            - 'src-ip'
                            - 'dst-ip'
                            - 'src-dst-ip'
                    qos_policy:
                        aliases: ['qos-policy']
                        type: str
                        description: Switch controller QoS policy from available options.
                    sample_direction:
                        aliases: ['sample-direction']
                        type: str
                        description: SFlow sample direction.
                        choices:
                            - 'rx'
                            - 'tx'
                            - 'both'
                    sflow_counter_interval:
                        aliases: ['sflow-counter-interval']
                        type: int
                        description: SFlow sampler counter polling interval
                    sflow_sample_rate:
                        aliases: ['sflow-sample-rate']
                        type: int
                        description: SFlow sampler sample rate
                    sflow_sampler:
                        aliases: ['sflow-sampler']
                        type: str
                        description: Enable/disable sFlow protocol on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    stp_bpdu_guard:
                        aliases: ['stp-bpdu-guard']
                        type: str
                        description: Enable/disable STP BPDU guard on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    stp_bpdu_guard_timeout:
                        aliases: ['stp-bpdu-guard-timeout']
                        type: int
                        description: BPDU Guard disabling protection
                    stp_root_guard:
                        aliases: ['stp-root-guard']
                        type: str
                        description: Enable/disable STP root guard on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    stp_state:
                        aliases: ['stp-state']
                        type: str
                        description: Enable/disable Spanning Tree Protocol
                        choices:
                            - 'disabled'
                            - 'enabled'
                    type:
                        type: str
                        description: Interface type
                        choices:
                            - 'physical'
                            - 'trunk'
                    untagged_vlans:
                        aliases: ['untagged-vlans']
                        type: raw
                        description: (list or str) Configure switch port untagged vlans
                    vlan:
                        type: str
                        description: Assign switch ports to a VLAN.
                    export_to_pool_flag:
                        aliases: ['export-to-pool-flag']
                        type: int
                        description: Switch controller export port to pool-list.
                    mac_addr:
                        aliases: ['mac-addr']
                        type: str
                        description: Port/Trunk MAC.
                    packet_sample_rate:
                        aliases: ['packet-sample-rate']
                        type: int
                        description: Packet sampling rate
                    packet_sampler:
                        aliases: ['packet-sampler']
                        type: str
                        description: Enable/disable packet sampling on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    sticky_mac:
                        aliases: ['sticky-mac']
                        type: str
                        description: Enable or disable sticky-mac on the interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    storm_control_policy:
                        aliases: ['storm-control-policy']
                        type: str
                        description: Switch controller storm control policy from available options.
                    dot1x_enable:
                        aliases: ['dot1x-enable']
                        type: str
                        description: Dot1x enable.
                        choices:
                            - 'disable'
                            - 'enable'
                    max_miss_heartbeats:
                        aliases: ['max-miss-heartbeats']
                        type: int
                        description: Maximum tolerant missed heartbeats.
                    access_mode:
                        aliases: ['access-mode']
                        type: str
                        description: Access mode of the port.
                        choices:
                            - 'normal'
                            - 'nac'
                            - 'dynamic'
                            - 'static'
                    ip_source_guard:
                        aliases: ['ip-source-guard']
                        type: str
                        description: Enable/disable IP source guard.
                        choices:
                            - 'disable'
                            - 'enable'
                    mclag_icl_port:
                        aliases: ['mclag-icl-port']
                        type: int
                        description: Mclag icl port.
                    p2p_port:
                        aliases: ['p2p-port']
                        type: int
                        description: P2p port.
                    aggregator_mode:
                        aliases: ['aggregator-mode']
                        type: str
                        description: LACP member select mode.
                        choices:
                            - 'bandwidth'
                            - 'count'
                    rpvst_port:
                        aliases: ['rpvst-port']
                        type: str
                        description: Enable/disable inter-operability with rapid PVST on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    flow_control:
                        aliases: ['flow-control']
                        type: str
                        description: Flow control direction.
                        choices:
                            - 'disable'
                            - 'tx'
                            - 'rx'
                            - 'both'
                    media_type:
                        aliases: ['media-type']
                        type: str
                        description: Media type.
                    pause_meter:
                        aliases: ['pause-meter']
                        type: int
                        description: Configure ingress pause metering rate, in kbps
                    pause_meter_resume:
                        aliases: ['pause-meter-resume']
                        type: str
                        description: Resume threshold for resuming traffic on ingress port.
                        choices:
                            - '25%'
                            - '50%'
                            - '75%'
                    trunk_member:
                        aliases: ['trunk-member']
                        type: int
                        description: Trunk member.
                    fec_capable:
                        aliases: ['fec-capable']
                        type: int
                        description: FEC capable.
                    fec_state:
                        aliases: ['fec-state']
                        type: str
                        description: State of forward error correction.
                        choices:
                            - 'disabled'
                            - 'cl74'
                            - 'cl91'
                            - 'detect-by-module'
                    matched_dpp_intf_tags:
                        aliases: ['matched-dpp-intf-tags']
                        type: str
                        description: Matched interface tags in the dynamic port policy.
                    matched_dpp_policy:
                        aliases: ['matched-dpp-policy']
                        type: str
                        description: Matched child policy in the dynamic port policy.
                    port_policy:
                        aliases: ['port-policy']
                        type: str
                        description: Switch controller dynamic port policy from available options.
                    status:
                        type: str
                        description: Switch port admin status
                        choices:
                            - 'down'
                            - 'up'
                    dsl_profile:
                        aliases: ['dsl-profile']
                        type: str
                        description: DSL policy configuration.
                    flap_duration:
                        aliases: ['flap-duration']
                        type: int
                        description: Period over which flap events are calculated
                    flap_rate:
                        aliases: ['flap-rate']
                        type: int
                        description: Number of stage change events needed within flap-duration.
                    flap_timeout:
                        aliases: ['flap-timeout']
                        type: int
                        description: Flap guard disabling protection
                    flapguard:
                        type: str
                        description: Enable/disable flap guard.
                        choices:
                            - 'disable'
                            - 'enable'
                    interface_tags:
                        aliases: ['interface-tags']
                        type: raw
                        description: (list or str) Tag
                    poe_max_power:
                        aliases: ['poe-max-power']
                        type: str
                        description: Poe max power.
                    poe_standard:
                        aliases: ['poe-standard']
                        type: str
                        description: Poe standard.
                    igmp_snooping_flood_reports:
                        aliases: ['igmp-snooping-flood-reports']
                        type: str
                        description: Enable/disable flooding of IGMP reports to this interface when igmp-snooping enabled.
                        choices:
                            - 'disable'
                            - 'enable'
                    mcast_snooping_flood_traffic:
                        aliases: ['mcast-snooping-flood-traffic']
                        type: str
                        description: Enable/disable flooding of IGMP snooping traffic to this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    link_status:
                        aliases: ['link-status']
                        type: str
                        description: Link status.
                        choices:
                            - 'down'
                            - 'up'
                    poe_mode_bt_cabable:
                        aliases: ['poe-mode-bt-cabable']
                        type: int
                        description: PoE mode IEEE 802.
                    poe_port_mode:
                        aliases: ['poe-port-mode']
                        type: str
                        description: Configure PoE port mode.
                        choices:
                            - 'ieee802-3af'
                            - 'ieee802-3at'
                            - 'ieee802-3bt'
                    poe_port_power:
                        aliases: ['poe-port-power']
                        type: str
                        description: Configure PoE port power.
                        choices:
                            - 'normal'
                            - 'perpetual'
                            - 'perpetual-fast'
                    poe_port_priority:
                        aliases: ['poe-port-priority']
                        type: str
                        description: Configure PoE port priority.
                        choices:
                            - 'critical-priority'
                            - 'high-priority'
                            - 'low-priority'
                            - 'medium-priority'
                    acl_group:
                        aliases: ['acl-group']
                        type: raw
                        description: (list) ACL groups on this port.
                    dhcp_snoop_option82_override:
                        aliases: ['dhcp-snoop-option82-override']
                        type: list
                        elements: dict
                        description: Dhcp snoop option82 override.
                        suboptions:
                            circuit_id:
                                aliases: ['circuit-id']
                                type: str
                                description: Circuit ID string.
                            remote_id:
                                aliases: ['remote-id']
                                type: str
                                description: Remote ID string.
                            vlan_name:
                                aliases: ['vlan-name']
                                type: str
                                description: DHCP snooping option 82 VLAN.
                    fortiswitch_acls:
                        aliases: ['fortiswitch-acls']
                        type: raw
                        description: (list) ACLs on this port.
                    isl_peer_device_sn:
                        aliases: ['isl-peer-device-sn']
                        type: str
                        description: Isl peer device sn.
                    authenticated_port:
                        aliases: ['authenticated-port']
                        type: int
                        description: Authenticated port.
                    encrypted_port:
                        aliases: ['encrypted-port']
                        type: int
                        description: Encrypted port.
                    ptp_status:
                        aliases: ['ptp-status']
                        type: str
                        description: Enable/disable PTP policy on this FortiSwitch port.
                        choices:
                            - 'disable'
                            - 'enable'
                    restricted_auth_port:
                        aliases: ['restricted-auth-port']
                        type: int
                        description: Restricted auth port.
                    allow_arp_monitor:
                        aliases: ['allow-arp-monitor']
                        type: str
                        description: Enable/Disable allow ARP monitor.
                        choices:
                            - 'disable'
                            - 'enable'
                    export_to:
                        aliases: ['export-to']
                        type: raw
                        description: (list) Export managed-switch port to a tenant VDOM.
                    export_to_pool:
                        aliases: ['export-to-pool']
                        type: raw
                        description: (list) Switch controller export port to pool-list.
                    fallback_port:
                        aliases: ['fallback-port']
                        type: str
                        description: LACP fallback port.
                    fgt_peer_device_name:
                        aliases: ['fgt-peer-device-name']
                        type: str
                        description: Fgt peer device name.
                    fgt_peer_port_name:
                        aliases: ['fgt-peer-port-name']
                        type: str
                        description: Fgt peer port name.
                    fiber_port:
                        aliases: ['fiber-port']
                        type: int
                        description: Fiber port.
                    flags:
                        type: int
                        description: Flags.
                    fortilink_port:
                        aliases: ['fortilink-port']
                        type: int
                        description: Fortilink port.
                    isl_local_trunk_name:
                        aliases: ['isl-local-trunk-name']
                        type: str
                        description: Isl local trunk name.
                    isl_peer_device_name:
                        aliases: ['isl-peer-device-name']
                        type: str
                        description: Isl peer device name.
                    isl_peer_port_name:
                        aliases: ['isl-peer-port-name']
                        type: str
                        description: Isl peer port name.
                    poe_capable:
                        aliases: ['poe-capable']
                        type: int
                        description: PoE capable.
                    port_number:
                        aliases: ['port-number']
                        type: int
                        description: Port number.
                    port_prefix_type:
                        aliases: ['port-prefix-type']
                        type: int
                        description: Port prefix type.
                    ptp_policy:
                        aliases: ['ptp-policy']
                        type: raw
                        description: (list) PTP policy configuration.
                    speed:
                        type: str
                        description: Switch port speed; default and available settings depend on hardware.
                        choices:
                            - 'auto'
                            - '10full'
                            - '10half'
                            - '100full'
                            - '100half'
                            - '1000full'
                            - '10000full'
                            - '1000auto'
                            - '40000full'
                            - '1000fiber'
                            - '10000'
                            - '40000'
                            - 'auto-module'
                            - '100FX-half'
                            - '100FX-full'
                            - '100000full'
                            - '2500full'
                            - '25000full'
                            - '50000full'
                            - '40000auto'
                            - '10000cr'
                            - '10000sr'
                            - '100000sr4'
                            - '100000cr4'
                            - '25000cr4'
                            - '25000sr4'
                            - '5000full'
                            - '2500auto'
                            - '5000auto'
                            - '1000full-fiber'
                            - '40000sr4'
                            - '40000cr4'
                            - '25000cr'
                            - '25000sr'
                            - '50000cr'
                            - '50000sr'
                    speed_mask:
                        aliases: ['speed-mask']
                        type: int
                        description: Switch port speed mask.
                    stacking_port:
                        aliases: ['stacking-port']
                        type: int
                        description: Stacking port.
                    switch_id:
                        aliases: ['switch-id']
                        type: str
                        description: Switch id.
                    virtual_port:
                        aliases: ['virtual-port']
                        type: int
                        description: Virtualized switch port.
                    export_tags:
                        aliases: ['export-tags']
                        type: raw
                        description: (list) Configure export tag
                    log_mac_event:
                        aliases: ['log-mac-event']
                        type: str
                        description: Enable/disable logging for dynamic MAC address events.
                        choices:
                            - 'disable'
                            - 'enable'
                    pd_capable:
                        aliases: ['pd-capable']
                        type: int
                        description: Powered device capable.
                    qnq:
                        type: raw
                        description: (list) '802.'
            switch_id:
                aliases: ['switch-id']
                type: str
                description: Managed-switch id.
                required: true
            override_snmp_community:
                aliases: ['override-snmp-community']
                type: str
                description: Enable/disable overriding the global SNMP communities.
                choices:
                    - 'disable'
                    - 'enable'
            override_snmp_sysinfo:
                aliases: ['override-snmp-sysinfo']
                type: str
                description: Enable/disable overriding the global SNMP system information.
                choices:
                    - 'disable'
                    - 'enable'
            override_snmp_trap_threshold:
                aliases: ['override-snmp-trap-threshold']
                type: str
                description: Enable/disable overriding the global SNMP trap threshold values.
                choices:
                    - 'disable'
                    - 'enable'
            override_snmp_user:
                aliases: ['override-snmp-user']
                type: str
                description: Enable/disable overriding the global SNMP users.
                choices:
                    - 'disable'
                    - 'enable'
            poe_detection_type:
                aliases: ['poe-detection-type']
                type: int
                description: Poe detection type.
            remote_log:
                aliases: ['remote-log']
                type: list
                elements: dict
                description: Remote log.
                suboptions:
                    csv:
                        type: str
                        description: Enable/disable comma-separated value
                        choices:
                            - 'disable'
                            - 'enable'
                    facility:
                        type: str
                        description: Facility to log to remote syslog server.
                        choices:
                            - 'kernel'
                            - 'user'
                            - 'mail'
                            - 'daemon'
                            - 'auth'
                            - 'syslog'
                            - 'lpr'
                            - 'news'
                            - 'uucp'
                            - 'cron'
                            - 'authpriv'
                            - 'ftp'
                            - 'ntp'
                            - 'audit'
                            - 'alert'
                            - 'clock'
                            - 'local0'
                            - 'local1'
                            - 'local2'
                            - 'local3'
                            - 'local4'
                            - 'local5'
                            - 'local6'
                            - 'local7'
                    name:
                        type: str
                        description: Remote log name.
                    port:
                        type: int
                        description: Remote syslog server listening port.
                    server:
                        type: str
                        description: IPv4 address of the remote syslog server.
                    severity:
                        type: str
                        description: Severity of logs to be transferred to remote log server.
                        choices:
                            - 'emergency'
                            - 'alert'
                            - 'critical'
                            - 'error'
                            - 'warning'
                            - 'notification'
                            - 'information'
                            - 'debug'
                    status:
                        type: str
                        description: Enable/disable logging by FortiSwitch device to a remote syslog server.
                        choices:
                            - 'disable'
                            - 'enable'
            snmp_community:
                aliases: ['snmp-community']
                type: list
                elements: dict
                description: Snmp community.
                suboptions:
                    events:
                        type: list
                        elements: str
                        description: SNMP notifications
                        choices:
                            - 'cpu-high'
                            - 'mem-low'
                            - 'log-full'
                            - 'intf-ip'
                            - 'ent-conf-change'
                            - 'l2mac'
                    hosts:
                        type: list
                        elements: dict
                        description: Hosts.
                        suboptions:
                            id:
                                type: int
                                description: Host entry ID.
                            ip:
                                type: str
                                description: IPv4 address of the SNMP manager
                    id:
                        type: int
                        description: SNMP community ID.
                    name:
                        type: str
                        description: SNMP community name.
                    query_v1_port:
                        aliases: ['query-v1-port']
                        type: int
                        description: SNMP v1 query port
                    query_v1_status:
                        aliases: ['query-v1-status']
                        type: str
                        description: Enable/disable SNMP v1 queries.
                        choices:
                            - 'disable'
                            - 'enable'
                    query_v2c_port:
                        aliases: ['query-v2c-port']
                        type: int
                        description: SNMP v2c query port
                    query_v2c_status:
                        aliases: ['query-v2c-status']
                        type: str
                        description: Enable/disable SNMP v2c queries.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable this SNMP community.
                        choices:
                            - 'disable'
                            - 'enable'
                    trap_v1_lport:
                        aliases: ['trap-v1-lport']
                        type: int
                        description: SNMP v2c trap local port
                    trap_v1_rport:
                        aliases: ['trap-v1-rport']
                        type: int
                        description: SNMP v2c trap remote port
                    trap_v1_status:
                        aliases: ['trap-v1-status']
                        type: str
                        description: Enable/disable SNMP v1 traps.
                        choices:
                            - 'disable'
                            - 'enable'
                    trap_v2c_lport:
                        aliases: ['trap-v2c-lport']
                        type: int
                        description: SNMP v2c trap local port
                    trap_v2c_rport:
                        aliases: ['trap-v2c-rport']
                        type: int
                        description: SNMP v2c trap remote port
                    trap_v2c_status:
                        aliases: ['trap-v2c-status']
                        type: str
                        description: Enable/disable SNMP v2c traps.
                        choices:
                            - 'disable'
                            - 'enable'
            snmp_user:
                aliases: ['snmp-user']
                type: list
                elements: dict
                description: Snmp user.
                suboptions:
                    auth_proto:
                        aliases: ['auth-proto']
                        type: str
                        description: Authentication protocol.
                        choices:
                            - 'md5'
                            - 'sha'
                            - 'sha1'
                            - 'sha256'
                            - 'sha384'
                            - 'sha512'
                            - 'sha224'
                    auth_pwd:
                        aliases: ['auth-pwd']
                        type: raw
                        description: (list) Password for authentication protocol.
                    name:
                        type: str
                        description: SNMP user name.
                    priv_proto:
                        aliases: ['priv-proto']
                        type: str
                        description: Privacy
                        choices:
                            - 'des'
                            - 'aes'
                            - 'aes128'
                            - 'aes192'
                            - 'aes256'
                            - 'aes192c'
                            - 'aes256c'
                    priv_pwd:
                        aliases: ['priv-pwd']
                        type: raw
                        description: (list) Password for privacy
                    queries:
                        type: str
                        description: Enable/disable SNMP queries for this user.
                        choices:
                            - 'disable'
                            - 'enable'
                    query_port:
                        aliases: ['query-port']
                        type: int
                        description: SNMPv3 query port
                    security_level:
                        aliases: ['security-level']
                        type: str
                        description: Security level for message authentication and encryption.
                        choices:
                            - 'no-auth-no-priv'
                            - 'auth-no-priv'
                            - 'auth-priv'
            mclag_igmp_snooping_aware:
                aliases: ['mclag-igmp-snooping-aware']
                type: str
                description: Enable/disable MCLAG IGMP-snooping awareness.
                choices:
                    - 'disable'
                    - 'enable'
            ip_source_guard:
                aliases: ['ip-source-guard']
                type: list
                elements: dict
                description: Ip source guard.
                suboptions:
                    binding_entry:
                        aliases: ['binding-entry']
                        type: list
                        elements: dict
                        description: Binding entry.
                        suboptions:
                            entry_name:
                                aliases: ['entry-name']
                                type: str
                                description: Configure binding pair.
                            ip:
                                type: str
                                description: Source IP for this rule.
                            mac:
                                type: str
                                description: MAC address for this rule.
                    description:
                        type: str
                        description: Description.
                    port:
                        type: str
                        description: Ingress interface to which source guard is bound.
            l3_discovered:
                aliases: ['l3-discovered']
                type: int
                description: L3 discovered.
            qos_drop_policy:
                aliases: ['qos-drop-policy']
                type: str
                description: Set QoS drop-policy.
                choices:
                    - 'taildrop'
                    - 'random-early-detection'
            qos_red_probability:
                aliases: ['qos-red-probability']
                type: int
                description: Set QoS RED/WRED drop probability.
            switch_dhcp_opt43_key:
                aliases: ['switch-dhcp_opt43_key']
                type: str
                description: DHCP option43 key.
            tdr_supported:
                aliases: ['tdr-supported']
                type: str
                description: Tdr supported.
            custom_command:
                aliases: ['custom-command']
                type: list
                elements: dict
                description: Custom command.
                suboptions:
                    command_entry:
                        aliases: ['command-entry']
                        type: str
                        description: List of FortiSwitch commands.
                    command_name:
                        aliases: ['command-name']
                        type: str
                        description: Names of commands to be pushed to this FortiSwitch device, as configured under config switch-controller custom-com...
            firmware_provision:
                aliases: ['firmware-provision']
                type: str
                description: Enable/disable provisioning of firmware to FortiSwitches on join connection.
                choices:
                    - 'disable'
                    - 'enable'
            firmware_provision_version:
                aliases: ['firmware-provision-version']
                type: str
                description: Firmware version to provision to this FortiSwitch on bootup
            dhcp_server_access_list:
                aliases: ['dhcp-server-access-list']
                type: str
                description: DHCP snooping server access list.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'global'
            firmware_provision_latest:
                aliases: ['firmware-provision-latest']
                type: str
                description: Enable/disable one-time automatic provisioning of the latest firmware version.
                choices:
                    - 'disable'
                    - 'once'
            dhcp_snooping_static_client:
                aliases: ['dhcp-snooping-static-client']
                type: list
                elements: dict
                description: Dhcp snooping static client.
                suboptions:
                    ip:
                        type: str
                        description: Client static IP address.
                    mac:
                        type: str
                        description: Client MAC address.
                    name:
                        type: str
                        description: Client name.
                    port:
                        type: str
                        description: Interface name.
                    vlan:
                        type: str
                        description: VLAN name.
            ptp_profile:
                aliases: ['ptp-profile']
                type: str
                description: PTP profile configuration.
            ptp_status:
                aliases: ['ptp-status']
                type: str
                description: Enable/disable PTP profile on this FortiSwitch.
                choices:
                    - 'disable'
                    - 'enable'
            route_offload:
                aliases: ['route-offload']
                type: str
                description: Enable/disable route offload on this FortiSwitch.
                choices:
                    - 'disable'
                    - 'enable'
            route_offload_mclag:
                aliases: ['route-offload-mclag']
                type: str
                description: Enable/disable route offload MCLAG on this FortiSwitch.
                choices:
                    - 'disable'
                    - 'enable'
            route_offload_router:
                aliases: ['route-offload-router']
                type: list
                elements: dict
                description: Route offload router.
                suboptions:
                    router_ip:
                        aliases: ['router-ip']
                        type: str
                        description: Router IP address.
                    vlan_name:
                        aliases: ['vlan-name']
                        type: str
                        description: VLAN name.
            mgmt_mode:
                aliases: ['mgmt-mode']
                type: int
                description: FortiLink management mode.
            purdue_level:
                aliases: ['purdue-level']
                type: str
                description: Purdue Level of this FortiSwitch.
                choices:
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
                    - '1.5'
                    - '2.5'
                    - '3.5'
                    - '5.5'
            radius_nas_ip:
                aliases: ['radius-nas-ip']
                type: str
                description: NAS-IP address.
            radius_nas_ip_override:
                aliases: ['radius-nas-ip-override']
                type: str
                description: Use locally defined NAS-IP.
                choices:
                    - 'disable'
                    - 'enable'
            tunnel_discovered:
                aliases: ['tunnel-discovered']
                type: int
                description: Tunnel discovered.
            vlan:
                type: list
                elements: dict
                description: Vlan.
                suboptions:
                    assignment_priority:
                        aliases: ['assignment-priority']
                        type: int
                        description: '802.'
                    vlan_name:
                        aliases: ['vlan-name']
                        type: str
                        description: VLAN name.
            802_1X_settings:
                aliases: ['802-1X-settings']
                type: dict
                description: 802 1X settings.
                suboptions:
                    link_down_auth:
                        aliases: ['link-down-auth']
                        type: str
                        description: Authentication state to set if a link is down.
                        choices:
                            - 'set-unauth'
                            - 'no-action'
                    local_override:
                        aliases: ['local-override']
                        type: str
                        description: Enable to override global 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    mab_reauth:
                        aliases: ['mab-reauth']
                        type: str
                        description: Enable or disable MAB reauthentication settings.
                        choices:
                            - 'disable'
                            - 'enable'
                    mac_called_station_delimiter:
                        aliases: ['mac-called-station-delimiter']
                        type: str
                        description: MAC called station delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mac_calling_station_delimiter:
                        aliases: ['mac-calling-station-delimiter']
                        type: str
                        description: MAC calling station delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mac_case:
                        aliases: ['mac-case']
                        type: str
                        description: MAC case
                        choices:
                            - 'uppercase'
                            - 'lowercase'
                    mac_password_delimiter:
                        aliases: ['mac-password-delimiter']
                        type: str
                        description: MAC authentication password delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mac_username_delimiter:
                        aliases: ['mac-username-delimiter']
                        type: str
                        description: MAC authentication username delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    max_reauth_attempt:
                        aliases: ['max-reauth-attempt']
                        type: int
                        description: Maximum number of authentication attempts
                    reauth_period:
                        aliases: ['reauth-period']
                        type: int
                        description: Reauthentication time interval
                    tx_period:
                        aliases: ['tx-period']
                        type: int
                        description: '802.'
            access_profile:
                aliases: ['access-profile']
                type: raw
                description: (list) FortiSwitch access profile.
            delayed_restart_trigger:
                aliases: ['delayed-restart-trigger']
                type: int
                description: Delayed restart triggered for this FortiSwitch.
            directly_connected:
                aliases: ['directly-connected']
                type: int
                description: Directly connected.
            dynamic_capability:
                aliases: ['dynamic-capability']
                type: str
                description: List of features this FortiSwitch supports
            dynamically_discovered:
                aliases: ['dynamically-discovered']
                type: int
                description: Dynamically discovered.
            flow_identity:
                aliases: ['flow-identity']
                type: str
                description: Flow-tracking netflow ipfix switch identity in hex format
            fsw_wan1_admin:
                aliases: ['fsw-wan1-admin']
                type: str
                description: FortiSwitch WAN1 admin status; enable to authorize the FortiSwitch as a managed switch.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'discovered'
            fsw_wan1_peer:
                aliases: ['fsw-wan1-peer']
                type: raw
                description: (list) FortiSwitch WAN1 peer port.
            fsw_wan2_admin:
                aliases: ['fsw-wan2-admin']
                type: str
                description: FortiSwitch WAN2 admin status; enable to authorize the FortiSwitch as a managed switch.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'discovered'
            fsw_wan2_peer:
                aliases: ['fsw-wan2-peer']
                type: str
                description: FortiSwitch WAN2 peer port.
            igmp_snooping:
                aliases: ['igmp-snooping']
                type: dict
                description: Igmp snooping.
                suboptions:
                    aging_time:
                        aliases: ['aging-time']
                        type: int
                        description: Maximum time to retain a multicast snooping entry for which no packets have been seen
                    flood_unknown_multicast:
                        aliases: ['flood-unknown-multicast']
                        type: str
                        description: Enable/disable unknown multicast flooding.
                        choices:
                            - 'disable'
                            - 'enable'
                    local_override:
                        aliases: ['local-override']
                        type: str
                        description: Enable/disable overriding the global IGMP snooping configuration.
                        choices:
                            - 'disable'
                            - 'enable'
                    vlans:
                        type: list
                        elements: dict
                        description: Vlans.
                        suboptions:
                            proxy:
                                type: str
                                description: IGMP snooping proxy for the VLAN interface.
                                choices:
                                    - 'disable'
                                    - 'enable'
                                    - 'global'
                            querier:
                                type: str
                                description: Enable/disable IGMP snooping querier for the VLAN interface.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            querier_addr:
                                aliases: ['querier-addr']
                                type: str
                                description: IGMP snooping querier address.
                            version:
                                type: int
                                description: IGMP snooping querying version.
                            vlan_name:
                                aliases: ['vlan-name']
                                type: raw
                                description: (list) List of FortiSwitch VLANs.
            max_allowed_trunk_members:
                aliases: ['max-allowed-trunk-members']
                type: int
                description: FortiSwitch maximum allowed trunk members.
            mirror:
                type: list
                elements: dict
                description: Mirror.
                suboptions:
                    dst:
                        type: str
                        description: Destination port.
                    name:
                        type: str
                        description: Mirror name.
                    src_egress:
                        aliases: ['src-egress']
                        type: raw
                        description: (list) Source egress interfaces.
                    src_ingress:
                        aliases: ['src-ingress']
                        type: raw
                        description: (list) Source ingress interfaces.
                    status:
                        type: str
                        description: Active/inactive mirror configuration.
                        choices:
                            - 'inactive'
                            - 'active'
                    switching_packet:
                        aliases: ['switching-packet']
                        type: str
                        description: Enable/disable switching functionality when mirroring.
                        choices:
                            - 'disable'
                            - 'enable'
            owner_vdom:
                aliases: ['owner-vdom']
                type: str
                description: VDOM which owner of port belongs to.
            poe_pre_standard_detection:
                aliases: ['poe-pre-standard-detection']
                type: str
                description: Enable/disable PoE pre-standard detection.
                choices:
                    - 'disable'
                    - 'enable'
            pre_provisioned:
                aliases: ['pre-provisioned']
                type: int
                description: Pre-provisioned managed switch.
            sn:
                type: str
                description: Managed-switch serial number.
            snmp_sysinfo:
                aliases: ['snmp-sysinfo']
                type: dict
                description: Snmp sysinfo.
                suboptions:
                    contact_info:
                        aliases: ['contact-info']
                        type: str
                        description: Contact information.
                    description:
                        type: str
                        description: System description.
                    engine_id:
                        aliases: ['engine-id']
                        type: str
                        description: Local SNMP engine ID string
                    location:
                        type: str
                        description: System location.
                    status:
                        type: str
                        description: Enable/disable SNMP.
                        choices:
                            - 'disable'
                            - 'enable'
            snmp_trap_threshold:
                aliases: ['snmp-trap-threshold']
                type: dict
                description: Snmp trap threshold.
                suboptions:
                    trap_high_cpu_threshold:
                        aliases: ['trap-high-cpu-threshold']
                        type: int
                        description: CPU usage when trap is sent.
                    trap_log_full_threshold:
                        aliases: ['trap-log-full-threshold']
                        type: int
                        description: Log disk usage when trap is sent.
                    trap_low_memory_threshold:
                        aliases: ['trap-low-memory-threshold']
                        type: int
                        description: Memory usage when trap is sent.
            staged_image_version:
                aliases: ['staged-image-version']
                type: str
                description: Staged image version for FortiSwitch.
            static_mac:
                aliases: ['static-mac']
                type: list
                elements: dict
                description: Static mac.
                suboptions:
                    description:
                        type: str
                        description: Description.
                    id:
                        type: int
                        description: ID.
                    interface:
                        type: str
                        description: Interface name.
                    mac:
                        type: str
                        description: MAC address.
                    type:
                        type: str
                        description: Type.
                        choices:
                            - 'static'
                            - 'sticky'
                    vlan:
                        type: raw
                        description: (list) Vlan.
            storm_control:
                aliases: ['storm-control']
                type: dict
                description: Storm control.
                suboptions:
                    broadcast:
                        type: str
                        description: Enable/disable storm control to drop broadcast traffic.
                        choices:
                            - 'disable'
                            - 'enable'
                    local_override:
                        aliases: ['local-override']
                        type: str
                        description: Enable to override global FortiSwitch storm control settings for this FortiSwitch.
                        choices:
                            - 'disable'
                            - 'enable'
                    rate:
                        type: int
                        description: Rate in packets per second at which storm control drops excess traffic
                    unknown_multicast:
                        aliases: ['unknown-multicast']
                        type: str
                        description: Enable/disable storm control to drop unknown multicast traffic.
                        choices:
                            - 'disable'
                            - 'enable'
                    unknown_unicast:
                        aliases: ['unknown-unicast']
                        type: str
                        description: Enable/disable storm control to drop unknown unicast traffic.
                        choices:
                            - 'disable'
                            - 'enable'
            stp_instance:
                aliases: ['stp-instance']
                type: list
                elements: dict
                description: Stp instance.
                suboptions:
                    id:
                        type: str
                        description: Instance ID.
                    priority:
                        type: str
                        description: Priority.
                        choices:
                            - '0'
                            - '4096'
                            - '8192'
                            - '12288'
                            - '12328'
                            - '16384'
                            - '20480'
                            - '24576'
                            - '28672'
                            - '32768'
                            - '36864'
                            - '40960'
                            - '45056'
                            - '49152'
                            - '53248'
                            - '57344'
                            - '61440'
            stp_settings:
                aliases: ['stp-settings']
                type: dict
                description: Stp settings.
                suboptions:
                    forward_time:
                        aliases: ['forward-time']
                        type: int
                        description: Period of time a port is in listening and learning state
                    hello_time:
                        aliases: ['hello-time']
                        type: int
                        description: Period of time between successive STP frame Bridge Protocol Data Units
                    local_override:
                        aliases: ['local-override']
                        type: str
                        description: Enable to configure local STP settings that override global STP settings.
                        choices:
                            - 'disable'
                            - 'enable'
                    max_age:
                        aliases: ['max-age']
                        type: int
                        description: Maximum time before a bridge port saves its configuration BPDU information
                    max_hops:
                        aliases: ['max-hops']
                        type: int
                        description: Maximum number of hops between the root bridge and the furthest bridge
                    name:
                        type: str
                        description: Name of local STP settings configuration.
                    pending_timer:
                        aliases: ['pending-timer']
                        type: int
                        description: Pending time
                    revision:
                        type: int
                        description: STP revision number
                    status:
                        type: str
                        description: Enable/disable STP.
                        choices:
                            - 'disable'
                            - 'enable'
            switch_device_tag:
                aliases: ['switch-device-tag']
                type: str
                description: User definable label/tag.
            switch_log:
                aliases: ['switch-log']
                type: dict
                description: Switch log.
                suboptions:
                    local_override:
                        aliases: ['local-override']
                        type: str
                        description: Enable to configure local logging settings that override global logging settings.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity of FortiSwitch logs that are added to the FortiGate event log.
                        choices:
                            - 'emergency'
                            - 'alert'
                            - 'critical'
                            - 'error'
                            - 'warning'
                            - 'notification'
                            - 'information'
                            - 'debug'
                    status:
                        type: str
                        description: Enable/disable adding FortiSwitch logs to the FortiGate event log.
                        choices:
                            - 'disable'
                            - 'enable'
            switch_profile:
                aliases: ['switch-profile']
                type: raw
                description: (list) FortiSwitch profile.
            type:
                type: str
                description: Indication of switch type, physical or virtual.
                choices:
                    - 'physical'
                    - 'virtual'
            version:
                type: int
                description: FortiSwitch version.
            poe_lldp_detection:
                aliases: ['poe-lldp-detection']
                type: str
                description: Enable/disable PoE LLDP detection.
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure FortiSwitch devices that are managed by this FortiGate.
      fortinet.fortimanager.fmgr_switchcontroller_managedswitch:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_managedswitch:
          switch_id: "your value" # Required variable, string
          # _platform: <string>
          # description: <string>
          # name: <string>
          # ports:
          #   - allowed_vlans: <list or string>
          #     allowed_vlans_all: <value in [disable, enable]>
          #     arp_inspection_trust: <value in [untrusted, trusted]>
          #     bundle: <value in [disable, enable]>
          #     description: <string>
          #     dhcp_snoop_option82_trust: <value in [disable, enable]>
          #     dhcp_snooping: <value in [trusted, untrusted]>
          #     discard_mode: <value in [none, all-untagged, all-tagged]>
          #     edge_port: <value in [disable, enable]>
          #     igmp_snooping: <value in [disable, enable]>
          #     igmps_flood_reports: <value in [disable, enable]>
          #     igmps_flood_traffic: <value in [disable, enable]>
          #     lacp_speed: <value in [slow, fast]>
          #     learning_limit: <integer>
          #     lldp_profile: <string>
          #     lldp_status: <value in [disable, rx-only, tx-only, ...]>
          #     loop_guard: <value in [disabled, enabled]>
          #     loop_guard_timeout: <integer>
          #     max_bundle: <integer>
          #     mclag: <value in [disable, enable]>
          #     member_withdrawal_behavior: <value in [forward, block]>
          #     members: <list or string>
          #     min_bundle: <integer>
          #     mode: <value in [static, lacp-passive, lacp-active]>
          #     poe_pre_standard_detection: <value in [disable, enable]>
          #     poe_status: <value in [disable, enable]>
          #     port_name: <string>
          #     port_owner: <string>
          #     port_security_policy: <string>
          #     port_selection_criteria: <value in [src-mac, dst-mac, src-dst-mac, ...]>
          #     qos_policy: <string>
          #     sample_direction: <value in [rx, tx, both]>
          #     sflow_counter_interval: <integer>
          #     sflow_sample_rate: <integer>
          #     sflow_sampler: <value in [disabled, enabled]>
          #     stp_bpdu_guard: <value in [disabled, enabled]>
          #     stp_bpdu_guard_timeout: <integer>
          #     stp_root_guard: <value in [disabled, enabled]>
          #     stp_state: <value in [disabled, enabled]>
          #     type: <value in [physical, trunk]>
          #     untagged_vlans: <list or string>
          #     vlan: <string>
          #     export_to_pool_flag: <integer>
          #     mac_addr: <string>
          #     packet_sample_rate: <integer>
          #     packet_sampler: <value in [disabled, enabled]>
          #     sticky_mac: <value in [disable, enable]>
          #     storm_control_policy: <string>
          #     dot1x_enable: <value in [disable, enable]>
          #     max_miss_heartbeats: <integer>
          #     access_mode: <value in [normal, nac, dynamic, ...]>
          #     ip_source_guard: <value in [disable, enable]>
          #     mclag_icl_port: <integer>
          #     p2p_port: <integer>
          #     aggregator_mode: <value in [bandwidth, count]>
          #     rpvst_port: <value in [disabled, enabled]>
          #     flow_control: <value in [disable, tx, rx, ...]>
          #     media_type: <string>
          #     pause_meter: <integer>
          #     pause_meter_resume: <value in [25%, 50%, 75%]>
          #     trunk_member: <integer>
          #     fec_capable: <integer>
          #     fec_state: <value in [disabled, cl74, cl91, ...]>
          #     matched_dpp_intf_tags: <string>
          #     matched_dpp_policy: <string>
          #     port_policy: <string>
          #     status: <value in [down, up]>
          #     dsl_profile: <string>
          #     flap_duration: <integer>
          #     flap_rate: <integer>
          #     flap_timeout: <integer>
          #     flapguard: <value in [disable, enable]>
          #     interface_tags: <list or string>
          #     poe_max_power: <string>
          #     poe_standard: <string>
          #     igmp_snooping_flood_reports: <value in [disable, enable]>
          #     mcast_snooping_flood_traffic: <value in [disable, enable]>
          #     link_status: <value in [down, up]>
          #     poe_mode_bt_cabable: <integer>
          #     poe_port_mode: <value in [ieee802-3af, ieee802-3at, ieee802-3bt]>
          #     poe_port_power: <value in [normal, perpetual, perpetual-fast]>
          #     poe_port_priority: <value in [critical-priority, high-priority, low-priority, ...]>
          #     acl_group: <list or string>
          #     dhcp_snoop_option82_override:
          #       - circuit_id: <string>
          #         remote_id: <string>
          #         vlan_name: <string>
          #     fortiswitch_acls: <list or integer>
          #     isl_peer_device_sn: <string>
          #     authenticated_port: <integer>
          #     encrypted_port: <integer>
          #     ptp_status: <value in [disable, enable]>
          #     restricted_auth_port: <integer>
          #     allow_arp_monitor: <value in [disable, enable]>
          #     export_to: <list or string>
          #     export_to_pool: <list or string>
          #     fallback_port: <string>
          #     fgt_peer_device_name: <string>
          #     fgt_peer_port_name: <string>
          #     fiber_port: <integer>
          #     flags: <integer>
          #     fortilink_port: <integer>
          #     isl_local_trunk_name: <string>
          #     isl_peer_device_name: <string>
          #     isl_peer_port_name: <string>
          #     poe_capable: <integer>
          #     port_number: <integer>
          #     port_prefix_type: <integer>
          #     ptp_policy: <list or string>
          #     speed: <value in [auto, 10full, 10half, ...]>
          #     speed_mask: <integer>
          #     stacking_port: <integer>
          #     switch_id: <string>
          #     virtual_port: <integer>
          #     export_tags: <list or string>
          #     log_mac_event: <value in [disable, enable]>
          #     pd_capable: <integer>
          #     qnq: <list or string>
          # override_snmp_community: <value in [disable, enable]>
          # override_snmp_sysinfo: <value in [disable, enable]>
          # override_snmp_trap_threshold: <value in [disable, enable]>
          # override_snmp_user: <value in [disable, enable]>
          # poe_detection_type: <integer>
          # remote_log:
          #   - csv: <value in [disable, enable]>
          #     facility: <value in [kernel, user, mail, ...]>
          #     name: <string>
          #     port: <integer>
          #     server: <string>
          #     severity: <value in [emergency, alert, critical, ...]>
          #     status: <value in [disable, enable]>
          # snmp_community:
          #   - events:
          #       - "cpu-high"
          #       - "mem-low"
          #       - "log-full"
          #       - "intf-ip"
          #       - "ent-conf-change"
          #       - "l2mac"
          #     hosts:
          #       - id: <integer>
          #         ip: <string>
          #     id: <integer>
          #     name: <string>
          #     query_v1_port: <integer>
          #     query_v1_status: <value in [disable, enable]>
          #     query_v2c_port: <integer>
          #     query_v2c_status: <value in [disable, enable]>
          #     status: <value in [disable, enable]>
          #     trap_v1_lport: <integer>
          #     trap_v1_rport: <integer>
          #     trap_v1_status: <value in [disable, enable]>
          #     trap_v2c_lport: <integer>
          #     trap_v2c_rport: <integer>
          #     trap_v2c_status: <value in [disable, enable]>
          # snmp_user:
          #   - auth_proto: <value in [md5, sha, sha1, ...]>
          #     auth_pwd: <list or string>
          #     name: <string>
          #     priv_proto: <value in [des, aes, aes128, ...]>
          #     priv_pwd: <list or string>
          #     queries: <value in [disable, enable]>
          #     query_port: <integer>
          #     security_level: <value in [no-auth-no-priv, auth-no-priv, auth-priv]>
          # mclag_igmp_snooping_aware: <value in [disable, enable]>
          # ip_source_guard:
          #   - binding_entry:
          #       - entry_name: <string>
          #         ip: <string>
          #         mac: <string>
          #     description: <string>
          #     port: <string>
          # l3_discovered: <integer>
          # qos_drop_policy: <value in [taildrop, random-early-detection]>
          # qos_red_probability: <integer>
          # switch_dhcp_opt43_key: <string>
          # tdr_supported: <string>
          # custom_command:
          #   - command_entry: <string>
          #     command_name: <string>
          # firmware_provision: <value in [disable, enable]>
          # firmware_provision_version: <string>
          # dhcp_server_access_list: <value in [disable, enable, global]>
          # firmware_provision_latest: <value in [disable, once]>
          # dhcp_snooping_static_client:
          #   - ip: <string>
          #     mac: <string>
          #     name: <string>
          #     port: <string>
          #     vlan: <string>
          # ptp_profile: <string>
          # ptp_status: <value in [disable, enable]>
          # route_offload: <value in [disable, enable]>
          # route_offload_mclag: <value in [disable, enable]>
          # route_offload_router:
          #   - router_ip: <string>
          #     vlan_name: <string>
          # mgmt_mode: <integer>
          # purdue_level: <value in [1, 2, 3, ...]>
          # radius_nas_ip: <string>
          # radius_nas_ip_override: <value in [disable, enable]>
          # tunnel_discovered: <integer>
          # vlan:
          #   - assignment_priority: <integer>
          #     vlan_name: <string>
          # 802_1X_settings:
          #   link_down_auth: <value in [set-unauth, no-action]>
          #   local_override: <value in [disable, enable]>
          #   mab_reauth: <value in [disable, enable]>
          #   mac_called_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          #   mac_calling_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          #   mac_case: <value in [uppercase, lowercase]>
          #   mac_password_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          #   mac_username_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          #   max_reauth_attempt: <integer>
          #   reauth_period: <integer>
          #   tx_period: <integer>
          # access_profile: <list or string>
          # delayed_restart_trigger: <integer>
          # directly_connected: <integer>
          # dynamic_capability: <string>
          # dynamically_discovered: <integer>
          # flow_identity: <string>
          # fsw_wan1_admin: <value in [disable, enable, discovered]>
          # fsw_wan1_peer: <list or string>
          # fsw_wan2_admin: <value in [disable, enable, discovered]>
          # fsw_wan2_peer: <string>
          # igmp_snooping:
          #   aging_time: <integer>
          #   flood_unknown_multicast: <value in [disable, enable]>
          #   local_override: <value in [disable, enable]>
          #   vlans:
          #     - proxy: <value in [disable, enable, global]>
          #       querier: <value in [disable, enable]>
          #       querier_addr: <string>
          #       version: <integer>
          #       vlan_name: <list or string>
          # max_allowed_trunk_members: <integer>
          # mirror:
          #   - dst: <string>
          #     name: <string>
          #     src_egress: <list or string>
          #     src_ingress: <list or string>
          #     status: <value in [inactive, active]>
          #     switching_packet: <value in [disable, enable]>
          # owner_vdom: <string>
          # poe_pre_standard_detection: <value in [disable, enable]>
          # pre_provisioned: <integer>
          # sn: <string>
          # snmp_sysinfo:
          #   contact_info: <string>
          #   description: <string>
          #   engine_id: <string>
          #   location: <string>
          #   status: <value in [disable, enable]>
          # snmp_trap_threshold:
          #   trap_high_cpu_threshold: <integer>
          #   trap_log_full_threshold: <integer>
          #   trap_low_memory_threshold: <integer>
          # staged_image_version: <string>
          # static_mac:
          #   - description: <string>
          #     id: <integer>
          #     interface: <string>
          #     mac: <string>
          #     type: <value in [static, sticky]>
          #     vlan: <list or string>
          # storm_control:
          #   broadcast: <value in [disable, enable]>
          #   local_override: <value in [disable, enable]>
          #   rate: <integer>
          #   unknown_multicast: <value in [disable, enable]>
          #   unknown_unicast: <value in [disable, enable]>
          # stp_instance:
          #   - id: <string>
          #     priority: <value in [0, 4096, 8192, ...]>
          # stp_settings:
          #   forward_time: <integer>
          #   hello_time: <integer>
          #   local_override: <value in [disable, enable]>
          #   max_age: <integer>
          #   max_hops: <integer>
          #   name: <string>
          #   pending_timer: <integer>
          #   revision: <integer>
          #   status: <value in [disable, enable]>
          # switch_device_tag: <string>
          # switch_log:
          #   local_override: <value in [disable, enable]>
          #   severity: <value in [emergency, alert, critical, ...]>
          #   status: <value in [disable, enable]>
          # switch_profile: <list or string>
          # type: <value in [physical, virtual]>
          # version: <integer>
          # poe_lldp_detection: <value in [disable, enable]>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/switch-controller/managed-switch',
        '/pm/config/global/obj/switch-controller/managed-switch'
    ]
    url_params = ['adom']
    module_primary_key = 'switch-id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_managedswitch': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                '_platform': {'type': 'str'},
                'description': {'type': 'str'},
                'name': {'type': 'str'},
                'ports': {
                    'type': 'list',
                    'options': {
                        'allowed-vlans': {'type': 'raw'},
                        'allowed-vlans-all': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'arp-inspection-trust': {'choices': ['untrusted', 'trusted'], 'type': 'str'},
                        'bundle': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'description': {'type': 'str'},
                        'dhcp-snoop-option82-trust': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp-snooping': {'choices': ['trusted', 'untrusted'], 'type': 'str'},
                        'discard-mode': {'choices': ['none', 'all-untagged', 'all-tagged'], 'type': 'str'},
                        'edge-port': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'igmp-snooping': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'igmps-flood-reports': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'igmps-flood-traffic': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'lacp-speed': {'choices': ['slow', 'fast'], 'type': 'str'},
                        'learning-limit': {'type': 'int'},
                        'lldp-profile': {'type': 'str'},
                        'lldp-status': {'choices': ['disable', 'rx-only', 'tx-only', 'tx-rx'], 'type': 'str'},
                        'loop-guard': {'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'loop-guard-timeout': {'type': 'int'},
                        'max-bundle': {'type': 'int'},
                        'mclag': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'member-withdrawal-behavior': {'choices': ['forward', 'block'], 'type': 'str'},
                        'members': {'type': 'raw'},
                        'min-bundle': {'type': 'int'},
                        'mode': {'choices': ['static', 'lacp-passive', 'lacp-active'], 'type': 'str'},
                        'poe-pre-standard-detection': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'poe-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'port-name': {'type': 'str'},
                        'port-owner': {'type': 'str'},
                        'port-security-policy': {'type': 'str'},
                        'port-selection-criteria': {'choices': ['src-mac', 'dst-mac', 'src-dst-mac', 'src-ip', 'dst-ip', 'src-dst-ip'], 'type': 'str'},
                        'qos-policy': {'type': 'str'},
                        'sample-direction': {'choices': ['rx', 'tx', 'both'], 'type': 'str'},
                        'sflow-counter-interval': {'type': 'int'},
                        'sflow-sample-rate': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                        'sflow-sampler': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'stp-bpdu-guard': {'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'stp-bpdu-guard-timeout': {'type': 'int'},
                        'stp-root-guard': {'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'stp-state': {'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'type': {'choices': ['physical', 'trunk'], 'type': 'str'},
                        'untagged-vlans': {'type': 'raw'},
                        'vlan': {'type': 'str'},
                        'export-to-pool-flag': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'mac-addr': {'v_range': [['6.2.1', '6.2.1'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'packet-sample-rate': {'v_range': [['6.2.0', '']], 'type': 'int'},
                        'packet-sampler': {'v_range': [['6.2.0', '']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'sticky-mac': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'storm-control-policy': {'v_range': [['6.2.0', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'dot1x-enable': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-miss-heartbeats': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'},
                        'access-mode': {'v_range': [['6.4.0', '']], 'choices': ['normal', 'nac', 'dynamic', 'static'], 'type': 'str'},
                        'ip-source-guard': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mclag-icl-port': {'v_range': [['6.4.0', '']], 'type': 'int'},
                        'p2p-port': {'v_range': [['6.4.0', '']], 'type': 'int'},
                        'aggregator-mode': {'v_range': [['6.4.2', '']], 'choices': ['bandwidth', 'count'], 'type': 'str'},
                        'rpvst-port': {'v_range': [['6.4.2', '']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'flow-control': {'v_range': [['6.4.3', '']], 'choices': ['disable', 'tx', 'rx', 'both'], 'type': 'str'},
                        'media-type': {'v_range': [['6.4.3', '']], 'type': 'str'},
                        'pause-meter': {'v_range': [['6.4.3', '']], 'type': 'int'},
                        'pause-meter-resume': {'v_range': [['6.4.3', '']], 'choices': ['25%', '50%', '75%'], 'type': 'str'},
                        'trunk-member': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'type': 'int'},
                        'fec-capable': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'fec-state': {'v_range': [['7.0.0', '']], 'choices': ['disabled', 'cl74', 'cl91', 'detect-by-module'], 'type': 'str'},
                        'matched-dpp-intf-tags': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'matched-dpp-policy': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'port-policy': {'v_range': [['7.0.0', '7.0.4'], ['7.2.0', '']], 'type': 'str'},
                        'status': {'v_range': [['6.4.6', '']], 'choices': ['down', 'up'], 'type': 'str'},
                        'dsl-profile': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'flap-duration': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'flap-rate': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'flap-timeout': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'flapguard': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'interface-tags': {'v_range': [['7.0.2', '']], 'type': 'raw'},
                        'poe-max-power': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'poe-standard': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'igmp-snooping-flood-reports': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mcast-snooping-flood-traffic': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'link-status': {'v_range': [['7.2.2', '']], 'choices': ['down', 'up'], 'type': 'str'},
                        'poe-mode-bt-cabable': {'v_range': [['7.2.2', '']], 'type': 'int'},
                        'poe-port-mode': {'v_range': [['7.2.2', '']], 'choices': ['ieee802-3af', 'ieee802-3at', 'ieee802-3bt'], 'type': 'str'},
                        'poe-port-power': {'v_range': [['7.2.2', '']], 'choices': ['normal', 'perpetual', 'perpetual-fast'], 'type': 'str'},
                        'poe-port-priority': {
                            'v_range': [['7.2.2', '']],
                            'choices': ['critical-priority', 'high-priority', 'low-priority', 'medium-priority'],
                            'type': 'str'
                        },
                        'acl-group': {'v_range': [['7.4.0', '']], 'type': 'raw'},
                        'dhcp-snoop-option82-override': {
                            'v_range': [['7.4.0', '']],
                            'type': 'list',
                            'options': {
                                'circuit-id': {'v_range': [['7.4.0', '']], 'type': 'str'},
                                'remote-id': {'v_range': [['7.4.0', '']], 'type': 'str'},
                                'vlan-name': {'v_range': [['7.4.0', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'fortiswitch-acls': {'v_range': [['7.4.0', '']], 'type': 'raw'},
                        'isl-peer-device-sn': {'v_range': [['7.4.0', '']], 'type': 'str'},
                        'authenticated-port': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'encrypted-port': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'ptp-status': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'restricted-auth-port': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'allow-arp-monitor': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'export-to': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                        'export-to-pool': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                        'fallback-port': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'fgt-peer-device-name': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'fgt-peer-port-name': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'fiber-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'flags': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'fortilink-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'isl-local-trunk-name': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'isl-peer-device-name': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'isl-peer-port-name': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'poe-capable': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'port-number': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'port-prefix-type': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'ptp-policy': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                        'speed': {
                            'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': [
                                'auto', '10full', '10half', '100full', '100half', '1000full', '10000full', '1000auto', '40000full', '1000fiber', '10000',
                                '40000', 'auto-module', '100FX-half', '100FX-full', '100000full', '2500full', '25000full', '50000full', '40000auto',
                                '10000cr', '10000sr', '100000sr4', '100000cr4', '25000cr4', '25000sr4', '5000full', '2500auto', '5000auto',
                                '1000full-fiber', '40000sr4', '40000cr4', '25000cr', '25000sr', '50000cr', '50000sr'
                            ],
                            'type': 'str'
                        },
                        'speed-mask': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'stacking-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'switch-id': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'virtual-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'export-tags': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                        'log-mac-event': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pd-capable': {'v_range': [['7.4.4', '']], 'type': 'int'},
                        'qnq': {'v_range': [['7.6.0', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                },
                'switch-id': {'required': True, 'type': 'str'},
                'override-snmp-community': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-snmp-sysinfo': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-snmp-trap-threshold': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-snmp-user': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'poe-detection-type': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'remote-log': {
                    'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'csv': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'facility': {
                            'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': [
                                'kernel', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit',
                                'alert', 'clock', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
                            ],
                            'type': 'str'
                        },
                        'name': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'port': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'server': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'severity': {
                            'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'snmp-community': {
                    'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'events': {
                            'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'type': 'list',
                            'choices': ['cpu-high', 'mem-low', 'log-full', 'intf-ip', 'ent-conf-change', 'l2mac'],
                            'elements': 'str'
                        },
                        'hosts': {
                            'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                                'ip': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'id': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'query-v1-port': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'query-v1-status': {
                            'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'query-v2c-port': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'query-v2c-status': {
                            'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'trap-v1-lport': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'trap-v1-rport': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'trap-v1-status': {
                            'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'trap-v2c-lport': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'trap-v2c-rport': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'trap-v2c-status': {
                            'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'snmp-user': {
                    'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'auth-proto': {
                            'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['md5', 'sha', 'sha1', 'sha256', 'sha384', 'sha512', 'sha224'],
                            'type': 'str'
                        },
                        'auth-pwd': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                        'name': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'priv-proto': {
                            'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['des', 'aes', 'aes128', 'aes192', 'aes256', 'aes192c', 'aes256c'],
                            'type': 'str'
                        },
                        'priv-pwd': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                        'queries': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'query-port': {'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'security-level': {
                            'v_range': [['6.2.1', '6.2.3'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['no-auth-no-priv', 'auth-no-priv', 'auth-priv'],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'mclag-igmp-snooping-aware': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip-source-guard': {
                    'v_range': [['6.4.0', '6.4.1'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'binding-entry': {
                            'v_range': [['6.4.0', '6.4.1'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'entry-name': {'v_range': [['6.4.0', '6.4.1'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                                'ip': {'v_range': [['6.4.0', '6.4.1'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                                'mac': {'v_range': [['6.4.0', '6.4.1'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'description': {'v_range': [['6.4.0', '6.4.1'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'port': {'v_range': [['6.4.0', '6.4.1'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'l3-discovered': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'qos-drop-policy': {'v_range': [['6.4.0', '']], 'choices': ['taildrop', 'random-early-detection'], 'type': 'str'},
                'qos-red-probability': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'switch-dhcp_opt43_key': {'v_range': [['6.4.0', '']], 'no_log': True, 'type': 'str'},
                'tdr-supported': {'v_range': [['6.4.3', '']], 'type': 'str'},
                'custom-command': {
                    'v_range': [['7.0.0', '']],
                    'type': 'list',
                    'options': {'command-entry': {'v_range': [['7.0.0', '']], 'type': 'str'}, 'command-name': {'v_range': [['7.0.0', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'firmware-provision': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'firmware-provision-version': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'dhcp-server-access-list': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable', 'global'], 'type': 'str'},
                'firmware-provision-latest': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'once'], 'type': 'str'},
                'dhcp-snooping-static-client': {
                    'v_range': [['7.2.2', '']],
                    'type': 'list',
                    'options': {
                        'ip': {'v_range': [['7.2.2', '']], 'type': 'str'},
                        'mac': {'v_range': [['7.2.2', '']], 'type': 'str'},
                        'name': {'v_range': [['7.2.2', '']], 'type': 'str'},
                        'port': {'v_range': [['7.2.2', '']], 'type': 'str'},
                        'vlan': {'v_range': [['7.2.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ptp-profile': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'ptp-status': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-offload': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-offload-mclag': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-offload-router': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'options': {'router-ip': {'v_range': [['7.4.1', '']], 'type': 'str'}, 'vlan-name': {'v_range': [['7.4.1', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'mgmt-mode': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'purdue-level': {'v_range': [['7.4.2', '']], 'choices': ['1', '2', '3', '4', '5', '1.5', '2.5', '3.5', '5.5'], 'type': 'str'},
                'radius-nas-ip': {'v_range': [['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'radius-nas-ip-override': {'v_range': [['7.2.6', '7.2.11'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-discovered': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'vlan': {
                    'v_range': [['7.4.2', '']],
                    'type': 'list',
                    'options': {
                        'assignment-priority': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'vlan-name': {'v_range': [['7.4.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                '802-1X-settings': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'link-down-auth': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['set-unauth', 'no-action'], 'type': 'str'},
                        'local-override': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mab-reauth': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mac-called-station-delimiter': {
                            'v_range': [['7.4.3', '']],
                            'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                            'type': 'str'
                        },
                        'mac-calling-station-delimiter': {
                            'v_range': [['7.4.3', '']],
                            'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                            'type': 'str'
                        },
                        'mac-case': {'v_range': [['7.4.3', '']], 'choices': ['uppercase', 'lowercase'], 'type': 'str'},
                        'mac-password-delimiter': {'v_range': [['7.4.3', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                        'mac-username-delimiter': {'v_range': [['7.4.3', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                        'max-reauth-attempt': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'reauth-period': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'tx-period': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'}
                    }
                },
                'access-profile': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'delayed-restart-trigger': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'directly-connected': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'dynamic-capability': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'dynamically-discovered': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'flow-identity': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'fsw-wan1-admin': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'discovered'], 'type': 'str'},
                'fsw-wan1-peer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'fsw-wan2-admin': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'discovered'], 'type': 'str'},
                'fsw-wan2-peer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'igmp-snooping': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'aging-time': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'flood-unknown-multicast': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-override': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vlans': {
                            'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'proxy': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'global'], 'type': 'str'},
                                'querier': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'querier-addr': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                                'version': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                                'vlan-name': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'}
                            },
                            'elements': 'dict'
                        }
                    }
                },
                'max-allowed-trunk-members': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'mirror': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'dst': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'src-egress': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                        'src-ingress': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                        'status': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['inactive', 'active'], 'type': 'str'},
                        'switching-packet': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'owner-vdom': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'poe-pre-standard-detection': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pre-provisioned': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'sn': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'snmp-sysinfo': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'contact-info': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'description': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'engine-id': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'location': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'snmp-trap-threshold': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'trap-high-cpu-threshold': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'trap-log-full-threshold': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'trap-low-memory-threshold': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'}
                    }
                },
                'staged-image-version': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'static-mac': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'description': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'mac': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'type': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['static', 'sticky'], 'type': 'str'},
                        'vlan': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                },
                'storm-control': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'broadcast': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-override': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rate': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'unknown-multicast': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'unknown-unicast': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'stp-instance': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'priority': {
                            'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': [
                                '0', '4096', '8192', '12288', '12328', '16384', '20480', '24576', '28672', '32768', '36864', '40960', '45056', '49152',
                                '53248', '57344', '61440'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'stp-settings': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'forward-time': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'hello-time': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'local-override': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-age': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'max-hops': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'pending-timer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'revision': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'switch-device-tag': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'switch-log': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'local-override': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'severity': {
                            'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'switch-profile': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'type': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['physical', 'virtual'], 'type': 'str'},
                'version': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'poe-lldp-detection': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_managedswitch'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
