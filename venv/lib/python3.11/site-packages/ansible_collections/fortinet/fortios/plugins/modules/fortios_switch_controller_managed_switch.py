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
module: fortios_switch_controller_managed_switch
short_description: Configure FortiSwitch devices that are managed by this FortiGate in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify switch_controller feature and managed_switch category.
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

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    switch_controller_managed_switch:
        description:
            - Configure FortiSwitch devices that are managed by this FortiGate.
        default: null
        type: dict
        suboptions:
            settings_802_1X:
                description:
                    - Configuration method to edit FortiSwitch 802.1X global settings.
                type: dict
                suboptions:
                    link_down_auth:
                        description:
                            - Authentication state to set if a link is down.
                        type: str
                        choices:
                            - 'set-unauth'
                            - 'no-action'
                    local_override:
                        description:
                            - Enable to override global 802.1X settings on individual FortiSwitches.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    mab_reauth:
                        description:
                            - Enable or disable MAB reauthentication settings.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    mac_called_station_delimiter:
                        description:
                            - MAC called station delimiter .
                        type: str
                        choices:
                            - 'colon'
                            - 'hyphen'
                            - 'none'
                            - 'single-hyphen'
                    mac_calling_station_delimiter:
                        description:
                            - MAC calling station delimiter .
                        type: str
                        choices:
                            - 'colon'
                            - 'hyphen'
                            - 'none'
                            - 'single-hyphen'
                    mac_case:
                        description:
                            - MAC case .
                        type: str
                        choices:
                            - 'lowercase'
                            - 'uppercase'
                    mac_password_delimiter:
                        description:
                            - MAC authentication password delimiter .
                        type: str
                        choices:
                            - 'colon'
                            - 'hyphen'
                            - 'none'
                            - 'single-hyphen'
                    mac_username_delimiter:
                        description:
                            - MAC authentication username delimiter .
                        type: str
                        choices:
                            - 'colon'
                            - 'hyphen'
                            - 'none'
                            - 'single-hyphen'
                    max_reauth_attempt:
                        description:
                            - Maximum number of authentication attempts (0 - 15).
                        type: int
                    reauth_period:
                        description:
                            - Reauthentication time interval (1 - 1440 min).
                        type: int
                    tx_period:
                        description:
                            - 802.1X Tx period (seconds).
                        type: int
            access_profile:
                description:
                    - FortiSwitch access profile. Source switch-controller.security-policy.local-access.name.
                type: str
            custom_command:
                description:
                    - Configuration method to edit FortiSwitch commands to be pushed to this FortiSwitch device upon rebooting the FortiGate switch controller
                       or the FortiSwitch.
                type: list
                elements: dict
                suboptions:
                    command_entry:
                        description:
                            - List of FortiSwitch commands.
                        required: true
                        type: str
                    command_name:
                        description:
                            - Names of commands to be pushed to this FortiSwitch device, as configured under config switch-controller custom-command. Source
                               switch-controller.custom-command.command-name.
                        type: str
            delayed_restart_trigger:
                description:
                    - Delayed restart triggered for this FortiSwitch.
                type: int
            description:
                description:
                    - Description.
                type: str
            dhcp_server_access_list:
                description:
                    - DHCP snooping server access list.
                type: str
                choices:
                    - 'global'
                    - 'enable'
                    - 'disable'
            dhcp_snooping_static_client:
                description:
                    - Configure FortiSwitch DHCP snooping static clients.
                type: list
                elements: dict
                suboptions:
                    ip:
                        description:
                            - Client static IP address.
                        type: str
                    mac:
                        description:
                            - Client MAC address.
                        type: str
                    name:
                        description:
                            - Client name.
                        required: true
                        type: str
                    port:
                        description:
                            - Interface name.
                        type: str
                    vlan:
                        description:
                            - VLAN name. Source system.interface.name.
                        type: str
            directly_connected:
                description:
                    - Directly connected FortiSwitch.
                type: int
            dynamic_capability:
                description:
                    - List of features this FortiSwitch supports (not configurable) that is sent to the FortiGate device for subsequent configuration
                       initiated by the FortiGate device.
                type: str
            dynamically_discovered:
                description:
                    - Dynamically discovered FortiSwitch.
                type: int
            firmware_provision:
                description:
                    - Enable/disable provisioning of firmware to FortiSwitches on join connection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            firmware_provision_latest:
                description:
                    - Enable/disable one-time automatic provisioning of the latest firmware version.
                type: str
                choices:
                    - 'disable'
                    - 'once'
            firmware_provision_version:
                description:
                    - Firmware version to provision to this FortiSwitch on bootup (major.minor.build, i.e. 6.2.1234).
                type: str
            flow_identity:
                description:
                    - Flow-tracking netflow ipfix switch identity in hex format(00000000-FFFFFFFF ).
                type: str
            fsw_wan1_admin:
                description:
                    - FortiSwitch WAN1 admin status; enable to authorize the FortiSwitch as a managed switch.
                type: str
                choices:
                    - 'discovered'
                    - 'disable'
                    - 'enable'
            fsw_wan1_peer:
                description:
                    - FortiSwitch WAN1 peer port. Source system.interface.name.
                type: str
            fsw_wan2_admin:
                description:
                    - FortiSwitch WAN2 admin status; enable to authorize the FortiSwitch as a managed switch.
                type: str
                choices:
                    - 'discovered'
                    - 'disable'
                    - 'enable'
            fsw_wan2_peer:
                description:
                    - FortiSwitch WAN2 peer port.
                type: str
            igmp_snooping:
                description:
                    - Configure FortiSwitch IGMP snooping global settings.
                type: dict
                suboptions:
                    aging_time:
                        description:
                            - Maximum time to retain a multicast snooping entry for which no packets have been seen (15 - 3600 sec).
                        type: int
                    flood_unknown_multicast:
                        description:
                            - Enable/disable unknown multicast flooding.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    local_override:
                        description:
                            - Enable/disable overriding the global IGMP snooping configuration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    vlans:
                        description:
                            - Configure IGMP snooping VLAN.
                        type: list
                        elements: dict
                        suboptions:
                            proxy:
                                description:
                                    - IGMP snooping proxy for the VLAN interface.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                                    - 'global'
                            querier:
                                description:
                                    - Enable/disable IGMP snooping querier for the VLAN interface.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            querier_addr:
                                description:
                                    - IGMP snooping querier address.
                                type: str
                            version:
                                description:
                                    - IGMP snooping querying version.
                                type: int
                            vlan_name:
                                description:
                                    - List of FortiSwitch VLANs. Source system.interface.name.
                                required: true
                                type: str
            ip_source_guard:
                description:
                    - IP source guard.
                type: list
                elements: dict
                suboptions:
                    binding_entry:
                        description:
                            - IP and MAC address configuration.
                        type: list
                        elements: dict
                        suboptions:
                            entry_name:
                                description:
                                    - Configure binding pair.
                                required: true
                                type: str
                            ip:
                                description:
                                    - Source IP for this rule.
                                type: str
                            mac:
                                description:
                                    - MAC address for this rule.
                                type: str
                    description:
                        description:
                            - Description.
                        type: str
                    port:
                        description:
                            - Ingress interface to which source guard is bound.
                        required: true
                        type: str
            l3_discovered:
                description:
                    - Layer 3 management discovered.
                type: int
            max_allowed_trunk_members:
                description:
                    - FortiSwitch maximum allowed trunk members.
                type: int
            mclag_igmp_snooping_aware:
                description:
                    - Enable/disable MCLAG IGMP-snooping awareness.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mgmt_mode:
                description:
                    - FortiLink management mode.
                type: int
            mirror:
                description:
                    - Configuration method to edit FortiSwitch packet mirror.
                type: list
                elements: dict
                suboptions:
                    dst:
                        description:
                            - Destination port.
                        type: str
                    name:
                        description:
                            - Mirror name.
                        required: true
                        type: str
                    src_egress:
                        description:
                            - Source egress interfaces.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Interface name.
                                required: true
                                type: str
                    src_ingress:
                        description:
                            - Source ingress interfaces.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Interface name.
                                required: true
                                type: str
                    status:
                        description:
                            - Active/inactive mirror configuration.
                        type: str
                        choices:
                            - 'active'
                            - 'inactive'
                    switching_packet:
                        description:
                            - Enable/disable switching functionality when mirroring.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            name:
                description:
                    - Managed-switch name.
                type: str
            override_snmp_community:
                description:
                    - Enable/disable overriding the global SNMP communities.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            override_snmp_sysinfo:
                description:
                    - Enable/disable overriding the global SNMP system information.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            override_snmp_trap_threshold:
                description:
                    - Enable/disable overriding the global SNMP trap threshold values.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            override_snmp_user:
                description:
                    - Enable/disable overriding the global SNMP users.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            owner_vdom:
                description:
                    - VDOM which owner of port belongs to.
                type: str
            poe_detection_type:
                description:
                    - PoE detection type for FortiSwitch.
                type: int
            poe_lldp_detection:
                description:
                    - Enable/disable PoE LLDP detection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            poe_pre_standard_detection:
                description:
                    - Enable/disable PoE pre-standard detection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ports:
                description:
                    - Managed-switch port list.
                type: list
                elements: dict
                suboptions:
                    access_mode:
                        description:
                            - Access mode of the port.
                        type: str
                        choices:
                            - 'dynamic'
                            - 'nac'
                            - 'static'
                            - 'normal'
                    acl_group:
                        description:
                            - ACL groups on this port.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - ACL group name. Source switch-controller.acl.group.name.
                                required: true
                                type: str
                    aggregator_mode:
                        description:
                            - LACP member select mode.
                        type: str
                        choices:
                            - 'bandwidth'
                            - 'count'
                    allow_arp_monitor:
                        description:
                            - Enable/Disable allow ARP monitor.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    allowed_vlans:
                        description:
                            - Configure switch port tagged VLANs.
                        type: list
                        elements: dict
                        suboptions:
                            vlan_name:
                                description:
                                    - VLAN name. Source system.interface.name.
                                required: true
                                type: str
                    allowed_vlans_all:
                        description:
                            - Enable/disable all defined vlans on this port.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    arp_inspection_trust:
                        description:
                            - Trusted or untrusted dynamic ARP inspection.
                        type: str
                        choices:
                            - 'untrusted'
                            - 'trusted'
                    bundle:
                        description:
                            - Enable/disable Link Aggregation Group (LAG) bundling for non-FortiLink interfaces.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    description:
                        description:
                            - Description for port.
                        type: str
                    dhcp_snoop_option82_override:
                        description:
                            - Configure DHCP snooping option 82 override.
                        type: list
                        elements: dict
                        suboptions:
                            circuit_id:
                                description:
                                    - Circuit ID string.
                                type: str
                            remote_id:
                                description:
                                    - Remote ID string.
                                type: str
                            vlan_name:
                                description:
                                    - DHCP snooping option 82 VLAN. Source system.interface.name.
                                required: true
                                type: str
                    dhcp_snoop_option82_trust:
                        description:
                            - Enable/disable allowance of DHCP with option-82 on untrusted interface.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    dhcp_snooping:
                        description:
                            - Trusted or untrusted DHCP-snooping interface.
                        type: str
                        choices:
                            - 'untrusted'
                            - 'trusted'
                    discard_mode:
                        description:
                            - Configure discard mode for port.
                        type: str
                        choices:
                            - 'none'
                            - 'all-untagged'
                            - 'all-tagged'
                    edge_port:
                        description:
                            - Enable/disable this interface as an edge port, bridging connections between workstations and/or computers.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    export_tags:
                        description:
                            - Configure export tag(s) for FortiSwitch port when exported to a virtual port pool.
                        type: list
                        elements: dict
                        suboptions:
                            tag_name:
                                description:
                                    - FortiSwitch port tag name when exported to a virtual port pool. Source switch-controller.switch-interface-tag.name.
                                required: true
                                type: str
                    export_to:
                        description:
                            - Export managed-switch port to a tenant VDOM. Source system.vdom.name.
                        type: str
                    export_to_pool:
                        description:
                            - Switch controller export port to pool-list. Source switch-controller.virtual-port-pool.name.
                        type: str
                    export_to_pool_flag:
                        description:
                            - Switch controller export port to pool-list.
                        type: int
                    fallback_port:
                        description:
                            - LACP fallback port.
                        type: str
                    fec_capable:
                        description:
                            - FEC capable.
                        type: int
                    fec_state:
                        description:
                            - State of forward error correction.
                        type: str
                        choices:
                            - 'disabled'
                            - 'cl74'
                            - 'cl91'
                            - 'detect-by-module'
                    fgt_peer_device_name:
                        description:
                            - FGT peer device name.
                        type: str
                    fgt_peer_port_name:
                        description:
                            - FGT peer port name.
                        type: str
                    fiber_port:
                        description:
                            - Fiber-port.
                        type: int
                    flags:
                        description:
                            - Port properties flags.
                        type: int
                    flap_duration:
                        description:
                            - Period over which flap events are calculated (seconds).
                        type: int
                    flap_rate:
                        description:
                            - Number of stage change events needed within flap-duration.
                        type: int
                    flap_timeout:
                        description:
                            - Flap guard disabling protection (min).
                        type: int
                    flapguard:
                        description:
                            - Enable/disable flap guard.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    flow_control:
                        description:
                            - Flow control direction.
                        type: str
                        choices:
                            - 'disable'
                            - 'tx'
                            - 'rx'
                            - 'both'
                    fortilink_port:
                        description:
                            - FortiLink uplink port.
                        type: int
                    fortiswitch_acls:
                        description:
                            - ACLs on this port.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - ACL ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                    igmp_snooping:
                        description:
                            - Set IGMP snooping mode for the physical port interface.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    igmp_snooping_flood_reports:
                        description:
                            - Enable/disable flooding of IGMP reports to this interface when igmp-snooping enabled.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    igmps_flood_reports:
                        description:
                            - Enable/disable flooding of IGMP reports to this interface when igmp-snooping enabled.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    igmps_flood_traffic:
                        description:
                            - Enable/disable flooding of IGMP snooping traffic to this interface.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    interface_tags:
                        description:
                            - Tag(s) associated with the interface for various features including virtual port pool, dynamic port policy.
                        type: list
                        elements: dict
                        suboptions:
                            tag_name:
                                description:
                                    - FortiSwitch port tag name when exported to a virtual port pool or matched to dynamic port policy. Source
                                       switch-controller.switch-interface-tag.name.
                                required: true
                                type: str
                    ip_source_guard:
                        description:
                            - Enable/disable IP source guard.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    isl_local_trunk_name:
                        description:
                            - ISL local trunk name.
                        type: str
                    isl_peer_device_name:
                        description:
                            - ISL peer device name.
                        type: str
                    isl_peer_port_name:
                        description:
                            - ISL peer port name.
                        type: str
                    lacp_speed:
                        description:
                            - End Link Aggregation Control Protocol (LACP) messages every 30 seconds (slow) or every second (fast).
                        type: str
                        choices:
                            - 'slow'
                            - 'fast'
                    learning_limit:
                        description:
                            - Limit the number of dynamic MAC addresses on this Port (1 - 128, 0 = no limit, default).
                        type: int
                    lldp_profile:
                        description:
                            - LLDP port TLV profile. Source switch-controller.lldp-profile.name.
                        type: str
                    lldp_status:
                        description:
                            - LLDP transmit and receive status.
                        type: str
                        choices:
                            - 'disable'
                            - 'rx-only'
                            - 'tx-only'
                            - 'tx-rx'
                    log_mac_event:
                        description:
                            - Enable/disable logging for dynamic MAC address events.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    loop_guard:
                        description:
                            - Enable/disable loop-guard on this interface, an STP optimization used to prevent network loops.
                        type: str
                        choices:
                            - 'enabled'
                            - 'disabled'
                    loop_guard_timeout:
                        description:
                            - Loop-guard timeout (0 - 120 min).
                        type: int
                    mac_addr:
                        description:
                            - Port/Trunk MAC.
                        type: str
                    matched_dpp_intf_tags:
                        description:
                            - Matched interface tags in the dynamic port policy.
                        type: str
                    matched_dpp_policy:
                        description:
                            - Matched child policy in the dynamic port policy.
                        type: str
                    max_bundle:
                        description:
                            - Maximum size of LAG bundle (1 - 24).
                        type: int
                    mcast_snooping_flood_traffic:
                        description:
                            - Enable/disable flooding of IGMP snooping traffic to this interface.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    mclag:
                        description:
                            - Enable/disable multi-chassis link aggregation (MCLAG).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    mclag_icl_port:
                        description:
                            - MCLAG-ICL port.
                        type: int
                    media_type:
                        description:
                            - Media type.
                        type: str
                    member_withdrawal_behavior:
                        description:
                            - Port behavior after it withdraws because of loss of control packets.
                        type: str
                        choices:
                            - 'forward'
                            - 'block'
                    members:
                        description:
                            - Aggregated LAG bundle interfaces.
                        type: list
                        elements: dict
                        suboptions:
                            member_name:
                                description:
                                    - Interface name from available options.
                                required: true
                                type: str
                    min_bundle:
                        description:
                            - Minimum size of LAG bundle (1 - 24).
                        type: int
                    mode:
                        description:
                            - 'LACP mode: ignore and do not send control messages, or negotiate 802.3ad aggregation passively or actively.'
                        type: str
                        choices:
                            - 'static'
                            - 'lacp-passive'
                            - 'lacp-active'
                    p2p_port:
                        description:
                            - General peer to peer tunnel port.
                        type: int
                    packet_sample_rate:
                        description:
                            - Packet sampling rate (0 - 99999 p/sec).
                        type: int
                    packet_sampler:
                        description:
                            - Enable/disable packet sampling on this interface.
                        type: str
                        choices:
                            - 'enabled'
                            - 'disabled'
                    pause_meter:
                        description:
                            - Configure ingress pause metering rate, in kbps .
                        type: int
                    pause_meter_resume:
                        description:
                            - Resume threshold for resuming traffic on ingress port.
                        type: str
                        choices:
                            - '75%'
                            - '50%'
                            - '25%'
                    pd_capable:
                        description:
                            - Powered device capable.
                        type: int
                    poe_capable:
                        description:
                            - PoE capable.
                        type: int
                    poe_max_power:
                        description:
                            - PoE maximum power.
                        type: str
                    poe_mode_bt_cabable:
                        description:
                            - PoE mode IEEE 802.3BT capable.
                        type: int
                    poe_port_mode:
                        description:
                            - Configure PoE port mode.
                        type: str
                        choices:
                            - 'ieee802-3af'
                            - 'ieee802-3at'
                            - 'ieee802-3bt'
                    poe_port_power:
                        description:
                            - Configure PoE port power.
                        type: str
                        choices:
                            - 'normal'
                            - 'perpetual'
                            - 'perpetual-fast'
                    poe_port_priority:
                        description:
                            - Configure PoE port priority.
                        type: str
                        choices:
                            - 'critical-priority'
                            - 'high-priority'
                            - 'low-priority'
                            - 'medium-priority'
                    poe_pre_standard_detection:
                        description:
                            - Enable/disable PoE pre-standard detection.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    poe_standard:
                        description:
                            - PoE standard supported.
                        type: str
                    poe_status:
                        description:
                            - Enable/disable PoE status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    port_name:
                        description:
                            - Switch port name.
                        required: true
                        type: str
                    port_number:
                        description:
                            - Port number.
                        type: int
                    port_owner:
                        description:
                            - Switch port name.
                        type: str
                    port_policy:
                        description:
                            - Switch controller dynamic port policy from available options. Source switch-controller.dynamic-port-policy.name.
                        type: str
                    port_prefix_type:
                        description:
                            - Port prefix type.
                        type: int
                    port_security_policy:
                        description:
                            - Switch controller authentication policy to apply to this managed switch from available options. Source switch-controller
                              .security-policy.802-1X.name.
                        type: str
                    port_selection_criteria:
                        description:
                            - Algorithm for aggregate port selection.
                        type: str
                        choices:
                            - 'src-mac'
                            - 'dst-mac'
                            - 'src-dst-mac'
                            - 'src-ip'
                            - 'dst-ip'
                            - 'src-dst-ip'
                    ptp_policy:
                        description:
                            - PTP policy configuration. Source switch-controller.ptp.interface-policy.name.
                        type: str
                    ptp_status:
                        description:
                            - Enable/disable PTP policy on this FortiSwitch port.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    qnq:
                        description:
                            - 802.1AD VLANs in the VDom. Source system.interface.name.
                        type: str
                    qos_policy:
                        description:
                            - Switch controller QoS policy from available options. Source switch-controller.qos.qos-policy.name.
                        type: str
                    rpvst_port:
                        description:
                            - Enable/disable inter-operability with rapid PVST on this interface.
                        type: str
                        choices:
                            - 'disabled'
                            - 'enabled'
                    sample_direction:
                        description:
                            - Packet sampling direction.
                        type: str
                        choices:
                            - 'tx'
                            - 'rx'
                            - 'both'
                    sflow_counter_interval:
                        description:
                            - sFlow sampling counter polling interval in seconds (0 - 255).
                        type: int
                    sflow_sample_rate:
                        description:
                            - sFlow sampler sample rate (0 - 99999 p/sec).
                        type: int
                    sflow_sampler:
                        description:
                            - Enable/disable sFlow protocol on this interface.
                        type: str
                        choices:
                            - 'enabled'
                            - 'disabled'
                    speed:
                        description:
                            - Switch port speed; default and available settings depend on hardware.
                        type: str
                        choices:
                            - '10half'
                            - '10full'
                            - '100half'
                            - '100full'
                            - '1000full'
                            - '10000full'
                            - 'auto'
                            - '1000auto'
                            - '1000full-fiber'
                            - '40000full'
                            - 'auto-module'
                            - '100FX-half'
                            - '100FX-full'
                            - '100000full'
                            - '2500auto'
                            - '2500full'
                            - '25000full'
                            - '50000full'
                            - '10000cr'
                            - '10000sr'
                            - '100000sr4'
                            - '100000cr4'
                            - '40000sr4'
                            - '40000cr4'
                            - '40000auto'
                            - '25000cr'
                            - '25000sr'
                            - '50000cr'
                            - '50000sr'
                            - '5000auto'
                            - '1000fiber'
                            - '10000'
                            - '40000'
                            - '25000cr4'
                            - '25000sr4'
                            - '5000full'
                    speed_mask:
                        description:
                            - Switch port speed mask.
                        type: int
                    stacking_port:
                        description:
                            - Stacking port.
                        type: int
                    status:
                        description:
                            - 'Switch port admin status: up or down.'
                        type: str
                        choices:
                            - 'up'
                            - 'down'
                    sticky_mac:
                        description:
                            - Enable or disable sticky-mac on the interface.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    storm_control_policy:
                        description:
                            - Switch controller storm control policy from available options. Source switch-controller.storm-control-policy.name.
                        type: str
                    stp_bpdu_guard:
                        description:
                            - Enable/disable STP BPDU guard on this interface.
                        type: str
                        choices:
                            - 'enabled'
                            - 'disabled'
                    stp_bpdu_guard_timeout:
                        description:
                            - BPDU Guard disabling protection (0 - 120 min).
                        type: int
                    stp_root_guard:
                        description:
                            - Enable/disable STP root guard on this interface.
                        type: str
                        choices:
                            - 'enabled'
                            - 'disabled'
                    stp_state:
                        description:
                            - Enable/disable Spanning Tree Protocol (STP) on this interface.
                        type: str
                        choices:
                            - 'enabled'
                            - 'disabled'
                    switch_id:
                        description:
                            - Switch id.
                        type: str
                    type:
                        description:
                            - 'Interface type: physical or trunk port.'
                        type: str
                        choices:
                            - 'physical'
                            - 'trunk'
                    untagged_vlans:
                        description:
                            - Configure switch port untagged VLANs.
                        type: list
                        elements: dict
                        suboptions:
                            vlan_name:
                                description:
                                    - VLAN name. Source system.interface.name.
                                required: true
                                type: str
                    virtual_port:
                        description:
                            - Virtualized switch port.
                        type: int
                    vlan:
                        description:
                            - Assign switch ports to a VLAN. Source system.interface.name.
                        type: str
            pre_provisioned:
                description:
                    - Pre-provisioned managed switch.
                type: int
            ptp_profile:
                description:
                    - PTP profile configuration. Source switch-controller.ptp.profile.name.
                type: str
            ptp_status:
                description:
                    - Enable/disable PTP profile on this FortiSwitch.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            purdue_level:
                description:
                    - Purdue Level of this FortiSwitch.
                type: str
                choices:
                    - '1'
                    - '1.5'
                    - '2'
                    - '2.5'
                    - '3'
                    - '3.5'
                    - '4'
                    - '5'
                    - '5.5'
            qos_drop_policy:
                description:
                    - Set QoS drop-policy.
                type: str
                choices:
                    - 'taildrop'
                    - 'random-early-detection'
            qos_red_probability:
                description:
                    - Set QoS RED/WRED drop probability.
                type: int
            radius_nas_ip:
                description:
                    - NAS-IP address.
                type: str
            radius_nas_ip_override:
                description:
                    - Use locally defined NAS-IP.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            remote_log:
                description:
                    - Configure logging by FortiSwitch device to a remote syslog server.
                type: list
                elements: dict
                suboptions:
                    csv:
                        description:
                            - Enable/disable comma-separated value (CSV) strings.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    facility:
                        description:
                            - Facility to log to remote syslog server.
                        type: str
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
                        description:
                            - Remote log name.
                        required: true
                        type: str
                    port:
                        description:
                            - Remote syslog server listening port.
                        type: int
                    server:
                        description:
                            - IPv4 address of the remote syslog server.
                        type: str
                    severity:
                        description:
                            - Severity of logs to be transferred to remote log server.
                        type: str
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
                        description:
                            - Enable/disable logging by FortiSwitch device to a remote syslog server.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            route_offload:
                description:
                    - Enable/disable route offload on this FortiSwitch.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            route_offload_mclag:
                description:
                    - Enable/disable route offload MCLAG on this FortiSwitch.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            route_offload_router:
                description:
                    - Configure route offload MCLAG IP address.
                type: list
                elements: dict
                suboptions:
                    router_ip:
                        description:
                            - Router IP address.
                        type: str
                    vlan_name:
                        description:
                            - VLAN name. Source system.interface.name.
                        required: true
                        type: str
            router_static:
                description:
                    - Configure static routes.
                type: list
                elements: dict
                suboptions:
                    blackhole:
                        description:
                            - Enable/disable blackhole on this route.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    comment:
                        description:
                            - Comment.
                        type: str
                    device:
                        description:
                            - Gateway out interface. Source switch-controller.managed-switch.system-interface.name.
                        type: str
                    distance:
                        description:
                            - Administrative distance for the route (1 - 255).
                        type: int
                    dst:
                        description:
                            - Destination ip and mask for this route.
                        type: str
                    dynamic_gateway:
                        description:
                            - Enable/disable dynamic gateway.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    gateway:
                        description:
                            - Gateway ip for this route.
                        type: str
                    id:
                        description:
                            - Entry sequence number. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    status:
                        description:
                            - Enable/disable route status.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_id:
                        description:
                            - Switch ID. Source switch-controller.managed-switch.switch-id.
                        type: str
                    vrf:
                        description:
                            - VRF for this route. Source switch-controller.managed-switch.router-vrf.name.
                        type: str
            router_vrf:
                description:
                    - Configure VRF.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - VRF entry name.
                        required: true
                        type: str
                    switch_id:
                        description:
                            - Switch ID. Source switch-controller.managed-switch.switch-id.
                        type: str
                    vrfid:
                        description:
                            - VRF ID.
                        type: int
            sn:
                description:
                    - Managed-switch serial number.
                type: str
            snmp_community:
                description:
                    - Configuration method to edit Simple Network Management Protocol (SNMP) communities.
                type: list
                elements: dict
                suboptions:
                    events:
                        description:
                            - SNMP notifications (traps) to send.
                        type: list
                        elements: str
                        choices:
                            - 'cpu-high'
                            - 'mem-low'
                            - 'log-full'
                            - 'intf-ip'
                            - 'ent-conf-change'
                            - 'l2mac'
                    hosts:
                        description:
                            - Configure IPv4 SNMP managers (hosts).
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Host entry ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            ip:
                                description:
                                    - IPv4 address of the SNMP manager (host).
                                type: str
                    id:
                        description:
                            - SNMP community ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    name:
                        description:
                            - SNMP community name.
                        type: str
                    query_v1_port:
                        description:
                            - SNMP v1 query port .
                        type: int
                    query_v1_status:
                        description:
                            - Enable/disable SNMP v1 queries.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    query_v2c_port:
                        description:
                            - SNMP v2c query port .
                        type: int
                    query_v2c_status:
                        description:
                            - Enable/disable SNMP v2c queries.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        description:
                            - Enable/disable this SNMP community.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    trap_v1_lport:
                        description:
                            - SNMP v2c trap local port .
                        type: int
                    trap_v1_rport:
                        description:
                            - SNMP v2c trap remote port .
                        type: int
                    trap_v1_status:
                        description:
                            - Enable/disable SNMP v1 traps.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    trap_v2c_lport:
                        description:
                            - SNMP v2c trap local port .
                        type: int
                    trap_v2c_rport:
                        description:
                            - SNMP v2c trap remote port .
                        type: int
                    trap_v2c_status:
                        description:
                            - Enable/disable SNMP v2c traps.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            snmp_sysinfo:
                description:
                    - Configuration method to edit Simple Network Management Protocol (SNMP) system info.
                type: dict
                suboptions:
                    contact_info:
                        description:
                            - Contact information.
                        type: str
                    description:
                        description:
                            - System description.
                        type: str
                    engine_id:
                        description:
                            - Local SNMP engine ID string (max 24 char).
                        type: str
                    location:
                        description:
                            - System location.
                        type: str
                    status:
                        description:
                            - Enable/disable SNMP.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            snmp_trap_threshold:
                description:
                    - Configuration method to edit Simple Network Management Protocol (SNMP) trap threshold values.
                type: dict
                suboptions:
                    trap_high_cpu_threshold:
                        description:
                            - CPU usage when trap is sent.
                        type: int
                    trap_log_full_threshold:
                        description:
                            - Log disk usage when trap is sent.
                        type: int
                    trap_low_memory_threshold:
                        description:
                            - Memory usage when trap is sent.
                        type: int
            snmp_user:
                description:
                    - Configuration method to edit Simple Network Management Protocol (SNMP) users.
                type: list
                elements: dict
                suboptions:
                    auth_proto:
                        description:
                            - Authentication protocol.
                        type: str
                        choices:
                            - 'md5'
                            - 'sha1'
                            - 'sha224'
                            - 'sha256'
                            - 'sha384'
                            - 'sha512'
                            - 'sha'
                    auth_pwd:
                        description:
                            - Password for authentication protocol.
                        type: str
                    name:
                        description:
                            - SNMP user name.
                        required: true
                        type: str
                    priv_proto:
                        description:
                            - Privacy (encryption) protocol.
                        type: str
                        choices:
                            - 'aes128'
                            - 'aes192'
                            - 'aes192c'
                            - 'aes256'
                            - 'aes256c'
                            - 'des'
                            - 'aes'
                    priv_pwd:
                        description:
                            - Password for privacy (encryption) protocol.
                        type: str
                    queries:
                        description:
                            - Enable/disable SNMP queries for this user.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    query_port:
                        description:
                            - SNMPv3 query port .
                        type: int
                    security_level:
                        description:
                            - Security level for message authentication and encryption.
                        type: str
                        choices:
                            - 'no-auth-no-priv'
                            - 'auth-no-priv'
                            - 'auth-priv'
            staged_image_version:
                description:
                    - Staged image version for FortiSwitch.
                type: str
            static_mac:
                description:
                    - Configuration method to edit FortiSwitch Static and Sticky MAC.
                type: list
                elements: dict
                suboptions:
                    description:
                        description:
                            - Description.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    interface:
                        description:
                            - Interface name.
                        type: str
                    mac:
                        description:
                            - MAC address.
                        type: str
                    type:
                        description:
                            - Type.
                        type: str
                        choices:
                            - 'static'
                            - 'sticky'
                    vlan:
                        description:
                            - Vlan. Source system.interface.name.
                        type: str
            storm_control:
                description:
                    - Configuration method to edit FortiSwitch storm control for measuring traffic activity using data rates to prevent traffic disruption.
                type: dict
                suboptions:
                    broadcast:
                        description:
                            - Enable/disable storm control to drop broadcast traffic.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    burst_size_level:
                        description:
                            - Increase level to handle bursty traffic (0 - 4).
                        type: int
                    local_override:
                        description:
                            - Enable to override global FortiSwitch storm control settings for this FortiSwitch.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rate:
                        description:
                            - Rate in packets per second at which storm control drops excess traffic(0-10000000).
                        type: int
                    unknown_multicast:
                        description:
                            - Enable/disable storm control to drop unknown multicast traffic.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    unknown_unicast:
                        description:
                            - Enable/disable storm control to drop unknown unicast traffic.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            stp_instance:
                description:
                    - Configuration method to edit Spanning Tree Protocol (STP) instances.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Instance ID.
                        required: true
                        type: str
                    priority:
                        description:
                            - Priority.
                        type: str
                        choices:
                            - '0'
                            - '4096'
                            - '8192'
                            - '12288'
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
                description:
                    - Configuration method to edit Spanning Tree Protocol (STP) settings used to prevent bridge loops.
                type: dict
                suboptions:
                    forward_time:
                        description:
                            - Period of time a port is in listening and learning state (4 - 30 sec).
                        type: int
                    hello_time:
                        description:
                            - Period of time between successive STP frame Bridge Protocol Data Units (BPDUs) sent on a port (1 - 10 sec).
                        type: int
                    local_override:
                        description:
                            - Enable to configure local STP settings that override global STP settings.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    max_age:
                        description:
                            - Maximum time before a bridge port saves its configuration BPDU information (6 - 40 sec).
                        type: int
                    max_hops:
                        description:
                            - Maximum number of hops between the root bridge and the furthest bridge (1- 40).
                        type: int
                    name:
                        description:
                            - Name of local STP settings configuration.
                        type: str
                    pending_timer:
                        description:
                            - Pending time (1 - 15 sec).
                        type: int
                    revision:
                        description:
                            - STP revision number (0 - 65535).
                        type: int
                    status:
                        description:
                            - Enable/disable STP.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            switch_device_tag:
                description:
                    - User definable label/tag.
                type: str
            switch_dhcp_opt43_key:
                description:
                    - DHCP option43 key.
                type: str
            switch_id:
                description:
                    - Managed-switch name.
                required: true
                type: str
            switch_log:
                description:
                    - Configuration method to edit FortiSwitch logging settings (logs are transferred to and inserted into the FortiGate event log).
                type: dict
                suboptions:
                    local_override:
                        description:
                            - Enable to configure local logging settings that override global logging settings.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    severity:
                        description:
                            - Severity of FortiSwitch logs that are added to the FortiGate event log.
                        type: str
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
                        description:
                            - Enable/disable adding FortiSwitch logs to the FortiGate event log.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            switch_profile:
                description:
                    - FortiSwitch profile. Source switch-controller.switch-profile.name.
                type: str
            switch_stp_settings:
                description:
                    - Configure spanning tree protocol (STP).
                type: dict
                suboptions:
                    status:
                        description:
                            - Enable/disable STP.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            system_dhcp_server:
                description:
                    - Configure DHCP servers.
                type: list
                elements: dict
                suboptions:
                    default_gateway:
                        description:
                            - Default gateway IP address assigned by the DHCP server.
                        type: str
                    dns_server1:
                        description:
                            - DNS server 1.
                        type: str
                    dns_server2:
                        description:
                            - DNS server 2.
                        type: str
                    dns_server3:
                        description:
                            - DNS server 3.
                        type: str
                    dns_service:
                        description:
                            - Options for assigning DNS servers to DHCP clients.
                        type: str
                        choices:
                            - 'local'
                            - 'default'
                            - 'specify'
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    interface:
                        description:
                            - DHCP server can assign IP configurations to clients connected to this interface. Source switch-controller.managed-switch
                              .system-interface.name.
                        type: str
                    ip_range:
                        description:
                            - DHCP IP range configuration.
                        type: list
                        elements: dict
                        suboptions:
                            end_ip:
                                description:
                                    - End of IP range.
                                type: str
                            id:
                                description:
                                    - ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            start_ip:
                                description:
                                    - Start of IP range.
                                type: str
                    lease_time:
                        description:
                            - Lease time in seconds, 0 means unlimited.
                        type: int
                    netmask:
                        description:
                            - Netmask assigned by the DHCP server.
                        type: str
                    ntp_server1:
                        description:
                            - NTP server 1.
                        type: str
                    ntp_server2:
                        description:
                            - NTP server 2.
                        type: str
                    ntp_server3:
                        description:
                            - NTP server 3.
                        type: str
                    ntp_service:
                        description:
                            - Options for assigning Network Time Protocol (NTP) servers to DHCP clients.
                        type: str
                        choices:
                            - 'local'
                            - 'default'
                            - 'specify'
                    options:
                        description:
                            - DHCP options.
                        type: list
                        elements: dict
                        suboptions:
                            code:
                                description:
                                    - DHCP option code.
                                type: int
                            id:
                                description:
                                    - ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            ip:
                                description:
                                    - DHCP option IPs.
                                type: list
                                elements: str
                            type:
                                description:
                                    - DHCP option type.
                                type: str
                                choices:
                                    - 'hex'
                                    - 'string'
                                    - 'ip'
                                    - 'fqdn'
                            value:
                                description:
                                    - DHCP option value.
                                type: str
                    status:
                        description:
                            - Enable/disable this DHCP configuration.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_id:
                        description:
                            - Switch ID. Source switch-controller.managed-switch.switch-id.
                        type: str
            system_interface:
                description:
                    - Configure system interface on FortiSwitch.
                type: list
                elements: dict
                suboptions:
                    allowaccess:
                        description:
                            - Permitted types of management access to this interface.
                        type: list
                        elements: str
                        choices:
                            - 'ping'
                            - 'https'
                            - 'http'
                            - 'ssh'
                            - 'snmp'
                            - 'telnet'
                            - 'radius-acct'
                    interface:
                        description:
                            - Interface name. Source switch-controller.managed-switch.ports.port-name.
                        type: str
                    ip:
                        description:
                            - IP and mask for this interface.
                        type: str
                    mode:
                        description:
                            - Interface addressing mode.
                        type: str
                        choices:
                            - 'static'
                            - 'dhcp'
                    name:
                        description:
                            - Interface name.
                        required: true
                        type: str
                    status:
                        description:
                            - Enable/disable interface status.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_id:
                        description:
                            - Switch ID. Source switch-controller.managed-switch.switch-id.
                        type: str
                    type:
                        description:
                            - Interface type.
                        type: str
                        choices:
                            - 'vlan'
                            - 'physical'
                    vlan:
                        description:
                            - VLAN name. Source system.interface.name.
                        type: str
                    vrf:
                        description:
                            - VRF for this route. Source switch-controller.managed-switch.router-vrf.name.
                        type: str
            tdr_supported:
                description:
                    - TDR supported.
                type: str
            type:
                description:
                    - Indication of switch type, physical or virtual.
                type: str
                choices:
                    - 'virtual'
                    - 'physical'
            version:
                description:
                    - FortiSwitch version.
                type: int
            vlan:
                description:
                    - Configure VLAN assignment priority.
                type: list
                elements: dict
                suboptions:
                    assignment_priority:
                        description:
                            - 802.1x Radius (Tunnel-Private-Group-Id) VLANID assign-by-name priority. A smaller value has a higher priority.
                        type: int
                    vlan_name:
                        description:
                            - VLAN name. Source system.interface.name.
                        required: true
                        type: str
"""

EXAMPLES = """
- name: Configure FortiSwitch devices that are managed by this FortiGate.
  fortinet.fortios.fortios_switch_controller_managed_switch:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      switch_controller_managed_switch:
          settings_802_1X:
              link_down_auth: "set-unauth"
              local_override: "enable"
              mab_reauth: "disable"
              mac_called_station_delimiter: "colon"
              mac_calling_station_delimiter: "colon"
              mac_case: "lowercase"
              mac_password_delimiter: "colon"
              mac_username_delimiter: "colon"
              max_reauth_attempt: "3"
              reauth_period: "60"
              tx_period: "30"
          access_profile: "<your_own_value> (source switch-controller.security-policy.local-access.name)"
          custom_command:
              -
                  command_entry: "<your_own_value>"
                  command_name: "<your_own_value> (source switch-controller.custom-command.command-name)"
          delayed_restart_trigger: "0"
          description: "<your_own_value>"
          dhcp_server_access_list: "global"
          dhcp_snooping_static_client:
              -
                  ip: "<your_own_value>"
                  mac: "<your_own_value>"
                  name: "default_name_25"
                  port: "<your_own_value>"
                  vlan: "<your_own_value> (source system.interface.name)"
          directly_connected: "0"
          dynamic_capability: "<your_own_value>"
          dynamically_discovered: "0"
          firmware_provision: "enable"
          firmware_provision_latest: "disable"
          firmware_provision_version: "<your_own_value>"
          flow_identity: "<your_own_value>"
          fsw_wan1_admin: "discovered"
          fsw_wan1_peer: "<your_own_value> (source system.interface.name)"
          fsw_wan2_admin: "discovered"
          fsw_wan2_peer: "<your_own_value>"
          igmp_snooping:
              aging_time: "300"
              flood_unknown_multicast: "enable"
              local_override: "enable"
              vlans:
                  -
                      proxy: "disable"
                      querier: "disable"
                      querier_addr: "<your_own_value>"
                      version: "2"
                      vlan_name: "<your_own_value> (source system.interface.name)"
          ip_source_guard:
              -
                  binding_entry:
                      -
                          entry_name: "<your_own_value>"
                          ip: "<your_own_value>"
                          mac: "<your_own_value>"
                  description: "<your_own_value>"
                  port: "<your_own_value>"
          l3_discovered: "0"
          max_allowed_trunk_members: "0"
          mclag_igmp_snooping_aware: "enable"
          mgmt_mode: "0"
          mirror:
              -
                  dst: "<your_own_value>"
                  name: "default_name_62"
                  src_egress:
                      -
                          name: "default_name_64"
                  src_ingress:
                      -
                          name: "default_name_66"
                  status: "active"
                  switching_packet: "enable"
          name: "default_name_69"
          override_snmp_community: "enable"
          override_snmp_sysinfo: "disable"
          override_snmp_trap_threshold: "enable"
          override_snmp_user: "enable"
          owner_vdom: "<your_own_value>"
          poe_detection_type: "0"
          poe_lldp_detection: "enable"
          poe_pre_standard_detection: "enable"
          ports:
              -
                  access_mode: "dynamic"
                  acl_group:
                      -
                          name: "default_name_81 (source switch-controller.acl.group.name)"
                  aggregator_mode: "bandwidth"
                  allow_arp_monitor: "disable"
                  allowed_vlans:
                      -
                          vlan_name: "<your_own_value> (source system.interface.name)"
                  allowed_vlans_all: "enable"
                  arp_inspection_trust: "untrusted"
                  bundle: "enable"
                  description: "<your_own_value>"
                  dhcp_snoop_option82_override:
                      -
                          circuit_id: "<your_own_value>"
                          remote_id: "<your_own_value>"
                          vlan_name: "<your_own_value> (source system.interface.name)"
                  dhcp_snoop_option82_trust: "enable"
                  dhcp_snooping: "untrusted"
                  discard_mode: "none"
                  edge_port: "enable"
                  export_tags:
                      -
                          tag_name: "<your_own_value> (source switch-controller.switch-interface-tag.name)"
                  export_to: "<your_own_value> (source system.vdom.name)"
                  export_to_pool: "<your_own_value> (source switch-controller.virtual-port-pool.name)"
                  export_to_pool_flag: "0"
                  fallback_port: "<your_own_value>"
                  fec_capable: "0"
                  fec_state: "disabled"
                  fgt_peer_device_name: "<your_own_value>"
                  fgt_peer_port_name: "<your_own_value>"
                  fiber_port: "0"
                  flags: "0"
                  flap_duration: "30"
                  flap_rate: "5"
                  flap_timeout: "0"
                  flapguard: "enable"
                  flow_control: "disable"
                  fortilink_port: "0"
                  fortiswitch_acls:
                      -
                          id: "117"
                  igmp_snooping: "enable"
                  igmp_snooping_flood_reports: "enable"
                  igmps_flood_reports: "enable"
                  igmps_flood_traffic: "enable"
                  interface_tags:
                      -
                          tag_name: "<your_own_value> (source switch-controller.switch-interface-tag.name)"
                  ip_source_guard: "disable"
                  isl_local_trunk_name: "<your_own_value>"
                  isl_peer_device_name: "<your_own_value>"
                  isl_peer_port_name: "<your_own_value>"
                  lacp_speed: "slow"
                  learning_limit: "0"
                  lldp_profile: "<your_own_value> (source switch-controller.lldp-profile.name)"
                  lldp_status: "disable"
                  log_mac_event: "disable"
                  loop_guard: "enabled"
                  loop_guard_timeout: "45"
                  mac_addr: "<your_own_value>"
                  matched_dpp_intf_tags: "<your_own_value>"
                  matched_dpp_policy: "<your_own_value>"
                  max_bundle: "24"
                  mcast_snooping_flood_traffic: "enable"
                  mclag: "enable"
                  mclag_icl_port: "0"
                  media_type: "<your_own_value>"
                  member_withdrawal_behavior: "forward"
                  members:
                      -
                          member_name: "<your_own_value>"
                  min_bundle: "1"
                  mode: "static"
                  p2p_port: "0"
                  packet_sample_rate: "512"
                  packet_sampler: "enabled"
                  pause_meter: "0"
                  pause_meter_resume: "75%"
                  pd_capable: "0"
                  poe_capable: "0"
                  poe_max_power: "<your_own_value>"
                  poe_mode_bt_cabable: "0"
                  poe_port_mode: "ieee802-3af"
                  poe_port_power: "normal"
                  poe_port_priority: "critical-priority"
                  poe_pre_standard_detection: "enable"
                  poe_standard: "<your_own_value>"
                  poe_status: "enable"
                  port_name: "<your_own_value>"
                  port_number: "0"
                  port_owner: "<your_own_value>"
                  port_policy: "<your_own_value> (source switch-controller.dynamic-port-policy.name)"
                  port_prefix_type: "0"
                  port_security_policy: "<your_own_value> (source switch-controller.security-policy.802-1X.name)"
                  port_selection_criteria: "src-mac"
                  ptp_policy: "<your_own_value> (source switch-controller.ptp.interface-policy.name)"
                  ptp_status: "disable"
                  qnq: "<your_own_value> (source system.interface.name)"
                  qos_policy: "<your_own_value> (source switch-controller.qos.qos-policy.name)"
                  rpvst_port: "disabled"
                  sample_direction: "tx"
                  sflow_counter_interval: "0"
                  sflow_sample_rate: "49999"
                  sflow_sampler: "enabled"
                  speed: "10half"
                  speed_mask: "2147483647"
                  stacking_port: "0"
                  status: "up"
                  sticky_mac: "enable"
                  storm_control_policy: "<your_own_value> (source switch-controller.storm-control-policy.name)"
                  stp_bpdu_guard: "enabled"
                  stp_bpdu_guard_timeout: "5"
                  stp_root_guard: "enabled"
                  stp_state: "enabled"
                  switch_id: "<your_own_value>"
                  type: "physical"
                  untagged_vlans:
                      -
                          vlan_name: "<your_own_value> (source system.interface.name)"
                  virtual_port: "0"
                  vlan: "<your_own_value> (source system.interface.name)"
          pre_provisioned: "0"
          ptp_profile: "<your_own_value> (source switch-controller.ptp.profile.name)"
          ptp_status: "disable"
          purdue_level: "1"
          qos_drop_policy: "taildrop"
          qos_red_probability: "12"
          radius_nas_ip: "<your_own_value>"
          radius_nas_ip_override: "disable"
          remote_log:
              -
                  csv: "enable"
                  facility: "kernel"
                  name: "default_name_206"
                  port: "514"
                  server: "192.168.100.40"
                  severity: "emergency"
                  status: "enable"
          route_offload: "disable"
          route_offload_mclag: "disable"
          route_offload_router:
              -
                  router_ip: "<your_own_value>"
                  vlan_name: "<your_own_value> (source system.interface.name)"
          router_static:
              -
                  blackhole: "disable"
                  comment: "Comment."
                  device: "<your_own_value> (source switch-controller.managed-switch.system-interface.name)"
                  distance: "10"
                  dst: "<your_own_value>"
                  dynamic_gateway: "disable"
                  gateway: "<your_own_value>"
                  id: "224"
                  status: "disable"
                  switch_id: "<your_own_value> (source switch-controller.managed-switch.switch-id)"
                  vrf: "<your_own_value> (source switch-controller.managed-switch.router-vrf.name)"
          router_vrf:
              -
                  name: "default_name_229"
                  switch_id: "<your_own_value> (source switch-controller.managed-switch.switch-id)"
                  vrfid: "0"
          sn: "<your_own_value>"
          snmp_community:
              -
                  events: "cpu-high"
                  hosts:
                      -
                          id: "236"
                          ip: "<your_own_value>"
                  id: "238"
                  name: "default_name_239"
                  query_v1_port: "161"
                  query_v1_status: "disable"
                  query_v2c_port: "161"
                  query_v2c_status: "disable"
                  status: "disable"
                  trap_v1_lport: "162"
                  trap_v1_rport: "162"
                  trap_v1_status: "disable"
                  trap_v2c_lport: "162"
                  trap_v2c_rport: "162"
                  trap_v2c_status: "disable"
          snmp_sysinfo:
              contact_info: "<your_own_value>"
              description: "<your_own_value>"
              engine_id: "<your_own_value>"
              location: "<your_own_value>"
              status: "disable"
          snmp_trap_threshold:
              trap_high_cpu_threshold: "80"
              trap_log_full_threshold: "90"
              trap_low_memory_threshold: "80"
          snmp_user:
              -
                  auth_proto: "md5"
                  auth_pwd: "<your_own_value>"
                  name: "default_name_264"
                  priv_proto: "aes128"
                  priv_pwd: "<your_own_value>"
                  queries: "disable"
                  query_port: "161"
                  security_level: "no-auth-no-priv"
          staged_image_version: "<your_own_value>"
          static_mac:
              -
                  description: "<your_own_value>"
                  id: "273"
                  interface: "<your_own_value>"
                  mac: "<your_own_value>"
                  type: "static"
                  vlan: "<your_own_value> (source system.interface.name)"
          storm_control:
              broadcast: "enable"
              burst_size_level: "0"
              local_override: "enable"
              rate: "500"
              unknown_multicast: "enable"
              unknown_unicast: "enable"
          stp_instance:
              -
                  id: "286"
                  priority: "0"
          stp_settings:
              forward_time: "15"
              hello_time: "2"
              local_override: "enable"
              max_age: "20"
              max_hops: "20"
              name: "default_name_294"
              pending_timer: "4"
              revision: "0"
              status: "enable"
          switch_device_tag: "<your_own_value>"
          switch_dhcp_opt43_key: "<your_own_value>"
          switch_id: "<your_own_value>"
          switch_log:
              local_override: "enable"
              severity: "emergency"
              status: "enable"
          switch_profile: "<your_own_value> (source switch-controller.switch-profile.name)"
          switch_stp_settings:
              status: "enable"
          system_dhcp_server:
              -
                  default_gateway: "<your_own_value>"
                  dns_server1: "<your_own_value>"
                  dns_server2: "<your_own_value>"
                  dns_server3: "<your_own_value>"
                  dns_service: "local"
                  id: "314"
                  interface: "<your_own_value> (source switch-controller.managed-switch.system-interface.name)"
                  ip_range:
                      -
                          end_ip: "<your_own_value>"
                          id: "318"
                          start_ip: "<your_own_value>"
                  lease_time: "604800"
                  netmask: "<your_own_value>"
                  ntp_server1: "<your_own_value>"
                  ntp_server2: "<your_own_value>"
                  ntp_server3: "<your_own_value>"
                  ntp_service: "local"
                  options:
                      -
                          code: "0"
                          id: "328"
                          ip: "<your_own_value>"
                          type: "hex"
                          value: "<your_own_value>"
                  status: "disable"
                  switch_id: "<your_own_value> (source switch-controller.managed-switch.switch-id)"
          system_interface:
              -
                  allowaccess: "ping"
                  interface: "<your_own_value> (source switch-controller.managed-switch.ports.port-name)"
                  ip: "<your_own_value>"
                  mode: "static"
                  name: "default_name_339"
                  status: "disable"
                  switch_id: "<your_own_value> (source switch-controller.managed-switch.switch-id)"
                  type: "vlan"
                  vlan: "<your_own_value> (source system.interface.name)"
                  vrf: "<your_own_value> (source switch-controller.managed-switch.router-vrf.name)"
          tdr_supported: "<your_own_value>"
          type: "virtual"
          version: "0"
          vlan:
              -
                  assignment_priority: "128"
                  vlan_name: "<your_own_value> (source system.interface.name)"
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


def filter_switch_controller_managed_switch_data(json):
    option_list = [
        "settings_802_1X",
        "access_profile",
        "custom_command",
        "delayed_restart_trigger",
        "description",
        "dhcp_server_access_list",
        "dhcp_snooping_static_client",
        "directly_connected",
        "dynamic_capability",
        "dynamically_discovered",
        "firmware_provision",
        "firmware_provision_latest",
        "firmware_provision_version",
        "flow_identity",
        "fsw_wan1_admin",
        "fsw_wan1_peer",
        "fsw_wan2_admin",
        "fsw_wan2_peer",
        "igmp_snooping",
        "ip_source_guard",
        "l3_discovered",
        "max_allowed_trunk_members",
        "mclag_igmp_snooping_aware",
        "mgmt_mode",
        "mirror",
        "name",
        "override_snmp_community",
        "override_snmp_sysinfo",
        "override_snmp_trap_threshold",
        "override_snmp_user",
        "owner_vdom",
        "poe_detection_type",
        "poe_lldp_detection",
        "poe_pre_standard_detection",
        "ports",
        "pre_provisioned",
        "ptp_profile",
        "ptp_status",
        "purdue_level",
        "qos_drop_policy",
        "qos_red_probability",
        "radius_nas_ip",
        "radius_nas_ip_override",
        "remote_log",
        "route_offload",
        "route_offload_mclag",
        "route_offload_router",
        "router_static",
        "router_vrf",
        "sn",
        "snmp_community",
        "snmp_sysinfo",
        "snmp_trap_threshold",
        "snmp_user",
        "staged_image_version",
        "static_mac",
        "storm_control",
        "stp_instance",
        "stp_settings",
        "switch_device_tag",
        "switch_dhcp_opt43_key",
        "switch_id",
        "switch_log",
        "switch_profile",
        "switch_stp_settings",
        "system_dhcp_server",
        "system_interface",
        "tdr_supported",
        "type",
        "version",
        "vlan",
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
        ["snmp_community", "events"],
        ["system_interface", "allowaccess"],
        ["system_dhcp_server", "options", "ip"],
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


def valid_attr_to_invalid_attr(data):
    speciallist = {"802_1X_settings": "settings_802_1X"}

    for k, v in speciallist.items():
        if v == data:
            return k

    return data


def valid_attr_to_invalid_attrs(data):
    if isinstance(data, list):
        new_data = []
        for elem in data:
            elem = valid_attr_to_invalid_attrs(elem)
            new_data.append(elem)
        data = new_data
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[valid_attr_to_invalid_attr(k)] = valid_attr_to_invalid_attrs(v)
        data = new_data

    return valid_attr_to_invalid_attr(data)


def switch_controller_managed_switch(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    switch_controller_managed_switch_data = data["switch_controller_managed_switch"]

    filtered_data = filter_switch_controller_managed_switch_data(
        switch_controller_managed_switch_data
    )
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey(
            "switch-controller", "managed-switch", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "switch-controller", "managed-switch", vdom=vdom, mkey=mkey
        )
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
    data_copy["switch_controller_managed_switch"] = filtered_data
    fos.do_member_operation(
        "switch-controller",
        "managed-switch",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "switch-controller", "managed-switch", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "switch-controller",
            "managed-switch",
            mkey=converted_data["switch-id"],
            vdom=vdom,
        )
    else:
        fos._module.fail_json(msg="state must be present or absent!")


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


def fortios_switch_controller(data, fos, check_mode):

    if data["switch_controller_managed_switch"]:
        resp = switch_controller_managed_switch(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("switch_controller_managed_switch")
        )
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
    "type": "list",
    "elements": "dict",
    "children": {
        "switch_id": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "sn": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "description": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "switch_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "access_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "purdue_level": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [
                {"value": "1"},
                {"value": "1.5"},
                {"value": "2"},
                {"value": "2.5"},
                {"value": "3"},
                {"value": "3.5"},
                {"value": "4"},
                {"value": "5"},
                {"value": "5.5"},
            ],
        },
        "fsw_wan1_peer": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "fsw_wan1_admin": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "discovered"},
                {"value": "disable"},
                {"value": "enable"},
            ],
        },
        "poe_pre_standard_detection": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dhcp_server_access_list": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "global"}, {"value": "enable"}, {"value": "disable"}],
        },
        "poe_detection_type": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "version": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "max_allowed_trunk_members": {
            "v_range": [
                ["v6.0.0", "v6.0.11"],
                ["v6.2.3", "v6.2.3"],
                ["v6.4.0", "v6.4.0"],
                ["v6.4.4", ""],
            ],
            "type": "integer",
        },
        "pre_provisioned": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "mgmt_mode": {"v_range": [["v7.4.2", ""]], "type": "integer"},
        "dynamic_capability": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "switch_device_tag": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "switch_dhcp_opt43_key": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "mclag_igmp_snooping_aware": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ptp_status": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ptp_profile": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "radius_nas_ip_override": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "radius_nas_ip": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "route_offload": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "route_offload_mclag": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "route_offload_router": {
            "type": "list",
            "elements": "dict",
            "children": {
                "vlan_name": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "required": True,
                },
                "router_ip": {"v_range": [["v7.4.1", ""]], "type": "string"},
            },
            "v_range": [["v7.4.1", ""]],
        },
        "vlan": {
            "type": "list",
            "elements": "dict",
            "children": {
                "vlan_name": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "required": True,
                },
                "assignment_priority": {"v_range": [["v7.4.2", ""]], "type": "integer"},
            },
            "v_range": [["v7.4.2", ""]],
        },
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "virtual"}, {"value": "physical"}],
        },
        "owner_vdom": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "flow_identity": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "staged_image_version": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "delayed_restart_trigger": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "firmware_provision": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "firmware_provision_version": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "firmware_provision_latest": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "once"}],
        },
        "ports": {
            "type": "list",
            "elements": "dict",
            "children": {
                "port_name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "port_owner": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "speed": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "10half"},
                        {"value": "10full"},
                        {"value": "100half"},
                        {"value": "100full"},
                        {"value": "1000full"},
                        {
                            "value": "10000full",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
                        },
                        {"value": "auto"},
                        {"value": "1000auto"},
                        {
                            "value": "1000full-fiber",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
                        },
                        {
                            "value": "40000full",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
                        },
                        {"value": "auto-module"},
                        {"value": "100FX-half"},
                        {"value": "100FX-full"},
                        {"value": "100000full"},
                        {
                            "value": "2500auto",
                            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                        },
                        {
                            "value": "2500full",
                            "v_range": [
                                ["v6.0.0", "v6.0.11"],
                                ["v6.2.3", "v6.2.3"],
                                ["v7.4.4", ""],
                            ],
                        },
                        {"value": "25000full"},
                        {"value": "50000full"},
                        {
                            "value": "10000cr",
                            "v_range": [["v6.0.0", "v6.0.0"], ["v6.0.11", ""]],
                        },
                        {
                            "value": "10000sr",
                            "v_range": [["v6.0.0", "v6.0.0"], ["v6.0.11", ""]],
                        },
                        {
                            "value": "100000sr4",
                            "v_range": [["v6.0.0", "v6.0.0"], ["v6.0.11", ""]],
                        },
                        {
                            "value": "100000cr4",
                            "v_range": [["v6.0.0", "v6.0.0"], ["v6.0.11", ""]],
                        },
                        {
                            "value": "40000sr4",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
                        },
                        {
                            "value": "40000cr4",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
                        },
                        {"value": "40000auto", "v_range": [["v7.4.4", ""]]},
                        {
                            "value": "25000cr",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
                        },
                        {
                            "value": "25000sr",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
                        },
                        {
                            "value": "50000cr",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
                        },
                        {
                            "value": "50000sr",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
                        },
                        {
                            "value": "5000auto",
                            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
                        },
                        {
                            "value": "1000fiber",
                            "v_range": [["v6.0.0", "v7.0.7"], ["v7.2.0", "v7.2.2"]],
                        },
                        {
                            "value": "10000",
                            "v_range": [["v6.0.0", "v7.0.7"], ["v7.2.0", "v7.2.2"]],
                        },
                        {
                            "value": "40000",
                            "v_range": [["v6.0.0", "v7.0.7"], ["v7.2.0", "v7.2.2"]],
                        },
                        {
                            "value": "25000cr4",
                            "v_range": [
                                ["v6.0.0", "v6.0.0"],
                                ["v6.0.11", "v7.0.7"],
                                ["v7.2.0", "v7.2.2"],
                            ],
                        },
                        {
                            "value": "25000sr4",
                            "v_range": [
                                ["v6.0.0", "v6.0.0"],
                                ["v6.0.11", "v7.0.7"],
                                ["v7.2.0", "v7.2.2"],
                            ],
                        },
                        {
                            "value": "5000full",
                            "v_range": [
                                ["v6.0.0", "v6.0.0"],
                                ["v6.0.11", "v7.0.7"],
                                ["v7.2.0", "v7.2.2"],
                            ],
                        },
                    ],
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "up"}, {"value": "down"}],
                },
                "poe_status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ip_source_guard": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "ptp_status": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "ptp_policy": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                },
                "aggregator_mode": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "bandwidth"}, {"value": "count"}],
                },
                "flapguard": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "flap_rate": {"v_range": [["v7.2.0", ""]], "type": "integer"},
                "flap_duration": {"v_range": [["v7.2.0", ""]], "type": "integer"},
                "flap_timeout": {"v_range": [["v7.2.0", ""]], "type": "integer"},
                "rpvst_port": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disabled"}, {"value": "enabled"}],
                },
                "poe_pre_standard_detection": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "poe_capable": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "pd_capable": {"v_range": [["v7.6.0", ""]], "type": "integer"},
                "poe_mode_bt_cabable": {"v_range": [["v7.2.4", ""]], "type": "integer"},
                "poe_port_mode": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ieee802-3af"},
                        {"value": "ieee802-3at"},
                        {"value": "ieee802-3bt"},
                    ],
                },
                "poe_port_priority": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "critical-priority"},
                        {"value": "high-priority"},
                        {"value": "low-priority"},
                        {"value": "medium-priority"},
                    ],
                },
                "poe_port_power": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "normal"},
                        {"value": "perpetual"},
                        {"value": "perpetual-fast"},
                    ],
                },
                "vlan": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "allowed_vlans_all": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "allowed_vlans": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vlan_name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "untagged_vlans": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vlan_name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "physical"}, {"value": "trunk"}],
                },
                "access_mode": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "dynamic", "v_range": [["v7.0.0", ""]]},
                        {"value": "nac"},
                        {"value": "static", "v_range": [["v7.0.0", ""]]},
                        {"value": "normal", "v_range": [["v6.4.0", "v6.4.4"]]},
                    ],
                },
                "matched_dpp_policy": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "matched_dpp_intf_tags": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                },
                "acl_group": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.4.0", ""]],
                },
                "fortiswitch_acls": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.4.0", ""]],
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.4.0", ""]],
                },
                "dhcp_snooping": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "untrusted"}, {"value": "trusted"}],
                },
                "dhcp_snoop_option82_trust": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "dhcp_snoop_option82_override": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vlan_name": {
                            "v_range": [["v7.4.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "circuit_id": {"v_range": [["v7.4.0", ""]], "type": "string"},
                        "remote_id": {"v_range": [["v7.4.0", ""]], "type": "string"},
                    },
                    "v_range": [["v7.4.0", ""]],
                },
                "arp_inspection_trust": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "untrusted"}, {"value": "trusted"}],
                },
                "igmp_snooping_flood_reports": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "mcast_snooping_flood_traffic": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "stp_state": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enabled"}, {"value": "disabled"}],
                },
                "stp_root_guard": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enabled"}, {"value": "disabled"}],
                },
                "stp_bpdu_guard": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enabled"}, {"value": "disabled"}],
                },
                "stp_bpdu_guard_timeout": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "edge_port": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "discard_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "all-untagged"},
                        {"value": "all-tagged"},
                    ],
                },
                "packet_sampler": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enabled"}, {"value": "disabled"}],
                },
                "packet_sample_rate": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "sflow_counter_interval": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "sample_direction": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "tx"}, {"value": "rx"}, {"value": "both"}],
                },
                "fec_capable": {"v_range": [["v7.0.0", ""]], "type": "integer"},
                "fec_state": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disabled"},
                        {"value": "cl74"},
                        {"value": "cl91"},
                        {"value": "detect-by-module", "v_range": [["v7.4.2", ""]]},
                    ],
                },
                "flow_control": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "tx"},
                        {"value": "rx"},
                        {"value": "both"},
                    ],
                },
                "pause_meter": {"v_range": [["v6.4.4", ""]], "type": "integer"},
                "pause_meter_resume": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "75%"}, {"value": "50%"}, {"value": "25%"}],
                },
                "loop_guard": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enabled"}, {"value": "disabled"}],
                },
                "loop_guard_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "port_policy": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "qos_policy": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "storm_control_policy": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "port_security_policy": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "export_to_pool": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "interface_tags": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "tag_name": {
                            "v_range": [["v7.0.2", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.0.2", ""]],
                },
                "learning_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "sticky_mac": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "lldp_status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "rx-only"},
                        {"value": "tx-only"},
                        {"value": "tx-rx"},
                    ],
                },
                "lldp_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "export_to": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "mac_addr": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "allow_arp_monitor": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "qnq": {"v_range": [["v7.6.0", ""]], "type": "string"},
                "log_mac_event": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "port_selection_criteria": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "src-mac"},
                        {"value": "dst-mac"},
                        {"value": "src-dst-mac"},
                        {"value": "src-ip"},
                        {"value": "dst-ip"},
                        {"value": "src-dst-ip"},
                    ],
                },
                "description": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "lacp_speed": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "slow"}, {"value": "fast"}],
                },
                "mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "static"},
                        {"value": "lacp-passive"},
                        {"value": "lacp-active"},
                    ],
                },
                "bundle": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "member_withdrawal_behavior": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "forward"}, {"value": "block"}],
                },
                "mclag": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "min_bundle": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "max_bundle": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "members": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "member_name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "fallback_port": {"v_range": [["v7.4.4", ""]], "type": "string"},
                "switch_id": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
                "port_number": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "port_prefix_type": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "fortilink_port": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "stacking_port": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "p2p_port": {
                    "v_range": [["v6.4.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "mclag_icl_port": {
                    "v_range": [["v6.4.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "fiber_port": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "media_type": {
                    "v_range": [["v6.4.4", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
                "poe_standard": {
                    "v_range": [["v7.0.1", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
                "poe_max_power": {
                    "v_range": [["v7.0.1", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
                "flags": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "isl_local_trunk_name": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
                "isl_peer_port_name": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
                "isl_peer_device_name": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
                "fgt_peer_port_name": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
                "fgt_peer_device_name": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
                "igmps_flood_reports": {
                    "v_range": [["v6.0.0", "v7.2.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "igmps_flood_traffic": {
                    "v_range": [["v6.0.0", "v7.2.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "export_tags": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "tag_name": {
                            "v_range": [["v6.0.0", "v7.0.1"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v7.0.1"]],
                },
                "igmp_snooping": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "speed_mask": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "integer",
                },
                "virtual_port": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "integer",
                },
                "export_to_pool_flag": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "integer",
                },
                "sflow_sampler": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [{"value": "enabled"}, {"value": "disabled"}],
                },
                "sflow_sample_rate": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "integer",
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ip_source_guard": {
            "type": "list",
            "elements": "dict",
            "children": {
                "port": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "description": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "binding_entry": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "entry_name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "ip": {"v_range": [["v6.4.0", ""]], "type": "string"},
                        "mac": {"v_range": [["v6.4.0", ""]], "type": "string"},
                    },
                    "v_range": [["v6.4.0", ""]],
                },
            },
            "v_range": [["v6.4.0", ""]],
        },
        "stp_settings": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "local_override": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "name": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "revision": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "hello_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "forward_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "max_age": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "max_hops": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "pending_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "status": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "stp_instance": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v6.2.0", ""]], "type": "string", "required": True},
                "priority": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "0"},
                        {"value": "4096"},
                        {"value": "8192"},
                        {"value": "12288"},
                        {"value": "16384"},
                        {"value": "20480"},
                        {"value": "24576"},
                        {"value": "28672"},
                        {"value": "32768"},
                        {"value": "36864"},
                        {"value": "40960"},
                        {"value": "45056"},
                        {"value": "49152"},
                        {"value": "53248"},
                        {"value": "57344"},
                        {"value": "61440"},
                    ],
                },
            },
            "v_range": [["v6.2.0", ""]],
        },
        "override_snmp_sysinfo": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "snmp_sysinfo": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "engine_id": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "description": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "contact_info": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "location": {"v_range": [["v6.2.0", ""]], "type": "string"},
            },
        },
        "override_snmp_trap_threshold": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "snmp_trap_threshold": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "trap_high_cpu_threshold": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                },
                "trap_low_memory_threshold": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                },
                "trap_log_full_threshold": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                },
            },
        },
        "override_snmp_community": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "snmp_community": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "name": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "status": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "hosts": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "ip": {"v_range": [["v6.2.0", ""]], "type": "string"},
                    },
                    "v_range": [["v6.2.0", ""]],
                },
                "query_v1_status": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "query_v1_port": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "query_v2c_status": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "query_v2c_port": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "trap_v1_status": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "trap_v1_lport": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "trap_v1_rport": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "trap_v2c_status": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "trap_v2c_lport": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "trap_v2c_rport": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "events": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "cpu-high"},
                        {"value": "mem-low"},
                        {"value": "log-full"},
                        {"value": "intf-ip"},
                        {"value": "ent-conf-change"},
                        {"value": "l2mac", "v_range": [["v7.6.0", ""]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
            "v_range": [["v6.2.0", ""]],
        },
        "override_snmp_user": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "snmp_user": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "queries": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "query_port": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "security_level": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "no-auth-no-priv"},
                        {"value": "auth-no-priv"},
                        {"value": "auth-priv"},
                    ],
                },
                "auth_proto": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "md5"},
                        {"value": "sha1", "v_range": [["v7.0.0", ""]]},
                        {"value": "sha224", "v_range": [["v7.0.0", ""]]},
                        {"value": "sha256", "v_range": [["v7.0.0", ""]]},
                        {"value": "sha384", "v_range": [["v7.0.0", ""]]},
                        {"value": "sha512", "v_range": [["v7.0.0", ""]]},
                        {"value": "sha", "v_range": [["v6.2.0", "v6.4.4"]]},
                    ],
                },
                "auth_pwd": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "priv_proto": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "aes128", "v_range": [["v7.0.0", ""]]},
                        {"value": "aes192", "v_range": [["v7.0.0", ""]]},
                        {"value": "aes192c", "v_range": [["v7.0.0", ""]]},
                        {"value": "aes256", "v_range": [["v7.0.0", ""]]},
                        {"value": "aes256c", "v_range": [["v7.0.0", ""]]},
                        {"value": "des"},
                        {"value": "aes", "v_range": [["v6.2.0", "v6.4.4"]]},
                    ],
                },
                "priv_pwd": {"v_range": [["v6.2.0", ""]], "type": "string"},
            },
            "v_range": [["v6.2.0", ""]],
        },
        "qos_drop_policy": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "taildrop"}, {"value": "random-early-detection"}],
        },
        "qos_red_probability": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "switch_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "local_override": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "severity": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "emergency"},
                        {"value": "alert"},
                        {"value": "critical"},
                        {"value": "error"},
                        {"value": "warning"},
                        {"value": "notification"},
                        {"value": "information"},
                        {"value": "debug"},
                    ],
                },
            },
        },
        "remote_log": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "server": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "port": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "severity": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "emergency"},
                        {"value": "alert"},
                        {"value": "critical"},
                        {"value": "error"},
                        {"value": "warning"},
                        {"value": "notification"},
                        {"value": "information"},
                        {"value": "debug"},
                    ],
                },
                "csv": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "facility": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "kernel"},
                        {"value": "user"},
                        {"value": "mail"},
                        {"value": "daemon"},
                        {"value": "auth"},
                        {"value": "syslog"},
                        {"value": "lpr"},
                        {"value": "news"},
                        {"value": "uucp"},
                        {"value": "cron"},
                        {"value": "authpriv"},
                        {"value": "ftp"},
                        {"value": "ntp"},
                        {"value": "audit"},
                        {"value": "alert"},
                        {"value": "clock"},
                        {"value": "local0"},
                        {"value": "local1"},
                        {"value": "local2"},
                        {"value": "local3"},
                        {"value": "local4"},
                        {"value": "local5"},
                        {"value": "local6"},
                        {"value": "local7"},
                    ],
                },
            },
            "v_range": [["v6.2.0", ""]],
        },
        "storm_control": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "local_override": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "burst_size_level": {"v_range": [["v7.6.4", ""]], "type": "integer"},
                "unknown_unicast": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "unknown_multicast": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "broadcast": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "mirror": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "active"}, {"value": "inactive"}],
                },
                "switching_packet": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "dst": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "src_ingress": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "src_egress": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "static_mac": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "type": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "static"}, {"value": "sticky"}],
                },
                "vlan": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "mac": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "interface": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "description": {"v_range": [["v6.2.0", ""]], "type": "string"},
            },
            "v_range": [["v6.2.0", ""]],
        },
        "custom_command": {
            "type": "list",
            "elements": "dict",
            "children": {
                "command_entry": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "command_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "dhcp_snooping_static_client": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "required": True,
                },
                "vlan": {"v_range": [["v7.2.4", ""]], "type": "string"},
                "ip": {"v_range": [["v7.2.4", ""]], "type": "string"},
                "mac": {"v_range": [["v7.2.4", ""]], "type": "string"},
                "port": {"v_range": [["v7.2.4", ""]], "type": "string"},
            },
            "v_range": [["v7.2.4", ""]],
        },
        "igmp_snooping": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "local_override": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "aging_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "flood_unknown_multicast": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "vlans": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vlan_name": {
                            "v_range": [["v7.0.2", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "proxy": {
                            "v_range": [["v7.0.2", ""]],
                            "type": "string",
                            "options": [
                                {"value": "disable"},
                                {"value": "enable"},
                                {"value": "global"},
                            ],
                        },
                        "querier": {
                            "v_range": [["v7.0.2", ""]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "querier_addr": {"v_range": [["v7.0.2", ""]], "type": "string"},
                        "version": {"v_range": [["v7.0.2", ""]], "type": "integer"},
                    },
                    "v_range": [["v7.0.2", ""]],
                },
            },
        },
        "router_vrf": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "required": True,
                },
                "switch_id": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "vrfid": {"v_range": [["v7.6.4", ""]], "type": "integer"},
            },
            "v_range": [["v7.6.4", ""]],
        },
        "system_interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "required": True,
                },
                "switch_id": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "mode": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "options": [{"value": "static"}, {"value": "dhcp"}],
                },
                "ip": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "status": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "allowaccess": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "list",
                    "options": [
                        {"value": "ping"},
                        {"value": "https"},
                        {"value": "http"},
                        {"value": "ssh"},
                        {"value": "snmp"},
                        {"value": "telnet"},
                        {"value": "radius-acct"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "vlan": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "type": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "options": [{"value": "vlan"}, {"value": "physical"}],
                },
                "interface": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "vrf": {"v_range": [["v7.6.4", ""]], "type": "string"},
            },
            "v_range": [["v7.6.4", ""]],
        },
        "router_static": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "integer",
                    "required": True,
                },
                "switch_id": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "blackhole": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "comment": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "device": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "distance": {"v_range": [["v7.6.4", ""]], "type": "integer"},
                "dst": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "dynamic_gateway": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "gateway": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "status": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "vrf": {"v_range": [["v7.6.4", ""]], "type": "string"},
            },
            "v_range": [["v7.6.4", ""]],
        },
        "system_dhcp_server": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "integer",
                    "required": True,
                },
                "switch_id": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "status": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "lease_time": {"v_range": [["v7.6.4", ""]], "type": "integer"},
                "dns_service": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "local"},
                        {"value": "default"},
                        {"value": "specify"},
                    ],
                },
                "dns_server1": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "dns_server2": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "dns_server3": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "ntp_service": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "local"},
                        {"value": "default"},
                        {"value": "specify"},
                    ],
                },
                "ntp_server1": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "ntp_server2": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "ntp_server3": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "default_gateway": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "netmask": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "interface": {"v_range": [["v7.6.4", ""]], "type": "string"},
                "ip_range": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.6.4", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "start_ip": {"v_range": [["v7.6.4", ""]], "type": "string"},
                        "end_ip": {"v_range": [["v7.6.4", ""]], "type": "string"},
                    },
                    "v_range": [["v7.6.4", ""]],
                },
                "options": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.6.4", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "code": {"v_range": [["v7.6.4", ""]], "type": "integer"},
                        "type": {
                            "v_range": [["v7.6.4", ""]],
                            "type": "string",
                            "options": [
                                {"value": "hex"},
                                {"value": "string"},
                                {"value": "ip"},
                                {"value": "fqdn"},
                            ],
                        },
                        "value": {"v_range": [["v7.6.4", ""]], "type": "string"},
                        "ip": {
                            "v_range": [["v7.6.4", ""]],
                            "type": "list",
                            "multiple_values": True,
                            "elements": "str",
                        },
                    },
                    "v_range": [["v7.6.4", ""]],
                },
            },
            "v_range": [["v7.6.4", ""]],
        },
        "name": {"v_range": [["v6.0.0", "v7.2.4"]], "type": "string"},
        "directly_connected": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "l3_discovered": {
            "v_range": [["v6.4.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "tdr_supported": {
            "v_range": [["v6.4.4", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "dynamically_discovered": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "poe_lldp_detection": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fsw_wan2_peer": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "fsw_wan2_admin": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
            "options": [
                {"value": "discovered"},
                {"value": "disable"},
                {"value": "enable"},
            ],
        },
        "switch_stp_settings": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                }
            },
        },
        "settings_802_1X": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "local_override": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "link_down_auth": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "set-unauth"}, {"value": "no-action"}],
                },
                "reauth_period": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "max_reauth_attempt": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "tx_period": {"v_range": [["v6.4.0", ""]], "type": "integer"},
                "mab_reauth": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "mac_username_delimiter": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "colon"},
                        {"value": "hyphen"},
                        {"value": "none"},
                        {"value": "single-hyphen"},
                    ],
                },
                "mac_password_delimiter": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "colon"},
                        {"value": "hyphen"},
                        {"value": "none"},
                        {"value": "single-hyphen"},
                    ],
                },
                "mac_calling_station_delimiter": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "colon"},
                        {"value": "hyphen"},
                        {"value": "none"},
                        {"value": "single-hyphen"},
                    ],
                },
                "mac_called_station_delimiter": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "colon"},
                        {"value": "hyphen"},
                        {"value": "none"},
                        {"value": "single-hyphen"},
                    ],
                },
                "mac_case": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "lowercase"}, {"value": "uppercase"}],
                },
            },
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "switch_id"
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
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "switch_controller_managed_switch": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["switch_controller_managed_switch"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["switch_controller_managed_switch"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "switch_controller_managed_switch"
        )

        is_error, has_changed, result, diff = fortios_switch_controller(
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
