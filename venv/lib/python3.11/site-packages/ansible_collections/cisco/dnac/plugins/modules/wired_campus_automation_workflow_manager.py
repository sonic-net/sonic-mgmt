#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to manage wired campus automation in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Rugvedi Kapse, Madhan Sankaranarayanan"


DOCUMENTATION = r"""
---
module: wired_campus_automation_workflow_manager
short_description: Manage wired campus automation operations in Cisco Catalyst Center
description:
  - BETA MODULE, CISCO INTERNAL USE ONLY
  - This module is currently in beta and is intended for Cisco internal purposes only.
  - It is not available for customer consumption and should not be used in production environments.
  - This module provides comprehensive management of Layer 2 wired network configurations in
  - Cisco Catalyst Center.
  - Configure VLANs, STP, CDP, LLDP, VTP, DHCP Snooping, IGMP/MLD Snooping, authentication,
  - port channels, and interface settings.
  - Supports both creation and updating of configurations on network devices.
  - Provides automated deployment of intended configurations to devices.
  - Includes comprehensive validation of all configuration parameters before applying changes.

  - Feature Support Matrix
  - C(VLANs) - create, update, delete
  - C(CDP) - create, update, delete
  - C(LLDP) - create, update, delete
  - C(STP) - create, update (delete not supported due to API limitations)
  - C(VTP) - create, update, delete
  - C(DHCP Snooping) - create, update, delete
  - C(IGMP Snooping) - create, update (delete not supported due to API limitations)
  - C(MLD Snooping) - create, update (delete not supported due to API limitations)
  - C(Authentication) - create, update, delete
  - C(Logical Ports) - create, update (delete not supported due to API limitations)
  - C(Port Configuration) - create, update (delete not supported due to API limitations)

  - Known API Limitations & Issues
  - The deleted state is not supported for STP, IGMP Snooping, MLD Snooping,
    Port Configuration, and Logical Ports due to underlying beta API limitations.
  - Several known issues exist with the beta APIs that may affect functionality.

  - VLANs (vlanConfig) -
  - VLAN configuration may silently fail when VTP mode is SERVER (CSCwr00884)
  - VLAN name cannot be reset to empty string once set

  - STP (stpGlobalConfig) -
  - STP instance deletion does not properly remove deployed configuration (CSCwr01764)
  - Incorrect payload structure validation for isStpEnabled parameter (CSCwr0107)

  - VTP (vtpGlobalConfig) -
  - Domain name cannot be removed once set (expected behavior)
  - Configuration file name and source interface cannot be reset to empty string (CSCwr01195)
  - Misleading validation error when attempting to remove VTP domain name (CSCwr01131)

  - DHCP Snooping (dhcpSnoopingGlobalConfig) -
  - Global configuration not fully reset to defaults after intent deletion (CSCwr01309)
  - Agent URL, proxy bridge VLANs, and snooping VLANs cannot be reset using empty strings (CSCwr01255, CSCwr01321, CSCwr01327)

  - IGMP/MLD Snooping (igmpSnoopingGlobalConfig, mldSnoopingGlobalConfig) -
  - Querier address does not reset to default on intent deletion (CSCwr01879)
  - MLD snooping rejects empty querier address in update operations (CSCwr06296)

  - Logical Ports (portchannelConfig) -
  - Port channel configuration may fail silently without proper error response (CSCwr01895)
  - Optional fields incorrectly enforced as required during validation (CSCwr08060)

  - Port Configuration (switchportInterfaceConfig) -
  - Switchport configuration may silently fail during comprehensive port updates
  - Storm Control, Port Security, and UDLD interface configurations are not supported (available in 3.2.x release)
version_added: "6.20.0"
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Rugvedi Kapse (@rukapse)
  - Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: Set to true to verify the Cisco Catalyst
      Center configuration after applying the playbook
      configuration.
    type: bool
    default: false
  state:
    description: The desired state of Cisco Catalyst Center after module execution.
    type: str
    choices: [merged, deleted]
    default: "merged"
  config:
    description: List of wired campus automation configurations to be applied to network devices.
    type: list
    elements: dict
    required: true
    suboptions:
      ip_address:
        description:
          - The management IP address of the network device to configure.
          - Must be a valid IPv4 address format.
          - Either "ip_address" or "hostname" must be provided to identify the device.
          - If both are provided, ip_address takes precedence.
          - Example - "192.168.1.1"
        type: str
        required: false
      hostname:
        description:
          - The hostname of the network device to configure.
          - Used when IP address is not available or preferred.
          - Must match the hostname registered in Catalyst Center.
          - Either "ip_address" or "hostname" must be provided to identify the device.
        type: str
        required: false
      device_collection_status_check:
        description:
          - Controls whether to verify the device's collection status before applying configurations.
          - When true, ensures the device is in "Managed" or "In Progress" state before proceeding.
          - When false, skips the collection status check (useful for devices being onboarded).
          - Recommended to keep as true for production environments.
        type: bool
        required: false
        default: true
      layer2_configuration:
        description:
          - Comprehensive Layer 2 configuration settings for the network device.
          - Contains all supported Layer 2 protocols and features.
          - Each feature is optional and can be configured independently.
        type: dict
        required: false
        suboptions:
          vlans:
            description:
              - List of VLAN configurations to create or modify on the device.
              - VLANs are fundamental building blocks for network segmentation.
              - Each VLAN must have a unique ID within the valid range (1-4094).
              - Default VLANs (1, 1002-1005) are typically pre-configured and should not be modified.
            type: list
            elements: dict
            required: false
            suboptions:
              vlan_id:
                description:
                  - Unique identifier for the VLAN.
                  - Must be within the valid range of 1 to 4094.
                  - VLAN 1 is the default VLAN and exists on all switches.
                  - VLANs 1002-1005 are reserved for legacy protocols.
                  - Extended VLANs (1006-4094) may require VTP version 3.
                type: int
                required: true
              vlan_name:
                description:
                  - Descriptive name for the VLAN to aid in identification and management.
                  - Maximum length depends on VTP version (32 chars for v1/v2, 128 chars for v3).
                  - Should be descriptive and follow organizational naming conventions.
                  - If not specified, defaults to "VLAN" followed by the VLAN ID with leading zeros.
                  - Must contain only ASCII characters (0-127) as per Catalyst Center API requirements.
                  - Cannot contain whitespace characters (spaces, tabs, newlines) or question marks (?).
                  - Use underscores (_) or hyphens (-) instead of spaces for better compatibility.
                  - Empty strings are not allowed and will cause API validation errors.
                  - Examples - "SALES_VLAN", "IOT_DEVICES", "GUEST_NETWORK"
                type: str
                required: false
              vlan_admin_status:
                description:
                  - Administrative status of the VLAN (enabled or disabled).
                  - When true, the VLAN is active and can carry traffic.
                  - When false, the VLAN is administratively shut down.
                  - Disabled VLANs do not forward traffic but retain their configuration.
                  - NOTE - "vlan_admin_status" Can only be modified for VLAN IDs 2-1001.
                  - Extended range VLANs (1002-4094) do not support admin status updates.
                type: bool
                required: false
                default: true
          cdp:
            description:
              - Cisco Discovery Protocol (CDP) global configuration settings.
              - CDP is a Cisco proprietary protocol for discovering neighboring Cisco devices.
              - Runs over Layer 2 and provides device information like platform, capabilities, and addresses.
              - Useful for network topology discovery and troubleshooting.
            type: dict
            required: false
            suboptions:
              cdp_admin_status:
                description:
                  - Globally enable or disable CDP on the device.
                  - When true, CDP is enabled globally (equivalent to "cdp run" command).
                  - When false, CDP is disabled globally on all interfaces.
                  - Individual interfaces can still override this setting.
                type: bool
                required: false
                default: true
              cdp_hold_time:
                description:
                  - Time in seconds that receiving devices should hold CDP information before discarding it.
                  - Must be between 10 and 255 seconds.
                  - Should be set higher than the timer interval to prevent information loss.
                  - Typical values are 180 seconds (3 times the default timer).
                  - Equivalent to "cdp holdtime" command.
                type: int
                required: false
                default: 180
              cdp_timer:
                description:
                  - Frequency in seconds at which CDP advertisements are sent.
                  - Must be between 5 and 254 seconds.
                  - Lower values provide more current information but increase network overhead.
                  - Higher values reduce overhead but may delay topology discovery.
                  - Equivalent to "cdp timer" command.
                type: int
                required: false
                default: 60
              cdp_advertise_v2:
                description:
                  - Enable CDP version 2 advertisements.
                  - When true, sends CDP version 2 advertisements (default and recommended).
                  - When false, sends CDP version 1 advertisements (legacy compatibility).
                  - Version 2 provides additional information and error detection.
                  - Equivalent to "cdp advertise-v2" command.
                type: bool
                required: false
                default: true
              cdp_log_duplex_mismatch:
                description:
                  - Enable logging of duplex mismatches detected by CDP.
                  - When true, logs warnings when CDP detects duplex mismatches with neighbors.
                  - When false, duplex mismatch detection is disabled.
                  - Useful for identifying and troubleshooting duplex configuration issues.
                  - Equivalent to "cdp log mismatch duplex" command.
                type: bool
                required: false
                default: true
          lldp:
            description:
              - Link Layer Discovery Protocol (LLDP) global configuration settings.
              - LLDP is an IEEE 802.1AB standard protocol for discovering neighboring devices.
              - Vendor-neutral alternative to CDP, supported by multiple vendors.
              - Provides device identification, capabilities, and management information.
            type: dict
            required: false
            suboptions:
              lldp_admin_status:
                description:
                  - Globally enable or disable LLDP on the device.
                  - When true, LLDP is enabled globally (equivalent to "lldp run" command).
                  - When false, LLDP is disabled globally on all interfaces.
                  - Individual interfaces can still override this setting.
                type: bool
                required: false
                default: false
              lldp_hold_time:
                description:
                  - Time in seconds that receiving devices should hold LLDP information before discarding it.
                  - Must be between 0 and 32767 seconds.
                  - Should be set higher than the timer interval to prevent information loss.
                  - A value of 0 means the information should not be aged out.
                  - Equivalent to "lldp holdtime" command.
                type: int
                required: false
                default: 120
              lldp_timer:
                description:
                  - Frequency in seconds at which LLDP advertisements are sent.
                  - Must be between 5 and 32767 seconds.
                  - Lower values provide more current information but increase network overhead.
                  - Higher values reduce overhead but may delay topology discovery.
                  - Equivalent to "lldp timer" command.
                type: int
                required: false
                default: 30
              lldp_reinitialization_delay:
                description:
                  - Delay in seconds for LLDP initialization on any interface.
                  - Must be between 2 and 5 seconds.
                  - Prevents rapid enable/disable cycles during interface initialization.
                  - Provides stability during interface state changes.
                  - Equivalent to "lldp reinit" command.
                type: int
                required: false
                default: 2
          stp:
            description:
              - Spanning Tree Protocol (STP) global and per-VLAN configuration settings.
              - STP prevents loops in redundant network topologies while providing path redundancy.
              - Supports PVST+, RSTP, and MST modes for different network requirements.
              - Critical for network stability in environments with redundant paths.
            type: dict
            required: false
            suboptions:
              stp_mode:
                description:
                  - Spanning Tree Protocol mode to operate in.
                  - C(PVST) (Per-VLAN Spanning Tree Plus) - Cisco proprietary, one instance per VLAN.
                  - C(RSTP) (Rapid Spanning Tree Protocol) - IEEE 802.1w, faster convergence than PVST.
                  - C(MST) (Multiple Spanning Tree) - IEEE 802.1s, maps multiple VLANs to instances.
                  - Choose based on network size, convergence requirements, and vendor compatibility.
                type: str
                required: false
                choices: ["PVST", "RSTP", "MST"]
                default: "RSTP"
              stp_portfast_mode:
                description:
                  - Global PortFast mode configuration for edge ports.
                  - C(ENABLE) - Enables PortFast on all access ports globally.
                  - C(DISABLE) - Disables PortFast globally.
                  - C(EDGE) - Enables PortFast on edge ports (recommended for end devices).
                  - C(NETWORK) - Configures network ports (inter-switch links).
                  - C(TRUNK) - Enables PortFast on trunk ports (use with caution).
                  - PortFast bypasses listening and learning states for faster convergence.
                  - Advanced portfast modes (EDGE, NETWORK, TRUNK) are only supported on
                    Catalyst 9600 Series and specific Catalyst 9500 Series models (C9500-32C,
                    C9500-32QC, C9500-48Y4C, C9500-24Y4C, C9500X-28C8D).
                type: str
                required: false
                choices: ["ENABLE", "DISABLE", "EDGE", "NETWORK", "TRUNK"]
              stp_bpdu_guard:
                description:
                  - Global BPDU Guard configuration for PortFast-enabled ports.
                  - When true, shuts down PortFast ports that receive BPDUs.
                  - Protects against accidental switch connections to access ports.
                  - Essential security feature for edge port protection.
                  - Equivalent to "spanning-tree portfast bpduguard default" command.
                type: bool
                required: false
                default: false
              stp_bpdu_filter:
                description:
                  - Global BPDU Filter configuration for PortFast-enabled ports.
                  - When true, prevents sending and receiving BPDUs on PortFast ports.
                  - Should be used with caution as it can create loops if misconfigured.
                  - Typically used in environments where STP is not needed on edge ports.
                  - Equivalent to "spanning-tree portfast bpdufilter default" command.
                type: bool
                required: false
                default: false
              stp_backbonefast:
                description:
                  - Enable BackboneFast for faster convergence on indirect link failures.
                  - When true, enables BackboneFast to detect indirect failures quickly.
                  - Reduces convergence time from 50 seconds to 30 seconds for indirect failures.
                  - Works in conjunction with UplinkFast for optimal convergence.
                  - Equivalent to "spanning-tree backbonefast" command.
                type: bool
                required: false
                default: false
              stp_extended_system_id:
                description:
                  - Enable extended system ID for bridge priority calculation.
                  - When true, uses VLAN ID as part of bridge ID calculation.
                  - Required for PVST plus operation with more than 64 VLANs.
                  - Changes bridge priority calculation to include VLAN ID.
                  - Equivalent to "spanning-tree extend system-id" command.
                type: bool
                required: false
                default: true
              stp_logging:
                description:
                  - Enable STP event logging for troubleshooting.
                  - When true, logs STP state changes and events.
                  - Useful for monitoring STP behavior and troubleshooting issues.
                  - May increase log verbosity in environments with frequent topology changes.
                  - Equivalent to "spanning-tree logging" command.
                type: bool
                required: false
                default: false
              stp_loopguard:
                description:
                  - Global Loop Guard configuration to prevent loops from unidirectional failures.
                  - When true, prevents alternate/root ports from becoming designated ports.
                  - Protects against loops caused by unidirectional link failures.
                  - Complements UDLD for comprehensive loop prevention.
                  - Equivalent to "spanning-tree loopguard default" command.
                type: bool
                required: false
                default: false
              stp_transmit_hold_count:
                description:
                  - Maximum number of BPDUs sent per hello interval.
                  - Must be between 1 and 20.
                  - Controls BPDU transmission rate to prevent overwhelming neighbors.
                  - Higher values allow more BPDUs but may impact performance.
                  - Equivalent to "spanning-tree transmit hold-count" command.
                type: int
                required: false
                default: 6
              stp_uplinkfast:
                description:
                  - Enable UplinkFast for faster convergence on direct link failures.
                  - When true, enables UplinkFast for access layer switches.
                  - Provides sub-second convergence for direct uplink failures.
                  - Should only be enabled on access layer switches, not distribution/core.
                  - Equivalent to "spanning-tree uplinkfast" command.
                type: bool
                required: false
                default: false
              stp_uplinkfast_max_update_rate:
                description:
                  - Maximum rate of update packets sent when UplinkFast is enabled.
                  - Must be between 0 and 32000 packets per second.
                  - Controls the rate of multicast packets sent during convergence.
                  - Higher rates provide faster convergence but may impact performance.
                  - Only applicable when UplinkFast is enabled.
                type: int
                required: false
                default: 150
              stp_etherchannel_guard:
                description:
                  - Enable EtherChannel Guard to detect EtherChannel misconfigurations.
                  - When true, detects when one side has EtherChannel configured but the other doesn't.
                  - Prevents loops and inconsistencies in EtherChannel configurations.
                  - Essential for maintaining EtherChannel integrity.
                  - Equivalent to "spanning-tree etherchannel guard misconfig" command.
                type: bool
                required: false
                default: true
              stp_instances:
                description:
                  - List of per-VLAN STP instance configurations.
                  - Allows customization of STP parameters for specific VLANs.
                  - Each instance can have different priorities and timers.
                  - Useful for load balancing and fine-tuning STP behavior.
                type: list
                elements: dict
                required: false
                suboptions:
                  stp_instance_vlan_id:
                    description:
                      - VLAN ID for this STP instance configuration.
                      - Must be between 1 and 4094.
                      - Each VLAN can have its own STP parameters.
                      - VLAN must exist before STP instance configuration.
                    type: int
                    required: true
                  stp_instance_priority:
                    description:
                      - Bridge priority for this VLAN's STP instance.
                      - Must be between 0 and 61440 in increments of 4096.
                      - Lower values have higher priority (more likely to be root).
                      - Default is 32768. Common values 4096, 8192, 16384, 24576.
                      - Used for load balancing across multiple VLANs.
                    type: int
                    required: false
                    default: 32768
                  enable_stp:
                    description:
                      - Enable or disable STP for this specific VLAN.
                      - When true, STP is active for this VLAN.
                      - When false, STP is disabled for this VLAN (use with caution).
                      - Disabling STP can create loops if redundant paths exist.
                    type: bool
                    required: false
                    default: true
                  stp_instance_max_age_timer:
                    description:
                      - Maximum age timer for this STP instance in seconds.
                      - Must be between 6 and 40 seconds.
                      - Time to wait for BPDUs before aging out port information.
                      - Should be coordinated with hello interval and forward delay.
                      - Affects convergence time and stability.
                    type: int
                    required: false
                    default: 20
                  stp_instace_hello_interval_timer:
                    description:
                      - Hello interval timer for this STP instance in seconds.
                      - Must be between 1 and 10 seconds.
                      - Frequency of BPDU transmission by the root bridge.
                      - Lower values provide faster detection but increase overhead.
                      - Should be coordinated with max age and forward delay.
                    type: int
                    required: false
                    default: 2
                  stp_instace_forward_delay_timer:
                    description:
                      - Forward delay timer for this STP instance in seconds.
                      - Must be between 4 and 30 seconds.
                      - Time spent in listening and learning states during convergence.
                      - Should be coordinated with max age and hello interval.
                      - Affects convergence time, shorter delays mean faster convergence.
                    type: int
                    required: false
                    default: 15
          vtp:
            description:
              - VLAN Trunking Protocol (VTP) configuration settings.
              - VTP synchronizes VLAN configuration across switches in a domain.
              - Enables centralized VLAN management for large switched networks.
              - Requires careful planning to avoid accidental VLAN deletion.
            type: dict
            required: false
            suboptions:
              vtp_mode:
                description:
                  - VTP operational mode for this switch.
                  - C(SERVER) - Can create, modify, and delete VLANs; propagates changes.
                  - C(CLIENT) - Cannot modify VLANs locally; accepts updates from servers.
                  - C(TRANSPARENT) - Can modify VLANs locally; forwards but doesn't process updates.
                  - C(OFF) - VTP is disabled; no VTP processing or forwarding.
                  - Choose based on network role and VLAN management strategy.
                  - VTP modes SERVER and CLIENT do not support extended range VLANs (1006-4094).
                  - If extended range VLANs are configured on the device, VTP mode
                    must be set to TRANSPARENT or OFF.
                type: str
                required: false
                choices: ["SERVER", "CLIENT", "TRANSPARENT", "OFF"]
                default: "SERVER"
              vtp_version:
                description:
                  - VTP protocol version to use.
                  - C(VERSION_1) - Original VTP implementation, basic functionality.
                  - C(VERSION_2) - Adds support for Token Ring and unrecognized TLVs.
                  - C(VERSION_3) - Adds extended VLANs, private VLANs, and MST support.
                  - Higher versions provide more features but require compatible switches.
                type: str
                required: false
                choices: ["VERSION_1", "VERSION_2", "VERSION_3"]
                default: "VERSION_1"
              vtp_domain_name:
                description:
                  - VTP domain name for switch participation.
                  - Maximum 32 characters for VTP domains.
                  - All switches in the same domain share VLAN information.
                  - Case-sensitive and must match exactly across all domain switches.
                  - Required for VTP version 3 operation.
                  - Once domain name is set, it can be updated but cannot be reset.
                type: str
                required: false
              vtp_configuration_file_name:
                description:
                  - Custom filename for VTP configuration storage.
                  - Default is "vlan.dat" in the flash file system.
                  - Maximum 244 characters for custom filenames.
                  - Useful for backup and recovery procedures.
                  - Should include full path if not in default location.
                  - NOTE - Due to API limitations, this parameter does not support
                    empty string values ("") for resetting to default.
                  - To reset this parameter, the entire VTP configuration has
                    to be reset using the "deleted" state.
                type: str
                required: false
              vtp_source_interface:
                description:
                  - Interface to use as the source for VTP updates.
                  - Specifies which interface IP becomes the VTP updater address.
                  - Useful for identifying which switch made the last update.
                  - Should be a consistently available interface like a loopback.
                  - Format interface type and number (Example, "GigabitEthernet1/0/1").
                  - NOTE - Due to API limitations, this parameter does not support
                    empty string values ("") for resetting to default.
                  - To reset this parameter, the entire VTP configuration
                    has to be reset using the "deleted" state.
                type: str
                required: false
              vtp_pruning:
                description:
                  - Enable VTP pruning to optimize bandwidth usage.
                  - When true, restricts flooded traffic to only necessary trunk links.
                  - Reduces unnecessary broadcast traffic in the VTP domain.
                  - Only affects VLANs 2-1001; VLAN 1 and extended VLANs are not pruned.
                  - Can only be configured when "vtp_mode" is "SERVER".
                type: bool
                required: false
                default: false
          dhcp_snooping:
            description:
              - DHCP Snooping configuration for securing DHCP operations.
              - Prevents rogue DHCP servers and protects against DHCP-based attacks.
              - Maintains a binding table of legitimate DHCP assignments.
              - Foundation for other security features like IP Source Guard.
            type: dict
            required: false
            suboptions:
              dhcp_admin_status:
                description:
                  - Globally enable or disable DHCP Snooping on the device.
                  - When true, enables DHCP Snooping globally.
                  - When false, disables DHCP Snooping on all VLANs.
                  - Must be enabled before configuring per-VLAN or per-interface settings.
                  - Equivalent to "ip dhcp snooping" command.
                type: bool
                required: false
                default: false
              dhcp_snooping_vlans:
                description:
                  - List of VLAN IDs where DHCP Snooping should be enabled.
                  - Each VLAN ID must be between 1 and 4094.
                  - Only VLANs in this list will have DHCP packets inspected.
                  - VLANs not in the list will forward DHCP packets normally.
                  - Can be configured as individual VLANs or ranges.
                  - All VLANs specified in "dhcp_snooping_proxy_bridge_vlans"
                    must also be included in this list.
                type: list
                elements: int
                required: false
              dhcp_snooping_glean:
                description:
                  - Enable DHCP gleaning for learning bindings from DHCP traffic.
                  - When true, learns DHCP bindings by monitoring DHCP acknowledgments.
                  - Useful for populating the binding table in existing networks.
                  - Should be used temporarily during initial deployment.
                  - Equivalent to "ip dhcp snooping glean" command.
                type: bool
                required: false
                default: false
              dhcp_snooping_database_agent_url:
                description:
                  - URL for storing DHCP Snooping binding database remotely.
                  - Supports TFTP, FTP, and other file transfer protocols.
                  - Provides persistence of bindings across switch reboots.
                  - Minimum 5 characters, maximum 227 characters.
                  - Format for the URL - "protocol://server_ip/filename"
                  - The URL must start with one of the following protocol prefixes
                    ("bootflash:", "crashinfo:", "flash:", "ftp:", "http:", "https:"
                    "rcp:", "scp:", "sftp:", "tftp:")
                  - Examples of valid URLs
                  - tftp URL - "tftp://192.168.1.100/dhcp_bindings.db",
                  - ftp URL - "ftp://server.example.com/backups/dhcp_bindings.db",
                  - flash URL - "flash:dhcp_bindings.db",
                  - bootflash URL - "bootflash:dhcp_bindings.db"
                type: str
                required: false
              dhcp_snooping_database_timeout:
                description:
                  - Timeout in seconds for database operations.
                  - Must be between 0 and 86400 seconds (24 hours).
                  - Time to wait for database read/write operations to complete.
                  - 0 means no timeout (wait indefinitely).
                  - Should be set based on network latency and server performance.
                type: int
                required: false
                default: 300
              dhcp_snooping_database_write_delay:
                description:
                  - Delay in seconds between database write operations.
                  - Must be between 15 and 86400 seconds.
                  - Batches multiple binding changes to reduce I/O overhead.
                  - Lower values provide more current data but increase overhead.
                  - Should balance between data currency and performance.
                type: int
                required: false
                default: 300
              dhcp_snooping_proxy_bridge_vlans:
                description:
                  - List of VLAN IDs to enable in bridge mode for DHCP relay.
                  - Each VLAN ID must be between 1 and 4094.
                  - Enables DHCP relay functionality in bridge mode.
                  - Useful for environments with DHCP servers on different subnets.
                  - Works in conjunction with DHCP relay configuration.
                  - All VLANs specified here must also be included in "dhcp_snooping_vlans" list.
                type: list
                elements: int
                required: false
          igmp_snooping:
            description:
              - Internet Group Management Protocol (IGMP) Snooping configuration.
              - Optimizes multicast traffic delivery in Layer 2 networks.
              - Prevents unnecessary multicast flooding by learning group memberships.
              - Essential for efficient multicast application delivery.
            type: dict
            required: false
            suboptions:
              enable_igmp_snooping:
                description:
                  - Globally enable or disable IGMP Snooping.
                  - When true, enables IGMP Snooping globally on the switch.
                  - When false, disables IGMP Snooping and floods all multicast traffic.
                  - When disabling IGMP snooping globally, first disable IGMP
                    snooping on all VLANs where it is currently enabled
                  - Enabled by default on most modern switches.
                  - Equivalent to "ip igmp snooping" command.
                type: bool
                required: false
                default: true
              igmp_snooping_querier:
                description:
                  - Enable IGMP Querier functionality globally.
                  - When true, the switch can act as an IGMP querier.
                  - When false, relies on external queriers (routers).
                  - Required when no multicast router is present in the VLAN.
                  - Equivalent to "ip igmp snooping querier" command.
                type: bool
                required: false
                default: false
              igmp_snooping_querier_address:
                description:
                  - Source IP address for IGMP query messages.
                  - Must be a valid IPv4 or IPv6 address.
                  - Used when the switch acts as an IGMP querier.
                  - Should be an address reachable by all multicast receivers.
                  - Helps identify the querier in network troubleshooting.
                type: str
                required: false
              igmp_snooping_querier_version:
                description:
                  - IGMP version for query messages.
                  - C(VERSION_1) - Basic join/leave functionality.
                  - C(VERSION_2) - Adds leave group messages and group-specific queries.
                  - C(VERSION_3) - Adds source-specific multicast (SSM) support.
                  - Choose based on receiver capabilities and application requirements.
                type: str
                required: false
                choices: ["VERSION_1", "VERSION_2", "VERSION_3"]
                default: "VERSION_2"
              igmp_snooping_querier_query_interval:
                description:
                  - Interval in seconds between IGMP general query messages.
                  - Must be between 1 and 18000 seconds.
                  - Lower values provide faster detection of membership changes.
                  - Higher values reduce network overhead but slow detection.
                  - Should be coordinated with receiver timeout settings.
                type: int
                required: false
                default: 125
              igmp_snooping_vlans:
                description:
                  - List of per-VLAN IGMP Snooping configurations.
                  - Allows customization of IGMP Snooping parameters per VLAN.
                  - Each VLAN can have different querier settings and mrouter ports.
                  - Useful for optimizing multicast delivery per network segment.
                type: list
                elements: dict
                required: false
                suboptions:
                  igmp_snooping_vlan_id:
                    description:
                      - VLAN ID for this IGMP Snooping configuration.
                      - Must be between 1 and 4094.
                      - VLAN must exist before configuring IGMP Snooping.
                      - Each VLAN can have independent IGMP Snooping settings.
                    type: int
                    required: true
                  enable_igmp_snooping:
                    description:
                      - Enable IGMP Snooping for this specific VLAN.
                      - When true, IGMP Snooping is active for this VLAN.
                      - When false, multicast traffic is flooded in this VLAN.
                      - Overrides the global IGMP Snooping setting for this VLAN.
                    type: bool
                    required: false
                    default: true
                  igmp_snooping_immediate_leave:
                    description:
                      - Enable immediate leave processing for IGMP in this VLAN.
                      - When true, immediately removes port from multicast group upon leave message.
                      - When false, waits for query timeout before removing port from group.
                      - Use with caution in shared media environments where multiple devices may be on same port.
                      - Provides faster leave processing for point-to-point links and single device connections.
                      - Equivalent to "ip igmp snooping immediate-leave" command per VLAN.
                    type: bool
                    required: false
                    default: true
                  igmp_snooping_querier:
                    description:
                      - Enable IGMP Querier for this specific VLAN.
                      - When true, this VLAN can have its own querier.
                      - When false, relies on external queriers for this VLAN.
                      - Useful when different VLANs have different querier requirements.
                      - If any VLAN in "igmp_snooping_vlans" has "igmp_snooping_querier" set to true, this must also be true.
                    type: bool
                    required: false
                    default: false
                  igmp_snooping_querier_address:
                    description:
                      - Source IP address for IGMP queries in this VLAN.
                      - Must be a valid IPv4 or IPv6 address.
                      - Should be an address within the VLAN's subnet.
                      - Used for VLAN-specific querier identification.
                    type: str
                    required: false
                  igmp_snooping_querier_version:
                    description:
                      - IGMP version for this VLAN's query messages.
                      - C(VERSION_1) - Basic join/leave functionality.
                      - C(VERSION_2) - Adds leave group messages and group-specific queries.
                      - C(VERSION_3) - Adds source-specific multicast (SSM) support.
                      - Can be different from the global IGMP version.
                      - Choose based on VLAN-specific application requirements.
                    type: str
                    required: false
                    choices: ["VERSION_1", "VERSION_2", "VERSION_3"]
                    default: "VERSION_2"
                  igmp_snooping_querier_query_interval:
                    description:
                      - Query interval for this specific VLAN in seconds.
                      - Must be between 1 and 18000 seconds.
                      - Can be optimized based on VLAN's multicast traffic patterns.
                      - Lower intervals for VLANs with dynamic memberships.
                    type: int
                    required: false
                  igmp_snooping_mrouter_port_list:
                    description:
                      - List of interface names that connect to multicast routers.
                      - Interfaces in this list are treated as mrouter ports.
                      - Multicast traffic is always forwarded to these ports.
                      - Format interface type and number (Example, "GigabitEthernet1/0/1").
                      - Essential for proper multicast routing integration.
                    type: list
                    elements: str
                    required: false
          mld_snooping:
            description:
              - Multicast Listener Discovery (MLD) Snooping configuration for IPv6.
              - IPv6 equivalent of IGMP Snooping for optimizing IPv6 multicast traffic.
              - Prevents unnecessary IPv6 multicast flooding in Layer 2 networks.
              - Essential for efficient IPv6 multicast application delivery.
            type: dict
            required: false
            suboptions:
              enable_mld_snooping:
                description:
                  - Globally enable or disable MLD Snooping.
                  - When true, enables MLD Snooping globally on the switch.
                  - When false, disables MLD Snooping and floods all IPv6 multicast traffic.
                  - Disabled by default on most switches.
                  - Equivalent to "ipv6 mld snooping" command.
                type: bool
                required: false
                default: false
              mld_snooping_querier:
                description:
                  - Enable MLD Querier functionality globally.
                  - When true, the switch can act as an MLD querier.
                  - When false, relies on external queriers (IPv6 routers).
                  - Required when no IPv6 multicast router is present in the VLAN.
                  - Equivalent to "ipv6 mld snooping querier" command.
                type: bool
                required: false
                default: false
              mld_snooping_querier_address:
                description:
                  - Source IPv6 address for MLD query messages.
                  - Querier Address must be a valid IPv6 Link-Local address.
                  - Used when the switch acts as an MLD querier.
                  - Should be an address reachable by all IPv6 multicast listeners.
                  - Helps identify the querier in network troubleshooting.
                type: str
                required: false
              mld_snooping_querier_version:
                description:
                  - MLD version for query messages.
                  - C(VERSION_1) - Basic IPv6 multicast listener functionality.
                  - C(VERSION_2) - Adds source-specific multicast and enhanced features.
                  - Choose based on IPv6 application requirements and receiver capabilities.
                  - VERSION_2" is recommended for modern IPv6 networks.
                type: str
                required: false
                choices: ["VERSION_1", "VERSION_2"]
                default: "VERSION_2"
              mld_snooping_listener:
                description:
                  - Enable listener message suppression for MLD.
                  - When true, suppresses duplicate listener reports to reduce overhead.
                  - When false, forwards all listener reports to queriers.
                  - Helps optimize bandwidth usage in dense IPv6 multicast environments.
                  - Equivalent to "ipv6 mld snooping listener-message-suppression" command.
                type: bool
                required: false
                default: true
              mld_snooping_querier_query_interval:
                description:
                  - Interval in seconds between MLD general query messages.
                  - Must be between 1 and 18000 seconds.
                  - Lower values provide faster detection of IPv6 membership changes.
                  - Higher values reduce network overhead but slow detection.
                  - Should be coordinated with IPv6 receiver timeout settings.
                type: int
                required: false
                default: 125
              mld_snooping_vlans:
                description:
                  - List of per-VLAN MLD Snooping configurations.
                  - Allows customization of MLD Snooping parameters per VLAN.
                  - Each VLAN can have different querier settings and mrouter ports.
                  - Useful for optimizing IPv6 multicast delivery per network segment.
                type: list
                elements: dict
                required: false
                suboptions:
                  mld_snooping_vlan_id:
                    description:
                      - VLAN ID for this MLD Snooping configuration.
                      - Must be between 1 and 4094.
                      - VLAN must exist before configuring MLD Snooping.
                      - Each VLAN can have independent MLD Snooping settings.
                    type: int
                    required: true
                  enable_mld_snooping:
                    description:
                      - Enable MLD Snooping for this specific VLAN.
                      - When true, MLD Snooping is active for this VLAN.
                      - When false, IPv6 multicast traffic is flooded in this VLAN.
                      - Overrides the global MLD Snooping setting for this VLAN.
                    type: bool
                    required: false
                    default: false
                  mld_snooping_enable_immediate_leave:
                    description:
                      - Enable immediate leave processing for MLDv1 in this VLAN.
                      - When true, immediately removes port from multicast group upon leave.
                      - When false, waits for query timeout before removing port.
                      - Use with caution in shared media environments.
                      - Provides faster leave processing for point-to-point links.
                    type: bool
                    required: false
                    default: false
                  mld_snooping_querier:
                    description:
                      - Enable MLD Querier for this specific VLAN.
                      - When true, this VLAN can have its own MLD querier.
                      - When false, relies on external queriers for this VLAN.
                      - Useful when different VLANs have different querier requirements.
                    type: bool
                    required: false
                    default: false
                  mld_snooping_querier_address:
                    description:
                      - Source IPv6 address for MLD queries in this VLAN.
                      - Must be a valid IPv6 address format.
                      - Should be an address within the VLAN's IPv6 prefix.
                      - Used for VLAN-specific querier identification.
                    type: str
                    required: false
                  mld_snooping_querier_version:
                    description:
                      - MLD version for this VLAN's query messages.
                      - C(VERSION_1) - Basic IPv6 multicast listener functionality.
                      - C(VERSION_2) - Adds source-specific multicast and enhanced features.
                      - Can be different from the global MLD version.
                      - Choose based on VLAN-specific IPv6 application requirements.
                    type: str
                    required: false
                    choices: ["VERSION_1", "VERSION_2"]
                    default: "VERSION_1"
                  mld_snooping_querier_query_interval:
                    description:
                      - Query interval for this specific VLAN in seconds.
                      - Must be between 1 and 18000 seconds.
                      - Can be optimized based on VLAN's IPv6 multicast traffic patterns.
                      - Lower intervals for VLANs with dynamic IPv6 memberships.
                    type: int
                    required: false
                  mld_snooping_mrouter_port_list:
                    description:
                      - List of interface names that connect to IPv6 multicast routers.
                      - Interfaces in this list are treated as IPv6 mrouter ports.
                      - IPv6 multicast traffic is always forwarded to these ports.
                      - Format interface type and number (Example, "GigabitEthernet1/0/1").
                      - Essential for proper IPv6 multicast routing integration.
                    type: list
                    elements: str
                    required: false
          authentication:
            description:
              - IEEE 802.1X authentication configuration settings.
              - Provides port-based network access control for enhanced security.
              - Authenticates devices before granting network access.
              - Foundation for Identity-Based Networking Services (IBNS).
            type: dict
            required: false
            suboptions:
              enable_dot1x_authentication:
                description:
                  - Globally enable or disable 802.1X authentication.
                  - When true, enables 802.1X authentication globally.
                  - When false, disables 802.1X authentication on all ports.
                  - Must be enabled before configuring per-port authentication.
                  - Equivalent to "dot1x system-auth-control" command.
                type: bool
                required: false
                default: false
              authentication_config_mode:
                description:
                  - Authentication configuration mode (legacy vs. new style).
                  - C(LEGACY) - Traditional authentication manager configuration mode.
                  - C(NEW_STYLE) - Identity-Based Networking Services (IBNS) mode.
                  - NEW_STYLE is recommended for modern authentication deployments.
                  - Affects how authentication policies are configured and applied.
                  - Once the authentication configuration mode is set, it cannot be changed.
                type: str
                required: false
                choices: ["LEGACY", "NEW_STYLE"]
                default: "LEGACY"
          logical_ports:
            description:
              - Port channel (EtherChannel) configuration for link aggregation.
              - Combines multiple physical links into a single logical interface.
              - Provides increased bandwidth and redundancy for critical connections.
              - Supports LACP, PAgP, and static (manual) aggregation methods.
            type: dict
            required: false
            suboptions:
              port_channel_auto:
                description:
                  - Enable automatic port channel creation (Auto-LAG).
                  - When true, enables automatic detection and creation of port channels.
                  - When false, requires manual port channel configuration.
                  - Auto-LAG can simplify configuration but may not suit all environments.
                  - Equivalent to "port-channel auto" command.
                type: bool
                required: false
                default: false
              port_channel_lacp_system_priority:
                description:
                  - System priority for LACP protocol negotiation.
                  - Must be between 0 and 65535.
                  - Lower values have higher priority in LACP negotiations.
                  - Used to determine which switch controls the port channel.
                  - Should be consistent across switches for predictable behavior.
                type: int
                required: false
                default: 32768
              port_channel_load_balancing_method:
                description:
                  - Method for distributing traffic across port channel members.
                  - Based on MAC addresses - "SRC_MAC", "DST_MAC", "SRC_DST_MAC".
                  - Based on IP addresses - "SRC_IP", "DST_IP", "SRC_DST_IP".
                  - Based on TCP/UDP ports - "RC_PORT", "DST_PORT", "SRC_DST_PORT".
                  - VLAN-based load balancing methods - "VLAN_SRC_IP", "VLAN_DST_IP", "VLAN_SRC_DST_IP",
                    "VLAN_SRC_MIXED_IP_PORT", "VLAN_DST_MIXED_IP_PORT", "VLAN_SRC_DST_MIXED_IP_PORT".
                  - VLAN-based load balancing methods for port channels are only
                    supported on Cisco Catalyst 9600 Series Switches.
                  - Choose based on traffic patterns and load balancing requirements.
                  - Mixed options combine multiple criteria for better distribution.
                type: str
                required: false
                choices: ["SRC_MAC", "DST_MAC", "SRC_DST_MAC", "SRC_IP", "DST_IP",
                        "SRC_DST_IP", "SRC_PORT", "DST_PORT", "SRC_DST_PORT", "SRC_DST_MIXED_IP_PORT",
                        "SRC_MIXED_IP_PORT", "DST_MIXED_IP_PORT", "VLAN_SRC_IP", "VLAN_DST_IP",
                        "VLAN_SRC_DST_IP", "VLAN_SRC_MIXED_IP_PORT", "VLAN_DST_MIXED_IP_PORT",
                        "VLAN_SRC_DST_MIXED_IP_PORT"]
                default: "SRC_DST_IP"
              port_channels:
                description:
                  - List of port channel configurations to create.
                  - Each port channel aggregates multiple physical interfaces.
                  - Supports different protocols (LACP, PAgP, static).
                  - Each port channel has unique members and configuration.
                  - Port channels can only be configured when "port_channel_auto" is false.
                type: list
                elements: dict
                required: false
                suboptions:
                  port_channel_protocol:
                    description:
                      - Protocol to use for this port channel.
                      - C(LACP) - IEEE 802.3ad standard, recommended for most environments.
                      - C(PAGP) - Cisco proprietary protocol, for Cisco-only environments.
                      - C(NONE) - Static port channel without negotiation protocol.
                      - LACP provides better standards compliance and interoperability.
                    type: str
                    required: true
                    choices: ["LACP", "PAGP", "NONE"]
                  port_channel_name:
                    description:
                      - Name identifier for the port channel interface.
                      - Must be between 13 and 15 characters.
                      - Format typically follows "Port-channelX" where X is the number.
                      - Must be unique within the switch configuration.
                      - Used in interface configuration and monitoring.
                    type: str
                    required: true
                  port_channel_min_links:
                    description:
                      - Minimum number of active links required for port channel to be operational.
                      - Must be between 2 and 8.
                      - Port channel goes down if active links fall below this threshold.
                      - Provides guaranteed bandwidth and redundancy requirements.
                      - Should be set based on application bandwidth and availability needs.
                    type: int
                    required: false
                    default: 1
                  port_channel_members:
                    description:
                      - List of physical interfaces that belong to this port channel.
                      - All member interfaces must have compatible configuration.
                      - Includes interface names and protocol-specific parameters.
                      - Member configuration varies based on the chosen protocol.
                    type: list
                    elements: dict
                    required: true
                    suboptions:
                      port_channel_interface_name:
                        description:
                          - Name of the physical interface to add to the port channel.
                          - Must be a valid interface on the switch.
                          - Format interface type and number (Example, "GigabitEthernet1/0/1").
                          - Interface must not be a member of another port channel.
                          - Interface configuration must be compatible with other members.
                        type: str
                        required: true
                      port_channel_mode:
                        description:
                          - Port channel mode for this member interface.
                          - For "LACP" protocol
                          - C(ACTIVE) - (initiates negotiation)
                          - C(PASSIVE) - (responds only)
                          - For "PAgP" protocol
                          - C(AUTO) - (responds only)
                          - C(AUTO_NON_SILENT - (responds only, with more frequent messages)
                          - C(DESIRABLE) - (initiates negotiation)
                          - C(DESIRABLE_NON_SILENT) - (initiates negotiation, with more frequent messages)
                          - For "NONE" protocol
                          - C(ON) - (static aggregation without negotiation)
                          - Choose based on desired negotiation behavior and protocol.
                        type: str
                        required: false
                        choices: ["ACTIVE", "PASSIVE", "AUTO", "AUTO_NON_SILENT", "DESIRABLE", "DESIRABLE_NON_SILENT", "ON"]
                      port_channel_port_priority:
                        description:
                          - Priority for this interface in port channel selection.
                          - For "LACP" protocol - 0-65535 (lower values have higher priority).
                          - For "PAgP" protocol - 0-255 (lower values have higher priority).
                          - Used when more interfaces are available than can be active.
                          - Helps determine which interfaces carry traffic in standby scenarios.
                        type: int
                        required: false
                      port_channel_rate:
                        description:
                          - LACP packet transmission rate (LACP protocol only).
                          - C(1) - Fast rate (1 second intervals).
                          - C(30) - Normal rate (30 second intervals).
                          - Fast rate provides quicker failure detection but increases overhead.
                          - Only applicable when using LACP protocol.
                        type: int
                        required: false
                        choices: [1, 30]
                        default: 30
                      port_channel_learn_method:
                        description:
                          - Learning method for PAgP protocol (PAgP only).
                          - C(AGGREGATION_PORT) - Learn on the port channel interface.
                          - C(PHYSICAL_PORT) - Learn on individual physical interfaces.
                          - Affects MAC address learning and forwarding behavior.
                          - Only applicable when using PAgP protocol.
                        type: str
                        required: false
                        choices: ["AGGREGATION_PORT", "PHYSICAL_PORT"]
                        default: "AGGREGATION_PORT"
          port_configuration:
            description:
              - Individual interface configuration settings for all port types.
              - Allows per-interface customization of Layer 2 features.
              - Each interface can have unique switchport, security, and protocol settings.
              - Essential for fine-grained network access control and optimization.
              - NOTE - configure switchport_interface_config FIRST before other interface features
            type: list
            elements: dict
            required: false
            suboptions:
              interface_name:
                description:
                  - Name of the interface to configure.
                  - Must be a valid interface identifier on the target switch.
                  - Format interface type and number (Example, "GigabitEthernet1/0/1").
                  - Interface must exist on the device and be configurable.
                  - Used as the key to identify which interface to configure.
                type: str
                required: true
              switchport_interface_config:
                description:
                  - Basic switchport configuration for Layer 2 operation.
                  - Defines interface mode, VLAN assignments, and administrative settings.
                  - Essential for connecting end devices and configuring trunk links.
                  - Forms the foundation of Layer 2 connectivity.
                type: dict
                required: false
                suboptions:
                  switchport_description:
                    description:
                      - Descriptive text for interface documentation and identification.
                      - Maximum 230 characters of descriptive text.
                      - Should follow organizational naming conventions.
                      - Useful for documentation, monitoring, and troubleshooting.
                      - Cannot include non-ASCII characters.
                    type: str
                    required: false
                  switchport_mode:
                    description:
                      - Switchport operational mode.
                      - C(ACCESS) - Interface carries traffic for a single VLAN.
                      - C(TRUNK) - Interface carries traffic for multiple VLANs.
                      - C(DYNAMIC_AUTO) - Negotiates mode with neighbor (becomes trunk if neighbor is trunk/desirable).
                      - C(DYNAMIC_DESIRABLE) - Actively negotiates to become trunk.
                      - C(DOT1Q_TUNNEL) - Interface acts as a tunnel port for service provider networks.
                    type: str
                    required: false
                    choices: ["ACCESS", "TRUNK", "DYNAMIC_AUTO", "DYNAMIC_DESIRABLE", "DOT1Q_TUNNEL"]
                    default: "ACCESS"
                  access_vlan:
                    description:
                      - VLAN ID for untagged traffic when interface is in access mode.
                      - Must be between 1 and 4094.
                      - Only applicable when switchport_mode is "ACCESS".
                      - VLAN must exist before assigning to interface.
                      - Defines which VLAN untagged traffic will be placed in.
                    type: int
                    required: false
                    default: 1
                  voice_vlan:
                    description:
                      - VLAN ID for IP phone traffic on access ports.
                      - Must be between 1 and 4094.
                      - Allows IP phones to use a separate VLAN for voice traffic.
                      - Enables QoS prioritization and security separation for voice.
                      - Only applicable on access ports with connected IP phones.
                    type: int
                    required: false
                  admin_status:
                    description:
                      - Administrative status of the interface.
                      - When true, interface is administratively enabled (no shutdown).
                      - When false, interface is administratively disabled (shutdown).
                      - Disabled interfaces do not pass traffic but retain configuration.
                      - Used for maintenance and security purposes.
                    type: bool
                    required: false
                    default: true
                  allowed_vlans:
                    description:
                      - List of VLAN IDs allowed on trunk interfaces.
                      - Each VLAN ID must be between 1 and 4094.
                      - Only applicable when switchport_mode is TRUNK.
                      - Controls which VLANs can traverse the trunk link.
                      - Helps optimize bandwidth and enhance security.
                    type: list
                    elements: int
                    required: false
                  native_vlan_id:
                    description:
                      - Native VLAN ID for trunk interfaces (untagged traffic).
                      - Must be between 1 and 4094.
                      - Only applicable when switchport_mode is TRUNK.
                      - Defines which VLAN untagged traffic belongs to on trunk.
                      - Should be changed from default (VLAN 1) for security.
                    type: int
                    required: false
                    default: 1
              vlan_trunking_interface_config:
                description:
                  - VLAN trunking specific configuration for trunk interfaces.
                  - Controls DTP negotiation, protection, and VLAN pruning.
                  - Optimizes trunk operation and enhances security.
                type: dict
                required: false
                suboptions:
                  enable_dtp_negotiation:
                    description:
                      - Dynamic Trunking Protocol (DTP) negotiation setting.
                      - Controls whether the interface participates in DTP negotiation.
                      - When enabled, interface can negotiate trunking with neighbor.
                      - When disabled, prevents DTP packet transmission (recommended for security).
                      - Disable DTP when connecting to non-Cisco devices or for security.
                      - DTP negotiation control REQUIRES "switchport_mode" to be "TRUNK" (not "DYNAMIC")
                    type: bool
                    required: false
                    default: true
                  protected:
                    description:
                      - Enable protected port functionality.
                      - When true, prevents traffic between protected ports at Layer 2.
                      - Traffic between protected ports must traverse a Layer 3 device.
                      - Useful for isolating ports within the same VLAN.
                      - Enhances security in shared network environments.
                    type: bool
                    required: false
                    default: false
                  pruning_vlan_ids:
                    description:
                      - List of VLAN IDs eligible for VTP pruning on this trunk.
                      - Each VLAN ID must be between 1 and 4094.
                      - Controls which VLANs can be pruned from this trunk.
                      - Helps optimize bandwidth by removing unnecessary VLAN traffic.
                      - Works in conjunction with global VTP pruning settings.
                    type: list
                    elements: int
                    required: false
              dot1x_interface_config:
                description:
                  - 802.1X authentication configuration for the interface.
                  - Configures authentication settings, timers, and behavior for network access control.
                type: dict
                required: false
                suboptions:
                  dot1x_interface_authentication_mode:
                    description:
                      - Sets the 802.1X authentication mode for the interface.
                      - C(AUTO) - Interface can authenticate both 802.1X and non-802.1X devices.
                      - C(FORCE_AUTHORIZED) - Interface only allows authenticated devices.
                      - C(FORCE_UNAUTHORIZED) - Interface only allows unauthenticated devices.
                      - Determines how the interface handles authentication requests.
                    type: str
                    choices: ["AUTO", "FORCE_AUTHORIZED", "FORCE_UNAUTHORIZED"]
                    required: false
                  dot1x_interface_pae_type:
                    description:
                      - Port Access Entity (PAE) type for 802.1X authentication.
                      - C(AUTHENTICATOR) - Interface acts as an authenticator (common for switches).
                      - C(SUPPLICANT) - Interface acts as a supplicant (common for client
                        devices).
                      - C(BOTH) - Interface can act as both authenticator and supplicant.
                      - Defines the role of the interface in the authentication process.
                    type: str
                    choices: ["AUTHENTICATOR", "SUPPLICANT", "BOTH"]
                    required: false
                  dot1x_interface_control_direction:
                    description:
                      - Control direction for 802.1X authentication on the interface.
                      - When set to C(BOTH), controls both inbound and outbound traffic.
                      - When set to C(IN), only controls inbound traffic.
                      - Specifies which traffic direction is controlled by authentication.
                    type: str
                    choices: ["BOTH", "IN"]
                    required: false
                  dot1x_interface_host_mode:
                    description:
                      - Host mode for 802.1X authentication on the interface.
                      - C(SINGLE_HOST) - Only one host can authenticate on the port.
                      - C(MULTI_HOST) - Multiple hosts can authenticate, but only one at a
                        time.
                      - C(MULTI_AUTH) - Multiple hosts can authenticate simultaneously.
                      - C(MULTI_DOMAIN) - Multiple hosts from different domains can authenticate.
                      - Determines how many hosts can authenticate on a single port.
                    type: str
                    choices: ["SINGLE_HOST", "MULTI_HOST", "MULTI_AUTH", "MULTI_DOMAIN"]
                    required: false
                  dot1x_interface_enable_inactivity_timer_from_server:
                    description:
                      - Enable receiving inactivity timer value from RADIUS server.
                      - When enabled, uses server-provided inactivity timeout values.
                    type: bool
                    required: false
                  dot1x_interface_inactivity_timer:
                    description:
                      - Inactivity timer value in seconds for 802.1X authentication.
                      - Time after which an inactive authenticated session is terminated.
                      - Valid range is 1-65535 seconds.
                    type: int
                    required: false
                  dot1x_interface_authentication_order:
                    description:
                      - Authentication method order for the interface.
                      - C(DOT1X) - 802.1X authentication method.
                      - C(MAB) - MAC Authentication Bypass method.
                      - C(WEBAUTH) - Web-based authentication method.
                      - Defines the sequence in which authentication methods are tried.
                      - Methods are attempted in the order specified in the list.
                    type: list
                    elements: str
                    choices: ["DOT1X", "MAB", "WEBAUTH"]
                    required: false
                  dot1x_interface_enable_reauth:
                    description:
                      - Enable periodic re-authentication for 802.1X on the interface.
                      - When enabled, authenticated clients are re-authenticated periodically.
                    type: bool
                    required: false
                  dot1x_interface_port_control:
                    description:
                      - Port control mode for 802.1X authentication.
                      - C(AUTO) - Port automatically authorizes or unauthorizes based on
                        authentication state.
                      - C(FORCE_AUTHORIZED) - Port is always authorized regardless of
                        authentication state.
                      - C(FORCE_UNAUTHORIZED) - Port is always unauthorized regardless of
                        authentication state.
                      - Determines the initial authorization state of the port.
                    type: str
                    choices: ["AUTO", "FORCE_AUTHORIZED", "FORCE_UNAUTHORIZED"]
                    required: false
                  dot1x_interface_priority:
                    description:
                      - Authentication priority list for the interface.
                      - Defines priority order for authentication methods when multiple are configured.
                    type: list
                    elements: str
                    required: false
                  dot1x_interface_max_reauth_requests:
                    description:
                      - Maximum number of re-authentication requests sent to a client.
                      - After this limit, the client is considered unreachable.
                      - Valid range is 1-10 requests.
                    type: int
                    required: false
                  dot1x_interface_enable_reauth_timer_from_server:
                    description:
                      - Enable receiving re-authentication timer value from RADIUS server.
                      - When enabled, uses server-provided re-authentication timeout values.
                    type: bool
                    required: false
                  dot1x_interface_reauth_timer:
                    description:
                      - Re-authentication timer value in seconds for 802.1X authentication.
                      - Time interval between periodic re-authentication attempts.
                      - Valid range is 1-65535 seconds.
                    type: int
                    required: false
                  dot1x_interface_tx_period:
                    description:
                      - Transmission period for EAP Request/Identity frames.
                      - Time interval between successive EAP Request/Identity transmissions.
                      - Valid range is 1-65535 seconds.
                    type: int
                    required: false
              mab_interface_config:
                description:
                  - MAC Authentication Bypass (MAB) configuration for this interface.
                  - Provides authentication for devices that don't support 802.1X.
                  - Uses device MAC address as the authentication credential.
                  - Common for printers, cameras, and legacy devices.
                type: dict
                required: false
                suboptions:
                  enable_mab:
                    description:
                      - Enable MAC Authentication Bypass on this interface.
                      - When true, allows authentication using device MAC address.
                      - When false, disables MAB authentication method.
                      - Useful for devices that cannot perform 802.1X authentication.
                      - Often used in combination with 802.1X authentication.
                    type: bool
                    required: false
                    default: false
              stp_interface_config:
                description:
                  - Spanning Tree Protocol configuration for this specific interface.
                  - Controls STP behavior, timers, and protection features per port.
                  - Allows fine-tuning of STP operation for different interface types.
                  - Essential for optimizing convergence and preventing loops.
                type: dict
                required: false
                suboptions:
                  stp_interface_portfast_mode:
                    description:
                      - PortFast mode configuration for this interface.
                      - C(NONE) - No PortFast configuration (uses global setting).
                      - C(DISABLE) - Explicitly disable PortFast on this interface.
                      - C(EDGE) - Enable PortFast for edge ports (end device connections).
                      - C(EDGE_TRUNK) - Enable PortFast on trunk ports to edge devices.
                      - C(NETWORK) - Configure as network port (inter-switch links).
                      - C(TRUNK) - Enable PortFast on all trunk ports.
                      - Advanced portfast modes (EDGE_TRUNK, NETWORK, TRUNK) are only supported on
                        Catalyst 9600 Series switches and specific Catalyst 9500 Series models
                        (C9500-32C, C9500-32QC, C9500-48Y4C, C9500-24Y4C, C9500X-28C8D).
                    type: str
                    required: false
                    choices: ["NONE", "DISABLE", "EDGE", "EDGE_TRUNK", "NETWORK", "TRUNK"]
                  stp_interface_bpdu_filter:
                    description:
                      - BPDU Filter configuration for this interface.
                      - When true, prevents sending and receiving BPDUs on PortFast ports.
                      - When false, allows normal BPDU processing.
                      - Use with caution as it can create loops if misconfigured.
                      - Typically used on ports connected to end devices.
                    type: bool
                    required: false
                    default: false
                  stp_interface_bpdu_guard:
                    description:
                      - BPDU Guard configuration for this interface.
                      - When true, shuts down PortFast ports that receive BPDUs.
                      - When false, disables BPDU Guard protection.
                      - Protects against accidental switch connections to access ports.
                      - Essential security feature for edge port protection.
                    type: bool
                    required: false
                    default: false
                  stp_interface_cost:
                    description:
                      - Path cost for this interface in STP calculations.
                      - Must be between 1 and 20000000.
                      - Lower costs are preferred paths in STP topology.
                      - Allows manual control of STP path selection.
                      - Should reflect actual link bandwidth and desired traffic flow.
                    type: int
                    required: false
                  stp_interface_guard:
                    description:
                      - Guard mode configuration for this interface
                      - C(LOOP) - Enable Loop Guard to prevent loops from unidirectional failures.
                      - C(ROOT) - Enable Root Guard to prevent inferior BPDUs.
                      - C(NONE) - Disable guard features on this interface.
                      - Choose based on interface role and protection requirements.
                    type: str
                    required: false
                    choices: ["LOOP", "ROOT", "NONE"]
                  stp_interface_priority:
                    description:
                      - Port priority for this interface in STP tie-breaking.
                      - Must be between 0 and 240 in increments of 16.
                      - Lower values have higher priority for forwarding state.
                      - Used when multiple ports have equal cost to root bridge.
                      - Helps control which ports forward traffic in redundant topologies.
                    type: int
                    required: false
                    default: 128
                  stp_interface_per_vlan_cost:
                    description:
                      - Per-VLAN cost configuration for this interface.
                      - Allows different costs for different VLANs on the same interface.
                      - Enables per-VLAN load balancing in PVST plus environments.
                      - Useful for optimizing traffic flow across VLANs.
                    type: dict
                    required: false
                    suboptions:
                      priority:
                        description:
                          - Cost value to apply to the specified VLANs.
                          - Must be between 1 and 20000000.
                          - Lower costs make this path preferred for the specified VLANs.
                          - Should be coordinated with overall STP design.
                        type: int
                        required: false
                      vlan_ids:
                        description:
                          - List of VLAN IDs to apply this cost setting to.
                          - Each VLAN ID must be between 1 and 4094.
                          - Allows grouping VLANs with the same cost requirements.
                          - VLANs must exist before applying cost settings.
                        type: list
                        elements: int
                        required: false
                  stp_interface_per_vlan_priority:
                    description:
                      - Per-VLAN priority configuration for this interface.
                      - Allows different priorities for different VLANs on the same interface.
                      - Enables per-VLAN load balancing and traffic engineering.
                      - Useful for optimizing port selection across VLANs.
                    type: dict
                    required: false
                    suboptions:
                      priority:
                        description:
                          - Priority value to apply to the specified VLANs.
                          - Must be between 0 and 240 in increments of 16.
                          - Lower values have higher priority for forwarding state.
                          - Should be coordinated with overall STP design.
                        type: int
                        required: false
                      vlan_ids:
                        description:
                          - List of VLAN IDs to apply this priority setting to.
                          - Each VLAN ID must be between 1 and 4094.
                          - Allows grouping VLANs with the same priority requirements.
                          - VLANs must exist before applying priority settings.
                        type: list
                        elements: int
                        required: false
              dhcp_snooping_interface_config:
                description:
                  - DHCP Snooping interface configuration for this specific interface.
                  - Controls DHCP security features and trust settings per interface.
                  - Provides granular control over DHCP packet processing on individual ports.
                  - Essential for securing DHCP operations against rogue servers and attacks.
                type: dict
                required: false
                suboptions:
                  dhcp_snooping_interface_rate:
                    description:
                      - Maximum rate of DHCP packets per second allowed on this interface.
                      - Must be between 1 and 2048 packets per second.
                      - Helps prevent DHCP flooding attacks by rate-limiting DHCP traffic.
                      - Higher rates may be needed for interfaces connecting to DHCP servers.
                      - Lower rates are typically sufficient for client access ports.
                    type: int
                    required: false
                    default: 100
                  dhcp_snooping_interface_trust:
                    description:
                      - Configure this interface as trusted for DHCP operations.
                      - When true, interface is trusted and DHCP packets are forwarded without inspection.
                      - When false, interface is untrusted and DHCP packets are inspected and filtered.
                      - Trusted interfaces typically connect to legitimate DHCP servers or uplinks.
                      - Untrusted interfaces typically connect to end devices that should not offer DHCP.
                    type: bool
                    required: false
                    default: false
              cdp_interface_config:
                description:
                  - Cisco Discovery Protocol (CDP) interface configuration for this specific interface.
                  - Controls CDP operation on individual interfaces independent of global settings.
                  - Allows per-interface customization of CDP behavior and logging.
                  - Useful for selectively enabling/disabling CDP on specific ports.
                type: dict
                required: false
                suboptions:
                  cdp_interface_admin_status:
                    description:
                      - Enable or disable CDP on this specific interface.
                      - When true, CDP is enabled on this interface (sends and receives CDP packets).
                      - When false, CDP is disabled on this interface.
                      - Overrides the global CDP setting for this specific interface.
                      - Recommended to disable on interfaces connecting to untrusted devices.
                    type: bool
                    required: false
                    default: true
                  cdp_interface_log_duplex_mismatch:
                    description:
                      - Enable logging of duplex mismatches detected by CDP on this interface.
                      - When true, logs warnings when CDP detects duplex mismatches with the neighbor.
                      - When false, duplex mismatch detection logging is disabled for this interface.
                      - Useful for troubleshooting connectivity issues and performance problems.
                      - Helps identify configuration inconsistencies between connected devices.
                    type: bool
                    required: false
                    default: true
              lldp_interface_config:
                description:
                  - Link Layer Discovery Protocol (LLDP) interface configuration for this specific interface.
                  - Controls LLDP packet transmission and reception behavior per interface.
                  - Provides granular control over LLDP operation on individual ports.
                  - Allows optimization of LLDP behavior based on interface usage.
                type: dict
                required: false
                suboptions:
                  lldp_interface_receive_transmit:
                    description:
                      - Configure LLDP transmission and reception behavior for this interface.
                      - C(TRANSMIT_ONLY) - Only send LLDP packets, do not process received packets.
                      - C(RECEIVE_ONLY) - Only receive and process LLDP packets, do not transmit.
                      - C(TRANSMIT_AND_RECEIVE) - Both send and receive LLDP packets (default behavior).
                      - C(DISABLED) - Completely disable LLDP on this interface.
                      - Choose based on security requirements and interface role in the network.
                    type: str
                    required: false
                    choices: ["TRANSMIT_ONLY", "RECEIVE_ONLY", "TRANSMIT_AND_RECEIVE", "DISABLED"]
                    default: "TRANSMIT_AND_RECEIVE"
              vtp_interface_config:
                description:
                  - VLAN Trunking Protocol (VTP) interface configuration for this specific interface.
                  - Controls VTP advertisement processing on individual interfaces.
                  - Allows per-interface control of VTP participation.
                  - Useful for securing VTP domains and preventing unauthorized updates.
                type: dict
                required: false
                suboptions:
                  vtp_interface_admin_status:
                    description:
                      - Enable or disable VTP on this specific interface.
                      - When true, VTP advertisements are processed on this interface.
                      - When false, VTP advertisements are blocked on this interface.
                      - Helps prevent VTP updates from untrusted sources.
                      - Recommended to disable on interfaces connecting to untrusted switches.
                    type: bool
                    required: false
                    default: true
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.9
notes:
   - SDK Method used are
    - devices.get_device_list
    - wired.Wired.get_configurations_for_an_intended_layer2_feature_on_a_wired_device
    - wired.Wired.get_configurations_for_a_deployed_layer2_feature_on_a_wired_device
    - wired.Wired.create_configurations_for_an_intended_layer2_feature_on_a_wired_device
    - wired.Wired.update_configurations_for_an_intended_layer2_feature_on_a_wired_device
    - wired.Wired.delete_configurations_for_an_intended_layer2_feature_on_a_wired_device
    - wired.Wired.deploy_the_intended_configuration_features_on_a_wired_device
   - Paths used are
    - GET /dna/intent/api/v1/networkDevices
    - GET /dna/intent/api/v1/networkDevices/${id}/configFeatures/intended/layer2/${feature}
    - GET /dna/intent/api/v1/networkDevices/${id}/configFeatures/intended/layer2/${feature}
    - POST /dna/intent/api/v1/networkDevices/${id}/configFeatures/intended/layer2/${feature}
    - PUT /dna/intent/api/v1/networkDevices/${id}/configFeatures/intended/layer2/${feature}
    - DELETE /dna/intent/api/v1/networkDevices/${id}/configFeatures/intended/layer2/${feature}
    - POST /dna/intent/api/v1/networkDevices/${id}/configFeatures/deploy
"""

EXAMPLES = r"""
- name: Create multiple VLANs with comprehensive settings
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        device_collection_status_check: false
        layer2_configuration:
          vlans:
            - vlan_id: 100
              vlan_name: Production_Network
              vlan_admin_status: true
            - vlan_id: 200
              vlan_name: Development_Network
              vlan_admin_status: true
            - vlan_id: 300
              vlan_name: Guest_Network
              vlan_admin_status: false

- name: Update VLAN settings
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          vlans:
            - vlan_id: 300
              vlan_name: Guest_Network_Updated
              vlan_admin_status: true

- name: Delete VLANs
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: deleted
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          vlans:
            - vlan_id: 300

- name: Configure CDP discovery protocol
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          cdp:
            cdp_admin_status: true
            cdp_hold_time: 180
            cdp_timer: 60
            cdp_advertise_v2: true
            cdp_log_duplex_mismatch: true

- name: Configure LLDP discovery protocol
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          lldp:
            lldp_admin_status: true
            lldp_hold_time: 240
            lldp_timer: 30
            lldp_reinitialization_delay: 3

- name: Configure Spanning Tree Protocol
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          stp:
            stp_mode: MST
            stp_portfast_mode: ENABLE
            stp_bpdu_guard: true
            stp_bpdu_filter: false
            stp_backbonefast: true
            stp_extended_system_id: true
            stp_logging: true
            stp_loopguard: false
            stp_transmit_hold_count: 8
            stp_uplinkfast: false
            stp_uplinkfast_max_update_rate: 200
            stp_etherchannel_guard: true
            stp_instances:
              - stp_instance_vlan_id: 100
                stp_instance_priority: 32768
                enable_stp: true
                stp_instance_max_age_timer: 20
                stp_instance_hello_interval_timer: 2
                stp_instance_forward_delay_timer: 15
              - stp_instance_vlan_id: 200
                stp_instance_priority: 16384
                enable_stp: true

- name: Configure VLAN Trunking Protocol
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          vtp:
            vtp_mode: TRANSPARENT
            vtp_version: VERSION_2
            vtp_domain_name: CORPORATE_DOMAIN
            vtp_pruning: true
            vtp_configuration_file_name: flash:vtp_config.dat
            vtp_source_interface: Loopback0

- name: Configure DHCP Snooping
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          dhcp_snooping:
            dhcp_admin_status: true
            dhcp_snooping_vlans:
              - 100
              - 200
              - 300
            dhcp_snooping_glean: true
            dhcp_snooping_database_agent_url: tftp://192.168.1.100/dhcp_binding.db
            dhcp_snooping_database_timeout: 600
            dhcp_snooping_database_write_delay: 300
            dhcp_snooping_proxy_bridge_vlans:
              - 100
              - 200

- name: Configure IGMP Snooping for multicast
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          igmp_snooping:
            enable_igmp_snooping: true
            igmp_snooping_querier: false
            igmp_snooping_querier_address: 192.168.1.10
            igmp_snooping_querier_version: VERSION_2
            igmp_snooping_querier_query_interval: 125
            igmp_snooping_vlans:
              - igmp_snooping_vlan_id: 100
                enable_igmp_snooping: true
                igmp_snooping_querier: false
                igmp_snooping_querier_address: 192.168.1.11
                igmp_snooping_querier_version: VERSION_2
                igmp_snooping_querier_query_interval: 125
                igmp_snooping_mrouter_port_list:
                  - GigabitEthernet1/0/1
                  - GigabitEthernet1/0/2
              - igmp_snooping_vlan_id: 200
                enable_igmp_snooping: true
                igmp_snooping_querier: true
                igmp_snooping_querier_version: VERSION_3
                igmp_snooping_querier_query_interval: 90

- name: Configure MLD Snooping for IPv6 multicast
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          mld_snooping:
            enable_mld_snooping: true
            mld_snooping_querier: false
            mld_snooping_querier_address: fe80::1
            mld_snooping_querier_version: VERSION_2
            mld_snooping_listener: true
            mld_snooping_querier_query_interval: 125
            mld_snooping_vlans:
              - mld_snooping_vlan_id: 100
                enable_mld_snooping: true
                mld_snooping_enable_immediate_leave: false
                mld_snooping_querier: false
                mld_snooping_querier_address: fe80::10
                mld_snooping_querier_version: VERSION_2
                mld_snooping_querier_query_interval: 125
                mld_snooping_mrouter_port_list:
                  - GigabitEthernet1/0/3
                  - GigabitEthernet1/0/4

- name: Configure 802.1X Authentication
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          authentication:
          enable_dot1x_authentication: true
          authentication_config_mode: NEW_STYLE

- name: Configure LACP and PAGP Port Channels
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          logical_ports:
            port_channel_auto: false
            port_channel_lacp_system_priority: 4096
            port_channel_load_balancing_method: SRC_DST_MIXED_IP_PORT
            port_channels:
              - port_channel_protocol: LACP
                port_channel_name: Port-channel1
                port_channel_min_links: 2
                port_channel_members:
                  - port_channel_interface_name: GigabitEthernet1/0/10
                    port_channel_mode: ACTIVE
                    port_channel_port_priority: 128
                    port_channel_rate: 30
                  - port_channel_interface_name: GigabitEthernet1/0/11
                    port_channel_mode: ACTIVE
                    port_channel_port_priority: 128
                    port_channel_rate: 30
              - port_channel_protocol: PAGP
                port_channel_name: Port-channel2
                port_channel_min_links: 1
                port_channel_members:
                  - port_channel_interface_name: GigabitEthernet1/0/12
                    port_channel_mode: DESIRABLE
                    port_channel_port_priority: 128
                    port_channel_learn_method: AGGREGATION_PORT

- name: Configure Access Port with authentication and security
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          port_configuration:
            - interface_name: GigabitEthernet1/0/5
              switchport_interface_config:
                switchport_description: Access Port - Production Network
                switchport_mode: ACCESS
                access_vlan: 100
                admin_status: true
                voice_vlan: 200
              vlan_trunking_interface_config:
                enable_dtp_negotiation: false
                protected: false
              dot1x_interface_config:
                dot1x_interface_authentication_order:
                  - DOT1X
                  - MAB
                dot1x_interface_authentication_mode: OPEN
                dot1x_interface_pae_type: AUTHENTICATOR
                dot1x_interface_control_direction: BOTH
                dot1x_interface_host_mode: MULTI_AUTHENTICATION
                dot1x_interface_port_control: AUTO
                dot1x_interface_inactivity_timer: 300
                dot1x_interface_max_reauth_requests: 3
                dot1x_interface_reauth_timer: 3600
              mab_interface_config:
                mab_interface_enable: true
              stp_interface_config:
                stp_interface_enable_portfast: true
                stp_interface_enable_bpdu_guard: true
                stp_interface_enable_bpdu_filter: false
                stp_interface_enable_root_guard: false
                stp_interface_enable_loop_guard: false
                stp_interface_port_priority: 128
                stp_interface_cost: 19
              dhcp_snooping_interface_config:
                dhcp_snooping_interface_rate_limit: 100
                dhcp_snooping_interface_trust: true
              cdp_interface_config:
                cdp_interface_admin_status: true
                cdp_interface_logging: true
              lldp_interface_config:
                lldp_interface_transmit: true
                lldp_interface_receive: true
              vtp_interface_config:
                vtp_interface_admin_status: true

- name: Configure Trunk Port for inter-switch links
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          port_configuration:
            - interface_name: GigabitEthernet1/0/6
              switchport_interface_config:
                switchport_description: Trunk Port - Inter-Switch Link
                switchport_mode: TRUNK
                allowed_vlans:
                  - 100
                  - 200
                  - 300
                  - 400
                native_vlan_id: 100
                admin_status: true
              vlan_trunking_interface_config:
                enable_dtp_negotiation: true
                protected: true
                pruning_vlan_ids:
                  - 300
                  - 400
              stp_interface_config:
                stp_interface_enable_portfast: false
                stp_interface_enable_bpdu_guard: false
                stp_interface_enable_bpdu_filter: false
                stp_interface_enable_root_guard: true
                stp_interface_enable_loop_guard: true
                stp_interface_port_priority: 64
                stp_interface_cost: 100

- name: Comprehensive network configuration with all Layer 2 features
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - ip_address: 204.1.2.3
        device_collection_status_check: false
        layer2_configuration:
          vlans:
            - vlan_id: 10
              vlan_name: Management
              vlan_admin_status: true
            - vlan_id: 20
              vlan_name: Production
              vlan_admin_status: true
            - vlan_id: 30
              vlan_name: Development
              vlan_admin_status: true
            - vlan_id: 40
              vlan_name: Guest
              vlan_admin_status: true
          cdp:
            cdp_admin_status: true
            cdp_hold_time: 180
            cdp_timer: 60
            cdp_advertise_v2: true
            cdp_log_duplex_mismatch: true
          lldp:
            lldp_admin_status: true
            lldp_hold_time: 240
            lldp_timer: 30
            lldp_reinitialization_delay: 3
          stp:
            stp_mode: RSTP
            stp_portfast_mode: ENABLE
            stp_bpdu_guard: true
            stp_bpdu_filter: false
            stp_backbonefast: true
            stp_extended_system_id: true
            stp_logging: true
            stp_instances:
              - stp_instance_vlan_id: 10
                stp_instance_priority: 32768
                enable_stp: true
              - stp_instance_vlan_id: 20
                stp_instance_priority: 16384
                enable_stp: true
          vtp:
            vtp_mode: SERVER
            vtp_version: VERSION_2
            vtp_domain_name: ENTERPRISE_DOMAIN
            vtp_pruning: true
          dhcp_snooping:
            dhcp_admin_status: true
            dhcp_snooping_vlans:
              - 20
              - 30
              - 40
            dhcp_snooping_glean: true
          igmp_snooping:
            enable_igmp_snooping: true
            igmp_snooping_querier: false
            igmp_snooping_querier_version: VERSION_2
            igmp_snooping_vlans:
              - igmp_snooping_vlan_id: 20
                enable_igmp_snooping: true
                igmp_snooping_querier: false
          authentication:
            enable_dot1x_authentication: true
            authentication_config_mode: NEW_STYLE
          logical_ports:
            port_channel_auto: false
            port_channel_lacp_system_priority: 8192
            port_channel_load_balancing_method: SRC_DST_IP
            port_channels:
              - port_channel_protocol: LACP
                port_channel_name: Port-channel10
                port_channel_min_links: 2
                port_channel_members:
                  - port_channel_interface_name: GigabitEthernet1/0/16
                    port_channel_mode: ACTIVE
                    port_channel_port_priority: 128
                    port_channel_rate: 30
                  - port_channel_interface_name: GigabitEthernet1/0/17
                    port_channel_mode: ACTIVE
                    port_channel_port_priority: 128
                    port_channel_rate: 30
          port_configuration:
            - interface_name: GigabitEthernet1/0/1
              switchport_interface_config:
                switchport_description: Management Port
                switchport_mode: ACCESS
                access_vlan: 10
                admin_status: true
              stp_interface_config:
                stp_interface_enable_portfast: true
                stp_interface_enable_bpdu_guard: true
              dhcp_snooping_interface_config:
                dhcp_snooping_interface_trust: true
            - interface_name: GigabitEthernet1/0/2
              switchport_interface_config:
                switchport_description: Production User Port
                switchport_mode: ACCESS
                access_vlan: 20
                admin_status: true
              dot1x_interface_config:
                dot1x_interface_authentication_order:
                  - DOT1X
                  - MAB
                dot1x_interface_port_control: AUTO
              stp_interface_config:
                stp_interface_enable_portfast: true

- name: Reset CDP to default settings
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: deleted
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          cdp: {}

- name: Reset LLDP to default settings
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: deleted
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          lldp: {}

- name: Comprehensive cleanup of all Layer 2 configurations
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: deleted
    config:
      - ip_address: 204.1.2.3
        layer2_configuration:
          vlans:
            - vlan_id: 10
            - vlan_id: 20
            - vlan_id: 30
            - vlan_id: 40
            - vlan_id: 100
            - vlan_id: 200
            - vlan_id: 300
          cdp: {}
          lldp: {}
          vtp: {}
          dhcp_snooping: {}
          authentication: {}

- name: Configure using device hostname
  cisco.dnac.wired_campus_automation_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: merged
    config:
      - hostname: switch01.example.com
        device_collection_status_check: true
        config_verification_wait_time: 15
        layer2_configuration:
          vlans:
            - vlan_id: 100
              vlan_name: Finance_VLAN
              vlan_admin_status: true
          cdp:
            cdp_admin_status: true
            cdp_hold_time: 200
            cdp_timer: 90
"""

RETURN = r"""
# Case_1: Success Scenario
response_1:
  description: A dictionary with  with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response":
        {
          "response": String,
          "version": String
        },
      "msg": String
    }
# Case_2: Error Scenario
response_2:
  description: A string with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: list
  sample: >
    {
      "response": [],
      "msg": String
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)
import copy


class WiredCampusAutomation(DnacBase):
    """
    A class for managing Wired Campus Automation within the Cisco DNA Center.
    """

    def __init__(self, module):
        """
        Initialize an instance of the class.
        Args:
          - module: The module associated with the class instance.
        Returns:
          The method does not return a value.
        """
        self.supported_states = ["merged", "deleted"]
        self.is_default_rf_profile_in_config = False
        super().__init__(module)

    def validate_input(self):
        """
        Validates the input configuration parameters for the playbook.
        Returns:
            object: An instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either "success" or "failed").
                - self.validated_config: If successful, a validated version of the "config" parameter.
        """
        self.log("Starting validation of input configuration parameters.", "DEBUG")

        # Check if configuration is available
        if not self.config:
            self.msg = "The playbook configuration is empty or missing."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        # Expected schema for configuration parameters
        self.temp_spec = {
            "ip_address": {"type": "str", "required": False},
            "hostname": {"type": "str", "required": False},
            "layer2_configuration": {
                "type": "dict",
                "required": False,
                "vlans": {
                    "type": "list",
                    "elements": "dict",
                    "suboptions": {
                        "vlan_id": {"type": "int", "required": True},
                        "vlan_name": {"type": "str"},
                        "vlan_admin_status": {"type": "bool"},
                    },
                },
                "cdp": {
                    "type": "dict",
                    "cdp_admin_status": {"type": "bool"},
                    "cdp_hold_time": {"type": "int"},
                    "cdp_timer": {"type": "int"},
                    "cdp_advertise_v2": {"type": "bool"},
                    "cdp_log_duplex_mismatch": {"type": "bool"},
                },
                "lldp": {
                    "type": "dict",
                    "lldp_admin_status": {"type": "bool"},
                    "lldp_hold_time": {"type": "int"},
                    "lldp_timer": {"type": "int"},
                    "lldp_reinitialization_delay": {"type": "int"},
                },
                "stp": {
                    "type": "dict",
                    "stp_mode": {"type": "str"},
                    "stp_portfast_mode": {"type": "str"},
                    "stp_bpdu_guard": {"type": "bool"},
                    "stp_bpdu_filter": {"type": "bool"},
                    "stp_backbonefast": {"type": "bool"},
                    "stp_extended_system_id": {"type": "bool"},
                    "stp_logging": {"type": "bool"},
                    "stp_loopguard": {"type": "bool"},
                    "stp_transmit_hold_count": {"type": "int"},
                    "stp_uplinkfast": {"type": "bool"},
                    "stp_uplinkfast_max_update_rate": {"type": "int"},
                    "stp_etherchannel_guard": {"type": "bool"},
                    "stp_instances": {
                        "type": "list",
                        "elements": "dict",
                        "suboptions": {
                            "stp_instance_vlan_id": {"type": "int", "required": True},
                            "stp_instance_priority": {"type": "int"},
                            "enable_stp": {"type": "bool"},
                            "stp_instance_max_age_timer": {"type": "int"},
                            "stp_instance_hello_interval_timer": {"type": "int"},
                            "stp_instance_forward_delay_timer": {"type": "int"},
                        },
                    },
                },
                "vtp": {
                    "type": "dict",
                    "vtp_mode": {"type": "str"},
                    "vtp_version": {"type": "str"},
                    "vtp_domain_name": {"type": "str"},
                    "vtp_configuration_file_name": {"type": "str"},
                    "vtp_source_interface": {"type": "str"},
                    "vtp_pruning": {"type": "bool"},
                },
                "dhcp_snooping": {
                    "type": "dict",
                    "dhcp_admin_status": {"type": "bool"},
                    "dhcp_snooping_vlans": {"type": "list", "elements": "int"},
                    "dhcp_snooping_glean": {"type": "bool"},
                    "dhcp_snooping_database_agent_url": {"type": "str"},
                    "dhcp_snooping_database_timeout": {"type": "int"},
                    "dhcp_snooping_database_write_delay": {"type": "int"},
                    "dhcp_snooping_proxy_bridge_vlans": {
                        "type": "list",
                        "elements": "int",
                    },
                },
                "igmp_snooping": {
                    "type": "dict",
                    "enable_igmp_snooping": {"type": "bool"},
                    "igmp_snooping_querier": {"type": "bool"},
                    "igmp_snooping_querier_address": {"type": "str"},
                    "igmp_snooping_querier_version": {"type": "str"},
                    "igmp_snooping_querier_query_interval": {"type": "int"},
                    "igmp_snooping_vlans": {
                        "type": "list",
                        "elements": "dict",
                        "suboptions": {
                            "igmp_snooping_vlan_id": {"type": "int", "required": True},
                            "enable_igmp_snooping": {"type": "bool"},
                            "igmp_snooping_querier": {"type": "bool"},
                            "igmp_snooping_querier_address": {"type": "str"},
                            "igmp_snooping_querier_version": {"type": "str"},
                            "igmp_snooping_querier_query_interval": {"type": "int"},
                            "igmp_snooping_mrouter_port_list": {
                                "type": "list",
                                "elements": "str",
                            },
                        },
                    },
                },
                "mld_snooping": {
                    "type": "dict",
                    "enable_mld_snooping": {"type": "bool"},
                    "mld_snooping_querier": {"type": "bool"},
                    "mld_snooping_querier_address": {"type": "str"},
                    "mld_snooping_querier_version": {"type": "str"},
                    "mld_snooping_querier_query_interval": {"type": "int"},
                    "mld_snooping_listener": {"type": "bool"},
                    "mld_snooping_vlans": {
                        "type": "list",
                        "elements": "dict",
                        "suboptions": {
                            "mld_snooping_vlan_id": {"type": "int", "required": True},
                            "enable_mld_snooping": {"type": "bool"},
                            "mld_snooping_enable_immediate_leave": {"type": "bool"},
                            "mld_snooping_querier": {"type": "bool"},
                            "mld_snooping_querier_address": {"type": "str"},
                            "mld_snooping_querier_version": {"type": "str"},
                            "mld_snooping_querier_query_interval": {"type": "int"},
                            "mld_snooping_mrouter_port_list": {
                                "type": "list",
                                "elements": "str",
                            },
                        },
                    },
                },
                "authentication": {
                    "type": "dict",
                    "enable_dot1x_authentication": {"type": "bool"},
                    "authentication_config_mode": {"type": "str"},
                },
                "logical_ports": {
                    "type": "dict",
                    "port_channel_auto": {"type": "bool"},
                    "port_channel_lacp_system_priority": {"type": "int"},
                    "port_channel_load_balancing_method": {"type": "str"},
                    "port_channels": {
                        "type": "list",
                        "elements": "dict",
                        "suboptions": {
                            "port_channel_protocol": {"type": "str"},
                            "port_channel_name": {"type": "str"},
                            "port_channel_min_links": {"type": "int"},
                            "port_channel_members": {
                                "type": "list",
                                "elements": "dict",
                                "suboptions": {
                                    "port_channel_interface_name": {"type": "str"},
                                    "port_channel_mode": {"type": "str"},
                                    "port_channel_port_priority": {"type": "int"},
                                    "port_channel_rate": {"type": "int"},
                                    "port_channel_learn_method": {"type": "str"},
                                },
                            },
                        },
                    },
                },
                "port_configuration": {
                    "type": "list",
                    "elements": "dict",
                    "suboptions": {
                        "interface_name": {"type": "str", "required": True},
                        "switchport_interface_config": {
                            "type": "dict",
                            "switchport_description": {"type": "str"},
                            "switchport_mode": {"type": "str"},
                            "access_vlan": {"type": "int"},
                            "voice_vlan": {"type": "int"},
                            "admin_status": {"type": "bool"},
                            "allowed_vlans": {"type": "list", "elements": "int"},
                            "native_vlan_id": {"type": "int"},
                        },
                        "vlan_trunking_interface_config": {
                            "type": "dict",
                            "enable_dtp_negotiation": {"type": "bool"},
                            "protected": {"type": "bool"},
                            "pruning_vlan_ids": {"type": "list"},
                        },
                        "dot1x_interface_config": {
                            "type": "dict",
                            "dot1x_interface_authentication_mode": {"type": "str"},
                            "dot1x_interface_pae_type": {"type": "str"},
                            "dot1x_interface_control_direction": {"type": "str"},
                            "dot1x_interface_host_mode": {"type": "str"},
                            "dot1x_interface_enable_inactivity_timer_from_server": {
                                "type": "bool"
                            },
                            "dot1x_interface_inactivity_timer": {"type": "int"},
                            "dot1x_interface_authentication_order": {
                                "type": "list",
                                "elements": "str",
                            },
                            "dot1x_interface_enable_reauth": {"type": "bool"},
                            "dot1x_interface_port_control": {"type": "str"},
                            "dot1x_interface_priority": {
                                "type": "list",
                                "elements": "str",
                            },
                            "dot1x_interface_max_reauth_requests": {"type": "int"},
                            "dot1x_interface_enable_reauth_timer_from_server": {
                                "type": "bool"
                            },
                            "dot1x_interface_reauth_timer": {"type": "int"},
                            "dot1x_interface_tx_period": {"type": "int"},
                        },
                        "mab_interface_config": {
                            "type": "dict",
                            "enable_mab": {"type": "bool"},
                        },
                        "stp_interface_config": {
                            "type": "dict",
                            "stp_interface_portfast_mode": {"type": "str"},
                            "stp_interface_bpdu_filter": {"type": "bool"},
                            "stp_interface_bpdu_guard": {"type": "bool"},
                            "stp_interface_cost": {"type": "int"},
                            "stp_interface_guard": {"type": "str"},
                            "stp_interface_priority": {
                                "range": (0, 240),
                                "multiple_of": 16,
                                "required": False,
                            },
                            "stp_interface_per_vlan_cost": {
                                "type": "dict",
                                "priority": {"type": "int"},
                                "vlan_ids": {"type": "list", "elements": "int"},
                            },
                            "stp_interface_per_vlan_priority": {
                                "type": "dict",
                                "priority": {"type": "int"},
                                "vlan_ids": {"type": "list", "elements": "int"},
                            },
                        },
                        "dhcp_snooping_interface_config": {
                            "type": "dict",
                            "dhcp_snooping_interface_rate": {"type": "int"},
                            "dhcp_snooping_interface_trust": {"type": "bool"},
                        },
                        "cdp_interface_config": {
                            "type": "dict",
                            "cdp_interface_admin_status": {"type": "bool"},
                            "cdp_interface_log_duplex_mismatch": {"type": "bool"},
                        },
                        "lldp_interface_config": {
                            "type": "dict",
                            "lldp_interface_receive_transmit": {"type": "str"},
                        },
                        "vtp_interface_config": {
                            "type": "dict",
                            "vtp_interface_admin_status": {"type": "bool"},
                        },
                    },
                },
            },
            "device_collection_status_check": {
                "type": "bool",
                "required": False,
                "default": True,
            },
            "config_verification_wait_time": {
                "type": "int",
                "required": False,
                "default": 10,
            },
        }

        # Validate params against the expected schema
        valid_temp, invalid_params = validate_list_of_dicts(self.config, self.temp_spec)

        # Check if any invalid parameters were found
        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(invalid_params)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        # Set the validated configuration and update the result with success status
        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validated_input': {0}".format(
            str(valid_temp)
        )
        self.set_operation_result("success", False, self.msg, "INFO")
        return self

    def get_device_list_params(self, ip_address, hostname):
        """
        Generates a dictionary of device list parameters based on the provided IP address or hostname.
        Args:
            ip_address (str): The management IP address of the device.
            hostname (str): The hostname of the device.
        Returns:
            dict: A dictionary containing the device list parameters with either 'management_ip_address' or 'hostname'.
        """
        # Return a dictionary with 'management_ip_address' if ip_address is provided
        if ip_address:
            self.log(
                "Using IP address '{0}' for device list parameters".format(ip_address),
                "DEBUG",
            )
            return {"management_ip_address": ip_address}

        # Return a dictionary with 'hostname' if hostname is provided
        if hostname:
            self.log(
                "Using hostname '{0}' for device list parameters".format(hostname),
                "DEBUG",
            )
            return {"hostname": hostname}

        # Return an empty dictionary if neither is provided
        self.log(
            "No IP address or hostname provided, returning empty parameters", "DEBUG"
        )
        return {}

    def get_device_ids_by_params(self, get_device_list_params):
        """
        Fetches device IDs from Cisco Catalyst Center based on provided parameters.
        Args:
            get_device_list_params (dict): Parameters for querying the device list, such as IP address or hostname.
        Returns:
            dict: A dictionary mapping management IP addresses to device instance IDs.
        Description:
            This method queries Cisco Catalyst Center using the provided parameters to retrieve device information.
            It checks if the device is reachable, managed, and not a Unified AP. If valid, it maps the management IP
            address to the device instance ID. If any error occurs or no valid device is found, it logs an error message
            and sets the validation status to "failed".
        """
        # Initialize the dictionary to map management IP to instance ID
        mgmt_ip_to_instance_id_map = {}
        self.log(
            "Parameters for 'get_device_list API call: {0}".format(
                get_device_list_params
            ),
            "DEBUG",
        )
        try:
            # Query Cisco Catalyst Center for device information using the parameters
            response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                op_modifies=False,
                params=get_device_list_params,
            )
            self.log(
                "Response received from 'get_device_list' API call: {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

            response = response.get("response")
            # Check if a valid response is received
            if not response:
                self.log(
                    "No devices were returned for the given parameters: {0}".format(
                        get_device_list_params
                    ),
                    "ERROR",
                )
                return mgmt_ip_to_instance_id_map

            # Get the device information from the response
            device_info = response[0]
            device_ip = device_info.get("managementIpAddress")

            # Check if the device is reachable, not a Unified AP, and in a managed state
            if (
                device_info.get("reachabilityStatus") == "Reachable"
                and device_info.get("collectionStatus") in ["Managed", "In Progress"]
                and device_info.get("family") != "Unified AP"
            ):
                device_id = device_info["id"]
                mgmt_ip_to_instance_id_map[device_ip] = device_id
                self.log(
                    "Device {0} is valid and added to the map.".format(device_ip),
                    "INFO",
                )
            else:
                self.log(
                    "Device {0} is not valid (either unreachable, not managed, or a Unified AP).".format(
                        device_ip
                    ),
                    "ERROR",
                )

        except Exception as e:
            # Log an error message if any exception occurs during the process
            self.log(
                "Error while fetching device ID from Cisco Catalyst Center using API 'get_device_list' for Device: {0}. "
                "Error: {1}".format(get_device_list_params, str(e)),
                "ERROR",
            )
        # Log an error if no valid device is found
        if not mgmt_ip_to_instance_id_map:
            self.msg = ("Unable to retrieve details for the Device: {0}.").format(
                get_device_list_params.get("management_ip_address")
                or get_device_list_params.get("hostname")
            )
            self.fail_and_exit(self.msg)

        return mgmt_ip_to_instance_id_map

    def get_network_device_id(self, ip_address, hostname):
        """
        Retrieves the network device ID for a given IP address or hostname.
        Args:
            ip_address (str): The IP address of the device to be queried.
            hostname (str): The hostname of the device to be queried.
        Returns:
            dict: A dictionary mapping management IP addresses to device IDs.
                  Returns an empty dictionary if no devices are found.
        """
        # Get Device IP Address and Id (networkDeviceId required)
        self.log(
            "Starting device ID retrieval for IP: '{0}' or Hostname: '{1}'.".format(
                ip_address, hostname
            ),
            "DEBUG",
        )
        get_device_list_params = self.get_device_list_params(ip_address, hostname)
        self.log(
            "get_device_list_params constructed: {0}".format(get_device_list_params),
            "DEBUG",
        )
        mgmt_ip_to_instance_id_map = self.get_device_ids_by_params(
            get_device_list_params
        )
        self.log(
            "Collected mgmt_ip_to_instance_id_map: {0}".format(
                mgmt_ip_to_instance_id_map
            ),
            "DEBUG",
        )

        return mgmt_ip_to_instance_id_map

    def validate_device_exists_and_reachable(
        self, ip_address, hostname, device_collection_status_check
    ):
        """
        Validates whether a device is present in the Catalyst Center, is reachable, and has an acceptable collection status.
        Args:
            ip_address (str): The IP address of the device to be validated.
            hostname (str): The hostname of the device to be validated.
            device_collection_status_check (bool): If True, skips the check for the device's collection status.
        Returns:
            bool: True if the device is reachable and has an acceptable collection status (or the check is skipped).
                  False if the device is unreachable or has an unacceptable collection status.
        """
        device_identifier = ip_address or hostname
        self.log(
            "Initiating validation for device: '{0}'.".format(device_identifier), "INFO"
        )

        if ip_address:
            get_device_list_params = {"management_ip_address": ip_address}
        elif hostname:
            get_device_list_params = {"hostname": hostname}

        self.log(
            "Executing 'get_device_list' API call with parameters: {0}".format(
                get_device_list_params
            ),
            "DEBUG",
        )

        response = self.execute_get_request(
            "devices", "get_device_list", get_device_list_params
        )

        if not response or not response.get("response"):
            self.msg = (
                "Failed to retrieve details for the specified device: {0}. "
                "Please verify that the device exists in the Catalyst Center."
            ).format(device_identifier)
            self.fail_and_exit(self.msg)

        device_info = response["response"][0]
        reachability_status = device_info.get("reachabilityStatus")
        collection_status = device_info.get("collectionStatus")

        # Device is not reachable
        if reachability_status != "Reachable":
            self.msg = (
                "Device '{0}' is not reachable. Cannot proceed with port onboarding. "
                "reachabilityStatus: '{1}', collectionStatus: '{2}'.".format(
                    device_identifier, reachability_status, collection_status
                )
            )
            return False

        self.log("Device '{0}' is reachable.".format(device_identifier), "INFO")

        # Skip collection status check
        if not device_collection_status_check:
            self.log(
                "Skipping collection status check for device '{0}' as 'device_collection_status_check' is set to False.".format(
                    device_identifier
                ),
                "INFO",
            )
            return True

        # Check collection status
        if collection_status in ["In Progress", "Managed"]:
            self.log(
                "Device '{0}' has an acceptable collection status: '{1}'.".format(
                    device_identifier, collection_status
                ),
                "INFO",
            )
            return True

        # Unacceptable collection status
        self.msg = (
            "Device '{0}' does not have an acceptable collection status. "
            "Current collection status: '{1}'.".format(
                device_identifier, collection_status
            )
        )
        return False

    def validate_ip_and_hostname(
        self, ip_address, hostname, device_collection_status_check
    ):
        """
        Validates the provided IP address and hostname.
        Args:
            ip_address (str): The IP address to be validated.
            hostname (str): The hostname to be validated.
        Returns:
            None: This method does not return a value. It updates the instance attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either "success" or "failed").
        """
        self.log(
            "Validating IP address: '{0}' and hostname: '{1}'".format(
                ip_address, hostname
            ),
            "DEBUG",
        )

        # Check if both IP address and hostname are not provided
        if not ip_address and not hostname:
            self.msg = "Provided IP address: {0}, hostname: {1}. Either an IP address or a hostname is required.".format(
                ip_address, hostname
            )
            self.fail_and_exit(self.msg)

        # Check if an IP address is provided but it is not valid
        if ip_address and not self.is_valid_ipv4(ip_address):
            self.msg = "IP address: {0} is not a valid IP Address.".format(ip_address)
            self.fail_and_exit(self.msg)

        # Check if device exists and is reachable in Catalyst Center
        if not self.validate_device_exists_and_reachable(
            ip_address, hostname, device_collection_status_check
        ):
            self.fail_and_exit(self.msg)

        self.log("Validation successful: Provided IP address or hostname are valid")

    def get_layer2_configuration_validation_rules(self):
        """
        Returns the validation rules for Layer 2 configurations.
        """
        return {
            "vlans": {
                "vlan_id": {"type": "int", "range": (2, 4094), "required": True},
                "vlan_name": {"type": "str", "maxLength": 128, "required": False},
                "vlan_admin_status": {"type": "bool", "required": False},
            },
            "cdp": {
                "cdp_admin_status": {"type": "bool", "required": False},
                "cdp_hold_time": {"type": "int", "range": (10, 255), "required": False},
                "cdp_timer": {
                    "type": "int",
                    "range": (5, 254),
                    "required": False,
                },  # Added type: int
                "cdp_advertise_v2": {"type": "bool", "required": False},
                "cdp_log_duplex_mismatch": {"type": "bool", "required": False},
            },
            "lldp": {
                "lldp_admin_status": {"type": "bool", "required": False},
                "lldp_hold_time": {
                    "type": "int",
                    "range": (0, 32767),
                    "required": False,
                },  # Added type: int
                "lldp_timer": {
                    "type": "int",
                    "range": (5, 32767),
                    "required": False,
                },  # Added type: int
                "lldp_reinitialization_delay": {
                    "type": "int",
                    "range": (2, 5),
                    "required": False,
                },  # Added type: int
            },
            "stp": {
                "stp_mode": {
                    "type": "str",
                    "choices": ["PVST", "RSTP", "MST"],
                    "required": False,
                },
                "stp_portfast_mode": {
                    "type": "str",
                    "choices": ["ENABLE", "DISABLE", "EDGE", "NETWORK", "TRUNK"],
                    "required": False,
                },
                "stp_bpdu_guard": {"type": "bool", "required": False},
                "stp_bpdu_filter": {"type": "bool", "required": False},
                "stp_backbonefast": {"type": "bool", "required": False},
                "stp_extended_system_id": {"type": "bool", "required": False},
                "stp_logging": {"type": "bool", "required": False},
                "stp_loopguard": {"type": "bool", "required": False},
                "stp_transmit_hold_count": {
                    "type": "int",
                    "range": (1, 20),
                    "required": False,
                },  # Added type: int
                "stp_uplinkfast": {"type": "bool", "required": False},
                "stp_uplinkfast_max_update_rate": {
                    "type": "int",
                    "range": (0, 32000),
                    "required": False,
                },  # Added type: int
                "stp_etherchannel_guard": {"type": "bool", "required": False},
                "stp_instances": {"type": "list", "required": False},
            },
            "stp_instance": {
                "stp_instance_vlan_id": {
                    "type": "int",
                    "range": (1, 4094),
                    "required": True,
                },  # Added type: int
                "stp_instance_priority": {
                    "type": "int",
                    "range": (0, 61440),
                    "multiple_of": 4096,
                    "required": False,
                },  # Added type: int
                "enable_stp": {"type": "bool", "required": False},
                "stp_instance_max_age_timer": {
                    "type": "int",
                    "range": (6, 40),
                    "required": False,
                },  # Added type: int
                "stp_instance_hello_interval_timer": {
                    "type": "int",
                    "range": (1, 10),
                    "required": False,
                },  # Added type: int
                "stp_instance_forward_delay_timer": {
                    "type": "int",
                    "range": (4, 30),
                    "required": False,
                },  # Added type: int
            },
            "vtp": {
                "vtp_mode": {
                    "type": "str",
                    "choices": ["SERVER", "CLIENT", "TRANSPARENT", "OFF"],
                    "required": False,
                },
                "vtp_version": {
                    "type": "str",
                    "choices": ["VERSION_1", "VERSION_2", "VERSION_3"],
                    "required": False,
                },
                "vtp_domain_name": {"type": "str", "maxLength": 32, "required": False},
                "vtp_pruning": {"type": "bool", "required": False},
                "vtp_configuration_file_name": {
                    "type": "str",
                    "maxLength": 244,
                    "required": False,
                },
                "vtp_source_interface": {"type": "str", "required": False},
            },
            "dhcp_snooping": {
                "dhcp_admin_status": {"type": "bool", "required": False},
                "dhcp_snooping_vlans": {
                    "type": "list",
                    "elements": "int",
                    "vlan_range": (1, 4094),
                    "required": False,
                },
                "dhcp_snooping_glean": {"type": "bool", "required": False},
                "dhcp_snooping_database_agent_url": {
                    "type": "str",
                    "minLength": 0,
                    "maxLength": 227,
                    "required": False,
                },
                "dhcp_snooping_database_timeout": {
                    "type": "int",
                    "range": (0, 86400),
                    "required": False,
                },  # Added type: int
                "dhcp_snooping_database_write_delay": {
                    "type": "int",
                    "range": (15, 86400),
                    "required": False,
                },  # Added type: int
                "dhcp_snooping_proxy_bridge_vlans": {
                    "type": "list",
                    "elements": "int",
                    "vlan_range": (1, 4094),
                    "required": False,
                },
            },
            "igmp_snooping": {
                "enable_igmp_snooping": {"type": "bool", "required": False},
                "igmp_snooping_querier": {"type": "bool", "required": False},
                "igmp_snooping_querier_address": {"type": "str", "required": False},
                "igmp_snooping_querier_version": {
                    "type": "str",
                    "choices": ["VERSION_1", "VERSION_2", "VERSION_3"],
                    "required": False,
                },
                "igmp_snooping_querier_query_interval": {
                    "type": "int",
                    "range": (1, 18000),
                    "required": False,
                },  # Added type: int
                "igmp_snooping_vlans": {"type": "list", "required": False},
            },
            "igmp_snooping_vlan": {
                "igmp_snooping_vlan_id": {
                    "type": "int",
                    "range": (1, 4094),
                    "required": True,
                },  # Added type: int
                "enable_igmp_snooping": {"type": "bool", "required": False},
                "igmp_snooping_immediate_leave": {"type": "bool", "required": False},
                "igmp_snooping_querier": {"type": "bool", "required": False},
                "igmp_snooping_querier_address": {"type": "str", "required": False},
                "igmp_snooping_querier_version": {
                    "type": "str",
                    "choices": ["VERSION_1", "VERSION_2", "VERSION_3"],
                    "required": False,
                },
                "igmp_snooping_querier_query_interval": {
                    "type": "int",
                    "range": (1, 18000),
                    "required": False,
                },  # Added type: int
                "igmp_snooping_mrouter_port_list": {"type": "list", "required": False},
            },
            "mld_snooping": {
                "enable_mld_snooping": {"type": "bool", "required": False},
                "mld_snooping_querier": {"type": "bool", "required": False},
                "mld_snooping_querier_address": {"type": "str", "required": False},
                "mld_snooping_querier_version": {
                    "type": "str",
                    "choices": ["VERSION_1", "VERSION_2"],
                    "required": False,
                },
                "mld_snooping_querier_query_interval": {
                    "type": "int",
                    "range": (1, 18000),
                    "required": False,
                },  # Added type: int
                "mld_snooping_listener": {"type": "bool", "required": False},
                "mld_snooping_vlans": {"type": "list", "required": False},
            },
            "mld_snooping_vlan": {
                "mld_snooping_vlan_id": {
                    "type": "int",
                    "range": (1, 4094),
                    "required": True,
                },  # Added type: int
                "enable_mld_snooping": {"type": "bool", "required": False},
                "mld_snooping_enable_immediate_leave": {
                    "type": "bool",
                    "required": False,
                },
                "mld_snooping_querier": {"type": "bool", "required": False},
                "mld_snooping_querier_address": {"type": "str", "required": False},
                "mld_snooping_querier_version": {
                    "type": "str",
                    "choices": ["VERSION_1", "VERSION_2"],
                    "required": False,
                },
                "mld_snooping_querier_query_interval": {
                    "type": "int",
                    "range": (1, 18000),
                    "required": False,
                },  # Added type: int
                "mld_snooping_mrouter_port_list": {"type": "list", "required": False},
            },
            "authentication": {
                "enable_dot1x_authentication": {"type": "bool", "required": False},
                "authentication_config_mode": {
                    "type": "str",
                    "choices": ["LEGACY", "NEW_STYLE"],
                    "required": False,
                },
            },
            "logical_ports": {
                "port_channel_auto": {"type": "bool", "required": False},
                "port_channel_lacp_system_priority": {
                    "type": "int",
                    "range": (0, 65535),
                    "required": False,
                },  # Added type: int
                "port_channel_load_balancing_method": {
                    "type": "str",
                    "choices": [
                        "SRC_MAC",
                        "DST_MAC",
                        "SRC_DST_MAC",
                        "SRC_IP",
                        "DST_IP",
                        "SRC_DST_IP",
                        "SRC_PORT",
                        "DST_PORT",
                        "SRC_DST_PORT",
                        "SRC_DST_MIXED_IP_PORT",
                        "SRC_MIXED_IP_PORT",
                        "DST_MIXED_IP_PORT",
                        "VLAN_SRC_IP",
                        "VLAN_DST_IP",
                        "VLAN_SRC_DST_IP",
                        "VLAN_SRC_MIXED_IP_PORT",
                        "VLAN_DST_MIXED_IP_PORT",
                        "VLAN_SRC_DST_MIXED_IP_PORT",
                    ],
                    "required": False,
                },
                "port_channels": {"type": "list", "required": False},
            },
            "port_channel": {
                "port_channel_protocol": {
                    "type": "str",
                    "choices": ["LACP", "PAGP", "NONE"],
                    "required": True,
                },
                "port_channel_name": {
                    "type": "str",
                    "minLength": 13,
                    "maxLength": 15,
                    "required": False,
                },
                "port_channel_min_links": {
                    "type": "int",
                    "range": (2, 8),
                    "required": False,
                },  # Added type: int
                "port_channel_members": {"type": "list", "required": True},
            },
            "port_channel_member_lacp": {
                "port_channel_interface_name": {"type": "str", "required": False},
                "port_channel_mode": {
                    "type": "str",
                    "choices": ["ACTIVE", "PASSIVE"],
                    "required": False,
                },
                "port_channel_port_priority": {
                    "type": "int",
                    "range": (0, 65535),
                    "required": False,
                },  # Added type: int
                "port_channel_rate": {
                    "type": "int",
                    "range": (1, 30),
                    "required": False,
                },  # Added type: int
            },
            "port_channel_member_pagp": {
                "port_channel_interface_name": {"type": "str", "required": True},
                "port_channel_mode": {
                    "type": "str",
                    "choices": [
                        "AUTO",
                        "AUTO_NON_SILENT",
                        "DESIRABLE",
                        "DESIRABLE_NON_SILENT",
                    ],
                    "required": False,
                },
                "port_channel_port_priority": {
                    "type": "int",
                    "range": (0, 255),
                    "required": False,
                },  # Added type: int
                "port_channel_learn_method": {
                    "type": "str",
                    "choices": ["AGGREGATION_PORT", "PHYSICAL_PORT"],
                    "required": False,
                },
            },
            "port_channel_member_none": {
                "port_channel_interface_name": {"type": "str", "required": True},
                "port_channel_mode": {
                    "type": "str",
                    "choices": ["ON"],
                    "required": False,
                },
            },
            "switchport_interface_config": {
                "switchport_description": {
                    "type": "str",
                    "maxLength": 230,
                    "required": False,
                },
                "switchport_mode": {
                    "type": "str",
                    "choices": [
                        "ACCESS",
                        "TRUNK",
                        "DYNAMIC_AUTO",
                        "DYNAMIC_DESIRABLE",
                        "DOT1Q_TUNNEL",
                    ],
                    "required": False,
                },
                "access_vlan": {
                    "type": "int",
                    "range": (1, 4094),
                    "required": False,
                },  # Added type: int
                "voice_vlan": {
                    "type": "int",
                    "range": (1, 4094),
                    "required": False,
                },  # Added type: int
                "admin_status": {"type": "bool", "required": False},
                "allowed_vlans": {
                    "type": "list",
                    "elements": "int",
                    "vlan_range": (1, 4094),
                    "required": False,
                },
                "native_vlan_id": {
                    "type": "int",
                    "range": (1, 4094),
                    "required": False,
                },  # Added type: int
            },
            "vlan_trunking_interface_config": {
                "enable_dtp_negotiation": {"type": "bool", "required": False},
                "protected": {"type": "bool", "required": False},
                "pruning_vlan_ids": {
                    "type": "list",
                    "elements": "int",
                    "required": False,
                },
            },
            "dot1x_interface_config": {
                "dot1x_interface_authentication_mode": {
                    "type": "str",
                    "choices": ["OPEN", "CLOSED"],
                    "required": False,
                },
                "dot1x_interface_pae_type": {
                    "type": "str",
                    "choices": ["NONE", "AUTHENTICATOR", "SUPPLICANT", "BOTH"],
                    "required": False,
                },
                "dot1x_interface_control_direction": {
                    "type": "str",
                    "choices": ["IN", "BOTH"],
                    "required": False,
                },
                "dot1x_interface_host_mode": {
                    "type": "str",
                    "choices": [
                        "MULTI_AUTHENTICATION",
                        "MULTI_HOST",
                        "SINGLE_HOST",
                        "MULTI_DOMAIN",
                    ],
                    "required": False,
                },
                "dot1x_interface_inactivity_timer_from_server": {
                    "type": "bool",
                    "required": False,
                },
                "dot1x_interface_inactivity_timer": {
                    "type": "int",
                    "range": (0, 65535),
                    "required": False,
                },  # Added type: int
                "dot1x_interface_authentication_order": {
                    "type": "list",
                    "elements": "str",
                    "choices": ["DOT1X", "MAB", "WEBAUTH"],
                    "max_items": 3,
                    "required": False,
                },
                "dot1x_interface_reauthentication": {"type": "bool", "required": False},
                "dot1x_interface_port_control": {
                    "type": "str",
                    "choices": ["AUTO", "FORCE_AUTHORIZED", "FORCE_UNAUTHORIZED"],
                    "required": False,
                },
                "dot1x_interface_priority": {
                    "type": "list",
                    "elements": "str",
                    "choices": ["DOT1X", "MAB", "WEBAUTH"],
                    "required": False,
                },
                "dot1x_interface_max_reauth_requests": {
                    "type": "int",
                    "range": (1, 10),
                    "required": False,
                },  # Added type: int
                "dot1x_interface_reauth_timer_from_server": {
                    "type": "bool",
                    "required": False,
                },
                "dot1x_interface_reauth_timer": {
                    "type": "int",
                    "range": (1, 1073741823),
                    "required": False,
                },  # Added type: int
                "dot1x_interface_tx_period": {
                    "type": "int",
                    "range": (1, 65535),
                    "required": False,
                },  # Added type: int
            },
            "mab_interface_config": {
                "enable_mab": {"type": "bool", "required": False},
            },
            "stp_interface_config": {
                "stp_interface_portfast_mode": {
                    "type": "str",
                    "choices": [
                        "NONE",
                        "DISABLE",
                        "EDGE",
                        "EDGE_TRUNK",
                        "NETWORK",
                        "TRUNK",
                    ],
                    "required": False,
                },
                "stp_interface_bpdu_filter": {"type": "bool", "required": False},
                "stp_interface_bpdu_guard": {"type": "bool", "required": False},
                "stp_interface_cost": {
                    "type": "int",
                    "range": (1, 20000000),
                    "required": False,
                },  # Added type: int
                "stp_interface_guard": {
                    "type": "str",
                    "choices": ["LOOP", "ROOT", "NONE"],
                    "required": False,
                },
                "stp_interface_priority": {
                    "type": "int",
                    "range": (0, 240),
                    "multiple_of": 16,
                    "required": False,
                },  # Added type: int
            },
            "dhcp_snooping_interface_config": {
                "dhcp_snooping_interface_rate": {
                    "type": "int",
                    "range": (1, 2048),
                    "required": False,
                },  # Added type: int
                "dhcp_snooping_interface_trust": {"type": "bool", "required": False},
            },
            "cdp_interface_config": {
                "cdp_interface_admin_status": {"type": "bool", "required": False},
                "cdp_interface_log_duplex_mismatch": {
                    "type": "bool",
                    "required": False,
                },
            },
            "lldp_interface_config": {
                "lldp_interface_receive_transmit": {
                    "type": "str",
                    "choices": [
                        "TRANSMIT_ONLY",
                        "RECEIVE_ONLY",
                        "TRANSMIT_AND_RECEIVE",
                        "DISABLED",
                    ],
                    "required": False,
                },
            },
            "vtp_interface_config": {
                "vtp_interface_admin_status": {"type": "bool", "required": False},
            },
            "stp_interface_per_vlan_cost": {
                "priority": {
                    "type": "int",
                    "range": (1, 20000000),
                    "required": False,
                },  # Added type: int
                "vlan_ids": {
                    "type": "list",
                    "elements": "int",
                    "vlan_range": (1, 4094),
                    "required": False,
                },
            },
            "stp_interface_per_vlan_priority": {
                "priority": {
                    "type": "int",
                    "range": (0, 240),
                    "multiple_of": 16,
                    "required": False,
                },  # Added type: int
                "vlan_ids": {
                    "type": "list",
                    "elements": "int",
                    "vlan_range": (1, 4094),
                    "required": False,
                },
            },
        }

    def validate_config_against_rules(self, config_name, config_values, rules):
        """
        Validates a specific configuration against the provided validation rules.
        Args:
            config_name (str): The name of the configuration (Example, "vlan").
            config_values (dict): The configuration values provided by the user.
            rules (dict): The validation rules for the configuration.
        Raises:
            ValueError: If any validation fails.
        """
        self.log(
            "Starting validation for configuration '{0}'.".format(config_name), "INFO"
        )
        self.log("Configuration values: {0}".format(config_values), "DEBUG")
        self.log("Validation rules: {0}".format(rules), "DEBUG")

        # First check if config_values is the expected type (dictionary)
        if not isinstance(config_values, dict):
            self.msg = "Configuration '{0}' must be of type dictionary. Provided value: '{1}' (type: {2}).".format(
                config_name, config_values, type(config_values).__name__
            )
            self.fail_and_exit(self.msg)

        for param, rule in rules.items():
            value = config_values.get(param)
            self.log(
                "Validating parameter '{0}' with value '{1}' against rule '{2}'.".format(
                    param, value, rule
                ),
                "DEBUG",
            )

            # Check if the parameter is required but missing
            if rule.get("required") and value is None:
                self.msg = "Missing required parameter '{0}' for configuration '{1}'. Full configuration: {2}".format(
                    param, config_name, config_values
                )
                self.fail_and_exit(self.msg)

            # Skip further validation if value is None (and not required)
            if value is None:
                self.log(
                    "Parameter '{0}' has None value and is not required. Skipping validation.".format(
                        param
                    ),
                    "DEBUG",
                )
                continue

            # Validate data type if specified
            if "type" in rule and value is not None:
                expected_type = rule["type"]

                # Check for boolean first since isinstance(False, int) returns True in Python
                if expected_type == "bool" and not isinstance(value, bool):
                    self.msg = (
                        "Parameter '{0}' in configuration '{1}' must be of type boolean. "
                        "Provided value: '{2}' (type: {3}). Full configuration: {4}"
                    ).format(param, config_name, value, type(value).__name__, config_values)
                    self.fail_and_exit(self.msg)
                elif expected_type == "str" and not isinstance(value, str):
                    self.msg = (
                        "Parameter '{0}' in configuration '{1}' must be of type string. "
                        "Provided value: '{2}' (type: {3}). Full configuration: {4}"
                    ).format(param, config_name, value, type(value).__name__, config_values)
                    self.fail_and_exit(self.msg)
                elif expected_type == "int" and (
                    isinstance(value, bool) or not isinstance(value, int)
                ):
                    # Explicitly reject boolean values for integer fields
                    self.msg = (
                        "Parameter '{0}' in configuration '{1}' must be of type integer. "
                        "Provided value: '{2}' (type: {3}). Full configuration: {4}"
                    ).format(param, config_name, value, type(value).__name__, config_values)
                    self.fail_and_exit(self.msg)
                elif expected_type == "list" and not isinstance(value, list):
                    self.msg = (
                        "Parameter '{0}' in configuration '{1}' must be of type list. "
                        "Provided value: '{2}' (type: {3}). Full configuration: {4}"
                    ).format(param, config_name, value, type(value).__name__, config_values)
                    self.fail_and_exit(self.msg)
                elif expected_type == "dict" and not isinstance(value, dict):
                    self.msg = (
                        "Parameter '{0}' in configuration '{1}' must be of type dictionary. "
                        "Provided value: '{2}' (type: {3}). Full configuration: {4}"
                    ).format(param, config_name, value, type(value).__name__, config_values)
                    self.fail_and_exit(self.msg)

            # Validate the range of the parameter
            if "range" in rule and value is not None:
                min_val, max_val = rule["range"]
                if not (min_val <= value <= max_val):
                    self.msg = "Parameter '{0}' in configuration '{1}' must be within the range {2}. Provided value: {3}. Full configuration: {4}".format(
                        param, config_name, rule["range"], value, config_values
                    )
                    self.fail_and_exit(self.msg)

            # Validate if value is a multiple of a specific number
            if "multiple_of" in rule and value is not None:
                multiple = rule["multiple_of"]
                if value % multiple != 0:
                    self.msg = "Parameter '{0}' in configuration '{1}' must be a multiple of {2}. Provided value: '{3}'. Full configuration: {4}".format(
                        param, config_name, multiple, value, config_values
                    )
                    self.fail_and_exit(self.msg)

            # Validate the minimum length of the parameter
            if "minLength" in rule and value is not None and isinstance(value, str):
                if len(value) < rule["minLength"]:
                    self.msg = (
                        "Parameter '{0}' in configuration '{1}' must be at least {2} characters long. "
                        "Provided value length: {3}. Full configuration: {4}"
                    ).format(param, config_name, rule["minLength"], len(value), config_values)
                    self.fail_and_exit(self.msg)

            # Validate the maximum length of the parameter
            if "maxLength" in rule and value is not None:
                if len(value) > rule["maxLength"]:
                    self.msg = (
                        "Parameter '{0}' in configuration '{1}' exceeds maximum length of {2}. "
                        "Provided value length: {3}. Full configuration: {4}"
                    ).format(param, config_name, rule["maxLength"], len(value), config_values)
                    self.fail_and_exit(self.msg)

            # Validate maximum number of items in list
            if "max_items" in rule and isinstance(value, list):
                max_items = rule["max_items"]
                if len(value) > max_items:
                    self.msg = "Parameter '{0}' in configuration '{1}' exceeds maximum of {2} items. Provided {3} items: {4}. Full configuration: {5}".format(
                        param, config_name, max_items, len(value), value, config_values
                    )
                    self.fail_and_exit(self.msg)

            # Validate the choices for parameters (handle both single values and lists)
            if "choices" in rule and value is not None:
                # Convert choices to uppercase for case-insensitive comparison
                valid_choices = [
                    choice.upper() if isinstance(choice, str) else choice
                    for choice in rule["choices"]
                ]

                if isinstance(value, list):
                    # For list parameters, validate each element
                    for i, item in enumerate(value):
                        # Convert item to uppercase for case-insensitive comparison
                        item_upper = item.upper() if isinstance(item, str) else item
                        if item_upper not in valid_choices:
                            self.msg = (
                                "Item '{0}' at index {1} in parameter '{2}' of configuration '{3}' must be one of {4}. "
                                "Provided value: '{5}'. Full configuration: {6}"
                            ).format(
                                item,
                                i,
                                param,
                                config_name,
                                rule["choices"],
                                value,
                                config_values,
                            )
                            self.fail_and_exit(self.msg)
                else:
                    # For single values, validate directly
                    value_upper = value.upper() if isinstance(value, str) else value
                    if value_upper not in valid_choices:
                        self.msg = "Parameter '{0}' in configuration '{1}' must be one of {2}. Provided value: '{3}'. Full configuration: {4}".format(
                            param, config_name, rule["choices"], value, config_values
                        )
                        self.fail_and_exit(self.msg)

            # Validate list elements with VLAN range check
            if (
                "elements" in rule
                and rule["elements"] == "int"
                and "vlan_range" in rule
                and isinstance(value, list)
            ):
                min_vlan, max_vlan = rule["vlan_range"]
                for i, item in enumerate(value):
                    if not isinstance(item, int) or not (min_vlan <= item <= max_vlan):
                        self.msg = (
                            "Item {0} in list parameter '{1}' of configuration '{2}' must be an integer "
                            "between {3} and {4}. Provided value: '{5}'. Full configuration: {6}"
                        ).format(
                            i,
                            param,
                            config_name,
                            min_vlan,
                            max_vlan,
                            item,
                            config_values,
                        )
                        self.fail_and_exit(self.msg)

            self.log("Parameter '{0}' passed validation.".format(param), "DEBUG")

        self.log(
            "Validation for configuration '{0}' completed successfully.".format(
                config_name
            ),
            "INFO",
        )

    def _validate_vlans_config(self, vlan_config, rules):
        """
        Validates VLAN configuration which is a list of dictionaries.
        Args:
            vlan_config (list): A list of VLAN configurations.
            rules (dict): Validation rules for VLAN parameters.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log(
            "Starting validation for VLAN configurations list with {0} items".format(
                len(vlan_config)
            ),
            "INFO",
        )

        # Iterate over each VLAN configuration in the list
        for index, vlan in enumerate(vlan_config):
            self.log(
                "Processing VLAN configuration at index {0}".format(index), "DEBUG"
            )

            # Validate that each VLAN configuration is a dictionary
            if not isinstance(vlan, dict):
                self.msg = (
                    "Each VLAN configuration must be a dictionary. Found: {0}".format(
                        type(vlan).__name__
                    )
                )
                self.log(
                    "VLAN configuration type validation failed at index {0}".format(
                        index
                    ),
                    "ERROR",
                )
                self.fail_and_exit(self.msg)

            self.log("Validating VLAN configuration: {0}".format(vlan), "DEBUG")

            # Validate the individual VLAN configuration against the provided rules
            self.validate_config_against_rules("vlans", vlan, rules)

            self.log(
                "VLAN configuration at index {0} validated successfully".format(index),
                "DEBUG",
            )

        self.log("All VLAN configurations validated successfully", "INFO")

    def _validate_cdp_config(self, cdp_config, rules):
        """
        Validates CDP global configuration parameters.
        Args:
            cdp_config (dict): The CDP configuration.
            rules (dict): Validation rules for CDP parameters.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for CDP global configuration", "INFO")
        self.log("Validating CDP configuration: {0}".format(cdp_config), "DEBUG")

        # Validate the CDP configuration against the provided validation rules
        self.validate_config_against_rules("cdp", cdp_config, rules)

        self.log("CDP configuration validation completed successfully", "INFO")

    def _validate_lldp_config(self, lldp_config, rules):
        """
        Validates LLDP global configuration parameters.
        Args:
            lldp_config (dict): The LLDP configuration.
            rules (dict): Validation rules for LLDP parameters.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for LLDP global configuration", "INFO")
        self.log("Validating LLDP configuration: {0}".format(lldp_config), "DEBUG")

        # Validate the LLDP configuration against the provided validation rules
        self.validate_config_against_rules("lldp", lldp_config, rules)

        self.log("LLDP configuration validation completed successfully", "INFO")

    def _validate_stp_config(self, stp_config, rules):
        """
        Validates STP configuration which includes both global params and instances.
        Args:
            stp_config (dict): The STP configuration.
            rules (dict): Validation rules for STP parameters.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for STP global configuration", "INFO")
        self.log("Validating STP configuration: {0}".format(stp_config), "DEBUG")

        # First check if stp_config is the expected type (dictionary)
        if not isinstance(stp_config, dict):
            self.msg = "STP configuration must be of type dictionary. Provided value: '{0}' (type: {1}).".format(
                stp_config, type(stp_config).__name__
            )
            self.log("STP configuration type validation failed", "ERROR")
            self.fail_and_exit(self.msg)

        # Create a copy of stp_config without the stp_instances for global validation
        stp_global_config = stp_config.copy()
        stp_instances = stp_global_config.pop("stp_instances", None)

        self.log(
            "Extracted STP instances for separate validation: {0}".format(
                bool(stp_instances)
            ),
            "DEBUG",
        )

        # Validate the STP global configuration against the provided rules
        self.validate_config_against_rules("stp", stp_global_config, rules)

        self.log("STP global configuration validation completed successfully", "DEBUG")

        # Validate STP instances if present
        if stp_instances:
            self.log("Validating STP instances configuration", "DEBUG")
            self._validate_stp_instances(stp_instances)
            self.log("STP instances validation completed successfully", "DEBUG")
        else:
            self.log("No STP instances found to validate", "DEBUG")

        self.log("STP configuration validation completed successfully", "INFO")

    def _validate_stp_instances(self, stp_instances):
        """
        Validates STP instance configurations.
        Args:
            stp_instances (list): A list of STP instance configurations.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for STP instances configuration", "INFO")

        # Ensure stp_instances is a list
        if not isinstance(stp_instances, list):
            self.msg = "STP instances configuration must be a list of dictionaries. Provided: {0}".format(
                type(stp_instances).__name__
            )
            self.log(
                "STP instances type validation failed - expected list but got {0}".format(
                    type(stp_instances).__name__
                ),
                "ERROR",
            )
            self.fail_and_exit(self.msg)

        self.log(
            "STP instances list contains {0} items".format(len(stp_instances)), "DEBUG"
        )

        # Get validation rules for STP instance
        rules = self.get_layer2_configuration_validation_rules().get("stp_instance")
        self.log(
            "Validation rules for STP instance configurations: {0}".format(rules),
            "DEBUG",
        )

        # Iterate over each STP instance configuration in the list
        for index, instance in enumerate(stp_instances):
            self.log("Processing STP instance at index {0}".format(index), "DEBUG")

            # Validate that each instance is a dictionary
            if not isinstance(instance, dict):
                self.msg = "Each STP instance configuration must be a dictionary. Found: {0}".format(
                    type(instance).__name__
                )
                self.log(
                    "STP instance type validation failed at index {0} - expected dict but got {1}".format(
                        index, type(instance).__name__
                    ),
                    "ERROR",
                )
                self.fail_and_exit(self.msg)

            self.log(
                "Validating STP instance configuration: {0}".format(instance), "DEBUG"
            )

            # Validate the individual STP instance configuration against the validation rules
            self.validate_config_against_rules("stp_instance", instance, rules)

            self.log(
                "STP instance at index {0} validated successfully".format(index),
                "DEBUG",
            )

        self.log("All STP instance configurations validated successfully", "INFO")

    def _validate_vtp_config(self, vtp_config, rules):
        """
        Validates VTP global configuration parameters.
        Args:
            vtp_config (dict): The VTP configuration.
            rules (dict): Validation rules for VTP parameters.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for VTP global configuration", "INFO")
        self.log("Validating VTP configuration: {0}".format(vtp_config), "DEBUG")

        # Validate the VTP configuration against the provided validation rules
        self.validate_config_against_rules("vtp", vtp_config, rules)

        self.log("VTP configuration validation completed successfully", "INFO")

    def _validate_dhcp_snooping_config(self, dhcp_snooping_config, rules):
        """
        Validates DHCP Snooping global configuration parameters.
        Args:
            dhcp_snooping_config (dict): The DHCP Snooping configuration.
            rules (dict): Validation rules for DHCP Snooping parameters.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for DHCP Snooping global configuration", "INFO")
        self.log(
            "Validating DHCP Snooping configuration: {0}".format(dhcp_snooping_config),
            "DEBUG",
        )

        # Add type check BEFORE trying to use dictionary methods
        if not isinstance(dhcp_snooping_config, dict):
            self.msg = "DHCP Snooping configuration must be of type dictionary. Provided value: '{0}' (type: {1}).".format(
                dhcp_snooping_config, type(dhcp_snooping_config).__name__
            )
            self.log("DHCP Snooping configuration type validation failed", "ERROR")
            self.fail_and_exit(self.msg)

        # Validate VLAN lists if provided
        vlan_params = ["dhcp_snooping_vlans", "dhcp_snooping_proxy_bridge_vlans"]
        for param in vlan_params:
            value = dhcp_snooping_config.get(param)
            if value:
                self.log(
                    "Validating VLAN parameter '{0}' with value: {1}".format(
                        param, value
                    ),
                    "DEBUG",
                )

                # Check that the value is a list
                if not isinstance(value, list):
                    self.msg = "Parameter '{0}' must be a list. Provided: {1}. Full configuration: {2}".format(
                        param, type(value).__name__, dhcp_snooping_config
                    )
                    self.log(self.msg, "ERROR")
                    self.fail_and_exit(self.msg)

                # Check that all elements are integers and within valid VLAN range
                for index, vlan_id in enumerate(value):
                    if not isinstance(vlan_id, int):
                        self.msg = "All elements in '{0}' must be integers. Found: {1} at index {2}. Full configuration: {3}".format(
                            param, type(vlan_id).__name__, index, dhcp_snooping_config
                        )
                        self.log(self.msg, "ERROR")
                        self.fail_and_exit(self.msg)

                    if vlan_id < 1 or vlan_id > 4094:
                        self.msg = "VLAN ID in '{0}' must be between 1 and 4094. Found: {1} at index {2}. Full configuration: {3}".format(
                            param, vlan_id, index, dhcp_snooping_config
                        )
                        self.log(self.msg, "ERROR")
                        self.fail_and_exit(self.msg)

                self.log(
                    "VLAN parameter '{0}' validated successfully with {1} VLAN IDs".format(
                        param, len(value)
                    ),
                    "DEBUG",
                )

        # Validate the DHCP Snooping configuration against rules
        self.validate_config_against_rules("dhcp_snooping", dhcp_snooping_config, rules)

        self.log(
            "DHCP Snooping configuration validation completed successfully", "INFO"
        )

    def _validate_igmp_snooping_config(self, igmp_snooping_config, rules):
        """
        Validates IGMP Snooping configuration which includes both global params and VLAN-specific settings.
        Args:
            igmp_snooping_config (dict): The IGMP Snooping configuration.
            rules (dict): Validation rules for IGMP Snooping parameters.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for IGMP Snooping global configuration", "INFO")
        self.log(
            "Validating IGMP Snooping configuration: {0}".format(igmp_snooping_config),
            "DEBUG",
        )

        # Add type check BEFORE trying to use dictionary methods
        if not isinstance(igmp_snooping_config, dict):
            self.msg = "IGMP Snooping configuration must be of type dictionary. Provided value: '{0}' (type: {1}).".format(
                igmp_snooping_config, type(igmp_snooping_config).__name__
            )
            self.log("IGMP Snooping configuration type validation failed", "ERROR")
            self.fail_and_exit(self.msg)

        # Create a copy of igmp_snooping_config without the igmp_snooping_vlans for global validation
        igmp_global_config = igmp_snooping_config.copy()
        igmp_snooping_vlans = igmp_global_config.pop("igmp_snooping_vlans", None)

        self.log(
            "Extracted IGMP Snooping VLANs for separate validation: {0}".format(
                bool(igmp_snooping_vlans)
            ),
            "DEBUG",
        )

        # Validate the IGMP Snooping global configuration against the provided rules
        self.validate_config_against_rules("igmp_snooping", igmp_global_config, rules)

        self.log(
            "IGMP Snooping global configuration validation completed successfully",
            "DEBUG",
        )

        # Validate IGMP Snooping VLAN settings if present
        if igmp_snooping_vlans:
            self.log("Validating IGMP Snooping VLAN settings", "DEBUG")
            self._validate_igmp_snooping_vlans(igmp_snooping_vlans)
            self.log(
                "IGMP Snooping VLAN settings validation completed successfully", "DEBUG"
            )
        else:
            self.log("No IGMP Snooping VLAN settings found to validate", "DEBUG")

        self.log(
            "IGMP Snooping configuration validation completed successfully", "INFO"
        )

    def _validate_igmp_snooping_vlans(self, igmp_snooping_vlans):
        """
        Validates IGMP Snooping VLAN configurations.
        Args:
            igmp_snooping_vlans (list): A list of IGMP Snooping VLAN configurations.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for IGMP Snooping VLAN configurations", "INFO")

        # Ensure igmp_snooping_vlans is a list
        if not isinstance(igmp_snooping_vlans, list):
            self.msg = "IGMP Snooping VLANs configuration must be a list of dictionaries. Provided: {0}".format(
                type(igmp_snooping_vlans).__name__
            )
            self.log(
                "IGMP Snooping VLANs type validation failed - expected list but got {0}".format(
                    type(igmp_snooping_vlans).__name__
                ),
                "ERROR",
            )
            self.fail_and_exit(self.msg)

        self.log(
            "IGMP Snooping VLANs list contains {0} items".format(
                len(igmp_snooping_vlans)
            ),
            "DEBUG",
        )

        # Get validation rules for IGMP Snooping VLAN
        rules = self.get_layer2_configuration_validation_rules().get(
            "igmp_snooping_vlan"
        )
        self.log(
            "Validation rules for IGMP Snooping VLAN configurations: {0}".format(rules),
            "DEBUG",
        )

        # Iterate over each IGMP Snooping VLAN configuration in the list
        for index, vlan_config in enumerate(igmp_snooping_vlans):
            self.log(
                "Processing IGMP Snooping VLAN configuration at index {0}".format(
                    index
                ),
                "DEBUG",
            )

            # Validate that each VLAN configuration is a dictionary
            if not isinstance(vlan_config, dict):
                self.msg = "Each IGMP Snooping VLAN configuration must be a dictionary. Found: {0}".format(
                    type(vlan_config).__name__
                )
                self.log(
                    "IGMP Snooping VLAN configuration type validation failed at index {0} - expected dict but got {1}".format(
                        index, type(vlan_config).__name__
                    ),
                    "ERROR",
                )
                self.fail_and_exit(self.msg)

            self.log(
                "Validating IGMP Snooping VLAN configuration: {0}".format(vlan_config),
                "DEBUG",
            )

            # Validate the individual IGMP Snooping VLAN configuration against the validation rules
            self.validate_config_against_rules("igmp_snooping_vlan", vlan_config, rules)

            self.log(
                "IGMP Snooping VLAN configuration at index {0} validated successfully".format(
                    index
                ),
                "DEBUG",
            )

        self.log("All IGMP Snooping VLAN configurations validated successfully", "INFO")

    def _validate_mld_snooping_config(self, mld_snooping_config, rules):
        """
        Validates MLD Snooping configuration which includes both global params and VLAN-specific settings.
        Args:
            mld_snooping_config (dict): The MLD Snooping configuration.
            rules (dict): Validation rules for MLD Snooping parameters.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for MLD Snooping global configuration", "INFO")
        self.log(
            "Validating MLD Snooping configuration: {0}".format(mld_snooping_config),
            "DEBUG",
        )

        # Add type check BEFORE trying to use dictionary methods
        if not isinstance(mld_snooping_config, dict):
            self.msg = "MLD Snooping configuration must be of type dictionary. Provided value: '{0}' (type: {1}).".format(
                mld_snooping_config, type(mld_snooping_config).__name__
            )
            self.log("MLD Snooping configuration type validation failed", "ERROR")
            self.fail_and_exit(self.msg)

        # Create a copy of mld_snooping_config without the mld_snooping_vlans for global validation
        mld_global_config = mld_snooping_config.copy()
        mld_snooping_vlans = mld_global_config.pop("mld_snooping_vlans", None)

        self.log(
            "Extracted MLD Snooping VLANs for separate validation: {0}".format(
                bool(mld_snooping_vlans)
            ),
            "DEBUG",
        )

        # Validate the MLD Snooping global configuration against the provided rules
        self.validate_config_against_rules("mld_snooping", mld_global_config, rules)

        self.log(
            "MLD Snooping global configuration validation completed successfully",
            "DEBUG",
        )

        # Validate MLD Snooping VLAN settings if present
        if mld_snooping_vlans:
            self.log("Validating MLD Snooping VLAN settings", "DEBUG")
            self._validate_mld_snooping_vlans(mld_snooping_vlans)
            self.log(
                "MLD Snooping VLAN settings validation completed successfully", "DEBUG"
            )
        else:
            self.log("No MLD Snooping VLAN settings found to validate", "DEBUG")

        self.log("MLD Snooping configuration validation completed successfully", "INFO")

    def _validate_mld_snooping_vlans(self, mld_snooping_vlans):
        """
        Validates MLD Snooping VLAN configurations.
        Args:
            mld_snooping_vlans (list): A list of MLD Snooping VLAN configurations.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for MLD Snooping VLAN configurations", "INFO")

        # Ensure mld_snooping_vlans is a list
        if not isinstance(mld_snooping_vlans, list):
            self.msg = "MLD Snooping VLANs configuration must be a list of dictionaries. Provided: {0}".format(
                type(mld_snooping_vlans).__name__
            )
            self.log(
                "MLD Snooping VLANs type validation failed - expected list but got {0}".format(
                    type(mld_snooping_vlans).__name__
                ),
                "ERROR",
            )
            self.fail_and_exit(self.msg)

        self.log(
            "MLD Snooping VLANs list contains {0} items".format(
                len(mld_snooping_vlans)
            ),
            "DEBUG",
        )

        # Get validation rules for MLD Snooping VLAN
        rules = self.get_layer2_configuration_validation_rules().get(
            "mld_snooping_vlan"
        )
        self.log(
            "Validation rules for MLD Snooping VLAN configurations: {0}".format(rules),
            "DEBUG",
        )

        # Iterate over each MLD Snooping VLAN configuration in the list
        for index, vlan_config in enumerate(mld_snooping_vlans):
            self.log(
                "Processing MLD Snooping VLAN configuration at index {0}".format(index),
                "DEBUG",
            )

            # Validate that each VLAN configuration is a dictionary
            if not isinstance(vlan_config, dict):
                self.msg = "Each MLD Snooping VLAN configuration must be a dictionary. Found: {0}".format(
                    type(vlan_config).__name__
                )
                self.log(
                    "MLD Snooping VLAN configuration type validation failed at index {0} - expected dict but got {1}".format(
                        index, type(vlan_config).__name__
                    ),
                    "ERROR",
                )
                self.fail_and_exit(self.msg)

            self.log(
                "Validating MLD Snooping VLAN configuration: {0}".format(vlan_config),
                "DEBUG",
            )

            # Validate the individual MLD Snooping VLAN configuration against the validation rules
            self.validate_config_against_rules("mld_snooping_vlan", vlan_config, rules)

            self.log(
                "MLD Snooping VLAN configuration at index {0} validated successfully".format(
                    index
                ),
                "DEBUG",
            )

        self.log("All MLD Snooping VLAN configurations validated successfully", "INFO")

    def _validate_authentication_config(self, authentication_config, rules):
        """
        Validates authentication configuration parameters.
        Args:
            authentication_config (dict): The authentication configuration.
            rules (dict): Validation rules for authentication parameters.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for authentication configuration", "INFO")
        self.log(
            "Validating authentication configuration: {0}".format(
                authentication_config
            ),
            "DEBUG",
        )

        # Validate the authentication configuration against the provided validation rules
        self.validate_config_against_rules(
            "authentication", authentication_config, rules
        )

        self.log(
            "Authentication configuration validation completed successfully", "INFO"
        )

    def _validate_logical_ports_config(self, logical_ports_config, rules):
        """
        Validates logical ports configuration which includes both global params and port channels.
        Args:
            logical_ports_config (dict): The logical ports configuration.
            rules (dict): Validation rules for logical ports parameters.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for logical ports configuration", "INFO")
        self.log(
            "Validating logical ports configuration: {0}".format(logical_ports_config),
            "DEBUG",
        )

        # Check if logical_ports_config is a dictionary
        if not isinstance(logical_ports_config, dict):
            msg = "logical_ports configuration must be of type dict, got {0}".format(
                type(logical_ports_config).__name__
            )
            self.log(msg, "ERROR")
            self.module.fail_json(msg=msg)

        # Create a copy of logical_ports_config without the port_channels for global validation
        logical_ports_global_config = logical_ports_config.copy()
        port_channels = logical_ports_global_config.pop("port_channels", None)

        self.log(
            "Extracted port channels for separate validation: {0}".format(
                bool(port_channels)
            ),
            "DEBUG",
        )

        # Validate the logical ports global configuration against the provided rules
        self.validate_config_against_rules(
            "logical_ports", logical_ports_global_config, rules
        )

        self.log(
            "Logical ports global configuration validation completed successfully",
            "DEBUG",
        )

        # Validate port channels if present
        if port_channels:
            self.log("Validating port channels configuration", "DEBUG")
            self._validate_port_channels(port_channels)
            self.log("Port channels validation completed successfully", "DEBUG")
        else:
            self.log("No port channels found to validate", "DEBUG")

        self.log(
            "Logical ports configuration validation completed successfully", "INFO"
        )

    def _validate_port_channels(self, port_channels):
        """
        Validates port channel configurations.
        Args:
            port_channels (list): A list of port channel configurations.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for port channel configurations", "INFO")

        # Ensure port_channels is a list
        if not isinstance(port_channels, list):
            self.msg = "Port channels configuration must be a list of dictionaries. Provided: {0}".format(
                type(port_channels).__name__
            )
            self.log(
                "Port channels type validation failed - expected list but got {0}".format(
                    type(port_channels).__name__
                ),
                "ERROR",
            )
            self.fail_and_exit(self.msg)

        self.log(
            "Port channels list contains {0} items".format(len(port_channels)), "DEBUG"
        )

        # Get validation rules for port channel
        port_channel_rules = self.get_layer2_configuration_validation_rules().get(
            "port_channel"
        )
        self.log(
            "Validation rules for port channel configurations: {0}".format(
                port_channel_rules
            ),
            "DEBUG",
        )

        # Iterate over each port channel configuration in the list
        for index, channel in enumerate(port_channels):
            self.log(
                "Processing port channel configuration at index {0}".format(index),
                "DEBUG",
            )

            # Validate that each port channel configuration is a dictionary
            if not isinstance(channel, dict):
                self.msg = "Each port channel configuration must be a dictionary. Found: {0}".format(
                    type(channel).__name__
                )
                self.log(
                    "Port channel type validation failed at index {0} - expected dict but got {1}".format(
                        index, type(channel).__name__
                    ),
                    "ERROR",
                )
                self.fail_and_exit(self.msg)

            self.log(
                "Validating port channel configuration: {0}".format(channel), "DEBUG"
            )

            # Validate the port channel configuration against rules
            self.validate_config_against_rules(
                "port_channel", channel, port_channel_rules
            )

            # Get the protocol of this port channel
            protocol = channel.get("port_channel_protocol")
            self.log("Port channel protocol identified: {0}".format(protocol), "DEBUG")

            # Validate port channel members based on the protocol
            port_channel_members = channel.get("port_channel_members")
            if port_channel_members:
                self.log(
                    "Validating port channel members for protocol {0}".format(protocol),
                    "DEBUG",
                )
                self._validate_port_channel_members(port_channel_members, protocol)
                self.log(
                    "Port channel members validation completed for index {0}".format(
                        index
                    ),
                    "DEBUG",
                )
            else:
                self.log(
                    "No port channel members found at index {0}".format(index), "DEBUG"
                )

            self.log(
                "Port channel configuration at index {0} validated successfully".format(
                    index
                ),
                "DEBUG",
            )

        self.log("All port channel configurations validated successfully", "INFO")

    def _validate_port_channel_members(self, port_channel_members, protocol):
        """
        Validates port channel member configurations based on the protocol.
        Args:
            port_channel_members (list): A list of port channel member configurations.
            protocol (str): The protocol of the port channel (LACP, PAGP, or NONE).
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log(
            "Starting validation for port channel members with protocol {0}".format(
                protocol
            ),
            "INFO",
        )
        self.log(
            "Port channel members to validate: {0}".format(port_channel_members),
            "DEBUG",
        )

        # Ensure port_channel_members is a list
        if not isinstance(port_channel_members, list):
            self.msg = "Port channel members configuration must be a list of dictionaries. Provided: {0}".format(
                type(port_channel_members).__name__
            )
            self.log(
                "Port channel members type validation failed - expected list but got {0}".format(
                    type(port_channel_members).__name__
                ),
                "ERROR",
            )
            self.fail_and_exit(self.msg)

        self.log(
            "Port channel members list contains {0} items".format(
                len(port_channel_members)
            ),
            "DEBUG",
        )

        # Map protocol to the appropriate validation rule set
        protocol_rule_map = {
            "LACP": "port_channel_member_lacp",
            "PAGP": "port_channel_member_pagp",
            "NONE": "port_channel_member_none",
        }

        rule_set_name = protocol_rule_map.get(protocol)
        if not rule_set_name:
            self.msg = (
                "Invalid port channel protocol: '{0}'. Must be one of {1}.".format(
                    protocol, list(protocol_rule_map.keys())
                )
            )
            self.log("Invalid protocol specified: {0}".format(protocol), "ERROR")
            self.fail_and_exit(self.msg)

        self.log(
            "Using validation rule set: {0} for protocol {1}".format(
                rule_set_name, protocol
            ),
            "DEBUG",
        )

        # Get validation rules for the specific protocol's member ports
        member_rules = self.get_layer2_configuration_validation_rules().get(
            rule_set_name
        )
        self.log(
            "Validation rules for {0} port channel member configurations: {1}".format(
                protocol, member_rules
            ),
            "DEBUG",
        )

        # Enforce member limit for LACP (max 16 members)
        if protocol == "LACP" and len(port_channel_members) > 16:
            self.msg = "LACP port channel can have a maximum of 16 member ports. Found: {0}".format(
                len(port_channel_members)
            )
            self.log(
                "LACP member limit exceeded: {0} members found".format(
                    len(port_channel_members)
                ),
                "ERROR",
            )
            self.fail_and_exit(self.msg)

        # Iterate over each port channel member in the list
        for index, member in enumerate(port_channel_members):
            self.log(
                "Processing port channel member at index {0}".format(index), "DEBUG"
            )

            # Validate that each member configuration is a dictionary
            if not isinstance(member, dict):
                self.msg = "Each port channel member configuration must be a dictionary. Found: {0}".format(
                    type(member).__name__
                )
                self.log(
                    "Port channel member type validation failed at index {0} - expected dict but got {1}".format(
                        index, type(member).__name__
                    ),
                    "ERROR",
                )
                self.fail_and_exit(self.msg)

            self.log(
                "Validating {0} port channel member configuration: {1}".format(
                    protocol, member
                ),
                "DEBUG",
            )

            # Special validation for port_channel_rate in LACP
            if protocol == "LACP" and "port_channel_rate" in member:
                rate_value = member["port_channel_rate"]
                self.log(
                    "Validating LACP port_channel_rate parameter: {0}".format(
                        rate_value
                    ),
                    "DEBUG",
                )

                if isinstance(rate_value, int):
                    # Check if rate value is valid for LACP (1 or 30)
                    if rate_value != 1 and rate_value != 30:
                        self.msg = "Invalid port_channel_rate for LACP: {0}. Must be 1 (FAST) or 30 (NORMAL). Full member configuration: {1}".format(
                            rate_value, member
                        )
                        self.log(
                            "Invalid LACP rate value: {0}".format(rate_value), "ERROR"
                        )
                        self.fail_and_exit(self.msg)
                    # We keep the value as-is (1 or 30)
                    self.log("LACP rate value {0} is valid".format(rate_value), "DEBUG")
                else:
                    # If it's not an integer, fail with a detailed error message
                    self.msg = "port_channel_rate for LACP must be an integer (1 or 30). Received: {0} of type {1}. Full member configuration: {2}".format(
                        rate_value, type(rate_value).__name__, member
                    )
                    self.log(
                        "LACP rate value type validation failed: expected int but got {0}".format(
                            type(rate_value).__name__
                        ),
                        "ERROR",
                    )
                    self.fail_and_exit(self.msg)

            # Validate the member configuration against appropriate rules for the protocol
            self.validate_config_against_rules(rule_set_name, member, member_rules)

            self.log(
                "Port channel member at index {0} validated successfully".format(index),
                "DEBUG",
            )

        self.log(
            "All port channel members validated successfully for protocol {0}".format(
                protocol
            ),
            "INFO",
        )

    def _validate_port_configurations(self, port_configurations, rules=None):
        """
        Validates port configurations which is a list of interface configurations.
        Args:
            port_configurations (list): A list of port configurations for various interfaces.
            rules (dict): Not used for this validation but included for consistency with other validators.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for port configurations.", "INFO")

        # Ensure port_configurations is a list
        if not isinstance(port_configurations, list):
            self.msg = "Port configurations must be a list of dictionaries. Provided: {0}".format(
                type(port_configurations).__name__
            )
            self.fail_and_exit(self.msg)

        # Get all the validation rules
        validation_rules = self.get_layer2_configuration_validation_rules()

        # Iterate over each port configuration in the list
        for port_config in port_configurations:
            if not isinstance(port_config, dict):
                self.msg = (
                    "Each port configuration must be a dictionary. Found: {0}".format(
                        type(port_config).__name__
                    )
                )
                self.fail_and_exit(self.msg)

            # Validate interface_name is present
            if "interface_name" not in port_config:
                self.msg = "Each port configuration must have an 'interface_name'. Missing in: {0}".format(
                    port_config
                )
                self.fail_and_exit(self.msg)

            interface_name = port_config["interface_name"]

            # Validate interface_name is a string
            if not isinstance(interface_name, str):
                self.msg = "Parameter 'interface_name' must be of type string. Provided value: '{0}' (type: {1}). Full configuration: {2}".format(
                    interface_name, type(interface_name).__name__, port_config
                )
                self.fail_and_exit(self.msg)

            # Check that interface_name is not an empty string
            if not interface_name.strip():
                self.msg = "Parameter 'interface_name' must not be empty. Provided value: '{0}'. Full configuration: {1}".format(
                    interface_name, port_config
                )
                self.fail_and_exit(self.msg)

            self.log(
                "Validating port configuration for interface: {0}".format(
                    interface_name
                ),
                "DEBUG",
            )

            # Check each interface configuration type and validate it
            config_types = [
                "switchport_interface_config",
                "vlan_trunking_interface_config",
                "dot1x_interface_config",
                "mab_interface_config",
                "stp_interface_config",
                "dhcp_snooping_interface_config",
                "cdp_interface_config",
                "lldp_interface_config",
                "vtp_interface_config",
            ]

            for config_type in config_types:
                if config_type in port_config:
                    config_value = port_config[config_type]
                    config_rules = validation_rules.get(config_type)

                    if not config_rules:
                        self.msg = "No validation rules found for {0}. Available rules: {1}".format(
                            config_type, list(validation_rules.keys())
                        )
                        self.fail_and_exit(self.msg)

                    self.log(
                        "Validating {0} for interface {1}".format(
                            config_type, interface_name
                        ),
                        "DEBUG",
                    )

                    # Special handling for certain config types
                    if config_type == "stp_interface_config":
                        self._validate_stp_interface_config(
                            interface_name, config_value, config_rules
                        )
                    else:
                        # Standard validation for most config types
                        self.validate_config_against_rules(
                            config_type, config_value, config_rules
                        )

        self.log("Completed validation for all port configurations.", "INFO")

    def _validate_stp_interface_config(self, interface_name, config, rules):
        """
        Validates STP interface configuration, including special handling for per-VLAN settings.
        Args:
            interface_name (str): The name of the interface.
            config (dict): The STP interface configuration.
            rules (dict): Validation rules for STP interface parameters.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log(
            "Validating STP interface configuration for {0}: {1}".format(
                interface_name, config
            ),
            "DEBUG",
        )

        # First check if config is the expected type (dictionary)
        if not isinstance(config, dict):
            self.msg = "stp_interface_config must be a dictionary. Provided value: '{0}' (type: {1}). Interface: {2}".format(
                config, type(config).__name__, interface_name
            )
            self.fail_and_exit(self.msg)

        # Create a copy without the per-VLAN settings for standard validation
        stp_interface_config = config.copy()
        per_vlan_cost = stp_interface_config.pop("stp_interface_per_vlan_cost", None)
        per_vlan_priority = stp_interface_config.pop(
            "stp_interface_per_vlan_priority", None
        )

        self.log(
            "Extracted per-VLAN cost settings: {0}".format(bool(per_vlan_cost)), "DEBUG"
        )
        self.log(
            "Extracted per-VLAN priority settings: {0}".format(bool(per_vlan_priority)),
            "DEBUG",
        )

        # Validate the standard STP interface configuration
        self.validate_config_against_rules(
            "stp_interface_config", stp_interface_config, rules
        )

        self.log(
            "Standard STP interface configuration validation completed successfully",
            "DEBUG",
        )

        # Get validation rules for per-VLAN settings
        validation_rules = self.get_layer2_configuration_validation_rules()

        # Validate per-VLAN cost settings if present
        if per_vlan_cost:
            self.log(
                "Validating per-VLAN cost settings for interface {0}".format(
                    interface_name
                ),
                "DEBUG",
            )
            self.validate_config_against_rules(
                "stp_interface_per_vlan_cost",
                per_vlan_cost,
                validation_rules.get("stp_interface_per_vlan_cost"),
            )
            self.log(
                "Per-VLAN cost settings validation completed successfully", "DEBUG"
            )
        else:
            self.log("No per-VLAN cost settings found to validate", "DEBUG")

        # Validate per-VLAN priority settings if present
        if per_vlan_priority:
            self.log(
                "Validating per-VLAN priority settings for interface {0}".format(
                    interface_name
                ),
                "DEBUG",
            )
            self.validate_config_against_rules(
                "stp_interface_per_vlan_priority",
                per_vlan_priority,
                validation_rules.get("stp_interface_per_vlan_priority"),
            )
            self.log(
                "Per-VLAN priority settings validation completed successfully", "DEBUG"
            )
        else:
            self.log("No per-VLAN priority settings found to validate", "DEBUG")

        self.log(
            "STP interface configuration validation completed successfully for interface {0}".format(
                interface_name
            ),
            "INFO",
        )

    def validate_layer2_config_params(self, layer2_configuration):
        """
        Validates all Layer 2 configurations.
        Args:
            layer2_configuration (dict): The Layer 2 configuration provided by the user.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        self.log("Starting validation for Layer 2 configurations.", "INFO")

        # Check if layer2_configuration is present, not None, and not an empty dictionary
        if not layer2_configuration or not isinstance(layer2_configuration, dict):
            self.log(
                "Layer 2 configuration is either missing, None, or an empty dictionary. Skipping Layer 2 validation.",
                "INFO",
            )
            return

        # Map of feature names to their validation functions
        feature_validators = {
            "vlans": self._validate_vlans_config,
            "stp": self._validate_stp_config,
            "cdp": self._validate_cdp_config,
            "lldp": self._validate_lldp_config,
            "vtp": self._validate_vtp_config,
            "dhcp_snooping": self._validate_dhcp_snooping_config,
            "igmp_snooping": self._validate_igmp_snooping_config,
            "mld_snooping": self._validate_mld_snooping_config,
            "authentication": self._validate_authentication_config,
            "logical_ports": self._validate_logical_ports_config,
            "port_configuration": self._validate_port_configurations,
        }

        # Validate each configuration
        for config_name, config_values in layer2_configuration.items():
            self.log(
                "Validating Layer 2 configuration: {0}".format(config_name), "DEBUG"
            )

            # Handle None values (when user specifies "cdp:" without a value)
            if config_values is None:
                self.log(
                    "Configuration '{0}' has None value. Treating as empty configuration and skipping validation.".format(
                        config_name
                    ),
                    "INFO",
                )
                continue

            # Handle empty dictionaries or lists
            if not config_values:
                self.log(
                    "Configuration '{0}' is empty. Skipping validation.".format(
                        config_name
                    ),
                    "INFO",
                )
                continue

            # Get validation rules for this feature
            validation_rules = self.get_layer2_configuration_validation_rules().get(
                config_name
            )

            self.log(
                "Validation rules for {0} configuration: {1}".format(
                    config_name, validation_rules
                ),
                "DEBUG",
            )

            # Get the appropriate validator for this feature
            validator = feature_validators.get(config_name)

            if validator:
                # Call the specific validator with the config data and rules
                validator(config_values, validation_rules)
            else:
                # This should never happen if our feature_validators dictionary is complete
                self.msg = "No validator available for feature '{0}'.".format(
                    config_name
                )
                self.fail_and_exit(self.msg)

            self.log(
                "{0} configuration validated successfully.".format(config_name),
                "INFO",
            )

        self.log("Completed validation for all Layer 2 configurations.", "INFO")

    def validate_params(self, config, state):
        """
        Validates the input parameters for the playbook configuration.
        Args:
            config (dict): The configuration details from the playbook.
            state (str): The desired state of the configuration.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        # Validate the ip/hostname
        ip_address = config.get("ip_address")
        hostname = config.get("hostname")
        device_collection_status_check = config.get("device_collection_status_check")
        self.validate_ip_and_hostname(
            ip_address, hostname, device_collection_status_check
        )

        self.log("Starting validation of the input parameters.", "INFO")
        self.log("State: {0}".format(state), "DEBUG")

        self.log("Configuration to validate: {0}".format(config), "DEBUG")

        # Validate the Layer 2 configurations
        layer2_configuration = config.get("layer2_configuration", {})
        if layer2_configuration:
            # Validate Layer 2 configuration parameters
            self.validate_layer2_config_params(layer2_configuration)
        else:
            self.log(
                "No Layer 2 configurations provided. Skipping Layer 2 validation.",
                "INFO",
            )

        self.log("Completed validation of all input parameters.", "INFO")

    def _map_parameters(self, user_config, mapping_schema):
        """
        Maps user configuration parameters to API parameters based on a mapping schema.
        Args:
            user_config (dict/list): The user configuration to map.
            mapping_schema (dict): Schema defining how to map user parameters to API parameters.
        Returns:
            dict: The mapped configuration in API-compatible format.
        Raises:
            ValueError: If an invalid processing strategy is determined.
        """
        self.log("Starting parameter mapping operation", "INFO")
        self.log("Input user configuration: {0}".format(user_config), "DEBUG")
        self.log("Mapping schema provided: {0}".format(mapping_schema), "DEBUG")

        # Initialize the base structure
        mapped_config = self._initialize_mapped_config(mapping_schema)

        # Determine processing strategy based on input type and schema
        processing_strategy = self._determine_processing_strategy(
            user_config, mapping_schema
        )
        self.log("Using processing strategy: {0}".format(processing_strategy), "DEBUG")

        # Apply the appropriate mapping strategy
        if processing_strategy == "list_input":
            self._process_list_input(user_config, mapping_schema, mapped_config)
        elif processing_strategy == "dict_with_path":
            self._process_dict_with_path(user_config, mapping_schema, mapped_config)
        elif processing_strategy == "flat_dict":
            self._process_flat_dict(user_config, mapping_schema, mapped_config)
        else:
            self.log(
                "Unknown processing strategy: {0}".format(processing_strategy), "ERROR"
            )
            raise ValueError("Invalid processing strategy determined")

        self.log("Parameter mapping operation completed successfully", "INFO")
        self.log("Final mapped configuration: {0}".format(mapped_config), "DEBUG")

        return mapped_config

    def _initialize_mapped_config(self, mapping_schema):
        """
        Initialize the base mapped configuration structure.
        Args:
            mapping_schema (dict): The mapping schema containing output_structure.
        Returns:
            dict: Initialized mapped configuration.
        """
        output_structure = mapping_schema.get("output_structure", {})
        mapped_config = output_structure.copy() if output_structure else {}
        self.log(
            "Initialized base mapped configuration: {0}".format(mapped_config), "DEBUG"
        )
        return mapped_config

    def _determine_processing_strategy(self, user_config, mapping_schema):
        """
        Determine the appropriate processing strategy based on input type and schema.
        Args:
            user_config (dict/list): The user configuration
            mapping_schema (dict): The mapping schema
        Returns:
            str: The processing strategy to use
        """
        is_list_input = mapping_schema.get("is_list_input", False)
        input_is_list = isinstance(user_config, list)
        has_param_path = "param_path" in mapping_schema

        self.log(
            "Input analysis - is_list_input: {0}, input_is_list: {1}, has_param_path: {2}".format(
                is_list_input, input_is_list, has_param_path
            ),
            "DEBUG",
        )

        # Determine strategy based on schema configuration and input type
        if is_list_input and input_is_list:
            return "list_input"
        elif has_param_path:
            return "dict_with_path"
        else:
            return "flat_dict"

    def _process_list_input(self, user_config, mapping_schema, mapped_config):
        """
        Process list input configuration (like VLANs).
        Args:
            user_config (list): List of configuration items
            mapping_schema (dict): Mapping schema
            mapped_config (dict): The configuration being built
        """
        self.log(
            "Processing list input configuration with {0} items".format(
                len(user_config)
            ),
            "INFO",
        )

        # Extract schema components
        list_path = mapping_schema.get("list_path", [])
        item_config_type = mapping_schema.get("item_config_type", "")
        param_mapping = mapping_schema.get("param_mapping", {})

        self.log(
            "List processing parameters - path: {0}, config_type: {1}".format(
                list_path, item_config_type
            ),
            "DEBUG",
        )

        # Process each item in the list
        items_list = []
        for index, item in enumerate(user_config):
            mapped_item = self._map_single_item(
                item, param_mapping, item_config_type, index
            )
            items_list.append(mapped_item)

        self.log("Created {0} mapped items".format(len(items_list)), "INFO")

        # Place the items list in the correct location
        if list_path:
            self._place_items_at_path(mapped_config, list_path, items_list)
        else:
            self.log("No list path specified, items not placed in structure", "WARNING")

    def _process_dict_with_path(self, user_config, mapping_schema, mapped_config):
        """
        Process dictionary input with a specific parameter path (like CDP).
        Args:
            user_config (dict): Dictionary configuration
            mapping_schema (dict): Mapping schema
            mapped_config (dict): The configuration being built
        """
        self.log("Processing dictionary input with parameter path", "INFO")

        param_path = mapping_schema.get("param_path", [])
        item_config_type = mapping_schema.get("item_config_type", "")
        param_mapping = mapping_schema.get("param_mapping", {})

        self.log(
            "Path processing parameters - path: {0}, config_type: {1}".format(
                param_path, item_config_type
            ),
            "DEBUG",
        )

        # Navigate to the target location
        target_container = self._navigate_and_create_path(
            mapped_config, param_path, item_config_type
        )

        # Map parameters to the target container
        mapped_count = self._apply_parameter_mapping(
            user_config, param_mapping, target_container
        )

        self.log(
            "Mapped {0} parameters using parameter path".format(mapped_count), "INFO"
        )

    def _process_flat_dict(self, user_config, mapping_schema, mapped_config):
        """
        Process dictionary input with flat mapping (no nested paths).
        Args:
            user_config (dict): Dictionary configuration
            mapping_schema (dict): Mapping schema
            mapped_config (dict): The configuration being built
        """
        self.log("Processing dictionary input with flat mapping", "INFO")

        param_mapping = mapping_schema.get("param_mapping", {})

        # Apply flat mapping directly to mapped_config
        mapped_count = self._apply_parameter_mapping(
            user_config, param_mapping, mapped_config
        )

        self.log(
            "Mapped {0} parameters using flat mapping".format(mapped_count), "INFO"
        )

    def _map_single_item(self, item, param_mapping, config_type, item_index=None):
        """
        Map a single configuration item.
        Args:
            item (dict): Single configuration item
            param_mapping (dict): Parameter mapping rules
            config_type (str): ConfigType for this item
            item_index (int, optional): Index for logging purposes
        Returns:
            dict: Mapped item
        """
        index_str = " {0}".format(item_index) if item_index is not None else ""
        self.log("Mapping single item{0}: {1}".format(index_str, item), "DEBUG")

        # Create base item with configType
        mapped_item = {"configType": config_type} if config_type else {}

        # Apply parameter mapping
        mapped_count = self._apply_parameter_mapping(item, param_mapping, mapped_item)

        self.log(
            "Mapped {0} parameters for item{1}".format(mapped_count, index_str), "DEBUG"
        )
        self.log("Final mapped item{0}: {1}".format(index_str, mapped_item), "DEBUG")

        return mapped_item

    def _apply_parameter_mapping(self, source_config, param_mapping, target_container):
        """
        Apply parameter mapping from source to target container.
        Args:
            source_config (dict): Source configuration containing user parameters
            param_mapping (dict): Mapping from user params to API params
            target_container (dict): Target container to receive mapped parameters
        Returns:
            int: Number of parameters successfully mapped
        """
        mapped_count = 0

        for user_param, api_param in param_mapping.items():
            if user_param in source_config:
                original_value = source_config.get(user_param)

                # Handle special value transformations
                transformed_value = self._transform_parameter_value(
                    user_param, original_value, api_param
                )

                target_container[api_param] = transformed_value
                mapped_count += 1

                self.log(
                    "Mapped parameter '{0}' -> '{1}' with value: {2}".format(
                        user_param, api_param, transformed_value
                    ),
                    "DEBUG",
                )
            else:
                self.log(
                    "Parameter '{0}' not found in source config, skipping".format(
                        user_param
                    ),
                    "DEBUG",
                )

        return mapped_count

    def _transform_parameter_value(self, user_param, original_value, api_param):
        """
        Transform parameter values based on specific rules.
        Args:
            user_param (str): Original user parameter name
            original_value: Original parameter value
            api_param (str): Target API parameter name
        Returns:
            Transformed value for the API
        """
        self.log(
            "Starting parameter value transformation for parameter: {0}".format(
                user_param
            ),
            "DEBUG",
        )
        self.log(
            "Original value: {0} (type: {1})".format(
                original_value, type(original_value).__name__
            ),
            "DEBUG",
        )
        self.log("Target API parameter: {0}".format(api_param), "DEBUG")

        # Handle boolean to string transformations for specific parameters
        boolean_to_string_mappings = {
            "admin_status": lambda x: "UP" if x else "DOWN",
            "stp_interface_bpdu_filter": lambda x: "ENABLE" if x else "DISABLE",
            "stp_interface_bpdu_guard": lambda x: "ENABLE" if x else "DISABLE",
        }

        # Handle list to string transformations
        if isinstance(original_value, list) and "vlan" in user_param.lower():
            self.log("Applying VLAN list to string transformation", "DEBUG")
            transformed_value = self._convert_vlan_list_to_string(original_value)
            self.log("VLAN list transformed to: {0}".format(transformed_value), "DEBUG")
            return transformed_value

        # Apply boolean transformations if applicable
        if user_param in boolean_to_string_mappings:
            self.log(
                "Applying boolean to string transformation for parameter: {0}".format(
                    user_param
                ),
                "DEBUG",
            )
            transformed_value = boolean_to_string_mappings[user_param](original_value)
            self.log(
                "Boolean value {0} transformed to: {1}".format(
                    original_value, transformed_value
                ),
                "DEBUG",
            )
            return transformed_value

        # Return original value if no transformation needed
        self.log(
            "No transformation required for parameter: {0}".format(user_param), "DEBUG"
        )
        self.log("Returning original value: {0}".format(original_value), "DEBUG")
        return original_value

    def _navigate_and_create_path(self, base_config, path_list, final_config_type=""):
        """
        Navigate through a nested path, creating missing sections as needed.
        Args:
            base_config (dict): Base configuration to navigate
            path_list (list): List of path components to navigate
            final_config_type (str): ConfigType for final container if creating new
        Returns:
            dict: Target container at the end of the path
        """
        if not path_list:
            return base_config

        self.log("Navigating path: {0}".format(path_list), "DEBUG")

        current = base_config

        # Navigate to all but the last path component
        for path_index, path_part in enumerate(path_list[:-1]):
            current = self._navigate_to_path_component(current, path_part, path_index)

        # Handle the final path component specially
        final_key = path_list[-1]
        return self._get_or_create_final_container(
            current, final_key, final_config_type
        )

    def _navigate_to_path_component(
        self, current_container, path_component, path_index
    ):
        """
        Navigate to a single path component, creating it if necessary.
        Args:
            current_container (dict): Current container
            path_component (str): Path component to navigate to
            path_index (int): Index for logging
        Returns:
            dict: Container at the path component
        """
        self.log(
            "Navigating to path component {0}: '{1}'".format(
                path_index, path_component
            ),
            "DEBUG",
        )

        if path_component not in current_container:
            current_container[path_component] = {}
            self.log("Created new path section '{0}'".format(path_component), "DEBUG")
        else:
            self.log(
                "Path section '{0}' already exists".format(path_component), "DEBUG"
            )

        return current_container[path_component]

    def _get_or_create_final_container(self, parent_container, final_key, config_type):
        """
        Get or create the final target container for parameter mapping.
        Args:
            parent_container (dict): Parent container
            final_key (str): Final key in the path
            config_type (str): ConfigType for new containers
        Returns:
            dict: Target container for parameter mapping
        """
        if final_key not in parent_container:
            # Create new container with configType in a list structure
            parent_container[final_key] = (
                [{"configType": config_type}] if config_type else [{}]
            )
            self.log(
                "Created final container '{0}' with configType '{1}'".format(
                    final_key, config_type
                ),
                "DEBUG",
            )
        else:
            self.log("Final container '{0}' already exists".format(final_key), "DEBUG")

        # Return the first item in the list for parameter mapping
        target = parent_container[final_key][0]
        self.log("Target container for parameter mapping: {0}".format(target), "DEBUG")

        return target

    def _place_items_at_path(self, base_config, path_list, items_list):
        """
        Place a list of items at the specified path in the configuration.
        Args:
            base_config (dict): Base configuration
            path_list (list): Path where items should be placed
            items_list (list): List of items to place
        """
        if not path_list:
            self.log("Empty path provided for item placement", "WARNING")
            return

        self.log(
            "Placing {0} items at path: {1}".format(len(items_list), path_list), "DEBUG"
        )

        # Navigate to the parent of the final location
        current = base_config
        for path_part in path_list[:-1]:
            if path_part not in current:
                current[path_part] = {}
            current = current[path_part]

        # Set the items at the final location
        final_key = path_list[-1]
        current[final_key] = items_list

        self.log(
            "Successfully placed items at path key '{0}'".format(final_key), "INFO"
        )

    def _convert_vlan_list_to_string(self, vlan_list):
        """
        Converts a list of VLAN IDs to a comma-separated string.
        Args:
            vlan_list (list): List of VLAN IDs
        Returns:
            str: Comma-separated string of VLAN IDs
        """
        self.log("Starting VLAN list to string conversion", "DEBUG")
        self.log("Input VLAN list: {0}".format(vlan_list), "DEBUG")

        # Check if the VLAN list is empty or None
        if not vlan_list:
            self.log(
                "Empty or None VLAN list provided, returning empty string", "DEBUG"
            )
            return ""

        # Convert each VLAN ID to string and join with commas
        result = ",".join(map(str, vlan_list))

        self.log("VLAN list conversion completed successfully", "DEBUG")
        self.log("Converted VLAN list to string: {0}".format(result), "DEBUG")

        return result

    def _map_vlans_config(self, vlan_config):
        """
        Maps VLAN configuration parameters from user format to API format.
        Args:
            vlan_config (list): A list of VLAN configurations provided by the user.
        Returns:
            dict: Mapped VLAN configuration in API-compatible format with 'vlanConfig' as the key.
        """
        self.log("Mapping VLAN configuration: {0}".format(vlan_config), "DEBUG")

        # Define the mapping schema for VLANs - corrected to match API format
        vlan_mapping_schema = {
            "output_structure": {"vlanConfig": {"items": []}},
            "item_config_type": "VLAN",
            "is_list_input": True,
            "list_path": ["vlanConfig", "items"],
            "param_mapping": {
                "vlan_id": "vlanId",
                "vlan_name": "name",
                "vlan_admin_status": "isVlanEnabled",
            },
        }

        # Use the generic mapping function
        return self._map_parameters(vlan_config, vlan_mapping_schema)

    def _map_cdp_config(self, cdp_config):
        """
        Maps CDP configuration parameters from user format to API format.
        Args:
            cdp_config (dict): The CDP configuration provided by the user.
        Returns:
            dict: Mapped CDP configuration in API-compatible format.
        """
        self.log("Mapping CDP configuration: {0}".format(cdp_config), "DEBUG")

        # Define the mapping schema for CDP
        cdp_mapping_schema = {
            "output_structure": {},
            "item_config_type": "CDP_GLOBAL",
            "param_path": ["cdpGlobalConfig", "items"],
            "param_mapping": {
                "cdp_admin_status": "isCdpEnabled",
                "cdp_hold_time": "holdTime",
                "cdp_timer": "timer",
                "cdp_advertise_v2": "isAdvertiseV2Enabled",
                "cdp_log_duplex_mismatch": "isLogDuplexMismatchEnabled",
            },
        }

        # Use the generic mapping function
        return self._map_parameters(cdp_config, cdp_mapping_schema)

    def _map_lldp_config(self, lldp_config):
        """
        Maps LLDP configuration parameters from user format to API format.
        Args:
            lldp_config (dict): The LLDP configuration provided by the user.
        Returns:
            dict: Mapped LLDP configuration in API-compatible format.
        """
        self.log("Mapping LLDP configuration: {0}".format(lldp_config), "DEBUG")

        # Define the mapping schema for LLDP
        lldp_mapping_schema = {
            "output_structure": {},
            "item_config_type": "LLDP_GLOBAL",
            "param_path": ["lldpGlobalConfig", "items"],
            "param_mapping": {
                "lldp_admin_status": "isLldpEnabled",
                "lldp_hold_time": "holdTime",
                "lldp_timer": "timer",
                "lldp_reinitialization_delay": "reinitializationDelay",
            },
        }

        # Use the generic mapping function
        return self._map_parameters(lldp_config, lldp_mapping_schema)

    def _map_stp_config(self, stp_config):
        """
        Maps STP configuration parameters from user format to API format.
        Args:
            stp_config (dict): The STP configuration provided by the user.
        Returns:
            dict: Mapped STP configuration in API-compatible format.
        """
        self.log("Mapping STP configuration: {0}".format(stp_config), "DEBUG")

        # Extract stp_instances from the config for separate handling
        stp_instances = stp_config.get("stp_instances", [])
        main_stp_config = {k: v for k, v in stp_config.items() if k != "stp_instances"}

        self.log(
            "Extracted {0} STP instances for separate processing".format(
                len(stp_instances)
            ),
            "DEBUG",
        )
        self.log(
            "Main STP global config parameters: {0}".format(main_stp_config), "DEBUG"
        )

        # Define the mapping schema for the main STP global config
        stp_mapping_schema = {
            "output_structure": {},
            "item_config_type": "STP_GLOBAL",
            "param_path": ["stpGlobalConfig", "items"],
            "param_mapping": {
                "stp_mode": "stpMode",
                "stp_backbonefast": "isBackboneFastEnabled",
                "stp_etherchannel_guard": "isEtherChannelGuardEnabled",
                "stp_extended_system_id": "isExtendedSystemIdEnabled",
                "stp_logging": "isLoggingEnabled",
                "stp_loopguard": "isLoopGuardEnabled",
                "stp_portfast_mode": "portFastMode",
                "stp_bpdu_filter": "isBpduFilterEnabled",
                "stp_bpdu_guard": "isBpduGuardEnabled",
                "stp_uplinkfast": "isUplinkFastEnabled",
                "stp_transmit_hold_count": "transmitHoldCount",
                "stp_uplinkfast_max_update_rate": "uplinkFastMaxUpdateRate",
            },
        }

        # Use the generic mapping function for the main STP config
        mapped_config = self._map_parameters(main_stp_config, stp_mapping_schema)

        self.log("Main STP global configuration mapped successfully", "DEBUG")

        # Handle STP instances separately if present
        if stp_instances:
            self.log(
                "Processing {0} STP instances for integration".format(
                    len(stp_instances)
                ),
                "DEBUG",
            )

            # Get the stpGlobalConfig.items[0] reference to add instances to
            stp_item = mapped_config["stpGlobalConfig"]["items"][0]

            # Create the instances container
            stp_item["stpInstances"] = {"configType": "LIST", "items": []}

            self.log("Created STP instances container structure", "DEBUG")

            # Process each STP instance
            for instance in stp_instances:
                self.log(
                    "Processing STP instance for VLAN {0}".format(
                        instance.get("stp_instance_vlan_id")
                    ),
                    "DEBUG",
                )

                # Create a new instance with the required configType
                instance_item = {
                    "configType": "STP_VLAN",
                    "vlanId": instance.get("stp_instance_vlan_id"),
                }

                # Add priority if present
                if "stp_instance_priority" in instance:
                    instance_item["priority"] = instance.get("stp_instance_priority")
                    self.log(
                        "Added priority {0} for VLAN {1}".format(
                            instance.get("stp_instance_priority"),
                            instance.get("stp_instance_vlan_id"),
                        ),
                        "DEBUG",
                    )

                # Add enable_stp at the instance level (not in timers)
                if "enable_stp" in instance:
                    instance_item["isStpEnabled"] = instance.get("enable_stp")
                    self.log(
                        "Set STP enabled status to {0} for VLAN {1}".format(
                            instance.get("enable_stp"),
                            instance.get("stp_instance_vlan_id"),
                        ),
                        "DEBUG",
                    )

                # Create timers configuration if any timer parameters are present
                timer_params = [
                    "stp_instance_forward_delay_timer",
                    "stp_instance_hello_interval_timer",
                    "stp_instance_max_age_timer",
                ]

                # Check if any timer parameters are provided
                has_timer_params = any(param in instance for param in timer_params)

                if has_timer_params:
                    self.log(
                        "Timer parameters found for VLAN {0}, creating timers configuration".format(
                            instance.get("stp_instance_vlan_id")
                        ),
                        "DEBUG",
                    )

                    # Create the timers configuration (without isStpEnabled)
                    timers = {"configType": "STP_TIMERS"}

                    # Map timer parameters (excluding enable_stp)
                    timer_mapping = {
                        "stp_instance_forward_delay_timer": "forwardDelay",
                        "stp_instance_hello_interval_timer": "helloInterval",
                        "stp_instance_max_age_timer": "maxAge",
                    }

                    # Add timer parameters that are provided
                    for user_param, api_param in timer_mapping.items():
                        if user_param in instance:
                            timers[api_param] = instance.get(user_param)
                            self.log(
                                "Mapped timer parameter {0} to {1} with value {2}".format(
                                    user_param, api_param, instance.get(user_param)
                                ),
                                "DEBUG",
                            )

                    # Add timers to the instance
                    instance_item["timers"] = timers
                    self.log(
                        "Added timers configuration to VLAN {0} instance".format(
                            instance.get("stp_instance_vlan_id")
                        ),
                        "DEBUG",
                    )
                else:
                    self.log(
                        "No timer parameters found for VLAN {0}, skipping timers configuration".format(
                            instance.get("stp_instance_vlan_id")
                        ),
                        "DEBUG",
                    )

                # Add the instance to the instances list
                stp_item["stpInstances"]["items"].append(instance_item)
                self.log(
                    "Successfully added STP instance for VLAN {0} to instances list".format(
                        instance.get("stp_instance_vlan_id")
                    ),
                    "DEBUG",
                )

            self.log(
                "Completed processing all {0} STP instances".format(len(stp_instances)),
                "DEBUG",
            )
        else:
            self.log("No STP instances found to process", "DEBUG")

        self.log("STP configuration mapping completed successfully", "INFO")
        self.log("Final mapped STP configuration: {0}".format(mapped_config), "DEBUG")

        return mapped_config

    def _map_vtp_config(self, vtp_config):
        """
        Maps VTP configuration parameters from user format to API format.
        Args:
            vtp_config (dict): The VTP configuration provided by the user.
        Returns:
            dict: Mapped VTP configuration in API-compatible format.
        """
        self.log("Mapping VTP configuration: {0}".format(vtp_config), "DEBUG")

        # Define the mapping schema for VTP
        vtp_mapping_schema = {
            "output_structure": {},
            "item_config_type": "VTP_GLOBAL",
            "param_path": ["vtpGlobalConfig", "items"],
            "param_mapping": {
                "vtp_mode": "mode",
                "vtp_version": "version",
                "vtp_domain_name": "domainName",
                "vtp_pruning": "isPruningEnabled",
                "vtp_configuration_file_name": "configurationFileName",
                "vtp_source_interface": "sourceInterface",
            },
        }

        # Use the generic mapping function
        return self._map_parameters(vtp_config, vtp_mapping_schema)

    def _map_dhcp_snooping_config(self, dhcp_snooping_config):
        """
        Maps DHCP Snooping configuration parameters from user format to API format.
        Args:
            dhcp_snooping_config (dict): The DHCP Snooping configuration provided by the user.
        Returns:
            dict: Mapped DHCP Snooping configuration in API-compatible format.
        """
        self.log(
            "Mapping DHCP Snooping configuration: {0}".format(dhcp_snooping_config),
            "DEBUG",
        )

        # Create a copy of the configuration to avoid modifying the original
        dhcp_config = dhcp_snooping_config.copy()

        # Extract database-related parameters for separate handling
        database_params = {}
        db_params_keys = [
            "dhcp_snooping_database_agent_url",
            "dhcp_snooping_database_timeout",
            "dhcp_snooping_database_write_delay",
        ]

        for key in db_params_keys:
            if key in dhcp_config:
                # Remove from main config and add to database params
                database_params[key] = dhcp_config.pop(key)

        self.log(
            "Extracted {0} database parameters for separate processing".format(
                len(database_params)
            ),
            "DEBUG",
        )

        # Handle lists for VLANs - convert to comma-separated strings
        vlan_params = ["dhcp_snooping_vlans", "dhcp_snooping_proxy_bridge_vlans"]
        for param in vlan_params:
            if param in dhcp_config and isinstance(dhcp_config[param], list):
                # Convert list of integers to simple comma-separated string
                dhcp_config[param] = ",".join(map(str, dhcp_config[param]))
                self.log(
                    "Converted VLAN parameter '{0}' from list to comma-separated string".format(
                        param
                    ),
                    "DEBUG",
                )

        # Define the mapping schema for the main DHCP Snooping config
        dhcp_mapping_schema = {
            "output_structure": {},
            "item_config_type": "DHCP_SNOOPING_GLOBAL",
            "param_path": ["dhcpSnoopingGlobalConfig", "items"],
            "param_mapping": {
                "dhcp_admin_status": "isDhcpSnoopingEnabled",
                "dhcp_snooping_glean": "isGleaningEnabled",
                "dhcp_snooping_proxy_bridge_vlans": "proxyBridgeVlans",
                "dhcp_snooping_vlans": "dhcpSnoopingVlans",
            },
        }

        # Use the generic mapping function for the main DHCP Snooping config
        mapped_config = self._map_parameters(dhcp_config, dhcp_mapping_schema)

        self.log("Main DHCP Snooping configuration mapped successfully", "DEBUG")

        # Add the database agent configuration if any database parameters were provided
        if database_params:
            self.log(
                "Processing database agent configuration with {0} parameters".format(
                    len(database_params)
                ),
                "DEBUG",
            )

            # Create the database agent mapping schema
            db_mapping_schema = {
                "output_structure": {"configType": "DHCP_SNOOPING_DATABASE_AGENT"},
                "param_mapping": {
                    "dhcp_snooping_database_agent_url": "agentUrl",
                    "dhcp_snooping_database_timeout": "timeout",
                    "dhcp_snooping_database_write_delay": "writeDelay",
                },
            }

            # Map the database parameters
            mapped_db_config = self._map_parameters(database_params, db_mapping_schema)

            # Add the mapped database config to the main config
            if (
                mapped_config
                and "dhcpSnoopingGlobalConfig" in mapped_config
                and "items" in mapped_config["dhcpSnoopingGlobalConfig"]
            ):
                mapped_config["dhcpSnoopingGlobalConfig"]["items"][0][
                    "databaseAgent"
                ] = mapped_db_config
                self.log(
                    "Database agent configuration added to main DHCP Snooping config",
                    "DEBUG",
                )
        else:
            self.log(
                "No database parameters found, skipping database agent configuration",
                "DEBUG",
            )

        self.log("DHCP Snooping configuration mapping completed successfully", "INFO")
        self.log(
            "Final mapped DHCP Snooping configuration: {0}".format(mapped_config),
            "DEBUG",
        )

        return mapped_config

    def _map_igmp_snooping_config(self, igmp_snooping_config):
        """
        Maps IGMP Snooping configuration parameters from user format to API format.
        Args:
            igmp_snooping_config (dict): The IGMP Snooping configuration provided by the user.
        Returns:
            dict: Mapped IGMP Snooping configuration in API-compatible format.
        """
        self.log(
            "Mapping IGMP Snooping configuration: {0}".format(igmp_snooping_config),
            "DEBUG",
        )

        # Create a copy of the configuration to avoid modifying the original
        igmp_config = igmp_snooping_config.copy()

        # Extract VLAN-specific settings for separate handling if present
        # Using get() with empty list as default to handle the case when key doesn't exist
        igmp_snooping_vlans = igmp_config.pop("igmp_snooping_vlans", [])

        self.log(
            "Extracted {0} IGMP Snooping VLANs for separate processing".format(
                len(igmp_snooping_vlans)
            ),
            "DEBUG",
        )

        # Define the mapping schema for the main IGMP Snooping global config
        igmp_mapping_schema = {
            "output_structure": {},
            "item_config_type": "IGMP_SNOOPING_GLOBAL",
            "param_path": ["igmpSnoopingGlobalConfig", "items"],
            "param_mapping": {
                "enable_igmp_snooping": "isIgmpSnoopingEnabled",
                "igmp_snooping_querier": "isQuerierEnabled",
                "igmp_snooping_querier_address": "querierAddress",
                "igmp_snooping_querier_query_interval": "querierQueryInterval",
                "igmp_snooping_querier_version": "querierVersion",
            },
        }

        # Use the generic mapping function for the main IGMP Snooping global config
        mapped_config = self._map_parameters(igmp_config, igmp_mapping_schema)

        self.log("Main IGMP Snooping global configuration mapped successfully", "DEBUG")

        # Handle VLAN-specific IGMP Snooping settings if present
        if igmp_snooping_vlans:
            self.log(
                "Processing {0} IGMP Snooping VLANs for integration".format(
                    len(igmp_snooping_vlans)
                ),
                "DEBUG",
            )

            # Get the reference to the global config item to add VLAN settings
            if (
                mapped_config
                and "igmpSnoopingGlobalConfig" in mapped_config
                and "items" in mapped_config["igmpSnoopingGlobalConfig"]
            ):
                global_config_item = mapped_config["igmpSnoopingGlobalConfig"]["items"][
                    0
                ]

                # Create the VLAN settings container
                global_config_item["igmpSnoopingVlanSettings"] = {
                    "configType": "SET",
                    "items": [],
                }

                self.log(
                    "Created IGMP Snooping VLAN settings container structure", "DEBUG"
                )

                # Process each VLAN configuration
                for vlan_index, vlan_config in enumerate(igmp_snooping_vlans):
                    self.log(
                        "Processing IGMP Snooping VLAN configuration at index {0}".format(
                            vlan_index
                        ),
                        "DEBUG",
                    )

                    # Create a new VLAN config item
                    vlan_item = {
                        "configType": "IGMP_SNOOPING_VLAN",
                        "vlanId": vlan_config.get("igmp_snooping_vlan_id"),
                    }

                    # Map the standard VLAN parameters
                    vlan_param_mapping = {
                        "enable_igmp_snooping": "isIgmpSnoopingEnabled",
                        "igmp_snooping_immediate_leave": "isImmediateLeaveEnabled",
                        "igmp_snooping_querier": "isQuerierEnabled",
                        "igmp_snooping_querier_address": "querierAddress",
                        "igmp_snooping_querier_query_interval": "querierQueryInterval",
                        "igmp_snooping_querier_version": "querierVersion",
                    }

                    # Add each parameter that exists in the VLAN config
                    for user_param, api_param in vlan_param_mapping.items():
                        if user_param in vlan_config:
                            vlan_item[api_param] = vlan_config.get(user_param)
                            self.log(
                                "Mapped VLAN parameter '{0}' to '{1}' with value: {2}".format(
                                    user_param, api_param, vlan_config.get(user_param)
                                ),
                                "DEBUG",
                            )

                    # Handle mrouter port list if present
                    mrouter_ports = vlan_config.get(
                        "igmp_snooping_mrouter_port_list", []
                    )
                    if mrouter_ports:
                        self.log(
                            "Processing {0} mrouter ports for VLAN {1}".format(
                                len(mrouter_ports),
                                vlan_config.get("igmp_snooping_vlan_id"),
                            ),
                            "DEBUG",
                        )

                        # Create the mrouters container
                        vlan_item["igmpSnoopingVlanMrouters"] = {
                            "configType": "SET",
                            "items": [],
                        }

                        # Add each mrouter port to the list
                        for port_index, port in enumerate(mrouter_ports):
                            mrouter_item = {
                                "configType": "IGMP_SNOOPING_VLAN_MROUTER",
                                "interfaceName": port,
                            }
                            vlan_item["igmpSnoopingVlanMrouters"]["items"].append(
                                mrouter_item
                            )
                            self.log(
                                "Added mrouter port '{0}' at index {1} for VLAN {2}".format(
                                    port,
                                    port_index,
                                    vlan_config.get("igmp_snooping_vlan_id"),
                                ),
                                "DEBUG",
                            )
                    else:
                        self.log(
                            "No mrouter ports found for VLAN {0}".format(
                                vlan_config.get("igmp_snooping_vlan_id")
                            ),
                            "DEBUG",
                        )

                    # Add the VLAN config to the VLAN settings items list
                    global_config_item["igmpSnoopingVlanSettings"]["items"].append(
                        vlan_item
                    )
                    self.log(
                        "Successfully added IGMP Snooping VLAN {0} configuration to settings list".format(
                            vlan_config.get("igmp_snooping_vlan_id")
                        ),
                        "DEBUG",
                    )

                self.log(
                    "Completed processing all {0} IGMP Snooping VLANs".format(
                        len(igmp_snooping_vlans)
                    ),
                    "DEBUG",
                )
            else:
                self.log(
                    "Unable to add VLAN settings - global config structure not found",
                    "WARNING",
                )
        else:
            self.log("No IGMP Snooping VLANs found to process", "DEBUG")

        self.log("IGMP Snooping configuration mapping completed successfully", "INFO")
        self.log(
            "Final mapped IGMP Snooping configuration: {0}".format(mapped_config),
            "DEBUG",
        )

        return mapped_config

    def _map_mld_snooping_config(self, mld_snooping_config):
        """
        Maps MLD Snooping configuration parameters from user format to API format.
        Args:
            mld_snooping_config (dict): The MLD Snooping configuration provided by the user.
        Returns:
            dict: Mapped MLD Snooping configuration in API-compatible format.
        """
        self.log(
            "Mapping MLD Snooping configuration: {0}".format(mld_snooping_config),
            "DEBUG",
        )

        # Create a copy of the configuration to avoid modifying the original
        mld_config = mld_snooping_config.copy()

        # Extract VLAN-specific settings for separate handling if present
        # Using get() with empty list as default to handle the case when key doesn't exist
        mld_snooping_vlans = mld_config.pop("mld_snooping_vlans", [])

        self.log(
            "Extracted {0} MLD Snooping VLANs for separate processing".format(
                len(mld_snooping_vlans)
            ),
            "DEBUG",
        )

        # Define the mapping schema for the main MLD Snooping global config
        mld_mapping_schema = {
            "output_structure": {},
            "item_config_type": "MLD_SNOOPING_GLOBAL",
            "param_path": ["mldSnoopingGlobalConfig", "items"],
            "param_mapping": {
                "enable_mld_snooping": "isMldSnoopingEnabled",
                "mld_snooping_listener": "isSuppressListenerMessagesEnabled",
                "mld_snooping_querier": "isQuerierEnabled",
                "mld_snooping_querier_address": "querierAddress",
                "mld_snooping_querier_query_interval": "querierQueryInterval",
                "mld_snooping_querier_version": "querierVersion",
            },
        }

        # Use the generic mapping function for the main MLD Snooping global config
        mapped_config = self._map_parameters(mld_config, mld_mapping_schema)

        self.log("Main MLD Snooping global configuration mapped successfully", "DEBUG")

        # Handle VLAN-specific MLD Snooping settings if present
        if mld_snooping_vlans:
            self.log(
                "Processing {0} MLD Snooping VLANs for integration".format(
                    len(mld_snooping_vlans)
                ),
                "DEBUG",
            )

            # Get the reference to the global config item to add VLAN settings
            if (
                mapped_config
                and "mldSnoopingGlobalConfig" in mapped_config
                and "items" in mapped_config["mldSnoopingGlobalConfig"]
            ):
                global_config_item = mapped_config["mldSnoopingGlobalConfig"]["items"][
                    0
                ]

                # Create the VLAN settings container
                global_config_item["mldSnoopingVlanSettings"] = {
                    "configType": "SET",
                    "items": [],
                }

                self.log(
                    "Created MLD Snooping VLAN settings container structure", "DEBUG"
                )

                # Process each VLAN configuration
                for vlan_index, vlan_config in enumerate(mld_snooping_vlans):
                    self.log(
                        "Processing MLD Snooping VLAN configuration at index {0}".format(
                            vlan_index
                        ),
                        "DEBUG",
                    )

                    # Create a new VLAN config item
                    vlan_item = {
                        "configType": "MLD_SNOOPING_VLAN",
                        "vlanId": vlan_config.get("mld_snooping_vlan_id"),
                    }

                    # Map the standard VLAN parameters
                    vlan_param_mapping = {
                        "enable_mld_snooping": "isMldSnoopingEnabled",
                        "mld_snooping_enable_immediate_leave": "isImmediateLeaveEnabled",
                        "mld_snooping_querier": "isQuerierEnabled",
                        "mld_snooping_querier_address": "querierAddress",
                        "mld_snooping_querier_query_interval": "querierQueryInterval",
                        "mld_snooping_querier_version": "querierVersion",
                    }

                    # Add each parameter that exists in the VLAN config
                    for user_param, api_param in vlan_param_mapping.items():
                        if user_param in vlan_config:
                            vlan_item[api_param] = vlan_config.get(user_param)
                            self.log(
                                "Mapped VLAN parameter '{0}' to '{1}' with value: {2}".format(
                                    user_param, api_param, vlan_config.get(user_param)
                                ),
                                "DEBUG",
                            )

                    # Always include mldSnoopingVlanMrouters section to match API response format
                    # This ensures consistency with deployed configuration structure
                    mrouter_ports = vlan_config.get(
                        "mld_snooping_mrouter_port_list", []
                    )
                    vlan_item["mldSnoopingVlanMrouters"] = {
                        "configType": "SET",
                        "items": [],
                    }

                    # Add mrouter ports if they exist
                    for port_index, port in enumerate(mrouter_ports):
                        mrouter_item = {
                            "configType": "MLD_SNOOPING_VLAN_MROUTER",
                            "interfaceName": port,
                        }
                        vlan_item["mldSnoopingVlanMrouters"]["items"].append(
                            mrouter_item
                        )
                        self.log(
                            "Added mrouter port '{0}' at index {1} for VLAN {2}".format(
                                port,
                                port_index,
                                vlan_config.get("mld_snooping_vlan_id"),
                            ),
                            "DEBUG",
                        )

                    # Add the VLAN config to the VLAN settings items list
                    global_config_item["mldSnoopingVlanSettings"]["items"].append(
                        vlan_item
                    )
                    self.log(
                        "Successfully added MLD Snooping VLAN {0} configuration to settings list".format(
                            vlan_config.get("mld_snooping_vlan_id")
                        ),
                        "DEBUG",
                    )

                self.log(
                    "Completed processing all {0} MLD Snooping VLANs".format(
                        len(mld_snooping_vlans)
                    ),
                    "DEBUG",
                )
            else:
                self.log(
                    "Unable to add VLAN settings - global config structure not found",
                    "WARNING",
                )
        else:
            self.log("No MLD Snooping VLANs found to process", "DEBUG")

        self.log("MLD Snooping configuration mapping completed successfully", "INFO")
        self.log(
            "Final mapped MLD Snooping configuration: {0}".format(mapped_config),
            "DEBUG",
        )

        return mapped_config

    def _map_authentication_config(self, authentication_config):
        """
        Maps Authentication configuration parameters from user format to API format.
        Args:
            authentication_config (dict): The Authentication configuration provided by the user.
        Returns:
            dict: Mapped Authentication configuration in API-compatible format.
        """
        self.log(
            "Mapping Authentication configuration: {0}".format(authentication_config),
            "DEBUG",
        )

        # Define the mapping schema for Authentication
        auth_mapping_schema = {
            "output_structure": {},
            "item_config_type": "DOT1X_GLOBAL",
            "param_path": ["dot1xGlobalConfig", "items"],
            "param_mapping": {
                "enable_dot1x_authentication": "isDot1xEnabled",
                "authentication_config_mode": "authenticationConfigMode",
            },
        }

        # Use the generic mapping function
        return self._map_parameters(authentication_config, auth_mapping_schema)

    def _map_logical_ports_config(self, logical_ports_config):
        """
        Maps logical ports (port channel) configuration parameters from user format to API format.
        Args:
            logical_ports_config (dict): The logical ports configuration provided by the user.
        Returns:
            dict: Mapped logical ports configuration in API-compatible format.
        """
        self.log(
            "Mapping logical ports configuration: {0}".format(logical_ports_config),
            "DEBUG",
        )

        # Create a copy of the configuration to avoid modifying the original
        ports_config = logical_ports_config.copy()

        # Extract port channels for separate handling
        port_channels = ports_config.pop("port_channels", [])

        self.log(
            "Extracted {0} port channels for separate processing".format(
                len(port_channels)
            ),
            "DEBUG",
        )

        # Define the mapping schema for the main logical ports global config
        ports_mapping_schema = {
            "output_structure": {},
            "item_config_type": "PORTCHANNEL",
            "param_path": ["portchannelConfig", "items"],
            "param_mapping": {
                "port_channel_auto": "isAutoEnabled",
                "port_channel_load_balancing_method": "loadBalancingMethod",
                "port_channel_lacp_system_priority": "lacpSystemPriority",
            },
        }

        # Use the generic mapping function for the main logical ports global config
        mapped_config = self._map_parameters(ports_config, ports_mapping_schema)

        self.log("Main logical ports global configuration mapped successfully", "DEBUG")

        # Handle port channels if present
        if (
            port_channels
            and mapped_config
            and "portchannelConfig" in mapped_config
            and "items" in mapped_config["portchannelConfig"]
        ):
            self.log(
                "Processing {0} port channels for integration".format(
                    len(port_channels)
                ),
                "DEBUG",
            )

            global_config_item = mapped_config["portchannelConfig"]["items"][0]

            # Create the port channels container
            global_config_item["portchannels"] = {"configType": "SET", "items": []}

            self.log("Created port channels container structure", "DEBUG")

            # Process each port channel
            for channel_index, channel in enumerate(port_channels):
                self.log(
                    "Processing port channel at index {0}".format(channel_index),
                    "DEBUG",
                )

                protocol = channel.get("port_channel_protocol")

                # Skip if protocol is missing
                if not protocol:
                    self.log(
                        "Skipping port channel without protocol: {0}".format(channel),
                        "WARNING",
                    )
                    continue

                self.log(
                    "Processing port channel with protocol: {0}".format(protocol),
                    "DEBUG",
                )

                # Create the appropriate config type based on protocol
                if protocol == "LACP":
                    self.log("Creating LACP port channel configuration", "DEBUG")
                    channel_item = {
                        "configType": "LACP_PORTCHANNEL_CONFIG",
                        "name": channel.get("port_channel_name"),
                    }

                    # Add min links if present
                    if "port_channel_min_links" in channel:
                        channel_item["minLinks"] = channel.get("port_channel_min_links")
                        self.log(
                            "Added min links parameter: {0}".format(
                                channel.get("port_channel_min_links")
                            ),
                            "DEBUG",
                        )

                    # Handle member ports
                    member_ports = channel.get("port_channel_members", [])
                    if member_ports:
                        self.log(
                            "Processing {0} LACP member ports".format(
                                len(member_ports)
                            ),
                            "DEBUG",
                        )
                        channel_item["memberPorts"] = {"configType": "SET", "items": []}

                        for member_index, member in enumerate(member_ports):
                            self.log(
                                "Processing LACP member port at index {0}".format(
                                    member_index
                                ),
                                "DEBUG",
                            )
                            member_item = {
                                "configType": "LACP_PORTCHANNEL_MEMBER_PORT_CONFIG",
                                "interfaceName": member.get(
                                    "port_channel_interface_name"
                                ),
                            }

                            # Map optional member parameters
                            if "port_channel_mode" in member:
                                member_item["mode"] = member.get("port_channel_mode")
                                self.log(
                                    "Added LACP mode parameter: {0}".format(
                                        member.get("port_channel_mode")
                                    ),
                                    "DEBUG",
                                )
                            if "port_channel_port_priority" in member:
                                member_item["portPriority"] = member.get(
                                    "port_channel_port_priority"
                                )
                                self.log(
                                    "Added LACP port priority: {0}".format(
                                        member.get("port_channel_port_priority")
                                    ),
                                    "DEBUG",
                                )
                            if "port_channel_rate" in member:
                                member_item["rate"] = member.get("port_channel_rate")
                                self.log(
                                    "Added LACP rate parameter: {0}".format(
                                        member.get("port_channel_rate")
                                    ),
                                    "DEBUG",
                                )

                            channel_item["memberPorts"]["items"].append(member_item)

                elif protocol == "PAGP":
                    self.log("Creating PAGP port channel configuration", "DEBUG")
                    channel_item = {
                        "configType": "PAGP_PORTCHANNEL_CONFIG",
                        "name": channel.get("port_channel_name"),
                    }

                    # Add min links if present
                    if "port_channel_min_links" in channel:
                        channel_item["minLinks"] = channel.get("port_channel_min_links")
                        self.log(
                            "Added min links parameter: {0}".format(
                                channel.get("port_channel_min_links")
                            ),
                            "DEBUG",
                        )

                    # Handle member ports
                    member_ports = channel.get("port_channel_members", [])
                    if member_ports:
                        self.log(
                            "Processing {0} PAGP member ports".format(
                                len(member_ports)
                            ),
                            "DEBUG",
                        )
                        channel_item["memberPorts"] = {"configType": "SET", "items": []}

                        for member_index, member in enumerate(member_ports):
                            self.log(
                                "Processing PAGP member port at index {0}".format(
                                    member_index
                                ),
                                "DEBUG",
                            )
                            member_item = {
                                "configType": "PAGP_PORTCHANNEL_MEMBER_PORT_CONFIG",
                                "interfaceName": member.get(
                                    "port_channel_interface_name"
                                ),
                            }

                            # Map optional member parameters
                            if "port_channel_mode" in member:
                                member_item["mode"] = member.get("port_channel_mode")
                                self.log(
                                    "Added PAGP mode parameter: {0}".format(
                                        member.get("port_channel_mode")
                                    ),
                                    "DEBUG",
                                )
                            if "port_channel_port_priority" in member:
                                member_item["portPriority"] = member.get(
                                    "port_channel_port_priority"
                                )
                                self.log(
                                    "Added PAGP port priority: {0}".format(
                                        member.get("port_channel_port_priority")
                                    ),
                                    "DEBUG",
                                )
                            if "port_channel_learn_method" in member:
                                member_item["learnMethod"] = member.get(
                                    "port_channel_learn_method"
                                )
                                self.log(
                                    "Added PAGP learn method: {0}".format(
                                        member.get("port_channel_learn_method")
                                    ),
                                    "DEBUG",
                                )

                            channel_item["memberPorts"]["items"].append(member_item)

                elif protocol == "NONE":
                    self.log(
                        "Creating EtherChannel configuration for static aggregation",
                        "DEBUG",
                    )
                    channel_item = {
                        "configType": "ETHERCHANNEL_CONFIG",
                        "name": channel.get("port_channel_name"),
                    }

                    # Add min links if present
                    if "port_channel_min_links" in channel:
                        channel_item["minLinks"] = channel.get("port_channel_min_links")
                        self.log(
                            "Added min links parameter: {0}".format(
                                channel.get("port_channel_min_links")
                            ),
                            "DEBUG",
                        )

                    # Handle member ports
                    member_ports = channel.get("port_channel_members", [])
                    if member_ports:
                        self.log(
                            "Processing {0} EtherChannel member ports".format(
                                len(member_ports)
                            ),
                            "DEBUG",
                        )
                        channel_item["memberPorts"] = {"configType": "SET", "items": []}

                        for member_index, member in enumerate(member_ports):
                            self.log(
                                "Processing EtherChannel member port at index {0}".format(
                                    member_index
                                ),
                                "DEBUG",
                            )
                            member_item = {
                                "configType": "ETHERCHANNEL_MEMBER_PORT_CONFIG",
                                "interfaceName": member.get(
                                    "port_channel_interface_name"
                                ),
                            }

                            # Map optional member parameters
                            if "port_channel_mode" in member:
                                member_item["mode"] = member.get("port_channel_mode")
                                self.log(
                                    "Added EtherChannel mode parameter: {0}".format(
                                        member.get("port_channel_mode")
                                    ),
                                    "DEBUG",
                                )

                            channel_item["memberPorts"]["items"].append(member_item)

                else:
                    self.log(
                        "Unsupported port channel protocol: {0}".format(protocol),
                        "WARNING",
                    )
                    continue

                # Add the port channel item directly to the items list
                global_config_item["portchannels"]["items"].append(channel_item)
                self.log(
                    "Successfully added port channel '{0}' with protocol {1}".format(
                        channel.get("port_channel_name"), protocol
                    ),
                    "DEBUG",
                )

            self.log(
                "Completed processing all {0} port channels".format(len(port_channels)),
                "DEBUG",
            )
        else:
            self.log(
                "No port channels found to process or configuration structure incomplete",
                "DEBUG",
            )

        if mapped_config and "portchannelConfig" in mapped_config:
            self.log(
                "Returning portchannelConfig structure for SDK 'payload' parameter",
                "DEBUG",
            )
            self.log("Final mapped config: {0}".format(mapped_config), "DEBUG")

        self.log("Logical ports configuration mapping completed successfully", "INFO")

        return mapped_config

    def _convert_vlan_list_to_string(self, vlan_list):
        """
        Converts a list of VLAN IDs to a simple comma-separated string.
        Args:
            vlan_list (list): List of VLAN IDs
        Returns:
            str: Comma-separated string of VLAN IDs
        """
        self.log("Starting VLAN list to string conversion", "DEBUG")
        self.log("Input VLAN list: {0}".format(vlan_list), "DEBUG")

        # Check if the VLAN list is empty or None
        if not vlan_list:
            self.log(
                "Empty or None VLAN list provided, returning empty string", "DEBUG"
            )
            return ""

        # Convert each VLAN ID to string and join with commas
        result = ",".join(map(str, vlan_list))

        self.log("VLAN list conversion completed successfully", "DEBUG")
        self.log("Converted VLAN list to string: {0}".format(result), "DEBUG")

        return result

    def _process_switchport_interface_config(
        self, mapped_config, interface_name, switchport_config
    ):
        """
        Processes switchport interface configuration for a specific interface.
        Args:
            mapped_config (dict): The configuration being built
            interface_name (str): The name of the interface
            switchport_config (dict): The switchport configuration for this interface
        """
        if not switchport_config:
            return

        self.log(
            "Processing switchport configuration for {0}: {1}".format(
                interface_name, switchport_config
            ),
            "DEBUG",
        )

        # Initialize the switchport interface config section if it doesn't exist
        if "switchportInterfaceConfig" not in mapped_config:
            mapped_config["switchportInterfaceConfig"] = {"items": []}
            self.log(
                "Initialized switchportInterfaceConfig section in mapped configuration",
                "DEBUG",
            )

        # Create the new item for this interface
        switchport_item = {
            "configType": "SWITCHPORT_INTERFACE",
            "interfaceName": interface_name,
        }
        self.log(
            "Created switchport item structure for interface {0}".format(
                interface_name
            ),
            "DEBUG",
        )

        # Map the parameters
        param_mapping = {
            "switchport_description": "description",
            "switchport_mode": "mode",
            "access_vlan": "accessVlan",
            "voice_vlan": "voiceVlan",
            "native_vlan_id": "nativeVlan",
        }

        # Apply standard parameter mappings
        for user_param, api_param in param_mapping.items():
            if user_param in switchport_config:
                switchport_item[api_param] = switchport_config[user_param]
                self.log(
                    "Mapped parameter {0} to {1} with value {2}".format(
                        user_param, api_param, switchport_config[user_param]
                    ),
                    "DEBUG",
                )

        # Special handling for admin_status (bool to enum)
        if "admin_status" in switchport_config:
            switchport_item["adminStatus"] = (
                "UP" if switchport_config["admin_status"] else "DOWN"
            )
            self.log(
                "Applied admin status transformation: {0} -> {1}".format(
                    switchport_config["admin_status"], switchport_item["adminStatus"]
                ),
                "DEBUG",
            )

        # Special handling for allowed_vlans (list to string)
        if "allowed_vlans" in switchport_config and isinstance(
            switchport_config["allowed_vlans"], list
        ):
            # Convert list of integers to simple comma-separated string or ranges
            allowed_vlans = switchport_config["allowed_vlans"]
            if allowed_vlans:
                switchport_item["trunkAllowedVlans"] = (
                    self._convert_vlan_list_to_string(allowed_vlans)
                )
                self.log(
                    "Converted allowed VLANs list to string: {0}".format(
                        switchport_item["trunkAllowedVlans"]
                    ),
                    "DEBUG",
                )

        # Add the item to the items list
        mapped_config["switchportInterfaceConfig"]["items"].append(switchport_item)
        self.log(
            "Successfully added switchport configuration for interface {0} to mapped config".format(
                interface_name
            ),
            "DEBUG",
        )

    def _process_vlan_trunking_interface_config(
        self, mapped_config, interface_name, trunk_config
    ):
        """
        Processes VLAN trunking interface configuration for a specific interface.
        Args:
            mapped_config (dict): The configuration being built
            interface_name (str): The name of the interface
            trunk_config (dict): The VLAN trunking configuration for this interface
        """
        if not trunk_config:
            return

        self.log(
            "Processing VLAN trunking configuration for {0}: {1}".format(
                interface_name, trunk_config
            ),
            "DEBUG",
        )

        # Initialize the trunk interface config section if it doesn't exist
        if "trunkInterfaceConfig" not in mapped_config:
            mapped_config["trunkInterfaceConfig"] = {"items": []}
            self.log(
                "Initialized trunkInterfaceConfig section in mapped configuration",
                "DEBUG",
            )

        # Create the new item for this interface
        trunk_item = {"configType": "TRUNK_INTERFACE", "interfaceName": interface_name}
        self.log(
            "Created trunk item structure for interface {0}".format(interface_name),
            "DEBUG",
        )

        # Map the protected parameter
        if "protected" in trunk_config:
            trunk_item["isProtected"] = trunk_config["protected"]
            self.log(
                "Mapped protected parameter: {0}".format(trunk_config["protected"]),
                "DEBUG",
            )

        # Updated logic for enable_dtp_negotiation (boolean parameter)
        if "enable_dtp_negotiation" in trunk_config:
            trunk_item["isDtpNegotiationEnabled"] = trunk_config[
                "enable_dtp_negotiation"
            ]
            self.log(
                "Mapped DTP negotiation parameter: {0}".format(
                    trunk_config["enable_dtp_negotiation"]
                ),
                "DEBUG",
            )

        # Handle pruning VLAN IDs
        if "pruning_vlan_ids" in trunk_config and isinstance(
            trunk_config["pruning_vlan_ids"], list
        ):
            pruning_vlans = trunk_config["pruning_vlan_ids"]
            if pruning_vlans:
                trunk_item["pruneEligibleVlans"] = self._convert_vlan_list_to_string(
                    pruning_vlans
                )
                self.log(
                    "Converted pruning VLAN IDs list to string: {0}".format(
                        trunk_item["pruneEligibleVlans"]
                    ),
                    "DEBUG",
                )
            else:
                self.log(
                    "Empty pruning VLAN IDs list found, skipping conversion", "DEBUG"
                )

        # Add the item to the items list
        mapped_config["trunkInterfaceConfig"]["items"].append(trunk_item)
        self.log(
            "Successfully added VLAN trunking configuration for interface {0} to mapped config".format(
                interface_name
            ),
            "DEBUG",
        )

    def _process_dot1x_interface_config(
        self, mapped_config, interface_name, dot1x_config
    ):
        """
        Processes 802.1x interface configuration for a specific interface.
        Args:
            mapped_config (dict): The configuration being built
            interface_name (str): The name of the interface
            dot1x_config (dict): The 802.1x configuration for this interface
        """
        if not dot1x_config:
            return

        self.log(
            "Processing 802.1x configuration for {0}: {1}".format(
                interface_name, dot1x_config
            ),
            "DEBUG",
        )

        # Initialize the dot1x interface config section if it doesn't exist
        if "dot1xInterfaceConfig" not in mapped_config:
            mapped_config["dot1xInterfaceConfig"] = {"items": []}
            self.log(
                "Initialized dot1xInterfaceConfig section in mapped configuration",
                "DEBUG",
            )

        # Create the new item for this interface
        dot1x_item = {"configType": "DOT1X_INTERFACE", "interfaceName": interface_name}
        self.log(
            "Created dot1x item structure for interface {0}".format(interface_name),
            "DEBUG",
        )

        # Map basic parameters
        basic_param_mapping = {
            "dot1x_interface_authentication_mode": "authenticationMode",
            "dot1x_interface_pae_type": "paeType",
            "dot1x_interface_control_direction": "controlDirection",
            "dot1x_interface_host_mode": "hostMode",
            "dot1x_interface_inactivity_timer": "inactivityTimer",
            "dot1x_interface_reauthentication": "isReauthEnabled",
            "dot1x_interface_port_control": "portControl",
            "dot1x_interface_max_reauth_requests": "maxReauthRequests",
            "dot1x_interface_reauth_timer": "reauthTimer",
            "dot1x_interface_tx_period": "txPeriod",
        }

        # Apply basic parameter mappings
        for user_param, api_param in basic_param_mapping.items():
            if user_param in dot1x_config:
                dot1x_item[api_param] = dot1x_config[user_param]
                self.log(
                    "Mapped basic parameter '{0}' to '{1}' with value: {2}".format(
                        user_param, api_param, dot1x_config[user_param]
                    ),
                    "DEBUG",
                )

        # Map boolean parameters with different naming
        boolean_param_mapping = {
            "dot1x_interface_inactivity_timer_from_server": "isInactivityTimerFromServerEnabled",
            "dot1x_interface_reauth_timer_from_server": "isReauthTimerFromServerEnabled",
        }

        for user_param, api_param in boolean_param_mapping.items():
            if user_param in dot1x_config:
                dot1x_item[api_param] = dot1x_config[user_param]
                self.log(
                    "Mapped boolean parameter '{0}' to '{1}' with value: {2}".format(
                        user_param, api_param, dot1x_config[user_param]
                    ),
                    "DEBUG",
                )

        # Handle authentication order (list parameter)
        if "dot1x_interface_authentication_order" in dot1x_config:
            auth_order = dot1x_config["dot1x_interface_authentication_order"]
            if auth_order:  # Only add if not empty
                dot1x_item["authenticationOrder"] = {
                    "configType": "ORDERED_SET",
                    "items": auth_order,
                }
                self.log(
                    "Added authentication order with {0} items: {1}".format(
                        len(auth_order), auth_order
                    ),
                    "DEBUG",
                )
            else:
                self.log("Skipping empty authentication order list", "DEBUG")

        # Handle priority (list parameter)
        if "dot1x_interface_priority" in dot1x_config:
            priority_order = dot1x_config["dot1x_interface_priority"]
            if priority_order:  # Only add if not empty
                dot1x_item["priority"] = {
                    "configType": "ORDERED_SET",
                    "items": priority_order,
                }
                self.log(
                    "Added priority order with {0} items: {1}".format(
                        len(priority_order), priority_order
                    ),
                    "DEBUG",
                )
            else:
                self.log("Skipping empty priority order list", "DEBUG")

        # Add the item to the items list
        mapped_config["dot1xInterfaceConfig"]["items"].append(dot1x_item)
        self.log(
            "Successfully added 802.1x configuration for interface {0} to mapped config".format(
                interface_name
            ),
            "DEBUG",
        )

    def _process_mab_interface_config(self, mapped_config, interface_name, mab_config):
        """
        Processes MAB interface configuration for a specific interface.
        Args:
            mapped_config (dict): The configuration being built
            interface_name (str): The name of the interface
            mab_config (dict): The MAB configuration for this interface
        """
        if not mab_config:
            return

        self.log(
            "Processing MAB configuration for {0}: {1}".format(
                interface_name, mab_config
            ),
            "DEBUG",
        )

        # Initialize the mab interface config section if it doesn't exist
        if "mabInterfaceConfig" not in mapped_config:
            mapped_config["mabInterfaceConfig"] = {"items": []}
            self.log(
                "Initialized mabInterfaceConfig section in mapped configuration",
                "DEBUG",
            )

        # Create the new item for this interface
        mab_item = {"configType": "MAB_INTERFACE", "interfaceName": interface_name}
        self.log(
            "Created MAB item structure for interface {0}".format(interface_name),
            "DEBUG",
        )

        # Map the parameters
        if "enable_mab" in mab_config:
            mab_item["isMabEnabled"] = mab_config["enable_mab"]
            self.log(
                "Mapped enable_mab parameter to isMabEnabled with value: {0}".format(
                    mab_config["enable_mab"]
                ),
                "DEBUG",
            )

        # Add the item to the items list
        mapped_config["mabInterfaceConfig"]["items"].append(mab_item)
        self.log(
            "Successfully added MAB configuration for interface {0} to mapped config".format(
                interface_name
            ),
            "DEBUG",
        )

    def _process_stp_interface_config(self, mapped_config, interface_name, stp_config):
        """
        Processes STP interface configuration for a specific interface.
        Args:
            mapped_config (dict): The configuration being built
            interface_name (str): The name of the interface
            stp_config (dict): The STP configuration for this interface
        """
        if not stp_config:
            return

        self.log(
            "Processing STP configuration for {0}: {1}".format(
                interface_name, stp_config
            ),
            "DEBUG",
        )

        # Initialize the STP interface config section if it doesn't exist
        if "stpInterfaceConfig" not in mapped_config:
            mapped_config["stpInterfaceConfig"] = {"items": []}
            self.log(
                "Initialized stpInterfaceConfig section in mapped configuration",
                "DEBUG",
            )

        # Create the new item for this interface
        stp_item = {"configType": "STP_INTERFACE", "interfaceName": interface_name}
        self.log(
            "Created STP item structure for interface {0}".format(interface_name),
            "DEBUG",
        )

        # Map the basic parameters
        param_mapping = {
            "stp_interface_portfast_mode": "portFastMode",
            "stp_interface_guard": "guardMode",
            "stp_interface_cost": "pathCost",
            "stp_interface_priority": "priority",
        }

        # Apply standard parameter mappings
        for user_param, api_param in param_mapping.items():
            if user_param in stp_config:
                stp_item[api_param] = stp_config[user_param]
                self.log(
                    "Mapped parameter {0} to {1} with value {2}".format(
                        user_param, api_param, stp_config[user_param]
                    ),
                    "DEBUG",
                )

        # Special handling for boolean to string enum conversions
        if "stp_interface_bpdu_filter" in stp_config:
            stp_item["bpduFilter"] = (
                "ENABLE" if stp_config["stp_interface_bpdu_filter"] else "DISABLE"
            )
            self.log(
                "Applied BPDU filter transformation: {0} -> {1}".format(
                    stp_config["stp_interface_bpdu_filter"], stp_item["bpduFilter"]
                ),
                "DEBUG",
            )

        if "stp_interface_bpdu_guard" in stp_config:
            stp_item["bpduGuard"] = (
                "ENABLE" if stp_config["stp_interface_bpdu_guard"] else "DISABLE"
            )
            self.log(
                "Applied BPDU guard transformation: {0} -> {1}".format(
                    stp_config["stp_interface_bpdu_guard"], stp_item["bpduGuard"]
                ),
                "DEBUG",
            )

        # Handle per-VLAN cost settings
        per_vlan_cost = stp_config.get("stp_interface_per_vlan_cost")
        if (
            per_vlan_cost
            and "priority" in per_vlan_cost
            and "vlan_ids" in per_vlan_cost
        ):
            stp_item["portVlanCostSettings"] = {
                "configType": "LIST",
                "items": [
                    {
                        "configType": "STP_INTERFACE_VLAN_COST",
                        "cost": per_vlan_cost["priority"],
                        "vlans": self._convert_vlan_list_to_string(
                            per_vlan_cost["vlan_ids"]
                        ),
                    }
                ],
            }
            self.log(
                "Added per-VLAN cost settings with cost {0} for VLANs: {1}".format(
                    per_vlan_cost["priority"], per_vlan_cost["vlan_ids"]
                ),
                "DEBUG",
            )

        # Handle per-VLAN priority settings
        per_vlan_priority = stp_config.get("stp_interface_per_vlan_priority")
        if (
            per_vlan_priority
            and "priority" in per_vlan_priority
            and "vlan_ids" in per_vlan_priority
        ):
            stp_item["portVlanPrioritySettings"] = {
                "configType": "LIST",
                "items": [
                    {
                        "configType": "STP_INTERFACE_VLAN_PRIORITY",
                        "priority": per_vlan_priority["priority"],
                        "vlans": self._convert_vlan_list_to_string(
                            per_vlan_priority["vlan_ids"]
                        ),
                    }
                ],
            }
            self.log(
                "Added per-VLAN priority settings with priority {0} for VLANs: {1}".format(
                    per_vlan_priority["priority"], per_vlan_priority["vlan_ids"]
                ),
                "DEBUG",
            )

        # Add the item to the items list
        mapped_config["stpInterfaceConfig"]["items"].append(stp_item)
        self.log(
            "Successfully added STP configuration for interface {0} to mapped config".format(
                interface_name
            ),
            "DEBUG",
        )

    def _process_dhcp_snooping_interface_config(
        self, mapped_config, interface_name, dhcp_config
    ):
        """
        Processes DHCP Snooping interface configuration for a specific interface.
        Args:
            mapped_config (dict): The configuration being built
            interface_name (str): The name of the interface
            dhcp_config (dict): The DHCP Snooping configuration for this interface
        """
        if not dhcp_config:
            return

        self.log(
            "Processing DHCP Snooping configuration for {0}: {1}".format(
                interface_name, dhcp_config
            ),
            "DEBUG",
        )

        # Initialize the dhcp snooping interface config section if it doesn't exist
        if "dhcpSnoopingInterfaceConfig" not in mapped_config:
            mapped_config["dhcpSnoopingInterfaceConfig"] = {"items": []}
            self.log(
                "Initialized dhcpSnoopingInterfaceConfig section in mapped configuration",
                "DEBUG",
            )

        # Create the new item for this interface
        dhcp_item = {
            "configType": "DHCP_SNOOPING_INTERFACE",
            "interfaceName": interface_name,
        }
        self.log(
            "Created DHCP snooping item structure for interface {0}".format(
                interface_name
            ),
            "DEBUG",
        )

        # Map the parameters
        if "dhcp_snooping_interface_trust" in dhcp_config:
            dhcp_item["isTrustedInterface"] = dhcp_config[
                "dhcp_snooping_interface_trust"
            ]
            self.log(
                "Mapped dhcp_snooping_interface_trust parameter: {0}".format(
                    dhcp_config["dhcp_snooping_interface_trust"]
                ),
                "DEBUG",
            )

        if "dhcp_snooping_interface_rate" in dhcp_config:
            dhcp_item["messageRateLimit"] = dhcp_config["dhcp_snooping_interface_rate"]
            self.log(
                "Mapped dhcp_snooping_interface_rate parameter: {0}".format(
                    dhcp_config["dhcp_snooping_interface_rate"]
                ),
                "DEBUG",
            )

        # Add the item to the items list
        mapped_config["dhcpSnoopingInterfaceConfig"]["items"].append(dhcp_item)
        self.log(
            "Successfully added DHCP Snooping configuration for interface {0} to mapped config".format(
                interface_name
            ),
            "DEBUG",
        )

    def _process_cdp_interface_config(self, mapped_config, interface_name, cdp_config):
        """
        Processes CDP interface configuration for a specific interface.
        Args:
            mapped_config (dict): The configuration being built
            interface_name (str): The name of the interface
            cdp_config (dict): The CDP configuration for this interface
        """
        if not cdp_config:
            return

        self.log(
            "Processing CDP configuration for {0}: {1}".format(
                interface_name, cdp_config
            ),
            "DEBUG",
        )

        # Initialize the cdp interface config section if it doesn't exist
        if "cdpInterfaceConfig" not in mapped_config:
            mapped_config["cdpInterfaceConfig"] = {"items": []}
            self.log(
                "Initialized cdpInterfaceConfig section in mapped configuration",
                "DEBUG",
            )

        # Create the new item for this interface
        cdp_item = {"configType": "CDP_INTERFACE", "interfaceName": interface_name}
        self.log(
            "Created CDP item structure for interface {0}".format(interface_name),
            "DEBUG",
        )

        # Map the parameters
        if "cdp_interface_admin_status" in cdp_config:
            cdp_item["isCdpEnabled"] = cdp_config["cdp_interface_admin_status"]
            self.log(
                "Mapped cdp_interface_admin_status parameter: {0}".format(
                    cdp_config["cdp_interface_admin_status"]
                ),
                "DEBUG",
            )

        if "cdp_interface_log_duplex_mismatch" in cdp_config:
            cdp_item["isLogDuplexMismatchEnabled"] = cdp_config[
                "cdp_interface_log_duplex_mismatch"
            ]
            self.log(
                "Mapped cdp_interface_log_duplex_mismatch parameter: {0}".format(
                    cdp_config["cdp_interface_log_duplex_mismatch"]
                ),
                "DEBUG",
            )

        # Add the item to the items list
        mapped_config["cdpInterfaceConfig"]["items"].append(cdp_item)
        self.log(
            "Successfully added CDP configuration for interface {0} to mapped config".format(
                interface_name
            ),
            "DEBUG",
        )

    def _process_lldp_interface_config(
        self, mapped_config, interface_name, lldp_config
    ):
        """
        Processes LLDP interface configuration for a specific interface.
        Args:
            mapped_config (dict): The configuration being built
            interface_name (str): The name of the interface
            lldp_config (dict): The LLDP configuration for this interface
        """
        if not lldp_config:
            return

        self.log(
            "Processing LLDP configuration for {0}: {1}".format(
                interface_name, lldp_config
            ),
            "DEBUG",
        )

        # Initialize the lldp interface config section if it doesn't exist
        if "lldpInterfaceConfig" not in mapped_config:
            mapped_config["lldpInterfaceConfig"] = {"items": []}
            self.log(
                "Initialized lldpInterfaceConfig section in mapped configuration",
                "DEBUG",
            )

        # Create the new item for this interface
        lldp_item = {"configType": "LLDP_INTERFACE", "interfaceName": interface_name}
        self.log(
            "Created LLDP item structure for interface {0}".format(interface_name),
            "DEBUG",
        )

        # Map the parameters - specifically the receive/transmit status
        if "lldp_interface_receive_transmit" in lldp_config:
            lldp_item["adminStatus"] = lldp_config["lldp_interface_receive_transmit"]
            self.log(
                "Mapped lldp_interface_receive_transmit parameter: {0}".format(
                    lldp_config["lldp_interface_receive_transmit"]
                ),
                "DEBUG",
            )

        # Add the item to the items list
        mapped_config["lldpInterfaceConfig"]["items"].append(lldp_item)
        self.log(
            "Successfully added LLDP configuration for interface {0} to mapped config".format(
                interface_name
            ),
            "DEBUG",
        )

    def _process_vtp_interface_config(self, mapped_config, interface_name, vtp_config):
        """
        Processes VTP interface configuration for a specific interface.
        Args:
            mapped_config (dict): The configuration being built
            interface_name (str): The name of the interface
            vtp_config (dict): The VTP configuration for this interface
        """
        if not vtp_config:
            return

        self.log(
            "Processing VTP configuration for {0}: {1}".format(
                interface_name, vtp_config
            ),
            "DEBUG",
        )

        # Initialize the vtp interface config section if it doesn't exist
        if "vtpInterfaceConfig" not in mapped_config:
            mapped_config["vtpInterfaceConfig"] = {"items": []}
            self.log(
                "Initialized vtpInterfaceConfig section in mapped configuration",
                "DEBUG",
            )

        # Create the new item for this interface
        vtp_item = {"configType": "VTP_INTERFACE", "interfaceName": interface_name}
        self.log(
            "Created VTP item structure for interface {0}".format(interface_name),
            "DEBUG",
        )

        # Map the parameters
        if "vtp_interface_admin_status" in vtp_config:
            vtp_item["isVtpEnabled"] = vtp_config["vtp_interface_admin_status"]
            self.log(
                "Mapped vtp_interface_admin_status parameter: {0}".format(
                    vtp_config["vtp_interface_admin_status"]
                ),
                "DEBUG",
            )

        # Add the item to the items list
        mapped_config["vtpInterfaceConfig"]["items"].append(vtp_item)
        self.log(
            "Successfully added VTP configuration for interface {0} to mapped config".format(
                interface_name
            ),
            "DEBUG",
        )

    def _map_port_configuration(self, port_configurations):
        """
        Maps port configuration parameters from user format to API format.
        Args:
            port_configurations (list): A list of port configurations provided by the user.
        Returns:
            dict: Mapped port configuration in API-compatible format.
        """
        self.log("Mapping port configuration: {0}".format(port_configurations), "DEBUG")

        # Initialize the output structure for mapped configurations
        mapped_config = {}

        self.log(
            "Processing {0} port configurations for interface mapping".format(
                len(port_configurations)
            ),
            "DEBUG",
        )

        # Process each interface configuration sequentially
        for port_index, port_config in enumerate(port_configurations):
            self.log(
                "Processing port configuration at index {0}".format(port_index), "DEBUG"
            )

            interface_name = port_config.get("interface_name")

            if not interface_name:
                self.log(
                    "Skipping port configuration without interface_name", "WARNING"
                )
                continue

            self.log(
                "Processing interface configurations for: {0}".format(interface_name),
                "DEBUG",
            )

            # Process each feature configuration for this interface in the same order as temp_spec
            self._process_switchport_interface_config(
                mapped_config,
                interface_name,
                port_config.get("switchport_interface_config"),
            )

            self._process_vlan_trunking_interface_config(
                mapped_config,
                interface_name,
                port_config.get("vlan_trunking_interface_config"),
            )

            self._process_dot1x_interface_config(
                mapped_config, interface_name, port_config.get("dot1x_interface_config")
            )

            self._process_mab_interface_config(
                mapped_config, interface_name, port_config.get("mab_interface_config")
            )

            self._process_stp_interface_config(
                mapped_config, interface_name, port_config.get("stp_interface_config")
            )

            self._process_dhcp_snooping_interface_config(
                mapped_config,
                interface_name,
                port_config.get("dhcp_snooping_interface_config"),
            )

            self._process_cdp_interface_config(
                mapped_config, interface_name, port_config.get("cdp_interface_config")
            )

            self._process_lldp_interface_config(
                mapped_config, interface_name, port_config.get("lldp_interface_config")
            )

            self._process_vtp_interface_config(
                mapped_config, interface_name, port_config.get("vtp_interface_config")
            )

            self.log(
                "Completed processing all feature configurations for interface: {0}".format(
                    interface_name
                ),
                "DEBUG",
            )

        self.log("Port configuration mapping completed successfully", "INFO")
        self.log(
            "Final mapped configuration contains {0} feature sections".format(
                len(mapped_config)
            ),
            "DEBUG",
        )
        self.log("Mapped configuration structure: {0}".format(mapped_config), "DEBUG")

        return mapped_config

    def get_mapped_layer2_config_params(self, feature_name, config_data):
        """
        Maps user-provided configuration parameters to API-compatible format for a specific Layer 2 feature.
        Args:
            feature_name (str): The name of the Layer 2 feature (Example, "vlans", "cdp", "lldp").
            config_data (dict/list): The configuration data for the feature.
        Returns:
            dict: The mapped configuration parameters in API-compatible format.
        """
        self.log(
            "Mapping configuration parameters for feature '{0}'.".format(feature_name),
            "DEBUG",
        )

        # Feature-specific mapping functions
        feature_mappers = {
            "vlans": self._map_vlans_config,
            "cdp": self._map_cdp_config,
            "lldp": self._map_lldp_config,
            "stp": self._map_stp_config,
            "vtp": self._map_vtp_config,
            "dhcp_snooping": self._map_dhcp_snooping_config,
            "igmp_snooping": self._map_igmp_snooping_config,
            "mld_snooping": self._map_mld_snooping_config,
            "authentication": self._map_authentication_config,
            "logical_ports": self._map_logical_ports_config,
            "port_configuration": self._map_port_configuration,
        }

        # Get the appropriate mapper for this feature
        mapper = feature_mappers.get(feature_name)

        if mapper:
            self.log(
                "Found mapping function for feature '{0}', executing transformation".format(
                    feature_name
                ),
                "DEBUG",
            )

            # Call the specific mapper with the config data
            mapped_config = mapper(config_data)

            self.log(
                "Mapped configuration for '{0}': {1}".format(
                    feature_name, mapped_config
                ),
                "DEBUG",
            )

            self.log(
                "Configuration mapping completed successfully for feature '{0}'".format(
                    feature_name
                ),
                "INFO",
            )

            return mapped_config
        else:
            # This should never happen if our feature_mappers dictionary is complete
            self.msg = "No parameter mapper available for feature '{0}'.".format(
                feature_name
            )
            self.log(
                "Configuration mapping failed - no mapper found for feature '{0}'".format(
                    feature_name
                ),
                "ERROR",
            )
            self.fail_and_exit(self.msg)

    # def get_intended_layer2_feature_configuration(self, network_device_id, feature):
    #     """
    #     Retrieves the configurations for an intended layer 2 feature on a wired device.
    #     Args:
    #         device_id (str): Network device ID of the wired device.
    #         feature (str): Name of the layer 2 feature to retrieve (Example, 'vlan', 'cdp', 'stp').
    #     Returns:
    #         dict: The configuration details of the intended layer 2 feature.
    #     """
    #     self.log(
    #         "Retrieving intended configuration for layer 2 feature '{0}' on device {1}".format(
    #             feature, network_device_id
    #         ),
    #         "INFO",
    #     )
    #     # Prepare the API parameters
    #     api_params = {
    #         "id": network_device_id,
    #         "feature": feature
    #     }
    #     # Execute the API call to get the intended layer 2 feature configuration
    #     return self.execute_get_request(
    #         "wired", "get_configurations_for_an_intended_layer2_feature_on_a_wired_device", api_params
    #     )

    def get_intended_layer2_feature_configuration(self, network_device_id, feature):
        """
        Retrieves the configurations for an intended layer 2 feature on a wired device.
        """

        self.log(
            "Retrieving intended configuration for layer 2 feature '{0}' on device {1}".format(
                feature, network_device_id
            ),
            "INFO",
        )

        # Prepare the API parameters
        api_parameters = {"id": network_device_id, "feature": feature}

        try:
            # Execute the API call to get the intended layer 2 feature configuration
            api_function = (
                "get_configurations_for_an_intended_layer2_feature_on_a_wired_device"
            )
            api_family = "wired"

            response = self.dnac._exec(
                family=api_family,
                function=api_function,
                op_modifies=False,
                params=api_parameters,
            )

            self.log(
                "Response received from GET API call to Function: '{0}' from Family: '{1}' is Response: {2}".format(
                    api_function, api_family, str(response)
                ),
                "INFO",
            )

            # Check if the response is None, an empty string, or an empty dictionary
            if (
                response is None
                or response == ""
                or (isinstance(response, dict) and not response)
            ):
                self.log(
                    "No response received from GET API call to Function: '{0}' from Family: '{1}'.".format(
                        api_function, api_family
                    ),
                    "WARNING",
                )
                return {}

            return response

        except Exception as e:
            error_str = str(e)
            self.log(
                "Error retrieving intended configuration for feature '{0}': {1}".format(
                    feature, error_str
                ),
                "DEBUG",
            )

            # Check if this is a 404 error (resource not found) or the SDK's TypeError bug
            if (
                "404" in error_str
                or "Not Found" in error_str
                or "argument of type 'NoneType' is not iterable" in error_str
            ):
                self.log(
                    "No intended configuration exists for feature '{0}' - this is normal for features that haven't been configured yet".format(
                        feature
                    ),
                    "INFO",
                )
                # Return empty dict for 404 errors and SDK TypeError bug
                return {}

            # For other errors, log as WARNING but don't fail the entire operation
            self.log_traceback()
            self.msg = (
                "An error occurred while executing GET API call to Function: '{0}' from Family: '{1}'. "
                "Parameters: {2}. Exception: {3}.".format(
                    api_function, api_family, api_parameters, str(e)
                )
            )
            self.fail_and_exit(self.msg)

    def get_deployed_layer2_feature_configuration(self, network_device_id, feature):
        """
        Retrieves the configurations for a deployed layer 2 feature on a wired device.
        Args:
            device_id (str): Network device ID of the wired device.
            feature (str): Name of the layer 2 feature to retrieve (Example, 'vlan', 'cdp', 'stp').
        Returns:
            dict: The configuration details of the deployed layer 2 feature.
        """
        self.log(
            "Retrieving deployed configuration for layer 2 feature '{0}' on device {1}".format(
                feature, network_device_id
            ),
            "INFO",
        )
        # Prepare the API parameters
        api_params = {"id": network_device_id, "feature": feature}
        # Execute the API call to get the deployed layer 2 feature configuration
        return self.execute_get_request(
            "wired",
            "get_configurations_for_a_deployed_layer2_feature_on_a_wired_device",
            api_params,
        )

    def create_layer2_feature_configuration(
        self, network_device_id, feature, config_params
    ):
        """
        Creates configurations for an intended layer 2 feature on a wired device.
        Args:
            device_id (str): Network device ID of the wired device to configure.
            feature (str): Name of the layer 2 feature to configure (Example, 'vlan', 'cdp', 'stp').
            config_params (dict): A dictionary containing the configuration parameters for the feature.
                The keys should match the expected parameter names for the feature.
        Returns:
            dict: The response containing the task ID for the create operation.
        """
        self.log(
            "Initiating creation of layer 2 feature '{0}' on device {1} with parameters: {2}".format(
                feature, network_device_id, config_params
            ),
            "INFO",
        )
        # Prepare the API parameters
        api_params = {
            "id": network_device_id,
            "feature": feature,
            "active_validation": False,
            "payload": config_params,
        }
        # Add configuration parameters to the API parameters
        api_params.update(config_params)

        self.log(
            "Final API parameters for create intent operation: {0}".format(api_params),
            "DEBUG",
        )

        # Execute the API call to create the layer 2 feature configuration and return the task ID
        return self.get_taskid_post_api_call(
            "wired",
            "create_configurations_for_an_intended_layer2_feature_on_a_wired_device",
            api_params,
        )

    def update_layer2_feature_configuration(
        self, network_device_id, feature, config_params
    ):
        """
        Updates configurations for an intended layer 2 feature on a wired device.
        Args:
            device_id (str): Network device ID of the wired device to configure.
            feature (str): Name of the layer 2 feature to update (Example, 'vlan', 'cdp', 'stp').
            config_params (dict): A dictionary containing the updated configuration parameters for the feature.
                The keys should match the expected parameter names for the feature.
        Returns:
            dict: The response containing the task ID for the update operation.
        """
        self.log(
            "Initiating update of layer 2 feature '{0}' on device {1} with parameters: {2}".format(
                feature, network_device_id, config_params
            ),
            "INFO",
        )
        # Prepare the API parameters
        api_params = {
            "id": network_device_id,
            "feature": feature,
            "active_validation": False,
            "payload": config_params,
        }
        # Add configuration parameters to the API parameters
        api_params.update(config_params)

        self.log(
            "Final API parameters for udpate intent operation: {0}".format(api_params),
            "DEBUG",
        )

        # Execute the API call to update the layer 2 feature configuration and return the task ID
        return self.get_taskid_post_api_call(
            "wired",
            "update_configurations_for_an_intended_layer2_feature_on_a_wired_device",
            api_params,
        )

    def delete_layer2_feature_configuration(self, network_device_id, feature):
        """
        Deletes configurations for an intended layer 2 feature on a wired device.
        Args:
            device_id (str): Network device ID of the wired device to configure.
            feature (str): Name of the layer 2 feature to delete (Example, 'vlan', 'cdp', 'stp').
        Returns:
            dict: The response containing the task ID for the delete operation.
        """
        self.log(
            "Initiating deletion of layer 2 feature '{0}' on device {1}".format(
                feature, network_device_id
            ),
            "INFO",
        )
        # Prepare the API parameters
        api_params = {"id": network_device_id, "feature": feature}
        # Execute the API call to delete the layer 2 feature configuration and return the task ID
        return self.get_taskid_post_api_call(
            "wired",
            "delete_configurations_for_an_intended_layer2_feature_on_a_wired_device",
            api_params,
        )

    def deploy_intended_configurations(self, network_device_id):
        """
        Deploys the intended configuration features on a wired device.
        Args:
            device_id (str): Network device ID of the wired device to provision.
        Returns:
            dict: The response containing the task ID for the deployment operation.
        """
        self.log(
            "Initiating deployment of intended configurations on device {0}".format(
                network_device_id
            ),
            "INFO",
        )
        # Prepare the API parameters
        api_params = {"network_device_id": network_device_id}
        # Execute the API call to deploy the intended configurations and return the task ID
        return self.get_taskid_post_api_call(
            "wired",
            "deploy_the_intended_configuration_features_on_a_wired_device",
            api_params,
        )

    def get_current_configs_for_features(self, network_device_id, features):
        """
        Fetch current deployed and intended configs for specified features.
        Args:
            network_device_id (str): Network device ID to fetch configurations from
            features (list): List of API feature names to fetch
        Returns:
            tuple: (deployed_configs, intended_configs) dictionaries
        """
        self.log(
            "Starting retrieval of current configurations for {0} features".format(
                len(features)
            ),
            "INFO",
        )
        self.log("Device ID: {0}".format(network_device_id), "DEBUG")
        self.log("Features to retrieve: {0}".format(features), "DEBUG")

        deployed_configs = {}
        intended_configs = {}

        for feature in features:
            self.log(
                "Retrieving configurations for feature: {0}".format(feature), "DEBUG"
            )

            try:
                # Fetch deployed configuration
                self.log(
                    "Fetching deployed configuration for feature: {0}".format(feature),
                    "DEBUG",
                )
                deployed = self.get_deployed_layer2_feature_configuration(
                    network_device_id, feature
                )

                if deployed:
                    deployed_configs[feature] = deployed
                    self.log(
                        "Successfully retrieved deployed config for {0}".format(
                            feature
                        ),
                        "DEBUG",
                    )
                    self.log(
                        "Deployed config structure for {0}: {1}".format(
                            feature, deployed
                        ),
                        "DEBUG",
                    )
                else:
                    self.log(
                        "No deployed configuration found for feature: {0}".format(
                            feature
                        ),
                        "DEBUG",
                    )

                # Fetch intended configuration
                self.log(
                    "Fetching intended configuration for feature: {0}".format(feature),
                    "DEBUG",
                )
                intended = self.get_intended_layer2_feature_configuration(
                    network_device_id, feature
                )

                if intended:
                    intended_configs[feature] = intended
                    self.log(
                        "Successfully retrieved intended config for {0}".format(
                            feature
                        ),
                        "DEBUG",
                    )
                    self.log(
                        "Intended config structure for {0}: {1}".format(
                            feature, intended
                        ),
                        "DEBUG",
                    )
                else:
                    self.log(
                        "No intended configuration found for feature: {0}".format(
                            feature
                        ),
                        "DEBUG",
                    )

            except Exception as e:
                self.log(
                    "Error retrieving configurations for feature {0}: {1}".format(
                        feature, str(e)
                    ),
                    "WARNING",
                )
                # Continue with other features even if one fails
                continue

        self.log(
            "Successfully retrieved configurations for {0} features".format(
                len(features)
            ),
            "INFO",
        )
        self.log(
            "Deployed configs retrieved for features: {0}".format(
                list(deployed_configs.keys())
            ),
            "DEBUG",
        )
        self.log(
            "Intended configs retrieved for features: {0}".format(
                list(intended_configs.keys())
            ),
            "DEBUG",
        )

        return deployed_configs, intended_configs

    def extract_layer2_feature_mappings(self, config):
        """
        Extract Layer2 feature mappings from user configuration.
        Args:
            config (dict): User configuration from playbook
        Returns:
            tuple: (discovered_features_set, feature_mappings_dict)
                - discovered_features_set (set): Set of API feature names that need processing
                - feature_mappings_dict (dict): Maps user feature names to their API format configs
        """
        self.log(
            "Starting extraction of Layer2 feature mappings from user configuration",
            "INFO",
        )
        self.log("Input configuration structure: {0}".format(config), "DEBUG")

        discovered_features = set()
        feature_mappings = {}

        # Get layer2_configuration from config
        layer2_config = config.get("layer2_configuration", {})

        if not layer2_config:
            self.log(
                "No layer2_configuration found in config, skipping feature mapping",
                "INFO",
            )
            return discovered_features, feature_mappings

        self.log(
            "Found layer2_configuration with {0} features".format(len(layer2_config)),
            "DEBUG",
        )
        self.log(
            "Layer2 features to process: {0}".format(list(layer2_config.keys())),
            "DEBUG",
        )

        for feature_name, feature_config in layer2_config.items():
            self.log("Processing feature: {0}".format(feature_name), "DEBUG")
            self.log("Feature configuration: {0}".format(feature_config), "DEBUG")

            try:
                self.log(
                    "Mapping configuration parameters for feature: {0}".format(
                        feature_name
                    ),
                    "DEBUG",
                )
                mapped_config = self.get_mapped_layer2_config_params(
                    feature_name, feature_config
                )

                if mapped_config:
                    # Track discovered API features
                    api_features = list(mapped_config.keys())
                    discovered_features.update(api_features)
                    feature_mappings[feature_name] = mapped_config

                    self.log(
                        "Successfully mapped feature '{0}' to {1} API features: {2}".format(
                            feature_name, len(api_features), api_features
                        ),
                        "INFO",
                    )
                    self.log(
                        "Mapped configuration for '{0}': {1}".format(
                            feature_name, mapped_config
                        ),
                        "DEBUG",
                    )
                else:
                    self.log(
                        "No mapping returned for feature: {0}".format(feature_name),
                        "WARNING",
                    )

            except Exception as e:
                self.log(
                    "Error mapping feature '{0}': {1}".format(feature_name, str(e)),
                    "ERROR",
                )
                # Continue with other features even if one fails
                continue

        self.log("Feature mapping extraction completed successfully", "INFO")
        self.log(
            "Total discovered API features: {0}".format(len(discovered_features)),
            "INFO",
        )
        self.log(
            "Discovered API feature names: {0}".format(list(discovered_features)),
            "DEBUG",
        )
        self.log(
            "User features mapped: {0}".format(list(feature_mappings.keys())), "DEBUG"
        )

        return discovered_features, feature_mappings

    def _analyze_configuration_differences(self):
        """
        Analyzes differences between want and have configurations to determine required operations.
        Returns:
            dict: Analysis results containing features to process and their operation types
        """
        self.log("Starting configuration difference analysis", "INFO")

        # Extract data from want and have states
        want_feature_mappings = self.want.get("user_feature_mappings", {})
        deployed_configs = self.have.get("current_deployed_configs", {})
        intended_configs = self.have.get("current_intended_configs", {})
        network_device_id = self.have.get("network_device_id")

        self.log(
            "Analyzing {0} user feature mappings".format(len(want_feature_mappings)),
            "DEBUG",
        )

        # Initialize analysis results
        analysis_results = {
            "network_device_id": network_device_id,
            "features_to_process": {},
            "summary": {
                "total_features": len(want_feature_mappings),
                "create_intent_operations": 0,
                "update_intent_operations": 0,
                "total_api_features": 0,
            },
        }

        # Process each user feature mapping
        for user_feature_name, user_feature_config in want_feature_mappings.items():
            self.log("Processing user feature: {0}".format(user_feature_name), "DEBUG")

            # Process each API feature within this user feature
            for api_feature_name, api_feature_config in user_feature_config.items():
                self.log("Analyzing API feature: {0}".format(api_feature_name), "DEBUG")

                # Determine the operation type for this API feature
                feature_operation = self._determine_feature_operation(
                    api_feature_name,
                    api_feature_config,
                    deployed_configs.get(api_feature_name, {}),
                    intended_configs.get(api_feature_name, {}),
                    # user_feature_name
                )

                if feature_operation:
                    analysis_results["features_to_process"][
                        api_feature_name
                    ] = feature_operation
                    analysis_results["summary"]["total_api_features"] += 1

                    # Count operation types
                    if feature_operation["intent_operation"] == "create":
                        analysis_results["summary"]["create_intent_operations"] += 1
                    elif feature_operation["intent_operation"] == "update":
                        analysis_results["summary"]["update_intent_operations"] += 1

        self.log(
            "Configuration analysis completed: {0}".format(analysis_results["summary"]),
            "INFO",
        )
        return analysis_results

    def _determine_feature_operation(
        self, api_feature_name, desired_config, deployed_config, intended_config
    ):
        """
        Determines the required operation (create/update intent) and final configuration for an API feature.
        Args:
            api_feature_name (str): Name of the API feature (Example, 'vlanConfig', 'cdpGlobalConfig')
            desired_config (dict): Desired configuration from user input
            deployed_config (dict): Current deployed configuration from device
            intended_config (dict): Current intended configuration from Catalyst Center
        Returns:
            dict: Operation details including final config and intent operation type
        """
        self.log(
            "Determining operation for feature: {0}".format(api_feature_name), "DEBUG"
        )
        self.log("Desired config: {0}".format(desired_config), "DEBUG")
        self.log(
            "Deployed config exists: {0}".format(
                bool(
                    deployed_config.get("response", {})
                    .get(api_feature_name, {})
                    .get("items")
                )
            ),
            "DEBUG",
        )
        self.log(
            "Intended config exists: {0}".format(
                bool(
                    intended_config.get("response", {})
                    .get(api_feature_name, {})
                    .get("items")
                )
            ),
            "DEBUG",
        )

        # Extract actual configurations from API response format
        deployed_feature_config = deployed_config.get("response", {}).get(
            api_feature_name, {}
        )
        intended_feature_config = intended_config.get("response", {}).get(
            api_feature_name, {}
        )

        # Determine configuration operation (create/update config)
        config_operation_result = self._determine_config_operation(
            api_feature_name, desired_config, deployed_feature_config
        )

        if not config_operation_result:
            self.log(
                "No configuration changes needed for feature: {0}".format(
                    api_feature_name
                ),
                "DEBUG",
            )
            return None

        # Determine intent operation (create/update intent) - FIX: Pass all required parameters
        intent_operation = self._determine_intent_operation(
            intended_config,
            api_feature_name,
            desired_config,  # Pass intended_config (full), not intended_feature_config
        )

        # Prepare final configuration for API call
        final_config = self._prepare_final_config(
            api_feature_name,
            config_operation_result["final_config"],
            intended_feature_config,
            intent_operation,
        )

        operation_details = {
            "api_feature_name": api_feature_name,
            "config_operation": config_operation_result[
                "operation"
            ],  # "create" or "update"
            "intent_operation": intent_operation,  # "create" or "update"
            "final_config": final_config,
            "changes_detected": config_operation_result.get("changes_detected", True),
        }

        self.log(
            "Operation determined for {0}: config_op={1}, intent_op={2}".format(
                api_feature_name,
                operation_details["config_operation"],
                operation_details["intent_operation"],
            ),
            "INFO",
        )

        return operation_details

    def _determine_config_operation(
        self, api_feature_name, desired_config, deployed_config
    ):
        """
        Determines if configuration needs to be created or updated based on deployed state.
        Args:
            api_feature_name (str): Name of the API feature
            desired_config (dict): Desired configuration
            deployed_config (dict): Current deployed configuration
        Returns:
            dict: Configuration operation details or None if no changes needed
        """
        deployed_items = deployed_config.get("items", [])
        desired_items = desired_config.get("items", [])

        self.log(
            "Config operation analysis for {0}: deployed_items={1}, desired_items={2}".format(
                api_feature_name, len(deployed_items), len(desired_items)
            ),
            "DEBUG",
        )

        # Handle different feature types based on their specific requirements
        if self._is_vlan_feature(api_feature_name):
            self.log(
                "Processing VLAN feature operation analysis for {0}".format(
                    api_feature_name
                ),
                "DEBUG",
            )
            return self._determine_vlan_config_operation(desired_items, deployed_items)
        elif self._is_global_feature(api_feature_name):
            self.log(
                "Processing global feature operation analysis for {0}".format(
                    api_feature_name
                ),
                "DEBUG",
            )
            return self._determine_global_config_operation(
                desired_items, deployed_items
            )
        elif self._is_interface_feature(api_feature_name):
            self.log(
                "Processing interface feature operation analysis for {0}".format(
                    api_feature_name
                ),
                "DEBUG",
            )
            return self._determine_interface_config_operation(
                desired_items, deployed_items
            )
        else:
            # Default handling for other features that don't fit standard categories
            self.log(
                "Processing default feature operation analysis for {0}".format(
                    api_feature_name
                ),
                "DEBUG",
            )
            return self._determine_default_config_operation(
                desired_items, deployed_items
            )

    def _determine_vlan_config_operation(self, desired_vlans, deployed_vlans):
        """
        Determines VLAN configuration operation (supports create/update of individual VLANs).
        Args:
            desired_vlans (list): List of desired VLAN configurations
            deployed_vlans (list): List of currently deployed VLANs
        Returns:
            dict: VLAN operation details
        """
        self.log("Analyzing VLAN configuration operation", "DEBUG")

        # Create lookup for deployed VLANs by ID
        deployed_vlan_lookup = {vlan.get("vlanId"): vlan for vlan in deployed_vlans}

        # Determine VLANs that need create vs update
        vlans_to_create = []
        vlans_to_update = []

        for desired_vlan in desired_vlans:
            vlan_id = desired_vlan.get("vlanId")
            deployed_vlan = deployed_vlan_lookup.get(vlan_id)

            if not deployed_vlan:
                # VLAN doesn't exist - needs creation
                vlans_to_create.append(desired_vlan)
                self.log("VLAN {0} needs creation".format(vlan_id), "DEBUG")
            else:
                # VLAN exists - check if update is needed
                if self._config_needs_update(desired_vlan, deployed_vlan):
                    # Update existing VLAN with new parameters
                    updated_vlan = deployed_vlan.copy()
                    updated_vlan.update(
                        {k: v for k, v in desired_vlan.items() if k != "configType"}
                    )
                    vlans_to_update.append(updated_vlan)
                    self.log("VLAN {0} needs update".format(vlan_id), "DEBUG")

        # Combine all VLANs for final configuration
        all_vlans = vlans_to_create + vlans_to_update

        if not all_vlans:
            return None  # No changes needed

        return {
            "operation": "create" if vlans_to_create else "update",
            "final_config": {"items": all_vlans},
            "changes_detected": True,
            "vlans_to_create": len(vlans_to_create),
            "vlans_to_update": len(vlans_to_update),
        }

    def _determine_global_config_operation(self, desired_items, deployed_items):
        """
        Determines global configuration operation with support for nested instances.
        Args:
            desired_items (list): List of desired configuration items
            deployed_items (list): List of currently deployed configuration items
        Returns:
            dict: Global configuration operation details or None if no changes needed
        """
        self.log(
            "Analyzing global configuration operation with nested instance support",
            "DEBUG",
        )

        if not desired_items:
            return None

        desired_item = desired_items[0]  # Global configs typically have one item

        if not deployed_items:
            # No deployed config - needs creation
            self.log("Global config needs creation (no deployed config)", "DEBUG")
            return {
                "operation": "create",
                "final_config": {"items": [desired_item]},
                "changes_detected": True,
            }

        deployed_item = deployed_items[0]

        # Check if this is a global feature with nested instances
        if self._has_nested_instances(desired_item):
            self.log(
                "Detected global feature with nested instances, using specialized comparison",
                "DEBUG",
            )
            needs_update = self._global_config_with_instances_needs_update(
                desired_item, deployed_item
            )
        else:
            # Standard global config comparison
            needs_update = self._config_needs_update(desired_item, deployed_item)

        if needs_update:
            # Determine merge strategy based on feature type
            config_type = desired_item.get("configType", "")

            if config_type in [
                "IGMP_SNOOPING_GLOBAL",
                "MLD_SNOOPING_GLOBAL",
                "PORTCHANNEL",
            ]:
                self.log(
                    "Using desired config as-is for feature type: {0}".format(
                        config_type
                    ),
                    "DEBUG",
                )
                updated_item = desired_item
            else:
                # Standard deep merge for other global features
                updated_item = self._deep_merge_config(deployed_item, desired_item)

            self.log("Global config needs update", "DEBUG")
            return {
                "operation": "update",
                "final_config": {"items": [updated_item]},
                "changes_detected": True,
            }

        return None

    def _global_config_with_instances_needs_update(self, desired_item, deployed_item):
        """
        Determines if a global configuration with nested instances needs updating.
        This method compares global parameters and nested instances separately.
        Args:
            desired_item (dict): Desired configuration item
            deployed_item (dict): Currently deployed configuration item
        Returns:
            bool: True if update is needed, False otherwise
        """
        self.log("Comparing global configuration with nested instances", "DEBUG")

        # Get nested instance containers for different feature types
        nested_instance_keys = {
            "STP_GLOBAL": ["stpInstances"],
            "IGMP_SNOOPING_GLOBAL": ["igmpSnoopingVlanSettings"],
            "MLD_SNOOPING_GLOBAL": ["mldSnoopingVlanSettings"],
            "PORTCHANNEL": ["portchannels"],
        }

        config_type = desired_item.get("configType", "")
        instance_keys = nested_instance_keys.get(config_type, [])

        # First, compare global parameters (excluding nested instances)
        for key, desired_value in desired_item.items():
            if key in ["configType"] + instance_keys:
                continue  # Skip configType and nested instance keys

            current_value = deployed_item.get(key)
            if desired_value != current_value:
                self.log(
                    "Global parameter '{0}' differs: desired='{1}', current='{2}'".format(
                        key, desired_value, current_value
                    ),
                    "DEBUG",
                )
                return True

        # Then, compare nested instances if present
        for instance_key in instance_keys:
            if instance_key in desired_item:
                desired_instances = desired_item[instance_key].get("items", [])
                current_instances = deployed_item.get(instance_key, {}).get("items", [])

                if self._nested_instances_need_update(
                    desired_instances, current_instances, instance_key
                ):
                    self.log(
                        "Nested instances '{0}' differ - update needed".format(
                            instance_key
                        ),
                        "DEBUG",
                    )
                    return True

        self.log(
            "Global configuration with instances matches - no update needed", "DEBUG"
        )
        return False

    def _deep_merge_config(self, base_config, new_config):
        """
        Performs deep merge of configuration objects, preserving nested structures.
        Only updates values when they actually differ from the current values.
        Args:
            base_config (dict): Base configuration (existing deployed/intended)
            new_config (dict): New configuration with updates
        Returns:
            dict: Merged configuration
        """
        self.log("Starting deep merge of configuration objects", "DEBUG")
        self.log(
            "Base configuration keys: {0}".format(list(base_config.keys())), "DEBUG"
        )
        self.log("New configuration keys: {0}".format(list(new_config.keys())), "DEBUG")

        # Create a copy of the base configuration to avoid modifying the original
        merged = base_config.copy()
        self.log("Created copy of base configuration for merging", "DEBUG")

        # Track if any actual changes were made
        changes_made = 0

        # Iterate through each key-value pair in the new configuration
        for key, value in new_config.items():
            self.log("Processing configuration key: {0}".format(key), "DEBUG")

            # Skip configType as it should not be merged
            if key == "configType":
                self.log("Skipping configType key during merge", "DEBUG")
                continue

            # Check if this key exists in merged config and both values are dictionaries
            if (
                key in merged
                and isinstance(merged[key], dict)
                and isinstance(value, dict)
            ):
                self.log(
                    "Found nested dictionary for key '{0}', performing recursive merge".format(
                        key
                    ),
                    "DEBUG",
                )
                # Recursively merge nested dictionaries
                original_nested = merged[key]
                merged_nested = self._deep_merge_config(merged[key], value)

                # Only update if the recursive merge actually changed something
                if original_nested != merged_nested:
                    merged[key] = merged_nested
                    changes_made += 1
                    self.log(
                        "Updated nested dictionary for key '{0}' due to detected changes".format(
                            key
                        ),
                        "DEBUG",
                    )
                else:
                    self.log(
                        "No changes detected in nested dictionary for key '{0}' - keeping original".format(
                            key
                        ),
                        "DEBUG",
                    )
            else:
                # For non-dict values or new keys, check if value actually differs
                if key in merged:
                    # Key exists - check if values are different
                    current_value = merged[key]
                    if current_value != value:
                        merged[key] = value
                        changes_made += 1
                        self.log(
                            "Updated parameter '{0}': changed from '{1}' to '{2}' (values differ)".format(
                                key, current_value, value
                            ),
                            "DEBUG",
                        )
                    else:
                        self.log(
                            "Parameter '{0}' already has desired value '{1}' - no update needed".format(
                                key, value
                            ),
                            "DEBUG",
                        )
                else:
                    # New key - add it
                    merged[key] = value
                    changes_made += 1
                    self.log(
                        "Added new key '{0}' to merged configuration with value '{1}'".format(
                            key, value
                        ),
                        "DEBUG",
                    )

        self.log("Deep merge completed successfully", "DEBUG")
        self.log("Total configuration changes made: {0}".format(changes_made), "DEBUG")
        self.log("Merged configuration contains {0} keys".format(len(merged)), "DEBUG")

        return merged

    def _has_nested_instances(self, config_item):
        """
        Enhanced check for configuration items with nested instances that need special handling.
        Now includes deeper nested structures like memberPorts and mrouters.
        Args:
            config_item (dict): Configuration item to check
        Returns:
            bool: True if the item has nested instances, False otherwise
        """
        # Define the nested instance containers for each feature type
        nested_instance_keys = {
            "STP_GLOBAL": ["stpInstances"],
            "IGMP_SNOOPING_GLOBAL": ["igmpSnoopingVlanSettings"],
            "MLD_SNOOPING_GLOBAL": ["mldSnoopingVlanSettings"],
            "PORTCHANNEL": ["portchannels"],
        }

        config_type = config_item.get("configType", "")
        instance_keys = nested_instance_keys.get(config_type, [])

        # Check if any of the nested instance keys exist in the config
        for key in instance_keys:
            if (
                key in config_item
                and isinstance(config_item[key], dict)
                and config_item[key].get("items")
            ):
                self.log(
                    "Found nested instances in key '{0}' for config type '{1}'".format(
                        key, config_type
                    ),
                    "DEBUG",
                )
                return True

        return False

    def _nested_instances_need_update(
        self, desired_instances, current_instances, instance_type
    ):
        """
        Enhanced comparison of nested instances with support for deeply nested structures.
        Returns True at the first mismatch found.
        Args:
            desired_instances (list): List of desired instance configurations
            current_instances (list): List of current instance configurations
            instance_type (str): Type of instances being compared
        Returns:
            bool: True if update is needed, False otherwise
        """
        self.log(
            "Comparing {0} nested instances: desired={1}, current={2}".format(
                instance_type, len(desired_instances), len(current_instances)
            ),
            "DEBUG",
        )

        # Use different comparison strategies based on instance type
        if instance_type in [
            "stpInstances",
            "igmpSnoopingVlanSettings",
            "mldSnoopingVlanSettings",
        ]:
            return self._compare_vlan_based_instances(
                desired_instances, current_instances, instance_type
            )
        elif instance_type == "portchannels":
            return self._compare_portchannel_instances(
                desired_instances, current_instances
            )
        else:
            # Fallback to generic comparison
            return self._compare_generic_instances(desired_instances, current_instances)

    def _deep_compare_instances(self, desired_instance, current_instance):
        """
        Performs deep comparison of two instances, returning True if they differ.
        Args:
            desired_instance (dict): Desired instance configuration
            current_instance (dict): Current instance configuration
        Returns:
            bool: True if instances differ, False if they match
        """
        self.log("Performing deep instance comparison", "DEBUG")

        # Compare all parameters except configType
        for key, desired_value in desired_instance.items():
            if key == "configType":
                continue

            current_value = current_instance.get(key)

            if isinstance(desired_value, dict) and isinstance(current_value, dict):
                # Recursive comparison for nested dictionaries
                if self._deep_compare_nested_dict(desired_value, current_value):
                    self.log("Nested dictionary '{0}' differs".format(key), "DEBUG")
                    return True
            elif isinstance(desired_value, list) and isinstance(current_value, list):
                # Comparison for nested lists
                if self._deep_compare_nested_list(desired_value, current_value):
                    self.log("Nested list '{0}' differs".format(key), "DEBUG")
                    return True
            else:
                # Direct comparison for simple values
                if desired_value != current_value:
                    self.log(
                        "Parameter '{0}' differs: desired='{1}', current='{2}'".format(
                            key, desired_value, current_value
                        ),
                        "DEBUG",
                    )
                    return True

        return False

    def _compare_portchannel_instances(self, desired_instances, current_instances):
        """
        Enhanced comparison of port channel instances by name with support for memberPorts.
        Args:
            desired_instances (list): Desired port channel instances
            current_instances (list): Current port channel instances
        Returns:
            bool: True if update is needed, False otherwise
        """
        self.log(
            "Performing enhanced port channel instance comparison with memberPorts support",
            "DEBUG",
        )

        # Create lookup map for current instances by name
        current_by_name = {}
        for instance in current_instances:
            name = instance.get("name")
            if name:
                current_by_name[name] = instance

        # Check each desired instance
        for desired_instance in desired_instances:
            name = desired_instance.get("name")
            if not name:
                continue

            current_instance = current_by_name.get(name)

            if not current_instance:
                self.log(
                    "Port channel '{0}' not found in current instances - update needed".format(
                        name
                    ),
                    "DEBUG",
                )
                return True

            # Enhanced comparison that handles memberPorts specifically
            if self._deep_compare_portchannel_instance(
                desired_instance, current_instance
            ):
                self.log(
                    "Port channel '{0}' instance differs - update needed".format(name),
                    "DEBUG",
                )
                return True

        return False

    def _deep_compare_portchannel_instance(self, desired_instance, current_instance):
        """
        Performs deep comparison of port channel instances with special handling for memberPorts.
        Args:
            desired_instance (dict): Desired port channel configuration
            current_instance (dict): Current port channel configuration
        Returns:
            bool: True if instances differ, False if they match
        """
        self.log(
            "Performing deep port channel instance comparison with memberPorts support",
            "DEBUG",
        )

        # Compare all parameters except configType and memberPorts
        for key, desired_value in desired_instance.items():
            if key in ["configType", "memberPorts"]:
                continue

            current_value = current_instance.get(key)
            if desired_value != current_value:
                self.log(
                    "Port channel parameter '{0}' differs: desired='{1}', current='{2}'".format(
                        key, desired_value, current_value
                    ),
                    "DEBUG",
                )
                return True

        # Special handling for memberPorts
        if "memberPorts" in desired_instance:
            desired_member_ports = desired_instance["memberPorts"].get("items", [])
            current_member_ports = current_instance.get("memberPorts", {}).get(
                "items", []
            )

            if self._compare_member_ports(desired_member_ports, current_member_ports):
                self.log("Port channel memberPorts differ", "DEBUG")
                return True

        return False

    def _compare_member_ports(self, desired_members, current_members):
        """
        Compares member ports within a port channel by interfaceName.
        Args:
            desired_members (list): Desired member port configurations
            current_members (list): Current member port configurations
        Returns:
            bool: True if member ports differ, False if they match
        """
        self.log(
            "Comparing member ports: desired={0}, current={1}".format(
                len(desired_members), len(current_members)
            ),
            "DEBUG",
        )

        # Create lookup map for current members by interfaceName
        current_by_interface = {}
        for member in current_members:
            interface_name = member.get("interfaceName")
            if interface_name:
                current_by_interface[interface_name] = member

        # Check each desired member
        for desired_member in desired_members:
            interface_name = desired_member.get("interfaceName")
            if not interface_name:
                continue

            current_member = current_by_interface.get(interface_name)

            if not current_member:
                self.log(
                    "Member port '{0}' not found in current members - update needed".format(
                        interface_name
                    ),
                    "DEBUG",
                )
                return True

            # Compare member port parameters
            if self._deep_compare_instances(desired_member, current_member):
                self.log(
                    "Member port '{0}' differs - update needed".format(interface_name),
                    "DEBUG",
                )
                return True

        return False

    def _compare_vlan_based_instances(
        self, desired_instances, current_instances, instance_type
    ):
        """
        Enhanced comparison of VLAN-based instances with support for nested mrouters.
        Args:
            desired_instances (list): Desired VLAN-based instances
            current_instances (list): Current VLAN-based instances
            instance_type (str): Type of instances (stpInstances, igmpSnoopingVlanSettings, mldSnoopingVlanSettings)
        Returns:
            bool: True if update is needed, False otherwise
        """
        self.log(
            "Performing enhanced VLAN-based instance comparison for {0}".format(
                instance_type
            ),
            "DEBUG",
        )

        # Create lookup map for current instances by VLAN ID
        current_by_vlan = {}
        for instance in current_instances:
            vlan_id = instance.get("vlanId")
            if vlan_id is not None:
                current_by_vlan[vlan_id] = instance

        # Check each desired instance
        for desired_instance in desired_instances:
            vlan_id = desired_instance.get("vlanId")
            if vlan_id is None:
                continue

            current_instance = current_by_vlan.get(vlan_id)

            if not current_instance:
                self.log(
                    "VLAN {0} not found in current instances - update needed".format(
                        vlan_id
                    ),
                    "DEBUG",
                )
                return True

            # Enhanced comparison based on instance type
            if instance_type == "stpInstances":
                if self._deep_compare_stp_instance(desired_instance, current_instance):
                    self.log(
                        "STP VLAN {0} instance differs - update needed".format(vlan_id),
                        "DEBUG",
                    )
                    return True
            elif instance_type in [
                "igmpSnoopingVlanSettings",
                "mldSnoopingVlanSettings",
            ]:
                if self._deep_compare_snooping_vlan_instance(
                    desired_instance, current_instance, instance_type
                ):
                    self.log(
                        "{0} VLAN {1} instance differs - update needed".format(
                            instance_type, vlan_id
                        ),
                        "DEBUG",
                    )
                    return True
            else:
                # Fallback to standard deep comparison
                if self._deep_compare_instances(desired_instance, current_instance):
                    self.log(
                        "VLAN {0} instance differs - update needed".format(vlan_id),
                        "DEBUG",
                    )
                    return True

        return False

    def _deep_compare_stp_instance(self, desired_instance, current_instance):
        """
        Performs deep comparison of STP instances with special handling for timers.
        Args:
            desired_instance (dict): Desired STP instance configuration
            current_instance (dict): Current STP instance configuration
        Returns:
            bool: True if instances differ, False if they match
        """
        self.log("Performing deep STP instance comparison with timers support", "DEBUG")

        # Compare all parameters except configType and timers
        for key, desired_value in desired_instance.items():
            if key in ["configType", "timers"]:
                continue

            current_value = current_instance.get(key)
            if desired_value != current_value:
                self.log(
                    "STP parameter '{0}' differs: desired='{1}', current='{2}'".format(
                        key, desired_value, current_value
                    ),
                    "DEBUG",
                )
                return True

        # Special handling for timers
        if "timers" in desired_instance:
            desired_timers = desired_instance["timers"]
            current_timers = current_instance.get("timers", {})

            if self._deep_compare_nested_dict(desired_timers, current_timers):
                self.log("STP timers differ", "DEBUG")
                return True

        return False

    def _deep_compare_snooping_vlan_instance(
        self, desired_instance, current_instance, instance_type
    ):
        """
        Performs deep comparison of IGMP/MLD snooping VLAN instances with special handling for mrouters.
        Args:
            desired_instance (dict): Desired snooping VLAN instance configuration
            current_instance (dict): Current snooping VLAN instance configuration
            instance_type (str): Type of snooping (igmpSnoopingVlanSettings or mldSnoopingVlanSettings)
        Returns:
            bool: True if instances differ, False if they match
        """
        self.log(
            "Performing deep {0} instance comparison with mrouters support".format(
                instance_type
            ),
            "DEBUG",
        )

        # Determine the mrouter key based on instance type
        mrouter_key = (
            "igmpSnoopingVlanMrouters"
            if "igmp" in instance_type.lower()
            else "mldSnoopingVlanMrouters"
        )

        # Compare all parameters except configType and mrouters
        for key, desired_value in desired_instance.items():
            if key in ["configType", mrouter_key]:
                continue

            current_value = current_instance.get(key)
            if desired_value != current_value:
                self.log(
                    "Snooping parameter '{0}' differs: desired='{1}', current='{2}'".format(
                        key, desired_value, current_value
                    ),
                    "DEBUG",
                )
                return True

        # Special handling for mrouters
        if mrouter_key in desired_instance:
            desired_mrouters = desired_instance[mrouter_key].get("items", [])
            current_mrouters = current_instance.get(mrouter_key, {}).get("items", [])

            if self._compare_mrouter_ports(desired_mrouters, current_mrouters):
                self.log("Snooping mrouters differ", "DEBUG")
                return True

        return False

    def _compare_mrouter_ports(self, desired_mrouters, current_mrouters):
        """
        Compares mrouter port configurations by interfaceName.
        Args:
            desired_mrouters (list): Desired mrouter port configurations
            current_mrouters (list): Current mrouter port configurations
        Returns:
            bool: True if mrouter ports differ, False if they match
        """
        self.log(
            "Comparing mrouter ports: desired={0}, current={1}".format(
                len(desired_mrouters), len(current_mrouters)
            ),
            "DEBUG",
        )

        # Create lookup map for current mrouters by interfaceName
        current_by_interface = {}
        for mrouter in current_mrouters:
            interface_name = mrouter.get("interfaceName")
            if interface_name:
                current_by_interface[interface_name] = mrouter

        # Check each desired mrouter
        for desired_mrouter in desired_mrouters:
            interface_name = desired_mrouter.get("interfaceName")
            if not interface_name:
                continue

            current_mrouter = current_by_interface.get(interface_name)

            if not current_mrouter:
                self.log(
                    "Mrouter port '{0}' not found in current mrouters - update needed".format(
                        interface_name
                    ),
                    "DEBUG",
                )
                return True

            # Compare mrouter parameters
            if self._deep_compare_instances(desired_mrouter, current_mrouter):
                self.log(
                    "Mrouter port '{0}' differs - update needed".format(interface_name),
                    "DEBUG",
                )
                return True

        return False

    def _deep_compare_nested_list(self, desired_list, current_list):
        """
        Enhanced comparison of nested lists with improved identifier detection.
        Args:
            desired_list (list): Desired nested list
            current_list (list): Current nested list
        Returns:
            bool: True if lists differ, False if they match
        """
        if len(desired_list) != len(current_list):
            return True

        # For lists containing dictionaries with identifiers, try to match by identifier
        if desired_list and isinstance(desired_list[0], dict):
            # Check for various identifier types in priority order
            if "interfaceName" in desired_list[0]:
                return self._compare_interface_based_list(desired_list, current_list)
            elif "vlanId" in desired_list[0]:
                return self._compare_vlan_based_list(desired_list, current_list)
            elif "name" in desired_list[0]:
                return self._compare_name_based_list(desired_list, current_list)
            else:
                # Fallback to index-based comparison
                return self._compare_index_based_list(desired_list, current_list)
        else:
            # Simple list comparison for non-dictionary items
            for i, desired_item in enumerate(desired_list):
                if i >= len(current_list) or desired_item != current_list[i]:
                    return True

        return False

    def _compare_name_based_list(self, desired_list, current_list):
        """
        Compares lists of items that have name as identifier (Example, port channels).
        Args:
            desired_list (list): Desired list with name-based items
            current_list (list): Current list with name-based items
        Returns:
            bool: True if lists differ, False if they match
        """
        current_by_name = {
            item.get("name"): item for item in current_list if item.get("name")
        }

        for desired_item in desired_list:
            name = desired_item.get("name")
            if not name:
                continue

            current_item = current_by_name.get(name)
            if not current_item:
                return True

            if self._deep_compare_instances(desired_item, current_item):
                return True

        return False

    def _determine_interface_config_operation(self, desired_items, deployed_items):
        """
        Determines interface configuration operation.
        Args:
            desired_items (list): Desired interface configurations
            deployed_items (list): Currently deployed interface configurations
        Returns:
            dict: Interface config operation details
        """
        self.log("Analyzing interface configuration operation", "DEBUG")

        if not desired_items:
            return None

        # Create lookup for deployed interfaces by name
        deployed_interface_lookup = {
            item.get("interfaceName"): item for item in deployed_items
        }

        interfaces_to_process = []
        operation_type = "create"

        for desired_interface in desired_items:
            interface_name = desired_interface.get("interfaceName")
            deployed_interface = deployed_interface_lookup.get(interface_name)

            if not deployed_interface:
                # Interface config doesn't exist - needs creation
                interfaces_to_process.append(desired_interface)
                self.log(
                    "Interface {0} config needs creation".format(interface_name),
                    "DEBUG",
                )
            else:
                # Interface config exists - check if update is needed
                if self._config_needs_update(desired_interface, deployed_interface):
                    # Update existing interface with new parameters
                    updated_interface = deployed_interface.copy()
                    updated_interface.update(
                        {
                            k: v
                            for k, v in desired_interface.items()
                            if k not in ["configType", "interfaceName"]
                        }
                    )
                    interfaces_to_process.append(updated_interface)
                    operation_type = "update"
                    self.log(
                        "Interface {0} config needs update".format(interface_name),
                        "DEBUG",
                    )

        if not interfaces_to_process:
            return None  # No changes needed

        return {
            "operation": operation_type,
            "final_config": {"items": interfaces_to_process},
            "changes_detected": True,
        }

    def _determine_default_config_operation(self, desired_items, deployed_items):
        """
        Default configuration operation determination for other feature types.
        Args:
            desired_items (list): Desired configuration items
            deployed_items (list): Currently deployed items
        Returns:
            dict: Default config operation details
        """
        self.log("Analyzing default configuration operation", "DEBUG")

        if not desired_items:
            return None

        if not deployed_items:
            # No deployed config - needs creation
            self.log(
                "No deployed configuration found - operation needs creation", "DEBUG"
            )
            return {
                "operation": "create",
                "final_config": {"items": desired_items},
                "changes_detected": True,
            }

        # Check if any changes are needed
        changes_needed = False
        updated_items = []

        # Compare each desired item with corresponding deployed item
        for i, desired_item in enumerate(desired_items):
            if i < len(deployed_items):
                deployed_item = deployed_items[i]
                self.log(
                    "Comparing desired and deployed configurations for item at index {0}".format(i),
                    "DEBUG",
                )

                if self._config_needs_update(desired_item, deployed_item):
                    # Update existing item with new parameters
                    updated_item = deployed_item.copy()
                    updated_item.update(
                        {k: v for k, v in desired_item.items() if k != "configType"}
                    )
                    updated_items.append(updated_item)
                    changes_needed = True
                    self.log(
                        "Item {0} requires update - parameters differ from deployed state".format(
                            i
                        ),
                        "DEBUG",
                    )
                else:
                    # Keep existing item as no changes needed
                    updated_items.append(deployed_item)
                    self.log(
                        "Item {0} matches deployed state - no changes needed".format(i),
                        "DEBUG",
                    )
            else:
                # Add new item that doesn't exist in deployed config
                updated_items.append(desired_item)
                changes_needed = True
                self.log(
                    "Item {0} is new - will be added to configuration".format(i),
                    "DEBUG",
                )

        if not changes_needed:
            self.log(
                "No configuration changes detected - operation not needed", "DEBUG"
            )
            return None

        self.log("Configuration changes detected - update operation required", "DEBUG")
        return {
            "operation": "update",
            "final_config": {"items": updated_items},
            "changes_detected": True,
        }

    def _determine_intent_operation(
        self, intended_config, api_feature_name=None, desired_config=None
    ):
        """
        Determines whether to create or update intent configuration.
        Args:
            intended_config (dict): Current intended configuration
            api_feature_name (str): Name of the API feature
            desired_config (dict): Desired configuration
        Returns:
            str: "create" or "update"
        """
        if not intended_config or not intended_config.get("response", {}).get(
            api_feature_name, {}
        ).get("items"):
            self.log("No intended config exists - intent needs creation", "DEBUG")
            return "create"

        # For interface-based features, check if specific interfaces exist
        if api_feature_name and desired_config and "items" in desired_config:
            existing_intended = (
                intended_config.get("response", {})
                .get(api_feature_name, {})
                .get("items", [])
            )
            desired_interfaces = [
                item.get("interfaceName")
                for item in desired_config["items"]
                if item.get("interfaceName")
            ]
            existing_interfaces = [
                item.get("interfaceName")
                for item in existing_intended
                if item.get("interfaceName")
            ]

            # If any desired interface doesn't exist in intended config, we need update (not create)
            if any(
                interface not in existing_interfaces for interface in desired_interfaces
            ):
                self.log(
                    "Some interfaces not in intended config - intent needs update",
                    "DEBUG",
                )
                return "update"

        self.log("Intended config exists - intent needs update", "DEBUG")
        return "update"

    # def _determine_intent_operation(self, intended_config):
    #     """
    #     Determines if intent needs to be created or updated.

    #     Args:
    #         intended_config (dict): Current intended configuration

    #     Returns:
    #         str: "create" or "update"
    #     """
    #     intended_items = intended_config.get("items", [])

    #     if not intended_items:
    #         self.log("No intended config exists - intent needs creation", "DEBUG")
    #         return "create"
    #     else:
    #         self.log("Intended config exists - intent needs update", "DEBUG")
    #         return "update"

    def _is_interface_feature(self, api_feature_name):
        """
        Determines if the given API feature is an interface-specific feature.
        Args:
            api_feature_name (str): Name of the API feature
        Returns:
            bool: True if it's an interface feature, False otherwise
        """
        self.log(
            "Checking if API feature '{0}' is an interface-specific feature".format(
                api_feature_name
            ),
            "DEBUG",
        )

        # Define the list of interface-specific features that configure individual interfaces
        interface_features = [
            "switchportInterfaceConfig",
            "vlanTrunkingInterfaceConfig",
            "dot1xInterfaceConfig",
            "mabInterfaceConfig",
            "stpInterfaceConfig",
            "dhcpSnoopingInterfaceConfig",
            "cdpInterfaceConfig",
            "lldpInterfaceConfig",
            "vtpInterfaceConfig",
        ]

        # Check if the feature is in the interface features list
        is_interface = api_feature_name in interface_features

        self.log(
            "Feature '{0}' classification result: {1}".format(
                api_feature_name,
                "interface feature" if is_interface else "not an interface feature",
            ),
            "DEBUG",
        )

        return is_interface

    def _prepare_final_config(
        self,
        api_feature_name,
        config_to_apply,
        intended_config,
        intent_operation,
        deployed_config=None,
    ):
        """
        Prepares the final configuration for API calls, merging with existing intended config when needed.
        Args:
            api_feature_name (str): Name of the API feature
            config_to_apply (dict): Configuration that needs to be applied
            intended_config (dict): Current intended configuration
            intent_operation (str): "create" or "update"
            deployed_config (dict, optional): Current deployed configuration
        Returns:
            dict: Final configuration ready for API call
        """
        self.log("Preparing final config for {0}".format(api_feature_name), "DEBUG")

        if intent_operation == "create":
            # For create operations, use config as-is
            final_config = config_to_apply.copy()
            self.log("Using create operation - applying configuration as-is", "DEBUG")
        else:
            # For update operations, merge with existing intended config
            self.log(
                "Using update operation - merging with existing intended configuration",
                "DEBUG",
            )

            # Special handling for IGMP and MLD snooping which have nested VLAN configurations
            if api_feature_name == "igmpSnoopingGlobalConfig":
                self.log(
                    "Merging IGMP snooping configuration with special VLAN handling",
                    "DEBUG",
                )
                final_config = self._merge_igmp_snooping_config(
                    config_to_apply, intended_config
                )
            elif api_feature_name == "mldSnoopingGlobalConfig":
                self.log(
                    "Merging MLD snooping configuration with special VLAN handling",
                    "DEBUG",
                )
                final_config = self._merge_mld_snooping_config(
                    config_to_apply, intended_config
                )
            elif api_feature_name == "portchannelConfig":
                self.log(
                    "Merging port channel configuration with special handling", "DEBUG"
                )
                final_config = self._merge_port_channel_config(
                    config_to_apply, intended_config
                )
            elif self._is_interface_feature(api_feature_name):
                self.log("Merging interface feature configuration", "DEBUG")
                final_config = self._merge_interface_configs(
                    api_feature_name, config_to_apply, intended_config
                )
            elif self._is_vlan_feature(api_feature_name):
                self.log("Merging VLAN feature configuration", "DEBUG")
                final_config = self._merge_vlan_configs(
                    api_feature_name, config_to_apply, intended_config
                )
            elif api_feature_name == "stpGlobalConfig":
                # Special handling for STP to merge instances properly
                self.log(
                    "Merging STP global configuration with special instance handling",
                    "DEBUG",
                )
                final_config = self._merge_stp_global_config(
                    config_to_apply, intended_config
                )
            else:
                # For global features, replace the configuration
                self.log("Replacing global feature configuration", "DEBUG")
                final_config = config_to_apply.copy()

        self.log(
            "Final config prepared for {0}: {1}".format(api_feature_name, final_config),
            "DEBUG",
        )

        # Prepare the full API payload structure
        final_merged_config = {api_feature_name: final_config}
        self.log(
            "Final merged config for {0}: {1}".format(
                api_feature_name, final_merged_config
            ),
            "DEBUG",
        )

        return final_merged_config

    def _merge_stp_global_config(self, new_config, existing_intended):
        """
        Merges new STP global configuration with existing intended STP configuration, with special handling for STP instances.
        Args:
            new_config (dict): New STP configuration to apply
            existing_intended (dict): Current intended STP configuration
        Returns:
            dict: Merged STP configuration
        """
        self.log(
            "Merging STP global configuration with special instance handling", "DEBUG"
        )

        # Get existing intended items
        existing_items = existing_intended.get("items", [])
        new_items = new_config.get("items", [])

        if not existing_items:
            # No existing config, use new config as-is
            self.log(
                "No existing STP configuration found, using new configuration as-is",
                "DEBUG",
            )
            return new_config

        if not new_items:
            # No new config, return existing
            self.log(
                "No new STP configuration provided, returning existing configuration",
                "DEBUG",
            )
            return {"items": existing_items}

        # Take the first item (STP global configs typically have one item)
        existing_item = existing_items[0].copy()
        new_item = new_items[0]

        self.log(
            "Processing STP global configuration merge for single configuration item",
            "DEBUG",
        )

        # Update global parameters (everything except stpInstances)
        for key, value in new_item.items():
            if key != "stpInstances":
                existing_item[key] = value
                self.log(
                    "Updated STP global parameter '{0}' with value: {1}".format(
                        key, value
                    ),
                    "DEBUG",
                )

        # Handle STP instances merging specially
        if "stpInstances" in new_item:
            self.log("Processing STP instances for special merge handling", "DEBUG")

            existing_instances = existing_item.get("stpInstances", {})
            new_instances = new_item["stpInstances"]

            merged_instances = self._merge_stp_instances(
                existing_instances, new_instances
            )
            existing_item["stpInstances"] = merged_instances

            self.log(
                "Merged STP instances: {0} total instances".format(
                    len(merged_instances.get("items", []))
                ),
                "DEBUG",
            )
        else:
            self.log("No STP instances found in new configuration to merge", "DEBUG")

        self.log("STP global configuration merge completed successfully", "DEBUG")

        return {"items": [existing_item]}

    def _merge_stp_instances(self, current_instances, desired_instances):
        """
        Merge STP instances - add new instances while preserving existing ones.
        Args:
            current_instances (dict): Current STP instances configuration
            desired_instances (dict): Desired STP instances configuration to merge
        Returns:
            dict: Merged STP instances configuration with combined items
        """
        try:
            self.log("Starting merge of STP instances", "DEBUG")

            # Initialize the merged structure
            merged_instances = {"configType": "LIST", "items": []}

            # Get current instances
            current_items = (
                current_instances.get("items", []) if current_instances else []
            )
            desired_items = (
                desired_instances.get("items", []) if desired_instances else []
            )

            self.log("Current instances count: {0}".format(len(current_items)), "DEBUG")
            self.log("Desired instances count: {0}".format(len(desired_items)), "DEBUG")

            # Create a dict of current instances by VLAN ID for easy lookup
            current_by_vlan = {}
            for item in current_items:
                vlan_id = item.get("vlanId")
                if vlan_id:
                    current_by_vlan[vlan_id] = item
                    self.log(
                        "Added current instance for VLAN {0} to lookup".format(vlan_id),
                        "DEBUG",
                    )

            # Start with all current instances
            merged_by_vlan = current_by_vlan.copy()
            self.log(
                "Initialized merged instances with {0} current instances".format(
                    len(merged_by_vlan)
                ),
                "DEBUG",
            )

            # Add or update with desired instances
            for desired_item in desired_items:
                vlan_id = desired_item.get("vlanId")
                if vlan_id:
                    if vlan_id in merged_by_vlan:
                        # Update existing instance
                        merged_by_vlan[vlan_id].update(desired_item)
                        self.log(
                            "Updated STP instance for VLAN {0}".format(vlan_id), "DEBUG"
                        )
                    else:
                        # Add new instance
                        merged_by_vlan[vlan_id] = desired_item
                        self.log(
                            "Added new STP instance for VLAN {0}".format(vlan_id),
                            "DEBUG",
                        )

            # Convert back to list and sort by VLAN ID for consistency
            merged_instances["items"] = sorted(
                merged_by_vlan.values(), key=lambda x: x.get("vlanId", 0)
            )

            self.log(
                "Merged STP instances: {0} total instances".format(
                    len(merged_instances["items"])
                ),
                "DEBUG",
            )
            self.log("STP instances merge completed successfully", "DEBUG")

            return merged_instances

        except Exception as e:
            self.log("Error merging STP instances: {0}".format(str(e)), "ERROR")
            self.log("Returning desired instances as fallback", "DEBUG")
            return desired_instances  # Fallback to desired instances

    def _merge_interface_configs(self, api_feature_name, new_config, existing_intended):
        """
        Merges new interface configuration with existing intended configuration.
        Args:
            api_feature_name (str): Name of the API feature
            new_config (dict): New configuration to apply
            existing_intended (dict): Current intended configuration
        Returns:
            dict: Merged configuration
        """
        self.log("Merging interface configs for {0}".format(api_feature_name), "DEBUG")
        self.log("New config to merge: {0}".format(new_config), "DEBUG")
        self.log("Existing intended config: {0}".format(existing_intended), "DEBUG")

        # Start with existing intended configuration
        existing_items = existing_intended.get("items", [])
        new_items = new_config.get("items", [])

        # Create a lookup of existing items by interface name
        existing_items_by_interface = {}
        for item in existing_items:
            interface_name = item.get("interfaceName")
            if interface_name:
                existing_items_by_interface[interface_name] = item

        self.log(
            "Found {0} existing interfaces in intended config".format(
                len(existing_items_by_interface)
            ),
            "DEBUG",
        )

        # Process new items
        for new_item in new_items:
            interface_name = new_item.get("interfaceName")
            if interface_name:
                # Replace existing config for this interface with new config
                existing_items_by_interface[interface_name] = new_item
                self.log(
                    "Updated/added config for interface: {0}".format(interface_name),
                    "DEBUG",
                )

        # Convert back to list format
        merged_items = list(existing_items_by_interface.values())

        merged_config = {"items": merged_items}

        self.log(
            "Merged config contains {0} total interfaces".format(len(merged_items)),
            "DEBUG",
        )
        self.log("Final merged interface config: {0}".format(merged_config), "DEBUG")

        return merged_config

    def _merge_vlan_configs(self, api_feature_name, new_config, existing_intended):
        """
        Merges new VLAN configuration with existing intended VLANs.
        Args:
            api_feature_name (str): API feature name
            new_config (dict): New VLAN configuration
            existing_intended (dict): Existing intended configuration (not list)
        Returns:
            dict: Merged VLAN configuration
        """
        new_vlans = new_config.get("items", [])

        # Create lookup for new VLANs by ID
        new_vlan_lookup = {vlan.get("vlanId"): vlan for vlan in new_vlans}

        # Extract existing intended VLAN items - FIX: Handle the nested structure
        existing_items = existing_intended.get("items", [])

        # Start with existing intended VLANs
        merged_vlans = []
        for existing_vlan in existing_items:
            vlan_id = existing_vlan.get("vlanId")
            if vlan_id in new_vlan_lookup:
                # Use the new configuration for this VLAN
                merged_vlans.append(new_vlan_lookup[vlan_id])
                del new_vlan_lookup[vlan_id]  # Remove from lookup to avoid duplicates
            else:
                # Keep the existing VLAN
                merged_vlans.append(existing_vlan)

        # Add any remaining new VLANs
        merged_vlans.extend(new_vlan_lookup.values())

        return {"items": merged_vlans}

    # def _merge_vlan_configs(self, api_feature_name, new_config, existing_intended):
    #     """
    #     Merges new VLAN configuration with existing intended VLANs.

    #     Args:
    #         api_feature_name (str): API feature name
    #         new_config (dict): New VLAN configuration
    #         existing_intended (list): Existing intended VLAN items

    #     Returns:
    #         dict: Merged VLAN configuration
    #     """
    #     new_vlans = new_config.get("items", [])

    #     # Create lookup for new VLANs by ID
    #     new_vlan_lookup = {vlan.get("vlanId"): vlan for vlan in new_vlans}

    #     # Start with existing intended VLANs
    #     merged_vlans = []
    #     for existing_vlan in existing_intended:
    #         vlan_id = existing_vlan.get("vlanId")
    #         if vlan_id in new_vlan_lookup:
    #             # Use the new configuration for this VLAN
    #             merged_vlans.append(new_vlan_lookup[vlan_id])
    #             del new_vlan_lookup[vlan_id]  # Remove from lookup to avoid duplicates
    #         else:
    #             # Keep the existing VLAN
    #             merged_vlans.append(existing_vlan)

    #     # Add any remaining new VLANs
    #     merged_vlans.extend(new_vlan_lookup.values())

    #     return {api_feature_name: {"items": merged_vlans}}

    # def _merge_igmp_snooping_config(self, existing_config, desired_config):
    #     """
    #     Merges IGMP snooping configurations with special handling for VLANs.
    #     Args:
    #         existing_config (dict): The existing IGMP snooping configuration from intended config.
    #         desired_config (dict): The desired IGMP snooping configuration from user input.
    #     Returns:
    #         dict: The merged configuration with updated global parameters and preserved VLAN settings.
    #     """
    #     self.log("Starting IGMP snooping configuration merge", "DEBUG")

    #     # Get the items from both configs
    #     existing_items = existing_config.get("items", [])
    #     self.log("Existing IGMP items: {0}".format(existing_items), "DEBUG")

    #     desired_items = desired_config.get("items", [])
    #     self.log("Desired IGMP items: {0}".format(desired_items), "DEBUG")

    #     if not existing_items and not desired_items:
    #         self.log("No existing or desired IGMP items found, returning desired config", "DEBUG")
    #         return desired_config

    #     # If no existing config, return desired
    #     if not existing_items:
    #         return desired_config

    #     # If no desired config, return existing
    #     if not desired_items:
    #         return existing_config

    #     # Merge the configurations
    #     merged_items = []

    #     for existing_item in existing_items:
    #         if existing_item.get("configType") == "IGMP_SNOOPING_GLOBAL":
    #             # Start with existing global config as the final intended config
    #             final_intended_item = copy.deepcopy(existing_item)
    #             self.log("Final intended IGMP item initialized from existing: {0}".format(final_intended_item), "DEBUG")

    #             # Find corresponding desired item
    #             desired_item = None
    #             for d_item in desired_items:
    #                 if d_item.get("configType") == "IGMP_SNOOPING_GLOBAL":
    #                     desired_item = d_item
    #                     break

    #             if desired_item:
    #                 # Merge global parameters (non-VLAN settings)
    #                 for key, value in desired_item.items():
    #                     if key != "igmpSnoopingVlanSettings" and key != "configType":
    #                         self.log("Updating global parameter '{0}' from '{1}' to '{2}'".format(
    #                             key, final_intended_item.get(key), value), "DEBUG")
    #                         final_intended_item[key] = value

    #                 # Handle VLAN settings merge with correct three-category approach
    #                 current_vlan_settings = existing_item.get("igmpSnoopingVlanSettings", {})
    #                 desired_vlan_settings = desired_item.get("igmpSnoopingVlanSettings", {})

    #                 if desired_vlan_settings:
    #                     self.log("Merging IGMP VLAN settings - current intended has {0} VLANs, user desires {1} VLANs".format(
    #                         len(current_vlan_settings.get("items", [])),
    #                         len(desired_vlan_settings.get("items", []))), "DEBUG")

    #                     # Apply the three-category logic: current -> desired -> final
    #                     merged_vlan_settings = self._merge_igmp_vlan_settings(current_vlan_settings, desired_vlan_settings)
    #                     final_intended_item["igmpSnoopingVlanSettings"] = merged_vlan_settings
    #                     self.log("IGMP VLAN settings merge completed", "DEBUG")
    #                 else:
    #                     self.log("No desired VLAN settings found to merge", "DEBUG")

    #             merged_items.append(final_intended_item)

    #     return {"items": merged_items}

    def _merge_igmp_snooping_config(self, desired_config, existing_config):
        """
        Merges IGMP snooping configurations with special handling for VLANs.
        Args:
            existing_config (dict): The existing IGMP snooping configuration from intended config.
            desired_config (dict): The desired IGMP snooping configuration from user input.
        Returns:
            dict: The merged configuration with updated global parameters and preserved VLAN settings.
        """
        self.log("Starting IGMP snooping configuration merge", "DEBUG")
        self.log("Function entry parameters validation", "DEBUG")
        self.log(
            "Existing config type: {0}, keys: {1}".format(
                type(existing_config).__name__,
                list(existing_config.keys()) if existing_config else "None",
            ),
            "DEBUG",
        )
        self.log(
            "Desired config type: {0}, keys: {1}".format(
                type(desired_config).__name__,
                list(desired_config.keys()) if desired_config else "None",
            ),
            "DEBUG",
        )

        # Get the items from both configs
        existing_items = existing_config.get("items", [])
        self.log("Existing IGMP items: {0}".format(existing_items), "DEBUG")
        self.log(
            "Extracted {0} existing items from configuration".format(
                len(existing_items)
            ),
            "DEBUG",
        )
        desired_items = desired_config.get("items", [])
        self.log("Desired IGMP items: {0}".format(desired_items), "DEBUG")
        self.log(
            "Extracted {0} desired items from configuration".format(len(desired_items)),
            "DEBUG",
        )
        # Early exit conditions with detailed logging
        if not existing_items and not desired_items:
            self.log(
                "No existing or desired IGMP items found, returning desired config",
                "DEBUG",
            )
            self.log("Early exit: Both configurations are empty", "DEBUG")
            return desired_config

        # If no existing config, return desired
        if not existing_items:
            self.log(
                "No existing configuration found, returning desired configuration as-is",
                "DEBUG",
            )
            self.log(
                "Early exit: Only desired configuration exists with {0} items".format(
                    len(desired_items)
                ),
                "DEBUG",
            )
            return desired_config

        # If no desired config, return existing
        if not desired_items:
            self.log(
                "No desired configuration found, returning existing configuration as-is",
                "DEBUG",
            )
            self.log(
                "Early exit: Only existing configuration exists with {0} items".format(
                    len(existing_items)
                ),
                "DEBUG",
            )
            return existing_config

        # Start main merge process
        self.log("Both configurations exist - proceeding with merge operation", "DEBUG")
        self.log(
            "Merge operation will process {0} existing items and {1} desired items".format(
                len(existing_items), len(desired_items)
            ),
            "DEBUG",
        )

        # Merge the configurations
        merged_items = []
        self.log("Initialized merged_items list for storing merge results", "DEBUG")

        # Process each existing item
        for existing_item_index, existing_item in enumerate(existing_items):
            self.log(
                "Processing existing item {0} of {1}".format(
                    existing_item_index + 1, len(existing_items)
                ),
                "DEBUG",
            )
            self.log("Existing item structure: {0}".format(existing_item), "DEBUG")

            existing_config_type = existing_item.get("configType")
            self.log(
                "Existing item configType: {0}".format(existing_config_type), "DEBUG"
            )

            if existing_config_type == "IGMP_SNOOPING_GLOBAL":
                self.log("Found IGMP_SNOOPING_GLOBAL item for processing", "DEBUG")

                # Start with existing global config as the final intended config
                final_intended_item = copy.deepcopy(existing_item)
                self.log(
                    "Final intended IGMP item initialized from existing: {0}".format(
                        final_intended_item
                    ),
                    "DEBUG",
                )
                self.log(
                    "Created deep copy of existing item with {0} keys".format(
                        len(final_intended_item.keys())
                    ),
                    "DEBUG",
                )
                # Find corresponding desired item
                self.log(
                    "Searching for corresponding desired item with IGMP_SNOOPING_GLOBAL configType",
                    "DEBUG",
                )
                desired_item = None
                desired_item_found_index = None

                for d_item_index, d_item in enumerate(desired_items):
                    d_item_config_type = d_item.get("configType")
                    self.log(
                        "Checking desired item {0}: configType = {1}".format(
                            d_item_index, d_item_config_type
                        ),
                        "DEBUG",
                    )

                    if d_item_config_type == "IGMP_SNOOPING_GLOBAL":
                        desired_item = d_item
                        desired_item_found_index = d_item_index
                        self.log(
                            "Found matching desired item at index {0}".format(
                                d_item_index
                            ),
                            "DEBUG",
                        )
                        break

                if desired_item:
                    self.log(
                        "Successfully found corresponding desired item for merge",
                        "DEBUG",
                    )
                    self.log(
                        "Desired item structure: {0}".format(desired_item), "DEBUG"
                    )
                    self.log(
                        "Desired item contains {0} keys for processing".format(
                            len(desired_item.keys())
                        ),
                        "DEBUG",
                    )

                    # Process global parameters (non-VLAN settings)
                    self.log(
                        "Starting global parameters merge (excluding VLAN settings)",
                        "DEBUG",
                    )
                    global_params_updated = 0

                    for key, value in desired_item.items():
                        if key != "igmpSnoopingVlanSettings" and key != "configType":
                            old_value = final_intended_item.get(key)
                            self.log(
                                "Updating global parameter '{0}' from '{1}' to '{2}'".format(
                                    key, old_value, value
                                ),
                                "DEBUG",
                            )
                            final_intended_item[key] = value
                            global_params_updated += 1
                        else:
                            self.log(
                                "Skipping parameter '{0}' (will be handled separately)".format(
                                    key
                                ),
                                "DEBUG",
                            )

                    self.log(
                        "Global parameters merge completed: {0} parameters updated".format(
                            global_params_updated
                        ),
                        "DEBUG",
                    )

                    # Handle VLAN settings merge with correct three-category approach
                    self.log(
                        "Starting VLAN settings extraction and validation", "DEBUG"
                    )
                    current_vlan_settings = existing_item.get(
                        "igmpSnoopingVlanSettings", {}
                    )
                    desired_vlan_settings = desired_item.get(
                        "igmpSnoopingVlanSettings", {}
                    )

                    self.log(
                        "Current VLAN settings type: {0}".format(
                            type(current_vlan_settings).__name__
                        ),
                        "DEBUG",
                    )
                    self.log(
                        "Desired VLAN settings type: {0}".format(
                            type(desired_vlan_settings).__name__
                        ),
                        "DEBUG",
                    )

                    current_vlan_items = current_vlan_settings.get("items", [])
                    desired_vlan_items = desired_vlan_settings.get("items", [])

                    self.log(
                        "Current VLAN settings structure: {0}".format(
                            current_vlan_settings
                        ),
                        "DEBUG",
                    )
                    self.log(
                        "Desired VLAN settings structure: {0}".format(
                            desired_vlan_settings
                        ),
                        "DEBUG",
                    )
                    if desired_vlan_settings:
                        self.log(
                            "VLAN settings found in desired configuration - proceeding with VLAN merge",
                            "DEBUG",
                        )
                        self.log(
                            "Merging IGMP VLAN settings - current intended has {0} VLANs, user desires {1} VLANs".format(
                                len(current_vlan_items), len(desired_vlan_items)
                            ),
                            "DEBUG",
                        )

                        self.log(
                            "Calling _merge_igmp_vlan_settings with parameters:",
                            "DEBUG",
                        )
                        self.log(
                            "  - Current VLAN settings: {0} items".format(
                                len(current_vlan_items)
                            ),
                            "DEBUG",
                        )
                        self.log(
                            "  - Desired VLAN settings: {0} items".format(
                                len(desired_vlan_items)
                            ),
                            "DEBUG",
                        )

                        # Apply the three-category logic: current -> desired -> final
                        merged_vlan_settings = self._merge_igmp_vlan_settings(
                            current_vlan_settings, desired_vlan_settings
                        )

                        self.log(
                            "VLAN settings merge function returned successfully",
                            "DEBUG",
                        )
                        self.log(
                            "Merged VLAN settings structure: {0}".format(
                                merged_vlan_settings
                            ),
                            "DEBUG",
                        )

                        merged_vlan_items = merged_vlan_settings.get("items", [])
                        self.log(
                            "Final merged VLAN settings contain {0} items".format(
                                len(merged_vlan_items)
                            ),
                            "DEBUG",
                        )

                        final_intended_item["igmpSnoopingVlanSettings"] = (
                            merged_vlan_settings
                        )
                        self.log(
                            "Successfully applied merged VLAN settings to final intended item",
                            "DEBUG",
                        )
                        self.log("IGMP VLAN settings merge completed", "DEBUG")
                    else:
                        self.log(
                            "No desired VLAN settings found in user configuration",
                            "DEBUG",
                        )
                        self.log(
                            "VLAN settings will remain unchanged from current intended configuration",
                            "DEBUG",
                        )
                        self.log(
                            "Current VLAN settings preserved: {0} items".format(
                                len(current_vlan_items)
                            ),
                            "DEBUG",
                        )

                    self.log("Global item merge completed successfully", "DEBUG")
                    self.log(
                        "Final intended item contains {0} keys".format(
                            len(final_intended_item.keys())
                        ),
                        "DEBUG",
                    )

                else:
                    self.log(
                        "No corresponding desired item found with IGMP_SNOOPING_GLOBAL configType",
                        "DEBUG",
                    )
                    self.log("Existing item will be preserved without changes", "DEBUG")

                # Add the processed item to merged results
                merged_items.append(final_intended_item)
                self.log(
                    "Added final intended item to merged results (item {0})".format(
                        len(merged_items)
                    ),
                    "DEBUG",
                )

            else:
                self.log(
                    "Existing item has non-global configType '{0}', preserving as-is".format(
                        existing_config_type
                    ),
                    "DEBUG",
                )
                merged_items.append(existing_item)
                self.log(
                    "Added non-global item to merged results (item {0})".format(
                        len(merged_items)
                    ),
                    "DEBUG",
                )

        # Final result preparation
        self.log("Merge operation completed successfully", "DEBUG")
        self.log("Total merged items: {0}".format(len(merged_items)), "DEBUG")

        final_result = {"items": merged_items}
        self.log(
            "Final merged configuration structure: {0}".format(final_result), "DEBUG"
        )
        self.log(
            "Returning merged configuration with {0} items".format(len(merged_items)),
            "DEBUG",
        )

        return final_result

    def _merge_igmp_vlan_settings(self, current_vlan_settings, desired_vlan_settings):
        """
        Merge IGMP VLAN settings using the three-category approach:
        1. current = current intended config (ALL VLANs) - this becomes our base
        2. desired = user provided config (ONLY USER-SPECIFIED VLANs) - these are the changes
        3. final = copy current, then apply user's desired changes for specified VLANs

        Args:
            current_vlan_settings (dict): Current intended VLAN settings (ALL VLANs).
            desired_vlan_settings (dict): User desired VLAN settings (ONLY USER-SPECIFIED VLANs).
        Returns:
            dict: Final VLAN settings with user's desired values applied to current intended config.
        """
        self.log(
            "Starting IGMP VLAN settings merge using three-category approach", "DEBUG"
        )

        # Category 1: current = current intended config (ALL VLANs)
        current_vlans = current_vlan_settings.get("items", [])
        self.log("Current intended VLANs: {0}".format(current_vlans), "DEBUG")
        # Category 2: desired = user provided config (ONLY USER-SPECIFIED VLANs)
        desired_vlans = desired_vlan_settings.get("items", [])
        self.log("User desired VLANs: {0}".format(desired_vlans), "DEBUG")
        self.log(
            "Current intended VLANs count: {0}".format(len(current_vlans)), "DEBUG"
        )
        self.log("User desired VLANs count: {0}".format(len(desired_vlans)), "DEBUG")

        # Category 3: final = copy current intended config as base
        final_vlan_dict = {}

        # Initialize the parameters_updated counter
        parameters_updated = 0

        # Step 1: Copy ALL current intended VLANs into final config
        for current_vlan in current_vlans:
            vlan_id = current_vlan.get("vlanId")
            if vlan_id:
                final_vlan_dict[vlan_id] = copy.deepcopy(current_vlan)
                self.log(
                    "Copied current intended VLAN {0} to final config".format(vlan_id),
                    "DEBUG",
                )

        self.log(
            "Copied {0} current intended VLANs to final config".format(
                len(final_vlan_dict)
            ),
            "DEBUG",
        )
        # Step 2: Apply user's desired changes ONLY for user-specified VLANs
        for desired_vlan in desired_vlans:
            vlan_id = desired_vlan.get("vlanId")
            if vlan_id:
                self.log("Processing user-specified VLAN {0}".format(vlan_id), "DEBUG")

                if vlan_id in final_vlan_dict:
                    # VLAN exists in current intended config - UPDATE with user's desired parameters
                    final_vlan = final_vlan_dict[vlan_id]
                    self.log(
                        "VLAN {0} exists in current intended config - updating with user's desired values".format(
                            vlan_id
                        ),
                        "DEBUG",
                    )

                    # Update ONLY the parameters provided by the user
                    igmp_vlan_params = [
                        "isIgmpSnoopingEnabled",
                        "isImmediateLeaveEnabled",
                        "isQuerierEnabled",
                        "querierAddress",
                        "querierQueryInterval",
                        "querierVersion",
                    ]

                    for param in igmp_vlan_params:
                        if param in desired_vlan:
                            old_value = final_vlan.get(param)
                            new_value = desired_vlan[param]
                            # FIX: Only update if values are different
                            if old_value != new_value:
                                final_vlan[param] = new_value
                                parameters_updated += 1
                                self.log(
                                    "VLAN {0}: Updated parameter '{1}' from current '{2}' to user's desired '{3}' (values differ)".format(
                                        vlan_id, param, old_value, new_value
                                    ),
                                    "DEBUG",
                                )
                            else:
                                self.log(
                                    "VLAN {0}: Parameter '{1}' already matches desired value '{2}' - no update needed".format(
                                        vlan_id, param, new_value
                                    ),
                                    "DEBUG",
                                )

                    # Handle mrouter configuration if provided by user
                    if "igmpSnoopingVlanMrouters" in desired_vlan:
                        final_vlan["igmpSnoopingVlanMrouters"] = copy.deepcopy(
                            desired_vlan["igmpSnoopingVlanMrouters"]
                        )
                        self.log(
                            "VLAN {0}: Applied user's mrouter configuration".format(
                                vlan_id
                            ),
                            "DEBUG",
                        )
                    elif "igmpSnoopingVlanMrouters" not in final_vlan:
                        final_vlan["igmpSnoopingVlanMrouters"] = {
                            "configType": "SET",
                            "items": [],
                        }
                        self.log(
                            "VLAN {0}: Added default mrouter structure".format(vlan_id),
                            "DEBUG",
                        )

                else:
                    # VLAN doesn't exist in current intended config - ADD new VLAN
                    self.log(
                        "VLAN {0} does not exist in current intended config - adding new VLAN".format(
                            vlan_id
                        ),
                        "DEBUG",
                    )
                    new_vlan_config = copy.deepcopy(desired_vlan)

                    # Ensure required structure for new VLAN
                    if "configType" not in new_vlan_config:
                        new_vlan_config["configType"] = "IGMP_SNOOPING_VLAN"

                    if "igmpSnoopingVlanMrouters" not in new_vlan_config:
                        new_vlan_config["igmpSnoopingVlanMrouters"] = {
                            "configType": "SET",
                            "items": [],
                        }

                    final_vlan_dict[vlan_id] = new_vlan_config
                    self.log(
                        "Added new VLAN {0} to final intended config".format(vlan_id),
                        "DEBUG",
                    )

        # Convert final result back to list format sorted by VLAN ID
        final_vlans = sorted(final_vlan_dict.values(), key=lambda x: x.get("vlanId", 0))

        self.log(
            "IGMP VLAN settings merge completed with {0} total VLANs in final config".format(
                len(final_vlans)
            ),
            "DEBUG",
        )
        self.log("Total parameters updated: {0}".format(parameters_updated), "DEBUG")

        return {"configType": "SET", "items": final_vlans}

    def _merge_mld_snooping_config(self, desired_config, existing_config):
        """
        Merges MLD snooping configurations with special handling for VLANs.
        Args:
            existing_config (dict): The existing MLD snooping configuration from intended config.
            desired_config (dict): The desired MLD snooping configuration from user input.
        Returns:
            dict: The merged configuration with updated global parameters and preserved VLAN settings.
        """
        self.log("Starting MLD snooping configuration merge", "DEBUG")
        self.log("Function entry parameters validation", "DEBUG")
        self.log(
            "Existing config type: {0}, keys: {1}".format(
                type(existing_config).__name__,
                list(existing_config.keys()) if existing_config else "None",
            ),
            "DEBUG",
        )
        self.log(
            "Desired config type: {0}, keys: {1}".format(
                type(desired_config).__name__,
                list(desired_config.keys()) if desired_config else "None",
            ),
            "DEBUG",
        )

        # Get the items from both configs
        existing_items = existing_config.get("items", [])
        self.log("Existing MLD items: {0}".format(existing_items), "DEBUG")
        self.log(
            "Extracted {0} existing items from configuration".format(
                len(existing_items)
            ),
            "DEBUG",
        )
        desired_items = desired_config.get("items", [])
        self.log("Desired MLD items: {0}".format(desired_items), "DEBUG")
        self.log(
            "Extracted {0} desired items from configuration".format(len(desired_items)),
            "DEBUG",
        )

        # Early exit conditions with detailed logging
        if not existing_items and not desired_items:
            self.log(
                "No existing or desired MLD items found, returning desired config",
                "DEBUG",
            )
            self.log("Early exit: Both configurations are empty", "DEBUG")
            return desired_config

        # If no existing config, return desired
        if not existing_items:
            self.log(
                "No existing configuration found, returning desired configuration as-is",
                "DEBUG",
            )
            self.log(
                "Early exit: Only desired configuration exists with {0} items".format(
                    len(desired_items)
                ),
                "DEBUG",
            )
            return desired_config

        # If no desired config, return existing
        if not desired_items:
            self.log(
                "No desired configuration found, returning existing configuration as-is",
                "DEBUG",
            )
            self.log(
                "Early exit: Only existing configuration exists with {0} items".format(
                    len(existing_items)
                ),
                "DEBUG",
            )
            return existing_config

        # Start main merge process
        self.log("Both configurations exist - proceeding with merge operation", "DEBUG")
        self.log(
            "Merge operation will process {0} existing items and {1} desired items".format(
                len(existing_items), len(desired_items)
            ),
            "DEBUG",
        )

        # Merge the configurations
        merged_items = []
        self.log("Initialized merged_items list for storing merge results", "DEBUG")

        # Process each existing item
        for existing_item_index, existing_item in enumerate(existing_items):
            self.log(
                "Processing existing item {0} of {1}".format(
                    existing_item_index + 1, len(existing_items)
                ),
                "DEBUG",
            )
            self.log("Existing item structure: {0}".format(existing_item), "DEBUG")

            existing_config_type = existing_item.get("configType")
            self.log(
                "Existing item configType: {0}".format(existing_config_type), "DEBUG"
            )

            if existing_config_type == "MLD_SNOOPING_GLOBAL":
                self.log("Found MLD_SNOOPING_GLOBAL item for processing", "DEBUG")

                # Start with existing global config as the final intended config
                final_intended_item = copy.deepcopy(existing_item)
                self.log(
                    "Final intended MLD item initialized from existing: {0}".format(
                        final_intended_item
                    ),
                    "DEBUG",
                )
                self.log(
                    "Created deep copy of existing item with {0} keys".format(
                        len(final_intended_item.keys())
                    ),
                    "DEBUG",
                )

                # Find corresponding desired item
                self.log(
                    "Searching for corresponding desired item with MLD_SNOOPING_GLOBAL configType",
                    "DEBUG",
                )
                desired_item = None
                desired_item_found_index = None

                for d_item_index, d_item in enumerate(desired_items):
                    d_item_config_type = d_item.get("configType")
                    self.log(
                        "Checking desired item {0}: configType = {1}".format(
                            d_item_index, d_item_config_type
                        ),
                        "DEBUG",
                    )

                    if d_item_config_type == "MLD_SNOOPING_GLOBAL":
                        desired_item = d_item
                        desired_item_found_index = d_item_index
                        self.log(
                            "Found matching desired item at index {0}".format(
                                d_item_index
                            ),
                            "DEBUG",
                        )
                        break

                if desired_item:
                    self.log(
                        "Successfully found corresponding desired item for merge",
                        "DEBUG",
                    )
                    self.log(
                        "Desired item structure: {0}".format(desired_item), "DEBUG"
                    )
                    self.log(
                        "Desired item contains {0} keys for processing".format(
                            len(desired_item.keys())
                        ),
                        "DEBUG",
                    )

                    # Process global parameters (non-VLAN settings)
                    self.log(
                        "Starting global parameters merge (excluding VLAN settings)",
                        "DEBUG",
                    )
                    global_params_updated = 0

                    for key, value in desired_item.items():
                        if key != "mldSnoopingVlanSettings" and key != "configType":
                            old_value = final_intended_item.get(key)
                            self.log(
                                "Updating global parameter '{0}' from '{1}' to '{2}'".format(
                                    key, old_value, value
                                ),
                                "DEBUG",
                            )
                            final_intended_item[key] = value
                            global_params_updated += 1
                        else:
                            self.log(
                                "Skipping parameter '{0}' (will be handled separately)".format(
                                    key
                                ),
                                "DEBUG",
                            )

                    self.log(
                        "Global parameters merge completed: {0} parameters updated".format(
                            global_params_updated
                        ),
                        "DEBUG",
                    )

                    # Handle VLAN settings merge with correct three-category approach
                    self.log(
                        "Starting VLAN settings extraction and validation", "DEBUG"
                    )
                    current_vlan_settings = existing_item.get(
                        "mldSnoopingVlanSettings", {}
                    )
                    desired_vlan_settings = desired_item.get(
                        "mldSnoopingVlanSettings", {}
                    )

                    self.log(
                        "Current VLAN settings type: {0}".format(
                            type(current_vlan_settings).__name__
                        ),
                        "DEBUG",
                    )
                    self.log(
                        "Desired VLAN settings type: {0}".format(
                            type(desired_vlan_settings).__name__
                        ),
                        "DEBUG",
                    )

                    current_vlan_items = current_vlan_settings.get("items", [])
                    desired_vlan_items = desired_vlan_settings.get("items", [])

                    self.log(
                        "Current VLAN settings structure: {0}".format(
                            current_vlan_settings
                        ),
                        "DEBUG",
                    )
                    self.log(
                        "Desired VLAN settings structure: {0}".format(
                            desired_vlan_settings
                        ),
                        "DEBUG",
                    )

                    if desired_vlan_settings:
                        self.log(
                            "VLAN settings found in desired configuration - proceeding with VLAN merge",
                            "DEBUG",
                        )
                        self.log(
                            "Merging MLD VLAN settings - current intended has {0} VLANs, user desires {1} VLANs".format(
                                len(current_vlan_items), len(desired_vlan_items)
                            ),
                            "DEBUG",
                        )

                        self.log(
                            "Calling _merge_mld_vlan_settings with parameters:", "DEBUG"
                        )
                        self.log(
                            "  - Current VLAN settings: {0} items".format(
                                len(current_vlan_items)
                            ),
                            "DEBUG",
                        )
                        self.log(
                            "  - Desired VLAN settings: {0} items".format(
                                len(desired_vlan_items)
                            ),
                            "DEBUG",
                        )

                        # Apply the three-category logic: current -> desired -> final
                        merged_vlan_settings = self._merge_mld_vlan_settings(
                            current_vlan_settings, desired_vlan_settings
                        )

                        self.log(
                            "VLAN settings merge function returned successfully",
                            "DEBUG",
                        )
                        self.log(
                            "Merged VLAN settings structure: {0}".format(
                                merged_vlan_settings
                            ),
                            "DEBUG",
                        )

                        merged_vlan_items = merged_vlan_settings.get("items", [])
                        self.log(
                            "Final merged VLAN settings contain {0} items".format(
                                len(merged_vlan_items)
                            ),
                            "DEBUG",
                        )

                        final_intended_item["mldSnoopingVlanSettings"] = (
                            merged_vlan_settings
                        )
                        self.log(
                            "Successfully applied merged VLAN settings to final intended item",
                            "DEBUG",
                        )
                        self.log("MLD VLAN settings merge completed", "DEBUG")
                    else:
                        self.log(
                            "No desired VLAN settings found in user configuration",
                            "DEBUG",
                        )
                        self.log(
                            "VLAN settings will remain unchanged from current intended configuration",
                            "DEBUG",
                        )
                        self.log(
                            "Current VLAN settings preserved: {0} items".format(
                                len(current_vlan_items)
                            ),
                            "DEBUG",
                        )

                    self.log("Global item merge completed successfully", "DEBUG")
                    self.log(
                        "Final intended item contains {0} keys".format(
                            len(final_intended_item.keys())
                        ),
                        "DEBUG",
                    )

                else:
                    self.log(
                        "No corresponding desired item found with MLD_SNOOPING_GLOBAL configType",
                        "DEBUG",
                    )
                    self.log("Existing item will be preserved without changes", "DEBUG")

                # Add the processed item to merged results
                merged_items.append(final_intended_item)
                self.log(
                    "Added final intended item to merged results (item {0})".format(
                        len(merged_items)
                    ),
                    "DEBUG",
                )

            else:
                self.log(
                    "Existing item has non-global configType '{0}', preserving as-is".format(
                        existing_config_type
                    ),
                    "DEBUG",
                )
                merged_items.append(existing_item)
                self.log(
                    "Added non-global item to merged results (item {0})".format(
                        len(merged_items)
                    ),
                    "DEBUG",
                )

        # Final result preparation
        self.log("Merge operation completed successfully", "DEBUG")
        self.log("Total merged items: {0}".format(len(merged_items)), "DEBUG")

        final_result = {"items": merged_items}
        self.log(
            "Final merged configuration structure: {0}".format(final_result), "DEBUG"
        )
        self.log(
            "Returning merged configuration with {0} items".format(len(merged_items)),
            "DEBUG",
        )

        return final_result

    def _merge_mld_vlan_settings(self, current_vlan_settings, desired_vlan_settings):
        """
        Merge MLD VLAN settings using the three-category approach:
        1. current = current intended config (ALL VLANs) - this becomes our base
        2. desired = user provided config (ONLY USER-SPECIFIED VLANs) - these are the changes
        3. final = copy current, then apply user's desired changes for specified VLANs

        Args:
            current_vlan_settings (dict): Current intended VLAN settings (ALL VLANs).
            desired_vlan_settings (dict): User desired VLAN settings (ONLY USER-SPECIFIED VLANs).
        Returns:
            dict: Final VLAN settings with user's desired values applied to current intended config.
        """
        self.log(
            "Starting MLD VLAN settings merge using three-category approach", "DEBUG"
        )

        # Category 1: current = current intended config (ALL VLANs)
        current_vlans = current_vlan_settings.get("items", [])
        self.log("Current intended VLANs: {0}".format(current_vlans), "DEBUG")
        # Category 2: desired = user provided config (ONLY USER-SPECIFIED VLANs)
        desired_vlans = desired_vlan_settings.get("items", [])
        self.log("User desired VLANs: {0}".format(desired_vlans), "DEBUG")
        self.log(
            "Current intended VLANs count: {0}".format(len(current_vlans)), "DEBUG"
        )
        self.log("User desired VLANs count: {0}".format(len(desired_vlans)), "DEBUG")

        # Category 3: final = copy current intended config as base
        final_vlan_dict = {}

        # Initialize the parameters_updated counter
        parameters_updated = 0

        # Step 1: Copy ALL current intended VLANs into final config
        for current_vlan in current_vlans:
            vlan_id = current_vlan.get("vlanId")
            if vlan_id:
                final_vlan_dict[vlan_id] = copy.deepcopy(current_vlan)
                self.log(
                    "Copied current intended VLAN {0} to final config".format(vlan_id),
                    "DEBUG",
                )

        self.log(
            "Copied {0} current intended VLANs to final config".format(
                len(final_vlan_dict)
            ),
            "DEBUG",
        )

        # Step 2: Apply user's desired changes ONLY for user-specified VLANs
        for desired_vlan in desired_vlans:
            vlan_id = desired_vlan.get("vlanId")
            if vlan_id:
                self.log("Processing user-specified VLAN {0}".format(vlan_id), "DEBUG")

                if vlan_id in final_vlan_dict:
                    # VLAN exists in current intended config - UPDATE with user's desired parameters
                    final_vlan = final_vlan_dict[vlan_id]
                    self.log(
                        "VLAN {0} exists in current intended config - updating with user's desired values".format(
                            vlan_id
                        ),
                        "DEBUG",
                    )

                    # Update ONLY the parameters provided by the user
                    mld_vlan_params = [
                        "isMldSnoopingEnabled",
                        "isImmediateLeaveEnabled",
                        "isQuerierEnabled",
                        "querierAddress",
                        "querierQueryInterval",
                        "querierVersion",
                    ]

                    for param in mld_vlan_params:
                        if param in desired_vlan:
                            old_value = final_vlan.get(param)
                            new_value = desired_vlan[param]

                            # FIX: Skip empty querierAddress when querier is disabled
                            if (
                                param == "querierAddress"
                                and not new_value
                                and not desired_vlan.get("isQuerierEnabled", False)
                            ):
                                # Remove empty querierAddress when querier is disabled
                                if param in final_vlan:
                                    del final_vlan[param]
                                self.log(
                                    "Removed empty querierAddress for VLAN {0} (querier disabled)".format(
                                        vlan_id
                                    ),
                                    "DEBUG",
                                )
                                continue

                            # Only update if values are different
                            if old_value != new_value:
                                final_vlan[param] = new_value
                                parameters_updated += 1
                                self.log(
                                    "VLAN {0}: Updated parameter '{1}' from current '{2}' to user's desired '{3}' (values differ)".format(
                                        vlan_id, param, old_value, new_value
                                    ),
                                    "DEBUG",
                                )
                            else:
                                self.log(
                                    "VLAN {0}: Parameter '{1}' already matches desired value '{2}' - no update needed".format(
                                        vlan_id, param, new_value
                                    ),
                                    "DEBUG",
                                )

                    # Handle mrouter configuration if provided by user
                    if "mldSnoopingVlanMrouters" in desired_vlan:
                        final_vlan["mldSnoopingVlanMrouters"] = copy.deepcopy(
                            desired_vlan["mldSnoopingVlanMrouters"]
                        )
                        self.log(
                            "VLAN {0}: Applied user's mrouter configuration".format(
                                vlan_id
                            ),
                            "DEBUG",
                        )
                    elif "mldSnoopingVlanMrouters" not in final_vlan:
                        final_vlan["mldSnoopingVlanMrouters"] = {
                            "configType": "SET",
                            "items": [],
                        }
                        self.log(
                            "VLAN {0}: Added default mrouter structure".format(vlan_id),
                            "DEBUG",
                        )

                else:
                    # VLAN doesn't exist in current intended config - ADD new VLAN
                    self.log(
                        "VLAN {0} does not exist in current intended config - adding new VLAN".format(
                            vlan_id
                        ),
                        "DEBUG",
                    )
                    new_vlan_config = copy.deepcopy(desired_vlan)

                    # Ensure required structure for new VLAN
                    if "configType" not in new_vlan_config:
                        new_vlan_config["configType"] = "MLD_SNOOPING_VLAN"

                    # FIX: Remove empty querierAddress if querier is disabled for new VLANs
                    if (
                        "querierAddress" in new_vlan_config
                        and not new_vlan_config["querierAddress"]
                        and not new_vlan_config.get("isQuerierEnabled", False)
                    ):
                        del new_vlan_config["querierAddress"]
                        self.log(
                            "Removed empty querierAddress from new VLAN {0} (querier disabled)".format(
                                vlan_id
                            ),
                            "DEBUG",
                        )

                    if "mldSnoopingVlanMrouters" not in new_vlan_config:
                        new_vlan_config["mldSnoopingVlanMrouters"] = {
                            "configType": "SET",
                            "items": [],
                        }

                    final_vlan_dict[vlan_id] = new_vlan_config
                    self.log(
                        "Added new VLAN {0} to final intended config".format(vlan_id),
                        "DEBUG",
                    )

        # Convert final result back to list format sorted by VLAN ID
        final_vlans = sorted(final_vlan_dict.values(), key=lambda x: x.get("vlanId", 0))

        self.log(
            "MLD VLAN settings merge completed with {0} total VLANs in final config".format(
                len(final_vlans)
            ),
            "DEBUG",
        )
        self.log("Total parameters updated: {0}".format(parameters_updated), "DEBUG")

        return {"configType": "SET", "items": final_vlans}

    def _merge_port_channel_config(self, desired_config, existing_config):
        """
        Merges port channel configurations by port channel name.
        Args:
            desired_config (dict): The desired port channel configuration from user input.
            existing_config (dict): The existing port channel configuration from intended config.
        Returns:
            dict: The merged configuration with updated global parameters and preserved port channels.
        """
        self.log("Starting port channel configuration merge", "DEBUG")

        # Create a deep copy of existing config to avoid modifying original
        merged_config = copy.deepcopy(existing_config)

        # Get the first item from both configs (port channel configs have single item)
        existing_items = existing_config.get("items", [])
        desired_items = desired_config.get("items", [])

        if not existing_items or not desired_items:
            self.log(
                "Missing items in existing or desired config, returning desired config",
                "DEBUG",
            )
            return desired_config

        existing_item = existing_items[0]
        desired_item = desired_items[0]

        # Start with existing item as base
        merged_item = copy.deepcopy(existing_item)

        # Update global parameters (excluding portchannels)
        for key, value in desired_item.items():
            if key not in ["portchannels", "configType"]:
                merged_item[key] = value
                self.log(
                    "Updated global parameter '{0}': {1}".format(key, value), "DEBUG"
                )

        # Extract current and desired port channels
        existing_portchannels = existing_item.get("portchannels", {}).get("items", [])
        desired_portchannels = desired_item.get("portchannels", {}).get("items", [])

        self.log(
            "Current intended port channels count: {0}".format(
                len(existing_portchannels)
            ),
            "DEBUG",
        )
        self.log(
            "User desired port channels count: {0}".format(len(desired_portchannels)),
            "DEBUG",
        )

        # Create a mapping of existing port channels by name
        existing_pc_map = {}
        for pc in existing_portchannels:
            pc_name = pc.get("name")
            if pc_name:
                existing_pc_map[pc_name] = pc
                self.log("Found existing port channel: {0}".format(pc_name), "DEBUG")

        # Process desired port channels
        updated_portchannels = []

        # First, add all existing port channels that are not being updated
        for pc_name, pc_config in existing_pc_map.items():
            # Check if this port channel is being updated
            is_being_updated = any(
                desired_pc.get("name") == pc_name for desired_pc in desired_portchannels
            )

            if not is_being_updated:
                updated_portchannels.append(pc_config)
                self.log(
                    "Preserving existing port channel: {0}".format(pc_name), "DEBUG"
                )

        # Then, add/update port channels from desired config
        for desired_pc in desired_portchannels:
            pc_name = desired_pc.get("name")
            if not pc_name:
                self.log("Skipping port channel without name", "WARNING")
                continue

            if pc_name in existing_pc_map:
                self.log("Updating existing port channel: {0}".format(pc_name), "DEBUG")
                # Merge the port channel configuration
                merged_pc = self._merge_single_port_channel(
                    existing_pc_map[pc_name], desired_pc
                )
                updated_portchannels.append(merged_pc)
            else:
                self.log("Adding new port channel: {0}".format(pc_name), "DEBUG")
                updated_portchannels.append(desired_pc)

        # Update the portchannels in the merged item (not at root level)
        if "portchannels" not in merged_item:
            merged_item["portchannels"] = {"configType": "SET", "items": []}

        merged_item["portchannels"]["items"] = updated_portchannels

        # Update the merged config with the single merged item
        merged_config["items"] = [merged_item]

        self.log(
            "Port channel merge completed. Final count: {0}".format(
                len(updated_portchannels)
            ),
            "DEBUG",
        )
        return merged_config

    def _merge_single_port_channel(self, current_pc, desired_pc):
        """
        Merges a single port channel configuration.
        Args:
            current_pc (dict): Current port channel configuration.
            desired_pc (dict): Desired port channel configuration.
        Returns:
            dict: Merged port channel configuration.
        """
        self.log(
            "Merging port channel: {0}".format(current_pc.get("name", "Unknown")),
            "DEBUG",
        )

        # Start with current configuration
        merged_pc = copy.deepcopy(current_pc)

        # Update with desired parameters (excluding member ports for now)
        for key, value in desired_pc.items():
            if key not in ["memberPorts", "configType"]:
                merged_pc[key] = value
                self.log(
                    "Updated port channel parameter '{0}': {1}".format(key, value),
                    "DEBUG",
                )

        # Handle member ports merge
        current_members = current_pc.get("memberPorts", {}).get("items", [])
        desired_members = desired_pc.get("memberPorts", {}).get("items", [])

        # Create mapping of current members by interface name
        current_member_map = {}
        for member in current_members:
            interface_name = member.get("interfaceName")
            if interface_name:
                current_member_map[interface_name] = member

        # Process desired members
        updated_members = []

        # Add existing members that are not being updated
        for interface_name, member_config in current_member_map.items():
            is_being_updated = any(
                desired_member.get("interfaceName") == interface_name
                for desired_member in desired_members
            )

            if not is_being_updated:
                updated_members.append(member_config)
                self.log(
                    "Preserving existing member: {0}".format(interface_name), "DEBUG"
                )

        # Add/update members from desired config
        for desired_member in desired_members:
            interface_name = desired_member.get("interfaceName")
            if not interface_name:
                continue

            if interface_name in current_member_map:
                self.log(
                    "Updating existing member: {0}".format(interface_name), "DEBUG"
                )
                # Merge member configuration
                merged_member = copy.deepcopy(current_member_map[interface_name])
                for key, value in desired_member.items():
                    if key != "configType":
                        merged_member[key] = value
                updated_members.append(merged_member)
            else:
                self.log("Adding new member: {0}".format(interface_name), "DEBUG")
                updated_members.append(desired_member)

        # Update member ports in merged config
        if updated_members:
            merged_pc["memberPorts"] = {"configType": "SET", "items": updated_members}

        self.log(
            "Port channel merge completed. Members: {0}".format(len(updated_members)),
            "DEBUG",
        )
        return merged_pc

    def _config_needs_update(self, desired_config, current_config):
        """
        Compares desired configuration with current configuration to determine if update is needed.
        Args:
            desired_config (dict): Desired configuration
            current_config (dict): Current configuration
        Returns:
            bool: True if update is needed, False otherwise
        """
        self.log(
            "Starting configuration comparison to determine update necessity", "DEBUG"
        )
        self.log(
            "Desired configuration keys: {0}".format(list(desired_config.keys())),
            "DEBUG",
        )
        self.log(
            "Current configuration keys: {0}".format(list(current_config.keys())),
            "DEBUG",
        )

        # Compare all parameters except configType
        for key, desired_value in desired_config.items():
            if key == "configType":
                self.log("Skipping configType parameter during comparison", "DEBUG")
                continue

            current_value = current_config.get(key)
            self.log(
                "Comparing parameter '{0}': desired='{1}', current='{2}'".format(
                    key, desired_value, current_value
                ),
                "DEBUG",
            )

            if current_value != desired_value:
                self.log(
                    "Parameter {0} differs: desired={1}, current={2}".format(
                        key, desired_value, current_value
                    ),
                    "DEBUG",
                )
                self.log(
                    "Configuration update is required due to parameter differences",
                    "DEBUG",
                )
                return True
            else:
                self.log(
                    "Parameter '{0}' matches between desired and current configuration".format(
                        key
                    ),
                    "DEBUG",
                )

        self.log(
            "All parameters match between desired and current configuration", "DEBUG"
        )
        self.log("No configuration update is required", "DEBUG")

        return False

    def _is_vlan_feature(self, api_feature_name):
        """
        Check if the feature is VLAN-related.
        Args:
            api_feature_name (str): Name of the API feature to check
        Returns:
            bool: True if the feature is VLAN-related, False otherwise
        """
        self.log(
            "Checking if API feature '{0}' is VLAN-related".format(api_feature_name),
            "DEBUG",
        )

        # Check if the feature name matches the VLAN configuration identifier
        is_vlan = api_feature_name == "vlanConfig"

        self.log(
            "VLAN feature check result for '{0}': {1}".format(
                api_feature_name, is_vlan
            ),
            "DEBUG",
        )

        return is_vlan

    def _is_global_feature(self, api_feature_name):
        """
        Check if the feature is a global configuration.
        Args:
            api_feature_name (str): Name of the API feature to check
        Returns:
            bool: True if the feature is a global configuration, False otherwise
        """
        self.log(
            "Checking if API feature '{0}' is a global configuration feature".format(
                api_feature_name
            ),
            "DEBUG",
        )

        # Define the list of global configuration features that configure device-wide settings
        global_features = [
            "cdpGlobalConfig",
            "lldpGlobalConfig",
            "stpGlobalConfig",
            "vtpGlobalConfig",
            "dhcpSnoopingGlobalConfig",
            "igmpSnoopingGlobalConfig",
            "mldSnoopingGlobalConfig",
            "dot1xGlobalConfig",
            "portchannelConfig",
            "udldGlobalConfig",
        ]

        # Check if the feature is in the global features list
        is_global = api_feature_name in global_features

        self.log(
            "Global feature check result for '{0}': {1}".format(
                api_feature_name,
                "global feature" if is_global else "not a global feature",
            ),
            "DEBUG",
        )

        return is_global

    def _is_interface_feature(self, api_feature_name):
        """
        Check if the feature is an interface configuration.
        Args:
            api_feature_name (str): Name of the API feature to check
        Returns:
            bool: True if the feature is an interface configuration, False otherwise
        """
        self.log(
            "Checking if API feature '{0}' is an interface configuration feature".format(
                api_feature_name
            ),
            "DEBUG",
        )

        # Define the list of interface-specific features that configure individual interfaces
        interface_features = [
            "switchportInterfaceConfig",
            "trunkInterfaceConfig",
            "cdpInterfaceConfig",
            "lldpInterfaceConfig",
            "stpInterfaceConfig",
            "dhcpSnoopingInterfaceConfig",
            "dot1xInterfaceConfig",
            "mabInterfaceConfig",
            "vtpInterfaceConfig",
        ]

        # Check if the feature is in the interface features list
        is_interface = api_feature_name in interface_features

        self.log(
            "Interface feature check result for '{0}': {1}".format(
                api_feature_name,
                (
                    "interface configuration feature"
                    if is_interface
                    else "not an interface configuration feature"
                ),
            ),
            "DEBUG",
        )

        return is_interface

    def _execute_api_operations(self, diff_analysis):
        """
        Executes the API operations for all features that require changes.
        Description:
            This is the main orchestration function that:
            1. Checks if any operations are needed (exits with success if none)
            2. Executes intent operations (create/update) for each feature
            3. Fails immediately if any intent operation fails
            4. Attempts deployment only if all intent operations succeed
            5. Sets appropriate operation results and messages
        Args:
            diff_analysis (dict): Analysis results from _analyze_configuration_differences
        Returns:
            dict: Results of all API operations executed
        """
        self.log("Starting execution of API operations", "INFO")

        network_device_id = diff_analysis.get("network_device_id")
        features_to_process = diff_analysis.get("features_to_process", {})
        device_identifier = self.want.get("device_identifier")

        if not features_to_process:
            self.msg = "No Layer 2 configuration changes required for device {0}. Current configuration is already up-to-date.".format(
                device_identifier
            )
            self.set_operation_result("success", False, self.msg, "INFO")
            return {
                "executed_operations": {},
                "deployment_result": None,
                "summary": {
                    "total_operations": 0,
                    "successful_operations": 0,
                    "failed_operations": 0,
                    "deployment_attempted": False,
                    "deployment_successful": False,
                },
            }

        self.log(
            "Executing API operations for {0} features".format(
                len(features_to_process)
            ),
            "INFO",
        )

        executed_operations = {}
        successful_operations = 0
        failed_operations = 0
        failed_features = []

        # Execute intent operations for each feature
        for api_feature_name, operation_details in features_to_process.items():
            user_feature_name = self._get_user_feature_name(api_feature_name)
            self.log(
                "Executing operation for feature: {0} (user: {1})".format(
                    api_feature_name, user_feature_name
                ),
                "INFO",
            )

            try:
                operation_result = self._execute_single_feature_operation(
                    network_device_id,
                    api_feature_name,
                    operation_details,
                    user_feature_name,
                )

                executed_operations[api_feature_name] = operation_result

                if operation_result.get("status") == "success":
                    successful_operations += 1
                    self.log(
                        "Successfully executed operation for feature: {0}".format(
                            user_feature_name
                        ),
                        "INFO",
                    )
                else:
                    failed_operations += 1
                    failed_features.append(
                        {
                            "feature": user_feature_name,
                            "operation": operation_details.get("intent_operation"),
                            "error": operation_result.get("error", "Unknown error"),
                            "api_feature": api_feature_name,
                        }
                    )
                    self.log(
                        "Failed to execute operation for feature: {0}".format(
                            user_feature_name
                        ),
                        "ERROR",
                    )

            except Exception as e:
                error_msg = "Exception during operation for feature {0}: {1}".format(
                    user_feature_name, str(e)
                )
                self.log(error_msg, "ERROR")

                executed_operations[api_feature_name] = {
                    "status": "failed",
                    "error": error_msg,
                    "exception": str(e),
                }
                failed_operations += 1
                failed_features.append(
                    {
                        "feature": user_feature_name,
                        "operation": operation_details.get("intent_operation"),
                        "error": error_msg,
                        "api_feature": api_feature_name,
                    }
                )

        # If any intent operations failed, fail immediately without attempting deployment
        if failed_operations > 0:
            failure_details = self._build_detailed_failure_message(
                failed_features, device_identifier, "intent configuration"
            )
            self.msg = failure_details
            self.set_operation_result("failed", True, self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        # Attempt deployment if all intent operations were successful
        deployment_result = None
        deployment_successful = False

        if successful_operations > 0:
            self.log(
                "All intent operations successful. Attempting to deploy configurations to device",
                "INFO",
            )
            try:
                deployment_result = self._deploy_configurations(
                    network_device_id, device_identifier
                )
                deployment_successful = deployment_result.get("status") == "success"

                if deployment_successful:
                    success_msg = "Successfully deployed Wired Campus Automation configuration for device {0}.".format(
                        device_identifier
                    )
                    self.msg = success_msg
                    self.set_operation_result("success", True, self.msg, "INFO")
                    self.log(success_msg, "INFO")
                else:
                    deployment_error = deployment_result.get(
                        "error", "Unknown deployment error"
                    )
                    failure_msg = (
                        "Failed to deploy Wired Campus Automation configuration for device {0}. "
                        "Intent configuration was successful for {1} features, but deployment failed: {2}"
                    ).format(device_identifier, successful_operations, deployment_error)
                    self.msg = failure_msg
                    self.set_operation_result("failed", True, self.msg, "ERROR")
                    self.fail_and_exit(self.msg)

            except Exception as e:
                error_msg = "Exception during deployment for device {0}: {1}".format(
                    device_identifier, str(e)
                )
                self.log(error_msg, "ERROR")
                self.msg = error_msg
                self.set_operation_result("failed", True, self.msg, "ERROR")
                self.fail_and_exit(self.msg)

        operation_results = {
            "executed_operations": executed_operations,
            "deployment_result": deployment_result,
            "summary": {
                "total_operations": len(features_to_process),
                "successful_operations": successful_operations,
                "failed_operations": failed_operations,
                "deployment_attempted": successful_operations > 0,
                "deployment_successful": deployment_successful,
            },
        }

        self.log(
            "API operations execution completed: {0}".format(
                operation_results["summary"]
            ),
            "INFO",
        )
        return operation_results

    def _execute_single_feature_operation(
        self, network_device_id, api_feature_name, operation_details, user_feature_name
    ):
        """
        Executes the API operation for a single Layer 2 feature (create or update intent).
        Description:
            This function:
            1. Determines the intent operation type (create/update)
            2. Calls the appropriate API function with the final configuration
            3. Extracts the task ID from the response
            4. Monitors task completion using get_task_status_from_tasks_by_id
            5. Returns success/failure status with detailed information
        Args:
            network_device_id (str): Network device ID
            api_feature_name (str): API feature name (Example, 'vlanConfig')
            operation_details (dict): Operation details including intent operation and final config
            user_feature_name (str): User-friendly feature name for logging
        Returns:
            dict: Result of the API operation with status, task details, and error info
        """
        intent_operation = operation_details.get("intent_operation")
        final_config = operation_details.get("final_config")

        self.log(
            "Executing {0} intent operation for feature {1}".format(
                intent_operation, user_feature_name
            ),
            "DEBUG",
        )
        self.log("Final configuration to apply: {0}".format(final_config), "DEBUG")

        try:
            if intent_operation == "create":
                task_response = self.create_layer2_feature_configuration(
                    network_device_id, api_feature_name, final_config
                )
                task_name = "Create {0} Intent Configuration".format(user_feature_name)
                success_msg = "Successfully created {0} intent configuration".format(
                    user_feature_name
                )
            elif intent_operation == "update":
                task_response = self.update_layer2_feature_configuration(
                    network_device_id, api_feature_name, final_config
                )
                task_name = "Update {0} Intent Configuration".format(user_feature_name)
                success_msg = "Successfully updated {0} intent configuration".format(
                    user_feature_name
                )
            else:
                raise ValueError(
                    "Invalid intent operation: {0}".format(intent_operation)
                )

            # Debug: Log the task response structure and type
            self.log(
                "DEBUG: task_response type: {0}".format(type(task_response)), "DEBUG"
            )
            self.log("DEBUG: task_response content: {0}".format(task_response), "DEBUG")

            # Process the task response - get_taskid_post_api_call returns the task ID directly as a string
            if task_response and isinstance(task_response, str):
                task_id = task_response
                self.log(
                    "Task initiated for {0} operation on {1}, task ID: {2}".format(
                        intent_operation, user_feature_name, task_id
                    ),
                    "INFO",
                )

                # Monitor task completion using the same pattern as wireless design module
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()

                # Check the final status
                if self.status == "success":
                    return {
                        "status": "success",
                        "intent_operation": intent_operation,
                        "task_id": task_id,
                        "task_name": task_name,
                        "final_config": final_config,
                        "message": success_msg,
                    }
                else:
                    return {
                        "status": "failed",
                        "error": self.msg,
                        "intent_operation": intent_operation,
                        "task_id": task_id,
                        "task_name": task_name,
                    }
            else:
                error_msg = "Invalid task response format for {0} operation on {1}. Expected string task ID, got: {2} (type: {3})".format(
                    intent_operation,
                    user_feature_name,
                    task_response,
                    type(task_response).__name__,
                )
                self.log(error_msg, "ERROR")
                return {
                    "status": "failed",
                    "error": error_msg,
                    "intent_operation": intent_operation,
                    "response": task_response,
                }

        except Exception as e:
            error_msg = "Failed to execute {0} operation for {1}: {2}".format(
                intent_operation, user_feature_name, str(e)
            )
            self.log(error_msg, "ERROR")
            self.log("Exception details: {0}".format(str(e)), "DEBUG")

            # DEBUG: Add full traceback
            import traceback

            self.log(
                "DEBUG: Full exception traceback: {0}".format(traceback.format_exc()),
                "DEBUG",
            )

            return {
                "status": "failed",
                "error": error_msg,
                "exception": str(e),
                "intent_operation": intent_operation,
            }

    def _deploy_configurations(self, network_device_id, device_identifier):
        """
        Deploys the intended configurations to the device.
        Description:
            This function:
            1. Calls the deployment API to deploy all intended configurations
            2. Extracts the task ID from the response
            3. Monitors deployment task completion using get_task_status_from_tasks_by_id
            4. Returns success/failure status with detailed information
        Args:
            network_device_id (str): Network device ID
            device_identifier (str): Device identifier for user messages
        Returns:
            dict: Result of the deployment operation with status and task details
        """
        self.log(
            "Initiating deployment of configurations to device {0}".format(
                device_identifier
            ),
            "INFO",
        )

        try:
            deploy_response = self.deploy_intended_configurations(network_device_id)

            # Debug: Log the deploy response structure and type
            self.log(
                "DEBUG: deploy_response type: {0}".format(type(deploy_response)),
                "DEBUG",
            )
            self.log(
                "DEBUG: deploy_response content: {0}".format(deploy_response), "DEBUG"
            )

            # Process the deploy response - deploy_intended_configurations returns the task ID directly as a string
            if deploy_response and isinstance(deploy_response, str):
                task_id = deploy_response
                task_name = "Deploy Wired Campus Automation Configuration"
                success_msg = "Successfully deployed Wired Campus Automation configuration to device {0}".format(
                    device_identifier
                )
                self.log(
                    "Deployment task initiated, task ID: {0}".format(task_id), "INFO"
                )

                # Monitor deployment task completion using existing DnacBase function
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()

                # Check the final status
                if self.status == "success":
                    return {
                        "status": "success",
                        "task_id": task_id,
                        "task_name": task_name,
                    }
                else:
                    return {
                        "status": "failed",
                        "error": self.msg,
                        "task_id": task_id,
                        "task_name": task_name,
                    }
            else:
                error_msg = "Invalid deploy response format for deployment operation on device {0}. Expected string task ID, got: {1} (type: {2})".format(
                    device_identifier, deploy_response, type(deploy_response).__name__
                )
                self.log(error_msg, "ERROR")
                return {
                    "status": "failed",
                    "error": error_msg,
                    "response": deploy_response,
                }

        except Exception as e:
            error_msg = "Failed to deploy configurations to device {0}: {1}".format(
                device_identifier, str(e)
            )
            self.log(error_msg, "ERROR")
            return {"status": "failed", "error": error_msg, "exception": str(e)}

    def _get_user_feature_name(self, api_feature_name):
        """
        Maps API feature names to user-friendly feature names for better error messages.
        Description:
            Converts technical API feature names to human-readable names that users
            can understand in error messages and logs. This ensures that failure
            messages use terminology familiar to network administrators.
        Args:
            api_feature_name (str): API feature name (Example, 'vlanConfig')
        Returns:
            str: User-friendly feature name (Example, 'VLAN Configuration')
        """
        feature_mapping = {
            "vlanConfig": "VLAN Configuration",
            "cdpGlobalConfig": "CDP Configuration",
            "lldpGlobalConfig": "LLDP Configuration",
            "stpGlobalConfig": "STP Configuration",
            "vtpGlobalConfig": "VTP Configuration",
            "dhcpSnoopingGlobalConfig": "DHCP Snooping Configuration",
            "igmpSnoopingGlobalConfig": "IGMP Snooping Configuration",
            "mldSnoopingGlobalConfig": "MLD Snooping Configuration",
            "dot1xGlobalConfig": "802.1X Authentication Configuration",
            "portchannelConfig": "Port Channel Configuration",
            "switchportInterfaceConfig": "Switchport Interface Configuration",
            "trunkInterfaceConfig": "Trunk Interface Configuration",
            "cdpInterfaceConfig": "CDP Interface Configuration",
            "lldpInterfaceConfig": "LLDP Interface Configuration",
            "stpInterfaceConfig": "STP Interface Configuration",
            "dhcpSnoopingInterfaceConfig": "DHCP Snooping Interface Configuration",
            "dot1xInterfaceConfig": "802.1X Interface Configuration",
            "mabInterfaceConfig": "MAB Interface Configuration",
            "vtpInterfaceConfig": "VTP Interface Configuration",
        }

        return feature_mapping.get(api_feature_name, api_feature_name)

    def _build_detailed_failure_message(
        self, failed_features, device_identifier, operation_type
    ):
        """
        Builds a detailed failure message for failed operations using user-friendly feature names.
        Args:
            failed_features (list): List of failed feature details with user-friendly names
            device_identifier (str): Device identifier for the error message
            operation_type (str): Type of operation (Example, "intent configuration", "deployment")
        Returns:
            str: Detailed failure message with enumerated failure details
        """
        if not failed_features:
            return "Unknown failure occurred during {0} for device {1}".format(
                operation_type, device_identifier
            )

        failure_msg = "Failed to configure Wired Campus Automation for device {0} during {1}. Failures occurred in the following features:\n".format(
            device_identifier, operation_type
        )

        # Iterate through each failed feature and build detailed error description
        for i, failure in enumerate(failed_features, 1):
            feature_name = failure.get("feature", "Unknown Feature")
            operation = failure.get("operation", "unknown operation")
            error = failure.get("error", "Unknown error")

            failure_msg += "{0}. {1} ({2} operation): {3}\n".format(
                i, feature_name, operation, error
            )
            self.log(
                "Processing failure {0}: Feature '{1}', Operation '{2}', Error '{3}'".format(
                    i, feature_name, operation, error
                ),
                "DEBUG",
            )

        self.log(
            "Built detailed failure message for {0} failed features during {1}".format(
                len(failed_features), operation_type
            ),
            "DEBUG",
        )

        return failure_msg.rstrip()

    def _log_configuration_state(
        self, state_label, want_feature_mappings, deployed_configs
    ):
        """
        Logs the configuration state in a structured format.
        Args:
            state_label (str): Label for the state (Example, "Pre-operation", "Post-operation")
            want_feature_mappings (dict): User feature mappings for context
            deployed_configs (dict): Deployed configurations to log
        """
        for user_feature_name, user_feature_config in want_feature_mappings.items():
            self.log("User Feature: {0}".format(user_feature_name), "INFO")

            for api_feature_name in user_feature_config.keys():
                user_friendly_name = self._get_user_feature_name(api_feature_name)
                config = deployed_configs.get(api_feature_name, {})

                if config.get("response", {}).get(api_feature_name, {}).get("items"):
                    items_count = len(config["response"][api_feature_name]["items"])
                    self.log(
                        "  - {0}: {1} items configured".format(
                            user_friendly_name, items_count
                        ),
                        "INFO",
                    )
                    self.log(
                        "    {0} config structure: {1}".format(
                            state_label, config["response"][api_feature_name]
                        ),
                        "DEBUG",
                    )
                else:
                    self.log(
                        "  - {0}: No configuration found".format(user_friendly_name),
                        "INFO",
                    )

    def _perform_detailed_verification(
        self,
        want_feature_mappings,
        original_deployed_configs,
        post_operation_deployed_configs,
    ):
        """
        Performs detailed verification of configuration changes by comparing desired vs actual state.
        Args:
            want_feature_mappings (dict): Desired user feature configurations
            original_deployed_configs (dict): Pre-operation deployed configurations
            post_operation_deployed_configs (dict): Post-operation deployed configurations
        Returns:
            dict: Detailed verification results and summary
        """
        self.log("Starting detailed verification analysis", "DEBUG")

        verification_summary = {
            "total_features_verified": 0,
            "features_successfully_applied": 0,
            "features_failed_verification": 0,
            "features_not_found": 0,
            "verification_failed": False,
            "success_message": "",
            "failure_message": "",
            "detailed_results": {},
        }

        failed_verifications = []
        successful_verifications = []

        # Process each user feature mapping
        for user_feature_name, user_feature_config in want_feature_mappings.items():
            self.log("Verifying user feature: {0}".format(user_feature_name), "INFO")

            for api_feature_name, desired_config in user_feature_config.items():
                verification_summary["total_features_verified"] += 1
                user_friendly_name = self._get_user_feature_name(api_feature_name)

                self.log(
                    "Verifying API feature: {0} ({1})".format(
                        api_feature_name, user_friendly_name
                    ),
                    "INFO",
                )

                # Get configurations for comparison
                original_config = original_deployed_configs.get(api_feature_name, {})
                post_config = post_operation_deployed_configs.get(api_feature_name, {})

                # Perform feature-specific verification
                feature_verification = self._verify_single_feature(
                    api_feature_name,
                    user_friendly_name,
                    desired_config,
                    original_config,
                    post_config,
                )

                verification_summary["detailed_results"][
                    api_feature_name
                ] = feature_verification

                if feature_verification["status"] == "success":
                    verification_summary["features_successfully_applied"] += 1
                    successful_verifications.append(feature_verification["message"])
                    self.log("✓ {0}".format(feature_verification["message"]), "INFO")
                elif feature_verification["status"] == "failed":
                    verification_summary["features_failed_verification"] += 1
                    failed_verifications.append(feature_verification["message"])
                    self.log("✗ {0}".format(feature_verification["message"]), "ERROR")
                else:  # not_found
                    verification_summary["features_not_found"] += 1
                    failed_verifications.append(feature_verification["message"])
                    self.log("⚠ {0}".format(feature_verification["message"]), "WARNING")

        # Determine overall verification result
        if failed_verifications:
            verification_summary["verification_failed"] = True
            verification_summary["failure_message"] = (
                "Configuration verification failed for device {0}. "
                "Successfully verified: {1}, Failed: {2}, Not found: {3}. "
                "Failures: {4}".format(
                    self.want.get("device_identifier"),
                    verification_summary["features_successfully_applied"],
                    verification_summary["features_failed_verification"],
                    verification_summary["features_not_found"],
                    "; ".join(failed_verifications),
                )
            )
        else:
            verification_summary["success_message"] = (
                "Configuration verification successful for device {0}. "
                "All {1} Layer 2 features have been successfully deployed and verified.".format(
                    self.want.get("device_identifier"),
                    verification_summary["features_successfully_applied"],
                )
            )

        return verification_summary

    def _verify_single_feature(
        self,
        api_feature_name,
        user_friendly_name,
        desired_config,
        original_config,
        post_config,
    ):
        """
        Verifies a single feature configuration by comparing desired vs deployed state.
        Args:
            api_feature_name (str): API feature name
            user_friendly_name (str): User-friendly feature name
            desired_config (dict): Desired configuration for this feature
            original_config (dict): Original deployed configuration
            post_config (dict): Current deployed configuration
        Returns:
            dict: Verification result for this feature
        """
        self.log(
            "Performing detailed verification for feature: {0}".format(
                user_friendly_name
            ),
            "DEBUG",
        )

        # Extract actual configuration items
        original_items = (
            original_config.get("response", {})
            .get(api_feature_name, {})
            .get("items", [])
        )
        post_items = (
            post_config.get("response", {}).get(api_feature_name, {}).get("items", [])
        )
        desired_items = desired_config.get("items", [])

        self.log("Original items count: {0}".format(len(original_items)), "DEBUG")
        self.log("Post-operation items count: {0}".format(len(post_items)), "DEBUG")
        self.log("Desired items count: {0}".format(len(desired_items)), "DEBUG")

        # Check if configuration exists post-operation
        if not post_items:
            return {
                "status": "not_found",
                "message": "{0} configuration not found after deployment".format(
                    user_friendly_name
                ),
                "details": "Expected configuration items but found none in deployed state",
            }

        # Perform feature-type specific verification
        if self._is_vlan_feature(api_feature_name):
            return self._verify_vlan_configuration(
                user_friendly_name, desired_items, post_items, original_items
            )
        elif self._is_global_feature(api_feature_name):
            return self._verify_global_configuration(
                user_friendly_name, desired_items, post_items, original_items
            )
        elif self._is_interface_feature(api_feature_name):
            return self._verify_interface_configuration(
                user_friendly_name, desired_items, post_items, original_items
            )
        else:
            return self._verify_default_configuration(
                user_friendly_name, desired_items, post_items, original_items
            )

    def _verify_vlan_configuration(
        self, user_friendly_name, desired_items, post_items, original_items
    ):
        """
        Verifies VLAN configuration by checking individual VLAN parameters.
        Args:
            user_friendly_name (str): User-friendly name for the VLAN feature
            desired_items (list): List of desired VLAN configuration items
            post_items (list): List of post-operation deployed VLAN items
            original_items (list): List of original VLAN configuration items
        Returns:
            dict: Verification result containing status, message, and details
        """
        self.log("Verifying VLAN configuration details", "DEBUG")

        # Create lookup for deployed VLANs by ID
        post_vlan_lookup = {item.get("vlanId"): item for item in post_items}

        verified_vlans = []
        failed_vlans = []

        for desired_vlan in desired_items:
            vlan_id = desired_vlan.get("vlanId")
            post_vlan = post_vlan_lookup.get(vlan_id)

            if not post_vlan:
                failed_vlans.append(
                    "VLAN {0} not found in deployed configuration".format(vlan_id)
                )
                continue

            # Verify VLAN parameters
            vlan_verification = self._verify_vlan_parameters(desired_vlan, post_vlan)

            if vlan_verification["success"]:
                verified_vlans.append("VLAN {0}".format(vlan_id))
                self.log(
                    "VLAN {0} verification successful: {1}".format(
                        vlan_id, vlan_verification["details"]
                    ),
                    "DEBUG",
                )
            else:
                failed_vlans.append(
                    "VLAN {0}: {1}".format(vlan_id, vlan_verification["details"])
                )
                self.log(
                    "VLAN {0} verification failed: {1}".format(
                        vlan_id, vlan_verification["details"]
                    ),
                    "DEBUG",
                )

        if failed_vlans:
            return {
                "status": "failed",
                "message": "{0} verification failed for VLANs: {1}".format(
                    user_friendly_name, ", ".join(failed_vlans)
                ),
                "details": "Successfully verified: {0}, Failed: {1}".format(
                    len(verified_vlans), len(failed_vlans)
                ),
            }
        else:
            return {
                "status": "success",
                "message": "{0} successfully verified for {1} VLANs".format(
                    user_friendly_name, len(verified_vlans)
                ),
                "details": "All requested VLAN configurations match deployed state",
            }

    def _verify_global_configuration(
        self, user_friendly_name, desired_items, post_items, original_items
    ):
        """
        Verifies global configuration (single item configurations like CDP, LLDP, etc.).
        Args:
            user_friendly_name (str): User-friendly name for the global feature
            desired_items (list): List of desired global configuration items
            post_items (list): List of post-operation deployed global items
            original_items (list): List of original global configuration items
        Returns:
            dict: Verification result containing status, message, and details
        """
        self.log(
            "Verifying global configuration details for {0}".format(user_friendly_name),
            "DEBUG",
        )

        if not desired_items or not post_items:
            return {
                "status": "failed",
                "message": "{0} verification failed - missing configuration items".format(
                    user_friendly_name
                ),
                "details": "Expected configuration items but found incomplete data",
            }

        desired_item = desired_items[0]
        post_item = post_items[0]

        # Verify configuration parameters
        verification_result = self._verify_configuration_parameters(
            desired_item, post_item
        )

        if verification_result["success"]:
            return {
                "status": "success",
                "message": "{0} successfully verified and deployed".format(
                    user_friendly_name
                ),
                "details": verification_result["details"],
            }
        else:
            return {
                "status": "failed",
                "message": "{0} verification failed: {1}".format(
                    user_friendly_name, verification_result["details"]
                ),
                "details": "Configuration parameters do not match expected values",
            }

    def _verify_interface_configuration(
        self, user_friendly_name, desired_items, post_items, original_items
    ):
        """
        Verifies interface configuration by checking individual interface parameters.
        Args:
            user_friendly_name (str): User-friendly name for the interface feature
            desired_items (list): List of desired interface configuration items
            post_items (list): List of post-operation deployed interface items
            original_items (list): List of original interface configuration items
        Returns:
            dict: Verification result containing status, message, and details
        """
        self.log(
            "Verifying interface configuration details for {0}".format(
                user_friendly_name
            ),
            "DEBUG",
        )

        # Create lookup for deployed interfaces by name
        post_interface_lookup = {item.get("interfaceName"): item for item in post_items}

        verified_interfaces = []
        failed_interfaces = []

        for desired_interface in desired_items:
            interface_name = desired_interface.get("interfaceName")
            post_interface = post_interface_lookup.get(interface_name)

            if not post_interface:
                failed_interfaces.append(
                    "Interface {0} not found in deployed configuration".format(
                        interface_name
                    )
                )
                continue

            # Verify interface parameters
            interface_verification = self._verify_configuration_parameters(
                desired_interface, post_interface
            )

            if interface_verification["success"]:
                verified_interfaces.append("Interface {0}".format(interface_name))
                self.log(
                    "Interface {0} verification successful: {1}".format(
                        interface_name, interface_verification["details"]
                    ),
                    "DEBUG",
                )
            else:
                failed_interfaces.append(
                    "Interface {0}: {1}".format(
                        interface_name, interface_verification["details"]
                    )
                )
                self.log(
                    "Interface {0} verification failed: {1}".format(
                        interface_name, interface_verification["details"]
                    ),
                    "DEBUG",
                )

        if failed_interfaces:
            return {
                "status": "failed",
                "message": "{0} verification failed for interfaces: {1}".format(
                    user_friendly_name, ", ".join(failed_interfaces)
                ),
                "details": "Successfully verified: {0}, Failed: {1}".format(
                    len(verified_interfaces), len(failed_interfaces)
                ),
            }
        else:
            return {
                "status": "success",
                "message": "{0} successfully verified for {1} interfaces".format(
                    user_friendly_name, len(verified_interfaces)
                ),
                "details": "All requested interface configurations match deployed state",
            }

    def _verify_default_configuration(
        self, user_friendly_name, desired_items, post_items, original_items
    ):
        """
        Default verification for other configuration types.
        Args:
            user_friendly_name (str): User-friendly name for the configuration feature
            desired_items (list): List of desired configuration items
            post_items (list): List of post-operation deployed items
            original_items (list): List of original configuration items
        Returns:
            dict: Verification result containing status, message, and details
        """
        self.log(
            "Verifying default configuration for {0}".format(user_friendly_name),
            "DEBUG",
        )

        verified_items = 0
        failed_items = 0

        for i, desired_item in enumerate(desired_items):
            if i < len(post_items):
                post_item = post_items[i]

                verification_result = self._verify_configuration_parameters(
                    desired_item, post_item
                )

                if verification_result["success"]:
                    verified_items += 1
                else:
                    failed_items += 1
                    self.log(
                        "Item {0} verification failed: {1}".format(
                            i, verification_result["details"]
                        ),
                        "DEBUG",
                    )
            else:
                failed_items += 1
                self.log(
                    "Item {0} not found in deployed configuration".format(i), "DEBUG"
                )

        if failed_items > 0:
            return {
                "status": "failed",
                "message": "{0} verification failed for {1} items".format(
                    user_friendly_name, failed_items
                ),
                "details": "Successfully verified: {0}, Failed: {1}".format(
                    verified_items, failed_items
                ),
            }
        else:
            return {
                "status": "success",
                "message": "{0} successfully verified for all {1} items".format(
                    user_friendly_name, verified_items
                ),
                "details": "All configuration items match deployed state",
            }

    def _verify_vlan_parameters(self, desired_vlan, post_vlan):
        """
        Verifies individual VLAN parameters.
        Args:
            desired_vlan (dict): Desired VLAN configuration parameters
            post_vlan (dict): Post-operation deployed VLAN configuration
        Returns:
            dict: Verification result with success status and details
        """
        verification_details = []
        verification_success = True

        # Check VLAN name
        if "name" in desired_vlan:
            desired_name = desired_vlan["name"]
            post_name = post_vlan.get("name", "")
            if desired_name != post_name:
                verification_success = False
                verification_details.append(
                    "Name mismatch: expected '{0}', found '{1}'".format(
                        desired_name, post_name
                    )
                )
                self.log(
                    "VLAN name verification failed: expected '{0}', found '{1}'".format(
                        desired_name, post_name
                    ),
                    "DEBUG",
                )
            else:
                verification_details.append("Name verified: '{0}'".format(desired_name))
                self.log(
                    "VLAN name verification successful: '{0}'".format(desired_name),
                    "DEBUG",
                )

        # Check VLAN admin status
        if "isVlanEnabled" in desired_vlan:
            desired_status = desired_vlan["isVlanEnabled"]
            post_status = post_vlan.get("isVlanEnabled", True)
            if desired_status != post_status:
                verification_success = False
                verification_details.append(
                    "Admin status mismatch: expected {0}, found {1}".format(
                        desired_status, post_status
                    )
                )
                self.log(
                    "VLAN admin status verification failed: expected {0}, found {1}".format(
                        desired_status, post_status
                    ),
                    "DEBUG",
                )
            else:
                verification_details.append(
                    "Admin status verified: {0}".format(desired_status)
                )
                self.log(
                    "VLAN admin status verification successful: {0}".format(
                        desired_status
                    ),
                    "DEBUG",
                )

        self.log(
            "VLAN parameter verification completed: success={0}, details={1}".format(
                verification_success, len(verification_details)
            ),
            "DEBUG",
        )

        return {
            "success": verification_success,
            "details": (
                "; ".join(verification_details)
                if verification_details
                else "All parameters verified"
            ),
        }

    def _verify_configuration_parameters(self, desired_config, post_config):
        """
        Verifies configuration parameters by comparing desired vs deployed values.
        Args:
            desired_config (dict): Desired configuration parameters
            post_config (dict): Deployed configuration parameters
        Returns:
            dict: Verification result with success status and parameter details
        """
        verification_details = []
        verification_success = True
        verified_params = 0

        # Compare all parameters except configType
        for param, desired_value in desired_config.items():
            if param == "configType":
                continue

            post_value = post_config.get(param)

            # Handle different types of comparisons
            if self._values_match(desired_value, post_value):
                verified_params += 1
                verification_details.append("✓ {0}: verified".format(param))
                self.log(
                    "Parameter '{0}' verified successfully: {1}".format(
                        param, desired_value
                    ),
                    "DEBUG",
                )
            else:
                verification_success = False
                verification_details.append(
                    "✗ {0}: expected '{1}', found '{2}'".format(
                        param, desired_value, post_value
                    )
                )
                self.log(
                    "Parameter '{0}' verification failed: expected '{1}', found '{2}'".format(
                        param, desired_value, post_value
                    ),
                    "DEBUG",
                )

        summary = "Verified {0} parameters".format(verified_params)
        if not verification_success:
            failed_count = len([d for d in verification_details if d.startswith("✗")])
            summary += ", {0} failed".format(failed_count)

        self.log(
            "Configuration parameter verification completed: success={0}, verified={1}".format(
                verification_success, verified_params
            ),
            "DEBUG",
        )

        return {
            "success": verification_success,
            "details": summary,
            "parameter_details": verification_details,
        }

    def _values_match(self, desired, current):
        """
        Compare two values for equality, handling different data types appropriately.
        Args:
            desired: The desired value to compare
            current: The current value to compare against
        Returns:
            bool: True if values match, False otherwise
        """
        if not isinstance(desired, type(current)) and not isinstance(current, type(desired)):
            self.log(
                "Type mismatch detected: desired={0}, current={1}".format(
                    type(desired).__name__, type(current).__name__
                ),
                "DEBUG",
            )
            return False

        if isinstance(desired, list):
            self.log(
                "Comparing list values with lengths: desired={0}, current={1}".format(
                    len(desired), len(current)
                ),
                "DEBUG",
            )
            if len(desired) != len(current):
                self.log(
                    "List length mismatch: desired={0}, current={1}".format(
                        len(desired), len(current)
                    ),
                    "DEBUG",
                )
                return False

            # For lists containing dictionaries, we need to handle comparison differently
            if desired and isinstance(desired[0], dict):
                self.log(
                    "Found list of dictionaries, using specialized comparison method",
                    "DEBUG",
                )
                return self._compare_dict_lists(desired, current)
            else:
                # For lists of simple types, sort and compare
                try:
                    sorted_comparison = all(
                        self._values_match(d, c)
                        for d, c in zip(sorted(desired), sorted(current))
                    )
                    self.log("Sorted list comparison completed successfully", "DEBUG")
                    return sorted_comparison
                except TypeError:
                    # If sorting fails, compare without sorting (order matters)
                    self.log(
                        "Sorting failed, comparing lists in original order", "DEBUG"
                    )
                    return all(
                        self._values_match(d, c) for d, c in zip(desired, current)
                    )

        elif isinstance(desired, dict):
            self.log(
                "Comparing dictionary values with keys: desired={0}, current={1}".format(
                    len(desired), len(current)
                ),
                "DEBUG",
            )
            if set(desired.keys()) != set(current.keys()):
                self.log(
                    "Dictionary key sets differ between desired and current values",
                    "DEBUG",
                )
                return False
            dict_comparison = all(
                self._values_match(desired[key], current[key]) for key in desired.keys()
            )
            self.log(
                "Dictionary comparison completed: {0}".format(dict_comparison), "DEBUG"
            )
            return dict_comparison

        else:
            # Direct comparison for simple types
            simple_comparison = desired == current
            self.log(
                "Simple value comparison result: {0} (desired='{1}', current='{2}')".format(
                    simple_comparison, desired, current
                ),
                "DEBUG",
            )
            return simple_comparison

    def _compare_dict_lists(self, desired_list, current_list):
        """
        Compare two lists of dictionaries by finding matching items based on key fields.
        Args:
            desired_list (list): List of desired dictionary items to compare
            current_list (list): List of current dictionary items to compare against
        Returns:
            bool: True if lists match, False otherwise
        """
        if len(desired_list) != len(current_list):
            self.log(
                "List length mismatch: desired={0}, current={1}".format(
                    len(desired_list), len(current_list)
                ),
                "DEBUG",
            )
            return False

        # For STP instances, use vlanId as the key for matching
        if desired_list and "vlanId" in desired_list[0]:
            self.log(
                "Using vlanId-based matching for STP instances comparison", "DEBUG"
            )

            desired_by_vlan = {item["vlanId"]: item for item in desired_list}
            current_by_vlan = {item["vlanId"]: item for item in current_list}

            self.log(
                "Created VLAN lookup tables: desired={0} VLANs, current={1} VLANs".format(
                    len(desired_by_vlan), len(current_by_vlan)
                ),
                "DEBUG",
            )

            if set(desired_by_vlan.keys()) != set(current_by_vlan.keys()):
                self.log(
                    "VLAN ID sets differ between desired and current lists", "DEBUG"
                )
                return False

            # Compare each VLAN's configuration
            for vlan_id in desired_by_vlan.keys():
                if not self._values_match(
                    desired_by_vlan[vlan_id], current_by_vlan[vlan_id]
                ):
                    self.log(
                        "VLAN {0} configuration mismatch found".format(vlan_id), "DEBUG"
                    )
                    return False
                self.log("VLAN {0} configuration matches".format(vlan_id), "DEBUG")

            self.log("All STP instances match successfully", "DEBUG")
            return True

        # For other types of dict lists, try to match by content
        self.log("Using content-based matching for generic dictionary lists", "DEBUG")
        current_list_copy = current_list.copy()

        for i, desired_item in enumerate(desired_list):
            self.log("Looking for match for desired item {0}".format(i), "DEBUG")
            found_match = False

            for j, current_item in enumerate(current_list_copy):
                if self._values_match(desired_item, current_item):
                    current_list_copy.pop(j)
                    found_match = True
                    self.log(
                        "Found match for desired item {0} at current position {1}".format(
                            i, j
                        ),
                        "DEBUG",
                    )
                    break

            if not found_match:
                self.log("No match found for desired item {0}".format(i), "DEBUG")
                return False

        remaining_items = len(current_list_copy)
        self.log(
            "Content-based comparison completed: remaining unmatched items={0}".format(
                remaining_items
            ),
            "DEBUG",
        )

        return remaining_items == 0

    def _analyze_deletion_requirements(self, want_feature_mappings):
        """
        Analyzes deletion requirements and categorizes features by deletion type.
        Args:
            want_feature_mappings (dict): User feature mappings for deletion
        Returns:
            dict: Analysis results containing deletion requirements by type
        """
        self.log("Starting deletion requirements analysis", "INFO")

        # Extract data from have state
        deployed_configs = self.have.get("current_deployed_configs", {})
        intended_configs = self.have.get("current_intended_configs", {})
        network_device_id = self.have.get("network_device_id")

        self.log("Extracted configuration data for deletion analysis", "DEBUG")
        self.log("Network device ID: {0}".format(network_device_id), "DEBUG")
        self.log(
            "Available deployed configs: {0}".format(list(deployed_configs.keys())),
            "DEBUG",
        )
        self.log(
            "Available intended configs: {0}".format(list(intended_configs.keys())),
            "DEBUG",
        )

        # Initialize deletion analysis structure with all feature type categories
        deletion_analysis = {
            "network_device_id": network_device_id,
            "type1_global_resets": {},  # cdp, lldp, vtp, dhcp_snooping, authentication
            "type2_vlan_deletions": {},  # vlans
            "type3_hybrid_features": {},  # stp, igmp_snooping, mld_snooping, logical_ports
            "type4_port_configurations": {},  # port_configuration
            "summary": {
                "total_features": len(want_feature_mappings),
                "type1_features": 0,
                "type2_features": 0,
                "type3_features": 0,
                "type4_features": 0,
            },
        }

        self.log(
            "Initialized deletion analysis structure for {0} features".format(
                len(want_feature_mappings)
            ),
            "DEBUG",
        )

        # Process each user feature mapping to determine deletion type and requirements
        for user_feature_name, user_feature_config in want_feature_mappings.items():
            self.log(
                "Analyzing deletion for user feature: {0}".format(user_feature_name),
                "DEBUG",
            )
            self.log(
                "User feature config structure: {0}".format(user_feature_config),
                "DEBUG",
            )

            # Determine deletion type and process accordingly
            deletion_type = self._determine_deletion_type(
                user_feature_name, user_feature_config
            )
            self.log(
                "Determined deletion type '{0}' for feature: {1}".format(
                    deletion_type, user_feature_name
                ),
                "DEBUG",
            )

            if deletion_type == "type1":
                self.log(
                    "Processing Type 1 deletion (global reset) for feature: {0}".format(
                        user_feature_name
                    ),
                    "DEBUG",
                )
                self._analyze_type1_deletion(
                    user_feature_name,
                    user_feature_config,
                    deployed_configs,
                    intended_configs,
                    deletion_analysis,
                )
                deletion_analysis["summary"]["type1_features"] += 1

            elif deletion_type == "type2":
                self.log(
                    "Processing Type 2 deletion (VLAN deletion) for feature: {0}".format(
                        user_feature_name
                    ),
                    "DEBUG",
                )
                self._analyze_type2_deletion(
                    user_feature_name,
                    user_feature_config,
                    deployed_configs,
                    intended_configs,
                    deletion_analysis,
                )
                deletion_analysis["summary"]["type2_features"] += 1

            elif deletion_type == "type3":
                self.log(
                    "Processing Type 3 deletion (hybrid feature) for feature: {0}".format(
                        user_feature_name
                    ),
                    "DEBUG",
                )
                self._analyze_type3_deletion(
                    user_feature_name,
                    user_feature_config,
                    deployed_configs,
                    intended_configs,
                    deletion_analysis,
                )
                deletion_analysis["summary"]["type3_features"] += 1

            elif deletion_type == "type4":
                self.log(
                    "Processing Type 4 deletion (port configuration) for feature: {0}".format(
                        user_feature_name
                    ),
                    "DEBUG",
                )
                self._analyze_type4_deletion(
                    user_feature_name,
                    user_feature_config,
                    deployed_configs,
                    intended_configs,
                    deletion_analysis,
                )
                deletion_analysis["summary"]["type4_features"] += 1
            else:
                self.log(
                    "Unknown deletion type '{0}' for feature: {1}".format(
                        deletion_type, user_feature_name
                    ),
                    "WARNING",
                )

        self.log("Completed deletion analysis for all features", "INFO")
        self.log(
            "Deletion analysis completed: {0}".format(deletion_analysis["summary"]),
            "INFO",
        )
        self.log(
            "Type 1 features: {0}".format(
                deletion_analysis["summary"]["type1_features"]
            ),
            "DEBUG",
        )
        self.log(
            "Type 2 features: {0}".format(
                deletion_analysis["summary"]["type2_features"]
            ),
            "DEBUG",
        )
        self.log(
            "Type 3 features: {0}".format(
                deletion_analysis["summary"]["type3_features"]
            ),
            "DEBUG",
        )
        self.log(
            "Type 4 features: {0}".format(
                deletion_analysis["summary"]["type4_features"]
            ),
            "DEBUG",
        )

        return deletion_analysis

    def _determine_deletion_type(self, user_feature_name, user_feature_config):
        """
        Determines the deletion type for a given feature.
        Args:
            user_feature_name (str): Name of the user feature
            user_feature_config (dict): User feature configuration
        Returns:
            str: Deletion type (type1, type2, type3, type4)
        """
        self.log(
            "Starting deletion type determination for feature: {0}".format(
                user_feature_name
            ),
            "DEBUG",
        )
        self.log(
            "Analyzing feature configuration for deletion type classification", "DEBUG"
        )

        # Type 1: Global configs that support only resetting to default settings
        type1_features = ["cdp", "lldp", "vtp", "dhcp_snooping", "authentication"]

        # Type 2: VLANs (Delete vlans using update intent API)
        type2_features = ["vlans"]

        # Type 3: Configs with global parameters plus components
        type3_features = ["stp", "igmp_snooping", "mld_snooping", "logical_ports"]

        # Type 4: Port configurations
        type4_features = ["port_configuration"]

        self.log(
            "Checking feature '{0}' against Type 1 features (global reset): {1}".format(
                user_feature_name, type1_features
            ),
            "DEBUG",
        )
        if user_feature_name in type1_features:
            self.log(
                "Feature '{0}' classified as Type 1 deletion (global reset)".format(
                    user_feature_name
                ),
                "DEBUG",
            )
            return "type1"

        self.log(
            "Checking feature '{0}' against Type 2 features (VLAN deletion): {1}".format(
                user_feature_name, type2_features
            ),
            "DEBUG",
        )
        if user_feature_name in type2_features:
            self.log(
                "Feature '{0}' classified as Type 2 deletion (VLAN deletion)".format(
                    user_feature_name
                ),
                "DEBUG",
            )
            return "type2"

        self.log(
            "Checking feature '{0}' against Type 3 features (hybrid features): {1}".format(
                user_feature_name, type3_features
            ),
            "DEBUG",
        )
        if user_feature_name in type3_features:
            self.log(
                "Feature '{0}' classified as Type 3 deletion (hybrid feature)".format(
                    user_feature_name
                ),
                "DEBUG",
            )
            return "type3"

        self.log(
            "Checking feature '{0}' against Type 4 features (port configurations): {1}".format(
                user_feature_name, type4_features
            ),
            "DEBUG",
        )
        if user_feature_name in type4_features:
            self.log(
                "Feature '{0}' classified as Type 4 deletion (port configuration)".format(
                    user_feature_name
                ),
                "DEBUG",
            )
            return "type4"

        self.log(
            "Unknown feature type for deletion: {0}".format(user_feature_name),
            "WARNING",
        )
        self.log(
            "Feature '{0}' does not match any known deletion type patterns".format(
                user_feature_name
            ),
            "DEBUG",
        )
        return "unknown"

    def _analyze_type1_deletion(
        self,
        user_feature_name,
        user_feature_config,
        deployed_configs,
        intended_configs,
        deletion_analysis,
    ):
        """
        Analyzes Type 1 deletion requirements (global config resets).
        Args:
            user_feature_name (str): Name of the user feature
            user_feature_config (dict): User feature configuration
            deployed_configs (dict): Current deployed configurations
            intended_configs (dict): Current intended configurations
            deletion_analysis (dict): Analysis results to populate
        """
        self.log(
            "Analyzing Type 1 deletion for feature: {0}".format(user_feature_name),
            "DEBUG",
        )

        # Get the API feature name
        api_feature_name = list(user_feature_config.keys())[0]

        # Check if deployed configuration exists
        deployed_config = deployed_configs.get(api_feature_name, {})
        intended_config = intended_configs.get(api_feature_name, {})

        deployed_items = (
            deployed_config.get("response", {})
            .get(api_feature_name, {})
            .get("items", [])
        )
        intended_items = (
            intended_config.get("response", {})
            .get(api_feature_name, {})
            .get("items", [])
        )

        if not deployed_items:
            self.log(
                "No deployed configuration found for {0}, skipping deletion".format(
                    user_feature_name
                ),
                "INFO",
            )
            return

        deletion_analysis["type1_global_resets"][user_feature_name] = {
            "api_feature_name": api_feature_name,
            "has_deployed_config": bool(deployed_items),
            "has_intended_config": bool(intended_items),
            "deployed_config": deployed_config,
            "intended_config": intended_config,
            "operation_sequence": self._determine_type1_operation_sequence(
                bool(deployed_items), bool(intended_items)
            ),
        }

    def _analyze_type2_deletion(
        self,
        user_feature_name,
        user_feature_config,
        deployed_configs,
        intended_configs,
        deletion_analysis,
    ):
        """
        Analyzes Type 2 deletion requirements (VLAN deletions).
        Args:
            user_feature_name (str): Name of the user feature
            user_feature_config (dict): User feature configuration
            deployed_configs (dict): Current deployed configurations
            intended_configs (dict): Current intended configurations
            deletion_analysis (dict): Analysis results to populate
        """
        self.log(
            "Analyzing Type 2 deletion for feature: {0}".format(user_feature_name),
            "DEBUG",
        )

        # Get the API feature name
        api_feature_name = list(user_feature_config.keys())[0]
        desired_vlans = user_feature_config[api_feature_name].get("items", [])

        # Get current configurations
        deployed_config = deployed_configs.get(api_feature_name, {})
        intended_config = intended_configs.get(api_feature_name, {})

        deployed_items = (
            deployed_config.get("response", {})
            .get(api_feature_name, {})
            .get("items", [])
        )
        intended_items = (
            intended_config.get("response", {})
            .get(api_feature_name, {})
            .get("items", [])
        )

        # Create lookup for deployed VLANs by ID
        deployed_vlan_lookup = {vlan.get("vlanId"): vlan for vlan in deployed_items}
        intended_vlan_lookup = {vlan.get("vlanId"): vlan for vlan in intended_items}

        # Analyze which VLANs can be deleted
        vlans_to_delete = []
        vlans_to_skip = []

        for desired_vlan in desired_vlans:
            vlan_id = desired_vlan.get("vlanId")

            if vlan_id in deployed_vlan_lookup:
                vlans_to_delete.append(
                    {
                        "vlan_id": vlan_id,
                        "deployed_config": deployed_vlan_lookup[vlan_id],
                        "in_intended": vlan_id in intended_vlan_lookup,
                        "intended_config": intended_vlan_lookup.get(vlan_id),
                    }
                )
            else:
                vlans_to_skip.append(vlan_id)
                self.log(
                    "VLAN {0} not found in deployed config, skipping deletion".format(
                        vlan_id
                    ),
                    "INFO",
                )

        if vlans_to_delete or vlans_to_skip:
            deletion_analysis["type2_vlan_deletions"][user_feature_name] = {
                "api_feature_name": api_feature_name,
                "vlans_to_delete": vlans_to_delete,
                "vlans_to_skip": vlans_to_skip,
                "has_intended_config": bool(intended_items),
                "deployed_config": deployed_config,
                "intended_config": intended_config,
                "operation_sequence": self._determine_type2_operation_sequence(
                    vlans_to_delete, bool(intended_items)
                ),
            }

    def _analyze_type3_deletion(
        self,
        user_feature_name,
        user_feature_config,
        deployed_configs,
        intended_configs,
        deletion_analysis,
    ):
        """
        Analyzes Type 3 deletion requirements (hybrid features - not supported due to beta APIs).
        Args:
            user_feature_name (str): Name of the user feature
            user_feature_config (dict): User feature configuration
            deployed_configs (dict): Current deployed configurations
            intended_configs (dict): Current intended configurations
            deletion_analysis (dict): Analysis results to populate
        """
        self.log(
            "Type 3 deletion requested for feature: {0}".format(user_feature_name),
            "INFO",
        )
        self.log(
            "DELETION NOT SUPPORTED: Feature '{0}' deletion is not implemented due to beta API limitations".format(
                user_feature_name
            ),
            "INFO",
        )

        # Get the API feature name for logging purposes
        api_feature_name = (
            list(user_feature_config.keys())[0] if user_feature_config else "unknown"
        )

        deletion_analysis["type3_hybrid_features"][user_feature_name] = {
            "api_feature_name": api_feature_name,
            "status": "not_supported",
            "reason": "Feature deletion not implemented - underlying APIs are in beta",
            "message": "Deletion for {0} is not supported due to beta API limitations".format(
                user_feature_name
            ),
        }

    def _analyze_type4_deletion(
        self,
        user_feature_name,
        user_feature_config,
        deployed_configs,
        intended_configs,
        deletion_analysis,
    ):
        """
        Analyzes Type 4 deletion requirements (port configurations - not supported due to beta APIs).
        Args:
            user_feature_name (str): Name of the user feature
            user_feature_config (dict): User feature configuration
            deployed_configs (dict): Current deployed configurations
            intended_configs (dict): Current intended configurations
            deletion_analysis (dict): Analysis results to populate
        """
        self.log(
            "Type 4 deletion requested for feature: {0}".format(user_feature_name),
            "INFO",
        )
        self.log(
            "DELETION NOT SUPPORTED: Feature '{0}' deletion is not implemented due to beta API limitations".format(
                user_feature_name
            ),
            "INFO",
        )

        # Get the API feature name for logging purposes
        api_feature_name = (
            list(user_feature_config.keys())[0] if user_feature_config else "unknown"
        )

        deletion_analysis["type4_port_configurations"][user_feature_name] = {
            "api_feature_name": api_feature_name,
            "status": "not_supported",
            "reason": "Feature deletion not implemented - underlying APIs are in beta",
            "message": "Deletion for {0} is not supported due to beta API limitations".format(
                user_feature_name
            ),
        }

    def _determine_type1_operation_sequence(self, has_deployed, has_intended):
        """
        Determines operation sequence for Type 1 deletions.
        Args:
            has_deployed (bool): Whether deployed configuration exists
            has_intended (bool): Whether intended configuration exists
        Returns:
            str: Operation sequence identifier for Type 1 deletion
        """
        self.log(
            "Starting operation sequence determination for Type 1 deletion", "DEBUG"
        )
        self.log(
            "Configuration state analysis: deployed={0}, intended={1}".format(
                has_deployed, has_intended
            ),
            "DEBUG",
        )

        if not has_deployed:
            self.log(
                "No deployed configuration found - skipping deletion operation", "DEBUG"
            )
            self.log("Operation sequence determined: skip_no_deployed", "DEBUG")
            return "skip_no_deployed"
        else:
            self.log(
                "Deployed configuration exists - proceeding with deletion and deployment",
                "DEBUG",
            )
            self.log("Operation sequence determined: delete_intent_and_deploy", "DEBUG")
            # Simplified - the delete operation will handle intent creation if needed
            return "delete_intent_and_deploy"

    def _determine_type2_operation_sequence(self, vlans_to_delete, has_intended):
        """
        Determines operation sequence for Type 2 deletions.
        Args:
            vlans_to_delete (list): List of VLANs to delete
            has_intended (bool): Whether intended config exists
        Returns:
            str: Operation sequence identifier
        """
        self.log(
            "Starting operation sequence determination for Type 2 deletion", "DEBUG"
        )
        self.log("VLANs to delete count: {0}".format(len(vlans_to_delete)), "DEBUG")
        self.log("Intended configuration exists: {0}".format(has_intended), "DEBUG")

        if not vlans_to_delete:
            self.log("No VLANs found for deletion - skipping operation", "DEBUG")
            self.log("Operation sequence determined: skip_no_vlans", "DEBUG")
            return "skip_no_vlans"
        elif has_intended:
            self.log(
                "Intended configuration exists - updating existing intent to remove VLANs",
                "DEBUG",
            )
            self.log(
                "Operation sequence determined: update_intent_remove_vlans_and_deploy",
                "DEBUG",
            )
            return "update_intent_remove_vlans_and_deploy"
        else:
            self.log(
                "No intended configuration found - creating intent, updating, and deploying",
                "DEBUG",
            )
            self.log(
                "Operation sequence determined: create_intent_update_remove_and_deploy",
                "DEBUG",
            )
            return "create_intent_update_remove_and_deploy"

    def _execute_deletion_operations(
        self, deletion_analysis, network_device_id, device_identifier
    ):
        """
        Executes all deletion operations based on the analysis.
        Args:
            deletion_analysis (dict): Analysis results from _analyze_deletion_requirements
            network_device_id (str): Network device ID
            device_identifier (str): Device identifier for logging
        Returns:
            dict: Results of all deletion operations
        """
        self.log(
            "Starting execution of deletion operations for device {0}".format(
                device_identifier
            ),
            "INFO",
        )

        deletion_results = {
            "executed_operations": {},
            "summary": {
                "total_operations": 0,
                "successful_operations": 0,
                "failed_operations": 0,
                "skipped_operations": 0,
            },
            "deployment_results": [],
        }

        failed_operations = []

        # Execute Type 1 deletions (global resets)
        if deletion_analysis.get("type1_global_resets"):
            self.log("Executing Type 1 global reset operations", "INFO")
            for feature_name, analysis in deletion_analysis[
                "type1_global_resets"
            ].items():
                try:
                    result = self._execute_type1_deletion(
                        feature_name, analysis, network_device_id
                    )
                    deletion_results["executed_operations"][feature_name] = result
                    deletion_results["summary"]["total_operations"] += 1

                    if result.get("status") == "success":
                        deletion_results["summary"]["successful_operations"] += 1
                    else:
                        deletion_results["summary"]["failed_operations"] += 1
                        failed_operations.append(
                            {"feature": feature_name, "error": result.get("error")}
                        )

                except Exception as e:
                    error_msg = "Exception during Type 1 deletion for {0}: {1}".format(
                        feature_name, str(e)
                    )
                    self.log(error_msg, "ERROR")
                    failed_operations.append(
                        {"feature": feature_name, "error": error_msg}
                    )
                    deletion_results["summary"]["failed_operations"] += 1

        # Execute Type 2 deletions (VLAN deletions)
        if deletion_analysis.get("type2_vlan_deletions"):
            self.log("Executing Type 2 VLAN deletion operations", "INFO")
            for feature_name, analysis in deletion_analysis[
                "type2_vlan_deletions"
            ].items():
                try:
                    result = self._execute_type2_deletion(
                        feature_name, analysis, network_device_id
                    )
                    deletion_results["executed_operations"][feature_name] = result
                    deletion_results["summary"]["total_operations"] += 1

                    if result.get("status") == "success":
                        deletion_results["summary"]["successful_operations"] += 1
                    elif result.get("status") == "skipped":
                        deletion_results["summary"]["skipped_operations"] += 1
                    else:
                        deletion_results["summary"]["failed_operations"] += 1
                        failed_operations.append(
                            {"feature": feature_name, "error": result.get("error")}
                        )

                except Exception as e:
                    error_msg = "Exception during Type 2 deletion for {0}: {1}".format(
                        feature_name, str(e)
                    )
                    self.log(error_msg, "ERROR")
                    failed_operations.append(
                        {"feature": feature_name, "error": error_msg}
                    )
                    deletion_results["summary"]["failed_operations"] += 1

        # Execute Type 3 deletions (hybrid features)
        if deletion_analysis.get("type3_hybrid_features"):
            self.log("Processing Type 3 hybrid feature deletion requests", "INFO")
            for feature_name, analysis in deletion_analysis[
                "type3_hybrid_features"
            ].items():
                try:
                    result = self._execute_type3_deletion(
                        feature_name, analysis, network_device_id
                    )
                    deletion_results["executed_operations"][feature_name] = result
                    deletion_results["summary"]["total_operations"] += 1

                    if result.get("status") == "success":
                        deletion_results["summary"]["successful_operations"] += 1
                    elif result.get("status") in ["skipped", "not_supported"]:
                        deletion_results["summary"]["skipped_operations"] += 1
                    else:
                        deletion_results["summary"]["failed_operations"] += 1
                        failed_operations.append(
                            {"feature": feature_name, "error": result.get("error")}
                        )

                except Exception as e:
                    error_msg = "Exception during Type 3 deletion for {0}: {1}".format(
                        feature_name, str(e)
                    )
                    self.log(error_msg, "ERROR")
                    failed_operations.append(
                        {"feature": feature_name, "error": error_msg}
                    )
                    deletion_results["summary"]["failed_operations"] += 1

        # Execute Type 4 deletions (port configurations)
        if deletion_analysis.get("type4_port_configurations"):
            self.log("Processing Type 4 port configuration deletion requests", "INFO")
            for feature_name, analysis in deletion_analysis[
                "type4_port_configurations"
            ].items():
                try:
                    result = self._execute_type4_deletion(
                        feature_name, analysis, network_device_id
                    )
                    deletion_results["executed_operations"][feature_name] = result
                    deletion_results["summary"]["total_operations"] += 1

                    if result.get("status") == "success":
                        deletion_results["summary"]["successful_operations"] += 1
                    elif result.get("status") in ["skipped", "not_supported"]:
                        deletion_results["summary"]["skipped_operations"] += 1
                    else:
                        deletion_results["summary"]["failed_operations"] += 1
                        failed_operations.append(
                            {"feature": feature_name, "error": result.get("error")}
                        )

                except Exception as e:
                    error_msg = "Exception during Type 4 deletion for {0}: {1}".format(
                        feature_name, str(e)
                    )
                    self.log(error_msg, "ERROR")
                    failed_operations.append(
                        {"feature": feature_name, "error": error_msg}
                    )
                    deletion_results["summary"]["failed_operations"] += 1

        # Check for failures
        if failed_operations:
            failure_msg = "Failed to delete Wired Campus Automation configurations for device {0}. Failures: {1}".format(
                device_identifier, "; ".join([f["error"] for f in failed_operations])
            )
            self.msg = failure_msg
            self.set_operation_result("failed", True, self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        # Set appropriate message based on what actually happened
        if deletion_results["summary"]["successful_operations"] > 0:
            success_msg = "Successfully deleted Wired Campus Automation configurations for device {0}.".format(
                device_identifier
            )
            self.msg = success_msg
            self.set_operation_result("success", True, self.msg, "INFO")
        elif deletion_results["summary"]["skipped_operations"] > 0:
            # When all operations were skipped (like in this VLAN 4001 case)
            no_op_msg = (
                "No Wired Campus Automation configuration changes required for device {0}. "
                "Requested configurations were not found or already in desired state."
            ).format(device_identifier)
            self.msg = no_op_msg
            self.set_operation_result("success", False, self.msg, "INFO")
        else:
            no_op_msg = "No Wired Campus Automation configurations required deletion for device {0}.".format(
                device_identifier
            )
            self.msg = no_op_msg
            self.set_operation_result("success", False, self.msg, "INFO")

        return deletion_results

    def _execute_type1_deletion(self, feature_name, analysis, network_device_id):
        """
        Executes Type 1 deletion (global config reset) with proper intent handling.
        Args:
            feature_name (str): Name of the feature to delete
            analysis (dict): Analysis results containing deletion requirements
            network_device_id (str): Network device ID for the deletion operation
        Returns:
            dict: Result of the deletion operation with status and operation details
        """
        self.log(
            "Executing Type 1 deletion for feature: {0}".format(feature_name), "INFO"
        )

        api_feature_name = analysis["api_feature_name"]
        operation_sequence = analysis["operation_sequence"]

        self.log(
            "Processing deletion with API feature name: {0}".format(api_feature_name),
            "DEBUG",
        )
        self.log(
            "Operation sequence determined: {0}".format(operation_sequence), "DEBUG"
        )

        try:
            if operation_sequence == "skip_no_deployed":
                self.log(
                    "Skipping deletion operation - no deployed configuration exists",
                    "INFO",
                )
                return {
                    "status": "success",
                    "message": "No deployed configuration found for {0}, skipping deletion".format(
                        feature_name
                    ),
                    "operations_performed": [],
                }

            elif operation_sequence == "delete_intent_and_deploy":
                self.log(
                    "Deleting intent for {0} (with automatic intent creation if needed)".format(
                        feature_name
                    ),
                    "INFO",
                )

                # Execute the delete intent operation
                delete_result = self._execute_delete_intent_operation(
                    network_device_id, api_feature_name, feature_name
                )

                if delete_result["status"] != "success":
                    self.log(
                        "Delete intent operation failed for feature: {0}".format(
                            feature_name
                        ),
                        "ERROR",
                    )
                    return delete_result

                self.log(
                    "Delete intent operation completed successfully for feature: {0}".format(
                        feature_name
                    ),
                    "DEBUG",
                )

                # Deploy changes if not already deployed during intent creation
                if not delete_result.get("skipped"):
                    self.log("Proceeding with deployment of deletion changes", "INFO")
                    deploy_result = self._execute_deployment_operation(
                        network_device_id
                    )

                    if deploy_result["status"] == "success":
                        self.log("Deployment operation completed successfully", "DEBUG")
                        success_message = "Successfully reset {0} configuration".format(
                            feature_name
                        )
                        self.log(success_message, "INFO")

                        return {
                            "status": "success",
                            "message": success_message,
                            "operations_performed": ["delete_intent", "deploy"],
                            "delete_result": delete_result,
                            "deploy_result": deploy_result,
                        }
                    else:
                        self.log(
                            "Deployment operation failed for feature: {0}".format(
                                feature_name
                            ),
                            "ERROR",
                        )
                        failure_message = "Failed to deploy {0} deletion".format(
                            feature_name
                        )

                        return {
                            "status": "failed",
                            "message": failure_message,
                            "operations_performed": ["delete_intent", "deploy"],
                            "delete_result": delete_result,
                            "deploy_result": deploy_result,
                        }
                else:
                    self.log(
                        "Deployment was skipped during delete intent operation", "DEBUG"
                    )
                    return delete_result
            else:
                # Handle unexpected operation sequence
                error_msg = "Unknown operation sequence '{0}' for Type 1 deletion of feature: {1}".format(
                    operation_sequence, feature_name
                )
                self.log(error_msg, "ERROR")
                return {"status": "failed", "error": error_msg}

        except Exception as e:
            error_msg = "Exception during Type 1 deletion for {0}: {1}".format(
                feature_name, str(e)
            )
            self.log(error_msg, "ERROR")
            self.log(
                "Exception details for Type 1 deletion: {0}".format(str(e)), "DEBUG"
            )

            return {"status": "failed", "error": error_msg, "exception": str(e)}

    def _execute_type2_deletion(self, feature_name, analysis, network_device_id):
        """
        Executes Type 2 deletion (VLAN deletion via update).
        Args:
            feature_name (str): Feature name
            analysis (dict): Deletion analysis for this feature
            network_device_id (str): Network device ID
        Returns:
            dict: Operation result
        """
        self.log(
            "Executing Type 2 deletion for feature: {0}".format(feature_name), "INFO"
        )

        api_feature_name = analysis["api_feature_name"]
        vlans_to_delete = analysis["vlans_to_delete"]
        operation_sequence = analysis["operation_sequence"]

        if not vlans_to_delete:
            return {
                "status": "skipped",
                "message": "No VLANs found for deletion in {0}".format(feature_name),
                "operations_performed": [],
            }

        try:
            if operation_sequence == "update_intent_remove_vlans_and_deploy":
                # Get current intended config and remove VLANs
                intended_config = analysis["intended_config"]
                updated_config = self._remove_vlans_from_intent_config(
                    intended_config, vlans_to_delete, api_feature_name
                )

                self.log(
                    "Updating intent to remove VLANs for {0}".format(feature_name),
                    "INFO",
                )
                update_result = self._execute_update_intent_operation(
                    network_device_id, api_feature_name, updated_config, feature_name
                )

                if update_result["status"] != "success":
                    return update_result

                # Deploy changes
                deploy_result = self._execute_deployment_operation(network_device_id)

                return {
                    "status": (
                        "success" if deploy_result["status"] == "success" else "failed"
                    ),
                    "message": (
                        "Successfully deleted {0} VLANs from {1}".format(
                            len(vlans_to_delete), feature_name
                        )
                        if deploy_result["status"] == "success"
                        else "Failed to deploy VLAN deletion for {0}".format(
                            feature_name
                        )
                    ),
                    "operations_performed": ["update_intent", "deploy"],
                    "vlans_deleted": [v["vlan_id"] for v in vlans_to_delete],
                    "update_result": update_result,
                    "deploy_result": deploy_result,
                }

            elif operation_sequence == "create_intent_update_remove_and_deploy":
                # Create intent from deployed config
                deployed_config = analysis["deployed_config"]
                mapped_config = self._map_deployed_to_intent_config(
                    api_feature_name, deployed_config
                )

                self.log(
                    "Creating intent for {0} from deployed config".format(feature_name),
                    "INFO",
                )
                create_result = self._execute_create_intent_operation(
                    network_device_id, api_feature_name, mapped_config, feature_name
                )

                if create_result["status"] != "success":
                    return create_result

                # Deploy intent
                deploy_result1 = self._execute_deployment_operation(network_device_id)
                if deploy_result1["status"] != "success":
                    return {
                        "status": "failed",
                        "error": "Failed to deploy intent creation for {0}: {1}".format(
                            feature_name, deploy_result1.get("error")
                        ),
                        "operations_performed": ["create_intent"],
                    }

                # Remove VLANs and update
                updated_config = self._remove_vlans_from_intent_config(
                    {"response": {api_feature_name: mapped_config[api_feature_name]}},
                    vlans_to_delete,
                    api_feature_name,
                )

                self.log(
                    "Updating intent to remove VLANs for {0}".format(feature_name),
                    "INFO",
                )
                update_result = self._execute_update_intent_operation(
                    network_device_id, api_feature_name, updated_config, feature_name
                )

                if update_result["status"] != "success":
                    return update_result

                # Deploy deletion
                deploy_result2 = self._execute_deployment_operation(network_device_id)

                return {
                    "status": (
                        "success" if deploy_result2["status"] == "success" else "failed"
                    ),
                    "message": (
                        "Successfully deleted {0} VLANs from {1}".format(
                            len(vlans_to_delete), feature_name
                        )
                        if deploy_result2["status"] == "success"
                        else "Failed to deploy VLAN deletion for {0}".format(
                            feature_name
                        )
                    ),
                    "operations_performed": [
                        "create_intent",
                        "deploy",
                        "update_intent",
                        "deploy",
                    ],
                    "vlans_deleted": [v["vlan_id"] for v in vlans_to_delete],
                    "create_result": create_result,
                    "deploy_result1": deploy_result1,
                    "update_result": update_result,
                    "deploy_result2": deploy_result2,
                }

        except Exception as e:
            error_msg = "Exception during Type 2 deletion for {0}: {1}".format(
                feature_name, str(e)
            )
            self.log(error_msg, "ERROR")
            return {"status": "failed", "error": error_msg, "exception": str(e)}

    def _execute_type3_deletion(self, feature_name, analysis, network_device_id):
        """
        Handles Type 3 deletion (not supported due to beta APIs).
        Args:
            feature_name (str): Feature name
            analysis (dict): Deletion analysis for this feature
            network_device_id (str): Network device ID
        Returns:
            dict: Operation result indicating not supported
        """
        self.log(
            "Type 3 deletion execution for feature: {0}".format(feature_name), "INFO"
        )
        self.log(
            "DELETION NOT SUPPORTED: {0}".format(
                analysis.get("message", "Feature deletion not supported")
            ),
            "INFO",
        )

        return {
            "status": "not_supported",
            "message": analysis.get(
                "message", "Deletion not supported due to beta API limitations"
            ),
            "reason": analysis.get("reason", "Underlying APIs are in beta"),
            "operations_performed": [],
        }

    def _execute_type4_deletion(self, feature_name, analysis, network_device_id):
        """
        Handles Type 4 deletion (not supported due to beta APIs).
        Args:
            feature_name (str): Feature name
            analysis (dict): Deletion analysis for this feature
            network_device_id (str): Network device ID
        Returns:
            dict: Operation result indicating not supported
        """
        self.log(
            "Type 4 deletion execution for feature: {0}".format(feature_name), "INFO"
        )
        self.log(
            "DELETION NOT SUPPORTED: {0}".format(
                analysis.get("message", "Feature deletion not supported")
            ),
            "INFO",
        )

        return {
            "status": "not_supported",
            "message": analysis.get(
                "message", "Deletion not supported due to beta API limitations"
            ),
            "reason": analysis.get("reason", "Underlying APIs are in beta"),
            "operations_performed": [],
        }

    def _execute_delete_intent_operation(
        self, network_device_id, api_feature_name, feature_name
    ):
        """
        Executes delete intent operation with proper intent existence checking.
        Uses already-fetched intended configuration from self.have to avoid additional API calls.
        Args:
            network_device_id (str): Network device ID
            api_feature_name (str): API feature name
            feature_name (str): User-friendly feature name
        Returns:
            dict: Delete operation result
        """
        self.log(
            "Checking if intent exists before deletion for {0}".format(feature_name),
            "DEBUG",
        )

        # Use already-fetched intended configuration from self.have
        current_intended_configs = self.have.get("current_intended_configs", {})
        intended_config = current_intended_configs.get(api_feature_name, {})
        intent_exists = bool(
            intended_config.get("response", {}).get(api_feature_name, {}).get("items")
        )

        self.log(
            "Intent existence check for {0}: {1}".format(feature_name, intent_exists),
            "DEBUG",
        )

        if not intent_exists:
            self.log(
                "No intent exists for {0}, creating intent from deployed config before deletion".format(
                    feature_name
                ),
                "INFO",
            )

            # Use already-fetched deployed configuration from self.have
            current_deployed_configs = self.have.get("current_deployed_configs", {})
            deployed_config = current_deployed_configs.get(api_feature_name, {})

            if (
                not deployed_config.get("response", {})
                .get(api_feature_name, {})
                .get("items")
            ):
                self.log(
                    "No deployed configuration found for {0}, skipping deletion".format(
                        feature_name
                    ),
                    "INFO",
                )
                return {
                    "status": "success",
                    "message": "No configuration found to delete for {0}".format(
                        feature_name
                    ),
                    "skipped": True,
                }

            # Map deployed config to intent format
            mapped_config = self._map_deployed_to_intent_config(
                api_feature_name, deployed_config
            )

            # Create intent from deployed config
            create_result = self._execute_create_intent_operation(
                network_device_id, api_feature_name, mapped_config, feature_name
            )

            if create_result["status"] != "success":
                return {
                    "status": "failed",
                    "error": "Failed to create intent before deletion for {0}: {1}".format(
                        feature_name, create_result.get("error")
                    ),
                    "create_result": create_result,
                }

            # Deploy the created intent
            deploy_result = self._execute_deployment_operation(network_device_id)

            if deploy_result["status"] != "success":
                return {
                    "status": "failed",
                    "error": "Failed to deploy intent before deletion for {0}: {1}".format(
                        feature_name, deploy_result.get("error")
                    ),
                    "deploy_result": deploy_result,
                }

            self.log(
                "Successfully created and deployed intent for {0}, proceeding with deletion".format(
                    feature_name
                ),
                "INFO",
            )

        # Now proceed with the actual deletion
        try:
            task_response = self.delete_layer2_feature_configuration(
                network_device_id, api_feature_name
            )

            if task_response and isinstance(task_response, str):
                task_id = task_response
                task_name = "Delete {0} Intent Configuration".format(feature_name)
                success_msg = "Successfully deleted {0} intent configuration".format(
                    feature_name
                )

                self.log(
                    "Delete task initiated for {0}, task ID: {1}".format(
                        feature_name, task_id
                    ),
                    "INFO",
                )

                # Monitor task completion
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()

                if self.status == "success":
                    return {
                        "status": "success",
                        "task_id": task_id,
                        "message": success_msg,
                    }
                else:
                    return {"status": "failed", "error": self.msg, "task_id": task_id}
            else:
                return {
                    "status": "failed",
                    "error": "Invalid delete response format for {0}".format(
                        feature_name
                    ),
                    "response": task_response,
                }

        except Exception as e:
            error_msg = "Failed to execute delete operation for {0}: {1}".format(
                feature_name, str(e)
            )
            self.log(error_msg, "ERROR")
            return {"status": "failed", "error": error_msg, "exception": str(e)}

    def _execute_create_intent_operation(
        self, network_device_id, api_feature_name, config, feature_name
    ):
        """
        Executes create intent operation.
        Args:
            network_device_id (str): Network device ID
            api_feature_name (str): API feature name
            config (dict): Configuration to create
            feature_name (str): User-friendly feature name
        Returns:
            dict: Create operation result
        """
        try:
            task_response = self.create_layer2_feature_configuration(
                network_device_id, api_feature_name, config
            )

            if task_response and isinstance(task_response, str):
                task_id = task_response
                task_name = "Create {0} Intent Configuration".format(feature_name)
                success_msg = "Successfully created {0} intent configuration".format(
                    feature_name
                )

                self.log(
                    "Create task initiated for {0}, task ID: {1}".format(
                        feature_name, task_id
                    ),
                    "INFO",
                )

                # Monitor task completion
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()

                if self.status == "success":
                    return {
                        "status": "success",
                        "task_id": task_id,
                        "message": success_msg,
                    }
                else:
                    return {"status": "failed", "error": self.msg, "task_id": task_id}
            else:
                return {
                    "status": "failed",
                    "error": "Invalid create response format for {0}".format(
                        feature_name
                    ),
                    "response": task_response,
                }

        except Exception as e:
            error_msg = "Failed to execute create operation for {0}: {1}".format(
                feature_name, str(e)
            )
            self.log(error_msg, "ERROR")
            return {"status": "failed", "error": error_msg, "exception": str(e)}

    def _execute_update_intent_operation(
        self, network_device_id, api_feature_name, config, feature_name
    ):
        """
        Executes update intent operation using existing infrastructure.
        Args:
            network_device_id (str): Network device ID
            api_feature_name (str): API feature name
            config (dict): Configuration to update
            feature_name (str): User-friendly feature name
        Returns:
            dict: Update operation result
        """
        try:
            task_response = self.update_layer2_feature_configuration(
                network_device_id, api_feature_name, config
            )

            if task_response and isinstance(task_response, str):
                task_id = task_response
                task_name = "Update {0} Intent Configuration".format(feature_name)
                success_msg = "Successfully updated {0} intent configuration".format(
                    feature_name
                )

                self.log(
                    "Update task initiated for {0}, task ID: {1}".format(
                        feature_name, task_id
                    ),
                    "INFO",
                )

                # Monitor task completion using existing infrastructure
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()

                if self.status == "success":
                    return {
                        "status": "success",
                        "task_id": task_id,
                        "message": success_msg,
                    }
                else:
                    return {"status": "failed", "error": self.msg, "task_id": task_id}
            else:
                return {
                    "status": "failed",
                    "error": "Invalid update response format for {0}".format(
                        feature_name
                    ),
                    "response": task_response,
                }

        except Exception as e:
            error_msg = "Failed to execute update operation for {0}: {1}".format(
                feature_name, str(e)
            )
            self.log(error_msg, "ERROR")
            return {"status": "failed", "error": error_msg, "exception": str(e)}

    def _execute_deployment_operation(self, network_device_id):
        """
        Executes deployment operation using existing infrastructure.
        Args:
            network_device_id (str): Network device ID
        Returns:
            dict: Deploy operation result
        """
        try:
            task_response = self.deploy_intended_configurations(network_device_id)

            if task_response and isinstance(task_response, str):
                task_id = task_response
                task_name = "Deploy Wired Campus Automation Configuration"
                success_msg = (
                    "Successfully deployed Wired Campus Automation configuration"
                )

                self.log(
                    "Deployment task initiated, task ID: {0}".format(task_id), "INFO"
                )

                # Monitor task completion using existing infrastructure
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()

                if self.status == "success":
                    return {
                        "status": "success",
                        "task_id": task_id,
                        "message": success_msg,
                    }
                else:
                    return {"status": "failed", "error": self.msg, "task_id": task_id}
            else:
                return {
                    "status": "failed",
                    "error": "Invalid deployment response format",
                    "response": task_response,
                }

        except Exception as e:
            error_msg = "Failed to execute deployment operation: {0}".format(str(e))
            self.log(error_msg, "ERROR")
            return {"status": "failed", "error": error_msg, "exception": str(e)}

    def _map_deployed_to_intent_config(self, api_feature_name, deployed_config):
        """
        Maps deployed configuration to intent configuration format.
        Args:
            api_feature_name (str): API feature name
            deployed_config (dict): Deployed configuration
        Returns:
            dict: Intent configuration format
        """
        self.log(
            "Starting mapping of deployed configuration to intent format for feature: {0}".format(
                api_feature_name
            ),
            "DEBUG",
        )
        self.log(
            "Input deployed configuration structure: {0}".format(deployed_config),
            "DEBUG",
        )

        deployed_items = (
            deployed_config.get("response", {})
            .get(api_feature_name, {})
            .get("items", [])
        )

        self.log(
            "Extracted {0} deployed items from configuration".format(
                len(deployed_items)
            ),
            "DEBUG",
        )

        if not deployed_items:
            self.log(
                "No deployed items found, returning empty intent configuration", "DEBUG"
            )
            return {api_feature_name: {"items": []}}

        # Map deployed items to intent format
        intent_items = []
        for item in deployed_items:
            self.log("Processing deployed item for intent mapping", "DEBUG")
            # Remove any deployment-specific fields and keep configuration fields
            intent_item = self._clean_deployed_item_for_intent(item)
            intent_items.append(intent_item)
            self.log("Successfully mapped deployed item to intent format", "DEBUG")

        self.log(
            "Successfully mapped {0} deployed items to intent format".format(
                len(intent_items)
            ),
            "DEBUG",
        )

        intent_config = {api_feature_name: {"items": intent_items}}

        self.log(
            "Final intent configuration structure: {0}".format(intent_config), "DEBUG"
        )
        self.log(
            "Deployed to intent mapping completed successfully for feature: {0}".format(
                api_feature_name
            ),
            "INFO",
        )

        return intent_config

    def _clean_deployed_item_for_intent(self, deployed_item):
        """
        Cleans deployed item to make it suitable for intent configuration.
        Args:
            deployed_item (dict): Deployed configuration item
        Returns:
            dict: Cleaned item for intent
        """
        self.log(
            "Starting cleanup of deployed item for intent configuration compatibility",
            "DEBUG",
        )
        self.log("Input deployed item structure: {0}".format(deployed_item), "DEBUG")

        # Create a copy of the item
        intent_item = deployed_item.copy()
        self.log("Created copy of deployed item for cleaning process", "DEBUG")

        # Remove deployment-specific fields that shouldn't be in intent
        fields_to_remove = [
            "id",
            "deviceId",
            "deviceName",
            "lastUpdated",
            "status",
            "deploymentId",
        ]

        self.log(
            "Removing {0} deployment-specific fields from item".format(
                len(fields_to_remove)
            ),
            "DEBUG",
        )

        for field in fields_to_remove:
            if field in intent_item:
                del intent_item[field]
                self.log(
                    "Removed deployment field '{0}' from intent item".format(field),
                    "DEBUG",
                )
            else:
                self.log(
                    "Field '{0}' not present in deployed item, skipping removal".format(
                        field
                    ),
                    "DEBUG",
                )

        self.log("Deployed item cleanup completed successfully", "DEBUG")
        self.log("Cleaned intent item structure: {0}".format(intent_item), "DEBUG")

        return intent_item

    def _remove_vlans_from_intent_config(
        self, intended_config, vlans_to_delete, api_feature_name
    ):
        """
        Removes specified VLANs from intent configuration.
        Args:
            intended_config (dict): Current intended configuration
            vlans_to_delete (list): List of VLANs to delete
            api_feature_name (str): API feature name
        Returns:
            dict: Updated configuration with VLANs removed
        """
        self.log("Removing VLANs from intent configuration", "DEBUG")

        # Get current intended items
        intended_items = (
            intended_config.get("response", {})
            .get(api_feature_name, {})
            .get("items", [])
        )

        # Create set of VLAN IDs to delete for efficient lookup
        vlan_ids_to_delete = {vlan["vlan_id"] for vlan in vlans_to_delete}

        # Filter out VLANs that need to be deleted
        remaining_items = []
        for item in intended_items:
            vlan_id = item.get("vlanId")
            if vlan_id not in vlan_ids_to_delete:
                remaining_items.append(item)
            else:
                self.log(
                    "Removing VLAN {0} from intent configuration".format(vlan_id),
                    "DEBUG",
                )

        self.log(
            "Remaining VLANs after deletion: {0}".format(len(remaining_items)), "DEBUG"
        )

        return {api_feature_name: {"items": remaining_items}}

    def get_want(self, config, state):
        """
        Validates input parameters, extracts Layer2 feature mappings, and prepares the desired state.
        Args:
            config (dict): The configuration details from the playbook
            state (str): The desired state of the configuration (Example, "merged", "deleted")
        Returns:
            self: Returns the instance with the updated "want" attribute containing desired state
        """
        self.log("Starting 'get_want' operation with state: {0}".format(state), "INFO")
        self.log("Input configuration: {0}".format(config), "DEBUG")

        # Validate the parameters first
        self.log("Validating input parameters", "DEBUG")
        self.validate_params(config, state)
        self.log("Parameter validation completed successfully", "DEBUG")

        # Extract device identification information
        ip_address = config.get("ip_address")
        hostname = config.get("hostname")
        device_collection_status_check = config.get(
            "device_collection_status_check", True
        )
        config_verification_wait_time = config.get("config_verification_wait_time", 10)

        self.log(
            "Device identifiers - IP: {0}, Hostname: {1}".format(ip_address, hostname),
            "DEBUG",
        )
        self.log(
            "Verification wait time: {0} seconds".format(config_verification_wait_time),
            "DEBUG",
        )

        # Extract Layer2 feature mappings from user configuration
        self.log("Extracting Layer2 feature mappings from user configuration", "INFO")
        discovered_features, feature_mappings = self.extract_layer2_feature_mappings(
            config
        )

        self.log("Feature mapping extraction completed", "DEBUG")
        self.log(
            "Discovered {0} API features for processing".format(
                len(discovered_features)
            ),
            "INFO",
        )

        # Build the comprehensive 'want' state
        want = {
            # Device identification information
            "device_identifier": ip_address or hostname,
            "ip_address": ip_address,
            "hostname": hostname,
            "device_collection_status_check": device_collection_status_check,
            "config_verification_wait_time": config_verification_wait_time,
            # Feature discovery and mapping results
            "discovered_api_features": list(discovered_features),
            "user_feature_mappings": feature_mappings,
            "total_discovered_features": len(discovered_features),
        }

        # Store the want state
        self.want = want

        self.log("Desired State (want) assembly completed successfully", "INFO")
        self.log("Device identifier: {0}".format(want["device_identifier"]), "INFO")
        self.log(
            "Features to be processed: {0}".format(want["total_discovered_features"]),
            "INFO",
        )
        self.log(
            "API features discovered: {0}".format(want["discovered_api_features"]),
            "DEBUG",
        )
        self.log("Complete 'want' state structure: {0}".format(str(self.want)), "DEBUG")

        self.msg = "Successfully collected all parameters from the playbook for Wired Campus Automation Operations."
        self.status = "success"
        return self

    def get_have(self, config, state):
        """
        Gathers the current state of the network device based on the desired state from get_want.
        Retrieves network device ID and fetches current deployed/intended configurations for all features identified in the want state.
        Args:
            config (dict): The configuration details (for compatibility, but want is used)
            state (str): The desired state (for compatibility, but want is used)
        Returns:
            self: Returns the instance with the updated "have" attribute containing current state
        """
        self.log("Starting 'get_have' operation", "INFO")
        self.log(
            "Initiating current state gathering for network device configuration analysis",
            "DEBUG",
        )

        # Ensure want state exists
        if not hasattr(self, "want") or not self.want:
            self.msg = (
                "No 'want' state found. get_want() must be called before get_have()."
            )
            self.log(
                "Want state validation failed - no want state available for processing",
                "ERROR",
            )
            self.fail_and_exit(self.msg)

        # Extract information from want state
        ip_address = self.want.get("ip_address")
        hostname = self.want.get("hostname")
        discovered_features = self.want.get("discovered_api_features", [])
        device_identifier = self.want.get("device_identifier")

        self.log("Processing device: {0}".format(device_identifier), "INFO")
        self.log("Extracted device identification parameters from want state", "DEBUG")
        self.log("Features to retrieve: {0}".format(discovered_features), "DEBUG")
        self.log(
            "Total discovered features count: {0}".format(len(discovered_features)),
            "DEBUG",
        )

        # Retrieve the network device ID based on the provided IP address or hostname
        self.log("Retrieving network device ID for device identification", "DEBUG")
        self.log(
            "Initiating device ID resolution using IP address or hostname", "DEBUG"
        )
        mgmt_ip_to_instance_id_map = self.get_network_device_id(ip_address, hostname)

        if not mgmt_ip_to_instance_id_map:
            self.msg = "Failed to retrieve network device ID for device: {0}".format(
                device_identifier
            )
            self.log(
                "Device ID resolution failed for device: {0}".format(device_identifier),
                "ERROR",
            )
            self.fail_and_exit(self.msg)

        network_device_id = list(mgmt_ip_to_instance_id_map.values())[0]
        resolved_ip_address = list(mgmt_ip_to_instance_id_map.keys())[0]

        self.log(
            "Device resolution successful - Network Device ID: {0}".format(
                network_device_id
            ),
            "INFO",
        )
        self.log("Successfully resolved device identification parameters", "DEBUG")
        self.log("Resolved IP Address: {0}".format(resolved_ip_address), "DEBUG")
        self.log("Device ID mapping completed successfully", "DEBUG")

        # Initialize configurations dictionaries
        deployed_configs = {}
        intended_configs = {}

        self.log("Initialized configuration storage dictionaries", "DEBUG")

        # Fetch current configurations only if we have features to process
        if discovered_features:
            self.log("Fetching current configurations for discovered features", "INFO")
            self.log(
                "Starting configuration retrieval for {0} discovered features".format(
                    len(discovered_features)
                ),
                "DEBUG",
            )
            deployed_configs, intended_configs = self.get_current_configs_for_features(
                network_device_id, discovered_features
            )
            self.log("Configuration retrieval completed", "INFO")
            self.log("Configuration fetching operation completed successfully", "DEBUG")
            self.log(
                "Retrieved deployed configs for {0} features".format(
                    len(deployed_configs)
                ),
                "DEBUG",
            )
            self.log(
                "Retrieved intended configs for {0} features".format(
                    len(intended_configs)
                ),
                "DEBUG",
            )
            self.log(
                "Configuration data successfully populated from Catalyst Center",
                "DEBUG",
            )
        else:
            self.log(
                "No features discovered from user configuration, skipping config retrieval",
                "INFO",
            )
            self.log(
                "Configuration retrieval bypassed due to empty feature list", "DEBUG"
            )

        # Build the comprehensive 'have' state
        have = {
            # Device identification and resolution
            "device_identifier": device_identifier,
            "network_device_id": network_device_id,
            "resolved_ip_address": resolved_ip_address,
            # Current configurations from Catalyst Center
            "current_deployed_configs": deployed_configs,
            "current_intended_configs": intended_configs,
            # Summary information
            "configs_retrieved_for_features": len(deployed_configs),
            "total_features_processed": len(discovered_features),
        }

        # Store the have state
        self.have = have

        self.log("Have state structure assembled successfully", "DEBUG")

        # Log comprehensive summary
        self.log("Current State (have) assembly completed successfully", "INFO")
        self.log(
            "Device: {0} (ID: {1})".format(
                have["device_identifier"], have["network_device_id"]
            ),
            "INFO",
        )
        self.log(
            "Deployed configs retrieved for: {0} features".format(
                have["configs_retrieved_for_features"]
            ),
            "INFO",
        )
        self.log(
            "Total features processed: {0}".format(have["total_features_processed"]),
            "INFO",
        )
        self.log(
            "Have state processing completed with comprehensive device and configuration data",
            "DEBUG",
        )

        # Debug logging of complete have structure
        self.log("Complete 'have' state structure: {0}".format(str(self.have)), "DEBUG")
        self.log(
            "Have state contains all required components for difference analysis",
            "DEBUG",
        )

        return self

    def get_diff_merged(self):
        """
        Main entry point for the merged state operation.
        Description:
            This is the primary function called when the module is run with state='merged'.
            It orchestrates the entire process:
            1. Analyzes configuration differences between current and desired state
            2. Executes required API operations (create/update intent, then deploy)
            3. Sets final operation results and handles success/failure scenarios
            4. Stores results for potential verification steps
        Returns:
            self: Returns the instance with updated diff and result attributes
        """
        self.log("Starting 'get_diff_merged' operation.", "INFO")

        # Analyze configuration differences and determine operations
        self.log(
            "Analyzing configuration differences and determining required operations",
            "INFO",
        )
        diff_analysis = self._analyze_configuration_differences()

        # Store the diff analysis results
        self.diff = diff_analysis

        # Execute API operations based on the analysis
        operation_results = self._execute_api_operations(diff_analysis)

        # Store operation results for potential use in verification
        self.result["operation_results"] = operation_results

        self.log(
            "Configuration difference analysis and API operations completed", "INFO"
        )
        return self

    def get_diff_deleted(self):
        """
        Handles the deletion state operation for Layer 2 configurations.
        Description:
            This method processes deletion requests for Layer 2 features by:
            1. Analyzing current configurations to determine what can be deleted
            2. Executing delete operations for intended configurations
            3. Setting appropriate operation results
        Note: This method only deletes intended configurations, not deployed ones.
        Returns:
            self: Returns the instance with updated diff and result attributes
        """
        self.log(
            "Starting 'get_diff_deleted' operation for Layer 2 configuration deletion",
            "INFO",
        )

        # Extract deletion requirements from want state
        want_feature_mappings = self.want.get("user_feature_mappings", {})
        network_device_id = self.have.get("network_device_id")
        device_identifier = self.want.get("device_identifier")

        self.log("Extracted deletion requirements from want and have states", "DEBUG")
        self.log("Network device ID: {0}".format(network_device_id), "DEBUG")
        self.log("Device identifier: {0}".format(device_identifier), "DEBUG")
        self.log(
            "Feature mappings to process for deletion: {0}".format(
                len(want_feature_mappings)
            ),
            "DEBUG",
        )

        if not want_feature_mappings:
            self.log("No feature mappings found for deletion operation", "INFO")
            self.msg = "No Layer 2 configurations specified for deletion from device {0}".format(
                device_identifier
            )
            self.set_operation_result("success", False, self.msg, "INFO")
            self.log(
                "Deletion operation completed - no configurations to delete", "INFO"
            )
            return self

        self.log(
            "Processing deletion for {0} Layer 2 features on device {1}".format(
                len(want_feature_mappings), device_identifier
            ),
            "INFO",
        )

        # Analyze what exists and can be deleted
        self.log("Starting deletion requirements analysis", "DEBUG")
        deletion_analysis = self._analyze_deletion_requirements(want_feature_mappings)
        self.log("Deletion requirements analysis completed successfully", "DEBUG")
        self.log(
            "Deletion analysis summary: {0}".format(
                deletion_analysis.get("summary", {})
            ),
            "DEBUG",
        )

        # Execute deletion operations
        self.log("Starting execution of deletion operations", "INFO")
        deletion_results = self._execute_deletion_operations(
            deletion_analysis, network_device_id, device_identifier
        )
        self.log("Deletion operations execution completed", "INFO")
        self.log(
            "Deletion results summary: {0}".format(deletion_results.get("summary", {})),
            "DEBUG",
        )

        # Store results for verification
        self.result["deletion_results"] = deletion_results
        self.log("Stored deletion results for potential verification use", "DEBUG")

        self.log(
            "Deletion operations completed for device {0}".format(device_identifier),
            "INFO",
        )
        self.log("Get diff deleted operation completed successfully", "DEBUG")

        return self

    def verify_diff_merged(self):
        """
        Verifies that the configuration changes were successfully applied by comparing the current deployed state with the desired configuration.
        Description:
            This function performs post-deployment verification by:
            1. Retrieving the current deployed configurations for all features
            2. Comparing them with the originally desired configurations
            3. Logging detailed pre and post operation states
            4. Logging final verification results without setting operation status
        Returns:
            self: Returns the instance after completing the verification process
        """
        self.log(
            "Starting 'verify_diff_merged' operation for configuration verification",
            "INFO",
        )

        # Extract verification data from previous operations
        want_feature_mappings = self.want.get("user_feature_mappings", {})
        network_device_id = self.have.get("network_device_id")
        device_identifier = self.want.get("device_identifier")
        discovered_features = self.want.get("discovered_api_features", [])

        self.log("Extracted verification parameters from want and have states", "DEBUG")
        self.log("Network device ID: {0}".format(network_device_id), "DEBUG")
        self.log("Device identifier: {0}".format(device_identifier), "DEBUG")
        self.log(
            "Want feature mappings count: {0}".format(len(want_feature_mappings)),
            "DEBUG",
        )
        self.log(
            "Discovered features count: {0}".format(len(discovered_features)), "DEBUG"
        )

        # Get pre-operation state from self.have
        pre_operation_deployed_configs = self.have.get("current_deployed_configs", {})

        self.log(
            "Retrieved pre-operation deployed configurations from have state", "DEBUG"
        )
        self.log(
            "Pre-operation deployed configs available for {0} features".format(
                len(pre_operation_deployed_configs)
            ),
            "DEBUG",
        )

        if not want_feature_mappings:
            self.log("No desired configurations found for verification", "INFO")
            self.log(
                "VERIFICATION RESULT: No configuration changes were requested for verification",
                "INFO",
            )
            return self

        if not network_device_id:
            self.log(
                "Network device ID not found, cannot perform verification", "ERROR"
            )
            self.log(
                "VERIFICATION RESULT: Unable to verify configuration - network device ID not available",
                "ERROR",
            )
            return self

        # Add configurable wait time before verification
        config_verification_wait_time = self.want.get(
            "config_verification_wait_time", 10
        )  # Default 10 seconds
        self.log(
            "Waiting {0} seconds for configuration changes to propagate before verification".format(
                config_verification_wait_time
            ),
            "INFO",
        )

        # Import time module for sleep functionality
        import time

        time.sleep(config_verification_wait_time)

        self.log("Configuration propagation wait period completed", "DEBUG")

        self.log(
            "CONFIGURATION VERIFICATION - PRE-OPERATION vs POST-OPERATION ANALYSIS",
            "INFO",
        )
        self.log(
            "Device being verified: {0} (ID: {1})".format(
                device_identifier, network_device_id
            ),
            "INFO",
        )
        self.log(
            "Total user features to verify: {0}".format(len(want_feature_mappings)),
            "INFO",
        )

        # Log original pre-operation state
        self.log("PRE-OPERATION DEPLOYED CONFIGURATION STATE:", "INFO")
        self.log(
            "Starting pre-operation state logging for verification baseline", "DEBUG"
        )
        self._log_configuration_state(
            "Pre-operation", want_feature_mappings, pre_operation_deployed_configs
        )
        self.log("Completed pre-operation state logging", "DEBUG")

        # Fetch current post-operation deployed configurations using existing function
        self.log(
            "Retrieving current post-operation deployed configurations for verification",
            "INFO",
        )

        try:
            self.log(
                "Initiating post-operation configuration retrieval from Catalyst Center",
                "DEBUG",
            )
            post_operation_deployed_configs, post_operation_intended_configs = self.get_current_configs_for_features(
                network_device_id, discovered_features
            )

            self.log(
                "Successfully retrieved post-operation configurations for {0} features".format(
                    len(post_operation_deployed_configs)
                ),
                "INFO",
            )
            self.log(
                "Post-operation configuration retrieval completed successfully", "DEBUG"
            )

        except Exception as e:
            error_msg = "Failed to retrieve post-operation configurations for verification: {0}".format(
                str(e)
            )
            self.log(error_msg, "ERROR")
            self.log(
                "Post-operation configuration retrieval failed with exception: {0}".format(
                    str(e)
                ),
                "DEBUG",
            )
            self.log("VERIFICATION RESULT: {0}".format(error_msg), "ERROR")
            return self

        # Log post-operation state
        self.log("POST-OPERATION DEPLOYED CONFIGURATION STATE:", "INFO")
        self.log(
            "Starting post-operation state logging for verification comparison", "DEBUG"
        )
        self._log_configuration_state(
            "Post-operation", want_feature_mappings, post_operation_deployed_configs
        )
        self.log("Completed post-operation state logging", "DEBUG")

        # Perform detailed verification analysis
        self.log("DETAILED VERIFICATION ANALYSIS:", "INFO")
        self.log("Initiating detailed configuration verification analysis", "DEBUG")

        verification_results = self._perform_detailed_verification(
            want_feature_mappings,
            pre_operation_deployed_configs,
            post_operation_deployed_configs,
        )

        self.log("Detailed verification analysis completed successfully", "DEBUG")
        self.log(
            "Verification results structure populated with {0} feature results".format(
                len(verification_results.get("detailed_results", {}))
            ),
            "DEBUG",
        )

        # Log verification summary
        self.log("VERIFICATION SUMMARY:", "INFO")
        self.log(
            "Total features verified: {0}".format(
                verification_results["total_features_verified"]
            ),
            "INFO",
        )
        self.log(
            "Features successfully applied: {0}".format(
                verification_results["features_successfully_applied"]
            ),
            "INFO",
        )
        self.log(
            "Features with verification failures: {0}".format(
                verification_results["features_failed_verification"]
            ),
            "INFO",
        )
        self.log(
            "Features not found post-operation: {0}".format(
                verification_results["features_not_found"]
            ),
            "INFO",
        )

        self.log("Verification summary logging completed", "DEBUG")

        # Log final verification result without setting operation status
        if verification_results["verification_failed"]:
            self.log(
                "VERIFICATION RESULT: {0}".format(
                    verification_results["failure_message"]
                ),
                "ERROR",
            )
            self.log(
                "Configuration verification failed - some features did not meet expected state",
                "DEBUG",
            )
        else:
            self.log(
                "VERIFICATION RESULT: {0}".format(
                    verification_results["success_message"]
                ),
                "INFO",
            )
            self.log(
                "Configuration verification succeeded - all features verified successfully",
                "DEBUG",
            )

        self.log("Completed 'verify_diff_merged' operation", "INFO")
        self.log("Verification operation completed and returning instance", "DEBUG")
        return self

    def verify_diff_deleted(self):
        """
        Placeholder for deletion verification - not implemented due to beta API limitations.
        Description:
            Deletion verification is not implemented because the underlying APIs are in beta.
            This ensures stability and prevents issues with verification logic on unstable endpoints.
        """
        device_identifier = self.want.get("device_identifier", "unknown")

        self.log(
            "DELETION VERIFICATION NOTICE: Verification for deleted configurations is not implemented",
            "INFO",
        )
        self.log(
            "Reason: The underlying Layer 2 configuration APIs are in beta and verification logic",
            "INFO",
        )
        self.log(
            "may not be reliable with beta API responses. Verification will be added when",
            "INFO",
        )
        self.log("APIs reach general availability (GA) status.", "INFO")
        self.log(
            "VERIFICATION RESULT: Deletion verification skipped for device {0} due to beta API limitations".format(
                device_identifier
            ),
            "INFO",
        )
        self.log("Completed 'verify_diff_deleted' operation (skipped)", "INFO")

        return self


def main():
    """main entry point for module execution"""
    # Define the specification for the module"s arguments
    element_spec = {
        "dnac_host": {"required": True, "type": "str"},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": "True"},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "dnac_log": {"type": "bool", "default": False},
        "validate_response_schema": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
    }

    # Initialize the Ansible module with the provided argument specifications
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    # Initialize the NetworkCompliance object with the module
    ccc_wired_campus_automation = WiredCampusAutomation(module)
    if (
        ccc_wired_campus_automation.compare_dnac_versions(
            ccc_wired_campus_automation.get_ccc_version(), "3.1.3.0"
        )
        < 0
    ):
        ccc_wired_campus_automation.msg = (
            "The specified version '{0}' does not support the Wired Campus Automation Operations. Supported versions start "
            "  from '3.1.3.0' onwards. Version '3.1.3.0' introduces APIs for performing Wired Campus Automation Operations".format(
                ccc_wired_campus_automation.get_ccc_version()
            )
        )
        ccc_wired_campus_automation.set_operation_result(
            "failed", False, ccc_wired_campus_automation.msg, "ERROR"
        ).check_return_status()

    # Get the state parameter from the provided parameters
    state = ccc_wired_campus_automation.params.get("state")

    # Check if the state is valid
    if state not in ccc_wired_campus_automation.supported_states:
        ccc_wired_campus_automation.status = "invalid"
        ccc_wired_campus_automation.msg = "State {0} is invalid".format(state)
        ccc_wired_campus_automation.check_return_status()

    # Validate the input parameters and check the return status
    ccc_wired_campus_automation.validate_input().check_return_status()

    # Get the config_verify parameter from the provided parameters
    config_verify = ccc_wired_campus_automation.params.get("config_verify")

    # Iterate over the validated configuration parameters
    for config in ccc_wired_campus_automation.validated_config:
        ccc_wired_campus_automation.reset_values()
        ccc_wired_campus_automation.get_want(config, state).check_return_status()
        ccc_wired_campus_automation.get_have(config, state).check_return_status()
        ccc_wired_campus_automation.get_diff_state_apply[state]().check_return_status()
        if config_verify:
            ccc_wired_campus_automation.verify_diff_state_apply[
                state
            ]().check_return_status()

    module.exit_json(**ccc_wired_campus_automation.result)


if __name__ == "__main__":
    main()
