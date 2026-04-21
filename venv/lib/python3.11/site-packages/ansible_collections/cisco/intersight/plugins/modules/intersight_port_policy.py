#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: intersight_port_policy
short_description: Manage Port Policies for Cisco Intersight
description:
  - Create, update, and delete Port Policies on Cisco Intersight.
  - Manage port configurations including breakout ports, server roles, uplink port channels, and LAN pin groups.
  - Supports various device models with model-specific port configurations.
  - Port policies define the configuration of unified ports on fabric interconnects.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/fabric/PortPolicies/get/).
extends_documentation_fragment: intersight
options:
  state:
    description:
      - If C(present), will verify the resource is present and will create if needed.
      - If C(absent), will verify the resource is absent and will delete if needed.
    type: str
    choices: [present, absent]
    default: present
  organization:
    description:
      - The name of the Organization this resource is assigned to.
      - Policies created within a Custom Organization are applicable only to devices in the same Organization.
      - Use 'default' for the default organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the Port Policy.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Port Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  device_model:
    description:
      - The device model for which the Port Policy is intended.
      - Different models support different port configurations and capabilities.
      - Required when C(state=present).
      - "UCS-FI-6454: 54 ports (1-54), FC ports 1-16, breakout ports 49-54"
      - "UCS-FI-64108: 108 ports (1-108), FC ports 1-16, breakout ports 97-108, 1Gbps only on ports 89-96, 40/100Gbps only on ports 97-108"
      - "UCS-FI-6536: 36 ports (1-36), FC only via breakout ports 33-36, all ports support breakout, 1Gbps only on ports 9-10"
      - "UCS-FI-6664: 64 ports (1-64), FC ports 25-40, no breakout support, 40/100Gbps only on ports 1-24 and 41-64"
      - "UCSX-S9108-100G: 8 ports (1-8), FC only via breakout ports 1-2, 1Gbps only on ports 7-8"
    type: str
    choices: ['UCS-FI-6454', 'UCS-FI-64108', 'UCS-FI-6536', 'UCS-FI-6664', 'UCSX-S9108-100G']
  fc_port_mode:
    description:
      - Configure Fibre Channel port mode for a range of ports.
      - This converts Ethernet ports to Fibre Channel ports.
      - Only one FC port mode configuration is allowed per policy.
      - Device-specific FC port ranges apply (see device_model documentation).
      - For UCS-FI-6536 and UCSX-S9108-100G, fc_port_mode is not supported.
      - FC functionality is available through breakout ports only. If specified, this parameter will be ignored with a warning.
    type: dict
    suboptions:
      port_id_start:
        description:
          - Starting port ID for FC mode configuration.
          - For UCS-FI-6454/64108, must be 1 (minimum FC port).
          - For UCS-FI-6664, must be 25 (minimum FC port).
          - Not applicable for UCS-FI-6536 and UCSX-S9108-100G (use breakout ports for FC).
        type: int
        default: 1
      port_id_end:
        description:
          - Ending port ID for FC mode configuration.
          - Valid values depend on device model and supported FC range.
          - For UCS-FI-6454/64108, valid values are 4, 8, 12, or 16.
          - For UCS-FI-6664, must be within range 25-40.
          - Not applicable for UCS-FI-6536 and UCSX-S9108-100G (use breakout ports for FC).
        type: int
        required: true
      state:
        description:
          - Whether to enable or disable FC port mode.
        type: str
        choices: ['present', 'absent']
        default: present
  breakout_ports:
    description:
      - List of breakout port configurations.
      - Breakout ports allow splitting a high-speed port into multiple lower-speed ports.
      - Device-specific breakout support applies (see device_model documentation).
      - UCS-FI-6664 does not support breakout ports at all.
    type: list
    elements: dict
    suboptions:
      port_id:
        description:
          - Port ID to configure for breakout.
          - This port will be split into multiple sub-ports (e.g., '49/1', '49/2', '49/3', '49/4').
          - Must be within the device's supported breakout port range.
          - "UCS-FI-6454: ports 49-54 (Ethernet breakout only)"
          - "UCS-FI-64108: ports 97-108 (Ethernet breakout only)"
          - "UCS-FI-6536: ports 1-32 (Ethernet breakout only), ports 33-36 (FC breakout only)"
          - "UCSX-S9108-100G: ports 1-2 (FC breakout only), ports 3-6 (Ethernet breakout)"
          - "UCS-FI-6536: ports 1-36 (including FC ports)"
          - "UCSX-S9108-100G: ports 1-8"
        type: int
        required: true
      custom_mode:
        description:
          - Breakout mode for the ports.
          - Ethernet breakout modes (BreakoutEthernet10G, BreakoutEthernet25G) are supported on all models that support breakout.
          - FC breakout modes (BreakoutFibreChannel8G, BreakoutFibreChannel16G, BreakoutFibreChannel32G) are only supported on UCS-FI-6536 and UCSX-S9108-100G.
        type: str
        choices: ['BreakoutEthernet10G', 'BreakoutEthernet25G', 'BreakoutFibreChannel8G', 'BreakoutFibreChannel16G', 'BreakoutFibreChannel32G']
        required: true
      state:
        description:
          - Whether to create/update or delete the breakout port configuration.
        type: str
        choices: ['present', 'absent']
        default: present
  server_ports:
    description:
      - List of server port configurations.
      - Server ports connect to server adapters.
    type: list
    elements: dict
    suboptions:
      port_id:
        description:
          - Port ID to configure as server port.
          - Can be a regular port (e.g., 49) or aggregate port (e.g., '49/2').
          - Aggregate ports use breakout port syntax where '49/2' means sub-port 2 of port 49.
        type: str
        required: true
      fec:
        description:
          - Forward Error Correction (FEC) mode.
        type: str
        choices: ['Auto', 'Cl74']
        default: 'Auto'
      manual_numbering:
        description:
          - Enable manual numbering on the port.
          - When true, preferred_device_type defaults to 'Chassis' and preferred_device_id becomes required.
          - Cannot be true for aggregate ports (e.g., '49/1') as manual numbering is not supported on breakout ports.
          - Chassis and Rack Servers are numbered automatically as discovered.
          - Chassis are numbered separately from rack servers. Enable this to allow manual setting of discovered device IDs.
        type: bool
        default: false
      user_label:
        description:
          - User-defined label for the port.
          - User label must be between 0 and 128 alphanumeric characters.
        type: str
      preferred_device_type:
        description:
          - Preferred device type when manual chassis/server numbering is enabled.
          - Defaults to 'Chassis' when manual_numbering is true.
        type: str
        choices: ['Chassis', 'RackServer']
      preferred_device_id:
        description:
          - Preferred device ID when manual chassis/server numbering is enabled.
          - Required when manual_numbering is true or when preferred_device_type is specified.
        type: int
      state:
        description:
          - Whether to create/update or delete the server port configuration.
        type: str
        choices: ['present', 'absent']
        default: present
  ethernet_uplink_port_channels:
    description:
      - List of Ethernet uplink port channel configurations.
      - Port channels aggregate multiple Ethernet ports into a single logical link.
    type: list
    elements: dict
    suboptions:
      pc_id:
        description:
          - Port Channel Identifier.
          - Valid range is 1-256.
        type: int
        required: true
      admin_speed:
        description:
          - Administrative speed of the port channel.
        type: str
        choices: ['Auto', '1Gbps', '10Gbps', '25Gbps', '40Gbps', '100Gbps']
        default: 'Auto'
      fec:
        description:
          - Forward Error Correction (FEC) mode.
        type: str
        choices: ['Auto', 'Off']
        default: 'Auto'
      user_label:
        description:
          - User-defined label for the port channel.
          - User label must be between 0 and 128 alphanumeric characters.
        type: str
      ports:
        description:
          - List of Ethernet ports to include in the port channel.
        type: list
        elements: dict
        required: true
        suboptions:
          port_id:
            description:
              - Port ID to include in the port channel.
              - Can be a regular port (e.g., 36) or aggregate port (e.g., '49/2').
              - Aggregate ports use breakout port syntax where '49/2' means sub-port 2 of port 49.
            type: str
            required: true
      eth_network_group_policy_names:
        description:
          - List of Ethernet Network Group Policy names to associate.
          - The Ethernet Network Group Policy specifies a set of VLANs to allow on the uplink port.
          - The specified VLAN set must be either identical or disjoint from those specified on other uplink interfaces.
          - Ensure that the VLANs are defined in the VLAN Policy and 'Auto Allow on Uplinks' option is disabled.
          - Note, default VLAN-1 is auto allowed and can be specified as the native VLAN.
        type: list
        elements: str
      flow_control_policy_name:
        description:
          - Flow Control Policy name to associate.
        type: str
      link_aggregation_policy_name:
        description:
          - Link Aggregation Policy name to associate.
        type: str
      link_control_policy_name:
        description:
          - Link Control Policy name to associate.
        type: str
      state:
        description:
          - Whether to create/update or delete the port channel.
        type: str
        choices: ['present', 'absent']
        default: present
  fc_uplink_port_channels:
    description:
      - List of FC uplink port channel configurations.
      - Port channels aggregate multiple FC ports into a single logical link.
      - Only applicable when fc_port_mode is configured.
    type: list
    elements: dict
    suboptions:
      pc_id:
        description:
          - Port Channel Identifier.
          - Valid range is 1-256.
        type: int
        required: true
      admin_speed:
        description:
          - Administrative speed of the FC port channel.
        type: str
        choices: ['8Gbps', '16Gbps', '32Gbps']
        default: '16Gbps'
      vsan_id:
        description:
          - VSAN ID associated to the FC port channel.
        type: int
        default: 1
      user_label:
        description:
          - User-defined label for the port channel.
          - User label must be between 0 and 128 alphanumeric characters.
        type: str
      ports:
        description:
          - List of FC ports to include in the port channel.
          - Ports must be within the FC port mode range.
        type: list
        elements: dict
        required: true
        suboptions:
          port_id:
            description:
              - FC port ID to include in the port channel.
            type: str
            required: true
      state:
        description:
          - Whether to create/update or delete the port channel.
        type: str
        choices: ['present', 'absent']
        default: present
  fcoe_uplink_port_channels:
    description:
      - List of FCoE uplink port channel configurations.
      - Port channels provide Fibre Channel over Ethernet connectivity.
    type: list
    elements: dict
    suboptions:
      pc_id:
        description:
          - Port Channel Identifier.
          - Valid range is 1-256.
        type: int
        required: true
      admin_speed:
        description:
          - Administrative speed of the port channel.
        type: str
        choices: ['Auto', '1Gbps', '10Gbps', '25Gbps', '40Gbps', '100Gbps']
        default: 'Auto'
      fec:
        description:
          - Forward Error Correction (FEC) mode.
        type: str
        choices: ['Auto', 'Off']
        default: 'Auto'
      user_label:
        description:
          - User-defined label for the port channel.
          - User label must be between 0 and 128 alphanumeric characters.
        type: str
      ports:
        description:
          - List of Ethernet ports to include in the port channel.
        type: list
        elements: dict
        required: true
        suboptions:
          port_id:
            description:
              - Port ID to include in the port channel.
              - Can be a regular port (e.g., 36) or aggregate port (e.g., '49/2').
              - Aggregate ports use breakout port syntax where '49/2' means sub-port 2 of port 49.
            type: str
            required: true
      link_aggregation_policy_name:
        description:
          - Link Aggregation Policy name to associate.
          - The relationship to the Link Aggregation Policy.
        type: str
      link_control_policy_name:
        description:
          - Link Control Policy name to associate.
        type: str
      state:
        description:
          - Whether to create/update or delete the port channel.
        type: str
        choices: ['present', 'absent']
        default: present
  appliance_port_channels:
    description:
      - List of appliance port channel configurations.
      - Port channels for direct-attached storage connectivity.
    type: list
    elements: dict
    suboptions:
      pc_id:
        description:
          - Port Channel Identifier.
          - Valid range is 1-256.
        type: int
        required: true
      admin_speed:
        description:
          - Administrative speed of the port channel.
        type: str
        choices: ['Auto', '1Gbps', '10Gbps', '25Gbps', '40Gbps', '100Gbps']
        default: 'Auto'
      fec:
        description:
          - Forward Error Correction (FEC) mode.
        type: str
        choices: ['Auto', 'Off']
        default: 'Auto'
      priority:
        description:
          - QoS priority for the appliance port channel.
        type: str
        choices: ['Best Effort', 'FC', 'Platinum', 'Gold', 'Silver', 'Bronze']
        default: 'Best Effort'
      mode:
        description:
          - Port mode for the appliance port channel.
        type: str
        choices: ['trunk', 'access']
        default: 'trunk'
      user_label:
        description:
          - User-defined label for the port channel.
          - User label must be between 0 and 128 alphanumeric characters.
        type: str
      ports:
        description:
          - List of Ethernet ports to include in the port channel.
        type: list
        elements: dict
        required: true
        suboptions:
          port_id:
            description:
              - Port ID to include in the port channel.
              - Can be a regular port (e.g., 36) or aggregate port (e.g., '49/2').
              - Aggregate ports use breakout port syntax where '49/2' means sub-port 2 of port 49.
            type: str
            required: true
      eth_network_group_policy_name:
        description:
          - Ethernet Network Group Policy name (required).
          - The relationship to the Fabric Network Group Policy.
        type: str
        required: true
      eth_network_control_policy_name:
        description:
          - Ethernet Network Control Policy name (required).
          - The relationship to the Fabric Network Control Policy.
        type: str
        required: true
      link_aggregation_policy_name:
        description:
          - Link Aggregation Policy name to associate.
          - The relationship to the Link Aggregation Policy.
        type: str
      state:
        description:
          - Whether to create/update or delete the port channel.
        type: str
        choices: ['present', 'absent']
        default: present
  pin_groups:
    description:
      - List of pin group configurations (both LAN and SAN).
      - Pin groups control traffic distribution across uplinks.
      - LAN pin groups are used for Ethernet uplink ports and port channels.
      - SAN pin groups are used for FCoE uplink ports and port channels.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name of the pin group.
        type: str
        required: true
      pin_group_type:
        description:
          - Type of pin group.
          - Use 'lan' for Ethernet uplink ports and port channels.
          - Use 'san' for FCoE uplink ports and port channels.
        type: str
        choices: ['lan', 'san']
        required: true
      target_interface_type:
        description:
          - Type of target interface.
        type: str
        choices: ['pc', 'port']
        required: true
      target_interface_name:
        description:
          - Name or identifier of the target interface.
          - For pc, this should be the pc_id of an uplink port channel.
          - For port, this should be the port identifier (e.g., '14' or '49/1').
        type: str
        required: true
      state:
        description:
          - Whether to create/update or delete the pin group.
        type: str
        choices: ['present', 'absent']
        default: present
  fc_uplink_ports:
    description:
      - List of FC Uplink port configurations.
      - FC Uplink ports are used for Fibre Channel connectivity to storage networks.
      - For UCS-FI-6454, UCS-FI-64108, UCS-FI-6664 requires fc_port_mode configuration.
      - For UCS-FI-6536, UCSX-S9108-100G uses FC breakout ports (no fc_port_mode needed).
    type: list
    elements: dict
    suboptions:
      port_id:
        description:
          - Port ID to configure as FC Uplink.
          - Must be within the FC port mode range.
          - Can be a regular port (e.g., 1) or aggregate port for FC breakout (e.g., '36/1').
          - For aggregate ports, the base port must be configured as FC breakout.
        type: str
        required: true
      admin_speed:
        description:
          - Administrative speed of the FC port.
        type: str
        choices: ['Auto', '8Gbps', '16Gbps', '32Gbps']
        default: 'Auto'
      vsan_id:
        description:
          - Virtual SAN Identifier associated to the FC port.
        type: int
        required: true
      user_label:
        description:
          - User-defined label for the port.
          - User label must be between 0 and 128 alphanumeric characters.
        type: str
      state:
        description:
          - Whether to create/update or delete the FC Uplink port.
        type: str
        choices: ['present', 'absent']
        default: present
  fc_storage_ports:
    description:
      - List of FC Storage port configurations.
      - FC Storage ports are used for direct storage connectivity.
      - For UCS-FI-6454, UCS-FI-64108, UCS-FI-6664 requires fc_port_mode configuration.
      - For UCS-FI-6536, UCSX-S9108-100G uses FC breakout ports (no fc_port_mode needed).
    type: list
    elements: dict
    suboptions:
      port_id:
        description:
          - Port ID to configure as FC Storage.
          - Must be within the FC port mode range.
          - Can be a regular port (e.g., 2) or aggregate port for FC breakout (e.g., '36/2').
          - For aggregate ports, the base port must be configured as FC breakout.
        type: str
        required: true
      admin_speed:
        description:
          - Administrative speed of the FC port.
        type: str
        choices: ['8Gbps', '16Gbps', '32Gbps']
        default: '8Gbps'
      vsan_id:
        description:
          - VSAN ID associated to the FC Storage port.
        type: int
        required: true
      user_label:
        description:
          - User-defined label for the port.
          - User label must be between 0 and 128 alphanumeric characters.
        type: str
      state:
        description:
          - Whether to create/update or delete the FC Storage port.
        type: str
        choices: ['present', 'absent']
        default: present
  appliance_ports:
    description:
      - List of Appliance port configurations.
      - Appliance ports are used for direct-attached storage connectivity.
    type: list
    elements: dict
    suboptions:
      port_id:
        description:
          - Port ID to configure as Appliance port.
          - Can be a regular port (e.g., 13) or aggregate port (e.g., '49/1').
        type: str
        required: true
      admin_speed:
        description:
          - Administrative speed of the port.
          - 1Gbps only allowed for ports 45-48.
          - 40Gbps and 100Gbps only allowed for ports 49-54.
        type: str
        choices: ['Auto', '1Gbps', '10Gbps', '25Gbps', '40Gbps', '100Gbps']
        default: 'Auto'
      fec:
        description:
          - Forward Error Correction (FEC) mode.
        type: str
        choices: ['Auto', 'Off']
        default: 'Auto'
      priority:
        description:
          - QoS priority for the appliance port.
        type: str
        choices: ['Best Effort', 'FC', 'Platinum', 'Gold', 'Silver', 'Bronze']
        default: 'Best Effort'
      mode:
        description:
          - Port mode for the appliance port.
        type: str
        choices: ['trunk', 'access']
        default: 'trunk'
      eth_network_group_policy_name:
        description:
          - Ethernet Network Group Policy name (required).
          - The relationship to the Fabric Network Group Policy.
        type: str
        required: true
      eth_network_control_policy_name:
        description:
          - Ethernet Network Control Policy name (required).
          - The relationship to the Fabric Network Control Policy.
        type: str
        required: true
      user_label:
        description:
          - User-defined label for the port.
          - User label must be between 0 and 128 alphanumeric characters.
        type: str
      state:
        description:
          - Whether to create/update or delete the appliance port.
        type: str
        choices: ['present', 'absent']
        default: present
  ethernet_uplink_ports:
    description:
      - List of Ethernet Uplink port configurations.
      - Ethernet Uplink ports connect to upstream network switches.
    type: list
    elements: dict
    suboptions:
      port_id:
        description:
          - Port ID to configure as Ethernet Uplink.
          - Can be a regular port (e.g., 14) or aggregate port (e.g., '49/1').
        type: str
        required: true
      admin_speed:
        description:
          - Administrative speed of the port.
          - Speed restrictions apply based on port numbers.
        type: str
        choices: ['Auto', '1Gbps', '10Gbps', '25Gbps', '40Gbps', '100Gbps']
        default: 'Auto'
      fec:
        description:
          - Forward Error Correction (FEC) mode.
        type: str
        choices: ['Auto', 'Off']
        default: 'Auto'
      eth_network_group_policy_name:
        description:
          - List of Ethernet Network Group Policy names.
          - The Ethernet Network Group Policy specifies a set of VLANs to allow on the uplink port.
          - The specified VLAN set must be either identical or disjoint from those specified on other uplink interfaces.
          - Ensure that the VLANs are defined in the VLAN Policy and 'Auto Allow on Uplinks' option is disabled.
          - Note, default VLAN-1 is auto allowed and can be specified as the native VLAN.
        type: list
        elements: str
      flow_control_policy_name:
        description:
          - Flow Control Policy name.
        type: str
      link_control_policy_name:
        description:
          - Link Control Policy name.
        type: str
      mac_sec_policy_name:
        description:
          - MAC Security Policy name.
          - The relationship to the Media Access Control Security (MACsec) Policy.
        type: str
      user_label:
        description:
          - User-defined label for the port.
          - User label must be between 0 and 128 alphanumeric characters.
        type: str
      state:
        description:
          - Whether to create/update or delete the Ethernet Uplink port.
        type: str
        choices: ['present', 'absent']
        default: present
  fcoe_uplink_ports:
    description:
      - List of FCoE Uplink port configurations.
      - FCoE Uplink ports provide Fibre Channel over Ethernet connectivity.
    type: list
    elements: dict
    suboptions:
      port_id:
        description:
          - Port ID to configure as FCoE Uplink.
          - Can be a regular port (e.g., 15) or aggregate port (e.g., '49/1').
        type: str
        required: true
      admin_speed:
        description:
          - Administrative speed of the port.
        type: str
        choices: ['Auto', '1Gbps', '10Gbps', '25Gbps', '40Gbps', '100Gbps']
        default: 'Auto'
      fec:
        description:
          - Forward Error Correction (FEC) mode.
        type: str
        choices: ['Auto', 'Off']
        default: 'Auto'
      link_control_policy_name:
        description:
          - Link Control Policy name.
        type: str
      user_label:
        description:
          - User-defined label for the port.
          - User label must be between 0 and 128 alphanumeric characters.
        type: str
      state:
        description:
          - Whether to create/update or delete the FCoE Uplink port.
        type: str
        choices: ['present', 'absent']
        default: present
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a Port Policy with breakout ports and server ports
  cisco.intersight.intersight_port_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "port-policy-example"
    description: "Example port policy with various configurations"
    device_model: "UCS-FI-6454"
    tags:
      - Key: "Environment"
        Value: "Production"
    breakout_ports:
      - port_id: 49
        custom_mode: "BreakoutEthernet25G"
        state: present
    server_ports:
      - port_id: 1
        fec: "Auto"
        manual_numbering: false
        user_label: "Server Port 1"
        state: present
      - port_id: 2
        fec: "Auto"
        manual_numbering: true
        preferred_device_type: "RackServer"
        preferred_device_id: 2
        user_label: "Server Port with Manual Numbering"
        state: present
    state: present

- name: Create a Port Policy with Ethernet uplink port channel
  cisco.intersight.intersight_port_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "port-policy-with-pc"
    description: "Port policy with port channel configurations"
    device_model: "UCS-FI-6454"
    ethernet_uplink_port_channels:
      - pc_id: 123
        admin_speed: "25Gbps"
        fec: "Auto"
        user_label: "Uplink PC 123"
        ports:
          - port_id: 36
          - port_id: 37
          - port_id: "49/1"
          - port_id: "49/2"
        eth_network_group_policy_names:
          - "default-network-group"
        flow_control_policy_name: "default-flow-control"
        link_aggregation_policy_name: "default-link-aggregation"
        link_control_policy_name: "default-link-control"
        state: present
    state: present

- name: Create a Port Policy with FC uplink port channel
  cisco.intersight.intersight_port_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-port-channel-policy"
    device_model: "UCS-FI-6454"
    fc_port_mode:
      port_id_end: 8
      state: present
    fc_uplink_port_channels:
      - pc_id: 13
        admin_speed: "16Gbps"
        vsan_id: 1
        ports:
          - port_id: 1
          - port_id: 2
          - port_id: 3
          - port_id: 4
        state: present
    state: present

- name: Create a Port Policy with appliance port channel
  cisco.intersight.intersight_port_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "appliance-pc-policy"
    device_model: "UCS-FI-6454"
    appliance_port_channels:
      - pc_id: 21
        admin_speed: "Auto"
        fec: "Auto"
        priority: "Best Effort"
        mode: "trunk"
        user_label: "Storage PC"
        ports:
          - port_id: 11
          - port_id: 12
        eth_network_group_policy_name: "storage-network-group"
        eth_network_control_policy_name: "storage-network-control"
        link_aggregation_policy_name: "default-link-aggregation"
        state: present
    state: present

- name: Create a Port Policy with LAN pin groups
  cisco.intersight.intersight_port_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "port-policy-with-pin-groups"
    description: "Port policy with LAN pin group configuration"
    device_model: "UCS-FI-6454"
    breakout_ports:
      - port_id: 49
        custom_mode: "BreakoutEthernet25G"
        state: present
    ethernet_uplink_port_channels:
      - pc_id: 1
        admin_speed: "Auto"
        ports:
          - port_id: 53
          - port_id: 54
        eth_network_group_policy_names:
          - "default-network-group"
        state: present
    ethernet_uplink_ports:
      - port_id: 14
        admin_speed: "Auto"
        fec: "Auto"
        eth_network_group_policy_name:
          - "default-network-group"
        state: present
    fcoe_uplink_ports:
      - port_id: "49/1"
        admin_speed: "Auto"
        fec: "Auto"
        state: present
    pin_groups:
      - name: "pin-group-1"
        pin_group_type: "lan"
        target_interface_type: "pc"
        target_interface_name: "1"
        state: present
      - name: "pin-group-2"
        pin_group_type: "lan"
        target_interface_type: "port"
        target_interface_name: "14"
        state: present
      - name: "pin-group-3"
        pin_group_type: "san"
        target_interface_type: "port"
        target_interface_name: "49/1"
        state: present
    state: present

- name: Update Port Policy - manage resource states
  cisco.intersight.intersight_port_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "port-policy-update"
    device_model: "UCS-FI-6454"
    server_ports:
      - port_id: 3
        user_label: "New Server Port"
        state: present
      - port_id: 4
        state: absent
    state: present

- name: Create a Port Policy with Fibre Channel ports 1-16
  cisco.intersight.intersight_port_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "fc-port-policy"
    device_model: "UCS-FI-6454"
    fc_port_mode:
      port_id_end: 16
      state: present
    fc_uplink_ports:
      - port_id: 1
        admin_speed: "8Gbps"
        vsan_id: 2
        user_label: "FC Uplink 1"
        state: present
      - port_id: "49/1"
        admin_speed: "16Gbps"
        vsan_id: 3
        user_label: "FC Uplink Aggregate"
        state: present
    fc_storage_ports:
      - port_id: 2
        admin_speed: "8Gbps"
        vsan_id: 5
        user_label: "FC Storage 2"
        state: present
    state: present

- name: Create a Port Policy with Appliance and Ethernet Uplink ports
  cisco.intersight.intersight_port_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "mixed-port-policy"
    device_model: "UCS-FI-6454"
    appliance_ports:
      - port_id: 13
        admin_speed: "10Gbps"
        fec: "Auto"
        priority: "Best Effort"
        mode: "trunk"
        eth_network_group_policy_name: "default-network-group"
        eth_network_control_policy_name: "default-network-control"
        user_label: "Storage Appliance"
        state: present
    ethernet_uplink_ports:
      - port_id: 14
        admin_speed: "Auto"
        fec: "Auto"
        eth_network_group_policy_name:
          - "default-network-group"
        flow_control_policy_name: "default-flow-control"
        link_control_policy_name: "default-link-control"
        state: present
    fcoe_uplink_ports:
      - port_id: 15
        admin_speed: "Auto"
        fec: "Auto"
        link_control_policy_name: "default-link-control"
        user_label: "FCoE Uplink"
        state: present
    state: present

- name: Delete a Port Policy
  cisco.intersight.intersight_port_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "port-policy-to-delete"
    state: absent

# Device Model Specific Examples

- name: UCS-FI-64108 Port Policy with device-specific features
  cisco.intersight.intersight_port_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "UCS-FI-64108-policy"
    device_model: "UCS-FI-64108"
    description: "Port policy for UCS-FI-64108 with 108 ports"
    breakout_ports:
      - port_id: 97
        custom_mode: "BreakoutEthernet25G"
        state: present
      - port_id: 108
        custom_mode: "BreakoutEthernet10G"
        state: present
    ethernet_uplink_ports:
      - port_id: 89
        admin_speed: "1Gbps"
        state: present
      - port_id: 97
        admin_speed: "100Gbps"
        state: present
    state: present

- name: UCS-FI-6536 Port Policy with FC breakout support
  cisco.intersight.intersight_port_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "UCS-FI-6536-policy"
    device_model: "UCS-FI-6536"
    description: "Port policy for UCS-FI-6536 with FC breakout"
    breakout_ports:
      - port_id: 36
        custom_mode: "BreakoutFibreChannel16G"
        state: present
      - port_id: 35
        custom_mode: "BreakoutFibreChannel32G"
        state: present
      - port_id: 1
        custom_mode: "BreakoutEthernet25G"
        state: present
    ethernet_uplink_ports:
      - port_id: 9
        admin_speed: "1Gbps"
        state: present
    fc_uplink_ports:
      - port_id: "36/1"
        admin_speed: "16Gbps"
        vsan_id: 1
        state: present
    fc_storage_ports:
      - port_id: "35/2"
        admin_speed: "32Gbps"
        vsan_id: 2
        state: present
    state: present

- name: UCS-FI-6664 Port Policy without breakout support
  cisco.intersight.intersight_port_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "UCS-FI-6664-policy"
    device_model: "UCS-FI-6664"
    description: "Port policy for UCS-FI-6664 - no breakout support"
    fc_port_mode:
      port_id_start: 25
      port_id_end: 40
      state: present
    ethernet_uplink_ports:
      - port_id: 1
        admin_speed: "100Gbps"
        state: present
      - port_id: 50
        admin_speed: "40Gbps"
        state: present
    fc_uplink_ports:
      - port_id: 25
        admin_speed: "32Gbps"
        vsan_id: 1
        state: present
    state: present

- name: UCSX-S9108-100G Port Policy with FC breakout
  cisco.intersight.intersight_port_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "UCSX-S9108-100G-policy"
    device_model: "UCSX-S9108-100G"
    description: "Port policy for UCSX-S9108-100G with FC breakout"
    breakout_ports:
      - port_id: 1
        custom_mode: "BreakoutFibreChannel16G"
        state: present
      - port_id: 2
        custom_mode: "BreakoutFibreChannel8G"
        state: present
    ethernet_uplink_ports:
      - port_id: 7
        admin_speed: "1Gbps"
        state: present
      - port_id: 8
        admin_speed: "1Gbps"
        state: present
    fc_uplink_ports:
      - port_id: "1/1"
        admin_speed: "16Gbps"
        vsan_id: 1
        state: present
      - port_id: "2/3"
        admin_speed: "8Gbps"
        vsan_id: 1
        state: present
    state: present
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "port-policy-example",
        "DeviceModel": "UCS-FI-6454",
        "ObjectType": "fabric.PortPolicy",
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Production"
            }
        ],
        "BreakoutPorts": [
            {
                "SlotId": 1,
                "PortIdStart": 49,
                "PortIdEnd": 49,
                "CustomMode": "BreakoutEthernet25G"
            }
        ],
        "ServerPorts": [
            {
                "SlotId": 1,
                "PortId": 1,
                "Fec": "Auto",
                "UserLabel": "Server Port 1"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def parse_port_id(port_input):
    """
    Parse port ID input to determine if it's a regular or aggregate port.

    Args:
        port_input: Port specification (int like 49 or string like "49/2")

    Returns:
        Dictionary with:
        - is_aggregate: Boolean indicating if it's an aggregate port
        - port_id: The port ID (2 for aggregate "49/2", 49 for regular 49)
        - aggregate_port_id: The aggregate port ID (49 for "49/2", None for regular)
        - display_name: Human readable name ("port49/2" or "port49")
    """
    if isinstance(port_input, str) and '/' in port_input:
        # Aggregate port syntax: "49/2"
        try:
            aggregate_port_str, port_str = port_input.split('/')
            aggregate_port_id = int(aggregate_port_str)
            port_id = int(port_str)

            # Validate aggregate port sub-port range (1-4)
            if not (1 <= port_id <= 4):
                raise ValueError(f"Aggregate port sub-port must be between 1-4, got {port_id}")

            return {
                'is_aggregate': True,
                'port_id': port_id,
                'aggregate_port_id': aggregate_port_id,
                'display_name': f"port{aggregate_port_id}/{port_id}"
            }
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid aggregate port format '{port_input}'. Expected format: '49/2'") from e
    else:
        # Regular port: just a number
        try:
            port_id = int(port_input)
            return {
                'is_aggregate': False,
                'port_id': port_id,
                'aggregate_port_id': None,
                'display_name': f"port{port_id}"
            }
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid port format '{port_input}'. Expected integer or 'X/Y' format") from e


def get_device_model_constraints(device_model):
    """
    Get device model specific constraints and capabilities.

    Args:
        device_model: Device model string

    Returns:
        Dictionary with device-specific constraints
    """
    constraints = {
        'UCS-FI-6454': {
            'total_ports': 54,
            'port_range': (1, 54),
            'fc_port_range': (1, 16),
            'breakout_ports': (49, 54),
            'fc_breakout_supported': False,
            'admin_speed_restrictions': {
                # No specific restrictions for UCS-FI-6454 in the original implementation
            },
            'supported_breakout_modes': ['BreakoutEthernet10G', 'BreakoutEthernet25G']
        },
        'UCS-FI-64108': {
            'total_ports': 108,
            'port_range': (1, 108),
            'fc_port_range': (1, 16),
            'breakout_ports': (97, 108),
            'fc_breakout_supported': False,
            'admin_speed_restrictions': {
                (89, 96): ['1Gbps'],  # 1Gbps only for ports 89-96
                (97, 108): ['40Gbps', '100Gbps']  # 40Gbps and 100Gbps for ports 97-108
            },
            'supported_breakout_modes': ['BreakoutEthernet10G', 'BreakoutEthernet25G']
        },
        'UCS-FI-6536': {
            'total_ports': 36,
            'port_range': (1, 36),
            'fc_port_range': (33, 36),
            'breakout_ports': (1, 36),
            'fc_breakout_supported': True,
            'admin_speed_restrictions': {
                (9, 10): ['1Gbps']  # 1Gbps only for ports 9-10
            },
            'supported_breakout_modes': [
                'BreakoutEthernet10G',
                'BreakoutEthernet25G',
                'BreakoutFibreChannel8G',
                'BreakoutFibreChannel16G',
                'BreakoutFibreChannel32G'
            ]
        },
        'UCS-FI-6664': {
            'total_ports': 64,
            'port_range': (1, 64),
            'fc_port_range': (25, 40),
            'breakout_ports': None,  # No breakout support
            'fc_breakout_supported': False,
            'admin_speed_restrictions': {
                (1, 24): ['40Gbps', '100Gbps'],  # 40Gbps and 100Gbps for ports 1-24
                (41, 64): ['40Gbps', '100Gbps']  # 40Gbps and 100Gbps for ports 41-64
            },
            'supported_breakout_modes': []
        },
        'UCSX-S9108-100G': {
            'total_ports': 8,
            'port_range': (1, 8),
            'fc_port_range': (1, 2),
            'breakout_ports': (1, 2),  # Only FC ports support breakout
            'fc_breakout_supported': True,
            'admin_speed_restrictions': {
                (7, 8): ['1Gbps']  # 1Gbps only for ports 7-8
            },
            'supported_breakout_modes': ['BreakoutFibreChannel8G', 'BreakoutFibreChannel16G', 'BreakoutFibreChannel32G']
        }
    }

    return constraints.get(device_model, {})


def validate_port_range_for_device(module, port_id, device_model, port_type="port"):
    """
    Validate port ID is within the valid range for the device model.

    Args:
        module: AnsibleModule instance
        port_id: Port ID to validate
        device_model: Device model string
        port_type: Type of port for error messages
    """
    constraints = get_device_model_constraints(device_model)

    if not constraints:
        module.fail_json(msg=f"Unsupported device model: {device_model}")

    port_range = constraints.get('port_range', (1, 1))
    min_port, max_port = port_range

    if port_id < min_port or port_id > max_port:
        module.fail_json(
            msg=f"{port_type} {port_id} is outside valid range for {device_model}. "
                f"Valid range: {min_port}-{max_port}"
        )


def validate_admin_speed_for_device(module, port_id, admin_speed, device_model, port_type="port"):
    """
    Validate admin speed is allowed for the specific port on the device model.

    Args:
        module: AnsibleModule instance
        port_id: Port ID
        admin_speed: Admin speed to validate
        device_model: Device model string
        port_type: Type of port for error messages
    """
    if admin_speed == 'Auto':
        return  # Auto is always allowed

    constraints = get_device_model_constraints(device_model)
    speed_restrictions = constraints.get('admin_speed_restrictions', {})

    for port_range, allowed_speeds in speed_restrictions.items():
        min_port, max_port = port_range
        if min_port <= port_id <= max_port:
            if admin_speed not in allowed_speeds:
                allowed_str = ', '.join(allowed_speeds)
                module.fail_json(
                    msg=f"{port_type} {port_id} on {device_model} only supports admin speeds: {allowed_str}. "
                        f"Got: {admin_speed}"
                )
            return


def validate_breakout_port_for_device(module, port_id, device_model):
    """
    Validate that breakout is supported for the specific port on the device model.

    Args:
        module: AnsibleModule instance
        port_id: Port ID to validate
        device_model: Device model string
    """
    constraints = get_device_model_constraints(device_model)
    breakout_ports = constraints.get('breakout_ports')

    if breakout_ports is None:
        module.fail_json(
            msg=f"Breakout ports are not supported on {device_model}"
        )

    min_breakout, max_breakout = breakout_ports
    if port_id < min_breakout or port_id > max_breakout:
        module.fail_json(
            msg=f"Port {port_id} cannot be configured as breakout on {device_model}. "
                f"Breakout ports range: {min_breakout}-{max_breakout}"
        )


def validate_fc_port_range_for_device(module, port_id, device_model):
    """
    Validate FC port ID is within the valid FC range for the device model.

    Args:
        module: AnsibleModule instance
        port_id: Port ID to validate
        device_model: Device model string
    """
    constraints = get_device_model_constraints(device_model)
    fc_port_range = constraints.get('fc_port_range')

    if not fc_port_range:
        module.fail_json(
            msg=f"FC ports are not supported on {device_model}"
        )

    min_fc, max_fc = fc_port_range
    if port_id < min_fc or port_id > max_fc:
        module.fail_json(
            msg=f"FC port {port_id} is outside valid FC range for {device_model}. "
                f"Valid FC range: {min_fc}-{max_fc}"
        )


def validate_breakout_mode_for_device(module, custom_mode, device_model):
    """
    Validate breakout mode is supported for the device model.

    Args:
        module: AnsibleModule instance
        custom_mode: Breakout mode to validate
        device_model: Device model string
    """
    constraints = get_device_model_constraints(device_model)
    supported_modes = constraints.get('supported_breakout_modes', [])

    if custom_mode not in supported_modes:
        supported_str = ', '.join(supported_modes)
        module.fail_json(
            msg=f"Breakout mode '{custom_mode}' is not supported on {device_model}. "
                f"Supported modes: {supported_str}"
        )


def validate_breakout_port_config(module, breakout_config):
    """
    Validate breakout port configuration with device model specific constraints.

    Args:
        module: AnsibleModule instance
        breakout_config: Dictionary containing breakout port configuration
    """
    port_id = breakout_config.get('port_id')
    custom_mode = breakout_config.get('custom_mode')
    device_model = module.params.get('device_model')

    if port_id:
        # Basic port ID validation
        if port_id < 1:
            module.fail_json(msg=f"port_id ({port_id}) must be greater than 0")

        # Device-specific validations
        validate_port_range_for_device(module, port_id, device_model, "Breakout port")
        validate_breakout_port_for_device(module, port_id, device_model)

        if custom_mode:
            validate_breakout_mode_for_device(module, custom_mode, device_model)


def validate_uplink_port_channel_config(module, pc_config):
    """
    Validate uplink port channel configuration.

    Args:
        module: AnsibleModule instance
        pc_config: Dictionary containing port channel configuration
    """
    ports = pc_config.get('ports', [])

    if not ports:
        module.fail_json(msg=f"At least one port must be specified for port channel {pc_config.get('pc_id')}")

    port_ids = [p['port_id'] for p in ports]
    if len(port_ids) != len(set(port_ids)):
        module.fail_json(msg=f"Duplicate ports found in port channel {pc_config.get('pc_id')}")


def validate_port_id_uniqueness(module):
    """
    Validate that port IDs don't overlap across different port types.
    Handles both regular ports and aggregate ports properly.

    Args:
        module: AnsibleModule instance
    """
    # Separate lists for regular ports and aggregate ports
    regular_ports = []  # Regular port IDs (e.g., 49)
    aggregate_ports = []  # Aggregate port strings (e.g., "port49/2")
    aggregate_base_ports = set()  # Base ports used for aggregation (e.g., 49)

    def add_port_to_lists(port_input):
        """Helper to add port to appropriate list based on type."""
        try:
            port_info = parse_port_id(port_input)
            if port_info['is_aggregate']:
                aggregate_ports.append(port_info['display_name'])
                # Track the base port used for aggregation
                aggregate_base_ports.add(port_info['aggregate_port_id'])
            else:
                regular_ports.append(port_info['port_id'])
        except ValueError as e:
            module.fail_json(msg=f"Invalid port specification: {e}")

    # Add all port role configurations
    port_role_configs = [
        ('server_ports', module.params.get('server_ports')),
        ('fc_uplink_ports', module.params.get('fc_uplink_ports')),
        ('fc_storage_ports', module.params.get('fc_storage_ports')),
        ('appliance_ports', module.params.get('appliance_ports')),
        ('ethernet_uplink_ports', module.params.get('ethernet_uplink_ports')),
        ('fcoe_uplink_ports', module.params.get('fcoe_uplink_ports'))
    ]

    for port_type_name, port_configs in port_role_configs:
        if port_configs:
            for port_config in port_configs:
                if port_config.get('state', 'present') == 'present':
                    add_port_to_lists(port_config['port_id'])

    # Add port channel member ports (can be regular or aggregate)
    # TODO: Note to myself, please don't remove it or take it into account for now - I will need to handle port channel for aggregation in specific hardware.
    def add_port_channel_ports(port_channels):
        """Helper function to add port channel ports to appropriate lists."""
        for pc_config in port_channels:
            if pc_config.get('state', 'present') == 'present':
                ports = pc_config.get('ports', [])
                for port in ports:
                    port_id = port['port_id']
                    aggregate_port_id = port.get('aggregate_port_id')

                    if aggregate_port_id:
                        # Legacy syntax: aggregate_port_id specified separately
                        aggregate_ports.append(f"port{aggregate_port_id}/{port_id}")
                        # Track the base port used for aggregation
                        aggregate_base_ports.add(aggregate_port_id)
                    else:
                        # port_id can be "49/2" format or regular
                        add_port_to_lists(port_id)

    # Add all port channel types
    if module.params.get('ethernet_uplink_port_channels'):
        add_port_channel_ports(module.params.get('ethernet_uplink_port_channels'))
    if module.params.get('fc_uplink_port_channels'):
        add_port_channel_ports(module.params.get('fc_uplink_port_channels'))
    if module.params.get('fcoe_uplink_port_channels'):
        add_port_channel_ports(module.params.get('fcoe_uplink_port_channels'))
    if module.params.get('appliance_port_channels'):
        add_port_channel_ports(module.params.get('appliance_port_channels'))

    # Add breakout port ranges (these create the base ports for aggregation)
    breakout_ports = module.params.get('breakout_ports')
    if breakout_ports:
        for breakout_config in breakout_ports:
            if breakout_config.get('state', 'present') == 'present':
                port_id = breakout_config['port_id']
                # Breakout ports become aggregate base ports, not regular ports
                aggregate_base_ports.add(port_id)

    def find_duplicates(port_list):
        """Helper function to find duplicates in a list."""
        if len(port_list) == len(set(port_list)):
            return []

        duplicates = []
        unique_items = set(port_list)
        for item in unique_items:
            if port_list.count(item) > 1:
                duplicates.append(item)
        return duplicates

    # Check for duplicates in both port lists
    regular_duplicates = find_duplicates(regular_ports)
    aggregate_duplicates = find_duplicates(aggregate_ports)

    # Check for conflicts between regular ports and aggregate base ports
    regular_ports_set = set(regular_ports)
    base_regular_conflicts = regular_ports_set.intersection(aggregate_base_ports)

    # Report conflicts
    conflicts = []
    if regular_duplicates:
        regular_conflict_str = ', '.join(map(str, sorted(regular_duplicates)))
        conflicts.append(f"Regular ports: {regular_conflict_str}")

    if aggregate_duplicates:
        aggregate_conflict_str = ', '.join(sorted(aggregate_duplicates))
        conflicts.append(f"Aggregate ports: {aggregate_conflict_str}")

    if base_regular_conflicts:
        base_conflict_str = ', '.join(map(str, sorted(base_regular_conflicts)))
        conflicts.append(f"Ports used as both regular and aggregate base: {base_conflict_str}")

    if conflicts:
        conflict_message = "Port ID conflicts detected. The following ports are assigned multiple roles:\n" + '\n'.join(conflicts)
        module.fail_json(msg=conflict_message)


def validate_fc_port_constraints(module):
    """
    Validate FC port constraints with device model specific validation.

    Args:
        module: AnsibleModule instance
    """
    fc_port_mode = module.params.get('fc_port_mode')
    fc_uplink_ports = module.params.get('fc_uplink_ports')
    fc_storage_ports = module.params.get('fc_storage_ports')
    device_model = module.params.get('device_model')

    # For UCS-FI-6536 and UCSX-S9108-100G, FC is only available through breakout ports
    # Warn user if they specify fc_port_mode for these models
    if fc_port_mode and device_model in ['UCS-FI-6536', 'UCSX-S9108-100G']:
        module.warn(
            f"fc_port_mode is not supported on {device_model}. "
            f"FC functionality is available through breakout ports only. "
            f"Ignoring fc_port_mode configuration."
        )
        # Override the parameter to prevent it from being processed
        module.params['fc_port_mode'] = None
        fc_port_mode = None

    # If FC mode is configured, validate FC port IDs are within range
    if fc_port_mode and fc_port_mode.get('state', 'present') == 'present':
        port_start = fc_port_mode.get('port_id_start', 1)
        port_end = fc_port_mode['port_id_end']

        # Validate FC port mode range against device capabilities
        constraints = get_device_model_constraints(device_model)
        fc_port_range = constraints.get('fc_port_range')

        if not fc_port_range:
            module.fail_json(msg=f"FC ports are not supported on {device_model}")

        device_fc_min, device_fc_max = fc_port_range

        # For most models (except UCS-FI-6536), the minimum FC port must always be included in the range
        if device_model != 'UCS-FI-6536' and port_start != device_fc_min:
            module.fail_json(
                msg=f"For {device_model}, FC port mode must always include the minimum FC port. "
                    f"port_id_start must be {device_fc_min}, got {port_start}"
            )

        # Device-specific validation for maximum FC port
        if device_model == 'UCS-FI-6536':
            # For UCS-FI-6536, port 36 must always be included in FC range
            if port_end != 36:
                module.fail_json(
                    msg=f"For {device_model}, FC port mode must always include port 36. "
                        f"port_id_end must be 36, got {port_end}"
                )
        elif device_model in ['UCS-FI-6454', 'UCS-FI-64108']:
            # For these models, port_id_end must be one of the standard values
            if port_end not in [4, 8, 12, 16]:
                module.fail_json(
                    msg=f"For {device_model}, port_id_end must be one of [4, 8, 12, 16]. Got {port_end}"
                )

        # Validate that FC port mode range is within device FC capabilities
        if port_start < device_fc_min or port_end > device_fc_max:
            module.fail_json(
                msg=f"FC port mode range ({port_start}-{port_end}) is outside device FC range for {device_model}. "
                    f"Valid FC range: {device_fc_min}-{device_fc_max}"
            )

        def validate_fc_port_range(fc_configs, port_type):
            """Helper function to validate FC ports are within FC port mode range and device capabilities."""
            if not fc_configs:
                return
            for fc_config in fc_configs:
                if fc_config.get('state', 'present') == 'present':
                    try:
                        port_info = parse_port_id(fc_config['port_id'])
                        # For aggregate ports, check the base port; for regular ports, check the port itself
                        check_port = port_info['aggregate_port_id'] if port_info['is_aggregate'] else port_info['port_id']

                        # Special validation for FC breakout ports
                        if port_info['is_aggregate']:
                            # FC roles on aggregate ports (FC breakout) are only supported on specific devices
                            if device_model not in ['UCS-FI-6536', 'UCSX-S9108-100G']:
                                module.fail_json(
                                    msg=f"FC roles on breakout ports (aggregate ports) are only supported on UCS-FI-6536 and UCSX-S9108-100G. "
                                        f"Device {device_model} does not support {port_type} on breakout port {fc_config['port_id']}"
                                )

                        # Validate against FC port mode range
                        if check_port < port_start or check_port > port_end:
                            module.fail_json(
                                msg=f"{port_type} port {fc_config['port_id']} is outside the FC port mode range ({port_start}-{port_end})"
                            )

                        # Validate against device FC capabilities
                        validate_fc_port_range_for_device(module, check_port, device_model)

                        # Validate admin speed for FC ports
                        admin_speed = fc_config.get('admin_speed')
                        if admin_speed and admin_speed != 'Auto':
                            validate_admin_speed_for_device(module, check_port, admin_speed, device_model, f"{port_type} port")

                    except ValueError as e:
                        module.fail_json(msg=f"Invalid {port_type} port specification: {e}")

        # Validate both FC port types
        validate_fc_port_range(fc_uplink_ports, "FC Uplink")
        validate_fc_port_range(fc_storage_ports, "FC Storage")


def validate_server_port_constraints(module):
    """
    Validate server port specific constraints with device model validation.

    Args:
        module: AnsibleModule instance
    """
    server_ports = module.params.get('server_ports')
    device_model = module.params.get('device_model')

    if not server_ports:
        return

    for server_config in server_ports:
        if server_config.get('state', 'present') == 'present':
            manual_numbering = server_config.get('manual_numbering', False)
            preferred_device_type = server_config.get('preferred_device_type')
            preferred_device_id = server_config.get('preferred_device_id')
            port_id = server_config['port_id']

            # Parse port ID to check if it's an aggregate port
            port_info = parse_port_id(port_id)
            check_port = port_info['aggregate_port_id'] if port_info['is_aggregate'] else port_info['port_id']

            # Device model specific validation
            validate_port_range_for_device(module, check_port, device_model, "Server port")

            # Manual numbering cannot be used with aggregate ports
            if manual_numbering and port_info['is_aggregate']:
                module.fail_json(
                    msg=f"manual_numbering cannot be true for aggregate port {port_id}. Manual numbering is not supported on breakout/aggregate ports."
                )

            # If manual_numbering is true, device type and device ID are required
            if manual_numbering:
                if not preferred_device_type:
                    # Default to 'Chassis' if not specified when manual numbering is enabled
                    server_config['preferred_device_type'] = 'Chassis'
                    preferred_device_type = 'Chassis'

                if not preferred_device_id:
                    module.fail_json(
                        msg=f"preferred_device_id is required when manual_numbering is true for server port {port_id}"
                    )

            # If preferred_device_type is specified, preferred_device_id is required
            if preferred_device_type and not preferred_device_id:
                module.fail_json(
                    msg=f"preferred_device_id is required when preferred_device_type is specified for server port {server_config['port_id']}"
                )

            # If preferred_device_id is specified, preferred_device_type is required
            if preferred_device_id and not preferred_device_type:
                module.fail_json(
                    msg=f"preferred_device_type is required when preferred_device_id is specified for server port {server_config['port_id']}"
                )


def validate_appliance_port_constraints(module):
    """
    Validate appliance port specific constraints with device model validation.

    Args:
        module: AnsibleModule instance
    """
    appliance_ports = module.params.get('appliance_ports')
    device_model = module.params.get('device_model')

    if not appliance_ports:
        return

    for appliance_config in appliance_ports:
        if appliance_config.get('state', 'present') == 'present':
            try:
                port_info = parse_port_id(appliance_config['port_id'])
                # For aggregate ports, check the base port; for regular ports, check the port itself
                check_port = port_info['aggregate_port_id'] if port_info['is_aggregate'] else port_info['port_id']
                admin_speed = appliance_config.get('admin_speed', 'Auto')

                # Device model specific validation
                validate_port_range_for_device(module, check_port, device_model, "Appliance port")

                # Validate admin speed for the device model and port
                validate_admin_speed_for_device(module, check_port, admin_speed, device_model, "Appliance port")

            except ValueError as e:
                module.fail_json(msg=f"Invalid Appliance port specification: {e}")


def validate_port_channel_constraints(module):
    """
    Validate port channel specific constraints.

    Args:
        module: AnsibleModule instance
    """
    # List of all port channel parameter names
    port_channel_params = [
        'ethernet_uplink_port_channels',
        'fc_uplink_port_channels',
        'fcoe_uplink_port_channels',
        'appliance_port_channels'
    ]

    for param_name in port_channel_params:
        port_channels = module.params.get(param_name)
        if not port_channels:
            continue

        for pc_config in port_channels:
            if pc_config.get('state', 'present') == 'present':
                pc_id = pc_config.get('pc_id')
                if pc_id is not None:
                    # PcId must be less than 257
                    if pc_id >= 257:
                        module.fail_json(
                            msg=f"pc_id {pc_id} in {param_name} must be less than 256. Valid range is 1-256."
                        )
                    # PcId must be positive
                    if pc_id < 1:
                        module.fail_json(
                            msg=f"pc_id {pc_id} in {param_name} must be greater than 0. Valid range is 1-256."
                        )


def validate_generic_ports(module, port_configs, port_type):
    """
    Generic port validation for various port types.

    Args:
        module: AnsibleModule instance
        port_configs: List of port configurations
        port_type: Type of port for error messages
    """
    if not port_configs:
        return

    device_model = module.params.get('device_model')

    for port_config in port_configs:
        if port_config.get('state', 'present') == 'present':
            try:
                port_info = parse_port_id(port_config['port_id'])
                check_port = port_info['aggregate_port_id'] if port_info['is_aggregate'] else port_info['port_id']

                # Device model specific validation
                validate_port_range_for_device(module, check_port, device_model, port_type)

                # Validate admin speed if present
                admin_speed = port_config.get('admin_speed')
                if admin_speed and admin_speed != 'Auto':
                    validate_admin_speed_for_device(module, check_port, admin_speed, device_model, port_type)

            except ValueError as e:
                module.fail_json(msg=f"Invalid {port_type} specification: {e}")


def validate_input(module):
    """
    Validate module input parameters with comprehensive device model support.

    Args:
        module: AnsibleModule instance
    """
    # Validate port ID uniqueness across all port types
    validate_port_id_uniqueness(module)

    # Validate FC port constraints
    validate_fc_port_constraints(module)

    # Validate server port constraints
    validate_server_port_constraints(module)

    # Validate appliance port constraints
    validate_appliance_port_constraints(module)

    # Validate ethernet uplink ports
    validate_generic_ports(module, module.params.get('ethernet_uplink_ports'), "Ethernet Uplink port")

    # Validate fcoe uplink ports
    validate_generic_ports(module, module.params.get('fcoe_uplink_ports'), "FCoE Uplink port")

    # Validate port channel constraints
    validate_port_channel_constraints(module)

    # Validate breakout port configurations
    breakout_ports = module.params.get('breakout_ports')
    if breakout_ports:
        for breakout_config in breakout_ports:
            if breakout_config.get('state', 'present') == 'present':
                validate_breakout_port_config(module, breakout_config)

    # Validate uplink port channel configurations
    uplink_port_channels = module.params.get('uplink_port_channels')
    if uplink_port_channels:
        for pc_config in uplink_port_channels:
            if pc_config.get('state', 'present') == 'present':
                validate_uplink_port_channel_config(module, pc_config)


def resolve_policy_moid(intersight, policy_cache, resource_path, policy_name, policy_type):
    """
    Resolve policy name to MOID with caching and organization scoping.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary for caching policy MOIDs
        resource_path: API resource path for the policy
        policy_name: Name of the policy to resolve
        policy_type: Type of policy for error messages

    Returns:
        MOID of the policy or None if not found
    """
    cache_key = f"{resource_path}:{policy_name}"

    if cache_key in policy_cache:
        return policy_cache[cache_key]

    organization_name = intersight.module.params['organization']
    moid = intersight.get_moid_by_name_and_org(
        resource_path=resource_path,
        resource_name=policy_name,
        organization_name=organization_name
    )

    if not moid:
        intersight.module.fail_json(msg=f"{policy_type} '{policy_name}' not found in organization '{organization_name}'")

    policy_cache[cache_key] = moid
    return moid


def build_port_policy_filter(api_body):
    """
    Build specific filter string for port policy secondary resources.

    Creates a precise filter to identify exactly one resource by combining:
    - PortPolicy.Moid (required for all port policy resources)
    - SlotId (always 1, required for port-specific resources)
    - Resource-specific identifiers (PortId, PcId, PortIdStart/End, AggregatePortId)

    Args:
        api_body: Dictionary containing the API body

    Returns:
        Filter string for querying the specific resource
    """
    filter_conditions = []

    # Always filter by PortPolicy - required for all port policy resources
    if 'PortPolicy' in api_body:
        if isinstance(api_body['PortPolicy'], dict) and 'Moid' in api_body['PortPolicy']:
            filter_conditions.append(f"PortPolicy.Moid eq '{api_body['PortPolicy']['Moid']}'")
        elif isinstance(api_body['PortPolicy'], str):
            filter_conditions.append(f"PortPolicy.Moid eq '{api_body['PortPolicy']}'")

    # Add PcId filter for port channels (most specific identifier)
    if 'PcId' in api_body:
        filter_conditions.append(f"PcId eq {api_body['PcId']}")
    # Add PortId filter for individual ports
    elif 'PortId' in api_body:
        filter_conditions.append(f"PortId eq {api_body['PortId']}")
        # Add AggregatePortId filter for aggregate ports (makes port unique)
        if 'AggregatePortId' in api_body:
            filter_conditions.append(f"AggregatePortId eq {api_body['AggregatePortId']}")
    # Add PortIdStart/PortIdEnd for breakout ports and FC port modes
    elif 'PortIdStart' in api_body and 'PortIdEnd' in api_body:
        filter_conditions.append(f"PortIdStart eq {api_body['PortIdStart']}")
        filter_conditions.append(f"PortIdEnd eq {api_body['PortIdEnd']}")

    return ' and '.join(filter_conditions)


def configure_port_policy_resource(intersight, resource_path, state):
    """
    Configure a port policy secondary resource using proper field-based filtering.

    Args:
        intersight: IntersightModule instance with api_body already set
        resource_path: API resource path
        state: Resource state ('present' or 'absent')

    Returns:
        MOID of the configured resource or None
    """
    # Build the appropriate filter for this resource type
    filter_str = build_port_policy_filter(intersight.api_body)

    # Use the enhanced configure_secondary_resource with custom filter
    return intersight.configure_secondary_resource(
        resource_path=resource_path,
        state=state,
        custom_filter=filter_str
    )


def configure_generic_port_channels(intersight, policy_cache, port_policy_moid, port_channels, build_func, resource_path, requires_policy_cache=True):
    """
    Generic function to configure port channels for the port policy.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary for caching policy MOIDs
        port_policy_moid: MOID of the port policy
        port_channels: List of port channel configurations
        build_func: Function to build the API body
        resource_path: API resource path
        requires_policy_cache: Whether the build function requires policy cache

    Returns:
        Dictionary mapping pc_id to MOID for created port channels
    """
    pc_moids = {}

    for pc_config in port_channels:
        pc_state = pc_config.get('state', 'present')
        pc_id = pc_config['pc_id']

        # Build API body using the provided build function (needed for both create and delete to build filter)
        if requires_policy_cache:
            intersight.api_body = build_func(intersight, policy_cache, pc_config, port_policy_moid)
        else:
            intersight.api_body = build_func(pc_config, port_policy_moid)

        # Configure the port channel using port policy specific handler
        moid = configure_port_policy_resource(
            intersight, resource_path, pc_state
        )

        if pc_state == 'present' and moid:
            pc_moids[pc_id] = moid

    return pc_moids


def configure_generic_ports(intersight, policy_cache, port_policy_moid, port_configs, build_func, resource_path, requires_policy_cache=True):
    """
    Generic function to configure individual ports for the port policy.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary for caching policy MOIDs
        port_policy_moid: MOID of the port policy
        port_configs: List of port configurations
        build_func: Function to build the API body
        resource_path: API resource path
        requires_policy_cache: Whether the build function requires policy cache

    Returns:
        List of API responses for all configured ports
    """
    port_responses = []

    for port_config in port_configs:
        port_state = port_config.get('state', 'present')

        # Build API body using the provided build function (needed for both create and delete to build filter)
        if requires_policy_cache:
            intersight.api_body = build_func(intersight, policy_cache, port_config, port_policy_moid)
        else:
            intersight.api_body = build_func(port_config, port_policy_moid)

        # Configure the port using port policy specific handler
        configure_port_policy_resource(
            intersight, resource_path, port_state
        )

        # Collect the response for this port
        if intersight.result.get('api_response'):
            port_responses.append(intersight.result['api_response'])

    return port_responses


def resolve_optional_policies(intersight, policy_cache, config, api_body, policy_mappings):
    """
    Generic helper to resolve optional policy MOIDs and add them to API body.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary to cache policy MOIDs
        config: Configuration dictionary containing policy names
        api_body: API body dictionary to update
        policy_mappings: Dictionary mapping config keys to (api_field, resource_path, display_name)
    """
    for config_key, (api_field, resource_path, display_name) in policy_mappings.items():
        if config.get(config_key):
            api_body[api_field] = resolve_policy_moid(
                intersight, policy_cache,
                resource_path,
                config[config_key],
                display_name
            )


def build_breakout_port_api_body(breakout_config, port_policy_moid):
    """
    Build API body for breakout port configuration.

    Args:
        breakout_config: Dictionary containing breakout port configuration
        port_policy_moid: MOID of the port policy

    Returns:
        Dictionary containing the API body
    """
    port_id = breakout_config['port_id']
    return {
        'PortPolicy': port_policy_moid,
        'SlotId': 1,
        'PortIdStart': port_id,
        'PortIdEnd': port_id,
        'CustomMode': breakout_config['custom_mode']
    }


def build_server_port_api_body(server_config, port_policy_moid):
    """
    Build API body for server port configuration.

    Args:
        server_config: Dictionary containing server port configuration
        port_policy_moid: MOID of the port policy

    Returns:
        Dictionary containing the API body
    """
    # Parse port ID to handle aggregate ports
    port_info = parse_port_id(server_config['port_id'])

    api_body = {
        'PortPolicy': port_policy_moid,
        'SlotId': 1,
        'PortId': port_info['port_id'],
        'Fec': server_config.get('fec', 'Auto'),
        'AutoNegotiationDisabled': server_config.get('manual_numbering', False)
    }

    # Add aggregate port ID if this is an aggregate port
    if port_info['is_aggregate']:
        api_body['AggregatePortId'] = port_info['aggregate_port_id']

    if server_config.get('user_label'):
        api_body['UserLabel'] = server_config['user_label']

    # Add preferred device configuration if specified
    if server_config.get('preferred_device_type'):
        api_body['PreferredDeviceType'] = server_config['preferred_device_type']
        if server_config.get('preferred_device_id'):
            api_body['PreferredDeviceId'] = server_config['preferred_device_id']

    return api_body


def build_port_channel_ports_list(ports):
    """
    Build the Ports list for port channel API body.

    Args:
        ports: List of port configurations with port_id

    Returns:
        List of formatted port dictionaries
    """
    port_list = []
    for port in ports:
        port_input = port['port_id']

        port_info = parse_port_id(port_input)
        port_entry = {
            'PortId': port_info['port_id'],
            'SlotId': 1,
            'id': port_info['display_name']
        }

        if port_info['is_aggregate']:
            port_entry['AggregatePortId'] = port_info['aggregate_port_id']

        port_list.append(port_entry)

    return port_list


def build_ethernet_uplink_pc_api_body(intersight, policy_cache, pc_config, port_policy_moid):
    """
    Build API body for Ethernet uplink port channel configuration.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary for caching policy MOIDs
        pc_config: Dictionary containing port channel configuration
        port_policy_moid: MOID of the port policy

    Returns:
        Dictionary containing the API body
    """
    api_body = {
        'PortPolicy': port_policy_moid,
        'PcId': pc_config['pc_id'],
        'AdminSpeed': pc_config.get('admin_speed', 'Auto'),
        'Fec': pc_config.get('fec', 'Auto'),
        'Ports': build_port_channel_ports_list(pc_config.get('ports', []))
    }

    if pc_config.get('user_label'):
        api_body['UserLabel'] = pc_config['user_label']

    # Resolve Ethernet Network Group Policy MOIDs
    if pc_config.get('eth_network_group_policy_names'):
        eth_network_group_moids = []
        for policy_name in pc_config['eth_network_group_policy_names']:
            moid = resolve_policy_moid(
                intersight, policy_cache,
                '/fabric/EthNetworkGroupPolicies',
                policy_name,
                'Ethernet Network Group Policy'
            )
            eth_network_group_moids.append(moid)
        api_body['EthNetworkGroupPolicy'] = eth_network_group_moids

    # Resolve optional policies using generic helper
    policy_mappings = {
        'flow_control_policy_name': ('FlowControlPolicy', '/fabric/FlowControlPolicies', 'Flow Control Policy'),
        'link_aggregation_policy_name': ('LinkAggregationPolicy', '/fabric/LinkAggregationPolicies', 'Link Aggregation Policy'),
        'link_control_policy_name': ('LinkControlPolicy', '/fabric/LinkControlPolicies', 'Link Control Policy')
    }

    resolve_optional_policies(intersight, policy_cache, pc_config, api_body, policy_mappings)

    return api_body


def build_fc_uplink_pc_api_body(pc_config, port_policy_moid):
    """
    Build API body for FC uplink port channel configuration.

    Args:
        pc_config: Dictionary containing port channel configuration
        port_policy_moid: MOID of the port policy

    Returns:
        Dictionary containing the API body
    """
    api_body = {
        'PortPolicy': port_policy_moid,
        'PcId': pc_config['pc_id'],
        'AdminSpeed': pc_config.get('admin_speed', '16Gbps'),
        'VsanId': pc_config.get('vsan_id', 1),
        'Ports': build_port_channel_ports_list(pc_config.get('ports', []))
    }

    if pc_config.get('user_label'):
        api_body['UserLabel'] = pc_config['user_label']

    return api_body


def build_fcoe_uplink_pc_api_body(intersight, policy_cache, pc_config, port_policy_moid):
    """
    Build API body for FCoE uplink port channel configuration.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary for caching policy MOIDs
        pc_config: Dictionary containing port channel configuration
        port_policy_moid: MOID of the port policy

    Returns:
        Dictionary containing the API body
    """
    api_body = {
        'PortPolicy': port_policy_moid,
        'PcId': pc_config['pc_id'],
        'AdminSpeed': pc_config.get('admin_speed', 'Auto'),
        'Fec': pc_config.get('fec', 'Auto'),
        'Ports': build_port_channel_ports_list(pc_config.get('ports', []))
    }

    if pc_config.get('user_label'):
        api_body['UserLabel'] = pc_config['user_label']

    # Resolve optional policies using generic helper
    policy_mappings = {
        'link_aggregation_policy_name': ('LinkAggregationPolicy', '/fabric/LinkAggregationPolicies', 'Link Aggregation Policy'),
        'link_control_policy_name': ('LinkControlPolicy', '/fabric/LinkControlPolicies', 'Link Control Policy')
    }

    resolve_optional_policies(intersight, policy_cache, pc_config, api_body, policy_mappings)

    return api_body


def build_appliance_pc_api_body(intersight, policy_cache, pc_config, port_policy_moid):
    """
    Build API body for appliance port channel configuration.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary for caching policy MOIDs
        pc_config: Dictionary containing port channel configuration
        port_policy_moid: MOID of the port policy

    Returns:
        Dictionary containing the API body
    """
    api_body = {
        'PortPolicy': port_policy_moid,
        'PcId': pc_config['pc_id'],
        'AdminSpeed': pc_config.get('admin_speed', 'Auto'),
        'Fec': pc_config.get('fec', 'Auto'),
        'Priority': pc_config.get('priority', 'Best Effort'),
        'Mode': pc_config.get('mode', 'trunk'),
        'Ports': build_port_channel_ports_list(pc_config.get('ports', []))
    }

    if pc_config.get('user_label'):
        api_body['UserLabel'] = pc_config['user_label']

    # Resolve policies using generic helper
    policy_mappings = {
        'eth_network_group_policy_name': ('EthNetworkGroupPolicy', '/fabric/EthNetworkGroupPolicies', 'Ethernet Network Group Policy'),
        'eth_network_control_policy_name': ('EthNetworkControlPolicy', '/fabric/EthNetworkControlPolicies', 'Ethernet Network Control Policy'),
        'link_aggregation_policy_name': ('LinkAggregationPolicy', '/fabric/LinkAggregationPolicies', 'Link Aggregation Policy')
    }

    resolve_optional_policies(intersight, policy_cache, pc_config, api_body, policy_mappings)

    return api_body


def get_port_channel_moid(intersight, port_policy_moid, pc_id, resource_path):
    """
    Get the MOID of a port channel by pc_id and resource path.

    Args:
        intersight: IntersightModule instance
        port_policy_moid: MOID of the port policy
        pc_id: Port channel ID
        resource_path: API resource path (e.g., '/fabric/UplinkPcRoles', '/fabric/FcoeUplinkPcRoles')

    Returns:
        MOID of the port channel or None if not found
    """
    # Build filter for the port channel
    filter_conditions = [f"PortPolicy.Moid eq '{port_policy_moid}'"]
    filter_conditions.append(f"PcId eq {pc_id}")
    filter_str = ' and '.join(filter_conditions)

    # Query the port channel
    intersight.get_resource(
        resource_path=resource_path,
        query_params={'$filter': filter_str, '$select': 'Moid'}
    )

    if intersight.result.get('api_response'):
        return intersight.result['api_response'].get('Moid')

    return None


def get_port_role_moid(intersight, port_policy_moid, port_id, resource_path):
    """
    Generic function to get the MOID of a port role by port ID and resource path.

    Args:
        intersight: IntersightModule instance
        port_policy_moid: MOID of the port policy
        port_id: Port identifier (e.g., '14' or '49/1')
        resource_path: API resource path (e.g., '/fabric/UplinkRoles', '/fabric/FcoeUplinkRoles')

    Returns:
        MOID of the port role or None if not found
    """
    # Parse port ID to handle aggregate ports
    try:
        port_info = parse_port_id(port_id)
    except ValueError as e:
        intersight.module.fail_json(msg=f"Invalid port ID format '{port_id}': {e}")

    # Build filter for the port role
    filter_conditions = [f"PortPolicy.Moid eq '{port_policy_moid}'"]
    filter_conditions.append(f"PortId eq {port_info['port_id']}")

    if port_info['is_aggregate']:
        filter_conditions.append(f"AggregatePortId eq {port_info['aggregate_port_id']}")

    filter_str = ' and '.join(filter_conditions)

    # Query the port role
    intersight.get_resource(
        resource_path=resource_path,
        query_params={'$filter': filter_str, '$select': 'Moid'}
    )

    if intersight.result.get('api_response'):
        return intersight.result['api_response'].get('Moid')

    return None


def get_uplink_port_moid(intersight, port_policy_moid, port_id):
    """
    Get the MOID of an uplink port role by port ID.

    Args:
        intersight: IntersightModule instance
        port_policy_moid: MOID of the port policy
        port_id: Port identifier (e.g., '14' or '49/1')

    Returns:
        MOID of the uplink port role or None if not found
    """
    return get_port_role_moid(intersight, port_policy_moid, port_id, '/fabric/UplinkRoles')


def get_fcoe_uplink_port_moid(intersight, port_policy_moid, port_id):
    """
    Get the MOID of an FCoE uplink port role by port ID.

    Args:
        intersight: IntersightModule instance
        port_policy_moid: MOID of the port policy
        port_id: Port identifier (e.g., '14' or '49/1')

    Returns:
        MOID of the FCoE uplink port role or None if not found
    """
    return get_port_role_moid(intersight, port_policy_moid, port_id, '/fabric/FcoeUplinkRoles')


def build_pin_group_api_body(intersight, pin_group_config, port_policy_moid, uplink_pc_moids):
    """
    Build API body for pin group configuration (both LAN and SAN).

    Args:
        intersight: IntersightModule instance
        pin_group_config: Dictionary containing pin group configuration
        port_policy_moid: MOID of the port policy
        uplink_pc_moids: Dictionary mapping pc_id to MOID

    Returns:
        Dictionary containing the API body
    """
    api_body = {
        'PortPolicy': port_policy_moid,
        'Name': pin_group_config['name']
    }

    # Determine the pin group type and target interface type
    pin_group_type = pin_group_config['pin_group_type']
    target_type = pin_group_config['target_interface_type']
    target_name = pin_group_config['target_interface_name']

    if target_type == 'pc':
        # Look up the MOID for the uplink port channel
        pc_id = int(target_name)
        pc_moid = None

        # First, try to get from current run's port channels
        if pc_id in uplink_pc_moids:
            pc_moid = uplink_pc_moids[pc_id]
        else:
            # If not found in current run, try to fetch from API based on pin group type
            if pin_group_type == 'lan':
                # For LAN pin groups, try Ethernet uplink, FCoE uplink, and appliance port channels
                pc_moid = get_port_channel_moid(intersight, port_policy_moid, pc_id, '/fabric/UplinkPcRoles')
            else:  # san
                # For SAN pin groups, try FCoE uplink port channels first, then others
                pc_moid = get_port_channel_moid(intersight, port_policy_moid, pc_id, '/fabric/FcoeUplinkPcRoles')

        if not pc_moid:
            intersight.module.fail_json(
                msg=f"Uplink port channel with pc_id {pc_id} not found for pin group '{pin_group_config['name']}'. "
                    f"Make sure the port channel is configured in the same policy."
            )

        # Set ObjectType based on pin group type
        if pin_group_type == 'lan':
            object_type = 'fabric.UplinkPcRole'
        else:  # san
            object_type = 'fabric.FcoeUplinkPcRole'

        api_body['PinTargetInterfaceRole'] = {
            'ObjectType': object_type,
            'Moid': pc_moid
        }
    else:  # target_type == 'port'
        # Look up the MOID for the uplink port
        if pin_group_type == 'lan':
            port_moid = get_uplink_port_moid(intersight, port_policy_moid, target_name)
            object_type = 'fabric.UplinkRole'
        else:  # san
            port_moid = get_fcoe_uplink_port_moid(intersight, port_policy_moid, target_name)
            object_type = 'fabric.FcoeUplinkRole'

        if not port_moid:
            port_type = "Ethernet uplink" if pin_group_type == 'lan' else "FCoE uplink"
            intersight.module.fail_json(
                msg=f"{port_type} port '{target_name}' not found for pin group '{pin_group_config['name']}'. "
                    f"Make sure the port is configured as a {port_type.lower()} port in the same policy."
            )

        api_body['PinTargetInterfaceRole'] = {
            'ObjectType': object_type,
            'Moid': port_moid
        }

    return api_body


def build_fc_port_mode_api_body(fc_config, port_policy_moid):
    """
    Build API body for FC port mode configuration.

    Args:
        fc_config: Dictionary containing FC port mode configuration
        port_policy_moid: MOID of the port policy

    Returns:
        Dictionary containing the API body
    """
    return {
        'PortPolicy': port_policy_moid,
        'PortIdStart': fc_config.get('port_id_start', 1),
        'PortIdEnd': fc_config['port_id_end'],
        'SlotId': 1
    }


def build_fc_uplink_port_api_body(fc_config, port_policy_moid):
    """
    Build API body for FC Uplink port configuration.

    Args:
        fc_config: Dictionary containing FC Uplink port configuration
        port_policy_moid: MOID of the port policy

    Returns:
        Dictionary containing the API body
    """
    # Parse port ID to handle aggregate ports
    port_info = parse_port_id(fc_config['port_id'])

    api_body = {
        'PortPolicy': port_policy_moid,
        'SlotId': 1,
        'PortId': port_info['port_id'],
        'AdminSpeed': fc_config.get('admin_speed', 'Auto'),
        'VsanId': fc_config['vsan_id']
    }

    # Add aggregate port ID if this is an aggregate port
    if port_info['is_aggregate']:
        api_body['AggregatePortId'] = port_info['aggregate_port_id']

    if fc_config.get('user_label'):
        api_body['UserLabel'] = fc_config['user_label']

    return api_body


def build_fc_storage_port_api_body(fc_config, port_policy_moid):
    """
    Build API body for FC Storage port configuration.

    Args:
        fc_config: Dictionary containing FC Storage port configuration
        port_policy_moid: MOID of the port policy

    Returns:
        Dictionary containing the API body
    """
    # Parse port ID to handle aggregate ports
    port_info = parse_port_id(fc_config['port_id'])

    api_body = {
        'PortPolicy': port_policy_moid,
        'SlotId': 1,
        'PortId': port_info['port_id'],
        'AdminSpeed': fc_config.get('admin_speed'),
        'VsanId': fc_config['vsan_id']
    }

    # Add aggregate port ID if this is an aggregate port
    if port_info['is_aggregate']:
        api_body['AggregatePortId'] = port_info['aggregate_port_id']

    if fc_config.get('user_label'):
        api_body['UserLabel'] = fc_config['user_label']

    return api_body


def build_appliance_port_api_body(intersight, policy_cache, appliance_config, port_policy_moid):
    """
    Build API body for Appliance port configuration.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary for caching policy MOIDs
        appliance_config: Dictionary containing Appliance port configuration
        port_policy_moid: MOID of the port policy

    Returns:
        Dictionary containing the API body
    """
    # Parse port ID to handle aggregate ports
    port_info = parse_port_id(appliance_config['port_id'])

    api_body = {
        'PortPolicy': port_policy_moid,
        'SlotId': 1,
        'PortId': port_info['port_id'],
        'AdminSpeed': appliance_config.get('admin_speed', 'Auto'),
        'Fec': appliance_config.get('fec', 'Auto'),
        'Priority': appliance_config.get('priority', 'Best Effort'),
        'Mode': appliance_config.get('mode', 'trunk')
    }

    # Add aggregate port ID if this is an aggregate port
    if port_info['is_aggregate']:
        api_body['AggregatePortId'] = port_info['aggregate_port_id']

    if appliance_config.get('user_label'):
        api_body['UserLabel'] = appliance_config['user_label']

    # Resolve policies using generic helper
    policy_mappings = {
        'eth_network_group_policy_name': ('EthNetworkGroupPolicy', '/fabric/EthNetworkGroupPolicies', 'Ethernet Network Group Policy'),
        'eth_network_control_policy_name': ('EthNetworkControlPolicy', '/fabric/EthNetworkControlPolicies', 'Ethernet Network Control Policy')
    }

    resolve_optional_policies(intersight, policy_cache, appliance_config, api_body, policy_mappings)

    return api_body


def build_ethernet_uplink_port_api_body(intersight, policy_cache, uplink_config, port_policy_moid):
    """
    Build API body for Ethernet Uplink port configuration.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary for caching policy MOIDs
        uplink_config: Dictionary containing Ethernet Uplink port configuration
        port_policy_moid: MOID of the port policy

    Returns:
        Dictionary containing the API body
    """
    # Parse port ID to handle aggregate ports
    port_info = parse_port_id(uplink_config['port_id'])

    api_body = {
        'PortPolicy': port_policy_moid,
        'SlotId': 1,
        'PortId': port_info['port_id'],
        'AdminSpeed': uplink_config.get('admin_speed', 'Auto'),
        'Fec': uplink_config.get('fec', 'Auto')
    }

    # Add aggregate port ID if this is an aggregate port
    if port_info['is_aggregate']:
        api_body['AggregatePortId'] = port_info['aggregate_port_id']

    if uplink_config.get('user_label'):
        api_body['UserLabel'] = uplink_config['user_label']

    # Resolve Ethernet Network Group Policy MOIDs
    if uplink_config.get('eth_network_group_policy_name'):
        eth_network_group_moids = []
        for policy_name in uplink_config['eth_network_group_policy_name']:
            moid = resolve_policy_moid(
                intersight, policy_cache,
                '/fabric/EthNetworkGroupPolicies',
                policy_name,
                'Ethernet Network Group Policy'
            )
            eth_network_group_moids.append(moid)
        api_body['EthNetworkGroupPolicy'] = eth_network_group_moids

    # Resolve single policies using generic helper
    policy_mappings = {
        'flow_control_policy_name': ('FlowControlPolicy', '/fabric/FlowControlPolicies', 'Flow Control Policy'),
        'link_control_policy_name': ('LinkControlPolicy', '/fabric/LinkControlPolicies', 'Link Control Policy'),
        'mac_sec_policy_name': ('MacSecPolicy', '/fabric/MacSecPolicies', 'MAC Security Policy')
    }

    resolve_optional_policies(intersight, policy_cache, uplink_config, api_body, policy_mappings)

    return api_body


def build_fcoe_uplink_port_api_body(intersight, policy_cache, fcoe_config, port_policy_moid):
    """
    Build API body for FCoE Uplink port configuration.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary for caching policy MOIDs
        fcoe_config: Dictionary containing FCoE Uplink port configuration
        port_policy_moid: MOID of the port policy

    Returns:
        Dictionary containing the API body
    """
    # Parse port ID to handle aggregate ports
    port_info = parse_port_id(fcoe_config['port_id'])

    api_body = {
        'PortPolicy': port_policy_moid,
        'SlotId': 1,
        'PortId': port_info['port_id'],
        'AdminSpeed': fcoe_config.get('admin_speed', 'Auto'),
        'Fec': fcoe_config.get('fec', 'Auto')
    }

    # Add aggregate port ID if this is an aggregate port
    if port_info['is_aggregate']:
        api_body['AggregatePortId'] = port_info['aggregate_port_id']

    if fcoe_config.get('user_label'):
        api_body['UserLabel'] = fcoe_config['user_label']

    # Resolve policies using generic helper
    policy_mappings = {
        'link_control_policy_name': ('LinkControlPolicy', '/fabric/LinkControlPolicies', 'Link Control Policy')
    }

    resolve_optional_policies(intersight, policy_cache, fcoe_config, api_body, policy_mappings)

    return api_body


def configure_breakout_ports(intersight, port_policy_moid, breakout_ports):
    """
    Configure breakout ports for the port policy.

    Args:
        intersight: IntersightModule instance
        port_policy_moid: MOID of the port policy
        breakout_ports: List of breakout port configurations

    Returns:
        List of API responses for all configured breakout ports
    """
    breakout_responses = []

    for breakout_config in breakout_ports:
        breakout_state = breakout_config.get('state', 'present')

        # Build API body for breakout port (needed for both create and delete to build filter)
        intersight.api_body = build_breakout_port_api_body(breakout_config, port_policy_moid)

        # Configure the breakout port using field-based filtering
        configure_port_policy_resource(intersight, '/fabric/PortModes', breakout_state)

        # Collect the response for this breakout port
        if intersight.result.get('api_response'):
            breakout_responses.append(intersight.result['api_response'])

    return breakout_responses


def configure_server_ports(intersight, port_policy_moid, server_ports):
    """
    Configure server ports for the port policy.

    Args:
        intersight: IntersightModule instance
        port_policy_moid: MOID of the port policy
        server_ports: List of server port configurations

    Returns:
        List of API responses for all configured server ports
    """
    server_responses = []

    for server_config in server_ports:
        server_state = server_config.get('state', 'present')

        # Build API body for server port (needed for both create and delete to build filter)
        intersight.api_body = build_server_port_api_body(server_config, port_policy_moid)

        # Configure the server port using field-based filtering
        configure_port_policy_resource(intersight, '/fabric/ServerRoles', server_state)

        # Collect the response for this server port
        if intersight.result.get('api_response'):
            server_responses.append(intersight.result['api_response'])

    return server_responses


def configure_ethernet_uplink_port_channels(intersight, policy_cache, port_policy_moid, port_channels):
    """Configure Ethernet uplink port channels."""
    return configure_generic_port_channels(
        intersight, policy_cache, port_policy_moid, port_channels,
        build_ethernet_uplink_pc_api_body, '/fabric/UplinkPcRoles'
    )


def configure_fc_uplink_port_channels(intersight, port_policy_moid, port_channels):
    """Configure FC uplink port channels."""
    return configure_generic_port_channels(
        intersight, None, port_policy_moid, port_channels,
        build_fc_uplink_pc_api_body, '/fabric/FcUplinkPcRoles',
        requires_policy_cache=False
    )


def configure_fcoe_uplink_port_channels(intersight, policy_cache, port_policy_moid, port_channels):
    """Configure FCoE uplink port channels."""
    return configure_generic_port_channels(
        intersight, policy_cache, port_policy_moid, port_channels,
        build_fcoe_uplink_pc_api_body, '/fabric/FcoeUplinkPcRoles'
    )


def configure_appliance_port_channels(intersight, policy_cache, port_policy_moid, port_channels):
    """Configure appliance port channels."""
    return configure_generic_port_channels(
        intersight, policy_cache, port_policy_moid, port_channels,
        build_appliance_pc_api_body, '/fabric/AppliancePcRoles'
    )


def configure_pin_groups(intersight, port_policy_moid, pin_groups, uplink_pc_moids):
    """
    Configure pin groups (both LAN and SAN) for the port policy.

    Args:
        intersight: IntersightModule instance
        port_policy_moid: MOID of the port policy
        pin_groups: List of pin group configurations
        uplink_pc_moids: Dictionary mapping pc_id to MOID
    """
    for pin_group_config in pin_groups:
        pin_group_state = pin_group_config.get('state', 'present')
        pin_group_type = pin_group_config['pin_group_type']

        # Build API body for pin group (needed for both create and delete for consistency)
        if pin_group_state == 'present':
            intersight.api_body = build_pin_group_api_body(
                intersight, pin_group_config, port_policy_moid, uplink_pc_moids
            )

        resource_name = pin_group_config['name']

        # Determine resource path based on pin group type
        if pin_group_type == 'lan':
            resource_path = '/fabric/LanPinGroups'
        else:  # san
            resource_path = '/fabric/SanPinGroups'

        # Configure the pin group
        # Filter by both pin group name AND PortPolicy to avoid affecting pin groups in other policies
        custom_filter = f"Name eq '{resource_name}' and PortPolicy.Moid eq '{port_policy_moid}'"
        intersight.configure_secondary_resource(
            resource_path=resource_path,
            state=pin_group_state,
            custom_filter=custom_filter
        )


def configure_fc_port_mode(intersight, port_policy_moid, fc_port_mode):
    """
    Configure FC port mode for the port policy.

    Args:
        intersight: IntersightModule instance
        port_policy_moid: MOID of the port policy
        fc_port_mode: Dictionary containing FC port mode configuration
    """
    if not fc_port_mode:
        return

    fc_state = fc_port_mode.get('state', 'present')

    # Build API body for FC port mode (needed for both create and delete to build filter)
    intersight.api_body = build_fc_port_mode_api_body(fc_port_mode, port_policy_moid)

    # Configure the FC port mode using field-based filtering
    configure_port_policy_resource(intersight, '/fabric/PortModes', fc_state)


def configure_fc_uplink_ports(intersight, port_policy_moid, fc_uplink_ports):
    """
    Configure FC Uplink ports for the port policy.

    Args:
        intersight: IntersightModule instance
        port_policy_moid: MOID of the port policy
        fc_uplink_ports: List of FC Uplink port configurations

    Returns:
        List of API responses for all configured FC Uplink ports
    """
    return configure_generic_ports(
        intersight, None, port_policy_moid, fc_uplink_ports,
        build_fc_uplink_port_api_body, '/fabric/FcUplinkRoles',
        requires_policy_cache=False
    )


def configure_fc_storage_ports(intersight, port_policy_moid, fc_storage_ports):
    """
    Configure FC Storage ports for the port policy.

    Args:
        intersight: IntersightModule instance
        port_policy_moid: MOID of the port policy
        fc_storage_ports: List of FC Storage port configurations

    Returns:
        List of API responses for all configured FC Storage ports
    """
    return configure_generic_ports(
        intersight, None, port_policy_moid, fc_storage_ports,
        build_fc_storage_port_api_body, '/fabric/FcStorageRoles',
        requires_policy_cache=False
    )


def configure_appliance_ports(intersight, policy_cache, port_policy_moid, appliance_ports):
    """
    Configure Appliance ports for the port policy.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary for caching policy MOIDs
        port_policy_moid: MOID of the port policy
        appliance_ports: List of Appliance port configurations

    Returns:
        List of API responses for all configured Appliance ports
    """
    return configure_generic_ports(
        intersight, policy_cache, port_policy_moid, appliance_ports,
        build_appliance_port_api_body, '/fabric/ApplianceRoles',
        requires_policy_cache=True
    )


def configure_ethernet_uplink_ports(intersight, policy_cache, port_policy_moid, ethernet_uplink_ports):
    """
    Configure Ethernet Uplink ports for the port policy.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary for caching policy MOIDs
        port_policy_moid: MOID of the port policy
        ethernet_uplink_ports: List of Ethernet Uplink port configurations

    Returns:
        List of API responses for all configured Ethernet Uplink ports
    """
    return configure_generic_ports(
        intersight, policy_cache, port_policy_moid, ethernet_uplink_ports,
        build_ethernet_uplink_port_api_body, '/fabric/UplinkRoles',
        requires_policy_cache=True
    )


def configure_fcoe_uplink_ports(intersight, policy_cache, port_policy_moid, fcoe_uplink_ports):
    """
    Configure FCoE Uplink ports for the port policy.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary for caching policy MOIDs
        port_policy_moid: MOID of the port policy
        fcoe_uplink_ports: List of FCoE Uplink port configurations

    Returns:
        List of API responses for all configured FCoE Uplink ports
    """
    return configure_generic_ports(
        intersight, policy_cache, port_policy_moid, fcoe_uplink_ports,
        build_fcoe_uplink_port_api_body, '/fabric/FcoeUplinkRoles',
        requires_policy_cache=True
    )


def main():
    # Define FC port mode options
    fc_port_mode_options = dict(
        port_id_start=dict(type='int', default=1),
        port_id_end=dict(type='int', required=True),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )

    # Define breakout port options
    breakout_port_options = dict(
        port_id=dict(type='int', required=True),
        custom_mode=dict(
            type='str',
            choices=[
                'BreakoutEthernet10G',
                'BreakoutEthernet25G',
                'BreakoutFibreChannel8G',
                'BreakoutFibreChannel16G',
                'BreakoutFibreChannel32G'
            ],
            required=True
        ),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )

    # Define server port options
    server_port_options = dict(
        port_id=dict(type='str', required=True),
        fec=dict(type='str', choices=['Auto', 'Cl74'], default='Auto'),
        manual_numbering=dict(type='bool', default=False),
        user_label=dict(type='str'),
        preferred_device_type=dict(type='str', choices=['Chassis', 'RackServer']),
        preferred_device_id=dict(type='int'),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )

    # Define port options for port channels
    ethernet_port_options = dict(
        port_id=dict(type='str', required=True)
    )

    fc_port_options = dict(
        port_id=dict(type='str', required=True)
    )

    # Define Ethernet uplink port channel options
    ethernet_uplink_pc_options = dict(
        pc_id=dict(type='int', required=True),
        admin_speed=dict(type='str', choices=['Auto', '1Gbps', '10Gbps', '25Gbps', '40Gbps', '100Gbps'], default='Auto'),
        fec=dict(type='str', choices=['Auto', 'Off'], default='Auto'),
        user_label=dict(type='str'),
        ports=dict(type='list', elements='dict', options=ethernet_port_options, required=True),
        eth_network_group_policy_names=dict(type='list', elements='str'),
        flow_control_policy_name=dict(type='str'),
        link_aggregation_policy_name=dict(type='str'),
        link_control_policy_name=dict(type='str'),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )

    # Define FC uplink port channel options
    fc_uplink_pc_options = dict(
        pc_id=dict(type='int', required=True),
        admin_speed=dict(type='str', choices=['8Gbps', '16Gbps', '32Gbps'], default='16Gbps'),
        vsan_id=dict(type='int', default=1),
        user_label=dict(type='str'),
        ports=dict(type='list', elements='dict', options=fc_port_options, required=True),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )

    # Define FCoE uplink port channel options
    fcoe_uplink_pc_options = dict(
        pc_id=dict(type='int', required=True),
        admin_speed=dict(type='str', choices=['Auto', '1Gbps', '10Gbps', '25Gbps', '40Gbps', '100Gbps'], default='Auto'),
        fec=dict(type='str', choices=['Auto', 'Off'], default='Auto'),
        user_label=dict(type='str'),
        ports=dict(type='list', elements='dict', options=ethernet_port_options, required=True),
        link_aggregation_policy_name=dict(type='str'),
        link_control_policy_name=dict(type='str'),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )

    # Define Appliance port channel options
    appliance_pc_options = dict(
        pc_id=dict(type='int', required=True),
        admin_speed=dict(type='str', choices=['Auto', '1Gbps', '10Gbps', '25Gbps', '40Gbps', '100Gbps'], default='Auto'),
        fec=dict(type='str', choices=['Auto', 'Off'], default='Auto'),
        priority=dict(type='str', choices=['Best Effort', 'FC', 'Platinum', 'Gold', 'Silver', 'Bronze'], default='Best Effort'),
        mode=dict(type='str', choices=['trunk', 'access'], default='trunk'),
        user_label=dict(type='str'),
        ports=dict(type='list', elements='dict', options=ethernet_port_options, required=True),
        eth_network_group_policy_name=dict(type='str', required=True),
        eth_network_control_policy_name=dict(type='str', required=True),
        link_aggregation_policy_name=dict(type='str'),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )

    # Define pin group options (both LAN and SAN)
    pin_group_options = dict(
        name=dict(type='str', required=True),
        pin_group_type=dict(type='str', choices=['lan', 'san'], required=True),
        target_interface_type=dict(type='str', choices=['pc', 'port'], required=True),
        target_interface_name=dict(type='str', required=True),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )

    # Define FC Uplink port options
    fc_uplink_port_options = dict(
        port_id=dict(type='str', required=True),
        admin_speed=dict(type='str', choices=['Auto', '8Gbps', '16Gbps', '32Gbps'], default='Auto'),
        vsan_id=dict(type='int', required=True),
        user_label=dict(type='str'),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )

    # Define FC Storage port options
    fc_storage_port_options = dict(
        port_id=dict(type='str', required=True),
        admin_speed=dict(type='str', choices=['8Gbps', '16Gbps', '32Gbps'], default='8Gbps'),
        vsan_id=dict(type='int', required=True),
        user_label=dict(type='str'),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )

    # Define Appliance port options
    appliance_port_options = dict(
        port_id=dict(type='str', required=True),
        admin_speed=dict(type='str', choices=['Auto', '1Gbps', '10Gbps', '25Gbps', '40Gbps', '100Gbps'], default='Auto'),
        fec=dict(type='str', choices=['Auto', 'Off'], default='Auto'),
        priority=dict(type='str', choices=['Best Effort', 'FC', 'Platinum', 'Gold', 'Silver', 'Bronze'], default='Best Effort'),
        mode=dict(type='str', choices=['trunk', 'access'], default='trunk'),
        eth_network_group_policy_name=dict(type='str', required=True),
        eth_network_control_policy_name=dict(type='str', required=True),
        user_label=dict(type='str'),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )

    # Define Ethernet Uplink port options
    ethernet_uplink_port_options = dict(
        port_id=dict(type='str', required=True),
        admin_speed=dict(type='str', choices=['Auto', '1Gbps', '10Gbps', '25Gbps', '40Gbps', '100Gbps'], default='Auto'),
        fec=dict(type='str', choices=['Auto', 'Off'], default='Auto'),
        eth_network_group_policy_name=dict(type='list', elements='str'),
        flow_control_policy_name=dict(type='str'),
        link_control_policy_name=dict(type='str'),
        mac_sec_policy_name=dict(type='str'),
        user_label=dict(type='str'),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )

    # Define FCoE Uplink port options
    fcoe_uplink_port_options = dict(
        port_id=dict(type='str', required=True),
        admin_speed=dict(type='str', choices=['Auto', '1Gbps', '10Gbps', '25Gbps', '40Gbps', '100Gbps'], default='Auto'),
        fec=dict(type='str', choices=['Auto', 'Off'], default='Auto'),
        link_control_policy_name=dict(type='str'),
        user_label=dict(type='str'),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )

    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        device_model=dict(
            type='str',
            choices=['UCS-FI-6454', 'UCS-FI-64108', 'UCS-FI-6536', 'UCS-FI-6664', 'UCSX-S9108-100G']
        ),
        fc_port_mode=dict(type='dict', options=fc_port_mode_options),
        breakout_ports=dict(type='list', elements='dict', options=breakout_port_options),
        server_ports=dict(type='list', elements='dict', options=server_port_options),
        ethernet_uplink_port_channels=dict(type='list', elements='dict', options=ethernet_uplink_pc_options),
        fc_uplink_port_channels=dict(type='list', elements='dict', options=fc_uplink_pc_options),
        fcoe_uplink_port_channels=dict(type='list', elements='dict', options=fcoe_uplink_pc_options),
        appliance_port_channels=dict(type='list', elements='dict', options=appliance_pc_options),
        pin_groups=dict(type='list', elements='dict', options=pin_group_options),
        fc_uplink_ports=dict(type='list', elements='dict', options=fc_uplink_port_options),
        fc_storage_ports=dict(type='list', elements='dict', options=fc_storage_port_options),
        appliance_ports=dict(type='list', elements='dict', options=appliance_port_options),
        ethernet_uplink_ports=dict(type='list', elements='dict', options=ethernet_uplink_port_options),
        fcoe_uplink_ports=dict(type='list', elements='dict', options=fcoe_uplink_port_options)
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'present', ['device_model']],
        ],
    )

    if module.params['state'] == 'present':
        validate_input(module)

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/fabric/PortPolicies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()
        intersight.api_body['DeviceModel'] = intersight.module.params['device_model']

    # Configure the port policy
    intersight.configure_policy_or_profile(resource_path=resource_path)

    # Save the port policy response
    port_policy_response = intersight.result['api_response']

    port_policy_moid = None
    if intersight.module.params['state'] == 'present' and port_policy_response:
        port_policy_moid = port_policy_response.get('Moid')

    # Process secondary resources if port policy is present
    secondary_responses = {}
    if intersight.module.params['state'] == 'present' and port_policy_moid:
        # Cache for policy MOIDs to avoid redundant API calls
        policy_cache = {}

        # Configure FC port mode
        if intersight.module.params.get('fc_port_mode'):
            configure_fc_port_mode(
                intersight,
                port_policy_moid,
                intersight.module.params['fc_port_mode']
            )
            secondary_responses['fc_port_mode'] = intersight.result.get('api_response')

        # Configure breakout ports
        if intersight.module.params.get('breakout_ports'):
            breakout_responses = configure_breakout_ports(
                intersight,
                port_policy_moid,
                intersight.module.params['breakout_ports']
            )
            if breakout_responses:
                secondary_responses['breakout_ports'] = breakout_responses

        # Configure server ports
        if intersight.module.params.get('server_ports'):
            server_responses = configure_server_ports(
                intersight,
                port_policy_moid,
                intersight.module.params['server_ports']
            )
            if server_responses:
                secondary_responses['server_ports'] = server_responses

        # Configure FC Uplink ports
        if intersight.module.params.get('fc_uplink_ports'):
            fc_uplink_responses = configure_fc_uplink_ports(
                intersight,
                port_policy_moid,
                intersight.module.params['fc_uplink_ports']
            )
            if fc_uplink_responses:
                secondary_responses['fc_uplink_ports'] = fc_uplink_responses

        # Configure FC Storage ports
        if intersight.module.params.get('fc_storage_ports'):
            fc_storage_responses = configure_fc_storage_ports(
                intersight,
                port_policy_moid,
                intersight.module.params['fc_storage_ports']
            )
            if fc_storage_responses:
                secondary_responses['fc_storage_ports'] = fc_storage_responses

        # Configure Appliance ports
        if intersight.module.params.get('appliance_ports'):
            appliance_responses = configure_appliance_ports(
                intersight,
                policy_cache,
                port_policy_moid,
                intersight.module.params['appliance_ports']
            )
            if appliance_responses:
                secondary_responses['appliance_ports'] = appliance_responses

        # Configure Ethernet Uplink ports
        if intersight.module.params.get('ethernet_uplink_ports'):
            ethernet_uplink_responses = configure_ethernet_uplink_ports(
                intersight,
                policy_cache,
                port_policy_moid,
                intersight.module.params['ethernet_uplink_ports']
            )
            if ethernet_uplink_responses:
                secondary_responses['ethernet_uplink_ports'] = ethernet_uplink_responses

        # Configure FCoE Uplink ports
        if intersight.module.params.get('fcoe_uplink_ports'):
            fcoe_uplink_responses = configure_fcoe_uplink_ports(
                intersight,
                policy_cache,
                port_policy_moid,
                intersight.module.params['fcoe_uplink_ports']
            )
            if fcoe_uplink_responses:
                secondary_responses['fcoe_uplink_ports'] = fcoe_uplink_responses

        # Configure Ethernet uplink port channels and get their MOIDs
        uplink_pc_moids = {}
        if intersight.module.params.get('ethernet_uplink_port_channels'):
            ethernet_pc_moids = configure_ethernet_uplink_port_channels(
                intersight,
                policy_cache,
                port_policy_moid,
                intersight.module.params['ethernet_uplink_port_channels']
            )
            uplink_pc_moids.update(ethernet_pc_moids)
            secondary_responses['ethernet_uplink_port_channels'] = intersight.result.get('api_response')

        # Configure FC uplink port channels
        if intersight.module.params.get('fc_uplink_port_channels'):
            fc_pc_moids = configure_fc_uplink_port_channels(
                intersight,
                port_policy_moid,
                intersight.module.params['fc_uplink_port_channels']
            )
            uplink_pc_moids.update(fc_pc_moids)
            secondary_responses['fc_uplink_port_channels'] = intersight.result.get('api_response')

        # Configure FCoE uplink port channels
        if intersight.module.params.get('fcoe_uplink_port_channels'):
            fcoe_pc_moids = configure_fcoe_uplink_port_channels(
                intersight,
                policy_cache,
                port_policy_moid,
                intersight.module.params['fcoe_uplink_port_channels']
            )
            uplink_pc_moids.update(fcoe_pc_moids)
            secondary_responses['fcoe_uplink_port_channels'] = intersight.result.get('api_response')

        # Configure Appliance port channels
        if intersight.module.params.get('appliance_port_channels'):
            appliance_pc_moids = configure_appliance_port_channels(
                intersight,
                policy_cache,
                port_policy_moid,
                intersight.module.params['appliance_port_channels']
            )
            uplink_pc_moids.update(appliance_pc_moids)
            secondary_responses['appliance_port_channels'] = intersight.result.get('api_response')

        # Configure pin groups (both LAN and SAN, must be after all port channels)
        if intersight.module.params.get('pin_groups'):
            configure_pin_groups(
                intersight,
                port_policy_moid,
                intersight.module.params['pin_groups'],
                uplink_pc_moids
            )
            secondary_responses['pin_groups'] = intersight.result.get('api_response')

    # Combine port policy and secondary resources in the main response
    if port_policy_response:
        port_policy_response.update(secondary_responses)
        intersight.result['api_response'] = port_policy_response

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
