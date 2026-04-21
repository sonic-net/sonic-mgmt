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
module: intersight_lan_connectivity_policy
short_description: Manage LAN Connectivity Policies and vNICs for Cisco Intersight
description:
  - Create, update, and delete LAN Connectivity Policies on Cisco Intersight.
  - Manage individual vNICs within LAN Connectivity policies.
  - Supports both Standalone and FIAttached target platforms with different configuration options.
  - LAN Connectivity policies define network connectivity settings for server profiles.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/vnic/LanConnectivityPolicy/get/).
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
      - The name assigned to the LAN Connectivity Policy.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the LAN Connectivity Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  target_platform:
    description:
      - The platform type for which the LAN Connectivity policy is intended.
      - standalone for standalone servers, attached for fabric interconnect attached servers.
    type: str
    choices: ['standalone', 'attached']
    default: 'standalone'
  azure_qos_enabled:
    description:
      - Enable Azure QoS for the LAN Connectivity policy.
      - Only applicable when target_platform is 'attached'.
    type: bool
    default: false
  iqn_allocation_type:
    description:
      - IQN allocation type for the LAN Connectivity policy.
      - Only applicable when target_platform is 'attached'.
    type: str
    choices: ['None', 'Pool', 'Static']
    default: 'None'
  placement_mode:
    description:
      - Placement mode for vNIC assignment.
      - Only applicable when target_platform is 'attached'.
    type: str
    choices: ['custom', 'auto']
    default: 'custom'
  iqn_pool_name:
    description:
      - Relationship to the iSCSI Qualified Name Pool.
      - Required when iqn_allocation_type is 'Pool'.
      - Only applicable for attached target platform.
    type: str
  static_iqn_name:
    description:
      - User provided static iSCSI Qualified Name (IQN) for use as initiator identifiers by iSCSI vNICs in a Fabric Interconnect domain.
      - Required when iqn_allocation_type is 'Static'.
      - Only applicable for attached target platform.
    type: str
  vnics:
    description:
      - List of vNICs to be created and attached to the LAN Connectivity policy.
      - Each vNIC will be configured with the specified network and adapter policies.
      - Required when C(state) is C(present).
      - At least one vNIC must be specified for both Standalone and FIAttached platforms.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - The name of the vNIC.
          - Must be unique within the LAN Connectivity policy.
        type: str
        required: true
      placement_slot_id:
        description:
          - PCIe Slot where the VIC adapter is installed.
          - Supported values are (1-15) and MLOM.
          - Required when vNIC state is 'present'.
        type: str
      uplink_port:
        description:
          - Adapter port on which the virtual interface will be created.
        type: int
        choices: [0, 1, 2, 3]
        default: 0
      order:
        description:
          - The order in which the virtual interface is brought up.
          - The order assigned to an interface should be unique for all the Ethernet and Fibre-Channel interfaces on each PCI link on a VIC adapter.
          - The order should start from zero with no overlaps.
          - The maximum value of PCI order is limited by the number of virtual interfaces (Ethernet and Fibre-Channel) on each PCI link on a VIC adapter.
          - All VIC adapters have a single PCI link except VIC 1340, VIC 1380 and VIC 1385 which have two.
        type: int
        default: 0
      cdn_source:
        description:
          - Source of the CDN. It can either be user specified or be the same as the vNIC name.
        type: str
        choices: ['vnic', 'user']
        default: 'vnic'
      cdn_value:
        description:
          - CDN value when cdn_source is 'user'.
        type: str
      eth_network_policy_name:
        description:
          - Relationship to the Ethernet Network Policy.
          - Required when vNIC state is 'present'.
        type: str
      eth_qos_policy_name:
        description:
          - Relationship to the Ethernet QoS Policy.
          - Required when vNIC state is 'present'.
        type: str
      eth_adapter_policy_name:
        description:
          - Relationship to the Ethernet Adapter Policy.
          - Required when vNIC state is 'present'.
        type: str
      connection_type:
        description:
          - Type of connection for the vNIC.
        type: str
        choices: ['none', 'usnic', 'vmq', 'sriov']
        default: 'none'
      mac_address_type:
        description:
          - Type of MAC address assignment.
          - Only applicable for attached target platform.
        type: str
        choices: ['pool', 'static']
        default: 'pool'
      mac_pool_name:
        description:
          - The MAC pool that is assigned.
          - Required when mac_address_type is 'pool' and target platform is attached.
          - Only applicable for attached target platform.
        type: str
      static_mac_address:
        description:
          - The MAC address must be in hexadecimal format xx:xx:xx:xx:xx:xx.
          - To ensure uniqueness of MACs in the LAN fabric, you are strongly encouraged to use the following MAC prefix 00:25:B5:xx:xx:xx.
          - Required when mac_address_type is 'static' and target platform is attached.
          - Only applicable for attached target platform.
        type: str
      pci_link:
        description:
          - The PCI Link used as transport for the virtual interface.
          - PCI Link is only applicable for select Cisco UCS VIC 1300 models (UCSC-PCIE-C40Q-03, UCSB-MLOM-40G-03, UCSB-VIC-M83-8P) that support two PCI links.
          - The value, if specified, for any other VIC model will be ignored.
          - For attached required when pci_link_assignment_mode is 'Custom'.
        type: int
        choices: [0, 1]
        default: 0
      auto_slot_id:
        description:
          - Enable or disable automatic assignment of the VIC slot ID.
          - If enabled and the server has only one VIC, the same VIC is chosen for all the vNICs.
          - If enabled and the server has multiple VICs, the vNIC/vHBA are deployed on the first VIC.
          - If disabled, placement_slot_id must be specified.
          - Only applicable for attached target platform when auto_vnic_placement_enabled is false.
        type: bool
        default: true
      auto_pci_link:
        description:
          - Enable or disable automatic assignment of the PCI Link in a dual-link adapter.
          - This option applies only to 13xx series VICs that support dual-link.
          - If enabled, the system determines the placement of the vNIC/vHBA on either of the PCI Links.
          - If disabled, pci_link_assignment_mode must be specified.
          - Only applicable for attached target platform when auto_vnic_placement_enabled is false.
        type: bool
        default: true
      pci_link_assignment_mode:
        description:
          - PCI Link assignment mode when auto_pci_link is disabled.
          - Custom allows manual selection of PCI link via pci_link parameter.
          - Load-Balanced automatically distributes vNICs across available PCI links.
          - Required when auto_pci_link is false and auto_vnic_placement_enabled is false.
          - Only applicable for attached target platform.
        type: str
        choices: ['Custom', 'Load-Balanced']
      auto_vnic_placement_enabled:
        description:
          - Enable automatic vNIC placement for FI-attached servers.
          - When enabled, the vNIC placement is simplified to only specify the switch ID.
          - When disabled, full placement control is available including order, auto_slot_id, and auto_pci_link.
          - Only applicable for attached target platform.
        type: bool
        default: false
      switch_id:
        description:
          - The fabric port to which the vNICs will be associated.
          - Only applicable for attached target platform.
        type: str
        choices: ['A', 'B']
        default: 'A'
      failover_enabled:
        description:
          - Enables automatic vNIC failover to the secondary Fabric Interconnect
            if the primary path fails.
          - Failover applies only to Cisco VICs that are connected to a Fabric Interconnect cluster.
          - Only applicable for attached target platform.
        type: bool
        default: false
      fabric_eth_network_group_policy_name:
        description:
          - Relationship to the Fabric Ethernet Group Policy.
          - Required when target platform is attached and vNIC state is 'present'.
          - Only applicable for attached target platform.
        type: str
      fabric_eth_network_control_policy_name:
        description:
          - Relationship to the Fabric Ethernet Network Policy.
          - Required when target platform is attached and vNIC state is 'present'.
          - Only applicable for attached target platform.
        type: str
      iscsi_boot_policy_name:
        description:
          - Relationship to the boot iSCSI Policy.
          - Only applicable for attached target platform.
        type: str
      pin_group_name:
        description:
          - Pingroup name associated to vNIC for static pinning.
          - LCP deploy will resolve pingroup name and fetches the corresponding uplink port/port channel to pin the vNIC traffic.
          - Only applicable for attached target platform.
        type: str
      usnic_settings:
        description:
          - USNIC settings when connection_type is 'usnic'.
          - Required when connection_type is 'usnic'.
        type: dict
        suboptions:
          count:
            description:
              - Number of usNIC interfaces to be created.
              - When usNIC is enabled, the valid values are from 1 to 225.
              - When usNIC is disabled, the default value is 0.
            type: int
            default: 0
          cos:
            description:
              - Class of Service to be used for traffic on the usNIC.
            type: int
            choices: [0, 1, 2, 3, 4, 5, 6]
            default: 5
          usnic_adapter_policy_name:
            description:
              - Ethernet Adapter policy to be associated with the usNICs.
              - Required when connection_type is 'usnic'.
            type: str
      vmq_settings:
        description:
          - VMQ settings when connection_type is 'vmq'.
        type: dict
        suboptions:
          enabled:
            description:
              - Enable VMQ.
            type: bool
            default: true
          multi_queue_support:
            description:
              - Enables Virtual Machine Multi-Queue feature on the virtual interface.
              - VMMQ allows configuration of multiple I/O queues for a single VM and thus distributes traffic across multiple CPU cores in a VM.
            type: bool
            default: false
          num_interrupts:
            description:
              - The number of interrupt resources to be allocated.
              - Recommended value is the number of CPU threads or logical processors available in the server.
            type: int
            default: 16
          num_vmqs:
            description:
              - The number of hardware Virtual Machine Queues to be allocated.
              - The number of VMQs per adapter must be one more than the maximum number of VM NICs.
            type: int
            default: 4
          num_sub_vnics:
            description:
              - Number of sub vNICs (0-64).
              - Only applicable when multi_queue_support is true.
            type: int
            default: 64
          vmmq_adapter_policy_name:
            description:
              - Name of the VMMQ Adapter Policy.
              - Only applicable when multi_queue_support is true.
            type: str
      sriov_settings:
        description:
          - SR-IOV settings when connection_type is 'sriov'.
        type: dict
        suboptions:
          enabled:
            description:
              - Enable SR-IOV.
            type: bool
            default: true
          vf_count:
            description:
              - Number of Virtual Functions (1-64).
            type: int
            default: 64
          rx_count_per_vf:
            description:
              - Receive Queue Count per VF (1-8).
            type: int
            default: 4
          tx_count_per_vf:
            description:
              - Transmit Queue Count per VF (1-8).
            type: int
            default: 1
          comp_count_per_vf:
            description:
              - Completion Queue Count per VF (1-16).
            type: int
            default: 5
          int_count_per_vf:
            description:
              - Interrupt Count per VF (1-16).
            type: int
            default: 8
      state:
        description:
          - Whether to create/update or delete the vNIC.
        type: str
        choices: ['present', 'absent']
        default: present
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a LAN Connectivity Policy for Standalone servers
  cisco.intersight.intersight_lan_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "standalone-lan-policy"
    description: "LAN connectivity policy for standalone servers"
    target_platform: "Standalone"
    tags:
      - Key: "Environment"
        Value: "Production"
      - Key: "Site"
        Value: "DataCenter-A"
    vnics:
      - name: "eth0"
        placement_slot_id: "1"
        pci_link: 0
        uplink_port: 0
        order: 0
        eth_network_policy_name: "default-network-policy"
        eth_qos_policy_name: "default-qos-policy"
        eth_adapter_policy_name: "default-adapter-policy"
        connection_type: "none"
      - name: "eth1"
        placement_slot_id: "2"
        pci_link: 0
        uplink_port: 1
        order: 1
        eth_network_policy_name: "vlan-network-policy"
        eth_qos_policy_name: "high-qos-policy"
        eth_adapter_policy_name: "performance-adapter-policy"
        connection_type: "none"
    state: present

- name: Create a LAN Connectivity Policy for FI-Attached servers
  cisco.intersight.intersight_lan_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fi-attached-lan-policy"
    description: "LAN connectivity policy for FI-attached servers"
    target_platform: "attached"
    azure_qos_enabled: true
    iqn_allocation_type: "Pool"
    iqn_pool_name: "default-iqn-pool"
    placement_mode: "custom"
    tags:
      - Key: "Environment"
        Value: "Production"
    vnics:
      - name: "vnic-fi-attached"
        order: 0
        cdn_source: "vnic"
        mac_address_type: "pool"
        mac_pool_name: "default-mac-pool"
        auto_slot_id: true
        auto_pci_link: true
        auto_vnic_placement_enabled: false
        switch_id: "A"
        failover_enabled: false
        fabric_eth_network_group_policy_name: "default-network-group"
        fabric_eth_network_control_policy_name: "default-network-control"
        eth_qos_policy_name: "default-qos-policy"
        eth_adapter_policy_name: "default-adapter-policy"
        connection_type: "none"
        state: present
    state: present

- name: Create a LAN Connectivity Policy with pin group for static pinning
  cisco.intersight.intersight_lan_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fi-attached-pinned-policy"
    description: "LAN connectivity policy with static uplink pinning"
    target_platform: "attached"
    azure_qos_enabled: false
    iqn_allocation_type: "None"
    placement_mode: "custom"
    vnics:
      - name: "pinned-vnic"
        order: 0
        cdn_source: "vnic"
        mac_address_type: "pool"
        mac_pool_name: "default-mac-pool"
        auto_slot_id: true
        auto_pci_link: true
        auto_vnic_placement_enabled: false
        switch_id: "A"
        failover_enabled: false
        fabric_eth_network_group_policy_name: "default-network-group"
        fabric_eth_network_control_policy_name: "default-network-control"
        eth_qos_policy_name: "default-qos-policy"
        eth_adapter_policy_name: "default-adapter-policy"
        pin_group_name: "pingroup-a"
        connection_type: "none"
        state: present
    state: present

- name: Create a LAN Connectivity Policy with automatic vNIC placement
  cisco.intersight.intersight_lan_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fi-attached-auto-placement-policy"
    description: "LAN connectivity policy with automatic vNIC placement"
    target_platform: "attached"
    azure_qos_enabled: false
    iqn_allocation_type: "None"
    placement_mode: "auto"
    vnics:
      - name: "auto-placed-vnic"
        cdn_source: "vnic"
        mac_address_type: "pool"
        mac_pool_name: "default-mac-pool"
        auto_vnic_placement_enabled: true
        switch_id: "A"
        failover_enabled: false
        fabric_eth_network_group_policy_name: "default-network-group"
        fabric_eth_network_control_policy_name: "default-network-control"
        eth_qos_policy_name: "default-qos-policy"
        eth_adapter_policy_name: "default-adapter-policy"
        connection_type: "none"
        state: present
    state: present

- name: Create a LAN Connectivity Policy with advanced placement control
  cisco.intersight.intersight_lan_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fi-attached-advanced-placement-policy"
    description: "LAN connectivity policy with advanced placement control"
    target_platform: "attached"
    azure_qos_enabled: false
    iqn_allocation_type: "None"
    placement_mode: "custom"
    vnics:
      - name: "advanced-placed-vnic"
        order: 9
        cdn_source: "vnic"
        mac_address_type: "pool"
        mac_pool_name: "default-mac-pool"
        auto_slot_id: false
        placement_slot_id: "5"
        auto_pci_link: false
        pci_link_assignment_mode: "Custom"
        pci_link: 0
        auto_vnic_placement_enabled: false
        switch_id: "A"
        failover_enabled: false
        fabric_eth_network_group_policy_name: "default-network-group"
        fabric_eth_network_control_policy_name: "default-network-control"
        eth_qos_policy_name: "default-qos-policy"
        eth_adapter_policy_name: "default-adapter-policy"
        connection_type: "none"
        state: present
    state: present

- name: Create a LAN Connectivity Policy with load-balanced PCI assignment
  cisco.intersight.intersight_lan_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fi-attached-load-balanced-policy"
    description: "LAN connectivity policy with load-balanced PCI assignment"
    target_platform: "attached"
    azure_qos_enabled: false
    iqn_allocation_type: "None"
    placement_mode: "custom"
    vnics:
      - name: "load-balanced-vnic"
        order: 5
        cdn_source: "vnic"
        mac_address_type: "pool"
        mac_pool_name: "default-mac-pool"
        auto_slot_id: false
        placement_slot_id: "MLOM"
        auto_pci_link: false
        pci_link_assignment_mode: "Load-Balanced"
        auto_vnic_placement_enabled: false
        switch_id: "B"
        failover_enabled: true
        fabric_eth_network_group_policy_name: "default-network-group"
        fabric_eth_network_control_policy_name: "default-network-control"
        eth_qos_policy_name: "default-qos-policy"
        eth_adapter_policy_name: "default-adapter-policy"
        connection_type: "none"
        state: present
    state: present

- name: Create a LAN Connectivity Policy with USNIC vNIC
  cisco.intersight.intersight_lan_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "usnic-lan-policy"
    description: "Policy with USNIC configuration"
    target_platform: "Standalone"
    vnics:
      - name: "usnic-eth0"
        placement_slot_id: "4"
        pci_link: 0
        uplink_port: 0
        order: 0
        eth_network_policy_name: "hpc-network-policy"
        eth_qos_policy_name: "hpc-qos-policy"
        eth_adapter_policy_name: "hpc-adapter-policy"
        connection_type: "usnic"
        usnic_settings:
          count: 0
          cos: 5
          usnic_adapter_policy_name: "hpc-adapter-policy"
    state: present

- name: Create a LAN Connectivity Policy with VMQ vNIC
  cisco.intersight.intersight_lan_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "vmq-lan-policy"
    description: "Policy with VMQ configuration"
    target_platform: "Standalone"
    vnics:
      - name: "vmq-eth0"
        placement_slot_id: "10"
        pci_link: 0
        uplink_port: 2
        order: 0
        eth_network_policy_name: "vm-network-policy"
        eth_qos_policy_name: "vm-qos-policy"
        eth_adapter_policy_name: "vm-adapter-policy"
        connection_type: "vmq"
        vmq_settings:
          enabled: true
          multi_queue_support: false
          num_interrupts: 16
          num_vmqs: 4
    state: present

- name: Create a LAN Connectivity Policy with VMQ multi-queue support
  cisco.intersight.intersight_lan_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "vmq-multiqueue-lan-policy"
    description: "Policy with VMQ multi-queue configuration"
    target_platform: "Standalone"
    vnics:
      - name: "vmq-mq-eth0"
        placement_slot_id: "11"
        pci_link: 1
        uplink_port: 3
        order: 0
        eth_network_policy_name: "vm-network-policy"
        eth_qos_policy_name: "vm-qos-policy"
        eth_adapter_policy_name: "vm-adapter-policy"
        connection_type: "vmq"
        vmq_settings:
          enabled: true
          multi_queue_support: true
          num_sub_vnics: 64
          vmmq_adapter_policy_name: "vmmq-adapter-policy"
    state: present

- name: Create a LAN Connectivity Policy with SR-IOV vNIC
  cisco.intersight.intersight_lan_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "sriov-lan-policy"
    description: "Policy with SR-IOV configuration"
    target_platform: "Standalone"
    vnics:
      - name: "sriov-eth0"
        placement_slot_id: "14"
        pci_link: 0
        uplink_port: 1
        order: 0
        eth_network_policy_name: "sriov-network-policy"
        eth_qos_policy_name: "sriov-qos-policy"
        eth_adapter_policy_name: "sriov-adapter-policy"
        connection_type: "sriov"
        sriov_settings:
          enabled: true
          vf_count: 64
          rx_count_per_vf: 4
          tx_count_per_vf: 1
          comp_count_per_vf: 5
          int_count_per_vf: 8
    state: present

- name: Create a LAN Connectivity Policy with custom CDN values
  cisco.intersight.intersight_lan_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "custom-cdn-lan-policy"
    description: "Policy with custom CDN values"
    target_platform: "Standalone"
    vnics:
      - name: "mgmt-nic"
        placement_slot_id: "1"
        pci_link: 0
        uplink_port: 0
        order: 0
        cdn_source: "user"
        cdn_value: "Management-NIC"
        eth_network_policy_name: "mgmt-network-policy"
        eth_qos_policy_name: "mgmt-qos-policy"
        eth_adapter_policy_name: "mgmt-adapter-policy"
        connection_type: "none"
    state: present

- name: Update LAN connectivity policy - manage vNIC states
  cisco.intersight.intersight_lan_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "mixed-vnic-states-policy"
    description: "Policy demonstrating vNIC state management"
    target_platform: "Standalone"
    vnics:
      - name: "eth0"
        placement_slot_id: "1"
        pci_link: 0
        uplink_port: 0
        order: 0
        eth_network_policy_name: "production-network"
        eth_qos_policy_name: "standard-qos"
        eth_adapter_policy_name: "standard-adapter"
        connection_type: "none"
        state: present
      - name: "eth1-old"
        state: absent
      - name: "eth2-new"
        placement_slot_id: "3"
        pci_link: 0
        uplink_port: 1
        order: 1
        eth_network_policy_name: "production-network"
        eth_qos_policy_name: "standard-qos"
        eth_adapter_policy_name: "standard-adapter"
        connection_type: "vmq"
        vmq_settings:
          enabled: true
          multi_queue_support: false
          num_interrupts: 16
          num_vmqs: 4
        state: present
    state: present

- name: Delete a LAN Connectivity Policy
  cisco.intersight.intersight_lan_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "old-lan-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "test-lan-policy",
        "ObjectType": "vnic.LanConnectivityPolicy",
        "TargetPlatform": "Standalone",
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Production"
            }
        ],
        "vNICs": [
            {
                "Name": "eth0",
                "ObjectType": "vnic.EthIf",
                "Order": 0,
                "Placement": {
                    "Id": "1"
                }
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec
from ansible_collections.cisco.intersight.plugins.module_utils.intersight_vnic_utils import (
    validate_cdn_config, validate_usnic_settings, validate_vmq_settings, validate_sriov_settings,
    build_cdn_config, build_connection_settings, resolve_policy_moids_from_mappings,
    get_common_policy_mappings, get_iscsi_boot_policy_mapping, get_fabric_network_policy_mappings,
    get_mac_pool_policy_mapping, get_common_settings_argument_spec
)


def validate_fi_attached_params(module):
    """
    Validate FI-Attached specific parameters
    """
    iqn_allocation_type = module.params.get('iqn_allocation_type')
    static_iqn_name = module.params.get('static_iqn_name')
    iqn_pool_name = module.params.get('iqn_pool_name')

    # Validate IQN allocation type requirements
    if iqn_allocation_type == 'Static' and not static_iqn_name:
        module.fail_json(msg="static_iqn_name is required when iqn_allocation_type is 'Static'")

    if iqn_allocation_type == 'Pool' and not iqn_pool_name:
        module.fail_json(msg="iqn_pool_name is required when iqn_allocation_type is 'Pool'")

    if iqn_allocation_type != 'Static' and static_iqn_name:
        module.fail_json(msg="static_iqn_name should only be specified when iqn_allocation_type is 'Static'")

    if iqn_allocation_type != 'Pool' and iqn_pool_name:
        module.fail_json(msg="iqn_pool_name should only be specified when iqn_allocation_type is 'Pool'")


def validate_fi_attached_vnic_config(module, vnic_config):
    """
    Validate FIAttached specific vNIC configuration
    """
    vnic_name = vnic_config.get('name', 'unknown')
    mac_address_type = vnic_config.get('mac_address_type', 'pool')
    mac_pool_name = vnic_config.get('mac_pool_name')
    static_mac_address = vnic_config.get('static_mac_address')

    # Validate MAC address configuration
    if mac_address_type == 'pool' and not mac_pool_name:
        module.fail_json(msg=f"mac_pool_name is required when mac_address_type is 'pool' for vNIC '{vnic_name}'")

    if mac_address_type == 'static' and not static_mac_address:
        module.fail_json(msg=f"static_mac_address is required when mac_address_type is 'static' for vNIC '{vnic_name}'")

    if mac_address_type != 'pool' and mac_pool_name:
        module.fail_json(msg=f"mac_pool_name should only be specified when mac_address_type is 'pool' for vNIC '{vnic_name}'")

    if mac_address_type != 'static' and static_mac_address:
        module.fail_json(msg=f"static_mac_address should only be specified when mac_address_type is 'static' for vNIC '{vnic_name}'")

    # Validate required FIAttached fields
    fabric_eth_network_group_policy_name = vnic_config.get('fabric_eth_network_group_policy_name')
    fabric_eth_network_control_policy_name = vnic_config.get('fabric_eth_network_control_policy_name')

    if not fabric_eth_network_group_policy_name:
        module.fail_json(msg=f"fabric_eth_network_group_policy_name is required for attached vNIC '{vnic_name}'")

    if not fabric_eth_network_control_policy_name:
        module.fail_json(msg=f"fabric_eth_network_control_policy_name is required for attached vNIC '{vnic_name}'")

    # Validate advanced placement configuration
    validate_fi_attached_placement_config(module, vnic_config)


def validate_fi_attached_placement_config(module, vnic_config):
    """
    Validate FIAttached placement configuration
    """
    vnic_name = vnic_config.get('name', 'unknown')
    auto_vnic_placement_enabled = vnic_config.get('auto_vnic_placement_enabled', False)

    # Skip advanced placement validation if auto placement is enabled
    if auto_vnic_placement_enabled:
        return

    auto_slot_id = vnic_config.get('auto_slot_id', True)
    placement_slot_id = vnic_config.get('placement_slot_id')
    auto_pci_link = vnic_config.get('auto_pci_link', True)
    pci_link_assignment_mode = vnic_config.get('pci_link_assignment_mode')
    pci_link = vnic_config.get('pci_link')

    # Validate slot ID configuration
    if not auto_slot_id and not placement_slot_id:
        module.fail_json(msg=f"placement_slot_id is required when auto_slot_id is false for vNIC '{vnic_name}'")

    if auto_slot_id and placement_slot_id:
        module.fail_json(msg=f"placement_slot_id should not be specified when auto_slot_id is true for vNIC '{vnic_name}'")

    # Validate PCI link configuration
    if not auto_pci_link and not pci_link_assignment_mode:
        module.fail_json(msg=f"pci_link_assignment_mode is required when auto_pci_link is false for vNIC '{vnic_name}'")

    if auto_pci_link and pci_link_assignment_mode:
        module.fail_json(msg=f"pci_link_assignment_mode should not be specified when auto_pci_link is true for vNIC '{vnic_name}'")

    # Validate PCI link when using Custom mode
    if pci_link_assignment_mode == 'Custom' and pci_link is None:
        module.fail_json(msg=f"pci_link is required when pci_link_assignment_mode is 'Custom' for vNIC '{vnic_name}'")

    if pci_link_assignment_mode != 'Custom' and pci_link is not None and pci_link != 0:
        module.fail_json(msg=f"pci_link should only be specified when pci_link_assignment_mode is 'Custom' for vNIC '{vnic_name}'")


def validate_standalone_vnic_config(module, vnic_config):
    """
    Validate Standalone specific vNIC configuration
    """
    vnic_name = vnic_config.get('name', 'unknown')

    # Validate required Standalone fields
    placement_slot_id = vnic_config.get('placement_slot_id')
    eth_network_policy_name = vnic_config.get('eth_network_policy_name')

    if not placement_slot_id:
        module.fail_json(msg=f"placement_slot_id is required for standalone vNIC '{vnic_name}'")

    if not eth_network_policy_name:
        module.fail_json(msg=f"eth_network_policy_name is required for standalone vNIC '{vnic_name}'")


def get_vnic_policy_mappings(target_platform, vnic_config):
    """
    Get policy mappings for vNIC configuration based on target platform.
    """
    # Start with common policies
    policy_mappings = get_common_policy_mappings()

    # Platform-specific policies
    if target_platform == 'attached':
        # Add fabric network policies
        policy_mappings.update(get_fabric_network_policy_mappings())

        # MAC pool for FIAttached when using pool type
        if vnic_config.get('mac_address_type', 'pool') == 'pool':
            policy_mappings.update(get_mac_pool_policy_mapping())

        # iSCSI boot policy
        if vnic_config.get('iscsi_boot_policy_name'):
            policy_mappings.update(get_iscsi_boot_policy_mapping())

    else:  # standalone server
        policy_mappings['eth_network_policy_name'] = ('/vnic/EthNetworkPolicies', 'EthNetworkPolicy', 'Ethernet Network Policy')

    return policy_mappings


def resolve_vnic_policy_moids(intersight, policy_cache, module, vnic_config, target_platform):
    """
    Resolve all policy MOIDs for a vNIC configuration based on target platform.
    """
    policy_mappings = get_vnic_policy_mappings(target_platform, vnic_config)
    organization_name = module.params['organization']
    return resolve_policy_moids_from_mappings(intersight, policy_cache, module, vnic_config, policy_mappings, organization_name)


def build_vnic_api_body(intersight, policy_cache, module, vnic_config, lan_connectivity_policy_moid):
    """
    Build vNIC API body for API call
    """
    target_platform = module.params.get('target_platform')

    if target_platform == 'attached':
        return build_fi_attached_vnic_api_body(intersight, policy_cache, module, vnic_config, lan_connectivity_policy_moid)
    else:
        return build_standalone_vnic_api_body(intersight, policy_cache, module, vnic_config, lan_connectivity_policy_moid)


def build_standalone_vnic_api_body(intersight, policy_cache, module, vnic_config, lan_connectivity_policy_moid):
    """
    Build Standalone vNIC API body for Intersight API call
    """
    # Base vNIC configuration for Standalone
    vnic_api_body = {
        'Name': vnic_config['name'],
        'Placement': {
            'Id': vnic_config['placement_slot_id'],
            'Uplink': vnic_config.get('uplink_port', 0),
            'PciLink': vnic_config.get('pci_link', 0)
        },
        'Order': vnic_config.get('order', 0),
        'LanConnectivityPolicy': lan_connectivity_policy_moid
    }

    # Add common CDN configuration
    vnic_api_body['Cdn'] = build_cdn_config(vnic_config)

    # Resolve and add policy MOIDs
    policy_moids = resolve_vnic_policy_moids(intersight, policy_cache, module, vnic_config, 'standalone')
    vnic_api_body.update(policy_moids)

    # Add common connection type settings
    organization_name = module.params['organization']
    connection_settings = build_connection_settings(intersight, policy_cache, module, vnic_config, organization_name)
    vnic_api_body.update(connection_settings)

    return vnic_api_body


def build_fi_attached_vnic_api_body(intersight, policy_cache, module, vnic_config, lan_connectivity_policy_moid):
    """
    Build FIAttached vNIC API body for Intersight API call
    """
    # Base vNIC configuration for FIAttached
    # Map lowercase user input to API format
    mac_address_type = vnic_config.get('mac_address_type', 'pool')
    api_mac_address_type = 'STATIC' if mac_address_type == 'static' else 'POOL'
    auto_vnic_placement_enabled = vnic_config.get('auto_vnic_placement_enabled', False)

    vnic_api_body = {
        'Name': vnic_config['name'],
        'MacAddressType': api_mac_address_type,
        'FailoverEnabled': vnic_config.get('failover_enabled', False),
        'LanConnectivityPolicy': lan_connectivity_policy_moid
    }

    # Handle placement based on auto_vnic_placement_enabled
    if auto_vnic_placement_enabled:
        vnic_api_body['Placement'] = {
            'SwitchId': vnic_config.get('switch_id', 'A'),
            'AutoSlotId': True,
            'AutoPciLink': True
        }
    else:
        # Full placement control
        placement = {
            'SwitchId': vnic_config.get('switch_id', 'A'),
            'AutoSlotId': vnic_config.get('auto_slot_id', True),
            'AutoPciLink': vnic_config.get('auto_pci_link', True)
        }

        # Add slot ID if auto_slot_id is disabled
        if not vnic_config.get('auto_slot_id', True):
            placement['Id'] = vnic_config['placement_slot_id']

        # Add PCI link configuration if auto_pci_link is disabled
        if not vnic_config.get('auto_pci_link', True):
            placement['PciLinkAssignmentMode'] = vnic_config['pci_link_assignment_mode']
            if vnic_config['pci_link_assignment_mode'] == 'Custom':
                placement['PciLink'] = vnic_config.get('pci_link', 0)

        vnic_api_body['Placement'] = placement
        vnic_api_body['Order'] = vnic_config.get('order', 0)

    # Add common CDN configuration
    vnic_api_body['Cdn'] = build_cdn_config(vnic_config)

    # Add static MAC address if using static type
    if mac_address_type == 'static':
        vnic_api_body['StaticMacAddress'] = vnic_config['static_mac_address']

    # Resolve and add policy MOIDs
    policy_moids = resolve_vnic_policy_moids(intersight, policy_cache, module, vnic_config, 'attached')
    vnic_api_body.update(policy_moids)

    # Add common connection type settings
    organization_name = module.params['organization']
    connection_settings = build_connection_settings(intersight, policy_cache, module, vnic_config, organization_name)
    vnic_api_body.update(connection_settings)

    # Add pin group name if specified
    if vnic_config.get('pin_group_name'):
        vnic_api_body['PinGroupName'] = vnic_config['pin_group_name']

    return vnic_api_body


def validate_input(module):
    """
    Validate module input parameters
    """
    # Validate FI-Attached specific requirements
    target_platform = module.params.get('target_platform')
    if target_platform == 'attached':
        validate_fi_attached_params(module)

    # Validate vNIC configurations
    vnics = module.params.get('vnics', [])
    for vnic_config in vnics:
        vnic_name = vnic_config.get('name')
        vnic_state = vnic_config.get('state', 'present')

        # Only validate present vNICs - absent vNICs only need name
        if vnic_state == 'present':
            # Validate common required fields
            required_fields = ['eth_qos_policy_name', 'eth_adapter_policy_name']
            for field in required_fields:
                if not vnic_config.get(field):
                    module.fail_json(msg=f"{field} is required when vNIC state is 'present' for vNIC '{vnic_name}'")

            # Validate target platform specific fields
            target_platform = module.params.get('target_platform')
            if target_platform == 'attached':
                validate_fi_attached_vnic_config(module, vnic_config)
            else:
                validate_standalone_vnic_config(module, vnic_config)

            # Validate CDN configuration
            validate_cdn_config(module, vnic_config)

            connection_type = vnic_config.get('connection_type', 'none')

            # Validate connection type specific settings
            vnic_name = vnic_config.get('name', 'unknown')
            if connection_type == 'usnic':
                usnic_settings = vnic_config.get('usnic_settings')
                validate_usnic_settings(module, usnic_settings, vnic_name)
            elif connection_type == 'vmq':
                vmq_settings = vnic_config.get('vmq_settings', {})
                validate_vmq_settings(module, vmq_settings, vnic_name)
            elif connection_type == 'sriov':
                sriov_settings = vnic_config.get('sriov_settings', {})
                validate_sriov_settings(module, sriov_settings, vnic_name)


def main():
    # Define vNIC options
    vnic_options = dict(
        name=dict(type='str', required=True),
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        placement_slot_id=dict(type='str'),
        pci_link=dict(type='int', choices=[0, 1], default=0),
        uplink_port=dict(type='int', choices=[0, 1, 2, 3], default=0),
        order=dict(type='int', default=0),
        eth_network_policy_name=dict(type='str'),
        eth_qos_policy_name=dict(type='str'),
        eth_adapter_policy_name=dict(type='str'),
        mac_address_type=dict(type='str', choices=['pool', 'static'], default='pool'),
        static_mac_address=dict(type='str'),
        auto_slot_id=dict(type='bool', default=True),
        auto_pci_link=dict(type='bool', default=True),
        pci_link_assignment_mode=dict(type='str', choices=['Custom', 'Load-Balanced']),
        auto_vnic_placement_enabled=dict(type='bool', default=False),
        pin_group_name=dict(type='str'),
    )
    # Add connection settings argument specs
    vnic_options.update(get_common_settings_argument_spec())

    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        target_platform=dict(type='str', choices=['standalone', 'attached'], default='standalone'),
        azure_qos_enabled=dict(type='bool', default=False),
        iqn_allocation_type=dict(type='str', choices=['None', 'Pool', 'Static'], default='None'),
        placement_mode=dict(type='str', choices=['custom', 'auto'], default='custom'),
        iqn_pool_name=dict(type='str'),
        static_iqn_name=dict(type='str'),
        vnics=dict(type='list', elements='dict', options=vnic_options)
    )

    required_if = [
        ['state', 'present', ['vnics']],
    ]

    module = AnsibleModule(
        argument_spec,
        required_if=required_if,
        supports_check_mode=True,
    )

    if module.params['state'] == 'present':
        validate_input(module)

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/vnic/LanConnectivityPolicies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()

        target_platform = intersight.module.params['target_platform']
        api_target_platform = 'FIAttached' if target_platform == 'attached' else 'Standalone'
        intersight.api_body['TargetPlatform'] = api_target_platform

        # Add FIAttached-specific parameters
        if intersight.module.params['target_platform'] == 'attached':
            intersight.api_body['AzureQosEnabled'] = intersight.module.params['azure_qos_enabled']
            intersight.api_body['IqnAllocationType'] = intersight.module.params['iqn_allocation_type']
            intersight.api_body['PlacementMode'] = intersight.module.params['placement_mode']

            # Resolve IQN pool MOID if specified
            if intersight.module.params['iqn_pool_name']:
                iqn_pool_moid = intersight.get_moid_by_name_and_org(
                    resource_path='/iqnpool/Pools',
                    resource_name=intersight.module.params['iqn_pool_name'],
                    organization_name=intersight.module.params['organization']
                )
                if not iqn_pool_moid:
                    intersight.module.fail_json(msg=f"IQN Pool '{intersight.module.params['iqn_pool_name']}' not found in organization ' \
                    {intersight.module.params['organization']}'")
                intersight.api_body['IqnPool'] = iqn_pool_moid

            if intersight.module.params['static_iqn_name']:
                intersight.api_body['StaticIqnName'] = intersight.module.params['static_iqn_name']

    intersight.configure_policy_or_profile(resource_path=resource_path)

    # Save the LAN connectivity policy response
    lan_connectivity_policy_response = intersight.result['api_response']

    lan_connectivity_policy_moid = None
    if intersight.module.params['state'] == 'present' and lan_connectivity_policy_response:
        lan_connectivity_policy_moid = lan_connectivity_policy_response.get('Moid')

    # Process vNICs
    vnics_response = []
    if intersight.module.params['state'] == 'present' and intersight.module.params.get('vnics'):
        # Cache for policy MOIDs to avoid redundant API calls
        policy_cache = {}

        for vnic_config in intersight.module.params['vnics']:
            vnic_state = vnic_config.get('state', 'present')

            # Only build API body for present vNICs
            if vnic_state == 'present':
                # Build vNIC API body using helper function
                vnic_api_body = build_vnic_api_body(
                    intersight, policy_cache, module, vnic_config, lan_connectivity_policy_moid
                )
                intersight.api_body = vnic_api_body

            # Configure the vNIC (create/update/delete)
            resource_path = '/vnic/EthIfs'
            # Filter by both vNIC name AND LAN Connectivity Policy to avoid affecting vNICs in other policies
            custom_filter = f"Name eq '{vnic_config['name']}' and LanConnectivityPolicy.Moid eq '{lan_connectivity_policy_moid}'"
            intersight.configure_secondary_resource(
                resource_path=resource_path,
                state=vnic_state,
                custom_filter=custom_filter
            )

            # Save the vNIC response only if it's present
            if vnic_state == 'present':
                vnics_response.append(intersight.result['api_response'])

    # Combine LAN connectivity policy and vNICs in the main response
    if lan_connectivity_policy_response:
        lan_connectivity_policy_response['vNICs'] = vnics_response
        intersight.result['api_response'] = lan_connectivity_policy_response

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
