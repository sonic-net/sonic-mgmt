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
module: intersight_san_connectivity_policy
short_description: Manage SAN Connectivity Policies and vHBAs for Cisco Intersight
description:
  - Create, update, and delete SAN Connectivity Policies on Cisco Intersight.
  - Manage individual vHBAs (virtual Host Bus Adapters) within SAN Connectivity policies.
  - Supports Standalone and FIAttached target platforms with different configuration options.
  - Note SAN Connectivity policies are not supported on Unified Edge Servers.
  - SAN Connectivity policies define storage connectivity settings for server profiles.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/vnic/SanConnectivityPolicy/get/).
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
      - The name assigned to the SAN Connectivity Policy.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the SAN Connectivity Policy.
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
      - The platform type for which the SAN Connectivity policy is intended.
      - C(standalone) for standalone servers.
      - C(fiattached) for fabric interconnect attached servers.
      - Note SAN Connectivity policies are not supported on unified edge servers.
    type: str
    choices: ['standalone', 'fiattached']
    default: 'standalone'
  placement_mode:
    description:
      - The mode used for placement of vHBAs on network adapters.
      - C(custom) requires manual placement specification for each vHBA.
      - C(auto) automatically distributes vHBAs between adapters during profile deployment.
      - Only applicable for fiattached target platform.
    type: str
    choices: ['custom', 'auto']
    default: 'custom'
  wwnn_address_type:
    description:
      - Type of WWNN address assignment.
      - C(pool) to use a WWNN pool.
      - C(static) to manually assign a static WWNN address.
      - Only applicable when target_platform is fiattached.
    type: str
    choices: ['pool', 'static']
    default: 'pool'
  wwnn_pool:
    description:
      - The WWNN pool that is assigned for WWNN address assignment.
      - Required when wwnn_address_type is pool and target platform is fiattached.
      - Only applicable for fiattached target platform.
    type: str
  static_wwnn_address:
    description:
      - The WWNN address for the server node must be in hexadecimal format xx:xx:xx:xx:xx:xx:xx:xx.
      - Allowed ranges are 20:00:00:00:00:00:00:00 to 20:FF:FF:FF:FF:FF:FF:FF or from 50:00:00:00:00:00:00:00 to 5F:FF:FF:FF:FF:FF:FF:FF.
      - To ensure uniqueness of WWN's in the SAN fabric, you are strongly encouraged to use the WWN prefix - 20:00:00:25:B5:xx:xx:xx.
      - Required when wwnn_address_type is static and target platform is fiattached.
      - Only applicable for fiattached target platform.
    type: str
  vhbas:
    description:
      - List of vHBAs to be created and attached to the SAN Connectivity policy.
      - Each vHBA will be configured with the specified fibre channel policies.
      - Configuration options vary based on target_platform.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name of the virtual fibre channel interface.
          - Must be unique within the SAN Connectivity policy.
        type: str
        required: true
      state:
        description:
          - Whether to create/update or delete the vHBA.
        type: str
        choices: ['present', 'absent']
        default: present
      vhba_type:
        description:
          - vHBA Type configuration for SAN Connectivity Policy.
          - This configuration is supported only on Cisco VIC 14XX series and higher series of adapters.
          - Required when vHBA state is present.
        type: str
        choices: ['fc-initiator', 'fc-nvme-initiator', 'fc-nvme-target', 'fc-target']
      slot_id:
        description:
          - PCIe Slot where the VIC adapter is installed.
          - Supported values are (1-15) and MLOM.
          - Required for Standalone when vHBA state is present.
          - Required for FIAttached when vHBA state is present and auto_slot_id is false.
        type: str
      pci_link:
        description:
          - The PCI Link used as transport for the virtual interface.
          - PCI Link is only applicable for select Cisco UCS VIC 1300 models (UCSC-PCIE-C40Q-03, UCSB-MLOM-40G-03, UCSB-VIC-M83-8P) that support two PCI links.
          - The value, if specified, for any other VIC model will be ignored.
          - For Standalone, this is used directly.
          - For FIAttached, required when pci_link_assignment_mode is Custom.
        type: int
        choices: [0, 1]
        default: 0
      uplink_port:
        description:
          - Adapter port on which the virtual interface will be created.
          - Only applicable for Standalone platform.
        type: int
        choices: [0, 1, 2, 3]
        default: 0
      pci_order:
        description:
          - The order in which the virtual interface is brought up.
          - The order assigned to an interface should be unique for all the Ethernet and Fibre-Channel interfaces on each PCI link on a VIC adapter.
          - The order should start from zero with no overlaps.
          - The maximum value of PCI order is limited by the number of virtual interfaces (Ethernet and Fibre-Channel) on each PCI link on a VIC adapter.
          - All VIC adapters have a single PCI link except VIC 1340, VIC 1380 and VIC 1385 which have two.
        type: int
        default: 0
      persistent_lun_bindings:
        description:
          - Enables retention of LUN ID associations in memory until they are manually cleared.
        type: bool
        default: false
      fibre_channel_network_policy:
        description:
          - Name of the Fibre Channel Network Policy.
          - Required when vHBA state is present.
        type: str
      fibre_channel_qos_policy:
        description:
          - Name of the Fibre Channel QoS Policy.
          - Required when vHBA state is present.
        type: str
      fibre_channel_adapter_policy:
        description:
          - Name of the Fibre Channel Adapter Policy.
          - Required when vHBA state is present.
        type: str
      pin_group_name:
        description:
          - Pingroup name associated to vHBA for static pinning.
          - SCP deploy will resolve pingroup name and fetches the corresponding uplink port/port channel to pin the vHBA traffic.
          - Optional field for FIAttached target platform.
        type: str
      wwpn_address_type:
        description:
          - Type of WWPN address assignment.
          - C(pool) to use a WWPN pool.
          - C(static) to manually assign a static WWPN address.
          - Only applicable for fiattached target platform.
        type: str
        choices: ['pool', 'static']
        default: 'pool'
      wwpn_pool:
        description:
          - The WWPN pool used for assigning the WWPN address to the vHBA.
          - Required when wwpn_address_type is pool and target platform is fiattached.
          - Only applicable for fiattached target platform.
        type: str
      static_wwpn_address:
        description:
          - The WWPN address must be in hexadecimal format xx:xx:xx:xx:xx:xx:xx:xx.
          - Allowed ranges are 20:00:00:00:00:00:00:00 to 20:FF:FF:FF:FF:FF:FF:FF or from 50:00:00:00:00:00:00:00 to 5F:FF:FF:FF:FF:FF:FF:FF.
          - To ensure uniqueness of WWN's in the SAN fabric, you are strongly encouraged to use the WWN prefix - 20:00:00:25:B5:xx:xx:xx.
          - Required when wwpn_address_type is static and target platform is fiattached.
          - Only applicable for fiattached target platform.
        type: str
      switch_id:
        description:
          - The fabric port to which the vHBA will be associated.
          - Only applicable for fiattached target platform.
        type: str
        choices: ['a', 'b']
        default: 'a'
      auto_slot_id:
        description:
          - Enable or disable automatic assignment of the VIC slot ID.
          - If enabled and the server has only one VIC, the same VIC is chosen for all the vHBAs.
          - If enabled and the server has multiple VICs, the vHBA is deployed on the first VIC.
          - If disabled, slot_id must be specified.
          - Only applicable for FIAttached target platform.
        type: bool
        default: true
      auto_pci_link:
        description:
          - Enable or disable automatic assignment of the PCI Link in a dual-link adapter.
          - This option applies only to 13xx series VICs that support dual-link.
          - If enabled, the system determines the placement of the vHBA on either of the PCI Links.
          - If disabled, pci_link_assignment_mode must be specified.
          - Only applicable for FIAttached target platform.
        type: bool
        default: true
      pci_link_assignment_mode:
        description:
          - PCI Link assignment mode when auto_pci_link is disabled.
          - C(custom) allows manual selection of PCI link via pci_link parameter.
          - C(load-balanced) automatically distributes vHBAs across available PCI links.
          - Required when auto_pci_link is false.
          - Only applicable for fiattached target platform.
        type: str
        choices: ['custom', 'load-balanced']
      fibre_channel_zone_policies:
        description:
          - List of Fibre Channel Zone Policy names.
          - Relationship to the FC Zone policy to configure Zones on the switch.
          - Optional field for FIAttached target platform.
        type: list
        elements: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a SAN Connectivity Policy for Standalone servers
  cisco.intersight.intersight_san_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "standalone-san-policy"
    description: "SAN connectivity policy for standalone servers"
    target_platform: "standalone"
    tags:
      - Key: "Environment"
        Value: "Production"
      - Key: "Site"
        Value: "DataCenter-A"
    vhbas:
      - name: "vhba0"
        vhba_type: "fc-initiator"
        slot_id: "1"
        pci_link: 0
        uplink_port: 0
        pci_order: 0
        persistent_lun_bindings: false
        fibre_channel_network_policy: "fc-network-policy"
        fibre_channel_qos_policy: "fc-qos-policy"
        fibre_channel_adapter_policy: "fc-adapter-policy"
      - name: "vhba1"
        vhba_type: "fc-nvme-initiator"
        slot_id: "4"
        pci_link: 0
        uplink_port: 2
        pci_order: 5
        persistent_lun_bindings: true
        fibre_channel_network_policy: "fc-network-policy"
        fibre_channel_qos_policy: "fc-qos-policy"
        fibre_channel_adapter_policy: "fc-adapter-policy"
    state: present

- name: Create a SAN Connectivity Policy with auto placement
  cisco.intersight.intersight_san_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "auto-placement-san-policy"
    description: "SAN policy with automatic vHBA placement"
    target_platform: "fiattached"
    placement_mode: "auto"
    wwnn_address_type: "pool"
    wwnn_pool: "default-wwnn-pool"
    vhbas:
      - name: "vhba-auto-1"
        vhba_type: "fc-initiator"
        wwpn_address_type: "pool"
        wwpn_pool: "default-wwpn-pool"
        switch_id: "a"
        fibre_channel_network_policy: "fc-network-policy"
        fibre_channel_qos_policy: "fc-qos-policy"
        fibre_channel_adapter_policy: "fc-adapter-policy"
      - name: "vhba-auto-2"
        vhba_type: "fc-initiator"
        wwpn_address_type: "pool"
        wwpn_pool: "default-wwpn-pool"
        switch_id: "b"
        fibre_channel_network_policy: "fc-network-policy"
        fibre_channel_qos_policy: "fc-qos-policy"
        fibre_channel_adapter_policy: "fc-adapter-policy"
    state: present

- name: Create a SAN Connectivity Policy for FI-Attached servers with WWNN pool
  cisco.intersight.intersight_san_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fi-attached-san-policy"
    description: "SAN connectivity policy for FI-attached servers"
    target_platform: "fiattached"
    placement_mode: "custom"
    wwnn_address_type: "pool"
    wwnn_pool: "default-wwnn-pool"
    tags:
      - Key: "Environment"
        Value: "Production"
    vhbas:
      - name: "vhba-a"
        vhba_type: "fc-initiator"
        wwpn_address_type: "pool"
        wwpn_pool: "default-wwpn-pool"
        switch_id: "a"
        auto_slot_id: true
        auto_pci_link: true
        pci_order: 0
        persistent_lun_bindings: false
        fibre_channel_network_policy: "fc-network-policy"
        fibre_channel_qos_policy: "fc-qos-policy"
        fibre_channel_adapter_policy: "fc-adapter-policy"
        fibre_channel_zone_policies:
          - "fc-zone-policy-1"
      - name: "vhba-b"
        vhba_type: "fc-initiator"
        wwpn_address_type: "pool"
        wwpn_pool: "default-wwpn-pool"
        switch_id: "b"
        auto_slot_id: true
        auto_pci_link: true
        pci_order: 1
        persistent_lun_bindings: false
        fibre_channel_network_policy: "fc-network-policy"
        fibre_channel_qos_policy: "fc-qos-policy"
        fibre_channel_adapter_policy: "fc-adapter-policy"
        fibre_channel_zone_policies:
          - "fc-zone-policy-1"
    state: present

- name: Create a SAN Connectivity Policy for FI-Attached with static WWPN
  cisco.intersight.intersight_san_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fi-attached-static-san-policy"
    description: "SAN connectivity policy with static addresses"
    target_platform: "fiattached"
    placement_mode: "custom"
    wwnn_address_type: "pool"
    wwnn_pool: "default-wwnn-pool"
    vhbas:
      - name: "vhba-static"
        vhba_type: "fc-target"
        wwpn_address_type: "static"
        static_wwpn_address: "50:00:00:00:00:00:00:00"
        switch_id: "b"
        auto_slot_id: false
        slot_id: "2"
        auto_pci_link: false
        pci_link_assignment_mode: "load-balanced"
        pci_order: 1
        persistent_lun_bindings: true
        fibre_channel_network_policy: "fc-network-policy"
        fibre_channel_qos_policy: "fc-qos-policy"
        fibre_channel_adapter_policy: "fc-adapter-policy"
        fibre_channel_zone_policies:
          - "fc-zone-policy-1"
    state: present

- name: Create a SAN Connectivity Policy for FI-Attached with advanced placement
  cisco.intersight.intersight_san_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fi-attached-advanced-placement"
    description: "SAN connectivity with custom placement"
    target_platform: "fiattached"
    placement_mode: "custom"
    wwnn_address_type: "static"
    static_wwnn_address: "20:00:00:25:B5:00:00:01"
    vhbas:
      - name: "vhba-custom"
        vhba_type: "fc-initiator"
        wwpn_address_type: "pool"
        wwpn_pool: "wwpn-pool"
        switch_id: "a"
        auto_slot_id: false
        slot_id: "MLOM"
        auto_pci_link: false
        pci_link_assignment_mode: "custom"
        pci_link: 1
        pci_order: 3
        persistent_lun_bindings: false
        pin_group_name: "pingroup-a"
        fibre_channel_network_policy: "fc-network-policy"
        fibre_channel_qos_policy: "fc-qos-policy"
        fibre_channel_adapter_policy: "fc-adapter-policy"
    state: present

- name: Update SAN connectivity policy - manage vHBA states
  cisco.intersight.intersight_san_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "mixed-vhba-states-policy"
    description: "Policy demonstrating vHBA state management"
    target_platform: "standalone"
    vhbas:
      - name: "vhba0"
        vhba_type: "fc-initiator"
        slot_id: "1"
        pci_link: 0
        uplink_port: 0
        pci_order: 0
        persistent_lun_bindings: false
        fibre_channel_network_policy: "fc-network-policy"
        fibre_channel_qos_policy: "fc-qos-policy"
        fibre_channel_adapter_policy: "fc-adapter-policy"
        state: present
      - name: "vhba-old"
        state: absent
      - name: "vhba-new"
        vhba_type: "fc-nvme-initiator"
        slot_id: "3"
        pci_link: 0
        uplink_port: 1
        pci_order: 1
        persistent_lun_bindings: true
        fibre_channel_network_policy: "fc-network-policy"
        fibre_channel_qos_policy: "fc-qos-policy"
        fibre_channel_adapter_policy: "fc-adapter-policy"
        state: present
    state: present

- name: Delete a SAN Connectivity Policy
  cisco.intersight.intersight_san_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "old-san-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "fi-attached-san-policy",
        "ObjectType": "vnic.SanConnectivityPolicy",
        "TargetPlatform": "FIAttached",
        "WwnnAddressType": "POOL",
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Production"
            }
        ],
        "vHBAs": [
            {
                "Name": "vhba-a",
                "ObjectType": "vnic.FcIf",
                "Type": "fc-initiator",
                "Order": 0,
                "Placement": {
                    "SwitchId": "A",
                    "AutoSlotId": true,
                    "AutoPciLink": true
                }
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec
from ansible_collections.cisco.intersight.plugins.module_utils.intersight_vhba_utils import (
    validate_wwnn_address_config, validate_wwpn_address_config, validate_fi_attached_placement_config,
    validate_standalone_vhba_config, resolve_policy_moids_from_mappings,
    resolve_fc_zone_policies, build_wwpn_address_config, build_fi_attached_placement,
    build_standalone_placement, get_san_connectivity_vhba_policy_mappings
)


def validate_fi_attached_params(module):
    """
    Validate FI-Attached specific parameters.
    """
    validate_wwnn_address_config(module, module.params)


def validate_fi_attached_vhba_config(module, vhba_config):
    """
    Validate FIAttached specific vHBA configuration.
    """
    vhba_name = vhba_config.get('name', 'unknown')
    validate_wwpn_address_config(module, vhba_config, f"vHBA '{vhba_name}'")
    validate_fi_attached_placement_config(module, vhba_config)


def validate_input(module):
    """
    Validate module input parameters.
    """
    target_platform = module.params.get('target_platform')
    if target_platform == 'fiattached':
        validate_fi_attached_params(module)
    vhbas = module.params.get('vhbas', [])
    for vhba_config in vhbas:
        vhba_name = vhba_config.get('name')
        vhba_state = vhba_config.get('state', 'present')
        if vhba_state == 'present':
            required_fields = ['vhba_type', 'fibre_channel_network_policy', 'fibre_channel_qos_policy', 'fibre_channel_adapter_policy']
            for field in required_fields:
                if not vhba_config.get(field):
                    module.fail_json(msg=f"{field} is required when vHBA state is 'present' for vHBA '{vhba_name}'")
            if target_platform == 'fiattached':
                validate_fi_attached_vhba_config(module, vhba_config)
            elif target_platform == 'standalone':
                validate_standalone_vhba_config(module, vhba_config)


def build_standalone_vhba_api_body(intersight, policy_cache, module, vhba_config, san_connectivity_policy_moid):
    """
    Build Standalone vHBA API body for Intersight API call.
    """
    organization_name = module.params['organization']
    target_platform = module.params.get('target_platform')
    vhba_api_body = {
        'Name': vhba_config['name'],
        'Type': vhba_config['vhba_type'],
        'Placement': build_standalone_placement(vhba_config),
        'Order': vhba_config.get('pci_order', 0),
        'PersistentBindings': vhba_config.get('persistent_lun_bindings', False),
        'SanConnectivityPolicy': san_connectivity_policy_moid,
        'StaticWwpnAddress': ''
    }
    # Resolve FC policy MOIDs
    policy_mappings = get_san_connectivity_vhba_policy_mappings(target_platform)
    policy_moids = resolve_policy_moids_from_mappings(intersight, policy_cache, module, vhba_config, policy_mappings, organization_name)
    vhba_api_body.update(policy_moids)
    vhba_api_body['FcZonePolicies'] = []
    return vhba_api_body


def build_fi_attached_vhba_api_body(intersight, policy_cache, module, vhba_config, san_connectivity_policy_moid):
    """
    Build FIAttached vHBA API body for Intersight API call.
    """
    organization_name = module.params['organization']
    target_platform = module.params.get('target_platform')
    vhba_api_body = {
        'Name': vhba_config['name'],
        'Type': vhba_config['vhba_type'],
        'Order': vhba_config.get('pci_order', 0),
        'PersistentBindings': vhba_config.get('persistent_lun_bindings', False),
        'SanConnectivityPolicy': san_connectivity_policy_moid
    }
    # Build WWPN address configuration
    wwpn_config = build_wwpn_address_config(vhba_config, intersight, policy_cache, module, organization_name)
    vhba_api_body.update(wwpn_config)

    # Build placement configuration
    vhba_api_body['Placement'] = build_fi_attached_placement(vhba_config)

    # Resolve FC policy MOIDs
    policy_mappings = get_san_connectivity_vhba_policy_mappings(target_platform)
    policy_moids = resolve_policy_moids_from_mappings(intersight, policy_cache, module, vhba_config, policy_mappings, organization_name)
    vhba_api_body.update(policy_moids)

    # Resolve FC Zone Policies (optional)
    fc_zone_policy_names = vhba_config.get('fibre_channel_zone_policies')
    fc_zone_policy_moids = resolve_fc_zone_policies(intersight, policy_cache, module, fc_zone_policy_names, organization_name)
    vhba_api_body['FcZonePolicies'] = fc_zone_policy_moids

    # Add pin group name if specified
    if vhba_config.get('pin_group_name'):
        vhba_api_body['PinGroupName'] = vhba_config['pin_group_name']

    return vhba_api_body


def build_vhba_api_body(intersight, policy_cache, module, vhba_config, san_connectivity_policy_moid):
    """
    Build vHBA API body based on target platform.
    """
    target_platform = module.params.get('target_platform')
    if target_platform == 'fiattached':
        return build_fi_attached_vhba_api_body(intersight, policy_cache, module, vhba_config, san_connectivity_policy_moid)
    else:
        return build_standalone_vhba_api_body(intersight, policy_cache, module, vhba_config, san_connectivity_policy_moid)


def main():
    vhba_options = dict(
        name=dict(type='str', required=True),
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        vhba_type=dict(type='str', choices=['fc-initiator', 'fc-nvme-initiator', 'fc-nvme-target', 'fc-target']),
        slot_id=dict(type='str'),
        pci_link=dict(type='int', choices=[0, 1], default=0),
        uplink_port=dict(type='int', choices=[0, 1, 2, 3], default=0),
        pci_order=dict(type='int', default=0),
        persistent_lun_bindings=dict(type='bool', default=False),
        fibre_channel_network_policy=dict(type='str'),
        fibre_channel_qos_policy=dict(type='str'),
        fibre_channel_adapter_policy=dict(type='str'),
        pin_group_name=dict(type='str'),
        wwpn_address_type=dict(type='str', choices=['pool', 'static'], default='pool'),
        wwpn_pool=dict(type='str'),
        static_wwpn_address=dict(type='str'),
        switch_id=dict(type='str', choices=['a', 'b'], default='a'),
        auto_slot_id=dict(type='bool', default=True),
        auto_pci_link=dict(type='bool', default=True),
        pci_link_assignment_mode=dict(type='str', choices=['custom', 'load-balanced']),
        fibre_channel_zone_policies=dict(type='list', elements='str')
    )
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        target_platform=dict(type='str', choices=['standalone', 'fiattached'], default='standalone'),
        placement_mode=dict(type='str', choices=['custom', 'auto'], default='custom'),
        wwnn_address_type=dict(type='str', choices=['pool', 'static'], default='pool'),
        wwnn_pool=dict(type='str'),
        static_wwnn_address=dict(type='str'),
        vhbas=dict(type='list', elements='dict', options=vhba_options)
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )
    if module.params['state'] == 'present':
        validate_input(module)

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    resource_path = '/vnic/SanConnectivityPolicies'
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()
        target_platform_map = {
            'standalone': 'Standalone',
            'fiattached': 'FIAttached'
        }
        api_target_platform = target_platform_map[intersight.module.params['target_platform']]
        intersight.api_body['TargetPlatform'] = api_target_platform

        if intersight.module.params['target_platform'] == 'fiattached':
            # PlacementMode is only applicable for FIAttached
            placement_mode_map = {'custom': 'custom', 'auto': 'auto'}
            api_placement_mode = placement_mode_map[intersight.module.params['placement_mode']]
            intersight.api_body['PlacementMode'] = api_placement_mode
            wwnn_address_type_map = {'pool': 'POOL', 'static': 'STATIC'}
            api_wwnn_address_type = wwnn_address_type_map[intersight.module.params['wwnn_address_type']]
            intersight.api_body['WwnnAddressType'] = api_wwnn_address_type

            if intersight.module.params['wwnn_address_type'] == 'pool':
                wwnn_pool_moid = intersight.get_moid_by_name_and_org(
                    resource_path='/fcpool/Pools',
                    resource_name=intersight.module.params['wwnn_pool'],
                    organization_name=intersight.module.params['organization']
                )
                if not wwnn_pool_moid:
                    intersight.module.fail_json(
                        msg=f"WWNN Pool '{intersight.module.params['wwnn_pool']}' not found in organization '{intersight.module.params['organization']}'"
                    )
                intersight.api_body['WwnnPool'] = wwnn_pool_moid
                intersight.api_body['StaticWwnnAddress'] = ''
            else:
                intersight.api_body['StaticWwnnAddress'] = intersight.module.params['static_wwnn_address']

        elif intersight.module.params['target_platform'] == 'standalone':
            intersight.api_body['PlacementMode'] = 'custom'
            intersight.api_body['WwnnAddressType'] = 'POOL'
            intersight.api_body['StaticWwnnAddress'] = ''

    intersight.configure_policy_or_profile(resource_path=resource_path)
    san_connectivity_policy_response = intersight.result['api_response']
    san_connectivity_policy_moid = None
    if intersight.module.params['state'] == 'present' and san_connectivity_policy_response:
        san_connectivity_policy_moid = san_connectivity_policy_response.get('Moid')

    # Process vHBAs
    vhbas_response = []
    if intersight.module.params['state'] == 'present' and intersight.module.params.get('vhbas'):
        policy_cache = {}
        for vhba_config in intersight.module.params['vhbas']:
            vhba_state = vhba_config.get('state', 'present')
            if vhba_state == 'present':
                vhba_api_body = build_vhba_api_body(
                    intersight, policy_cache, module, vhba_config, san_connectivity_policy_moid
                )
                intersight.api_body = vhba_api_body

            resource_path = '/vnic/FcIfs'
            custom_filter = f"Name eq '{vhba_config['name']}' and SanConnectivityPolicy.Moid eq '{san_connectivity_policy_moid}'"
            intersight.configure_secondary_resource(
                resource_path=resource_path,
                state=vhba_state,
                custom_filter=custom_filter
            )
            if vhba_state == 'present':
                vhbas_response.append(intersight.result['api_response'])

    if san_connectivity_policy_response:
        san_connectivity_policy_response['vHBAs'] = vhbas_response
        intersight.result['api_response'] = san_connectivity_policy_response

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
