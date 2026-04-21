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
module: intersight_vnic_template
short_description: Manage vNIC Templates for Cisco Intersight
description:
  - Create, update, and delete vNIC Templates on Cisco Intersight.
  - vNIC Templates define network interface configurations that can be used by LAN Connectivity policies.
  - Templates provide a standardized way to configure vNICs with consistent network and adapter policies.
  - vNIC Templates are only applicable for FI-Attached (Fabric Interconnect) deployments.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/vnic/VnicTemplate/get/).
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
      - The name assigned to the vNIC Template.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the vNIC Template.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  enable_override:
    description:
      - When enabled, the configuration of the derived instances may override the template configuration.
    type: bool
    default: false
  switch_id:
    description:
      - The fabric port to which the vNIC will be associated.
    type: str
    choices: ['A', 'B']
    default: 'A'
  failover_enabled:
    description:
      - Enables automatic vNIC failover to the secondary Fabric Interconnect
        if the primary path fails.
      - Failover applies only to Cisco VICs that are connected to a Fabric Interconnect cluster.
    type: bool
    default: false
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
  mac_pool_name:
    description:
      - The MAC pool that is assigned to the vNIC Template.
      - Required when state is 'present'.
    type: str
  fabric_eth_network_group_policy_name:
    description:
      - Relationship to the Fabric Ethernet Group Policy.
      - Required when state is 'present'.
    type: str
  fabric_eth_network_control_policy_name:
    description:
      - Relationship to the Fabric Ethernet Network Control Policy.
      - Required when state is 'present'.
    type: str
  eth_qos_policy_name:
    description:
      - Relationship to the Ethernet QoS Policy.
      - Required when state is 'present'.
    type: str
  eth_adapter_policy_name:
    description:
      - Relationship to the Ethernet Adapter Policy.
      - Required when state is 'present'.
    type: str
  iscsi_boot_policy_name:
    description:
      - Relationship to the boot iSCSI Policy.
    type: str
  pin_group_name:
    description:
      - Pingroup name associated to vNIC for static pinning.
      - LCP deploy will resolve pingroup name and fetches the corresponding uplink port/port channel to pin the vNIC traffic.
    type: str
  connection_type:
    description:
      - Type of connection for the vNIC.
    type: str
    choices: ['none', 'usnic', 'vmq', 'sriov']
    default: 'none'
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
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a basic vNIC Template
  cisco.intersight.intersight_vnic_template:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "basic-vnic-template"
    description: "Basic vNIC template for production servers"
    enable_override: false
    switch_id: "A"
    failover_enabled: false
    cdn_source: "vnic"
    mac_pool_name: "default-mac-pool"
    fabric_eth_network_group_policy_name: "default-network-group"
    fabric_eth_network_control_policy_name: "default-network-control"
    eth_qos_policy_name: "default-qos-policy"
    eth_adapter_policy_name: "default-adapter-policy"
    connection_type: "none"
    tags:
      - Key: "Environment"
        Value: "Production"
      - Key: "Site"
        Value: "DataCenter-A"
    state: present

- name: Create a vNIC Template with custom CDN
  cisco.intersight.intersight_vnic_template:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "custom-cdn-template"
    description: "vNIC template with custom CDN value"
    enable_override: true
    switch_id: "B"
    failover_enabled: true
    cdn_source: "user"
    cdn_value: "Management-NIC"
    mac_pool_name: "mgmt-mac-pool"
    fabric_eth_network_group_policy_name: "mgmt-network-group"
    fabric_eth_network_control_policy_name: "mgmt-network-control"
    eth_qos_policy_name: "mgmt-qos-policy"
    eth_adapter_policy_name: "mgmt-adapter-policy"
    iscsi_boot_policy_name: "mgmt-iscsi-boot-policy"
    connection_type: "none"
    state: present

- name: Create a vNIC Template with USNIC
  cisco.intersight.intersight_vnic_template:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "usnic-template"
    description: "vNIC template with USNIC configuration"
    enable_override: false
    switch_id: "A"
    mac_pool_name: "hpc-mac-pool"
    fabric_eth_network_group_policy_name: "hpc-network-group"
    fabric_eth_network_control_policy_name: "hpc-network-control"
    eth_qos_policy_name: "hpc-qos-policy"
    eth_adapter_policy_name: "hpc-adapter-policy"
    connection_type: "usnic"
    usnic_settings:
      count: 0
      cos: 5
      usnic_adapter_policy_name: "hpc-adapter-policy"
    state: present

- name: Create a vNIC Template with VMQ
  cisco.intersight.intersight_vnic_template:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "vmq-template"
    description: "vNIC template with VMQ configuration"
    enable_override: false
    switch_id: "A"
    mac_pool_name: "vm-mac-pool"
    fabric_eth_network_group_policy_name: "vm-network-group"
    fabric_eth_network_control_policy_name: "vm-network-control"
    eth_qos_policy_name: "vm-qos-policy"
    eth_adapter_policy_name: "vm-adapter-policy"
    connection_type: "vmq"
    vmq_settings:
      enabled: true
      multi_queue_support: false
      num_interrupts: 16
      num_vmqs: 4
    state: present

- name: Create a vNIC Template with VMQ multi-queue support
  cisco.intersight.intersight_vnic_template:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "vmq-multiqueue-template"
    description: "vNIC template with VMQ multi-queue configuration"
    enable_override: true
    switch_id: "B"
    mac_pool_name: "vm-mac-pool"
    fabric_eth_network_group_policy_name: "vm-network-group"
    fabric_eth_network_control_policy_name: "vm-network-control"
    eth_qos_policy_name: "vm-qos-policy"
    eth_adapter_policy_name: "vm-adapter-policy"
    connection_type: "vmq"
    vmq_settings:
      enabled: true
      multi_queue_support: true
      num_sub_vnics: 64
      vmmq_adapter_policy_name: "vmmq-adapter-policy"
    state: present

- name: Create a vNIC Template with SR-IOV
  cisco.intersight.intersight_vnic_template:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "sriov-template"
    description: "vNIC template with SR-IOV configuration"
    enable_override: false
    switch_id: "A"
    mac_pool_name: "sriov-mac-pool"
    fabric_eth_network_group_policy_name: "sriov-network-group"
    fabric_eth_network_control_policy_name: "sriov-network-control"
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

- name: Create a vNIC Template with pin group
  cisco.intersight.intersight_vnic_template:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "vnic-pinned-template"
    description: "vNIC template with static pinning"
    enable_override: false
    switch_id: "A"
    failover_enabled: false
    mac_pool_name: "default-mac-pool"
    fabric_eth_network_group_policy_name: "default-network-group"
    fabric_eth_network_control_policy_name: "default-network-control"
    eth_qos_policy_name: "default-qos-policy"
    eth_adapter_policy_name: "default-adapter-policy"
    pin_group_name: "pingroup-a"
    connection_type: "none"
    state: present

- name: Delete a vNIC Template
  cisco.intersight.intersight_vnic_template:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "old-vnic-template"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "test-vnic-template",
        "ObjectType": "vnic.VnicTemplate",
        "EnableOverride": false,
        "SwitchId": "A",
        "FailoverEnabled": false,
        "Cdn": {
            "Source": "vnic"
        },
        "MacPool": {
            "Name": "default-mac-pool",
            "ObjectType": "macpool.Pool"
        },
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Production"
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


def get_template_policy_mappings(module):
    """
    Get policy mappings for vNIC Template configuration.
    """
    # Start with common policies
    policy_mappings = get_common_policy_mappings()

    # Add fabric network policies (vNIC templates are FI-attached only)
    policy_mappings.update(get_fabric_network_policy_mappings())

    # Add MAC pool (always required for templates)
    policy_mappings.update(get_mac_pool_policy_mapping())

    # iSCSI boot policy is optional - only add if specified
    if module.params.get('iscsi_boot_policy_name'):
        policy_mappings.update(get_iscsi_boot_policy_mapping())

    return policy_mappings


def resolve_policy_moids(intersight, policy_cache, module):
    """
    Resolve all policy MOIDs for vNIC Template configuration.
    """
    policy_mappings = get_template_policy_mappings(module)
    organization_name = module.params['organization']
    return resolve_policy_moids_from_mappings(intersight, policy_cache, module, module.params, policy_mappings, organization_name)


def validate_input(module):
    """
    Validate module input parameters
    """
    if module.params['state'] == 'present':
        # Validate required fields for vNIC Template creation
        required_fields = [
            'mac_pool_name',
            'fabric_eth_network_group_policy_name',
            'fabric_eth_network_control_policy_name',
            'eth_qos_policy_name',
            'eth_adapter_policy_name'
        ]
        for field in required_fields:
            if not module.params.get(field):
                module.fail_json(msg=f"{field} is required when state is 'present'")

        # Validate CDN configuration
        validate_cdn_config(module, module.params)

        connection_type = module.params.get('connection_type', 'none')

        # Validate connection type specific settings
        template_name = module.params.get('name', 'unknown')
        if connection_type == 'usnic':
            usnic_settings = module.params.get('usnic_settings')
            validate_usnic_settings(module, usnic_settings, template_name)
        elif connection_type == 'vmq':
            vmq_settings = module.params.get('vmq_settings', {})
            validate_vmq_settings(module, vmq_settings, template_name)
        elif connection_type == 'sriov':
            sriov_settings = module.params.get('sriov_settings', {})
            validate_sriov_settings(module, sriov_settings, template_name)


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        enable_override=dict(type='bool', default=False),
        eth_qos_policy_name=dict(type='str'),
        eth_adapter_policy_name=dict(type='str'),
        pin_group_name=dict(type='str'),
    )
    # Add connection settings argument specs
    argument_spec.update(get_common_settings_argument_spec())

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    if module.params['state'] == 'present':
        validate_input(module)

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure vNIC Template
    resource_path = '/vnic/VnicTemplates'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Add vNIC Template specific parameters
        intersight.api_body['EnableOverride'] = intersight.module.params['enable_override']
        intersight.api_body['SwitchId'] = intersight.module.params['switch_id']
        intersight.api_body['FailoverEnabled'] = intersight.module.params['failover_enabled']

        # Add CDN configuration
        intersight.api_body['Cdn'] = build_cdn_config(intersight.module.params)

        # Cache for policy MOIDs to avoid redundant API calls
        policy_cache = {}

        # Resolve and add policy MOIDs
        policy_moids = resolve_policy_moids(intersight, policy_cache, intersight.module)
        intersight.api_body.update(policy_moids)

        # Add connection type specific settings
        organization_name = intersight.module.params['organization']
        connection_settings = build_connection_settings(intersight, policy_cache, intersight.module, intersight.module.params, organization_name)
        intersight.api_body.update(connection_settings)

        # Add pin group name if specified
        if intersight.module.params.get('pin_group_name'):
            intersight.api_body['PinGroupName'] = intersight.module.params['pin_group_name']

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
