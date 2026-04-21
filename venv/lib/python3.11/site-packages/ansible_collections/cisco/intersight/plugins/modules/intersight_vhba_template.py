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
module: intersight_vhba_template
short_description: Manage vHBA Templates for Cisco Intersight
description:
  - Create, update, and delete vHBA Templates on Cisco Intersight.
  - vHBA Templates define fibre channel interface configurations that can be used by SAN Connectivity policies.
  - Templates provide a standardized way to configure vHBAs with consistent fibre channel policies.
  - vHBA Templates are only applicable for FI-Attached (Fabric Interconnect) deployments.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/vnic/VhbaTemplate/get/).
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
      - The name assigned to the vHBA Template.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the vHBA Template.
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
  vhba_type:
    description:
      - vHBA Type configuration for the template.
      - This configuration is supported only on Cisco VIC 14XX series and higher series of adapters.
      - Required when state is present.
    type: str
    choices: ['fc-initiator', 'fc-nvme-initiator', 'fc-nvme-target', 'fc-target']
  switch_id:
    description:
      - The fabric port to which the vHBA will be associated.
    type: str
    choices: ['A', 'B']
    default: 'A'
  persistent_bindings:
    description:
      - Enables retention of LUN ID associations in memory until they are manually cleared.
    type: bool
    default: false
  wwpn_pool_name:
    description:
      - The WWPN pool that is assigned to the vHBA Template.
      - Required when state is present.
    type: str
  fibre_channel_network_policy_name:
    description:
      - Name of the Fibre Channel Network Policy.
      - Required when state is present.
    type: str
  fibre_channel_qos_policy_name:
    description:
      - Name of the Fibre Channel QoS Policy.
      - Required when state is present.
    type: str
  fibre_channel_adapter_policy_name:
    description:
      - Name of the Fibre Channel Adapter Policy.
      - Required when state is present.
    type: str
  fibre_channel_zone_policy_names:
    description:
      - List of Fibre Channel Zone Policy names.
      - Relationship to the FC Zone policies to configure Zones on the switch.
    type: list
    elements: str
  pin_group_name:
    description:
      - Pingroup name associated to vHBA for static pinning.
      - SCP deploy will resolve pingroup name and fetches the corresponding uplink port/port channel to pin the vHBA traffic.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a basic vHBA Template with WWPN pool
  cisco.intersight.intersight_vhba_template:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "basic-vhba-template"
    description: "Basic vHBA template for production servers"
    enable_override: false
    vhba_type: "fc-initiator"
    switch_id: "A"
    persistent_bindings: false
    wwpn_pool_name: "default-wwpn-pool"
    fibre_channel_network_policy_name: "fc-network-policy"
    fibre_channel_qos_policy_name: "fc-qos-policy"
    fibre_channel_adapter_policy_name: "fc-adapter-policy"
    tags:
      - Key: "Environment"
        Value: "Production"
      - Key: "Site"
        Value: "DataCenter-A"
    state: present

- name: Create a vHBA Template with override enabled
  cisco.intersight.intersight_vhba_template:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "override-vhba-template"
    description: "vHBA template with override enabled"
    enable_override: true
    vhba_type: "fc-target"
    switch_id: "B"
    persistent_bindings: true
    wwpn_pool_name: "default-wwpn-pool"
    fibre_channel_network_policy_name: "fc-network-policy"
    fibre_channel_qos_policy_name: "fc-qos-policy"
    fibre_channel_adapter_policy_name: "fc-adapter-policy"
    state: present

- name: Create a vHBA Template with FC Zone policies
  cisco.intersight.intersight_vhba_template:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "vhba-with-zones"
    description: "vHBA template with FC zone policies"
    enable_override: false
    vhba_type: "fc-initiator"
    switch_id: "A"
    persistent_bindings: false
    wwpn_pool_name: "default-wwpn-pool"
    fibre_channel_network_policy_name: "fc-network-policy"
    fibre_channel_qos_policy_name: "fc-qos-policy"
    fibre_channel_adapter_policy_name: "fc-adapter-policy"
    fibre_channel_zone_policy_names:
      - "fc-zone-policy-1"
      - "fc-zone-policy-2"
    state: present

- name: Create a vHBA Template with pin group
  cisco.intersight.intersight_vhba_template:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "vhba-pinned-template"
    description: "vHBA template with static pinning"
    enable_override: false
    vhba_type: "fc-nvme-initiator"
    switch_id: "A"
    persistent_bindings: true
    wwpn_address_type: "pool"
    wwpn_pool_name: "nvme-wwpn-pool"
    fibre_channel_network_policy_name: "fc-network-policy"
    fibre_channel_qos_policy_name: "fc-qos-policy"
    fibre_channel_adapter_policy_name: "fc-adapter-policy"
    pin_group_name: "pingroup-a"
    state: present

- name: Delete a vHBA Template
  cisco.intersight.intersight_vhba_template:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "old-vhba-template"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "test-vhba-template",
        "ObjectType": "vnic.VhbaTemplate",
        "EnableOverride": false,
        "Type": "fc-initiator",
        "SwitchId": "A",
        "PersistentBindings": false,
        "WwpnAddressType": "POOL",
        "WwpnPool": {
            "Name": "default-wwpn-pool",
            "ObjectType": "fcpool.Pool"
        },
        "FcNetworkPolicy": {
            "Name": "fc-network-policy",
            "ObjectType": "vnic.FcNetworkPolicy"
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
from ansible_collections.cisco.intersight.plugins.module_utils.intersight_vhba_utils import (
    get_policy_moid_with_org, resolve_policy_moids_from_mappings, resolve_fc_zone_policies,
    get_vhba_template_policy_mappings
)


def validate_input(module):
    """
    Validate module input parameters.
    """
    if module.params['state'] == 'present':
        # Validate required fields for vHBA Template creation
        required_fields = [
            'vhba_type',
            'wwpn_pool_name',
            'fibre_channel_network_policy_name',
            'fibre_channel_qos_policy_name',
            'fibre_channel_adapter_policy_name'
        ]
        for field in required_fields:
            if not module.params.get(field):
                module.fail_json(msg=f"{field} is required when state is 'present'")


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        enable_override=dict(type='bool', default=False),
        vhba_type=dict(type='str', choices=['fc-initiator', 'fc-nvme-initiator', 'fc-nvme-target', 'fc-target']),
        switch_id=dict(type='str', choices=['A', 'B'], default='A'),
        persistent_bindings=dict(type='bool', default=False),
        wwpn_pool_name=dict(type='str'),
        fibre_channel_network_policy_name=dict(type='str'),
        fibre_channel_qos_policy_name=dict(type='str'),
        fibre_channel_adapter_policy_name=dict(type='str'),
        fibre_channel_zone_policy_names=dict(type='list', elements='str'),
        pin_group_name=dict(type='str')
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

    # Resource path used to configure vHBA Template
    resource_path = '/vnic/VhbaTemplates'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Add vHBA Template specific parameters
        intersight.api_body['EnableOverride'] = intersight.module.params['enable_override']
        intersight.api_body['Type'] = intersight.module.params['vhba_type']
        intersight.api_body['SwitchId'] = intersight.module.params['switch_id']
        intersight.api_body['PersistentBindings'] = intersight.module.params['persistent_bindings']

        # Cache for policy MOIDs to avoid redundant API calls
        policy_cache = {}
        organization_name = intersight.module.params['organization']

        # Resolve WWPN Pool MOID
        wwpn_pool_moid = get_policy_moid_with_org(
            intersight, policy_cache, module, '/fcpool/Pools',
            intersight.module.params['wwpn_pool_name'], organization_name, 'WWPN Pool'
        )
        intersight.api_body['WwpnPool'] = wwpn_pool_moid

        # Resolve FC policy MOIDs
        policy_mappings = get_vhba_template_policy_mappings()
        policy_moids = resolve_policy_moids_from_mappings(intersight, policy_cache, module, intersight.module.params, policy_mappings, organization_name)
        intersight.api_body.update(policy_moids)

        # Resolve Fibre Channel Zone Policies (optional)
        fc_zone_policy_names = intersight.module.params.get('fibre_channel_zone_policy_names')
        fc_zone_policy_moids = resolve_fc_zone_policies(intersight, policy_cache, module, fc_zone_policy_names, organization_name)
        intersight.api_body['FcZonePolicies'] = fc_zone_policy_moids

        # Add pin group name if specified
        if intersight.module.params.get('pin_group_name'):
            intersight.api_body['PinGroupName'] = intersight.module.params['pin_group_name']

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
