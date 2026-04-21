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
module: intersight_fibre_channel_zone_policy
short_description: Manage Fibre Channel Zone Policies for Cisco Intersight
description:
  - Create, update, and delete Fibre Channel Zone Policies on Cisco Intersight.
  - Manage FC target members (zones) within FC zone policies.
  - FC Zone policies define zoning configurations for Fibre Channel networks.
  - Supports SIST (Single Initiator Single Target), SIMT (Single Initiator Multiple Target), and None zoning types.
  - When zoning type is None, targets cannot be added and existing targets will be disabled.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/fabric/FcZonePolicies/get/).
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
      - The name assigned to the Fibre Channel Zone Policy.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Fibre Channel Zone Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  fc_target_zoning_type:
    description:
      - Type of FC zoning configuration.
      - C(SIST) - Single Initiator Single Target zoning.
      - C(SIMT) - Single Initiator Multiple Target zoning.
      - C(None) - No zoning. When None is selected, targets cannot be added and existing targets will be disabled.
    type: str
    choices: [SIST, SIMT, None]
    default: None
  fc_target_members:
    description:
      - List of FC target members (zones) to be created within the FC zone policy.
      - Each target defines a WWPN that is a member of the FC zone.
      - Leave empty when fc_target_zoning_type is None.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name identifier for the FC target member.
          - Must be unique within the policy.
        type: str
        required: true
      wwpn:
        description:
          - World Wide Port Name (WWPN) that is a member of the FC zone.
          - Format should be colon-separated hex values (e.g., 21:00:00:e0:8b:05:05:04).
          - Must be a valid WWPN format.
        type: str
        required: true
      switch_id:
        description:
          - Unique identifier for the Fabric object.
          - Specifies which fabric interconnect the target is associated with.
        type: str
        choices: [A, B]
        default: A
      vsan_id:
        description:
          - VSAN ID with scope defined as Storage in the VSAN policy.
          - Must be between 1 and 4093.
        type: int
        required: true
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create FC Zone Policy with SIMT zoning and multiple targets
  cisco.intersight.intersight_fibre_channel_zone_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-zone-policy-simt"
    description: "FC Zone policy with SIMT zoning"
    fc_target_zoning_type: SIMT
    fc_target_members:
      - name: "target1"
        wwpn: "21:00:00:e0:8b:05:05:04"
        switch_id: A
        vsan_id: 100
      - name: "target2"
        wwpn: "21:00:00:e0:8b:05:05:03"
        switch_id: B
        vsan_id: 100
      - name: "target3"
        wwpn: "21:00:00:e0:8b:05:05:09"
        switch_id: A
        vsan_id: 200
    tags:
      - Key: Environment
        Value: Production
    state: present

- name: Create FC Zone Policy with SIST zoning
  cisco.intersight.intersight_fibre_channel_zone_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-zone-policy-sist"
    description: "FC Zone policy with SIST zoning"
    fc_target_zoning_type: SIST
    fc_target_members:
      - name: "single-target"
        wwpn: "21:00:00:e0:8b:05:05:01"
        switch_id: A
        vsan_id: 100
    state: present

- name: Create FC Zone Policy with no zoning (None type)
  cisco.intersight.intersight_fibre_channel_zone_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-zone-policy-none"
    description: "FC Zone policy with no zoning"
    fc_target_zoning_type: None
    state: present

- name: Update FC Zone Policy - add new target
  cisco.intersight.intersight_fibre_channel_zone_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-zone-policy-simt"
    description: "Updated FC Zone policy"
    fc_target_zoning_type: SIMT
    fc_target_members:
      - name: "target1"
        wwpn: "21:00:00:e0:8b:05:05:04"
        switch_id: A
        vsan_id: 100
      - name: "target2"
        wwpn: "21:00:00:e0:8b:05:05:03"
        switch_id: B
        vsan_id: 100
      - name: "target3"
        wwpn: "21:00:00:e0:8b:05:05:09"
        switch_id: A
        vsan_id: 200
      - name: "target4"
        wwpn: "21:00:00:e0:8b:05:05:10"
        switch_id: B
        vsan_id: 200
    state: present

- name: Update FC Zone Policy - remove a target (only specify remaining targets)
  cisco.intersight.intersight_fibre_channel_zone_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-zone-policy-simt"
    fc_target_zoning_type: SIMT
    fc_target_members:
      - name: "target1"
        wwpn: "21:00:00:e0:8b:05:05:04"
        switch_id: A
        vsan_id: 100
      - name: "target3"
        wwpn: "21:00:00:e0:8b:05:05:09"
        switch_id: A
        vsan_id: 200
    state: present

- name: Delete FC Zone Policy
  cisco.intersight.intersight_fibre_channel_zone_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-zone-policy-simt"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "fc-zone-policy-simt",
        "ObjectType": "fabric.FcZonePolicy",
        "Moid": "1234567890abcdef12345678",
        "Description": "FC Zone policy with SIMT zoning",
        "FcTargetZoningType": "SIMT",
        "FcTargetMembers": [
            {
                "Name": "target1",
                "Wwpn": "21:00:00:e0:8b:05:05:04",
                "SwitchId": "A",
                "VsanId": 100
            },
            {
                "Name": "target2",
                "Wwpn": "21:00:00:e0:8b:05:05:03",
                "SwitchId": "B",
                "VsanId": 100
            }
        ],
        "Organization": {
            "Moid": "abcdef1234567890abcdef12",
            "ObjectType": "organization.Organization"
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
import re


def validate_wwpn(wwpn):
    """
    Validate WWPN format.
    """
    wwpn_pattern = r'^([0-9a-fA-F]{2}:){7}[0-9a-fA-F]{2}$'
    if not re.match(wwpn_pattern, wwpn):
        raise ValueError(f"Invalid WWPN format '{wwpn}'. Expected format: XX:XX:XX:XX:XX:XX:XX:XX (hex values)")
    return True


def validate_vsan_id(vsan_id):
    """
    Validate VSAN ID is within acceptable range (1-4093).
    """
    if vsan_id < 1 or vsan_id > 4093:
        raise ValueError(f"VSAN ID {vsan_id} is out of valid range (1-4093)")
    return True


def validate_parameters(module):
    """
    Validate module parameters for FC Zone policy configuration.
    """
    if module.params['state'] != 'present':
        return
    fc_target_zoning_type = module.params.get('fc_target_zoning_type')
    fc_target_members = module.params.get('fc_target_members', [])
    # Validate that if zoning type is None, no targets should be provided
    if fc_target_zoning_type == 'None' and fc_target_members:
        module.fail_json(msg="When fc_target_zoning_type is 'None', fc_target_members should be empty. Targets cannot be added when zoning type is None.")
    # Validate fc_target_members if provided
    if fc_target_members:
        for target in fc_target_members:
            # Validate WWPN format
            wwpn = target.get('wwpn')
            if wwpn:
                try:
                    validate_wwpn(wwpn)
                except ValueError as e:
                    module.fail_json(msg=str(e))
            # Validate VSAN ID range
            vsan_id = target.get('vsan_id')
            if vsan_id:
                try:
                    validate_vsan_id(vsan_id)
                except ValueError as e:
                    module.fail_json(msg=str(e))


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        fc_target_zoning_type=dict(type='str', choices=['SIST', 'SIMT', 'None'], default='None'),
        fc_target_members=dict(type='list', elements='dict', options=dict(
            name=dict(type='str', required=True),
            wwpn=dict(type='str', required=True),
            switch_id=dict(type='str', choices=['A', 'B'], default='A'),
            vsan_id=dict(type='int', required=True)
        ))
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )
    intersight = IntersightModule(module)

    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Validate module parameters
    validate_parameters(module)

    # Resource path used to configure policy
    resource_path = '/fabric/FcZonePolicies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': module.params['organization'],
        },
        'Name': module.params['name']
    }

    if module.params['state'] == 'present':
        intersight.api_body['FcTargetZoningType'] = module.params['fc_target_zoning_type']
        # Build FcTargetMembers list
        fc_target_members = []
        if module.params.get('fc_target_members'):
            for target in module.params['fc_target_members']:
                fc_target_members.append({
                    'Name': target['name'],
                    'Wwpn': target['wwpn'],
                    'SwitchId': target['switch_id'],
                    'VsanId': target['vsan_id']
                })
        intersight.api_body['FcTargetMembers'] = fc_target_members
        intersight.set_tags_and_description()

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
